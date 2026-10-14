package com.sparrowwallet.drongo.antiexfil;

import com.sparrowwallet.drongo.Utils;
import com.sparrowwallet.drongo.protocol.Sha256Hash;
import java.io.*;
import java.nio.file.*;
import java.time.Instant;
import java.util.*;

/** Nonsecret V3 audit. Cold immutable frames are authoritative; the hot view is
 * counters, one active exchange and at most 128 details. No lifetime event budget. */
final class AntiExfilRecoveryHistory {
    enum Type { IMPORT_V2, FRESH_START_APPROVED, SESSION_STARTED, REVEAL_MAY_HAVE_ESCAPED,
        VERIFIED_COMPLETE, PRE_REVEAL_END, PRE_REVEAL_REJECTED, ENDED_UNVERIFIED, OWNER_LOST_UNVERIFIED }
    record Context(String session, String psbt, String payment, int network) { }
    record Legacy(Path path, byte[] identity) { }
    record Counts(long starts, long reveals, long completions, long uncertain, long preRevealEnds, boolean unknown) { }
    record Frame(long sequence, String predecessor, Type type, Context context, long time, String reason,
                 String locator, long sourceBytes, String sourceHash, String sourceIdentity) { }
    private static final Context NONE = new Context("", "", "", -1);
    private static final String ZERO = "0".repeat(64);
    private final Path directory;
    private final String account;
    private final AntiExfilExchangeLease lease;
    private final FrameWriter writer;
    private final ArrayDeque<Frame> recent = new ArrayDeque<>();
    private final Map<String, Long> reasons = new TreeMap<>();
    private Context active;
    private boolean revealed;
    private Context approved;
    private String revision = ZERO;
    private long sequence, starts, reveals, completions, uncertain, preRevealEnds, unknownPaymentUncertain;
    private boolean unknown;

    AntiExfilRecoveryHistory(Path directory, byte[] identity, AntiExfilExchangeLease lease) {
        this(directory, identity, lease, (path, body) -> AntiExfilDurableFiles.write(path, body, true, 4096));
    }
    AntiExfilRecoveryHistory(Path directory, byte[] identity, AntiExfilExchangeLease lease, FrameWriter writer) {
        this.directory = directory.toAbsolutePath().normalize();
        this.account = Utils.bytesToHex(identity);
        this.lease = lease;
        this.writer = writer;
        refresh();
    }

    synchronized void refresh() {
        checked(() -> AntiExfilDurableFiles.locked(directory.resolve("history"), () -> {
            lease.check();
            sequence = starts = reveals = completions = uncertain = preRevealEnds = unknownPaymentUncertain = 0;
            unknown = revealed = false; active = approved = null; revision = ZERO;
            recent.clear(); reasons.clear();
            // A scratch disk set proves all retained START identifiers unique without
            // an account-lifetime hot-memory set. It is never a recovery authority.
            Path scratch = Files.createTempDirectory(directory, ".sid-validation-");
            try {
                long index = 1;
                while(Files.exists(framePath(index))) {
                    byte[] body = AntiExfilDurableFiles.read(framePath(index), 4096);
                    Frame frame = decode(body);
                    if(frame.sequence != index || !frame.predecessor.equals(revision)) throw new IOException("Audit predecessor/sequence differs");
                    if(frame.type == Type.SESSION_STARTED) {
                        Path marker = scratch.resolve(frame.context.session);
                        try { Files.writeString(marker, "V3", StandardOpenOption.CREATE_NEW); } catch(FileAlreadyExistsException e) { throw new IOException("Reused session identity", e); }
                    } else if(frame.type == Type.IMPORT_V2 && !frame.locator.isEmpty()) {
                        for(var event : snapshot(frame).events()) {
                            Path marker = scratch.resolve(Utils.bytesToHex(event.getSessionId()));
                            if(Files.exists(marker)) {
                                if(!Files.readString(marker).equals("V2")) throw new IOException("V2 imported an already used V3 session identity");
                            } else Files.writeString(marker, "V2", StandardOpenOption.CREATE_NEW);
                        }
                    }
                    reduce(frame);
                    revision = Utils.bytesToHex(Sha256Hash.hash(body));
                    index = Math.incrementExact(index);
                }
                // Streaming enumeration detects a gap or unexpected tail without sorting
                // all names into a growing in-memory list.
                long files = 0;
                try(DirectoryStream<Path> paths = Files.newDirectoryStream(directory, "*.aex3")) {
                    for(Path path : paths) {
                        String name = path.getFileName().toString();
                        if(!name.matches("[0-9]{20}\\.aex3")) throw new IOException("Unknown audit filename");
                        files = Math.incrementExact(files);
                    }
                }
                if(files != sequence) throw new IOException("Audit sequence has a gap");
                checkLegacy();
                lease.check();
            } finally {
                try(DirectoryStream<Path> markers = Files.newDirectoryStream(scratch)) { for(Path marker : markers) Files.delete(marker); }
                Files.delete(scratch);
            }
            return null;
        }));
    }

    synchronized void importLegacy(List<Legacy> sources, boolean sessionFilesPresent) {
        if(active != null) invalid("Reconcile the old exchange before migration");
        for(Legacy source : sources) {
            Path canonical = AntiExfilDurableFiles.canonicalPath(source.path);
            String locator = directory.relativize(canonical).toString();
            if(hasImport(locator)) continue;
            var snapshot = new AntiExfilAbortJournal(canonical, source.identity).readOnlySnapshot();
            Set<String> ids = new HashSet<>(); // Bounded by V2's own 10k format limit.
            snapshot.events().forEach(event -> ids.add(Utils.bytesToHex(event.getSessionId())));
            checked(() -> {
                for(long i = 1; i <= sequence; i++) {
                    Frame frame = decode(AntiExfilDurableFiles.read(framePath(i), 4096));
                    if(frame.type == Type.SESSION_STARTED && ids.contains(frame.context.session)) throw new IOException("Imported V2 session conflicts with V3");
                }
                return null;
            });
            append(Type.IMPORT_V2, NONE, "", locator, snapshot.bytes(), Utils.bytesToHex(snapshot.hash()), Utils.bytesToHex(source.identity));
        }
        if(sessionFilesPresent && !unknown) append(Type.IMPORT_V2, NONE, "LEGACY_SESSION_PRESENCE", "", -1, ZERO, ZERO);
    }

    synchronized void reconcile() {
        // active was derived from the entire cold stream in refresh, never recent.
        if(active != null) append(revealed ? Type.OWNER_LOST_UNVERIFIED : Type.PRE_REVEAL_END,
                active, "OWNER_LOST_UNVERIFIED");
    }
    synchronized Counts counts() { return new Counts(starts, reveals, completions, uncertain, preRevealEnds, unknown); }
    synchronized Map<String, Long> reasonCounts() { return Map.copyOf(reasons); }
    synchronized String revision() { return revision; }
    synchronized int hotDetailSize() { return recent.size(); }
    synchronized long unknownPaymentUncertain() { return unknownPaymentUncertain; }
    synchronized boolean needsApproval() { return uncertain != 0 || unknown; }

    synchronized long paymentUncertain(String payment) {
        return checked(() -> {
            long count = 0;
            for(long i = 1; i <= sequence; i++) {
                Frame f = decode(AntiExfilDurableFiles.read(framePath(i), 4096));
                if((f.type == Type.ENDED_UNVERIFIED || f.type == Type.OWNER_LOST_UNVERIFIED) && f.context.payment.equals(payment)) count = Math.incrementExact(count);
            }
            return count;
        });
    }
    synchronized boolean hasSession(String id) {
        return checked(() -> {
            if(legacyHasSession(id)) return true;
            for(long i = 1; i <= sequence; i++) {
                Frame f = decode(AntiExfilDurableFiles.read(framePath(i), 4096));
                if(f.type == Type.SESSION_STARTED && f.context.session.equals(id)) return true;
            }
            return false;
        });
    }
    synchronized void start(Context context, boolean approval) {
        if(active != null || hasSession(context.session)) invalid("A session is already live or its identity was previously used");
        if(needsApproval() && !approval) throw new AntiExfilException(AntiExfilException.Code.RECOVERY_APPROVAL_REQUIRED, "Confirm the retained interruption history before starting again");
        if(approval) append(Type.FRESH_START_APPROVED, context, approvalSummary());
        append(Type.SESSION_STARTED, context, "");
    }
    synchronized void reveal(Context context) { require(context, false); append(Type.REVEAL_MAY_HAVE_ESCAPED, context, ""); }
    synchronized void requirePending(Context context) { require(context, true); lease.check(); checkLegacy(); }
    synchronized void complete(Context context) { require(context, true); append(Type.VERIFIED_COMPLETE, context, ""); }
    synchronized void end(Context context, String reason, boolean rejected) {
        require(context, revealed);
        append(revealed ? Type.ENDED_UNVERIFIED : rejected ? Type.PRE_REVEAL_REJECTED : Type.PRE_REVEAL_END, context, reason);
    }
    synchronized void beforeDisclosure() { lease.check(); checkLegacy(); }

    private String approvalSummary() {
        return revision + ";" + starts + ";" + reveals + ";" + completions + ";" + uncertain + ";" + preRevealEnds + ";" + unknown;
    }
    private void require(Context context, boolean afterReveal) {
        if(active == null || !active.equals(context) || revealed != afterReveal) invalid("No matching live session at this stage");
    }
    private void append(Type type, Context context, String reason) { append(type, context, reason, "", -1, ZERO, ZERO); }
    private void append(Type type, Context context, String reason, String locator, long bytes, String hash, String identity) {
        checked(() -> AntiExfilDurableFiles.locked(directory.resolve("history"), () -> {
            lease.check(); checkLegacy();
            // An unexpected tail is evidence of another writer, never an overwrite target.
            long next = Math.incrementExact(sequence);
            if(Files.exists(framePath(next))) throw new IOException("Unexpected audit writer");
            Frame frame = new Frame(next, revision, type, context, Instant.now().getEpochSecond(), reason, locator, bytes, hash, identity);
            byte[] body = encode(frame);
            writer.write(framePath(next), body);
            reduce(frame);
            revision = Utils.bytesToHex(Sha256Hash.hash(body));
            lease.check();
            return null;
        }));
    }
    private void reduce(Frame frame) throws IOException {
        switch(frame.type) {
            case IMPORT_V2 -> {
                if(active != null) throw new IOException("Reconcile the prior exchange before migration");
                if(frame.locator.isEmpty()) {
                    if(!frame.reason.equals("LEGACY_SESSION_PRESENCE")) throw new IOException("Invalid legacy observation");
                    unknown = true;
                } else {
                    if(hasImport(frame.locator)) throw new IOException("Duplicate migration source");
                    try(LegacyAccumulator accumulator = new LegacyAccumulator()) {
                        eachImport(prior -> { if(!prior.locator.isEmpty()) accumulator.add(snapshot(prior).events()); });
                        LegacyTotals before = accumulator.totals();
                        accumulator.add(snapshot(frame).events());
                        LegacyTotals totals = accumulator.totals();
                        starts = Math.addExact(starts, totals.starts - before.starts); reveals = Math.addExact(reveals, totals.reveals - before.reveals);
                        completions = Math.addExact(completions, totals.completions - before.completions); uncertain = Math.addExact(uncertain, totals.uncertain - before.uncertain);
                        unknownPaymentUncertain = Math.addExact(unknownPaymentUncertain, totals.uncertain - before.uncertain);
                        preRevealEnds = Math.addExact(preRevealEnds, totals.pre - before.pre); unknown |= totals.unknown;
                        Set<String> keys = new TreeSet<>(before.reasons.keySet()); keys.addAll(totals.reasons.keySet());
                        for(String key : keys) {
                            long value = Math.addExact(reasons.getOrDefault(key, 0L), totals.reasons.getOrDefault(key, 0L) - before.reasons.getOrDefault(key, 0L));
                            if(value == 0) reasons.remove(key); else reasons.put(key, value);
                        }
                    }
                }
            }
            case FRESH_START_APPROVED -> {
                if(active != null || !frame.reason.equals(approvalSummary())) throw new IOException("Approval history context differs");
                approved = frame.context;
            }
            case SESSION_STARTED -> {
                if(active != null || (needsApproval() && !frame.context.equals(approved))) throw new IOException("Unapproved or overlapping session");
                active = frame.context; revealed = false; approved = null; starts = Math.incrementExact(starts);
            }
            case REVEAL_MAY_HAVE_ESCAPED -> { require(frame.context, false); revealed = true; reveals = Math.incrementExact(reveals); }
            case VERIFIED_COMPLETE -> { require(frame.context, true); completions = Math.incrementExact(completions); active = null; revealed = false; }
            case PRE_REVEAL_END, PRE_REVEAL_REJECTED -> { require(frame.context, false); preRevealEnds = Math.incrementExact(preRevealEnds); active = null; }
            case ENDED_UNVERIFIED, OWNER_LOST_UNVERIFIED -> {
                require(frame.context, true); uncertain = Math.incrementExact(uncertain);
                reasons.merge(normalizeReason(frame.reason), 1L, Math::addExact); active = null; revealed = false;
            }
        }
        sequence = frame.sequence;
        if(recent.size() == 128) recent.removeFirst();
        recent.addLast(frame);
    }

    private static String normalizeReason(String reason) {
        return switch(reason) {
            case "SIGNATURE_REJECTED", "USER_ABANDONED", "TRANSPORT_FAILED", "SIGNER_CANCELLED", "OWNER_LOST_UNVERIFIED", "HOST_EXCHANGE_CLOSED" -> reason;
            default -> "LEGACY_UNKNOWN";
        };
    }
    private void eachImport(ImportAction action) throws IOException {
        for(long i = 1; i <= sequence; i++) {
            Frame frame = decode(AntiExfilDurableFiles.read(framePath(i), 4096));
            if(frame.type == Type.IMPORT_V2) action.accept(frame);
        }
    }
    @FunctionalInterface private interface ImportAction { void accept(Frame frame) throws IOException; }
    private boolean hasImport(String locator) {
        return checked(() -> { boolean[] found = {false}; eachImport(frame -> { if(frame.locator.equals(locator)) found[0] = true; }); return found[0]; });
    }
    private boolean legacyHasSession(String id) {
        return checked(() -> { boolean[] found = {false}; eachImport(frame -> { if(legacyContains(frame, id)) found[0] = true; }); return found[0]; });
    }
    private void checkLegacy() { checked(() -> { eachImport(frame -> { if(!frame.locator.isEmpty()) snapshot(frame); }); return null; }); }
    private AntiExfilAbortJournal.LegacySnapshot snapshot(Frame frame) {
        Path path = directory.resolve(frame.locator).normalize();
        if(!path.getFileName().toString().endsWith(".aexj")) throw storage(new IOException("Unsupported migration source"));
        var snapshot = new AntiExfilAbortJournal(path, Utils.hexToBytes(frame.sourceIdentity))
                .readOnlySnapshot(frame.sourceBytes, Utils.hexToBytes(frame.sourceHash));
        if(snapshot.bytes() != frame.sourceBytes || !Utils.bytesToHex(snapshot.hash()).equals(frame.sourceHash))
            throw new AntiExfilException(AntiExfilException.Code.VERSION_CONFLICT, "An older host changed the retained V2 history. Stop older hosts; preserve both versions of the history before investigation.");
        return snapshot;
    }
    private boolean legacyContains(Frame frame, String session) {
        return !frame.locator.isEmpty() && snapshot(frame).events().stream().anyMatch(e -> Utils.bytesToHex(e.getSessionId()).equals(session));
    }
    private record LegacyTotals(long starts, long reveals, long completions, long uncertain, long pre, boolean unknown, Map<String, Long> reasons) { }
    /** Disk-backed, derived migration workspace: no growing hot session/source map.
     * It is rebuilt from the validated cold audit, never used as an authority later. */
    private final class LegacyAccumulator implements AutoCloseable {
        private final Path scratch;
        private long starts, reveals, complete, risk, pre;
        private boolean unknown;
        private final Map<String, Long> reasons = new TreeMap<>();
        LegacyAccumulator() throws IOException { scratch = Files.createTempDirectory(directory, ".legacy-validation-"); }
        LegacyTotals totals() { return new LegacyTotals(starts, reveals, complete, risk, pre, unknown, Map.copyOf(reasons)); }
        void add(List<AntiExfilAbortJournal.AbortEvent> events) throws IOException {
            for(var event : events) {
                if(event.getReason().equals("LEGACY_ACCOUNT_HISTORY")) { unknown = true; continue; }
                String sid = Utils.bytesToHex(event.getSessionId()), digest = Utils.bytesToHex(event.getPsbtDigest());
                Path file = scratch.resolve(sid); int before = 0; String priorReason = "OWNER_LOST_UNVERIFIED";
                if(Files.exists(file)) {
                    try(DataInputStream in = new DataInputStream(Files.newInputStream(file))) {
                        if(!in.readUTF().equals(digest)) throw new IOException("Legacy session context differs");
                        before = in.readInt(); priorReason = in.readUTF();
                        if(in.read() != -1) throw new IOException("Migration workspace changed");
                    }
                }
                int after = before; String reason = priorReason;
                // flags: PRE=1, POSSIBLE=2, COMPLETE=4, ENDED=8.
                switch(event.getReason()) {
                    case "PRE_REVEAL_REJECTED" -> { if((before & ~1) != 0) throw new IOException("Contradictory legacy rejection"); after |= 1; }
                    case "PENDING_REVEAL" -> { if((before & 1) != 0) throw new IOException("Contradictory legacy pending"); after |= 2; }
                    case "VERIFIED_COMPLETE" -> { if((before & 2) == 0 || (before & 9) != 0) throw new IOException("Legacy completion after end or without reveal"); after |= 4; }
                    default -> {
                        if((before & 5) != 0) throw new IOException("Contradictory legacy end");
                        after |= 10;
                        if(!reason.equals("SIGNATURE_REJECTED")) reason = normalizeReason(event.getReason());
                    }
                }
                if(before == 0) starts = Math.incrementExact(starts);
                reveals = Math.addExact(reveals, bit(after, 2) - bit(before, 2));
                complete = Math.addExact(complete, bit(after, 4) - bit(before, 4));
                pre = Math.addExact(pre, bit(after, 1) - bit(before, 1));
                boolean wasRisk = (before & 2) != 0 && (before & 4) == 0, nowRisk = (after & 2) != 0 && (after & 4) == 0;
                risk = Math.addExact(risk, (nowRisk ? 1 : 0) - (wasRisk ? 1 : 0));
                if(wasRisk) reasons.compute(priorReason, (key, count) -> count == 1 ? null : count - 1);
                if(nowRisk) reasons.merge(reason, 1L, Math::addExact);
                try(DataOutputStream out = new DataOutputStream(Files.newOutputStream(file))) { out.writeUTF(digest); out.writeInt(after); out.writeUTF(reason); }
            }
        }
        private static int bit(int flags, int mask) { return (flags & mask) == 0 ? 0 : 1; }
        @Override public void close() throws IOException {
            try(DirectoryStream<Path> files = Files.newDirectoryStream(scratch)) { for(Path file : files) Files.delete(file); }
            Files.delete(scratch);
        }
    }

    private Path framePath(long number) { return directory.resolve(String.format(Locale.ROOT, "%020d.aex3", number)); }
    private byte[] encode(Frame frame) throws IOException {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        try(DataOutputStream out = new DataOutputStream(bytes)) {
            out.writeInt(0x41455833); out.writeUTF(account); out.writeLong(frame.sequence); out.writeUTF(frame.predecessor);
            out.writeByte(frame.type.ordinal()); out.writeUTF(frame.context.session); out.writeUTF(frame.context.psbt);
            out.writeUTF(frame.context.payment); out.writeInt(frame.context.network); out.writeLong(frame.time);
            out.writeUTF(frame.reason); out.writeUTF(frame.locator); out.writeLong(frame.sourceBytes);
            out.writeUTF(frame.sourceHash); out.writeUTF(frame.sourceIdentity);
        }
        return bytes.toByteArray();
    }
    private Frame decode(byte[] body) throws IOException {
        try(DataInputStream in = new DataInputStream(new ByteArrayInputStream(body))) {
            if(in.readInt() != 0x41455833 || !in.readUTF().equals(account)) throw new IOException("Foreign or unknown history frame");
            long seq = in.readLong(); String prev = in.readUTF(); int type = in.readUnsignedByte();
            if(type >= Type.values().length || !prev.matches("[0-9a-f]{64}")) throw new IOException("Invalid history header");
            Context context = new Context(in.readUTF(), in.readUTF(), in.readUTF(), in.readInt());
            Frame f = new Frame(seq, prev, Type.values()[type], context, in.readLong(), in.readUTF(), in.readUTF(), in.readLong(), in.readUTF(), in.readUTF());
            if(in.available() != 0 || seq < 1 || f.time < 0 || f.reason.length() > 512 || f.locator.length() > 1024 ||
                    !f.sourceHash.matches("[0-9a-f]{64}") || !f.sourceIdentity.matches("[0-9a-f]{64}")) throw new IOException("Invalid history frame");
            if(f.type != Type.IMPORT_V2 && (!context.session.matches("[0-9a-f]{64}") || !context.psbt.matches("[0-9a-f]{64}") ||
                    !context.payment.matches("[0-9a-f]{64}") || context.network < 0 || context.network > 4)) throw new IOException("Invalid signing context");
            return f;
        } catch(EOFException e) { throw new IOException("Truncated history frame", e); }
    }
    private <T> T checked(AntiExfilDurableFiles.IOAction<T> action) {
        try { return action.run(); }
        catch(AntiExfilException e) {
            if(e.getCode() == AntiExfilException.Code.VERSION_CONFLICT || e.getCode() == AntiExfilException.Code.HISTORY_STORAGE_ERROR) throw e;
            throw storage(e);
        } catch(IOException | ArithmeticException e) { throw storage(e); }
    }
    private static AntiExfilException storage(Exception e) { return new AntiExfilException(AntiExfilException.Code.HISTORY_STORAGE_ERROR, "Protected QR history is inconsistent or storage failed. Preserve the files; no signing data was released by this failed transition.", e); }
    private static void invalid(String detail) { throw new AntiExfilException(AntiExfilException.Code.STATE_INVALID, detail); }
    @FunctionalInterface interface FrameWriter { void write(Path path, byte[] body) throws IOException; }
}
