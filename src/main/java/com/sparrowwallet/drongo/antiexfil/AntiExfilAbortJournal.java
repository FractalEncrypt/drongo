package com.sparrowwallet.drongo.antiexfil;

import com.sparrowwallet.drongo.protocol.Sha256Hash;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public final class AntiExfilAbortJournal {
    private static final byte[] MAGIC = {'A', 'E', 'X', 'J'};
    private static final int VERSION = 2;
    private static final int MAX_FILE_BYTES = 4 * 1024 * 1024;
    private static final int MAX_EVENTS = 10_000;
    private static final int MAX_REASON_BYTES = 512;

    private final Path path;
    private final byte[] walletIdentity;

    public AntiExfilAbortJournal(Path path, byte[] walletIdentity) {
        if(path == null || walletIdentity == null || walletIdentity.length != 32) {
            throw new AntiExfilException(AntiExfilException.Code.STATE_INVALID, "Invalid abort-journal identity");
        }
        this.path = AntiExfilDurableFiles.canonicalPath(path);
        this.walletIdentity = walletIdentity.clone();
    }

    public List<AbortEvent> getEvents() {
        return locked(LockedJournal::getEvents);
    }

    /** Migration reader: no creation, rewrite, or session-file access. */
    LegacySnapshot readOnlySnapshot() {
        return readOnlySnapshot(null, null);
    }
    LegacySnapshot readOnlySnapshot(Long expectedBytes, byte[] expectedHash) {
        return AntiExfilDurableFiles.locked(path, () -> {
            if(!Files.exists(path)) {
                if(expectedBytes != null && expectedBytes != -1) throw changedLegacy();
                return new LegacySnapshot(-1, new byte[32], List.of());
            }
            long size = Files.size(path);
            if(size > MAX_FILE_BYTES) {
                if(expectedBytes != null) throw changedLegacy();
                throw new IOException("Legacy history exceeds its format bound");
            }
            byte[] raw = Files.readAllBytes(path), hash = Sha256Hash.hash(raw);
            if(expectedBytes != null && (raw.length != expectedBytes || !Arrays.equals(hash, expectedHash))) throw changedLegacy();
            Journal loaded = decode(AntiExfilDurableFiles.read(path, MAX_FILE_BYTES));
            if(!Arrays.equals(walletIdentity, loaded.walletIdentity)) throw new IOException("Legacy history identity differs");
            return new LegacySnapshot(raw.length, hash, List.copyOf(loaded.events));
        });
    }
    private static AntiExfilException changedLegacy() {
        return new AntiExfilException(AntiExfilException.Code.VERSION_CONFLICT,
                "Retained V2 history changed. Stop older hosts and preserve the files before investigation.");
    }

    record LegacySnapshot(long bytes, byte[] hash, List<AbortEvent> events) { }

    AbortEvent append(byte[] sessionId, byte[] psbtDigest, String reason) {
        String normalizedReason = validateEvent(sessionId, psbtDigest, reason);
        return locked(journal -> journal.append(sessionId, psbtDigest, normalizedReason));
    }

    <T> T locked(LockedAction<T> action) {
        return AntiExfilDurableFiles.locked(path, () -> action.run(new LockedJournal(loadOrCreate())));
    }

    private static String validateEvent(byte[] sessionId, byte[] psbtDigest, String reason) {
        if(sessionId == null || sessionId.length != 32 || psbtDigest == null || psbtDigest.length != 32) {
            throw new AntiExfilException(AntiExfilException.Code.STATE_INVALID, "Invalid abort event context");
        }
        byte[] reasonBytes = reason == null ? new byte[0] : reason.strip().getBytes(StandardCharsets.UTF_8);
        if(reasonBytes.length == 0 || reasonBytes.length > MAX_REASON_BYTES) {
            throw new AntiExfilException(AntiExfilException.Code.STATE_INVALID,
                    "Abort reason must contain 1 to " + MAX_REASON_BYTES + " UTF-8 bytes");
        }
        return new String(reasonBytes, StandardCharsets.UTF_8);
    }

    private Journal loadOrCreate() throws IOException {
        if(!Files.exists(path)) {
            Journal journal = new Journal(walletIdentity, List.of());
            AntiExfilDurableFiles.write(path, encode(journal), true, MAX_FILE_BYTES);
            return journal;
        }
        Journal journal = decode(AntiExfilDurableFiles.read(path, MAX_FILE_BYTES));
        if(!Arrays.equals(walletIdentity, journal.walletIdentity)) throw new IOException("Abort journal belongs to another wallet key identity");
        return journal;
    }

    private static byte[] encode(Journal journal) throws IOException {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        try(DataOutputStream output = new DataOutputStream(bytes)) {
            output.write(MAGIC);
            output.writeByte(VERSION);
            output.write(journal.walletIdentity);
            output.writeInt(journal.events.size());
            for(AbortEvent event : journal.events) {
                byte[] reason = event.reason.getBytes(StandardCharsets.UTF_8);
                output.write(event.sessionId);
                output.write(event.psbtDigest);
                output.writeLong(event.recordedAtEpochSecond);
                output.writeShort(reason.length);
                output.write(reason);
            }
        }
        return bytes.toByteArray();
    }

    private static Journal decode(byte[] body) throws IOException {
        try(DataInputStream input = new DataInputStream(new ByteArrayInputStream(body))) {
            byte[] magic = input.readNBytes(4);
            int version = input.readUnsignedByte();
            if(!Arrays.equals(magic, MAGIC) || version < 1 || version > VERSION) throw new IOException("Unknown abort-journal format");
            byte[] identity = input.readNBytes(32);
            int count = input.readInt();
            if(identity.length != 32 || count < 0 || count > MAX_EVENTS) throw new IOException("Invalid abort-journal header");
            List<AbortEvent> events = new ArrayList<>(count);
            for(int i = 0; i < count; i++) {
                byte[] sessionId = input.readNBytes(32);
                byte[] digest = input.readNBytes(32);
                long timestamp = input.readLong();
                int reasonLength = input.readUnsignedShort();
                byte[] reason = input.readNBytes(reasonLength);
                if(sessionId.length != 32 || digest.length != 32 || reasonLength < 1
                        || reasonLength > MAX_REASON_BYTES || reason.length != reasonLength || timestamp < 0) {
                    throw new IOException("Invalid abort-journal event");
                }
                events.add(new AbortEvent(sessionId, digest, timestamp, new String(reason, StandardCharsets.UTF_8)));
            }
            if(input.available() != 0) throw new IOException("Trailing abort-journal data");
            return new Journal(identity, events);
        } catch(EOFException e) {
            throw new IOException("Truncated abort journal", e);
        }
    }

    public static final class AbortEvent {
        private final byte[] sessionId;
        private final byte[] psbtDigest;
        private final long recordedAtEpochSecond;
        private final String reason;

        private AbortEvent(byte[] sessionId, byte[] psbtDigest, long recordedAtEpochSecond, String reason) {
            this.sessionId = sessionId.clone();
            this.psbtDigest = psbtDigest.clone();
            this.recordedAtEpochSecond = recordedAtEpochSecond;
            this.reason = reason;
        }

        public byte[] getSessionId() { return sessionId.clone(); }
        public byte[] getPsbtDigest() { return psbtDigest.clone(); }
        public long getRecordedAtEpochSecond() { return recordedAtEpochSecond; }
        public String getReason() { return reason; }
    }

    final class LockedJournal {
        private Journal journal;

        private LockedJournal(Journal loaded) {
            this.journal = loaded; // Preserve every historical event, including legacy aborts.
        }

        // Legacy post-reveal events are permanently unresolved. PRE_REVEAL_REJECTED
        // conveys no reveal and cannot be used to resolve a later pending marker.
        private List<AbortEvent> unresolved() {
            List<AbortEvent> pending = new ArrayList<>();
            for(AbortEvent event : journal.events) {
                if(event.reason.equals("PRE_REVEAL_REJECTED")) continue;
                if(event.reason.equals("VERIFIED_COMPLETE")) {
                    AbortEvent prior = findBySession(pending, event.sessionId);
                    if(prior == null || !prior.reason.equals("PENDING_REVEAL")
                            || !Arrays.equals(prior.psbtDigest, event.psbtDigest)) {
                        throw new AntiExfilException(AntiExfilException.Code.STATE_INVALID, "Invalid lifecycle resolution");
                    }
                    pending.remove(prior);
                } else if(findBySession(pending, event.sessionId) == null) {
                    pending.add(event);
                }
            }
            return pending;
        }

        void requireFreshAttempt() {
            if(!unresolved().isEmpty()) throw new AntiExfilException(AntiExfilException.Code.RETRY_CONFLICT,
                    "This account key has an unresolved possible reveal or legacy abort. A fresh Protected QR challenge is refused; only the surviving in-memory exchange can retry exactly. Show QR remains ordinary signing.");
        }

        void requirePending(byte[] sessionId, byte[] digest) {
            List<AbortEvent> pending = unresolved();
            if(pending.size() != 1 || !pending.getFirst().reason.equals("PENDING_REVEAL")
                    || !Arrays.equals(pending.getFirst().sessionId, sessionId)
                    || !Arrays.equals(pending.getFirst().psbtDigest, digest)) {
                throw new AntiExfilException(AntiExfilException.Code.RETRY_CONFLICT, "No matching durable pending reveal");
            }
        }

        void beginReveal(byte[] sessionId, byte[] digest) throws IOException {
            requireFreshAttempt();
            // Session identifiers must never be reused, even following a resolved event.
            if(findBySession(journal.events, sessionId) != null) throw new IOException("Session identity was already used");
            append(sessionId, digest, "PENDING_REVEAL");
        }

        void resolveReveal(byte[] sessionId, byte[] digest) throws IOException {
            requirePending(sessionId, digest);
            append(sessionId, digest, "VERIFIED_COMPLETE");
        }

        AbortEvent noteUnresolved(byte[] sessionId, byte[] digest, String reason) throws IOException {
            requirePending(sessionId, digest);
            // Keep the pending marker; an explicit interruption can never clear it.
            return append(sessionId, digest, reason);
        }

        List<AbortEvent> getEvents() {
            return List.copyOf(journal.events);
        }

        byte[] getDigest() throws IOException {
            return Sha256Hash.hash(encode(journal));
        }

        AbortEvent append(byte[] sessionId, byte[] psbtDigest, String reason) throws IOException {
            String normalizedReason = validateEvent(sessionId, psbtDigest, reason);
            for(AbortEvent existing : journal.events) {
                if(Arrays.equals(existing.sessionId, sessionId) && existing.reason.equals(normalizedReason)) {
                    if(!Arrays.equals(existing.psbtDigest, psbtDigest)) throw new IOException("Lifecycle context changed");
                    return existing;
                }
            }
            if(journal.events.size() >= MAX_EVENTS) throw new IOException("Abort journal is full");
            AbortEvent event = new AbortEvent(sessionId, psbtDigest, Instant.now().getEpochSecond(), normalizedReason);
            List<AbortEvent> updated = new ArrayList<>(journal.events);
            updated.add(event);
            journal = new Journal(walletIdentity, updated);
            AntiExfilDurableFiles.write(path, encode(journal), false, MAX_FILE_BYTES);
            return event;
        }
    }

    private static AbortEvent findBySession(List<AbortEvent> events, byte[] sessionId) {
        for(AbortEvent event : events) {
            if(Arrays.equals(event.sessionId, sessionId)) return event;
        }
        return null;
    }

    @FunctionalInterface
    interface LockedAction<T> {
        T run(LockedJournal journal) throws IOException;
    }

    private record Journal(byte[] walletIdentity, List<AbortEvent> events) {
    }
}
