package com.sparrowwallet.drongo.antiexfil;

import com.sparrowwallet.drongo.protocol.Sha256Hash;
import com.sparrowwallet.drongo.psbt.PSBT;
import com.sparrowwallet.drongo.wallet.Keystore;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.nio.file.Files;
import java.security.SecureRandom;
import java.util.*;
import static com.sparrowwallet.drongo.antiexfil.AntiExfilException.Code.*;

/** Active transcripts and host randomness are never serialized. Only the key-scoped,
 * nonsecret lifecycle journal survives this object. Managed runtimes/OS dumps and
 * recorded reveal QRs remain outside the application's non-retention boundary. */
public final class AntiExfilCoordinator implements AutoCloseable {
    private static final int MAX_PSBT_BYTES = 16 * 1024 * 1024;
    private final AntiExfilRecoveryHistory history;
    private final AntiExfilExchangeLease lease;
    private final AntiExfilRecoveryHistory.Context context;
    private final Keystore keystore;
    private final byte[] walletIdentity;
    private State state;
    private Completion completed;
    private Phase phase = Phase.COMMITMENTS_CREATED;
    private byte[] sessionId;
    private byte[] psbtDigest;

    private AntiExfilCoordinator(PreparedAttempt attempt) {
        this.history = attempt.history;
        this.lease = attempt.lease;
        this.context = attempt.context;
        this.keystore = attempt.keystore;
        this.walletIdentity = getWalletKeyIdentity(keystore);
    }

    public record RecoverySummary(String account, String unsignedTxid, long starts, long possibleReveals,
                                  long completions, long unfinishedAfterReveal, long thisPaymentUnfinished, long unknownPaymentUnfinished,
                                  boolean unknownLegacyHistory, Map<String, Long> reasons) {
        public RecoverySummary { reasons = Map.copyOf(reasons); }
        public boolean requiresConfirmation() { return unfinishedAfterReveal != 0 || unknownLegacyHistory; }
    }
    public static final class Approval {
        private final PreparedAttempt owner;
        private Approval(PreparedAttempt owner) { this.owner = owner; }
    }

    /** Owns the account while the dialog is open, but holds no short history lock. */
    public static final class PreparedAttempt implements AutoCloseable {
        private final AntiExfilExchangeLease lease;
        private final AntiExfilRecoveryHistory history;
        private final AntiExfilRecoveryHistory.Context context;
        private final Keystore keystore;
        private final AntiExfilNetwork network;
        private final String revision;
        private final AntiExfilRecoveryHistory.Counts counts;
        private final RecoverySummary summary;
        private final byte[] psbt;
        private boolean closed, transferred;

        private PreparedAttempt(Path directory, List<AntiExfilRecoveryHistory.Legacy> legacy, boolean legacySessions,
                                byte[] psbt, Keystore keystore, AntiExfilNetwork network, SecureRandom random) {
            if(keystore == null || !keystore.supportsAntiExfil()) throw fail(STATE_INVALID, "Keystore does not support anti-exfil signing");
            if(psbt == null || psbt.length > MAX_PSBT_BYTES || network == null || random == null) throw fail(INVALID_MESSAGE, "Invalid coordinator initialization");
            AntiExfilPsbt.enumerateSigningSlots(psbt, keystore); // Before any history is created.
            this.psbt = psbt.clone(); this.keystore = publicSnapshot(keystore); this.network = network;
            lease = AntiExfilExchangeLease.acquire(directory);
            try {
                history = new AntiExfilRecoveryHistory(directory, getSigningKeyHistoryIdentity(keystore), lease);
                history.reconcile();
                history.importLegacy(legacy, legacySessions);
                String sid = null;
                for(int i = 0; i < 1024; i++) {
                    String candidate = com.sparrowwallet.drongo.Utils.bytesToHex(random32(random));
                    if(!history.hasSession(candidate)) { sid = candidate; break; }
                }
                if(sid == null) throw fail(STATE_INVALID, "CSPRNG repeatedly reused session identities");
                String payment = AntiExfilPsbt.parseCanonicalV0(psbt).getTransaction().getTxId().toString();
                context = new AntiExfilRecoveryHistory.Context(sid, com.sparrowwallet.drongo.Utils.bytesToHex(Sha256Hash.hash(psbt)), payment, network.getCode());
                revision = history.revision(); counts = history.counts();
                summary = new RecoverySummary(com.sparrowwallet.drongo.Utils.bytesToHex(getSigningKeyHistoryIdentity(keystore)), payment,
                        counts.starts(), counts.reveals(), counts.completions(), counts.uncertain(), history.paymentUncertain(payment), history.unknownPaymentUncertain(), counts.unknown(), history.reasonCounts());
            } catch(RuntimeException e) { lease.close(); Arrays.fill(this.psbt, (byte)0); throw e; }
        }
        public RecoverySummary summary() { if(closed) throw fail(STATE_INVALID, "Prepared exchange is closed"); return summary; }
        public Approval approve() { summary(); return new Approval(this); }
        public AntiExfilCoordinator start(Approval approval) { return start(approval, new SecureRandom()); }
        private AntiExfilCoordinator start(Approval approval, SecureRandom random) {
            if(closed || transferred) throw fail(STATE_INVALID, "Prepared exchange was already consumed");
            try {
                lease.check(); history.refresh();
                if(!revision.equals(history.revision()) || !counts.equals(history.counts())) throw fail(RECOVERY_APPROVAL_REQUIRED, "History changed while confirmation was open; prepare and confirm again");
                if(approval != null && approval.owner != this) throw fail(RECOVERY_APPROVAL_REQUIRED, "Approval belongs to a different prepared exchange");
                history.start(context, approval != null);
                AntiExfilCoordinator coordinator = new AntiExfilCoordinator(this);
                Map<AntiExfilSigningSlot.Identifier, byte[]> rhos = new LinkedHashMap<>();
                try {
                    for(AntiExfilSigningSlot slot : AntiExfilPsbt.enumerateSigningSlots(psbt, keystore)) {
                        byte[] rho = null;
                        for(int i = 0; i < 1024; i++) {
                            byte[] candidate = random32(random);
                            if(!containsValue(rhos, candidate)) { rho = candidate; break; }
                            Arrays.fill(candidate, (byte)0);
                        }
                        if(rho == null) throw fail(STATE_INVALID, "CSPRNG repeatedly produced duplicate host randomness");
                        rhos.put(slot.getIdentifier(), rho);
                    }
                    byte[] id = com.sparrowwallet.drongo.Utils.hexToBytes(context.session());
                    AntiExfilMessage commit = AntiExfilPsbt.buildHostCommitMessage(psbt, keystore, network, id, rhos);
                    coordinator.state = new State(Phase.COMMITMENTS_CREATED, coordinator.walletIdentity, psbt,
                            AntiExfilCodec.encode(commit), null, null, null, null, rhos, null);
                    coordinator.sessionId = id; coordinator.psbtDigest = commit.getPsbtDigest();
                    history.beforeDisclosure();
                    transferred = true;
                    return coordinator;
                } finally {
                    rhos.values().forEach(value -> Arrays.fill(value, (byte)0));
                    if(!transferred) coordinator.closeWithoutEvent();
                }
            } catch(RuntimeException e) { close(); throw e; }
        }
        @Override public void close() {
            if(closed) return;
            closed = true; Arrays.fill(psbt, (byte)0);
            if(!transferred) lease.close();
        }
    }

    private static Keystore publicSnapshot(Keystore original) {
        Keystore copy = new Keystore();
        copy.setSource(original.getSource()); copy.setWalletModel(original.getWalletModel());
        copy.setAntiExfilPolicy(original.getAntiExfilPolicy()); copy.setAntiExfilProfile(original.getAntiExfilProfile());
        copy.setKeyDerivation(original.getKeyDerivation().copy());
        copy.setExtendedPublicKey(original.getExtendedPublicKey().copy());
        return copy;
    }

    public static PreparedAttempt prepare(Path directory, Path ramJournal, Path legacyJournal, boolean legacySessionPresent,
                                          byte[] psbt, Keystore keystore, AntiExfilNetwork network) {
        List<AntiExfilRecoveryHistory.Legacy> sources = new ArrayList<>();
        if(ramJournal != null) sources.add(new AntiExfilRecoveryHistory.Legacy(ramJournal, getSigningKeyHistoryIdentity(keystore)));
        if(legacyJournal != null && !legacyJournal.equals(ramJournal)) sources.add(new AntiExfilRecoveryHistory.Legacy(legacyJournal, getWalletKeyIdentity(keystore)));
        return new PreparedAttempt(directory, sources, legacySessionPresent, psbt, keystore, network, new SecureRandom());
    }
    public static AntiExfilCoordinator create(Path ignoredSessionPath, Path journalPath, byte[] psbt, Keystore keystore, AntiExfilNetwork network) {
        return create(ignoredSessionPath, journalPath, psbt, keystore, network, false, new SecureRandom());
    }
    /** A legacy boolean is not an approval token and cannot suppress confirmation. */
    public static AntiExfilCoordinator create(Path ignoredSessionPath, Path journalPath, byte[] psbt, Keystore keystore, AntiExfilNetwork network, boolean ignored) {
        return create(ignoredSessionPath, journalPath, psbt, keystore, network, ignored, new SecureRandom());
    }
    static AntiExfilCoordinator create(Path ignoredSessionPath, Path journalPath, byte[] psbt, Keystore keystore, AntiExfilNetwork network, boolean ignored, SecureRandom random) {
        Path directory = journalPath.toAbsolutePath().getParent().resolve("history-v3").resolve(com.sparrowwallet.drongo.Utils.bytesToHex(getSigningKeyHistoryIdentity(keystore)));
        try(var attempt = new PreparedAttempt(directory, List.of(new AntiExfilRecoveryHistory.Legacy(journalPath, getSigningKeyHistoryIdentity(keystore))), false, psbt, keystore, network, random)) {
            return attempt.start(null, random);
        }
    }

    /** Never opens or replays legacy secret-bearing session files. */
    public static AntiExfilCoordinator load(Path ignoredSessionPath, Path ignoredJournalPath, Keystore ignoredKeystore) {
        throw fail(STATE_INVALID, "Anti-exfil sessions are RAM-only and cannot be restored after host restart");
    }

    private State active() {
        if(state == null) throw fail(STATE_INVALID, "Active anti-exfil host state is no longer available");
        return state;
    }
    public synchronized byte[] getHostCommitMessage() { return transition(() -> { history.beforeDisclosure(); return active().message1.clone(); }); }
    public synchronized byte[] getFrozenPsbt() { return active().originalPsbt.clone(); }
    public synchronized byte[] getHostRevealMessage() {
        return transition(() -> {
            State state = active();
            if(state.phase != Phase.OPENINGS_ACCEPTED) throw fail(WRONG_STAGE, "Signer openings have not been accepted");
            history.beforeDisclosure();
            return state.message3.clone();
        });
    }
    public synchronized Completion getCompletedResult() {
        if(completed == null) throw fail(WRONG_STAGE, "Coordinator session is not complete");
        return completed;
    }

    public synchronized byte[] acceptOpenings(byte[] encodedOpenings) {
        return transition(() -> {
            if(encodedOpenings == null) throw fail(INVALID_MESSAGE, "Signer openings are required");
            State current = active();
            if(current.phase == Phase.OPENINGS_ACCEPTED) {
                history.requirePending(context);
                if(!Arrays.equals(encodedOpenings, current.message2)) throw fail(RETRY_CONFLICT, "Retry changed accepted signer openings");
                history.beforeDisclosure();
                return current.message3.clone();
            }

            AntiExfilMessage commit = AntiExfilCodec.decode(current.message1);
            AntiExfilMessage openings = AntiExfilCodec.decode(encodedOpenings);
            if(openings.getStage() != AntiExfilStage.SIGNER_OPENINGS) throw fail(WRONG_STAGE, "Expected signer openings");
            AntiExfilCodec.validateTransition(commit, openings);
            List<AntiExfilSlot> revealSlots = new ArrayList<>(openings.getSlots().size());
            for(AntiExfilSlot slot : openings.getSlots()) {
                byte[] rho = current.rhos.get(identifier(slot));
                if(rho == null) throw fail(SIGNATURE_SLOT_MISMATCH, "Opening has no authoritative host-randomness slot");
                revealSlots.add(new AntiExfilSlot(slot.getInputIndex(), slot.getSighashType(), slot.getSignerPublicKey(),
                        slot.getMessageHash(), slot.getCommitment(), slot.getOpening(), rho, null));
            }
            AntiExfilMessage reveal = new AntiExfilMessage(openings.getNetwork(), AntiExfilStage.HOST_REVEAL,
                    openings.getSessionId(), openings.getPsbtDigest(), revealSlots);
            AntiExfilCodec.validateTransition(openings, reveal);
            byte[] message3 = AntiExfilCodec.encode(reveal);
            // Persist only a nonsecret marker BEFORE any reveal bytes can be returned.
            // If persistence fails, no reveal is returned. No acknowledgement can bypass it.
            history.reveal(context);
            state = new State(Phase.OPENINGS_ACCEPTED, walletIdentity, current.originalPsbt,
                    current.message1, encodedOpenings, message3, null, null, current.rhos, null);
            phase = Phase.OPENINGS_ACCEPTED;
            wipe(current);
            history.beforeDisclosure();
            return message3;
        });
    }

    public synchronized Completion complete(byte[] encodedSignatures) {
        return transition(() -> {
            if(encodedSignatures == null) throw fail(INVALID_MESSAGE, "Signer signatures are required");
            State current = active();
            if(current.phase != Phase.OPENINGS_ACCEPTED) throw fail(WRONG_STAGE, "Cannot complete before accepting openings");
            history.requirePending(context);
            AntiExfilMessage reveal = AntiExfilCodec.decode(current.message3);
            AntiExfilMessage signatures = AntiExfilCodec.decode(encodedSignatures);
            if(signatures.getStage() != AntiExfilStage.SIGNER_SIGNATURES) throw fail(WRONG_STAGE, "Expected signer signatures");
            AntiExfilCodec.validateTransition(reveal, signatures);
            byte[] signed = AntiExfilPsbt.reconstructSignedPsbt(current.originalPsbt, keystore,
                    AntiExfilCodec.decode(current.message1), AntiExfilCodec.decode(current.message2), reveal, signatures, current.rhos);
            State verified = new State(Phase.COMPLETE, walletIdentity, current.originalPsbt, current.message1,
                    current.message2, current.message3, encodedSignatures, signed, current.rhos, null);
            try {
                Completion result = new Completion(signed, deriveVerifiedSignatures(verified), false);
                // A crash before durable resolution remains uncertain, even after successful verification.
                history.complete(context);
                history.beforeDisclosure();
                completed = result;
                phase = Phase.COMPLETE;
                wipe(current);
                state = null;
                lease.close();
                return result;
            } finally {
                wipe(verified);
            }
        });
    }

    private Set<VerifiedAntiExfilSignature> deriveVerifiedSignatures(State state) {
        if(state.phase != Phase.COMPLETE || state.message4 == null || state.signedPsbt == null) invalidPhase();
        AntiExfilMessage commit = AntiExfilCodec.decode(state.message1);
        AntiExfilMessage openings = AntiExfilCodec.decode(state.message2);
        AntiExfilMessage reveal = AntiExfilCodec.decode(state.message3);
        AntiExfilMessage signatures = AntiExfilCodec.decode(state.message4);
        List<AntiExfilSigningSlot> semantic = AntiExfilPsbt.enumerateSigningSlots(state.originalPsbt, keystore);
        byte[] reconstructed = AntiExfilPsbt.reconstructSignedPsbt(state.originalPsbt, keystore,
                commit, openings, reveal, signatures, state.rhos);
        if(!Arrays.equals(reconstructed, state.signedPsbt)) {
            throw fail(STATE_INVALID, "Verified-signature evidence does not reconstruct the stored signed PSBT");
        }
        PSBT original = AntiExfilPsbt.parseCanonicalV0(state.originalPsbt);
        byte[] originalDigest = Sha256Hash.hash(state.originalPsbt);
        Set<VerifiedAntiExfilSignature> verified = new LinkedHashSet<>();
        for(int i = 0; i < semantic.size(); i++) {
            AntiExfilSigningSlot authoritative = semantic.get(i);
            AntiExfilSlot signature = signatures.getSlots().get(i);
            byte[] outpoint = original.getTransaction().getInputs().get(authoritative.getInputIndex())
                    .getOutpoint().bitcoinSerialize();
            verified.add(new VerifiedAntiExfilSignature(commit.getSessionId(), originalDigest,
                    state.walletIdentity, authoritative.getInputIndex(), outpoint,
                    authoritative.getSignerPublicKey(), authoritative.getMessageHash(),
                    authoritative.getSighashType(), signature.getSignature()));
        }
        if(verified.size() != semantic.size()) {
            throw fail(STATE_INVALID, "Verified-signature evidence contains duplicate records");
        }
        return Collections.unmodifiableSet(verified);
    }


    public synchronized AntiExfilAbortJournal.AbortEvent recordPostRevealAbort(AbortReason reason) {
        if(reason == null || phase != Phase.OPENINGS_ACCEPTED) throw fail(WRONG_STAGE, "Only a live post-reveal exchange can end");
        try { history.end(context, reason.name(), false); return null; }
        finally { closeWithoutEvent(); }
    }
    public synchronized AntiExfilAbortJournal.AbortEvent recordSignerDataRejection() {
        if(state == null) return null; // A coordinator validation failure already recorded it.
        try { history.end(context, "SIGNATURE_REJECTED", true); return null; }
        finally { closeWithoutEvent(); }
    }
    public synchronized Status getStatus() {
        return new Status(phase, sessionId, psbtDigest, (int)Math.min(Integer.MAX_VALUE, history.counts().uncertain()), false);
    }
    private <T> T transition(java.util.function.Supplier<T> action) {
        try { return action.get(); }
        catch(RuntimeException failure) {
            try {
                if(state != null && (!(failure instanceof AntiExfilException ae) ||
                        (ae.getCode() != HISTORY_STORAGE_ERROR && ae.getCode() != VERSION_CONFLICT)))
                    history.end(context, failure instanceof AntiExfilException ae && isSignerDataRejection(ae) ? "SIGNATURE_REJECTED" : "TRANSPORT_FAILED", true);
            } catch(RuntimeException bookkeeping) { failure.addSuppressed(bookkeeping); }
            finally { closeWithoutEvent(); }
            throw failure;
        }
    }

    /** History is independent of mutable wallet labels, origin metadata and signer model. */
    public static byte[] getSigningKeyHistoryIdentity(Keystore keystore) {
        if(keystore == null || keystore.getExtendedPublicKey() == null) throw fail(STATE_INVALID, "Public account key is required");
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        bytes.writeBytes(keystore.getExtendedPublicKey().getKey().getPubKey());
        bytes.writeBytes(keystore.getExtendedPublicKey().getKey().getChainCode());
        return Sha256Hash.hash(bytes.toByteArray());
    }

    /** Legacy callers must use prepare() so migration and confirmation share the lease. */
    @Deprecated public static void preserveLegacyHistory(Path historyPath, Path legacyJournalPath, boolean present, Keystore keystore) {
        throw fail(STATE_INVALID, "Use prepared recovery with read-only V2 migration");
    }

    /** Best-effort wiping; JVM/OS copies are outside the non-retention guarantee. */
    @Override public synchronized void close() {
        try { if(state != null) history.end(context, "HOST_EXCHANGE_CLOSED", false); }
        finally { closeWithoutEvent(); }
    }
    private void closeWithoutEvent() {
        try {
            if(state != null) { wipe(state); state = null; }
            if(phase != Phase.COMPLETE) phase = Phase.CLOSED;
        } finally { lease.close(); }
    }
    private static void wipe(State state) {
        for(byte[] value : new byte[][]{state.originalPsbt, state.message1, state.message2, state.message3, state.message4, state.signedPsbt}) {
            if(value != null) Arrays.fill(value, (byte)0);
        }
        state.rhos.values().forEach(value -> Arrays.fill(value, (byte)0));
    }
    public static byte[] getWalletKeyIdentity(Keystore keystore) {
        if(keystore.getExtendedPublicKey() == null || keystore.getKeyDerivation() == null) throw fail(STATE_INVALID, "Public account keystore is required");
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        try {
            bytes.write(keystore.getExtendedPublicKey().getKey().getPubKey());
            bytes.write(keystore.getExtendedPublicKey().getKey().getChainCode());
            bytes.write(keystore.getKeyDerivation().toString().getBytes(StandardCharsets.US_ASCII));
        } catch(IOException impossible) {
            throw new AssertionError(impossible);
        }
        return Sha256Hash.hash(bytes.toByteArray());
    }

    private static byte[] random32(SecureRandom random) {
        byte[] value = new byte[32];
        random.nextBytes(value);
        return value;
    }

    private static boolean containsValue(Map<AntiExfilSigningSlot.Identifier, byte[]> values, byte[] candidate) {
        return values.values().stream().anyMatch(value -> Arrays.equals(value, candidate));
    }

    private static AntiExfilSigningSlot.Identifier identifier(AntiExfilSlot slot) {
        if(slot.getInputIndex() > Integer.MAX_VALUE) throw fail(SIGNATURE_SLOT_MISMATCH, "Input index is outside Java PSBT limits");
        return new AntiExfilSigningSlot.Identifier((int)slot.getInputIndex(), slot.getSignerPublicKey());
    }

    public static boolean isSignerDataRejection(AntiExfilException exception) {
        if(exception == null) return false;
        return switch(exception.getCode()) {
            case INVALID_MESSAGE, TRANSACTION_MISMATCH, SIGNATURE_SLOT_MISMATCH, COMMITMENT_MISMATCH,
                    OPENING_MISMATCH, SIGNATURE_INVALID, UNEXPECTED_RETURN_DATA -> true;
            case WRONG_STAGE, RETRY_CONFLICT, STATE_INVALID, SESSION_MISMATCH, ACCOUNT_EXCHANGE_BUSY,
                    HISTORY_STORAGE_ERROR, VERSION_CONFLICT, RECOVERY_APPROVAL_REQUIRED -> false;
        };
    }

    private static void invalidPhase() {
        throw fail(STATE_INVALID, "Coordinator phase and stored transcripts disagree");
    }

    private static AntiExfilException fail(AntiExfilException.Code code, String message) {
        return new AntiExfilException(code, message);
    }

    public enum Phase {
        COMMITMENTS_CREATED,
        OPENINGS_ACCEPTED,
        COMPLETE,
        CLOSED
    }

    public enum AbortReason {
        TRANSPORT_FAILED,
        SIGNER_CANCELLED,
        SIGNATURE_REJECTED,
        USER_ABANDONED
    }

    public static final class Completion {
        private final byte[] signedPsbt;
        private final Set<VerifiedAntiExfilSignature> verifiedSignatures;
        private final boolean broadcast;

        private Completion(byte[] signedPsbt, Set<VerifiedAntiExfilSignature> verifiedSignatures, boolean broadcast) {
            this.signedPsbt = signedPsbt.clone();
            this.verifiedSignatures = Set.copyOf(verifiedSignatures);
            this.broadcast = broadcast;
        }

        public byte[] getSignedPsbt() { return signedPsbt.clone(); }
        public Set<VerifiedAntiExfilSignature> getVerifiedSignatures() { return verifiedSignatures; }
        public boolean isBroadcast() { return broadcast; }
    }

    public static final class Status {
        private final Phase phase;
        private final byte[] sessionId;
        private final byte[] psbtDigest;
        private final int postRevealAbortCount;
        private final boolean broadcast;

        private Status(Phase phase, byte[] sessionId, byte[] psbtDigest, int postRevealAbortCount, boolean broadcast) {
            this.phase = phase;
            this.sessionId = sessionId.clone();
            this.psbtDigest = psbtDigest.clone();
            this.postRevealAbortCount = postRevealAbortCount;
            this.broadcast = broadcast;
        }

        public Phase getPhase() { return phase; }
        public byte[] getSessionId() { return sessionId.clone(); }
        public byte[] getPsbtDigest() { return psbtDigest.clone(); }
        public int getPostRevealAbortCount() { return postRevealAbortCount; }
        public boolean isBroadcast() { return broadcast; }
    }

    private record State(Phase phase, byte[] walletIdentity, byte[] originalPsbt, byte[] message1,
                         byte[] message2, byte[] message3, byte[] message4, byte[] signedPsbt,
                         Map<AntiExfilSigningSlot.Identifier, byte[]> rhos, byte[] abortJournalDigest) {
        private State {
            walletIdentity = walletIdentity.clone();
            originalPsbt = originalPsbt.clone();
            message1 = message1.clone();
            message2 = copy(message2);
            message3 = copy(message3);
            message4 = copy(message4);
            signedPsbt = copy(signedPsbt);
            abortJournalDigest = copy(abortJournalDigest);
            Map<AntiExfilSigningSlot.Identifier, byte[]> copied = new LinkedHashMap<>();
            rhos.forEach((identifier, rho) -> copied.put(identifier, rho.clone()));
            rhos = Map.copyOf(copied);
        }

        private static byte[] copy(byte[] value) { return value == null ? null : value.clone(); }
    }
}
