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
    private final Path journalPath;
    private final Keystore keystore;
    private final byte[] walletIdentity;
    private State state;
    private Completion completed;
    private Phase phase = Phase.COMMITMENTS_CREATED;
    private byte[] sessionId;
    private byte[] psbtDigest;

    private AntiExfilCoordinator(Path journalPath, Keystore keystore) {
        if(journalPath == null || keystore == null) throw fail(STATE_INVALID, "Journal and keystore are required");
        this.journalPath = AntiExfilDurableFiles.canonicalPath(journalPath);
        this.keystore = keystore;
        this.walletIdentity = getWalletKeyIdentity(keystore);
    }

    public static AntiExfilCoordinator create(Path ignoredSessionPath, Path journalPath, byte[] originalPsbt,
                                               Keystore keystore, AntiExfilNetwork network) {
        return create(ignoredSessionPath, journalPath, originalPsbt, keystore, network, false, new SecureRandom());
    }

    /** Legacy signature retained for source compatibility. Acknowledgement cannot override uncertainty. */
    public static AntiExfilCoordinator create(Path ignoredSessionPath, Path journalPath, byte[] originalPsbt,
                                               Keystore keystore, AntiExfilNetwork network, boolean ignoredAcknowledgement) {
        return create(ignoredSessionPath, journalPath, originalPsbt, keystore, network, ignoredAcknowledgement, new SecureRandom());
    }

    static AntiExfilCoordinator create(Path ignoredSessionPath, Path journalPath, byte[] originalPsbt,
                                        Keystore keystore, AntiExfilNetwork network, boolean ignoredAcknowledgement, SecureRandom random) {
        if(keystore == null || !keystore.supportsAntiExfil()) throw fail(STATE_INVALID, "Keystore does not support anti-exfil signing");
        if(originalPsbt == null || originalPsbt.length > MAX_PSBT_BYTES || network == null || random == null) {
            throw fail(INVALID_MESSAGE, "Invalid coordinator initialization");
        }
        // Reject invalid PSBT semantics/signatures before any durable journal is created.
        List<AntiExfilSigningSlot> slots = AntiExfilPsbt.enumerateSigningSlots(originalPsbt, keystore);
        AntiExfilCoordinator coordinator = new AntiExfilCoordinator(journalPath, keystore);
        return coordinator.abortJournal().locked(journal -> {
            journal.requireFreshAttempt();
            byte[] id = random32(random);
            Map<AntiExfilSigningSlot.Identifier, byte[]> rhos = new LinkedHashMap<>();
            try {
                for(AntiExfilSigningSlot slot : slots) {
                    byte[] rho;
                    int attempts = 0;
                    do {
                        if(attempts++ >= 1024) throw fail(STATE_INVALID, "CSPRNG repeatedly produced duplicate host randomness");
                        rho = random32(random);
                    } while(containsValue(rhos, rho));
                    rhos.put(slot.getIdentifier(), rho);
                }
                AntiExfilMessage commit = AntiExfilPsbt.buildHostCommitMessage(originalPsbt, keystore, network, id, rhos);
                coordinator.state = new State(Phase.COMMITMENTS_CREATED, coordinator.walletIdentity, originalPsbt,
                        AntiExfilCodec.encode(commit), null, null, null, null, rhos, null);
                coordinator.sessionId = id.clone();
                coordinator.psbtDigest = commit.getPsbtDigest();
                return coordinator;
            } finally {
                rhos.values().forEach(rho -> Arrays.fill(rho, (byte)0));
            }
        });
    }

    /** Never opens or replays legacy secret-bearing session files. */
    public static AntiExfilCoordinator load(Path ignoredSessionPath, Path ignoredJournalPath, Keystore ignoredKeystore) {
        throw fail(STATE_INVALID, "Anti-exfil sessions are RAM-only and cannot be restored after host restart");
    }

    private State active() {
        if(state == null) throw fail(STATE_INVALID, "Active anti-exfil host state is no longer available");
        return state;
    }
    public synchronized byte[] getHostCommitMessage() { return active().message1.clone(); }
    public synchronized byte[] getFrozenPsbt() { return active().originalPsbt.clone(); }
    public synchronized byte[] getHostRevealMessage() {
        State state = active();
        if(state.phase != Phase.OPENINGS_ACCEPTED) throw fail(WRONG_STAGE, "Signer openings have not been accepted");
        return state.message3.clone();
    }
    public synchronized Completion getCompletedResult() {
        if(completed == null) throw fail(WRONG_STAGE, "Coordinator session is not complete");
        return completed;
    }

    public synchronized byte[] acceptOpenings(byte[] encodedOpenings) {
        if(encodedOpenings == null) throw fail(INVALID_MESSAGE, "Signer openings are required");
        State current = active();
        return abortJournal().locked(journal -> {
            if(current.phase == Phase.OPENINGS_ACCEPTED) {
                journal.requirePending(sessionId, psbtDigest);
                if(!Arrays.equals(encodedOpenings, current.message2)) throw fail(RETRY_CONFLICT, "Retry changed accepted signer openings");
                return current.message3.clone();
            }
            journal.requireFreshAttempt();
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
            journal.beginReveal(sessionId, psbtDigest);
            state = new State(Phase.OPENINGS_ACCEPTED, walletIdentity, current.originalPsbt,
                    current.message1, encodedOpenings, message3, null, null, current.rhos, null);
            phase = Phase.OPENINGS_ACCEPTED;
            wipe(current);
            return message3;
        });
    }

    public synchronized Completion complete(byte[] encodedSignatures) {
        if(encodedSignatures == null) throw fail(INVALID_MESSAGE, "Signer signatures are required");
        State current = active();
        if(current.phase != Phase.OPENINGS_ACCEPTED) throw fail(WRONG_STAGE, "Cannot complete before accepting openings");
        return abortJournal().locked(journal -> {
            journal.requirePending(sessionId, psbtDigest);
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
                journal.resolveReveal(sessionId, psbtDigest);
                completed = result;
                phase = Phase.COMPLETE;
                wipe(current);
                state = null;
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
        if(reason == null || phase != Phase.OPENINGS_ACCEPTED) throw fail(WRONG_STAGE, "Only an active post-reveal session can be abandoned");
        try { return abortJournal().locked(journal -> journal.noteUnresolved(sessionId, psbtDigest, reason.name())); }
        finally { close(); }
    }

    public synchronized AntiExfilAbortJournal.AbortEvent recordSignerDataRejection() {
        active();
        try {
            return abortJournal().locked(journal -> phase == Phase.OPENINGS_ACCEPTED
                    ? journal.noteUnresolved(sessionId, psbtDigest, AbortReason.SIGNATURE_REJECTED.name())
                    : journal.append(sessionId, psbtDigest, "PRE_REVEAL_REJECTED"));
        } finally { close(); }
    }

    public synchronized Status getStatus() {
        return new Status(phase, sessionId, psbtDigest, abortJournal().getEvents().size(), false);
    }

    private AntiExfilAbortJournal abortJournal() { return new AntiExfilAbortJournal(journalPath, getSigningKeyHistoryIdentity(keystore)); }

    /** History is independent of mutable wallet labels, origin metadata and signer model. */
    public static byte[] getSigningKeyHistoryIdentity(Keystore keystore) {
        if(keystore == null || keystore.getExtendedPublicKey() == null) throw fail(STATE_INVALID, "Public account key is required");
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        bytes.writeBytes(keystore.getExtendedPublicKey().getKey().getPubKey());
        bytes.writeBytes(keystore.getExtendedPublicKey().getKey().getChainCode());
        return Sha256Hash.hash(bytes.toByteArray());
    }

    /** Preserve known legacy history without opening a rho-bearing session file or resetting the old journal. */
    public static void preserveLegacyHistory(Path historyPath, Path legacyJournalPath, boolean legacySessionPresent, Keystore keystore) {
        byte[] oldIdentity = getWalletKeyIdentity(keystore);
        AntiExfilAbortJournal history = new AntiExfilAbortJournal(historyPath, getSigningKeyHistoryIdentity(keystore));
        history.locked(journal -> {
            boolean legacyAbort = Files.exists(legacyJournalPath)
                    && !new AntiExfilAbortJournal(legacyJournalPath, oldIdentity).getEvents().isEmpty();
            if(legacySessionPresent || legacyAbort) {
                // The old journal/session is retained at its original path. This nonsecret reference
                // makes the conservative refusal follow the actual account even if origin metadata changes.
                journal.append(Sha256Hash.hash(oldIdentity), oldIdentity, "LEGACY_ACCOUNT_HISTORY");
            }
            return null;
        });
    }

    /** Best-effort wiping of owned arrays, not a promise to erase JVM/OS copies. */
    @Override public synchronized void close() {
        if(state != null) { wipe(state); state = null; }
        if(phase != Phase.COMPLETE) phase = Phase.CLOSED;
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
            case WRONG_STAGE, RETRY_CONFLICT, STATE_INVALID, SESSION_MISMATCH -> false;
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
