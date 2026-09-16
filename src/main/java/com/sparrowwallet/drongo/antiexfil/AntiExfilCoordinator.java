package com.sparrowwallet.drongo.antiexfil;

import com.sparrowwallet.drongo.protocol.Sha256Hash;
import com.sparrowwallet.drongo.psbt.PSBT;
import com.sparrowwallet.drongo.wallet.Keystore;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static com.sparrowwallet.drongo.antiexfil.AntiExfilException.Code.*;

public final class AntiExfilCoordinator {
    private static final byte[] MAGIC = {'A', 'E', 'X', 'S'};
    private static final int VERSION = 2;
    private static final int MAX_STATE_BYTES = 32 * 1024 * 1024;
    private static final int MAX_PSBT_BYTES = 16 * 1024 * 1024;
    private static final int MAX_BLOB_BYTES = 16 * 1024 * 1024;

    private final Path sessionPath;
    private final Path journalPath;
    private final Keystore keystore;
    private final byte[] walletIdentity;

    private AntiExfilCoordinator(Path sessionPath, Path journalPath, Keystore keystore) {
        if(sessionPath == null || journalPath == null || keystore == null) throw fail(STATE_INVALID, "Coordinator paths and keystore are required");
        this.sessionPath = AntiExfilDurableFiles.canonicalPath(sessionPath);
        this.journalPath = AntiExfilDurableFiles.canonicalPath(journalPath);
        if(this.sessionPath.equals(this.journalPath)) throw fail(STATE_INVALID, "Session and abort journal paths must be distinct");
        this.keystore = keystore;
        this.walletIdentity = walletIdentity(keystore);
    }

    public static AntiExfilCoordinator create(Path sessionPath, Path journalPath, byte[] originalPsbt,
                                               Keystore keystore, AntiExfilNetwork network) {
        return create(sessionPath, journalPath, originalPsbt, keystore, network, false, new SecureRandom());
    }

    public static AntiExfilCoordinator create(Path sessionPath, Path journalPath, byte[] originalPsbt,
                                               Keystore keystore, AntiExfilNetwork network,
                                               boolean acknowledgePostRevealAbortRisk) {
        return create(sessionPath, journalPath, originalPsbt, keystore, network,
                acknowledgePostRevealAbortRisk, new SecureRandom());
    }

    static AntiExfilCoordinator create(Path sessionPath, Path journalPath, byte[] originalPsbt,
                                        Keystore keystore, AntiExfilNetwork network,
                                        boolean acknowledgePostRevealAbortRisk, SecureRandom random) {
        if(keystore == null || !keystore.supportsAntiExfil()) {
            throw fail(STATE_INVALID, "Keystore does not support anti-exfil signing");
        }
        AntiExfilCoordinator coordinator = new AntiExfilCoordinator(sessionPath, journalPath, keystore);
        if(originalPsbt == null || originalPsbt.length > MAX_PSBT_BYTES || network == null || random == null) {
            throw fail(INVALID_MESSAGE, "Invalid coordinator initialization");
        }
        List<AntiExfilSigningSlot> slots = AntiExfilPsbt.enumerateSigningSlots(originalPsbt, keystore);
        byte[] sessionId = random32(random);
        Map<AntiExfilSigningSlot.Identifier, byte[]> rhos = new LinkedHashMap<>();
        for(AntiExfilSigningSlot slot : slots) {
            byte[] rho;
            int attempts = 0;
            do {
                if(attempts++ >= 1024) throw fail(STATE_INVALID, "CSPRNG repeatedly produced duplicate host randomness");
                rho = random32(random);
            } while(containsValue(rhos, rho));
            rhos.put(slot.getIdentifier(), rho);
        }
        AntiExfilMessage commit = AntiExfilPsbt.buildHostCommitMessage(originalPsbt, keystore, network, sessionId, rhos);
        coordinator.abortJournal().locked(journal -> {
            if(!journal.getEvents().isEmpty() && !acknowledgePostRevealAbortRisk) {
                throw fail(RETRY_CONFLICT, "Post-reveal abort history requires explicit high-severity acknowledgement before a fresh session");
            }
            State state = new State(Phase.COMMITMENTS_CREATED, coordinator.walletIdentity, originalPsbt,
                    AntiExfilCodec.encode(commit), null, null, null, null, rhos, journal.getDigest());
            return AntiExfilDurableFiles.locked(coordinator.sessionPath, () -> {
                AntiExfilDurableFiles.write(coordinator.sessionPath, encode(state), true, MAX_STATE_BYTES);
                return null;
            });
        });
        return coordinator;
    }

    public static AntiExfilCoordinator load(Path sessionPath, Path journalPath, Keystore keystore) {
        AntiExfilCoordinator coordinator = new AntiExfilCoordinator(sessionPath, journalPath, keystore);
        coordinator.readValidatedState();
        new AntiExfilAbortJournal(journalPath, coordinator.walletIdentity).getEvents();
        return coordinator;
    }

    public byte[] getHostCommitMessage() {
        return readValidatedState().message1.clone();
    }

    public byte[] getFrozenPsbt() {
        return readValidatedState().originalPsbt.clone();
    }

    public byte[] getHostRevealMessage() {
        State state = readValidatedState();
        if(state.phase == Phase.COMMITMENTS_CREATED) throw fail(WRONG_STAGE, "Signer openings have not been accepted");
        return state.message3.clone();
    }

    public Completion getCompletedResult() {
        State state = readValidatedState();
        if(state.phase != Phase.COMPLETE) throw fail(WRONG_STAGE, "Coordinator session is not complete");
        return completion(state);
    }

    public byte[] acceptOpenings(byte[] encodedOpenings) {
        if(encodedOpenings == null) throw fail(INVALID_MESSAGE, "Signer openings are required");
        return abortJournal().locked(journal -> AntiExfilDurableFiles.locked(sessionPath, () -> {
            State state = readValidatedStateUnlocked();
            if(state.phase == Phase.COMPLETE || state.phase == Phase.OPENINGS_ACCEPTED) {
                if(!Arrays.equals(encodedOpenings, state.message2)) throw fail(RETRY_CONFLICT, "Retry changed accepted signer openings");
                return state.message3.clone();
            }
            AntiExfilMessage commit = AntiExfilCodec.decode(state.message1);
            if(state.abortJournalDigest == null || !Arrays.equals(state.abortJournalDigest, journal.getDigest())) {
                throw fail(RETRY_CONFLICT, "Abort history changed after session creation; start a newly acknowledged session");
            }
            byte[] message3;
            try {
                AntiExfilMessage openings = AntiExfilCodec.decode(encodedOpenings);
                if(openings.getStage() != AntiExfilStage.SIGNER_OPENINGS) throw fail(WRONG_STAGE, "Expected signer openings");
                AntiExfilCodec.validateTransition(commit, openings);
                List<AntiExfilSlot> revealSlots = new ArrayList<>(openings.getSlots().size());
                for(AntiExfilSlot slot : openings.getSlots()) {
                    AntiExfilSigningSlot.Identifier identifier = identifier(slot);
                    byte[] rho = state.rhos.get(identifier);
                    if(rho == null) throw fail(SIGNATURE_SLOT_MISMATCH, "Opening has no authoritative host-randomness slot");
                    revealSlots.add(new AntiExfilSlot(slot.getInputIndex(), slot.getSighashType(), slot.getSignerPublicKey(),
                            slot.getMessageHash(), slot.getCommitment(), slot.getOpening(), rho, null));
                }
                AntiExfilMessage reveal = new AntiExfilMessage(openings.getNetwork(), AntiExfilStage.HOST_REVEAL,
                        openings.getSessionId(), openings.getPsbtDigest(), revealSlots);
                AntiExfilCodec.validateTransition(openings, reveal);
                message3 = AntiExfilCodec.encode(reveal);
            } catch(AntiExfilException e) {
                if(isSignerDataRejection(e)) {
                    journal.append(commit.getSessionId(), commit.getPsbtDigest(), AbortReason.SIGNATURE_REJECTED.name());
                }
                throw e;
            }
            State accepted = new State(Phase.OPENINGS_ACCEPTED, state.walletIdentity, state.originalPsbt,
                    state.message1, encodedOpenings, message3, null, null, state.rhos, state.abortJournalDigest);
            // This durable write is the security boundary: no rho is returned before it succeeds.
            AntiExfilDurableFiles.write(sessionPath, encode(accepted), false, MAX_STATE_BYTES);
            return message3.clone();
        }));
    }

    public Completion complete(byte[] encodedSignatures) {
        if(encodedSignatures == null) throw fail(INVALID_MESSAGE, "Signer signatures are required");
        return abortJournal().locked(journal -> AntiExfilDurableFiles.locked(sessionPath, () -> {
            State state = readValidatedStateUnlocked();
            if(state.phase == Phase.COMMITMENTS_CREATED) throw fail(WRONG_STAGE, "Cannot complete before accepting openings");
            if(state.phase == Phase.COMPLETE) {
                if(!Arrays.equals(encodedSignatures, state.message4)) throw fail(RETRY_CONFLICT, "Completed session received different signatures");
                return completion(state);
            }
            AntiExfilMessage reveal = AntiExfilCodec.decode(state.message3);
            byte[] signed;
            try {
                AntiExfilMessage signatures = AntiExfilCodec.decode(encodedSignatures);
                if(signatures.getStage() != AntiExfilStage.SIGNER_SIGNATURES) throw fail(WRONG_STAGE, "Expected signer signatures");
                AntiExfilCodec.validateTransition(reveal, signatures);
                signed = AntiExfilPsbt.reconstructSignedPsbt(state.originalPsbt, keystore,
                        AntiExfilCodec.decode(state.message1), AntiExfilCodec.decode(state.message2), reveal,
                        signatures, state.rhos);
            } catch(AntiExfilException e) {
                if(isSignerDataRejection(e)) {
                    AntiExfilMessage commit = AntiExfilCodec.decode(state.message1);
                    journal.append(commit.getSessionId(), commit.getPsbtDigest(), AbortReason.SIGNATURE_REJECTED.name());
                }
                throw e;
            }
            State complete = new State(Phase.COMPLETE, state.walletIdentity, state.originalPsbt,
                    state.message1, state.message2, state.message3, encodedSignatures, signed, state.rhos,
                    state.abortJournalDigest);
            AntiExfilDurableFiles.write(sessionPath, encode(complete), false, MAX_STATE_BYTES);
            return completion(complete);
        }));
    }

    private Completion completion(State state) {
        return new Completion(state.signedPsbt, deriveVerifiedSignatures(state), false);
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

    public AntiExfilAbortJournal.AbortEvent recordPostRevealAbort(AbortReason reason) {
        if(reason == null) throw fail(STATE_INVALID, "A post-reveal abort reason is required");
        return abortJournal().locked(journal -> AntiExfilDurableFiles.locked(sessionPath, () -> {
            State state = readValidatedStateUnlocked();
            if(state.phase != Phase.OPENINGS_ACCEPTED) {
                throw fail(WRONG_STAGE, "Only an incomplete post-reveal session can record a selective-abort event");
            }
            AntiExfilMessage commit = AntiExfilCodec.decode(state.message1);
            return journal.append(commit.getSessionId(), commit.getPsbtDigest(), reason.name());
        }));
    }

    public AntiExfilAbortJournal.AbortEvent recordSignerDataRejection() {
        return abortJournal().locked(journal -> AntiExfilDurableFiles.locked(sessionPath, () -> {
            State state = readValidatedStateUnlocked();
            if(state.phase == Phase.COMPLETE) {
                throw fail(WRONG_STAGE, "A completed session cannot record a signer-data rejection");
            }
            AntiExfilMessage commit = AntiExfilCodec.decode(state.message1);
            return journal.append(commit.getSessionId(), commit.getPsbtDigest(), AbortReason.SIGNATURE_REJECTED.name());
        }));
    }

    public Status getStatus() {
        State state = readValidatedState();
        AntiExfilMessage commit = AntiExfilCodec.decode(state.message1);
        int abortCount = new AntiExfilAbortJournal(journalPath, walletIdentity).getEvents().size();
        return new Status(state.phase, commit.getSessionId(), commit.getPsbtDigest(), abortCount, false);
    }

    private State readValidatedState() {
        // An absent session is a pure validation failure. Check before acquiring the
        // durable lock because opening the lock sidecar necessarily creates it.
        if(!Files.exists(sessionPath)) {
            throw fail(STATE_INVALID, "Cannot access durable anti-exfil state: Coordinator session does not exist");
        }
        return AntiExfilDurableFiles.locked(sessionPath, this::readValidatedStateUnlocked);
    }

    private AntiExfilAbortJournal abortJournal() {
        return new AntiExfilAbortJournal(journalPath, walletIdentity);
    }

    private State readValidatedStateUnlocked() throws IOException {
        if(!Files.exists(sessionPath)) throw new IOException("Coordinator session does not exist");
        State state = decode(AntiExfilDurableFiles.read(sessionPath, MAX_STATE_BYTES));
        validateState(state);
        return state;
    }

    private void validateState(State state) {
        if(!Arrays.equals(walletIdentity, state.walletIdentity)) throw fail(STATE_INVALID, "Coordinator session belongs to another wallet key identity");
        List<AntiExfilSigningSlot> slots = AntiExfilPsbt.enumerateSigningSlots(state.originalPsbt, keystore);
        AntiExfilMessage commit = AntiExfilCodec.decode(state.message1);
        AntiExfilMessage rebuilt = AntiExfilPsbt.buildHostCommitMessage(state.originalPsbt, keystore,
                commit.getNetwork(), commit.getSessionId(), state.rhos);
        if(!Arrays.equals(state.message1, AntiExfilCodec.encode(rebuilt))) throw fail(STATE_INVALID, "Stored commitment transcript is not authoritative");
        if(state.rhos.size() != slots.size()) throw fail(STATE_INVALID, "Stored host-randomness set changed");
        if(state.phase == Phase.COMMITMENTS_CREATED) {
            if(state.message2 != null || state.message3 != null || state.message4 != null || state.signedPsbt != null) invalidPhase();
            return;
        }
        if(state.message2 == null || state.message3 == null) invalidPhase();
        AntiExfilMessage openings = AntiExfilCodec.decode(state.message2);
        AntiExfilMessage reveal = AntiExfilCodec.decode(state.message3);
        AntiExfilCodec.validateTransition(commit, openings);
        AntiExfilCodec.validateTransition(openings, reveal);
        for(AntiExfilSlot slot : reveal.getSlots()) {
            byte[] expected = state.rhos.get(identifier(slot));
            if(expected == null || !Arrays.equals(expected, slot.getHostRandomness())) throw fail(STATE_INVALID, "Stored reveal differs from durable randomness");
        }
        if(state.phase == Phase.OPENINGS_ACCEPTED) {
            if(state.message4 != null || state.signedPsbt != null) invalidPhase();
            return;
        }
        if(state.message4 == null || state.signedPsbt == null) invalidPhase();
        AntiExfilMessage signatures = AntiExfilCodec.decode(state.message4);
        AntiExfilCodec.validateTransition(reveal, signatures);
        byte[] rebuiltSigned = AntiExfilPsbt.reconstructSignedPsbt(state.originalPsbt, keystore,
                commit, openings, reveal, signatures, state.rhos);
        if(!Arrays.equals(rebuiltSigned, state.signedPsbt)) throw fail(STATE_INVALID, "Stored signed PSBT is not reconstructible from verified signatures");
    }

    private static byte[] walletIdentity(Keystore keystore) {
        return getWalletKeyIdentity(keystore);
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

    private static byte[] encode(State state) throws IOException {
        int expectedFileLength = checkedStateFileLength(state.originalPsbt.length, state.message1.length,
                nullableLength(state.message2), nullableLength(state.message3),
                nullableLength(state.message4), nullableLength(state.signedPsbt),
                nullableLength(state.abortJournalDigest), state.rhos.size(), MAX_STATE_BYTES);
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        try(DataOutputStream output = new DataOutputStream(bytes)) {
            output.write(MAGIC);
            output.writeByte(VERSION);
            output.writeByte(state.phase.ordinal());
            output.write(state.walletIdentity);
            writeBlob(output, state.originalPsbt);
            writeBlob(output, state.message1);
            writeNullableBlob(output, state.message2);
            writeNullableBlob(output, state.message3);
            writeNullableBlob(output, state.message4);
            writeNullableBlob(output, state.signedPsbt);
            writeNullableBlob(output, state.abortJournalDigest);
            output.writeShort(state.rhos.size());
            for(Map.Entry<AntiExfilSigningSlot.Identifier, byte[]> entry : state.rhos.entrySet()) {
                output.writeInt(entry.getKey().getInputIndex());
                output.write(entry.getKey().getSignerPublicKey());
                output.write(entry.getValue());
            }
        }
        byte[] body = bytes.toByteArray();
        if(body.length != expectedFileLength - 32) {
            throw new IOException("Encoded coordinator state length disagrees with its bounded schema");
        }
        return body;
    }

    static int checkedStateFileLength(int originalPsbtLength, int message1Length,
                                      int message2Length, int message3Length, int message4Length,
                                      int signedPsbtLength, int abortJournalDigestLength,
                                      int rhoCount, int maximumFileBytes) throws IOException {
        requireStoredLength(originalPsbtLength, MAX_PSBT_BYTES, false, "original PSBT");
        requireStoredLength(message1Length, AntiExfilCodec.MAX_MESSAGE_BYTES, false, "message 1");
        requireStoredLength(message2Length, AntiExfilCodec.MAX_MESSAGE_BYTES, true, "message 2");
        requireStoredLength(message3Length, AntiExfilCodec.MAX_MESSAGE_BYTES, true, "message 3");
        requireStoredLength(message4Length, AntiExfilCodec.MAX_MESSAGE_BYTES, true, "message 4");
        requireStoredLength(signedPsbtLength, MAX_BLOB_BYTES, true, "signed PSBT");
        if(abortJournalDigestLength != -1 && abortJournalDigestLength != 32) {
            throw new IOException("Stored abort-journal digest length is outside limits");
        }
        if(rhoCount < 1 || rhoCount > AntiExfilCodec.MAX_SLOTS) {
            throw new IOException("Stored host-randomness count is outside limits");
        }

        long valueBytes = positiveLength(originalPsbtLength) + positiveLength(message1Length)
                + positiveLength(message2Length) + positiveLength(message3Length)
                + positiveLength(message4Length) + positiveLength(signedPsbtLength)
                + positiveLength(abortJournalDigestLength);
        // Fixed state header, seven four-byte blob lengths, rho count, checksum, and 69 bytes per rho.
        long fileBytes = 100L + valueBytes + (69L * rhoCount);
        if(maximumFileBytes < 32 || fileBytes > maximumFileBytes) {
            throw new IOException("Encoded coordinator state exceeds the durable file limit");
        }
        return Math.toIntExact(fileBytes);
    }

    private static void requireStoredLength(int length, int maximum, boolean nullable, String name)
            throws IOException {
        if((nullable && length == -1) || (length >= 1 && length <= maximum)) return;
        throw new IOException("Stored " + name + " length is outside limits");
    }

    private static int nullableLength(byte[] value) {
        return value == null ? -1 : value.length;
    }

    private static long positiveLength(int length) {
        return length < 0 ? 0L : length;
    }

    private static State decode(byte[] body) throws IOException {
        try(DataInputStream input = new DataInputStream(new ByteArrayInputStream(body))) {
            if(!Arrays.equals(input.readNBytes(4), MAGIC)) throw new IOException("Unknown coordinator-state format");
            int version = input.readUnsignedByte();
            if(version < 1 || version > VERSION) throw new IOException("Unknown coordinator-state format");
            int phaseCode = input.readUnsignedByte();
            if(phaseCode >= Phase.values().length) throw new IOException("Unknown coordinator phase");
            byte[] identity = input.readNBytes(32);
            byte[] original = readBlob(input, MAX_PSBT_BYTES, false);
            byte[] message1 = readBlob(input, AntiExfilCodec.MAX_MESSAGE_BYTES, false);
            byte[] message2 = readBlob(input, AntiExfilCodec.MAX_MESSAGE_BYTES, true);
            byte[] message3 = readBlob(input, AntiExfilCodec.MAX_MESSAGE_BYTES, true);
            byte[] message4 = readBlob(input, AntiExfilCodec.MAX_MESSAGE_BYTES, true);
            byte[] signed = readBlob(input, MAX_BLOB_BYTES, true);
            byte[] abortJournalDigest = version >= 2 ? readBlob(input, 32, true) : null;
            int count = input.readUnsignedShort();
            if(identity.length != 32 || (abortJournalDigest != null && abortJournalDigest.length != 32)
                    || count < 1 || count > AntiExfilCodec.MAX_SLOTS) throw new IOException("Invalid coordinator-state header");
            Map<AntiExfilSigningSlot.Identifier, byte[]> rhos = new LinkedHashMap<>();
            for(int i = 0; i < count; i++) {
                int index = input.readInt();
                byte[] key = input.readNBytes(33);
                byte[] rho = input.readNBytes(32);
                if(key.length != 33 || rho.length != 32 || rhos.put(new AntiExfilSigningSlot.Identifier(index, key), rho) != null) {
                    throw new IOException("Invalid or duplicate coordinator randomness record");
                }
            }
            if(input.available() != 0) throw new IOException("Trailing coordinator-state data");
            return new State(Phase.values()[phaseCode], identity, original, message1, message2, message3,
                    message4, signed, rhos, abortJournalDigest);
        } catch(EOFException e) {
            throw new IOException("Truncated coordinator state", e);
        }
    }

    private static void writeBlob(DataOutputStream output, byte[] value) throws IOException {
        output.writeInt(value.length);
        output.write(value);
    }

    private static void writeNullableBlob(DataOutputStream output, byte[] value) throws IOException {
        if(value == null) output.writeInt(-1); else writeBlob(output, value);
    }

    private static byte[] readBlob(DataInputStream input, int maximum, boolean nullable) throws IOException {
        int length = input.readInt();
        if(nullable && length == -1) return null;
        if(length < 1 || length > maximum) throw new IOException("Stored blob length is outside limits");
        byte[] value = input.readNBytes(length);
        if(value.length != length) throw new IOException("Truncated stored blob");
        return value;
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
                    OPENING_MISMATCH, SIGNATURE_INVALID, UNEXPECTED_RETURN_DATA, SESSION_MISMATCH -> true;
            case WRONG_STAGE, RETRY_CONFLICT, STATE_INVALID -> false;
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
        COMPLETE
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
