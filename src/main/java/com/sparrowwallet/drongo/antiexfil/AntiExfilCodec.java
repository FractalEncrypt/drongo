package com.sparrowwallet.drongo.antiexfil;

import com.sparrowwallet.drongo.crypto.ECKey;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static com.sparrowwallet.drongo.antiexfil.AntiExfilException.Code.*;

public final class AntiExfilCodec {
    private static final byte[] WIRE_MAGIC = {'A', 'E', 'X', 'B'};
    /** @deprecated Use the codec rather than mutable framing bytes. Kept only for source compatibility. */
    @Deprecated
    public static final byte[] MAGIC = WIRE_MAGIC.clone();
    public static final int FORMAT_VERSION = 1;
    public static final long SIGHASH_ALL = 1;
    public static final int MAX_SLOTS = 128;
    public static final int MAX_SLOTS_PER_INPUT = 16;
    public static final int MAX_MESSAGE_BYTES = 65_536;
    public static final int HEADER_LENGTH = 78;
    public static final int COMMON_RECORD_LENGTH = 105;

    private AntiExfilCodec() {
    }

    public static byte[] encode(AntiExfilMessage message) {
        validate(message);
        int payloadLength = Math.multiplyExact(message.getSlots().size(), message.getStage().getRecordLength());
        ByteBuffer buffer = ByteBuffer.allocate(HEADER_LENGTH + payloadLength);
        buffer.put(WIRE_MAGIC).put((byte)FORMAT_VERSION).put((byte)message.getNetwork().getCode())
                .put((byte)message.getStage().getCode()).put((byte)0).putInt(payloadLength)
                .put(message.getSessionId()).put(message.getPsbtDigest()).putShort((short)message.getSlots().size());
        for(AntiExfilSlot slot : message.getSlots()) {
            buffer.putInt((int)slot.getInputIndex()).putInt((int)slot.getSighashType())
                    .put(slot.getSignerPublicKey()).put(slot.getMessageHash()).put(slot.getCommitment());
            if(message.getStage().getCode() >= AntiExfilStage.SIGNER_OPENINGS.getCode()) buffer.put(slot.getOpening());
            if(message.getStage() == AntiExfilStage.HOST_REVEAL) buffer.put(slot.getHostRandomness());
            if(message.getStage() == AntiExfilStage.SIGNER_SIGNATURES) buffer.put(slot.getSignature());
        }
        return buffer.array();
    }

    public static AntiExfilMessage decode(byte[] encoded) {
        if(encoded == null || encoded.length < HEADER_LENGTH || encoded.length > MAX_MESSAGE_BYTES) {
            throw fail(INVALID_MESSAGE, "AEXB message length is outside v1 limits");
        }
        ByteBuffer buffer = ByteBuffer.wrap(encoded);
        byte[] magic = new byte[4];
        buffer.get(magic);
        if(!Arrays.equals(magic, WIRE_MAGIC)) throw fail(INVALID_MESSAGE, "Wrong AEXB magic");
        if(Byte.toUnsignedInt(buffer.get()) != FORMAT_VERSION) throw fail(INVALID_MESSAGE, "Unsupported AEXB version");
        AntiExfilNetwork network = AntiExfilNetwork.fromCode(Byte.toUnsignedInt(buffer.get()));
        AntiExfilStage stage = AntiExfilStage.fromCode(Byte.toUnsignedInt(buffer.get()));
        if(buffer.get() != 0) throw fail(INVALID_MESSAGE, "Unknown AEXB flags are set");
        long payloadLength = Integer.toUnsignedLong(buffer.getInt());
        byte[] sessionId = new byte[32];
        byte[] psbtDigest = new byte[32];
        buffer.get(sessionId).get(psbtDigest);
        int slotCount = Short.toUnsignedInt(buffer.getShort());
        if(slotCount < 1 || slotCount > MAX_SLOTS) throw fail(INVALID_MESSAGE, "AEXB slot count is outside v1 limits");
        long expectedPayload = (long)slotCount * stage.getRecordLength();
        if(payloadLength != expectedPayload || encoded.length != HEADER_LENGTH + expectedPayload) {
            throw fail(INVALID_MESSAGE, "AEXB payload length is not canonical for its stage");
        }
        List<AntiExfilSlot> slots = new ArrayList<>(slotCount);
        for(int i = 0; i < slotCount; i++) {
            long inputIndex = Integer.toUnsignedLong(buffer.getInt());
            long sighash = Integer.toUnsignedLong(buffer.getInt());
            byte[] publicKey = read(buffer, 33);
            byte[] messageHash = read(buffer, 32);
            byte[] commitment = read(buffer, 32);
            byte[] opening = stage.getCode() >= AntiExfilStage.SIGNER_OPENINGS.getCode() ? read(buffer, 33) : null;
            byte[] rho = stage == AntiExfilStage.HOST_REVEAL ? read(buffer, 32) : null;
            byte[] signature = stage == AntiExfilStage.SIGNER_SIGNATURES ? read(buffer, 64) : null;
            slots.add(new AntiExfilSlot(inputIndex, sighash, publicKey, messageHash, commitment, opening, rho, signature));
        }
        AntiExfilMessage message = new AntiExfilMessage(network, stage, sessionId, psbtDigest, slots);
        validate(message);
        return message;
    }

    public static void validateTransition(AntiExfilMessage previous, AntiExfilMessage current) {
        // This is a public object-form boundary: callers are not required to have
        // obtained either endpoint through decode(), so validate both in full.
        validate(previous);
        validate(current);
        if(current.getStage().getCode() != previous.getStage().getCode() + 1) throw fail(WRONG_STAGE, "Stages are not adjacent");
        if(!Arrays.equals(previous.getSessionId(), current.getSessionId())) {
            throw fail(SESSION_MISMATCH, "Session identity changed between stages");
        }
        if(previous.getNetwork() != current.getNetwork()
                || !Arrays.equals(previous.getPsbtDigest(), current.getPsbtDigest())) {
            throw fail(TRANSACTION_MISMATCH, "Transcript context changed between stages");
        }
        if(previous.getSlots().size() != current.getSlots().size()) throw fail(SIGNATURE_SLOT_MISMATCH, "Slot count changed");
        for(int i = 0; i < previous.getSlots().size(); i++) {
            AntiExfilSlot before = previous.getSlots().get(i);
            AntiExfilSlot after = current.getSlots().get(i);
            if(before.getInputIndex() != after.getInputIndex()
                    || before.getSighashType() != after.getSighashType()
                    || !Arrays.equals(before.getSignerPublicKey(), after.getSignerPublicKey())
                    || !Arrays.equals(before.getMessageHash(), after.getMessageHash())) {
                throw fail(SIGNATURE_SLOT_MISMATCH, "Slot identity or signing context changed");
            }
            if(!Arrays.equals(before.getCommitment(), after.getCommitment())) throw fail(COMMITMENT_MISMATCH, "Commitment changed");
            if(previous.getStage().getCode() >= AntiExfilStage.SIGNER_OPENINGS.getCode()
                    && !Arrays.equals(before.getOpening(), after.getOpening())) throw fail(OPENING_MISMATCH, "Accepted opening changed");
            if(current.getStage() == AntiExfilStage.HOST_REVEAL
                    && !Arrays.equals(AntiExfilCrypto.hostCommit(after.getHostRandomness()), after.getCommitment())) {
                throw fail(COMMITMENT_MISMATCH, "Host reveal does not match commitment");
            }
        }
    }

    public static void validate(AntiExfilMessage message) {
        if(message == null || message.getNetwork() == null || message.getStage() == null
                || length(message.getSessionId()) != 32 || length(message.getPsbtDigest()) != 32
                || message.getSlots() == null || message.getSlots().isEmpty() || message.getSlots().size() > MAX_SLOTS) {
            throw fail(INVALID_MESSAGE, "Invalid AEXB message header");
        }
        Set<Bytes> commitments = new HashSet<>();
        Set<Bytes> reveals = new HashSet<>();
        Map<Bytes, Set<Bytes>> openingsBySigner = new HashMap<>();
        long previousInput = -1;
        byte[] previousKey = null;
        int perInput = 0;
        for(AntiExfilSlot slot : message.getSlots()) {
            validateSlot(message.getStage(), slot);
            int order = previousKey == null ? 1 : compareIdentifier(previousInput, previousKey, slot.getInputIndex(), slot.getSignerPublicKey());
            if(order >= 0 && previousKey != null) throw fail(SIGNATURE_SLOT_MISMATCH, "Slots are not uniquely ordered");
            if(!commitments.add(new Bytes(slot.getCommitment()))) throw fail(COMMITMENT_MISMATCH, "Duplicate host commitment");
            if(slot.getHostRandomness() != null && !reveals.add(new Bytes(slot.getHostRandomness()))) throw fail(COMMITMENT_MISMATCH, "Duplicate host reveal");
            if(slot.getOpening() != null) {
                Set<Bytes> signerOpenings = openingsBySigner.computeIfAbsent(
                        new Bytes(slot.getSignerPublicKey()), ignored -> new HashSet<>());
                if(!signerOpenings.add(new Bytes(slot.getOpening()))) {
                    throw fail(OPENING_MISMATCH, "Signer openings must be unique per signer public key");
                }
            }
            perInput = slot.getInputIndex() == previousInput ? perInput + 1 : 1;
            if(perInput > MAX_SLOTS_PER_INPUT) throw fail(SIGNATURE_SLOT_MISMATCH, "Input exceeds the slot limit");
            previousInput = slot.getInputIndex();
            previousKey = slot.getSignerPublicKey();
        }
    }

    private static void validateSlot(AntiExfilStage stage, AntiExfilSlot slot) {
        if(slot == null || slot.getInputIndex() < 0 || slot.getInputIndex() > 0xffff_ffffL || slot.getSighashType() != SIGHASH_ALL) {
            throw fail(INVALID_MESSAGE, "Invalid slot index or sighash");
        }
        requirePoint(slot.getSignerPublicKey(), "signer public key");
        requireLength(slot.getMessageHash(), 32, "message hash");
        requireLength(slot.getCommitment(), 32, "host commitment");
        boolean needsOpening = stage.getCode() >= AntiExfilStage.SIGNER_OPENINGS.getCode();
        if((slot.getOpening() != null) != needsOpening) throw fail(INVALID_MESSAGE, "Opening presence conflicts with stage");
        if((slot.getHostRandomness() != null) != (stage == AntiExfilStage.HOST_REVEAL)) throw fail(INVALID_MESSAGE, "Reveal presence conflicts with stage");
        if((slot.getSignature() != null) != (stage == AntiExfilStage.SIGNER_SIGNATURES)) throw fail(INVALID_MESSAGE, "Signature presence conflicts with stage");
        if(slot.getOpening() != null) requirePoint(slot.getOpening(), "signer opening");
        if(slot.getHostRandomness() != null) requireLength(slot.getHostRandomness(), 32, "host reveal");
        if(slot.getSignature() != null) {
            requireLength(slot.getSignature(), 64, "compact signature");
            BigInteger r = new BigInteger(1, Arrays.copyOfRange(slot.getSignature(), 0, 32));
            BigInteger s = new BigInteger(1, Arrays.copyOfRange(slot.getSignature(), 32, 64));
            if(r.signum() <= 0 || r.compareTo(ECKey.CURVE.getN()) >= 0 || s.signum() <= 0 || s.compareTo(ECKey.HALF_CURVE_ORDER) > 0) {
                throw fail(INVALID_MESSAGE, "Signature scalars are invalid or non-low-S");
            }
        }
    }

    private static int compareIdentifier(long leftIndex, byte[] leftKey, long rightIndex, byte[] rightKey) {
        int indexComparison = Long.compare(leftIndex, rightIndex);
        if(indexComparison != 0) return indexComparison;
        return Arrays.compareUnsigned(leftKey, rightKey);
    }

    private static void requirePoint(byte[] point, String name) {
        requireLength(point, 33, name);
        if(point[0] != 2 && point[0] != 3) throw fail(INVALID_MESSAGE, name + " is not compressed");
        try {
            if(ECKey.CURVE.getCurve().decodePoint(point).isInfinity()) throw fail(INVALID_MESSAGE, name + " is infinity");
        } catch(IllegalArgumentException e) {
            throw new AntiExfilException(INVALID_MESSAGE, name + " is not a secp256k1 point", e);
        }
    }

    private static void requireLength(byte[] value, int expected, String name) {
        if(length(value) != expected) throw fail(INVALID_MESSAGE, name + " must be exactly " + expected + " bytes");
    }

    private static int length(byte[] value) { return value == null ? -1 : value.length; }
    private static byte[] read(ByteBuffer buffer, int length) { byte[] value = new byte[length]; buffer.get(value); return value; }
    private static AntiExfilException fail(AntiExfilException.Code code, String message) { return new AntiExfilException(code, message); }

    private record Bytes(byte[] value) {
        @Override public boolean equals(Object object) { return object instanceof Bytes other && Arrays.equals(value, other.value); }
        @Override public int hashCode() { return Arrays.hashCode(value); }
    }
}
