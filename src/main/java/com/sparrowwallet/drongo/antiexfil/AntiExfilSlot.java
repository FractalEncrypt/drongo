package com.sparrowwallet.drongo.antiexfil;

import java.util.Arrays;

public final class AntiExfilSlot {
    private final long inputIndex;
    private final long sighashType;
    private final byte[] signerPublicKey;
    private final byte[] messageHash;
    private final byte[] commitment;
    private final byte[] opening;
    private final byte[] hostRandomness;
    private final byte[] signature;

    public AntiExfilSlot(long inputIndex, long sighashType, byte[] signerPublicKey, byte[] messageHash,
                         byte[] commitment, byte[] opening, byte[] hostRandomness, byte[] signature) {
        this.inputIndex = inputIndex;
        this.sighashType = sighashType;
        this.signerPublicKey = copy(signerPublicKey);
        this.messageHash = copy(messageHash);
        this.commitment = copy(commitment);
        this.opening = copy(opening);
        this.hostRandomness = copy(hostRandomness);
        this.signature = copy(signature);
    }

    private static byte[] copy(byte[] value) {
        return value == null ? null : value.clone();
    }

    public long getInputIndex() { return inputIndex; }
    public long getSighashType() { return sighashType; }
    public byte[] getSignerPublicKey() { return copy(signerPublicKey); }
    public byte[] getMessageHash() { return copy(messageHash); }
    public byte[] getCommitment() { return copy(commitment); }
    public byte[] getOpening() { return copy(opening); }
    public byte[] getHostRandomness() { return copy(hostRandomness); }
    public byte[] getSignature() { return copy(signature); }

    @Override
    public boolean equals(Object object) {
        if(this == object) return true;
        if(!(object instanceof AntiExfilSlot other)) return false;
        return inputIndex == other.inputIndex && sighashType == other.sighashType
                && Arrays.equals(signerPublicKey, other.signerPublicKey)
                && Arrays.equals(messageHash, other.messageHash)
                && Arrays.equals(commitment, other.commitment)
                && Arrays.equals(opening, other.opening)
                && Arrays.equals(hostRandomness, other.hostRandomness)
                && Arrays.equals(signature, other.signature);
    }

    @Override
    public int hashCode() {
        int result = Long.hashCode(inputIndex);
        result = 31 * result + Long.hashCode(sighashType);
        result = 31 * result + Arrays.hashCode(signerPublicKey);
        result = 31 * result + Arrays.hashCode(messageHash);
        result = 31 * result + Arrays.hashCode(commitment);
        result = 31 * result + Arrays.hashCode(opening);
        result = 31 * result + Arrays.hashCode(hostRandomness);
        return 31 * result + Arrays.hashCode(signature);
    }
}
