package com.sparrowwallet.drongo.antiexfil;

import java.util.Arrays;
import java.util.Objects;

/**
 * Immutable evidence that one exact PSBT signature was produced by a
 * successfully revalidated anti-exfil ceremony.
 */
public final class VerifiedAntiExfilSignature {
    private final byte[] sessionId;
    private final byte[] originalPsbtDigest;
    private final byte[] walletKeyIdentity;
    private final int inputIndex;
    private final byte[] outpoint;
    private final byte[] signerPublicKey;
    private final byte[] messageHash;
    private final long sighashType;
    private final byte[] compactSignature;

    VerifiedAntiExfilSignature(byte[] sessionId, byte[] originalPsbtDigest, byte[] walletKeyIdentity,
                               int inputIndex, byte[] outpoint, byte[] signerPublicKey, byte[] messageHash,
                               long sighashType, byte[] compactSignature) {
        requireLength(sessionId, 32, "session ID");
        requireLength(originalPsbtDigest, 32, "original PSBT digest");
        requireLength(walletKeyIdentity, 32, "wallet-key identity");
        requireLength(outpoint, 36, "outpoint");
        requireLength(signerPublicKey, 33, "signer public key");
        requireLength(messageHash, 32, "message hash");
        requireLength(compactSignature, 64, "compact signature");
        if(inputIndex < 0) throw new IllegalArgumentException("Input index must be non-negative");
        this.sessionId = sessionId.clone();
        this.originalPsbtDigest = originalPsbtDigest.clone();
        this.walletKeyIdentity = walletKeyIdentity.clone();
        this.inputIndex = inputIndex;
        this.outpoint = outpoint.clone();
        this.signerPublicKey = signerPublicKey.clone();
        this.messageHash = messageHash.clone();
        this.sighashType = sighashType;
        this.compactSignature = compactSignature.clone();
    }

    public byte[] getSessionId() { return sessionId.clone(); }
    public byte[] getOriginalPsbtDigest() { return originalPsbtDigest.clone(); }
    public byte[] getWalletKeyIdentity() { return walletKeyIdentity.clone(); }
    public int getInputIndex() { return inputIndex; }
    public byte[] getOutpoint() { return outpoint.clone(); }
    public byte[] getSignerPublicKey() { return signerPublicKey.clone(); }
    public byte[] getMessageHash() { return messageHash.clone(); }
    public long getSighashType() { return sighashType; }
    public byte[] getCompactSignature() { return compactSignature.clone(); }

    @Override
    public boolean equals(Object object) {
        if(this == object) return true;
        if(!(object instanceof VerifiedAntiExfilSignature other)) return false;
        return inputIndex == other.inputIndex && sighashType == other.sighashType
                && Arrays.equals(sessionId, other.sessionId)
                && Arrays.equals(originalPsbtDigest, other.originalPsbtDigest)
                && Arrays.equals(walletKeyIdentity, other.walletKeyIdentity)
                && Arrays.equals(outpoint, other.outpoint)
                && Arrays.equals(signerPublicKey, other.signerPublicKey)
                && Arrays.equals(messageHash, other.messageHash)
                && Arrays.equals(compactSignature, other.compactSignature);
    }

    @Override
    public int hashCode() {
        int result = Objects.hash(inputIndex, sighashType);
        result = 31 * result + Arrays.hashCode(sessionId);
        result = 31 * result + Arrays.hashCode(originalPsbtDigest);
        result = 31 * result + Arrays.hashCode(walletKeyIdentity);
        result = 31 * result + Arrays.hashCode(outpoint);
        result = 31 * result + Arrays.hashCode(signerPublicKey);
        result = 31 * result + Arrays.hashCode(messageHash);
        return 31 * result + Arrays.hashCode(compactSignature);
    }

    private static void requireLength(byte[] value, int length, String name) {
        if(value == null || value.length != length) {
            throw new IllegalArgumentException("Invalid " + name);
        }
    }
}
