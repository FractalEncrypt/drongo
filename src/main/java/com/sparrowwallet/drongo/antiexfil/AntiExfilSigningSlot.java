package com.sparrowwallet.drongo.antiexfil;

import com.sparrowwallet.drongo.KeyDerivation;

import java.util.Arrays;

public final class AntiExfilSigningSlot {
    private final int inputIndex;
    private final byte[] signerPublicKey;
    private final byte[] messageHash;
    private final long sighashType;
    private final KeyDerivation keyDerivation;
    private final String scriptKind;

    public AntiExfilSigningSlot(int inputIndex, byte[] signerPublicKey, byte[] messageHash, long sighashType,
                               KeyDerivation keyDerivation, String scriptKind) {
        this.inputIndex = inputIndex;
        this.signerPublicKey = signerPublicKey.clone();
        this.messageHash = messageHash.clone();
        this.sighashType = sighashType;
        this.keyDerivation = keyDerivation.copy();
        this.scriptKind = scriptKind;
    }

    public int getInputIndex() { return inputIndex; }
    public byte[] getSignerPublicKey() { return signerPublicKey.clone(); }
    public byte[] getMessageHash() { return messageHash.clone(); }
    public long getSighashType() { return sighashType; }
    public KeyDerivation getKeyDerivation() { return keyDerivation.copy(); }
    public String getScriptKind() { return scriptKind; }

    public Identifier getIdentifier() {
        return new Identifier(inputIndex, signerPublicKey);
    }

    public static final class Identifier implements Comparable<Identifier> {
        private final int inputIndex;
        private final byte[] signerPublicKey;

        public Identifier(int inputIndex, byte[] signerPublicKey) {
            this.inputIndex = inputIndex;
            this.signerPublicKey = signerPublicKey.clone();
        }

        public int getInputIndex() { return inputIndex; }
        public byte[] getSignerPublicKey() { return signerPublicKey.clone(); }

        @Override
        public int compareTo(Identifier other) {
            int inputComparison = Integer.compareUnsigned(inputIndex, other.inputIndex);
            return inputComparison == 0 ? Arrays.compareUnsigned(signerPublicKey, other.signerPublicKey) : inputComparison;
        }

        @Override
        public boolean equals(Object object) {
            return object instanceof Identifier other && inputIndex == other.inputIndex
                    && Arrays.equals(signerPublicKey, other.signerPublicKey);
        }

        @Override
        public int hashCode() {
            return 31 * Integer.hashCode(inputIndex) + Arrays.hashCode(signerPublicKey);
        }
    }
}
