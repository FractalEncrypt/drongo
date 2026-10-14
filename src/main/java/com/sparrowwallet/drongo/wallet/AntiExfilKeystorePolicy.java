package com.sparrowwallet.drongo.wallet;

/**
 * Declares whether a keystore can use the interactive anti-exfil signing
 * protocol. REQUIRED is retained solely for legacy profile compatibility; it has no mandatory signing semantics.
 */
public enum AntiExfilKeystorePolicy {
    UNSUPPORTED("Unsupported"),
    OPTIONAL("Enabled"),
    REQUIRED("Enabled (legacy)");

    private final String displayName;

    AntiExfilKeystorePolicy(String displayName) {
        this.displayName = displayName;
    }

    public boolean isSupported() {
        return this != UNSUPPORTED;
    }

    public boolean isRequired() {
        return false; // Required provenance is retired; ordinal retained for old profiles.
    }

    @Override
    public String toString() {
        return displayName;
    }
}
