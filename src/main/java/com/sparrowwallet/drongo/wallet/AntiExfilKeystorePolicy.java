package com.sparrowwallet.drongo.wallet;

/**
 * Declares whether a keystore can use the interactive anti-exfil signing
 * protocol and whether that protocol is mandatory.
 */
public enum AntiExfilKeystorePolicy {
    UNSUPPORTED("Unsupported"),
    OPTIONAL("Optional"),
    REQUIRED("Required");

    private final String displayName;

    AntiExfilKeystorePolicy(String displayName) {
        this.displayName = displayName;
    }

    public boolean isSupported() {
        return this != UNSUPPORTED;
    }

    public boolean isRequired() {
        return this == REQUIRED;
    }

    @Override
    public String toString() {
        return displayName;
    }
}
