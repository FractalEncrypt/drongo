package com.sparrowwallet.drongo.wallet;

/** Stable carriage identity persisted with an anti-exfil-capable keystore. */
public enum AntiExfilProfile {
    NONE("none"),
    AEXT_V1("aext-v1"),
    IN_PSBT_V1("in-psbt-v1");

    private final String id;

    AntiExfilProfile(String id) {
        this.id = id;
    }

    public String getId() {
        return id;
    }

    public static AntiExfilProfile fromId(String id) {
        for(AntiExfilProfile profile : values()) {
            if(profile.id.equals(id) || profile.name().equals(id)) {
                return profile;
            }
        }
        throw new IllegalArgumentException("Unknown anti-exfil profile: " + id);
    }
}
