package com.sparrowwallet.drongo.antiexfil;

public enum AntiExfilNetwork {
    MAINNET(0), TESTNET3(1), REGTEST(2), SIGNET(3), TESTNET4(4);

    private final int code;

    AntiExfilNetwork(int code) {
        this.code = code;
    }

    public int getCode() {
        return code;
    }

    public static AntiExfilNetwork fromCode(int code) {
        for(AntiExfilNetwork network : values()) {
            if(network.code == code) {
                return network;
            }
        }
        throw new AntiExfilException(AntiExfilException.Code.INVALID_MESSAGE, "Unknown AEXB network " + code);
    }
}
