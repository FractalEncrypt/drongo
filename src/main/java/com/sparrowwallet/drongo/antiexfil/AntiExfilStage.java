package com.sparrowwallet.drongo.antiexfil;

public enum AntiExfilStage {
    HOST_COMMIT(1, 0),
    SIGNER_OPENINGS(2, 33),
    HOST_REVEAL(3, 65),
    SIGNER_SIGNATURES(4, 97);

    private final int code;
    private final int extraLength;

    AntiExfilStage(int code, int extraLength) {
        this.code = code;
        this.extraLength = extraLength;
    }

    public int getCode() {
        return code;
    }

    public int getRecordLength() {
        return AntiExfilCodec.COMMON_RECORD_LENGTH + extraLength;
    }

    public static AntiExfilStage fromCode(int code) {
        for(AntiExfilStage stage : values()) {
            if(stage.code == code) {
                return stage;
            }
        }
        throw new AntiExfilException(AntiExfilException.Code.WRONG_STAGE, "Unknown AEXB stage " + code);
    }
}
