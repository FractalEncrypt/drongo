package com.sparrowwallet.drongo.antiexfil;

public class AntiExfilException extends IllegalArgumentException {
    public enum Code {
        INVALID_MESSAGE,
        WRONG_STAGE,
        TRANSACTION_MISMATCH,
        SIGNATURE_SLOT_MISMATCH,
        COMMITMENT_MISMATCH,
        OPENING_MISMATCH,
        SIGNATURE_INVALID,
        UNEXPECTED_RETURN_DATA
    }

    private final Code code;

    public AntiExfilException(Code code, String message) {
        super(message);
        this.code = code;
    }

    public AntiExfilException(Code code, String message, Throwable cause) {
        super(message, cause);
        this.code = code;
    }

    public Code getCode() {
        return code;
    }
}
