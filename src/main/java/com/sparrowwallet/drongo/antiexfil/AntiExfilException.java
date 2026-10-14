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
        UNEXPECTED_RETURN_DATA,
        SESSION_MISMATCH,
        RETRY_CONFLICT,
        STATE_INVALID,
        ACCOUNT_EXCHANGE_BUSY,
        HISTORY_STORAGE_ERROR,
        VERSION_CONFLICT,
        RECOVERY_APPROVAL_REQUIRED
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
