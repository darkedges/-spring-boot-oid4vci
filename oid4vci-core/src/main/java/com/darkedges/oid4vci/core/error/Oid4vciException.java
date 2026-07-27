package com.darkedges.oid4vci.core.error;

/** Base class for exceptions that carry an {@link Oid4vciErrorCode} for a Token/Credential Endpoint
 * error response. */
public class Oid4vciException extends RuntimeException {

    private final Oid4vciErrorCode errorCode;

    public Oid4vciException(Oid4vciErrorCode errorCode, String message) {
        super(message);
        this.errorCode = errorCode;
    }

    public Oid4vciException(Oid4vciErrorCode errorCode, String message, Throwable cause) {
        super(message, cause);
        this.errorCode = errorCode;
    }

    public Oid4vciErrorCode errorCode() {
        return errorCode;
    }
}
