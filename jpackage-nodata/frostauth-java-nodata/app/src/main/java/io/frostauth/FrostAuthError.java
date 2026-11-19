package io.frostauth;

/** Error thrown by every FrostAuth SDK call. */
public class FrostAuthError extends RuntimeException {

    public final String code;
    public final int status;
    public final boolean retryable;
    public final String requestId;
    public final int retryAfterSeconds;

    public FrostAuthError(String message, String code, int status, boolean retryable) {
        this(message, code, status, retryable, null, 0);
    }

    public FrostAuthError(String message, String code, int status, boolean retryable,
                          String requestId, int retryAfterSeconds) {
        super(message);
        this.code = code == null ? Codes.SERVER_ERROR : code;
        this.status = status;
        this.retryable = retryable;
        this.requestId = requestId;
        this.retryAfterSeconds = retryAfterSeconds;
    }

    public boolean needsActivation() {
        return status == 404 && !retryable;
    }

    public boolean terminal() {
        return !retryable && !needsActivation() && status >= 400 && status < 500;
    }

    public static final class Codes {
        public static final String CONFIG = "CONFIG";
        public static final String NETWORK = "NETWORK";
        public static final String TIMEOUT = "TIMEOUT";
        public static final String NOT_INITIALIZED = "NOT_INITIALIZED";
        public static final String NOT_ACTIVATED = "NOT_ACTIVATED";
        public static final String SERVER_ERROR = "SERVER_ERROR";
        public static final String SIGNATURE = "SIGNATURE";
        public static final String RATE_LIMITED = "RATE_LIMITED";
    }
}
