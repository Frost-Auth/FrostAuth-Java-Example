package io.frostauth;

import java.math.BigInteger;
import java.net.InetAddress;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.PublicKey;
import java.security.interfaces.EdECPublicKey;
import java.security.spec.EdECPoint;
import java.security.spec.EdECPublicKeySpec;
import java.security.spec.NamedParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.BiConsumer;
import java.util.function.Consumer;

/**
 * FrostAuth SDK — Java port.
 *
 * Mirrors sdk/frostauth.js wire behavior: every response is Ed25519-verified
 * over "timestamp\nnonce\nmethod\npath\nstatus\nbody" (±60s skew, pinned key
 * IDs), init() pins the server key against the key baked into this build,
 * offline assertions are verified locally when the network is gone, and a
 * DNS-hijack tripwire refuses loopback/private answers before any licence
 * material is sent.
 *
 * Requires JDK 17+. Zero external dependencies.
 */
public final class FrostAuth {

    public static final String SDK_VERSION = "1.0.0";
    public static final String DEFAULT_BASE_URL = "https://api.frostauth.cc";
    static final long MAX_SIGNATURE_SKEW_MS = 60_000;
    static final int MAX_RETRY_AFTER_SECONDS = 10;
    static final String ASSERTION_PREFIX = "frostauth:assertion:v1";

    /** Signing keys baked into this build (TOFU). */
    public static final Map<String, String> PUBLIC_KEYS = buildPublicKeys();

    private static Map<String, String> buildPublicKeys() {
        Map<String, String> m = new LinkedHashMap<>();
        m.put("k2", "MCowBQYDK2VwAyEA7xdiHZqo4DmS4O1C8FavYq9Yqk5QbBkJiicb1MTTFzo");
        return Map.copyOf(m);
    }

    // ── construction ─────────────────────────────────────────────────────────

    private final String owner;
    private final String product;
    private final String version;
    private final String baseUrl;
    private final Duration timeout;
    private final int retries;
    private final long offlineGraceSeconds;
    private final boolean allowInsecure;
    private final boolean allowPrivateDns;
    private final boolean collectHardware;
    private final String hwOverride;
    private final HttpClient http;
    private final SecureRandom random = new SecureRandom();

    private final Object lock = new Object();
    private Map<String, PublicKey> keys = new LinkedHashMap<>();     // id -> Ed25519 key
    private Map<String, byte[]> rawKeys = new LinkedHashMap<>();     // id -> raw 32 bytes
    private Map<String, Object> app;
    private Map<String, Object> license;
    private Map<String, Object> productInfo;
    private Map<String, Object> device;
    private String user;
    private Map<String, Object> account;
    private List<Object> subscriptions = new ArrayList<>();
    private Map<String, Object> session;
    private String storedKey;
    private String assertion;
    private String offlineUntil;
    private Instant offlineSince;
    private String machineId;
    private boolean initialized;
    private boolean activated;
    private boolean closed;

    // Event hooks — assign before startHeartbeat(), called from the heartbeat thread.
    public Consumer<Map<String, Object>> onActivated;
    public Consumer<Map<String, Object>> onLoggedIn;
    public Consumer<Map<String, Object>> onValidated;
    public BiConsumer<String, String> onUpdateAvailable;             // (current, latest)
    public TriConsumer<FrostAuthError, Long, Boolean> onOffline;     // (err, seconds, verified)
    public Consumer<FrostAuthError> onInvalid;
    public Consumer<FrostAuthError> onNeedsActivation;

    @FunctionalInterface
    public interface TriConsumer<A, B, C> { void accept(A a, B b, C c); }

    public FrostAuth(String owner, String product, String version) {
        this(owner, product, version, DEFAULT_BASE_URL);
    }

    public FrostAuth(String owner, String product, String version, String baseUrl) {
        for (String[] pair : new String[][]{{"owner", owner}, {"product", product}, {"version", version}}) {
            if (pair[1] == null || pair[1].isBlank()) {
                throw new FrostAuthError(pair[0] + " is required", FrostAuthError.Codes.CONFIG, 0, false);
            }
        }
        this.owner = owner.trim();
        this.product = product.trim();
        this.version = version.trim();
        this.baseUrl = (baseUrl == null || baseUrl.isBlank()) ? DEFAULT_BASE_URL : baseUrl;
        this.timeout = Duration.ofSeconds(10);
        this.retries = 2;
        this.offlineGraceSeconds = 900;
        this.allowInsecure = false;
        this.allowPrivateDns = false;
        this.collectHardware = true;
        this.hwOverride = null;

        URI uri = URI.create(this.baseUrl);
        String host = uri.getHost() == null ? "" : uri.getHost();
        boolean loopback = host.equals("localhost") || host.equals("127.0.0.1") || host.equals("[::1]") || host.equals("::1");
        if (!"https".equalsIgnoreCase(uri.getScheme()) && !loopback && !allowInsecure) {
            throw new FrostAuthError(
                "Refusing to send a licence key over plain http. Use https, or pass allowInsecure if you know what you are doing.",
                FrostAuthError.Codes.CONFIG, 0, false);
        }
        this.http = HttpClient.newBuilder().connectTimeout(timeout).build();
    }

    // ── public API ───────────────────────────────────────────────────────────

    /** Fetches the public catalog and pins the server's signing key (TOFU). */
    public Map<String, Object> init() {
        assertRealHost();
        String path = "/api/v1/settings/catalog/" + enc(owner) + "/" + enc(product);
        Map<String, Object> body = requestRaw("GET", path, null);
        Object success = body.get("success");
        if (!Boolean.TRUE.equals(success)) {
            String code = body.get("error") instanceof String s && !s.isBlank() ? s : "APP_NOT_FOUND";
            String msg = body.get("message") instanceof String s && !s.isBlank() ? s : "Application not found";
            throw new FrostAuthError(msg, code, 404, false);
        }
        String keyId = str(body.get("key_id"));
        String served = str(body.get("public_key"));
        String pinned = PUBLIC_KEYS.get(keyId);
        if (keyId.isBlank() || pinned == null || !pinned.equals(served)) {
            throw new FrostAuthError("Server identity check failed — refusing to continue",
                FrostAuthError.Codes.SIGNATURE, 401, false);
        }
        PublicKey key = spkiToKey(pinned);
        synchronized (lock) {
            keys = new LinkedHashMap<>();
            rawKeys = new LinkedHashMap<>();
            keys.put(keyId, key);
            rawKeys.put(keyId, spkiToRaw(pinned));
            Map<String, Object> a = new LinkedHashMap<>();
            a.put("name", body.get("app_name"));
            a.put("ownerId", body.get("owner_id"));
            a.put("messages", body.get("errors") == null ? Map.of() : body.get("errors"));
            app = a;
            initialized = true;
        }
        return snapshot();
    }

    /** Binds a licence key to this machine and opens a session. */
    public Map<String, Object> activate(String key, String buildHash, String label) {
        requireInit();
        if (key == null || key.isBlank()) {
            throw new FrostAuthError("licence key is required", FrostAuthError.Codes.CONFIG, 0, false);
        }
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("key", key.trim());
        body.put("hwid", machine());
        body.put("os", osName());
        body.put("appVersion", version);
        body.putAll(hardwareExtra());
        if (buildHash != null && !buildHash.isBlank()) body.put("hash", buildHash);
        if (label != null && !label.isBlank()) body.put("label", label.substring(0, Math.min(64, label.length())));
        Map<String, Object> data = requestEnvelope("POST", "/api/v1/activate", body);
        synchronized (lock) {
            storedKey = key.trim();
            adopt(data);
            activated = true;
            offlineSince = null;
        }
        if (onActivated != null) onActivated.accept(snapshot());
        return snapshot();
    }

    /** Creates an app user from a licence key, then opens a session. */
    public Map<String, Object> register(String key, String username, String password,
                                        String buildHash, String label) {
        requireInit();
        if (key == null || key.isBlank()) {
            throw new FrostAuthError("licence key is required", FrostAuthError.Codes.CONFIG, 0, false);
        }
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("key", key.trim());
        body.put("username", username.trim());
        body.put("password", password);
        body.put("hwid", machine());
        body.put("os", osName());
        body.put("appVersion", version);
        body.putAll(hardwareExtra());
        if (buildHash != null && !buildHash.isBlank()) body.put("hash", buildHash);
        if (label != null && !label.isBlank()) body.put("label", label.substring(0, Math.min(64, label.length())));
        Map<String, Object> data = requestEnvelope("POST", "/api/v1/sdk/register", body);
        synchronized (lock) {
            storedKey = key.trim();
            adopt(data);
            activated = true;
            offlineSince = null;
        }
        if (onActivated != null) onActivated.accept(snapshot());
        return snapshot();
    }

    /** Signs in an app user and opens a session. */
    public Map<String, Object> login(String username, String password, String twofa,
                                     String buildHash, String label) {
        requireInit();
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("owner", owner);
        body.put("product", product);
        body.put("username", username.trim());
        body.put("password", password);
        body.put("hwid", machine());
        body.put("os", osName());
        body.put("appVersion", version);
        body.putAll(hardwareExtra());
        if (twofa != null && !twofa.isBlank()) body.put("twofa", twofa);
        if (buildHash != null && !buildHash.isBlank()) body.put("hash", buildHash);
        if (label != null && !label.isBlank()) body.put("label", label.substring(0, Math.min(64, label.length())));
        Map<String, Object> data = requestEnvelope("POST", "/api/v1/sdk/login", body);
        synchronized (lock) {
            adopt(data);
            activated = true;
            offlineSince = null;
        }
        if (onActivated != null) onActivated.accept(snapshot());
        return snapshot();
    }

    /** Attaches a licence key to an existing app user. */
    public Map<String, Object> upgrade(String username, String password, String key) {
        requireInit();
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("owner", owner);
        body.put("product", product);
        body.put("username", username.trim());
        body.put("password", password);
        body.put("key", key.trim());
        return requestEnvelope("POST", "/api/v1/sdk/upgrade", body);
    }

    /** Invalidates the session server-side and closes the client. */
    public Map<String, Object> logout() {
        boolean had;
        synchronized (lock) { had = token() != null; }
        try {
            if (had) return authed("POST", "/api/v1/sdk/logout", null);
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("signedOut", true);
            return out;
        } finally {
            close();
        }
    }

    /** Re-fetches and adopts current session state. */
    public Map<String, Object> session() {
        Map<String, Object> data = authed("GET", "/api/v1/sdk/session", null);
        synchronized (lock) { adopt(data); }
        return snapshot();
    }

    public String variable(String key) {
        Map<String, Object> d = authed("GET", "/api/v1/sdk/vars/app/" + enc(key), null);
        return str(d.get("value"));
    }

    public List<Object> listVars() {
        Map<String, Object> d = authed("GET", "/api/v1/sdk/vars/user", null);
        Object v = d.get("variables");
        return v instanceof List<?> l ? new ArrayList<>(l) : new ArrayList<>();
    }

    public String getVar(String key) {
        Map<String, Object> d = authed("GET", "/api/v1/sdk/vars/user/" + enc(key), null);
        return str(d.get("value"));
    }

    public Map<String, Object> setVar(String key, String value) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("value", value == null ? "" : value);
        return authed("PUT", "/api/v1/sdk/vars/user/" + enc(key), body);
    }

    public Map<String, Object> changeUsername(String username, String password) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("username", username.trim());
        body.put("password", password);
        Map<String, Object> data = authed("PATCH", "/api/v1/sdk/username", body);
        synchronized (lock) {
            if (account != null && data.get("username") != null) account.put("username", data.get("username"));
            if (data.get("username") instanceof String s) user = s;
        }
        return data;
    }

    public Map<String, Object> log(String message) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("message", message == null ? "" : message.substring(0, Math.min(256, message.length())));
        return authed("POST", "/api/v1/sdk/log", body);
    }

    public Map<String, Object> ban(String reason) {
        try {
            Map<String, Object> body = new LinkedHashMap<>();
            body.put("reason", reason == null ? "" : reason.substring(0, Math.min(200, reason.length())));
            return authed("POST", "/api/v1/sdk/ban", body);
        } finally {
            stopHeartbeat();
            synchronized (lock) {
                activated = false;
                assertion = null;
                offlineUntil = null;
            }
        }
    }

    public Map<String, Object> fetchOnline() { return authed("GET", "/api/v1/sdk/online", null); }

    public Map<String, Object> checkBlacklist() { return authed("GET", "/api/v1/sdk/checkblacklist", null); }

    public Map<String, Object> webhook(String webId, String params, String body, String conttype) {
        if (webId == null || webId.isBlank()) {
            throw new FrostAuthError("webhook id is required", FrostAuthError.Codes.CONFIG, 0, false);
        }
        Map<String, Object> payload = new LinkedHashMap<>();
        if (params != null && !params.isEmpty()) payload.put("params", trunc(params, 2048));
        if (body != null && !body.isEmpty()) payload.put("body", trunc(body, 8192));
        if (conttype != null && !conttype.isEmpty()) payload.put("conttype", trunc(conttype, 128));
        return authed("POST", "/api/v1/sdk/webhook/" + enc(webId), payload);
    }

    public Map<String, Object> appData() { return authed("GET", "/api/v1/sdk/app", null); }

    /** File download by handle. Currently disabled server-side (route
     *  unmounted) — mirrors the JS reference SDK, which throws. */
    public byte[] file(String fileId) {
        throw new FrostAuthError("File downloads are disabled on this server",
            FrostAuthError.Codes.SERVER_ERROR, 0, false);
    }

    /** Re-checks the licence/session with the server; falls back from a stale
     *  session token to the stored licence key once. */
    public Map<String, Object> validate() {
        requireInit();
        boolean hasCred;
        synchronized (lock) { hasCred = token() != null || storedKey != null; }
        if (!hasCred) {
            throw new FrostAuthError("Activate before validating", FrostAuthError.Codes.NOT_ACTIVATED, 0, false);
        }
        try {
            Map<String, Object> data = sendValidate();
            synchronized (lock) {
                adopt(data);
                activated = true;
                offlineSince = null;
            }
            return snapshot();
        } catch (FrostAuthError err) {
            boolean stale = "INVALID_TOKEN".equals(err.code) || "INVALID_SESSION".equals(err.code);
            String key;
            synchronized (lock) { key = storedKey; }
            if (stale && key != null) {
                synchronized (lock) { session = null; }
                Map<String, Object> data = sendValidate();
                synchronized (lock) {
                    adopt(data);
                    activated = true;
                    offlineSince = null;
                }
                return snapshot();
            }
            throw err;
        }
    }

    private final AtomicReference<ScheduledFuture<?>> heartbeatTask = new AtomicReference<>();
    private final ScheduledExecutorService heartbeatPool =
        Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "frostauth-heartbeat");
            t.setDaemon(true);
            return t;
        });

    /** Validates periodically (server cadence or explicit seconds) until stopped. */
    public void startHeartbeat(Integer intervalSeconds) {
        boolean hasCred;
        synchronized (lock) { hasCred = token() != null || storedKey != null; }
        if (!hasCred) {
            throw new FrostAuthError(
                "Nothing to heartbeat with: activate with a licence key, or sign in on a plan that issues session tokens.",
                FrostAuthError.Codes.NOT_ACTIVATED, 0, false);
        }
        synchronized (lock) { closed = false; }
        stopHeartbeat();
        heartbeatTask.set(heartbeatPool.scheduleWithFixedDelay(() -> {
            try {
                validate();
            } catch (FrostAuthError err) {
                if (err.needsActivation()) {
                    synchronized (lock) { activated = false; }
                    stopHeartbeat();
                    if (onNeedsActivation != null) onNeedsActivation.accept(err);
                    return;
                }
                if (FrostAuthError.Codes.SIGNATURE.equals(err.code) || err.terminal()) {
                    synchronized (lock) { activated = false; }
                    stopHeartbeat();
                    if (onInvalid != null) onInvalid.accept(err);
                    return;
                }
                long offlineFor;
                boolean verified;
                boolean stop;
                synchronized (lock) {
                    if (offlineSince == null) offlineSince = Instant.now();
                    offlineFor = Duration.between(offlineSince, Instant.now()).getSeconds();
                    String a = assertion;
                    String mid = machineId;
                    Map<String, byte[]> pins = rawKeys;
                    verified = a != null && VerifyAssertion(a, pins, mid).ok();
                    stop = !verified && (a != null || offlineFor >= offlineGraceSeconds);
                    if (stop) activated = false;
                }
                if (onOffline != null) onOffline.accept(err, offlineFor, verified);
                if (stop) {
                    stopHeartbeat();
                    if (onInvalid != null) {
                        onInvalid.accept(new FrostAuthError(
                            "Could not reach the licence server for " + offlineFor + "s",
                            FrostAuthError.Codes.NETWORK, 0, true));
                    }
                }
            }
        }, initialDelay(intervalSeconds), periodMillis(intervalSeconds), TimeUnit.MILLISECONDS));
    }

    private long initialDelay(Integer intervalSeconds) {
        return intervalSeconds != null ? Math.max(1, intervalSeconds) * 1000L : 1000L;
    }

    private long periodMillis(Integer intervalSeconds) {
        long jitter = random.nextInt(5000);
        if (intervalSeconds != null) return Math.max(1, intervalSeconds) * 1000L + (jitter % 250);
        long base;
        synchronized (lock) {
            base = session != null && session.get("heartbeatSeconds") instanceof Number n
                ? n.longValue() : 180;
        }
        return Math.max(15, base) * 1000L + jitter;
    }

    public void stopHeartbeat() {
        ScheduledFuture<?> f = heartbeatTask.getAndSet(null);
        if (f != null) f.cancel(false);
    }

    /** Tears down the client and drops the offline assertion. */
    public void close() {
        stopHeartbeat();
        synchronized (lock) {
            closed = true;
            storedKey = null;
            session = null;
            activated = false;
            account = null;
            subscriptions = new ArrayList<>();
            assertion = null;
            offlineUntil = null;
            offlineSince = null;
        }
    }

    /** Verifies the last server-issued assertion locally. */
    public CheckOfflineResult checkOffline() {
        String a;
        String mid;
        Map<String, byte[]> pins;
        synchronized (lock) {
            a = assertion;
            mid = machineId;
            pins = rawKeys;
        }
        if (a == null) return new CheckOfflineResult(false, "no assertion issued yet");
        if (pins.isEmpty()) return new CheckOfflineResult(false, "no pinned publicKey to verify against");
        AssertionResult r = VerifyAssertion(a, pins, mid);
        return new CheckOfflineResult(r.ok, r.reason);
    }

    public record CheckOfflineResult(boolean ok, String reason) {}

    public Map<String, Object> snapshot() {
        synchronized (lock) {
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("app", app);
            out.put("license", license);
            out.put("product", productInfo);
            out.put("device", device);
            out.put("user", user);
            out.put("account", account);
            out.put("subscriptions", subscriptions);
            out.put("valid", activated && !closed);
            return out;
        }
    }

    // ── offline assertions ───────────────────────────────────────────────────

    public record AssertionResult(boolean ok, String reason, Map<String, Object> claims) {}

    static byte[] claimString(Map<String, Object> claims) {
        String[] fields = {"lic", "pid", "dev", "hwid", "status", "tier", "exp", "iat", "nbf", "naf"};
        StringBuilder sb = new StringBuilder(ASSERTION_PREFIX).append("\n1");
        for (String f : fields) {
            sb.append('\n');
            Object v = claims.get(f);
            sb.append(v == null ? "" : String.valueOf(v));
        }
        return sb.toString().getBytes(StandardCharsets.UTF_8);
    }

    static Long parseMs(Object v) {
        if (v instanceof Number n) return n.longValue();
        if (v instanceof String s && !s.isBlank()) {
            try {
                return Instant.parse(s.trim()).toEpochMilli();
            } catch (Exception ignore) {
                return null;
            }
        }
        return null;
    }

    /** Verifies a server-issued assertion against pinned raw keys. Fails closed. */
    public static AssertionResult VerifyAssertion(String assertion, Map<String, byte[]> pins, String hwid) {
        if (pins == null || pins.isEmpty()) return new AssertionResult(false, "no pinned public key", null);
        String[] parts = (assertion == null ? "" : assertion).split("\\.");
        if (parts.length != 3) return new AssertionResult(false, "malformed", null);
        String payload = parts[0], sigB64 = parts[1], keyId = parts[2];

        List<byte[]> candidates = new ArrayList<>();
        for (Map.Entry<String, byte[]> e : pins.entrySet()) {
            if (keyId.isBlank() || e.getKey().equals(keyId)) candidates.add(e.getValue());
        }
        if (candidates.isEmpty()) {
            return new AssertionResult(false, "signed with key \"" + keyId + "\", which this build does not trust", null);
        }
        Map<String, Object> claims;
        byte[] signature;
        try {
            claims = (Map<String, Object>) Json.parse(new String(b64uDecode(payload), StandardCharsets.UTF_8));
            signature = b64uDecode(sigB64);
        } catch (Exception e) {
            return new AssertionResult(false, "unreadable", null);
        }

        byte[] material = claimString(claims);
        boolean ok = false;
        for (byte[] raw : candidates) {
            if (edVerify(raw, material, signature)) { ok = true; break; }
        }
        if (!ok) return new AssertionResult(false, "signature does not verify", claims);

        if (hwid != null && !hwid.isBlank() && !hwid.equals(str(claims.get("hwid")))) {
            return new AssertionResult(false, "issued for a different machine", claims);
        }
        Long nbf = parseMs(claims.get("nbf"));
        Long naf = parseMs(claims.get("naf"));
        if (nbf == null || naf == null || naf <= nbf) {
            return new AssertionResult(false, "offline window is missing or unreadable", claims);
        }
        long at = System.currentTimeMillis();
        if (at < nbf) return new AssertionResult(false, "not yet valid", claims);
        if (at > naf) return new AssertionResult(false, "offline period has run out", claims);
        Object expRaw = claims.get("exp");
        boolean hasExp = expRaw != null && !(expRaw instanceof String s && s.isBlank());
        if (hasExp) {
            Long exp = parseMs(expRaw);
            if (exp == null || at > exp) return new AssertionResult(false, "licence expired", claims);
        }
        return new AssertionResult(true, "", claims);
    }

    // ── crypto plumbing ──────────────────────────────────────────────────────

    static byte[] b64uDecode(String s) {
        return Base64.getUrlDecoder().decode(s.trim() + "===".substring((s.trim().length() + 3) % 4));
    }

    static byte[] spkiToRaw(String b64) {
        byte[] der = Base64.getMimeDecoder().decode(b64.trim());
        if (der.length != 44) {
            throw new FrostAuthError("not a usable Ed25519 public key", FrostAuthError.Codes.CONFIG, 0, false);
        }
        return Arrays.copyOfRange(der, 12, 44);
    }

    /** Rebuilds a JCA Ed25519 PublicKey from the raw 32-byte encoding.
     *  The encoding is a little-endian y coordinate with the x-parity bit in
     *  the top bit of the last byte — BigInteger reads big-endian, so bytes
     *  must be reversed and the parity bit stripped first. */
    static PublicKey rawToPublicKey(byte[] raw32) {
        try {
            boolean xOdd = (raw32[31] & 0x80) != 0;
            byte[] yBytes = raw32.clone();
            yBytes[31] &= 0x7F;
            byte[] be = new byte[32];
            for (int i = 0; i < 32; i++) be[i] = yBytes[31 - i];
            BigInteger y = new BigInteger(1, be);
            EdECPublicKeySpec spec = new EdECPublicKeySpec(NamedParameterSpec.ED25519,
                new EdECPoint(xOdd, y));
            return KeyFactory.getInstance("Ed25519").generatePublic(spec);
        } catch (Exception e) {
            throw new FrostAuthError("not a usable Ed25519 public key", FrostAuthError.Codes.CONFIG, 0, false, null, 0);
        }
    }

    static PublicKey spkiToKey(String b64) {
        return rawToPublicKey(spkiToRaw(b64));
    }

    static boolean edVerify(byte[] rawPub, byte[] message, byte[] signature) {
        try {
            PublicKey pub = rawToPublicKey(rawPub);
            Signature sig = Signature.getInstance("Ed25519");
            sig.initVerify(pub);
            sig.update(message);
            return sig.verify(signature);
        } catch (Exception e) {
            return false;
        }
    }

    // ── machine identity ─────────────────────────────────────────────────────

    static String osName() {
        String os = System.getProperty("os.name", "").toLowerCase(Locale.ROOT);
        if (os.contains("win")) return "windows";
        if (os.contains("mac") || os.contains("darwin")) return "darwin";
        if (os.contains("linux")) return "linux";
        return os;
    }

    private String machine() {
        synchronized (lock) {
            if (machineId != null) return machineId;
            if (hwOverride != null && !hwOverride.isBlank()) {
                machineId = hwOverride;
                return machineId;
            }
            String scope = app != null && str(app.get("ownerId")) != null && !str(app.get("ownerId")).isBlank()
                ? str(app.get("ownerId")) : owner;
            machineId = hardwareId(scope);
            return machineId;
        }
    }

    /** Scoped SHA-256 of the machine id — the raw id never leaves the device. */
    public static String hardwareId(String scope) {
        String s = (scope == null || scope.isBlank()) ? "frostauth" : scope;
        return sha256Hex(s + "|" + rawMachineId());
    }

    static volatile String machineCache;

    static String rawMachineId() {
        String cached = machineCache;
        if (cached != null) return cached;
        String found = null;
        try {
            switch (osName()) {
                case "windows" -> {
                    Process p = Runtime.getRuntime().exec(new String[]{
                        "reg", "query", "HKLM\\SOFTWARE\\Microsoft\\Cryptography", "/v", "MachineGuid"});
                    String out = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
                    p.waitFor(5, TimeUnit.SECONDS);
                    for (String line : out.split("\n")) {
                        int i = line.indexOf("REG_SZ");
                        if (i >= 0) { found = line.substring(i + 6).trim(); break; }
                    }
                }
                case "darwin" -> {
                    Process p = Runtime.getRuntime().exec(new String[]{
                        "ioreg", "-rd1", "-c", "IOPlatformExpertDevice"});
                    String out = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
                    p.waitFor(5, TimeUnit.SECONDS);
                    for (String line : out.split("\n")) {
                        int i = line.indexOf("\"IOPlatformUUID\"");
                        if (i >= 0) {
                            int eq = line.indexOf("\" = \"");
                            if (eq >= 0) {
                                found = line.substring(eq + 5).replace("\"", "").trim();
                                break;
                            }
                        }
                    }
                }
                case "linux" -> {
                    for (String path : new String[]{"/etc/machine-id", "/var/lib/dbus/machine-id"}) {
                        try {
                            String v = Files.readString(Path.of(path)).trim();
                            if (!v.isBlank()) { found = v; break; }
                        } catch (Exception ignore) { /* try next */ }
                    }
                }
                default -> { /* fall through to fallback */ }
            }
        } catch (Exception ignore) { /* fall through to fallback */ }
        String id = (found == null || found.isBlank())
            ? "fallback:" + hostname() + ":" + safeUser() + ":" + osName()
            : found;
        machineCache = id;
        return id;
    }

    static String hostname() {
        try { return InetAddress.getLocalHost().getHostName(); }
        catch (Exception e) { return "unknown"; }
    }

    static String safeUser() {
        return System.getProperty("user.name", "unknown");
    }

    static String sha256Hex(String input) {
        try {
            byte[] d = MessageDigest.getInstance("SHA-256").digest(input.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder();
            for (byte b : d) sb.append(String.format("%02x", b));
            return sb.toString();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    static String facet(String v) {
        return sha256Hex(v).substring(0, 32);
    }

    private Map<String, Object> hardwareExtra() {
        if (!collectHardware) return Map.of();
        try {
            String cpu = "unknown";
            try {
                switch (osName()) {
                    case "windows" -> {
                        Process p = Runtime.getRuntime().exec(new String[]{
                            "reg", "query", "HKLM\\HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0",
                            "/v", "ProcessorNameString"});
                        String out = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
                        p.waitFor(5, TimeUnit.SECONDS);
                        for (String line : out.split("\n")) {
                            int i = line.indexOf("REG_SZ");
                            if (i >= 0) { cpu = line.substring(i + 6).trim(); break; }
                        }
                    }
                    case "darwin" -> {
                        Process p = Runtime.getRuntime().exec(new String[]{
                            "sysctl", "-n", "machdep.cpu.brand_string"});
                        cpu = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8).trim();
                    }
                    case "linux" -> {
                        for (String line : Files.readAllLines(Path.of("/proc/cpuinfo"))) {
                            if (line.startsWith("model name")) {
                                int i = line.indexOf(':');
                                if (i >= 0) cpu = line.substring(i + 1).trim();
                                break;
                            }
                        }
                    }
                    default -> { /* keep unknown */ }
                }
            } catch (Exception ignore) { /* keep unknown */ }

            String host = hostname();
            List<Map<String, String>> components = new ArrayList<>();
            components.add(Map.of("n", "cpu", "v", facet(cpu + "|" + Runtime.getRuntime().availableProcessors())));
            components.add(Map.of("n", "ram", "v", facet("unknown")));
            components.add(Map.of("n", "arch", "v", facet(System.getProperty("os.arch", "unknown"))));
            components.add(Map.of("n", "platform", "v", facet(osName())));
            components.add(Map.of("n", "host", "v", facet(host)));
            // MAC facet is intentionally omitted in the Java port: enumerating
            // NICs is slow and the server treats facets as advisory-only.

            Map<String, Object> out = new LinkedHashMap<>();
            out.put("components", components);
            out.put("virtual", cpu.toLowerCase(Locale.ROOT).matches(".*(vmware|virtualbox|vbox|qemu|kvm|xen|hyper-v|hyperv|parallels|bhyve|virtual machine|innotek).*"));
            return out;
        } catch (Exception e) {
            return Map.of();
        }
    }

    // ── DNS-hijack tripwire ──────────────────────────────────────────────────

    private void assertRealHost() {
        if (allowPrivateDns) return;
        try {
            URI uri = URI.create(baseUrl);
            String host = uri.getHost();
            if (host == null || host.isBlank()) return;
            String bare = host.replaceAll("^\\[|\\]$", "");
            if (bare.equals("localhost") || bare.equals("127.0.0.1") || bare.equals("::1")) return;
            if (bare.matches("[\\d.]+") || bare.contains(":")) return; // IP literal
            for (InetAddress addr : InetAddress.getAllByName(bare)) {
                if (addr.isLoopbackAddress() || addr.isSiteLocalAddress()
                    || addr.isLinkLocalAddress() || addr.isAnyLocalAddress()) {
                    throw new FrostAuthError(
                        "\"" + bare + "\" resolves to loopback or private space (" + addr.getHostAddress()
                            + ") — this is what a hosts-file hijack or licence emulator looks like. Refusing to continue.",
                        FrostAuthError.Codes.NETWORK, 0, false);
                }
            }
        } catch (FrostAuthError e) {
            throw e;
        } catch (Exception e) {
            throw new FrostAuthError("Cannot resolve the licence server host — refusing to continue",
                FrostAuthError.Codes.NETWORK, 0, false, null, 0);
        }
    }

    // ── transport ────────────────────────────────────────────────────────────

    /** One request, parsed as plain JSON (catalog shape, no envelope). */
    private Map<String, Object> requestRaw(String method, String path, Map<String, Object> body) {
        Round round = oneRound(method, path, body, null);
        try {
            return round.body.isBlank() ? Map.of() : Json.parseObject(round.body);
        } catch (Exception e) {
            return Map.of();
        }
    }

    private void requireInit() {
        synchronized (lock) {
            if (!initialized) {
                throw new FrostAuthError("Call init() before anything else", FrostAuthError.Codes.NOT_INITIALIZED, 0, false);
            }
        }
    }

    private String token() {
        if (session == null) return null;
        return str(session.get("token"));
    }

    private Map<String, Object> authed(String method, String path, Map<String, Object> body) {
        String t;
        synchronized (lock) { t = token(); }
        if (t == null || t.isBlank()) {
            throw new FrostAuthError("This call needs a session — activate or sign in first",
                FrostAuthError.Codes.NOT_ACTIVATED, 0, false);
        }
        return requestEnvelope(method, path, body, t);
    }

    private void adopt(Map<String, Object> data) {
        // caller holds lock
        if (data == null) return;
        Object sess = data.get("session");
        if (sess instanceof Map<?, ?> s && s.get("token") != null) {
            @SuppressWarnings("unchecked")
            Map<String, Object> sm = (Map<String, Object>) s;
            session = sm;
        }
        if (data.get("license") instanceof Map) license = castMap(data.get("license"));
        if (data.get("product") instanceof Map) productInfo = castMap(data.get("product"));
        if (data.get("device") instanceof Map) device = castMap(data.get("device"));
        if (data.get("user") instanceof String s && !s.isBlank()) user = s;
        if (data.get("account") instanceof Map) account = castMap(data.get("account"));
        if (data.get("subscriptions") instanceof List<?> l) subscriptions = new ArrayList<>(l);
        if (data.get("offline") instanceof Map<?, ?> off) {
            Object a = ((Map<?, ?>) off).get("assertion");
            if (a instanceof String s && !s.isBlank()) {
                assertion = s;
                Object na = ((Map<?, ?>) off).get("notAfter");
                offlineUntil = na instanceof String s2 ? s2 : null;
            }
        }
        if (productInfo != null && Boolean.TRUE.equals(productInfo.get("updateAvailable"))) {
            String latest = str(productInfo.get("latest"));
            if (latest.isBlank()) latest = str(productInfo.get("version"));
            if (onUpdateAvailable != null) onUpdateAvailable.accept(version, latest);
        }
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> castMap(Object o) {
        return (Map<String, Object>) o;
    }

    private Map<String, Object> sendValidate() {
        String hwid = machine();
        Map<String, Object> payload = new LinkedHashMap<>();
        String t;
        String k;
        synchronized (lock) { t = token(); k = storedKey; }
        if (t != null && !t.isBlank()) {
            payload.put("token", t);
        } else if (k != null && !k.isBlank()) {
            payload.put("key", k);
        } else {
            throw new FrostAuthError("activate before validating", FrostAuthError.Codes.NOT_ACTIVATED, 0, false);
        }
        payload.put("hwid", hwid);
        payload.put("appVersion", version);
        payload.put("os", osName());
        return requestEnvelope("POST", "/api/v1/validate", payload);
    }

    /** One retry-aware request; returns response.data on success, throws otherwise. */
    private Map<String, Object> requestEnvelope(String method, String path, Map<String, Object> body) {
        return requestEnvelope(method, path, body, null);
    }

    private Map<String, Object> requestEnvelope(String method, String path, Map<String, Object> body, String token) {
        FrostAuthError last = null;
        for (int attempt = 0; attempt <= retries; attempt++) {
            if (attempt > 0) sleep(random.nextInt(Math.min(300 * (1 << attempt), 15_000)) + 1);
            Round round;
            try {
                round = oneRound(method, path, body, token);
            } catch (FrostAuthError e) {
                if (FrostAuthError.Codes.SIGNATURE.equals(e.code)) throw e; // never retry a bad signature
                last = e;
                continue;
            }
            if (round.status == 429) {
                int wait = 2;
                String ra = round.headers.firstValue("retry-after").orElse("");
                try {
                    int parsed = Integer.parseInt(ra.trim());
                    if (parsed > 0 && parsed <= MAX_RETRY_AFTER_SECONDS) wait = parsed;
                } catch (NumberFormatException ignore) { /* default 2 */ }
                last = new FrostAuthError("Rate limited by the licence server",
                    FrostAuthError.Codes.RATE_LIMITED, 429, true, null, wait);
                if (attempt < retries) { sleep(wait * 1000L); continue; }
                throw last;
            }
            Map<String, Object> payload;
            try {
                payload = round.body.isBlank() ? Map.of() : Json.parseObject(round.body);
            } catch (Exception e) {
                payload = Map.of();
            }
            if (round.status >= 500) {
                Object ec = resp(payload, "errorCode");
                if (ec instanceof String s && !s.isBlank()) {
                    String msg = resp(payload, "message") instanceof String m && !m.isBlank()
                        ? m : "Request failed (" + round.status + ")";
                    throw new FrostAuthError(msg, s, round.status, false);
                }
                last = new FrostAuthError(
                    resp(payload, "message") instanceof String m && !m.isBlank()
                        ? m : "The licence server is having trouble",
                    FrostAuthError.Codes.SERVER_ERROR, round.status, true);
                continue;
            }
            Object errFlag = payload.get("error");
            boolean hasError = !(errFlag == null || Boolean.FALSE.equals(errFlag));
            if (hasError || round.status < 200 || round.status > 299) {
                String code = resp(payload, "errorCode") instanceof String s && !s.isBlank() ? s
                    : errFlag instanceof String s2 && !s2.isBlank() ? s2
                    : FrostAuthError.Codes.SERVER_ERROR;
                String msg = resp(payload, "message") instanceof String m && !m.isBlank()
                    ? m : "Request failed (" + round.status + ")";
                throw new FrostAuthError(msg, code, round.status, false);
            }
            Object data = resp(payload, "data");
            Map<String, Object> out = data instanceof Map ? castMap(data) : new LinkedHashMap<>();
            synchronized (lock) { adopt(out); }
            return out;
        }
        throw last != null ? last : new FrostAuthError("Request failed", FrostAuthError.Codes.NETWORK, 0, true);
    }

    private static Object resp(Map<String, Object> payload, String field) {
        Object r = payload.get("response");
        if (r instanceof Map<?, ?> m) {
            Object v = m.get(field);
            if (v instanceof String s) return s;
            if (v != null) return v;
        }
        // catalog-shaped errors keep message at the top level
        if ("message".equals(field)) return payload.get("message");
        return null;
    }

    private record Round(int status, String body, java.net.http.HttpHeaders headers) {}

    private Round oneRound(String method, String path, Map<String, Object> body, String token) {
        byte[] nonce = new byte[16];
        random.nextBytes(nonce);
        String nonceB64 = Base64.getUrlEncoder().withoutPadding().encodeToString(nonce);
        long now = System.currentTimeMillis();

        HttpRequest.Builder rb = HttpRequest.newBuilder()
            .uri(URI.create(baseUrl + path))
            .timeout(timeout)
            .header("Content-Type", "application/json")
            .header("Accept", "application/json")
            .header("User-Agent", "frostauth-sdk-java/" + SDK_VERSION + " (" + osName() + ")")
            .header("X-Frost-Nonce", nonceB64)
            .header("X-Frost-Timestamp", String.valueOf(now));
        if (body != null) {
            rb.method(method, HttpRequest.BodyPublishers.ofString(Json.write(body), StandardCharsets.UTF_8));
        } else {
            rb.method(method, HttpRequest.BodyPublishers.noBody());
        }
        if (token != null && !token.isBlank()) rb.header("Authorization", "Bearer " + token);

        HttpResponse<String> resp;
        try {
            resp = http.send(rb.build(), HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
        } catch (Exception e) {
            boolean timedOut = e instanceof java.net.http.HttpTimeoutException;
            throw new FrostAuthError(
                timedOut ? "Request timed out after " + timeout.toSeconds() + "s"
                    : "Could not reach the licence server",
                timedOut ? FrostAuthError.Codes.TIMEOUT : FrostAuthError.Codes.NETWORK, 0, true);
        }

        String sig = resp.headers().firstValue("x-frost-signature").orElse("");
        if (resp.statusCode() != 429 || !sig.isBlank()) {
            verifyResponse(resp, nonceB64, method, path);
        }
        return new Round(resp.statusCode(), resp.body(), resp.headers());
    }

    private void verifyResponse(HttpResponse<String> resp, String nonce, String method, String path) {
        Map<String, PublicKey> currentKeys;
        synchronized (lock) { currentKeys = keys; }
        if (currentKeys.isEmpty()) return;

        int status = resp.statusCode();
        java.net.http.HttpHeaders h = resp.headers();
        String sig = h.firstValue("x-frost-signature").orElse("");
        String ts = h.firstValue("x-frost-timestamp").orElse("");
        if (sig.isBlank() || ts.isBlank()) throw sigReject(status, "it was not signed");
        if (!nonce.equals(h.firstValue("x-frost-nonce").orElse(""))) throw sigReject(status, "it answered a different request");
        long tsN;
        try {
            tsN = Long.parseLong(ts.trim());
        } catch (NumberFormatException e) {
            throw sigReject(status, "bad timestamp");
        }
        if (Math.abs(System.currentTimeMillis() - tsN) > MAX_SIGNATURE_SKEW_MS) throw sigReject(status, "it was signed too long ago");
        String keyId = h.firstValue("x-frost-key-id").orElse("");
        List<PublicKey> candidates = new ArrayList<>();
        for (Map.Entry<String, PublicKey> e : currentKeys.entrySet()) {
            if (keyId.isBlank() || e.getKey().equals(keyId)) candidates.add(e.getValue());
        }
        if (candidates.isEmpty()) throw sigReject(status, "it was signed with key \"" + keyId + "\", which this build does not trust");

        String raw = resp.body();
        String material = ts + "\n" + nonce + "\n" + method.toUpperCase(Locale.ROOT) + "\n" + path
            + "\n" + status + "\n" + raw;
        byte[] signature;
        try {
            signature = b64uDecode(sig);
        } catch (Exception e) {
            throw sigReject(status, "bad signature encoding");
        }
        for (PublicKey key : candidates) {
            try {
                Signature verifier = Signature.getInstance("Ed25519");
                verifier.initVerify(key);
                verifier.update(material.getBytes(StandardCharsets.UTF_8));
                if (verifier.verify(signature)) return;
            } catch (Exception ignore) { /* try next key */ }
        }
        throw sigReject(status, "the signature did not match");
    }

    private static FrostAuthError sigReject(int status, String why) {
        return new FrostAuthError("Refusing an unverified answer from the licence server: " + why,
            FrostAuthError.Codes.SIGNATURE, status, false);
    }

    // ── small helpers ────────────────────────────────────────────────────────

    private static String str(Object o) { return o == null ? "" : String.valueOf(o); }

    private static String trunc(String s, int n) {
        return s.length() <= n ? s : s.substring(0, n);
    }

    private static String enc(String s) {
        return URLEncoder.encode(s, StandardCharsets.UTF_8);
    }

    private static void sleep(long ms) {
        try { Thread.sleep(ms); } catch (InterruptedException e) { Thread.currentThread().interrupt(); }
    }
}
