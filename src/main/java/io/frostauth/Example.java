package io.frostauth;

import java.io.File;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.List;
import java.util.Map;
import java.util.Scanner;

/** FrostAuth Java SDK — console example. Mirrors sdk/example.mjs output. */
public final class Example {

    /** Locale-style timestamp, e.g. 9/16/2026, 6:08:02 PM (system zone). */
    private static final DateTimeFormatter LOC =
        DateTimeFormatter.ofPattern("M/d/yyyy, h:mm:ss a");

    private static String loc(Object iso) {
        if (iso == null || iso.toString().isBlank()) return "unknown";
        try {
            String s = iso.toString().trim();
            // Server sometimes sends millis-less ISO ("2026-09-15T18:09:11Z").
            // Instant.parse needs the fraction, OffsetDateTime doesn't care.
            Instant instant;
            try {
                instant = Instant.parse(s);
            } catch (DateTimeParseException e) {
                instant = OffsetDateTime.parse(s).toInstant();
            }
            return instant.atZone(ZoneId.systemDefault()).format(LOC);
        } catch (Exception e) {
            return "unknown";
        }
    }

    public static void main(String[] args) {
        FrostAuth app = new FrostAuth(
            "0809wkVP",
            "33abf48a-8e33-4df5-a4bd-d79195704d52",
            "1.0.2"
            // , "https://api.frostauth.cc"
        );

        try {
            app.init();
        } catch (FrostAuthError e) {
            fail(e);
        }

        System.out.println("[1] Login\n[2] Register\n[3] License\n[4] Upgrade");
        Scanner in = new Scanner(System.in);
        System.out.print("Select an option: ");
        String option = in.nextLine().trim();

        try {
            switch (option) {
                case "1" -> app.login(ask(in, "Username: "), ask(in, "Password: "), null, null, null);
                case "2" -> app.register(ask(in, "License: "), ask(in, "Username: "), ask(in, "Password: "), null, null);
                case "3" -> app.activate(ask(in, "License: "), null, null);
                case "4" -> {
                    String username = ask(in, "Username: ");
                    String password = ask(in, "Password: ");
                    String license = ask(in, "License: ");
                    app.upgrade(username, password, license);
                    System.out.println("Upgraded. Sign in to use the new licence.");
                    app.login(username, password, null, null, null);
                }
                default -> {
                    System.out.println("Invalid option selected.");
                    return;
                }
            }
        } catch (FrostAuthError e) {
            fail(e);
        }

        dashboard(app);
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> section(Map<String, Object> snap, String key) {
        if (snap.get(key) instanceof Map<?, ?> m) {
            return (Map<String, Object>) m;
        }
        return Map.of();
    }

    private static String when(Object iso) {
        if (iso == null || iso.toString().isBlank()) return "—";
        String s = loc(iso);
        return "unknown".equals(s) ? "—" : s;
    }

    private static Integer daysLeft(String expiry) {
        try {
            Instant e;
            try {
                e = Instant.parse(expiry.trim());
            } catch (DateTimeParseException ex) {
                e = OffsetDateTime.parse(expiry.trim()).toInstant();
            }
            long diff = e.getEpochSecond() - Instant.now().getEpochSecond();
            if (diff <= 0) return 0;
            return (int) ((diff + 86399) / 86400);
        } catch (Exception ex) {
            return null;
        }
    }

    /**
     * Snapshot-backed profile readout. Everything here comes from the local
     * snapshot (populated by activate/register/login on every plan), so it works
     * with or without a session token — unlike appData/fetchOnline, which are
     * session-backed and fail on plans without tokenSystem.
     * Only prints fields the backend actually returns (licenseView + accountView
     * + device + product) — no invented email/key/plan lookups.
     */
    private static void showUser(Map<String, Object> snap) {
        Map<String, Object> license = section(snap, "license");
        Map<String, Object> account = section(snap, "account");
        Map<String, Object> device = section(snap, "device");
        Map<String, Object> product = section(snap, "product");

        Object userObj = snap.get("user");
        String who = userObj != null ? userObj.toString() : "";
        if (who.isBlank()) {
            Object au = account.get("username");
            who = au != null ? au.toString() : "";
        }
        if (who.isBlank()) who = "unknown";

        String tier = strOrUnknown(license, "tier");
        if ("unknown".equals(tier)) tier = "starter";
        String state = strOrUnknown(license, "status");

        String expiry = strOrUnknown(license, "expiresAt");
        if ("unknown".equals(expiry)) expiry = null;
        if (expiry == null && snap.get("subscriptions") instanceof List<?> rawSubs) {
            for (Object o : rawSubs) {
                if (o instanceof Map<?, ?> sm && sm.get("expiresAt") != null) {
                    expiry = String.valueOf(sm.get("expiresAt"));
                    break;
                }
            }
        }
        String validLine = "never";
        if (expiry != null) {
            validLine = when(expiry);
            Integer dl = daysLeft(expiry);
            if (dl != null) validLine += " (" + dl + "d left)";
        }

        String prodName = strOrUnknown(product, "name");
        if ("unknown".equals(prodName)) prodName = "—";
        String prodVer = strOrUnknown(product, "version");
        String prodLine = prodName + ("unknown".equals(prodVer) ? "" : " v" + prodVer);

        Object du = license.get("devicesUsed");
        String used = du != null ? String.valueOf(du) : "—";
        String devicesLine = used;
        if (Boolean.TRUE.equals(license.get("unlimitedDevices"))) {
            devicesLine = used + " (unlimited)";
        } else if (license.get("deviceLimit") != null) {
            devicesLine = used + " / " + license.get("deviceLimit");
        }

        String devLine = strOrUnknown(device, "id");
        if ("unknown".equals(devLine)) devLine = "—";
        String ipLine = strOrUnknown(account, "lastIp");
        if ("unknown".equals(ipLine)) ipLine = "—";

        System.out.println("");
        System.out.println("Signed in as " + who);
        System.out.println("----------------------------------------------");
        System.out.println("  Licence ..... " + state + " (" + tier + ")");
        System.out.println("  IP Address .. " + ipLine);
        System.out.println("  Product ..... " + prodLine);
        System.out.println("  Devices ..... " + devicesLine);
        System.out.println("  Valid Until . " + validLine);
        System.out.println("  Device Id ... " + devLine);
        System.out.println("  First Seen .. " + when(account.get("createdAt")));
        System.out.println("  Last Seen ... " + when(account.get("lastLoginAt")));
        System.out.println("----------------------------------------------");
    }

    private static void dashboard(FrostAuth app) {
        // Snapshot-backed profile only. Session-backed reads (appData/online)
        // are plan-gated (tokenSystem: Developer/Pro) and print "unknown" on
        // other plans, so they are not shown here at all.
        Map<String, Object> snap = app.snapshot();

        showUser(snap);
        System.out.println("");

        @SuppressWarnings("unchecked")
        List<Map<String, Object>> subs =
            (List<Map<String, Object>>) snap.getOrDefault("subscriptions", List.of());
        for (int i = 0; i < subs.size(); i++) {
            Map<String, Object> sub = subs.get(i);
            String tier = (String) sub.get("tier");
            String name = tier != null && !tier.isBlank() ? tier : (String) sub.get("status");
            String expiry = sub.get("expiresAt") != null ? loc(sub.get("expiresAt")) : "never";
            System.out.printf("[%d/%d] | Subscription: %s - Expiry: %s%n", i + 1, subs.size(), name, expiry);
        }

        System.out.println("Created at: " + loc(sub(snap, "account", "createdAt", null)));
        System.out.println("Last Login: " + loc(sub(snap, "account", "lastLoginAt", null)));
        String firstExpiry = "never";
        for (Map<String, Object> sub : subs) {
            if (sub.get("expiresAt") != null) {
                firstExpiry = loc(sub.get("expiresAt"));
                break;
            }
        }
        System.out.println("Expires: " + firstExpiry);

        try {
            Map<String, Object> res = app.webhook("discord", "",
                "{\"content\":\"Hello from FrostAuth\"}", "");
            System.out.println("\nWebhook test: upstream " + res.get("status") + " (ok: " + res.get("ok") + ")");
        } catch (FrostAuthError e) {
            System.out.println("\nWebhook test failed: " + (e.code == null ? "" : e.code + " ") + e.getMessage());
        }

        // Build-hash extra: hash THIS file's contents when the product has
        // CHECK HASH enabled; pass it to activate/register/login.
        try {
            byte[] self = Files.readAllBytes(new File(Example.class
                .getProtectionDomain().getCodeSource().getLocation().toURI()).toPath());
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(self);
            StringBuilder hex = new StringBuilder();
            for (byte b : digest) hex.append(String.format("%02x", b));
            System.out.println("\nBuild hash (this file):");
            System.out.println("  " + hex);
            System.out.println("  Pass it to activate/register/login (hash parameter) when the product requires it.");
        } catch (Exception ignore) { /* best-effort */ }

        System.out.println("\nClosing app in 10 seconds...");
        try { Thread.sleep(10_000); } catch (InterruptedException ignore) { /* exit */ }
        try {
            app.logout();
        } catch (FrostAuthError ignore) { /* already closed */ }
    }

    private static String strOrUnknown(Map<String, Object> map, String key) {
        if (map == null) return "unknown";
        Object v = map.get(key);
        return v == null ? "unknown" : String.valueOf(v);
    }

    private static String sub(Map<String, Object> snap, String section, String key, String dflt) {
        if (snap.get(section) instanceof Map<?, ?> m && m.get(key) != null) {
            return String.valueOf(m.get(key));
        }
        return dflt;
    }

    private static String ask(Scanner in, String prompt) {
        System.out.print(prompt);
        return in.nextLine().trim();
    }

    private static void fail(FrostAuthError e) {
        System.out.println("An error occurred: " + e.getMessage());
        System.exit(1);
    }
}
