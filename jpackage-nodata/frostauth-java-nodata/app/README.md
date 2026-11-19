# FrostAuth-Java-Example 🌟

FrostAuth Java example SDK for https://www.frostauth.cc license key API auth.

This example ships the SDK source directly — the `io.frostauth` package
(`FrostAuth.java` + `FrostAuthError.java` + `Json.java`). Copy the package into
your project, mirror `Example.java`, and you're integrated. Zero dependencies
(JDK 17+, built-in JSON parser included).

## Bugs

If you're running this example with no significant changes and something's broken,
open an issue with your FrostAuth version, JDK version (`java -version`), and
the exact error text.

We do **NOT** provide support for wiring FrostAuth into your project. If the
build steps below don't make sense yet, learn some Java first
(docs.oracle.com/YouTube), then come back.

## Security practices

* Ship releases through a protector/obfuscator (Stringer, Zelix, VMProtect on
the launcher) and put license checks behind their markers — plain class files
decompile in seconds.
* Run frequent integrity checks so patched memory kills the session instead of
granting access.
* Never write a downloaded file to disk if you don't want the user to have it.
Execute in memory and wipe the buffer the moment you're done.
* Treat every client answer as advisory. The server re-checks the license on
each call — don't add a local `isValid` boolean that bypasses it.

FrostAuth signs every response and pins the server key, but no API survives a
client that trusts itself. Obfuscation + integrity checks stop tampering; the
API stops key sharing.

## Copyright License

Copyright (c) 2026 FrostAuth. All rights reserved.

* You may not offer this SDK (or a modified copy of it) to third parties as a
hosted or managed service that reproduces any substantial part of FrostAuth.
* You may not move, change, disable, or circumvent the license-key
functionality in the SDK, and you may not remove or obscure any license-key
enforcement it performs.
* You may not remove or obscure any licensing, copyright, or attribution
notices in the SDK files.

Thank you for your compliance — this SDK is a large body of work, and keeping
the notices intact is what keeps it free.

## What is FrostAuth?

FrostAuth is a cloud licensing platform that protects your software from piracy
and unauthorized access. Hardware-locked licenses, secure auth, real-time
analytics, and a dashboard your customers never see. Client SDKs for Java (this
repo), C++, C#, Python, Go, Rust, and JavaScript. Come ask questions on
Discord: https://www.frostauth.cc/discord

## Requirements

* JDK 17+ (`java.net.http`, EdDSA). No Maven/Gradle needed — but a `pom.xml`
(`cc.frostauth:frostauth-sdk:1.0.0`) is included if you want it.

## Build

```bash
cd FrostAuth-Java-Example
javac -d out $(find src/main/java -name "*.java")   # Windows PowerShell: javac -d out (Get-ChildItem -Recurse src/main/java/*.java).FullName
java -cp out io.frostauth.Example
```

Or package the runnable jar (needs `jar` on PATH — full path is usually
`C:/Program Files/Java/jdk-XX/bin/jar.exe`):

```bash
jar cfe frostauth-java-example.jar io.frostauth.Example -C out .
java -jar frostauth-java-example.jar
```

## `FrostAuth` instance definition

Open your FrostAuth dashboard, pick your product, and copy the three values
into [`src/main/java/io/frostauth/Example.java`](src/main/java/io/frostauth/Example.java):

```java
FrostAuth app = new FrostAuth(
    "YOUR-OWNER-ID",    // dashboard → product → owner id
    "YOUR-PRODUCT-ID",  // dashboard → product → product id
    "1.0.0"             // must match the version you ship
);
```

## Initialize application

You must call this before anything else. It fetches the public catalog and
pins the server's signing key (TOFU) — every later response is Ed25519-checked
against it, so a MITM serving a fake key aborts here instead of later.

```java
app.init();
```

## Display application information

```java
Map<String, Object> appData = app.appData();
Map<?, ?> prod = (Map<?, ?>) appData.get("product");
System.out.println("App Version: " + prod.get("version"));
System.out.println("Customer panel: enabled");
```

## Check session validation

Re-checks the license/session with the server. Falls back from a stale session
token to the stored license key once.

```java
app.validate(); // throws FrostAuthError when the session is dead — exit, don't continue
```

## Check blacklist status

Whether this device/IP/key is blacklisted. Optional: the server already
refuses blacklisted callers on login/register, so this is just an early exit
for clients that want to close before showing UI.

```java
app.checkBlacklist(); // throws on block — exit
```

## Login with username/password

```java
Map<String, Object> snap = app.login(username, password, twofa, buildHash, label);
```

(`twofa`/`buildHash`/`label` may be `null`.)

## Register with username/password/key

```java
Map<String, Object> snap = app.register(key, username, password, buildHash, label);
```

## Upgrade user with key

Attaches a license key to an existing app user (adds time). Unlike login and
register this opens **no session** — sign the user in after a successful
upgrade.

```java
app.upgrade(username, password, key);
System.out.println("Upgraded. Sign in to use the new licence.");
Map<String, Object> snap = app.login(username, password, null, null, null);
```

## Login with just license key

For key-only products. Binds the key to this machine and opens a session —
no username needed.

```java
Map<String, Object> snap = app.activate(key, buildHash, label);
```

## User Data

Everything about the current session lives in the snapshot:

```java
Map<String, Object> snap = app.session();
System.out.println("Username: " + snap.get("user"));
Map<?, ?> account = (Map<?, ?>) snap.get("account");
Map<?, ?> device = (Map<?, ?>) snap.get("device");
System.out.println("IP: " + account.get("lastIp"));
System.out.println("Device Id: " + device.get("id"));
```

## Check subscription of user

Gate features by tier. Compare against the tier name you configured on the
dashboard — exact match, case-insensitive on the server side.

```java
boolean pro = ((List<?>) snap.get("subscriptions")).stream()
    .anyMatch(s -> "pro".equalsIgnoreCase(String.valueOf(((Map<?, ?>) s).get("tier"))));
if (!pro) { System.out.println("This feature needs a Pro subscription."); return; }
```

## Application variables

Server-side strings, global for all users (feature flags, MOTD, config).
Read-only from the client; edit them on the dashboard. Tier- and
version-gated server-side.

```java
System.out.println("MOTD: " + app.variable("maintenance_message"));
```

## User Variables

Per-user key/value pairs. Read and write them unless the operator marked one
read-only (balances, ranks — server-writable only).

```java
System.out.println(app.listVars());          // every variable on this user
System.out.println(app.getVar("theme"));     // one variable's value
app.setVar("theme", "dark");                 // write it back
```

## Application Logs

Ship an event to the operator log. Good for anti-debug alerts and crash
breadcrumbs. If the operator set a Discord webhook, it lands there instead of
the dashboard (dashboard logs rotate after 30 days).

```java
app.log("client started, integrity check passed");
```

## Ban the user

Blacklists the HWID + IP. Call it when your integrity checks catch tampering.
Only works after login. Ends the local session either way.

```java
app.ban("debugger detected"); // reason shows on next login + dashboard
```

## Server-sided webhooks

Fire an operator-configured webhook by id. The destination URL lives on the
server — the client only supplies params/body, so secrets never ship in your
binary. Tier-gated like files/variables.

```java
Map<String, Object> res = app.webhook("discord", "", "{\"content\":\"Hello from FrostAuth\"}", null);
System.out.println("upstream: " + res.get("status") + " ok: " + res.get("ok"));
```

## Download file

> Currently disabled server-side (route unmounted). `file()` throws
> `File downloads are disabled on this server` until file storage ships. The
> snippet below is the integration pattern for when it lands.

```java
byte[] blob = app.file("loader");
Files.write(Path.of("loader.bin"), blob);
```

## Changing username

Lets a signed-in user rename themselves (password re-checked server-side).

```java
Map<String, Object> res = app.changeUsername(newName, password);
System.out.println("Renamed to " + res.get("username"));
```

## Heartbeat & offline

`validate()` on a timer keeps the session fresh. The SDK caches a signed
offline assertion — when the network drops, `checkOffline()` verifies it
locally so the app keeps working inside the grace window.

```java
app.onOffline = (err, secs, verified) -> System.out.println("offline: " + secs);
app.startHeartbeat(null); // server cadence until stop/close
// ...
var off = app.checkOffline();
if (!off.ok()) System.out.println("offline: " + off.reason());
// ...
app.stopHeartbeat();
app.close();
```

## SDK layout

* `src/main/java/io/frostauth/` — `FrostAuth.java`, `FrostAuthError.java`,
`Json.java` (built-in parser, zero deps). Copy the package.
* `Example.java` — the interactive demo this README walks through.
