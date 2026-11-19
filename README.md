# FrostAuth-Java-Example 🌟

Java example for the [FrostAuth license key API](https://www.frostauth.cc/).

Copy the `io.frostauth` package into your project. It uses the JDK's HTTP and Ed25519 APIs and includes a JSON parser. Run `Example.java` to try the console flow.

## Bugs

Open an issue if you can reproduce the failure with the example. Include your FrostAuth SDK version, `java -version`, and the exact error. Remove license keys and tokens before posting.

## Security practices

- If you use VMProtect or Themida, put the protector's markers around the license checks.
- Run integrity checks during the session. End the session if a check detects tampering.
- Keep files you need to protect on the server. Clear temporary buffers when the app is done with them.
- Use the API to recheck licenses and enforce access to server resources there. A local `isValid` flag alone can't enforce access.

## Copyright License

Copyright (c) 2026 FrostAuth. All rights reserved.

This SDK is distributed under Elastic License 2.0. See [LICENSE](LICENSE).

## What is FrostAuth?

FrostAuth is a cloud licensing API with device-bound keys, app accounts, and a dashboard for managing licenses and tracking activations. SDKs are available for C++, C#, Go, Java, JavaScript, Python, and Rust. For product questions, join the [FrostAuth Discord](https://www.frostauth.cc/discord).

## Requirements

Install JDK 17 or newer and Apache Maven. Check that your terminal can find both:

```powershell
java -version
mvn -version
```

The SDK has no external runtime dependencies. Its Maven coordinates are `cc.frostauth:frostauth-sdk:1.0.0`.

## Build

Open a terminal in the directory containing `pom.xml`. To run the console example, first set the owner ID, product ID, and app version in `src/main/java/io/frostauth/Example.java`. To build only the library, run Maven with the default example settings.

```powershell
mvn clean package
```

Maven writes `target/frostauth-sdk-1.0.0.jar` and includes the SDK license. The `target/` folder is ignored by Git.

Run the console example from PowerShell:

```powershell
java -cp .\target\frostauth-sdk-1.0.0.jar io.frostauth.Example
```

On Linux or macOS, use a forward slash in the JAR path:

```bash
java -cp target/frostauth-sdk-1.0.0.jar io.frostauth.Example
```

The Java SDK workflow runs a clean Maven build on GitHub and checks that the JAR contains both the SDK and the license.

## `FrostAuth` instance definition

Copy the owner ID and product ID from the FrostAuth dashboard into `src/main/java/io/frostauth/Example.java`. Set the version you plan to ship.

```java
FrostAuth app = new FrostAuth(
    "0809y7MP",                                  // dashboard → product → owner id
    "33abf48a-8e33-4df5-a4bd-d79195704d52",      // dashboard → product → product id
    "1.0.0"                                      // must match the version you ship
);
```

## Initialize application

Call `init()` first. It fetches the public product catalog and checks the returned key ID and Ed25519 public key against the SDK's pin. The SDK uses the pinned key to verify signed responses.

```java
app.init();
```

## Display application information

Fetch application information after activation or sign-in returns a session token.

```java
Map<String, Object> appData = app.appData();
if (appData.get("product") instanceof Map<?, ?> product) {
    System.out.println("App version: " + product.get("version"));
}
```

## Check session validation

After activation or sign-in, call `validate()` to check the license again. If the API rejects a stale session token, the SDK retries once with the stored license key when it has one.

```java
app.validate();
```

## Check blacklist status

Check the blacklist with an active session. The API also checks it during activation and sign-in.

```java
app.checkBlacklist();
```

## Login with username/password

Supply the account credentials. If the account uses two-factor authentication, include its code.

```java
Map<String, Object> snap = app.login(username, password, twofa, buildHash, label);
```

## Register with username/password/key

```java
Map<String, Object> snap = app.register(key, username, password, buildHash, label);
```

## Upgrade user with key

Apply the key to the existing account. Sign in after the upgrade to open a session.

```java
app.upgrade(username, password, key);
System.out.println("Upgraded. Sign in to use the new licence.");
Map<String, Object> snap = app.login(username, password, null, null, null);
```

## Login with just license key

For a key-only product, activate with the license key. The API applies the product's device rules and issues a session token where supported.

```java
Map<String, Object> snap = app.activate(key, buildHash, label);
```

Pass `null` for the optional build hash or device label when you leave either value unset.

## User Data

Read the current user, account, device, and subscriptions from the snapshot.

```java
Map<String, Object> snap = app.snapshot();
System.out.println("Username: " + snap.get("user"));
Map<?, ?> account = (Map<?, ?>) snap.get("account");
Map<?, ?> device = (Map<?, ?>) snap.get("device");
System.out.println("IP: " + (account == null ? null : account.get("lastIp")));
System.out.println("Device Id: " + (device == null ? null : device.get("id")));
```

## Check subscription of user

Use the tier name you set in the dashboard. The example checks for `pro`.

```java
boolean pro = ((List<?>) snap.get("subscriptions")).stream()
    .anyMatch(s -> "pro".equalsIgnoreCase(String.valueOf(((Map<?, ?>) s).get("tier"))));
if (!pro) { System.out.println("This feature needs a Pro subscription."); return; }
```

## Application variables

Edit shared variables in the dashboard. The API applies each variable's tier and version rules on read.

```java
System.out.println("MOTD: " + app.variable("maintenance_message"));
```

## User Variables

Read or update values for the signed-in user. The API rejects writes to variables the operator marked read-only.

```java
System.out.println(app.listVars());          // every variable on this user
System.out.println(app.getVar("theme"));     // one variable's value
app.setVar("theme", "dark");                 // write it back
```

## Application Logs

Send an event to the operator's log. The product's logging settings determine where it appears.

```java
app.log("client started, integrity check passed");
```

## Ban the user

Use an active session to ban the current device and IP address. The call also ends the local session.

```java
app.ban("debugger detected"); // reason shows on next login + dashboard
```

## Server-side webhooks

Call a webhook by its configured ID. The API stores the destination and the client supplies the parameters and body.

```java
Map<String, Object> res = app.webhook("discord", "", "{\"content\":\"Hello from FrostAuth\"}", null);
System.out.println("upstream: " + res.get("status") + " ok: " + res.get("ok"));
```

## Heartbeat & offline

After activation or sign-in, start the heartbeat. `checkOffline()` verifies the cached signed assertion, including its expiry. If the assertion has expired or fails verification during an outage, the next failed heartbeat clears the active state. An invalid API response signature also stops the heartbeat and clears the active state.

Sessions that received no assertion have a 15-minute fallback.

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

## Compatibility checks

On Linux, run `bash sdk/compatibility/run.sh java` from the Cerberus root. The suite tests activation, validation, signed errors, and offline heartbeat behavior against a local API fixture.

This SDK initialized successfully against the live FrostAuth API on November 18, 2026. A live activation and heartbeat require a disposable license.

## SDK layout

- `src/main/java/io/frostauth/` contains the SDK, error class, JSON parser and `Example.java`.
