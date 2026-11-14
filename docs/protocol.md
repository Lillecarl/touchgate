# Minimal read-only Bitwarden client: protocol spec (from source)

## Sources and citation roots

Every citation is `ROOT/relative/path:line`. All three trees are the pinned nixpkgs sources on this machine.

| root | store path | version evidence |
| --- | --- | --- |
| `RBW` | `/nix/store/972lp40096pxkzkkyd4lfklqprny6sr4-source` | rbw 1.15.0, `RBW/Cargo.toml:3` |
| `VW` | `/nix/store/ih4gja1drzngnkidc850l5sj8vgjyyjg-source` | vaultwarden 1.37.4, `/etc/nixpkgs/pkgs/by-name/va/vaultwarden/package.nix:23` (its own `Cargo.toml` says 1.0.0) |
| `BW` | `/nix/store/2cz4hpdxr0z6yygkyg732d5ylbmvrbkn-source` | bitwarden/clients, CLI 2026.9.1, `BW/apps/cli/package.json:4` |

The clients tree delegates most crypto to the closed wasm `@bitwarden/sdk-internal` (`PureCrypto`, e.g. `BW/libs/legacy-crypto/src/services/default-key-generation.service.ts:56`, `BW/libs/legacy-crypto/src/node/node-crypto-function.service.ts:93-114`). Where a primitive lives only in the SDK, rbw is the citation.

## 0. URLs and transport

- vaultwarden mounts the API at `<base>/api` and identity at `<base>/identity` (`VW/src/main.rs:584`, `VW/src/main.rs:587`). rbw builds the same: `base_url + "/api"`, `base_url + "/identity"` (`RBW/src/config.rs:146-170`).
- Identity endpoints in use: `POST /identity/accounts/prelogin`, `POST /identity/connect/token`, `POST /identity/accounts/register/send-verification-email`, `POST /identity/accounts/register/finish` (`VW/src/api/identity.rs:43-55`).
- API endpoints in use: `GET /api/sync`, `POST /api/accounts/api-key` (`VW/src/api/core/ciphers.rs:122`, `VW/src/api/core/accounts.rs:1479`).
- JSON key casing differs per endpoint:
  - prelogin response: camelCase (`VW/src/api/core/accounts.rs:1412-1424`).
  - token response: mixed. `access_token`, `refresh_token`, `expires_in`, `token_type`, `scope` are snake_case; `Key`, `PrivateKey`, `Kdf`, `KdfIterations`, `KdfMemory`, `KdfParallelism`, `AccountKeys`, `UserDecryptionOptions` are PascalCase (`VW/src/api/identity.rs:568-591`).
  - error bodies and sync: camelCase (`VW/src/error.rs:239-256`, `VW/src/api/core/ciphers.rs:197-211`).
  - The official Bitwarden server uses PascalCase in places. rbw accepts both by `rename = "Pascal", alias = "camel"` on every field (`RBW/src/api.rs:276-286`, `RBW/src/api.rs:389-431`). A client that targets only vaultwarden can read camelCase for sync, but must read PascalCase in the token response.

Headers:

- rbw sends on every request: `Bitwarden-Client-Name: cli`, `Bitwarden-Client-Version: <rbw version>`, `Device-Type: 8`, a `User-Agent` (`RBW/src/api.rs:812-817`, `RBW/src/api.rs:843-864`).
- vaultwarden reads `Device-Type` only for event logging, and falls back to 14 (UnknownBrowser) when it is absent or unparseable (`VW/src/auth.rs:620-625`). It is not required.
- vaultwarden never reads `Auth-Email` (grep of `VW/src` finds no match). rbw sends it as URL-safe base64 without padding of the raw email (`RBW/src/api.rs:1030-1033`, `RBW/src/base64.rs:7-9`). It is harmless and the official server wants it; send it for portability.
- `Bitwarden-Client-Version` matters on `/api/sync`, see section 5.

## 1. Prelogin

Request: `POST /identity/accounts/prelogin`, JSON body `{"email": "<email>"}` (`VW/src/api/core/accounts.rs:1377-1381`, `RBW/src/api.rs:271-274`, `RBW/src/api.rs:900-909`). `/identity/accounts/prelogin/password` is an alias with the same handler (`VW/src/api/identity.rs:1025-1028`).

Server behaviour (`VW/src/api/core/accounts.rs:1400-1425`):

- Normalises with `email.trim().to_lowercase()` before lookup (`:1405`).
- Rate limit: unauthenticated bucket, see section 9 (`:1401`).
- Unknown email: no error. It returns deterministic fake KDF settings, chosen by a keyed HMAC of the email, from a fixed list that includes PBKDF2 5000 (`:1383-1398`, `VW/src/auth.rs:114-118`). So prelogin cannot tell a client whether an account exists.

Response (camelCase):

```json
{"kdf": 0|1, "kdfIterations": N, "kdfMemory": M|null, "kdfParallelism": P|null,
 "kdfSettings": {"iterations": N, "kdfType": 0|1, "memory": M|null, "parallelism": P|null},
 "salt": null}
```

- `kdf`: 0 = PBKDF2-SHA256, 1 = Argon2id (`RBW/src/api.rs:166-170`, `BW/libs/legacy-crypto/src/enums/kdf-type.enum.ts:3-6`).
- PBKDF2: `kdfIterations` = iteration count; memory and parallelism are null (`VW/src/api/core/accounts.rs:708-711`).
- Argon2id: `kdfIterations` = Argon2 time cost (t); `kdfMemory` = memory in **MiB**; `kdfParallelism` = lanes (p). rbw multiplies memory by 1024 to get KiB for the argon2 crate (`RBW/src/identity.rs:49-54`); the clients label the unit MiB (`BW/libs/legacy-crypto/src/models/kdf-config.ts:110-113`).
- `salt` is always null on vaultwarden (`VW/src/api/core/accounts.rs:1423`). The salt is the email, see section 2.

Downgrade guard used by the official clients before deriving anything (`BW/libs/legacy-crypto/src/models/kdf-config.ts:19`, `:46-52`, `:75-77`, `:126-143`): reject PBKDF2 iterations < 5000; reject Argon2 iterations < 2, memory < 16 MiB, parallelism < 1. rbw has no guard; it only rejects 0 iterations (`RBW/src/identity.rs:22-23`).

## 2. Key derivation

Let `password` = UTF-8 bytes of the master password, unmodified. Let `email_norm` = `email.trim().to_lowercase()` (rbw: `RBW/src/identity.rs:20`; clients: `email.toLowerCase().trim()`, `BW/libs/common/src/key-management/master-password/services/master-password.service.ts:163-165`, and again defensively at `:253` and `:294`). For the current registration body shape only, vaultwarden enforces that the declared salt equals `data.email.trim().to_lowercase()` (`VW/src/api/core/accounts.rs:131-145`); the flat shape carries no salt.

### 2.1 Master key (32 bytes)

PBKDF2 (`RBW/src/identity.rs:31-39`):

```
master_key = PBKDF2-HMAC-SHA256(password = password, salt = email_norm (UTF-8), iterations = kdfIterations, dkLen = 32)
```

Argon2id (`RBW/src/identity.rs:41-64`):

```
salt       = SHA-256(email_norm UTF-8)                 # 32 raw bytes, not hex
master_key = Argon2id(version 0x13, m = kdfMemory*1024 KiB, t = kdfIterations, p = kdfParallelism,
                      password = password, salt = salt, outlen = 32)
```

### 2.2 Master password hash sent to the server

```
mp_hash   = PBKDF2-HMAC-SHA256(password = master_key, salt = password, iterations = 1, dkLen = 32)
wire_hash = standard base64 WITH padding of mp_hash      # 44 chars
```

- Argument order: the master key is the PBKDF2 *password* and the master password is the *salt* (`RBW/src/identity.rs:67-75`; clients: `pbkdf2(masterKey.toEncoded(), password, "sha256", 1)`, `BW/libs/common/src/key-management/master-password/services/master-password.service.ts:255-270`).
- It uses the **unstretched** master key (`RBW/src/identity.rs:69-75` runs before the HKDF at `:77-83`).
- Encoding: standard alphabet with padding (`RBW/src/api.rs:1010`, `RBW/src/base64.rs:3-5`; clients `Utils.fromBufferToB64`, `master-password.service.ts:263`).
- vaultwarden treats `wire_hash` as an opaque byte string and hashes it again server-side with PBKDF2-SHA256 over a per-user random salt (`VW/src/db/models/user.rs:164-171`, `VW/src/crypto.rs:12-24`; default 600 000 server iterations, `VW/src/config.rs:644`). Consequence: the base64 spelling at login must be byte-identical to the spelling at registration.

### 2.3 Stretched master key (64 bytes)

```
enc_key = HKDF-Expand-SHA256(PRK = master_key, info = "enc", L = 32)
mac_key = HKDF-Expand-SHA256(PRK = master_key, info = "mac", L = 32)
stretched = enc_key || mac_key
```

- HKDF-Expand only; no HKDF-Extract and no salt: rbw uses `Hkdf::from_prk(master_key)` (`RBW/src/identity.rs:77-83`); clients call `hkdfExpand(key, "enc"|"mac", 32, "sha256")` (`BW/libs/legacy-crypto/src/services/default-key-generation.service.ts:60-86`).
- The clients refuse to stretch anything but a 32-byte key (`default-key-generation.service.ts:63-65`).
- The clients' HKDF-Expand is RFC 5869: `T(i) = HMAC(PRK, T(i-1) || info || i)` (`BW/libs/legacy-crypto/src/node/node-crypto-function.service.ts:58-75`).

## 3. Password login: `POST /identity/connect/token`

Body: `application/x-www-form-urlencoded` (rbw `.form(...)`, `RBW/src/api.rs:1026-1029`; clients `Content-Type: application/x-www-form-urlencoded; charset=utf-8`, `BW/libs/common/src/services/api.service.ts:176-180`).

vaultwarden matches form field names case-insensitively and accepts both snake and camel spellings, e.g. `device_identifier` or `deviceIdentifier` (`VW/src/api/identity.rs:1106-1169`).

| field | value | required by vaultwarden |
| --- | --- | --- |
| `grant_type` | `password` | yes |
| `username` | email | yes; server does `trim()` then lowercase lookup (`VW/src/api/identity.rs:379-381`, `VW/src/db/models/user.rs:424-425`) |
| `password` | `wire_hash` (2.2) | yes |
| `scope` | exactly `api offline_access` | yes; any other string fails (`VW/src/auth.rs:1244-1263`, `VW/src/api/identity.rs:373`) |
| `client_id` | `cli` (rbw, `RBW/src/api.rs:1015`). The password path shows only a presence check (`VW/src/api/identity.rs:70`); it is passed into the tokens (`:497`), so resend the same value on refresh (`:157`) | yes |
| `deviceType` | integer; rbw sends 8 = LinuxDesktop (`RBW/src/api.rs:1016`). LinuxCLI is 25, SDK 21 (`BW/libs/common/src/enums/device-type.enum.ts:12`, `:25`, `:29`). Unparseable → 14 (`VW/src/api/identity.rs:781-783`) | yes (`:77`) |
| `deviceIdentifier` | stable per installation; rbw uses a persisted UUIDv4 (`RBW/src/config.rs:219-234`). vaultwarden stores any string (`VW/src/db/models/device.rs:384-387`) | yes (`:75`) |
| `deviceName` | free text, rbw `rbw` | yes (`:76`) |
| `devicePushToken` | empty; vaultwarden ignores it (`VW/src/api/identity.rs:1142-1145`) | no |
| `twoFactorToken`, `twoFactorProvider`, `twoFactorRemember` | only on the 2FA retry | no |

Required-field checks: `VW/src/api/identity.rs:69-79`. A missing field returns 400 "`<field> cannot be blank`" (`:1170-1175`).

### 3.1 Success response (HTTP 200)

`VW/src/api/identity.rs:536-598`:

```json
{
  "access_token": "<JWT>", "expires_in": N, "token_type": "Bearer",
  "refresh_token": "<opaque>", "scope": "api offline_access",
  "Key": "<EncString: user key wrapped by stretched master key>",   // present only if akey non-empty (:589-591)
  "PrivateKey": "<EncString type 2: PKCS#8 DER private key wrapped by user key>" | null,
  "Kdf": 0|1, "KdfIterations": N, "KdfMemory": M|null, "KdfParallelism": P|null,
  "ForcePasswordReset": false, "MasterPasswordPolicy": {...},
  "AccountKeys": {"publicKeyEncryptionKeyPair": {"wrappedPrivateKey": ..., "publicKey": ..., "Object": ...}, "Object": "privateKeys"} | null,
  "UserDecryptionOptions": {"HasMasterPassword": bool,
     "MasterPasswordUnlock": {"Kdf": {"KdfType","Iterations","Memory","Parallelism"},
        "MasterKeyEncryptedUserKey": akey, "MasterKeyWrappedUserKey": akey, "Salt": user.email} | null,
     "Object": "userDecryptionOptions"},
  "TwoFactorToken": "..."    // only when twoFactorRemember=1 succeeded (:593-595)
}
```

- `Salt` is the stored email, which `User::new` lowercased (`VW/src/db/models/user.rs:114-116`). Re-apply trim+lowercase anyway.
- Refresh: `grant_type=refresh_token`, `client_id`, `refresh_token` (`RBW/src/api.rs:365-370`, `RBW/src/api.rs:1545-1562`; `VW/src/api/identity.rs:64-67`, `:141-179`). The response has no `Key`. A bad token gives 400 with `{"error":"invalid_grant"}` (`:147-163`). Refresh tokens last 30 days, 90 for mobile device types (`VW/src/auth.rs:46-47`, `:1317-1321`).
- A rejected bearer token on `/api/*` gives HTTP 401 (`VW/src/error.rs:425-435`). rbw refreshes on 401 and retries once (`RBW/src/actions.rs:313-337`, `RBW/src/api.rs:1188-1190`).

### 3.2 Error shape

Status is 400 unless a handler sets another code (`VW/src/error.rs:12`, `:20-27`, `:331`). Ordinary errors serialize as (`VW/src/error.rs:226-260`):

```json
{"message": "<msg>", "validationErrors": {"": ["<msg>"]},
 "errorModel": {"message": "<msg>", "object": "error"},
 "error": "", "error_description": "",
 "exceptionMessage": null, "exceptionStackTrace": null, "innerExceptionMessage": null, "object": "error"}
```

- Wrong password or unknown user: message `Username or password is incorrect. Try again` (`VW/src/api/identity.rs:381-383`, `:420-428`). Note `error` is the empty string, not `invalid_grant`. rbw special-cases that (`RBW/src/api.rs:1741-1762`).
- Disabled user: `This user has been disabled` (`:430-439`).
- Unverified email, only when SMTP is on and `SIGNUPS_VERIFY=true`: `Please verify your email before trying again.` (`:448-478`).
- Rate limit: HTTP 429, `Too many login requests` (`VW/src/ratelimit.rs:39-43`).

### 3.3 Two-factor

When the user has any enabled provider and no valid `twoFactorToken` (`VW/src/api/identity.rs:798-837`), the body is a raw JSON error (`err_json!`, kind `Json`, serialized as-is, status 400; `VW/src/error.rs:84`, `:415-418`):

```json
{"error": "invalid_grant", "error_description": "Two factor required.",
 "TwoFactorProviders": ["0", "1", ...],          // strings, not numbers (:948)
 "TwoFactorProviders2": {"0": null, "1": {"Email": "a***@x"}, ...},
 "MasterPasswordPolicy": ...}
```

(`VW/src/api/identity.rs:943-1018`.) Provider numbers: 0 Authenticator, 1 Email, 2 Duo, 3 YubiKey, 4 U2F, 5 Remember, 6 OrganizationDuo, 7 WebAuthn, 8 RecoveryCode (`VW/src/db/models/two_factor.rs:28-37`). Retry the same request with `twoFactorToken` and `twoFactorProvider` (`RBW/src/api.rs:1020-1022`). The clients send `twoFactorRemember` as "1"/"0" (`BW/libs/common/src/auth/models/request/identity-token/token.request.ts:44-50`). A token that is blank after trim counts as absent (`VW/src/api/identity.rs:834-837`).

### 3.4 New-device verification

vaultwarden 1.37.4 has **no** new-device OTP challenge. On a new `deviceIdentifier` it only emails a notification when SMTP is configured, and fails the login only if that email fails and `REQUIRE_DEVICE_EMAIL=true` (`VW/src/api/identity.rs:510-524`; default false, `VW/src/config.rs:730`). The official clients detect the cloud's challenge by 400 with `ErrorModel.Message == "new device verification required"` and resend with `newDeviceOtp` (`BW/libs/common/src/services/api.service.ts:139-140`, `:216-220`; `BW/libs/common/src/auth/models/request/identity-token/password-token.request.ts:25-27`). rbw's answer to the cloud challenge is to log in once with the personal API key so the device becomes known (`RBW/src/actions.rs:3-14`, `RBW/src/api.rs:919-972`).

## 4. Personal API-key login (`client_credentials`)

Form fields (`RBW/src/api.rs:925-946`; `BW/libs/common/src/auth/models/request/identity-token/user-api-token.request.ts:15-22`; `VW/src/api/identity.rs:81-87`, `:601-618`):

| field | value |
| --- | --- |
| `grant_type` | `client_credentials` |
| `client_id` | `user.<user uuid>` (`VW/src/api/identity.rs:627-631`) |
| `client_secret` | the 30-char alphanumeric API key (`VW/src/crypto.rs:103-107`) |
| `scope` | exactly `api` (`VW/src/auth.rs:1247`, `VW/src/api/identity.rs:606-613`) |
| `deviceType`, `deviceIdentifier`, `deviceName` | required for the user key (`VW/src/api/identity.rs:608-611`) |
| `username` | not read by vaultwarden; rbw sends the email (`RBW/src/api.rs:927-934`) |

- Getting the key: log in with a password first, then `POST /api/accounts/api-key` with JSON `{"masterPasswordHash": "<wire_hash>"}` (camelCase per `rename_all`, alias `MasterPasswordHash`, `VW/src/api/mod.rs:49-55`) and the bearer token. The response is `{"apiKey": "...", "revisionDate": "...", "object": "apiKey"}` (`VW/src/api/core/accounts.rs:1461-1482`, `VW/src/api/mod.rs:51-69`). The user uuid is `profile.id` in sync (`VW/src/db/models/user.rs:308`).
- API-key login skips 2FA (`VW/src/api/identity.rs:650`).
- Response (`VW/src/api/identity.rs:693-748`): same key material as 3.1 (`Key`, `PrivateKey`, `Kdf*`, `UserDecryptionOptions.MasterPasswordUnlock.Salt`), scope `api`, and **no `refresh_token`**. Re-run the grant when the token expires (`:725-726`).
- **The master password is still required to decrypt.** The API key only authenticates; `Key` is still wrapped by the stretched master key. The official CLI says "To unlock your vault, use the `unlock` command" after an API-key login (`BW/apps/cli/src/auth/commands/login.command.ts:447-459`). No email is typed in this flow, so take the KDF parameters and the salt from the token response (`VW/src/api/identity.rs:694-707`, `:734-737`).
- Bad secret: 400 `Incorrect client_secret`; bad client_id: `Malformed client_id` / `Invalid client_id` (`VW/src/api/identity.rs:628-660`). rbw maps the official server's `invalid_client` to "incorrect API key" (`RBW/src/api.rs:1738-1740`).

## 5. Sync: `GET /api/sync`

Headers: `Authorization: Bearer <access_token>` (`RBW/src/api.rs:1158-1163`; vaultwarden takes the text after the last `"Bearer "`, `VW/src/auth.rs:654-656`).

- Send `Bitwarden-Client-Version: 2024.12.0` or newer. Without a header that parses as semver >= 2024.12.0, vaultwarden silently drops SSH-key ciphers (type 5) (`VW/src/api/core/ciphers.rs:129-138`, `VW/src/auth.rs:1213-1232`). rbw overrides its own version for this reason (`RBW/src/api.rs:1161-1162`).
- Optional query `excludeDomains=true` drops the equivalent-domains blob (`VW/src/api/core/ciphers.rs:117-120`, `:171-175`). rbw sends no query (`RBW/src/api.rs:1159`).

Response (camelCase, `VW/src/api/core/ciphers.rs:197-211`): `profile`, `folders`, `collections`, `policies`, `policiesNew`, `ciphers`, `domains`, `sends`, `userDecryption.masterPasswordUnlock` (`kdf.{kdfType,iterations,memory,parallelism}`, `masterKeyWrappedUserKey`, `salt`), `object: "sync"`.

Encrypted data, and which key opens it:

| location | content | key |
| --- | --- | --- |
| `profile.key` | user key, 64 bytes | stretched master key (`VW/src/db/models/user.rs:316`) |
| `profile.privateKey` | PKCS#8 DER RSA private key; **may be null** if registration sent no `keys` (`VW/src/api/core/accounts.rs:104-105`, `:397-400`) | user key (`VW/src/db/models/user.rs:317`) |
| `profile.accountKeys.publicKeyEncryptionKeyPair.wrappedPrivateKey` | same as `privateKey`; `signatureKeyPair` and `securityState` always null (`VW/src/db/models/user.rs:264-281`) | user key |
| `profile.organizations[].key` | org key, 64 bytes; only **confirmed** memberships are listed (`VW/src/db/models/user.rs:284-287`, `VW/src/db/models/organization.rs:526`) | RSA private key |
| `profile.organizations[].name`, `profile.email`, `profile.id` | plaintext (`VW/src/db/models/organization.rs:468`, `VW/src/db/models/user.rs:308-310`) | - |
| `folders[].name` | folder name | **user key always**, even for org ciphers (`VW/src/db/models/folder.rs:58`, `RBW/src/bin/rbw/commands.rs:2301-2306`) |
| `collections[].name` | collection name (`VW/src/db/models/collection.rs:74`) | org key (inferred: collections belong to an org; not read in source) |
| `ciphers[]` | see section 7 | cipher key, else org key if `organizationId` set, else user key |

Cipher JSON (`VW/src/db/models/cipher.rs:328-407`): `id`, `type` (1 login, 2 secure note, 3 card, 4 identity, 5 ssh key, 6 bank account, 7 driver's licence, 8 passport, `:45-54`), `organizationId`, `key`, `name`, `notes`, `fields`, `passwordHistory`, `deletedDate`, `reprompt`, `folderId`, `attachments`, and exactly one populated type object: `login`, `secureNote`, `card`, `identity`, `sshKey`, `bankAccount`, `driversLicense`, `passport` (the rest null). Skip ciphers with non-null `deletedDate` (trash), as rbw does (`RBW/src/api.rs:438-440`). Login responses also carry a legacy top-level `login.uri` copied from `uris[0].uri` (`VW/src/db/models/cipher.rs:259-279`).

## 6. EncString

Wire format: `<type>.<b64>|<b64>[|<b64>]`; base64 is standard alphabet with padding (`RBW/src/base64.rs:3-15`). Type enum and part counts (`BW/libs/legacy-crypto/src/enums/encryption-type.enum.ts:3-49`):

| type | name | parts | layout |
| --- | --- | --- | --- |
| 0 | AesCbc256_B64 | 2 | `0.iv|ct` (no MAC) |
| 1 | AesCbc128_HmacSha256_B64 | - | removed (`:6`) |
| 2 | AesCbc256_HmacSha256_B64 | 3 | `2.iv|ct|mac` |
| 3 | Rsa2048_OaepSha256_B64 | 1 | `3.ct` |
| 4 | Rsa2048_OaepSha1_B64 | 1 | `4.ct` |
| 5 | Rsa2048_OaepSha256_HmacSha256_B64 | 2 | `5.ct|mac` |
| 6 | Rsa2048_OaepSha1_HmacSha256_B64 | 2 | `6.ct|mac` |
| 7 | CoseEncrypt0 | 1 | `7.<cose>` (XChaCha20-Poly1305 inside, `:8-10`) |

A string with no `.` is parsed by the clients as type 0 `iv|ct` (`BW/libs/legacy-crypto/src/models/enc-string.ts:132-158`).

What a vaultwarden account uses:

- Symmetric data, user key, private key, cipher keys: type 2. Org keys: type 4 (rbw implements exactly 2 and 4|6 and calls everything else "too old" or "unimplemented", `RBW/src/cipherstring.rs:11-22`, `:43-93`).
- Type 7 implies a COSE key longer than 64 bytes (`BW/libs/legacy-crypto/src/models/symmetric-crypto-key.ts:45-65`) and the "v2" account format with a signature key pair. vaultwarden always sends `signatureKeyPair: null` and `securityState: null` (`VW/src/db/models/user.rs:271-276`). Reject type 7 with a clear error.

Type 2 decryption (`RBW/src/cipherstring.rs:123-150`, `:215-235`):

1. Split on `.`, then `|`; base64-decode iv (16 bytes), ct, mac (32 bytes).
2. `expected = HMAC-SHA256(key = mac_key, data = iv || ct)`; compare to `mac` in constant time (rbw `Mac::verify`, `:221-231`). MAC is over the raw bytes, not the base64.
3. `pt = AES-256-CBC-decrypt(key = enc_key, iv, ct)`, then strip PKCS#7 padding (`:140-142`).

Here `enc_key || mac_key` is the 64-byte key that opens this string. Encryption mirrors it with a random 16-byte IV (`:96-121`, `:262-267`).

Security note: rbw accepts a type-2 string with only two parts and then **skips the MAC check** (`RBW/src/cipherstring.rs:46`, `:59-66`, `:221`). Type 0 and the bare `iv|ct` form have no MAC either. A new client should require three parts for type 2 and reject types 0, 1, 3, 5 and 7.

Type 4 decryption (`RBW/src/cipherstring.rs:183-212`): base64-decode the single part; RSA-2048 OAEP with **SHA-1** (MGF1-SHA1, empty label) using the PKCS#8 DER private key. For type 6, rbw drops the `|mac` part and does not verify it (`:74-82`). The RSA test vector in section 10 uses SHA-1 (`BW/libs/legacy-crypto/src/node/node-crypto-function.service.spec.ts:175`).

## 7. Key hierarchy

```
password, email_norm, KDF params
  └─ master_key (32)                     section 2.1
       ├─ wire_hash (login only)          section 2.2
       └─ stretched (enc||mac, 64)        section 2.3
            └─ decrypt Key/profile.key (type 2) → user_key (64: enc 0..32, mac 32..64)
                 ├─ decrypt profile.privateKey (type 2) → PKCS#8 DER RSA key
                 │    └─ decrypt organizations[].key (type 4) → org_key (64)
                 ├─ personal cipher fields, folder names
                 └─ cipher.key (type 2) → item_key (64) → that cipher's fields
```

Citations: user key unwrap `RBW/src/actions.rs:101-111` (a MAC failure here means wrong password, `:105-109`); private key `:113-119`; org keys `:121-131`; 64-byte split `RBW/src/locked.rs:105-111`; key selection by org `RBW/src/bin/rbw-agent/state.rs:32-36`; item key `RBW/src/bin/rbw-agent/actions.rs:568-579` then `:663-668`; clients unwrap `cipher.key` with the user or org key, then decrypt the rest with it (`BW/libs/common/src/vault/models/domain/cipher.ts:148-172`).

rbw-specific detail, not protocol: rbw decrypts into a fixed buffer and leaves the PKCS#7 padding in place, so it unpads the private key a second time before PKCS#8 parsing (`RBW/src/cipherstring.rs:152-181`, `:188-190`). A normal implementation unpads once.

A cipher's `key` must be opened with the org key when `organizationId` is set, otherwise with the user key (`RBW/src/bin/rbw-agent/actions.rs:563-576`).

Encrypted cipher fields (each a type-2 EncString or null), per the clients' domain models and rbw:

- cipher: `name`, `notes`, `key` (`BW/libs/common/src/vault/models/domain/cipher.ts:44-45`, `:70`)
- `fields[]`: `name`, `value`; `type` (0 text, 1 hidden, 2 boolean, 3 linked) and `linkedId` are plaintext (`BW/libs/common/src/vault/models/domain/field.ts:19-20`; `RBW/src/api.rs:668-735`, `RBW/src/bin/rbw/commands.rs:2315-2345`)
- `passwordHistory[]`: `password`; `lastUsedDate` plaintext (`BW/libs/common/src/vault/models/domain/password.ts:12`)
- `login`: `username`, `password`, `totp`, `uris[].uri`, `uris[].uriChecksum`; `uris[].match` plaintext (`BW/libs/common/src/vault/models/domain/login.ts:17-20`, `login-uri.ts:18-19`, `RBW/src/bin/rbw/commands.rs:2379-2419`)
- `login.fido2Credentials[]`: every field incl. `keyValue`, `counter`, `discoverable` (`BW/libs/common/src/vault/models/domain/fido2-credential.ts:13-24`)
- `card`: `cardholderName`, `brand`, `number`, `expMonth`, `expYear`, `code` (`card.ts:13-18`)
- `identity`: `title`, `firstName`, `middleName`, `lastName`, `address1..3`, `city`, `state`, `postalCode`, `country`, `company`, `email`, `phone`, `ssn`, `username`, `passportNumber`, `licenseNumber` (`identity.ts:13-30`)
- `sshKey`: `privateKey`, `publicKey`, `keyFingerprint` (`ssh-key.ts:12-16`)
- `attachments[]`: `fileName`, `key` (`attachment.ts:18-19`)
- `secureNote`: only `type`, plaintext (`VW/src/db/models/cipher.rs:287-296`)

## 8. Creating an account on vaultwarden 1.37.4 (test setup)

The old `POST /api/accounts/register` is gone: neither route list has it (`VW/src/api/core/accounts.rs:38-81`, `VW/src/api/identity.rs:43-55`), and `grep -rn 'accounts/register' VW/src` finds only `VW/src/api/identity.rs:1051` and `:1100`. Registration is two calls.

The request bodies below are derived from the serde attributes. They were not run against a server.

### 8.1 Step 1: get a signup token

`POST /identity/accounts/register/send-verification-email`, JSON `{"email": "<email>", "name": "<optional>"}` (`VW/src/api/identity.rs:1030-1036`, `:1051-1098`).

- Allowed only if `CONFIG.is_signup_allowed(email)` or an invitation exists (`:1063-1067`). `is_signup_allowed` = `SIGNUPS_ALLOWED` when `SIGNUPS_DOMAINS_WHITELIST` is empty, else the domain must be in the whitelist (`VW/src/config.rs:1519-1529`). `SIGNUPS_ALLOWED` defaults to **true** (`VW/src/config.rs:618`).
- If SMTP is configured **and** `SIGNUPS_VERIFY=true`, the token goes by email and the response is 204 (`VW/src/api/identity.rs:1069`, `:1074-1088`). Otherwise the token comes back in the response body (`:1089-1097`).
- Body format: a JSON string (quoted) when the request's `Accept` prefers `application/json`; otherwise **plain text** (`:1046-1049`, `:1092-1096`).
- The token is a JWT valid 30 minutes; `sub` = the email exactly as sent (`VW/src/auth.rs:462-472`).

To avoid email verification in a test: leave SMTP unconfigured, or set `SIGNUPS_VERIFY=false` (the default, `VW/src/config.rs:621`). `mail_enabled()` is true only with SMTP enabled plus `SMTP_HOST` or `USE_SENDMAIL` (`VW/src/config.rs:1594-1597`). With mail off, login never demands verification (`VW/src/api/identity.rs:448`).

### 8.2 Step 2: finish

`POST /identity/accounts/register/finish`, JSON. Two accepted body shapes, decided by `#[serde(untagged)]` (`VW/src/api/core/accounts.rs:96-187`).

Common fields (`RegisterData`, camelCase, `:96-116`):

- `email` (required)
- `emailVerificationToken`: the step-1 token. Required for a plain signup; without it (and without an invite or emergency-access pair) the call fails with `Registration is missing required parameters` (`:272-327`).
- `userAsymmetricKeys` or `keys`: `{"encryptedPrivateKey": "<type-2 EncString of PKCS#8 DER under user_key>", "publicKey": "<base64 SPKI DER>"}` (`:104-105`, `:189-194`). Optional to the server, but without it `privateKey` is null and org keys cannot be opened.
- `masterPasswordHint` (optional)

Shape A, flat (`RegisterDataOld`, `:148-158`). That struct has no `rename_all`, so its own keys are `key` (alias `userSymmetricKey`) and `master_password_hash` (alias `masterPasswordHash`). The flattened `KDFData` is camelCase: `kdf`, `kdfIterations`, `kdfMemory`, `kdfParallelism`, with aliases `kdfType`, `iterations`, `memory`, `parallelism` (`:83-94`).

```json
{"email": "u@example.test", "emailVerificationToken": "<jwt>",
 "masterPasswordHash": "<wire_hash>", "key": "<type-2 EncString of user_key under stretched>",
 "kdf": 0, "kdfIterations": 600000,
 "userAsymmetricKeys": {"encryptedPrivateKey": "2....", "publicKey": "MIIBIjAN..."}}
```

Shape B, current (`RegisterDataCur`, `:160-167`, `:196-216`):

```json
{"email": "...", "emailVerificationToken": "...",
 "masterPasswordAuthentication": {"kdf": {"kdfType": 0, "iterations": 600000, "memory": null, "parallelism": null},
                                  "salt": "<email_norm>", "masterPasswordAuthenticationHash": "<wire_hash>"},
 "masterPasswordUnlock": {"kdf": {...same...}, "salt": "<email_norm>", "masterKeyWrappedUserKey": "2...."},
 "userAsymmetricKeys": {...}}
```

Shape B fails with HTTP 422 when the two `kdf` objects differ or either `salt` is not `email.trim().to_lowercase()` (`:131-145`, `:268-270`).

Server checks, in order:

- `claims.sub != data.email` → `Email verification token does not match email` (`:283-285`). This compares the **raw** email, before lowercasing. Send the same string in both steps.
- KDF bounds (`set_kdf_data`, `:683-716`):
  - PBKDF2: iterations ≥ 100 000.
  - Argon2id: iterations ≥ 1, memory 15..=1024 (MB), parallelism 1..=16, memory and parallelism required.
  - Note these are looser than the clients' bounds: PBKDF2 600 000..2 000 000, Argon2 t 2..10, m 16..1024, p 1..16 (`BW/libs/legacy-crypto/src/models/kdf-config.ts:18`, `:71-73`).
- Existing user with a password → `Registration not allowed or user already exists` (`:342-346`).
- The email must pass `is_valid_email` on save (`VW/src/db/models/user.rs:331-334`, `VW/src/util.rs:533-541`).
- Success: `{"object": "registerFinish"}` (`:430-432`).

Client-side material to generate for the test account:

1. `user_key` = 64 random bytes.
2. `key` = type-2 EncString of `user_key` under the stretched master key.
3. RSA-2048 key pair; `encryptedPrivateKey` = type-2 EncString of the PKCS#8 DER under `user_key`; `publicKey` = base64 of SPKI DER. Formats match the clients' test fixtures: `MIIBIjAN...` is SPKI, `MIIEvQIBADAN...` is PKCS#8 (`BW/libs/legacy-crypto/src/node/node-crypto-function.service.spec.ts:13-37`, `:180-186`), and rbw parses the private key with `from_pkcs8_der` (`RBW/src/cipherstring.rs:191`).
4. `masterPasswordHash` = `wire_hash`.

Then, for API-key tests: log in (section 3), `POST /api/accounts/api-key` (section 4).

Environment names: each config field is read from the environment variable of the same name in upper case (`VW/src/config.rs:254-257`), e.g. `signups_verify` → `SIGNUPS_VERIFY`, `login_ratelimit_max_burst` → `LOGIN_RATELIMIT_MAX_BURST`. An `.env` file (path from `ENV_FILE`) is loaded first (`VW/src/config.rs:218-220`).

Other server settings relevant to a test instance:

- `I_REALLY_WANT_VOLATILE_STORAGE=true` silences the startup check for a non-persistent data folder (`VW/src/main.rs:452`, `:488-496`).
- `DOMAIN` must include the scheme when set (`VW/src/config.rs:998`).
- `PASSWORD_ITERATIONS` (server-side hash, default 600 000, minimum 100 000) affects login CPU time only (`VW/src/config.rs:644`, `:972`).

## 9. Commonly gotten wrong

1. **Salt normalisation.** Salt is `trim` + lowercase of the email, applied by the client. vaultwarden lowercases on lookup (`VW/src/db/models/user.rs:424-425`) but does not trim in `register` (`VW/src/api/core/accounts.rs:263`). rbw passes the raw email to prelogin and the token `username` and normalises only for the salt (`RBW/src/actions.rs:31-51`, `RBW/src/identity.rs:20`).
2. **Argon2 salt** is SHA-256 of the normalised email (32 raw bytes), not the email (`RBW/src/identity.rs:42-44`).
3. **Argon2 memory unit** is MiB on the wire; libraries usually want KiB (`RBW/src/identity.rs:50`).
4. **Hash argument order and iteration count:** PBKDF2(password = master_key, salt = master password, 1 iteration), on the unstretched key (2.2).
5. **HKDF:** expand only, info `enc` and `mac`, 32 bytes each. Running HKDF-Extract first gives wrong keys (2.3).
6. **Base64 variants:** standard with padding for EncStrings and `wire_hash`; URL-safe without padding only for the `Auth-Email` header (`RBW/src/base64.rs:3-15`). vaultwarden compares `wire_hash` as opaque bytes, so a padding difference fails the login (2.2).
7. **MAC:** HMAC-SHA256 over `iv || ct` raw bytes with the mac half of the key; verify in constant time **before** decrypting; do not accept a two-part type 2 (section 6).
8. **Org cipher keys:** `cipher.key` and the fields of an org cipher use the org key; folder names always use the user key (section 5, 7).
9. **Wrong password detection:** the first observable failure is the MAC check on `Key`; rbw maps `InvalidMac` there to "incorrect password" (`RBW/src/actions.rs:103-110`). At the server, a wrong password gives `error: ""` plus `errorModel.message`, not `invalid_grant` (3.2).
10. **Scope strings:** `api offline_access` for password, `api` for the user API key, `api.organization` for org keys; anything else is rejected (`VW/src/auth.rs:1244-1263`).
11. **SSH-key ciphers vanish** from sync without `Bitwarden-Client-Version` >= 2024.12.0 (section 5).
12. **Rate limits** will bite a test suite: login bucket burst 10, one token per 60 s (`VW/src/config.rs:779-781`); unauthenticated bucket (prelogin, register) burst 50 per 60 s (`VW/src/config.rs:784-786`); both give HTTP 429 (`VW/src/ratelimit.rs:30-43`). Raise `LOGIN_RATELIMIT_MAX_BURST` / `LOGIN_RATELIMIT_SECONDS` for tests.
13. **Prelogin never 404s** for an unknown email (section 1).
14. **Unicode passwords:** encode as UTF-8, no normalisation. The clients' PBKDF2 vectors include `pǻssword` and an emoji password (`BW/libs/legacy-crypto/src/node/node-crypto-function.service.spec.ts:207-209`).

## 10. Test vectors found in the trees

There are **no end-to-end vectors** (email + password + KDF → master key → hash → stretched key → decrypted `Key`) in any of the three trees. What was searched and found:

- Clients' master-password spec: `PureCrypto` appears only as a mocked call target, checked with `toHaveBeenCalledWith` (`BW/libs/common/src/key-management/master-password/services/master-password.service.spec.ts:14`, `:219`, `:236`); the hash test mocks `Utils.fromBufferToB64` (`:560`). The encrypt-service spec mocks every `PureCrypto` decrypt (`BW/libs/legacy-crypto/src/services/encrypt.service.spec.ts:34-41`).
- Password-protected export fixture (KDF + stretch + type 2, the same construction, `BW/libs/legacy-crypto/src/services/default-key-generation.service.ts:88-94`): `BW/libs/importer/src/importers/spec-data/bitwarden-json/password-protected.json.ts:1-10` gives salt `Oy0xcgVRzxQ+9NpB5GLehw==`, PBKDF2 100000 and `encKeyValidation_DO_NOT_EDIT`, but its spec uses a random password (`Utils.newGuid()`, `BW/libs/importer/src/importers/bitwarden/bitwarden-password-protected-importer.spec.ts:34`), so it is not a vector.
- Searched patterns over the whole `BW` tree: `encKeyValidation_DO_NOT_EDIT`, `"2.<b64>|` in `*.spec.ts`. The `2.…` strings found (e.g. `BW/libs/legacy-crypto/src/models/enc-string.spec.ts:156`) come without a key or plaintext.
- rbw: one crypto test, PKCS#7 unpad (`RBW/src/cipherstring.rs:295-315`); its other tests are in the CLI (`RBW/src/bin/rbw/commands.rs:2814`). vaultwarden: tests exist in `util.rs`, `auth.rs`, `api/admin.rs`, `storage.rs` (`VW/src/util.rs:939`, `VW/src/auth.rs:1381`, `VW/src/api/admin.rs:901`, `VW/src/storage.rs:262`); none covers client crypto, which vaultwarden never performs.

Primitive vectors, all from `BW/libs/legacy-crypto/src/node/node-crypto-function.service.spec.ts`:

PBKDF2-HMAC-SHA256, 5000 iterations, 32-byte output (`:45-47`, `:198-239`):

| password | salt | output (base64) |
| --- | --- | --- |
| `password` | `user@example.com` | `pj9prw/OHPleXI6bRdmlaD+saJS4awrMiQsQiDjeu2I=` |
| `pǻssword` | `üser@example.com` | `yqvoFXgMRmHR3QPYr5pyR4uVuoHkltv9aHUP63p8n7I=` |
| `😀password🙏` | `user@example.com` | `ZdeOata6xoRpB4DLp8zHhXz5kLmkWtX5pd+TdRH8w8w=` |

The first row is exactly the Bitwarden master key for password `password`, email `user@example.com`, PBKDF2 5000 (section 2.1), since that email is already normalised.

HKDF-Expand-SHA256, info `info` (`:76-90`, `:288-306`):

- PRK `F5h4KdYQnIVH4rKH0P9CZb1GrR4n16/sJrS0PsQEn0Y=`, L = 32 → `BnIqJlfnHm0e/2iB/15cbHyR19ARPIcWRp4oNS22CD8=`
- same PRK, L = 64 → `BnIqJlfnHm0e/2iB/15cbHyR19ARPIcWRp4oNS22CD9BV+/queOZenPNkDhmlVyL2WZ3OSU5+7ISNF5NhNfvZA==`

Full HKDF-SHA256 (extract + expand; not what Bitwarden's stretch uses), IKM `criAmKtfzxanbgea5/kelQ==`, salt `salt`, info `info`, L = 32 → `qBUmEYtwTwwGPuw/z6bs/qYXXYNUlocFlyAuuANI8Pw=` (`:64`, `:247-260`).

RSA-OAEP-SHA1 decrypt (`:165-177`): private key `RsaPrivateKey` (PKCS#8 DER, base64 at `:19-37`), ciphertext base64 at `:169-173`, plaintext `EncryptMe!`. `rsaExtractPublicKey` of that key equals `RsaPublicKey` (SPKI DER, `:13-18`, `:180-186`). This is a direct vector for the type-4 org-key unwrap.

PKCS#7 unpad cases: `RBW/src/cipherstring.rs:295-315`.

Recommendation: since no published vector covers stretch + type-2 decrypt, generate a fixture once against the running vaultwarden (register with fixed inputs, capture `Key` from the token response) and pin it in the test suite.
