# Changelog

## 3.0.0

The PRF output stays in the browser. The JavaScript module returns it to the caller and no longer posts it, the seed
is derived in the browser with the new `derivePrfSeed()`, and `verify()` and `authenticate()` refuse a credential that
carries a PRF output. The rest of the PHP API, the broker interface and the options JSON are unchanged.

### Upgrading from 2.0.0

- Require `"ophelios/php-webauthn-passkey": "^3.0"` and copy `backpack/public/javascripts/pulsar/modules/passkey.js`
  into your public assets again. `verify()` and `authenticate()` answer 400 `PRF results are not accepted` to a
  credential whose `clientExtensionResults` carries `prf.results` or `prfResults`, which the 2.0.0 module posted with
  `prf: { enabled: true }`. `prf: { enabled: true }` alone is accepted.
- `PasskeyService::deriveSeedFromPrf()` is removed. Return the passkey's `prf_salt` in base64url (it is not secret), in
  your verify response or from an endpoint of your own, and derive the seed in the browser:
  `derivePrfSeed(result.prf.first, result.prf_salt)`. For the same PRF output and salt bytes it returns the seed
  `deriveSeedFromPrf()` returned, so data encrypted under that seed stays readable. A broker that returns `prf_salt` as
  hex text decodes it before sending it, as `deriveSeedFromPrf()` did. The README shows a verify endpoint that adds
  the salt.
- `runPrfBoundAction()` is removed from the module. Call `prfEvaluate()`, unchanged, and use its `prfFirst` in the
  browser.
- `registerPasskey()` and `passkeyLogin()` return the verify endpoint's JSON with `ok: true`, where they returned
  `{ ok: true }`; with `prf: { enabled: true }` they add `prf: { first, second? }` (base64url) when the authenticator
  returned a PRF output. The `onSuccess` callbacks receive the same result.
- The registration POST carries the client extension results without `prf` and `prfResults`. The login POST carries
  no `clientExtensionResults`, with or without `prf: { enabled: true }`.
- An integration that never passed `prf: { enabled: true }` and never called `runPrfBoundAction()` or
  `deriveSeedFromPrf()` only copies the module again.

### New

- `derivePrfSeed(prfFirstB64Url, saltB64Url)` in the module: HKDF-SHA256 by WebCrypto, `info` `seed:v1`, 32 bytes,
  base64url. It throws on a PRF output that is not 32 bytes and on an empty salt.
- `composer test-js` runs the module's tests with Node (`node --test tests/js`, no dependency).

## 2.0.0

The first release since 1.0.0. It moves to `web-auth/webauthn-lib` 5.3.17 or later (with `web-auth/cose-lib` 4.8 and
`spomky-labs/cbor-php` 3.4 or later), adds the PRF extension and hardens both ceremonies. The JSON sent to the browser
is unchanged.

### Upgrading from 1.0.0

- Require `"ophelios/php-webauthn-passkey": "^2.0"`. Code of your own that calls `web-auth/webauthn-lib` directly must
  follow its 5.x API.
- `PasskeyBrokerInterface` renames three methods: `findUserIdByCredentialId(): ?int` becomes
  `findIdentifierByCredentialId(): mixed`, `findUserIdentity(string)` becomes `findIdentity(mixed)` and
  `findAllByUserId(string)` becomes `findAllByIdentity(mixed)`.
- The identifier is `mixed` everywhere: `Passkey::$user_id`, `PasskeyProvider::findUserIdByCredentialId()` and
  `getUserCredentialEntity()`. `Passkey::fromRow()` no longer casts it to `int`, and the `authenticate()` callback
  receives it exactly as your broker returns it.
- `Passkey` takes two new arguments, `prf_salt` and `prf_eval_label`, before `transports`: pass them by name.
- Byte fields carry raw bytes. 1.0.0 handed `credential_id` and `public_key_cose` to `insert()` as hex strings and
  decoded hex rows. Encode them in your broker as the README does, and convert the rows a 1.0.0 broker stored as hex
  text (the 1.0.0 README did). For PostgreSQL:

  ```sql
  UPDATE account.passkeys
     SET credential_id = decode(convert_from(credential_id, 'UTF8'), 'hex'),
         public_key_cose = decode(convert_from(public_key_cose, 'UTF8'), 'hex');
  ```
- `PasskeyProvider::getCredentialSource()` returns `?Webauthn\CredentialRecord` instead of
  `?Webauthn\PublicKeyCredentialSource`.
- The origin must match exactly. It defaults to `https://` followed by the RP ID, where 1.0.0 accepted any HTTPS
  subdomain of the RP ID on any port. A site served on a subdomain of an apex RP ID, or on a port other than 443,
  lists its origins in the new `allowedOrigins` argument.
- `verify()` and `authenticate()` answer a refusal instead of throwing: `ok` false, `err` `Verification failed`, with
  400 for a credential they cannot read and 401 for one the checks refuse. An exception now means a server failure
  (your broker, your callback).
- Options serve one attempt, accepted or refused, and expire after 5 minutes (400 `Options expired`). Options issued
  before the upgrade carry no issue time and are refused once; the JavaScript module asks for new options on each try.
- `verify()` refuses a credential ID that is already registered (400 `Credential already registered`).

### New

- PRF extension, opt-in with `enablePrf: true`: a site-scoped PRF input, a random 32-byte `prf_salt` per passkey (add
  the column) and `deriveSeedFromPrf()`, which takes a 32-byte PRF output.
- `PasskeyProvider::findByCredentialId(): ?Passkey` and `PasskeyProvider::findAllByIdentity()`.
- Constructor arguments `allowedOrigins` and `clock` (PSR-20, for the options lifetime), added last.
- Only the transports WebAuthn defines are stored: `usb`, `nfc`, `ble`, `internal`, `hybrid`, `smart-card`.

### Fixed

- A passkey stored without transports no longer fails at sign-in with a `TypeError`.
- The identifier `0` signs in; 1.0.0 answered it `Unknown credential`.
