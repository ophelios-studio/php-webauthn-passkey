# Changelog

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
