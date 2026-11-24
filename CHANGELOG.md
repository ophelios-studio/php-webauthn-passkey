# Changelog

## 2.0.0

The WebAuthn dependencies move to their patched versions: `web-auth/webauthn-lib` 5.3.17 or later, which brings
`web-auth/cose-lib` 4.8 and `spomky-labs/cbor-php` 3.4 or later. The JSON sent to the browser is unchanged.

- Breaking: `PasskeyProvider::getCredentialSource()` returns `?Webauthn\CredentialRecord` instead of
  `?Webauthn\PublicKeyCredentialSource`. The rest of the public API is unchanged.
- Fixed: a passkey stored without transports no longer fails at sign-in with a `TypeError`.
- Fixed: no more deprecation notices on PHP 8.4.

See "Upgrading from 1.x" in the README.
