# PHP WebAuthn Passkey

## 💿 Installation and dependencies
Install with Composer:

```
composer require ophelios/php-webauthn-passkey
```

Requirements: PHP >= 8.4 and `web-auth/webauthn-lib` 5.3.17 or later (installed by Composer). The pages that run
the ceremonies must be served over HTTPS, `localhost` included.

### Upgrading from 1.0.0

The broker interface, the byte fields, the origin rule and the way refusals are returned changed: see "Upgrading from
1.0.0" in [CHANGELOG.md](CHANGELOG.md).

### Add the required table into your database. The example below is for PostgreSQL:

```postgresql
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

CREATE TABLE account.passkeys
(
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id INT NOT NULL REFERENCES <YOUR USER ID REFERENCE> ON DELETE CASCADE,
    credential_id BYTEA NOT NULL UNIQUE, -- raw credentialId (binary)
    public_key_cose BYTEA NOT NULL, -- COSE-encoded public key
    sign_count BIGINT NOT NULL DEFAULT 0,
    backup_eligible BOOLEAN NOT NULL DEFAULT false,
    prf_salt BYTEA, -- 32-byte per-passkey salt (used for deterministic PRF seed derivation)
    transports TEXT, -- e.g. "internal,usb,nfc"
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used_at TIMESTAMPTZ
);
```
Replace the `<YOUR USER ID REFERENCE>` with the column name of your user identifier.

The `UNIQUE` constraint on `credential_id` is required: a credential ID belongs to one user. `verify()` refuses one
that is already registered, but only the constraint holds when two registrations run at the same time.

The identifier column is of type UUID given by `gen_random_uuid()` which is included in the extension `pgcrypto`. 
You can enable it with `CREATE EXTENSION IF NOT EXISTS "pgcrypto";` as shown above.

## 🌱 Usage

### Create the broker instance 

First, create the broker instance you will use to interact with the database.

```php
<?php namespace Models\Account\Brokers;

use Passkey\Passkey;
use Passkey\PasskeyBrokerInterface;
use stdClass;
use Zephyrus\Database\DatabaseBroker;

class PasskeyBroker extends DatabaseBroker implements PasskeyBrokerInterface
{
    public function findIdentifierByCredentialId(string $credentialId): mixed
    {
        $sql = "SELECT user_id FROM account.passkeys WHERE credential_id = decode(?, 'hex') LIMIT 1";
        $row = $this->selectSingle($sql, [bin2hex($credentialId)]);
        return $row?->user_id ?? null;
    }

    public function findByCredentialId(string $credentialId): ?stdClass
    {
        $sql = "SELECT * FROM account.passkeys WHERE credential_id = decode(?, 'hex') LIMIT 1";
        return $this->selectSingle($sql, [bin2hex($credentialId)]);
    }

    public function findAllByIdentity(mixed $identifier): array
    {
        $sql = "SELECT * FROM account.passkeys WHERE user_id = ?";
        return $this->select($sql, [$identifier]);
    }

    public function findIdentity(mixed $identifier): stdClass
    {
        $sql = "SELECT email, fullname AS display_name FROM account.view_user_profile WHERE id = ?";
        return $this->selectSingle($sql, [$identifier]);
    }

    public function updateUsageAndCounter(string $credentialId, int $newSignCount): void
    {
        $this->query("UPDATE account.passkeys 
                         SET sign_count = ?, 
                             last_used_at = now() 
                       WHERE credential_id = decode(?, 'hex')", [
            $newSignCount,
            bin2hex($credentialId)
        ]);
    }

    public function insert(Passkey $passkey): void
    {
        $sql = "INSERT INTO account.passkeys (user_id, credential_id, public_key_cose, sign_count, backup_eligible, prf_salt, transports) 
                VALUES (?, decode(?, 'hex'), decode(?, 'hex'), ?, ?, decode(?, 'hex'), ?)";
        $this->query($sql, [
            $passkey->user_id,
            bin2hex($passkey->credential_id),
            bin2hex($passkey->public_key_cose),
            $passkey->sign_count,
            $passkey->backup_eligible,
            bin2hex($passkey->prf_salt ?? ''),
            $passkey->transports
        ]);
    }
}
```
If you already have a table and want to use the PRF extension, add the column:

```sql
ALTER TABLE account.passkeys ADD COLUMN prf_salt BYTEA;
```

### Create the service

```php
use Models\Account\Brokers\PasskeyBroker;
use Passkey\PasskeyProvider;
use Passkey\PasskeyService;

$service = new PasskeyService(
    provider: new PasskeyProvider(new PasskeyBroker()),
    rpName: 'Your App',
    rpId: 'app.example.com',
);
```

- **Fix `rpId` in production.** Without it, the RP ID comes from the request's `Host` header: the server then acts as
  the relying party of any host name that reaches it, and the PRF input changes with the host (`www.` or not), which
  makes PRF-encrypted data unreadable.
- The origin of a ceremony must match exactly: `https://` followed by the RP ID. A site served on a subdomain of the
  RP ID, or on a port other than 443, lists its origins: `allowedOrigins: ['https://app.example.com']`.
- `verify()` and `authenticate()` return `['ok' => true]`, or `['ok' => false, 'err' => '...']` with the HTTP status
  set to 400 or 401: return the array as JSON. They throw only when your broker or your callback fails.
- Options serve one attempt and expire after 5 minutes.

### Create your registration Controller
```php
<?php namespace Controllers\Application;

use Models\Account\Brokers\PasskeyBroker;
use Passkey\PasskeyProvider;
use Passkey\PasskeyService;
use Zephyrus\Network\Response;
use Zephyrus\Network\Router\Post;

class WebAuthnController extends AppController
{
    #[Post("/webauthn/register/options")]
    public function options(): Response
    {
        return $this->json($this->passkeys()->options(Passport::getUserId()));
    }

    #[Post("/webauthn/register/verify")]
    public function verify(): Response
    {
        return $this->json($this->passkeys()->verify(Passport::getUserId()));
    }

    private function passkeys(): PasskeyService
    {
        return new PasskeyService(new PasskeyProvider(new PasskeyBroker()), rpName: 'Your App', rpId: 'app.example.com');
    }
}
```

### Create your authentication Controller
```php
<?php namespace Controllers\Public;

use Controllers\Controller;
use Models\Account\Brokers\PasskeyBroker;
use Passkey\PasskeyProvider;
use Passkey\PasskeyService;
use Zephyrus\Network\Response;
use Zephyrus\Network\Router\Post;

class WebAuthnController extends Controller
{
    #[Post("/webauthn/login/options")]
    public function options(): Response
    {
        return $this->json($this->passkeys()->assertionOptions());
    }

    #[Post("/webauthn/login/verify")]
    public function verify(): Response
    {
        // The callback runs only once the assertion is verified, with the identifier your broker stored
        return $this->json($this->passkeys()->authenticate(function (mixed $userId): void {
            $this->signIn($userId); // your own sign-in: regenerate the session ID, remember the user
        }));
    }

    private function passkeys(): PasskeyService
    {
        return new PasskeyService(new PasskeyProvider(new PasskeyBroker()), rpName: 'Your App', rpId: 'app.example.com');
    }
}
```

### Add routes exception to the CSRF middleware
Add the following exception pattern to the CSRF middleware in your `config.yml` file for a Zephyrus-based project.

```yml
security:
  csrf:
    enabled: true
    exceptions: ['\/webauthn.*']
  
```

### Front-end module (ESM) for passkey registration and login
We provide an ES module you can use to handle both Passkey registration (create) and authentication (login) with configurable endpoints.

- Module file: backpack/public/javascripts/pulsar/modules/passkey.js

Registration (create) example with callbacks:

```html
<button id="createPasskeyBtn">Create a Passkey</button>
<script type="module">
  import { initPasskeyRegistration } from '/javascripts/pulsar/modules/passkey.js';
  initPasskeyRegistration({
    buttonSelector: '#createPasskeyBtn',
    optionsUrl: '/webauthn/register/options',
    verifyUrl: '/webauthn/register/verify',
    // Experimental PRF (disabled by default)
    prf: { enabled: true },
    onSuccess: () => {
      // e.g., show a toast or update UI
      console.log('Passkey created successfully');
    },
    onError: (err) => {
      console.error('Registration failed:', err);
    }
  });
</script>
```

Login (assertion) example with callbacks:

```html
<button id="btn-passkey-login">Login with Passkey</button>
<script type="module">
  import { initPasskeyLogin } from '/javascripts/pulsar/modules/passkey.js';
  initPasskeyLogin({
    buttonSelector: '#btn-passkey-login',
    optionsUrl: '/webauthn/login/options',
    verifyUrl: '/webauthn/login/verify',
    // Experimental PRF (disabled by default)
    prf: { enabled: true },
    onSuccess: () => {
      // e.g., redirect or update UI
      window.location.href = '/';
    },
    onError: (err) => {
      console.error('Login failed:', err);
    }
  });
</script>
```

Programmatic usage (no UI binding):

```js
import { registerPasskey, passkeyLogin } from '/javascripts/pulsar/modules/passkey.js';

// Registration
const reg = await registerPasskey({
  optionsUrl: '/webauthn/register/options',
  verifyUrl: '/webauthn/register/verify'
});
if (!reg.ok) {
  console.error(reg.err);
}

// Authentication
const auth = await passkeyLogin({
  optionsUrl: '/webauthn/login/options',
  verifyUrl: '/webauthn/login/verify',
  prf: { enabled: true } // experimental
});
if (auth.ok) {
  // success
}
```

## Experimental: PRF-based deterministic seed (opt-in)

- Server exposes a site-scoped PRF input salt when enabled. Instantiate the service with `enablePrf: true`:

```php
$service = new Passkey\PasskeyService($provider, rpName: 'Your App', enablePrf: true);
```

- During registration, a per-passkey 32-byte random salt is generated and stored in `prf_salt`.

- Clients that opt-in to PRF (`prf: { enabled: true }`) will request PRF from the authenticator and return the PRF output in `clientExtensionResults.prfResults`.

- After a successful assertion (or attestation), you can derive a deterministic 32-byte seed on the server from the client PRF output and the stored `prf_salt` using:

```php
$seedB64Url = $service->deriveSeedFromPrf($credentialIdRaw, $prfFirstOutputB64Url);
```

- The PRF output must be 32 bytes (`UnexpectedValueException` otherwise); an unknown credential throws a
  `RuntimeException`.

- **The seed proves nothing by itself.** `deriveSeedFromPrf()` derives a seed from whatever PRF output it is given:
  the seed is bound to no verified assertion. Never treat a derived seed as authentication; use it only as key
  material, where a wrong PRF output gives a key that decrypts nothing.
>Notes on PRF-derived seed usage: 
> - Unfortunately, not all authenticators support PRF, as this is a client opt-in extension, you cannot enforce it. I would highly recommend keeping a fallback solution. Currently, only linux-based platform authenticators, macOS/iOS, android and certain authenticator app support PRF.
> - The derived PRF output is a stable and cryptographically strong 32-byte material that can be used as a `seed` for encryption. It is not a secret by itself. And thus, cannot and should not be used as one.