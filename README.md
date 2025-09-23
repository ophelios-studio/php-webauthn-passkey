# PHP WebAuthn Passkey

## 💿 Installation and dependencies
Install with Composer:

```
composer require ophelios/php-webauthn-passkey
```

Requirements: PHP >= 8.4

### Add the required table into your database. The example below if for PostgreSQL:

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
    transports TEXT, -- e.g. "internal,usb,nfc"
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used_at TIMESTAMPTZ
);
```
Replace the `<YOUR USER ID REFERENCE>` with the column name of your user identifier.

The identifier column if of type UUID given by `gen_random_uuid()` which is included in the extension `pgcrypto`. 
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
    public function findUserIdByCredentialId(string $credentialId): ?int
    {
        $sql = "SELECT user_id FROM account.passkeys WHERE credential_id = ? LIMIT 1";
        $row = $this->selectSingle($sql, [bin2hex($credentialId)]);
        return $row?->user_id ?? null;
    }

    public function findByCredentialId(string $credentialId): ?stdClass
    {
        $sql = "SELECT * FROM account.passkeys WHERE credential_id = ? LIMIT 1";
        return $this->selectSingle($sql, [bin2hex($credentialId)]);
    }

    public function findAllByUserId(string $userId): array
    {
        $sql = "SELECT * FROM account.passkeys WHERE user_id = ?";
        return $this->select($sql, [$userId]);
    }

    public function findUserIdentity(string $userId): stdClass
    {
        $sql = "SELECT email, fullname AS display_name FROM account.view_user_profile WHERE id = ?";
        return $this->selectSingle($sql, [$userId]);
    }

    public function updateUsageAndCounter(string $credentialId, int $newSignCount): void
    {
        $this->query("UPDATE account.passkeys 
                         SET sign_count = ?, 
                             last_used_at = now() 
                       WHERE credential_id = ?", [
            $newSignCount,
            bin2hex($credentialId)
        ]);
    }

    public function insert(Passkey $passkey): void
    {
        $sql = "INSERT INTO account.passkeys (user_id, credential_id, public_key_cose, sign_count, backup_eligible, transports) 
                VALUES (?, decode(?, 'hex'), decode(?, 'hex'), ?, ?, ?)";
        $this->query($sql, [
            $passkey->user_id,
            bin2hex($passkey->credential_id),
            bin2hex($passkey->public_key_cose),
            $passkey->sign_count,
            $passkey->backup_eligible,
            $passkey->transports
        ]);
    }
}
```

### Create your registration Controller
```php
<?php namespace Controllers\Application;

use Models\Account\Services\WebAuthnService;
use Zephyrus\Network\Response;
use Zephyrus\Network\Router\Post;

class WebAuthnController extends AppController
{
    #[Post("/webauthn/register/options")]
    public function options(): Response
    {
        $service = new PasskeyService();
        return $this->json($service->options(Passport::getUserId()));
    }

    #[Post("/webauthn/register/verify")]
    public function verify(): Response
    {
        $service = new PasskeyService();
        return $this->json($service->verify(Passport::getUserId()));
    }
}
```

### Create your authentication Controller
```php
<?php namespace Controllers\Public;

use Controllers\Controller;
use Models\Account\Services\WebAuthnService;
use Zephyrus\Network\Response;
use Zephyrus\Network\Router\Post;

class WebAuthnController extends Controller
{
    #[Post("/webauthn/login/options")]
    public function options(): Response
    {
        $service = new WebAuthnService();
        return $this->json($service->assertionOptions());
    }

    #[Post("/webauthn/login/verify")]
    public function verify(): Response
    {
        $service = new WebAuthnService();
        return $this->json($service->authenticate());
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

- Module file: backpack/public/javascripts/modules/passkey.js

Registration (create) example with callbacks:

```html
<button id="createPasskeyBtn">Create a Passkey</button>
<script type="module">
  import { initPasskeyRegistration } from '/javascripts/modules/passkey.js';
  initPasskeyRegistration({
    buttonSelector: '#createPasskeyBtn',
    optionsUrl: '/webauthn/register/options',
    verifyUrl: '/webauthn/register/verify',
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
  import { initPasskeyLogin } from '/javascripts/modules/passkey.js';
  initPasskeyLogin({
    buttonSelector: '#btn-passkey-login',
    optionsUrl: '/webauthn/login/options',
    verifyUrl: '/webauthn/login/verify',
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
import { registerPasskey, passkeyLogin } from '/javascripts/modules/passkey.js';

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
  verifyUrl: '/webauthn/login/verify'
});
if (auth.ok) {
  // success
}
```
