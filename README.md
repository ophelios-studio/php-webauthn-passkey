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

CREATE TABLE account.passkey
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

use stdClass;

class PasskeyBroker extends DatabaseBroker implements PasskeyBrokerInterface
{
    public function findUserIdByCredentialId(string $credentialId): ?int
    {
        $sql = "SELECT user_id FROM account.passkey WHERE credential_id = decode(?, 'hex') LIMIT 1";
        $row = $this->selectSingle($sql, [bin2hex($credentialId)]);
        return $row?->user_id ?? null;
    }

    public function findByCredentialId(string $credentialId): ?stdClass
    {
        $sql = "SELECT * FROM account.passkey WHERE credential_id = decode(?, 'hex') LIMIT 1";
        return $this->selectSingle($sql, [bin2hex($credentialId)]);
    }

    public function findAllByUserId(string $userId): array
    {
        $sql = "SELECT * FROM account.passkey WHERE user_id = ?";
        return $this->select($sql, [$userId]);
    }

    public function findUserIdentity(string $userId): stdClass
    {
        $sql = "SELECT email, COALESCE(fullname, username) AS display_name FROM account.view_user_profile WHERE id = ?";
        return $this->selectSingle($sql, [$userId]);
    }

    public function updateUsageAndCounter(string $credentialId, int $newSignCount): void
    {
        $this->query("UPDATE account.passkey 
                         SET sign_count = ?, 
                             last_used_at = now() 
                       WHERE credential_id = decode(?, 'hex')", [
            $newSignCount,
            bin2hex($credentialId)
        ]);
    }

    public function insert(Passkey $passkey): void
    {
        // Insert binary data into BYTEA columns using decode(hex, 'hex') to avoid UTF-8 encoding issues
        $sql = "INSERT INTO account.passkey (user_id, credential_id, public_key_cose, sign_count, backup_eligible, transports) 
                VALUES (?, decode(?, 'hex'), decode(?, 'hex'), ?, ?, ?)";
        $this->query($sql, [
            $passkey->user_id,
            $passkey->credential_id,
            $passkey->public_key_cose,
            $passkey->sign_count,
            $passkey->backup_eligible,
            $passkey->transports
        ]);
    }
}
```
