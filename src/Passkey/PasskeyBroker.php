<?php namespace Passkey;

use stdClass;

class PasskeyBroker extends DatabaseBroker implements PasskeyBrokerInterface
{
    public function findUserIdByCredentialId(string $credentialId): ?int
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

    public function findAllByUserId(string $userId): array
    {
        $sql = "SELECT * FROM account.passkeys WHERE user_id = ?";
        return $this->select($sql, [$userId]);
    }

    public function findUserIdentity(string $userId): stdClass
    {
        $sql = "SELECT email, COALESCE(fullname, username) AS display_name FROM account.view_user_profile WHERE id = ?";
        return $this->selectSingle($sql, [$userId]);
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
        // Insert binary data into BYTEA columns using decode(hex, 'hex') to avoid UTF-8 encoding issues
        $sql = "INSERT INTO account.passkeys (user_id, credential_id, public_key_cose, sign_count, backup_eligible, transports) 
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