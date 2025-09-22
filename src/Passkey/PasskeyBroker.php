<?php namespace Passkey;

use Symfony\Component\Uid\Uuid;
use Webauthn\PublicKeyCredentialUserEntity;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\PublicKeyCredentialSource;
use Webauthn\TrustPath\EmptyTrustPath;

class PasskeyBroker extends DatabaseBroker implements PasskeyBrokerInterface
{
    public function findUserIdByCredentialId(string $credentialId): ?int
    {
        $row = $this->selectSingle("SELECT user_id FROM account.passkeys WHERE credential_id = decode(?, 'hex') LIMIT 1", [bin2hex($credentialId)]);
        return $row?->user_id ?? null;
    }
    public function getUserEntity(int $userId): PublicKeyCredentialUserEntity
    {
        $profile = $this->selectSingle("SELECT email, COALESCE(firstname || ' ' || lastname, username) AS display_name FROM account.view_user_profile WHERE id = ?", [$userId]);
        $email = $profile->email ?? (string)$userId;
        $display = $profile->display_name ?? (string)$userId;
        return new PublicKeyCredentialUserEntity($email, (string) $userId, $display);
    }

    public function getCredentialSource(string $credentialId): ?PublicKeyCredentialSource
    {
        $sql = "SELECT * FROM account.passkeys WHERE credential_id = decode(?, 'hex') LIMIT 1";
        $row = $this->selectSingle($sql, [bin2hex($credentialId)]);
        if (!$row) return null;

        // Normalize BYTEA fields which may be returned as streams/resources
        $credIdBin = $this->byteaToString($row->credential_id ?? null);
        $pubKeyCoseBin = $this->byteaToString($row->public_key_cose ?? null);

        $transports = null;
        if (!empty($row->transports)) {
            $transports = array_values(array_filter(array_map('trim', explode(',', $row->transports))));
        }
        return new PublicKeyCredentialSource(
            publicKeyCredentialId: $credIdBin,
            type: PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY,
            transports: $transports,
            attestationType: 'none',
            trustPath: new EmptyTrustPath(),
            aaguid: new Uuid($row->id),
            credentialPublicKey: $pubKeyCoseBin,
            userHandle: (string)$row->user_id,
            counter: (int)$row->sign_count,
            otherUI: []
        );
    }

    /**
     * @return Passkey[]
     */
    public function findAllForUser(int $userId): array
    {
        $sql = "SELECT * FROM account.passkeys WHERE user_id = ?";
        $rows = $this->select($sql, [$userId]);
        return Passkey::fromRows($rows);
    }

    public function updateUsageAndCounter(string $credentialId, int $newSignCount): void
    {
        $this->query("UPDATE account.passkeys SET sign_count = ?, last_used_at = now() WHERE credential_id = decode(?, 'hex')", [
            $newSignCount,
            bin2hex($credentialId)
        ]);
    }

    public function saveAttestation(int $userId, string $credentialId, string $publicKeyCose, int $signCount, bool $backupEligible, ?string $transports): void
    {
        // Insert binary data into BYTEA columns using decode(hex, 'hex') to avoid UTF-8 encoding issues
        $sql = "INSERT INTO account.passkeys (user_id, credential_id, public_key_cose, sign_count, backup_eligible, transports) VALUES (?, decode(?, 'hex'), decode(?, 'hex'), ?, ?, ?)";
        $this->query($sql, [
            $userId,
            bin2hex($credentialId),
            bin2hex($publicKeyCose),
            $signCount,
            $backupEligible,
            $transports
        ]);
    }
    private function byteaToString(mixed $v): string
    {
        if (is_resource($v)) {
            $data = stream_get_contents($v);
            return $data === false ? '' : $data;
        }
        if ($v instanceof \Stringable) {
            return (string)$v;
        }
        return is_string($v) ? $v : '';
    }
}