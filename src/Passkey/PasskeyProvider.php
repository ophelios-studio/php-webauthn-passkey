<?php namespace Passkey;

use Symfony\Component\Uid\Uuid;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\PublicKeyCredentialSource;
use Webauthn\PublicKeyCredentialUserEntity;
use Webauthn\TrustPath\EmptyTrustPath;

readonly class PasskeyProvider
{
    private PasskeyBrokerInterface $broker;

    public function __construct(PasskeyBrokerInterface $broker)
    {
        $this->broker = $broker;
    }

    public function findUserIdByCredentialId(string $credentialId): ?int
    {
        return $this->broker->findUserIdByCredentialId($credentialId);
    }

    public function getUserCredentialEntity(string $userId): PublicKeyCredentialUserEntity
    {
        $profile = $this->broker->findUserIdentity($userId);
        $email = $profile->email ?? $userId;
        $display = $profile->display_name ?? $userId;
        return new PublicKeyCredentialUserEntity($email, $userId, $display);
    }

    public function getCredentialSource(string $credentialId): ?PublicKeyCredentialSource
    {
        $row = $this->broker->findByCredentialId($credentialId);
        if (!$row) {
            return null;
        }
        $passkey = Passkey::fromRow($row);

        // Normalize BYTEA fields
        $credIdBin = Utils::byteaToString($passkey->credential_id ?? null);
        $pubKeyCoseBin = Utils::byteaToString($passkey->public_key_cose ?? null);

        $transports = null;
        if (!empty($row->transports)) {
            $transports = array_values(array_filter(array_map('trim', explode(',', $row->transports))));
        }
        // Ensure credential_id and public_key_cose are raw binary. If values look like hex strings, decode them.
        $credId = $credIdBin;
        $pubKeyCose = $pubKeyCoseBin;
        if ($credId !== '' && ctype_xdigit($credId) && (strlen($credId) % 2 === 0)) {
            $decoded = @hex2bin($credId);
            if ($decoded !== false) {
                $credId = $decoded;
            }
        }
        if ($pubKeyCose !== '' && ctype_xdigit($pubKeyCose) && (strlen($pubKeyCose) % 2 === 0)) {
            $decoded = @hex2bin($pubKeyCose);
            if ($decoded !== false) {
                $pubKeyCose = $decoded;
            }
        }

        // AAGUID is the authenticator GUID, not the DB row id. If you do not store it, use the nil UUID.
        $nilAaguid = Uuid::fromString('00000000-0000-0000-0000-000000000000');

        return new PublicKeyCredentialSource(
            publicKeyCredentialId: $credId,
            type: PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY,
            transports: $transports,
            attestationType: 'none',
            trustPath: new EmptyTrustPath(),
            aaguid: $nilAaguid,
            credentialPublicKey: $pubKeyCose,
            userHandle: (string)$row->user_id,
            counter: (int)$row->sign_count,
            otherUI: []
        );
    }

    public function updateUsageAndCounter(string $credentialId, int $newSignCount): void
    {
        $this->broker->updateUsageAndCounter($credentialId, $newSignCount);
    }

    public function saveAttestation(Passkey $passkey): void
    {
        $this->broker->insert($passkey);
    }
}
