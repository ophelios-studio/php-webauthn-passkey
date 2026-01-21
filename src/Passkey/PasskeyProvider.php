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

    public function findByCredentialId(string $credentialId): Passkey
    {
        $res = $this->broker->findByCredentialId($credentialId);
        return Passkey::fromRow($res);
    }

    /**
     * @return Passkey[]
     */
    public function findAllByIdentity(mixed $identifier): array
    {
        return Passkey::fromRows($this->broker->findAllByIdentity($identifier));
    }

    public function findUserIdByCredentialId(string $credentialId): ?int
    {
        return $this->broker->findIdentifierByCredentialId($credentialId);
    }

    public function getUserCredentialEntity(mixed $userId): PublicKeyCredentialUserEntity
    {
        $profile = $this->broker->findIdentity($userId);
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
        $credIdBin = $passkey->credential_id ?? null;
        $pubKeyCoseBin = $passkey->public_key_cose ?? null;
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
            aaguid: Uuid::fromString('00000000-0000-0000-0000-000000000000'),
            credentialPublicKey: $pubKeyCoseBin,
            userHandle: (string) $row->user_id,
            counter: (int) $row->sign_count,
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
