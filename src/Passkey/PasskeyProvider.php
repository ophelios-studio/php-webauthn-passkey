<?php namespace Passkey;

use Symfony\Component\Uid\Uuid;
use Webauthn\CredentialRecord;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\PublicKeyCredentialUserEntity;
use Webauthn\TrustPath\EmptyTrustPath;

readonly class PasskeyProvider
{
    private PasskeyBrokerInterface $broker;

    public function __construct(PasskeyBrokerInterface $broker)
    {
        $this->broker = $broker;
    }

    public function findByCredentialId(string $credentialId): ?Passkey
    {
        $row = $this->broker->findByCredentialId($credentialId);
        return $row === null ? null : Passkey::fromRow($row);
    }

    /**
     * @return Passkey[]
     */
    public function findAllByIdentity(mixed $identifier): array
    {
        return Passkey::fromRows($this->broker->findAllByIdentity($identifier));
    }

    /**
     * The identifier the broker stored with the credential, or null when the credential is unknown.
     */
    public function findUserIdByCredentialId(string $credentialId): mixed
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

    /**
     * The stored credential as the assertion validator needs it. Its backup eligibility is left
     * unknown (null): stored values were written with a false default, and a wrong one would make
     * the library refuse every assertion of a synced passkey.
     */
    public function getCredentialSource(string $credentialId): ?CredentialRecord
    {
        $row = $this->broker->findByCredentialId($credentialId);
        if (!$row) {
            return null;
        }
        $passkey = Passkey::fromRow($row);
        $credIdBin = $passkey->credential_id ?? null;
        $pubKeyCoseBin = $passkey->public_key_cose ?? null;
        $transports = [];
        if (!empty($row->transports)) {
            $transports = array_values(array_filter(array_map('trim', explode(',', $row->transports))));
        }
        return new CredentialRecord(
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
