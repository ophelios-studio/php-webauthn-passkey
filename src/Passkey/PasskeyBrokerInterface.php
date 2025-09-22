<?php namespace Passkey;

use Webauthn\PublicKeyCredentialUserEntity;
use Webauthn\PublicKeyCredentialSource;

interface PasskeyBrokerInterface
{
    /**
     * Locate the user id that owns the given credential id (binary rawId).
     */
    public function findUserIdByCredentialId(string $credentialId): ?int;

    /**
     * Build the WebAuthn user entity used during registration options.
     */
    public function getUserEntity(int $userId): PublicKeyCredentialUserEntity;

    /**
     * Load a PublicKeyCredentialSource for the given credential id (binary rawId).
     */
    public function getCredentialSource(string $credentialId): ?PublicKeyCredentialSource;

    /**
     * Update last-used timestamp and signature counter for a credential.
     */
    public function updateUsageAndCounter(string $credentialId, int $newSignCount): void;

    /**
     * Persist a new attested credential for a user.
     */
    public function saveAttestation(int $userId, string $credentialId, string $publicKeyCose, int $signCount, bool $backupEligible, ?string $transports): void;
}
