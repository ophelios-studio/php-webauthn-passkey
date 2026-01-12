<?php namespace Passkey;

use stdClass;

interface PasskeyBrokerInterface
{
    public function findIdentifierByCredentialId(string $credentialId): mixed;

    public function findIdentity(mixed $identifier): stdClass;

    public function updateUsageAndCounter(string $credentialId, int $newSignCount): void;

    public function findByCredentialId(string $credentialId): ?stdClass;

    public function findAllByIdentity(mixed $identifier): array;

    public function insert(Passkey $passkey): void;
}
