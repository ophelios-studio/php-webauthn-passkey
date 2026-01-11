<?php namespace Passkey;

use stdClass;

interface PasskeyBrokerInterface
{
    public function findUserIdByCredentialId(string $credentialId): mixed;

    public function findUserIdentity(mixed $identity): stdClass;

    public function updateUsageAndCounter(string $credentialId, int $newSignCount): void;

    public function findByCredentialId(string $credentialId): ?stdClass;

    public function findAllByUserId(mixed $identity): array;

    public function insert(Passkey $passkey): void;
}
