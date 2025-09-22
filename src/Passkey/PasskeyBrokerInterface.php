<?php namespace Passkey;

use stdClass;

interface PasskeyBrokerInterface
{
    public function findUserIdByCredentialId(string $credentialId): ?int;

    public function findUserIdentity(string $userId): stdClass;

    public function updateUsageAndCounter(string $credentialId, int $newSignCount): void;

    public function findByCredentialId(string $credentialId): ?stdClass;

    public function findAllByUserId(string $userId): array;

    public function insert(Passkey $passkey): void;
}
