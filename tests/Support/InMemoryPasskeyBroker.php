<?php

declare(strict_types=1);

namespace Passkey\Tests\Support;

use Passkey\Passkey;
use Passkey\PasskeyBrokerInterface;
use stdClass;

/**
 * A broker that keeps passkeys in memory, shaped like the rows a database broker returns
 * (binary columns as strings, transports as a comma separated list).
 */
final class InMemoryPasskeyBroker implements PasskeyBrokerInterface
{
    /** @var array<string, stdClass> rows keyed by raw credential id */
    private array $rows = [];

    /** @var array<string, stdClass> identities keyed by identifier */
    private array $identities = [];

    /** @var list<Passkey> */
    public array $inserted = [];

    public function addIdentity(string $identifier, string $email, string $displayName): void
    {
        $this->identities[$identifier] = (object) ['email' => $email, 'display_name' => $displayName];
    }

    public function findIdentifierByCredentialId(string $credentialId): mixed
    {
        return $this->rows[$credentialId]->user_id ?? null;
    }

    public function findIdentity(mixed $identifier): stdClass
    {
        return $this->identities[(string) $identifier] ?? new stdClass();
    }

    public function updateUsageAndCounter(string $credentialId, int $newSignCount): void
    {
        $this->rows[$credentialId]->sign_count = $newSignCount;
        $this->rows[$credentialId]->last_used_at = '2030-01-01 00:00:00+00';
    }

    public function findByCredentialId(string $credentialId): ?stdClass
    {
        return isset($this->rows[$credentialId]) ? clone $this->rows[$credentialId] : null;
    }

    public function findAllByIdentity(mixed $identifier): array
    {
        return array_values(array_filter(
            $this->rows,
            static fn (stdClass $row): bool => (string) $row->user_id === (string) $identifier,
        ));
    }

    public function insert(Passkey $passkey): void
    {
        $this->inserted[] = $passkey;
        $this->rows[$passkey->credential_id] = (object) [
            'id' => 'passkey-' . count($this->inserted),
            'user_id' => $passkey->user_id,
            'credential_id' => $passkey->credential_id,
            'public_key_cose' => $passkey->public_key_cose,
            'sign_count' => $passkey->sign_count,
            'backup_eligible' => $passkey->backup_eligible,
            'prf_salt' => $passkey->prf_salt,
            'prf_eval_label' => $passkey->prf_eval_label,
            'transports' => $passkey->transports,
            'created_at' => '2030-01-01 00:00:00+00',
            'last_used_at' => null,
        ];
    }

    public function signCountOf(string $credentialId): ?int
    {
        return $this->rows[$credentialId]->sign_count ?? null;
    }

    /**
     * Overwrites a stored column, to put a row in a state a real database could hold.
     */
    public function setColumn(string $credentialId, string $column, mixed $value): void
    {
        $this->rows[$credentialId]->$column = $value;
    }
}
