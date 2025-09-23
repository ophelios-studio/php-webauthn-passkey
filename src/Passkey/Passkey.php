<?php namespace Passkey;

final readonly class Passkey
{
    public function __construct(
        public ?string $id, // uuid
        public int $user_id,
        public string $credential_id, // binary (BYTEA) from DB
        public string $public_key_cose, // binary (BYTEA)
        public int $sign_count,
        public bool $backup_eligible,
        public ?string $transports,
        public ?string $created_at = null,
        public ?string $last_used_at = null,
    ) {}

    /**
     * Create a Passkey instance from a database row (object, array, or ArrayAccess),
     * normalizing BYTEA streams/resources to strings and casting types safely.
     */
    public static function fromRow(object|array $row): self
    {
        // Access helpers for both array and object rows
        $get = static function(string $k) use ($row) {
            if (is_array($row)) return $row[$k] ?? null;
            return $row->$k ?? null;
        };

        $id = (string) $get('id');
        $userId = (int) $get('user_id');
        $credentialId = Utils::byteaToString($get('credential_id'));
        $publicKeyCose = Utils::byteaToString($get('public_key_cose'));
        $signCount = (int) $get('sign_count');
        $backupEligible = (bool) $get('backup_eligible');
        $transports = $get('transports');
        $transports = $transports !== null ? (string)$transports : null;
        $createdAt = (string) $get('created_at');
        $lastUsedAt = $get('last_used_at');
        $lastUsedAt = $lastUsedAt !== null ? (string)$lastUsedAt : null;

        return new self(
            id: $id,
            user_id: $userId,
            credential_id: $credentialId,
            public_key_cose: $publicKeyCose,
            sign_count: $signCount,
            backup_eligible: $backupEligible,
            transports: $transports,
            created_at: $createdAt,
            last_used_at: $lastUsedAt,
        );
    }

    /**
     * Build an array of Passkey from a set of rows.
     * @param iterable<object|array> $rows
     * @return array<self>
     */
    public static function fromRows(iterable $rows): array
    {
        $out = [];
        foreach ($rows as $r) {
            $out[] = self::fromRow($r);
        }
        return $out;
    }
}
