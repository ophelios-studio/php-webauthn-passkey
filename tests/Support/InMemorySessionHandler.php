<?php

declare(strict_types=1);

namespace Passkey\Tests\Support;

use SessionHandlerInterface;

/**
 * Native session storage kept in memory, so a test can start the PHP session the library relies
 * on without touching the file system.
 */
final class InMemorySessionHandler implements SessionHandlerInterface
{
    /** @var array<string, string> */
    private array $sessions = [];

    public function open(string $path, string $name): bool
    {
        return true;
    }

    public function close(): bool
    {
        return true;
    }

    public function read(string $id): string
    {
        return $this->sessions[$id] ?? '';
    }

    public function write(string $id, string $data): bool
    {
        $this->sessions[$id] = $data;
        return true;
    }

    public function destroy(string $id): bool
    {
        unset($this->sessions[$id]);
        return true;
    }

    public function gc(int $max_lifetime): int
    {
        return 0;
    }
}
