<?php

declare(strict_types=1);

namespace Passkey\Tests\Support;

use DateTimeImmutable;
use Psr\Clock\ClockInterface;

/**
 * A clock that tells the same instant until a test moves it forward.
 */
final class FrozenClock implements ClockInterface
{
    private function __construct(private DateTimeImmutable $now)
    {
    }

    public static function at(string $instant): self
    {
        return new self(new DateTimeImmutable($instant));
    }

    public function now(): DateTimeImmutable
    {
        return $this->now;
    }

    public function advance(int $seconds): void
    {
        $this->now = $this->now->modify(sprintf('+%d seconds', $seconds));
    }
}
