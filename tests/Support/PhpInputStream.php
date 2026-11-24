<?php

declare(strict_types=1);

namespace Passkey\Tests\Support;

/**
 * Replaces the built-in "php" stream wrapper so php://input returns a chosen request body, the way
 * the web server hands it to verify() and authenticate(). Every other php:// stream (memory, temp,
 * stdout) is opened by the built-in wrapper and passed through.
 */
final class PhpInputStream
{
    private static ?string $body = null;

    /** @var resource|null set by PHP */
    public $context;

    /** @var resource|null the built-in stream for any path other than php://input */
    private $inner = null;

    private string $data = '';

    private int $position = 0;

    public static function serve(string $body): void
    {
        if (self::$body === null) {
            stream_wrapper_unregister('php');
            stream_wrapper_register('php', self::class);
        }
        self::$body = $body;
    }

    public static function restore(): void
    {
        if (self::$body !== null) {
            stream_wrapper_restore('php');
            self::$body = null;
        }
    }

    public function stream_open(string $path, string $mode, int $options, ?string &$openedPath): bool
    {
        if (strtolower($path) === 'php://input') {
            $this->data = (string) self::$body;
            return true;
        }
        stream_wrapper_restore('php');
        try {
            $this->inner = fopen($path, $mode) ?: null;
        } finally {
            stream_wrapper_unregister('php');
            stream_wrapper_register('php', self::class);
        }
        return $this->inner !== null;
    }

    public function stream_read(int $count): string|false
    {
        if ($this->inner !== null) {
            return fread($this->inner, $count);
        }
        $chunk = substr($this->data, $this->position, $count);
        $this->position += strlen($chunk);
        return $chunk;
    }

    public function stream_write(string $data): int|false
    {
        return $this->inner !== null ? fwrite($this->inner, $data) : false;
    }

    public function stream_eof(): bool
    {
        return $this->inner !== null ? feof($this->inner) : $this->position >= strlen($this->data);
    }

    public function stream_tell(): int|false
    {
        return $this->inner !== null ? ftell($this->inner) : $this->position;
    }

    public function stream_seek(int $offset, int $whence): bool
    {
        if ($this->inner !== null) {
            return fseek($this->inner, $offset, $whence) === 0;
        }
        return false;
    }

    public function stream_flush(): bool
    {
        return $this->inner === null || fflush($this->inner);
    }

    /**
     * @return array<int|string, int>|false
     */
    public function stream_stat(): array|false
    {
        return $this->inner !== null ? fstat($this->inner) : ['size' => strlen($this->data)];
    }

    public function stream_close(): void
    {
        if ($this->inner !== null) {
            fclose($this->inner);
        }
    }
}
