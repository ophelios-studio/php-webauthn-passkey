<?php

declare(strict_types=1);

namespace Passkey\Tests\Support;

use Passkey\PasskeyProvider;
use Passkey\PasskeyService;
use PHPUnit\Framework\TestCase;

/**
 * Runs the service the way a request does: a native PHP session (kept in memory), the relying
 * party host in $_SERVER, and a response code reset to 200 before each test.
 */
abstract class PasskeyTestCase extends TestCase
{
    protected const string HOST = 'app.example.com';
    protected const string ORIGIN = 'https://app.example.com';
    protected const string USER_ID = '42';

    protected InMemoryPasskeyBroker $broker;

    /** @var array<string, mixed> */
    private array $serverBackup;

    protected function setUp(): void
    {
        $this->serverBackup = $_SERVER;
        $_SERVER['HTTP_HOST'] = self::HOST;
        session_set_save_handler(new InMemorySessionHandler(), false);
        session_start();
        http_response_code(200);

        $this->broker = new InMemoryPasskeyBroker();
        $this->broker->addIdentity(self::USER_ID, 'ada@example.com', 'Ada Lovelace');
    }

    protected function tearDown(): void
    {
        $_SESSION = [];
        session_destroy();
        $_SERVER = $this->serverBackup;
    }

    protected function service(bool $enablePrf = false): PasskeyService
    {
        return new PasskeyService(new PasskeyProvider($this->broker), 'Test App', enablePrf: $enablePrf);
    }

    protected static function base64UrlDecode(string $encoded): string
    {
        $decoded = base64_decode(strtr($encoded, '-_', '+/'), true);
        self::assertIsString($decoded, 'not valid base64url');
        return $decoded;
    }
}
