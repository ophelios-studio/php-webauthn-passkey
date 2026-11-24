<?php

declare(strict_types=1);

namespace Passkey\Tests\Support;

use Passkey\PasskeyProvider;
use Passkey\PasskeyService;
use PHPUnit\Framework\TestCase;
use Throwable;

/**
 * Runs the service the way a request does: a native PHP session (kept in memory), the relying
 * party host in $_SERVER, the request body behind php://input, and a response code reset to 200
 * before each test. Time stands still on a frozen clock until a test moves it.
 */
abstract class PasskeyTestCase extends TestCase
{
    protected const string HOST = 'app.example.com';
    protected const string ORIGIN = 'https://app.example.com';
    protected const string USER_ID = '42';

    protected InMemoryPasskeyBroker $broker;

    protected FrozenClock $clock;

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
        $this->clock = FrozenClock::at('2030-01-01T00:00:00+00:00');
    }

    protected function tearDown(): void
    {
        PhpInputStream::restore();
        $_SESSION = [];
        session_destroy();
        $_SERVER = $this->serverBackup;
    }

    /**
     * @param list<string> $allowedOrigins
     */
    protected function service(bool $enablePrf = false, ?string $rpId = null, array $allowedOrigins = []): PasskeyService
    {
        return new PasskeyService(
            new PasskeyProvider($this->broker),
            'Test App',
            rpId: $rpId,
            enablePrf: $enablePrf,
            allowedOrigins: $allowedOrigins,
            clock: $this->clock,
        );
    }

    /**
     * Serves {"credential": ...} as the request body, the way the JavaScript module posts it.
     *
     * @param array<string, mixed> $credential
     */
    protected static function postCredential(array $credential): void
    {
        PhpInputStream::serve(json_encode(['credential' => $credential], JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR));
    }

    /**
     * Runs the call and returns what it threw, so a test can assert the refusal and then the state
     * it left behind.
     */
    protected static function refusalOf(callable $call): ?Throwable
    {
        try {
            $call();
        } catch (Throwable $refusal) {
            return $refusal;
        }
        return null;
    }

    protected static function base64UrlDecode(string $encoded): string
    {
        $decoded = base64_decode(strtr($encoded, '-_', '+/'), true);
        self::assertIsString($decoded, 'not valid base64url');
        return $decoded;
    }
}
