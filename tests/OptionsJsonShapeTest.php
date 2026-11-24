<?php

declare(strict_types=1);

namespace Passkey\Tests;

use Passkey\Tests\Support\PasskeyTestCase;
use PHPUnit\Framework\Attributes\DataProvider;

/**
 * Pins the JSON that options() and assertionOptions() hand to the browser: the JavaScript module
 * (backpack/public/javascripts/pulsar/modules/passkey.js) reads these keys and decodes these
 * base64url fields, so any change of key, nesting, type or encoding breaks every consumer.
 */
final class OptionsJsonShapeTest extends PasskeyTestCase
{
    /** Its base64 is "dXNlcjphZGE/Pn4=": the base64url form must carry "_" and no padding. */
    private const string USER_HANDLE = 'user:ada?>~';

    private const string MASKED_CHALLENGE = '<random 32 bytes, base64url>';

    #[DataProvider('ceremonies')]
    public function test_the_options_json_sent_to_the_browser_keeps_its_shape(
        string $ceremony,
        bool $enablePrf,
        string $fixture,
    ): void {
        $this->broker->addIdentity(self::USER_HANDLE, 'ada@example.com', 'Ada Lovelace');
        $service = $this->service($enablePrf);

        $options = $ceremony === 'registration'
            ? $service->options(self::USER_HANDLE)
            : $service->assertionOptions();

        self::assertIsArray($options);
        self::assertSame(self::fixture($fixture), self::sortKeys(self::maskChallenge($options)));
    }

    /**
     * @return iterable<string, array{string, bool, string}>
     */
    public static function ceremonies(): iterable
    {
        yield 'registration' => ['registration', false, 'creation-options.json'];
        yield 'registration with PRF' => ['registration', true, 'creation-options-prf.json'];
        yield 'login' => ['login', false, 'request-options.json'];
        yield 'login with PRF' => ['login', true, 'request-options-prf.json'];
    }

    /**
     * The challenge is the only random value: check its encoding and length, then mask it.
     *
     * @param array<string, mixed> $options
     * @return array<string, mixed>
     */
    private static function maskChallenge(array $options): array
    {
        self::assertIsString($options['challenge'] ?? null);
        self::assertMatchesRegularExpression('/^[A-Za-z0-9_-]{43}$/', $options['challenge']);
        self::assertSame(32, strlen(self::base64UrlDecode($options['challenge'])));
        $options['challenge'] = self::MASKED_CHALLENGE;
        return $options;
    }

    /**
     * Key order means nothing to the browser; types and values do.
     */
    private static function sortKeys(mixed $value): mixed
    {
        if (!is_array($value)) {
            return $value;
        }
        $value = array_map(self::sortKeys(...), $value);
        if (!array_is_list($value)) {
            ksort($value);
        }
        return $value;
    }

    private static function fixture(string $name): mixed
    {
        $json = file_get_contents(__DIR__ . '/Fixtures/' . $name);
        self::assertIsString($json);
        return self::sortKeys(json_decode($json, true, flags: JSON_THROW_ON_ERROR));
    }
}
