<?php

declare(strict_types=1);

namespace Passkey\Tests;

use Passkey\Tests\Support\PasskeyTestCase;
use Passkey\Tests\Support\PhpInputStream;
use PHPUnit\Framework\Attributes\DataProvider;

/**
 * A body the library cannot read is answered, not thrown: every consumer returns the array as
 * JSON, so an exception would surface as a server error on any garbage a client posts.
 */
final class MalformedRequestTest extends PasskeyTestCase
{
    #[DataProvider('unreadableBodies')]
    public function test_an_unreadable_credential_is_answered_with_a_bad_request(string $ceremony, string $body): void
    {
        $service = $this->service();
        $service->options(self::USER_ID);
        $service->assertionOptions();
        $signedIn = false;
        PhpInputStream::serve($body);

        $result = $ceremony === 'registration'
            ? $service->verify(self::USER_ID)
            : $service->authenticate(static function () use (&$signedIn): void {
                $signedIn = true;
            });

        self::assertSame(['ok' => false, 'err' => 'Verification failed'], $result);
        self::assertSame(400, http_response_code());
        self::assertSame([], $this->broker->inserted);
        self::assertFalse($signedIn);
    }

    /**
     * One row per way the library's denormalizer fails: a shape it refuses, a base64url, a JSON and
     * a CBOR it cannot decode.
     *
     * @return iterable<string, array{string, string}>
     */
    public static function unreadableBodies(): iterable
    {
        $clientData = self::base64Url('{"type":"webauthn.get","challenge":"AAAA","origin":"https://app.example.com"}');
        $bodies = [
            'the credential is not an object' => '{"credential":"x"}',
            'the raw id is not base64url' => self::body(['id' => '***', 'rawId' => '***', 'type' => 'public-key', 'response' => ['clientDataJSON' => $clientData, 'authenticatorData' => 'AA', 'signature' => 'AA']]),
            'the client data is not JSON' => self::body(['id' => 'AA', 'rawId' => 'AA', 'type' => 'public-key', 'response' => ['clientDataJSON' => self::base64Url('nope'), 'authenticatorData' => 'AA', 'signature' => 'AA']]),
            'the attestation object is not CBOR' => self::body(['id' => 'AA', 'rawId' => 'AA', 'type' => 'public-key', 'response' => ['clientDataJSON' => $clientData, 'attestationObject' => self::base64Url("\xff\xff")]]),
        ];
        foreach (['registration', 'login'] as $ceremony) {
            foreach ($bodies as $name => $body) {
                yield "$ceremony: $name" => [$ceremony, $body];
            }
        }
    }

    /**
     * @param array<string, mixed> $credential
     */
    private static function body(array $credential): string
    {
        return json_encode(['credential' => $credential], JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
    }

    private static function base64Url(string $bytes): string
    {
        return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
    }
}
