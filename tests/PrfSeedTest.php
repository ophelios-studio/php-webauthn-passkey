<?php

declare(strict_types=1);

namespace Passkey\Tests;

use Passkey\PasskeyService;
use Passkey\Tests\Support\PasskeyTestCase;
use Passkey\Tests\Support\SoftwareAuthenticator;
use PHPUnit\Framework\Attributes\DataProvider;
use RuntimeException;
use UnexpectedValueException;

/**
 * deriveSeedFromPrf(): the seed a PRF output and the passkey's stored salt derive.
 */
final class PrfSeedTest extends PasskeyTestCase
{
    /** 32 bytes of 0x01, base64url. */
    private const string PRF_OUTPUT = 'AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE';

    private PasskeyService $service;

    private SoftwareAuthenticator $authenticator;

    protected function setUp(): void
    {
        parent::setUp();
        $this->service = $this->service(enablePrf: true);
        $this->authenticator = new SoftwareAuthenticator();
        self::postCredential($this->authenticator->register($this->service->options(self::USER_ID), self::ORIGIN));
        $this->service->verify(self::USER_ID);
    }

    /**
     * Pinned: data encrypted under a seed stays readable only while the derivation never changes.
     */
    public function test_a_32_byte_prf_output_derives_the_hkdf_seed_of_the_stored_salt(): void
    {
        $this->broker->setColumn($this->authenticator->credentialId, 'prf_salt', str_repeat('Z', 32));

        $seed = $this->service->deriveSeedFromPrf($this->authenticator->credentialId, self::PRF_OUTPUT);

        self::assertSame('h5W5K-XXFahvEPSvNobz588Osn8vgHaCLFTEg0sGJ5A', $seed);
    }

    public function test_an_unknown_credential_has_no_seed(): void
    {
        $thrown = self::refusalOf(fn () => $this->service->deriveSeedFromPrf(random_bytes(16), self::PRF_OUTPUT));

        self::assertInstanceOf(RuntimeException::class, $thrown);
    }

    #[DataProvider('outputsThatAreNot32Bytes')]
    public function test_a_prf_output_that_is_not_32_bytes_is_refused(string $output): void
    {
        $thrown = self::refusalOf(fn () => $this->service->deriveSeedFromPrf($this->authenticator->credentialId, $output));

        self::assertInstanceOf(UnexpectedValueException::class, $thrown);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function outputsThatAreNot32Bytes(): iterable
    {
        yield 'empty' => [''];
        yield '31 bytes' => [rtrim(strtr(base64_encode(str_repeat("\x01", 31)), '+/', '-_'), '=')];
        yield '33 bytes' => [rtrim(strtr(base64_encode(str_repeat("\x01", 33)), '+/', '-_'), '=')];
        yield 'not base64url' => ['***'];
    }
}
