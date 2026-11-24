<?php

declare(strict_types=1);

namespace Passkey\Tests;

use Passkey\Tests\Support\PasskeyTestCase;
use Passkey\Tests\Support\SoftwareAuthenticator;
use PHPUnit\Framework\Attributes\DataProvider;

/**
 * The PRF output is key material for the browser alone. A genuine credential that carries one, as a
 * client older than 3.0.0 posts it, is refused before it is read: nothing is saved, nobody signs in.
 */
final class PrfResultsRefusedTest extends PasskeyTestCase
{
    private const array REFUSED = ['ok' => false, 'err' => 'PRF results are not accepted'];

    /** 32 bytes of 0x01, base64url. */
    private const string PRF_OUTPUT = 'AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE';

    /**
     * @param array<string, mixed> $clientExtensionResults
     */
    #[DataProvider('extensionResultsCarryingThePrfOutput')]
    public function test_a_registration_carrying_the_prf_output_is_refused(array $clientExtensionResults): void
    {
        $service = $this->service(enablePrf: true);
        self::postCredential((new SoftwareAuthenticator())->register($service->options(self::USER_ID), self::ORIGIN, $clientExtensionResults));

        $result = $service->verify(self::USER_ID);

        self::assertSame(self::REFUSED, $result);
        self::assertSame(400, http_response_code());
        self::assertSame([], $this->broker->inserted);
    }

    /**
     * @param array<string, mixed> $clientExtensionResults
     */
    #[DataProvider('extensionResultsCarryingThePrfOutput')]
    public function test_an_assertion_carrying_the_prf_output_is_refused(array $clientExtensionResults): void
    {
        $service = $this->service(enablePrf: true);
        $authenticator = new SoftwareAuthenticator();
        self::postCredential($authenticator->register($service->options(self::USER_ID), self::ORIGIN));
        $service->verify(self::USER_ID);
        $signedIn = false;
        self::postCredential($authenticator->login($service->assertionOptions(), self::ORIGIN, clientExtensionResults: $clientExtensionResults));

        $result = $service->authenticate(static function () use (&$signedIn): void {
            $signedIn = true;
        });

        self::assertSame(self::REFUSED, $result);
        self::assertSame(400, http_response_code());
        self::assertFalse($signedIn);
        self::assertSame(0, $this->broker->signCountOf($authenticator->credentialId));
    }

    /**
     * @return iterable<string, array{array<string, mixed>}>
     */
    public static function extensionResultsCarryingThePrfOutput(): iterable
    {
        yield 'prf.results, the key browsers report' => [['prf' => ['results' => ['first' => self::PRF_OUTPUT]]]];
        yield 'prfResults, the key the 2.0.0 module posted' => [['prfResults' => ['results' => ['first' => self::PRF_OUTPUT]]]];
    }
}
