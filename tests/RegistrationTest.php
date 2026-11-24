<?php

declare(strict_types=1);

namespace Passkey\Tests;

use Passkey\Tests\Support\PasskeyTestCase;
use Passkey\Tests\Support\SoftwareAuthenticator;
use Webauthn\Exception\AuthenticatorResponseVerificationException;

/**
 * Registration through the public API: options(), the authenticator's answer, verify().
 */
final class RegistrationTest extends PasskeyTestCase
{
    public function test_a_verified_registration_saves_the_passkey_of_the_authenticator(): void
    {
        $service = $this->service();
        $authenticator = new SoftwareAuthenticator();
        self::postCredential($authenticator->register($service->options(self::USER_ID), self::ORIGIN));

        $result = $service->verify(self::USER_ID);

        self::assertSame(['ok' => true], $result);
        self::assertCount(1, $this->broker->inserted);
        $passkey = $this->broker->inserted[0];
        self::assertSame(self::USER_ID, $passkey->user_id);
        self::assertSame($authenticator->credentialId, $passkey->credential_id);
        self::assertSame($authenticator->cose, $passkey->public_key_cose);
        self::assertSame(0, $passkey->sign_count);
        self::assertFalse($passkey->backup_eligible);
        self::assertSame('internal', $passkey->transports);
        self::assertSame(32, strlen((string) $passkey->prf_salt));
    }

    public function test_a_synced_passkey_is_saved_as_backup_eligible(): void
    {
        $service = $this->service();
        self::postCredential((new SoftwareAuthenticator(synced: true))->register($service->options(self::USER_ID), self::ORIGIN));

        $service->verify(self::USER_ID);

        self::assertTrue($this->broker->inserted[0]->backup_eligible);
    }

    public function test_a_registration_carrying_the_prf_results_the_browser_sends_is_accepted(): void
    {
        $service = $this->service(enablePrf: true);
        $options = $service->options(self::USER_ID);
        self::postCredential((new SoftwareAuthenticator())->register($options, self::ORIGIN, [
            'prf' => ['enabled' => true],
            'prfResults' => ['results' => ['first' => 'c2VlZC1tYXRlcmlhbC1mcm9tLXRoZS1hdXRoZW50aWNhdG9y']],
        ]));

        $result = $service->verify(self::USER_ID);

        self::assertSame(['ok' => true], $result);
        self::assertCount(1, $this->broker->inserted);
    }

    public function test_a_registration_answering_the_challenge_of_another_ceremony_is_refused(): void
    {
        $service = $this->service();
        $earlierOptions = $service->options(self::USER_ID);
        $service->options(self::USER_ID);
        self::postCredential((new SoftwareAuthenticator())->register($earlierOptions, self::ORIGIN));

        $refusal = self::refusalOf(fn () => $service->verify(self::USER_ID));

        self::assertInstanceOf(AuthenticatorResponseVerificationException::class, $refusal);
        self::assertSame([], $this->broker->inserted);
    }

    public function test_a_registration_from_another_origin_is_refused(): void
    {
        $service = $this->service();
        self::postCredential((new SoftwareAuthenticator())->register($service->options(self::USER_ID), 'https://app.example.net'));

        $refusal = self::refusalOf(fn () => $service->verify(self::USER_ID));

        self::assertInstanceOf(AuthenticatorResponseVerificationException::class, $refusal);
        self::assertSame([], $this->broker->inserted);
    }
}
