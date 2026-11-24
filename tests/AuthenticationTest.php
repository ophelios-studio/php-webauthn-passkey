<?php

declare(strict_types=1);

namespace Passkey\Tests;

use Passkey\PasskeyService;
use Passkey\Tests\Support\PasskeyTestCase;
use Passkey\Tests\Support\SoftwareAuthenticator;
use PHPUnit\Framework\Attributes\DataProvider;
use Webauthn\Exception\AuthenticatorResponseVerificationException;
use Webauthn\Exception\CounterException;

/**
 * Login through the public API: assertionOptions(), the authenticator's assertion,
 * authenticate($callback), against a passkey registered through the public API.
 */
final class AuthenticationTest extends PasskeyTestCase
{
    private PasskeyService $service;

    private SoftwareAuthenticator $authenticator;

    /** @var list<mixed> the identifiers the login callback received */
    private array $signedIn = [];

    protected function setUp(): void
    {
        parent::setUp();
        $this->service = $this->service(enablePrf: true);
        $this->authenticator = $this->registeredAuthenticator(new SoftwareAuthenticator());
    }

    /**
     * @param array<string, mixed>|null $clientExtensionResults
     */
    #[DataProvider('browserExtensionResults')]
    public function test_a_valid_assertion_signs_the_user_in_and_records_the_counter(?array $clientExtensionResults): void
    {
        self::postCredential($this->authenticator->login(
            $this->service->assertionOptions(),
            self::ORIGIN,
            counter: 7,
            clientExtensionResults: $clientExtensionResults,
        ));

        $result = $this->service->authenticate($this->signIn(...));

        self::assertSame(['ok' => true], $result);
        self::assertSame([42], $this->signedIn);
        self::assertSame(7, $this->broker->signCountOf($this->authenticator->credentialId));
    }

    /**
     * @return iterable<string, array{array<string, mixed>|null}>
     */
    public static function browserExtensionResults(): iterable
    {
        yield 'without PRF' => [null];
        yield 'with the PRF results' => [['prfResults' => ['results' => ['first' => 'c2VlZC1tYXRlcmlhbC1mcm9tLXRoZS1hdXRoZW50aWNhdG9y']]]];
    }

    public function test_an_assertion_answering_the_challenge_of_another_ceremony_is_refused(): void
    {
        $earlierOptions = $this->service->assertionOptions();
        $this->service->assertionOptions();
        self::postCredential($this->authenticator->login($earlierOptions, self::ORIGIN));

        $refusal = self::refusalOf(fn () => $this->service->authenticate($this->signIn(...)));

        self::assertInstanceOf(AuthenticatorResponseVerificationException::class, $refusal);
        $this->assertNobodySignedIn();
    }

    #[DataProvider('foreignOrigins')]
    public function test_an_assertion_from_a_foreign_origin_is_refused(string $origin): void
    {
        self::postCredential($this->authenticator->login($this->service->assertionOptions(), $origin));

        $refusal = self::refusalOf(fn () => $this->service->authenticate($this->signIn(...)));

        self::assertInstanceOf(AuthenticatorResponseVerificationException::class, $refusal);
        $this->assertNobodySignedIn();
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function foreignOrigins(): iterable
    {
        yield 'another domain' => ['https://app.example.net'];
        yield 'plain http outside localhost' => ['http://app.example.com'];
    }

    public function test_an_assertion_whose_counter_goes_back_is_refused(): void
    {
        $this->signInWithCounter(10);
        self::postCredential($this->authenticator->login($this->service->assertionOptions(), self::ORIGIN, counter: 5));

        $refusal = self::refusalOf(fn () => $this->service->authenticate($this->signIn(...)));

        self::assertInstanceOf(CounterException::class, $refusal);
        self::assertSame([42], $this->signedIn);
        self::assertSame(10, $this->broker->signCountOf($this->authenticator->credentialId));
    }

    public function test_a_replayed_assertion_is_refused_once_the_options_are_spent(): void
    {
        self::postCredential($this->authenticator->login($this->service->assertionOptions(), self::ORIGIN));
        $this->service->authenticate($this->signIn(...));

        $result = $this->service->authenticate($this->signIn(...));

        self::assertSame(['ok' => false, 'err' => 'Options missing'], $result);
        self::assertSame(400, http_response_code());
        self::assertSame([42], $this->signedIn);
    }

    public function test_an_unknown_credential_is_refused(): void
    {
        self::postCredential((new SoftwareAuthenticator())->login($this->service->assertionOptions(), self::ORIGIN));

        $result = $this->service->authenticate($this->signIn(...));

        self::assertSame(['ok' => false, 'err' => 'Unknown credential'], $result);
        self::assertSame(401, http_response_code());
        $this->assertNobodySignedIn();
    }

    /**
     * The backup_eligible column of existing installs was written with "?? false". Checking the
     * assertion's BE flag against it would lock every synced passkey out, so the stored value is
     * not handed to the validator.
     */
    public function test_a_synced_passkey_is_not_locked_out_by_a_stale_backup_eligible_column(): void
    {
        $synced = $this->registeredAuthenticator(new SoftwareAuthenticator(synced: true));
        $this->broker->setColumn($synced->credentialId, 'backup_eligible', false);
        self::postCredential($synced->login($this->service->assertionOptions(), self::ORIGIN));

        $result = $this->service->authenticate($this->signIn(...));

        self::assertSame(['ok' => true], $result);
        self::assertSame([42], $this->signedIn);
    }

    public function test_a_passkey_stored_without_transports_signs_in(): void
    {
        $this->broker->setColumn($this->authenticator->credentialId, 'transports', null);
        self::postCredential($this->authenticator->login($this->service->assertionOptions(), self::ORIGIN));

        $result = $this->service->authenticate($this->signIn(...));

        self::assertSame(['ok' => true], $result);
        self::assertSame([42], $this->signedIn);
    }

    private function registeredAuthenticator(SoftwareAuthenticator $authenticator): SoftwareAuthenticator
    {
        self::postCredential($authenticator->register($this->service->options(self::USER_ID), self::ORIGIN));
        self::assertSame(['ok' => true], $this->service->verify(self::USER_ID));
        return $authenticator;
    }

    private function signInWithCounter(int $counter): void
    {
        self::postCredential($this->authenticator->login($this->service->assertionOptions(), self::ORIGIN, counter: $counter));
        self::assertSame(['ok' => true], $this->service->authenticate($this->signIn(...)));
    }

    private function signIn(mixed $identifier): void
    {
        $this->signedIn[] = $identifier;
    }

    private function assertNobodySignedIn(): void
    {
        self::assertSame([], $this->signedIn);
        self::assertSame(0, $this->broker->signCountOf($this->authenticator->credentialId));
    }
}
