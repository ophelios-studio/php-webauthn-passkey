<?php

declare(strict_types=1);

namespace Passkey\Tests;

use Passkey\PasskeyService;
use Passkey\Tests\Support\PasskeyTestCase;
use Passkey\Tests\Support\SoftwareAuthenticator;
use PHPUnit\Framework\Attributes\DataProvider;
use RuntimeException;

/**
 * Login through the public API: assertionOptions(), the authenticator's assertion,
 * authenticate($callback), against a passkey registered through the public API.
 */
final class AuthenticationTest extends PasskeyTestCase
{
    private const array REFUSED = ['ok' => false, 'err' => 'Verification failed'];

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
        self::assertSame([self::USER_ID], $this->signedIn);
        self::assertSame(7, $this->broker->signCountOf($this->authenticator->credentialId));
    }

    /**
     * @return iterable<string, array{array<string, mixed>|null}>
     */
    public static function browserExtensionResults(): iterable
    {
        yield 'without PRF' => [null];
        yield 'reporting prf enabled, without its output' => [['prf' => ['enabled' => true]]];
    }

    /**
     * @param array<string, mixed> $answer how the authenticator departs from a genuine assertion
     */
    #[DataProvider('assertionsTheAuthenticatorDidNotVouchFor')]
    public function test_an_assertion_the_authenticator_did_not_vouch_for_is_refused(array $answer): void
    {
        self::postCredential($this->authenticator->login($this->service->assertionOptions(), self::ORIGIN, ...$answer));

        $result = $this->service->authenticate($this->signIn(...));

        self::assertSame(self::REFUSED, $result);
        self::assertSame(401, http_response_code());
        $this->assertNobodySignedIn();
    }

    /**
     * @return iterable<string, array{array<string, mixed>}>
     */
    public static function assertionsTheAuthenticatorDidNotVouchFor(): iterable
    {
        yield 'without user verification' => [['userVerified' => false]];
        yield 'without user presence' => [['userPresent' => false]];
        yield 'altered after signing' => [['alteredAfterSigning' => true]];
        yield 'for another relying party' => [['rpId' => 'example.com']];
        yield 'with the client data of a registration' => [['type' => 'webauthn.create']];
    }

    public function test_an_assertion_answering_the_challenge_of_another_ceremony_is_refused(): void
    {
        $earlierOptions = $this->service->assertionOptions();
        $this->service->assertionOptions();
        self::postCredential($this->authenticator->login($earlierOptions, self::ORIGIN));

        $result = $this->service->authenticate($this->signIn(...));

        self::assertSame(self::REFUSED, $result);
        $this->assertNobodySignedIn();
    }

    #[DataProvider('foreignOrigins')]
    public function test_an_assertion_from_a_foreign_origin_is_refused(string $origin): void
    {
        self::postCredential($this->authenticator->login($this->service->assertionOptions(), $origin));

        $result = $this->service->authenticate($this->signIn(...));

        self::assertSame(self::REFUSED, $result);
        $this->assertNobodySignedIn();
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function foreignOrigins(): iterable
    {
        yield 'another domain' => ['https://app.example.net'];
        yield 'a subdomain of the relying party' => ['https://evil.deep.app.example.com'];
        yield 'plain http outside localhost' => ['http://app.example.com'];
    }

    public function test_an_assertion_whose_counter_goes_back_is_refused(): void
    {
        $this->signInWithCounter(10);
        self::postCredential($this->authenticator->login($this->service->assertionOptions(), self::ORIGIN, counter: 5));

        $result = $this->service->authenticate($this->signIn(...));

        self::assertSame(self::REFUSED, $result);
        self::assertSame([self::USER_ID], $this->signedIn);
        self::assertSame(10, $this->broker->signCountOf($this->authenticator->credentialId));
    }

    public function test_a_replayed_assertion_is_refused_once_the_options_are_spent(): void
    {
        self::postCredential($this->authenticator->login($this->service->assertionOptions(), self::ORIGIN));
        $this->service->authenticate($this->signIn(...));

        $result = $this->service->authenticate($this->signIn(...));

        self::assertSame(['ok' => false, 'err' => 'Options missing'], $result);
        self::assertSame(400, http_response_code());
        self::assertSame([self::USER_ID], $this->signedIn);
    }

    public function test_a_refused_assertion_spends_the_options(): void
    {
        $options = $this->service->assertionOptions();
        self::postCredential($this->authenticator->login($options, self::ORIGIN, alteredAfterSigning: true));
        $this->service->authenticate($this->signIn(...));
        self::postCredential($this->authenticator->login($options, self::ORIGIN));

        $result = $this->service->authenticate($this->signIn(...));

        self::assertSame(['ok' => false, 'err' => 'Options missing'], $result);
        $this->assertNobodySignedIn();
    }

    public function test_options_answered_more_than_five_minutes_later_are_refused(): void
    {
        $options = $this->service->assertionOptions();
        $this->clock->advance(301);
        self::postCredential($this->authenticator->login($options, self::ORIGIN));

        $result = $this->service->authenticate($this->signIn(...));

        self::assertSame(['ok' => false, 'err' => 'Options expired'], $result);
        self::assertSame(400, http_response_code());
        $this->assertNobodySignedIn();
    }

    public function test_options_stored_without_an_issue_time_are_refused(): void
    {
        $options = $this->service->assertionOptions();
        unset($_SESSION['webauthn_request_options_issued_at']);
        self::postCredential($this->authenticator->login($options, self::ORIGIN));

        $result = $this->service->authenticate($this->signIn(...));

        self::assertSame(['ok' => false, 'err' => 'Options expired'], $result);
        $this->assertNobodySignedIn();
    }

    public function test_options_answered_within_five_minutes_are_accepted(): void
    {
        $options = $this->service->assertionOptions();
        $this->clock->advance(300);
        self::postCredential($this->authenticator->login($options, self::ORIGIN));

        $result = $this->service->authenticate($this->signIn(...));

        self::assertSame(['ok' => true], $result);
        self::assertSame([self::USER_ID], $this->signedIn);
    }

    public function test_an_unknown_credential_is_refused(): void
    {
        self::postCredential((new SoftwareAuthenticator())->login($this->service->assertionOptions(), self::ORIGIN));

        $result = $this->service->authenticate($this->signIn(...));

        self::assertSame(['ok' => false, 'err' => 'Unknown credential'], $result);
        self::assertSame(401, http_response_code());
        $this->assertNobodySignedIn();
    }

    #[DataProvider('identifiers')]
    public function test_the_callback_receives_the_identifier_the_broker_stored(string $identifier): void
    {
        $this->broker->addIdentity($identifier, 'grace@example.com', 'Grace Hopper');
        $authenticator = new SoftwareAuthenticator();
        self::postCredential($authenticator->register($this->service->options($identifier), self::ORIGIN));
        $this->service->verify($identifier);
        self::postCredential($authenticator->login($this->service->assertionOptions(), self::ORIGIN));

        $result = $this->service->authenticate($this->signIn(...));

        self::assertSame(['ok' => true], $result);
        self::assertSame([$identifier], $this->signedIn);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function identifiers(): iterable
    {
        yield 'a UUID' => ['0b9c4c1e-4d5c-4e43-9a51-2f4c3f1c9a10'];
        yield 'zero' => ['0'];
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
        self::assertSame([self::USER_ID], $this->signedIn);
    }

    public function test_a_passkey_stored_without_transports_signs_in(): void
    {
        $this->broker->setColumn($this->authenticator->credentialId, 'transports', null);
        self::postCredential($this->authenticator->login($this->service->assertionOptions(), self::ORIGIN));

        $result = $this->service->authenticate($this->signIn(...));

        self::assertSame(['ok' => true], $result);
        self::assertSame([self::USER_ID], $this->signedIn);
    }

    public function test_a_failing_callback_is_not_turned_into_a_refusal(): void
    {
        $failure = new RuntimeException('session store unavailable');
        self::postCredential($this->authenticator->login($this->service->assertionOptions(), self::ORIGIN));

        $thrown = self::refusalOf(fn () => $this->service->authenticate(static fn () => throw $failure));

        self::assertSame($failure, $thrown);
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
