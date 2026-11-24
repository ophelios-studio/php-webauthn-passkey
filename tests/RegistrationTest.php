<?php

declare(strict_types=1);

namespace Passkey\Tests;

use Passkey\Tests\Support\PasskeyTestCase;
use Passkey\Tests\Support\SoftwareAuthenticator;
use PHPUnit\Framework\Attributes\DataProvider;
use RuntimeException;

/**
 * Registration through the public API: options(), the authenticator's answer, verify().
 */
final class RegistrationTest extends PasskeyTestCase
{
    private const array REFUSED = ['ok' => false, 'err' => 'Verification failed'];

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

    /**
     * @param array<string, mixed> $answer how the authenticator departs from a genuine answer
     */
    #[DataProvider('answersTheAuthenticatorDidNotVouchFor')]
    public function test_a_registration_the_authenticator_did_not_vouch_for_is_refused(array $answer): void
    {
        $service = $this->service();
        self::postCredential((new SoftwareAuthenticator())->register($service->options(self::USER_ID), self::ORIGIN, ...$answer));

        $result = $service->verify(self::USER_ID);

        self::assertSame(self::REFUSED, $result);
        self::assertSame(401, http_response_code());
        self::assertSame([], $this->broker->inserted);
    }

    /**
     * @return iterable<string, array{array<string, mixed>}>
     */
    public static function answersTheAuthenticatorDidNotVouchFor(): iterable
    {
        yield 'without user verification' => [['userVerified' => false]];
        yield 'without user presence' => [['userPresent' => false]];
        yield 'for another relying party' => [['rpId' => 'example.com']];
    }

    public function test_a_registration_answering_the_challenge_of_another_ceremony_is_refused(): void
    {
        $service = $this->service();
        $earlierOptions = $service->options(self::USER_ID);
        $service->options(self::USER_ID);
        self::postCredential((new SoftwareAuthenticator())->register($earlierOptions, self::ORIGIN));

        $result = $service->verify(self::USER_ID);

        self::assertSame(self::REFUSED, $result);
        self::assertSame(401, http_response_code());
        self::assertSame([], $this->broker->inserted);
    }

    #[DataProvider('foreignOrigins')]
    public function test_a_registration_from_a_foreign_origin_is_refused(string $origin): void
    {
        $service = $this->service();
        self::postCredential((new SoftwareAuthenticator())->register($service->options(self::USER_ID), $origin));

        $result = $service->verify(self::USER_ID);

        self::assertSame(self::REFUSED, $result);
        self::assertSame([], $this->broker->inserted);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function foreignOrigins(): iterable
    {
        yield 'another domain' => ['https://app.example.net'];
        yield 'a subdomain of the relying party' => ['https://user-content.app.example.com'];
        yield 'plain http' => ['http://app.example.com'];
    }

    public function test_a_replayed_registration_is_refused_once_the_options_are_spent(): void
    {
        $service = $this->service();
        self::postCredential((new SoftwareAuthenticator())->register($service->options(self::USER_ID), self::ORIGIN));
        $service->verify(self::USER_ID);

        $result = $service->verify(self::USER_ID);

        self::assertSame(['ok' => false, 'err' => 'Options missing'], $result);
        self::assertSame(400, http_response_code());
        self::assertCount(1, $this->broker->inserted);
    }

    public function test_a_refused_registration_spends_the_options(): void
    {
        $service = $this->service();
        $options = $service->options(self::USER_ID);
        $authenticator = new SoftwareAuthenticator();
        self::postCredential($authenticator->register($options, 'https://app.example.net'));
        $service->verify(self::USER_ID);
        self::postCredential($authenticator->register($options, self::ORIGIN));

        $result = $service->verify(self::USER_ID);

        self::assertSame(['ok' => false, 'err' => 'Options missing'], $result);
        self::assertSame([], $this->broker->inserted);
    }

    public function test_options_answered_more_than_five_minutes_later_are_refused(): void
    {
        $service = $this->service();
        $options = $service->options(self::USER_ID);
        $this->clock->advance(301);
        self::postCredential((new SoftwareAuthenticator())->register($options, self::ORIGIN));

        $result = $service->verify(self::USER_ID);

        self::assertSame(['ok' => false, 'err' => 'Options expired'], $result);
        self::assertSame(400, http_response_code());
        self::assertSame([], $this->broker->inserted);
    }

    public function test_options_stored_without_an_issue_time_are_refused(): void
    {
        $service = $this->service();
        $options = $service->options(self::USER_ID);
        unset($_SESSION['webauthn_creation_options_issued_at']);
        self::postCredential((new SoftwareAuthenticator())->register($options, self::ORIGIN));

        $result = $service->verify(self::USER_ID);

        self::assertSame(['ok' => false, 'err' => 'Options expired'], $result);
        self::assertSame([], $this->broker->inserted);
    }

    public function test_options_answered_within_five_minutes_are_accepted(): void
    {
        $service = $this->service();
        $options = $service->options(self::USER_ID);
        $this->clock->advance(300);
        self::postCredential((new SoftwareAuthenticator())->register($options, self::ORIGIN));

        $result = $service->verify(self::USER_ID);

        self::assertSame(['ok' => true], $result);
    }

    public function test_a_credential_id_already_registered_is_refused(): void
    {
        $this->broker->addIdentity('43', 'eve@example.com', 'Eve');
        $service = $this->service();
        $victim = new SoftwareAuthenticator();
        self::postCredential($victim->register($service->options(self::USER_ID), self::ORIGIN));
        $service->verify(self::USER_ID);
        $impostor = new SoftwareAuthenticator(credentialId: $victim->credentialId);
        self::postCredential($impostor->register($service->options('43'), self::ORIGIN));

        $result = $service->verify('43');

        self::assertSame(['ok' => false, 'err' => 'Credential already registered'], $result);
        self::assertSame(400, http_response_code());
        self::assertCount(1, $this->broker->inserted);
        self::assertSame(self::USER_ID, $this->broker->findIdentifierByCredentialId($victim->credentialId));
    }

    /**
     * @param list<string> $posted
     */
    #[DataProvider('postedTransports')]
    public function test_only_the_transports_webauthn_defines_are_saved(array $posted, ?string $saved): void
    {
        $service = $this->service();
        self::postCredential((new SoftwareAuthenticator())->register($service->options(self::USER_ID), self::ORIGIN, transports: $posted));

        $service->verify(self::USER_ID);

        self::assertSame($saved, $this->broker->inserted[0]->transports);
    }

    /**
     * @return iterable<string, array{list<string>, string|null}>
     */
    public static function postedTransports(): iterable
    {
        yield 'every transport webauthn defines' => [
            ['usb', 'nfc', 'ble', 'internal', 'hybrid', 'smart-card'],
            'usb,nfc,ble,internal,hybrid,smart-card',
        ];
        yield 'unknown values among them' => [
            ['internal', '<img src=x onerror=alert(1)>', 'hybrid', str_repeat('a', 1000)],
            'internal,hybrid',
        ];
        yield 'nothing webauthn defines' => [['<script>'], null];
    }

    public function test_a_database_failure_after_the_verification_is_not_turned_into_a_refusal(): void
    {
        $failure = new RuntimeException('database unavailable');
        $this->broker->insertFailure = $failure;
        $service = $this->service();
        self::postCredential((new SoftwareAuthenticator())->register($service->options(self::USER_ID), self::ORIGIN));

        $thrown = self::refusalOf(fn () => $service->verify(self::USER_ID));

        self::assertSame($failure, $thrown);
    }
}
