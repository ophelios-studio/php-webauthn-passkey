<?php

declare(strict_types=1);

namespace Passkey\Tests;

use Passkey\Tests\Support\PasskeyTestCase;
use Passkey\Tests\Support\SoftwareAuthenticator;

/**
 * The relying party a ceremony is bound to: a fixed rpId, and the exact origins allowed.
 */
final class RelyingPartyTest extends PasskeyTestCase
{
    /** @var list<mixed> the identifiers the login callback received */
    private array $signedIn = [];

    public function test_a_fixed_rp_id_holds_whatever_host_the_request_names(): void
    {
        $_SERVER['HTTP_HOST'] = 'attacker.example';
        $service = $this->service(rpId: self::HOST);
        $options = $service->options(self::USER_ID);
        $authenticator = new SoftwareAuthenticator();
        self::postCredential($authenticator->register($options, self::ORIGIN));
        $service->verify(self::USER_ID);
        self::postCredential($authenticator->login($service->assertionOptions(), self::ORIGIN));

        $result = $service->authenticate($this->signIn(...));

        self::assertSame(self::HOST, $options['rp']['id']);
        self::assertSame(['ok' => true], $result);
        self::assertSame([self::USER_ID], $this->signedIn);
    }

    /**
     * A site served on a subdomain of an apex rpId lists its own origin.
     */
    public function test_an_allowed_origin_signs_in_under_an_apex_rp_id(): void
    {
        $service = $this->service(rpId: 'example.com', allowedOrigins: [self::ORIGIN]);
        $authenticator = new SoftwareAuthenticator();
        self::postCredential($authenticator->register($service->options(self::USER_ID), self::ORIGIN));
        $service->verify(self::USER_ID);
        self::postCredential($authenticator->login($service->assertionOptions(), self::ORIGIN));

        $result = $service->authenticate($this->signIn(...));

        self::assertSame(['ok' => true], $result);
        self::assertSame([self::USER_ID], $this->signedIn);
    }

    public function test_allowed_origins_replace_the_origin_of_the_rp_id(): void
    {
        $service = $this->service(rpId: 'example.com', allowedOrigins: [self::ORIGIN]);
        self::postCredential((new SoftwareAuthenticator())->register($service->options(self::USER_ID), 'https://example.com'));

        $result = $service->verify(self::USER_ID);

        self::assertSame(['ok' => false, 'err' => 'Verification failed'], $result);
        self::assertSame([], $this->broker->inserted);
    }

    private function signIn(mixed $identifier): void
    {
        $this->signedIn[] = $identifier;
    }
}
