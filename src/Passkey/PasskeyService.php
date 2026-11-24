<?php namespace Passkey;

use Symfony\Component\Serializer\Encoder\JsonEncode;
use Symfony\Component\Serializer\Normalizer\AbstractObjectNormalizer;
use Symfony\Component\Serializer\SerializerInterface;
use Webauthn\AttestationStatement\AttestationStatementSupportManager;
use Webauthn\CeremonyStep\CeremonyStepManagerFactory;
use Webauthn\PublicKeyCredential;
use Webauthn\PublicKeyCredentialOptions;
use Webauthn\PublicKeyCredentialRpEntity;
use Webauthn\AuthenticatorSelectionCriteria;
use Webauthn\PublicKeyCredentialParameters;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\Denormalizer\WebauthnSerializerFactory;
use Webauthn\AuthenticatorAttestationResponseValidator;
use Webauthn\AuthenticatorAttestationResponse;
use Webauthn\PublicKeyCredentialRequestOptions;
use Webauthn\AuthenticatorAssertionResponseValidator;
use Webauthn\AuthenticatorAssertionResponse;
use Cose\Algorithms;
use DateTimeImmutable;
use Psr\Clock\ClockInterface;
use Throwable;

final readonly class PasskeyService
{
    /** Seconds during which issued options can be answered. */
    private const int OPTIONS_LIFETIME = 300;

    private const string CREATION_OPTIONS = 'webauthn_creation_options';
    private const string REQUEST_OPTIONS = 'webauthn_request_options';

    /** The transports WebAuthn defines: anything else the client posts is dropped. */
    private const array TRANSPORTS = ['usb', 'nfc', 'ble', 'internal', 'hybrid', 'smart-card'];

    /**
     * @param string|null $rpId the relying party ID; when null it comes from the Host header, so fix it in production
     * @param list<string> $allowedOrigins the exact origins (scheme, host, port) a ceremony may come from; when
     *        empty, "https://" followed by the RP ID
     * @param ClockInterface|null $clock tells when options are issued and answered; the system clock when null
     */
    public function __construct(
        private PasskeyProvider $provider,
        private string $rpName = 'Your App',
        private ?string $rpId = null,
        private bool $enablePrf = false,
        private string $prfEvalSaltLabel = 'webauthn:prf-eval:v1',
        private array $allowedOrigins = [],
        private ?ClockInterface $clock = null,
    ) {}

    public function options(string $authenticatedUserId): mixed
    {
        $userEntity = $this->provider->getUserCredentialEntity($authenticatedUserId);

        $rpId = $this->resolveRpId();
        // webauthn-lib 5.3 deprecates the RP name on the entity: rpName is set on the browser JSON below
        $rp = new PublicKeyCredentialRpEntity(id: $rpId);

        $algos = [
            new PublicKeyCredentialParameters('public-key', Algorithms::COSE_ALGORITHM_ES256),
            new PublicKeyCredentialParameters('public-key', Algorithms::COSE_ALGORITHM_EDDSA),
            new PublicKeyCredentialParameters('public-key', Algorithms::COSE_ALGORITHM_RS256),
        ];

        $authSel = AuthenticatorSelectionCriteria::create(
            userVerification: AuthenticatorSelectionCriteria::USER_VERIFICATION_REQUIREMENT_REQUIRED,
            residentKey: AuthenticatorSelectionCriteria::RESIDENT_KEY_REQUIREMENT_REQUIRED,
        );

        $creation = PublicKeyCredentialCreationOptions::create(
            rp: $rp,
            user: $userEntity,
            challenge: random_bytes(32),
            pubKeyCredParams: $algos,
            authenticatorSelection: $authSel,
            attestation: PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_NONE,
        );

        // Store the full options as JSON for later verification; the browser receives the same JSON
        $json = self::optionsToJson($creation);
        $this->storeOptions(self::CREATION_OPTIONS, $json);
        $result = self::browserOptions($json);
        $result['rp']['name'] = $this->rpName;
        if ($this->enablePrf) {
            $rpEvalSalt = $this->deriveEvalSalt($rpId);
            $result['extensions']['prf']['eval']['first'] = self::base64url_encode($rpEvalSalt);
        }
        return $result;
    }

    public function verify(string $authenticatedUserId): array
    {
        $rpId = $this->resolveRpId();
        [$optionsData, $issuedAt] = $this->takeOptions(self::CREATION_OPTIONS);
        if ($optionsData === null) {
            return self::refuse(400, 'Options missing');
        }
        if ($this->hasExpired($issuedAt)) {
            return self::refuse(400, 'Options expired');
        }

        // Re-create options from stored data using Serializer (no deprecated createFrom*). No check
        // reads rp.name, and denormalizing it trips the webauthn-lib 5.3 deprecation of the RP name.
        $serializer = self::serializer();
        $storedOptions = json_decode($optionsData, true, flags: JSON_THROW_ON_ERROR);
        unset($storedOptions['rp']['name']);
        $creation = $serializer->denormalize($storedOptions, PublicKeyCredentialCreationOptions::class, 'json');

        try {
            $clientResponse = self::postedCredential();
            if (!$clientResponse) {
                return self::refuse(400, 'Missing credential');
            }
            if (self::carriesPrfResults($clientResponse)) {
                return self::refuse(400, 'PRF results are not accepted');
            }
            $publicKeyCredential = $serializer->denormalize($clientResponse, PublicKeyCredential::class);
        } catch (Throwable) {
            return self::refuse(400, 'Verification failed');
        }
        if (!($publicKeyCredential->response instanceof AuthenticatorAttestationResponse)) {
            return self::refuse(400, 'Invalid response type');
        }

        $validator = new AuthenticatorAttestationResponseValidator($this->ceremonies($rpId)->creationCeremony());
        try {
            $source = $validator->check($publicKeyCredential->response, $creation, $rpId);
        } catch (Throwable) {
            return self::refuse(401, 'Verification failed');
        }

        if ($this->provider->findByCredentialId($source->publicKeyCredentialId) !== null) {
            return self::refuse(400, 'Credential already registered');
        }

        $passkey = new Passkey(
            id: null,
            user_id: $authenticatedUserId,
            credential_id: $source->publicKeyCredentialId,
            public_key_cose: $source->credentialPublicKey,
            sign_count: $source->counter,
            backup_eligible: $source->backupEligible ?? false,
            prf_salt: random_bytes(32),
            prf_eval_label: $this->prfEvalSaltLabel,
            transports: self::knownTransports($source->transports),
        );
        $this->provider->saveAttestation($passkey);
        return ['ok' => true];
    }

    public function assertionOptions(): array
    {
        $rpId = $this->resolveRpId();
        $options = PublicKeyCredentialRequestOptions::create(
            challenge: random_bytes(32),
            rpId: $rpId,
            allowCredentials: [], // username-less, resident keys
            userVerification: AuthenticatorSelectionCriteria::USER_VERIFICATION_REQUIREMENT_REQUIRED,
        );
        $json = self::optionsToJson($options);
        $this->storeOptions(self::REQUEST_OPTIONS, $json);
        $result = self::browserOptions($json);
        if ($this->enablePrf) {
            $result['extensions']['prf']['eval']['first'] = self::base64url_encode($this->deriveEvalSalt($rpId));
        }
        return $result;
    }

    public function authenticate(callable $callback): array
    {
        $rpId = $this->resolveRpId();
        [$optionsData, $issuedAt] = $this->takeOptions(self::REQUEST_OPTIONS);
        if ($optionsData === null) {
            return self::refuse(400, 'Options missing');
        }
        if ($this->hasExpired($issuedAt)) {
            return self::refuse(400, 'Options expired');
        }

        $serializer = self::serializer();
        /** @var PublicKeyCredentialRequestOptions $requestOptions */
        $requestOptions = $serializer->deserialize($optionsData, PublicKeyCredentialRequestOptions::class, 'json');

        try {
            $clientResponse = self::postedCredential();
            if (!$clientResponse) {
                return self::refuse(400, 'Missing credential');
            }
            if (self::carriesPrfResults($clientResponse)) {
                return self::refuse(400, 'PRF results are not accepted');
            }
            $publicKeyCredential = $serializer->denormalize($clientResponse, PublicKeyCredential::class);
        } catch (Throwable) {
            return self::refuse(400, 'Verification failed');
        }
        if (!($publicKeyCredential->response instanceof AuthenticatorAssertionResponse)) {
            return self::refuse(400, 'Invalid response type');
        }

        // Determine user and credential source
        $credId = $publicKeyCredential->rawId; // binary
        $userId = $this->provider->findUserIdByCredentialId($credId);
        if ($userId === null) {
            return self::refuse(401, 'Unknown credential');
        }
        $credentialSource = $this->provider->getCredentialSource($credId);
        if (!$credentialSource) {
            return self::refuse(401, 'Credential source not found');
        }

        $validator = new AuthenticatorAssertionResponseValidator($this->ceremonies($rpId)->requestCeremony());
        try {
            $source = $validator->check($credentialSource, $publicKeyCredential->response, $requestOptions, $rpId, (string)$userId);
        } catch (Throwable) {
            return self::refuse(401, 'Verification failed');
        }

        // Update usage and sign count
        $this->provider->updateUsageAndCounter($source->publicKeyCredentialId, $source->counter);

        $callback($userId);
        return ['ok' => true];
    }

    /**
     * Resolves the RP ID to be used for the current request. By default, it derives the RP ID from the current HTTP
     * host, removing any port number if present.
     *
     * @return string The resolved RP ID.
     */
    private function resolveRpId(): string
    {
        $host = $_SERVER['HTTP_HOST'] ?? ($_SERVER['SERVER_NAME'] ?? 'localhost');
        $host = preg_replace('/:.*/', '', $host) ?: 'localhost';
        return $this->rpId ?? $host;
    }

    /**
     * The ceremony steps, with the origin compared exactly (scheme, host and port). The suffix rule of
     * the deprecated CheckOrigin step accepted any HTTPS subdomain of the RP ID.
     */
    private function ceremonies(string $rpId): CeremonyStepManagerFactory
    {
        $factory = new CeremonyStepManagerFactory();
        $factory->setAllowedOrigins($this->allowedOrigins !== [] ? $this->allowedOrigins : ['https://' . $rpId], false);
        return $factory;
    }

    private function storeOptions(string $key, string $json): void
    {
        self::startSession();
        $_SESSION[$key] = $json;
        $_SESSION[$key . '_issued_at'] = $this->now();
    }

    /**
     * Takes the options out of the session before anything is checked: they answer one attempt,
     * accepted or refused.
     *
     * @return array{?string, ?int} the options JSON and the time they were issued
     */
    private function takeOptions(string $key): array
    {
        self::startSession();
        $json = $_SESSION[$key] ?? null;
        $issuedAt = $_SESSION[$key . '_issued_at'] ?? null;
        unset($_SESSION[$key], $_SESSION[$key . '_issued_at']);
        return [is_string($json) && $json !== '' ? $json : null, is_int($issuedAt) ? $issuedAt : null];
    }

    /**
     * Options without an issue time were stored before it was recorded: they count as expired.
     */
    private function hasExpired(?int $issuedAt): bool
    {
        return $issuedAt === null || $this->now() - $issuedAt > self::OPTIONS_LIFETIME;
    }

    private function now(): int
    {
        return ($this->clock?->now() ?? new DateTimeImmutable())->getTimestamp();
    }

    private static function startSession(): void
    {
        if (session_status() !== PHP_SESSION_ACTIVE) {
            session_start();
        }
    }

    /**
     * The credential the JavaScript module posts as {"credential": ...}, or null.
     */
    private static function postedCredential(): mixed
    {
        $body = json_decode((string) file_get_contents('php://input'), true);
        return is_array($body) ? ($body['credential'] ?? null) : null;
    }

    /**
     * True when the posted credential carries a PRF output, under the standard key (prf.results) or
     * the one the 2.0.0 JavaScript module posted (prfResults). The PRF output is key material for the
     * browser alone: the JavaScript module never posts it, and a client that still does is refused
     * instead of accepted. prf.enabled alone is accepted.
     */
    private static function carriesPrfResults(mixed $credential): bool
    {
        $extensions = is_array($credential) ? ($credential['clientExtensionResults'] ?? null) : null;
        if (!is_array($extensions)) {
            return false;
        }
        return array_key_exists('prfResults', $extensions)
            || (is_array($extensions['prf'] ?? null) && array_key_exists('results', $extensions['prf']));
    }

    private static function refuse(int $status, string $error): array
    {
        http_response_code($status);
        return ['ok' => false, 'err' => $error];
    }

    /**
     * @param array<mixed> $transports as the client posted them
     */
    private static function knownTransports(array $transports): ?string
    {
        $known = array_values(array_unique(array_filter(
            $transports,
            static fn (mixed $transport): bool => in_array($transport, self::TRANSPORTS, true),
        )));
        return $known !== [] ? implode(',', $known) : null;
    }

    private static function serializer(): SerializerInterface
    {
        return new WebauthnSerializerFactory(AttestationStatementSupportManager::create())->create();
    }

    /**
     * Serializes ceremony options with the library's serializer: binary fields as base64url, null
     * fields left out. The options objects are not JsonSerializable, so json_encode() would dump
     * their raw public properties instead.
     */
    private static function optionsToJson(PublicKeyCredentialOptions $options): string
    {
        return self::serializer()->serialize($options, 'json', [
            AbstractObjectNormalizer::SKIP_NULL_VALUES => true,
            JsonEncode::OPTIONS => JSON_THROW_ON_ERROR,
        ]);
    }

    /**
     * The options array handed to the browser. An empty credential list is left out, as it always
     * was: webauthn-lib 5 serializes it as [] where 4.x omitted it.
     */
    private static function browserOptions(string $json): array
    {
        $options = json_decode($json, true, flags: JSON_THROW_ON_ERROR);
        foreach (['excludeCredentials', 'allowCredentials'] as $list) {
            if (($options[$list] ?? null) === []) {
                unset($options[$list]);
            }
        }
        return $options;
    }

    private function deriveEvalSalt(string $rpId): string
    {
        $label = trim($this->prfEvalSaltLabel);
        if ($label === '') {
            $label = 'webauthn:prf-eval:v1'; // safety fallback
        }
        return hash('sha256', $label . "\0" . $rpId, true);
    }

    private static function base64url_encode(string $bin): string
    {
        return rtrim(strtr(base64_encode($bin), '+/', '-_'), '=');
    }
}
