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

final readonly class PasskeyService
{
    public function __construct(
        private PasskeyProvider $provider,
        private string $rpName = 'Your App',
        private ?string $rpId = null,
        private bool $enablePrf = false,
        private string $prfEvalSaltLabel = 'webauthn:prf-eval:v1'
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

        if (session_status() !== PHP_SESSION_ACTIVE) {
            session_start();
        }

        // Store the full options as JSON for later verification; the browser receives the same JSON
        $json = self::optionsToJson($creation);
        $_SESSION['webauthn_creation_options'] = $json;
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
        if (session_status() !== PHP_SESSION_ACTIVE) {
            session_start();
        }
        $optionsData = $_SESSION['webauthn_creation_options'] ?? null;
        if (!$optionsData) {
            http_response_code(400);
            return ['ok' => false, 'err' => 'Options missing'];
        }

        $raw = file_get_contents('php://input');
        $body = json_decode($raw, true);
        $clientResponse = $body['credential'] ?? null;
        if (!$clientResponse) {
            http_response_code(400);
            return ['ok' => false, 'err' => 'Missing credential'];
        }

        // Load the credential from client using the Serializer (no deprecated loader)
        $serializer = self::serializer();
        $publicKeyCredential = $serializer->denormalize($clientResponse, PublicKeyCredential::class);
        if (!($publicKeyCredential->response instanceof AuthenticatorAttestationResponse)) {
            http_response_code(400);
            return ['ok' => false, 'err' => 'Invalid response type'];
        }
        $attestationResponse = $publicKeyCredential->response;

        // Re-create options from stored data using Serializer (no deprecated createFrom*). No check
        // reads rp.name, and denormalizing it trips the webauthn-lib 5.3 deprecation of the RP name.
        $storedOptions = json_decode($optionsData, true, flags: JSON_THROW_ON_ERROR);
        unset($storedOptions['rp']['name']);
        $creation = $serializer->denormalize($storedOptions, PublicKeyCredentialCreationOptions::class, 'json');

        // Validate attestation
        $validator = new AuthenticatorAttestationResponseValidator(new CeremonyStepManagerFactory()->creationCeremony());
        $source = $validator->check($attestationResponse, $creation, $this->resolveRpId());

        unset($_SESSION['webauthn_creation_options']);

        $passkey = new Passkey(
            id: null,
            user_id: $authenticatedUserId,
            credential_id: $source->publicKeyCredentialId,
            public_key_cose: $source->credentialPublicKey,
            sign_count: $source->counter,
            backup_eligible: $source->backupEligible ?? false,
            prf_salt: random_bytes(32),
            prf_eval_label: $this->prfEvalSaltLabel,
            transports: !empty($source->transports)
                ? implode(',', $source->transports)
                : null
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
        if (session_status() !== PHP_SESSION_ACTIVE) {
            session_start();
        }
        $json = self::optionsToJson($options);
        $_SESSION['webauthn_request_options'] = $json;
        $result = self::browserOptions($json);
        if ($this->enablePrf) {
            $result['extensions']['prf']['eval']['first'] = self::base64url_encode($this->deriveEvalSalt($rpId));
        }
        return $result;
    }

    public function authenticate(callable $callback): array
    {
        if (session_status() !== PHP_SESSION_ACTIVE) {
            session_start();
        }
        $optionsData = $_SESSION['webauthn_request_options'] ?? null;
        if (!$optionsData) {
            http_response_code(400);
            return ['ok' => false, 'err' => 'Options missing'];
        }

        $raw = file_get_contents('php://input');
        $body = json_decode($raw, true);
        $clientResponse = $body['credential'] ?? null;
        if (!$clientResponse) {
            http_response_code(400);
            return ['ok' => false, 'err' => 'Missing credential'];
        }

        $serializer = self::serializer();
        $publicKeyCredential = $serializer->denormalize($clientResponse, PublicKeyCredential::class);
        if (!($publicKeyCredential->response instanceof AuthenticatorAssertionResponse)) {
            http_response_code(400);
            return ['ok' => false, 'err' => 'Invalid response type'];
        }
        $assertionResponse = $publicKeyCredential->response;

        /** @var PublicKeyCredentialRequestOptions $requestOptions */
        $requestOptions = $serializer->deserialize($optionsData, PublicKeyCredentialRequestOptions::class, 'json');

        // Determine user and credential source
        $credId = $publicKeyCredential->rawId; // binary
        $userId = $this->provider->findUserIdByCredentialId($credId);
        if (!$userId) {
            http_response_code(401);
            return ['ok' => false, 'err' => 'Unknown credential'];
        }
        $credentialSource = $this->provider->getCredentialSource($credId);
        if (!$credentialSource) {
            http_response_code(401);
            return ['ok' => false, 'err' => 'Credential source not found'];
        }

        $validator = new AuthenticatorAssertionResponseValidator(new CeremonyStepManagerFactory()->requestCeremony());
        $source = $validator->check($credentialSource, $assertionResponse, $requestOptions, $this->resolveRpId(), (string)$userId);

        unset($_SESSION['webauthn_request_options']);

        // Update usage and sign count
        $this->provider->updateUsageAndCounter($source->publicKeyCredentialId, $source->counter);

        $callback($userId);
        return ['ok' => true];
    }

    /**
     * Derives a stable 32-byte seed from the WebAuthn PRF output and the
     * credential's stored salt using HKDF (SHA-256). Returns base64url.
     * @return string The PRF-Based Seed
     */
    public function deriveSeedFromPrf(string $credentialIdRaw, string $prfFirstB64Url): string
    {
        $passkey = $this->provider->findByCredentialId($credentialIdRaw);
        if (!$passkey || $passkey->prf_salt === null || $passkey->prf_salt === '') {
            throw new \RuntimeException('Passkey salt not found');
        }
        $prf = self::base64url_decode($prfFirstB64Url);
        $salt = $passkey->prf_salt;
        if (is_string($salt) && strlen($salt) % 2 === 0 && ctype_xdigit($salt)) {
            $salt = hex2bin($salt) ?: $salt;
        }
        $seed = hash_hkdf('sha256', $prf, 32, 'seed:v1', $salt);
        return self::base64url_encode($seed);
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

    private static function base64url_decode(string $b64): string
    {
        $b64 = strtr($b64, '-_', '+/');
        $pad = strlen($b64) % 4;
        if ($pad) {
            $b64 .= str_repeat('=', 4 - $pad);
        }
        return base64_decode($b64, true) ?: '';
    }
}
