<?php

namespace Passkey;

use Webauthn\AttestationStatement\AttestationStatementSupportManager;
use Webauthn\PublicKeyCredential;
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
    ) {}

    public function options(string $authenticatedUserId): mixed
    {
        $userEntity = $this->provider->getUserCredentialEntity($authenticatedUserId);

        $rpId = $this->resolveRpId();
        $rp = new PublicKeyCredentialRpEntity($this->rpName, $rpId);

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

        // Store full options as JSON for later verification (ensures nested JsonSerializable objects are properly serialized)
        $_SESSION['webauthn_creation_options'] = json_encode($creation, JSON_THROW_ON_ERROR);
        $result = json_decode(json_encode($creation, JSON_THROW_ON_ERROR), true, flags: JSON_THROW_ON_ERROR);
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
        $attestationSupport = AttestationStatementSupportManager::create();
        $serializer = new WebauthnSerializerFactory($attestationSupport)->create();
        $publicKeyCredential = $serializer->denormalize($clientResponse, PublicKeyCredential::class);
        if (!($publicKeyCredential->response instanceof AuthenticatorAttestationResponse)) {
            http_response_code(400);
            return ['ok' => false, 'err' => 'Invalid response type'];
        }
        $attestationResponse = $publicKeyCredential->response;

        // Re-create options from stored data using Serializer (no deprecated createFrom*)
        $creation = $serializer->deserialize($optionsData, PublicKeyCredentialCreationOptions::class, 'json');

        // Validate attestation
        $validator = new AuthenticatorAttestationResponseValidator();
        $source = $validator->check($attestationResponse, $creation, $this->resolveRpId());

        unset($_SESSION['webauthn_creation_options']);

        // Store credential_id and public_key_cose as hex strings because the broker uses decode(?, 'hex') when inserting
        $passkey = new Passkey(
            id: null,
            user_id: $authenticatedUserId,
            credential_id: bin2hex($source->publicKeyCredentialId),
            public_key_cose: bin2hex($source->credentialPublicKey),
            sign_count: $source->counter,
            backup_eligible: ($source->backupEligible ?? false),
            prf_salt: bin2hex(random_bytes(32)),
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
        $_SESSION['webauthn_request_options'] = json_encode($options, JSON_THROW_ON_ERROR);
        $result = json_decode(json_encode($options, JSON_THROW_ON_ERROR), true, flags: JSON_THROW_ON_ERROR);
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

        $attestationSupport = AttestationStatementSupportManager::create();
        $serializer = new WebauthnSerializerFactory($attestationSupport)->create();
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

        $validator = new AuthenticatorAssertionResponseValidator();
        // Pass the PublicKeyCredentialSource as required by the library
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

    private function deriveEvalSalt(string $rpId): string
    {
        return hash('sha256', 'webauthn:prf-eval:v1|' . $rpId, true);
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
