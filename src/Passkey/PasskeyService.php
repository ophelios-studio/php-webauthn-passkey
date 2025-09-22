<?php namespace Passkey;

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
        private ?string $rpId = null
    ) {}

    private function requireUserId(): int
    {
        $uid = Passport::getUserId();
        if (is_null($uid)) {
            http_response_code(401);
            exit('Not authenticated');
        }
        return $uid;
    }

    private function resolveRpId(): string
    {
        // Derive RP ID from current HTTP host by default (strip port)
        $host = $_SERVER['HTTP_HOST'] ?? ($_SERVER['SERVER_NAME'] ?? 'localhost');
        $host = preg_replace('/:.*/', '', $host) ?: 'localhost';
        return $this->rpId ?? $host;
    }

    public function options(): mixed
    {
        $userId = $this->requireUserId();

        // Build user entity via broker (loads profile info as needed)
        $userEntity = $this->provider->getUserEntity($userId);

        $rpId = $this->resolveRpId();
        $rp = new PublicKeyCredentialRpEntity($this->rpName, $rpId);

        $algos = [
            new PublicKeyCredentialParameters('public-key', Algorithms::COSE_ALGORITHM_ES256),
            new PublicKeyCredentialParameters('public-key', Algorithms::COSE_ALGORITHM_EDDSA),
            new PublicKeyCredentialParameters('public-key', Algorithms::COSE_ALGORITHM_RS256),
        ];

        $authSel = AuthenticatorSelectionCriteria::create(
            authenticatorAttachment: null,
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

        if (session_status() !== PHP_SESSION_ACTIVE) session_start();
        // Store full options as JSON for later verification (ensures nested JsonSerializable objects are properly serialized)
        $_SESSION['webauthn_creation_options'] = json_encode($creation, JSON_THROW_ON_ERROR);

        return json_decode(json_encode($creation, JSON_THROW_ON_ERROR), true, flags: JSON_THROW_ON_ERROR);
    }

    public function verify(): array {
        $userId = $this->requireUserId();
        if (session_status() !== PHP_SESSION_ACTIVE) session_start();
        $optionsData = $_SESSION['webauthn_creation_options'] ?? null;
        if (!$optionsData) { http_response_code(400); return ['ok'=>false,'err'=>'Options missing']; }

        $raw = file_get_contents('php://input');
        $body = json_decode($raw, true);
        $clientResponse = $body['credential'] ?? null;
        if (!$clientResponse) { http_response_code(400); return ['ok'=>false,'err'=>'Missing credential']; }

        // Load the credential from client using the Serializer (no deprecated loader)
        $attestationSupport = \Webauthn\AttestationStatement\AttestationStatementSupportManager::create();
        $serializer = (new WebauthnSerializerFactory($attestationSupport))->create();
        $publicKeyCredential = $serializer->denormalize($clientResponse, \Webauthn\PublicKeyCredential::class);
        if (!($publicKeyCredential->response instanceof AuthenticatorAttestationResponse)) {
            http_response_code(400); return ['ok'=>false,'err'=>'Invalid response type'];
        }
        $attestationResponse = $publicKeyCredential->response;

        // Re-create options from stored data using Serializer (no deprecated createFrom*)
        $creation = $serializer->deserialize($optionsData, PublicKeyCredentialCreationOptions::class, 'json');

        // Validate attestation
        $validator = new AuthenticatorAttestationResponseValidator();
        $source = $validator->check($attestationResponse, $creation, $this->resolveRpId());

        unset($_SESSION['webauthn_creation_options']);

        $credentialId   = $source->publicKeyCredentialId;    // binary
        $publicKeyCose  = $source->credentialPublicKey;      // binary
        $signCount      = $source->counter;
        $backupEligible = (bool)($source->backupEligible ?? false);
        $transports     = !empty($source->transports) ? implode(',', $source->transports) : null;

        // Store in DB via broker
        $this->provider->saveAttestation($userId, $credentialId, $publicKeyCose, $signCount, $backupEligible, $transports);

        return ['ok'=>true];
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
        if (session_status() !== PHP_SESSION_ACTIVE) session_start();
        $_SESSION['webauthn_request_options'] = json_encode($options, JSON_THROW_ON_ERROR);
        return json_decode(json_encode($options, JSON_THROW_ON_ERROR), true, flags: JSON_THROW_ON_ERROR);
    }

    public function authenticate(): array
    {
        if (session_status() !== PHP_SESSION_ACTIVE) session_start();
        $optionsData = $_SESSION['webauthn_request_options'] ?? null;
        if (!$optionsData) { http_response_code(400); return ['ok'=>false,'err'=>'Options missing']; }

        $raw = file_get_contents('php://input');
        $body = json_decode($raw, true);
        $clientResponse = $body['credential'] ?? null;
        if (!$clientResponse) { http_response_code(400); return ['ok'=>false,'err'=>'Missing credential']; }

        $attestationSupport = \Webauthn\AttestationStatement\AttestationStatementSupportManager::create();
        $serializer = (new WebauthnSerializerFactory($attestationSupport))->create();
        $publicKeyCredential = $serializer->denormalize($clientResponse, \Webauthn\PublicKeyCredential::class);
        if (!($publicKeyCredential->response instanceof AuthenticatorAssertionResponse)) {
            http_response_code(400); return ['ok'=>false,'err'=>'Invalid response type']; }
        $assertionResponse = $publicKeyCredential->response;

        /** @var PublicKeyCredentialRequestOptions $requestOptions */
        $requestOptions = $serializer->deserialize($optionsData, PublicKeyCredentialRequestOptions::class, 'json');

        // Determine user and credential source
        $credId = $publicKeyCredential->rawId; // binary
        $userId = $this->provider->findUserIdByCredentialId($credId);
        if (!$userId) { http_response_code(401); return ['ok'=>false,'err'=>'Unknown credential']; }
        $credentialSource = $this->provider->getCredentialSource($credId);
        if (!$credentialSource) { http_response_code(401); return ['ok'=>false,'err'=>'Credential source not found']; }

        $validator = new AuthenticatorAssertionResponseValidator();
        // Pass the PublicKeyCredentialSource as required by the library
        $source = $validator->check($credentialSource, $assertionResponse, $requestOptions, $this->resolveRpId(), (string)$userId);

        unset($_SESSION['webauthn_request_options']);

        // Update usage and sign count
        $this->provider->updateUsageAndCounter($source->publicKeyCredentialId, $source->counter);

        // Log user in
        $user = UserService::read($userId);
        UserService::updateLastConnection($user->id);
        Passport::registerUser($user);

        return ['ok'=>true];
    }
}