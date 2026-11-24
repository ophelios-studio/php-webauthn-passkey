<?php

declare(strict_types=1);

namespace Passkey\Tests\Support;

use OpenSSLAsymmetricKey;
use RuntimeException;

/**
 * A test-only ES256 authenticator: a real P-256 key from OpenSSL, attestation format "none", the
 * authenticator data and the COSE key encoded in CBOR by hand. It reads the options JSON the way a
 * browser does and returns the credential JSON the JavaScript module posts back, so the library's
 * validators check genuine signatures. Its knobs answer the way a faulty or hostile authenticator
 * would: a flag left out, another relying party, another ceremony, data altered after signing.
 */
final class SoftwareAuthenticator
{
    private const int FLAG_USER_PRESENT = 0x01;
    private const int FLAG_USER_VERIFIED = 0x04;
    private const int FLAG_BACKUP_ELIGIBLE = 0x08;
    private const int FLAG_BACKED_UP = 0x10;
    private const int FLAG_ATTESTED_CREDENTIAL_DATA = 0x40;

    public readonly string $credentialId;

    /** The canonical COSE_Key of the public key: {1: 2, 3: -7, -1: 1, -2: x, -3: y}. */
    public readonly string $cose;

    /** The user handle (user.id) received at registration, as a resident key keeps it. */
    private ?string $userHandle = null;

    private int $counter = 0;

    private OpenSSLAsymmetricKey $privateKey;

    /**
     * @param bool $synced a synced passkey: backup eligible and backed up (BE and BS flags)
     * @param string|null $credentialId the credential ID to claim; a random one when null
     */
    public function __construct(private readonly bool $synced = false, ?string $credentialId = null)
    {
        $this->privateKey = openssl_pkey_new([
            'private_key_type' => OPENSSL_KEYTYPE_EC,
            'curve_name' => 'prime256v1',
        ]) ?: throw new RuntimeException('P-256 key generation failed');
        $details = openssl_pkey_get_details($this->privateKey) ?: throw new RuntimeException('no key details');

        $this->credentialId = $credentialId ?? random_bytes(16);
        $this->cose = "\xA5"
            . "\x01\x02"
            . "\x03\x26"
            . "\x20\x01"
            . "\x21\x58\x20" . str_pad($details['ec']['x'], 32, "\x00", STR_PAD_LEFT)
            . "\x22\x58\x20" . str_pad($details['ec']['y'], 32, "\x00", STR_PAD_LEFT);
    }

    /**
     * Answers navigator.credentials.create() for the given creation options JSON.
     *
     * @param array<string, mixed> $options the array options() returned
     * @param array<string, mixed> $clientExtensionResults
     * @param string|null $rpId the relying party the authenticator data is hashed for; the options' one when null
     * @param list<string> $transports the transports the client reports
     * @return array<string, mixed> the credential as the JavaScript module posts it
     */
    public function register(
        array $options,
        string $origin,
        array $clientExtensionResults = [],
        bool $userPresent = true,
        bool $userVerified = true,
        ?string $rpId = null,
        array $transports = ['internal'],
    ): array {
        $this->userHandle = self::base64UrlDecode($options['user']['id']);
        $clientData = self::clientData('webauthn.create', $options['challenge'], $origin);
        $authData = hash('sha256', $rpId ?? $options['rp']['id'], true)
            . chr($this->flags($userPresent, $userVerified) | self::FLAG_ATTESTED_CREDENTIAL_DATA)
            . pack('N', $this->counter)
            . str_repeat("\x00", 16)
            . pack('n', strlen($this->credentialId))
            . $this->credentialId
            . $this->cose;
        $attestationObject = "\xA3"
            . self::cborText('fmt') . self::cborText('none')
            . self::cborText('attStmt') . "\xA0"
            . self::cborText('authData') . self::cborHead(2, strlen($authData)) . $authData;

        return [
            'id' => self::base64Url($this->credentialId),
            'type' => 'public-key',
            'rawId' => self::base64Url($this->credentialId),
            'response' => [
                'clientDataJSON' => self::base64Url($clientData),
                'attestationObject' => self::base64Url($attestationObject),
                'transports' => $transports,
            ],
            'clientExtensionResults' => (object) $clientExtensionResults,
        ];
    }

    /**
     * Answers navigator.credentials.get() for the given request options JSON.
     *
     * @param array<string, mixed> $options the array assertionOptions() returned
     * @param int|null $counter the signature counter to report; the next one when null
     * @param array<string, mixed>|null $clientExtensionResults
     * @param string|null $rpId the relying party the authenticator data is hashed for; the options' one when null
     * @param string $type the ceremony the client data claims
     * @param bool $alteredAfterSigning flips a bit of the authenticator data once it is signed
     * @return array<string, mixed> the credential as the JavaScript module posts it
     */
    public function login(
        array $options,
        string $origin,
        ?int $counter = null,
        ?array $clientExtensionResults = null,
        bool $userPresent = true,
        bool $userVerified = true,
        ?string $rpId = null,
        string $type = 'webauthn.get',
        bool $alteredAfterSigning = false,
    ): array {
        $this->counter = $counter ?? $this->counter + 1;
        $clientData = self::clientData($type, $options['challenge'], $origin);
        $authData = hash('sha256', $rpId ?? $options['rpId'], true)
            . chr($this->flags($userPresent, $userVerified))
            . pack('N', $this->counter);
        openssl_sign($authData . hash('sha256', $clientData, true), $signature, $this->privateKey, OPENSSL_ALGO_SHA256)
            ?: throw new RuntimeException('signature failed');
        if ($alteredAfterSigning) {
            $authData[36] = chr(ord($authData[36]) ^ 0x01); // the last byte of the counter
        }

        $credential = [
            'id' => self::base64Url($this->credentialId),
            'type' => 'public-key',
            'rawId' => self::base64Url($this->credentialId),
            'response' => [
                'authenticatorData' => self::base64Url($authData),
                'clientDataJSON' => self::base64Url($clientData),
                'signature' => self::base64Url($signature),
                'userHandle' => $this->userHandle === null ? null : self::base64Url($this->userHandle),
            ],
        ];
        if ($clientExtensionResults !== null) {
            $credential['clientExtensionResults'] = (object) $clientExtensionResults;
        }
        return $credential;
    }

    private function flags(bool $userPresent, bool $userVerified): int
    {
        return ($userPresent ? self::FLAG_USER_PRESENT : 0)
            | ($userVerified ? self::FLAG_USER_VERIFIED : 0)
            | ($this->synced ? self::FLAG_BACKUP_ELIGIBLE | self::FLAG_BACKED_UP : 0);
    }

    private static function clientData(string $type, string $challenge, string $origin): string
    {
        return json_encode(
            ['type' => $type, 'challenge' => $challenge, 'origin' => $origin, 'crossOrigin' => false],
            JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR,
        );
    }

    private static function cborText(string $text): string
    {
        return self::cborHead(3, strlen($text)) . $text;
    }

    private static function cborHead(int $majorType, int $length): string
    {
        $type = $majorType << 5;
        return match (true) {
            $length < 24 => chr($type | $length),
            $length < 0x100 => chr($type | 24) . chr($length),
            $length < 0x10000 => chr($type | 25) . pack('n', $length),
            default => chr($type | 26) . pack('N', $length),
        };
    }

    private static function base64Url(string $bytes): string
    {
        return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
    }

    private static function base64UrlDecode(string $encoded): string
    {
        $decoded = base64_decode(strtr($encoded, '-_', '+/'), true);
        return $decoded !== false ? $decoded : throw new RuntimeException('invalid base64url');
    }
}
