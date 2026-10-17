<?php

use PHPUnit\Framework\TestCase;
use Symfony\Component\Uid\Uuid;
use VoltCMS\UserAccess\Passkey;
use VoltCMS\UserAccess\Utils;
use Webauthn\CredentialRecord;
use Webauthn\TrustPath\CertificateTrustPath;
use Webauthn\TrustPath\EmptyTrustPath;

class PasskeyTest extends TestCase
{
    private function makePasskey(): Passkey
    {
        $passkey = new Passkey();
        $passkey->setAttributes([
            '_id' => '22222222-2222-2222-2222-222222222222',
            '_created' => 1700000000.0,
            '_modified' => 1700000000.0,
            'userId' => '11111111-1111-1111-1111-111111111111',
            'name' => 'Work laptop',
            'credentialId' => Utils::base64UrlEncode("\x01\x02\x03\xfe\xff"),
            'publicKey' => Utils::base64UrlEncode('cose-key-bytes'),
            'signCount' => 7,
            'transports' => ['internal', 'hybrid'],
            'attestationType' => 'none',
            'trustPath' => [],
            'aaguid' => 'ADCE0002-35BC-C60A-648B-0B25F1F05503',
            'backupEligible' => true,
            'backupStatus' => true,
            'uvInitialized' => true,
            'lastUsed' => 1700000500,
        ]);
        return $passkey;
    }

    public function testBlankNameFallsBackToDefault(): void
    {
        $passkey = new Passkey();
        $passkey->setName('   ');
        $this->assertSame(Passkey::DEFAULT_NAME, $passkey->getName());
    }

    public function testNameIsTrimmed(): void
    {
        $passkey = new Passkey();
        $passkey->setName('  Phone  ');
        $this->assertSame('Phone', $passkey->getName());
    }

    public function testNameWithControlCharactersIsRejected(): void
    {
        $passkey = new Passkey();
        $this->expectExceptionMessage('EXCEPTION_INVALID_PASSKEY_NAME');
        $passkey->setName("Phone\nline two");
    }

    public function testNameLongerThanTheLimitIsRejected(): void
    {
        $passkey = new Passkey();
        // Counted in characters, not bytes: 64 multi-byte characters fit.
        $passkey->setName(str_repeat('ü', Passkey::NAME_MAX_LENGTH));
        $this->assertSame(str_repeat('ü', Passkey::NAME_MAX_LENGTH), $passkey->getName());
        $this->expectExceptionMessage('EXCEPTION_INVALID_PASSKEY_NAME');
        $passkey->setName(str_repeat('ü', Passkey::NAME_MAX_LENGTH + 1));
    }

    public function testEmptyUserIdIsRejected(): void
    {
        $passkey = new Passkey();
        $this->expectExceptionMessage('EXCEPTION_EMPTY_ID');
        $passkey->setUserId(' ');
    }

    public function testCredentialIdIsStoredCanonically(): void
    {
        $passkey = new Passkey();
        // Padded input is accepted but stored unpadded, the form sign-in uses
        // to look the credential up.
        $passkey->setCredentialId('AQID-v8=');
        $this->assertSame('AQID-v8', $passkey->getCredentialId());
    }

    public function testCredentialIdOutsideTheBase64UrlAlphabetIsRejected(): void
    {
        $passkey = new Passkey();
        $this->expectExceptionMessage('EXCEPTION_INVALID_PASSKEY');
        $passkey->setCredentialId('not+base64url/');
    }

    public function testOverlongCredentialIdIsRejected(): void
    {
        $passkey = new Passkey();
        $this->expectExceptionMessage('EXCEPTION_INVALID_PASSKEY');
        $passkey->setCredentialId(Utils::base64UrlEncode(str_repeat('x', Passkey::CREDENTIAL_ID_MAX_LENGTH + 1)));
    }

    public function testNegativeSignCountIsRejected(): void
    {
        $passkey = new Passkey();
        $this->expectExceptionMessage('EXCEPTION_INVALID_PASSKEY');
        $passkey->setSignCount(-1);
    }

    public function testInvalidAaguidIsRejected(): void
    {
        $passkey = new Passkey();
        $this->expectExceptionMessage('EXCEPTION_INVALID_PASSKEY');
        $passkey->setAaguid('not-a-uuid');
    }

    public function testAttributesRoundTrip(): void
    {
        $passkey = $this->makePasskey();
        $copy = new Passkey();
        $copy->setAttributes($passkey->getAttributes());

        $this->assertSame($passkey->getAttributes(), $copy->getAttributes());
        $this->assertSame(1700000000, $copy->getCreated());
        $this->assertSame('adce0002-35bc-c60a-648b-0b25f1f05503', $copy->getAaguid());
    }

    public function testCredentialRecordRoundTrip(): void
    {
        $passkey = $this->makePasskey();
        $record = $passkey->toCredentialRecord();

        $this->assertSame("\x01\x02\x03\xfe\xff", $record->publicKeyCredentialId);
        $this->assertSame('cose-key-bytes', $record->credentialPublicKey);
        // The user handle is the owning user's id.
        $this->assertSame('11111111-1111-1111-1111-111111111111', $record->userHandle);
        $this->assertSame(7, $record->counter);
        $this->assertInstanceOf(EmptyTrustPath::class, $record->trustPath);

        $copy = new Passkey();
        $copy->fromCredentialRecord($record);
        $this->assertSame($passkey->getCredentialId(), $copy->getCredentialId());
        $this->assertSame($passkey->getPublicKey(), $copy->getPublicKey());
        $this->assertSame($passkey->getUserId(), $copy->getUserId());
        $this->assertSame($passkey->getTransports(), $copy->getTransports());
        $this->assertTrue($copy->getBackupStatus());
    }

    public function testCertificateTrustPathIsKept(): void
    {
        $record = CredentialRecord::create(
            "\x09\x08",
            'public-key',
            [],
            'basic',
            CertificateTrustPath::create(['-----BEGIN CERTIFICATE-----']),
            Uuid::fromString('00000000-0000-0000-0000-000000000000'),
            'cose-key-bytes',
            '11111111-1111-1111-1111-111111111111',
            0
        );
        $passkey = new Passkey();
        $passkey->fromCredentialRecord($record);

        $this->assertSame(['-----BEGIN CERTIFICATE-----'], $passkey->getTrustPath());
        $this->assertInstanceOf(CertificateTrustPath::class, $passkey->toCredentialRecord()->trustPath);
    }

    public function testToArrayLeavesOutKeyMaterial(): void
    {
        $summary = $this->makePasskey()->toArray();

        $this->assertSame('22222222-2222-2222-2222-222222222222', $summary['id']);
        $this->assertSame('Work laptop', $summary['name']);
        $this->assertSame(date(DATE_ATOM, 1700000500), $summary['lastUsed']);
        $this->assertTrue($summary['synced']);
        $this->assertArrayNotHasKey('publicKey', $summary);
        $this->assertArrayNotHasKey('credentialId', $summary);
        $this->assertArrayNotHasKey('signCount', $summary);
    }

}
