<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Support\Contract;

use Clavia\Domain\Authentication\Passkey\Aaguid;
use Clavia\Domain\Authentication\Passkey\CoseAlgorithm;
use Clavia\Domain\Authentication\Passkey\CosePublicKey;
use Clavia\Domain\Authentication\Passkey\CredentialId;
use Clavia\Domain\Authentication\Passkey\Passkey;
use Clavia\Domain\Authentication\Passkey\PasskeyId;
use Clavia\Domain\Authentication\Passkey\PasskeyName;
use Clavia\Domain\Authentication\Passkey\PasskeyRepository;
use Clavia\Domain\Authentication\Passkey\Transport;
use Clavia\Domain\Identity\User;
use Clavia\Domain\Identity\UserId;
use Clavia\Domain\Identity\UserRepository;
use Clavia\Domain\Shared\AlreadyExists;
use ClaviaTest\Support\Fake\SeededRandomSource;
use DateTimeImmutable;
use PHPUnit\Framework\Attributes\Test;

/**
 * What every {@see PasskeyRepository} must do.
 */
trait PasskeyRepositoryContract
{
    abstract protected function users(): UserRepository;

    abstract protected function passkeys(): PasskeyRepository;

    #[Test]
    public function aSavedPasskeyIsReadBackWhole(): void
    {
        $owner = $this->passkeyOwner('ada@example.com');
        $passkey = Passkey::register(
            PasskeyId::generate(new SeededRandomSource(1)),
            $owner,
            CredentialId::fromBytes(self::credentialBytes('first')),
            CosePublicKey::fromBytes("\x00\xa5\x01\x02\x03\x26\xff\x20\x01 not text \x80\x81"),
            CoseAlgorithm::ES256,
            7,
            [Transport::Internal, Transport::Hybrid],
            Aaguid::fromString('adce0002-35bc-c60a-648b-0b25f1f05503'),
            true,
            true,
            PasskeyName::fromString('Work laptop'),
            new DateTimeImmutable('2026-01-15T10:00:00.123456Z'),
        );
        $this->passkeys()->save($passkey);

        $found = $this->passkeys()->one($passkey->id);

        self::assertNotNull($found);
        self::assertTrue($found->id->equals($passkey->id));
        self::assertTrue($found->userId->equals($owner));
        self::assertSame($passkey->credentialId->bytes(), $found->credentialId->bytes());
        self::assertSame($passkey->publicKey->bytes(), $found->publicKey->bytes());
        self::assertSame(CoseAlgorithm::ES256, $found->algorithm);
        self::assertSame(7, $found->signCount);
        self::assertSame([Transport::Internal, Transport::Hybrid], $found->transports);
        self::assertSame('adce0002-35bc-c60a-648b-0b25f1f05503', $found->aaguid?->value);
        self::assertTrue($found->backupEligible);
        self::assertTrue($found->backedUp);
        self::assertSame('Work laptop', $found->name->value);
        self::assertSame('2026-01-15T10:00:00.123456+00:00', $found->createdAt->format('Y-m-d\TH:i:s.uP'));
        self::assertNull($found->lastUsedAt);
    }

    #[Test]
    public function aPasskeyWithoutAnAaguidOrTransportsIsReadBackAsSuch(): void
    {
        $passkey = $this->passkeyFor($this->passkeyOwner('ada@example.com'), 'bare', aaguid: null, transports: []);
        $this->passkeys()->save($passkey);

        $found = $this->passkeys()->one($passkey->id);

        self::assertNull($found?->aaguid);
        self::assertSame([], $found?->transports);
        self::assertFalse($found?->backupEligible);
    }

    #[Test]
    public function aPasskeyIsFoundByItsCredentialIdExactlyAndByNothingElse(): void
    {
        $passkey = $this->passkeyFor($this->passkeyOwner('ada@example.com'), 'first');
        $this->passkeys()->save($passkey);

        self::assertTrue(
            $this->passkeys()->ofCredentialId(CredentialId::fromBytes(self::credentialBytes('first')))?->id
                ->equals($passkey->id),
        );
        self::assertNull($this->passkeys()->ofCredentialId(CredentialId::fromBytes(self::credentialBytes('other'))));
        self::assertNull($this->passkeys()->one(PasskeyId::generate(new SeededRandomSource(99))));
    }

    #[Test]
    public function aCredentialBelongsToOnePasskeyOnly(): void
    {
        $this->passkeys()->save($this->passkeyFor($this->passkeyOwner('ada@example.com'), 'shared'));

        $this->expectException(AlreadyExists::class);

        $this->passkeys()->save($this->passkeyFor($this->passkeyOwner('bob@example.com'), 'shared', idSeed: 2));
    }

    #[Test]
    public function aPasskeyIsSavedAgainWithoutBecomingAnother(): void
    {
        $passkey = $this->passkeyFor($this->passkeyOwner('ada@example.com'), 'first');
        $this->passkeys()->save($passkey);

        $this->passkeys()->save($passkey);

        self::assertSame(1, $this->passkeys()->countOf($passkey->userId));
    }

    #[Test]
    public function anAccountsPasskeysAreListedOldestFirstAndCountedApart(): void
    {
        $ada = $this->passkeyOwner('ada@example.com');
        $bob = $this->passkeyOwner('bob@example.com');
        foreach ([['b', 2, $ada], ['a', 1, $ada], ['c', 3, $ada], ['x', 4, $bob]] as [$seed, $day, $owner]) {
            $this->passkeys()->save($this->passkeyFor(
                $owner,
                $seed,
                idSeed: ord($seed),
                at: new DateTimeImmutable(sprintf('2026-01-%02dT10:00:00Z', $day)),
            ));
        }

        self::assertSame(
            ['a', 'b', 'c'],
            array_map(
                static fn (Passkey $passkey): string => $passkey->name->value,
                $this->passkeys()->ofUser($ada),
            ),
        );
        self::assertSame(3, $this->passkeys()->countOf($ada));
        self::assertSame(1, $this->passkeys()->countOf($bob));
        self::assertSame([], $this->passkeys()->ofUser($this->passkeyOwner('eve@example.com')));
        self::assertSame(0, $this->passkeys()->countOf($this->passkeyOwner('eve@example.com')));
    }

    #[Test]
    public function passkeysAreCountedForSeveralAccountsAtOnce(): void
    {
        $ada = $this->passkeyOwner('ada@example.com');
        $bob = $this->passkeyOwner('bob@example.com');
        $eve = $this->passkeyOwner('eve@example.com');
        $this->passkeys()->save($this->passkeyFor($ada, 'a1', idSeed: 1));
        $this->passkeys()->save($this->passkeyFor($ada, 'a2', idSeed: 2));
        $this->passkeys()->save($this->passkeyFor($bob, 'b1', idSeed: 3));

        $counts = $this->passkeys()->countsAmong([$ada, $bob, $eve]);

        self::assertSame(2, $counts[$ada->value] ?? null);
        self::assertSame(1, $counts[$bob->value] ?? null);
        self::assertArrayNotHasKey($eve->value, $counts);
        self::assertSame([], $this->passkeys()->countsAmong([]));
    }

    #[Test]
    public function aRenameIsKeptAndTheCounterIsNotMovedBySaving(): void
    {
        $passkey = $this->passkeyFor($this->passkeyOwner('ada@example.com'), 'first', signCount: 5);
        $this->passkeys()->save($passkey);
        $passkey->recordUse(9, false, new DateTimeImmutable('2026-02-01T00:00:00Z'));

        $passkey->rename(PasskeyName::fromString('Renamed'));
        $this->passkeys()->save($passkey);

        $found = $this->passkeys()->one($passkey->id);
        self::assertSame('Renamed', $found?->name->value);
        self::assertSame(5, $found?->signCount, 'Only recordUse() moves the counter.');
        self::assertNull($found?->lastUsedAt);
    }

    #[Test]
    public function aUseIsRecordedWhenTheCounterIsWhereItWasRead(): void
    {
        $passkey = $this->passkeyFor($this->passkeyOwner('ada@example.com'), 'first', signCount: 5);
        $this->passkeys()->save($passkey);
        $read = $this->passkeys()->one($passkey->id);
        self::assertNotNull($read);

        $read->recordUse(6, false, new DateTimeImmutable('2026-02-01T08:30:00.5Z'));

        self::assertTrue($this->passkeys()->recordUse($read, 5));
        $found = $this->passkeys()->one($passkey->id);
        self::assertSame(6, $found?->signCount);
        self::assertSame('2026-02-01T08:30:00.500000+00:00', $found?->lastUsedAt?->format('Y-m-d\TH:i:s.uP'));
    }

    #[Test]
    public function oneOfTwoRacingUsesWinsAndTheOtherLearnsItLost(): void
    {
        $passkey = $this->passkeyFor($this->passkeyOwner('ada@example.com'), 'first', signCount: 5);
        $this->passkeys()->save($passkey);
        $first = $this->passkeys()->one($passkey->id);
        $second = $this->passkeys()->one($passkey->id);
        self::assertNotNull($first);
        self::assertNotNull($second);
        $first->recordUse(6, false, new DateTimeImmutable('2026-02-01T08:00:00Z'));
        $second->recordUse(6, false, new DateTimeImmutable('2026-02-01T08:00:01Z'));

        self::assertTrue($this->passkeys()->recordUse($first, 5));
        self::assertFalse($this->passkeys()->recordUse($second, 5));

        self::assertSame(6, $this->passkeys()->one($passkey->id)?->signCount);
        self::assertSame(
            '2026-02-01T08:00:00+00:00',
            $this->passkeys()->one($passkey->id)?->lastUsedAt?->format('c'),
            'The loser wrote nothing.',
        );
    }

    #[Test]
    public function aSyncedPasskeyThatAlwaysReportsZeroCanRecordEveryUse(): void
    {
        $passkey = $this->passkeyFor($this->passkeyOwner('ada@example.com'), 'synced', signCount: 0, eligible: true);
        $this->passkeys()->save($passkey);

        foreach (['2026-02-01T08:00:00Z', '2026-02-02T08:00:00Z'] as $at) {
            $read = $this->passkeys()->one($passkey->id);
            self::assertNotNull($read);
            $read->recordUse(0, true, new DateTimeImmutable($at));

            self::assertTrue($this->passkeys()->recordUse($read, 0));
        }

        $found = $this->passkeys()->one($passkey->id);
        self::assertNotNull($found);
        self::assertSame(0, $found->signCount);
        self::assertTrue($found->backedUp);
        self::assertSame('2026-02-02T08:00:00+00:00', $found->lastUsedAt?->format('c'));
    }

    #[Test]
    public function recordingTheUseOfAPasskeyThatIsGoneChangesNothing(): void
    {
        $passkey = $this->passkeyFor($this->passkeyOwner('ada@example.com'), 'first');
        $this->passkeys()->save($passkey);
        $this->passkeys()->delete($passkey->id);

        self::assertFalse($this->passkeys()->recordUse($passkey, 0));
        self::assertNull($this->passkeys()->one($passkey->id));
    }

    #[Test]
    public function aDeletedPasskeyIsGoneAndDeletingItAgainIsHarmless(): void
    {
        $ada = $this->passkeyOwner('ada@example.com');
        $keep = $this->passkeyFor($ada, 'keep', idSeed: 1);
        $drop = $this->passkeyFor($ada, 'drop', idSeed: 2);
        $this->passkeys()->save($keep);
        $this->passkeys()->save($drop);

        $this->passkeys()->delete($drop->id);
        $this->passkeys()->delete($drop->id);

        self::assertNull($this->passkeys()->one($drop->id));
        self::assertNull($this->passkeys()->ofCredentialId($drop->credentialId));
        self::assertSame(1, $this->passkeys()->countOf($ada));
        self::assertTrue($this->passkeys()->one($keep->id)?->id->equals($keep->id));
    }

    #[Test]
    public function aCredentialCanBeRegisteredAgainOnceItsPasskeyIsGone(): void
    {
        $ada = $this->passkeyOwner('ada@example.com');
        $first = $this->passkeyFor($ada, 'same', idSeed: 1);
        $this->passkeys()->save($first);
        $this->passkeys()->delete($first->id);

        $this->passkeys()->save($this->passkeyFor($ada, 'same', idSeed: 2));

        self::assertSame(1, $this->passkeys()->countOf($ada));
    }

    private function passkeyOwner(string $email): UserId
    {
        $id = UserId::generate(new SeededRandomSource(crc32($email)));
        if ($this->users()->find($id) === null) {
            $this->users()->save(User::register($id, $email, null, new DateTimeImmutable('2026-01-15T10:00:00Z')));
        }

        return $id;
    }

    /** Thirty-two bytes that are not text, one set per seed. */
    private static function credentialBytes(string $seed): string
    {
        return hash('sha256', $seed, true);
    }

    /**
     * @param list<Transport> $transports
     */
    private function passkeyFor(
        UserId $owner,
        string $seed,
        int $idSeed = 1,
        int $signCount = 0,
        bool $eligible = false,
        ?Aaguid $aaguid = null,
        array $transports = [Transport::Usb],
        ?DateTimeImmutable $at = null,
    ): Passkey {
        return Passkey::register(
            PasskeyId::generate(new SeededRandomSource($idSeed)),
            $owner,
            CredentialId::fromBytes(self::credentialBytes($seed)),
            CosePublicKey::fromBytes("\xa5" . $seed),
            CoseAlgorithm::EdDSA,
            $signCount,
            $transports,
            $aaguid,
            $eligible,
            false,
            PasskeyName::fromString($seed),
            $at ?? new DateTimeImmutable('2026-01-15T10:00:00Z'),
        );
    }
}
