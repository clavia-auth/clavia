<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Application\Authentication\Account;

use Clavia\Application\Authentication\Account\PasswordScreen;
use Clavia\Domain\Shared\InvalidValue;
use ClaviaTest\Support\Fake\FakeBreachedPasswords;
use PHPUnit\Framework\TestCase;

/**
 * NIST SP 800-63B §5.1.1.2: the policy first, then the corpus of breached passwords.
 */
final class PasswordScreenTest extends TestCase
{
    public function testAPasswordPassingBothIsAccepted(): void
    {
        $screen = new PasswordScreen(new FakeBreachedPasswords(['password123']));

        self::assertSame('correct horse battery', $screen->accept('correct horse battery'));
    }

    public function testABreachedPasswordIsRefused(): void
    {
        $this->expectException(InvalidValue::class);
        $this->expectExceptionMessageIsOrContains(PasswordScreen::BREACHED);

        new PasswordScreen(new FakeBreachedPasswords(['password123']))->accept('password123');
    }

    public function testThePolicyComesFirstAndAsksNobody(): void
    {
        // A password the policy refuses never leaves the server, even as a hash prefix.
        $corpus = new FakeBreachedPasswords(['short']);

        try {
            new PasswordScreen($corpus)->accept('short');
            self::fail('The policy refuses it.');
        } catch (InvalidValue $refusal) {
            self::assertStringContainsString('at least 8 characters', $refusal->getMessage());
        }
        self::assertSame(0, $corpus->asked);
    }

    public function testAnUnavailableCorpusLetsThePasswordThrough(): void
    {
        // Fail open: somebody else's outage does not lock people out of their accounts.
        self::assertSame(
            'password123',
            new PasswordScreen(FakeBreachedPasswords::unavailable())->accept('password123'),
        );
    }
}
