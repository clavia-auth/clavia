<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Integration\Persistence;

use Clavia\Adapter\Secondary\Persistence\PhpDb\PhpDbAuditLog;
use Clavia\Domain\Audit\Actor;
use Clavia\Domain\Audit\AuditEvent;
use Clavia\Domain\Audit\AuditEventId;
use Clavia\Domain\Audit\AuditEventType;
use Clavia\Domain\Audit\AuditLog;
use Clavia\Domain\Audit\Outcome;
use ClaviaTest\Support\Contract\AuditLogContract;
use ClaviaTest\Support\Fake\SeededRandomSource;
use ClaviaTest\Support\IntegrationTestCase;
use ClaviaTest\Support\TestStorage;
use DateTimeImmutable;
use Throwable;

final class PhpDbAuditLogTest extends IntegrationTestCase
{
    use AuditLogContract;

    #[\Override]
    protected function auditLog(): AuditLog
    {
        return new PhpDbAuditLog(TestStorage::database());
    }

    public function testAnEventIsNeverChanged(): void
    {
        $this->auditLog()->append(AuditEvent::record(
            AuditEventId::generate(new SeededRandomSource(1)),
            AuditEventType::SignedIn,
            new DateTimeImmutable('2026-01-15T10:00:00Z'),
            Actor::system(),
            null,
            Outcome::Success,
        ));

        try {
            TestStorage::database()->execute("UPDATE audit_events SET outcome = 'failure'");
            self::fail('An audit event was changed.');
        } catch (Throwable $refused) {
            self::assertStringContainsString('audit events are never changed', self::messages($refused));
        }
        self::assertSame('success', TestStorage::database()->fetchValue('SELECT outcome FROM audit_events'));
    }

    private static function messages(Throwable $error): string
    {
        $messages = [];
        for ($cause = $error; $cause !== null; $cause = $cause->getPrevious()) {
            $messages[] = $cause->getMessage();
        }

        return implode(' | ', $messages);
    }
}
