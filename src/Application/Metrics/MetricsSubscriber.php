<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Metrics;

use Clavia\Application\Event\EventSubscriber;
use Clavia\Application\Port\Metrics;
use Clavia\Domain\Authentication\AuthenticationMethod;
use Clavia\Domain\Authentication\Event\SignedIn;
use Clavia\Domain\Authentication\Event\SignInRefused;
use Clavia\Domain\OAuth2\Event\AccessTokenIssued;

/**
 * Counts what the domain says happened (#23): tokens issued by grant, sessions by the methods that
 * established them, sign-ins refused by reason. Never who: the labels are kinds, never an account,
 * a client or an address.
 */
final readonly class MetricsSubscriber implements EventSubscriber
{
    public function __construct(private Metrics $metrics)
    {
    }

    #[\Override]
    public function subscriptions(): array
    {
        return [
            AccessTokenIssued::class => $this->tokenIssued(...),
            SignedIn::class => $this->signedIn(...),
            SignInRefused::class => $this->signInRefused(...),
        ];
    }

    private function tokenIssued(AccessTokenIssued $event): void
    {
        $this->metrics->count(Metric::TokensIssued, ['grant_type' => $event->grant->value]);
    }

    private function signedIn(SignedIn $event): void
    {
        $methods = array_map(static fn (AuthenticationMethod $m): string => $m->value, $event->session->methods);
        sort($methods);
        $this->metrics->count(Metric::SignIns, ['methods' => implode('+', $methods)]);
    }

    private function signInRefused(SignInRefused $event): void
    {
        $this->metrics->count(Metric::SignInRefusals, [
            'reason' => $event->reason->value,
            'method' => $event->method->value ?? 'unknown',
        ]);
    }
}
