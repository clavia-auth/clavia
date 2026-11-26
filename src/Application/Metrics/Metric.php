<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Metrics;

/**
 * What this server measures (#23), exposed in Prometheus's text format at `/metrics` on the internal
 * listener. Each metric's labels are fixed, and each label takes a bounded set of values (a grant
 * type, a refusal, a route's name), never an identifier: the number of series stays small.
 */
enum Metric
{
    case TokensIssued;
    case SignIns;
    case SignInRefusals;
    case OAuthErrors;
    case Mail;
    case RequestDuration;

    public function name(): string
    {
        return match ($this) {
            self::TokensIssued => 'clavia_tokens_issued_total',
            self::SignIns => 'clavia_sign_ins_total',
            self::SignInRefusals => 'clavia_sign_in_refusals_total',
            self::OAuthErrors => 'clavia_oauth_errors_total',
            self::Mail => 'clavia_mail_total',
            self::RequestDuration => 'clavia_http_request_duration_seconds',
        };
    }

    public function help(): string
    {
        return match ($this) {
            self::TokensIssued => 'Access tokens issued, by grant type.',
            self::SignIns => 'Sessions established, by the authentication methods used.',
            self::SignInRefusals => 'Sign-ins refused, by reason and by the factor refused.',
            self::OAuthErrors => 'OAuth error answers, at the authorization endpoint or the endpoints machines call.',
            self::Mail => 'Mail handed to the mail server, by outcome.',
            self::RequestDuration => 'HTTP requests, by route, method and status, and how long they took.',
        };
    }

    public function isHistogram(): bool
    {
        return $this === self::RequestDuration;
    }

    /**
     * The labels each sample carries, in order.
     *
     * @return list<non-empty-string>
     */
    public function labels(): array
    {
        return match ($this) {
            self::TokensIssued => ['grant_type'],
            self::SignIns => ['methods'],
            self::SignInRefusals => ['reason', 'method'],
            self::OAuthErrors => ['endpoint', 'error'],
            self::Mail => ['outcome'],
            self::RequestDuration => ['route', 'method', 'status'],
        };
    }

    /**
     * A histogram's bucket bounds, in seconds: from a cached JWKS (a few milliseconds) to a PBKDF2
     * verification or a call to an identity provider (hundreds).
     *
     * @return list<float>
     */
    public function buckets(): array
    {
        return $this->isHistogram() ? [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0] : [];
    }
}
