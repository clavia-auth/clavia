<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Primary\Http\Management;

use Clavia\Adapter\Primary\Http\Shared\ClientAddress;
use Clavia\Application\Management\Users\PasswordLinkRefused;
use Clavia\Application\Management\Users\SendPasswordLink;
use Clavia\Domain\Identity\UserId;
use Fig\Http\Message\StatusCodeInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * `POST /api/v1/users/{user_id}/password-reset` (`sendUserPasswordLink`): mail the user a
 * link to choose a password.
 *
 * `202` says the mail left and the link is open, and which of the two mails it was. A limit
 * reached is `429` and a mail server that did not take the message, or none configured, is
 * `503`: the caller is authenticated, so unlike the public form it is told.
 */
final readonly class UserPasswordLinkHandler implements RequestHandlerInterface
{
    public function __construct(
        private SendPasswordLink $send,
        private ManagementResponder $responder,
    ) {
    }

    #[\Override]
    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        $outcome = ($this->send)(
            UserId::fromString(ManagementRequest::of($request)->path('user_id')),
            ClientAddress::of($request),
        );

        return match ($outcome) {
            PasswordLinkRefused::LimitReached => $this->responder->problem(
                new Problem(
                    StatusCodeInterface::STATUS_TOO_MANY_REQUESTS,
                    'Too many emails have been sent to this address or from this one. Try again later.',
                ),
            ),
            PasswordLinkRefused::MailUnavailable => $this->responder->problem(
                new Problem(
                    StatusCodeInterface::STATUS_SERVICE_UNAVAILABLE,
                    'The email could not be sent. Try again later.',
                ),
            ),
            default => $this->responder->json(
                ['kind' => $outcome->invitation ? 'invitation' : 'reset'],
                StatusCodeInterface::STATUS_ACCEPTED,
            ),
        };
    }
}
