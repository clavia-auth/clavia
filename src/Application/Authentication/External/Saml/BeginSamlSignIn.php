<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Authentication\External\Saml;

use Clavia\Application\Authentication\External\ExternalSignInStarted;
use Clavia\Application\Authentication\External\ExternalSignInUnavailable;
use Clavia\Application\Connection\ConnectionAccess;
use Clavia\Application\Connection\Saml\SamlServiceProviderEndpoints;
use Clavia\Application\Port\ExternalSignInStore;
use Clavia\Application\Port\LoginStateStore;
use Clavia\Application\Port\Saml\AuthnRequestDetails;
use Clavia\Application\Port\Saml\SamlServiceProvider;
use Clavia\Domain\Authentication\LocalPath;
use Clavia\Domain\Authentication\PendingExternalSignIn;
use Clavia\Domain\Client\ClientRepository;
use Clavia\Domain\Connection\ConnectionName;
use Clavia\Domain\Connection\Saml\SamlRequestId;
use Clavia\Domain\OAuth2\CodeVerifier;
use Clavia\Domain\Oidc\Nonce;
use Clavia\Domain\Shared\Clock;
use Clavia\Domain\Shared\InvalidValue;
use Clavia\Domain\Shared\RandomSource;
use Clavia\Domain\Shared\SecretGenerator;
use Clavia\Domain\Shared\Url;

/**
 * `GET /auth/saml/{connection}` (docs/design/saml-connections.md §5.3, step 2): open the pending sign-in
 * (an opaque handle, the request id, ten minutes), and send the browser to the identity provider with a
 * deflated `AuthnRequest` and the handle as `RelayState`, which the `clavia_external_state` cookie
 * pairs with the browser. Only this server starts a SAML sign-in: a response must answer this request.
 */
final readonly class BeginSamlSignIn
{
    public function __construct(
        private ConnectionAccess $access,
        private ClientRepository $clients,
        private ExternalSignInStore $pending,
        private LoginStateStore $loginStates,
        private SamlServiceProvider $saml,
        private SamlServiceProviderEndpoints $endpoints,
        private SecretGenerator $secrets,
        private RandomSource $random,
        private Clock $clock,
    ) {
    }

    /** @return ExternalSignInStarted|ExternalSignInUnavailable|null Null without an enabled SAML connection of that name. */
    public function __invoke(
        string $connection,
        #[\SensitiveParameter] ?string $loginState,
    ): ExternalSignInStarted|ExternalSignInUnavailable|null {
        try {
            $found = $this->access->saml(ConnectionName::fromString($connection));
        } catch (InvalidValue) {
            $found = null;
        }
        $saml = $found?->saml;
        if ($found === null || $saml === null) {
            return null;
        }

        $loginState = $loginState === '' ? null : $loginState;
        $target = $loginState === null ? null : $this->loginStates->get($loginState);
        $clientId = $target?->clientId;
        $client = $clientId === null ? null : $this->clients->find($clientId);
        if (! $this->access->allows($client, $found->name)) {
            return new ExternalSignInUnavailable($found->displayName);
        }

        $requestId = SamlRequestId::generate($this->random);
        $handle = $this->secrets->token();
        $this->pending->open($handle, new PendingExternalSignIn(
            $found->name,
            CodeVerifier::generate($this->random),
            LocalPath::orDefault($target?->nextUrl)->value,
            $target?->clientId,
            $loginState,
            Nonce::fromString($this->secrets->token()),
            $requestId,
        ));

        return new ExternalSignInStarted(
            $this->saml->authnRequestUrl(new AuthnRequestDetails(
                $saml->singleSignOnUrl,
                $this->endpoints->entityId($found->name),
                Url::fromString($this->endpoints->assertionConsumerService($found->name)),
                $requestId,
                $handle,
                $this->clock->now(),
                $saml->options->nameIdFormat,
            )),
            $handle,
        );
    }
}
