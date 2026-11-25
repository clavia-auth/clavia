<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Authentication\External\Saml;

use Clavia\Application\Authentication\External\ExternalSignInFailure;
use Clavia\Application\Authentication\External\ExternalSignInRefused;
use Clavia\Application\Authentication\External\ResolveExternalAccount;
use Clavia\Application\Authentication\LoginThrottle;
use Clavia\Application\Authentication\SignIn\CompleteFirstFactor;
use Clavia\Application\Authentication\SignIn\SecondFactorRequired;
use Clavia\Application\Authentication\SignIn\SignedIn;
use Clavia\Application\Connection\ConnectionAccess;
use Clavia\Application\Connection\Saml\SamlServiceProviderEndpoints;
use Clavia\Application\Port\DomainEvents;
use Clavia\Application\Port\ExternalSignInStore;
use Clavia\Application\Port\LoginStateStore;
use Clavia\Application\Port\Saml\ContentKeyDecrypter;
use Clavia\Application\Port\Saml\ExpectedResponse;
use Clavia\Application\Port\Saml\OaepDigest;
use Clavia\Application\Port\Saml\SamlAssertionReplayCache;
use Clavia\Application\Port\Saml\SamlIdentity;
use Clavia\Application\Port\Saml\SamlResponseStore;
use Clavia\Application\Port\Saml\SamlServiceProvider;
use Clavia\Application\Port\Saml\ServiceProviderKeys;
use Clavia\Domain\Authentication\AuthenticationMethod;
use Clavia\Domain\Authentication\Event\SignInRefused;
use Clavia\Domain\Client\ClientRepository;
use Clavia\Domain\Connection\Connection;
use Clavia\Domain\Connection\ConnectionName;
use Clavia\Domain\Connection\Saml\SamlSettings;
use Clavia\Domain\Identity\AssertedIdentity;
use Clavia\Domain\Identity\User;
use Clavia\Domain\Shared\Clock;
use Clavia\Domain\Shared\InvalidValue;

/**
 * `GET /auth/saml/{connection}/complete` (docs/design/saml-connections.md §5.3, step 5), in order:
 *
 * 1. the parked response claimed, for this connection, or "expired";
 * 2. its `RelayState` equal, in constant time, to the `clavia_external_state` cookie, or "started in
 *    another browser";
 * 3. the pending sign-in claimed, for this connection, or "expired";
 * 4. the application still allows the connection, or "not available";
 * 5. the response consumed by the service provider port, with this connection's certificates, entity
 *    IDs and request id, or "the provider failed", the category logged, never the IdP's words;
 * 6. the assertion id claimed until it expires (plus the skew), or "expired";
 * 7. the account resolved by `(connection, subject)`, an address linking only when the connection
 *    trusts the identity provider for it; then the first factor completes (`amr` `ext`), so a second
 *    factor applies as after any sign-in.
 *
 * Every refusal is one `SignInRefused` and one page. The parked response and the pending sign-in are
 * spent before the response is read, so a failure cannot be tried again with the same handles; the
 * refusals of the response itself (5 and 6) count toward the sign-in throttle, and a throttled address
 * has its parked response spent and nothing read.
 */
final readonly class CompleteSamlSignIn
{
    private const int SKEW_SECONDS = 60;
    private const string EMAIL_NAME_ID = 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress';

    public function __construct(
        private ConnectionAccess $access,
        private ClientRepository $clients,
        private SamlResponseStore $responses,
        private ExternalSignInStore $pending,
        private SamlServiceProvider $saml,
        private SamlServiceProviderEndpoints $endpoints,
        private SamlAssertionReplayCache $assertions,
        private ServiceProviderKeys $keys,
        private LoginThrottle $throttle,
        private ResolveExternalAccount $resolveAccount,
        private LoginStateStore $loginStates,
        private CompleteFirstFactor $completeFirstFactor,
        private Clock $clock,
        private DomainEvents $events,
    ) {
    }

    /** @return SignedIn|SecondFactorRequired|ExternalSignInRefused|null Null when no enabled SAML connection has that name. */
    public function __invoke(SamlCallback $callback): SignedIn|SecondFactorRequired|ExternalSignInRefused|null
    {
        try {
            $connection = $this->access->saml(ConnectionName::fromString($callback->connection));
        } catch (InvalidValue) {
            $connection = null;
        }
        $saml = $connection?->saml;
        if ($connection === null || $saml === null) {
            return null;
        }
        $refuse = function (
            ExternalSignInFailure $reason,
            ?string $category = null,
            bool $counted = false,
        ) use (
            $connection,
            $callback,
        ): ExternalSignInRefused {
            // A failure counts against the address (§7) only once the response is read: that needs a
            // pending sign-in paired with this browser's own cookie, which a forged cross-site POST
            // cannot bring, so nobody locks another person out. It bounds the tries a padding oracle
            // would need, each of which also spends a pending sign-in.
            if ($counted) {
                $this->throttle->recordAddressFailure($callback->clientAddress);
            }
            $this->events->dispatch(new SignInRefused(
                AuthenticationMethod::External,
                $reason->refusal(),
                connection: $connection->name,
            ));

            return new ExternalSignInRefused($reason, $connection->displayName, $category);
        };

        if ($this->throttle->isAddressThrottled($callback->clientAddress)) {
            if ($callback->handle !== null && $callback->handle !== '') {
                $this->responses->claim($callback->handle);
            }

            return $refuse(ExternalSignInFailure::ProviderFailed, 'throttled');
        }
        $parked = $callback->handle === null || $callback->handle === ''
            ? null
            : $this->responses->claim($callback->handle);
        if ($parked === null || ! $parked->connection->equals($connection->name)) {
            return $refuse(ExternalSignInFailure::Expired);
        }
        if ($callback->browserState === null || ! hash_equals($callback->browserState, $parked->relayState)) {
            return $refuse(ExternalSignInFailure::StartedInAnotherBrowser);
        }
        $pending = $this->pending->claim($parked->relayState);
        $requestId = $pending?->samlRequestId;
        if ($pending === null || $requestId === null || ! $pending->provider->equals($connection->name)) {
            return $refuse(ExternalSignInFailure::Expired);
        }
        $client = $pending->clientId === null ? null : $this->clients->find($pending->clientId);
        if (! $this->access->allows($client, $connection->name)) {
            return $refuse(ExternalSignInFailure::NotAvailable);
        }

        $now = $this->clock->now();
        $identity = $this->saml->consume($parked->response, new ExpectedResponse(
            $saml->entityId,
            $saml->certificatePems(),
            $this->endpoints->entityId($connection->name),
            $this->endpoints->assertionConsumerService($connection->name),
            $requestId,
            $now,
            $saml->options->subjectAttribute,
            $this->decrypter(),
            $saml->options->requireEncryption,
            $saml->options->requireGcm,
        ));
        if (! $identity instanceof SamlIdentity) {
            return $refuse(ExternalSignInFailure::ProviderFailed, $identity->reason->value, counted: true);
        }
        $ttl = max(1, $identity->validUntil->getTimestamp() - $now->getTimestamp() + self::SKEW_SECONDS);
        if (! $this->assertions->claimAssertion($connection->name, $identity->assertionId, $ttl)) {
            return $refuse(ExternalSignInFailure::Expired, 'replayed', counted: true);
        }

        try {
            $asserted = self::asserted($connection, $saml, $identity);
        } catch (InvalidValue) {
            return $refuse(ExternalSignInFailure::ProviderFailed, 'subject');
        }
        $account = ($this->resolveAccount)(
            $asserted,
            $this->access->pools($client),
            unverifiedAddress: true,
            requireProvisioning: $connection->requiresProvisioning,
        );
        if (! $account instanceof User) {
            return $refuse($account);
        }
        if ($pending->loginState !== null) {
            $this->loginStates->forget($pending->loginState);
        }

        return ($this->completeFirstFactor)(
            $account->id,
            [AuthenticationMethod::External],
            $connection->name,
            $pending->nextUrl,
            $pending->clientId,
            $callback->currentSessionId,
        );
    }

    /**
     * Who the assertion says signed in, as every external sign-in names a person: `(connection,
     * subject)`, the address from the attribute the operator named or else an address `NameID`, verified
     * only when the operator trusts the identity provider for it (§2, "The address").
     *
     * @throws InvalidValue
     */
    private static function asserted(
        Connection $connection,
        SamlSettings $saml,
        SamlIdentity $identity,
    ): AssertedIdentity {
        $attribute = $saml->options->emailAttribute;
        $email = $attribute === null
            ? ($identity->nameIdFormat === self::EMAIL_NAME_ID ? $identity->nameId : null)
            : ($identity->attributes[$attribute][0] ?? null);

        return AssertedIdentity::of($connection->name, $identity->subject, $email, $saml->options->emailTrusted);
    }

    /**
     * This server's encryption keys, next, current and retired, for the port to unwrap a content key with
     * through {@see ServiceProviderKeys::decryptKey()}; null when there are none.
     */
    private function decrypter(): ?ContentKeyDecrypter
    {
        $keys = [];
        foreach ($this->keys->certificates()->keys as $key) {
            if ($key->decrypts()) {
                $keys[] = ['kid' => $key->kid, 'certificate' => $key->certificate];
            }
        }

        return $keys === [] ? null : new ContentKeyDecrypter(
            $keys,
            fn (string $kid, string $wrapped, OaepDigest $digest): string
                => $this->keys->decryptKey($kid, $wrapped, $digest),
        );
    }
}
