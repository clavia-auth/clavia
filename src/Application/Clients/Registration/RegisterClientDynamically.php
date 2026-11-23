<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Clients\Registration;

use Clavia\Application\Audit\AuditContext;
use Clavia\Application\Port\AttemptCounter;
use Clavia\Application\Port\DomainEvents;
use Clavia\Application\Port\PasswordHasher;
use Clavia\Application\Port\TransactionManager;
use Clavia\Domain\Audit\Actor;
use Clavia\Domain\Authentication\MfaPolicy;
use Clavia\Domain\Client\Client;
use Clavia\Domain\Client\ClientId;
use Clavia\Domain\Client\ClientRepository;
use Clavia\Domain\Client\ClientType;
use Clavia\Domain\Client\Event\ClientRegistered;
use Clavia\Domain\Client\Ownership;
use Clavia\Domain\Client\Registration\ClientRegistration;
use Clavia\Domain\Client\Registration\ClientRegistrationRepository;
use Clavia\Domain\Client\Registration\InitialAccessTokenRepository;
use Clavia\Domain\Shared\Clock;
use Clavia\Domain\Shared\Digest;
use Clavia\Domain\Shared\InvalidValue;
use Clavia\Domain\Shared\SecretGenerator;

/**
 * `POST /oauth2/register` (RFC 7591 §3; docs/design/dynamic-client-registration.md §5.1): software
 * holding an operator's initial access token registers itself as a client.
 *
 * The client is **third-party by construction**: its id is generated with
 * {@see Ownership::ThirdParty}, from nothing in the request, so it is refused every system API
 * before anyone signs in and at the token endpoint, asked for consent on every scope, and given no
 * connections of its own. PKCE stays required, and the operator's levers (MFA policy, pushed
 * requests) keep their defaults.
 *
 * In order: the client address is counted (registrations, valid or not); the token is looked up,
 * spending nothing; the metadata is read; then one transaction spends a use — a race for the last
 * one is lost here — registers the client and its registration, and dispatches
 * `ClientRegistered`, with the new client as the actor and the token named.
 */
final readonly class RegisterClientDynamically
{
    /**
     * @param positive-int $limit         Registrations one client address may ask for per window.
     * @param positive-int $windowSeconds
     */
    public function __construct(
        private InitialAccessTokenRepository $initialAccessTokens,
        private ClientRepository $clients,
        private ClientRegistrationRepository $registrations,
        private RegistrationMetadata $metadata,
        private PasswordHasher $hasher,
        private SecretGenerator $secrets,
        private Clock $clock,
        private TransactionManager $transactions,
        private AttemptCounter $counter,
        private AuditContext $audit,
        private DomainEvents $events,
        private int $limit,
        private int $windowSeconds,
    ) {
    }

    /**
     * @param string|null             $initialAccessToken The bearer token the request carried.
     * @param array<array-key, mixed> $members            The request's JSON object.
     *
     * @throws TooManyRegistrations
     * @throws InitialAccessTokenRejected
     * @throws RegistrationRefused
     */
    public function __invoke(
        #[\SensitiveParameter] ?string $initialAccessToken,
        array $members,
        string $clientAddress,
    ): ClientRegisteredItself {
        $subject = 'client-registration-address:' . $clientAddress;
        if ($this->counter->count($subject) >= $this->limit) {
            throw new TooManyRegistrations($this->windowSeconds);
        }
        $this->counter->increment($subject, $this->windowSeconds);

        $now = $this->clock->now();
        $digest = $initialAccessToken === null ? null : Digest::of($initialAccessToken);
        if ($digest === null || $this->initialAccessTokens->findByDigest($digest)?->isUsableAt($now) !== true) {
            throw new InitialAccessTokenRejected();
        }

        $metadata = $this->metadata->read($members);

        return $this->transactions->transactional(
            fn (): ClientRegisteredItself => $this->register($digest, $metadata),
        );
    }

    /**
     * @throws InitialAccessTokenRejected
     * @throws RegistrationRefused
     */
    private function register(Digest $digest, ClientMetadata $metadata): ClientRegisteredItself
    {
        $now = $this->clock->now();
        $spentFrom = $this->initialAccessTokens->spendOne($digest, $now)
            ?? throw new InitialAccessTokenRejected();

        $clientSecret = $metadata->type === ClientType::Confidential ? $this->secrets->token() : null;
        try {
            $client = Client::register(
                ClientId::generate($this->secrets, Ownership::ThirdParty),
                $metadata->name,
                $metadata->type,
                $metadata->authMethod,
                $clientSecret === null ? null : $this->hasher->hash($clientSecret),
                $metadata->redirectUris,
                $metadata->grantTypes,
                $metadata->responseTypes,
                $now,
                $metadata->postLogoutRedirectUris,
                [],
                $metadata->backChannelLogout,
                true,
                MfaPolicy::Optional,
                false,
                $metadata->requireDpop,
            );
        } catch (InvalidValue $contradiction) {
            // The domain's rules, as for an operator's client: they state a rule, never a value.
            throw RegistrationRefused::metadata($contradiction->getMessage());
        }

        $accessToken = $this->secrets->token();
        $registration = new ClientRegistration($client->id, Digest::of($accessToken), $spentFrom, $now);
        $this->clients->save($client);
        $this->registrations->add($registration);
        $this->audit->actAs(Actor::application($client->id));
        $this->events->dispatch(new ClientRegistered($client, $spentFrom));

        return new ClientRegisteredItself($client, $registration, $clientSecret, $accessToken);
    }
}
