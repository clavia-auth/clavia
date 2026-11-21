<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Development;

use Clavia\Application\Port\PasswordHasher;
use Clavia\Application\Port\SigningKeyStore;
use Clavia\Application\Port\TransactionManager;
use Clavia\Domain\Client\Client;
use Clavia\Domain\Client\ClientAuthMethod;
use Clavia\Domain\Client\ClientId;
use Clavia\Domain\Client\ClientRepository;
use Clavia\Domain\Client\ClientType;
use Clavia\Domain\Client\GrantType;
use Clavia\Domain\Client\Ownership;
use Clavia\Domain\Client\ResponseType;
use Clavia\Domain\Connection\ConnectionName;
use Clavia\Domain\Identity\User;
use Clavia\Domain\Identity\UserId;
use Clavia\Domain\Identity\UserRepository;
use Clavia\Domain\Oidc\SigningAlgorithm;
use Clavia\Domain\Shared\Clock;
use Clavia\Domain\Shared\InvalidValue;
use Clavia\Domain\Shared\RandomSource;
use Clavia\Domain\Shared\SecretGenerator;
use Clavia\Domain\Shared\Url;
use LogicException;

/**
 * Seeds a development user and a public PKCE client, so a fresh checkout has something
 * to sign in as and something to sign in to.
 *
 * Idempotent by *name* rather than by client id: ids are generated, so a rerun has
 * nothing fixed to look one up by, and registering the same logical client under a
 * fresh id every time would defeat the point of seeding.
 *
 * The password is a fixed default rather than a generated one so the command can print
 * working credentials on a rerun, which it could not do if the secret only existed as a
 * hash — exactly the trade-off that makes this development-only.
 */
final readonly class SeedDevelopmentData
{
    /** The client this seeds, looked up by name on a rerun. */
    public const string CLIENT_NAME = 'Clavia development client';

    public function __construct(
        private UserRepository $users,
        private ClientRepository $clients,
        private PasswordHasher $hasher,
        private TransactionManager $transactions,
        /** Null when the signing backend keeps its keys at a provider. */
        private ?SigningKeyStore $signingKeys,
        private SigningAlgorithm $signingAlgorithm,
        private SecretGenerator $secrets,
        private RandomSource $random,
        private Clock $clock,
        private bool $isDevelopment,
    ) {
    }

    /**
     * @throws LogicException When this is not a development deployment.
     * @throws InvalidValue   When the email or the redirect URI is malformed.
     */
    public function __invoke(
        string $email,
        #[\SensitiveParameter] string $password,
        string $redirectUri,
    ): SeededDevelopmentData {
        if (! $this->isDevelopment) {
            throw new LogicException('Refusing to seed development data outside a development deployment.');
        }

        $redirect = Url::fromString($redirectUri);

        return $this->transactions->transactional(
            fn (): SeededDevelopmentData => $this->seed($email, $password, $redirect),
        );
    }

    /**
     * Create whatever is missing. Runs inside the transaction, so a user is never left
     * without the client that was meant to come with it.
     */
    private function seed(
        string $email,
        #[\SensitiveParameter] string $password,
        Url $redirect,
    ): SeededDevelopmentData {
        $now = $this->clock->now();

        $user = $this->users->findByEmail(ConnectionName::defaultPool(), $email);
        $userCreated = $user === null;
        if ($user === null) {
            $this->users->save(User::register(
                UserId::generate($this->random),
                $email,
                $this->hasher->hash($password),
                $now,
            ));
        }

        $client = $this->clients->findByName(self::CLIENT_NAME);
        $clientCreated = $client === null;
        if ($client === null) {
            // A public client: no secret, PKCE is its only proof of possession.
            $client = Client::register(
                ClientId::generate($this->secrets, Ownership::FirstParty),
                self::CLIENT_NAME,
                ClientType::Public,
                ClientAuthMethod::None,
                null,
                [$redirect],
                [GrantType::AuthorizationCode],
                [ResponseType::Code],
                $now,
                [],
                // The development user's pool; other connections are enabled through the API.
                [ConnectionName::defaultPool()],
            );
            $this->clients->save($client);
        }

        // A token endpoint without a key fails loudly by design; a development setup
        // should not have to learn that the hard way. A remote backend's key is the
        // provider's to create.
        $signingKey = $this->signingKeys?->lockActive();
        $signingKeyCreated = $this->signingKeys !== null && $signingKey === null;
        if ($this->signingKeys !== null && $signingKey === null) {
            $signingKey = $this->signingKeys->create($this->signingAlgorithm, $now);
        }

        return new SeededDevelopmentData(
            $email,
            $userCreated,
            $client->id,
            $clientCreated,
            $signingKey?->kid(),
            $signingKeyCreated,
        );
    }
}
