<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Clients;

use Clavia\Application\Port\PasswordHasher;
use Clavia\Application\Port\SecretNotHashable;
use Clavia\Domain\Client\Client;
use Clavia\Domain\Client\ClientAuthMethod;
use Clavia\Domain\Client\ClientId;
use Clavia\Domain\Client\ClientRepository;
use Clavia\Domain\Client\ClientType;
use Clavia\Domain\Client\GrantType;
use Clavia\Domain\Shared\Clock;
use Clavia\Domain\Shared\InvalidValue;
use Clavia\Domain\Shared\SecretGenerator;

/**
 * Register a machine-to-machine client: `clavia clients:create-m2m`.
 *
 * Confidential, for the Client Credentials grant only, authenticating with HTTP Basic —
 * the method RFC 6749 §2.3.1 requires every server to support, so every client library
 * has it. Registered with no redirect URI and no response type: it never reaches the
 * authorization endpoint, and an attempt to run an interactive flow with it fails at
 * the first check instead of half-working.
 *
 * It holds nothing until a client grant binds it to an API. Every call registers a new
 * client; the id is generated, so there is nothing to recognise a rerun by.
 */
final readonly class RegisterMachineClient
{
    /** The length a chosen secret must at least have: a generated one has 43 characters. */
    public const int MIN_SECRET_LENGTH = 32;

    public function __construct(
        private ClientRepository $clients,
        private PasswordHasher $hasher,
        private SecretGenerator $secrets,
        private Clock $clock,
    ) {
    }

    /**
     * @param string|null $secret A secret to use instead of a generated one. Generating is better.
     *
     * @throws InvalidValue When the name is too long, or a chosen secret is shorter than 32
     *                      characters or cannot be hashed faithfully.
     */
    public function __invoke(string $name, #[\SensitiveParameter] ?string $secret = null): RegisteredMachineClient
    {
        $generated = $secret === null;
        $secret ??= $this->secrets->token();

        if (strlen($secret) < self::MIN_SECRET_LENGTH) {
            throw new InvalidValue(sprintf('A client secret has at least %d characters.', self::MIN_SECRET_LENGTH));
        }

        try {
            $hash = $this->hasher->hash($secret);
        } catch (SecretNotHashable) {
            throw new InvalidValue('A client secret is at most 72 bytes, with no NUL byte.');
        }

        $client = Client::register(
            ClientId::generate($this->secrets),
            $name,
            ClientType::Confidential,
            ClientAuthMethod::ClientSecretBasic,
            $hash,
            [],
            [GrantType::ClientCredentials],
            [],
            $this->clock->now(),
        );
        $this->clients->save($client);

        return new RegisteredMachineClient($client, $secret, $generated);
    }
}
