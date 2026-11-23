<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Secondary\BreachedPasswords;

use Clavia\Adapter\Secondary\Http\OutboundUrlPolicy;
use Clavia\Adapter\Secondary\Http\OutboundUrlRefused;
use Clavia\Application\Port\BreachCheckUnavailable;
use Clavia\Application\Port\BreachedPasswords;
use Psr\Http\Client\ClientExceptionInterface;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Log\LoggerInterface;

/**
 * {@see BreachedPasswords} on Have I Been Pwned's Pwned Passwords range API, by
 * k-anonymity: only the first five hexadecimal characters of the password's SHA-1 leave
 * the server (`GET /range/{prefix}`); the service answers every suffix it knows under that
 * prefix, with a count, and the match is made here.
 *
 * `Add-Padding: true` asks for a padded answer (suffixes with a count of 0, which are
 * not breaches), so the size of the response says nothing about the prefix to an
 * observer of the connection.
 *
 * The URL goes through the {@see OutboundUrlPolicy} like every other this server fetches,
 * here and again at connection time by the shared client. Failures are logged by endpoint
 * and reason, never with the prefix, and reported as {@see BreachCheckUnavailable}.
 */
final readonly class PwnedPasswordsRange implements BreachedPasswords
{
    public const string ENDPOINT = 'https://api.pwnedpasswords.com/range/';

    public function __construct(
        private ClientInterface $http,
        private RequestFactoryInterface $requests,
        private OutboundUrlPolicy $policy,
        private LoggerInterface $logger,
    ) {
    }

    #[\Override]
    public function isBreached(#[\SensitiveParameter] string $password): bool
    {
        $hash = self::hashOf($password);
        $prefix = substr($hash, 0, 5);
        $suffix = substr($hash, 5);
        $url = self::ENDPOINT . $prefix;

        try {
            $this->policy->check($url, 'breached-password service');
        } catch (OutboundUrlRefused $refused) {
            throw $this->unavailable($refused->getMessage());
        }

        $request = $this->requests->createRequest('GET', $url)
            ->withHeader('Add-Padding', 'true')
            ->withHeader('User-Agent', 'Clavia');

        try {
            $response = $this->http->sendRequest($request);
        } catch (ClientExceptionInterface $failure) {
            throw $this->unavailable(sprintf('it could not be reached (%s)', $failure::class));
        }
        if ($response->getStatusCode() !== 200) {
            throw $this->unavailable(sprintf('it answered %d', $response->getStatusCode()));
        }

        // One `SUFFIX:COUNT` per line, CRLF-separated; a padding entry has a count of 0.
        foreach (preg_split('/\r?\n/', (string) $response->getBody()) ?: [] as $line) {
            if (preg_match('/^([0-9A-F]{35}):(\d+)$/D', trim($line), $entry) !== 1) {
                continue;
            }
            if (hash_equals($entry[1], $suffix)) {
                return (int) $entry[2] > 0;
            }
        }

        return false;
    }

    /**
     * The key the corpus is indexed by: the password's SHA-1, in upper-case hexadecimal.
     *
     * @psalm-suppress WeakHash SHA-1 is the service's index, not a way of storing passwords:
     *                          passwords are bcrypt hashes, and only five characters of this leave.
     */
    public static function hashOf(#[\SensitiveParameter] string $password): string
    {
        return strtoupper(sha1($password));
    }

    private function unavailable(string $reason): BreachCheckUnavailable
    {
        $this->logger->warning('Breached-password check at {endpoint} failed, password let through: {reason}', [
            'endpoint' => self::ENDPOINT,
            'reason' => $reason,
        ]);

        return new BreachCheckUnavailable('The breached-password service is unavailable.');
    }
}
