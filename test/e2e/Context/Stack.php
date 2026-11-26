<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\E2e\Context;

use RuntimeException;

/**
 * Where the end-to-end stack is and how to reach it: the settings of `test/e2e` as the suites read them.
 *
 * The stack's names (`auth.clavia.test`, `management.clavia.test`) are called as they are, over HTTPS on
 * port 443, which {@see Browser} connects to wherever Caddy is published (`CLAVIA_E2E_ADDRESS`, default
 * 127.0.0.1, and `CLAVIA_E2E_HTTPS_PORT`; Mailpit's API at `CLAVIA_E2E_MAIL_PORT`), so no `/etc/hosts` entry
 * is needed and a URL in a response is
 * one the suite can follow. `CLAVIA_E2E_CA` and `CLAVIA_E2E_SEED` move the CA and the seed output, which
 * `up.sh` leaves in `test/e2e/.work/`.
 */
final readonly class Stack
{
    public const string DOMAIN = 'clavia.test';

    public function __construct(
        public string $address,
        public int $httpsPort,
        public int $mailPort,
        public string $certificateAuthority,
        public string $seedFile,
    ) {
    }

    public static function fromEnvironment(): self
    {
        $work = dirname(__DIR__) . '/.work';

        return new self(
            self::address(self::setting('CLAVIA_E2E_ADDRESS', '127.0.0.1')),
            self::port(self::setting('CLAVIA_E2E_HTTPS_PORT', '443')),
            self::port(self::setting('CLAVIA_E2E_MAIL_PORT', '8025')),
            self::existing(self::setting('CLAVIA_E2E_CA', $work . '/rootCA.pem')),
            self::existing(self::setting('CLAVIA_E2E_SEED', $work . '/seed.txt')),
        );
    }

    public function authUrl(string $path = ''): string
    {
        return 'https://auth.' . self::DOMAIN . $path;
    }

    public function managementUrl(string $path = ''): string
    {
        return 'https://management.' . self::DOMAIN . $path;
    }

    /** Mailpit's HTTP API, where what the stack mailed is read back. */
    public function mailUrl(string $path = ''): string
    {
        return sprintf('http://%s:%d%s', $this->address, $this->mailPort, $path);
    }

    /** The Management API's identifier, which is also where it is served. */
    public function managementAudience(): string
    {
        return $this->managementUrl('/api/v1/');
    }

    /**
     * The machine client `seed-dev` printed, as `id:secret`: the one holding every management scope.
     *
     * @throws RuntimeException when the stack was not seeded
     */
    public function machineCredentials(): string
    {
        $seed = (string) file_get_contents($this->seedFile);
        if (preg_match("/-u '([^']+)'/", $seed, $match) !== 1) {
            throw new RuntimeException(sprintf('No machine client in %s: run test/e2e/up.sh.', $this->seedFile));
        }

        return self::credentials($match[1]);
    }

    /**
     * A client id and secret as `seed-dev` prints them: made of what a Basic credential is made of.
     *
     * @psalm-taint-escape url_component
     */
    private static function credentials(string $credentials): string
    {
        if (preg_match('/^[A-Za-z0-9._~-]+:[A-Za-z0-9._~-]+$/', $credentials) !== 1) {
            throw new RuntimeException('The machine client in the seed output is not `id:secret`.');
        }

        return $credentials;
    }

    private static function setting(string $name, string $default): string
    {
        $value = getenv($name);

        return is_string($value) && $value !== '' ? $value : $default;
    }

    /**
     * The suite only ever talks to the machine it was told the stack is on: an address, never a name
     * that could lead elsewhere.
     *
     * @psalm-taint-escape ssrf
     * @psalm-taint-escape url_component
     */
    private static function address(string $address): string
    {
        if (filter_var($address, FILTER_VALIDATE_IP) === false && $address !== 'host.docker.internal') {
            throw new RuntimeException(sprintf('CLAVIA_E2E_ADDRESS is %s, not an IP address.', $address));
        }

        return $address;
    }

    /** @psalm-taint-escape ssrf */
    private static function port(string $port): int
    {
        $number = filter_var($port, FILTER_VALIDATE_INT, ['options' => ['min_range' => 1, 'max_range' => 65535]]);
        if ($number === false) {
            throw new RuntimeException(sprintf('%s is not a port.', $port));
        }

        return $number;
    }

    /**
     * @psalm-taint-escape file
     * @psalm-taint-escape ssrf
     * @psalm-taint-escape url_component
     * @psalm-taint-escape url_path
     */
    private static function existing(string $path): string
    {
        $real = realpath($path);
        if ($real === false) {
            throw new RuntimeException(sprintf('%s does not exist: run test/e2e/up.sh.', $path));
        }

        return $real;
    }
}
