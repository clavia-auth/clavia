<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Configuration;

use BackedEnum;
use JsonException;
use ReflectionClass;
use ReflectionNamedType;
use ReflectionParameter;
use Uri\Rfc3986\Uri;

/**
 * Turns raw `CLAVIA_*` variables into a checked {@see Settings}.
 *
 * Three passes: coerce each variable to its parameter's type and bounds, derive the
 * values that follow from others (issuer, database and Redis URLs), then refuse the
 * combinations that would be a security regression.
 *
 * @internal Reached through {@see Settings::fromEnvironment()}.
 */
final class SettingsBuilder
{
    /** A DNS name: labels of letters, digits and hyphens joined by dots. No scheme, port or path. */
    private const string DOMAIN_PATTERN = '/^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{1,63}$/D';

    private const array TRUE_WORDS = ['1', 'true', 't', 'yes', 'y', 'on'];
    private const array FALSE_WORDS = ['0', 'false', 'f', 'no', 'n', 'off'];

    private const array LOOPBACK_HOSTS = ['localhost', '127.0.0.1', '[::1]'];

    /**
     * @param array<string, string> $variables
     *
     * @throws InvalidSettings
     */
    public function build(array $variables): Settings
    {
        $arguments = [];
        $constructor = new ReflectionClass(Settings::class)->getConstructor();
        assert($constructor !== null);

        foreach ($constructor->getParameters() as $parameter) {
            $variable = Settings::variableName($parameter->getName());
            $raw = trim($variables[$variable] ?? '');

            if ($raw === '') {
                if (! $parameter->isDefaultValueAvailable()) {
                    throw new InvalidSettings(sprintf('%s is required.', $variable));
                }

                continue;
            }

            /** @psalm-suppress MixedAssignment The value is typed by the parameter it is coerced for. */
            $arguments[$parameter->getName()] = $this->coerce($parameter, $variable, $raw);
        }

        /** @psalm-suppress MixedArgument Each argument was coerced to its parameter's declared type. */
        $settings = new Settings(...$arguments);
        $settings = $this->derive($settings);
        $this->refuseUnsafeCombinations($settings);

        return $settings;
    }

    /**
     * @throws InvalidSettings
     */
    private function coerce(ReflectionParameter $parameter, string $variable, string $raw): mixed
    {
        $type = $parameter->getType();
        assert($type instanceof ReflectionNamedType);
        $name = $type->getName();

        return match (true) {
            $name === 'string' => $raw,
            $name === 'int' => $this->integer($parameter, $variable, $raw),
            $name === 'bool' => $this->boolean($variable, $raw),
            $name === 'array' => $this->stringList($variable, $raw),
            is_subclass_of($name, BackedEnum::class) => $this->enumeration($name, $variable, $raw),
            default => throw new InvalidSettings(sprintf('%s has an unsupported type %s.', $variable, $name)),
        };
    }

    /**
     * @throws InvalidSettings
     */
    private function integer(ReflectionParameter $parameter, string $variable, string $raw): int
    {
        $value = filter_var($raw, FILTER_VALIDATE_INT);
        if ($value === false) {
            throw new InvalidSettings(sprintf('%s must be an integer, got %s.', $variable, $this->quote($raw)));
        }

        foreach ($parameter->getAttributes(Range::class) as $attribute) {
            $range = $attribute->newInstance();
            if ($range->min !== null && $value < $range->min) {
                throw new InvalidSettings(sprintf('%s must be at least %d, got %d.', $variable, $range->min, $value));
            }
            if ($range->max !== null && $value > $range->max) {
                throw new InvalidSettings(sprintf('%s must be at most %d, got %d.', $variable, $range->max, $value));
            }
        }

        return $value;
    }

    /**
     * @throws InvalidSettings
     */
    private function boolean(string $variable, string $raw): bool
    {
        $word = strtolower($raw);

        return match (true) {
            in_array($word, self::TRUE_WORDS, true) => true,
            in_array($word, self::FALSE_WORDS, true) => false,
            default => throw new InvalidSettings(
                sprintf('%s must be true or false, got %s.', $variable, $this->quote($raw)),
            ),
        };
    }

    /**
     * A JSON array of strings, or a comma- or space-separated list.
     *
     * @return list<string>
     *
     * @throws InvalidSettings
     */
    private function stringList(string $variable, string $raw): array
    {
        if (! str_starts_with($raw, '[')) {
            $items = preg_split('/[\s,]+/', $raw, flags: PREG_SPLIT_NO_EMPTY);

            return $items === false ? [] : $items;
        }

        try {
            /** @var mixed $decoded */
            $decoded = json_decode($raw, flags: JSON_THROW_ON_ERROR);
        } catch (JsonException) {
            $decoded = null;
        }

        $isStringList = is_array($decoded)
            && array_is_list($decoded)
            && array_all($decoded, static fn (mixed $item): bool => is_string($item));

        if (! $isStringList) {
            throw new InvalidSettings(sprintf('%s must be a list of strings, got %s.', $variable, $this->quote($raw)));
        }

        /** @var list<string> $decoded */
        return $decoded;
    }

    /**
     * @param class-string<BackedEnum> $enum
     *
     * @throws InvalidSettings
     */
    private function enumeration(string $enum, string $variable, string $raw): BackedEnum
    {
        $case = $enum::tryFrom(strtolower($raw));
        if ($case === null) {
            throw new InvalidSettings(sprintf(
                '%s must be one of %s, got %s.',
                $variable,
                implode(', ', array_map(static fn (BackedEnum $case): string => (string) $case->value, $enum::cases())),
                $this->quote($raw),
            ));
        }

        return $case;
    }

    /**
     * @throws InvalidSettings
     */
    private function derive(Settings $settings): Settings
    {
        $rootDomain = $this->rootDomain($settings->rootDomain);
        $issuer = $this->issuer($settings, $rootDomain);

        return $settings->with([
            'rootDomain' => $rootDomain,
            'issuerUrl' => $issuer,
            // A plaintext issuer is only ever loopback in development (see issuer()); passkeys need
            // https, so they are off there, and warnings() says why.
            'passkeysEnabled' => $settings->passkeysEnabled && parse_url($issuer, PHP_URL_SCHEME) === 'https',
            'webauthnRpId' => $this->relyingPartyId($settings, $issuer, $rootDomain),
            'webauthnRpName' => trim($settings->webauthnRpName) !== '' ? trim($settings->webauthnRpName) : $rootDomain,
            'trustedProxies' => $this->trustedProxies($settings->trustedProxies),
            'databaseUrl' => $settings->databaseUrl !== '' ? $settings->databaseUrl : sprintf(
                'postgresql://%s:%s@%s:%d/%s',
                rawurlencode($settings->postgresUser),
                rawurlencode($settings->postgresPassword),
                $settings->postgresHost,
                $settings->postgresPort,
                rawurlencode($settings->postgresDb),
            ),
            'redisUrl' => $settings->redisUrl !== '' ? $settings->redisUrl : sprintf(
                'redis://%s:%d/%d',
                $settings->redisHost,
                $settings->redisPort,
                $settings->redisDb,
            ),
        ]);
    }

    /**
     * Lower-case, and refuse anything that is not a bare DNS name.
     *
     * A scheme, a port or a path here would be duplicated into every derived host and
     * produce URLs like `https://auth.https://acme.com`. Better to fail at startup with
     * the offending value than to issue tokens with that `iss`.
     *
     * @throws InvalidSettings
     */
    private function rootDomain(string $value): string
    {
        $candidate = rtrim(strtolower(trim($value)), '.');
        if (preg_match(self::DOMAIN_PATTERN, $candidate) !== 1) {
            throw new InvalidSettings(sprintf(
                "CLAVIA_ROOT_DOMAIN must be a bare domain such as 'acme.com', got %s.",
                $this->quote($value),
            ));
        }

        return $candidate;
    }

    /**
     * Fill in the issuer from the domain, then normalise and check it.
     *
     * OpenID Connect Discovery 1.0 §3 requires an `https` URL with no query or
     * fragment. Those are not stylistic rules: the value is compared verbatim against
     * the `iss` claim, so a stray trailing slash or query string makes every token fail
     * verification at the relying party, with an error that points nowhere near the
     * cause. Loopback is exempt from `https` in development.
     *
     * @throws InvalidSettings
     */
    private function issuer(Settings $settings, string $rootDomain): string
    {
        $candidate = $settings->issuerUrl !== '' ? $settings->issuerUrl : 'https://auth.' . $rootDomain;
        $candidate = rtrim(trim($candidate), '/');
        $uri = Uri::parse($candidate);

        if ($uri === null || $uri->getScheme() === null || ($uri->getHost() ?? '') === '') {
            throw new InvalidSettings(
                sprintf('CLAVIA_ISSUER_URL must be an absolute URL, got %s.', $this->quote($candidate)),
            );
        }
        if ($uri->getQuery() !== null || $uri->getFragment() !== null) {
            throw new InvalidSettings(
                'CLAVIA_ISSUER_URL must have no query or fragment component (OpenID Connect Discovery 1.0 §3).',
            );
        }
        if ($uri->getScheme() !== 'https') {
            $loopback = in_array($uri->getHost(), self::LOOPBACK_HOSTS, true);
            if (! ($settings->isDevelopment() && $loopback)) {
                throw new InvalidSettings(sprintf(
                    'CLAVIA_ISSUER_URL is %s. The issuer must use https outside development; plaintext is only '
                    . 'permitted on loopback.',
                    $this->quote($candidate),
                ));
            }
        }

        return $candidate;
    }

    /**
     * The WebAuthn relying party id, derived as the sign-in host and checked against it.
     *
     * WebAuthn Level 3 §5.1.3 lets a page use its own host or a registrable domain suffix of it. A
     * suffix outside CLAVIA_ROOT_DOMAIN could be a public suffix (`com`) or someone else's domain,
     * so the id must be the sign-in host or a parent of it within the root domain. With passkeys off
     * the id is not checked: nothing uses it.
     *
     * @throws InvalidSettings
     */
    private function relyingPartyId(Settings $settings, string $issuer, string $rootDomain): string
    {
        $host = strtolower((string) parse_url($issuer, PHP_URL_HOST));
        $candidate = rtrim(strtolower(trim($settings->webauthnRpId)), '.');
        $candidate = $candidate === '' ? $host : $candidate;
        if (! $settings->passkeysEnabled || parse_url($issuer, PHP_URL_SCHEME) !== 'https') {
            return $candidate;
        }
        $withinHost = $candidate === $host || str_ends_with($host, '.' . $candidate);
        $withinRoot = $candidate === $rootDomain || str_ends_with($candidate, '.' . $rootDomain);
        if (preg_match(self::DOMAIN_PATTERN, $candidate) !== 1 || ! $withinHost || ! $withinRoot) {
            throw new InvalidSettings(sprintf(
                'CLAVIA_WEBAUTHN_RP_ID must be the sign-in host %s or a parent of it within %s, got %s.',
                $this->quote($host),
                $this->quote($rootDomain),
                $this->quote($candidate),
            ));
        }

        return $candidate;
    }

    /**
     * @param list<string> $proxies
     *
     * @return list<non-empty-string>
     *
     * @throws InvalidSettings
     */
    private function trustedProxies(array $proxies): array
    {
        $checked = [];

        foreach ($proxies as $proxy) {
            if ($proxy === '') {
                continue;
            }
            if ($proxy === '*') {
                return ['*'];
            }

            [$address, $prefix] = explode('/', $proxy, 2) + [1 => null];
            $isIpv6 = filter_var($address, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false;
            $validAddress = $isIpv6 || filter_var($address, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false;
            $validPrefix = $prefix === null
                || (ctype_digit($prefix) && (int) $prefix <= ($isIpv6 ? 128 : 32));

            if (! $validAddress || ! $validPrefix) {
                throw new InvalidSettings(sprintf(
                    "CLAVIA_TRUSTED_PROXIES entries must be IP addresses, CIDR ranges or '*', got %s.",
                    $this->quote($proxy),
                ));
            }

            $checked[] = $proxy;
        }

        return $checked;
    }

    /**
     * Refuse an unusable signing or mail configuration and every development-only weakening
     * in a real environment.
     *
     * A server that boots and then cannot sign — or send the mail it promises — is worse than
     * one that refuses to boot. `devAutologinEmail` bypasses authentication entirely; a
     * session cookie without `Secure` travels over plaintext; the console mail backend writes
     * sign-in codes to the log; private outbound addresses disable the SSRF guard. All are
     * hard failures rather than warnings.
     *
     * @throws InvalidSettings
     */
    private function refuseUnsafeCombinations(Settings $settings): void
    {
        $env = $this->quote($settings->env->value);

        if ($settings->signingBackend !== 'postgres' && $settings->signingKeyRef === null) {
            throw new InvalidSettings(sprintf(
                "CLAVIA_SIGNING_BACKEND=%s requires CLAVIA_SIGNING_KEY_REF naming the provider's key.",
                $this->quote($settings->signingBackend),
            ));
        }

        if ($settings->signingRetiredKeyRefs !== []) {
            if ($settings->signingBackend === 'postgres') {
                throw new InvalidSettings(
                    'CLAVIA_SIGNING_RETIRED_KEY_REFS is for a remote signing backend; the postgres backend '
                    . 'retires its own keys (`clavia keys:rotate`).',
                );
            }
            $references = $settings->signingRetiredKeyRefs;
            $repeated = count(array_unique($references)) !== count($references);
            if ($repeated || in_array($settings->signingKeyRef, $references, true)) {
                throw new InvalidSettings(
                    'CLAVIA_SIGNING_RETIRED_KEY_REFS names each retired key once, and never the active one.',
                );
            }
        }

        if ($settings->azureClientSecret !== null || $settings->azureFederatedTokenFile !== null) {
            if ($settings->azureClientSecret !== null && $settings->azureFederatedTokenFile !== null) {
                throw new InvalidSettings(
                    'Set CLAVIA_AZURE_CLIENT_SECRET or CLAVIA_AZURE_FEDERATED_TOKEN_FILE, not both: they are '
                    . 'two ways of proving the same application.',
                );
            }
            if ($settings->azureTenantId === null || $settings->azureClientId === null) {
                throw new InvalidSettings(
                    'Signing in to Azure as an application needs CLAVIA_AZURE_TENANT_ID and CLAVIA_AZURE_CLIENT_ID.',
                );
            }
            // A file in the pod, where AKS projects it: never a URL, which file_get_contents() would fetch.
            $file = $settings->azureFederatedTokenFile;
            if ($file !== null && ! LocalFilePath::isAbsolute($file)) {
                throw new InvalidSettings(
                    'CLAVIA_AZURE_FEDERATED_TOKEN_FILE is an absolute path to a local file, never a URL.',
                );
            }
        }

        if ($settings->emailBackend === EmailBackend::Smtp && ($settings->smtpHost ?? '') === '') {
            throw new InvalidSettings('CLAVIA_EMAIL_BACKEND=smtp requires CLAVIA_SMTP_HOST naming the mail server.');
        }

        if ($settings->isDevelopment()) {
            return;
        }

        if ($settings->awsKmsEndpointUrl !== null) {
            throw new InvalidSettings(
                'CLAVIA_AWS_KMS_ENDPOINT_URL redirects signing away from AWS and is only permitted when '
                . sprintf('CLAVIA_ENV=development (currently %s).', $env),
            );
        }
        if ($settings->devAutologinEmail !== null) {
            throw new InvalidSettings(
                sprintf('CLAVIA_DEV_AUTOLOGIN_EMAIL is set but CLAVIA_ENV is %s. ', $env)
                . 'This setting bypasses authentication and is only permitted when CLAVIA_ENV=development.',
            );
        }
        if (! $settings->sessionCookieSecure) {
            throw new InvalidSettings(
                sprintf('CLAVIA_SESSION_COOKIE_SECURE is false but CLAVIA_ENV is %s. ', $env)
                . 'Serving session cookies without the Secure flag exposes them to interception; it is only '
                . 'permitted when CLAVIA_ENV=development.',
            );
        }
        if ($settings->emailBackend === EmailBackend::Console) {
            throw new InvalidSettings(
                sprintf("CLAVIA_EMAIL_BACKEND is 'console' but CLAVIA_ENV is %s. ", $env)
                . "The console backend writes sign-in codes and links to the log; use 'smtp', or 'none' to "
                . 'disable passwordless sign-in.',
            );
        }
        if ($settings->outboundAllowPrivateAddresses) {
            throw new InvalidSettings(
                sprintf('CLAVIA_OUTBOUND_ALLOW_PRIVATE_ADDRESSES is true but CLAVIA_ENV is %s. ', $env)
                . 'It disables the guard that keeps operator-supplied URLs from steering this server at its own '
                . 'network, and is only permitted when CLAVIA_ENV=development.',
            );
        }
    }

    private function quote(string $value): string
    {
        return "'" . $value . "'";
    }
}
