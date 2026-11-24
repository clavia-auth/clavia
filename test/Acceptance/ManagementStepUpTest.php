<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Acceptance;

use Clavia\Application\Management\Provisioning\AssignRole;
use Clavia\Application\Management\Provisioning\EnsureRole;
use Clavia\Domain\Authentication\AuthenticationContext;
use Clavia\Domain\Authentication\AuthenticationMethod as M;
use Clavia\Domain\Authentication\MfaPolicy;
use Clavia\Domain\Client\ClientId;
use Clavia\Domain\OAuth2\AccessToken;
use Clavia\Domain\OAuth2\AccessTokenId;
use Clavia\Domain\OAuth2\AccessTokenRepository;
use Clavia\Domain\ResourceServer\ResourceServerRepository;
use Clavia\Domain\Shared\Audience;
use Clavia\Domain\Shared\Digest;
use Clavia\Domain\Shared\ScopeSet;
use ClaviaTest\Support\AcceptanceTestCase;
use ClaviaTest\Support\Fake\SeededRandomSource;
use ClaviaTest\Support\MachineFixtures;
use ClaviaTest\Support\ManagementFixtures;
use ClaviaTest\Support\OAuth2Fixtures;
use DateTimeImmutable;
use Fig\Http\Message\StatusCodeInterface;

/**
 * The Management API asking for step-up (RFC 9470; docs/design/mfa-policies.md, slice 4): when
 * its own MFA policy is `required`, a token from a one-factor sign-in is answered `401` with
 * `insufficient_user_authentication` and the `acr_values` to ask for, after the audience and
 * before the scope. A machine token is not concerned.
 */
final class ManagementStepUpTest extends AcceptanceTestCase
{
    use OAuth2Fixtures;
    use MachineFixtures;
    use ManagementFixtures;

    private const string MFA = 'http://schemas.openid.net/pape/policies/2007/06/multi-factor';

    public function testAOneFactorAdministratorIsAskedToStepUp(): void
    {
        $this->requireMfa();

        $response = $this->api('GET', '/api/v1/users', token: $this->personToken([M::Password]));

        self::assertSame(StatusCodeInterface::STATUS_UNAUTHORIZED, $response->getStatusCode());
        self::assertSame(
            'Bearer realm="https://management.clavia.test/api/v1/", error="insufficient_user_authentication", '
            . 'error_description="The Management API requires a stronger sign-in.", acr_values="' . self::MFA . '"',
            $response->getHeaderLine('WWW-Authenticate'),
        );
        self::assertSame('insufficient_user_authentication', self::json($response)['error']);
    }

    public function testATwoFactorAdministratorPasses(): void
    {
        $this->requireMfa();

        $token = $this->personToken([M::Password, M::OneTimePassword, M::MultipleFactors]);

        self::assertSame(
            StatusCodeInterface::STATUS_OK,
            $this->api('GET', '/api/v1/users', token: $token)->getStatusCode(),
        );
    }

    public function testTheSignInIsCheckedBeforeTheScope(): void
    {
        // RFC 9470 §3: asking for a stronger sign-in first spares the client a useless new scope.
        $this->requireMfa();

        $response = $this->api('GET', '/api/v1/users', token: $this->personToken([M::Password], 'read:roles'));

        self::assertSame('insufficient_user_authentication', self::json($response)['error']);
    }

    public function testAMachineTokenHasNobodyToStepUp(): void
    {
        $this->requireMfa();
        $this->adminToken();

        self::assertSame(StatusCodeInterface::STATUS_OK, $this->api('GET', '/api/v1/users')->getStatusCode());
    }

    public function testWithThePolicyOptionalOneFactorIsEnough(): void
    {
        $this->managementApi();

        $response = $this->api('GET', '/api/v1/users', token: $this->personToken([M::Password]));

        self::assertSame(StatusCodeInterface::STATUS_OK, $response->getStatusCode());
    }

    private function requireMfa(): void
    {
        $this->container()->get(ResourceServerRepository::class)
            ->save($this->managementApi()->requiringMfa(MfaPolicy::Required));
    }

    /**
     * An administrator's access token for the Management API, from a sign-in with these methods.
     *
     * @param list<M> $methods
     */
    private function personToken(array $methods, string $scope = 'read:users'): string
    {
        $api = $this->managementApi();
        $user = $this->user();
        $this->container()->get(EnsureRole::class)('Administrator', 'All of it.', $api->identifier);
        $this->container()->get(AssignRole::class)('Administrator', self::TEST_USER_EMAIL);
        $this->publicClient();
        $value = 'person-token-' . count($methods) . '-' . str_replace(':', '-', $scope);
        $this->container()->get(AccessTokenRepository::class)->add(AccessToken::issueForUser(
            AccessTokenId::generate(new SeededRandomSource(crc32($value))),
            Digest::of($value),
            ClientId::fromString(self::TEST_CLIENT_ID),
            $user->id,
            Audience::fromString(self::MANAGEMENT_API),
            ScopeSet::fromString($scope),
            new DateTimeImmutable(),
            3600,
            AuthenticationContext::reconstitute(new DateTimeImmutable('-1 minute'), $methods),
        ));

        return $value;
    }
}
