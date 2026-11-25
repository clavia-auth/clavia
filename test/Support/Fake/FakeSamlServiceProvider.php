<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Support\Fake;

use Clavia\Application\Port\Saml\AuthnRequestDetails;
use Clavia\Application\Port\Saml\ExpectedResponse;
use Clavia\Application\Port\Saml\IdentityProviderMetadata;
use Clavia\Application\Port\Saml\SamlIdentity;
use Clavia\Application\Port\Saml\SamlRefusal;
use Clavia\Application\Port\Saml\SamlRefused;
use Clavia\Application\Port\Saml\SamlServiceProvider;
use Clavia\Application\Port\Saml\ServiceProviderDescription;
use Clavia\Domain\Shared\InvalidValue;

/**
 * The SAML service provider for use cases: it answers what it is told and remembers what it was
 * asked. It checks nothing; the real adapter's contract runs against genuine XML instead
 * ({@see \ClaviaTest\Support\Contract\SamlServiceProviderContract}).
 */
final class FakeSamlServiceProvider implements SamlServiceProvider
{
    /** @var list<AuthnRequestDetails> */
    public array $requests = [];

    /** @var list<ExpectedResponse> */
    public array $expectations = [];

    public SamlIdentity|SamlRefused $answer;

    public ?IdentityProviderMetadata $metadata = null;

    public function __construct()
    {
        $this->answer = new SamlRefused(SamlRefusal::Signature);
    }

    #[\Override]
    public function authnRequestUrl(AuthnRequestDetails $request, ?\Closure $sign = null): string
    {
        $this->requests[] = $request;

        return $request->singleSignOnUrl->value . '?SAMLRequest=fake&RelayState=' . rawurlencode($request->relayState);
    }

    #[\Override]
    public function consume(string $encodedResponse, ExpectedResponse $expected): SamlIdentity|SamlRefused
    {
        $this->expectations[] = $expected;

        return $this->answer;
    }

    #[\Override]
    public function readMetadata(string $document): IdentityProviderMetadata
    {
        return $this->metadata ?? throw new InvalidValue('The identity provider publishes no signing certificate.');
    }

    #[\Override]
    public function serviceProviderMetadata(ServiceProviderDescription $description): string
    {
        return '<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="'
            . htmlspecialchars($description->entityId, ENT_XML1 | ENT_QUOTES) . '"/>';
    }
}
