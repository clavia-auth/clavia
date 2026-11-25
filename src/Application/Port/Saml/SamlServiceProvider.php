<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Port\Saml;

use Clavia\Domain\Shared\InvalidValue;

/**
 * This server as a SAML 2.0 service provider (docs/design/saml-connections.md §4): the requests it
 * sends, the responses it accepts, the metadata it reads and the metadata it publishes. Everything
 * XML, and every check of the Web Browser SSO profile (SAML Profiles §4.1.4.2, §4.1.4.3, §4.1.4.5),
 * happens behind it, so the application never sees a document and a change of library touches one
 * adapter.
 */
interface SamlServiceProvider
{
    /**
     * Where to send the browser: the identity provider's single sign-on URL with a deflated
     * `AuthnRequest` and the `RelayState` (Bindings §3.4, HTTP-Redirect).
     */
    public function authnRequestUrl(AuthnRequestDetails $request): string;

    /**
     * Read a `SAMLResponse` as POSTed (base64) and hold it to every rule: one assertion, signed by a
     * certificate of the connection, for this service provider, answering this request, now.
     * Anything less is a refusal with its category, never the reason in the identity provider's
     * words.
     */
    #[\NoDiscard]
    public function consume(string $encodedResponse, ExpectedResponse $expected): SamlIdentity|SamlRefused;

    /**
     * An identity provider's metadata document: its entity ID, its HTTP-Redirect sign-on URL and the
     * certificates its assertions are signed with.
     *
     * @throws InvalidValue What the document lacks or holds that cannot be used, never its content.
     */
    public function readMetadata(string $document): IdentityProviderMetadata;

    /** This server's metadata for one connection (SAML Metadata §2.4.4, `SPSSODescriptor`). */
    public function serviceProviderMetadata(ServiceProviderDescription $description): string;
}
