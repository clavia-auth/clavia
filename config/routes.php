<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

use Clavia\Adapter\Primary\Http\Auth\ConsentHandler;
use Clavia\Adapter\Primary\Http\Auth\DeviceHandler;
use Clavia\Adapter\Primary\Http\Auth\ExternalSignInCallbackHandler;
use Clavia\Adapter\Primary\Http\Auth\ExternalSignInHandler;
use Clavia\Adapter\Primary\Http\Auth\LoginHandler;
use Clavia\Adapter\Primary\Http\Auth\LoginPageHandler;
use Clavia\Adapter\Primary\Http\Auth\LogoutHandler;
use Clavia\Adapter\Primary\Http\Auth\MfaChallengeHandler;
use Clavia\Adapter\Primary\Http\Auth\MfaSettingsHandler;
use Clavia\Adapter\Primary\Http\Auth\PasskeysHandler;
use Clavia\Adapter\Primary\Http\Auth\PasskeySignInHandler;
use Clavia\Adapter\Primary\Http\Auth\PasswordForgotHandler;
use Clavia\Adapter\Primary\Http\Auth\PasswordlessCodeHandler;
use Clavia\Adapter\Primary\Http\Auth\PasswordlessLinkHandler;
use Clavia\Adapter\Primary\Http\Auth\PasswordlessStartHandler;
use Clavia\Adapter\Primary\Http\Auth\PasswordResetHandler;
use Clavia\Adapter\Primary\Http\Auth\Saml\SamlAcsHandler;
use Clavia\Adapter\Primary\Http\Auth\Saml\SamlCompleteHandler;
use Clavia\Adapter\Primary\Http\Auth\Saml\SamlMetadataHandler;
use Clavia\Adapter\Primary\Http\Auth\Saml\SamlSignInHandler;
use Clavia\Adapter\Primary\Http\Auth\SignUpHandler;
use Clavia\Adapter\Primary\Http\Auth\ThemeHandler;
use Clavia\Adapter\Primary\Http\Auth\VerifyEmailHandler;
use Clavia\Adapter\Primary\Http\Management\AuditEventsHandler;
use Clavia\Adapter\Primary\Http\Management\ClientConnectionsHandler;
use Clavia\Adapter\Primary\Http\Management\ClientHandler;
use Clavia\Adapter\Primary\Http\Management\ClientsHandler;
use Clavia\Adapter\Primary\Http\Management\ConnectionHandler;
use Clavia\Adapter\Primary\Http\Management\ConnectionMetadataRefreshHandler;
use Clavia\Adapter\Primary\Http\Management\ConnectionsHandler;
use Clavia\Adapter\Primary\Http\Management\InitialAccessTokenHandler;
use Clavia\Adapter\Primary\Http\Management\InitialAccessTokensHandler;
use Clavia\Adapter\Primary\Http\Management\ProvisioningTokenHandler;
use Clavia\Adapter\Primary\Http\Management\ProvisioningTokensHandler;
use Clavia\Adapter\Primary\Http\Management\ManagementApiMiddleware;
use Clavia\Adapter\Primary\Http\Management\ResourceServerHandler;
use Clavia\Adapter\Primary\Http\Management\ResourceServersHandler;
use Clavia\Adapter\Primary\Http\Management\RoleHandler;
use Clavia\Adapter\Primary\Http\Management\RolesHandler;
use Clavia\Adapter\Primary\Http\Management\RoleUsersHandler;
use Clavia\Adapter\Primary\Http\Management\RotateClientSecretHandler;
use Clavia\Adapter\Primary\Http\Management\SamlKeysHandler;
use Clavia\Adapter\Primary\Http\Management\SigningKeysHandler;
use Clavia\Adapter\Primary\Http\Management\UserConsentsHandler;
use Clavia\Adapter\Primary\Http\Management\UserExportsHandler;
use Clavia\Adapter\Primary\Http\Management\UserHandler;
use Clavia\Adapter\Primary\Http\Management\UserIdentitiesHandler;
use Clavia\Adapter\Primary\Http\Management\UserImportsHandler;
use Clavia\Adapter\Primary\Http\Management\UserJobHandler;
use Clavia\Adapter\Primary\Http\Management\UserJobOutputHandler;
use Clavia\Adapter\Primary\Http\Management\UserMfaHandler;
use Clavia\Adapter\Primary\Http\Management\UserPasskeysHandler;
use Clavia\Adapter\Primary\Http\Management\UserPasswordLinkHandler;
use Clavia\Adapter\Primary\Http\Management\UserPermissionsHandler;
use Clavia\Adapter\Primary\Http\Management\UserRolesHandler;
use Clavia\Adapter\Primary\Http\Management\UserSessionsHandler;
use Clavia\Adapter\Primary\Http\Management\UsersHandler;
use Clavia\Adapter\Primary\Http\Management\WebhookDeliveriesHandler;
use Clavia\Adapter\Primary\Http\Management\WebhookHandler;
use Clavia\Adapter\Primary\Http\Management\WebhookSecretHandler;
use Clavia\Adapter\Primary\Http\Management\WebhookTestHandler;
use Clavia\Adapter\Primary\Http\Management\WebhooksHandler;
use Clavia\Adapter\Primary\Http\OAuth2\AuthorizeHandler;
use Clavia\Adapter\Primary\Http\OAuth2\ClientConfigurationHandler;
use Clavia\Adapter\Primary\Http\OAuth2\ClientRegistrationHandler;
use Clavia\Adapter\Primary\Http\OAuth2\DeviceAuthorizationHandler;
use Clavia\Adapter\Primary\Http\OAuth2\IntrospectionHandler;
use Clavia\Adapter\Primary\Http\OAuth2\PushedAuthorizationRequestHandler;
use Clavia\Adapter\Primary\Http\OAuth2\RevocationHandler;
use Clavia\Adapter\Primary\Http\OAuth2\TokenHandler;
use Clavia\Adapter\Primary\Http\Oidc\DiscoveryHandler;
use Clavia\Adapter\Primary\Http\Oidc\EndSessionHandler;
use Clavia\Adapter\Primary\Http\Oidc\JwksHandler;
use Clavia\Adapter\Primary\Http\Oidc\UserInfoHandler;
use Clavia\Adapter\Primary\Http\Scim\ProvisioningMiddleware;
use Clavia\Adapter\Primary\Http\Scim\ScimGroupHandler;
use Clavia\Adapter\Primary\Http\Scim\ScimGroupsHandler;
use Clavia\Adapter\Primary\Http\Scim\ScimCatalogueHandler;
use Clavia\Adapter\Primary\Http\Scim\ScimNotFoundHandler;
use Clavia\Adapter\Primary\Http\Scim\ScimNotImplementedHandler;
use Clavia\Adapter\Primary\Http\Scim\ScimUserHandler;
use Clavia\Adapter\Primary\Http\Scim\ScimUsersHandler;
use Clavia\Adapter\Primary\Http\Scim\ServiceProviderConfigHandler;
use Clavia\Adapter\Primary\Http\Shared\HealthHandler;
use Clavia\Configuration\ClientRegistration;
use Clavia\Configuration\Settings;
use Mezzio\Application;
use Psr\Container\ContainerInterface;

/**
 * Every route the server answers. One process serves all four surfaces; which host
 * reaches which paths is the reverse proxy's decision (see the Caddyfile). A feature a
 * setting turns off has no route at all, so its paths are the same 404 as any other.
 */
return static function (Application $app, ContainerInterface $container): void {
    /** @var Settings $settings */
    $settings = $container->get(Settings::class);

    $app->get('/healthz', HealthHandler::class, 'ops.healthz');

    // ── /oauth2/* — the authorization server. Callers authenticate as clients. ──
    $app->route('/oauth2/authorize', AuthorizeHandler::class, ['GET', 'POST'], 'oauth2.authorize');
    $app->post('/oauth2/token', TokenHandler::class, 'oauth2.token');
    $app->post('/oauth2/par', PushedAuthorizationRequestHandler::class, 'oauth2.par');
    $app->post('/oauth2/introspect', IntrospectionHandler::class, 'oauth2.introspect');
    $app->post('/oauth2/revoke', RevocationHandler::class, 'oauth2.revoke');
    $app->post('/oauth2/device/code', DeviceAuthorizationHandler::class, 'oauth2.device');
    // RFC 7591: only for a bearer of an initial access token, and only when an operator allows it.
    if ($settings->clientRegistration !== ClientRegistration::Off) {
        $app->post('/oauth2/register', ClientRegistrationHandler::class, 'oauth2.register');
        $app->route(
            '/oauth2/register/{client_id}',
            ClientConfigurationHandler::class,
            ['GET', 'PUT', 'DELETE'],
            'oauth2.register.client',
        );
    }

    // ── /.well-known/* — the provider's metadata, public and cacheable. One document at
    // both locations: OpenID relying parties and RFC 8414 clients look in different places. ──
    $app->get('/.well-known/openid-configuration', DiscoveryHandler::class, 'oidc.discovery');
    $app->get('/.well-known/oauth-authorization-server', DiscoveryHandler::class, 'oauth2.metadata');

    // ── /oidc/* — OpenID Connect. The JWKS is public; userinfo takes a bearer access
    // token, on GET and POST (OIDC Core §5.3.1). ──
    $app->get('/oidc/jwks.json', JwksHandler::class, 'oidc.jwks');
    $app->route('/oidc/userinfo', UserInfoHandler::class, ['GET', 'POST'], 'oidc.userinfo');
    // RP-Initiated Logout 1.0 §2: the end-session endpoint answers GET and POST.
    $app->route('/oidc/logout', EndSessionHandler::class, ['GET', 'POST'], 'oidc.logout');

    // ── /auth/* — the interactive sign-in. The browser authenticates with its session
    // cookie; every state change is a POST, and logout has no GET on purpose. ──
    $app->get('/auth/login', LoginPageHandler::class, 'auth.login');
    // Signing in through a SAML identity provider: out (HTTP-Redirect), back by a cross-site POST that
    // carries no Lax cookie, parked and turned into a GET where the cookies come back. The ACS is the one
    // /auth/* POST without a CSRF token: it changes nothing but a short-lived handle.
    $app->get('/auth/saml/{connection:[a-z][a-z0-9-]*}', SamlSignInHandler::class, 'auth.saml');
    $app->post('/auth/saml/{connection:[a-z][a-z0-9-]*}/acs', SamlAcsHandler::class, 'auth.saml.acs');
    $app->get('/auth/saml/{connection:[a-z][a-z0-9-]*}/complete', SamlCompleteHandler::class, 'auth.saml.complete');
    $app->get('/auth/saml/{connection}/metadata', SamlMetadataHandler::class, 'auth.saml.metadata');
    $app->post('/auth/login', LoginHandler::class, 'auth.login.submit');
    $app->post('/auth/logout', LogoutHandler::class, 'auth.logout');
    $app->post('/auth/theme', ThemeHandler::class, 'auth.theme');
    // The second step of a sign-in, and the account holder's own two-factor settings.
    $app->route('/auth/mfa', MfaChallengeHandler::class, ['GET', 'POST'], 'auth.mfa');
    if ($settings->passkeysEnabled) {
        $app->post('/auth/mfa/passkey', MfaChallengeHandler::class, 'auth.mfa.passkey');
        // Signing in with a passkey, from the login page's autofill or its button.
        $app->post('/auth/passkey', PasskeySignInHandler::class, 'auth.passkey');
    }
    $app->route('/auth/mfa/enroll', MfaSettingsHandler::class, ['GET', 'POST'], 'auth.mfa.enroll');
    $app->post('/auth/mfa/enroll/confirm', MfaSettingsHandler::class, 'auth.mfa.enroll.confirm');
    $app->post('/auth/mfa/enroll/continue', MfaSettingsHandler::class, 'auth.mfa.enroll.continue');
    $app->post('/auth/mfa/disable', MfaSettingsHandler::class, 'auth.mfa.disable');
    // The account holder's passkeys: the list, a new one, and renaming or removing one.
    if ($settings->passkeysEnabled) {
        $app->route('/auth/passkeys', PasskeysHandler::class, ['GET', 'POST'], 'auth.passkeys');
        $app->post('/auth/passkeys/new', PasskeysHandler::class, 'auth.passkeys.new');
        $app->post('/auth/passkeys/{passkey_id}/name', PasskeysHandler::class, 'auth.passkeys.name');
        $app->post('/auth/passkeys/{passkey_id}/remove', PasskeysHandler::class, 'auth.passkeys.remove');
    }
    // Whether an application may act as the signed-in person: the question, and the answer.
    $app->route('/auth/consent', ConsentHandler::class, ['GET', 'POST'], 'auth.consent');
    $app->route('/auth/device', DeviceHandler::class, ['GET', 'POST'], 'auth.device');
    // Signing in with a code or a link sent by email: the login page's email form starts
    // it; the code is typed back in the browser that asked, the link opens anywhere and
    // signs in only on the POST from the page it opens on.
    $app->post('/auth/passwordless/start', PasswordlessStartHandler::class, 'auth.passwordless.start');
    $app->route('/auth/passwordless/code', PasswordlessCodeHandler::class, ['GET', 'POST'], 'auth.passwordless.code');
    $app->route(
        '/auth/passwordless/verify',
        PasswordlessLinkHandler::class,
        ['GET', 'POST'],
        'auth.passwordless.verify',
    );
    // Self-service accounts: creating one, proving its address, choosing a new password.
    // Every link mailed opens on a page that asks, and changes something only on the POST
    // from it (docs/design/self-service-accounts.md).
    $app->route('/auth/signup', SignUpHandler::class, ['GET', 'POST'], 'auth.signup');
    $app->route('/auth/verify-email', VerifyEmailHandler::class, ['GET', 'POST'], 'auth.verify-email');
    $app->route('/auth/password/forgot', PasswordForgotHandler::class, ['GET', 'POST'], 'auth.password.forgot');
    $app->route('/auth/password/reset', PasswordResetHandler::class, ['GET', 'POST'], 'auth.password.reset');
    // Signing in through an external provider: out, then back. Both are navigations (GET);
    // the callback's path is the redirect URI registered at the provider.
    $app->get('/auth/social/{provider:[a-z][a-z0-9-]*}', ExternalSignInHandler::class, 'auth.social');
    $app->get(
        '/auth/social/{provider:[a-z][a-z0-9-]*}/callback',
        ExternalSignInCallbackHandler::class,
        'auth.social.callback',
    );

    // ── /api/v1/* — the Management API, a machine plane: a bearer token for this API on
    // every route, through ManagementApiMiddleware, which also checks each request
    // against docs/openapi/management-api.yaml. Never the session cookie. ──
    $management = static fn (string $handler): array => [ManagementApiMiddleware::class, $handler];
    $app->route('/api/v1/users', $management(UsersHandler::class), ['GET', 'POST'], 'api.users');
    $app->route(
        '/api/v1/users/{user_id}',
        $management(UserHandler::class),
        ['GET', 'PATCH', 'DELETE'],
        'api.user',
    );
    $app->delete('/api/v1/users/{user_id}/mfa', $management(UserMfaHandler::class), 'api.user.mfa');
    $app->post(
        '/api/v1/users/{user_id}/password-reset',
        $management(UserPasswordLinkHandler::class),
        'api.user.password-reset',
    );
    $app->route(
        '/api/v1/users/{user_id}/roles',
        $management(UserRolesHandler::class),
        ['GET', 'PUT'],
        'api.user.roles',
    );
    $app->get(
        '/api/v1/users/{user_id}/permissions',
        $management(UserPermissionsHandler::class),
        'api.user.permissions',
    );
    $app->get(
        '/api/v1/users/{user_id}/consents',
        $management(UserConsentsHandler::class),
        'api.user.consents',
    );
    $app->delete(
        '/api/v1/users/{user_id}/consents/{client_id}',
        $management(UserConsentsHandler::class),
        'api.user.consent',
    );
    $app->route(
        '/api/v1/users/{user_id}/sessions',
        $management(UserSessionsHandler::class),
        ['GET', 'DELETE'],
        'api.user.sessions',
    );
    $app->delete(
        '/api/v1/users/{user_id}/sessions/{sid}',
        $management(UserSessionsHandler::class),
        'api.user.session',
    );
    $app->get(
        '/api/v1/users/{user_id}/identities',
        $management(UserIdentitiesHandler::class),
        'api.user.identities',
    );
    $app->delete(
        '/api/v1/users/{user_id}/identities/{connection}',
        $management(UserIdentitiesHandler::class),
        'api.user.identity',
    );
    $app->get('/api/v1/users/{user_id}/passkeys', $management(UserPasskeysHandler::class), 'api.user.passkeys');
    $app->delete(
        '/api/v1/users/{user_id}/passkeys/{passkey_id}',
        $management(UserPasskeysHandler::class),
        'api.user.passkey',
    );
    $app->route('/api/v1/clients', $management(ClientsHandler::class), ['GET', 'POST'], 'api.clients');
    $app->route(
        '/api/v1/clients/{client_id}',
        $management(ClientHandler::class),
        ['GET', 'PATCH', 'DELETE'],
        'api.client',
    );
    $app->post(
        '/api/v1/clients/{client_id}/rotate-secret',
        $management(RotateClientSecretHandler::class),
        'api.client.rotate-secret',
    );
    $app->put(
        '/api/v1/clients/{client_id}/connections',
        $management(ClientConnectionsHandler::class),
        'api.client.connections',
    );
    $app->post(
        '/api/v1/connections/{name}/refresh-metadata',
        $management(ConnectionMetadataRefreshHandler::class),
        'api.connection.refresh-metadata',
    );
    $app->route('/api/v1/connections', $management(ConnectionsHandler::class), ['GET', 'POST'], 'api.connections');
    $app->route(
        '/api/v1/connections/{name}',
        $management(ConnectionHandler::class),
        ['GET', 'PATCH', 'DELETE'],
        'api.connection',
    );
    $app->route(
        '/api/v1/resource-servers',
        $management(ResourceServersHandler::class),
        ['GET', 'POST'],
        'api.resource-servers',
    );
    $app->route(
        '/api/v1/resource-servers/{resource_server_id}',
        $management(ResourceServerHandler::class),
        ['GET', 'PATCH', 'DELETE'],
        'api.resource-server',
    );
    $app->route('/api/v1/roles', $management(RolesHandler::class), ['GET', 'POST'], 'api.roles');
    $app->get('/api/v1/signing-keys', $management(SigningKeysHandler::class), 'api.signing-keys');
    $app->post('/api/v1/signing-keys/rotate', $management(SigningKeysHandler::class), 'api.signing-keys.rotate');
    $app->get('/api/v1/saml-keys', $management(SamlKeysHandler::class), 'api.saml-keys');
    $app->post('/api/v1/saml-keys/rotate', $management(SamlKeysHandler::class), 'api.saml-keys.rotate');
    $app->route(
        '/api/v1/initial-access-tokens',
        $management(InitialAccessTokensHandler::class),
        ['GET', 'POST'],
        'api.initial-access-tokens',
    );
    $app->route(
        '/api/v1/initial-access-tokens/{initial_access_token_id}',
        $management(InitialAccessTokenHandler::class),
        ['DELETE'],
        'api.initial-access-token',
    );
    $app->route(
        '/api/v1/provisioning-tokens',
        $management(ProvisioningTokensHandler::class),
        ['GET', 'POST'],
        'api.provisioning-tokens',
    );
    $app->route(
        '/api/v1/provisioning-tokens/{provisioning_token_id}',
        $management(ProvisioningTokenHandler::class),
        ['GET', 'DELETE'],
        'api.provisioning-token',
    );
    $app->route('/api/v1/webhooks', $management(WebhooksHandler::class), ['GET', 'POST'], 'api.webhooks');
    $app->route(
        '/api/v1/webhooks/{webhook_id}',
        $management(WebhookHandler::class),
        ['GET', 'PATCH', 'DELETE'],
        'api.webhook',
    );
    $app->post(
        '/api/v1/webhooks/{webhook_id}/rotate-secret',
        $management(WebhookSecretHandler::class),
        'api.webhook.rotate-secret',
    );
    $app->post('/api/v1/webhooks/{webhook_id}/test', $management(WebhookTestHandler::class), 'api.webhook.test');
    $app->get(
        '/api/v1/webhooks/{webhook_id}/deliveries',
        $management(WebhookDeliveriesHandler::class),
        'api.webhook.deliveries',
    );
    $app->post('/api/v1/jobs/users-imports', $management(UserImportsHandler::class), 'api.jobs.users-imports');
    $app->post('/api/v1/jobs/users-exports', $management(UserExportsHandler::class), 'api.jobs.users-exports');
    $app->get('/api/v1/jobs/{job_id}', $management(UserJobHandler::class), 'api.job');
    $app->get('/api/v1/jobs/{job_id}/output', $management(UserJobOutputHandler::class), 'api.job.output');
    $app->route('/api/v1/audit-events', $management(AuditEventsHandler::class), ['GET'], 'api.audit-events');
    $app->route(
        '/api/v1/roles/{role_id}',
        $management(RoleHandler::class),
        ['GET', 'PATCH', 'DELETE'],
        'api.role',
    );
    $app->route(
        '/api/v1/roles/{role_id}/users',
        $management(RoleUsersHandler::class),
        ['GET', 'POST'],
        'api.role.users',
    );
    $app->delete(
        '/api/v1/roles/{role_id}/users/{user_id}',
        $management(RoleUsersHandler::class),
        'api.role.user',
    );

    // ── /scim/v2/* — SCIM 2.0 (RFC 7644), the fifth surface: a directory, holding a provisioning
    // token for one connection, through ProvisioningMiddleware on every route. Never a Management
    // API token, never the session cookie (docs/design/scim-provisioning.md). ──
    $scim = static fn (string $handler): array => [ProvisioningMiddleware::class, $handler];
    $app->get('/scim/v2/ServiceProviderConfig', $scim(ServiceProviderConfigHandler::class), 'scim.config');
    $app->get(
        '/scim/v2/{catalogue:ResourceTypes|Schemas}[/{id}]',
        $scim(ScimCatalogueHandler::class),
        'scim.catalogue',
    );
    $app->route('/scim/v2/Users', $scim(ScimUsersHandler::class), ['GET', 'POST'], 'scim.users');
    $app->route(
        '/scim/v2/Users/{id}',
        $scim(ScimUserHandler::class),
        ['GET', 'PUT', 'PATCH', 'DELETE'],
        'scim.user',
    );
    $app->route('/scim/v2/Groups', $scim(ScimGroupsHandler::class), ['GET', 'POST'], 'scim.groups');
    $app->route(
        '/scim/v2/Groups/{id}',
        $scim(ScimGroupHandler::class),
        ['GET', 'PUT', 'PATCH', 'DELETE'],
        'scim.group',
    );
    // Offered by no directory this is for (§1): 501, as RFC 7644 §3.12 answers a missing feature.
    $app->post('/scim/v2/Bulk', $scim(ScimNotImplementedHandler::class), 'scim.bulk');
    $app->route(
        '/scim/v2/Me',
        $scim(ScimNotImplementedHandler::class),
        ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'],
        'scim.me',
    );
    // Anything else under the prefix is a SCIM 404, behind the token like the rest: a caller
    // without one learns nothing of what exists.
    $app->route(
        '/scim/v2[/{path:.*}]',
        $scim(ScimNotFoundHandler::class),
        ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'],
        'scim.not-found',
    );
};
