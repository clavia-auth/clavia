<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap;

use Clavia\Adapter\Primary\Cli\AssignRoleCommand;
use Clavia\Adapter\Primary\Cli\AuthorizeUrlCommand;
use Clavia\Adapter\Primary\Cli\CreateMachineClientCommand;
use Clavia\Adapter\Primary\Cli\CreateRoleCommand;
use Clavia\Adapter\Primary\Cli\DatabaseStatusCommand;
use Clavia\Adapter\Primary\Cli\GenerateEncryptionKeyCommand;
use Clavia\Adapter\Primary\Cli\GenerateSigningKeyCommand;
use Clavia\Adapter\Primary\Cli\GrantClientAccessCommand;
use Clavia\Adapter\Primary\Cli\ListManagementScopesCommand;
use Clavia\Adapter\Primary\Cli\ListRolesCommand;
use Clavia\Adapter\Primary\Cli\ListSigningKeysCommand;
use Clavia\Adapter\Primary\Cli\MailOutboxCommand;
use Clavia\Adapter\Primary\Cli\MigrateDatabaseCommand;
use Clavia\Adapter\Primary\Cli\PurgeAuditEventsCommand;
use Clavia\Adapter\Primary\Cli\RegisterManagementApiCommand;
use Clavia\Adapter\Primary\Cli\RotateSigningKeyCommand;
use Clavia\Adapter\Primary\Cli\SeedDevelopmentDataCommand;
use Clavia\Adapter\Primary\Cli\ShowConfigCommand;
use Clavia\Adapter\Primary\Http\Auth\AuthCookies;
use Clavia\Adapter\Primary\Http\Auth\AuthPageResponder;
use Clavia\Adapter\Primary\Http\Auth\ConsentHandler;
use Clavia\Adapter\Primary\Http\Auth\DeviceHandler;
use Clavia\Adapter\Primary\Http\Auth\ExternalSignInCallbackHandler;
use Clavia\Adapter\Primary\Http\Auth\ExternalSignInHandler;
use Clavia\Adapter\Primary\Http\Auth\LoginForm;
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
use Clavia\Adapter\Primary\Http\Auth\SignUpHandler;
use Clavia\Adapter\Primary\Http\Auth\ThemeHandler;
use Clavia\Adapter\Primary\Http\Auth\VerifyEmailHandler;
use Clavia\Adapter\Primary\Http\Management\AuditEventsHandler;
use Clavia\Adapter\Primary\Http\Management\ClientConnectionsHandler;
use Clavia\Adapter\Primary\Http\Management\ClientHandler;
use Clavia\Adapter\Primary\Http\Management\ClientsHandler;
use Clavia\Adapter\Primary\Http\Management\ConnectionHandler;
use Clavia\Adapter\Primary\Http\Management\ConnectionsHandler;
use Clavia\Adapter\Primary\Http\Management\ManagementApiMiddleware;
use Clavia\Adapter\Primary\Http\Management\ManagementContract;
use Clavia\Adapter\Primary\Http\Management\ManagementResponder;
use Clavia\Adapter\Primary\Http\Management\ResourceServerHandler;
use Clavia\Adapter\Primary\Http\Management\ResourceServersHandler;
use Clavia\Adapter\Primary\Http\Management\RoleHandler;
use Clavia\Adapter\Primary\Http\Management\RolesHandler;
use Clavia\Adapter\Primary\Http\Management\RoleUsersHandler;
use Clavia\Adapter\Primary\Http\Management\RotateClientSecretHandler;
use Clavia\Adapter\Primary\Http\Management\UserConsentsHandler;
use Clavia\Adapter\Primary\Http\Management\UserHandler;
use Clavia\Adapter\Primary\Http\Management\UserIdentitiesHandler;
use Clavia\Adapter\Primary\Http\Management\UserMfaHandler;
use Clavia\Adapter\Primary\Http\Management\UserPasskeysHandler;
use Clavia\Adapter\Primary\Http\Management\UserPasswordLinkHandler;
use Clavia\Adapter\Primary\Http\Management\UserPermissionsHandler;
use Clavia\Adapter\Primary\Http\Management\UserRolesHandler;
use Clavia\Adapter\Primary\Http\Management\UserSessionsHandler;
use Clavia\Adapter\Primary\Http\Management\UsersHandler;
use Clavia\Adapter\Primary\Http\OAuth2\AuthorizeHandler;
use Clavia\Adapter\Primary\Http\OAuth2\DeviceAuthorizationHandler;
use Clavia\Adapter\Primary\Http\OAuth2\IntrospectionHandler;
use Clavia\Adapter\Primary\Http\OAuth2\OAuth2Responder;
use Clavia\Adapter\Primary\Http\OAuth2\PushedAuthorizationRequestHandler;
use Clavia\Adapter\Primary\Http\OAuth2\RevocationHandler;
use Clavia\Adapter\Primary\Http\OAuth2\TokenHandler;
use Clavia\Adapter\Primary\Http\Oidc\DiscoveryHandler;
use Clavia\Adapter\Primary\Http\Oidc\EndSessionHandler;
use Clavia\Adapter\Primary\Http\Oidc\JwksHandler;
use Clavia\Adapter\Primary\Http\Oidc\UserInfoHandler;
use Clavia\Adapter\Primary\Http\Shared\AuditContextMiddleware;
use Clavia\Adapter\Primary\Http\Shared\BearerChallenger;
use Clavia\Adapter\Primary\Http\Shared\ErrorResponder;
use Clavia\Adapter\Primary\Http\Shared\HealthHandler;
use Clavia\Adapter\Primary\Http\Shared\MethodNotAllowedMiddleware;
use Clavia\Adapter\Primary\Http\Shared\NotFoundHandler;
use Clavia\Adapter\Primary\Http\Shared\PageRenderer;
use Clavia\Adapter\Secondary\Crypto\BcryptPasswordHasher;
use Clavia\Adapter\Secondary\Http\OutboundUrlPolicy;
use Clavia\Adapter\Secondary\IdentityProvider\IdTokenVerifier;
use Clavia\Adapter\Secondary\IdentityProvider\JwksCache;
use Clavia\Adapter\Secondary\IdentityProvider\ProviderHttp;
use Clavia\Adapter\Secondary\Persistence\PhpDb\Database;
use Clavia\Adapter\Secondary\Redis\RedisConnection;
use Clavia\Adapter\Secondary\Signing\Jose\JoseSignatureVerifier;
use Clavia\Adapter\Secondary\Signing\Remote\PublicKeyCache;
use Clavia\Adapter\Secondary\System\AfterResponseTasks;
use Clavia\Adapter\Secondary\System\SystemClock;
use Clavia\Adapter\Secondary\System\SystemRandomSource;
use Clavia\Application\Audit\Audit;
use Clavia\Application\Audit\AuditContext;
use Clavia\Application\Audit\PurgeAuditEvents;
use Clavia\Application\Audit\ReadAuditEvents;
use Clavia\Application\Audit\Trail\AuthenticationTrail;
use Clavia\Application\Audit\Trail\AuthorizationTrail;
use Clavia\Application\Audit\Trail\ConfigurationTrail;
use Clavia\Application\Audit\Trail\DirectoryTrail;
use Clavia\Application\Authentication\Account\AccountMail;
use Clavia\Application\Authentication\Account\ConfirmEmail;
use Clavia\Application\Authentication\Account\DescribeAccountLink;
use Clavia\Application\Authentication\Account\DescribeSignUpPage;
use Clavia\Application\Authentication\Account\PasswordScreen;
use Clavia\Application\Authentication\Account\RequestPasswordReset;
use Clavia\Application\Authentication\Account\ResetPassword;
use Clavia\Application\Authentication\Account\SendAccountLink;
use Clavia\Application\Authentication\Account\SignUp;
use Clavia\Application\Authentication\DevelopmentAutoLogin;
use Clavia\Application\Authentication\External\BeginExternalSignIn;
use Clavia\Application\Authentication\External\CompleteExternalSignIn;
use Clavia\Application\Authentication\External\ResolveExternalAccount;
use Clavia\Application\Authentication\LoginPage\DescribeLoginPage;
use Clavia\Application\Authentication\LoginThrottle;
use Clavia\Application\Authentication\Mfa\BeginEnrolmentOnTheWay;
use Clavia\Application\Authentication\Mfa\BeginPasskeySecondFactor;
use Clavia\Application\Authentication\Mfa\BeginStepUp;
use Clavia\Application\Authentication\Mfa\BeginTotpEnrollment;
use Clavia\Application\Authentication\Mfa\CompletePasskeySecondFactor;
use Clavia\Application\Authentication\Mfa\CompleteSecondFactor;
use Clavia\Application\Authentication\Mfa\ConfirmTotpEnrollment;
use Clavia\Application\Authentication\Mfa\DescribeEnrolmentOnTheWay;
use Clavia\Application\Authentication\Mfa\DescribeMfa;
use Clavia\Application\Authentication\Mfa\DescribeSecondFactorPage;
use Clavia\Application\Authentication\Mfa\DisableMfa;
use Clavia\Application\Authentication\Mfa\FinishEnrolmentOnTheWay;
use Clavia\Application\Authentication\Mfa\ResumeTotpEnrollment;
use Clavia\Application\Authentication\Mfa\SecondFactors;
use Clavia\Application\Authentication\Mfa\TotpSeeds;
use Clavia\Application\Authentication\Passkey\BeginPasskeyRegistration;
use Clavia\Application\Authentication\Passkey\CompletePasskeyRegistration;
use Clavia\Application\Authentication\Passkey\DescribePasskeys;
use Clavia\Application\Authentication\Passkey\RecentSignIn;
use Clavia\Application\Authentication\Passkey\RemovePasskey;
use Clavia\Application\Authentication\Passkey\RenamePasskey;
use Clavia\Application\Authentication\Passkey\UsePasskey;
use Clavia\Application\Authentication\Passwordless\AnswerPasswordlessCode;
use Clavia\Application\Authentication\Passwordless\DescribePasswordlessChallenge;
use Clavia\Application\Authentication\Passwordless\FinishPasswordlessSignIn;
use Clavia\Application\Authentication\Passwordless\FollowPasswordlessLink;
use Clavia\Application\Authentication\Passwordless\SignInMail;
use Clavia\Application\Authentication\Passwordless\StartPasswordlessSignIn;
use Clavia\Application\Authentication\RequireSignIn;
use Clavia\Application\Authentication\ResolveEndUser;
use Clavia\Application\Authentication\Sessions;
use Clavia\Application\Authentication\SignIn\BeginPasskeySignIn;
use Clavia\Application\Authentication\SignIn\CompleteFirstFactor;
use Clavia\Application\Authentication\SignIn\SignInWithPasskey;
use Clavia\Application\Authentication\SignIn\SignInWithPassword;
use Clavia\Application\Authentication\SignOut;
use Clavia\Application\Authentication\SignOutEverywhere;
use Clavia\Application\Clients\RegisterMachineClient;
use Clavia\Application\Connection\ConnectionAccess;
use Clavia\Application\Development\BuildAuthorizationUrl;
use Clavia\Application\Development\SeedDashboardClient;
use Clavia\Application\Development\SeedDevelopmentData;
use Clavia\Application\Development\SeedManagementAccess;
use Clavia\Application\Event\EventSubscriber;
use Clavia\Application\Management\Caller\AuthenticateManagementCaller;
use Clavia\Application\Management\Clients\BackChannelLogoutRegistration;
use Clavia\Application\Management\Clients\ClientConnections;
use Clavia\Application\Management\Clients\DeleteClient;
use Clavia\Application\Management\Clients\ReadClients;
use Clavia\Application\Management\Clients\RegisterClient;
use Clavia\Application\Management\Clients\RotateClientSecret;
use Clavia\Application\Management\Clients\UpdateClient;
use Clavia\Application\Management\Connections\CreateConnection;
use Clavia\Application\Management\Connections\DeleteConnection;
use Clavia\Application\Management\Connections\OidcConfiguration;
use Clavia\Application\Management\Connections\ReadConnections;
use Clavia\Application\Management\Connections\UpdateConnection;
use Clavia\Application\Management\Provisioning\AssignRole;
use Clavia\Application\Management\Provisioning\EnsureRole;
use Clavia\Application\Management\Provisioning\GrantClientAccess;
use Clavia\Application\Management\Provisioning\RegisterManagementApi;
use Clavia\Application\Management\ResourceServers\DeleteResourceServer;
use Clavia\Application\Management\ResourceServers\ReadResourceServers;
use Clavia\Application\Management\ResourceServers\RegisterResourceServer;
use Clavia\Application\Management\ResourceServers\UpdateResourceServer;
use Clavia\Application\Management\Roles\CreateRole;
use Clavia\Application\Management\Roles\DeleteRole;
use Clavia\Application\Management\Roles\ReadEffectivePermissions;
use Clavia\Application\Management\Roles\ReadRoleHolders;
use Clavia\Application\Management\Roles\ReadRoles;
use Clavia\Application\Management\Roles\RoleAssignments;
use Clavia\Application\Management\Roles\RolePermissions;
use Clavia\Application\Management\Roles\UpdateRole;
use Clavia\Application\Management\Users\CreateUser;
use Clavia\Application\Management\Users\DeleteUser;
use Clavia\Application\Management\Users\ReadConsents;
use Clavia\Application\Management\Users\ReadIdentities;
use Clavia\Application\Management\Users\ReadUserPasskeys;
use Clavia\Application\Management\Users\ReadUsers;
use Clavia\Application\Management\Users\RemoveUserPasskey;
use Clavia\Application\Management\Users\ResetUserMfa;
use Clavia\Application\Management\Users\SendPasswordLink;
use Clavia\Application\Management\Users\UnlinkIdentity;
use Clavia\Application\Management\Users\UpdateUser;
use Clavia\Application\Management\Users\UserSessions;
use Clavia\Application\Management\Users\WithdrawConsent;
use Clavia\Application\OAuth2\Authorize\AuthorizationRequestRules;
use Clavia\Application\OAuth2\Authorize\Authorize;
use Clavia\Application\OAuth2\ClientAuthentication\ClientAuthenticator;
use Clavia\Application\OAuth2\ClientAuthentication\ClientFailureThrottle;
use Clavia\Application\OAuth2\Consent\DecideConsent;
use Clavia\Application\OAuth2\Consent\DescribeConsent;
use Clavia\Application\OAuth2\Consent\HeldConsents;
use Clavia\Application\OAuth2\Device\DecideDeviceRequest;
use Clavia\Application\OAuth2\Device\DescribeDeviceRequest;
use Clavia\Application\OAuth2\Device\PendingDeviceRequests;
use Clavia\Application\OAuth2\Device\RequestDeviceAuthorization;
use Clavia\Application\OAuth2\Device\UserCodeThrottle;
use Clavia\Application\OAuth2\Par\PushAuthorizationRequest;
use Clavia\Application\OAuth2\ReadRequestedAccess;
use Clavia\Application\OAuth2\Token\AccessTokenMinter;
use Clavia\Application\OAuth2\Token\AuthorizationCodeGrant;
use Clavia\Application\OAuth2\Token\ClientCredentialsGrant;
use Clavia\Application\OAuth2\Token\DeviceCodeGrant;
use Clavia\Application\OAuth2\Token\IssueToken;
use Clavia\Application\OAuth2\Token\RefreshTokenGrant;
use Clavia\Application\OAuth2\Token\UserScope;
use Clavia\Application\OAuth2\TokenManagement\IntrospectToken;
use Clavia\Application\OAuth2\TokenManagement\IssuedTokens;
use Clavia\Application\OAuth2\TokenManagement\RevokeToken;
use Clavia\Application\Oidc\CompactJws;
use Clavia\Application\Oidc\Discovery\ProviderMetadata;
use Clavia\Application\Oidc\IdTokenIssuer;
use Clavia\Application\Oidc\Keys\GenerateSigningKey;
use Clavia\Application\Oidc\Keys\ListSigningKeys;
use Clavia\Application\Oidc\Keys\PublishSigningKeys;
use Clavia\Application\Oidc\Keys\RotateSigningKey;
use Clavia\Application\Oidc\Logout\BackChannelLogout;
use Clavia\Application\Oidc\Logout\EndSession;
use Clavia\Application\Oidc\UserInfo\ReadUserInfo;
use Clavia\Application\Port\AccountLinkStore;
use Clavia\Application\Port\AttemptCounter;
use Clavia\Application\Port\BackChannelLogoutDelivery;
use Clavia\Application\Port\BreachedPasswords;
use Clavia\Application\Port\ConsentStateStore;
use Clavia\Application\Port\DeferredTasks;
use Clavia\Application\Port\DeviceAuthorizationStore;
use Clavia\Application\Port\DomainEvents;
use Clavia\Application\Port\ExternalSignInStore;
use Clavia\Application\Port\IdentityProviders;
use Clavia\Application\Port\LoginStateStore;
use Clavia\Application\Port\Mailer;
use Clavia\Application\Port\MailOutbox;
use Clavia\Application\Port\MfaChallengeStore;
use Clavia\Application\Port\NonceRegistry;
use Clavia\Application\Port\OidcDiscovery;
use Clavia\Application\Port\OutboundUrls;
use Clavia\Application\Port\PasskeyVerifier;
use Clavia\Application\Port\PasswordHasher;
use Clavia\Application\Port\PasswordlessChallengeStore;
use Clavia\Application\Port\PushedAuthorizationRequestStore;
use Clavia\Application\Port\SchemaMigrator;
use Clavia\Application\Port\SecretCipher;
use Clavia\Application\Port\SessionStore;
use Clavia\Application\Port\SignatureVerifier;
use Clavia\Application\Port\SigningKeyStore;
use Clavia\Application\Port\TokenSigner;
use Clavia\Application\Port\TransactionManager;
use Clavia\Application\Port\WebAuthnChallengeStore;
use Clavia\Application\Secrets\GenerateEncryptionKey;
use Clavia\Configuration\Settings;
use Clavia\Domain\Audit\AuditLog;
use Clavia\Domain\Authentication\Mfa\MfaFactorRepository;
use Clavia\Domain\Authentication\Passkey\PasskeyRepository;
use Clavia\Domain\Authentication\Mfa\RecoveryCodeRepository;
use Clavia\Domain\Authentication\Passkey\RelyingParty;
use Clavia\Domain\Client\ClientRepository;
use Clavia\Domain\Connection\ConnectionRepository;
use Clavia\Domain\Consent\ConsentRepository;
use Clavia\Domain\Identity\ExternalIdentityRepository;
use Clavia\Domain\Identity\UserRepository;
use Clavia\Domain\OAuth2\AccessTokenRepository;
use Clavia\Domain\OAuth2\AuthorizationCodeRepository;
use Clavia\Domain\OAuth2\RefreshTokenRepository;
use Clavia\Domain\Oidc\SigningAlgorithm;
use Clavia\Domain\Rbac\RoleRepository;
use Clavia\Domain\ResourceServer\ClientGrantRepository;
use Clavia\Domain\ResourceServer\ResourceServerRepository;
use Clavia\Domain\Shared\Clock;
use Clavia\Domain\Shared\RandomSource;
use Clavia\Domain\Shared\SecretGenerator;
use Laminas\Diactoros\RequestFactory;
use Laminas\Diactoros\ResponseFactory;
use Laminas\Diactoros\ServerRequestFilter\FilterServerRequestInterface;
use Laminas\Diactoros\StreamFactory;
use Mezzio\Middleware\ErrorResponseGenerator as MezzioErrorResponseGenerator;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\StreamFactoryInterface;
use Psr\Log\LoggerInterface;
use Symfony\Component\Console\Application as ConsoleApplication;

/**
 * The composition root: the only place that knows which adapter implements which port.
 *
 * Everything under `src/` receives its collaborators through its constructor; the
 * factories in {@see Container} are the only code that reads the container. A service
 * is added here, never looked up from inside a ring.
 */
final class ConfigProvider
{
    private const string TEMPLATES = __DIR__ . '/../../templates';

    /**
     * Console commands, by the name they are run with. Loaded lazily: `clavia config`
     * does not construct the collaborators of every other command.
     */
    public const array CONSOLE_COMMANDS = [
        'config' => ShowConfigCommand::class,
        'db:migrate' => MigrateDatabaseCommand::class,
        'db:status' => DatabaseStatusCommand::class,
        'secrets:generate-key' => GenerateEncryptionKeyCommand::class,
        'seed-dev' => SeedDevelopmentDataCommand::class,
        'authorize-url' => AuthorizeUrlCommand::class,
        'keys:generate' => GenerateSigningKeyCommand::class,
        'keys:rotate' => RotateSigningKeyCommand::class,
        'keys:list' => ListSigningKeysCommand::class,
        'clients:create-m2m' => CreateMachineClientCommand::class,
        'clients:grant' => GrantClientAccessCommand::class,
        'management-api:register' => RegisterManagementApiCommand::class,
        'management-api:scopes' => ListManagementScopesCommand::class,
        'roles:create' => CreateRoleCommand::class,
        'roles:assign' => AssignRoleCommand::class,
        'roles:list' => ListRolesCommand::class,
        'mail:outbox' => MailOutboxCommand::class,
        'audit:purge' => PurgeAuditEventsCommand::class,
    ];

    /**
     * Who acts on domain events, in the order they are told: the audit trail first, so an
     * event is on record before anything else happens because of it.
     *
     * @var list<class-string<EventSubscriber>>
     */
    public const array EVENT_SUBSCRIBERS = [
        AuthenticationTrail::class,
        AuthorizationTrail::class,
        ConfigurationTrail::class,
        DirectoryTrail::class,
        BackChannelLogout::class,
    ];

    /**
     * @return array{
     *     dependencies: array<string, array<string, string>>,
     *     templates: array{extension: string, paths: array<string, list<string>>},
     * }
     */
    public function __invoke(): array
    {
        return [
            'dependencies' => [
                'invokables' => [
                    ResponseFactoryInterface::class => ResponseFactory::class,
                    StreamFactoryInterface::class => StreamFactory::class,
                    RequestFactoryInterface::class => RequestFactory::class,
                    SignatureVerifier::class => JoseSignatureVerifier::class,

                    // One per request: where it came from and who is acting, for the audit trail.
                    AuditContext::class => AuditContext::class,

                    // Ports whose adapter needs nothing to be built
                    Clock::class => SystemClock::class,
                    RandomSource::class => SystemRandomSource::class,
                    PasswordHasher::class => BcryptPasswordHasher::class,

                    // Console commands with no collaborator
                    ListManagementScopesCommand::class => ListManagementScopesCommand::class,
                ],
                'factories' => [
                    // Configuration and cross-cutting services
                    Settings::class => Container\SettingsFactory::class,
                    LoggerInterface::class => Container\LoggerFactory::class,
                    FilterServerRequestInterface::class => Container\ForwardedHeadersFilterFactory::class,

                    // Domain services and values
                    SecretGenerator::class => Container\SecretGeneratorFactory::class,
                    SigningAlgorithm::class => Container\SigningAlgorithmFactory::class,

                    // Use cases
                    GenerateEncryptionKey::class => Container\GenerateEncryptionKeyFactory::class,
                    DevelopmentAutoLogin::class => Container\DevelopmentAutoLoginFactory::class,
                    SeedDashboardClient::class => Container\SeedDashboardClientFactory::class,
                    ClientAuthenticator::class => Container\ClientAuthenticatorFactory::class,
                    ClientFailureThrottle::class => Container\ClientFailureThrottleFactory::class,
                    Authorize::class => Container\AuthorizeFactory::class,
                    AuthorizationRequestRules::class => Container\AuthorizationRequestRulesFactory::class,
                    PushAuthorizationRequest::class => Container\PushAuthorizationRequestFactory::class,
                    PushedAuthorizationRequestHandler::class
                        => Container\PushedAuthorizationRequestHandlerFactory::class,
                    HeldConsents::class => Container\HeldConsentsFactory::class,
                    DescribeConsent::class => Container\DescribeConsentFactory::class,
                    DecideConsent::class => Container\DecideConsentFactory::class,
                    AccessTokenMinter::class => Container\AccessTokenMinterFactory::class,
                    AuthorizationCodeGrant::class => Container\AuthorizationCodeGrantFactory::class,
                    RefreshTokenGrant::class => Container\RefreshTokenGrantFactory::class,
                    UserScope::class => Container\UserScopeFactory::class,
                    ClientCredentialsGrant::class => Container\ClientCredentialsGrantFactory::class,
                    RegisterMachineClient::class => Container\RegisterMachineClientFactory::class,
                    IssueToken::class => Container\IssueTokenFactory::class,
                    DeviceCodeGrant::class => Container\DeviceCodeGrantFactory::class,
                    ReadRequestedAccess::class => Container\ReadRequestedAccessFactory::class,
                    RequestDeviceAuthorization::class => Container\RequestDeviceAuthorizationFactory::class,
                    PendingDeviceRequests::class => Container\PendingDeviceRequestsFactory::class,
                    DescribeDeviceRequest::class => Container\DescribeDeviceRequestFactory::class,
                    DecideDeviceRequest::class => Container\DecideDeviceRequestFactory::class,
                    IssuedTokens::class => Container\IssuedTokensFactory::class,
                    IntrospectToken::class => Container\IntrospectTokenFactory::class,
                    RevokeToken::class => Container\RevokeTokenFactory::class,
                    SeedDevelopmentData::class => Container\SeedDevelopmentDataFactory::class,
                    SeedManagementAccess::class => Container\SeedManagementAccessFactory::class,
                    BuildAuthorizationUrl::class => Container\BuildAuthorizationUrlFactory::class,
                    Sessions::class => Container\SessionsFactory::class,
                    LoginThrottle::class => Container\LoginThrottleFactory::class,
                    UserCodeThrottle::class => Container\UserCodeThrottleFactory::class,
                    ResolveEndUser::class => Container\ResolveEndUserFactory::class,
                    SignInWithPassword::class => Container\SignInWithPasswordFactory::class,
                    SignOut::class => Container\SignOutFactory::class,
                    SignOutEverywhere::class => Container\SignOutEverywhereFactory::class,
                    BackChannelLogout::class => Container\BackChannelLogoutFactory::class,
                    BackChannelLogoutDelivery::class => Container\BackChannelLogoutDeliveryFactory::class,
                    AfterResponseTasks::class => Container\AfterResponseTasksFactory::class,
                    UserSessions::class => Container\UserSessionsFactory::class,
                    BackChannelLogoutRegistration::class => Container\BackChannelLogoutRegistrationFactory::class,
                    DescribeLoginPage::class => Container\DescribeLoginPageFactory::class,
                    CompactJws::class => Container\CompactJwsFactory::class,
                    IdTokenIssuer::class => Container\IdTokenIssuerFactory::class,
                    ProviderMetadata::class => Container\ProviderMetadataFactory::class,
                    PublishSigningKeys::class => Container\PublishSigningKeysFactory::class,
                    GenerateSigningKey::class => Container\GenerateSigningKeyFactory::class,
                    RotateSigningKey::class => Container\RotateSigningKeyFactory::class,
                    ListSigningKeys::class => Container\ListSigningKeysFactory::class,
                    ReadUserInfo::class => Container\ReadUserInfoFactory::class,
                    EndSession::class => Container\EndSessionFactory::class,
                    EndSessionHandler::class => Container\EndSessionHandlerFactory::class,
                    CompleteFirstFactor::class => Container\CompleteFirstFactorFactory::class,
                    ExternalIdentityRepository::class => Container\ExternalIdentityRepositoryFactory::class,
                    ExternalSignInStore::class => Container\ExternalSignInStoreFactory::class,
                    ProviderHttp::class => Container\ProviderHttpFactory::class,
                    BeginExternalSignIn::class => Container\BeginExternalSignInFactory::class,
                    ResolveExternalAccount::class => Container\ResolveExternalAccountFactory::class,
                    CompleteExternalSignIn::class => Container\CompleteExternalSignInFactory::class,
                    ExternalSignInHandler::class => Container\ExternalSignInHandlerFactory::class,
                    ExternalSignInCallbackHandler::class => Container\ExternalSignInCallbackHandlerFactory::class,
                    Mailer::class => Container\MailerFactory::class,
                    BreachedPasswords::class => Container\BreachedPasswordsFactory::class,
                    PasswordScreen::class => Container\PasswordScreenFactory::class,
                    MailOutbox::class => Container\MailOutboxFactory::class,
                    PasswordlessChallengeStore::class => Container\PasswordlessChallengeStoreFactory::class,
                    SignInMail::class => Container\SignInMailFactory::class,
                    DescribePasswordlessChallenge::class => Container\DescribePasswordlessChallengeFactory::class,
                    StartPasswordlessSignIn::class => Container\StartPasswordlessSignInFactory::class,
                    FinishPasswordlessSignIn::class => Container\FinishPasswordlessSignInFactory::class,
                    AnswerPasswordlessCode::class => Container\AnswerPasswordlessCodeFactory::class,
                    FollowPasswordlessLink::class => Container\FollowPasswordlessLinkFactory::class,
                    PasswordlessStartHandler::class => Container\PasswordlessStartHandlerFactory::class,
                    PasswordlessCodeHandler::class => Container\PasswordlessCodeHandlerFactory::class,
                    PasswordlessLinkHandler::class => Container\PasswordlessLinkHandlerFactory::class,
                    AccountLinkStore::class => Container\AccountLinkStoreFactory::class,
                    AccountMail::class => Container\AccountMailFactory::class,
                    SendAccountLink::class => Container\SendAccountLinkFactory::class,
                    SignUp::class => Container\SignUpFactory::class,
                    DescribeSignUpPage::class => Container\DescribeSignUpPageFactory::class,
                    ConfirmEmail::class => Container\ConfirmEmailFactory::class,
                    DescribeAccountLink::class => Container\DescribeAccountLinkFactory::class,
                    RequestPasswordReset::class => Container\RequestPasswordResetFactory::class,
                    ResetPassword::class => Container\ResetPasswordFactory::class,
                    SignUpHandler::class => Container\SignUpHandlerFactory::class,
                    VerifyEmailHandler::class => Container\VerifyEmailHandlerFactory::class,
                    PasswordForgotHandler::class => Container\PasswordForgotHandlerFactory::class,
                    PasswordResetHandler::class => Container\PasswordResetHandlerFactory::class,
                    ClientInterface::class => Container\HttpClientFactory::class,
                    IdentityProviders::class => Container\IdentityProvidersFactory::class,
                    IdTokenVerifier::class => Container\IdTokenVerifierFactory::class,
                    JwksCache::class => Container\JwksCacheFactory::class,
                    OutboundUrlPolicy::class => Container\OutboundUrlPolicyFactory::class,
                    OidcDiscovery::class => Container\OidcDiscoveryFactory::class,
                    ConnectionAccess::class => Container\ConnectionAccessFactory::class,
                    MfaFactorRepository::class => Container\MfaFactorRepositoryFactory::class,
                    PasskeyRepository::class => Container\PasskeyRepositoryFactory::class,
                    RecoveryCodeRepository::class => Container\RecoveryCodeRepositoryFactory::class,
                    MfaChallengeStore::class => Container\MfaChallengeStoreFactory::class,
                    TotpSeeds::class => Container\TotpSeedsFactory::class,
                    DescribeMfa::class => Container\DescribeMfaFactory::class,
                    BeginTotpEnrollment::class => Container\BeginTotpEnrollmentFactory::class,
                    ResumeTotpEnrollment::class => Container\ResumeTotpEnrollmentFactory::class,
                    ConfirmTotpEnrollment::class => Container\ConfirmTotpEnrollmentFactory::class,
                    DisableMfa::class => Container\DisableMfaFactory::class,
                    CompleteSecondFactor::class => Container\CompleteSecondFactorFactory::class,
                    DescribeSecondFactorPage::class => Container\DescribeSecondFactorPageFactory::class,
                    SecondFactors::class => Container\SecondFactorsFactory::class,
                    BeginStepUp::class => Container\BeginStepUpFactory::class,
                    DescribeEnrolmentOnTheWay::class => Container\DescribeEnrolmentOnTheWayFactory::class,
                    BeginEnrolmentOnTheWay::class => Container\BeginEnrolmentOnTheWayFactory::class,
                    FinishEnrolmentOnTheWay::class => Container\FinishEnrolmentOnTheWayFactory::class,
                    RequireSignIn::class => Container\RequireSignInFactory::class,
                    ResetUserMfa::class => Container\ResetUserMfaFactory::class,
                    SendPasswordLink::class => Container\SendPasswordLinkFactory::class,
                    MfaChallengeHandler::class => Container\MfaChallengeHandlerFactory::class,
                    ConsentHandler::class => Container\ConsentHandlerFactory::class,
                    MfaSettingsHandler::class => Container\MfaSettingsHandlerFactory::class,
                    PasskeysHandler::class => Container\PasskeysHandlerFactory::class,
                    BeginPasskeySecondFactor::class => Container\BeginPasskeySecondFactorFactory::class,
                    UsePasskey::class => Container\UsePasskeyFactory::class,
                    BeginPasskeySignIn::class => Container\BeginPasskeySignInFactory::class,
                    SignInWithPasskey::class => Container\SignInWithPasskeyFactory::class,
                    LoginForm::class => Container\LoginFormFactory::class,
                    PasskeySignInHandler::class => Container\PasskeySignInHandlerFactory::class,
                    CompletePasskeySecondFactor::class => Container\CompletePasskeySecondFactorFactory::class,
                    BeginPasskeyRegistration::class => Container\BeginPasskeyRegistrationFactory::class,
                    CompletePasskeyRegistration::class => Container\CompletePasskeyRegistrationFactory::class,
                    DescribePasskeys::class => Container\DescribePasskeysFactory::class,
                    RenamePasskey::class => Container\RenamePasskeyFactory::class,
                    RemovePasskey::class => Container\RemovePasskeyFactory::class,
                    RecentSignIn::class => Container\RecentSignInFactory::class,
                    RelyingParty::class => Container\RelyingPartyFactory::class,
                    UserMfaHandler::class => Container\UserMfaHandlerFactory::class,
                    UserPasskeysHandler::class => Container\UserPasskeysHandlerFactory::class,
                    ReadUserPasskeys::class => Container\ReadUserPasskeysFactory::class,
                    RemoveUserPasskey::class => Container\RemoveUserPasskeyFactory::class,
                    UserPasswordLinkHandler::class => Container\UserPasswordLinkHandlerFactory::class,
                    ReadUsers::class => Container\ReadUsersFactory::class,
                    CreateUser::class => Container\CreateUserFactory::class,
                    UpdateUser::class => Container\UpdateUserFactory::class,
                    DeleteUser::class => Container\DeleteUserFactory::class,
                    ReadClients::class => Container\ReadClientsFactory::class,
                    RegisterClient::class => Container\RegisterClientFactory::class,
                    ClientConnections::class => Container\ClientConnectionsFactory::class,
                    ReadConnections::class => Container\ReadConnectionsFactory::class,
                    OidcConfiguration::class => Container\OidcConfigurationFactory::class,
                    CreateConnection::class => Container\CreateConnectionFactory::class,
                    UpdateConnection::class => Container\UpdateConnectionFactory::class,
                    DeleteConnection::class => Container\DeleteConnectionFactory::class,
                    UpdateClient::class => Container\UpdateClientFactory::class,
                    RotateClientSecret::class => Container\RotateClientSecretFactory::class,
                    DeleteClient::class => Container\DeleteClientFactory::class,
                    ReadResourceServers::class => Container\ReadResourceServersFactory::class,
                    RegisterResourceServer::class => Container\RegisterResourceServerFactory::class,
                    UpdateResourceServer::class => Container\UpdateResourceServerFactory::class,
                    DeleteResourceServer::class => Container\DeleteResourceServerFactory::class,
                    GrantClientAccess::class => Container\GrantClientAccessFactory::class,
                    RegisterManagementApi::class => Container\RegisterManagementApiFactory::class,
                    AuthenticateManagementCaller::class => Container\AuthenticateManagementCallerFactory::class,
                    RolePermissions::class => Container\RolePermissionsFactory::class,
                    ReadRoles::class => Container\ReadRolesFactory::class,
                    CreateRole::class => Container\CreateRoleFactory::class,
                    UpdateRole::class => Container\UpdateRoleFactory::class,
                    DeleteRole::class => Container\DeleteRoleFactory::class,
                    RoleAssignments::class => Container\RoleAssignmentsFactory::class,
                    ReadRoleHolders::class => Container\ReadRoleHoldersFactory::class,
                    ReadEffectivePermissions::class => Container\ReadEffectivePermissionsFactory::class,
                    ReadConsents::class => Container\ReadConsentsFactory::class,
                    ReadIdentities::class => Container\ReadIdentitiesFactory::class,
                    UnlinkIdentity::class => Container\UnlinkIdentityFactory::class,
                    WithdrawConsent::class => Container\WithdrawConsentFactory::class,
                    EnsureRole::class => Container\EnsureRoleFactory::class,
                    AssignRole::class => Container\AssignRoleFactory::class,

                    // Secondary adapters, each registered under the port it implements
                    Database::class => Container\DatabaseFactory::class,
                    TransactionManager::class => Container\TransactionManagerFactory::class,
                    SchemaMigrator::class => Container\SchemaMigratorFactory::class,
                    RedisConnection::class => Container\RedisConnectionFactory::class,
                    SecretCipher::class => Container\SecretCipherFactory::class,
                    UserRepository::class => Container\UserRepositoryFactory::class,
                    ClientRepository::class => Container\ClientRepositoryFactory::class,
                    ConnectionRepository::class => Container\ConnectionRepositoryFactory::class,
                    AuthorizationCodeRepository::class => Container\AuthorizationCodeRepositoryFactory::class,
                    AccessTokenRepository::class => Container\AccessTokenRepositoryFactory::class,
                    RefreshTokenRepository::class => Container\RefreshTokenRepositoryFactory::class,
                    ResourceServerRepository::class => Container\ResourceServerRepositoryFactory::class,
                    ClientGrantRepository::class => Container\ClientGrantRepositoryFactory::class,
                    RoleRepository::class => Container\RoleRepositoryFactory::class,
                    ConsentRepository::class => Container\ConsentRepositoryFactory::class,
                    LoginStateStore::class => Container\LoginStateStoreFactory::class,
                    PushedAuthorizationRequestStore::class => Container\PushedAuthorizationRequestStoreFactory::class,
                    ConsentStateStore::class => Container\ConsentStateStoreFactory::class,
                    WebAuthnChallengeStore::class => Container\WebAuthnChallengeStoreFactory::class,
                    PasskeyVerifier::class => Container\PasskeyVerifierFactory::class,
                    DeviceAuthorizationStore::class => Container\DeviceAuthorizationStoreFactory::class,
                    SessionStore::class => Container\SessionStoreFactory::class,
                    AttemptCounter::class => Container\AttemptCounterFactory::class,
                    NonceRegistry::class => Container\NonceRegistryFactory::class,
                    TokenSigner::class => Container\TokenSignerFactory::class,
                    AuditLog::class => Container\AuditLogFactory::class,
                    Audit::class => Container\AuditFactory::class,
                    AuthenticationTrail::class => Container\AuthenticationTrailFactory::class,
                    AuthorizationTrail::class => Container\AuthorizationTrailFactory::class,
                    ConfigurationTrail::class => Container\ConfigurationTrailFactory::class,
                    DirectoryTrail::class => Container\DirectoryTrailFactory::class,
                    DomainEvents::class => Container\DomainEventsFactory::class,
                    ReadAuditEvents::class => Container\ReadAuditEventsFactory::class,
                    PurgeAuditEvents::class => Container\PurgeAuditEventsFactory::class,
                    AuditContextMiddleware::class => Container\AuditContextMiddlewareFactory::class,
                    AuditEventsHandler::class => Container\AuditEventsHandlerFactory::class,
                    PurgeAuditEventsCommand::class => Container\PurgeAuditEventsCommandFactory::class,
                    PublicKeyCache::class => Container\PublicKeyCacheFactory::class,
                    Container\SigningHttpClientFactory::SERVICE => Container\SigningHttpClientFactory::class,
                    SigningKeyStore::class => Container\SigningKeyStoreFactory::class,

                    // Primary adapter: HTTP
                    HealthHandler::class => Container\HealthHandlerFactory::class,
                    NotFoundHandler::class => Container\NotFoundHandlerFactory::class,
                    MethodNotAllowedMiddleware::class => Container\MethodNotAllowedMiddlewareFactory::class,
                    MezzioErrorResponseGenerator::class => Container\ErrorResponseGeneratorFactory::class,
                    PageRenderer::class => Container\PageRendererFactory::class,
                    ErrorResponder::class => Container\ErrorResponderFactory::class,
                    OAuth2Responder::class => Container\OAuth2ResponderFactory::class,
                    AuthorizeHandler::class => Container\AuthorizeHandlerFactory::class,
                    TokenHandler::class => Container\TokenHandlerFactory::class,
                    DeviceAuthorizationHandler::class => Container\DeviceAuthorizationHandlerFactory::class,
                    DeviceHandler::class => Container\DeviceHandlerFactory::class,
                    IntrospectionHandler::class => Container\IntrospectionHandlerFactory::class,
                    RevocationHandler::class => Container\RevocationHandlerFactory::class,
                    AuthCookies::class => Container\AuthCookiesFactory::class,
                    AuthPageResponder::class => Container\AuthPageResponderFactory::class,
                    LoginPageHandler::class => Container\LoginPageHandlerFactory::class,
                    LoginHandler::class => Container\LoginHandlerFactory::class,
                    LogoutHandler::class => Container\LogoutHandlerFactory::class,
                    ThemeHandler::class => Container\ThemeHandlerFactory::class,
                    BearerChallenger::class => Container\BearerChallengerFactory::class,
                    DiscoveryHandler::class => Container\DiscoveryHandlerFactory::class,
                    JwksHandler::class => Container\JwksHandlerFactory::class,
                    UserInfoHandler::class => Container\UserInfoHandlerFactory::class,
                    ManagementContract::class => Container\ManagementContractFactory::class,
                    ManagementResponder::class => Container\ManagementResponderFactory::class,
                    ManagementApiMiddleware::class => Container\ManagementApiMiddlewareFactory::class,
                    UsersHandler::class => Container\UsersHandlerFactory::class,
                    UserHandler::class => Container\UserHandlerFactory::class,
                    ClientsHandler::class => Container\ClientsHandlerFactory::class,
                    ClientHandler::class => Container\ClientHandlerFactory::class,
                    RotateClientSecretHandler::class => Container\RotateClientSecretHandlerFactory::class,
                    ResourceServersHandler::class => Container\ResourceServersHandlerFactory::class,
                    ResourceServerHandler::class => Container\ResourceServerHandlerFactory::class,
                    RolesHandler::class => Container\RolesHandlerFactory::class,
                    RoleHandler::class => Container\RoleHandlerFactory::class,
                    RoleUsersHandler::class => Container\RoleUsersHandlerFactory::class,
                    UserRolesHandler::class => Container\UserRolesHandlerFactory::class,
                    UserPermissionsHandler::class => Container\UserPermissionsHandlerFactory::class,
                    UserConsentsHandler::class => Container\UserConsentsHandlerFactory::class,
                    UserSessionsHandler::class => Container\UserSessionsHandlerFactory::class,
                    UserIdentitiesHandler::class => Container\UserIdentitiesHandlerFactory::class,
                    ConnectionsHandler::class => Container\ConnectionsHandlerFactory::class,
                    ConnectionHandler::class => Container\ConnectionHandlerFactory::class,
                    ClientConnectionsHandler::class => Container\ClientConnectionsHandlerFactory::class,

                    // Primary adapter: CLI
                    ConsoleApplication::class => Container\ConsoleApplicationFactory::class,
                    ShowConfigCommand::class => Container\ShowConfigCommandFactory::class,
                    MigrateDatabaseCommand::class => Container\MigrateDatabaseCommandFactory::class,
                    DatabaseStatusCommand::class => Container\DatabaseStatusCommandFactory::class,
                    GenerateEncryptionKeyCommand::class => Container\GenerateEncryptionKeyCommandFactory::class,
                    SeedDevelopmentDataCommand::class => Container\SeedDevelopmentDataCommandFactory::class,
                    AuthorizeUrlCommand::class => Container\AuthorizeUrlCommandFactory::class,
                    GenerateSigningKeyCommand::class => Container\GenerateSigningKeyCommandFactory::class,
                    RotateSigningKeyCommand::class => Container\RotateSigningKeyCommandFactory::class,
                    ListSigningKeysCommand::class => Container\ListSigningKeysCommandFactory::class,
                    CreateMachineClientCommand::class => Container\CreateMachineClientCommandFactory::class,
                    GrantClientAccessCommand::class => Container\GrantClientAccessCommandFactory::class,
                    RegisterManagementApiCommand::class => Container\RegisterManagementApiCommandFactory::class,
                    CreateRoleCommand::class => Container\CreateRoleCommandFactory::class,
                    AssignRoleCommand::class => Container\AssignRoleCommandFactory::class,
                    ListRolesCommand::class => Container\ListRolesCommandFactory::class,
                    MailOutboxCommand::class => Container\MailOutboxCommandFactory::class,
                ],
                // A port whose adapter is also asked for by its own name: one instance.
                'aliases' => [
                    // The entry point runs the tasks; the application only defers them.
                    DeferredTasks::class => AfterResponseTasks::class,
                    OutboundUrls::class => OutboundUrlPolicy::class,
                ],
            ],
            // The server-rendered pages: `layout::page`, `auth::login`, `error::page`,
            // `partial::field`…
            // laminas-view's PhpRenderer, through Mezzio's TemplateRendererInterface.
            'templates' => [
                'extension' => 'phtml',
                'paths' => [
                    'layout' => [self::TEMPLATES . '/layout'],
                    'auth' => [self::TEMPLATES . '/auth'],
                    'error' => [self::TEMPLATES . '/error'],
                    'partial' => [self::TEMPLATES . '/partial'],
                ],
            ],
        ];
    }
}
