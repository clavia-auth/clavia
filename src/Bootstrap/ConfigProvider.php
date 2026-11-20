<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap;

use Clavia\Adapter\Primary\Cli\AuthorizeUrlCommand;
use Clavia\Adapter\Primary\Cli\CreateMachineClientCommand;
use Clavia\Adapter\Primary\Cli\DatabaseStatusCommand;
use Clavia\Adapter\Primary\Cli\GenerateEncryptionKeyCommand;
use Clavia\Adapter\Primary\Cli\GenerateSigningKeyCommand;
use Clavia\Adapter\Primary\Cli\GrantClientAccessCommand;
use Clavia\Adapter\Primary\Cli\ListManagementScopesCommand;
use Clavia\Adapter\Primary\Cli\ListSigningKeysCommand;
use Clavia\Adapter\Primary\Cli\MigrateDatabaseCommand;
use Clavia\Adapter\Primary\Cli\RegisterManagementApiCommand;
use Clavia\Adapter\Primary\Cli\RotateSigningKeyCommand;
use Clavia\Adapter\Primary\Cli\SeedDevelopmentDataCommand;
use Clavia\Adapter\Primary\Cli\ShowConfigCommand;
use Clavia\Adapter\Primary\Http\Auth\AuthCookies;
use Clavia\Adapter\Primary\Http\Auth\AuthPageResponder;
use Clavia\Adapter\Primary\Http\Auth\LoginHandler;
use Clavia\Adapter\Primary\Http\Auth\LoginPageHandler;
use Clavia\Adapter\Primary\Http\Auth\LogoutHandler;
use Clavia\Adapter\Primary\Http\Auth\MfaChallengeHandler;
use Clavia\Adapter\Primary\Http\Auth\MfaSettingsHandler;
use Clavia\Adapter\Primary\Http\Auth\ThemeHandler;
use Clavia\Adapter\Primary\Http\Management\ClientHandler;
use Clavia\Adapter\Primary\Http\Management\ClientsHandler;
use Clavia\Adapter\Primary\Http\Management\ManagementApiMiddleware;
use Clavia\Adapter\Primary\Http\Management\ManagementContract;
use Clavia\Adapter\Primary\Http\Management\ManagementResponder;
use Clavia\Adapter\Primary\Http\Management\ResourceServerHandler;
use Clavia\Adapter\Primary\Http\Management\ResourceServersHandler;
use Clavia\Adapter\Primary\Http\Management\RotateClientSecretHandler;
use Clavia\Adapter\Primary\Http\Management\UserHandler;
use Clavia\Adapter\Primary\Http\Management\UserMfaHandler;
use Clavia\Adapter\Primary\Http\Management\UsersHandler;
use Clavia\Adapter\Primary\Http\OAuth2\AuthorizeHandler;
use Clavia\Adapter\Primary\Http\OAuth2\OAuth2Responder;
use Clavia\Adapter\Primary\Http\OAuth2\TokenHandler;
use Clavia\Adapter\Primary\Http\Oidc\DiscoveryHandler;
use Clavia\Adapter\Primary\Http\Oidc\JwksHandler;
use Clavia\Adapter\Primary\Http\Oidc\UserInfoHandler;
use Clavia\Adapter\Primary\Http\Shared\BearerChallenger;
use Clavia\Adapter\Primary\Http\Shared\ErrorResponder;
use Clavia\Adapter\Primary\Http\Shared\ErrorResponseGenerator;
use Clavia\Adapter\Primary\Http\Shared\HealthHandler;
use Clavia\Adapter\Primary\Http\Shared\MethodNotAllowedMiddleware;
use Clavia\Adapter\Primary\Http\Shared\NotFoundHandler;
use Clavia\Adapter\Primary\Http\Shared\PageRenderer;
use Clavia\Adapter\Secondary\Crypto\BcryptPasswordHasher;
use Clavia\Adapter\Secondary\Persistence\PhpDb\Database;
use Clavia\Adapter\Secondary\Redis\RedisConnection;
use Clavia\Adapter\Secondary\System\SystemClock;
use Clavia\Adapter\Secondary\System\SystemRandomSource;
use Clavia\Application\Authentication\DevelopmentAutoLogin;
use Clavia\Application\Authentication\LoginPage\DescribeLoginPage;
use Clavia\Application\Authentication\LoginThrottle;
use Clavia\Application\Authentication\Mfa\BeginTotpEnrollment;
use Clavia\Application\Authentication\Mfa\CompleteSecondFactor;
use Clavia\Application\Authentication\Mfa\ConfirmTotpEnrollment;
use Clavia\Application\Authentication\Mfa\DescribeMfa;
use Clavia\Application\Authentication\Mfa\DescribeSecondFactorPage;
use Clavia\Application\Authentication\Mfa\DisableMfa;
use Clavia\Application\Authentication\Mfa\ResumeTotpEnrollment;
use Clavia\Application\Authentication\Mfa\TotpSeeds;
use Clavia\Application\Authentication\RequireSignIn;
use Clavia\Application\Authentication\ResolveEndUser;
use Clavia\Application\Authentication\Sessions;
use Clavia\Application\Authentication\SignIn\SignInWithPassword;
use Clavia\Application\Authentication\SignOut;
use Clavia\Application\Clients\RegisterMachineClient;
use Clavia\Application\Development\BuildAuthorizationUrl;
use Clavia\Application\Development\SeedDevelopmentData;
use Clavia\Application\Development\SeedManagementAccess;
use Clavia\Application\Management\Caller\AuthenticateManagementCaller;
use Clavia\Application\Management\Clients\DeleteClient;
use Clavia\Application\Management\Clients\ReadClients;
use Clavia\Application\Management\Clients\RegisterClient;
use Clavia\Application\Management\Clients\RotateClientSecret;
use Clavia\Application\Management\Clients\UpdateClient;
use Clavia\Application\Management\Provisioning\GrantClientAccess;
use Clavia\Application\Management\Provisioning\RegisterManagementApi;
use Clavia\Application\Management\ResourceServers\DeleteResourceServer;
use Clavia\Application\Management\ResourceServers\ReadResourceServers;
use Clavia\Application\Management\ResourceServers\RegisterResourceServer;
use Clavia\Application\Management\ResourceServers\UpdateResourceServer;
use Clavia\Application\Management\Users\CreateUser;
use Clavia\Application\Management\Users\DeleteUser;
use Clavia\Application\Management\Users\ReadUsers;
use Clavia\Application\Management\Users\ResetUserMfa;
use Clavia\Application\Management\Users\UpdateUser;
use Clavia\Application\OAuth2\Authorize\Authorize;
use Clavia\Application\OAuth2\ClientAuthentication\ClientAuthenticator;
use Clavia\Application\OAuth2\Token\AuthorizationCodeGrant;
use Clavia\Application\OAuth2\Token\ClientCredentialsGrant;
use Clavia\Application\OAuth2\Token\IssueToken;
use Clavia\Application\Oidc\CompactJws;
use Clavia\Application\Oidc\Discovery\ProviderMetadata;
use Clavia\Application\Oidc\IdTokenIssuer;
use Clavia\Application\Oidc\Keys\GenerateSigningKey;
use Clavia\Application\Oidc\Keys\ListSigningKeys;
use Clavia\Application\Oidc\Keys\PublishSigningKeys;
use Clavia\Application\Oidc\Keys\RotateSigningKey;
use Clavia\Application\Oidc\UserInfo\ReadUserInfo;
use Clavia\Application\Port\AttemptCounter;
use Clavia\Application\Port\LoginStateStore;
use Clavia\Application\Port\MfaChallengeStore;
use Clavia\Application\Port\NonceRegistry;
use Clavia\Application\Port\PasswordHasher;
use Clavia\Application\Port\SchemaMigrator;
use Clavia\Application\Port\SecretCipher;
use Clavia\Application\Port\SessionStore;
use Clavia\Application\Port\SigningKeyStore;
use Clavia\Application\Port\TokenSigner;
use Clavia\Application\Port\TransactionManager;
use Clavia\Application\Secrets\GenerateEncryptionKey;
use Clavia\Configuration\Settings;
use Clavia\Domain\Authentication\Mfa\MfaFactorRepository;
use Clavia\Domain\Authentication\Mfa\RecoveryCodeRepository;
use Clavia\Domain\Client\ClientRepository;
use Clavia\Domain\Identity\UserRepository;
use Clavia\Domain\OAuth2\AccessTokenRepository;
use Clavia\Domain\OAuth2\AuthorizationCodeRepository;
use Clavia\Domain\Oidc\SigningAlgorithm;
use Clavia\Domain\ResourceServer\ClientGrantRepository;
use Clavia\Domain\ResourceServer\ResourceServerRepository;
use Clavia\Domain\Shared\Clock;
use Clavia\Domain\Shared\RandomSource;
use Clavia\Domain\Shared\SecretGenerator;
use Laminas\Diactoros\ResponseFactory;
use Laminas\Diactoros\ServerRequestFilter\FilterServerRequestInterface;
use Laminas\Diactoros\StreamFactory;
use Mezzio\Middleware\ErrorResponseGenerator as MezzioErrorResponseGenerator;
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
    /**
     * Console commands, by the name they are run with. Loaded lazily: `clavia config`
     * does not construct the collaborators of every other command.
     */
    private const string TEMPLATES = __DIR__ . '/../../templates';

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
                    ClientAuthenticator::class => Container\ClientAuthenticatorFactory::class,
                    Authorize::class => Container\AuthorizeFactory::class,
                    AuthorizationCodeGrant::class => Container\AuthorizationCodeGrantFactory::class,
                    ClientCredentialsGrant::class => Container\ClientCredentialsGrantFactory::class,
                    RegisterMachineClient::class => Container\RegisterMachineClientFactory::class,
                    IssueToken::class => Container\IssueTokenFactory::class,
                    SeedDevelopmentData::class => Container\SeedDevelopmentDataFactory::class,
                    SeedManagementAccess::class => Container\SeedManagementAccessFactory::class,
                    BuildAuthorizationUrl::class => Container\BuildAuthorizationUrlFactory::class,
                    Sessions::class => Container\SessionsFactory::class,
                    LoginThrottle::class => Container\LoginThrottleFactory::class,
                    ResolveEndUser::class => Container\ResolveEndUserFactory::class,
                    SignInWithPassword::class => Container\SignInWithPasswordFactory::class,
                    SignOut::class => Container\SignOutFactory::class,
                    DescribeLoginPage::class => Container\DescribeLoginPageFactory::class,
                    CompactJws::class => Container\CompactJwsFactory::class,
                    IdTokenIssuer::class => Container\IdTokenIssuerFactory::class,
                    ProviderMetadata::class => Container\ProviderMetadataFactory::class,
                    PublishSigningKeys::class => Container\PublishSigningKeysFactory::class,
                    GenerateSigningKey::class => Container\GenerateSigningKeyFactory::class,
                    RotateSigningKey::class => Container\RotateSigningKeyFactory::class,
                    ListSigningKeys::class => Container\ListSigningKeysFactory::class,
                    ReadUserInfo::class => Container\ReadUserInfoFactory::class,
                    MfaFactorRepository::class => Container\MfaFactorRepositoryFactory::class,
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
                    RequireSignIn::class => Container\RequireSignInFactory::class,
                    ResetUserMfa::class => Container\ResetUserMfaFactory::class,
                    MfaChallengeHandler::class => Container\MfaChallengeHandlerFactory::class,
                    MfaSettingsHandler::class => Container\MfaSettingsHandlerFactory::class,
                    UserMfaHandler::class => Container\UserMfaHandlerFactory::class,
                    ReadUsers::class => Container\ReadUsersFactory::class,
                    CreateUser::class => Container\CreateUserFactory::class,
                    UpdateUser::class => Container\UpdateUserFactory::class,
                    DeleteUser::class => Container\DeleteUserFactory::class,
                    ReadClients::class => Container\ReadClientsFactory::class,
                    RegisterClient::class => Container\RegisterClientFactory::class,
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

                    // Secondary adapters, each registered under the port it implements
                    Database::class => Container\DatabaseFactory::class,
                    TransactionManager::class => Container\TransactionManagerFactory::class,
                    SchemaMigrator::class => Container\SchemaMigratorFactory::class,
                    RedisConnection::class => Container\RedisConnectionFactory::class,
                    SecretCipher::class => Container\SecretCipherFactory::class,
                    UserRepository::class => Container\UserRepositoryFactory::class,
                    ClientRepository::class => Container\ClientRepositoryFactory::class,
                    AuthorizationCodeRepository::class => Container\AuthorizationCodeRepositoryFactory::class,
                    AccessTokenRepository::class => Container\AccessTokenRepositoryFactory::class,
                    ResourceServerRepository::class => Container\ResourceServerRepositoryFactory::class,
                    ClientGrantRepository::class => Container\ClientGrantRepositoryFactory::class,
                    LoginStateStore::class => Container\LoginStateStoreFactory::class,
                    SessionStore::class => Container\SessionStoreFactory::class,
                    AttemptCounter::class => Container\AttemptCounterFactory::class,
                    NonceRegistry::class => Container\NonceRegistryFactory::class,
                    TokenSigner::class => Container\TokenSignerFactory::class,
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
