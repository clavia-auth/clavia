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
use Clavia\Adapter\Primary\Cli\DatabaseStatusCommand;
use Clavia\Adapter\Primary\Cli\GenerateEncryptionKeyCommand;
use Clavia\Adapter\Primary\Cli\MigrateDatabaseCommand;
use Clavia\Adapter\Primary\Cli\SeedDevelopmentDataCommand;
use Clavia\Adapter\Primary\Cli\ShowConfigCommand;
use Clavia\Adapter\Primary\Http\Auth\AuthCookies;
use Clavia\Adapter\Primary\Http\Auth\AuthPageResponder;
use Clavia\Adapter\Primary\Http\Auth\LoginHandler;
use Clavia\Adapter\Primary\Http\Auth\LoginPageHandler;
use Clavia\Adapter\Primary\Http\Auth\LogoutHandler;
use Clavia\Adapter\Primary\Http\Auth\ThemeHandler;
use Clavia\Adapter\Primary\Http\OAuth2\AuthorizeHandler;
use Clavia\Adapter\Primary\Http\OAuth2\OAuth2Responder;
use Clavia\Adapter\Primary\Http\OAuth2\TokenHandler;
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
use Clavia\Application\Authentication\ResolveEndUser;
use Clavia\Application\Authentication\Sessions;
use Clavia\Application\Authentication\SignIn\SignInWithPassword;
use Clavia\Application\Authentication\SignOut;
use Clavia\Application\Development\BuildAuthorizationUrl;
use Clavia\Application\Development\SeedDevelopmentData;
use Clavia\Application\OAuth2\Authorize\Authorize;
use Clavia\Application\OAuth2\ClientAuthentication\ClientAuthenticator;
use Clavia\Application\OAuth2\Token\AuthorizationCodeGrant;
use Clavia\Application\OAuth2\Token\IssueToken;
use Clavia\Application\Port\AttemptCounter;
use Clavia\Application\Port\LoginStateStore;
use Clavia\Application\Port\PasswordHasher;
use Clavia\Application\Port\SchemaMigrator;
use Clavia\Application\Port\SecretCipher;
use Clavia\Application\Port\SessionStore;
use Clavia\Application\Port\TransactionManager;
use Clavia\Application\Secrets\GenerateEncryptionKey;
use Clavia\Configuration\Settings;
use Clavia\Domain\Client\ClientRepository;
use Clavia\Domain\Identity\UserRepository;
use Clavia\Domain\OAuth2\AccessTokenRepository;
use Clavia\Domain\OAuth2\AuthorizationCodeRepository;
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
                ],
                'factories' => [
                    // Configuration and cross-cutting services
                    Settings::class => Container\SettingsFactory::class,
                    LoggerInterface::class => Container\LoggerFactory::class,
                    FilterServerRequestInterface::class => Container\ForwardedHeadersFilterFactory::class,

                    // Domain services
                    SecretGenerator::class => Container\SecretGeneratorFactory::class,

                    // Use cases
                    GenerateEncryptionKey::class => Container\GenerateEncryptionKeyFactory::class,
                    DevelopmentAutoLogin::class => Container\DevelopmentAutoLoginFactory::class,
                    ClientAuthenticator::class => Container\ClientAuthenticatorFactory::class,
                    Authorize::class => Container\AuthorizeFactory::class,
                    AuthorizationCodeGrant::class => Container\AuthorizationCodeGrantFactory::class,
                    IssueToken::class => Container\IssueTokenFactory::class,
                    SeedDevelopmentData::class => Container\SeedDevelopmentDataFactory::class,
                    BuildAuthorizationUrl::class => Container\BuildAuthorizationUrlFactory::class,
                    Sessions::class => Container\SessionsFactory::class,
                    LoginThrottle::class => Container\LoginThrottleFactory::class,
                    ResolveEndUser::class => Container\ResolveEndUserFactory::class,
                    SignInWithPassword::class => Container\SignInWithPasswordFactory::class,
                    SignOut::class => Container\SignOutFactory::class,
                    DescribeLoginPage::class => Container\DescribeLoginPageFactory::class,

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
                    LoginStateStore::class => Container\LoginStateStoreFactory::class,
                    SessionStore::class => Container\SessionStoreFactory::class,
                    AttemptCounter::class => Container\AttemptCounterFactory::class,

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

                    // Primary adapter: CLI
                    ConsoleApplication::class => Container\ConsoleApplicationFactory::class,
                    ShowConfigCommand::class => Container\ShowConfigCommandFactory::class,
                    MigrateDatabaseCommand::class => Container\MigrateDatabaseCommandFactory::class,
                    DatabaseStatusCommand::class => Container\DatabaseStatusCommandFactory::class,
                    GenerateEncryptionKeyCommand::class => Container\GenerateEncryptionKeyCommandFactory::class,
                    SeedDevelopmentDataCommand::class => Container\SeedDevelopmentDataCommandFactory::class,
                    AuthorizeUrlCommand::class => Container\AuthorizeUrlCommandFactory::class,
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
