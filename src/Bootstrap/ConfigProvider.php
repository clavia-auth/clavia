<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap;

use Clavia\Application\Port\PasswordHasher;
use Clavia\Application\Port\SchemaMigrator;
use Clavia\Application\Port\SecretCipher;
use Clavia\Application\Port\TransactionManager;
use Clavia\Application\Secrets\GenerateEncryptionKey;
use Clavia\Configuration\Settings;
use Clavia\Domain\Shared\Clock;
use Clavia\Domain\Shared\RandomSource;
use Clavia\Domain\Shared\SecretGenerator;
use Clavia\Infrastructure\Crypto\BcryptPasswordHasher;
use Clavia\Infrastructure\Persistence\PhpDb\Database;
use Clavia\Infrastructure\Redis\RedisConnection;
use Clavia\Infrastructure\System\SystemClock;
use Clavia\Infrastructure\System\SystemRandomSource;
use Clavia\Ui\Cli\DatabaseStatusCommand;
use Clavia\Ui\Cli\GenerateEncryptionKeyCommand;
use Clavia\Ui\Cli\MigrateDatabaseCommand;
use Clavia\Ui\Cli\ShowConfigCommand;
use Clavia\Ui\Http\Shared\ErrorResponseGenerator;
use Clavia\Ui\Http\Shared\HealthHandler;
use Clavia\Ui\Http\Shared\JsonResponder;
use Clavia\Ui\Http\Shared\MethodNotAllowedMiddleware;
use Clavia\Ui\Http\Shared\NotFoundHandler;
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
    public const array CONSOLE_COMMANDS = [
        'config' => ShowConfigCommand::class,
        'db:migrate' => MigrateDatabaseCommand::class,
        'db:status' => DatabaseStatusCommand::class,
        'secrets:generate-key' => GenerateEncryptionKeyCommand::class,
    ];

    /**
     * @return array{dependencies: array<string, array<string, string>>}
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

                    // Driven adapters, each registered under the port it implements
                    Database::class => Container\DatabaseFactory::class,
                    TransactionManager::class => Container\TransactionManagerFactory::class,
                    SchemaMigrator::class => Container\SchemaMigratorFactory::class,
                    RedisConnection::class => Container\RedisConnectionFactory::class,
                    SecretCipher::class => Container\SecretCipherFactory::class,

                    // Driving adapter: HTTP
                    JsonResponder::class => Container\JsonResponderFactory::class,
                    HealthHandler::class => Container\HealthHandlerFactory::class,
                    NotFoundHandler::class => Container\NotFoundHandlerFactory::class,
                    MethodNotAllowedMiddleware::class => Container\MethodNotAllowedMiddlewareFactory::class,
                    MezzioErrorResponseGenerator::class => Container\ErrorResponseGeneratorFactory::class,

                    // Driving adapter: CLI
                    ConsoleApplication::class => Container\ConsoleApplicationFactory::class,
                    ShowConfigCommand::class => Container\ShowConfigCommandFactory::class,
                    MigrateDatabaseCommand::class => Container\MigrateDatabaseCommandFactory::class,
                    DatabaseStatusCommand::class => Container\DatabaseStatusCommandFactory::class,
                    GenerateEncryptionKeyCommand::class => Container\GenerateEncryptionKeyCommandFactory::class,
                ],
            ],
        ];
    }
}
