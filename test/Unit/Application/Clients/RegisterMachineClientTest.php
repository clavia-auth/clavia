<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Application\Clients;

use Clavia\Adapter\Primary\Cli\CreateMachineClientCommand;
use Clavia\Application\Clients\RegisterMachineClient;
use Clavia\Domain\Client\ClientAuthMethod;
use Clavia\Domain\Client\ClientType;
use Clavia\Domain\Client\GrantType;
use Clavia\Domain\Shared\InvalidValue;
use Clavia\Domain\Shared\SecretGenerator;
use ClaviaTest\Support\Fake\FakePasswordHasher;
use ClaviaTest\Support\Fake\FrozenClock;
use ClaviaTest\Support\Fake\InMemoryClientRepository;
use ClaviaTest\Support\Fake\SeededRandomSource;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Tester\CommandTester;

/**
 * `clavia clients:create-m2m` and the use case behind it.
 */
final class RegisterMachineClientTest extends TestCase
{
    private InMemoryClientRepository $clients;
    private FakePasswordHasher $hasher;
    private RegisterMachineClient $register;

    #[\Override]
    protected function setUp(): void
    {
        $this->clients = new InMemoryClientRepository();
        $this->hasher = new FakePasswordHasher();
        $this->register = new RegisterMachineClient(
            $this->clients,
            $this->hasher,
            new SecretGenerator(new SeededRandomSource(1)),
            new FrozenClock(),
        );
    }

    public function testAMachineClientIsConfidentialAndCanOnlyUseClientCredentials(): void
    {
        $registered = ($this->register)('Billing worker');

        $stored = $this->clients->find($registered->client->id);
        self::assertNotNull($stored);
        self::assertSame('Billing worker', $stored->name);
        self::assertSame(ClientType::Confidential, $stored->type);
        self::assertSame(ClientAuthMethod::ClientSecretBasic, $stored->authMethod);
        self::assertSame([GrantType::ClientCredentials], $stored->grantTypes);
        self::assertSame([], $stored->redirectUris);
        self::assertSame([], $stored->responseTypes);
    }

    public function testTheGeneratedSecretIsReturnedOnceAndStoredHashed(): void
    {
        $registered = ($this->register)('Billing worker');

        self::assertTrue($registered->secretGenerated);
        self::assertSame(43, strlen($registered->secret));
        $hash = (string) $this->clients->find($registered->client->id)?->secretHash();
        self::assertNotSame($registered->secret, $hash);
        self::assertTrue($this->hasher->verify($registered->secret, $hash));
    }

    public function testEveryCallRegistersAnotherClient(): void
    {
        $first = ($this->register)('Worker');
        $second = ($this->register)('Worker');

        self::assertFalse($first->client->id->equals($second->client->id));
    }

    public function testAChosenSecretIsUsedWhenItIsLongEnough(): void
    {
        $registered = ($this->register)('Worker', str_repeat('s', 32));

        self::assertFalse($registered->secretGenerated);
        self::assertSame(str_repeat('s', 32), $registered->secret);
    }

    public function testAChosenSecretThatIsTooShortOrTooLongIsRefused(): void
    {
        foreach ([str_repeat('s', 31), str_repeat('s', 73)] as $secret) {
            try {
                ($this->register)('Worker', $secret);
                self::fail('The secret was accepted.');
            } catch (InvalidValue $refusal) {
                self::assertNotSame('', $refusal->getMessage());
            }
        }

        self::assertSame([], $this->clients->all());
    }

    public function testTheCommandPrintsTheIdAndTheSecretAndHowToUseThem(): void
    {
        $tester = new CommandTester(new CreateMachineClientCommand($this->register, 'https://auth.clavia.test'));

        self::assertSame(Command::SUCCESS, $tester->execute(['name' => 'Billing worker']));

        $display = $tester->getDisplay(true);
        $client = $this->clients->all()[0] ?? null;
        self::assertNotNull($client);
        self::assertStringContainsString('Registered confidential client "Billing worker"', $display);
        self::assertStringContainsString("client_id:     {$client->id->value}", $display);
        self::assertMatchesRegularExpression('/client_secret: [A-Za-z0-9_-]{43}\n/', $display);
        self::assertStringContainsString('the only time it can be shown', $display);
        self::assertStringContainsString('curl -s https://auth.clavia.test/oauth2/token', $display);
        self::assertStringContainsString('-d grant_type=client_credentials', $display);
    }

    public function testTheCommandReportsARefusedSecretInsteadOfATrace(): void
    {
        $tester = new CommandTester(new CreateMachineClientCommand($this->register, 'https://auth.clavia.test'));

        self::assertSame(Command::FAILURE, $tester->execute(['name' => 'Worker', '--secret' => 'short']));
        self::assertStringContainsString('at least 32 characters', $tester->getDisplay(true));
    }
}
