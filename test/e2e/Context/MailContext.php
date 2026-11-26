<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\E2e\Context;

use Behat\Behat\Context\Context;
use Behat\Behat\Hook\Scope\BeforeScenarioScope;
use Behat\Hook\BeforeScenario;
use Behat\Step\Then;
use Fig\Http\Message\RequestMethodInterface;
use GuzzleHttp\Client;

/**
 * What the stack mailed, read back from Mailpit: the message to the scenario's person, who it is from,
 * and the link in it. Mail is sent after the response, so a message is waited for, never assumed.
 */
/**
 * @psalm-suppress PropertyNotSetInConstructor The scenario's hook gathers what this context shares.
 */
final class MailContext implements Context
{
    private const int WAIT_SECONDS = 20;

    private Client $mailbox;
    private ManagementContext $management;
    private ?Message $message = null;

    /**
     * @psalm-suppress PossiblyUnusedMethod Behat builds the context
     */
    public function __construct()
    {
        $this->mailbox = new Client(['http_errors' => false, 'timeout' => 10]);
    }

    #[BeforeScenario]
    public function gather(BeforeScenarioScope $scope): void
    {
        $this->management = Contexts::of($scope, ManagementContext::class);
    }

    /** The link the message carries, on the authorization server's host: its path and query. */
    public function link(): string
    {
        $message = $this->message ?? throw new \LogicException('No message: add a Then step that waits for one.');
        $pattern = '#https://auth\.clavia\.test(/auth/[a-z/-]+\?token=[A-Za-z0-9_-]+)#';
        Check::same(1, preg_match($pattern, $message->text, $match), 'no link in the message: ' . $message->text);

        return Stack::fromEnvironment()->authUrl($match[1]);
    }

    #[Then('an email arrives for the person')]
    public function anEmailArrivesForThePerson(): void
    {
        $address = $this->management->person()->email;
        $deadline = microtime(true) + (float) self::WAIT_SECONDS;
        do {
            $message = $this->latestTo($address);
            if ($message !== null) {
                $this->message = $message;

                return;
            }
            usleep(250_000);
        } while (microtime(true) < $deadline);

        throw new \RuntimeException(sprintf('No email for %s within %d seconds.', $address, self::WAIT_SECONDS));
    }

    #[Then('it comes from :address')]
    public function itComesFrom(string $address): void
    {
        Check::same($address, $this->message()->from);
    }

    #[Then('its subject says :words')]
    public function itsSubjectSays(string $words): void
    {
        Check::includes($words, $this->message()->subject, 'the subject');
    }

    #[Then('it carries a link to :path')]
    public function itCarriesALinkTo(string $path): void
    {
        Check::startsWith(Stack::fromEnvironment()->authUrl($path . '?token='), $this->link());
    }

    private function message(): Message
    {
        return $this->message ?? throw new \LogicException('No message: add a Then step that waits for one.');
    }

    private function latestTo(string $address): ?Message
    {
        $stack = Stack::fromEnvironment();
        $found = $this->mailbox->request(
            RequestMethodInterface::METHOD_GET,
            $stack->mailUrl('/api/v1/search?' . http_build_query(['query' => 'to:"' . $address . '"', 'limit' => 1])),
        );
        Check::same(200, $found->getStatusCode(), 'Mailpit: ' . (string) $found->getBody());
        /** @var array{messages?: list<array{ID: string}>} $result */
        $result = json_decode((string) $found->getBody(), true, flags: JSON_THROW_ON_ERROR);
        $id = $result['messages'][0]['ID'] ?? null;
        if ($id === null) {
            return null;
        }

        $read = $this->mailbox->request(RequestMethodInterface::METHOD_GET, $stack->mailUrl('/api/v1/message/' . $id));
        Check::same(200, $read->getStatusCode(), 'Mailpit: ' . (string) $read->getBody());
        /** @var array{From: array{Address: string}, Subject: string, Text: string} $body */
        $body = json_decode((string) $read->getBody(), true, flags: JSON_THROW_ON_ERROR);

        return new Message($body['From']['Address'], $body['Subject'], $body['Text']);
    }
}
