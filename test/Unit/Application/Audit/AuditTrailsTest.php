<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Application\Audit;

use Clavia\Application\Audit\AuditContext;
use Clavia\Application\Audit\Trail\AuthenticationTrail;
use Clavia\Application\Audit\Trail\AuthorizationTrail;
use Clavia\Application\Audit\Trail\ConfigurationTrail;
use Clavia\Application\Audit\Trail\DirectoryTrail;
use Clavia\Application\Event\EventSubscriber;
use Clavia\Domain\Audit\Actor;
use Clavia\Domain\Audit\ActorKind;
use Clavia\Domain\Audit\AuditEvent;
use Clavia\Domain\Audit\AuditEventType;
use Clavia\Domain\Audit\Outcome;
use Clavia\Domain\Authentication\AuthenticationMethod;
use Clavia\Domain\Authentication\Event\SecondFactorRemoved;
use Clavia\Domain\Authentication\Event\SessionEndReason;
use Clavia\Domain\Authentication\Event\SessionsEnded;
use Clavia\Domain\Authentication\Event\SignedIn;
use Clavia\Domain\Authentication\Event\SignInRefusal;
use Clavia\Domain\Authentication\Event\SignInRefused;
use Clavia\Domain\Authentication\Session;
use Clavia\Domain\Client\ClientId;
use Clavia\Domain\Client\Event\ClientConnectionsChanged;
use Clavia\Domain\Client\Event\ClientRegistered;
use Clavia\Domain\Client\GrantType;
use Clavia\Domain\Connection\ConnectionName;
use Clavia\Domain\Identity\Event\UserChanged;
use Clavia\Domain\Identity\UserId;
use Clavia\Domain\OAuth2\AccessToken;
use Clavia\Domain\OAuth2\AccessTokenId;
use Clavia\Domain\OAuth2\Event\AccessTokenIssued;
use Clavia\Domain\OAuth2\Event\RefreshTokenReplayed;
use Clavia\Domain\Rbac\Event\UserRolesReplaced;
use Clavia\Domain\Rbac\RoleId;
use Clavia\Domain\Shared\Audience;
use Clavia\Domain\Shared\Digest;
use Clavia\Domain\Shared\DomainEvent;
use Clavia\Domain\Shared\ScopeSet;
use ClaviaTest\Support\Audits;
use ClaviaTest\Support\Clients;
use ClaviaTest\Support\Fake\FrozenClock;
use ClaviaTest\Support\Fake\InMemoryAuditLog;
use ClaviaTest\Support\Fake\InMemoryDomainEvents;
use ClaviaTest\Support\Fake\SeededRandomSource;
use PHPUnit\Framework\TestCase;
use ReflectionClass;

/**
 * What the audit trails write for the domain events — and that no event goes unrecorded.
 *
 * The use cases' tests check the events they dispatch; the acceptance tests read the
 * trail through the Management API. This sits between: the mapping itself, event by
 * event where the mapping decides something (the actor, the outcome, what is left out).
 */
final class AuditTrailsTest extends TestCase
{
    private FrozenClock $clock;
    private InMemoryAuditLog $log;
    private AuditContext $context;
    private InMemoryDomainEvents $events;
    private UserId $person;

    #[\Override]
    protected function setUp(): void
    {
        $this->clock = new FrozenClock('2026-01-15T10:00:00Z');
        $this->log = new InMemoryAuditLog();
        $this->context = new AuditContext();
        $this->events = new InMemoryDomainEvents(...self::trails($this->log, $this->clock, $this->context));
        $this->person = UserId::generate(new SeededRandomSource(5));
    }

    public function testEveryDomainEventIsRecordedByExactlyOneTrail(): void
    {
        $subscribed = [];
        foreach (self::trails(new InMemoryAuditLog(), $this->clock, $this->context) as $trail) {
            foreach (array_keys($trail->subscriptions()) as $class) {
                $subscribed[] = $class;
            }
        }

        self::assertSame(array_unique($subscribed), $subscribed, 'An event recorded twice.');
        $missing = array_values(array_diff(self::domainEvents(), $subscribed));
        self::assertSame([], $missing, 'Domain events no trail records.');
    }

    public function testASignInIsThePersonsAndARefusalNobodys(): void
    {
        $this->events->dispatch(new SignedIn($this->session()));
        $this->events->dispatch(new SignInRefused(
            AuthenticationMethod::Password,
            SignInRefusal::WrongPassword,
            $this->person,
            'ada@example.com',
            ClientId::fromString('spa'),
        ));

        $signedIn = $this->only(AuditEventType::SignedIn);
        self::assertSame(ActorKind::Person, $signedIn->actor->kind);
        self::assertSame(['amr' => ['pwd'], 'connection' => 'password', 'sid' => 'sid-1'], $signedIn->details);

        $refused = $this->only(AuditEventType::SignInFailed);
        self::assertSame(Outcome::Failure, $refused->outcome);
        self::assertSame(ActorKind::Anonymous, $refused->actor->kind);
        self::assertSame('spa', $refused->actor->clientId?->value);
        self::assertSame($this->person->value, $refused->target?->id);
        self::assertSame(
            ['method' => 'pwd', 'reason' => 'wrong_password', 'email' => 'ada@example.com'],
            $refused->details,
        );
    }

    public function testASessionEndedByThePersonIsTheirsAndOtherwiseTheCallers(): void
    {
        $operator = UserId::generate(new SeededRandomSource(6));
        $this->context->actAs(Actor::person($operator, ClientId::fromString('dashboard')));

        $this->events->dispatch(new SessionsEnded(
            SessionEndReason::RpInitiatedLogout,
            [$this->session()],
            ClientId::fromString('spa'),
        ));
        $this->events->dispatch(new SessionsEnded(SessionEndReason::EndedEverywhere, [
            $this->session(),
            $this->session(),
        ]));

        $ended = $this->log->ofType(AuditEventType::SessionEnded);
        self::assertCount(3, $ended);
        [$logout, $first, $second] = [$ended[0], $ended[1], $ended[2]];
        self::assertSame($this->person->value, $logout->actor->userId?->value);
        self::assertSame('spa', $logout->actor->clientId?->value);
        self::assertSame(['reason' => 'rp_initiated_logout', 'sid' => 'sid-1'], $logout->details);
        self::assertSame($operator->value, $first->actor->userId?->value);
        self::assertSame($operator->value, $second->actor->userId?->value);
        self::assertSame('ended_everywhere', $second->details['reason'] ?? null);
    }

    public function testAResetSecondFactorIsTheOperatorsAndSaysSo(): void
    {
        $this->events->dispatch(new SecondFactorRemoved($this->person, byTheirOwner: false));

        $removed = $this->only(AuditEventType::MfaRemoved);
        self::assertSame(ActorKind::System, $removed->actor->kind);
        self::assertSame(['factor' => 'totp', 'reset' => true], $removed->details);
    }

    public function testAMachineTokenNamesTheMachineAndNeverTheToken(): void
    {
        $token = AccessToken::issueToClient(
            AccessTokenId::generate(new SeededRandomSource(7)),
            Digest::of('the-token-itself'),
            ClientId::fromString('m2m'),
            Audience::fromString('https://api.example/'),
            ScopeSet::fromString('read:things'),
            $this->clock->now(),
            3600,
        );

        $this->events->dispatch(new AccessTokenIssued($token, GrantType::ClientCredentials, false));

        $issued = $this->only(AuditEventType::TokenIssued);
        self::assertSame(ActorKind::Application, $issued->actor->kind);
        self::assertSame(['type' => 'client', 'id' => 'm2m'], [
            'type' => $issued->target?->type->value,
            'id' => $issued->target?->id,
        ]);
        self::assertSame([
            'grant_type' => 'client_credentials',
            'client_id' => 'm2m',
            'scope' => 'read:things',
            'audience' => 'https://api.example/',
            'refreshable' => false,
        ], $issued->details);
    }

    public function testAReplayIsAFailureByWhoeverPresentedIt(): void
    {
        $this->events->dispatch(new RefreshTokenReplayed(
            $this->person,
            ClientId::fromString('spa'),
            ClientId::fromString('spa'),
        ));

        $replayed = $this->only(AuditEventType::RefreshTokenReplayed);
        self::assertSame(Outcome::Failure, $replayed->outcome);
        self::assertSame(ActorKind::Anonymous, $replayed->actor->kind);
        self::assertSame(['client_id' => 'spa', 'presented_by' => 'spa'], $replayed->details);
    }

    public function testAdministrationIsTheCallersAndListsWhatChangedOnly(): void
    {
        $this->context->begin('198.51.100.4', 'Mozilla/5.0');
        $this->context->actAs(Actor::application(ClientId::fromString('m2m')));

        $this->events->dispatch(new ClientRegistered(Clients::public('spa')));
        $this->events->dispatch(new ClientConnectionsChanged(
            ClientId::fromString('spa'),
            [ConnectionName::defaultPool(), ConnectionName::email()],
        ));
        $this->events->dispatch(new UserChanged($this->person, ['email', 'has_password'], true));
        $role = RoleId::fromString('rol_aaaaaaaaaaaaaaaa');
        $this->events->dispatch(new UserRolesReplaced($this->person, [$role]));

        $created = $this->only(AuditEventType::ClientCreated);
        self::assertSame('m2m', $created->actor->clientId?->value);
        self::assertSame('198.51.100.4', $created->clientAddress);
        self::assertSame('public', $created->details['client_type'] ?? null);
        self::assertTrue($created->details['first_party'] ?? null);
        self::assertSame(
            ['fields' => ['connections'], 'connections' => ['password', 'email']],
            $this->only(AuditEventType::ClientUpdated)->details,
        );
        self::assertSame(
            ['fields' => ['email', 'has_password'], 'deactivated' => true],
            $this->only(AuditEventType::UserUpdated)->details,
        );
        self::assertSame(['roles' => [$role->value]], $this->only(AuditEventType::UserRolesChanged)->details);
    }

    /**
     * @return list<EventSubscriber>
     */
    private static function trails(InMemoryAuditLog $log, FrozenClock $clock, AuditContext $context): array
    {
        $audit = Audits::into($log, $clock, $context);

        return [
            new AuthenticationTrail($audit),
            new AuthorizationTrail($audit),
            new ConfigurationTrail($audit),
            new DirectoryTrail($audit),
        ];
    }

    /**
     * Every class under `src/Domain` that implements {@see DomainEvent}.
     *
     * @return list<class-string>
     */
    private static function domainEvents(): array
    {
        $events = [];
        $files = glob(dirname(__DIR__, 4) . '/src/Domain/*/Event/*.php');
        self::assertNotFalse($files);
        foreach ($files as $file) {
            $class = 'Clavia\\Domain\\' . basename(dirname($file, 2)) . '\\Event\\' . basename($file, '.php');
            self::assertTrue(class_exists($class) || enum_exists($class), $class);
            if (class_exists($class) && new ReflectionClass($class)->implementsInterface(DomainEvent::class)) {
                $events[] = $class;
            }
        }
        self::assertNotSame([], $events);

        return $events;
    }

    private function only(AuditEventType $type): AuditEvent
    {
        $events = $this->log->ofType($type);
        self::assertCount(1, $events, $type->value);

        return $events[0];
    }

    private function session(): Session
    {
        return Session::reconstitute(
            $this->person,
            $this->clock->now()->modify('-1 hour'),
            $this->clock->now()->modify('+1 hour'),
            [AuthenticationMethod::Password],
            'sid-1',
            ConnectionName::defaultPool(),
            [],
        );
    }
}
