<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Management\Users\Jobs;

use Clavia\Application\Audit\AuditContext;
use Clavia\Application\Management\Users\ProfileFields;
use Clavia\Application\Port\DomainEvents;
use Clavia\Application\Port\TransactionManager;
use Clavia\Domain\Identity\Event\UserCreated;
use Clavia\Domain\Identity\Jobs\LineError;
use Clavia\Domain\Identity\Jobs\UserJob;
use Clavia\Domain\Identity\Jobs\UserJobRepository;
use Clavia\Domain\Identity\Profile;
use Clavia\Domain\Identity\User;
use Clavia\Domain\Identity\UserId;
use Clavia\Domain\Identity\UserRepository;
use Clavia\Domain\Shared\AlreadyExists;
use Clavia\Domain\Shared\Clock;
use Clavia\Domain\Shared\InvalidValue;
use Clavia\Domain\Shared\RandomSource;

/**
 * `clavia jobs:run`: runs the queued bulk jobs on the users, one after another, then exits. Meant
 * for a scheduler, every minute; two runs at once never share a job ({@see UserJobRepository::claimNext()}).
 *
 * An import takes its lines in order, each in a transaction of its own: a refused line (unreadable,
 * a field the API would refuse, an address already in the pool) is reported by number and the
 * rest carry on, and an account is made with everything it needs or not at all. Each account is a
 * `UserCreated`, recorded in the trail as the work of whoever queued the job.
 *
 * Before taking new work it fails the jobs still running past {@see STALL_AFTER_SECONDS}, whose worker
 * stopped; after, it deletes the jobs finished more than {@see RETENTION_DAYS} days ago.
 */
final readonly class RunUserJobs
{
    /** A job running longer than this has lost its worker: 10,000 lines take seconds. */
    public const int STALL_AFTER_SECONDS = 3600;

    /** How long a finished job's report is kept. */
    public const int RETENTION_DAYS = 7;

    /** The report is saved every so many lines, so a reader sees it move. */
    private const int SAVE_EVERY = 100;

    public function __construct(
        private UserJobRepository $jobs,
        private UserRepository $users,
        private ImportLine $lines,
        private TransactionManager $transactions,
        private AuditContext $audit,
        private RandomSource $random,
        private Clock $clock,
        private DomainEvents $events,
    ) {
    }

    public function __invoke(): JobsRun
    {
        $stalled = 0;
        $now = $this->clock->now();
        foreach ($this->jobs->runningSince($now->modify(sprintf('-%d seconds', self::STALL_AFTER_SECONDS))) as $job) {
            $job->fail('The worker running it stopped before the end; queue the lines it did not take again.', $now);
            $this->jobs->save($job);
            ++$stalled;
        }

        $completed = 0;
        while (($job = $this->jobs->claimNext($this->clock->now())) !== null) {
            $this->import($job);
            ++$completed;
        }

        $purged = $this->jobs->purgeFinishedBefore(
            $this->clock->now()->modify(sprintf('-%d days', self::RETENTION_DAYS)),
        );

        return new JobsRun($completed, $stalled, $purged);
    }

    private function import(UserJob $job): void
    {
        $this->audit->actAs($job->requestedBy);
        $number = 0;
        foreach (preg_split('/\r?\n/', $job->input() ?? '') ?: [] as $line) {
            ++$number;
            if (trim($line) === '') {
                continue;
            }
            $read = $this->lines->read($line, $number);
            $outcome = $read instanceof LineError ? $read : $this->create($job, $read, $number);
            $outcome === null ? $job->recordCreated() : $job->recordRefused($outcome);
            if ($job->total() % self::SAVE_EVERY === 0) {
                $this->jobs->save($job);
            }
        }

        $job->complete($this->clock->now());
        $this->jobs->save($job);
    }

    /**
     * @param positive-int $number
     *
     * @return LineError|null Null when the account was made.
     */
    private function create(UserJob $job, ImportedAccount $account, int $number): ?LineError
    {
        try {
            $this->transactions->transactional(function () use ($job, $account): void {
                $now = $this->clock->now();
                if ($this->users->findByEmail($job->connection, $account->email) !== null) {
                    throw new AlreadyExists('An account in this pool has that address.');
                }
                $user = User::register(
                    UserId::generate($this->random),
                    $account->email,
                    $account->passwordHash,
                    $now,
                    $job->connection,
                );
                $user->changeProfile(ProfileFields::apply(Profile::empty(), $account->profile), $now);
                $user->recordEmailVerification($account->emailVerified, $now);
                if (! $account->isActive) {
                    $user->deactivate($now);
                }
                $this->users->save($user);
                $this->events->dispatch(new UserCreated($user));
            });
        } catch (AlreadyExists) {
            // An import only creates: an account already there, its password and its verified address
            // included, is never touched.
            return new LineError($number, 'already_exists', 'An account in this pool has that address.');
        } catch (InvalidValue $refusal) {
            // The domain's rules state the rule, never the value.
            $detail = $refusal->getMessage();

            return new LineError($number, 'invalid_field', $detail !== '' ? $detail : 'A field is not acceptable.');
        }

        return null;
    }
}
