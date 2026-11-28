<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Authorization\Evaluation;

use Clavia\Application\Authorization\SpeaksForNoApi;
use Clavia\Application\Authorization\SpokenForApi;
use Clavia\Application\Port\AccessCheck;
use Clavia\Application\Port\DecisionEngine;
use Clavia\Application\Port\DecisionEngineFailed;
use Clavia\Domain\Authorization\AuthorizationSettings;
use Clavia\Domain\Authorization\SubjectRef;
use Clavia\Domain\Client\ClientId;
use Clavia\Domain\ResourceServer\ResourceServer;
use Clavia\Domain\Shared\InvalidValue;

/**
 * AuthZEN's Access Evaluation and Access Evaluations (docs/design/fine-grained-authorization.md §5.2;
 * AuthZEN 1.0 §6, §7), answered from the store of the API the caller's client speaks for.
 *
 * For each question, in order, before the engine is asked anything:
 *
 *  1. the subject is a person (`user`) or an application (`client`), a type the model declares; the
 *     resource is of a type the model declares and that can be related to (not `user` or `client`);
 *     the action is a relation of that type; the context has no `clavia` member;
 *  2. the subject exists in Clavia: an active account, or an existing application. Otherwise the
 *     answer is a denial (`subject_inactive`), and OpenFGA is not asked: a leaver is out at once,
 *     whatever the store still says;
 *  3. Clavia's facts about the subject join the context as `clavia.subject` ({@see SubjectFacts}),
 *     read once per subject per request.
 *
 * Then the engine answers every question left in one batch. A question that fails step 1 is a `400`
 * alone ({@see self::one()}), and in a batch a denial carrying its error (AuthZEN §7.2.1). A question
 * the engine refuses to answer (a condition reading a parameter that is not there: OpenFGA's
 * `validation_error`) is a denial, `condition_failed`: fail closed, for that question alone, so a batch
 * the engine refuses is asked again one question at a time. The engine not answering at all is
 * {@see DecisionEngineFailed}, never a decision. Reasons go only to an API that asked.
 */
final readonly class EvaluateAccess
{
    /** The most questions in one request (§2, "Limits"). */
    public const int MAX_EVALUATIONS = 50;

    public function __construct(
        private SpokenForApi $apis,
        private DecisionEngine $engine,
        private SubjectFacts $facts,
    ) {
    }

    /**
     * One question (AuthZEN 1.0 §6).
     *
     * @throws SpeaksForNoApi
     * @throws EvaluationRefused When it cannot be asked: a `400`.
     * @throws DecisionEngineFailed
     */
    public function one(ClientId $caller, EvaluationRequest $question): Decision
    {
        [$api, $settings] = $this->apis->of($caller);
        $check = $this->prepare($settings, $question);
        $context = $this->contextFor($api, $question);
        if ($context === null) {
            return $this->told($settings, Decision::deny(DenialReason::SubjectInactive));
        }

        return $this->told($settings, $this->answer($settings, self::with($check, $context)));
    }

    /**
     * A batch (AuthZEN 1.0 §7): the answers in the order asked, up to where the semantic stops.
     *
     * @param list<EvaluationRequest> $questions At most {@see self::MAX_EVALUATIONS}.
     *
     * @return list<Decision>
     *
     * @throws SpeaksForNoApi
     * @throws DecisionEngineFailed
     */
    public function many(ClientId $caller, array $questions, EvaluationSemantic $semantic): array
    {
        [$api, $settings] = $this->apis->of($caller);
        if (count($questions) > self::MAX_EVALUATIONS) {
            throw new InvalidValue(sprintf('At most %d evaluations are asked at once.', self::MAX_EVALUATIONS));
        }

        /** @var array<int, Decision> $decisions */
        $decisions = [];
        /** @var array<int, AccessCheck> $asked */
        $asked = [];
        $facts = [];
        foreach ($questions as $index => $question) {
            try {
                $check = $this->prepare($settings, $question);
            } catch (EvaluationRefused $refusal) {
                $decisions[$index] = Decision::failed($refusal);
                continue;
            }
            $key = $question->subjectType . ':' . $question->subjectId;
            $facts[$key] ??= $this->facts->of($api, $question->subjectType, $question->subjectId) ?? false;
            if ($facts[$key] === false) {
                $decisions[$index] = Decision::deny(DenialReason::SubjectInactive);
                continue;
            }
            $asked[$index] = self::with($check, $question->context + ['clavia' => ['subject' => $facts[$key]]]);
        }

        if ($asked !== []) {
            try {
                $answers = $this->engine->batchCheck($settings->store, $settings->modelId, array_values($asked));
                foreach (array_keys($asked) as $at => $index) {
                    $decisions[$index] = ($answers[$at] ?? false)
                        ? Decision::permit()
                        : Decision::deny(DenialReason::NoRelation);
                }
            } catch (DecisionEngineFailed $failed) {
                if ($failed->refusal === null) {
                    throw $failed;
                }
                // One question the engine could not evaluate: each asked alone, so only it is denied for it.
                foreach ($asked as $index => $check) {
                    $decisions[$index] = $this->answer($settings, $check);
                }
            }
        }
        ksort($decisions);

        $answered = [];
        foreach ($decisions as $decision) {
            $answered[] = $this->told($settings, $decision);
            if (
                ($semantic === EvaluationSemantic::DenyOnFirstDeny && ! $decision->decision)
                || ($semantic === EvaluationSemantic::PermitOnFirstPermit && $decision->decision)
            ) {
                break;
            }
        }

        return $answered;
    }

    /**
     * The question as the engine will be asked it, without its context yet.
     *
     * @throws EvaluationRefused
     */
    private function prepare(AuthorizationSettings $settings, EvaluationRequest $question): AccessCheck
    {
        QuestionRules::context($question->context);
        $model = $settings->model;
        $subjectType = QuestionRules::subjectType($model, $question->subjectType);
        $resourceType = QuestionRules::resourceType($model, $question->resourceType);
        $relation = QuestionRules::relation($model, $resourceType, $question->action);

        return AccessCheck::of(
            QuestionRules::object($resourceType, $question->resourceId),
            $relation,
            SubjectRef::object(QuestionRules::object($subjectType, $question->subjectId)),
        );
    }

    /**
     * The engine's answer to one question; a question it refuses to evaluate is denied.
     *
     * @throws DecisionEngineFailed When it gives no answer at all.
     */
    private function answer(AuthorizationSettings $settings, AccessCheck $check): Decision
    {
        try {
            return $this->engine->check($settings->store, $settings->modelId, $check)
                ? Decision::permit()
                : Decision::deny(DenialReason::NoRelation);
        } catch (DecisionEngineFailed $failed) {
            if ($failed->refusal === null) {
                throw $failed;
            }

            return Decision::deny(DenialReason::ConditionFailed);
        }
    }

    /** @return array<string, mixed>|null The question's context with Clavia's facts; null for a subject not to ask about. */
    private function contextFor(ResourceServer $api, EvaluationRequest $question): ?array
    {
        $facts = $this->facts->of($api, $question->subjectType, $question->subjectId);

        return $facts === null ? null : $question->context + ['clavia' => ['subject' => $facts]];
    }

    /** @param array<string, mixed> $context */
    private static function with(AccessCheck $check, array $context): AccessCheck
    {
        return AccessCheck::of($check->object, $check->relation, $check->subject, $context);
    }

    /** A denial's kind only for an API that turned reasons on; an error always. */
    private function told(AuthorizationSettings $settings, Decision $decision): Decision
    {
        return $settings->denialReasons ? $decision : $decision->withoutReason();
    }
}
