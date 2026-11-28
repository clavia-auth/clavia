<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Authorization\Evaluation;

/**
 * What kind of denial it is (docs/design/fine-grained-authorization.md §2, "Answers"), returned only
 * to an API that turned reasons on, and only the kind.
 */
enum DenialReason: string
{
    /** The engine found no relationship granting it. */
    case NoRelation = 'no_relation';
    /** The subject is a person whose account is deactivated or unknown, or an application that does not exist. */
    case SubjectInactive = 'subject_inactive';
    /** A type the API's model does not declare, or a relation its type does not. */
    case UnknownType = 'unknown_type';
    /**
     * A condition of the model could not be evaluated: a parameter it reads is missing (an
     * `app_metadata` key the person does not have, a context member the API did not send). Denied,
     * as the engine could not grant it.
     */
    case ConditionFailed = 'condition_failed';
}
