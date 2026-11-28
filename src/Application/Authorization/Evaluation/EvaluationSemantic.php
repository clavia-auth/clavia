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
 * How a batch is answered (AuthZEN 1.0 §7.1.2.1, `options.evaluations_semantic`).
 */
enum EvaluationSemantic: string
{
    /** Every question answered (the default). */
    case ExecuteAll = 'execute_all';
    /** Answers up to the first denial or failure, which is the last one given: an `&&`. */
    case DenyOnFirstDeny = 'deny_on_first_deny';
    /** Answers up to the first permit, which is the last one given: an `||`. */
    case PermitOnFirstPermit = 'permit_on_first_permit';
}
