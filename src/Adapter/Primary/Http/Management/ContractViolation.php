<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Primary\Http\Management;

use Clavia\Adapter\Primary\Http\OpenApi\Validation\Location;
use Clavia\Adapter\Primary\Http\OpenApi\Validation\MalformedRequest;
use Clavia\Adapter\Primary\Http\OpenApi\Validation\RequestRejected;
use Clavia\Adapter\Primary\Http\OpenApi\Validation\UnsupportedMediaType;
use Clavia\Adapter\Primary\Http\OpenApi\Validation\Violation;
use Fig\Http\Message\StatusCodeInterface;

/**
 * A request the contract refused, as the problem document the caller gets back: 400
 * when it could not be read, 415 for a body that is not JSON, 422 for one that does not
 * satisfy the document — with an `errors` entry per violation saying where (an RFC 6901
 * `pointer` into the body, or the `parameter`) and why.
 *
 * Nothing in it comes from the server's state, and no value the caller sent is repeated
 * ({@see Violation}).
 */
final class ContractViolation
{
    public const string DETAIL = "The request does not satisfy the API's contract.";

    /** Enough to fix a request; a body with thousands of faults does not need them all listed. */
    private const int MAX_ERRORS = 50;

    private function __construct()
    {
    }

    public static function problem(RequestRejected $rejection): Problem
    {
        [$status, $detail] = match (true) {
            $rejection instanceof MalformedRequest => [
                StatusCodeInterface::STATUS_BAD_REQUEST,
                'The request cannot be read.',
            ],
            $rejection instanceof UnsupportedMediaType => [
                StatusCodeInterface::STATUS_UNSUPPORTED_MEDIA_TYPE,
                $rejection->getMessage(),
            ],
            default => [StatusCodeInterface::STATUS_UNPROCESSABLE_ENTITY, self::DETAIL],
        };

        return new Problem($status, $detail, array_map(
            self::error(...),
            array_slice($rejection->violations, 0, self::MAX_ERRORS),
        ));
    }

    /**
     * @return array{pointer?: string, parameter?: string, detail: string}
     */
    private static function error(Violation $violation): array
    {
        if ($violation->location === Location::Body) {
            return ['pointer' => $violation->pointer, 'detail' => $violation->message];
        }
        if ($violation->name !== null) {
            return ['parameter' => $violation->name, 'detail' => $violation->message];
        }

        return ['detail' => $violation->message];
    }
}
