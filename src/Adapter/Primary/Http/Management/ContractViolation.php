<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Primary\Http\Management;

use Phayne\OpenAPI\Validator\Message\Exception\Validation\InvalidBody;
use Phayne\OpenAPI\Validator\Message\Exception\Validation\InvalidParameter;
use Phayne\OpenAPI\Validator\Message\Exception\Validation\RequiredParameterMissing;
use Phayne\OpenAPI\Validator\Message\Exception\ValidationFailed;
use Phayne\OpenAPI\Validator\Schema\Exception\SchemaMismatch;

/**
 * A request the contract refused, as the problem document the caller gets back: 422,
 * with an `errors` entry saying where — an RFC 6901 pointer into the body, or the name
 * of the parameter — and why, in the validator's words.
 *
 * The validator stops at the first mismatch, so there is one entry. Nothing in it comes
 * from the server's state, and the value at fault is never repeated: the validator quotes
 * it in its message, and it may be a password.
 */
final class ContractViolation
{
    public const string DETAIL = "The request does not satisfy the API's contract.";

    private function __construct()
    {
    }

    public static function problem(ValidationFailed $failure): Problem
    {
        $parameter = null;
        $mismatch = null;
        for ($cause = $failure; $cause !== null; $cause = $cause->getPrevious()) {
            if ($cause instanceof InvalidParameter || $cause instanceof RequiredParameterMissing) {
                $parameter ??= $cause->name;
            }
            if ($cause instanceof SchemaMismatch) {
                $mismatch = $cause;
            }
        }

        $detail = match (true) {
            $mismatch !== null => self::redact(self::describe($mismatch), $mismatch->data),
            $failure instanceof RequiredParameterMissing => 'This parameter is required.',
            default => self::describe($failure),
        };

        if ($failure instanceof InvalidBody) {
            $error = ['pointer' => self::pointer($mismatch), 'detail' => $detail];
        } elseif ($parameter !== null) {
            $error = ['parameter' => $parameter, 'detail' => $detail];
        } else {
            $error = ['detail' => $detail];
        }

        return new Problem(422, self::DETAIL, [$error]);
    }

    /** The validator's message, without the prefix it puts on every keyword failure. */
    private static function describe(\Throwable $cause): string
    {
        $message = trim(preg_replace('/^Keyword validation failed:\s*/', '', $cause->getMessage()) ?? '');

        return $message === '' ? 'Not what the contract describes.' : $message;
    }

    /**
     * The message with the quoted value at fault replaced by an ellipsis.
     */
    private static function redact(string $message, mixed $value): string
    {
        $text = is_scalar($value) ? (string) $value : '';
        if ($text === '') {
            return $message;
        }

        return str_replace(["'" . $text . "'", '"' . $text . '"'], ["'…'", '"…"'], $message);
    }

    /**
     * Where in the body the mismatch is: RFC 6901, `~` and `/` escaped, the empty
     * string for the document itself.
     */
    private static function pointer(?SchemaMismatch $mismatch): string
    {
        $pointer = '';
        /** @var list<int|string|null> $chain */
        $chain = $mismatch?->dataBreadCrumb?->buildChain() ?? [];
        foreach ($chain as $token) {
            if ($token === null) {
                continue;
            }
            $pointer .= '/' . strtr((string) $token, ['~' => '~0', '/' => '~1']);
        }

        return $pointer;
    }
}
