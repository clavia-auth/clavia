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
 * An answer (AuthZEN 1.0 §5.5): `decision`, and on a denial, when the API asked for reasons, its kind
 * alone — never who or what would have granted it. A question in a batch that could not be asked at
 * all is a denial carrying its error (§7.2.1): it defaults to closed.
 */
final readonly class Decision
{
    private function __construct(
        public bool $decision,
        public ?DenialReason $reason = null,
        /** For a question that could not be asked: the status it would have had alone, and why. */
        public ?int $errorStatus = null,
        public ?string $errorMessage = null,
    ) {
    }

    public static function permit(): self
    {
        return new self(true);
    }

    public static function deny(DenialReason $reason): self
    {
        return new self(false, $reason);
    }

    public static function failed(EvaluationRefused $refusal): self
    {
        return new self(false, $refusal->reason, 400, $refusal->getMessage());
    }

    /** The same decision, its reason dropped: what an API that asked for none is told. */
    public function withoutReason(): self
    {
        return new self($this->decision, null, $this->errorStatus, $this->errorMessage);
    }
}
