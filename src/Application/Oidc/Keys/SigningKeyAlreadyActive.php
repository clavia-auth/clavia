<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Oidc\Keys;

use Clavia\Domain\Oidc\SigningKey;
use RuntimeException;

/**
 * A key is already active, so creating one would be a rotation.
 */
final class SigningKeyAlreadyActive extends RuntimeException
{
    public static function for(SigningKey $active): self
    {
        return new self(sprintf(
            'Signing key %s is already active. Run `clavia keys:rotate` to replace it: a rotation keeps it '
            . 'published until the tokens it signed have expired.',
            $active->kid(),
        ));
    }
}
