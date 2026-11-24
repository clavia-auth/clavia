<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Management\Users\Import;

use Clavia\Domain\Connection\ConnectionName;
use Clavia\Domain\Identity\User;

/**
 * The port through which an account is imported, one at a time, whatever brought it: a line of an
 * import job (\Clavia\Application\Management\Users\Jobs\RunUserJobs), a message from a queue
 * (`clavia users:import-sqs`). One set of rules for every way in ({@see ImportUser}).
 */
interface UserImport
{
    /**
     * Create the account `$line` describes in `$pool`, or say why not.
     *
     * @param string $line The JSON object of one account, as an import line holds it ({@see ImportLine}).
     */
    public function import(#[\SensitiveParameter] string $line, ConnectionName $pool): User|ImportRefusal;
}
