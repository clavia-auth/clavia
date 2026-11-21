<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Port;

/**
 * The last messages the development mail backend "sent": kept so a developer — or a
 * test — can read the code or the link without a mail server. Never used in production,
 * where the settings refuse the console backend.
 */
interface MailOutbox
{
    public function record(OutgoingMail $mail): void;

    /**
     * @param positive-int $limit
     *
     * @return list<OutgoingMail> Newest first.
     */
    public function recent(int $limit): array;
}
