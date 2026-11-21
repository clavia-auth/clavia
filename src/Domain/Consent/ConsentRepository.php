<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\Consent;

use Clavia\Domain\Client\ClientId;
use Clavia\Domain\Identity\UserId;
use Clavia\Domain\ResourceServer\ResourceServerId;

/**
 * The consents people gave, one per person, application and API.
 *
 * A consent goes with whatever it names: deleting the account, the application or the
 * API takes it along.
 */
interface ConsentRepository
{
    /**
     * @param ResourceServerId|null $resourceServerId Null for the consent given to a request that
     *                                                named no API.
     */
    public function find(UserId $userId, ClientId $clientId, ?ResourceServerId $resourceServerId): ?UserConsent;

    /**
     * Store the consent, replacing the one already held for its person, application and API.
     *
     * Two decisions racing on the same triple leave the last one written. That loses at
     * most a widening — the person is asked again — never grants more than was agreed.
     */
    public function save(UserConsent $consent): void;

    /**
     * Every consent the person gave, oldest first.
     *
     * @return list<UserConsent>
     */
    public function ofUser(UserId $userId): array;

    /**
     * Withdraw everything the person allowed the application, on every API. Withdrawing
     * nothing is not an error.
     */
    public function withdraw(UserId $userId, ClientId $clientId): void;
}
