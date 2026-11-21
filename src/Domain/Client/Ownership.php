<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\Client;

/**
 * Who runs an application: the operator of this server, or somebody else.
 *
 * - **First-party** — the operator's own application. Signing in through it is the
 *   consent, unless the API it asks for insists on asking; it may be given access to a
 *   system API, under that API's own rules.
 * - **Third-party** — a partner's or an outside developer's. Nobody here vouches for it,
 *   so every scope it asks for is put to the person on the consent screen, the answer is
 *   remembered, and it never gets anywhere near a system API — on anybody's behalf or as
 *   itself.
 *
 * Written into the client id ({@see ClientId::THIRD_PARTY_PREFIX}) when it is generated,
 * and read back from it: ownership is identity, fixed at registration, and the id is the
 * one place it is visible without a lookup — in every authorization request, log line and
 * support ticket.
 */
enum Ownership: string
{
    case FirstParty = 'first_party';

    case ThirdParty = 'third_party';
}
