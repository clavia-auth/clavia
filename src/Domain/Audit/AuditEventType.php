<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\Audit;

/**
 * What happened. The value is the name the trail and the Management API use:
 * `<subject>.<what happened to it>`, past tense, stable once published.
 */
enum AuditEventType: string
{
    // ── People signing in and out ───────────────────────────────────────────────
    case SignedIn = 'authentication.succeeded';
    case SignInFailed = 'authentication.failed';
    case SessionEnded = 'session.ended';
    case SessionSteppedUp = 'session.stepped_up';
    case MfaEnrolled = 'mfa.enrolled';
    case MfaRemoved = 'mfa.removed';
    case PasskeyRegistered = 'passkey.registered';
    case PasskeyRenamed = 'passkey.renamed';
    case PasskeyRemoved = 'passkey.removed';
    case PasskeyCounterRegressed = 'passkey.counter_regressed';

    // ── What people agree to ────────────────────────────────────────────────────
    case ConsentGiven = 'consent.given';
    case ConsentRefused = 'consent.refused';
    case ConsentWithdrawn = 'consent.withdrawn';
    case DeviceApproved = 'device.approved';
    case DeviceRefused = 'device.refused';

    // ── Tokens ──────────────────────────────────────────────────────────────────
    case TokenIssued = 'token.issued';
    case TokenRevoked = 'token.revoked';
    /** A spent authorization code presented again: what it issued is revoked (RFC 6749 §4.1.2). */
    case CodeReplayed = 'token.code_replayed';
    /** A spent refresh token presented again: its family is revoked (RFC 6749 §10.4). */
    case RefreshTokenReplayed = 'token.refresh_replayed';

    // ── Configuration, through the Management API or the console ───────────────
    case ClientCreated = 'client.created';
    case ClientUpdated = 'client.updated';
    case ClientDeleted = 'client.deleted';
    case ClientSecretRotated = 'client.secret_rotated';
    case ClientGranted = 'client.granted';
    case UserCreated = 'user.created';
    case UserUpdated = 'user.updated';
    case UserDeleted = 'user.deleted';
    case UserIdentityUnlinked = 'user.identity_unlinked';
    case UserRolesChanged = 'user.roles_changed';
    case UserSignedUp = 'user.signed_up';
    case UserEmailVerified = 'user.email_verified';
    case UserPasswordReset = 'user.password_reset';
    case UserPasswordLinkSent = 'user.password_link_sent';
    case UsersExported = 'user.exported';
    case RoleCreated = 'role.created';
    case RoleUpdated = 'role.updated';
    case RoleDeleted = 'role.deleted';
    case ResourceServerCreated = 'resource_server.created';
    case ResourceServerUpdated = 'resource_server.updated';
    case ResourceServerDeleted = 'resource_server.deleted';
    case ConnectionCreated = 'connection.created';
    case ConnectionUpdated = 'connection.updated';
    case ConnectionDeleted = 'connection.deleted';
    case SigningKeyCreated = 'signing_key.created';
    case SigningKeyRotated = 'signing_key.rotated';
    case InitialAccessTokenIssued = 'initial_access_token.issued';
    case InitialAccessTokenRevoked = 'initial_access_token.revoked';
    case WebhookCreated = 'webhook.created';
    case WebhookUpdated = 'webhook.updated';
    case WebhookDeleted = 'webhook.deleted';
    case WebhookSecretRotated = 'webhook.secret_rotated';
}
