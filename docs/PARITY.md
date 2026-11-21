# Parity matrix

Every test of the Python project (`tests/`, 404 functions) and the PHP test that covers the same behaviour. A parametrised Python test counts once. Where PHP does something else on purpose, the note points to [`DEVIATIONS.md`](DEVIATIONS.md); the PHP test then states the PHP behaviour.

`A → B::c` means test class `A` running the shared contract `B`. `::m (case)` names one case of a data provider.

**404 / 404 mapped.**

## `test_audience.py` (12)

| Python | PHP | Note |
|---|---|---|
| `test_audience_binds_a_machine_token_to_one_api` | `AudienceTest::testAudienceBindsAMachineTokenToOneApi` |  |
| `test_unknown_audience_is_invalid_target` | `AudienceTest::testUnknownAudienceIsInvalidTarget` |  |
| `test_client_without_a_grant_is_refused` | `AudienceTest::testClientWithoutAGrantIsRefused` |  |
| `test_the_grant_on_that_api_is_the_only_authority` | `AudienceTest::testTheGrantOnThatApiIsTheOnlyAuthority` |  |
| `test_permission_dropped_from_the_api_stops_being_grantable` | `AudienceTest::testPermissionDroppedFromTheApiStopsBeingGrantable` |  |
| `test_granting_an_undefined_permission_is_refused_at_the_grant` | `AudienceTest::testGrantingAnUndefinedPermissionIsRefusedAtTheGrant` |  |
| `test_audience_is_required` | `AudienceTest::testAudienceIsRequired` |  |
| `test_regranting_replaces_rather_than_accumulates` | `AudienceTest::testRegrantingReplacesRatherThanAccumulates` |  |
| `test_user_flow_carries_the_audience_onto_the_token` | `AudienceTest::testUserFlowCarriesTheAudienceOntoTheToken` |  |
| `test_user_flow_refuses_a_permission_the_api_does_not_define` | `AudienceTest::testUserFlowRefusesAPermissionTheApiDoesNotDefine` |  |
| `test_user_flow_refuses_an_unknown_audience_with_a_redirect` | `AudienceTest::testUserFlowRefusesAnUnknownAudienceWithARedirect` |  |
| `test_user_flow_without_an_audience_is_unchanged` | `AudienceTest::testUserFlowWithoutAnAudienceIsUnchanged` |  |

## `test_authorization_code_flow.py` (9)

| Python | PHP | Note |
|---|---|---|
| `test_authorize_issues_code_and_preserves_state` | `AuthorizationCodeFlowTest::testAuthorizeIssuesCodeAndPreservesState` |  |
| `test_authorization_code_is_not_stored_in_plaintext` | `AuthorizationCodeFlowTest::testAuthorizationCodeIsNotStoredInPlaintext` |  |
| `test_full_flow_exchanges_code_for_access_token` | `AuthorizationCodeFlowTest::testFullFlowExchangesCodeForAccessToken` |  |
| `test_code_is_marked_consumed_after_exchange` | `AuthorizationCodeFlowTest::testCodeIsMarkedConsumedAfterExchange` |  |
| `test_confidential_client_completes_the_flow_with_its_secret` | `AuthorizationCodeFlowTest::testConfidentialClientCompletesTheFlowWithItsSecret` |  |
| `test_scope_unknown_to_the_server_is_rejected` | `AuthorizationCodeFlowTest::testScopeUnknownToTheServerIsRejected` |  |
| `test_every_oidc_scope_may_be_requested_by_any_client` | `AuthorizationCodeFlowTest::testEveryOidcScopeMayBeRequestedByAnyClient` |  |
| `test_authorize_without_authenticated_user_redirects_to_login` | `AuthorizationCodeFlowTest::testAuthorizeWithoutAuthenticatedUserRedirectsToLogin` |  |
| `test_healthz` | `AuthorizationCodeFlowTest::testHealthz` |  |

## `test_authorize_prompt.py` (15)

| Python | PHP | Note |
|---|---|---|
| `test_the_authorization_response_names_the_issuer` | `AuthorizePromptTest::testTheAuthorizationResponseNamesTheIssuer` |  |
| `test_error_responses_name_the_issuer_too` | `AuthorizePromptTest::testErrorResponsesNameTheIssuerToo` |  |
| `test_prompt_none_without_a_session_is_login_required` | `AuthorizePromptTest::testPromptNoneWithoutASessionIsLoginRequired` |  |
| `test_prompt_none_with_a_session_issues_a_code` | `AuthorizePromptTest::testPromptNoneWithASessionIssuesACode` |  |
| `test_prompt_none_with_a_session_too_old_for_max_age_is_login_required` | `AuthorizePromptTest::testPromptNoneWithASessionTooOldForMaxAgeIsLoginRequired` |  |
| `test_prompt_none_combined_with_another_value_is_invalid` | `AuthorizePromptTest::testPromptNoneCombinedWithAnotherValueIsInvalid` |  |
| `test_prompt_login_reauthenticates_a_signed_in_user_exactly_once` | `AuthorizePromptTest::testPromptLoginReauthenticatesASignedInUserExactlyOnce` |  |
| `test_prompt_login_keeps_the_other_prompt_values` | `AuthorizePromptTest::testPromptLoginKeepsTheOtherPromptValues` |  |
| `test_prompt_select_account_is_honoured_by_signing_in_again` | `AuthorizePromptTest::testPromptSelectAccountIsHonouredBySigningInAgain` |  |
| `test_max_age_within_the_session_age_passes` | `AuthorizePromptTest::testMaxAgeWithinTheSessionAgePasses` |  |
| `test_max_age_exceeded_asks_for_a_sign_in` | `AuthorizePromptTest::testMaxAgeZeroAsksForASignInAndIsThenDropped`<br>`AuthorizePromptTest::testAPositiveMaxAgeSurvivesTheSignIn` |  |
| `test_a_positive_max_age_survives_the_sign_in` | `AuthorizePromptTest::testAPositiveMaxAgeSurvivesTheSignIn` |  |
| `test_max_age_without_a_known_auth_time_asks_for_a_sign_in` | `AuthorizePromptTest::testMaxAgeWithoutAKnownSignInTimeAsksForASignIn` |  |
| `test_a_negative_or_malformed_max_age_is_invalid` | `AuthorizePromptTest::testANegativeOrMalformedMaxAgeIsInvalid` |  |
| `test_request_objects_are_refused_with_the_defined_errors` | `AuthorizePromptTest::testRequestObjectsAreRefusedWithTheDefinedErrors` |  |

## `test_backchannel_logout.py` (22)

| Python | PHP | Note |
|---|---|---|
| `test_discovery_advertises_back_channel_logout` | `OidcTest::testDiscoveryDocument` |  |
| `test_id_token_carries_the_session_identifier` | `BackChannelLogoutTest::testTheIdTokenCarriesTheSessionIdentifier` |  |
| `test_sid_is_not_the_cookie_and_changes_with_the_session` | `BackChannelLogoutTest::testTheSidIsNotTheCookieAndChangesWithTheSession` |  |
| `test_no_sid_without_a_browser_session` | `BackChannelLogoutTest::testNoSidWithoutABrowserSession` |  |
| `test_the_session_remembers_which_applications_signed_in` | `BackChannelLogoutTest::testTheSessionRemembersWhichApplicationsSignedIn` |  |
| `test_logging_out_posts_a_logout_token_to_the_application` | `BackChannelLogoutTest::testLoggingOutPostsALogoutTokenToTheApplication` |  |
| `test_each_logout_token_is_unique` | `BackChannelLogoutTest::testEachLogoutTokenIsUnique` |  |
| `test_rp_initiated_logout_tells_the_other_applications_too` | `BackChannelLogoutTest::testRpInitiatedLogoutTellsTheApplicationsToo` |  |
| `test_an_application_without_a_uri_is_not_told` | `BackChannelLogoutTest::testAnApplicationWithoutAUriIsNotTold` |  |
| `test_an_application_that_did_not_sign_in_is_not_told` | `BackChannelLogoutTest::testAnApplicationThatDidNotSignInIsNotTold` |  |
| `test_a_session_that_ended_on_its_own_is_not_reported_twice` | `BackChannelLogoutTest::testASessionIsNotReportedTwice` |  |
| `test_a_failing_application_does_not_break_logout` | `BackChannelLogoutTest::testAFailingApplicationDoesNotBreakLogout` |  |
| `test_an_error_response_is_tolerated` | `BackChannelLogoutTest::testAnErrorResponseIsTolerated` |  |
| `test_a_private_address_is_refused_at_send_time` | `BackChannelLogoutTest::testAPrivateAddressIsRefusedAtSendTime` |  |
| `test_registration_carries_the_uri` | `BackChannelLogoutTest::testRegistrationCarriesTheUri` |  |
| `test_registration_refuses_a_uri_this_server_must_not_post_to` | `BackChannelLogoutTest::testRegistrationRefusesAUriThisServerMustNotPostTo` |  |
| `test_creation_checks_the_uri_too` | `BackChannelLogoutTest::testCreationChecksTheUriToo` |  |
| `test_sessions_are_listed_with_their_applications` | `BackChannelLogoutTest::testSessionsAreListedWithTheirApplications` |  |
| `test_sign_out_everywhere_ends_every_session_and_tells_the_applications` | `BackChannelLogoutTest::testSignOutEverywhereEndsEverySessionAndTellsTheApplications` |  |
| `test_one_session_can_be_ended_by_its_sid` | `BackChannelLogoutTest::testOneSessionCanBeEndedByItsSid` |  |
| `test_deactivating_a_user_signs_them_out_everywhere` | `BackChannelLogoutTest::testDeactivatingAUserSignsThemOutEverywhere` |  |
| `test_deleting_a_user_signs_them_out_everywhere` | `BackChannelLogoutTest::testDeletingAUserSignsThemOutEverywhere` |  |

## `test_client_credentials.py` (19)

| Python | PHP | Note |
|---|---|---|
| `test_issues_a_bearer_token_with_no_subject` | `ClientCredentialsTest::testIssuesABearerTokenWithNoSubject` |  |
| `test_token_is_stored_only_as_a_digest` | `ClientCredentialsTest::testTokenIsStoredOnlyAsADigest` |  |
| `test_client_secret_post_is_accepted_when_registered_for_it` | `ClientCredentialsTest::testClientSecretPostIsAcceptedWhenRegisteredForIt` |  |
| `test_client_registered_for_basic_cannot_post_its_secret` | `ClientCredentialsTest::testClientRegisteredForBasicCannotPostItsSecret` |  |
| `test_basic_credentials_are_read_whatever_the_header_case` | `ClientCredentialsTest::testBasicCredentialsAreReadWhateverTheHeaderCase` |  |
| `test_wrong_secret_is_refused` | `ClientCredentialsTest::testWrongSecretIsRefused` |  |
| `test_failed_authentication_carries_a_challenge` | `ClientCredentialsTest::testFailedAuthenticationCarriesAChallenge` |  |
| `test_unknown_client_is_refused` | `ClientCredentialsTest::testUnknownClientIsRefused` |  |
| `test_public_client_cannot_use_this_grant` | `ClientCredentialsTest::testPublicClientCannotUseThisGrant` |  |
| `test_client_marked_public_but_holding_a_secret_is_refused` | `ClientCredentialsTest::testClientMarkedPublicButHoldingASecretIsRefused` |  |
| `test_client_not_registered_for_the_grant_is_refused` | `ClientCredentialsTest::testClientNotRegisteredForTheGrantIsRefused` |  |
| `test_omitted_scope_grants_the_whole_grant` | `ClientCredentialsTest::testOmittedScopeGrantsTheWholeGrant` |  |
| `test_narrower_scope_is_honoured` | `ClientCredentialsTest::testNarrowerScopeIsHonoured` |  |
| `test_scope_beyond_the_grant_is_refused` | `ClientCredentialsTest::testScopeBeyondTheGrantIsRefused` |  |
| `test_scope_the_server_supports_but_the_grant_lacks_is_refused` | `ClientCredentialsTest::testScopeTheServerSupportsButTheGrantLacksIsRefused` |  |
| `test_openid_scope_is_refused_even_when_the_api_defines_it` | `ClientCredentialsTest::testOpenidScopeIsRefusedEvenWhenTheApiDefinesIt` |  |
| `test_machine_token_is_refused_by_userinfo` | `ClientCredentialsTest::testMachineTokenIsRefusedByUserinfo` |  |
| `test_machine_client_cannot_start_an_interactive_flow` | `ClientCredentialsTest::testMachineClientCannotStartAnInteractiveFlow` |  |
| `test_discovery_advertises_the_grant` | `ClientCredentialsTest::testDiscoveryAdvertisesTheGrant` |  |

## `test_connections.py` (29)

| Python | PHP | Note |
|---|---|---|
| `test_login_page_offers_only_the_applications_connections` | `ConnectionsTest::testTheLoginPageOffersOnlyTheApplicationsConnections` |  |
| `test_an_application_with_no_connections_says_so` | `ConnectionsTest::testAnApplicationWithNoConnectionsSaysSo` |  |
| `test_a_direct_visit_offers_every_usable_connection` | `ConnectionsTest::testADirectVisitOffersEveryUsableConnection` |  |
| `test_an_unconfigured_social_connection_is_never_offered` | `ConnectionsTest::testASocialConnectionWithoutCredentialsIsNeverOffered` |  |
| `test_a_disabled_connection_is_gone_for_everyone` | `ConnectionsTest::testASwitchedOffConnectionIsGoneForEveryone` |  |
| `test_password_post_is_refused_when_the_application_disables_it` | `ConnectionsTest::testAPasswordIsRefusedWhenTheApplicationDoesNotEnableAPool` |  |
| `test_provider_link_is_refused_when_the_application_disables_it` | `ConnectionsTest::testAProviderLinkIsRefusedWhenTheApplicationDoesNotEnableIt` |  |
| `test_provider_link_works_when_enabled` | `ConnectionsTest::testAProviderLinkWorksWhenEnabled` |  |
| `test_session_through_a_connection_the_application_disables_does_not_count` | `ConnectionsTest::testASessionThroughAConnectionTheApplicationNoLongerEnablesDoesNotCount` |  |
| `test_session_records_its_connection` | `ConnectionsTest::testASessionRecordsItsConnection` |  |
| `test_third_party_gets_domain_level_connections_only` | `ConnectionsTest::testAThirdPartyApplicationGetsTheDomainConnectionsOnly` |  |
| `test_third_party_cannot_be_given_a_list` | `ConnectionsTest::testAThirdPartyApplicationCannotBeGivenAList` |  |
| `test_new_application_gets_every_connection` | `ConnectionsTest::testANewApplicationGetsEveryConnection` |  |
| `test_application_connections_are_replaced_as_a_whole` | `ConnectionsTest::testTheConnectionsOfAnApplicationAreReplacedWhole` |  |
| `test_connections_are_listed_with_what_the_server_knows` | `ConnectionsTest::testConnectionsAreListedWithWhatTheServerKnowsOfThem` |  |
| `test_connection_switches` | `ConnectionsTest::testAConnectionIsSwitchedAndRenamed` |  |
| `test_connection_scopes_are_required` | `ConnectionsTest::testTheConnectionScopesAreRequired` |  |
| `test_password_login_still_works_end_to_end` | `ConnectionsTest::testAPasswordSignInStillWorksEndToEnd` |  |
| `test_users_are_created_in_a_pool` | `ConnectionsTest::testUsersAreCreatedInAPool` |  |
| `test_the_same_email_may_live_in_two_pools` | `ConnectionsTest::testTheSameAddressMayLiveInTwoPools` |  |
| `test_a_user_cannot_be_created_in_an_external_connection` | `ConnectionsTest::testAUserIsNotCreatedInAnExternalConnection` |  |
| `test_login_looks_only_in_the_pools_the_application_enables` | `ConnectionsTest::testASignInLooksOnlyInThePoolsTheApplicationEnables` |  |
| `test_same_email_in_two_pools_signs_in_as_whichever_password_matches` | `ConnectionsTest::testTheSameAddressInTwoPoolsSignsInAsWhicheverPasswordMatches` |  |
| `test_a_pool_with_users_cannot_be_deleted` | `ConnectionsTest::testAPoolWithAccountsIsNotDeleted` |  |
| `test_an_empty_pool_can_be_deleted` | `ConnectionsTest::testAnEmptyPoolIsDeletedAndNoApplicationEnablesItAfterwards` |  |
| `test_built_in_social_connections_cannot_be_deleted` | `ConnectionsTest::testSocialConnectionsAreBuiltInAndNeverCreatedOrDeleted` |  |
| `test_pool_names_are_plain` | `ConnectionsTest::testAConnectionNameIsPlain` |  |
| `test_identities_are_listed_and_can_be_unlinked` | `ConnectionsTest::testIdentitiesAreListedAndUnlinked` |  |
| `test_the_only_way_in_cannot_be_unlinked` | `ConnectionsTest::testTheOnlyWayIntoAnAccountIsNotUnlinked` |  |

## `test_consent.py` (23)

| Python | PHP | Note |
|---|---|---|
| `test_first_party_sign_in_never_asks` | `ConsentTest::testAFirstPartySignInNeverAsks` |  |
| `test_third_party_application_is_sent_to_the_consent_screen` | `ConsentTest::testAThirdPartyApplicationIsSentToTheConsentScreen` |  |
| `test_first_party_asks_when_the_api_forbids_skipping` | `ConsentTest::testAFirstPartyApplicationAsksWhenTheApiForbidsSkipping` |  |
| `test_first_party_skips_when_the_api_allows_it` | `ConsentTest::testAFirstPartyApplicationSkipsWhenTheApiAllowsIt` |  |
| `test_prompt_consent_asks_even_a_first_party_application` | `ConsentTest::testPromptConsentAsksEvenAFirstPartyApplication` |  |
| `test_prompt_none_cannot_ask_and_says_so` | `ConsentTest::testPromptNoneCannotAskAndSaysSo` |  |
| `test_allowing_records_the_consent_and_issues_the_code` | `ConsentTest::testAllowingRecordsTheConsentAndIssuesTheCode` |  |
| `test_a_recorded_consent_is_not_asked_for_again` | `ConsentTest::testARecordedConsentIsNotAskedForAgain` |  |
| `test_asking_for_more_asks_again_and_widens_the_record` | `ConsentTest::testAskingForMoreAsksAgainAndWidensTheRecord` |  |
| `test_refusing_sends_access_denied_to_the_application` | `ConsentTest::testRefusingSendsAccessDeniedToTheApplication` |  |
| `test_consent_on_one_api_says_nothing_about_another` | `ConsentTest::testConsentOnOneApiSaysNothingAboutAnother` |  |
| `test_screen_is_bound_to_the_user_who_was_asked` | `ConsentTest::testTheScreenIsBoundToThePersonWhoWasAsked` |  |
| `test_screen_needs_a_signed_in_user` | `ConsentTest::testTheScreenNeedsASignedInPerson` |  |
| `test_wrong_csrf_token_re_renders_without_deciding` | `ConsentTest::testAWrongCsrfTokenReRendersWithoutDeciding` |  |
| `test_unknown_handle_is_an_expired_request` | `ConsentTest::testAnUnknownHandleIsAnExpiredRequest` |  |
| `test_third_party_cannot_ask_a_user_for_the_management_api` | `ConsentTest::testAThirdPartyApplicationCannotAskAPersonForTheManagementApi` |  |
| `test_third_party_machine_client_cannot_be_granted_the_management_api` | `ConsentTest::testAThirdPartyMachineCannotBeGrantedTheManagementApi` |  |
| `test_first_party_machine_client_is_unaffected` | `ConsentTest::testAFirstPartyMachineIsUnaffected` |  |
| `test_third_party_client_id_carries_the_prefix` | `ClientIdTest::testAThirdPartyIdCarriesThePrefixAndSaysSo` |  |
| `test_ownership_is_set_at_creation_and_never_changed` | `ConsentTest::testOwnershipIsSetAtCreationAndNeverChanged` |  |
| `test_default_registration_is_first_party` | `ConsentTest::testTheDefaultRegistrationIsFirstParty` |  |
| `test_consents_are_listed_and_can_be_withdrawn` | `ConsentTest::testConsentsAreListedAndCanBeWithdrawn` |  |
| `test_api_can_stop_first_party_applications_skipping_consent` | `ConsentTest::testAnApiCanStopFirstPartyApplicationsSkippingConsent` |  |

## `test_device_authorization.py` (22)

| Python | PHP | Note |
|---|---|---|
| `test_device_gets_a_code_to_poll_with_and_a_code_to_show` | `DeviceAuthorizationTest::testADeviceGetsACodeToPollWithAndACodeToShow` |  |
| `test_a_client_not_registered_for_the_grant_is_refused` | `ClientCredentialsTest::testClientNotRegisteredForTheGrantIsRefused` |  |
| `test_unknown_client_is_refused` | `DeviceAuthorizationTest::testAnUnknownClientIsRefused` |  |
| `test_scope_is_checked_against_the_audience` | `DeviceAuthorizationTest::testTheScopeIsCheckedAgainstTheAudience` |  |
| `test_third_party_applications_cannot_register_for_the_grant` | `DeviceAuthorizationTest::testThirdPartyApplicationsCannotRegisterForTheGrant` |  |
| `test_polling_before_the_decision_is_pending` | `DeviceAuthorizationTest::testPollingBeforeTheDecisionIsPending` |  |
| `test_polling_too_fast_earns_slow_down_and_a_longer_interval` | `DeviceAuthorizationTest::testPollingTooFastEarnsSlowDownAndALongerInterval` |  |
| `test_polling_by_another_client_is_refused` | `DeviceAuthorizationTest::testPollingByAnotherClientIsRefused` |  |
| `test_an_unknown_device_code_is_invalid_grant` | `DeviceAuthorizationTest::testAnUnknownDeviceCodeIsInvalidGrant` |  |
| `test_an_expired_code_says_so` | `DeviceAuthorizationTest::testAnExpiredCodeSaysSo` |  |
| `test_the_page_needs_a_signed_in_person` | `DeviceAuthorizationTest::testThePageNeedsASignedInPerson` |  |
| `test_a_wrong_code_is_refused_on_the_page` | `DeviceAuthorizationTest::testAWrongCodeIsRefusedOnThePage` |  |
| `test_the_page_shows_who_is_asking_and_for_what` | `DeviceAuthorizationTest::testThePageShowsWhoIsAskingAndForWhat` |  |
| `test_typed_codes_are_forgiving` | `DeviceAuthorizationTest::testTypedCodesAreForgiving` |  |
| `test_approval_lets_the_device_redeem_the_code_once` | `DeviceAuthorizationTest::testApprovalLetsTheDeviceRedeemTheCodeOnce` |  |
| `test_refusal_reaches_the_device` | `DeviceAuthorizationTest::testRefusalReachesTheDevice` |  |
| `test_approval_is_recorded_as_a_consent` | `DeviceAuthorizationTest::testApprovalIsRecordedAsAConsent` |  |
| `test_a_code_cannot_be_approved_twice` | `DeviceAuthorizationTest::testACodeCannotBeDecidedTwice` |  |
| `test_the_token_is_narrowed_to_the_persons_roles` | `DeviceAuthorizationTest::testTheTokenIsNarrowedToThePersonsRoles` |  |
| `test_a_person_with_no_role_on_an_enforcing_api_cannot_approve` | `DeviceAuthorizationTest::testAPersonWithNoRoleOnAnEnforcingApiCannotApprove` |  |
| `test_approval_through_a_connection_the_application_disables_is_not_accepted` | `DeviceAuthorizationTest::testApprovalThroughAConnectionTheApplicationDoesNotEnableIsNotAccepted` |  |
| `test_discovery_advertises_the_grant` | `DeviceAuthorizationTest::testDiscoveryAdvertisesTheGrant` |  |

## `test_introspection_revocation.py` (17)

| Python | PHP | Note |
|---|---|---|
| `test_a_client_can_introspect_its_own_token` | `IntrospectionRevocationTest::testAClientIntrospectsItsOwnToken` |  |
| `test_a_resource_server_can_introspect_tokens_issued_for_it` | `IntrospectionRevocationTest::testAnApiIntrospectsTheTokensIssuedForIt` |  |
| `test_a_token_the_caller_has_no_stake_in_looks_unknown` | `IntrospectionRevocationTest::testATokenTheCallerHasNoStakeInLooksUnknown` |  |
| `test_a_public_client_cannot_introspect` | `IntrospectionRevocationTest::testAPublicClientCannotIntrospect` |  |
| `test_a_confidential_client_without_a_grant_learns_nothing` | `IntrospectionRevocationTest::testAConfidentialClientWithoutAStakeLearnsNothing` |  |
| `test_expired_revoked_and_unknown_tokens_are_inactive` | `IntrospectionRevocationTest::testExpiredRevokedAndUnknownTokensAreInactive` |  |
| `test_refresh_tokens_can_be_introspected_and_a_spent_one_is_inactive` | `IntrospectionRevocationTest::testARefreshTokenIsIntrospectedAndASpentOneIsInactive` |  |
| `test_the_hint_is_an_optimisation_not_a_constraint` | `IntrospectionRevocationTest::testTheHintIsAnOptimisationNotAConstraint` |  |
| `test_malformed_introspection_requests` | `IntrospectionRevocationTest::testMalformedIntrospectionRequests` |  |
| `test_a_public_client_can_revoke_its_own_access_token` | `IntrospectionRevocationTest::testAPublicClientRevokesItsOwnAccessToken` |  |
| `test_revoking_a_refresh_token_revokes_the_whole_family` | `IntrospectionRevocationTest::testRevokingARefreshTokenRevokesTheWholeFamily` |  |
| `test_revoking_an_access_token_leaves_the_refresh_token_alone` | `IntrospectionRevocationTest::testRevokingAnAccessTokenLeavesTheRefreshTokenAlone` |  |
| `test_a_machine_client_revokes_with_its_secret` | `IntrospectionRevocationTest::testAMachineClientRevokesWithItsSecret` |  |
| `test_another_clients_token_cannot_be_revoked` | `IntrospectionRevocationTest::testAnotherClientsTokenIsNotRevoked` |  |
| `test_an_unknown_token_revokes_quietly` | `IntrospectionRevocationTest::testAnUnknownTokenIsRevokedQuietly` |  |
| `test_revocation_needs_a_client` | `IntrospectionRevocationTest::testRevocationNeedsAClient` |  |
| `test_discovery_advertises_both_endpoints` | `IntrospectionRevocationTest::testDiscoveryAdvertisesBothEndpoints` |  |

## `test_login.py` (35)

| Python | PHP | Note |
|---|---|---|
| `test_login_page_renders_with_csrf_token` | `LoginTest::testLoginPageRendersWithCsrfToken` |  |
| `test_login_page_forbids_script` | `LoginTest::testLoginPageForbidsScript` |  |
| `test_theme_toggle_sets_a_cookie_and_returns_to_the_page` | `LoginTest::testThemeToggleSetsACookieAndReturnsToThePage` |  |
| `test_theme_auto_clears_the_cookie_and_follows_the_system` | `LoginTest::testThemeAutoClearsTheCookieAndFollowsTheSystem` |  |
| `test_theme_toggle_ignores_unknown_values_and_hostile_next` | `LoginTest::testThemeToggleIgnoresUnknownValuesAndHostileNext` |  |
| `test_successful_login_establishes_a_session` | `LoginTest::testSuccessfulLoginEstablishesASession` |  |
| `test_session_cookie_flags` | `LoginTest::testSessionCookieFlags` |  |
| `test_session_id_is_not_stored_in_plaintext` | `LoginTest::testSessionIdIsNotStoredInPlaintext` |  |
| `test_logout_destroys_the_session` | `LoginTest::testLogoutDestroysTheSession` |  |
| `test_logout_rejects_get` | `LoginTest::testLogoutRejectsGet` |  |
| `test_logout_redirects_to_a_registered_client_origin` | `LoginTest::testLogoutRedirectsToARegisteredClientOrigin` |  |
| `test_logout_ignores_an_unregistered_next` | `LoginTest::testLogoutIgnoresAnUnregisteredNext` |  |
| `test_wrong_password_is_rejected` | `LoginTest::testWrongPasswordIsRejected` |  |
| `test_unknown_account_gives_the_same_response_as_a_wrong_password` | `LoginTest::testUnknownAccountGivesTheSameResponseAsAWrongPassword` |  |
| `test_inactive_user_cannot_log_in` | `LoginTest::testInactiveUserCannotLogIn` |  |
| `test_account_without_a_password_cannot_log_in_with_one` | `LoginTest::testAccountWithoutAPasswordCannotLogInWithOne` |  |
| `test_deactivating_a_user_invalidates_their_live_session` | `LoginTest::testDeactivatingAUserInvalidatesTheirLiveSession` |  |
| `test_login_without_csrf_token_is_rejected` | `LoginTest::testLoginWithoutCsrfTokenIsRejected` |  |
| `test_login_with_mismatched_csrf_token_is_rejected` | `LoginTest::testLoginWithMismatchedCsrfTokenIsRejected` |  |
| `test_login_rotates_the_session_identifier` | `LoginTest::testLoginRotatesTheSessionIdentifier` |  |
| `test_session_past_its_absolute_lifetime_is_gone_even_if_used` | `LoginTest::testSessionPastItsAbsoluteLifetimeIsGoneEvenIfUsed` |  |
| `test_next_cannot_send_the_user_off_site` | `LoginTest::testNextCannotSendTheUserOffSite` |  |
| `test_next_preserves_a_local_target` | `LoginTest::testNextPreservesALocalTarget` |  |
| `test_login_state_is_single_use` | `LoginTest::testLoginStateIsSingleUse` |  |
| `test_failed_login_keeps_the_login_state` | `LoginTest::testFailedLoginKeepsTheLoginState` |  |
| `test_repeated_failures_lock_the_account_out` | `LoginTest::testRepeatedFailuresLockTheAccountOut` |  |
| `test_successful_login_clears_the_failure_counter` | `LoginTest::testSuccessfulLoginClearsTheFailureCounter` |  |
| `test_unauthenticated_authorize_redirects_to_login` | `LoginTest::testUnauthenticatedAuthorizeRedirectsToLogin` |  |
| `test_invalid_authorize_request_never_reaches_the_login_page` | `LoginTest::testInvalidAuthorizeRequestNeverReachesTheLoginPage` |  |
| `test_login_then_authorize_then_token` | `LoginTest::testLoginThenAuthorizeThenToken` |  |
| `test_csrf_token_survives_a_second_page_load` | `LoginTest::testCsrfTokenSurvivesASecondPageLoad` |  |
| `test_a_stale_second_csrf_cookie_does_not_lock_the_person_out` | `LoginTest::testAStaleSecondCsrfCookieDoesNotLockThePersonOut` |  |
| `test_signing_in_with_an_expired_state_lands_somewhere_that_says_so` | `LoginTest::testSigningInWithAnExpiredStateLandsSomewhereThatSaysSo` |  |
| `test_a_signed_in_visitor_with_an_authorization_request_still_gets_the_form` | `LoginTest::testASignedInVisitorWithAnAuthorizationRequestStillGetsTheForm` |  |
| `test_login_page_lets_a_submit_end_at_the_application` | `LoginTest::testLoginPageLetsASubmitEndAtTheApplication` |  |

## `test_management_api.py` (36)

| Python | PHP | Note |
|---|---|---|
| `test_no_credentials_gets_a_bare_challenge` | `ManagementApiTest::testNoCredentialsGetABareChallenge` |  |
| `test_unknown_token_is_refused` | `ManagementApiTest::testUnknownTokenIsRefused` |  |
| `test_token_for_another_api_is_refused` | `ManagementApiTest::testTokenForAnotherApiIsRefused` |  |
| `test_token_with_no_audience_is_refused` | `ManagementApiTest::testTokenWithNoAudienceIsRefused` |  |
| `test_revoked_token_is_refused` | `ManagementApiTest::testRevokedTokenIsRefused` |  |
| `test_missing_scope_is_refused_with_the_scope_named` | `ManagementApiTest::testMissingScopeIsRefusedWithTheScopeNamed` |  |
| `test_session_cookie_is_not_accepted` | `ManagementApiTest::testSessionCookieIsNotAccepted` |  |
| `test_token_in_the_query_string_is_not_accepted` | `ManagementApiTest::testTokenInTheQueryStringIsNotAccepted` |  |
| `test_token_is_refused_once_its_subject_is_deactivated` | `ManagementApiTest::testTokenIsRefusedOnceItsSubjectIsDeactivated` |  |
| `test_management_scopes_are_the_apis_permissions` | `ManagementApiTest::testManagementScopesAreTheApisPermissions` |  |
| `test_user_lifecycle` | `ManagementApiTest::testUserLifecycle` |  |
| `test_created_user_can_actually_log_in` | `ManagementApiTest::testCreatedUserCanActuallyLogIn` |  |
| `test_changing_the_email_resets_verification` | `ManagementApiTest::testChangingTheEmailResetsVerification` |  |
| `test_duplicate_email_is_a_conflict` | `ManagementApiTest::testDuplicateEmailIsAConflict` |  |
| `test_invalid_email_and_short_password_are_rejected` | `ManagementApiTest::testInvalidEmailAndShortPasswordAreRejected` |  |
| `test_unknown_fields_are_rejected_not_ignored` | `ManagementApiTest::testUnknownFieldsAreRejectedNotIgnored` |  |
| `test_users_are_paginated_and_searchable` | `ManagementApiTest::testUsersArePaginatedAndSearchable` |  |
| `test_creating_a_confidential_client_returns_its_secret_once` | `ManagementApiTest::testCreatingAConfidentialClientReturnsItsSecretOnce` |  |
| `test_client_id_cannot_be_chosen` | `ManagementApiTest::testClientIdCannotBeChosen` |  |
| `test_public_client_gets_no_secret` | `ManagementApiTest::testPublicClientGetsNoSecret` |  |
| `test_rotating_a_secret_invalidates_the_old_one` | `ManagementApiTest::testRotatingASecretInvalidatesTheOldOne` |  |
| `test_rotating_a_public_clients_secret_is_refused` | `ManagementApiTest::testRotatingAPublicClientsSecretIsRefused` |  |
| `test_incoherent_registrations_are_refused` | `ManagementApiTest::testIncoherentRegistrationsAreRefused` |  |
| `test_patch_rechecks_the_merged_registration` | `ManagementApiTest::testPatchRechecksTheMergedRegistration` |  |
| `test_a_token_cannot_delete_the_client_that_issued_it` | `ManagementApiTest::testATokenCannotDeleteTheClientThatIssuedIt` |  |
| `test_deleting_a_client_removes_it` | `ManagementApiTest::testDeletingAClientRemovesIt` |  |
| `test_clients_are_searchable_by_id_and_name` | `ManagementApiTest::testClientsAreSearchableByIdAndName` |  |
| `test_resource_server_lifecycle` | `ManagementApiTest::testResourceServerLifecycle` |  |
| `test_identifier_must_be_an_absolute_uri` | `ManagementApiTest::testIdentifierMustBeAnAbsoluteUri` |  |
| `test_duplicate_permission_values_are_rejected` | `ManagementApiTest::testDuplicatePermissionValuesAreRejected` |  |
| `test_duplicate_identifier_is_a_conflict` | `ManagementApiTest::testDuplicateIdentifierIsAConflict` |  |
| `test_the_management_api_cannot_be_deleted` | `ManagementApiTest::testTheManagementApiCannotBeDeleted` |  |
| `test_the_management_api_permissions_cannot_be_edited` | `ManagementApiTest::testTheManagementApiPermissionsCannotBeEdited` |  |
| `test_the_management_api_can_still_be_renamed` | `ManagementApiTest::testTheManagementApiCanStillBeRenamed` |  |
| `test_apis_are_searchable` | `ManagementApiTest::testApisAreSearchable` |  |
| `test_registering_a_client_and_reaching_an_api_end_to_end` | `ManagementApiTest::testRegisteringAClientAndReachingAnApiEndToEnd` |  |

## `test_mfa.py` (17)

| Python | PHP | Note |
|---|---|---|
| `test_totp_matches_the_rfc_6238_test_vectors` | `TotpTest::testTheCodesMatchTheRfc6238Vectors` |  |
| `test_verify_accepts_the_adjacent_steps_and_spends_the_matched_one` | `TotpTest::testTheAdjacentStepsAreAcceptedAndTheMatchedOneIsReturned`<br>`MfaTest::testACodeFromTheAdjacentStepIsAcceptedAndOneFurtherIsNot` |  |
| `test_verify_refuses_malformed_input` | `TotpTest::testMalformedInputMatchesNothing` |  |
| `test_provisioning_uri_is_what_authenticator_apps_expect` | `TotpTest::testTheProvisioningUriIsWhatAuthenticatorAppsExpect` |  |
| `test_enrollment_needs_a_session` | `MfaTest::testEnrollmentNeedsASessionAndComesBackToItAfterSigningIn` |  |
| `test_enrollment_confirms_only_with_a_correct_code` | `MfaTest::testEnrollmentConfirmsOnlyWithACorrectCodeAndKeepsTheSameSeed` |  |
| `test_seed_is_stored_encrypted_and_bound_to_the_user` | `MfaTest::testTheSeedIsSealedForItsAccountAndNeverStoredInTheClear` |  |
| `test_enrollment_page_has_no_script_and_the_qr_is_inline_svg` | `MfaTest::testTheSetUpPageHasNoScriptAndDrawsTheQrCodeInline` |  |
| `test_password_alone_no_longer_signs_in` | `MfaTest::testAPasswordAloneNoLongerSignsIn` |  |
| `test_correct_code_completes_the_sign_in_with_amr` | `MfaTest::testACorrectCodeFinishesTheSignInWithTheMethodsUsed` |  |
| `test_a_code_is_single_use` | `MfaTest::testACodeIsSingleUse` |  |
| `test_wrong_codes_exhaust_the_challenge` | `MfaTest::testWrongCodesExhaustTheChallenge` |  |
| `test_recovery_code_signs_in_once` | `MfaTest::testARecoveryCodeSignsInOnceInAnyCase` |  |
| `test_challenge_without_a_cookie_goes_back_to_login` | `MfaTest::testTheChallengeWithoutItsCookieGoesBackToTheLogin` |  |
| `test_disabling_removes_factor_and_codes` | `MfaTest::testTurningItOffRemovesTheFactorAndTheCodes` |  |
| `test_deactivated_user_cannot_finish_the_second_step` | `MfaTest::testADeactivatedUserCannotFinishTheSecondStep` |  |
| `test_operator_can_reset_a_locked_out_user` | `MfaTest::testAnOperatorCanResetAUserLockedOut` |  |

## `test_oidc.py` (26)

| Python | PHP | Note |
|---|---|---|
| `test_discovery_document` | `OidcTest::testDiscoveryDocument` |  |
| `test_rfc_8414_metadata_is_the_same_document` | `OidcTest::testRfc8414MetadataIsTheSameDocument` |  |
| `test_discovery_advertises_only_working_endpoints` | `OidcTest::testDiscoveryAdvertisesOnlyWorkingEndpoints` |  |
| `test_jwks_never_exposes_private_components` | `OidcTest::testJwksNeverExposesPrivateComponents` |  |
| `test_jwks_is_cacheable_for_the_documented_window` | `OidcTest::testJwksIsCacheableForTheDocumentedWindow` |  |
| `test_private_key_is_stored_encrypted` | `OidcTest::testPrivateKeyIsStoredEncrypted` |  |
| `test_id_token_issued_for_openid_scope` | `OidcTest::testIdTokenIssuedForOpenidScope` |  |
| `test_no_id_token_without_openid_scope` | `OidcTest::testNoIdTokenWithoutOpenidScope` |  |
| `test_id_token_verifies_against_published_jwks` | `OidcTest::testIdTokenVerifiesAgainstPublishedJwks` |  |
| `test_id_token_carries_email_only_when_scoped` | `OidcTest::testIdTokenCarriesEmailOnlyWhenScoped` |  |
| `test_id_token_carries_profile_claims_that_are_set` | `OidcTest::testIdTokenCarriesProfileClaimsThatAreSet` |  |
| `test_nonce_round_trips_into_the_id_token` | `OidcTest::testNonceRoundTripsIntoTheIdToken` |  |
| `test_replayed_nonce_is_refused` | `OidcTest::testReplayedNonceIsRefused` |  |
| `test_at_hash_binds_the_id_token_to_the_access_token` | `OidcTest::testAtHashBindsTheIdTokenToTheAccessToken` |  |
| `test_auth_time_reports_the_session_not_now` | `OidcTest::testAuthTimeReportsTheSessionNotNow` |  |
| `test_auth_time_is_omitted_when_unknown` | `OidcTest::testAuthTimeIsOmittedWhenUnknown` |  |
| `test_tokens_survive_rotation` | `OidcTest::testTokensSurviveRotation` |  |
| `test_withdrawn_keys_leave_the_jwks` | `OidcTest::testWithdrawnKeysLeaveTheJwks` |  |
| `test_issuing_without_a_key_fails_loudly` | `OidcTest::testIssuingWithoutAKeyFailsLoudly` |  |
| `test_userinfo_returns_claims_for_a_valid_token` | `OidcTest::testUserinfoReturnsClaimsForAValidToken` |  |
| `test_userinfo_agrees_with_the_id_token` | `OidcTest::testUserinfoAgreesWithTheIdToken` |  |
| `test_userinfo_withholds_email_without_the_scope` | `OidcTest::testUserinfoWithholdsEmailWithoutTheScope` |  |
| `test_userinfo_rejects_a_missing_or_unknown_token` | `OidcTest::testUserinfoRejectsAMissingOrUnknownToken` |  |
| `test_userinfo_rejects_a_revoked_token` | `OidcTest::testUserinfoRejectsARevokedToken` |  |
| `test_userinfo_rejects_a_deactivated_user` | `OidcTest::testUserinfoRejectsADeactivatedUser` |  |
| `test_userinfo_requires_the_openid_scope` | `OidcTest::testUserinfoRequiresTheOpenidScope` |  |

## `test_oidc_connection.py` (16)

| Python | PHP | Note |
|---|---|---|
| `test_registration_discovers_the_provider` | `OidcConnectionTest::testRegistrationDiscoversTheProviderAndSealsTheSecret` |  |
| `test_registration_refuses_an_issuer_that_does_not_answer` | `OidcConnectionTest::testAnIssuerThatDoesNotAnswerIsRefused` |  |
| `test_registration_refuses_issuers_the_server_must_not_fetch` | `OidcConnectionTest::testAnIssuerTheServerMustNotFetchIsRefused` |  |
| `test_discovery_document_cannot_point_endpoints_inside` | `OidcConnectionTest::testTheDiscoveryDocumentCannotAimTheServerInside` |  |
| `test_registration_needs_every_oidc_setting` | `OidcConnectionTest::testRegistrationNeedsEveryOidcSetting` |  |
| `test_social_connections_cannot_be_created` | `ConnectionsTest::testSocialConnectionsAreBuiltInAndNeverCreatedOrDeleted` |  |
| `test_login_page_offers_the_provider` | `OidcConnectionTest::testTheLoginPageOffersTheProvider` |  |
| `test_sign_in_creates_a_user_in_the_connection` | `OidcConnectionTest::testASignInCreatesAnAccountInTheConnection` |  |
| `test_a_token_from_another_issuer_is_refused` | `OidcConnectionTest::testAnUntrustworthyIdTokenSignsNobodyIn (from another issuer)` |  |
| `test_a_token_for_another_audience_is_refused` | `OidcConnectionTest::testAnUntrustworthyIdTokenSignsNobodyIn (for another audience)` |  |
| `test_a_token_without_the_nonce_is_refused` | `OidcConnectionTest::testAnUntrustworthyIdTokenSignsNobodyIn (without the nonce)` |  |
| `test_an_expired_token_is_refused` | `OidcConnectionTest::testAnUntrustworthyIdTokenSignsNobodyIn (expired)` |  |
| `test_a_token_signed_by_the_wrong_key_is_refused` | `OidcConnectionTest::testAnUntrustworthyIdTokenSignsNobodyIn (signed by another key)` |  |
| `test_provider_can_be_switched_off` | `OidcConnectionTest::testASwitchedOffProviderIsGone` |  |
| `test_provider_cannot_be_deleted_while_it_has_users` | `OidcConnectionTest::testAProviderWithAccountsIsNotDeleted` |  |
| `test_unused_provider_can_be_deleted` | `OidcConnectionTest::testAnUnusedProviderIsDeleted` |  |

## `test_passwordless.py` (19)

| Python | PHP | Note |
|---|---|---|
| `test_login_page_offers_passwordless_when_enabled` | `PasswordlessTest::testTheLoginPageOffersACodeAndALink` |  |
| `test_not_offered_when_the_server_cannot_send_email` | `PasswordlessTest::testNotOfferedWhenTheServerCannotSendEmail` |  |
| `test_not_offered_to_an_application_that_disables_it` | `PasswordlessTest::testNotOfferedToAnApplicationThatDisablesIt` |  |
| `test_code_signs_in_and_creates_the_account` | `PasswordlessTest::testACodeSignsInAndCreatesTheAccount` |  |
| `test_a_second_sign_in_reuses_the_account` | `PasswordlessTest::testASecondSignInReusesTheAccount` |  |
| `test_typed_codes_tolerate_spaces` | `PasswordlessTest::testTypedCodesTolerateSpaces` |  |
| `test_a_wrong_code_is_refused_and_a_budget_ends_the_challenge` | `PasswordlessTest::testAWrongCodeIsRefusedAndABudgetEndsTheChallenge` |  |
| `test_a_code_only_works_in_the_browser_that_asked` | `PasswordlessTest::testACodeOnlyWorksInTheBrowserThatAsked` |  |
| `test_a_code_is_single_use` | `PasswordlessTest::testACodeIsSingleUse` |  |
| `test_link_signs_in_from_any_browser` | `PasswordlessTest::testALinkSignsInFromAnyBrowser` |  |
| `test_opening_the_link_does_not_spend_it` | `PasswordlessTest::testOpeningTheLinkDoesNotSpendIt` |  |
| `test_a_link_is_single_use` | `PasswordlessTest::testALinkIsSingleUse` |  |
| `test_an_unknown_link_is_refused` | `PasswordlessTest::testAnUnknownLinkIsRefused` |  |
| `test_sends_are_rate_limited` | `PasswordlessTest::testSendsAreRateLimited` |  |
| `test_garbage_is_refused_without_sending` | `PasswordlessTest::testGarbageIsRefusedWithoutSending` |  |
| `test_a_password_account_with_the_same_address_is_a_different_account` | `PasswordlessTest::testAPasswordAccountWithTheSameAddressIsADifferentAccount` |  |
| `test_a_disabled_account_cannot_sign_in` | `PasswordlessTest::testADisabledAccountCannotSignIn` |  |
| `test_passwordless_completes_an_authorization_request` | `PasswordlessTest::testPasswordlessCompletesAnAuthorizationRequest` |  |
| `test_the_email_connection_is_built_in` | `PasswordlessTest::testTheEmailConnectionIsBuiltIn` |  |

## `test_pkce_security.py` (16)

| Python | PHP | Note |
|---|---|---|
| `test_authorize_without_pkce_is_rejected_for_public_client` | `PkceSecurityTest::testAuthorizeWithoutPkceIsRejectedForPublicClient` |  |
| `test_authorize_without_pkce_is_rejected_for_confidential_client` | `PkceSecurityTest::testAuthorizeWithoutPkceIsRejectedForConfidentialClient` |  |
| `test_plain_challenge_method_is_rejected` | `PkceSecurityTest::testPlainChallengeMethodIsRejected` |  |
| `test_missing_challenge_method_is_rejected` | `PkceSecurityTest::testMissingChallengeMethodIsRejected` |  |
| `test_wrong_code_verifier_is_rejected` | `PkceSecurityTest::testWrongCodeVerifierIsRejected` |  |
| `test_missing_code_verifier_is_rejected` | `PkceSecurityTest::testMissingCodeVerifierIsRejected` |  |
| `test_replayed_code_is_rejected_and_revokes_issued_tokens` | `PkceSecurityTest::testReplayedCodeIsRejectedAndRevokesIssuedTokens` |  |
| `test_expired_code_is_rejected` | `PkceSecurityTest::testExpiredCodeIsRejected` |  |
| `test_expired_code_is_not_consumed` | `PkceSecurityTest::testExpiredCodeIsNotConsumed` |  |
| `test_code_cannot_be_redeemed_by_a_different_client` | `PkceSecurityTest::testCodeCannotBeRedeemedByADifferentClient` |  |
| `test_wrong_client_secret_is_rejected_with_a_challenge` | `PkceSecurityTest::testWrongClientSecretIsRejectedWithAChallenge` |  |
| `test_unregistered_redirect_uri_does_not_redirect` | `PkceSecurityTest::testUnregisteredRedirectUriDoesNotRedirect` |  |
| `test_redirect_uri_must_match_at_token_endpoint` | `PkceSecurityTest::testRedirectUriMustMatchAtTokenEndpoint` |  |
| `test_unknown_client_is_rejected_before_anyone_is_asked_to_sign_in` | `PkceSecurityTest::testUnknownClientIsRejectedBeforeAnyoneIsAskedToSignIn` |  |
| `test_unknown_code_is_rejected` | `PkceSecurityTest::testUnknownCodeIsRejected` |  |
| `test_inactive_user_cannot_redeem_code` | `PkceSecurityTest::testInactiveUserCannotRedeemCode` |  |

## `test_rbac.py` (17)

| Python | PHP | Note |
|---|---|---|
| `test_without_rbac_the_apis_permissions_are_the_only_bound` | `RbacTest::testWithoutRolesTheApisPermissionsAreTheOnlyBound` |  |
| `test_rbac_narrows_the_token_to_what_the_users_roles_grant` | `RbacTest::testRolesNarrowTheTokenToWhatTheyGrant` |  |
| `test_user_holding_nothing_is_refused_at_authorize` | `RbacTest::testSomebodyHoldingNothingIsRefusedBeforeACodeExists` |  |
| `test_role_withdrawn_between_authorize_and_redeem_is_honoured` | `RbacTest::testARoleTakenAwayBeforeRedemptionIsHonoured` |  |
| `test_permission_removed_from_the_api_leaves_every_role` | `RbacTest::testAPermissionTheApiStopsDefiningLeavesEveryRole` |  |
| `test_machine_clients_are_governed_by_grants_not_roles` | `RbacTest::testMachineClientsAreGovernedByTheirGrantsNotByRoles` |  |
| `test_operator_token_is_narrowed_to_their_role` | `RbacTest::testAnOperatorsTokenIsNarrowedToTheirRoleAndHeldToIt` |  |
| `test_a_user_with_no_role_cannot_reach_the_management_api` | `RbacTest::testSomebodyWithNoRoleCannotReachTheManagementApi` |  |
| `test_the_management_api_cannot_have_rbac_turned_off` | `RbacTest::testTheManagementApiCannotHaveRolesTurnedOff` |  |
| `test_rbac_can_be_switched_on_an_ordinary_api` | `RbacTest::testRolesCanBeSwitchedOnAndOffForAnOrdinaryApi` |  |
| `test_role_lifecycle` | `RbacTest::testARoleFromDefinitionToDeletion` |  |
| `test_role_cannot_reference_a_permission_that_does_not_exist` | `RbacTest::testARoleCannotGrantWhatNoApiDefines` |  |
| `test_duplicate_role_name_is_a_conflict` | `RbacTest::testARoleNameIsTakenOnce` |  |
| `test_setting_a_users_roles_replaces_them` | `RbacTest::testSettingSomebodysRolesReplacesThem` |  |
| `test_conferring_authority_needs_update_roles` | `RbacTest::testConferringAuthorityNeedsUpdateRoles` |  |
| `test_roles_are_searchable` | `RbacTest::testRolesAreSearchedByNameAndDescription` |  |
| `test_administrator_bootstrap_is_idempotent` | `RbacTest::testTheAdministratorBootstrapIsIdempotent` |  |

## `test_refresh_token.py` (15)

| Python | PHP | Note |
|---|---|---|
| `test_issued_at_code_redemption_to_a_client_registered_for_it` | `RefreshTokenTest::testIssuedWithTheCodesTokensToAClientRegisteredForIt` |  |
| `test_family_deadline_is_fixed_at_sign_in` | `RefreshTokenTest::testNoAmountOfRefreshingOutlivesTheFamilysDeadline` |  |
| `test_refresh_rotates_both_tokens` | `RefreshTokenTest::testARefreshRotatesBothTokens` |  |
| `test_replaying_a_spent_token_revokes_the_whole_family` | `RefreshTokenTest::testReplayingASpentTokenRevokesTheWholeFamily` |  |
| `test_concurrent_refreshes_of_one_token_let_exactly_one_win` | `PhpDbAccessTokenRepositoryTest::testTwoRefreshesOfOneTokenAtOnceLetExactlyOneWin` | The row lock shown with two real sessions instead of two threads. |
| `test_scope_may_narrow_but_not_widen` | `RefreshTokenTest::testScopeMayNarrowButNeverWiden` |  |
| `test_audience_is_carried_and_cannot_be_retargeted` | `RefreshTokenTest::testTheAudienceIsCarriedAndCannotBeRetargeted` |  |
| `test_roles_are_re_read_on_every_refresh` | `RefreshTokenTest::testRolesAreReadAgainOnEveryRefresh` |  |
| `test_expired_token_is_refused_and_not_spent` | `RefreshTokenTest::testAnExpiredTokenIsRefusedAndNeitherSpentNorRevoked` |  |
| `test_unknown_token_is_refused` | `RefreshTokenTest::testAnUnknownTokenIsRefused` |  |
| `test_another_client_presenting_the_token_is_refused_without_burning_it` | `RefreshTokenTest::testAnotherClientPresentingTheTokenIsRefusedWithoutBurningIt` |  |
| `test_client_not_registered_for_the_grant_is_refused` | `ClientCredentialsTest::testClientNotRegisteredForTheGrantIsRefused` |  |
| `test_deactivated_user_is_refused` | `RefreshTokenTest::testADeactivatedAccountIsRefused` |  |
| `test_replayed_authorization_code_revokes_the_family_it_started` | `RefreshTokenTest::testAReplayedCodeRevokesTheFamilyItStarted` |  |
| `test_registering_refresh_without_authorization_code_is_refused` | `RefreshTokenTest::testRefreshTokensWithoutTheCodeFlowCannotBeRegistered` |  |

## `test_rp_logout.py` (6)

| Python | PHP | Note |
|---|---|---|
| `test_discovery_advertises_the_endpoint` | `RpLogoutTest::testDiscoveryAdvertisesTheEndpoint` |  |
| `test_id_token_hint_ends_the_session_and_redirects_to_a_registered_origin` | `RpLogoutTest::testAHintForTheSessionsPersonEndsItAndReturnsToTheRegisteredUriWithState` |  |
| `test_without_a_hint_the_session_survives` | `RpLogoutTest::testWithoutAHintThePersonIsAskedAndTheSessionSurvivesUntilTheyConfirm` |  |
| `test_a_hint_for_another_user_does_not_end_this_session` | `RpLogoutTest::testAHintForAnotherPersonDoesNotEndThisSession` |  |
| `test_a_forged_hint_is_ignored` | `RpLogoutTest::testAForgedHintIsNoProof` |  |
| `test_an_unregistered_redirect_falls_back_to_the_login_page` | `RpLogoutTest::testAnUnregisteredRedirectIsNotFollowed` |  |

## `test_signing_backends.py` (15)

| Python | PHP | Note |
|---|---|---|
| `test_postgres_backend_round_trip` | `PostgresSigningBackendTest → SigningBackendContract::aCreatedKeyIsTheActiveKeyAndWhatItSignsVerifiesAgainstItsPublishedJwk` |  |
| `test_factory_returns_postgres_by_default` | `RemoteSigningTest::testThePostgresBackendIsTheDefault` |  |
| `test_postgres_backend_refuses_to_sign_with_a_retired_kid` | `PostgresSigningBackendTest::testARetiredKidCannotBeUsedToSign` |  |
| `test_aws_backend_sends_the_message_and_round_trips` | `AwsKmsKeyTest::testKmsIsHandedTheDigestAndTheAlgorithmByItsOwnName`<br>`AwsKmsKeyTest → RemoteSigningKeyContract::aTokenItSignsVerifiesAgainstThePublishedKeys` | Digest, not message: see DEVIATIONS, Signing. |
| `test_aws_kid_does_not_leak_the_account` | `AwsKmsKeyTest → RemoteSigningKeyContract::itsKidIsTheThumbprintOfItsKeyAndNamesNoAccount` | `kid` is the key thumbprint (DEVIATIONS). |
| `test_gcp_backend_signs_a_digest_and_round_trips` | `GcpKmsKeyTest::testCloudKmsIsHandedTheDigestWithItsChecksumAndABearerToken`<br>`GcpKmsKeyTest → RemoteSigningKeyContract::aTokenItSignsVerifiesAgainstThePublishedKeys` |  |
| `test_gcp_kid_does_not_leak_the_project` | `GcpKmsKeyTest → RemoteSigningKeyContract::itsKidIsTheThumbprintOfItsKeyAndNamesNoAccount` | `kid` is the key thumbprint (DEVIATIONS). |
| `test_azure_backend_signs_a_digest_and_round_trips` | `AzureKeyVaultKeyTest::testKeyVaultIsHandedTheDigestUnderTheJoseName`<br>`AzureKeyVaultKeyTest → RemoteSigningKeyContract::aTokenItSignsVerifiesAgainstThePublishedKeys` |  |
| `test_azure_kid_is_derived_from_name_and_version` | `AzureKeyVaultKeyTest → RemoteSigningKeyContract::itsKidIsTheThumbprintOfItsKeyAndNamesNoAccount` | `kid` is the key thumbprint, not `<name>-<version>` (DEVIATIONS). |
| `test_remote_backends_refuse_unsupported_algorithms` | `WiringTest::testASigningAlgorithmNoKeyCanProduceIsRefused`<br>`GcpKmsKeyTest::testEveryRsaPkcs1Sha256KeySizeSignsRs256AndNothingElseDoes` | Only RS256 exists; anything else is refused by the settings. |
| `test_custom_backend_loaded_from_an_import_path` | `RemoteSigningTest::testTokensSignedByAKeyTheServerNeverHoldsVerifyAgainstItsJwks` |  |
| `test_custom_backend_missing_a_method_is_refused_at_startup` | `RemoteSigningTest::testANameThatIsNeitherABackendNorAKeyClassIsRefused` | A class must implement `RemoteSigningKey`; checked when the signer is built. |
| `test_unknown_backend_name_is_refused` | `RemoteSigningTest::testANameThatIsNeitherABackendNorAKeyClassIsRefused` |  |
| `test_remote_backend_without_a_key_reference_is_refused` | `SettingsTest::testARemoteSigningBackendNeedsItsKeyReference` |  |
| `test_seam_supports_a_non_extractable_backend_end_to_end` | `RemoteSigningTest::testTokensSignedByAKeyTheServerNeverHoldsVerifyAgainstItsJwks`<br>`RemoteTokenSignerTest::testWhatItSignsIsRs256OverTheExactInputAndVerifiesAgainstTheActiveKey` |  |

## `test_social_login.py` (18)

| Python | PHP | Note |
|---|---|---|
| `test_unconfigured_provider_is_a_404_like_an_unknown_one` | `SocialLoginTest::testAnUnconfiguredProviderIsA404LikeAnUnknownOne` |  |
| `test_login_page_offers_configured_providers` | `SocialLoginTest::testTheLoginPageOffersEachConfiguredProvider` |  |
| `test_start_sends_state_pkce_and_a_pairing_cookie` | `SocialLoginTest::testStartingSendsStatePkceAndAPairingCookie` |  |
| `test_first_sign_in_creates_a_verified_password_less_account` | `SocialLoginTest::testAFirstSignInCreatesAVerifiedPasswordLessAccount` |  |
| `test_identity_is_matched_by_subject_not_email` | `SocialLoginTest::testTheIdentityIsMatchedBySubjectNotByEmail` |  |
| `test_second_subject_with_the_same_verified_email_joins_the_account` | `SocialLoginTest::testASecondSubjectWithTheSameVerifiedAddressJoinsTheAccount` |  |
| `test_verified_email_links_to_the_existing_local_account` | `SocialLoginTest::testAVerifiedAddressLinksToTheExistingLocalAccount` |  |
| `test_unverified_email_links_nothing_and_creates_nothing` | `SocialLoginTest::testAnUnverifiedAddressLinksNothingAndCreatesNothing` |  |
| `test_auto_link_can_be_switched_off` | `SocialLoginTest::testLinkingByAddressCanBeSwitchedOff` |  |
| `test_callback_without_the_pairing_cookie_is_refused` | `SocialLoginTest::testACallbackWithoutThePairingCookieIsRefused` |  |
| `test_state_is_single_use` | `SocialLoginTest::testTheStateIsSingleUse` |  |
| `test_provider_error_is_not_echoed` | `SocialLoginTest::testTheProvidersErrorIsNotEchoed` |  |
| `test_failed_exchange_is_reported_generically` | `SocialLoginTest::testAFailedExchangeIsReportedGenericallyAndLogged` |  |
| `test_social_sign_in_returns_to_the_authorization_request` | `SocialLoginTest::testTheSignInReturnsToTheAuthorizationRequest` |  |
| `test_social_sign_in_still_demands_an_enrolled_second_factor` | `SocialLoginTest::testTheSignInStillAsksForAConfirmedSecondFactor` |  |
| `test_amr_reports_an_external_sign_in_in_the_id_token` | `SocialLoginTest::testTheIdTokenReportsAnExternalSignIn` |  |
| `test_password_sign_in_reports_pwd` | `SocialLoginTest::testAPasswordSignInStillReportsPwd` |  |
| `test_github_identity_uses_the_primary_verified_email` | `SocialLoginTest::testGitHubSignsInWithThePrimaryVerifiedAddress` |  |
