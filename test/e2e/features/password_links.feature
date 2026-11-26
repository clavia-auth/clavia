Feature: Choosing a password from a link
  A link in a mail sets a password once. The person who forgot theirs asks for it on the sign-in page,
  and an account an operator created without one is sent the same link from the Management API.

  Scenario: A person who forgot their password asks for a new one
    Given a person who signs in with a password
    And an application that allows signing in and refreshing, redirecting to "https://app.clavia.test/callback"
    When the person asks for a new password
    Then an email arrives for the person
    And it comes from "no-reply@clavia.test"
    And its subject says "Choose a new password"
    And it carries a link to "/auth/password/reset"
    When the person chooses the password "a brand new passphrase" from the link
    Then the password is changed
    And choosing a password with the same link again is refused
    And the old password no longer signs them in
    And the chosen password signs them in

  Scenario: An operator invites an account that has no password
    Given a person who was created without a password
    And an application that allows signing in and refreshing, redirecting to "https://app.clavia.test/callback"
    When an operator sends the person a password link
    Then an email arrives for the person
    And its subject says "You have been invited"
    And it carries a link to "/auth/password/reset"
    When the person chooses the password "a passphrase of their own" from the link
    Then the password is changed
    And choosing a password with the same link again is refused
    And the chosen password signs them in
