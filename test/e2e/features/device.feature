Feature: Signing in on a device without a browser
  A television asks for a code (RFC 8628), the person types it on their phone where they are signed in,
  and the television, polling at the pace it was given, is handed its tokens once they approve.

  Background:
    Given a person who signs in with a password
    And an application on a device without a browser

  Scenario: The person approves the device, and the device gets its tokens
    When the device asks for a code, asking for "openid"
    Then it is told where to go, which code to type and how often to ask
    And asking for its tokens now, it is told to wait
    When the person approves the code from their browser
    And the device asks for its tokens again, at the pace it was given
    Then it is given an access token and an ID token

  Scenario: The person refuses the device
    When the device asks for a code, asking for "openid"
    And the person refuses the code from their browser
    And the device asks for its tokens again, at the pace it was given
    Then it is told the person refused
