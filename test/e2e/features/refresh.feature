Feature: Refresh tokens rotate, and a replay ends the family
  A refresh token is spent once. One presented a second time means two parties hold it, and Clavia
  cannot tell which is the application: it revokes the whole family, the newer token included.

  Background:
    Given a person who signs in with a password
    And an application that allows signing in and refreshing, redirecting to "https://app.clavia.test/callback"
    When the person signs in to the application, asking for "openid"
    And the application redeems the code with its verifier
    Then the token response carries a refresh token

  Scenario: A refresh token is replaced by a new one when it is used
    When the application refreshes with it
    Then it is given a new refresh token and a new access token

  Scenario: A spent refresh token is refused
    When the application refreshes with it
    And the application presents the spent refresh token again
    Then it is refused as an invalid grant

  Scenario: Replaying a spent refresh token revokes the one issued in its place
    When the application refreshes with it
    And the application presents the spent refresh token again
    And the application presents the refresh token it was last given
    Then it is refused as an invalid grant
