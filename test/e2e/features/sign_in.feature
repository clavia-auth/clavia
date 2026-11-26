Feature: Signing in as a browser does it
  The authorization code flow with PKCE, through the real login page: what Caddy, PHP-FPM and the
  cookie rules of a browser add to what the acceptance suite proves in-process.

  Background:
    Given a person who signs in with a password
    And an application that allows signing in and refreshing, redirecting to "https://app.clavia.test/callback"

  Scenario: Authorization code with PKCE
    When the person signs in to the application, asking for "openid profile email"
    Then the session cookie is host-only, Secure, HttpOnly and SameSite
    When the application redeems the code with its verifier
    Then the token response is not cacheable and carries an access token and an ID token
    And the ID token verifies against the published keys and names the person
    And userinfo, asked with the access token, gives the person's address
