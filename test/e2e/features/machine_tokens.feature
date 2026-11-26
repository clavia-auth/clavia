Feature: A machine client's tokens, and what a wrong secret costs
  A confidential client holds a token, asks about it, and gives it back; once given back, nothing
  accepts it. A client address that keeps presenting a wrong secret is refused before any secret is
  checked, for a while.

  Scenario: A token is introspected, revoked, and refused from then on
    Given the machine client of the stack
    When it asks for a token for the Management API
    Then introspecting the token says it is active and was issued to the client
    And the Management API accepts it
    When the client revokes the token
    Then introspecting the token says it is no longer active
    And the Management API refuses it

  Scenario: Wrong secrets are refused, then the address waits
    Given the machine client of the stack
    When it presents a wrong secret 5 times
    Then each was refused as an invalid client, with a challenge
    And even its right secret is then refused for now, with a time to wait
    And once that time has passed, its right secret is accepted again
