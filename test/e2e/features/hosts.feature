Feature: Each host serves its own surface
  Clavia serves auth.clavia.test and management.clavia.test from one application, and Caddy keeps
  them apart: a machine plane reachable on the origin where credentials are typed would undo the
  separation the design relies on.

  Scenario Outline: The authorization server's host refuses the machine planes
    When I request "<path>" on the "auth" host
    Then the status is 404

    Examples:
      | path          |
      | /api/v1/users |
      | /scim/v2/Users |
      | /metrics      |

  Scenario Outline: The management host serves the planes that want a token
    When I request "<path>" on the "management" host
    Then the status is 401

    Examples:
      | path          |
      | /api/v1/users |
      | /scim/v2/Users |

  Scenario Outline: The management host hands everything else to the dashboard
    When I request "<path>" on the "management" host
    Then I am sent to "/dashboard" on the "management" host

    Examples:
      | path                                |
      | /oauth2/token                       |
      | /oauth2/authorize                   |
      | /auth/login                         |
      | /.well-known/openid-configuration   |

  Scenario: Metrics are the internal listener's alone
    When I request "/metrics" on the "management" host
    Then the status is 404

  Scenario: The internal listener is published nowhere
    Then the internal listener answers nobody outside the network
