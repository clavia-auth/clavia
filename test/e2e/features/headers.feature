Feature: What Caddy and the server say about every answer
  The headers that keep a sign-in page out of caches and frames, and a browser on HTTPS, are set where
  the stack answers, partly by Caddy and partly by the application: only the deployed stack shows them
  together. Its static files are named by their content, so a browser never pairs new pages with an old
  stylesheet.

  Scenario: A sign-in page is neither cached, framed nor run with any script
    When I request "/auth/login" on the "auth" host
    Then the status is 200
    And the answer is not cacheable
    And it is served over HTTPS only, for a year
    And it cannot be framed
    And its policy allows no inline script and nothing from another origin

  Scenario: An error from the token endpoint is not cacheable either
    When a client posts a token request without a grant type
    Then the status is 400
    And the answer is not cacheable
    And it is served over HTTPS only, for a year

  Scenario: The stylesheet a page names is the one served
    When I request "/auth/login" on the "auth" host
    And I request the stylesheet the page names
    Then the status is 200
    And it is CSS, revalidated on every use
    And its content is what its address names
