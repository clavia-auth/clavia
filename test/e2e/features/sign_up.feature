Feature: Signing up, and proving the address
  A pool that takes sign-ups and requires a verified address mails a link, and the link proves the
  mailbox, nothing more: it never signs anyone in, and a mail scanner opening it spends nothing.

  Background:
    Given a pool that takes sign-ups and requires a verified address
    And an application whose people come from that pool, redirecting to "https://app.clavia.test/callback"
    And a visitor with a new address and password

  Scenario: A visitor signs up and confirms their address from the mail
    When the visitor signs up at the application with that address and password
    Then they are asked to check their email, and nobody is signed in
    And an email arrives for the person
    And it comes from "no-reply@clavia.test"
    And its subject says "Confirm your email address"
    And it carries a link to "/auth/verify-email"
    When the link is opened twice, as a mail scanner would
    Then the page still asks them to confirm
    When they confirm their address
    Then the address is confirmed, and nobody is signed in
    And confirming with the same link again is refused
    And they can sign in with that address and password
