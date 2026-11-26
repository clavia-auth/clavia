<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\E2e\Context;

use Behat\Behat\Context\Context;
use Behat\Behat\Hook\Scope\BeforeScenarioScope;
use Behat\Hook\BeforeScenario;
use Behat\Step\Then;
use Behat\Step\When;
use Fig\Http\Message\RequestMethodInterface;
use GuzzleHttp\Cookie\SetCookie;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWKSet;
use Jose\Component\Signature\Algorithm\RS256;
use Jose\Component\Signature\JWSVerifier;
use Jose\Component\Signature\Serializer\CompactSerializer;
use Psr\Http\Message\ResponseInterface;

/**
 * The authorization code flow with PKCE as a browser and an application live it: the authorization
 * request, the real login page and its form, the redirect back with a code, the token request, userinfo
 * and the ID token checked against the keys the server publishes over TLS.
 */
/**
 * @psalm-suppress MissingConstructor The scenario's hook gathers what this context shares, before any step.
 */
final class SignInContext implements Context
{
    private Browser $browser;
    private ManagementContext $management;

    private string $verifier = '';
    private string $state = '';
    private string $nonce = '';
    private string $code = '';
    /** @var list<string> the Set-Cookie lines of the login form's answer, as the server sent them */
    private array $loginCookies = [];
    /** @var array<string, mixed> */
    private array $tokens = [];

    #[BeforeScenario]
    public function gather(BeforeScenarioScope $scope): void
    {
        $this->browser = Contexts::of($scope, HttpContext::class)->browser();
        $this->management = Contexts::of($scope, ManagementContext::class);
    }

    #[When('the person signs in to the application, asking for :scope')]
    public function thePersonSignsIn(string $scope): void
    {
        $page = $this->loginPage($scope);
        $person = $this->management->person();

        $this->postLogin($page, $person->email, $person->password);
        $this->loginCookies = array_values($this->browser->last()->getHeader('Set-Cookie'));
        $this->landAtTheApplication();
    }

    /** Start an authorization request with nobody signed in, and stop at the login page it sends to. */
    public function loginPage(string $scope): LoginPage
    {
        $application = $this->management->application();
        $this->verifier = self::base64Url(random_bytes(48));
        $this->state = bin2hex(random_bytes(8));
        $this->nonce = bin2hex(random_bytes(8));

        $authorize = '/oauth2/authorize?' . http_build_query([
            'response_type' => 'code',
            'client_id' => $application->clientId,
            'redirect_uri' => $application->redirectUri,
            'scope' => $scope,
            'state' => $this->state,
            'nonce' => $this->nonce,
            'code_challenge' => self::base64Url(hash('sha256', $this->verifier, true)),
            'code_challenge_method' => 'S256',
        ]);
        $this->browser->request(RequestMethodInterface::METHOD_GET, $this->browser->stack()->authUrl($authorize));

        // Not signed in: sent to the login page, which is shown, not redirected through.
        $page = $this->browser->follow(self::toTheApplication($application));
        Check::same(
            200,
            $page->getStatusCode(),
            'the login page: ' . $page->getHeaderLine('Location') . ' ' . substr((string) $page->getBody(), 0, 200),
        );
        $html = (string) $page->getBody();
        Check::same(1, preg_match('/name="csrf_token" value="([^"]+)"/', $html, $csrf), 'no CSRF token');
        preg_match('/name="state" value="([^"]*)"/', $html, $handle);

        return new LoginPage($html, $csrf[1], $handle[1] ?? '');
    }

    /** Post the login form, and answer what the server did with it. */
    public function postLogin(LoginPage $page, string $email, string $password): ResponseInterface
    {
        return $this->browser->request(
            RequestMethodInterface::METHOD_POST,
            $this->browser->stack()->authUrl('/auth/login'),
            ['form_params' => [
                'email' => $email,
                'password' => $password,
                'csrf_token' => $page->csrfToken,
                'state' => $page->handle,
            ]],
        );
    }

    /** Follow what a sign-in answered until the redirect to the application, and keep its code. */
    public function landAtTheApplication(): void
    {
        $application = $this->management->application();
        $stack = $this->browser->stack();

        $answer = $this->browser->follow(self::toTheApplication($application));
        Check::same(302, $answer->getStatusCode(), 'back to the application: ' . (string) $answer->getBody());
        $location = $this->browser->location();
        Check::startsWith($application->redirectUri . '?', $location);
        parse_str((string) parse_url($location, PHP_URL_QUERY), $query);
        Check::same($this->state, $query['state'] ?? null, 'the state comes back unchanged');
        Check::same($stack->authUrl(), $query['iss'] ?? null, 'the issuer is named (RFC 9207)');
        $code = $query['code'] ?? null;
        Check::string($code, 'a code');
        $this->code = $code;
    }

    private static function toTheApplication(Application $application): callable
    {
        return static fn (string $target): bool => str_starts_with($target, $application->redirectUri);
    }

    #[Then('the session cookie is host-only, Secure, HttpOnly and SameSite')]
    public function theSessionCookieIsHostOnly(): void
    {
        Check::that($this->loginCookies !== [], 'the login form set no cookie');
        $session = array_filter(
            array_map(static fn (string $line): SetCookie => SetCookie::fromString($line), $this->loginCookies),
            static fn (SetCookie $cookie): bool => (int) $cookie->getMaxAge() !== 0
                && $cookie->getExpires() !== 0 && $cookie->getValue() !== '',
        );
        Check::that($session !== [], 'the login form set no session: ' . implode(' | ', $this->loginCookies));
        foreach ($session as $cookie) {
            $name = (string) $cookie->getName();
            Check::same(null, $cookie->getDomain(), $name . ' names a Domain, so subdomains would receive it');
            Check::that($cookie->getSecure(), $name . ' is not Secure');
            Check::that($cookie->getHttpOnly(), $name . ' is not HttpOnly');
            Check::same('/', $cookie->getPath(), $name . ' is not scoped to the whole origin');
        }
        foreach ($this->loginCookies as $line) {
            Check::matches('/;\s*SameSite=(Lax|Strict)/i', $line);
        }
    }

    #[When('the application redeems the code with its verifier')]
    public function theApplicationRedeemsTheCode(): void
    {
        $application = $this->management->application();
        $this->redeem([
            'grant_type' => 'authorization_code',
            'client_id' => $application->clientId,
            'redirect_uri' => $application->redirectUri,
            'code' => $this->code,
            'code_verifier' => $this->verifier,
        ]);
        Check::same(200, $this->browser->last()->getStatusCode(), (string) $this->browser->last()->getBody());
    }

    #[Then('the token response is not cacheable and carries an access token and an ID token')]
    public function theTokenResponse(): void
    {
        $response = $this->browser->last();
        Check::includes('no-store', $response->getHeaderLine('Cache-Control'));
        Check::same('no-cache', $response->getHeaderLine('Pragma'));
        Check::string($this->token('access_token'));
        Check::same('Bearer', $this->token('token_type'));
        Check::string($this->token('id_token'));
    }

    #[Then('the ID token verifies against the published keys and names the person')]
    public function theIdTokenVerifies(): void
    {
        $stack = $this->browser->stack();
        $jwks = $this->browser->request(RequestMethodInterface::METHOD_GET, $stack->authUrl('/oidc/jwks.json'));
        Check::same(200, $jwks->getStatusCode());
        $keys = JWKSet::createFromJson((string) $jwks->getBody());

        $jws = new CompactSerializer()->unserialize((string) $this->tokens['id_token']);
        $verified = new JWSVerifier(new AlgorithmManager([new RS256()]))->verifyWithKeySet($jws, $keys, 0);
        Check::that($verified, 'the ID token does not verify against the JWKS fetched over TLS');

        /** @var array<string, mixed> $claims */
        $claims = json_decode((string) $jws->getPayload(), true, flags: JSON_THROW_ON_ERROR);
        Check::same($stack->authUrl(), $claims['iss'] ?? null);
        Check::same($this->management->person()->id, $claims['sub'] ?? null);
        Check::contains($this->management->application()->clientId, (array) ($claims['aud'] ?? []));
        Check::same($this->nonce, $claims['nonce'] ?? null);
        Check::that(($claims['exp'] ?? 0) > time(), 'the ID token has expired');
    }

    #[Then('userinfo, asked with the access token, gives the person\'s address')]
    public function userinfoGivesTheAddress(): void
    {
        $userinfo = $this->browser->stack()->authUrl('/oidc/userinfo');
        $response = $this->browser->request(RequestMethodInterface::METHOD_GET, $userinfo, [
            'headers' => ['Authorization' => 'Bearer ' . (string) $this->tokens['access_token']],
        ]);
        Check::same(200, $response->getStatusCode(), (string) $response->getBody());
        /** @var array<string, mixed> $claims */
        $claims = json_decode((string) $response->getBody(), true, flags: JSON_THROW_ON_ERROR);
        Check::same($this->management->person()->id, $claims['sub'] ?? null);
        Check::same($this->management->person()->email, $claims['email'] ?? null);
    }

    /** A string of what the last token request answered, or null when it answered none. */
    public function token(string $name): ?string
    {
        $tokens = $this->tokens;

        return isset($tokens[$name]) && is_string($tokens[$name]) ? $tokens[$name] : null;
    }

    /** Post to the token endpoint as the application does, and keep what it answered. */
    public function redeem(array $form): void
    {
        $endpoint = $this->browser->stack()->authUrl('/oauth2/token');
        $this->browser->request(RequestMethodInterface::METHOD_POST, $endpoint, ['form_params' => $form]);
        /** @var array<string, mixed> $body */
        $body = json_decode((string) $this->browser->last()->getBody(), true) ?? [];
        $this->tokens = $body;
    }

    private static function base64Url(string $bytes): string
    {
        return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
    }
}
