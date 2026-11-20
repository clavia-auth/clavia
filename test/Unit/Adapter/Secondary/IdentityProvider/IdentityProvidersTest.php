<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Adapter\Secondary\IdentityProvider;

use Clavia\Adapter\Secondary\IdentityProvider\ConfiguredIdentityProviders;
use Clavia\Adapter\Secondary\IdentityProvider\GitHubIdentityProvider;
use Clavia\Adapter\Secondary\IdentityProvider\GoogleIdentityProvider;
use Clavia\Adapter\Secondary\IdentityProvider\ProviderHttp;
use Clavia\Application\Port\IdentityProvider;
use Clavia\Application\Port\IdentityProviderFailed;
use Clavia\Domain\OAuth2\CodeChallenge;
use Clavia\Domain\OAuth2\CodeVerifier;
use ClaviaTest\Support\Fake\FakeHttpClient;
use ClaviaTest\Support\Fake\SeededRandomSource;
use ClaviaTest\Support\RecordingLogger;
use GuzzleHttp\Exception\ConnectException;
use Laminas\Diactoros\RequestFactory;
use Laminas\Diactoros\Response\HtmlResponse;
use Laminas\Diactoros\Response\JsonResponse;
use Laminas\Diactoros\StreamFactory;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;

/**
 * The Google and GitHub adapters against a fake wire: what they send, and what they make
 * of what comes back. Nothing here reaches either provider.
 */
final class IdentityProvidersTest extends TestCase
{
    private const string REDIRECT_URI = 'https://auth.clavia.test/auth/social/google/callback';

    private FakeHttpClient $http;
    private RecordingLogger $logger;
    private CodeVerifier $verifier;

    #[\Override]
    protected function setUp(): void
    {
        $this->http = new FakeHttpClient();
        $this->logger = new RecordingLogger();
        $this->verifier = CodeVerifier::generate(new SeededRandomSource());
    }

    public function testTheAuthorizationUrlCarriesTheCodeFlowWithPkce(): void
    {
        $challenge = CodeChallenge::forVerifier($this->verifier);

        $url = $this->google()->authorizationUrl(self::REDIRECT_URI, 'the-state', $challenge);

        self::assertStringStartsWith(GoogleIdentityProvider::AUTHORIZATION_ENDPOINT . '?', $url);
        parse_str((string) parse_url($url, PHP_URL_QUERY), $query);
        self::assertSame([
            'response_type' => 'code',
            'client_id' => 'google-client',
            'redirect_uri' => self::REDIRECT_URI,
            'scope' => 'openid email profile',
            'state' => 'the-state',
            'code_challenge' => $challenge->value,
            'code_challenge_method' => 'S256',
        ], $query);
    }

    public function testGoogleExchangesTheCodeServerSideAndReadsUserinfo(): void
    {
        $this->http->answerWith(FakeHttpClient::routes([
            GoogleIdentityProvider::TOKEN_ENDPOINT => new JsonResponse(['access_token' => 'at-1']),
            GoogleIdentityProvider::USERINFO_ENDPOINT => static fn (RequestInterface $request): ResponseInterface
                => $request->getHeaderLine('Authorization') === 'Bearer at-1'
                    ? new JsonResponse(['sub' => 'g-123', 'email' => 'ada@example.com', 'email_verified' => true])
                    : new JsonResponse([], 401),
        ]));

        $identity = $this->google()->identify('the-code', self::REDIRECT_URI, $this->verifier);

        self::assertSame('google', $identity->provider->value);
        self::assertSame('g-123', $identity->subject);
        self::assertSame('ada@example.com', $identity->verifiedEmail());
        $exchange = $this->http->requests[0];
        self::assertSame('POST', $exchange->getMethod());
        self::assertSame('application/json', $exchange->getHeaderLine('Accept'));
        self::assertSame('application/x-www-form-urlencoded', $exchange->getHeaderLine('Content-Type'));
        self::assertSame([
            'grant_type' => 'authorization_code',
            'code' => 'the-code',
            'redirect_uri' => self::REDIRECT_URI,
            'client_id' => 'google-client',
            'client_secret' => 'google-secret',
            'code_verifier' => $this->verifier->value,
        ], FakeHttpClient::form($exchange));
    }

    public function testGoogleSaysUnverifiedWhenUserinfoDoesNotSayVerified(): void
    {
        $this->http->answerWith(FakeHttpClient::routes([
            GoogleIdentityProvider::TOKEN_ENDPOINT => new JsonResponse(['access_token' => 'at-1']),
            GoogleIdentityProvider::USERINFO_ENDPOINT => new JsonResponse(
                ['sub' => 'g-123', 'email' => 'ada@example.com', 'email_verified' => 'true'],
            ),
        ]));

        self::assertNull($this->google()->identify('c', self::REDIRECT_URI, $this->verifier)->verifiedEmail());
    }

    public function testGitHubUsesTheNumericIdAndThePrimaryVerifiedAddress(): void
    {
        $this->http->answerWith(FakeHttpClient::routes([
            GitHubIdentityProvider::TOKEN_ENDPOINT => new JsonResponse(['access_token' => 'gh-1']),
            GitHubIdentityProvider::USER_ENDPOINT => new JsonResponse(['id' => 4242, 'login' => 'ada']),
            GitHubIdentityProvider::EMAILS_ENDPOINT => new JsonResponse([
                ['email' => 'old@example.com', 'primary' => false, 'verified' => true],
                ['email' => 'me@example.com', 'primary' => true, 'verified' => true],
            ]),
        ]));

        $identity = $this->github()->identify('c', self::REDIRECT_URI, $this->verifier);

        self::assertSame('4242', $identity->subject);
        self::assertSame('me@example.com', $identity->verifiedEmail());
        foreach (array_slice($this->http->requests, 1) as $apiCall) {
            self::assertSame('application/vnd.github+json', $apiCall->getHeaderLine('Accept'));
            self::assertSame('Bearer gh-1', $apiCall->getHeaderLine('Authorization'));
            self::assertSame(ProviderHttp::USER_AGENT, $apiCall->getHeaderLine('User-Agent'));
        }
    }

    public function testGitHubWithoutAPrimaryVerifiedAddressVouchesForNone(): void
    {
        $this->http->answerWith(FakeHttpClient::routes([
            GitHubIdentityProvider::TOKEN_ENDPOINT => new JsonResponse(['access_token' => 'gh-1']),
            GitHubIdentityProvider::USER_ENDPOINT => new JsonResponse(['id' => 4242, 'email' => 'public@example.com']),
            GitHubIdentityProvider::EMAILS_ENDPOINT => new JsonResponse(
                [['email' => 'me@example.com', 'primary' => true, 'verified' => false]],
            ),
        ]));

        $identity = $this->github()->identify('c', self::REDIRECT_URI, $this->verifier);

        self::assertNull($identity->email);
        self::assertNull($identity->verifiedEmail());
    }

    /**
     * @param callable(RequestInterface): ResponseInterface $answer
     */
    #[DataProvider('unusableAnswers')]
    public function testAnyUnusableAnswerIsOneFailureAndIsLoggedWithoutItsBody(callable $answer, string $logged): void
    {
        $this->http->answerWith($answer);

        try {
            $this->github()->identify('c', self::REDIRECT_URI, $this->verifier);
            self::fail('An unusable answer was used.');
        } catch (IdentityProviderFailed) {
            self::assertTrue($this->logger->hasRecordContaining($logged), $logged);
            self::assertFalse($this->logger->hasRecordContaining('secret-token'));
        }
    }

    /** @return iterable<string, array{callable(RequestInterface): ResponseInterface, string}> */
    public static function unusableAnswers(): iterable
    {
        yield 'the provider is unreachable' => [
            static fn (RequestInterface $request): never => throw new ConnectException('down', $request),
            'could not be reached',
        ];
        yield 'the token endpoint refuses' => [
            static fn (): ResponseInterface => new JsonResponse(['error' => 'secret-token'], 400),
            'answered 400',
        ];
        yield 'a refused code reported with 200' => [
            static fn (): ResponseInterface => new JsonResponse(['error' => 'bad_verification_code']),
            'no access token',
        ];
        yield 'not JSON' => [
            static fn (): ResponseInterface => new HtmlResponse('<html>secret-token'),
            'did not answer JSON',
        ];
        yield 'JSON that is not an object' => [
            static fn (): ResponseInterface => new JsonResponse('x'),
            'not answer a JSON object',
        ];
        yield 'a profile without an id' => [
            FakeHttpClient::routes([
                GitHubIdentityProvider::TOKEN_ENDPOINT => new JsonResponse(['access_token' => 'secret-token']),
                GitHubIdentityProvider::USER_ENDPOINT => new JsonResponse(['login' => 'ada']),
            ]),
            'no account id',
        ];
    }

    public function testTheRedirectOfAMisconfiguredEndpointIsNotFollowed(): void
    {
        $this->http->answerWith(
            static fn (): ResponseInterface => new JsonResponse([], 302, ['Location' => 'https://evil.example/']),
        );

        $this->expectException(IdentityProviderFailed::class);

        $this->google()->identify('c', self::REDIRECT_URI, $this->verifier);
    }

    public function testOnlyConfiguredProvidersAreOfferedInTheOrderGiven(): void
    {
        $providers = new ConfiguredIdentityProviders([$this->github(), $this->google()]);

        self::assertSame(
            ['github', 'google'],
            array_map(static fn (IdentityProvider $provider): string => $provider->name()->value, $providers->all()),
        );
        self::assertSame('Google', $providers->find('google')?->label());
        self::assertNull($providers->find('gitlab'));
        self::assertSame([], new ConfiguredIdentityProviders([])->all());
    }

    private function google(): GoogleIdentityProvider
    {
        return new GoogleIdentityProvider($this->providerHttp(), 'google-client', 'google-secret');
    }

    private function github(): GitHubIdentityProvider
    {
        return new GitHubIdentityProvider($this->providerHttp(), 'github-client', 'github-secret');
    }

    private function providerHttp(): ProviderHttp
    {
        return new ProviderHttp($this->http, new RequestFactory(), new StreamFactory(), $this->logger);
    }
}
