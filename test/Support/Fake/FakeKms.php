<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Support\Fake;

use Aws\CommandInterface;
use Aws\Exception\AwsException;
use Aws\Kms\KmsClient;
use Aws\MockHandler;
use Aws\Result;
use Psr\Http\Message\RequestInterface;

/**
 * AWS KMS, in process: a real {@see KmsClient} whose transport is a handler answering
 * `Sign` and `GetPublicKey` from a {@see LocalHsm}, as KMS does — refusing a "digest" that
 * is not one — and remembering every command sent.
 */
final class FakeKms
{
    /** @var list<CommandInterface> */
    public array $commands = [];

    public string $keyUsage = 'SIGN_VERIFY';

    /** @var list<string> */
    public array $signingAlgorithms = ['RSASSA_PKCS1_V1_5_SHA_256', 'RSASSA_PSS_SHA_256'];

    public ?string $refusal = null;

    public function __construct(private readonly LocalHsm $hsm = new LocalHsm())
    {
    }

    public function client(): KmsClient
    {
        $answer = function (CommandInterface $command, RequestInterface $request): Result|AwsException {
            $this->commands[] = $command;
            if ($this->refusal !== null) {
                return new AwsException('refused', $command, [
                    'message' => $this->refusal,
                    'code' => 'AccessDeniedException',
                ]);
            }

            return match ($command->getName()) {
                'Sign' => new Result(['Signature' => $this->sign($command)]),
                'GetPublicKey' => new Result([
                    'KeyId' => $command['KeyId'],
                    'KeyUsage' => $this->keyUsage,
                    'KeySpec' => 'RSA_2048',
                    'SigningAlgorithms' => $this->signingAlgorithms,
                    'PublicKey' => $this->hsm->publicDer(),
                ]),
                default => new AwsException('unexpected', $command),
            };
        };
        $handler = new MockHandler(array_fill(0, 20, $answer));

        return new KmsClient([
            'version' => '2014-11-01',
            'region' => 'eu-west-1',
            'credentials' => ['key' => 'AKIDEXAMPLE', 'secret' => 'secret'],
            'handler' => $handler,
        ]);
    }

    private function sign(CommandInterface $command): string
    {
        /** @var mixed $message */
        $message = $command['Message'];
        assert(is_string($message));

        // KMS hashes a RAW message itself; a DIGEST is signed as it is.
        return $this->hsm->signDigest($command['MessageType'] === 'DIGEST' ? $message : hash('sha256', $message, true));
    }
}
