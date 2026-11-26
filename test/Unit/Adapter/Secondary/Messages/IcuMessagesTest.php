<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Adapter\Secondary\Messages;

use Clavia\Adapter\Secondary\Messages\IcuMessages;
use Clavia\Application\Port\Messages;
use Clavia\Domain\Shared\Language;
use Clavia\Domain\Shared\Languages;
use ClaviaTest\Support\Contract\MessagesContract;
use ClaviaTest\Support\RecordingLogger;
use LogicException;
use PHPUnit\Framework\TestCase;

/** The catalogue as ARB files: the contract over files written from it, and what only files can get wrong. */
final class IcuMessagesTest extends TestCase
{
    use MessagesContract;

    private string $directory = '';
    private RecordingLogger $logger;

    #[\Override]
    protected function setUp(): void
    {
        $this->directory = sys_get_temp_dir() . '/clavia-messages-' . bin2hex(random_bytes(6));
        mkdir($this->directory);
        $this->logger = new RecordingLogger();
        foreach (self::CATALOGUES as $tag => $messages) {
            $arb = ['@@locale' => $tag, ...$messages];
            if ($tag === 'en') {
                $arb['@greeting'] = ['placeholders' => ['name' => ['type' => 'String']]];
            }
            file_put_contents($this->directory . '/' . $tag . '.arb', json_encode($arb, JSON_THROW_ON_ERROR));
        }
    }

    #[\Override]
    protected function tearDown(): void
    {
        $files = glob($this->directory . '/*');
        array_map('unlink', $files === false ? [] : $files);
        rmdir($this->directory);
    }

    #[\Override]
    protected function messages(Languages $languages): Messages
    {
        return new IcuMessages($this->directory, $languages, $this->logger);
    }

    public function testAFallbackIsLoggedOnceAMessage(): void
    {
        $messages = $this->messages(Languages::of([self::en(), self::fr()], self::en()));

        $messages->text(self::fr(), 'only.english');
        $messages->text(self::fr(), 'only.english');

        self::assertCount(1, $this->logger->records);
    }

    public function testTheDescriptionsOfAnArbFileAreNoMessages(): void
    {
        $this->expectException(LogicException::class);

        $this->messages(Languages::of([self::en()], self::en()))->text(self::en(), '@greeting');
    }

    public function testALanguageNotOfferedIsNeverRead(): void
    {
        $this->expectException(LogicException::class);

        $this->messages(Languages::of([self::en()], self::en()))->text(self::fr(), 'greeting');
    }

    public function testACatalogueThatIsNotJsonIsADefect(): void
    {
        file_put_contents($this->directory . '/fr.arb', '{"greeting": ');

        $this->expectException(LogicException::class);

        $this->messages(Languages::of([self::en(), self::fr()], self::en()))->text(self::fr(), 'greeting');
    }
}
