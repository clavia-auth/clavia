<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Primary\Cli;

use BackedEnum;
use Clavia\Configuration\Settings;
use ReflectionClass;
use ReflectionProperty;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;

/**
 * `clavia config` — print every setting, its environment variable, and its current value.
 *
 * Generated from {@see Settings} rather than from a hand-kept list, so it cannot drift.
 * It is the quickest way to check what a running server actually thinks.
 */
#[AsCommand(name: 'config', description: 'Print every setting, its environment variable, and its current value.')]
final class ShowConfigCommand extends Command
{
    public function __construct(private readonly Settings $settings)
    {
        parent::__construct();
    }

    #[\Override]
    protected function configure(): void
    {
        $this->addOption(
            'show-secrets',
            null,
            InputOption::VALUE_NONE,
            'Print credentials in full instead of masking them.',
        );
    }

    #[\Override]
    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $showSecrets = (bool) $input->getOption('show-secrets');
        $properties = new ReflectionClass($this->settings)->getProperties();
        $width = max(0, ...array_map(
            static fn (ReflectionProperty $property): int => strlen(Settings::variableName($property->getName())),
            $properties,
        ));

        foreach ($properties as $property) {
            $rendered = $this->render($property->getValue($this->settings));
            if (! $showSecrets) {
                $rendered = $this->mask($property->getName(), $rendered);
            }

            $output->writeln(
                sprintf('%s %s', str_pad(Settings::variableName($property->getName()), $width), $rendered),
                OutputInterface::OUTPUT_RAW,
            );
        }

        return Command::SUCCESS;
    }

    private function render(mixed $value): string
    {
        return match (true) {
            $value === null => '<unset>',
            is_bool($value) => $value ? 'true' : 'false',
            $value instanceof BackedEnum => (string) $value->value,
            is_array($value) => json_encode($value, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES),
            default => (string) $value,
        };
    }

    /**
     * Hide credentials, so the output can be pasted into an issue.
     *
     * URLs get only their password removed; the host and database still matter for
     * diagnosing a misconfiguration. A setting is a credential when its name ends in
     * `Password`, `Secret` or `ApiKey` (`smtpPassword`, `googleClientSecret`, `fgaApiKey`) or starts with `secret`
     * (`secretEncryptionKey`) — not merely when it contains the word: the passwordless
     * lifetimes and limits are not secrets.
     */
    private function mask(string $name, string $value): string
    {
        if (preg_match('#^(?<scheme>[a-z][a-z0-9+.-]*)://(?<user>[^:@/]*):[^@/]*@(?<rest>.*)$#i', $value, $url) === 1) {
            return sprintf('%s://%s:***@%s', $url['scheme'], $url['user'], $url['rest']);
        }

        if ($value !== '<unset>' && preg_match('/(?:Password|Secret|ApiKey)$|^secret/', $name) === 1) {
            return '***';
        }

        return $value;
    }
}
