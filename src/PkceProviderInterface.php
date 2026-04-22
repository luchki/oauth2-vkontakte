<?php
declare(strict_types=1);

namespace Luchki\OAuth2\Client\Provider;

interface PkceProviderInterface
{
        public function getAlgoritm(): string;

        public function getMethod(): string;
        public function makeVerifier(int $length = 64): string;

        public function setVerifier(string $verifier): void;

        public function getVerifier(): ?string;
}
