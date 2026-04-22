<?php
declare(strict_types=1);

namespace Luchki\OAuth2\Client\Provider;

class SessionPkceProvider implements PkceProviderInterface
{
        private $key;

        public function __construct(string $key = '__pkce') {
                $this->key = $key;
        }

        public function getAlgoritm(): string {
                return 'sha256';
        }

        public function getMethod(): string {
                return 'S256';
        }

        public function setVerifier(string $verifier): void {
                $_SESSION[$this->key] = $verifier;
        }

        public function getVerifier(): ?string {
                $value = $_SESSION[$this->key] ?? null;

                if ($value !== null) {
                        unset($_SESSION[$this->key]);
                }

                return $value;
        }

        public function makeVerifier(int $length = 64): string {
                return bin2hex(random_bytes($length));
        }
}