<?php

namespace BooneStudios\ApiKeys\Support;

use Illuminate\Support\Str;
use InvalidArgumentException;

class TokenFormatter
{
    /**
     * Rebuild the masked display prefix for an already-issued secret.
     *
     * @param  string  $secret
     * @return string
     */
    public static function displayPrefixForSecret(string $secret): string
    {
        $parsed = self::parse($secret);

        if ($parsed === null) {
            throw new InvalidArgumentException('Secret does not match the configured token pattern.');
        }

        $brand = (string) config('api-keys.token.brand', 'app');
        $mask = (string) config('api-keys.token.mask', '••••');

        return "{$brand}_{$parsed['environment_prefix']}_{$mask}".substr($parsed['suffix'], -4);
    }

    /**
     * Generate a brand-new token secret for the given environment prefix.
     *
     * @param  string  $environmentPrefix
     * @return array{token: string, prefix: string, environment_prefix: string}
     */
    public static function generate(string $environmentPrefix): array
    {
        $brand = (string) config('api-keys.token.brand', 'app');
        $length = (int) config('api-keys.token.secret_length', 32);
        $mask = (string) config('api-keys.token.mask', '••••');

        $suffix = Str::lower(Str::random($length));
        $token = "{$brand}_{$environmentPrefix}_{$suffix}";
        $prefix = "{$brand}_{$environmentPrefix}_{$mask}".substr($suffix, -4);

        return [
            // This is the one and only time the plaintext secret exists in memory
            // as far as we're concerned - the caller had better write it down.
            'token'              => $token,
            'prefix'             => $prefix,
            'environment_prefix' => $environmentPrefix,
        ];
    }

    /**
     * Parse a raw token into its environment prefix and random suffix.
     *
     * @param  string|null  $token
     * @return array{environment_prefix: string, suffix: string}|null
     */
    public static function parse(?string $token): ?array
    {
        if ($token === null || $token === '') {
            return null;
        }

        $pattern = (string) config('api-keys.token.pattern');

        if (! preg_match($pattern, $token, $matches)) {
            return null;
        }

        return [
            'environment_prefix' => $matches[1],
            // Just the random suffix here, not the whole secret.
            'suffix'             => $matches[2],
        ];
    }
}
