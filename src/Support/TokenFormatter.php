<?php

namespace BooneStudios\ApiKeys\Support;

use Illuminate\Support\Str;
use InvalidArgumentException;

class TokenFormatter
{
    /**
     * @return array{environment_prefix: string, secret: string}|null
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
            'secret' => $matches[2],
        ];
    }

    /**
     * @return array{secret: string, prefix: string, environment_prefix: string}
     */
    public static function generate(string $environmentPrefix): array
    {
        $brand = (string) config('api-keys.token.brand', 'app');
        $length = (int) config('api-keys.token.secret_length', 32);
        $mask = (string) config('api-keys.token.mask', '••••');

        $suffix = Str::lower(Str::random($length));
        $secret = "{$brand}_{$environmentPrefix}_{$suffix}";
        $prefix = "{$brand}_{$environmentPrefix}_{$mask}".substr($suffix, -4);

        return [
            'secret' => $secret,
            'prefix' => $prefix,
            'environment_prefix' => $environmentPrefix,
        ];
    }

    public static function displayPrefixForSecret(string $secret): string
    {
        $parsed = self::parse($secret);

        if ($parsed === null) {
            throw new InvalidArgumentException('Secret does not match the configured token pattern.');
        }

        $brand = (string) config('api-keys.token.brand', 'app');
        $mask = (string) config('api-keys.token.mask', '••••');

        return "{$brand}_{$parsed['environment_prefix']}_{$mask}".substr($parsed['secret'], -4);
    }
}
