<?php

namespace BooneStudios\ApiKeys\Services;

use BooneStudios\ApiKeys\Contracts\ResolvesEnvironmentFromTokenPrefix;
use BooneStudios\ApiKeys\Support\TokenFormatter;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\Hash;
use RuntimeException;

class Authenticator
{
    public function authenticate(?string $token): ?Model
    {
        $parsed = TokenFormatter::parse($token);

        if ($parsed === null) {
            return null;
        }

        $environment = $this->environmentResolver()->environmentFromPrefix($parsed['environment_prefix']);
        $prefix = TokenFormatter::displayPrefixForSecret((string) $token);
        $modelClass = $this->modelClass();
        $tenantRelation = (string) config('api-keys.tenant_relation', 'tenant');

        return $modelClass::query()
            ->active()
            ->forEnvironment($environment)
            ->where('prefix', $prefix)
            ->with($tenantRelation)
            ->get()
            ->first(function (Model $apiKey) use ($token): bool {
                if ($apiKey->isExpired()) {
                    return false;
                }

                // We must Hash::check() each row individually rather than doing a single
                // indexed lookup: bcrypt salts each hash uniquely, so there is no way to
                // derive an index from the salted digest. Looping per-candidate here also
                // keeps the comparison timing-safe (Hash::check() is constant-time).
                return Hash::check($token, (string) $apiKey->key_hash);
            });
    }

    /**
     * @return class-string<Model>
     */
    protected function modelClass(): string
    {
        $model = config('api-keys.model');

        if (! is_string($model) || $model === '') {
            throw new RuntimeException('api-keys.model is not configured.');
        }

        return $model;
    }

    protected function environmentResolver(): ResolvesEnvironmentFromTokenPrefix
    {
        $resolver = config('api-keys.environment_resolver');

        if (! is_string($resolver) || $resolver === '') {
            throw new RuntimeException('api-keys.environment_resolver is not configured.');
        }

        $instance = app($resolver);

        if (! $instance instanceof ResolvesEnvironmentFromTokenPrefix) {
            throw new RuntimeException('api-keys.environment_resolver must implement ResolvesEnvironmentFromTokenPrefix.');
        }

        return $instance;
    }
}
