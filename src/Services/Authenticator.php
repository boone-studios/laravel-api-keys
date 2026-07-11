<?php

namespace BooneStudios\ApiKeys\Services;

use BooneStudios\ApiKeys\Contracts\ResolvesEnvironmentFromTokenPrefix;
use BooneStudios\ApiKeys\Support\TokenFormatter;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\Hash;
use RuntimeException;

class Authenticator
{
    /**
     * Resolve the environment resolver configured for the application.
     *
     * @return ResolvesEnvironmentFromTokenPrefix
     */
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

    /**
     * Resolve the configured API key model class name.
     *
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

    /**
     * Resolve the API key model matching the given bearer token, if any.
     *
     * @param  string|null  $token
     * @return Model|null
     */
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

                // Bcrypt salts every row differently so there's no indexed shortcut
                // Each candidate gets checked constant-time
                return Hash::check($token, (string) $apiKey->key_hash);
            });
    }
}
