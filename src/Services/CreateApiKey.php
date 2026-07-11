<?php

namespace BooneStudios\ApiKeys\Services;

use BooneStudios\ApiKeys\Exceptions\InvalidEnvironmentException;
use BooneStudios\ApiKeys\Support\TokenFormatter;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\Hash;
use RuntimeException;

class CreateApiKey
{
    /**
     * @param  list<string>  $scopes
     * @return array{api_key: Model, secret: string}
     */
    public function create(
        Model $tenant,
        string $name,
        string $environmentPrefix,
        array $scopes,
        ?\DateTimeInterface $expiresAt = null,
    ): array {
        $token = TokenFormatter::generate($environmentPrefix);
        $modelClass = $this->modelClass();
        $tenantKey = (string) config('api-keys.tenant_foreign_key', 'tenant_id');
        $environment = app($this->environmentResolverClass())->environmentFromPrefix($environmentPrefix);

        $maxLength = (int) config('api-keys.environment_max_length', 16);

        if (strlen($environment) > $maxLength) {
            throw InvalidEnvironmentException::tooLong($environment, $maxLength);
        }

        $apiKey = $modelClass::query()->create([
            $tenantKey => $tenant->getKey(),
            'name' => $name,
            'environment' => $environment,
            'prefix' => $token['prefix'],
            'key_hash' => Hash::make($token['token']),
            'scopes' => array_values(array_unique($scopes)),
            'expires_at' => $expiresAt,
        ]);

        return [
            'api_key' => $apiKey,
            'secret' => $token['token'],
        ];
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

    /**
     * @return class-string
     */
    protected function environmentResolverClass(): string
    {
        $resolver = config('api-keys.environment_resolver');

        if (! is_string($resolver) || $resolver === '') {
            throw new RuntimeException('api-keys.environment_resolver is not configured.');
        }

        return $resolver;
    }
}
