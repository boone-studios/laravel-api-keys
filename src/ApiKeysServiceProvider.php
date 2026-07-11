<?php

namespace BooneStudios\ApiKeys;

use BooneStudios\ApiKeys\Http\Middleware\AuthenticateApiKey;
use BooneStudios\ApiKeys\Services\Authenticator;
use BooneStudios\ApiKeys\Services\CreateApiKey;
use Illuminate\Routing\Router;
use Illuminate\Support\ServiceProvider;

class ApiKeysServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__.'/../config/api-keys.php', 'api-keys');

        $this->app->singleton(Authenticator::class);
        $this->app->singleton(CreateApiKey::class);
    }

    public function boot(): void
    {
        if ($this->app->runningInConsole()) {
            $this->publishes([
                __DIR__.'/../config/api-keys.php' => config_path('api-keys.php'),
            ], 'api-keys-config');

            $this->publishes([
                __DIR__.'/../database/migrations/create_api_keys_table.php.stub' => database_path('migrations/'.date('Y_m_d_His').'_create_api_keys_table.php'),
            ], 'api-keys-migrations');
        }

        $this->app->make(Router::class)->aliasMiddleware(
            'auth.api_key',
            AuthenticateApiKey::class,
        );
    }
}
