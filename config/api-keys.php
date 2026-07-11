<?php

use BooneStudios\ApiKeys\Models\ApiKey;

return [

    /*
    |--------------------------------------------------------------------------
    | Model
    |--------------------------------------------------------------------------
    */

    'model' => ApiKey::class,

    'tenant_foreign_key' => 'tenant_id',

    'tenant_relation' => 'tenant',

    /*
    |--------------------------------------------------------------------------
    | Container bindings
    |--------------------------------------------------------------------------
    |
    | After authentication, the resolved API key and tenant are bound into the
    | container under these keys (typically your app model class names).
    |
    */

    'container_key' => null,

    'tenant_container_key' => null,

    'bind_token_permission_resolver' => true,

    /*
    |--------------------------------------------------------------------------
    | Token format
    |--------------------------------------------------------------------------
    |
    | Secrets look like: {brand}_{environment}_{random}
    | Display prefixes mask the middle: {brand}_{environment}_••••{last4}
    |
    */

    'token' => [
        'brand' => env('API_KEY_BRAND', 'app'),
        'secret_length' => 32,
        'pattern' => '/^[a-z]+_(live|sandbox|test)_([a-z0-9]{32})$/',
        'mask' => '••••',
    ],

    /*
    |--------------------------------------------------------------------------
    | Resolvers
    |--------------------------------------------------------------------------
    */

    'environment_resolver' => null,

    'scope_permissions' => null,

    'tenant_guard' => null,

    /*
    |--------------------------------------------------------------------------
    | Environment column length
    |--------------------------------------------------------------------------
    |
    | Must match the length of the `environment` column in the api_keys
    | migration (string(16) by default). If a custom environment resolver
    | returns a longer value, key creation will throw instead of letting a
    | raw database error surface.
    |
    */

    'environment_max_length' => 16,

    /*
    |--------------------------------------------------------------------------
    | Usage tracking
    |--------------------------------------------------------------------------
    */

    'track_last_used' => true,

    /*
    |--------------------------------------------------------------------------
    | last_used_at throttle
    |--------------------------------------------------------------------------
    |
    | To avoid writing to the database on every single authenticated request,
    | last_used_at is only updated when it is null or older than this many
    | seconds.
    |
    */

    'last_used_at_throttle_seconds' => 60,

];
