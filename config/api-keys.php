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
    | Usage tracking
    |--------------------------------------------------------------------------
    */

    'track_last_used' => true,

];
