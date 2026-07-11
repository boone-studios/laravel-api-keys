<?php

use BooneStudios\ApiKeys\Contracts\ResolvesEnvironmentFromTokenPrefix;
use BooneStudios\ApiKeys\Contracts\ResolvesScopePermissions;
use BooneStudios\ApiKeys\Models\ApiKey;
use BooneStudios\ApiKeys\Services\Authenticator;
use BooneStudios\ApiKeys\Services\CreateApiKey;
use BooneStudios\ApiKeys\Support\TokenFormatter;
use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Str;

beforeEach(function () {
    Schema::create('tenants', function (Blueprint $table) {
        $table->ulid('id')->primary();
        $table->timestamps();
    });

    Schema::create('api_keys', function (Blueprint $table) {
        $table->ulid('id')->primary();
        $table->string('tenant_id');
        $table->string('name');
        $table->string('environment', 16);
        $table->string('prefix', 32);
        $table->string('key_hash');
        $table->json('scopes');
        $table->timestamp('last_used_at')->nullable();
        $table->timestamp('expires_at')->nullable();
        $table->timestamp('revoked_at')->nullable();
        $table->timestamps();
        $table->index('prefix');
    });

    config([
        'api-keys.model' => TestApiKey::class,
        'api-keys.tenant_foreign_key' => 'tenant_id',
        'api-keys.tenant_relation' => 'tenant',
        'api-keys.environment_resolver' => TestEnvironmentResolver::class,
        'api-keys.scope_permissions' => TestScopePermissions::class,
        'api-keys.token.brand' => 'app',
        'api-keys.token.secret_length' => 32,
        'api-keys.token.pattern' => '/^app_(live|sandbox|test)_([a-z0-9]{32})$/',
    ]);
});

class FakeTenant extends Model
{
    use HasUlids;

    protected $table = 'tenants';

    protected $guarded = [];

    public $incrementing = false;

    protected $keyType = 'string';
}

class TestApiKey extends ApiKey
{
    protected $table = 'api_keys';

    public function tenant()
    {
        return $this->belongsTo(FakeTenant::class, 'tenant_id');
    }
}

class TestEnvironmentResolver implements ResolvesEnvironmentFromTokenPrefix
{
    public function environmentFromPrefix(string $prefix): string
    {
        return match ($prefix) {
            'live' => 'live',
            'sandbox', 'test' => 'sandbox',
            default => $prefix,
        };
    }
}

class TestScopePermissions implements ResolvesScopePermissions
{
    public static function allows(array $scopes, string $permission): bool
    {
        $permissions = collect($scopes)
            ->flatMap(fn (string $scope) => match ($scope) {
                'read' => ['view'],
                'write' => ['view', 'create'],
                default => [],
            })
            ->unique()
            ->all();

        return in_array($permission, $permissions, true);
    }
}

test('token formatter generates secrets that match the configured pattern', function () {
    $token = TokenFormatter::generate('live');

    expect($token['secret'])->toMatch('/^app_live_[a-z0-9]{32}$/')
        ->and($token['prefix'])->toContain('••••')
        ->and(TokenFormatter::parse($token['secret']))->not->toBeNull();
});

test('create api key stores a hashed secret and returns the plaintext once', function () {
    $tenant = FakeTenant::create(['id' => (string) Str::ulid()]);

    $result = app(CreateApiKey::class)->create($tenant, 'Primary', 'live', ['read']);

    expect($result['secret'])->toMatch('/^app_live_/')
        ->and(Hash::check($result['secret'], $result['api_key']->key_hash))->toBeTrue()
        ->and($result['api_key']->environment)->toBe('live')
        ->and($result['api_key']->scopes)->toBe(['read']);
});

test('authenticator resolves keys by prefix and hash', function () {
    $tenant = FakeTenant::create(['id' => (string) Str::ulid()]);
    $created = app(CreateApiKey::class)->create($tenant, 'Primary', 'sandbox', ['write']);

    $resolved = app(Authenticator::class)->authenticate($created['secret']);

    expect($resolved)->not->toBeNull()
        ->and($resolved->is($created['api_key']))->toBeTrue();
});

test('authenticator rejects revoked and expired keys', function () {
    $tenant = FakeTenant::create(['id' => (string) Str::ulid()]);
    $created = app(CreateApiKey::class)->create($tenant, 'Primary', 'live', ['read']);

    $created['api_key']->update(['revoked_at' => now()]);
    expect(app(Authenticator::class)->authenticate($created['secret']))->toBeNull();

    $created['api_key']->update(['revoked_at' => null, 'expires_at' => now()->subMinute()]);
    expect(app(Authenticator::class)->authenticate($created['secret']))->toBeNull();
});

test('api key model delegates permissions to the configured scope map', function () {
    $tenant = FakeTenant::create(['id' => (string) Str::ulid()]);
    $created = app(CreateApiKey::class)->create($tenant, 'Primary', 'live', ['write']);

    expect($created['api_key']->allows('create'))->toBeTrue()
        ->and($created['api_key']->allows('delete'))->toBeFalse();
});
