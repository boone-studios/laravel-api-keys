<?php

use BooneStudios\ApiKeys\Contracts\GuardsAuthenticatedTenant;
use BooneStudios\ApiKeys\Contracts\ResolvesEnvironmentFromTokenPrefix;
use BooneStudios\ApiKeys\Contracts\ResolvesScopePermissions;
use BooneStudios\ApiKeys\Http\Middleware\AuthenticateApiKey;
use BooneStudios\ApiKeys\Models\ApiKey;
use BooneStudios\ApiKeys\Services\CreateApiKey;
use BooneStudios\ScopedRoles\Contracts\TokenPermissionResolver;
use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Str;
use Symfony\Component\HttpFoundation\Response;

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
        $table->unique('prefix');
    });

    config([
        'api-keys.model' => MiddlewareTestApiKey::class,
        'api-keys.tenant_foreign_key' => 'tenant_id',
        'api-keys.tenant_relation' => 'tenant',
        'api-keys.environment_resolver' => MiddlewareTestEnvironmentResolver::class,
        'api-keys.scope_permissions' => MiddlewareTestScopePermissions::class,
        'api-keys.token.brand' => 'app',
        'api-keys.token.secret_length' => 32,
        'api-keys.token.pattern' => '/^app_(live|sandbox|test)_([a-z0-9]{32})$/',
        'api-keys.container_key' => 'currentApiKey',
        'api-keys.tenant_container_key' => 'currentTenant',
        'api-keys.tenant_guard' => null,
        'api-keys.track_last_used' => true,
        'api-keys.last_used_at_throttle_seconds' => 60,
    ]);

    Route::middleware(AuthenticateApiKey::class)->get('/_test/protected', function () {
        return response()->json(['ok' => true]);
    });
});

class MiddlewareFakeTenant extends Model
{
    use HasUlids;

    protected $table = 'tenants';

    protected $guarded = [];

    public $incrementing = false;

    protected $keyType = 'string';
}

class MiddlewareTestApiKey extends ApiKey
{
    protected $table = 'api_keys';

    public function tenant()
    {
        return $this->belongsTo(MiddlewareFakeTenant::class, 'tenant_id');
    }
}

class MiddlewareTestEnvironmentResolver implements ResolvesEnvironmentFromTokenPrefix
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

class MiddlewareTestScopePermissions implements ResolvesScopePermissions
{
    public static function allows(array $scopes, string $permission): bool
    {
        return in_array('read', $scopes, true) && $permission === 'view';
    }
}

class RejectingTenantGuard implements GuardsAuthenticatedTenant
{
    public function guard(Request $request, object $tenant): ?Response
    {
        return response()->json(['message' => 'Tenant suspended.'], 403);
    }
}

class AllowingTenantGuard implements GuardsAuthenticatedTenant
{
    public static bool $wasInvoked = false;

    public function guard(Request $request, object $tenant): ?Response
    {
        self::$wasInvoked = true;

        return null;
    }
}

function createTestApiKey(array $scopes = ['read']): array
{
    $tenant = MiddlewareFakeTenant::create(['id' => (string) Str::ulid()]);

    return app(CreateApiKey::class)->create($tenant, 'Primary', 'live', $scopes);
}

test('a valid api key authenticates and binds the api key and tenant into the container', function () {
    $created = createTestApiKey();

    $response = $this->withHeader('Authorization', 'Bearer '.$created['secret'])
        ->getJson('/_test/protected');

    $response->assertOk();
    $response->assertJson(['ok' => true]);

    expect(app('currentApiKey'))->toBeInstanceOf(MiddlewareTestApiKey::class)
        ->and(app('currentApiKey')->is($created['api_key']))->toBeTrue()
        ->and(app('currentTenant'))->toBeInstanceOf(MiddlewareFakeTenant::class)
        ->and(app(TokenPermissionResolver::class))->toBeInstanceOf(MiddlewareTestApiKey::class);
});

test('a missing or garbage bearer token is rejected with 401', function () {
    $response = $this->getJson('/_test/protected');
    $response->assertStatus(401);
    $response->assertJson(['message' => 'Unauthenticated.']);

    $response = $this->withHeader('Authorization', 'Bearer nonsense-token')
        ->getJson('/_test/protected');
    $response->assertStatus(401);
});

test('a revoked api key is rejected with 401', function () {
    $created = createTestApiKey();
    $created['api_key']->update(['revoked_at' => now()]);

    $response = $this->withHeader('Authorization', 'Bearer '.$created['secret'])
        ->getJson('/_test/protected');

    $response->assertStatus(401);
});

test('an expired api key is rejected with 401', function () {
    $created = createTestApiKey();
    $created['api_key']->update(['expires_at' => now()->subMinute()]);

    $response = $this->withHeader('Authorization', 'Bearer '.$created['secret'])
        ->getJson('/_test/protected');

    $response->assertStatus(401);
});

test('the tenant guard hook is invoked and can allow the request through', function () {
    AllowingTenantGuard::$wasInvoked = false;
    config(['api-keys.tenant_guard' => AllowingTenantGuard::class]);

    $created = createTestApiKey();

    $response = $this->withHeader('Authorization', 'Bearer '.$created['secret'])
        ->getJson('/_test/protected');

    $response->assertOk();
    expect(AllowingTenantGuard::$wasInvoked)->toBeTrue();
});

test('the tenant guard hook can reject the request', function () {
    config(['api-keys.tenant_guard' => RejectingTenantGuard::class]);

    $created = createTestApiKey();

    $response = $this->withHeader('Authorization', 'Bearer '.$created['secret'])
        ->getJson('/_test/protected');

    $response->assertStatus(403);
    $response->assertJson(['message' => 'Tenant suspended.']);
});

test('last_used_at is set on first use', function () {
    $created = createTestApiKey();

    expect($created['api_key']->last_used_at)->toBeNull();

    $this->withHeader('Authorization', 'Bearer '.$created['secret'])
        ->getJson('/_test/protected');

    expect($created['api_key']->fresh()->last_used_at)->not->toBeNull();
});

test('last_used_at is not rewritten on every request within the throttle window', function () {
    config(['api-keys.last_used_at_throttle_seconds' => 60]);

    $created = createTestApiKey();

    $this->withHeader('Authorization', 'Bearer '.$created['secret'])
        ->getJson('/_test/protected');

    $firstSeenAt = $created['api_key']->fresh()->last_used_at;

    $this->travel(10)->seconds();

    $this->withHeader('Authorization', 'Bearer '.$created['secret'])
        ->getJson('/_test/protected');

    $secondSeenAt = $created['api_key']->fresh()->last_used_at;

    expect($secondSeenAt->equalTo($firstSeenAt))->toBeTrue();
});

test('last_used_at is rewritten once the throttle window has elapsed', function () {
    config(['api-keys.last_used_at_throttle_seconds' => 60]);

    $created = createTestApiKey();

    $this->withHeader('Authorization', 'Bearer '.$created['secret'])
        ->getJson('/_test/protected');

    $firstSeenAt = $created['api_key']->fresh()->last_used_at;

    $this->travel(61)->seconds();

    $this->withHeader('Authorization', 'Bearer '.$created['secret'])
        ->getJson('/_test/protected');

    $secondSeenAt = $created['api_key']->fresh()->last_used_at;

    expect($secondSeenAt->greaterThan($firstSeenAt))->toBeTrue();
});
