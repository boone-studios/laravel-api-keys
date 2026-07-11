<?php

namespace BooneStudios\ApiKeys\Http\Middleware;

use BooneStudios\ApiKeys\Contracts\GuardsAuthenticatedTenant;
use BooneStudios\ApiKeys\Services\Authenticator;
use BooneStudios\ScopedRoles\Contracts\TokenPermissionResolver;
use Closure;
use DateTimeInterface;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\Request;
use RuntimeException;
use Symfony\Component\HttpFoundation\Response;

class AuthenticateApiKey
{
    public function __construct(
        protected Authenticator $authenticator,
    ) {}

    /**
     * @param  Closure(Request): (Response)  $next
     */
    public function handle(Request $request, Closure $next): Response
    {
        $apiKey = $this->authenticator->authenticate($request->bearerToken());

        if (! $apiKey instanceof Model) {
            return response()->json(['message' => 'Unauthenticated.'], 401);
        }

        $tenant = $this->resolveTenant($apiKey);

        if (! $tenant) {
            return response()->json(['message' => 'Unauthenticated.'], 401);
        }

        $guardResponse = $this->runTenantGuard($request, $tenant);

        if ($guardResponse instanceof Response) {
            return $guardResponse;
        }

        $this->bindAuthenticatedContext($apiKey, $tenant);

        if (config('api-keys.track_last_used', true) && $this->shouldUpdateLastUsedAt($apiKey)) {
            $apiKey->forceFill(['last_used_at' => now()])->save();
        }

        return $next($request);
    }

    /**
     * Debounce last_used_at writes so we don't hit the database on every
     * single authenticated request. Only write when the timestamp is
     * missing or older than the configured throttle threshold.
     */
    protected function shouldUpdateLastUsedAt(Model $apiKey): bool
    {
        $lastUsedAt = $apiKey->last_used_at;

        if (! $lastUsedAt instanceof DateTimeInterface) {
            return true;
        }

        $throttleSeconds = (int) config('api-keys.last_used_at_throttle_seconds', 60);

        return $lastUsedAt->diffInSeconds(now(), true) >= $throttleSeconds;
    }

    protected function resolveTenant(Model $apiKey): ?object
    {
        $relation = (string) config('api-keys.tenant_relation', 'tenant');

        if (! method_exists($apiKey, $relation)) {
            throw new RuntimeException("API key model is missing the [{$relation}] relation.");
        }

        $apiKey->loadMissing($relation);

        $tenant = $apiKey->{$relation};

        return is_object($tenant) ? $tenant : null;
    }

    protected function runTenantGuard(Request $request, object $tenant): ?Response
    {
        $guard = config('api-keys.tenant_guard');

        if (! is_string($guard) || $guard === '') {
            return null;
        }

        $instance = app($guard);

        if (! $instance instanceof GuardsAuthenticatedTenant) {
            throw new RuntimeException('api-keys.tenant_guard must implement GuardsAuthenticatedTenant.');
        }

        return $instance->guard($request, $tenant);
    }

    protected function bindAuthenticatedContext(Model $apiKey, object $tenant): void
    {
        $containerKey = config('api-keys.container_key') ?? config('api-keys.model');
        $tenantContainerKey = config('api-keys.tenant_container_key');

        if (is_string($containerKey) && $containerKey !== '') {
            app()->instance($containerKey, $apiKey);
        }

        if (config('api-keys.bind_token_permission_resolver', true) && $apiKey instanceof TokenPermissionResolver) {
            app()->instance(TokenPermissionResolver::class, $apiKey);
        }

        if (is_string($tenantContainerKey) && $tenantContainerKey !== '') {
            app()->instance($tenantContainerKey, $tenant);
        }
    }
}
