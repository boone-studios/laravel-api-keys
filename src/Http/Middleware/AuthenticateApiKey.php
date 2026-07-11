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
    /**
     * Bind the resolved API key and tenant into the container so the rest
     * of the request lifecycle can resolve them.
     *
     * @param  Model  $apiKey
     * @param  object  $tenant
     * @return void
     */
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

    /**
     * Resolve the tenant relation configured for the API key model.
     *
     * @param  Model  $apiKey
     * @return object|null
     */
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

    /**
     * Run the configured tenant guard, if any, against the resolved tenant.
     *
     * @param  Request  $request
     * @param  object  $tenant
     * @return Response|null
     */
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

    /**
     * Debounce last_used_at writes so we don't hit the database on every
     * single authenticated request. Only write when the timestamp is
     * missing or older than the configured throttle threshold.
     *
     * @param  Model  $apiKey
     * @return bool
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

    /**
     * Create a new middleware instance.
     *
     * @param  Authenticator  $authenticator
     */
    public function __construct(
        protected Authenticator $authenticator,
    ) {}

    /**
     * Handle the incoming request.
     *
     * @param  Request  $request
     * @param  Closure(Request): (Response)  $next
     * @return Response
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
}
