<?php

namespace BooneStudios\ApiKeys\Models;

use BooneStudios\ScopedRoles\Contracts\TokenPermissionResolver;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;

class ApiKey extends Model implements TokenPermissionResolver
{
    use HasUlids;

    /**
     * The attributes that aren't mass assignable.
     *
     * @var array<string>|bool
     */
    protected $guarded = [];

    /**
     * Get the attribute casts for the model.
     *
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'scopes'       => 'array',
            'last_used_at' => 'datetime',
            'expires_at'   => 'datetime',
            'revoked_at'   => 'datetime',
        ];
    }

    /**
     * Determine whether the given permission is allowed for the key's scopes.
     *
     * @param  string  $permission
     * @param  mixed  $scope
     * @return bool
     */
    public function allows(string $permission, mixed $scope = null): bool
    {
        $resolver = config('api-keys.scope_permissions');

        if (! is_string($resolver) || $resolver === '') {
            return false;
        }

        /** @var list<string> $scopes */
        $scopes = $this->scopes ?? [];

        return $resolver::allows($scopes, $permission);
    }

    /**
     * Determine whether the key has not been revoked.
     *
     * @return bool
     */
    public function isActive(): bool
    {
        return $this->revoked_at === null;
    }

    /**
     * Determine whether the key has passed its expiration timestamp.
     *
     * @return bool
     */
    public function isExpired(): bool
    {
        return $this->expires_at !== null && $this->expires_at->isPast();
    }

    /**
     * Determine whether the key has been revoked.
     *
     * @return bool
     */
    public function isRevoked(): bool
    {
        return $this->revoked_at !== null;
    }

    /**
     * Scope the query to only active (non-revoked) keys.
     *
     * @param  Builder<self>  $query
     * @return Builder<self>
     */
    public function scopeActive(Builder $query): Builder
    {
        return $query->whereNull('revoked_at');
    }

    /**
     * Scope the query to keys belonging to the given environment.
     *
     * @param  Builder<self>  $query
     * @param  string  $environment
     * @return Builder<self>
     */
    public function scopeForEnvironment(Builder $query, string $environment): Builder
    {
        return $query->where('environment', $environment);
    }
}
