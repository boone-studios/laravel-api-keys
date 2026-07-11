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
     * @var array<string>|bool
     */
    protected $guarded = [];

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'scopes' => 'array',
            'last_used_at' => 'datetime',
            'expires_at' => 'datetime',
            'revoked_at' => 'datetime',
        ];
    }

    public function isActive(): bool
    {
        return $this->revoked_at === null;
    }

    public function isRevoked(): bool
    {
        return $this->revoked_at !== null;
    }

    public function isExpired(): bool
    {
        return $this->expires_at !== null && $this->expires_at->isPast();
    }

    public function allows(string $permission): bool
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
     * @param  Builder<self>  $query
     * @return Builder<self>
     */
    public function scopeActive(Builder $query): Builder
    {
        return $query->whereNull('revoked_at');
    }

    /**
     * @param  Builder<self>  $query
     * @return Builder<self>
     */
    public function scopeForEnvironment(Builder $query, string $environment): Builder
    {
        return $query->where('environment', $environment);
    }
}
