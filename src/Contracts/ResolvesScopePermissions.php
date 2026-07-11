<?php

namespace BooneStudios\ApiKeys\Contracts;

interface ResolvesScopePermissions
{
    /**
     * Determine whether the given scopes grant the requested permission.
     *
     * @param  list<string>  $scopes
     * @param  string  $permission
     * @return bool
     */
    public static function allows(array $scopes, string $permission): bool;
}
