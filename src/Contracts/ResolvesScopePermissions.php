<?php

namespace BooneStudios\ApiKeys\Contracts;

interface ResolvesScopePermissions
{
    /**
     * @param  list<string>  $scopes
     */
    public static function allows(array $scopes, string $permission): bool;
}
