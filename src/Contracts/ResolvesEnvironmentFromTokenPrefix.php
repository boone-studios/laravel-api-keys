<?php

namespace BooneStudios\ApiKeys\Contracts;

interface ResolvesEnvironmentFromTokenPrefix
{
    /**
     * Map the environment segment parsed from the token to the stored column value.
     */
    public function environmentFromPrefix(string $prefix): string;
}
