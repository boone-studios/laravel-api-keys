<?php

namespace BooneStudios\ApiKeys\Contracts;

interface ResolvesEnvironmentFromTokenPrefix
{
    /**
     * Map the environment segment parsed from the token to the stored column value.
     *
     * @param  string  $prefix
     * @return string
     */
    public function environmentFromPrefix(string $prefix): string;
}
