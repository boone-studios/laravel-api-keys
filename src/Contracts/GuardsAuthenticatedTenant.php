<?php

namespace BooneStudios\ApiKeys\Contracts;

use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

interface GuardsAuthenticatedTenant
{
    /**
     * Return a response to abort the request, or null when the tenant may proceed.
     */
    public function guard(Request $request, object $tenant): ?Response;
}
