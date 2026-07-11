# boone-studios/laravel-api-keys

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Used by Forgebit](https://img.shields.io/badge/used%20by-Forgebit-amber)](https://forgebit.io)

Prefixed, hashed API keys with scope-to-permission mapping for multi-tenant Laravel APIs. Pairs naturally with [`boone-studios/laravel-scoped-roles`](https://github.com/boone-studios/laravel-scoped-roles) via `TokenPermissionResolver`.

## Features

- Brand-prefixed secrets (`app_live_…`) with masked display prefixes
- Hashed storage with prefix lookup + `Hash::check`
- Revocation and expiration support
- Scope → permission bridge for unified API + dashboard authorization
- Configurable tenant guard hook (e.g. block deleted organizations)

## Requirements

- PHP 8.2+
- Laravel 12 or 13
- `boone-studios/laravel-scoped-roles` (for token permission integration)

## Installation

```bash
composer require boone-studios/laravel-scoped-roles boone-studios/laravel-api-keys
```

```bash
php artisan vendor:publish --tag=api-keys-config
php artisan vendor:publish --tag=api-keys-migrations
php artisan migrate
```

## Quick start

1. Implement `ResolvesScopePermissions` on your scope enum (maps `read`/`write`/`admin` → permission strings).
2. Implement `ResolvesEnvironmentFromTokenPrefix` if you support multiple environments.
3. Optionally implement `GuardsAuthenticatedTenant` for tenant availability checks.
4. Extend `BooneStudios\ApiKeys\Models\ApiKey` and add your tenant relation.
5. Register middleware: `auth.api_key`.

## License

MIT © Boone Studios, LLC
