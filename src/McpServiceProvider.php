<?php

namespace Wazobia\NexusMcp;

use Illuminate\Support\ServiceProvider;

/**
 * Laravel service provider — auto-discovered via composer.json extra.laravel.providers.
 *
 * Registers the 'hmac' middleware alias so routes can use:
 *   Route::middleware('hmac:' . env('MCP_HMAC_SECRET'))
 */
class McpServiceProvider extends ServiceProvider
{
    public function boot(): void
    {
        // Register middleware alias on the HTTP kernel if present
        if ($this->app->bound('router')) {
            /** @var \Illuminate\Routing\Router $router */
            $router = $this->app->make('router');
            $router->aliasMiddleware('hmac', HmacMiddleware::class);
        }
    }

    public function register(): void
    {
        // Bind HmacClient as a singleton factory for each configured service.
        // Individual services instantiate HmacClient directly with their own secrets.
    }
}
