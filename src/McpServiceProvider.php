<?php

namespace Wazobia\NexusMcp;

use Illuminate\Support\ServiceProvider;

/**
 * Laravel service provider — auto-discovered via composer.json extra.laravel.providers.
 *
 * Registers the 'hmac' middleware alias. The recommended usage is via McpRouter::register(),
 * which binds the secret through the service container (avoids the comma-truncation footgun
 * of string-param middleware). Direct usage:
 *
 *   app()->singleton('nexus-mcp.hmac_secret', fn () => env('MCP_HMAC_SECRET'));
 *   Route::middleware(\Wazobia\NexusMcp\HmacMiddleware::class)->group(function () { ... });
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
