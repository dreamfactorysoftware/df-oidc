<?php

namespace DreamFactory\Core\Oidc;

use DreamFactory\Core\Oidc\Models\OidcConfig;
use DreamFactory\Core\Oidc\Services\OIDC;
use DreamFactory\Core\Services\ServiceManager;
use DreamFactory\Core\Services\ServiceType;
use DreamFactory\Core\Enums\ServiceTypeGroups;

class ServiceProvider extends \Illuminate\Support\ServiceProvider
{
    public function register()
    {
        // Add our service types.
        $this->app->resolving('df.service', function (ServiceManager $df){
            $df->addType(
                new ServiceType([
                    'name'            => 'oidc',
                    'label'           => 'OpenID Connect',
                    'description'     => 'OpenID Connect service supporting SSO.',
                    'group'           => ServiceTypeGroups::OAUTH,
                    'config_handler'  => OidcConfig::class,
                    'factory'         => function ($config){
                        return new OIDC($config);
                    },
                ])
            );
        });
    }

    public function boot()
    {
        // add migrations
        $this->loadMigrationsFrom(__DIR__ . '/../database/migrations');
    }
}