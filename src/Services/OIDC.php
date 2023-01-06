<?php

namespace DreamFactory\Core\Oidc\Services;

use DreamFactory\Core\OAuth\Services\BaseOAuthService;
use DreamFactory\Core\Oidc\Components\OidcProvider;
use DreamFactory\Core\Oidc\Resources\SSO;
use Arr;

class OIDC extends BaseOAuthService
{
    /**
     * Service provider name.
     */
    const PROVIDER_NAME = 'openid_connect';

    /** @type array Service Resources */
    protected static $resources = [
        SSO::RESOURCE_NAME => [
            'name'       => SSO::RESOURCE_NAME,
            'class_name' => SSO::class,
            'label'      => 'Single Sign On'
        ],
    ];

    /**
     * {@inheritdoc}
     */
    protected function setProvider($config)
    {
        $this->provider = new OidcProvider(
            Arr::get($config, 'client_id'),
            Arr::get($config, 'client_secret'),
            Arr::get($config, 'redirect_url')
        );
        $this->provider->setDiscoveryEndpoint(Arr::get($config, 'discovery_document'));
        $this->provider->setAuthEndpoint(Arr::get($config, 'auth_endpoint'));
        $this->provider->setTokenEndpoint(Arr::get($config, 'token_endpoint'));
        $this->provider->setUserEndpoint(Arr::get($config, 'user_endpoint'));
        $this->provider->setJwksUri(Arr::get($config, 'jwks_uri'));
        $this->provider->validateIdToken = boolval(Arr::get($config, 'validate_id_token'));;
        $scopes = array_map('trim', explode(',', Arr::get($config, 'scopes')));
        $this->provider->setScopes($scopes);
    }

    /**
     * {@inheritdoc}
     */
    public function getProviderName()
    {
        return self::PROVIDER_NAME;
    }
}