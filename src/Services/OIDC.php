<?php

namespace DreamFactory\Core\Oidc\Services;

use DreamFactory\Core\OAuth\Services\BaseOAuthService;
use DreamFactory\Core\Oidc\Components\OidcProvider;
use DreamFactory\Core\Oidc\Resources\SSO;

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
            array_get($config, 'client_id'),
            array_get($config, 'client_secret'),
            array_get($config, 'redirect_url')
        );
        $this->provider->setDiscoveryEndpoint(array_get($config, 'discovery_document'));
        $this->provider->setAuthEndpoint(array_get($config, 'auth_endpoint'));
        $this->provider->setTokenEndpoint(array_get($config, 'token_endpoint'));
        $this->provider->setUserEndpoint(array_get($config, 'user_endpoint'));
        $this->provider->setJwksUri(array_get($config, 'jwks_uri'));
        $this->provider->validateIdToken = boolval(array_get($config, 'validate_id_token'));;
        $scopes = array_map('trim', explode(',', array_get($config, 'scopes')));
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