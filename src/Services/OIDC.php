<?php

namespace DreamFactory\Core\Oidc\Services;
use DreamFactory\Core\OAuth\Services\BaseOAuthService;
use DreamFactory\Core\Oidc\Components\OidcProvider;

class OIDC extends BaseOAuthService
{
    /**
     * Service provider name.
     */
    const PROVIDER_NAME = 'openid_connect';

    protected function setProvider($config)
    {
        $this->provider = new OidcProvider(
            array_get($config, 'client_id'),
            array_get($config, 'client_secret'),
            array_get($config, 'redirect_url')
        );
        $this->provider->setAuthEndpoint(array_get($config, 'auth_endpoint'));
        $this->provider->setTokenEndpoint(array_get($config, 'token_endpoint'));
        $this->provider->setUserEndpoint(array_get($config, 'user_endpoint'));
        $this->provider->setJwksUri(array_get($config, 'jwks_uri'));
        $this->provider->validateIdToken = boolval(array_get($config, 'validate_id_token'));;
        $scopes = array_map('trim', explode(',', array_get($config, 'scopes')));
        $this->provider->setScopes($scopes);
    }

    public function getProviderName()
    {
        return self::PROVIDER_NAME;
    }
}