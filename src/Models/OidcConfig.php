<?php

namespace DreamFactory\Core\Oidc\Models;

use DreamFactory\Core\Components\AppRoleMapper;
use DreamFactory\Core\Exceptions\InternalServerErrorException;
use DreamFactory\Core\Models\BaseServiceConfigModel;
use DreamFactory\Core\Models\Role;
use DreamFactory\Core\Models\Service;
use GuzzleHttp\Client;
use Cache;
use Config;

class OidcConfig extends BaseServiceConfigModel
{
    use AppRoleMapper;

    /**
     * {@inheritdoc}
     */
    protected $table = 'oidc_config';

    /**
     * {@inheritdoc}
     */
    protected $fillable = [
        'service_id',
        'default_role',
        'discovery_document',
        'auth_endpoint',
        'token_endpoint',
        'user_endpoint',
        'validate_id_token',
        'jwks_uri',
        'scopes',
        'client_id',
        'client_secret',
        'redirect_url',
        'icon_class',
    ];

    /**
     * {@inheritdoc}
     */
    protected $encrypted = ['client_secret'];

    /**
     * {@inheritdoc}
     */
    protected $protected = ['client_secret'];

    /**
     * {@inheritdoc}
     */
    protected $casts = [
        'service_id'        => 'integer',
        'default_role'      => 'integer',
        'validate_id_token' => 'boolean'
    ];

    /**
     * {@inheritdoc}
     */
    protected $rules = [
        'client_id'     => 'required',
        'client_secret' => 'required',
        'redirect_url'  => 'required'
    ];

    /**
     * {@inheritdoc}
     */
    public function validate($data, $throwException = true)
    {
        $discovery = array_get($data, 'discovery_document');

        if (empty($discovery)) {
            $this->rules['auth_endpoint'] = 'required';
            $this->rules['token_endpoint'] = 'required';
            $this->rules['scopes'] = 'required';
            if (boolval(array_get($data, 'validate_id_token'))) {
                $this->rules['jwks_uri'] = 'required';
            }
        }

        return parent::validate($data, $throwException);
    }

    /**
     * @param $value
     */
    public function setDiscoveryDocumentAttribute($value)
    {
        $this->attributes['discovery_document'] = $value;
        $data = static::getDiscoveryData($value);
        if (!empty($data)) {
            if (!isset($this->attributes['auth_endpoint'])) {
                $this->attributes['auth_endpoint'] = array_get($data, 'authorization_endpoint');
            }
            if (!isset($this->attributes['token_endpoint'])) {
                $this->attributes['token_endpoint'] = array_get($data, 'token_endpoint');
            }
            if (!isset($this->attributes['user_endpoint'])) {
                $this->attributes['user_endpoint'] = array_get($data, 'userinfo_endpoint');
            }
            if (!isset($this->attributes['jwks_uri'])) {
                $this->attributes['jwks_uri'] = array_get($data, 'jwks_uri');
            }
            if (!isset($this->attributes['scopes'])) {
                $this->attributes['scopes'] = implode(',', array_get($data, 'scopes_supported'));
            }
        }
    }

    /**
     * @param $value
     */
    public function setAuthEndpointAttribute($value)
    {
        $dd = array_get($this->attributes, 'discovery_document');
        if (empty($value) && !empty($dd)) {
            $value = static::getDiscoveryData($dd, 'authorization_endpoint');
        }

        $this->attributes['auth_endpoint'] = $value;
    }

    /**
     * @param $value
     */
    public function setTokenEndpointAttribute($value)
    {
        $dd = array_get($this->attributes, 'discovery_document');
        if (empty($value) && !empty($dd)) {
            $value = static::getDiscoveryData($dd, 'token_endpoint');
        }

        $this->attributes['token_endpoint'] = $value;
    }

    /**
     * @param $value
     */
    public function setUserEndpointAttribute($value)
    {
        $dd = array_get($this->attributes, 'discovery_document');
        if (empty($value) && !empty($dd)) {
            $value = static::getDiscoveryData($dd, 'userinfo_endpoint');
        }

        $this->attributes['user_endpoint'] = $value;
    }

    /**
     * @param $value
     */
    public function setJwksUriAttribute($value)
    {
        $dd = array_get($this->attributes, 'discovery_document');
        if (empty($value) && !empty($dd)) {
            $value = static::getDiscoveryData($dd, 'jwks_uri');
        }

        $this->attributes['jwks_uri'] = $value;
    }

    /**
     * @param $value
     */
    public function setScopesAttribute($value)
    {
        $dd = array_get($this->attributes, 'discovery_document');
        if (empty($value) && !empty($dd)) {
            $value = implode(',', static::getDiscoveryData($dd, 'scopes_supported'));
        }

        $this->attributes['scopes'] = $value;
    }

    /**
     * @param string $dd
     * @param null   $key
     *
     * @return mixed|null
     * @throws \DreamFactory\Core\Exceptions\InternalServerErrorException
     */
    public static function getDiscoveryData($dd, $key = null)
    {
        if (empty($dd)) {
            return null;
        }
        $data = Cache::remember('DD:' . md5($dd), Config::get('df.default_cache_ttl'), function () use ($dd){
            $client = new Client();
            $response = $client->get($dd);

            return json_decode($response->getBody()->getContents(), true);
        });

        if (!empty($data)) {
            if (empty($key)) {
                return $data;
            } else {
                return array_get($data, $key);
            }
        } else {
            throw new InternalServerErrorException('Failed to retrieve discovery document. Please check service configuration.');
        }
    }

    /**
     * @return \Illuminate\Database\Eloquent\Relations\BelongsTo
     */
    public function service()
    {
        return $this->belongsTo(Service::class, 'service_id', 'id');
    }

    /**
     * @param array $schema
     */
    protected static function prepareConfigSchemaField(array &$schema)
    {
        parent::prepareConfigSchemaField($schema);

        switch ($schema['name']) {
            case 'default_role':
                $roles = Role::whereIsActive(1)->get();
                $roleList = [];
                foreach ($roles as $role) {
                    $roleList[] = [
                        'label' => $role->name,
                        'name'  => $role->id
                    ];
                }
                $schema['label'] = 'Default Role';
                $schema['type'] = 'picklist';
                $schema['values'] = $roleList;
                $schema['description'] = 'Select a default role for users logging in with this OAuth service type.';
                break;
            case 'discovery_document':
                $schema['label'] = 'Discovery Document Endpoint';
                $schema['description'] = 'Optional OpenID Connect Discovery Document endpoint. ' .
                    'When valid endpoint is provided, following configuration options will be set based on ' .
                    'the Discovery Document. Therefore, you may leave these options blank - Authorization Endpoint, ' .
                    'Token Endpoint, User Endpoint, Validate ID Token, JWKS URI, Scopes';
                break;
            case 'auth_endpoint':
                $schema['label'] = 'Authorization Endpoint';
                $schema['description'] =
                    'Authorization endpoint of the provider. Not required when Discovery Document Endpoint is entered.';
                break;
            case 'token_endpoint':
                $schema['label'] = 'Token Endpoint';
                $schema['description'] =
                    'Token endpoint of the provider. Not required when Discovery Document Endpoint is entered.';
                break;
            case 'user_endpoint':
                $schema['label'] = 'User Info Endpoint';
                $schema['description'] = 'User information endpoint of the provider.';
                break;
            case 'validate_id_token':
                $schema['label'] = 'Validate ID Token';
                $schema['description'] = 'Validate ID Token received from the provider.';
                break;
            case 'jwks_uri':
                $schema['label'] = 'JWKS URI';
                $schema['description'] =
                    'JWKS endpoint that provides the necessary keys to decode and validate the ID Token';
                break;
            case 'scopes':
                $schema['label'] = 'Scopes';
                $schema['description'] =
                    'Authorization scopes. Enter multiple scopes separated by comma. Not required when Discovery Document Endpoint is entered.';
                break;
            case 'client_id':
                $schema['label'] = 'Client ID';
                $schema['description'] =
                    'A public string used by the service to identify your app and to build authorization URLs.';
                break;
            case 'client_secret':
                $schema['label'] = 'Client Secret';
                $schema['description'] =
                    'A private string used by the service to authenticate the identity of the application.';
                break;
            case 'redirect_url':
                $schema['label'] = 'Redirect URL';
                $schema['description'] = 'The location the user will be redirected to after a successful login.';
                break;
            case 'icon_class':
                $schema['label'] = 'Icon Class';
                $schema['description'] = 'The icon to display for this OAuth service.';
                break;
        }
    }
}