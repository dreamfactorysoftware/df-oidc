<?php

namespace DreamFactory\Core\Oidc\Models;

use DreamFactory\Core\Components\AppRoleMapper;
use DreamFactory\Core\Exceptions\InternalServerErrorException;
use DreamFactory\Core\Models\BaseServiceConfigModel;
use DreamFactory\Core\Models\Role;
use DreamFactory\Core\Models\Service;
use DreamFactory\Core\Oidc\Models\RoleOidc;
use GuzzleHttp\Client;
use Cache;
use Config;
use Arr;

class OidcConfig extends BaseServiceConfigModel
{
    // Alias the trait's config methods so this model can layer group-to-role
    // mapping on top of the app_role_map handling the trait provides.
    use AppRoleMapper {
        getConfigSchema as protected getAppRoleMapperSchema;
        getConfig as protected getAppRoleMapperConfig;
        setConfig as protected setAppRoleMapperConfig;
    }

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
        'map_group_to_role',
        'groups_claim',
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
        'validate_id_token' => 'boolean',
        'map_group_to_role' => 'boolean',
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
        $discovery = Arr::get($data, 'discovery_document');

        if (empty($discovery)) {
            $this->rules['auth_endpoint'] = 'required';
            $this->rules['token_endpoint'] = 'required';
            $this->rules['scopes'] = 'required';
            if (boolval(Arr::get($data, 'validate_id_token'))) {
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
                $this->attributes['auth_endpoint'] = Arr::get($data, 'authorization_endpoint');
            }
            if (!isset($this->attributes['token_endpoint'])) {
                $this->attributes['token_endpoint'] = Arr::get($data, 'token_endpoint');
            }
            if (!isset($this->attributes['user_endpoint'])) {
                $this->attributes['user_endpoint'] = Arr::get($data, 'userinfo_endpoint');
            }
            if (!isset($this->attributes['jwks_uri'])) {
                $this->attributes['jwks_uri'] = Arr::get($data, 'jwks_uri');
            }
            if (!isset($this->attributes['scopes'])) {
                $this->attributes['scopes'] = implode(',', Arr::get($data, 'scopes_supported'));
            }
        }
    }

    /**
     * @param $value
     */
    public function setAuthEndpointAttribute($value)
    {
        $dd = Arr::get($this->attributes, 'discovery_document');
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
        $dd = Arr::get($this->attributes, 'discovery_document');
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
        $dd = Arr::get($this->attributes, 'discovery_document');
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
        $dd = Arr::get($this->attributes, 'discovery_document');
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
        $dd = Arr::get($this->attributes, 'discovery_document');
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
                return Arr::get($data, $key);
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
     * Get config including group-to-role mappings.
     *
     * @param int   $id
     * @param mixed $local_config
     * @param bool  $protect
     * @return array|null
     */
    public static function getConfig($id, $local_config = null, $protect = true)
    {
        // getAppRoleMapperConfig also appends app_role_map (via the trait).
        $config = static::getAppRoleMapperConfig($id, $local_config, $protect);

        if ($config) {
            $groupRoleMaps = RoleOidc::where('role_id', '>', 0)->get();
            $config['group_role_map'] = [];

            foreach ($groupRoleMaps as $map) {
                $config['group_role_map'][] = [
                    'role_id'   => $map->role_id,
                    'group_ref' => $map->group_ref,
                ];
            }
        }

        return $config;
    }

    /**
     * Set config including group-to-role mappings.
     *
     * @param int   $id
     * @param array $config
     * @param mixed $local_config
     * @return mixed
     */
    public static function setConfig($id, $config, $local_config = null)
    {
        // Extract group role map before delegating (the trait/base don't know it).
        $groupRoleMap = array_get($config, 'group_role_map');
        unset($config['group_role_map']);

        // Persist main config + app_role_map via the trait.
        $result = static::setAppRoleMapperConfig($id, $config, $local_config);

        if (isset($groupRoleMap) && is_array($groupRoleMap)) {
            RoleOidc::query()->delete();

            foreach ($groupRoleMap as $map) {
                if (!empty($map['role_id']) && !empty($map['group_ref'])) {
                    RoleOidc::create([
                        'role_id'   => $map['role_id'],
                        'group_ref' => $map['group_ref'],
                    ]);
                }
            }
        }

        return $result;
    }

    /**
     * {@inheritdoc}
     */
    public static function getConfigSchema()
    {
        // getAppRoleMapperSchema adds the app_role_map field.
        $schema = static::getAppRoleMapperSchema();

        $schema[] = [
            'name'        => 'group_role_map',
            'label'       => 'Group to Role Mapping',
            'description' => 'Map OpenID Connect provider group memberships to DreamFactory roles. ' .
                             'When "Map Groups to Roles" is enabled, users are assigned a role based on ' .
                             'the groups present in their token (or userinfo) response.',
            'type'        => 'array',
            'required'    => false,
            'allow_null'  => true,
            'items'       => RoleOidc::getConfigSchema(),
        ];

        return $schema;
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
                    'Token Endpoint, User Endpoint, JWKS URI, Scopes';
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
            case 'map_group_to_role':
                $schema['label'] = 'Map Groups to Roles';
                $schema['type'] = 'boolean';
                $schema['default'] = false;
                $schema['description'] = 'Enable mapping of OpenID Connect provider group memberships to ' .
                    'DreamFactory roles. The provider must include the configured groups claim in the ' .
                    'ID Token or userinfo response. For Azure AD via OIDC the groups claim is only present ' .
                    'in the ID Token, so "Validate ID Token" must also be enabled.';
                break;
            case 'groups_claim':
                $schema['label'] = 'Groups Claim Name';
                $schema['type'] = 'string';
                $schema['default'] = 'groups';
                $schema['description'] = 'Name of the claim that carries the user\'s group memberships. ' .
                    'Defaults to "groups" (Okta, Keycloak, Azure AD). For Auth0 use your namespaced ' .
                    'claim, e.g. "https://your-app/groups".';
                break;
        }
    }
}
