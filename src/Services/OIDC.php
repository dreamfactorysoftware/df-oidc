<?php

namespace DreamFactory\Core\Oidc\Services;

use DreamFactory\Core\Models\User;
use DreamFactory\Core\OAuth\Services\BaseOAuthService;
use DreamFactory\Core\Oidc\Components\OidcProvider;
use DreamFactory\Core\Oidc\Models\RoleOidc;
use DreamFactory\Core\Oidc\Resources\SSO;
use Laravel\Socialite\Contracts\User as OAuthUserContract;
use Illuminate\Support\Facades\Log;
use Arr;

class OIDC extends BaseOAuthService
{
    /**
     * Service provider name.
     */
    const PROVIDER_NAME = 'openid_connect';

    /**
     * Whether to map groups to roles.
     *
     * @var bool
     */
    protected $mapGroupToRole = false;

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
        $this->provider->validateIdToken = boolval(Arr::get($config, 'validate_id_token'));
        $scopes = array_map('trim', explode(',', Arr::get($config, 'scopes')));
        $this->provider->setScopes($scopes);

        $this->mapGroupToRole = boolval(Arr::get($config, 'map_group_to_role', false));
        if ($this->mapGroupToRole) {
            $this->provider->enableGroupMapping(Arr::get($config, 'groups_claim', 'groups'));
        }
    }

    /**
     * {@inheritdoc}
     */
    public function getProviderName()
    {
        return self::PROVIDER_NAME;
    }

    /**
     * Get role ID based on the user's group membership.
     *
     * @param array $groups List of group references (strings) from the token.
     * @return int|null
     */
    protected function getRoleByGroup(array $groups)
    {
        if (!$this->mapGroupToRole || empty($groups)) {
            return null;
        }

        foreach ($groups as $group) {
            if (is_string($group) && $group !== '') {
                $role = $this->findRoleByGroupRef($group);
                if (!empty($role)) {
                    return $role->role_id;
                }
            }
        }

        Log::warning('OIDC: No group matched any configured role mapping.', [
            'user_groups' => $groups,
        ]);

        return null;
    }

    /**
     * Find a role mapping by group reference (name or id).
     *
     * @param string $groupRef
     * @return RoleOidc|null
     */
    protected function findRoleByGroupRef($groupRef)
    {
        if (empty($groupRef)) {
            return null;
        }

        return RoleOidc::whereGroupRef($groupRef)->first();
    }

    /**
     * Override to support group-based role mapping.
     * {@inheritdoc}
     */
    public function createShadowOAuthUser(OAuthUserContract $OAuthUser)
    {
        $fullName = $OAuthUser->getName() ?: $OAuthUser->getNickname();
        @list($firstName, $lastName) = explode(' ', (string)$fullName);

        $email = $OAuthUser->getEmail();
        $serviceName = $this->getName();
        $providerName = $this->getProviderName();

        // Domain-safe token for synthesized addresses (service names may contain
        // characters like '_' that are invalid in a DNS domain, e.g. "azureoidc_oauth").
        $safeService = trim(preg_replace('/[^a-z0-9]+/i', '-', $serviceName), '-') ?: 'oidc';

        if (empty($email) || strpos($email, '@') === false) {
            // No usable email from the provider: synthesize a stable, valid address.
            $localId = $OAuthUser->getId() ?: ($email ?: uniqid('user_', true));
            $email = $localId . '+' . $safeService . '@' . $safeService . '.com';
        } else {
            list($emailId, $domain) = explode('@', $email, 2);
            $email = $emailId . '+' . $serviceName . '@' . $domain;
        }

        $user = User::whereEmail($email)->first();

        if (empty($user)) {
            $config = Arr::get($this->config, 'allow_new_users', true);
            if (!$config) {
                throw new \DreamFactory\Core\Exceptions\UnauthorizedException(
                    'New user registration is not allowed for this OAuth service. ' .
                    'Please contact your administrator to create an account or enable new user registration.'
                );
            }

            $data = [
                'username'       => $email,
                'name'           => $fullName,
                'first_name'     => $firstName,
                'last_name'      => $lastName,
                'email'          => $email,
                'is_active'      => true,
                'oauth_provider' => $providerName,
            ];

            $user = User::create($data);
        }

        // Priority: Group mapping > App role map > Default role
        $roleToApply = null;

        if ($this->mapGroupToRole) {
            $groups = Arr::get($OAuthUser->getRaw(), 'groups', []);
            $roleToApply = $this->getRoleByGroup($groups);
        }

        if (empty($roleToApply) && !empty($defaultRole = $this->getDefaultRole())) {
            $roleToApply = $defaultRole;
        }

        // Always refresh role assignments on login to reflect current group membership.
        if (!empty($roleToApply)) {
            \DB::table('user_to_app_to_role')->where('user_id', $user->id)->delete();
            User::applyDefaultUserAppRole($user, $roleToApply);
        } elseif (!empty($serviceId = $this->getServiceId())) {
            \DB::table('user_to_app_to_role')->where('user_id', $user->id)->delete();
            User::applyAppRoleMapByService($user, $serviceId);
        }

        return $user;
    }
}
