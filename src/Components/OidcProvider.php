<?php

namespace DreamFactory\Core\Oidc\Components;

use DreamFactory\Core\Exceptions\InternalServerErrorException;
use DreamFactory\Core\Exceptions\UnauthorizedException;
use DreamFactory\Core\OAuth\Components\DfOAuthTwoProvider;
use DreamFactory\Core\Oidc\Models\OidcConfig;
use Illuminate\Http\Request;
use Laravel\Socialite\Two\AbstractProvider;
use Laravel\Socialite\Two\InvalidStateException;
use Firebase\JWT\JWT;
use Firebase\JWT\JWK;
use Firebase\JWT\ExpiredException;
use SocialiteProviders\Manager\OAuth2\User;
use Cache;
use Config;
use Log;
use Arr;

/**
 * Class OidcProvider
 *
 * NOTE: THIS IMPLEMENTATION ADHERES TO OPENID CONNECT CORE 1.0 SPECIFICATION
 * FOUND AT http://openid.net/specs/openid-connect-core-1_0.html#CodeFlowAuth
 * BEFORE MAKING ANY CHANGES TO THIS IMPLEMENTATION PLEASE CONSIDER READING THE
 * SPECIFICATION.
 *
 * @package DreamFactory\Core\Oidc\Components
 */
class OidcProvider extends AbstractProvider
{
    /** Cache key constant */
    const JWKS_CACHE_KEY = 'oidc-jwks';

    use DfOAuthTwoProvider;

    /**
     * {@inheritdoc}
     */
    protected $scopeSeparator = ' ';

    /**
     * OpenID Connect discovery document endpoint
     *
     * @var null|string
     */
    protected $discoveryEndpoint = null;

    /**
     * OpenID Connect auth endpoint
     *
     * @var null|string
     */
    protected $authEndpoint = null;

    /**
     * OpenID Connect token endpoint
     *
     * @var null|string
     */
    protected $tokenEndpoint = null;

    /**
     * OpenID Connect user endpoint
     *
     * @var null|string
     */
    protected $userEndpoint = null;

    /**
     * OpenID Connect public keys endpoint
     *
     * @var null|string
     */
    protected $jwksUri = null;

    /**
     * OpenID Connect ID Token validation check flag
     *
     * @var bool
     */
    public $validateIdToken = false;

    /**
     * Whether to collect the groups claim for role mapping.
     *
     * @var bool
     */
    protected $mapGroupToRole = false;

    /**
     * Name of the claim that carries the user's group memberships.
     *
     * @var string
     */
    protected $groupsClaim = 'groups';

    /**
     * OidcProvider constructor.
     *
     * @param \Illuminate\Http\Request $clientId
     * @param string                   $clientSecret
     * @param string                   $redirectUrl
     */
    public function __construct($clientId, $clientSecret, $redirectUrl)
    {
        /** @var Request $request */
        $request = \Request::instance();
        parent::__construct($request, $clientId, $clientSecret, $redirectUrl);
    }

    /**
     * @param string $endpoint
     */
    public function setDiscoveryEndpoint($endpoint)
    {
        $this->discoveryEndpoint = $endpoint;
    }

    /**
     * @param string $endpoint
     */
    public function setAuthEndpoint($endpoint)
    {
        $this->authEndpoint = $endpoint;
    }

    /**
     * @param string $endpoint
     */
    public function setTokenEndpoint($endpoint)
    {
        $this->tokenEndpoint = $endpoint;
    }

    /**
     * @param string $endpoint
     */
    public function setUserEndpoint($endpoint)
    {
        $this->userEndpoint = $endpoint;
    }

    /**
     * @param string $uri
     */
    public function setJwksUri($uri)
    {
        $this->jwksUri = $uri;
    }

    /**
     * @param array $scopes
     */
    public function setScopes($scopes)
    {
        $this->scopes = $scopes;
    }

    /**
     * Enable group-to-role mapping and set the claim name to read groups from.
     *
     * @param string $claim
     * @return $this
     */
    public function enableGroupMapping($claim = 'groups')
    {
        $this->mapGroupToRole = true;
        $this->groupsClaim = !empty($claim) ? $claim : 'groups';

        return $this;
    }

    /**
     * {@inheritdoc}
     */
    public function user()
    {
        if ($this->hasInvalidState()) {
            throw new InvalidStateException();
        }

        $response = $this->getAccessTokenResponse($this->getCode());

        return $this->getUserFromTokenResponse($response);
    }

    /**
     * {@inheritdoc}
     */
    public function getUserFromTokenResponse($response)
    {
        $this->credentialsResponseBody = $response;
        $token = $this->parseAccessToken($response);
        $payload = $this->validateIdToken($response);

        // Prefer the validated id_token payload for identity. It is only
        // non-null when signature validation succeeded, so trusting it is safe.
        // Require a subject plus a display identifier; email is NOT required
        // here because providers such as Azure AD omit `email` but supply
        // `preferred_username` (mapUserToObject resolves the email fallback).
        // When there is no usable validated payload we fall back to the
        // server-to-server userinfo endpoint.
        $userInfo = null;
        $payloadSub = is_array($payload) ? ($payload['sub'] ?? $payload['oid'] ?? null) : null;
        $payloadName = is_array($payload) ? ($payload['name'] ?? $payload['preferred_username'] ?? null) : null;
        if (!empty($payloadSub) && !empty($payloadName)) {
            $user = $this->mapUserToObject($payload);
        } else {
            $userInfo = $this->getUserByToken($token);
            $user = $this->mapUserToObject($userInfo);
        }

        // Collect group memberships for role mapping from every trusted source.
        // The validated id_token payload is preferred (e.g. Azure AD returns
        // group Object IDs only in the id_token, and only when validation is on);
        // the userinfo response is the fallback for providers that expose groups
        // there. Attaching under a normalized 'groups' key on the raw user lets
        // the service read them uniformly via getRaw().
        if ($this->mapGroupToRole) {
            $groups = $this->extractGroups([
                is_array($payload) ? $payload : [],
                is_array($userInfo) ? $userInfo : [],
            ]);
            $user->setRaw(array_merge($user->getRaw(), ['groups' => $groups]));
        }

        if ($user instanceof User) {
            $user->setAccessTokenResponseBody($this->credentialsResponseBody);
        }

        return $user->setToken($token)
            ->setRefreshToken($this->parseRefreshToken($response))
            ->setExpiresIn($this->parseExpiresIn($response));
    }

    /**
     * Extract and normalize the configured groups claim from a list of trusted
     * sources (validated id_token payload and/or userinfo response).
     *
     * @param array $sources Array of associative arrays to inspect.
     * @return array De-duplicated list of group references (strings).
     */
    protected function extractGroups(array $sources)
    {
        $groups = [];
        $overageDetected = false;

        foreach ($sources as $source) {
            if (!is_array($source) || empty($source)) {
                continue;
            }

            $claim = Arr::get($source, $this->groupsClaim);

            // Azure AD "groups overage": when a user belongs to too many groups
            // to fit in the token, Azure omits the groups claim and returns a
            // _claim_names / _claim_sources pointer to the Graph API instead.
            // We cannot resolve those from the token alone. See README.
            if (empty($claim) && Arr::get($source, '_claim_names.groups') !== null) {
                $overageDetected = true;
                continue;
            }

            if (empty($claim)) {
                continue;
            }

            foreach ($this->normalizeGroupClaim($claim) as $value) {
                $groups[$value] = true; // key-based de-dup across sources
            }
        }

        if ($overageDetected && empty($groups)) {
            Log::warning(
                'OIDC group-to-role: provider signaled a groups overage (too many groups to fit in the '
                . 'token) via _claim_names/_claim_sources. Resolving the full group list requires a '
                . 'provider directory API call, which is not supported. No group role mapping was applied; '
                . 'the user will receive the default role.'
            );
        }

        return array_keys($groups);
    }

    /**
     * Normalize a groups claim value into a flat list of string references.
     * Handles: array of strings (Azure GUIDs, Okta names), array of objects
     * (pull id/displayName/name/value), and single delimited strings.
     *
     * @param mixed $claim
     * @return array
     */
    protected function normalizeGroupClaim($claim)
    {
        if (is_string($claim)) {
            return array_values(array_filter(array_map('trim', preg_split('/[\s,]+/', $claim))));
        }

        if (!is_array($claim)) {
            return [];
        }

        $out = [];
        foreach ($claim as $item) {
            if (is_string($item) || is_numeric($item)) {
                $out[] = (string)$item;
            } elseif (is_array($item)) {
                $val = Arr::get($item, 'id',
                    Arr::get($item, 'displayName',
                        Arr::get($item, 'name',
                            Arr::get($item, 'value'))));
                if (!empty($val)) {
                    $out[] = (string)$val;
                }
            }
        }

        return array_values(array_filter(array_map('trim', $out)));
    }

    /**
     * {@inheritdoc}
     */
    protected function parseAccessToken($body)
    {
        $token = Arr::get($body, 'access_token');
        if (empty($token)) {
            $token = '--NOT-AVAILABLE--';
        }

        return $token;
    }

    /**
     * @param array $response
     *
     * @return array|bool
     * @throws \DreamFactory\Core\Exceptions\InternalServerErrorException
     */
    protected function validateIdToken(array $response)
    {
        $idToken = Arr::get($response, 'id_token');

        // Always validate when an id_token is present. The previous behavior
        // had an `elseif (!empty($idToken))` branch that returned the raw
        // base64-decoded JWT payload WITHOUT verifying signature, issuer,
        // audience, or expiry — meaning a forged id_token from any source
        // (or an unsigned JWT) would be accepted and its claims trusted to
        // populate the user record. Removed.
        //
        // When validation is configured (validateIdToken=true and jwksUri
        // set), we run the full check. Otherwise we DO NOT trust the
        // id_token payload at all — getUserFromTokenResponse() falls back
        // to calling the userinfo endpoint with the access_token, which
        // is authenticated server-to-server.
        if ($this->validateIdToken === true) {
            if (empty($this->jwksUri)) {
                throw new InternalServerErrorException('Token validation is turned on but no JWKS URI found. Please check your service configuration.');
            }
            $payload = $this->verifySignature($idToken);
            $this->verifyIssuer(Arr::get($payload, 'iss'));
            $this->verifyAudience(Arr::get($payload, 'aud'), Arr::get($payload, 'azp'));
            $this->verifyExpiry(Arr::get($payload, 'exp'));

            return $payload;
        }

        if (!empty($idToken)) {
            Log::warning(
                'OIDC id_token received but validateIdToken is disabled or jwksUri unset; '
                . 'id_token claims will NOT be trusted. Falling back to userinfo endpoint. '
                . 'Enable validateIdToken + configure jwksUri to consume id_token claims directly.'
            );
        } else {
            Log::warning('No ID Token found for OpenID Connect service.');
        }

        return null;
    }

    /**
     * @param string $iss
     *
     * @return bool
     * @throws \DreamFactory\Core\Exceptions\UnauthorizedException
     */
    protected function verifyIssuer($iss)
    {
        if (empty($this->discoveryEndpoint)) {
            // Not enough information to verify issuer.
            return false;
        }
        if (OidcConfig::getDiscoveryData($this->discoveryEndpoint, 'issuer') === $iss) {
            return true;
        }
        throw new UnauthorizedException('Failed to verify ID Token issuer.');
    }

    /**
     * @param mixed  $aud
     * @param string $azp
     *
     * @return bool
     * @throws \DreamFactory\Core\Exceptions\UnauthorizedException
     */
    protected function verifyAudience($aud, $azp)
    {
        if (is_string($aud)) {
            if ($aud === $this->clientId) {
                return true;
            }
        } elseif (is_array($aud)) {
            if ($azp === $this->clientId) {
                return true;
            }
        }

        throw new UnauthorizedException('Failed to verify ID Token audience');
    }

    /**
     * @param int|string $exp
     *
     * @return bool
     * @throws \DreamFactory\Core\Exceptions\UnauthorizedException
     */
    protected function verifyExpiry($exp)
    {
        $exp = (int)$exp;
        if ($exp > time()) {
            return true;
        }

        throw new UnauthorizedException('Failed to verify ID Token. Token expired.');
    }

    /**
     * @param string $jwt
     *
     * @return mixed
     * @throws \DreamFactory\Core\Exceptions\InternalServerErrorException
     */
    protected function getJwtHeader($jwt)
    {
        $parts = explode('.', $jwt);

        if (count($parts) === 3) {
            $header = json_decode(base64_decode(strtr($parts[0], '-_,', '+/=')), true);
            if (!isset($header['kid'])) {
                throw new InternalServerErrorException('Invalid JWT header. No \'kid\' found.');
            }

            return $header;
        } else {
            throw new InternalServerErrorException('Cannot get JWT header. Incorrect number of segments in JWT.');
        }
    }

    /**
     * Fetch (and cache) the provider's raw JWKS document.
     *
     * @return array The decoded JWKS, e.g. ['keys' => [...]].
     * @throws \DreamFactory\Core\Exceptions\InternalServerErrorException
     */
    protected function getProviderKeys()
    {
        if (empty($this->jwksUri)) {
            throw new InternalServerErrorException('Validation failed. No JWKS endpoint found. Please check service configuration');
        }

        return Cache::remember(
            static::JWKS_CACHE_KEY . ':set:' . md5($this->jwksUri),
            Config::get('df.default_cache_ttl'),
            function () {
                $response = $this->getHttpClient()->get($this->jwksUri);

                return json_decode($response->getBody()->getContents(), true);
            }
        );
    }

    /**
     * Parse the provider JWKS into a map of kid => Firebase\JWT\Key.
     * Azure AD (and some others) omit 'alg' on JWKS entries, so RS256 is
     * supplied as the default.
     *
     * @return array<string, \Firebase\JWT\Key>
     * @throws \DreamFactory\Core\Exceptions\InternalServerErrorException
     */
    protected function getProviderKeySet()
    {
        try {
            return JWK::parseKeySet($this->getProviderKeys(), 'RS256');
        } catch (\Exception $e) {
            throw new InternalServerErrorException('Failed to parse provider JWKS. ' . $e->getMessage());
        }
    }

    /**
     * Algorithms accepted for ID Token signatures. We deliberately reject
     * 'none', HMAC variants (HS*), and anything else not on this list:
     * a malicious or compromised token/JWKS could otherwise downgrade
     * verification (alg=none) or trigger HMAC/RSA confusion.
     */
    public const ALLOWED_JWS_ALGS = ['RS256', 'RS384', 'RS512'];

    /**
     * Verify the ID Token signature and time claims using the provider JWKS.
     *
     * @param string $idToken
     *
     * @return array The verified token payload.
     * @throws \DreamFactory\Core\Exceptions\InternalServerErrorException
     * @throws \DreamFactory\Core\Exceptions\UnauthorizedException
     */
    protected function verifySignature($idToken)
    {
        // Enforce the algorithm allowlist from the token header up front, before
        // any signature work, to reject 'none', HMAC (HS*), and downgrade/confusion.
        $header = $this->getJwtHeader($idToken);
        $alg = Arr::get($header, 'alg');
        if (!in_array($alg, self::ALLOWED_JWS_ALGS, true)) {
            throw new UnauthorizedException(
                'Failed to verify JWT signature. Disallowed algorithm [' . $alg . '].'
            );
        }

        try {
            // Small leeway to tolerate minor clock skew on exp/nbf/iat.
            JWT::$leeway = 60;
            // JWT::decode selects the key by the token 'kid', verifies the RSA
            // signature, and validates exp/nbf/iat, throwing on any failure.
            $decoded = JWT::decode($idToken, $this->getProviderKeySet());

            return json_decode(json_encode($decoded), true);
        } catch (ExpiredException $e) {
            throw new UnauthorizedException('Failed to verify ID Token. Token expired.');
        } catch (\Exception $e) {
            throw new UnauthorizedException(
                $e->getMessage() .
                ' Uncheck \'Validate ID Token\' checkbox in the service configuration and try again.'
            );
        }
    }

    /**
     * {@inheritdoc}
     */
    protected function getAuthUrl($state)
    {
        return $this->buildAuthUrlFromBase($this->authEndpoint, $state);
    }

    /**
     * {@inheritdoc}
     */
    protected function getTokenUrl()
    {
        return $this->tokenEndpoint;
    }

    /**
     * {@inheritdoc}
     */
    protected function getTokenFields($code)
    {
        return Arr::add(parent::getTokenFields($code), 'grant_type', 'authorization_code');
    }

    /**
     * {@inheritdoc}
     */
    protected function getUserByToken($token)
    {
        if (empty($token)) {
            throw new InternalServerErrorException('Failed to retrieve user information. No access token found.');
        }
        if (empty($this->userEndpoint)) {
            throw new InternalServerErrorException('User Info Endpoint not set. Please check service configuration.');
        }
        $response = $this->getHttpClient()->get($this->userEndpoint, [
            'headers' => [
                'Authorization' => 'Bearer ' . $token
            ]
        ]);

        return json_decode($response->getBody()->getContents(), true);
    }

    /**
     * {@inheritdoc}
     *
     * Maps standard OpenID Connect claims. The subject is carried in `sub`
     * (not `id`), and many providers - notably Azure AD - omit `email` for
     * accounts without a mailbox, exposing the sign-in name in
     * `preferred_username`/`upn` instead. We fall back accordingly so a usable
     * identifier and email are always resolved when available.
     */
    protected function mapUserToObject(array $user)
    {
        return (new User)->setRaw($user)->map([
            'id'       => Arr::get($user, 'sub', Arr::get($user, 'oid', Arr::get($user, 'id'))),
            'nickname' => Arr::get($user, 'preferred_username', Arr::get($user, 'nickname')),
            'name'     => Arr::get($user, 'name', Arr::get($user, 'preferred_username')),
            'email'    => Arr::get($user, 'email',
                Arr::get($user, 'preferred_username',
                    Arr::get($user, 'upn'))),
            'avatar'   => Arr::get($user, 'picture'),
        ]);
    }
}
