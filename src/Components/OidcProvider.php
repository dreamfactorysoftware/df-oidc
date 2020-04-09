<?php

namespace DreamFactory\Core\Oidc\Components;

use DreamFactory\Core\Exceptions\InternalServerErrorException;
use DreamFactory\Core\Exceptions\UnauthorizedException;
use DreamFactory\Core\OAuth\Components\DfOAuthTwoProvider;
use DreamFactory\Core\Oidc\Models\OidcConfig;
use Illuminate\Http\Request;
use Laravel\Socialite\Two\AbstractProvider;
use Laravel\Socialite\Two\InvalidStateException;
use Namshi\JOSE\Base64\Base64UrlSafeEncoder;
use Namshi\JOSE\SimpleJWS;
use phpseclib\Crypt\RSA;
use phpseclib\Math\BigInteger;
use SocialiteProviders\Manager\OAuth2\User;
use Cache;
use Config;
use Log;

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
     * URL safe base 64 encoder
     *
     * @var null|\Namshi\JOSE\Base64\Encoder
     */
    protected $encoder = null;

    /**
     * OpenID Connect ID Token validation check flag
     *
     * @var bool
     */
    public $validateIdToken = false;

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
        $this->encoder = new Base64UrlSafeEncoder();
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

        if (!empty($payload) && is_array($payload) && !empty($payload['name']) && !empty($payload['email'])) {
            $user = $this->mapUserToObject($payload);
        } else {
            $user = $this->mapUserToObject($this->getUserByToken($token));
        }

        if ($user instanceof User) {
            $user->setAccessTokenResponseBody($this->credentialsResponseBody);
        }

        return $user->setToken($token)
            ->setRefreshToken($this->parseRefreshToken($response))
            ->setExpiresIn($this->parseExpiresIn($response));
    }

    /**
     * {@inheritdoc}
     */
    protected function parseAccessToken($body)
    {
        $token = array_get($body, 'access_token');
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
        $idToken = array_get($response, 'id_token');

        if ($this->validateIdToken === true) {
            if (empty($this->jwksUri)) {
                throw new InternalServerErrorException('Token validation is turned on but no JWKS URI found. Please check your service configuration.');
            }
            $header = $this->getJwtHeader($idToken);
            $kid = $header['kid'];
            $publicKeyInfo = $this->getProviderPublicKeyInfo($kid);
            $payload = $this->verifySignature($publicKeyInfo, $idToken);
            $this->verifyIssuer(array_get($payload, 'iss'));
            $this->verifyAudience(array_get($payload, 'aud'), array_get($payload, 'azp'));
            $this->verifyExpiry(array_get($payload, 'exp'));

            return $payload;
        } elseif (!empty($idToken)) {
            $parts = explode('.', $idToken);
            if (count($parts) !== 3) {
                throw new InternalServerErrorException('Cannot get JWT header. Incorrect number of segments in JWT.');
            }

            return json_decode($this->encoder->decode($parts[1]), true);
        } else {
            Log::warning('No ID Token found for OpenID Connect service.');

            return null;
        }
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
     * @param string $kid
     *
     * @return mixed
     */
    protected function getProviderPublicKeyInfo($kid)
    {
        $key = Cache::get(static::getJwksCacheKey($kid));

        if (empty($key)) {
            $keys = $this->getProviderKeys();
            foreach ($keys as $k) {
                if (array_get($k, 'kid') === $kid) {
                    $key = $k;
                    Cache::put(static::getJwksCacheKey($kid), $key, Config::get('df.default_cache_ttl'));
                }
            }
        }

        return $key;
    }

    /**
     * @return mixed
     * @throws \DreamFactory\Core\Exceptions\InternalServerErrorException
     */
    protected function getProviderKeys()
    {
        if (empty($this->jwksUri)) {
            throw new InternalServerErrorException('Validation failed. No JWKS endpoint found. Please check service configuration');
        }
        $response = $this->getHttpClient()->get($this->jwksUri);
        $keys = json_decode($response->getBody()->getContents(), true);

        return array_get($keys, 'keys');
    }

    /**
     * @param array  $keyData
     * @param string $idToken
     *
     * @return array
     * @throws \DreamFactory\Core\Exceptions\InternalServerErrorException
     * @throws \DreamFactory\Core\Exceptions\UnauthorizedException
     */
    protected function verifySignature($keyData, $idToken)
    {
        try {
            $kty = array_get($keyData, 'kty');
            $alg = array_get($keyData, 'alg', 'RS256');
            if ($kty === 'RSA') {
                $modulus = new BigInteger($this->encoder->decode($keyData['n']), (int)substr($alg, 2));
                $exponent = new BigInteger($this->encoder->decode($keyData['e']), (int)substr($alg, 2));

                $rsa = new RSA();
                $rsa->setHash('sha' . substr($alg, 2));
                $rsa->loadKey(['n' => $modulus, 'e' => $exponent]);
                $rsa->setPublicKey();
                $publicKey = $rsa->getPublicKey();
            } else {
                throw new InternalServerErrorException(
                    'Failed to verify JWT signature. Unsupported key type (kty) [' . $kty . ']' .
                    'Only RSA key type is supported at this time.'
                );
            }

            $jws = SimpleJWS::load($idToken, false, $this->encoder);
            if ($jws->verify($publicKey, $alg)) {
                return $jws->getPayload();
            }

            throw new InternalServerErrorException('Failed to verify ID Token signature.');
        } catch (\Exception $e) {
            throw new UnauthorizedException(
                $e->getMessage() .
                ' Uncheck \'Validate ID Token\' checkbox in the service configuration and try again.'
            );
        }
    }

    /**
     * @param string $kid
     *
     * @return string
     */
    protected static function getJwksCacheKey($kid)
    {
        return static::JWKS_CACHE_KEY . ':' . $kid;
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
        return array_add(parent::getTokenFields($code), 'grant_type', 'authorization_code');
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
     */
    protected function mapUserToObject(array $user)
    {
        return (new User)->setRaw($user)->map($user);
    }
}