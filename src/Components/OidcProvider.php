<?php

namespace DreamFactory\Core\Oidc\Components;

use DreamFactory\Core\Exceptions\InternalServerErrorException;
use DreamFactory\Core\Exceptions\UnauthorizedException;
use DreamFactory\Core\OAuth\Components\DfOAuthTwoProvider;
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
    const JWKS_CACHE_KEY = 'oidc-jwks';

    use DfOAuthTwoProvider;

    /**
     * The separating character for the requested scopes.
     *
     * @var string
     */
    protected $scopeSeparator = ' ';

    protected $authEndpoint = null;

    protected $tokenEndpoint = null;

    protected $userEndpoint = null;

    protected $jwksUri = null;

    public $validateIdToken = false;

    public function __construct($clientId, $clientSecret, $redirectUrl)
    {
        /** @var Request $request */
        $request = \Request::instance();
        parent::__construct($request, $clientId, $clientSecret, $redirectUrl);
    }

    public function setAuthEndpoint($endpoint)
    {
        $this->authEndpoint = $endpoint;
    }

    public function setTokenEndpoint($endpoint)
    {
        $this->tokenEndpoint = $endpoint;
    }

    public function setUserEndpoint($endpoint)
    {
        $this->userEndpoint = $endpoint;
    }

    public function setJwksUri($uri)
    {
        $this->jwksUri = $uri;
    }

    public function setScopes(array $scopes)
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
        $this->credentialsResponseBody = $response;
        $token = $this->parseAccessToken($response);
        $payload = $this->validateIdToken($response);

        if (!empty($payload) && is_array($payload)){
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

    protected function validateIdToken($response)
    {
        $idToken = array_get($response, 'id_token');
        if (empty($idToken)) {
            throw new InternalServerErrorException('An unexpected error occurred. No ID Token found in token response.');
        }

        if ($this->validateIdToken === true) {
            if (empty($this->jwksUri)) {
                throw new InternalServerErrorException('Token validation is turned on but no JWKS URI found. Please check your service configuration.');
            }
            $header = $this->getJwtHeader($idToken);
            $kid = $header['kid'];
            $publicKeyInfo = $this->getProviderPublicKeyInfo($kid);
            $payload = $this->verifySignature($publicKeyInfo, $idToken);

            if(false === $payload){
                throw new UnauthorizedException('Failed to verify ID Token signature.');
            }

            return $payload;
        }

        return false;
    }

    protected function getJwtHeader($jwt)
    {
        $parts = explode('.', $jwt);

        if(count($parts) === 3){
            $header = json_decode(base64_decode(strtr($parts[0], '-_,', '+/=')), true);
            if(!isset($header['kid'])){
                throw new InternalServerErrorException('Invalid JWT header. No \'kid\' found.');
            }

            return $header;
        } else {
            throw new InternalServerErrorException('Cannot get JWT header. Incorrect number of segments in JWT.');
        }
    }

    protected function getProviderPublicKeyInfo($kid)
    {
        $key = Cache::get(static::getJwksCacheKey($kid));

        if(empty($key)) {
            $keys = $this->getProviderKeys();
            foreach ($keys as $k) {
                if (array_get($k, 'kty') === 'RSA' && array_get($k, 'kid') === $kid) {
                    $key = $k;
                    Cache::put(static::getJwksCacheKey($kid), $key, Config::get('df.default_cache_ttl'));
                }
            }
        }

        return $key;
    }

    protected function getProviderKeys()
    {
        if(empty($this->jwksUri)){
            throw new InternalServerErrorException('Validation failed. No JWKS endpoint found. Please check service configuration');
        }
        $response = $this->getHttpClient()->get($this->jwksUri);
        $keys = json_decode($response->getBody()->getContents(), true);

        return array_get($keys, 'keys');
    }

    protected function verifySignature($keyData, $idToken)
    {
        if(isset($keyData['n']) && isset($keyData['e'])){
            $alg = array_get($keyData, 'alg');
            $encoder = new Base64UrlSafeEncoder();
            $modulus = new BigInteger($encoder->decode($keyData['n']), 256);
            $exponent = new BigInteger($encoder->decode($keyData['e']), 256);

            $rsa = new RSA();
            $rsa->setHash('sha' . substr($alg, 2));
            $rsa->loadKey(['n' => $modulus, 'e' => $exponent]);
            $rsa->setPublicKey();
            $publicKey = $rsa->getPublicKey();

            $jws = SimpleJWS::load($idToken, false, $encoder);
            if($jws->verify($publicKey, $alg)){
                return $jws->getPayload();
            }
        }
        throw new InternalServerErrorException('Failed to verify JWT signature. Invalid public key.');
    }

    protected static function getJwksCacheKey($kid)
    {
        return static::JWKS_CACHE_KEY . ':' . $kid;
    }

    protected function getAuthUrl($state)
    {
        return $this->buildAuthUrlFromBase($this->authEndpoint, $state);
    }

    protected function getTokenUrl()
    {
        return $this->tokenEndpoint;
    }

    protected function getTokenFields($code)
    {
        return array_add(
            parent::getTokenFields($code), 'grant_type', 'authorization_code'
        );
    }

    protected function getUserByToken($token)
    {
        if(empty($this->userEndpoint)){
            throw new InternalServerErrorException('User Info Endpoint not set. Please check service configuration.');
        }
        $response = $this->getHttpClient()->get($this->userEndpoint, [
            'headers' => [
                'Authorization' => 'Bearer ' . $token
            ]
        ]);

        return json_decode($response->getBody()->getContents(), true);
    }

    protected function mapUserToObject(array $user)
    {
        return (new User)->setRaw($user)->map($user);
    }
}