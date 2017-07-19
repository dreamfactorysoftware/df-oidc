<?php

namespace DreamFactory\Core\Oidc\Resources;

use DreamFactory\Core\OAuth\Resources\SSO as BaseSSO;

class SSO extends BaseSSO
{
    /** {@inheritdoc} */
    public static function getApiDocInfo($service, array $resource = [])
    {
        $base = parent::getApiDocInfo($service, $resource);
        $serviceName = strtolower($service);
        $class = trim(strrchr(static::class, '\\'), '\\');
        $resourceName = strtolower(array_get($resource, 'name', $class));
        $path = '/' . $serviceName . '/' . $resourceName;
        unset($base['paths'][$path]['get']);
        $base['paths'][$path]['post'] = [
            'tags'        => [$serviceName],
            'summary'     => 'performSSO() - Single Sign On',
            'operationId' => 'performSSO',
            'consumes'    => ['application/json', 'application/xml'],
            'produces'    => ['application/json', 'application/xml'],
            'description' => 'Performs Single Sign On using OAuth 2.0 access token',
            'parameters'  => [
                [
                    'name'        => 'body',
                    'description' => 'Content - OAuth token response',
                    'schema'      => [
                        'type'       => 'object',
                        'required'   => ['access_token', 'token_type', 'id_token'],
                        'properties' => [
                            'access_token'  => [
                                'type'        => 'string',
                                'description' => 'The access token issued by the authorization server.'
                            ],
                            'token_type'    => [
                                'type'        => 'string',
                                'description' => 'The type of the token. Typically Bearer.'
                            ],
                            'expires_in'    => [
                                'type'        => 'integer',
                                'description' => 'The lifetime in seconds of the access token.'
                            ],
                            'refresh_token' => [
                                'type'        => 'string',
                                'description' => 'The refresh token, which can be used to obtain new access tokens.'
                            ],
                            'scope'         => [
                                'type'        => 'string',
                                'description' => 'OPTIONAL, if identical to the scope requested by the client; otherwise, REQUIRED.'
                            ],
                            'id_token'      => [
                                'type'        => 'string',
                                'description' => 'User identification token.'
                            ],
                        ]
                    ],
                    'in'          => 'body',
                    'required'    => true
                ]
            ],
            'responses'   => [
                '200'     => [
                    'description' => 'Successful login',
                    'schema'      => [
                        'type'       => 'object',
                        'properties' => [
                            'session_token'   => ['type' => 'string'],
                            'session_id'      => ['type' => 'string'],
                            'id'              => ['type' => 'integer'],
                            'name'            => ['type' => 'string'],
                            'first_name'      => ['type' => 'string'],
                            'last_name'       => ['type' => 'string'],
                            'email'           => ['type' => 'string'],
                            'is_sys_admin'    => ['type' => 'string'],
                            'last_login_date' => ['type' => 'string'],
                            'host'            => ['type' => 'string'],
                            'oauth_token'     => ['type' => 'string'],
                        ]
                    ]
                ],
                'default' => [
                    'description' => 'Error',
                    'schema'      => ['$ref' => '#/definitions/Error']
                ]
            ],
        ];

        return $base;
    }
}