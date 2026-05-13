<?php

namespace DreamFactory\Core\OIDC\Tests\Security;

use DreamFactory\Core\Oidc\Components\OidcProvider;
use PHPUnit\Framework\TestCase;

/**
 * Security: only RSA SHA-2 algorithms are accepted from the JWKS doc.
 * Reject 'none', HMAC variants, or anything else that could downgrade
 * verification or trigger alg confusion.
 */
class JwksAlgAllowlistTest extends TestCase
{
    public function testAllowlistContainsRsaSha2Only(): void
    {
        $this->assertSame(
            ['RS256', 'RS384', 'RS512'],
            OidcProvider::ALLOWED_JWS_ALGS,
            'JWKS alg allowlist must be exactly RS256/RS384/RS512'
        );
    }

    public function testNoneAlgIsRejected(): void
    {
        $this->assertNotContains('none', OidcProvider::ALLOWED_JWS_ALGS);
        $this->assertNotContains('None', OidcProvider::ALLOWED_JWS_ALGS);
    }

    public function testHmacAlgsAreRejected(): void
    {
        foreach (['HS256', 'HS384', 'HS512'] as $alg) {
            $this->assertNotContains($alg, OidcProvider::ALLOWED_JWS_ALGS);
        }
    }

    public function testEcdsaAlgsAreRejected(): void
    {
        // ES256/384/512 are not currently supported by the verifier
        // (uses RSA-only path); ensure they are not silently allowlisted.
        foreach (['ES256', 'ES384', 'ES512'] as $alg) {
            $this->assertNotContains($alg, OidcProvider::ALLOWED_JWS_ALGS);
        }
    }
}
