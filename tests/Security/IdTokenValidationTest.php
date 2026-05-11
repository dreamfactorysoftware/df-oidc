<?php

namespace DreamFactory\Core\OIDC\Tests\Security;

use PHPUnit\Framework\TestCase;

/**
 * Security: OidcProvider::validateIdToken() must NOT decode and trust the
 * id_token payload without signature/issuer/audience/expiry verification.
 *
 * Phase 2 audit found:
 *
 *     if ($this->validateIdToken === true) { ...full validation... }
 *     elseif (!empty($idToken)) {
 *         $parts = explode('.', $idToken);
 *         return json_decode($this->encoder->decode($parts[1]), true);  // <-- accept any forged claims
 *     }
 *
 * The `elseif` branch returned the raw base64-decoded JWT payload without
 * verifying the signature. Any caller (or any IdP, including a forged
 * response) could mint claims (sub, email, roles) that DreamFactory then
 * used to identify or provision a user.
 *
 * After the fix, when validateIdToken is disabled or jwksUri unset, the
 * id_token claims are NEVER consumed. getUserFromTokenResponse() falls back
 * to calling the userinfo endpoint with the access_token, which is
 * authenticated server-to-server.
 */
class IdTokenValidationTest extends TestCase
{
    private string $sourcePath;
    private string $contents;

    protected function setUp(): void
    {
        $this->sourcePath = __DIR__ . '/../../src/Components/OidcProvider.php';
        $this->assertFileExists($this->sourcePath);
        $this->contents = file_get_contents($this->sourcePath);
    }

    /**
     * Slice the body of validateIdToken(array $response).
     */
    private function methodBody(): string
    {
        $start = strpos($this->contents, 'function validateIdToken(array');
        $this->assertNotFalse($start, 'validateIdToken(array $response) must exist');
        $next = strpos($this->contents, "\n    /**", $start + 10);
        return substr($this->contents, $start, $next === false ? null : ($next - $start));
    }

    public function testNoUnverifiedJsonDecodeOfIdToken(): void
    {
        $body = $this->methodBody();
        // The vulnerable shape was:
        //   return json_decode($this->encoder->decode($parts[1]), true);
        // Forbid that entire pattern.
        $this->assertDoesNotMatchRegularExpression(
            '/json_decode\s*\(\s*\$this->encoder->decode\s*\(\s*\$parts\[1\]\s*\)/',
            $body,
            'validateIdToken() must not decode + return the raw JWT payload '
            . 'when signature validation is disabled. The id_token claims must '
            . 'NEVER be trusted without verification.'
        );
    }

    public function testReturnsNullOrCallsValidationWhenIdTokenPresent(): void
    {
        $body = $this->methodBody();

        // After the fix, the disabled-validation branch must either
        // (a) return null when id_token is present (preferred — falls back to userinfo)
        // (b) throw an exception; or
        // (c) call full verification.
        // Forbid: returning the parsed payload as a value the caller will trust.
        $this->assertDoesNotMatchRegularExpression(
            '/return\s+json_decode\s*\(/',
            $body,
            'validateIdToken() must not return a json_decode result of the JWT payload'
        );
    }
}
