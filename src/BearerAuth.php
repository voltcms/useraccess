<?php

namespace VoltCMS\UserAccess;

// Stateless OAuth 2.0 Bearer-token authentication for the SCIM API.
//
// Real identity providers (Okta, Entra/Azure AD, OneLogin, …) provision over
// SCIM with a static, high-entropy shared secret sent as
// `Authorization: Bearer <token>`. This class validates that header against one
// or more configured tokens. A valid token authorizes the request as the
// provisioning service (full admin rights) — there is no per-user lookup, which
// matches how SCIM "Header/Bearer" provisioning is configured in practice.
//
// Tokens are held only as SHA-256 digests and compared in constant time
// (`hash_equals` over equal-length hashes), so neither a token's value nor its
// length leaks through timing or memory. Because the secret is high-entropy,
// failed Bearer attempts are intentionally NOT run through LoginThrottle:
// throttling would risk locking out a legitimately-configured IdP on a
// transient misconfiguration while adding no real protection against guessing.
class BearerAuth
{
    private $tokenHashes = [];

    public function __construct(array $tokens = [])
    {
        $this->setTokens($tokens);
    }

    // Configures the accepted tokens. Empty/blank entries are ignored. Tokens
    // are stored as SHA-256 digests, never in plaintext.
    public function setTokens(array $tokens): void
    {
        $this->tokenHashes = [];
        foreach ($tokens as $token) {
            $token = trim((string) $token);
            if ($token === '') {
                continue;
            }
            $this->tokenHashes[] = hash('sha256', $token);
        }
    }

    public function isConfigured(): bool
    {
        return !empty($this->tokenHashes);
    }

    // Extracts the token from a `Bearer` Authorization header, honoring the
    // Apache `REDIRECT_` fallback (same passthrough HeaderAuth relies on).
    public static function extractToken(): ?string
    {
        $authorizationHeader = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
        if ($authorizationHeader === '') {
            $authorizationHeader = $_SERVER['REDIRECT_HTTP_AUTHORIZATION'] ?? '';
        }
        if (!str_starts_with($authorizationHeader, 'Bearer ')) {
            return null;
        }
        $token = trim(substr($authorizationHeader, 7));
        return $token === '' ? null : $token;
    }

    // Constant-time check of a presented token against every configured token.
    // The loop does not short-circuit, so timing does not reveal which (or how
    // many) tokens are configured.
    public function isValidToken(string $token): bool
    {
        $presented = hash('sha256', $token);
        $valid = false;
        foreach ($this->tokenHashes as $hash) {
            if (hash_equals($hash, $presented)) {
                $valid = true;
            }
        }
        return $valid;
    }

    // Returns true when the current request carries a valid Bearer token.
    // Always false when no tokens are configured (feature is opt-in).
    public function authenticate(): bool
    {
        if (!$this->isConfigured()) {
            return false;
        }
        $token = self::extractToken();
        if ($token === null) {
            return false;
        }
        return $this->isValidToken($token);
    }
}
