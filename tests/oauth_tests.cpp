#include "dmcps/oauth.hpp"

#include <openssl/sha.h>

#include <iostream>
#include <stdexcept>
#include <string>

using json = nlohmann::json;

namespace {
void require(bool condition, const std::string& message) {
    if (!condition) throw std::runtime_error(message);
}

std::string pkceChallenge(const std::string& verifier) {
    std::array<unsigned char, SHA256_DIGEST_LENGTH> digest{};
    SHA256(reinterpret_cast<const unsigned char*>(verifier.data()), verifier.size(), digest.data());
    return dmcps::oauth::base64UrlEncode(
        std::string(reinterpret_cast<const char*>(digest.data()), digest.size()));
}
}

int main() {
    using dmcps::oauth::AuthorizationServer;
    using dmcps::oauth::OAuthError;

    try {
        const std::string apiKey = "test-api-key-that-is-long-enough";
        AuthorizationServer oauth(apiKey);
        const json registration = {
            {"client_name", "OAuth test client"},
            {"redirect_uris", {"http://localhost:4321/callback"}},
            {"grant_types", {"authorization_code"}},
            {"response_types", {"code"}},
            {"token_endpoint_auth_method", "client_secret_post"}
        };
        const json client = oauth.registerClient(registration, "127.0.0.1");
        const std::string clientId = client.at("client_id").get<std::string>();
        const std::string clientSecret = client.at("client_secret").get<std::string>();
        const std::string redirect = "http://localhost:4321/callback";
        const std::string verifier = dmcps::oauth::randomToken(32);
        const std::string challenge = pkceChallenge(verifier);
        oauth.validateAuthorizationRequest(clientId, redirect, challenge, "S256");

        const std::string code = oauth.authorize(clientId, redirect, "state-123", challenge, "S256", apiKey);
        const json form = {
            {"grant_type", "authorization_code"}, {"code", code},
            {"code_verifier", verifier}, {"client_id", clientId},
            {"client_secret", clientSecret}, {"redirect_uri", redirect}
        };
        const json token = oauth.exchangeToken(form, "");
        const std::string accessToken = token.at("access_token").get<std::string>();
        require(token.at("token_type") == "bearer", "OAuth token type should be bearer");
        require(token.at("expires_in") == 3600, "OAuth access token should be one hour");
        require(oauth.authenticateBearer(accessToken), "issued token should authenticate");
        require(oauth.authenticateBearer(apiKey), "legacy API key should continue to authenticate");
        require(!oauth.authenticateBearer(accessToken + "x"), "tampered access token must be rejected");

        bool replayRejected = false;
        try { (void)oauth.exchangeToken(form, ""); }
        catch (const OAuthError& error) { replayRejected = error.code == "invalid_grant"; }
        require(replayRejected, "authorization code must be single-use");

        bool wrongKeyRejected = false;
        try { (void)oauth.authorize(clientId, redirect, "state", challenge, "S256", "wrong-key"); }
        catch (const OAuthError& error) { wrongKeyRejected = error.code == "access_denied"; }
        require(wrongKeyRejected, "authorization must reject an incorrect API key");

        const auto httpsClient = oauth.registerClient(
            {{"redirect_uris", {"https://oauth-client.example/callback"}}}, "127.0.0.1");
        require(httpsClient.contains("client_id"), "registered HTTPS redirect client should be accepted");
        bool insecureRedirectRejected = false;
        try {
            (void)oauth.registerClient({{"redirect_uris", {"http://attacker.invalid/callback"}}}, "127.0.0.1");
        } catch (const OAuthError& error) { insecureRedirectRejected = error.code == "invalid_redirect_uri"; }
        require(insecureRedirectRejected, "non-local HTTP redirect URI must be rejected");
        std::cout << "OAuth PKCE tests passed\n";
    } catch (const std::exception& e) {
        std::cerr << "OAuth test failed: " << e.what() << '\n';
        return 1;
    }
    return 0;
}
