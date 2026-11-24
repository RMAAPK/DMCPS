#pragma once

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#include <arpa/inet.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <chrono>
#include <climits>
#include <cstddef>
#include <cstdint>
#include <ctime>
#include <deque>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

#include <nlohmann/json.hpp>

namespace dmcps::oauth {
using json = nlohmann::json;

struct OAuthError : std::runtime_error {
    int status;
    std::string code;
    OAuthError(int httpStatus, std::string oauthCode, std::string message)
        : std::runtime_error(std::move(message)), status(httpStatus), code(std::move(oauthCode)) {}
};

inline bool constantTimeEqual(std::string_view a, std::string_view b) {
    if (a.size() != b.size()) return false;
    unsigned char different = 0;
    for (std::size_t i = 0; i < a.size(); ++i)
        different |= static_cast<unsigned char>(a[i]) ^ static_cast<unsigned char>(b[i]);
    return different == 0;
}

inline std::string base64UrlEncode(std::string_view bytes) {
    if (bytes.size() > static_cast<std::size_t>(INT32_MAX)) throw std::runtime_error("OAuth value is too large");
    std::string output(4 * ((bytes.size() + 2) / 3) + 1, '\0');
    const int written = EVP_EncodeBlock(reinterpret_cast<unsigned char*>(output.data()),
        reinterpret_cast<const unsigned char*>(bytes.data()), static_cast<int>(bytes.size()));
    if (written < 0) throw std::runtime_error("Base64 encoding failed");
    output.resize(static_cast<std::size_t>(written));
    std::replace(output.begin(), output.end(), '+', '-');
    std::replace(output.begin(), output.end(), '/', '_');
    while (!output.empty() && output.back() == '=') output.pop_back();
    return output;
}

inline std::string base64UrlDecode(std::string_view encoded) {
    if (encoded.empty()) return {};
    if (encoded.size() > 32768) throw std::runtime_error("OAuth value is too large");
    std::string input(encoded);
    for (char c : input) {
        if (!(std::isalnum(static_cast<unsigned char>(c)) || c == '-' || c == '_'))
            throw std::runtime_error("Invalid base64url value");
    }
    std::replace(input.begin(), input.end(), '-', '+');
    std::replace(input.begin(), input.end(), '_', '/');
    const std::size_t padding = (4 - input.size() % 4) % 4;
    input.append(padding, '=');
    std::string output(3 * (input.size() / 4), '\0');
    const int written = EVP_DecodeBlock(reinterpret_cast<unsigned char*>(output.data()),
        reinterpret_cast<const unsigned char*>(input.data()), static_cast<int>(input.size()));
    if (written < 0 || static_cast<std::size_t>(written) < padding)
        throw std::runtime_error("Base64 decoding failed");
    output.resize(static_cast<std::size_t>(written) - padding);
    return output;
}

inline std::string base64DecodeBasic(std::string_view input) {
    if (input.empty() || input.size() > 8192) throw std::runtime_error("Invalid Basic authentication value");
    std::string encoded(input);
    const auto firstPadding = encoded.find('=');
    if (firstPadding != std::string::npos) {
        if (encoded.size() - firstPadding > 2 ||
            !std::all_of(encoded.begin() + static_cast<std::ptrdiff_t>(firstPadding), encoded.end(), [](char c) { return c == '='; }))
            throw std::runtime_error("Invalid Basic authentication padding");
        encoded.resize(firstPadding);
    }
    std::replace(encoded.begin(), encoded.end(), '+', '-');
    std::replace(encoded.begin(), encoded.end(), '/', '_');
    return base64UrlDecode(encoded);
}

inline std::string hmacSha256(std::string_view key, std::string_view message) {
    std::array<unsigned char, EVP_MAX_MD_SIZE> digest{};
    unsigned int digestSize = 0;
    if (key.size() > static_cast<std::size_t>(INT32_MAX) ||
        !HMAC(EVP_sha256(), key.data(), static_cast<int>(key.size()),
            reinterpret_cast<const unsigned char*>(message.data()), message.size(), digest.data(), &digestSize))
        throw std::runtime_error("HMAC-SHA256 failed");
    return {reinterpret_cast<const char*>(digest.data()), digestSize};
}

inline std::string randomToken(std::size_t bytes = 32) {
    if (bytes == 0 || bytes > 4096) throw std::runtime_error("Invalid random token size");
    std::string value(bytes, '\0');
    if (RAND_bytes(reinterpret_cast<unsigned char*>(value.data()), static_cast<int>(bytes)) != 1)
        throw std::runtime_error("Cryptographic random generation failed");
    return base64UrlEncode(value);
}

inline bool validRedirectUri(const std::string& uri) {
    if (uri.empty() || uri.size() > 2048 || uri.find('#') != std::string::npos || uri.find('\\') != std::string::npos)
        return false;
    for (unsigned char c : uri) if (c <= 0x20 || c == 0x7f) return false;
    const auto schemeEnd = uri.find("://");
    if (schemeEnd == std::string::npos) return false;
    std::string scheme = uri.substr(0, schemeEnd);
    std::transform(scheme.begin(), scheme.end(), scheme.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    if (scheme != "https" && scheme != "http") return false;
    const std::size_t authorityStart = schemeEnd + 3;
    const std::size_t authorityEnd = uri.find_first_of("/?", authorityStart);
    const std::string authority = uri.substr(authorityStart, authorityEnd == std::string::npos ? std::string::npos : authorityEnd - authorityStart);
    if (authority.empty() || authority.find('@') != std::string::npos) return false;
    const auto validPort = [](std::string_view value) {
        if (value.empty() || value.size() > 5) return false;
        unsigned int port = 0;
        for (unsigned char c : value) {
            if (!std::isdigit(c)) return false;
            port = port * 10 + (c - '0');
        }
        return port > 0 && port <= 65535;
    };
    std::string host;
    bool ipv6 = false;
    if (authority.front() == '[') {
        const auto bracket = authority.find(']');
        if (bracket == std::string::npos) return false;
        host = authority.substr(1, bracket - 1);
        ipv6 = true;
        const std::string rest = authority.substr(bracket + 1);
        if (!rest.empty() && (rest.front() != ':' || !validPort(rest.substr(1)))) return false;
    } else {
        const auto colon = authority.find(':');
        if (colon != std::string::npos) {
            if (authority.find(':', colon + 1) != std::string::npos || !validPort(authority.substr(colon + 1))) return false;
            host = authority.substr(0, colon);
        } else {
            host = authority;
        }
    }
    if (host.empty()) return false;
    if (ipv6) {
        std::array<unsigned char, 16> address{};
        if (::inet_pton(AF_INET6, host.c_str(), address.data()) != 1) return false;
        return scheme == "https" || host == "::1";
    }
    if (host.front() == '.' || host.back() == '.' || host.find("..") != std::string::npos ||
        !std::all_of(host.begin(), host.end(), [](unsigned char c) {
            return std::isalnum(c) || c == '.' || c == '-';
        })) return false;
    std::transform(host.begin(), host.end(), host.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    if (scheme == "https") return true;
    return host == "localhost" || host == "127.0.0.1";
}
inline bool validPkceChallenge(std::string_view value) {
    return value.size() == 43 && std::all_of(value.begin(), value.end(), [](unsigned char c) {
        return std::isalnum(c) || c == '-' || c == '_';
    });
}

inline bool validPkceVerifier(std::string_view value) {
    return value.size() >= 43 && value.size() <= 128 && std::all_of(value.begin(), value.end(), [](unsigned char c) {
        return std::isalnum(c) || c == '-' || c == '.' || c == '_' || c == '~';
    });
}

struct OAuthClient {
    std::vector<std::string> redirectUris;
    std::string secret;
    std::string tokenAuthMethod;
    std::string name;
};

struct AuthorizationCode {
    std::string clientId;
    std::string redirectUri;
    std::string state;
    std::string challenge;
    std::chrono::system_clock::time_point expires;
};

class AuthorizationServer {
public:
    explicit AuthorizationServer(std::string apiKey) : apiKey_(std::move(apiKey)) {}

    json authorizationMetadata(const std::string& issuer, const std::string& endpointBase = {}) const {
        const std::string endpoints = endpointBase.empty() ? issuer : endpointBase;
        return {
            {"issuer", issuer},
            {"authorization_endpoint", endpoints + "/authorize"},
            {"token_endpoint", endpoints + "/token"},
            {"registration_endpoint", endpoints + "/register"},
            {"response_types_supported", {"code"}},
            {"grant_types_supported", {"authorization_code"}},
            {"token_endpoint_auth_methods_supported", {"client_secret_post", "client_secret_basic"}},
            {"code_challenge_methods_supported", {"S256"}},
            {"scopes_supported", {"mcp"}}
        };
    }

    json protectedResourceMetadata(const std::string& resource, const std::string& issuer) const {
        return {
            {"resource", resource},
            {"authorization_servers", {issuer}},
            {"scopes_supported", {"mcp"}},
            {"bearer_methods_supported", {"header"}}
        };
    }

    json registerClient(const json& body, const std::string& remoteIp) {
        if (apiKey_.empty()) throw OAuthError(503, "server_error", "MCP bearer authentication is not configured");
        enforceRegistrationLimit(remoteIp);
        if (!body.is_object()) throw OAuthError(400, "invalid_client_metadata", "Expected a JSON object");
        if (!arrayIsExactly(body, "response_types", "code"))
            throw OAuthError(400, "unsupported_response_type", "Only the authorization-code response type is supported");
        if (!arrayIsExactly(body, "grant_types", "authorization_code"))
            throw OAuthError(400, "unsupported_grant_type", "Only the authorization-code grant is supported");

        const std::string authMethod = body.value("token_endpoint_auth_method", std::string("client_secret_post"));
        if (authMethod != "client_secret_post" && authMethod != "client_secret_basic")
            throw OAuthError(400, "invalid_client_metadata", "Use client_secret_post or client_secret_basic");
        if (!body.contains("redirect_uris") || !body["redirect_uris"].is_array() ||
            body["redirect_uris"].empty() || body["redirect_uris"].size() > 20)
            throw OAuthError(400, "invalid_redirect_uri", "One to twenty redirect_uris are required");

        std::vector<std::string> redirects;
        std::size_t totalBytes = 0;
        for (const auto& value : body["redirect_uris"]) {
            if (!value.is_string()) throw OAuthError(400, "invalid_redirect_uri", "Each redirect URI must be a string");
            const auto uri = value.get<std::string>();
            if (!validRedirectUri(uri)) throw OAuthError(400, "invalid_redirect_uri", "Redirect URI must be HTTPS or a localhost HTTP URI");
            totalBytes += uri.size();
            if (totalBytes > 8192) throw OAuthError(400, "invalid_redirect_uri", "Registered redirect URIs exceed the size limit");
            if (std::find(redirects.begin(), redirects.end(), uri) == redirects.end()) redirects.push_back(uri);
        }
        const std::string clientName = body.value("client_name", std::string("MCP client"));
        const std::string safeName = clientName.size() <= 128 ? clientName : clientName.substr(0, 128);
        const auto now = static_cast<std::int64_t>(std::time(nullptr));
        json payload = {
            {"v", 1}, {"redirect_uris", redirects}, {"token_auth_method", authMethod},
            {"client_name", safeName}, {"issued_at", now}, {"nonce", randomToken(12)}
        };
        const std::string encodedPayload = base64UrlEncode(payload.dump());
        const std::string signature = hmacSha256(apiKey_, encodedPayload);
        std::string signedValue = encodedPayload + signature;
        const std::string clientId = "dmcps_" + base64UrlEncode(signedValue);
        const std::string secret = base64UrlEncode(hmacSha256(apiKey_, "client-secret:" + clientId));
        return {
            {"client_id", clientId}, {"client_secret", secret}, {"client_id_issued_at", now},
            {"client_secret_expires_at", 0}, {"redirect_uris", redirects},
            {"client_name", safeName}, {"grant_types", {"authorization_code"}},
            {"response_types", {"code"}}, {"token_endpoint_auth_method", authMethod}
        };
    }

    OAuthClient validateAuthorizationRequest(const std::string& clientId, const std::string& redirectUri,
        const std::string& challenge, const std::string& method) const {
        const auto client = registeredClient(clientId);
        if (!client || std::find(client->redirectUris.begin(), client->redirectUris.end(), redirectUri) == client->redirectUris.end())
            throw OAuthError(400, "invalid_request", "Unknown client or redirect URI");
        if (method != "S256" || !validPkceChallenge(challenge))
            throw OAuthError(400, "invalid_request", "PKCE S256 is required");
        return *client;
    }

    std::string authorize(const std::string& clientId, const std::string& redirectUri,
        const std::string& state, const std::string& challenge, const std::string& method,
        const std::string& suppliedApiKey) {
        if (!constantTimeEqual(suppliedApiKey, apiKey_))
            throw OAuthError(403, "access_denied", "Invalid DMCPS access key");
        (void)validateAuthorizationRequest(clientId, redirectUri, challenge, method);
        if (state.size() > 1024) throw OAuthError(400, "invalid_request", "State parameter is too long");
        const std::string code = randomToken(32);
        const auto now = std::chrono::system_clock::now();
        std::lock_guard<std::mutex> lock(codesMutex_);
        for (auto it = codes_.begin(); it != codes_.end();) {
            if (it->second.expires <= now) it = codes_.erase(it);
            else ++it;
        }
        if (codes_.size() >= 10000) throw OAuthError(503, "temporarily_unavailable", "Too many pending authorization codes");
        codes_[code] = {clientId, redirectUri, state, challenge, now + std::chrono::minutes(5)};
        return code;
    }

    json exchangeToken(const json& form, const std::string& authorizationHeader) {
        if (apiKey_.empty()) throw OAuthError(503, "server_error", "MCP bearer authentication is not configured");
        if (!form.is_object()) throw OAuthError(400, "invalid_request", "Expected form fields");
        const auto field = [&](const char* name) -> std::string {
            return form.contains(name) && form[name].is_string() ? form[name].get<std::string>() : std::string{};
        };
        if (field("grant_type") != "authorization_code")
            throw OAuthError(400, "unsupported_grant_type", "Only authorization_code is supported");
        std::string clientId = field("client_id");
        std::string clientSecret = field("client_secret");
        bool usedBasic = false;
        if (authorizationHeader.size() >= 6 &&
            std::equal(authorizationHeader.begin(), authorizationHeader.begin() + 6, "Basic ",
                [](unsigned char a, unsigned char b) { return std::tolower(a) == std::tolower(b); })) {
            const std::string decoded = base64DecodeBasic(authorizationHeader.substr(6));
            const auto colon = decoded.find(':');
            if (colon == std::string::npos) throw OAuthError(401, "invalid_client", "Malformed client authentication");
            const std::string basicId = decoded.substr(0, colon);
            const std::string basicSecret = decoded.substr(colon + 1);
            if (!clientId.empty() && clientId != basicId) throw OAuthError(401, "invalid_client", "Client ID mismatch");
            clientId = basicId;
            clientSecret = basicSecret;
            usedBasic = true;
        }
        const auto client = registeredClient(clientId);
        if (!client) throw OAuthError(401, "invalid_client", "Invalid OAuth client");
        if ((client->tokenAuthMethod == "client_secret_basic") != usedBasic)
            throw OAuthError(401, "invalid_client", "Client authentication method does not match registration");
        if (!constantTimeEqual(client->secret, clientSecret))
            throw OAuthError(401, "invalid_client", "Invalid client secret");

        const std::string code = field("code");
        const std::string verifier = field("code_verifier");
        const std::string redirectUri = field("redirect_uri");
        if (code.empty() || !validPkceVerifier(verifier))
            throw OAuthError(400, "invalid_grant", "Invalid authorization code or PKCE verifier");
        const std::string computedChallenge = base64UrlEncode(sha256(verifier));
        {
            std::lock_guard<std::mutex> lock(codesMutex_);
            const auto it = codes_.find(code);
            if (it == codes_.end()) throw OAuthError(400, "invalid_grant", "Authorization code is invalid or already used");
            const auto entry = it->second;
            if (entry.expires <= std::chrono::system_clock::now()) {
                codes_.erase(it);
                throw OAuthError(400, "invalid_grant", "Authorization code expired");
            }
            if (entry.clientId != clientId || entry.redirectUri != redirectUri ||
                !constantTimeEqual(entry.challenge, computedChallenge))
                throw OAuthError(400, "invalid_grant", "Authorization code, redirect URI, or PKCE verifier does not match");
            codes_.erase(it);
        }
        return issueAccessToken();
    }

    bool authenticateBearer(const std::string& token) const {
        if (apiKey_.empty()) return false;
        if (constantTimeEqual(token, apiKey_)) return true; // Keep configured legacy MCP keys working.
        if (token.rfind("dmcps1.", 0) != 0) return false;
        const auto separator = token.find('.', 7);
        if (separator == std::string::npos || token.find('.', separator + 1) != std::string::npos) return false;
        const std::string encodedPayload = token.substr(7, separator - 7);
        const std::string encodedSignature = token.substr(separator + 1);
        try {
            const std::string suppliedSignature = base64UrlDecode(encodedSignature);
            const std::string expectedSignature = hmacSha256(apiKey_, encodedPayload);
            if (!constantTimeEqual(suppliedSignature, expectedSignature)) return false;
            const auto payload = json::parse(base64UrlDecode(encodedPayload));
            if (!payload.is_object() || payload.value("v", 0) != 1 || payload.value("aud", std::string{}) != "dmcps" ||
                payload.value("scope", std::string{}) != "mcp" || !payload.contains("sub") || !payload["sub"].is_string() ||
                !payload.contains("iat") || !payload["iat"].is_number_integer() ||
                !payload.contains("exp") || !payload["exp"].is_number_integer()) return false;
            const auto now = static_cast<std::int64_t>(std::time(nullptr));
            const auto issuedAt = payload["iat"].get<std::int64_t>();
            const auto expiresAt = payload["exp"].get<std::int64_t>();
            return issuedAt <= now + 60 && expiresAt > now && expiresAt <= issuedAt + 3600;
        } catch (...) {
            return false;
        }
    }

private:
    std::string apiKey_;
    mutable std::mutex codesMutex_;
    std::unordered_map<std::string, AuthorizationCode> codes_;
    mutable std::mutex registrationsMutex_;
    std::unordered_map<std::string, std::deque<std::chrono::system_clock::time_point>> registrationEvents_;

    static bool arrayIsExactly(const json& body, const char* name, const std::string& expected) {
        if (!body.contains(name)) return true;
        const auto& value = body[name];
        return value.is_array() && value.size() == 1 && value[0].is_string() && value[0].get<std::string>() == expected;
    }

    static std::string sha256(std::string_view value) {
        std::array<unsigned char, SHA256_DIGEST_LENGTH> digest{};
        if (!SHA256(reinterpret_cast<const unsigned char*>(value.data()), value.size(), digest.data()))
            throw std::runtime_error("SHA-256 failed");
        return {reinterpret_cast<const char*>(digest.data()), digest.size()};
    }

    std::optional<OAuthClient> registeredClient(const std::string& clientId) const {
        constexpr std::string_view prefix = "dmcps_";
        if (apiKey_.empty() || clientId.rfind(prefix, 0) != 0 || clientId.size() > 16384) return std::nullopt;
        try {
            const std::string packed = base64UrlDecode(std::string_view(clientId).substr(prefix.size()));
            if (packed.size() <= SHA256_DIGEST_LENGTH) return std::nullopt;
            const std::string payloadBytes = packed.substr(0, packed.size() - SHA256_DIGEST_LENGTH);
            const std::string signature = packed.substr(payloadBytes.size());
            const std::string expected = hmacSha256(apiKey_, base64UrlEncode(payloadBytes));
            if (!constantTimeEqual(signature, expected)) return std::nullopt;
            const auto payload = json::parse(payloadBytes);
            if (!payload.is_object() || payload.value("v", 0) != 1 ||
                !payload.contains("redirect_uris") || !payload["redirect_uris"].is_array() ||
                payload["redirect_uris"].empty() || payload["redirect_uris"].size() > 20) return std::nullopt;
            const std::string method = payload.value("token_auth_method", std::string{});
            if (method != "client_secret_basic" && method != "client_secret_post") return std::nullopt;
            OAuthClient client;
            client.tokenAuthMethod = method;
            client.name = payload.value("client_name", std::string("MCP client"));
            for (const auto& uri : payload["redirect_uris"]) {
                if (!uri.is_string() || !validRedirectUri(uri.get<std::string>())) return std::nullopt;
                client.redirectUris.push_back(uri.get<std::string>());
            }
            client.secret = base64UrlEncode(hmacSha256(apiKey_, "client-secret:" + clientId));
            return client;
        } catch (...) {
            return std::nullopt;
        }
    }

    void enforceRegistrationLimit(const std::string& remoteIp) {
        const std::string key = remoteIp.empty() ? "unknown" : remoteIp;
        const auto now = std::chrono::system_clock::now();
        std::lock_guard<std::mutex> lock(registrationsMutex_);
        if (registrationEvents_.size() >= 4096) {
            for (auto it = registrationEvents_.begin(); it != registrationEvents_.end();) {
                if (it->second.empty() || now - it->second.back() >= std::chrono::hours(1)) it = registrationEvents_.erase(it);
                else ++it;
            }
        }
        if (registrationEvents_.find(key) == registrationEvents_.end() && registrationEvents_.size() >= 4096)
            throw OAuthError(429, "rate_limited", "Too many client registration sources");
        auto& events = registrationEvents_[key];
        while (!events.empty() && now - events.front() >= std::chrono::hours(1)) events.pop_front();
        if (events.size() >= 20) throw OAuthError(429, "rate_limited", "Too many client registrations from this address");
        events.push_back(now);
    }

    json issueAccessToken() const {
        const auto now = static_cast<std::int64_t>(std::time(nullptr));
        json payload = {{"v", 1}, {"sub", "oauth-client"}, {"aud", "dmcps"},
            {"scope", "mcp"}, {"iat", now}, {"exp", now + 3600}};
        const std::string encoded = base64UrlEncode(payload.dump());
        const std::string signature = base64UrlEncode(hmacSha256(apiKey_, encoded));
        return {
            {"access_token", "dmcps1." + encoded + "." + signature},
            {"token_type", "bearer"}, {"expires_in", 3600}, {"scope", "mcp"}
        };
    }
};

} // namespace dmcps::oauth
