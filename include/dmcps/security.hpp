#pragma once

#include <filesystem>
#include <optional>
#include <string>
#include <vector>
#include <system_error>

namespace dmcps {
namespace fs = std::filesystem;

struct DirectorySetting {
    fs::path path;
    bool allowWrite{false};
    bool enableBackups{false};
};

// Resolve existing symlinks and normalize any non-existent suffix. This keeps
// lexical tricks such as ../ and symlinks from escaping an approved directory.
inline fs::path canonicalPath(const fs::path& input) {
    std::error_code ec;
    fs::path absolute = input.is_absolute() ? input : fs::absolute(input, ec);
    if (ec) throw fs::filesystem_error("Could not make path absolute", input, ec);
    fs::path resolved = fs::weakly_canonical(absolute, ec);
    if (ec) throw fs::filesystem_error("Could not resolve path", input, ec);
    return resolved.lexically_normal();
}

// Compare path components, not string prefixes (/work/a must not match /work/ab).
inline bool pathIsWithin(const fs::path& baseInput, const fs::path& targetInput) {
    const fs::path base = canonicalPath(baseInput);
    const fs::path target = canonicalPath(targetInput);
    auto b = base.begin();
    auto t = target.begin();
    for (; b != base.end(); ++b, ++t) {
        if (t == target.end() || *b != *t) return false;
    }
    return true;
}

inline std::optional<DirectorySetting> findDirectorySetting(
    const std::vector<DirectorySetting>& settings, const fs::path& target) {
    for (const auto& setting : settings) {
        if (pathIsWithin(setting.path, target)) return setting;
    }
    return std::nullopt;
}

} // namespace dmcps

