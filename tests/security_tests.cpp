#include "dmcps/security.hpp"

#include <filesystem>
#include <iostream>
#include <stdexcept>
#include <string>

namespace {
void require(bool condition, const std::string& message) {
    if (!condition) throw std::runtime_error(message);
}
}

int main() {
    namespace fs = std::filesystem;
    using dmcps::DirectorySetting;
    using dmcps::findDirectorySetting;
    using dmcps::pathIsWithin;

    try {
        require(pathIsWithin("/workspace/project", "/workspace/project"), "exact match should be allowed");
        require(pathIsWithin("/workspace/project", "/workspace/project/sub/file.txt"), "nested path should be allowed");
        require(!pathIsWithin("/workspace/project", "/workspace/project-evil/file.txt"), "prefix sibling must be denied");
        require(!pathIsWithin("/workspace/project", "/etc/passwd"), "outside path must be denied");
        require(!pathIsWithin("/workspace/project", "/workspace/project/../secret"), "traversal must be denied");

        const std::vector<DirectorySetting> settings{{"/workspace/project", true, false}};
        require(findDirectorySetting(settings, "/workspace/project/file.txt").has_value(), "approved nested path not found");
        require(!findDirectorySetting(settings, "/workspace/outside.txt").has_value(), "unapproved path was granted");

        const fs::path temp = fs::temp_directory_path() / "dmcps-security-test";
        fs::create_directories(temp / "allowed");
        fs::create_directories(temp / "allowed-suffix");
        require(pathIsWithin(temp / "allowed", temp / "allowed" / "new-file.txt"), "temporary nested path should be allowed");
        require(!pathIsWithin(temp / "allowed", temp / "allowed-suffix" / "file.txt"), "temporary prefix sibling must be denied");
        fs::remove_all(temp);
    } catch (const std::exception& e) {
        std::cerr << "security path test failed: " << e.what() << '\n';
        return 1;
    }
    std::cout << "security path tests passed\n";
    return 0;
}
