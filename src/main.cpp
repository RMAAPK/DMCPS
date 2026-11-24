#include "dmcps/security.hpp"

#include <httplib.h>
#include <nlohmann/json.hpp>
#include <curl/curl.h>

#include <algorithm>
#include <cctype>
#include <stdexcept>
#include <string_view>
#include <sys/stat.h>
#include <array>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <memory>
#include <mutex>
#include <optional>
#include <poll.h>
#include <random>
#include <sstream>
#include <string>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/prctl.h>
#include <thread>
#include <unordered_map>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>

namespace fs = std::filesystem;
using json = nlohmann::json;
using namespace std::chrono_literals;

namespace {
constexpr std::size_t kMaxHttpBody = 1024 * 1024;
constexpr std::size_t kMaxFileRead = 4 * 1024 * 1024;
constexpr std::size_t kMaxCommandOutput = 64 * 1024;
constexpr int kCommandTimeoutSeconds = 30;

std::string env(const char* name, const std::string& fallback = {}) {
    const char* value = std::getenv(name);
    return value ? std::string(value) : fallback;
}

std::string randomHex(std::size_t bytes = 32) {
    std::random_device rd;
    std::uniform_int_distribution<unsigned int> dist(0, 255);
    std::ostringstream out;
    out << std::hex << std::setfill('0');
    for (std::size_t i = 0; i < bytes; ++i) out << std::setw(2) << dist(rd);
    return out.str();
}

std::string timestamp() {
    const auto now = std::chrono::system_clock::now();
    const auto millis = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count();
    return std::to_string(millis);
}

std::string htmlEscape(const std::string& value) {
    std::string out;
    out.reserve(value.size());
    for (char c : value) {
        switch (c) {
            case '&': out += "&amp;"; break;
            case '<': out += "&lt;"; break;
            case '>': out += "&gt;"; break;
            case '"': out += "&quot;"; break;
            case '\'': out += "&#39;"; break;
            default: out += c; break;
        }
    }
    return out;
}

std::string base64Decode(const std::string& input) {
    static constexpr std::string_view alphabet =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string output;
    unsigned int buffer = 0;
    int bits = 0;
    for (unsigned char c : input) {
        if (c == '=') break;
        const auto pos = alphabet.find(static_cast<char>(c));
        if (pos == std::string_view::npos) return {};
        buffer = (buffer << 6) | static_cast<unsigned int>(pos);
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            output.push_back(static_cast<char>((buffer >> bits) & 0xff));
        }
        if (bits == 0) buffer = 0;
        else buffer &= (1u << bits) - 1u;
    }
    return output;
}

bool constantTimeEqual(const std::string& a, const std::string& b) {
    const std::size_t maxSize = std::max(a.size(), b.size());
    unsigned int difference = static_cast<unsigned int>(a.size() ^ b.size());
    for (std::size_t i = 0; i < maxSize; ++i) {
        const unsigned char ac = i < a.size() ? static_cast<unsigned char>(a[i]) : 0;
        const unsigned char bc = i < b.size() ? static_cast<unsigned char>(b[i]) : 0;
        difference |= static_cast<unsigned int>(ac ^ bc);
    }
    return difference == 0;
}

struct AppConfig {
    std::string apiKey;
    std::vector<dmcps::DirectorySetting> directories;
};

class ConfigStore {
public:
    ConfigStore() {
        path_ = env("CONFIG_PATH", "./config/allowed_dirs.json");
        std::lock_guard<std::mutex> lock(mutex_);
        loadLocked();
    }

    AppConfig snapshot() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return config_;
    }

    void addDirectory(const dmcps::DirectorySetting& setting) {
        std::lock_guard<std::mutex> lock(mutex_);
        const auto canonical = dmcps::canonicalPath(setting.path);
        for (auto& existing : config_.directories) {
            if (dmcps::canonicalPath(existing.path) == canonical) {
                existing.allowWrite = setting.allowWrite;
                existing.enableBackups = setting.enableBackups;
                persistLocked();
                return;
            }
        }
        config_.directories.push_back({canonical, setting.allowWrite, setting.enableBackups});
        persistLocked();
    }

    void removeDirectory(std::size_t index) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (index >= config_.directories.size()) throw std::out_of_range("Directory index is invalid");
        config_.directories.erase(config_.directories.begin() + static_cast<std::ptrdiff_t>(index));
        persistLocked();
    }

private:
    fs::path path_;
    mutable std::mutex mutex_;
    AppConfig config_;

    void loadLocked() {
        const auto apiKeyOverride = env("MCP_API_KEY");
        std::ifstream input(path_);
        if (input) {
            json root;
            try {
                input >> root;
            } catch (const std::exception& e) {
                throw std::runtime_error(std::string("Invalid config JSON: ") + e.what());
            }
            if (root.contains("apiKey") && root["apiKey"].is_string()) config_.apiKey = root["apiKey"].get<std::string>();
            if (root.contains("directorySettings") && root["directorySettings"].is_array()) {
                for (const auto& item : root["directorySettings"]) {
                    if (!item.is_object() || !item.contains("path") || !item["path"].is_string()) continue;
                    config_.directories.push_back({
                        item["path"].get<std::string>(),
                        item.value("allowWrite", false),
                        item.value("enableBackups", false)
                    });
                }
            } else if (root.contains("allowedDirectories") && root["allowedDirectories"].is_array()) {
                // Migrate the previous string[] format. Legacy grants stay grants;
                // writes/backups are explicit so they do not silently widen access.
                for (const auto& item : root["allowedDirectories"]) {
                    if (item.is_string()) config_.directories.push_back({item.get<std::string>(), false, false});
                }
            }
        }

        if (!apiKeyOverride.empty()) config_.apiKey = apiKeyOverride;
        if (config_.apiKey.empty()) config_.apiKey = "mcp_" + randomHex();
        persistLocked();
    }

    void persistLocked() const {
        std::error_code ec;
        if (!path_.parent_path().empty()) fs::create_directories(path_.parent_path(), ec);
        if (ec) throw std::runtime_error("Cannot create config directory: " + ec.message());
        json root;
        root["apiKey"] = config_.apiKey;
        root["directorySettings"] = json::array();
        for (const auto& item : config_.directories) {
            root["directorySettings"].push_back({
                {"path", item.path.string()},
                {"allowWrite", item.allowWrite},
                {"enableBackups", item.enableBackups}
            });
        }
        const fs::path temp = path_.string() + ".tmp";
        {
            std::ofstream output(temp, std::ios::binary | std::ios::trunc);
            if (!output) throw std::runtime_error("Cannot write config file: " + temp.string());
            output << root.dump(2) << '\n';
            output.flush();
            if (!output) throw std::runtime_error("Failed writing config file");
        }
        ::chmod(temp.c_str(), S_IRUSR | S_IWUSR);
        if (::rename(temp.c_str(), path_.c_str()) != 0) {
            const int savedErrno = errno;
            std::remove(temp.c_str());
            throw std::runtime_error("Cannot replace config file: " + std::string(std::strerror(savedErrno)));
        }
        ::chmod(path_.c_str(), S_IRUSR | S_IWUSR);
    }
};

bool checkAdmin(const httplib::Request& req, httplib::Response& res) {
    const std::string auth = req.get_header_value("Authorization");
    if (auth.rfind("Basic ", 0) == 0) {
        const std::string decoded = base64Decode(auth.substr(6));
        const auto colon = decoded.find(':');
        if (colon != std::string::npos) {
            const std::string user = decoded.substr(0, colon);
            const std::string password = decoded.substr(colon + 1);
            if (constantTimeEqual(user, env("ADMIN_USERNAME", "admin")) &&
                constantTimeEqual(password, env("ADMIN_PASSWORD"))) return true;
        }
    }
    res.set_header("WWW-Authenticate", "Basic realm=\"DMCPS Dashboard\", charset=\"UTF-8\"");
    res.status = 401;
    res.set_content("Authentication required", "text/plain; charset=utf-8");
    return false;
}

void addMcpCorsHeaders(const httplib::Request& req, httplib::Response& res) {
    const std::string origin = env("CORS_ORIGIN", "*");
    res.set_header("Access-Control-Allow-Origin", origin);
    res.set_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    res.set_header("Access-Control-Allow-Headers", "Authorization, Content-Type, Mcp-Session-Id, Mcp-Protocol-Version");
    res.set_header("Access-Control-Expose-Headers", "Mcp-Session-Id, Mcp-Protocol-Version");
    res.set_header("Vary", "Origin");
    (void)req;
}

bool checkMcpAuth(const httplib::Request& req, httplib::Response& res, const std::string& expected) {
    addMcpCorsHeaders(req, res);
    if (req.method == "OPTIONS") {
        res.status = 204;
        return true;
    }
    std::string supplied;
    const std::string header = req.get_header_value("Authorization");
    if (header.size() > 7 && std::equal(header.begin(), header.begin() + 7, "Bearer ",
            [](unsigned char a, unsigned char b) { return std::tolower(a) == std::tolower(b); })) {
        supplied = header.substr(7);
    } else if (req.has_param("key")) {
        supplied = req.get_param_value("key");
    }
    if (!constantTimeEqual(supplied, expected)) {
        res.status = 401;
        res.set_content(R"({"error":"Unauthorized"})", "application/json");
        return false;
    }
    return true;
}

std::string encodeQueryValue(const std::string& value) {
    std::ostringstream out;
    for (unsigned char c : value) {
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
            (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' || c == '~') {
            out << static_cast<char>(c);
        } else {
            out << '%' << std::uppercase << std::hex << std::setw(2) << std::setfill('0')
                << static_cast<int>(c) << std::nouppercase << std::dec;
        }
    }
    return out.str();
}

struct SseSession {
    std::mutex mutex;
    std::condition_variable ready;
    std::deque<std::string> messages;
    bool closed{false};

    void push(std::string message) {
        {
            std::lock_guard<std::mutex> lock(mutex);
            if (closed) return;
            messages.push_back(std::move(message));
        }
        ready.notify_one();
    }
};

class ToolDispatcher {
public:
    explicit ToolDispatcher(ConfigStore& config)
        : config_(config), workspace_(dmcps::canonicalPath(env("WORKSPACE_DIR", "./projects"))),
          backupDir_(env("BACKUP_DIR", "./backups")) {
        std::error_code ec;
        fs::create_directories(workspace_, ec);
        if (ec) throw std::runtime_error("Cannot create workspace directory: " + ec.message());
        fs::create_directories(backupDir_, ec);
        if (ec) throw std::runtime_error("Cannot create backup directory: " + ec.message());
    }

    json toolDefinitions() const {
        const auto makeTool = [](const std::string& name, const std::string& description,
                                 const json& properties, const json& required) {
            return json{
                {"name", name},
                {"description", description},
                {"inputSchema", {{"type", "object"}, {"properties", properties}, {"required", required}}}
            };
        };
        json tools = json::array();
        tools.push_back(makeTool("read_file", "Read UTF-8 text from an approved file",
                                 {{"filePath", {{"type", "string"}}}}, {"filePath"}));
        tools.push_back(makeTool("write_file", "Write UTF-8 text to an approved file; write permission must be enabled",
                                 {{"filePath", {{"type", "string"}}}, {"content", {{"type", "string"}}}}, {"filePath", "content"}));
        tools.push_back(makeTool("list_directory", "List entries in an approved directory",
                                 {{"dirPath", {{"type", "string"}}}}, {"dirPath"}));
        tools.push_back(makeTool("run_shell_command", "Run a command in the container from an approved working directory; bounded by time and output limits",
                                 {{"command", {{"type", "string"}}}, {"cwd", {{"type", "string"}}}}, {"command", "cwd"}));
        tools.push_back(makeTool("ph_graphql_query", "Run a Product Hunt GraphQL query when PH_ACCESS_TOKEN is configured",
                                 {{"query", {{"type", "string"}}}, {"variables", {{"type", "object"}}}}, {"query"}));
        return tools;
    }

    json callTool(const std::string& name, const json& args) {
        try {
            if (name == "read_file") {
                const fs::path file = approvedPath(requiredString(args, "filePath"), false);
                if (!fs::is_regular_file(file)) throw std::runtime_error("Path is not a regular file");
                const auto size = fs::file_size(file);
                if (size > kMaxFileRead) throw std::runtime_error("File exceeds the 4 MiB read limit");
                std::ifstream input(file, std::ios::binary);
                if (!input) throw std::runtime_error("Could not open file");
                std::ostringstream content;
                content << input.rdbuf();
                return toolText(content.str());
            }
            if (name == "write_file") {
                const fs::path file = approvedPath(requiredString(args, "filePath"), true);
                const std::string content = requiredString(args, "content");
                if (content.size() > kMaxHttpBody) throw std::runtime_error("Content exceeds the 1 MiB write limit");
                auto setting = dmcps::findDirectorySetting(config_.snapshot().directories, file);
                if (!setting || !setting->allowWrite) throw std::runtime_error("Write access is not enabled for this directory");
                const fs::path parent = dmcps::canonicalPath(file.parent_path());
                if (!fs::is_directory(parent)) throw std::runtime_error("Parent directory does not exist");
                if (setting->enableBackups && fs::is_regular_file(file)) createBackup(file);
                const fs::path temp = parent / ("." + file.filename().string() + ".tmp." + randomHex(6));
                {
                    std::ofstream output(temp, std::ios::binary | std::ios::trunc);
                    if (!output) throw std::runtime_error("Could not create temporary file");
                    output.write(content.data(), static_cast<std::streamsize>(content.size()));
                    output.flush();
                    if (!output) {
                        std::remove(temp.c_str());
                        throw std::runtime_error("Failed writing file contents");
                    }
                }
                ::chmod(temp.c_str(), S_IRUSR | S_IWUSR);
                if (::rename(temp.c_str(), file.c_str()) != 0) {
                    const int savedErrno = errno;
                    std::remove(temp.c_str());
                    throw std::runtime_error("Could not replace file: " + std::string(std::strerror(savedErrno)));
                }
                return toolText("Wrote successfully to " + file.string());
            }
            if (name == "list_directory") {
                const fs::path dir = approvedPath(requiredString(args, "dirPath"), false);
                if (!fs::is_directory(dir)) throw std::runtime_error("Path is not a directory");
                std::vector<std::string> entries;
                for (const auto& item : fs::directory_iterator(dir)) {
                    entries.push_back(std::string(item.is_directory() ? "[DIR] " : "[FILE] ") + item.path().filename().string());
                }
                std::sort(entries.begin(), entries.end());
                std::ostringstream output;
                for (const auto& entry : entries) output << entry << '\n';
                return toolText(entries.empty() ? "(empty directory)" : output.str());
            }
            if (name == "run_shell_command") {
                const std::string command = requiredString(args, "command");
                const fs::path cwd = approvedPath(requiredString(args, "cwd"), false);
                if (!fs::is_directory(cwd)) throw std::runtime_error("Working directory is not a directory");
                const auto result = runCommand(command, cwd);
                return toolText(result);
            }
            if (name == "ph_graphql_query") {
                return toolText(productHuntQuery(args));
            }
            throw std::runtime_error("Unknown tool: " + name);
        } catch (const std::exception& e) {
            return {{"content", json::array({{{"type", "text"}, {"text", std::string("Error: ") + e.what()}}})}, {"isError", true}};
        }
    }

private:
    ConfigStore& config_;
    fs::path workspace_;
    fs::path backupDir_;

    static json toolText(const std::string& text) {
        return {{"content", json::array({{{"type", "text"}, {"text", text}}})}};
    }

    static std::string requiredString(const json& object, const char* key) {
        if (!object.is_object() || !object.contains(key) || !object[key].is_string())
            throw std::runtime_error(std::string("Missing string argument: ") + key);
        return object[key].get<std::string>();
    }

    fs::path approvedPath(const std::string& input, bool forWrite) const {
        if (input.empty()) throw std::runtime_error("Path must not be empty");
        fs::path requested(input);
        if (!requested.is_absolute()) requested = workspace_ / requested;
        const fs::path resolved = dmcps::canonicalPath(requested);
        const auto setting = dmcps::findDirectorySetting(config_.snapshot().directories, resolved);
        if (!setting) throw std::runtime_error("Access denied: path is outside all approved directories");
        if (forWrite && !setting->allowWrite) throw std::runtime_error("Write access is disabled for this directory");
        return resolved;
    }

    void createBackup(const fs::path& file) {
        std::error_code ec;
        fs::create_directories(backupDir_, ec);
        if (ec) throw std::runtime_error("Could not create backup directory: " + ec.message());
        const fs::path backup = backupDir_ / (file.filename().string() + "." + timestamp() + "." + randomHex(4) + ".bkp");
        fs::copy_file(file, backup, fs::copy_options::none, ec);
        if (ec) throw std::runtime_error("Could not create local backup: " + ec.message());
        ::chmod(backup.c_str(), S_IRUSR | S_IWUSR);
        uploadBackupIfConfigured(backup);
    }

    static void uploadBackupIfConfigured(const fs::path& backup) {
        const std::string base = env("HF_BUCKET_URL");
        const std::string token = env("HF_API_KEY");
        if (base.empty() || token.empty()) return;
        if (base.rfind("https://", 0) != 0) {
            std::cerr << "HF_BUCKET_URL must use HTTPS; skipping remote backup upload\n";
            return;
        }
        CURL* curl = curl_easy_init();
        if (!curl) return;
        char* escaped = curl_easy_escape(curl, backup.filename().string().c_str(), 0);
        if (!escaped) { curl_easy_cleanup(curl); return; }
        std::string url = base;
        while (!url.empty() && url.back() == '/') url.pop_back();
        url += "/" + std::string(escaped);
        curl_free(escaped);
        FILE* file = std::fopen(backup.c_str(), "rb");
        if (!file) { curl_easy_cleanup(curl); return; }
        struct curl_slist* headers = nullptr;
        const std::string auth = "Authorization: Bearer " + token;
        headers = curl_slist_append(headers, auth.c_str());
        headers = curl_slist_append(headers, "Content-Type: application/octet-stream");
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_UPLOAD, 1L);
        curl_easy_setopt(curl, CURLOPT_READDATA, file);
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
        curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 0L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
        const CURLcode status = curl_easy_perform(curl);
        long httpCode = 0;
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &httpCode);
        if (status != CURLE_OK) std::cerr << "Remote backup upload failed: " << curl_easy_strerror(status) << '\n';
        else if (httpCode < 200 || httpCode >= 300) std::cerr << "Remote backup returned HTTP " << httpCode << '\n';
        curl_slist_free_all(headers);
        std::fclose(file);
        curl_easy_cleanup(curl);
    }

    static std::string runCommand(const std::string& command, const fs::path& cwd) {
        int fds[2];
        if (::pipe(fds) != 0) throw std::runtime_error("Could not create command pipe");
        if (::fcntl(fds[0], F_SETFD, FD_CLOEXEC) != 0 || ::fcntl(fds[1], F_SETFD, FD_CLOEXEC) != 0) {
            ::close(fds[0]); ::close(fds[1]);
            throw std::runtime_error("Could not secure command pipe descriptors");
        }
        const pid_t pid = ::fork();
        if (pid < 0) {
            ::close(fds[0]); ::close(fds[1]);
            throw std::runtime_error("Could not start command");
        }
        if (pid == 0) {
            ::setpgid(0, 0);
            ::close(fds[0]);
            ::dup2(fds[1], STDOUT_FILENO);
            ::dup2(fds[1], STDERR_FILENO);
            ::close(fds[1]);
            if (::chdir(cwd.c_str()) != 0) _exit(126);
            char* const childArgs[] = {
                const_cast<char*>("sh"), const_cast<char*>("-c"),
                const_cast<char*>(command.c_str()), nullptr
            };
            char* const childEnv[] = {
                const_cast<char*>("PATH=/usr/local/bin:/usr/bin:/bin"),
                const_cast<char*>("HOME=/tmp"), const_cast<char*>("TMPDIR=/tmp"),
                const_cast<char*>("LANG=C.UTF-8"), nullptr
            };
            ::execve("/bin/sh", childArgs, childEnv);
            _exit(127);
        }
        ::setpgid(pid, pid);
        ::close(fds[1]);
        const int flags = ::fcntl(fds[0], F_GETFL, 0);
        ::fcntl(fds[0], F_SETFL, flags | O_NONBLOCK);
        std::string output;
        output.reserve(4096);
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(kCommandTimeoutSeconds);
        bool timedOut = false;
        bool childDone = false;
        int childStatus = 0;
        bool eof = false;
        std::optional<std::chrono::steady_clock::time_point> pipeGraceDeadline;
        std::array<char, 4096> buffer{};
        while (!eof || !childDone) {
            if (std::chrono::steady_clock::now() >= deadline && !childDone) {
                timedOut = true;
                ::kill(-pid, SIGKILL);
                ::kill(pid, SIGKILL);
            }
            pollfd pfd{fds[0], POLLIN | POLLHUP, 0};
            ::poll(&pfd, 1, 100);
            if (pfd.revents & (POLLIN | POLLHUP)) {
                while (true) {
                    const ssize_t count = ::read(fds[0], buffer.data(), buffer.size());
                    if (count > 0) {
                        if (output.size() < kMaxCommandOutput) {
                            const auto kept = std::min<std::size_t>(static_cast<std::size_t>(count), kMaxCommandOutput - output.size());
                            output.append(buffer.data(), kept);
                        }
                    } else if (count == 0) {
                        eof = true;
                        break;
                    } else if (errno == EAGAIN || errno == EWOULDBLOCK) {
                        break;
                    } else if (errno == EINTR) {
                        continue;
                    } else {
                        eof = true;
                        break;
                    }
                }
            }
            if (!childDone) {
                const pid_t waited = ::waitpid(pid, &childStatus, WNOHANG);
                childDone = waited == pid;
            }
            if (childDone && !eof) {
                // Reap the command group so background subprocesses cannot outlive the request.
                if (::kill(-pid, 0) == 0) ::kill(-pid, SIGKILL);
                if (!pipeGraceDeadline) pipeGraceDeadline = std::chrono::steady_clock::now() + 1s;
                if (std::chrono::steady_clock::now() >= *pipeGraceDeadline) eof = true;
            }
        }
        ::close(fds[0]);
        if (!childDone) ::waitpid(pid, &childStatus, 0);
        if (timedOut) output += "\n[command timed out after 30 seconds]";
        if (output.size() >= kMaxCommandOutput) output += "\n[output truncated at 64 KiB]";
        if (WIFEXITED(childStatus)) output += "\n[exit code " + std::to_string(WEXITSTATUS(childStatus)) + "]";
        else if (WIFSIGNALED(childStatus)) output += "\n[terminated by signal " + std::to_string(WTERMSIG(childStatus)) + "]";
        return output.empty() ? "Command completed with no output" : output;
    }

    static std::size_t curlWrite(char* data, std::size_t size, std::size_t count, void* context) {
        const std::size_t bytes = size * count;
        auto* output = static_cast<std::string*>(context);
        constexpr std::size_t responseLimit = 4 * 1024 * 1024;
        if (bytes > responseLimit - output->size()) return 0;
        output->append(data, bytes);
        return bytes;
    }

    static std::string productHuntQuery(const json& args) {
        const std::string token = env("PH_ACCESS_TOKEN");
        if (token.empty()) throw std::runtime_error("Product Hunt is not configured; set PH_ACCESS_TOKEN");
        const std::string query = requiredString(args, "query");
        json body = {{"query", query}, {"variables", args.value("variables", json::object())}};
        CURL* curl = curl_easy_init();
        if (!curl) throw std::runtime_error("Could not initialize HTTPS client");
        std::string response;
        struct curl_slist* headers = nullptr;
        const std::string auth = "Authorization: Bearer " + token;
        headers = curl_slist_append(headers, auth.c_str());
        headers = curl_slist_append(headers, "Content-Type: application/json");
        headers = curl_slist_append(headers, "Accept: application/json");
        curl_easy_setopt(curl, CURLOPT_URL, "https://api.producthunt.com/v2/api/graphql");
        curl_easy_setopt(curl, CURLOPT_POST, 1L);
        const std::string payload = body.dump();
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, payload.c_str());
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, static_cast<long>(payload.size()));
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curlWrite);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
        curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 0L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
        const CURLcode result = curl_easy_perform(curl);
        long httpCode = 0;
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &httpCode);
        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
        if (result != CURLE_OK) throw std::runtime_error(std::string("Product Hunt request failed: ") + curl_easy_strerror(result));
        if (httpCode < 200 || httpCode >= 300) throw std::runtime_error("Product Hunt returned HTTP " + std::to_string(httpCode) + ": " + response.substr(0, 2048));
        return response;
    }
};

json rpcError(const json& id, int code, const std::string& message) {
    return {{"jsonrpc", "2.0"}, {"id", id}, {"error", {{"code", code}, {"message", message}}}};
}

std::optional<json> processRpc(const json& request, ToolDispatcher& tools) {
    if (!request.is_object() || !request.contains("method") || !request["method"].is_string())
        return rpcError(request.is_object() ? request.value("id", json(nullptr)) : json(nullptr), -32600, "Invalid Request");
    const bool hasId = request.contains("id");
    const json id = hasId ? request["id"] : json(nullptr);
    const std::string method = request["method"].get<std::string>();
    const json params = request.value("params", json::object());
    if (!hasId) {
        // MCP notifications must not receive JSON-RPC responses.
        return std::nullopt;
    }
    if (method == "initialize") {
        const std::string protocol = params.value("protocolVersion", "2024-11-05");
        return json{{"jsonrpc", "2.0"}, {"id", id}, {"result", {
            {"protocolVersion", protocol},
            {"capabilities", {{"tools", {{"listChanged", false}}}}},
            {"serverInfo", {{"name", "dmcps-cpp"}, {"version", "2.0.0"}}}
        }}};
    }
    if (method == "ping") return json{{"jsonrpc", "2.0"}, {"id", id}, {"result", json::object()}};
    if (method == "tools/list") {
        return json{{"jsonrpc", "2.0"}, {"id", id}, {"result", {{"tools", tools.toolDefinitions()}}}};
    }
    if (method == "tools/call") {
        if (!params.contains("name") || !params["name"].is_string()) return rpcError(id, -32602, "Missing tool name");
        const json args = params.value("arguments", json::object());
        const json result = tools.callTool(params["name"].get<std::string>(), args);
        return json{{"jsonrpc", "2.0"}, {"id", id}, {"result", result}};
    }
    if (method.rfind("notifications/", 0) == 0) return std::nullopt;
    return rpcError(id, -32601, "Method not found: " + method);
}

std::string readRequestJson(const httplib::Request& req) {
    if (req.body.size() > kMaxHttpBody) throw std::runtime_error("Request body exceeds the 1 MiB limit");
    return req.body;
}

void setSecurityHeaders(httplib::Response& res) {
    res.set_header("X-Content-Type-Options", "nosniff");
    res.set_header("X-Frame-Options", "DENY");
    res.set_header("Referrer-Policy", "no-referrer");
    res.set_header("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'");
}

std::string dashboardHtml(const AppConfig& config, const std::string& csrf) {
    std::ostringstream html;
    html << "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
         << "<title>DMCPS Admin</title><style>body{font:16px system-ui;background:#0b1020;color:#e5e7eb;margin:2rem auto;max-width:900px;padding:0 1rem}"
         << "section,li{background:#151d32;border:1px solid #334155;border-radius:12px;padding:1rem;margin:1rem 0}input,button{font:inherit;padding:.65rem;border-radius:6px}input[type=text]{width:min(32rem,90%)}button{cursor:pointer;background:#f97316;color:#111827;border:0;font-weight:700}"
         << "code{overflow-wrap:anywhere;color:#86efac}.muted{color:#94a3b8}.row{display:flex;gap:1rem;align-items:center;flex-wrap:wrap}</style></head><body>"
         << "<h1>DMCPS sandbox</h1><p class=\"muted\">Manage which container paths MCP tools may access. Shell commands run as an unprivileged container user.</p>"
         << "<section><h2>Server API key</h2><p><code>" << htmlEscape(config.apiKey) << "</code></p><p class=\"muted\">Keep this key private. Use it as an Authorization: Bearer token.</p></section>"
         << "<section><h2>Allowed directories</h2>";
    if (config.directories.empty()) html << "<p>No directories are approved; file and shell tools are locked out.</p>";
    html << "<ul>";
    for (std::size_t i = 0; i < config.directories.size(); ++i) {
        const auto& item = config.directories[i];
        html << "<li><strong>" << htmlEscape(item.path.string()) << "</strong><p>Write: " << (item.allowWrite ? "yes" : "no")
             << " · Backups: " << (item.enableBackups ? "yes" : "no") << "</p><form method=\"post\" action=\"/remove\">"
             << "<input type=\"hidden\" name=\"csrf\" value=\"" << htmlEscape(csrf) << "\"><input type=\"hidden\" name=\"index\" value=\"" << i
             << "\"><button type=\"submit\">Revoke access</button></form></li>";
    }
    html << "</ul><h3>Add or update a directory</h3><form method=\"post\" action=\"/add\">"
         << "<input type=\"hidden\" name=\"csrf\" value=\"" << htmlEscape(csrf) << "\">"
         << "<p><input type=\"text\" name=\"directory\" placeholder=\"/workspace/project\" required></p>"
         << "<p><label><input type=\"checkbox\" name=\"allowWrite\" checked> Allow writes</label> "
         << "<label><input type=\"checkbox\" name=\"enableBackups\"> Back up existing files before writes</label></p>"
         << "<button type=\"submit\">Save directory</button></form></section>"
         << "<section><h2>MCP client</h2><p>Endpoint: <code>/sse</code> (SSE) or <code>/mcp</code> (HTTP JSON-RPC); authenticate with the Bearer key above.</p>"
         << "<p class=\"muted\">Product Hunt queries require PH_ACCESS_TOKEN. Remote file backups are optional via HF_BUCKET_URL and HF_API_KEY.</p></section>"
         << "</body></html>";
    return html.str();
}

void sendJson(httplib::Response& res, const json& body, int status = 200) {
    res.status = status;
    res.set_content(body.dump(), "application/json; charset=utf-8");
}

void serveHttp(ConfigStore& config, ToolDispatcher& tools, int port) {
    httplib::Server server;
    server.set_payload_max_length(kMaxHttpBody);
    server.set_read_timeout(30, 0);
    server.set_write_timeout(30, 0);
    server.set_keep_alive_timeout(5);
    server.new_task_queue = [] { return new httplib::ThreadPool(24, 256); };
    const std::string csrfToken = randomHex(24);
    std::mutex sessionsMutex;
    std::unordered_map<std::string, std::shared_ptr<SseSession>> sessions;

    server.Get("/healthz", [](const httplib::Request&, httplib::Response& res) {
        sendJson(res, {{"status", "ok"}, {"service", "dmcps-cpp"}});
    });

    server.Get("/", [&](const httplib::Request& req, httplib::Response& res) {
        setSecurityHeaders(res);
        if (!checkAdmin(req, res)) return;
        res.set_content(dashboardHtml(config.snapshot(), csrfToken), "text/html; charset=utf-8");
    });

    server.Post("/add", [&](const httplib::Request& req, httplib::Response& res) {
        setSecurityHeaders(res);
        if (!checkAdmin(req, res)) return;
        if (!req.has_param("csrf") || !constantTimeEqual(req.get_param_value("csrf"), csrfToken)) {
            res.status = 403; res.set_content("Invalid CSRF token", "text/plain; charset=utf-8"); return;
        }
        try {
            if (!req.has_param("directory")) throw std::runtime_error("Directory is required");
            const fs::path path = dmcps::canonicalPath(req.get_param_value("directory"));
            if (!fs::is_directory(path)) throw std::runtime_error("Approved path must already exist and be a directory");
            const auto allowWrite = req.has_param("allowWrite");
            const auto backups = req.has_param("enableBackups");
            config.addDirectory({path, allowWrite, backups});
            res.status = 303; res.set_header("Location", "/");
        } catch (const std::exception& e) {
            res.status = 400; res.set_content(htmlEscape(e.what()), "text/plain; charset=utf-8");
        }
    });

    server.Post("/remove", [&](const httplib::Request& req, httplib::Response& res) {
        setSecurityHeaders(res);
        if (!checkAdmin(req, res)) return;
        if (!req.has_param("csrf") || !constantTimeEqual(req.get_param_value("csrf"), csrfToken)) {
            res.status = 403; res.set_content("Invalid CSRF token", "text/plain; charset=utf-8"); return;
        }
        try {
            if (!req.has_param("index")) throw std::runtime_error("Directory index is required");
            const auto index = std::stoull(req.get_param_value("index"));
            config.removeDirectory(index);
            res.status = 303; res.set_header("Location", "/");
        } catch (const std::exception& e) {
            res.status = 400; res.set_content(htmlEscape(e.what()), "text/plain; charset=utf-8");
        }
    });

    auto sseEndpoint = [&](const httplib::Request& req, httplib::Response& res) {
        if (!checkMcpAuth(req, res, config.snapshot().apiKey)) return;
        const std::string id = randomHex(16);
        auto session = std::make_shared<SseSession>();
        {
            std::lock_guard<std::mutex> lock(sessionsMutex);
            if (sessions.size() >= 256) {
                res.status = 429;
                res.set_content("Too many active MCP sessions", "text/plain; charset=utf-8");
                return;
            }
            sessions[id] = session;
        }
        std::string endpoint = "/message?sessionId=" + id;
        if (req.has_param("key")) endpoint += "&key=" + encodeQueryValue(req.get_param_value("key"));
        res.set_header("Cache-Control", "no-cache, no-transform");
        res.set_header("X-Accel-Buffering", "no");
        res.set_header("Connection", "keep-alive");
        res.set_chunked_content_provider("text/event-stream; charset=utf-8",
            [session, endpoint, id, &req, &sessionsMutex, &sessions](std::size_t, httplib::DataSink& sink) mutable {
                const auto closeSession = [&] {
                    {
                        std::lock_guard<std::mutex> lock(session->mutex);
                        session->closed = true;
                    }
                    session->ready.notify_all();
                    std::lock_guard<std::mutex> lock(sessionsMutex);
                    sessions.erase(id);
                };
                if (req.is_connection_closed()) {
                    closeSession();
                    sink.done();
                    return false;
                }
                if (!endpoint.empty()) {
                    const std::string initial = "event: endpoint\ndata: " + endpoint + "\n\n";
                    endpoint.clear();
                    if (!sink.write(initial.data(), initial.size())) { closeSession(); return false; }
                    return true;
                }
                std::string message;
                {
                    std::unique_lock<std::mutex> lock(session->mutex);
                    session->ready.wait_for(lock, 10s, [&] { return session->closed || !session->messages.empty(); });
                    if (session->closed) { sink.done(); return false; }
                    if (!session->messages.empty()) {
                        message = std::move(session->messages.front());
                        session->messages.pop_front();
                    }
                }
                if (message.empty()) message = ": keep-alive\n\n";
                if (!sink.write(message.data(), message.size())) { closeSession(); return false; }
                return true;
            });
    };
    server.Get("/sse", sseEndpoint);
    server.Get("/mcp", sseEndpoint);

    auto sessionMessage = [&](const httplib::Request& req, httplib::Response& res) {
        if (!checkMcpAuth(req, res, config.snapshot().apiKey)) return;
        if (!req.has_param("sessionId")) { res.status = 400; res.set_content("Missing sessionId", "text/plain"); return; }
        std::shared_ptr<SseSession> session;
        {
            std::lock_guard<std::mutex> lock(sessionsMutex);
            const auto it = sessions.find(req.get_param_value("sessionId"));
            if (it != sessions.end()) session = it->second;
        }
        if (!session) { res.status = 404; res.set_content("Session not found", "text/plain"); return; }
        try {
            const json request = json::parse(readRequestJson(req));
            const auto response = processRpc(request, tools);
            if (response) session->push("event: message\ndata: " + response->dump() + "\n\n");
            res.status = 202;
            res.set_content("", "text/plain");
        } catch (const std::exception& e) {
            sendJson(res, {{"error", e.what()}}, 400);
        }
    };
    server.Post("/message", sessionMessage);
    server.Post("/mcp/message", sessionMessage);

    auto directMessage = [&](const httplib::Request& req, httplib::Response& res) {
        if (!checkMcpAuth(req, res, config.snapshot().apiKey)) return;
        try {
            const json request = json::parse(readRequestJson(req));
            const auto response = processRpc(request, tools);
            if (!response) { res.status = 202; res.set_content("", "text/plain"); return; }
            if (response->contains("result") && (*response)["result"].is_object() &&
                (*response)["result"].contains("protocolVersion") && (*response)["result"]["protocolVersion"].is_string()) {
                res.set_header("Mcp-Protocol-Version", (*response)["result"]["protocolVersion"].get<std::string>());
            } else if (req.has_header("Mcp-Protocol-Version")) {
                res.set_header("Mcp-Protocol-Version", req.get_header_value("Mcp-Protocol-Version"));
            }
            sendJson(res, *response);
        } catch (const std::exception& e) {
            sendJson(res, rpcError(nullptr, -32700, std::string("Parse error: ") + e.what()), 400);
        }
    };
    server.Post("/mcp", directMessage);
    server.Post("/gemini", directMessage);

    auto options = [](const httplib::Request& req, httplib::Response& res) {
        addMcpCorsHeaders(req, res);
        res.status = 204;
    };
    server.Options("/sse", options);
    server.Options("/message", options);
    server.Options("/mcp", options);
    server.Options("/mcp/message", options);
    server.Options("/gemini", options);

    std::cerr << "DMCPS C++ listening on 0.0.0.0:" << port << '\n';
    if (!server.listen("0.0.0.0", port)) throw std::runtime_error("Could not bind HTTP server port " + std::to_string(port));
}

void runStdio(ToolDispatcher& tools) {
    std::string line;
    while (std::getline(std::cin, line)) {
        if (line.empty()) continue;
        try {
            const auto request = json::parse(line);
            const auto response = processRpc(request, tools);
            if (response) std::cout << response->dump() << std::endl;
        } catch (const std::exception& e) {
            std::cerr << "MCP stdio request error: " << e.what() << '\n';
            std::cout << rpcError(nullptr, -32700, "Parse error").dump() << std::endl;
        }
    }
}

} // namespace

int main(int argc, char** argv) {
    if (argc > 1 && std::string(argv[1]) == "--version") {
        std::cout << "DMCPS C++ 2.0.0\n";
        return 0;
    }
    if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK) {
        std::cerr << "Could not initialize libcurl\n";
        return 1;
    }
    try {
        // Prevent same-UID command children from reading this process' environment
        // (which may contain API credentials) through /proc or ptrace on Linux.
        if (::prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) != 0) {
            throw std::runtime_error("Could not disable process dumpability");
        }
        ConfigStore config;
        ToolDispatcher tools(config);
        if (argc > 1 && std::string(argv[1]) == "--stdio") {
            runStdio(tools);
        } else {
            const std::string adminPassword = env("ADMIN_PASSWORD");
            if (adminPassword.size() < 12) {
                throw std::runtime_error("Set ADMIN_PASSWORD to a value at least 12 characters long before starting the HTTP server");
            }
            int port = 3000;
            const std::string portValue = env("PORT", "3000");
            try { port = std::stoi(portValue); } catch (...) { throw std::runtime_error("PORT must be a valid integer"); }
            if (port < 1 || port > 65535) throw std::runtime_error("PORT must be between 1 and 65535");
            serveHttp(config, tools, port);
        }
    } catch (const std::exception& e) {
        std::cerr << "Fatal: " << e.what() << '\n';
        curl_global_cleanup();
        return 1;
    }
    curl_global_cleanup();
    return 0;
}
