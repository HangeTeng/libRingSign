#include "libringsign/config_manager.h"
#include <fstream>
#include <stdexcept>

namespace ring_signature_lib {

nlohmann::json ConfigManager::LoadJson(const std::string& path) {
    std::ifstream file(path);
    if (!file.is_open()) {
        throw std::runtime_error("Failed to open config file: " + path);
    }
    nlohmann::json j;
    file >> j;
    return j;
}

void ConfigManager::SaveJson(const std::string& path, const nlohmann::json& j) {
    std::ofstream file(path);
    if (!file.is_open()) {
        throw std::runtime_error("Failed to open config file for writing: " + path);
    }
    file << j.dump(4);
}

} // namespace ring_signature_lib
