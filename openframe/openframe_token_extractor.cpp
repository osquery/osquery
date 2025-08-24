#include "openframe_token_extractor.h"
#include <fstream>
#include <stdexcept>

OpenframeTokenExtractor::OpenframeTokenExtractor(std::shared_ptr<OpenframeEncryptionService> encryption_service,
                                               const std::string& token_file_path)
    : encryption_service_(encryption_service), token_file_path_(token_file_path) {
    if (!encryption_service_) {
        throw std::runtime_error("Encryption service cannot be null");
    }
    if (token_file_path_.empty()) {
        throw std::runtime_error("Token file path cannot be empty");
    }
}

std::string OpenframeTokenExtractor::extractToken() {
    // Open the token file
    std::ifstream token_file(token_file_path_);
    if (!token_file.is_open()) {
        throw std::runtime_error("Failed to open token file at: " + token_file_path_);
    }

    // Read the encrypted token
    std::string encrypted_token;
    std::getline(token_file, encrypted_token);
    token_file.close();

    if (encrypted_token.empty()) {
        throw std::runtime_error("Token file is empty");
    }

    try {
        // Decrypt the token using the encryption service
        return encryption_service_->decrypt(encrypted_token);
    } catch (const std::exception& e) {
        throw std::runtime_error("Failed to decrypt token: " + std::string(e.what()));
    }
} 