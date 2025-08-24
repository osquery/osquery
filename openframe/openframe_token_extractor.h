#pragma once

#include <string>
#include <memory>
#include "openframe_encryption_service.h"

class OpenframeTokenExtractor {
public:
    explicit OpenframeTokenExtractor(std::shared_ptr<OpenframeEncryptionService> encryption_service,
                                   const std::string& token_file_path);
    ~OpenframeTokenExtractor() = default;

    // Extract and decrypt the token from the file
    std::string extractToken();

private:
    std::string token_file_path_;
    std::shared_ptr<OpenframeEncryptionService> encryption_service_;
}; 