#pragma once

#include <string>
#include <memory>
#include "openframe_encryption_service.h"

class OpenframeTokenExtractor {
public:
    explicit OpenframeTokenExtractor(std::shared_ptr<OpenframeEncryptionService> encryption_service);
    ~OpenframeTokenExtractor() = default;

    // Extract and decrypt the token from the file
    std::string extractToken();

private:
    static constexpr const char* kTokenFilePath = "/etc/openframe/token.txt";
    std::shared_ptr<OpenframeEncryptionService> encryption_service_;
}; 