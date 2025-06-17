#pragma once

#include <string>
#include <vector>
#include <memory>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/err.h>
#include <stdexcept>

class OpenframeEncryptionService {
public:
    explicit OpenframeEncryptionService(const std::string& secret);
    ~OpenframeEncryptionService() = default;

    /**
     * Decrypts data using AES-GCM
     * @param data Base64 encoded encrypted data
     * @return Decrypted data as string
     * @throws std::runtime_error if decryption fails
     */
    std::string decrypt(const std::string& data);

    std::vector<unsigned char> base64Decode(const std::string& encoded);

private:
    static constexpr size_t KEY_SIZE = 32; // 256 bits
    static constexpr size_t IV_SIZE = 12;  // 96 bits for GCM
    static constexpr size_t TAG_SIZE = 16; // 128 bits for GCM

    void handleOpenSSLError();

    std::string secret_;
}; 