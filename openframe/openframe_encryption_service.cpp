#include "openframe_encryption_service.h"
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/evp.h>
#include <sstream>
#include <iomanip>

OpenframeEncryptionService::OpenframeEncryptionService(const std::string& secret)
    : secret_(secret) {
    if (secret_.empty()) {
        throw std::runtime_error("Secret cannot be empty");
    }
}

std::string OpenframeEncryptionService::decrypt(const std::string& data) {
    if (secret_.empty()) {
        throw std::runtime_error("Encryption service not initialized with secret");
    }

    // Decode base64 data
    auto decoded = base64Decode(data);
    if (decoded.size() < IV_SIZE + TAG_SIZE) {
        throw std::runtime_error("Invalid encrypted data size");
    }

    // Extract IV (first 12 bytes) and tag (last 16 bytes)
    std::vector<unsigned char> iv(decoded.begin(), decoded.begin() + IV_SIZE);
    std::vector<unsigned char> tag(decoded.end() - TAG_SIZE, decoded.end());
    std::vector<unsigned char> ciphertext(decoded.begin() + IV_SIZE, decoded.end() - TAG_SIZE);

    // Create and initialize the context
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        handleOpenSSLError();
    }

    // Initialize the decryption operation
    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, 
                               reinterpret_cast<const unsigned char*>(secret_.c_str()), 
                               iv.data())) {
        EVP_CIPHER_CTX_free(ctx);
        handleOpenSSLError();
    }

    // Set the tag
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_SIZE, tag.data())) {
        EVP_CIPHER_CTX_free(ctx);
        handleOpenSSLError();
    }

    // Decrypt the ciphertext
    std::vector<unsigned char> plaintext(ciphertext.size());
    int len = 0;
    if (1 != EVP_DecryptUpdate(ctx, plaintext.data(), &len, 
                              ciphertext.data(), ciphertext.size())) {
        EVP_CIPHER_CTX_free(ctx);
        handleOpenSSLError();
    }

    // Finalize the decryption
    int finalLen = 0;
    if (1 != EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &finalLen)) {
        EVP_CIPHER_CTX_free(ctx);
        handleOpenSSLError();
    }

    // Clean up
    EVP_CIPHER_CTX_free(ctx);

    // Convert the decrypted data to string
    return std::string(plaintext.begin(), plaintext.begin() + len + finalLen);
}

std::vector<unsigned char> OpenframeEncryptionService::base64Decode(const std::string& encoded) {
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    
    BIO* bmem = BIO_new_mem_buf(encoded.c_str(), encoded.length());
    bmem = BIO_push(b64, bmem);

    std::vector<unsigned char> decoded(encoded.length());
    int decodedLen = BIO_read(bmem, decoded.data(), encoded.length());

    BIO_free_all(bmem);

    if (decodedLen < 0) {
        throw std::runtime_error("Failed to decode base64 data");
    }

    decoded.resize(decodedLen);
    return decoded;
}

void OpenframeEncryptionService::handleOpenSSLError() {
    std::stringstream ss;
    unsigned long err;
    while ((err = ERR_get_error()) != 0) {
        char err_buf[256];
        ERR_error_string_n(err, err_buf, sizeof(err_buf));
        ss << err_buf << "; ";
    }
    throw std::runtime_error("OpenSSL error: " + ss.str());
} 