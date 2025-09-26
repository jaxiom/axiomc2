#pragma once

#include <string>
#include <cstdint>
#include <vector>

namespace Utils {
namespace Crypto {

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
     * RC4 encrypt/decrypt binary data
     * @param data Pointer to data to encrypt/decrypt
     * @param dataSize Size of data in bytes
     * @param key Encryption key
     * @param keySize Size of key in bytes
     * @return Vector containing encrypted/decrypted data
     */
    std::vector<uint8_t> Rc4EncryptBinary(const void* data, size_t dataSize, 
                                         const void* key, size_t keySize);

    /**
     * Simple XOR cipher for obfuscation
     * @param input Data to encrypt/decrypt
     * @param key XOR key (repeating)
     * @return XOR encrypted/decrypted data
     */
    std::string XorCipher(const std::string& input, const std::string& key);

    /**
     * Generate a cryptographically secure random key
     * @param keySize Size of key to generate in bytes
     * @return Random key as byte vector
     */
    std::vector<uint8_t> GenerateRandomKey(size_t keySize);

    /**
     * Generate a random key as string
     * @param keySize Size of key to generate in bytes
     * @return Random key as string
     */
    std::string GenerateRandomKeyString(size_t keySize);

    /**
     * Simple hash function (for checksums, not cryptographic security)
     * @param input Data to hash
     * @return 32-bit hash value
     */
    uint32_t SimpleHash(const std::string& input);

    /**
     * Calculate CRC32 checksum
     * @param data Pointer to data
     * @param length Length of data
     * @return CRC32 checksum
     */
    uint32_t Crc32(const void* data, size_t length);

    /**
     * Validate RC4 key strength
     * @param key Key to validate
     * @return true if key meets minimum security requirements
     */
    bool ValidateKeyStrength(const std::string& key);

    /**
     * Securely clear memory (prevents compiler optimization)
     * @param data Pointer to memory to clear
     * @param size Size of memory to clear
     */
    void SecureClearMemory(void* data, size_t size);

    /**
     * Generate a session key from base key and nonce
     * @param baseKey Base encryption key
     * @param nonce Unique nonce/salt
     * @return Derived session key
     */
    std::string DeriveSessionKey(const std::string& baseKey, const std::string& nonce);

    /**
     * Encrypt data with integrity check
     * @param plaintext Data to encrypt
     * @param key Encryption key
     * @return Encrypted data with embedded checksum
     */
    std::string EncryptWithIntegrity(const std::string& plaintext, const std::string& key);

    /**
     * Decrypt data and verify integrity
     * @param ciphertext Encrypted data with embedded checksum
     * @param key Decryption key
     * @param verified Output parameter indicating if integrity check passed
     * @return Decrypted data (empty if integrity check failed)
     */
    std::string DecryptWithIntegrity(const std::string& ciphertext, const std::string& key, bool& verified);

    /**
     * Obfuscate string for storage (not cryptographically secure)
     * @param input String to obfuscate
     * @return Obfuscated string
     */
    std::string ObfuscateString(const std::string& input);

    /**
     * Deobfuscate string
     * @param input Obfuscated string
     * @return Original string
     */
    std::string DeobfuscateString(const std::string& input);

} // namespace Crypto
} // namespace Utils