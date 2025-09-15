#pragma once

#include <string>
#include <vector>

namespace Utils {
namespace Encoding {

    /**
     * Encode string to Base64
     * @param input Input string to encode
     * @return Base64 encoded string
     */
    std::string base64_encode(const std::string& input);

    /**
     * Decode Base64 string
     * @param input Base64 encoded string to decode
     * @return Decoded string, empty if decoding fails
     */
    std::string base64_decode(const std::string& input);

    /**
     * Encode binary data to Base64
     * @param data Pointer to binary data
     * @param length Length of binary data
     * @return Base64 encoded string
     */
    std::string base64_encode_binary(const void* data, size_t length);

    /**
     * Decode Base64 to binary data
     * @param input Base64 encoded string
     * @return Vector of decoded bytes
     */
    std::vector<uint8_t> base64_decode_binary(const std::string& input);

    /**
     * URL-safe Base64 encode (uses - and _ instead of + and /)
     * @param input Input string to encode
     * @return URL-safe Base64 encoded string
     */
    std::string base64_encode_url_safe(const std::string& input);

    /**
     * URL-safe Base64 decode
     * @param input URL-safe Base64 encoded string
     * @return Decoded string
     */
    std::string base64_decode_url_safe(const std::string& input);

    /**
     * Encode string to hexadecimal
     * @param input Input string to encode
     * @param uppercase Whether to use uppercase hex digits
     * @return Hexadecimal encoded string
     */
    std::string hex_encode(const std::string& input, bool uppercase = false);

    /**
     * Decode hexadecimal string
     * @param input Hexadecimal string to decode
     * @return Decoded string, empty if decoding fails
     */
    std::string hex_decode(const std::string& input);

    /**
     * Encode binary data to hexadecimal
     * @param data Pointer to binary data
     * @param length Length of binary data
     * @param uppercase Whether to use uppercase hex digits
     * @return Hexadecimal encoded string
     */
    std::string hex_encode_binary(const void* data, size_t length, bool uppercase = false);

    /**
     * Decode hexadecimal to binary data
     * @param input Hexadecimal string
     * @return Vector of decoded bytes
     */
    std::vector<uint8_t> hex_decode_binary(const std::string& input);

    /**
     * Simple XOR encoding/decoding
     * @param input Input data to encode/decode
     * @param key XOR key
     * @return XOR encoded/decoded data
     */
    std::string xor_encode(const std::string& input, const std::string& key);

    /**
     * URL encode string (percent encoding)
     * @param input Input string to encode
     * @return URL encoded string
     */
    std::string url_encode(const std::string& input);

    /**
     * URL decode string
     * @param input URL encoded string to decode
     * @return Decoded string
     */
    std::string url_decode(const std::string& input);

    /**
     * Convert string to wide string (UTF-16)
     * @param input Input string (UTF-8)
     * @return Wide string
     */
    std::wstring string_to_wstring(const std::string& input);

    /**
     * Convert wide string to string (UTF-8)
     * @param input Wide string (UTF-16)
     * @return UTF-8 string
     */
    std::string wstring_to_string(const std::wstring& input);

    /**
     * Validate Base64 string format
     * @param input String to validate
     * @return true if valid Base64 format
     */
    bool is_valid_base64(const std::string& input);

    /**
     * Validate hexadecimal string format
     * @param input String to validate
     * @return true if valid hexadecimal format
     */
    bool is_valid_hex(const std::string& input);

    /**
     * Generate random Base64 string
     * @param length Length of random data before encoding
     * @return Random Base64 encoded string
     */
    std::string generate_random_base64(size_t length);

    /**
     * Calculate Base64 encoded size for given input length
     * @param input_length Length of input data
     * @return Encoded size in bytes
     */
    size_t calculate_base64_encoded_size(size_t input_length);

    /**
     * Calculate maximum decoded size for Base64 string
     * @param encoded_length Length of Base64 string
     * @return Maximum decoded size in bytes
     */
    size_t calculate_base64_decoded_size(size_t encoded_length);

} // namespace Encoding
} // namespace Utils