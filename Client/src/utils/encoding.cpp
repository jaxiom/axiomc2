#include "encoding.h"
#include "../config/config.h"

#include <windows.h>
#include <vector>
#include <algorithm>
#include <sstream>
#include <iomanip>
#include <random>

namespace Utils {
namespace Encoding {

    // Base64 character set
    static const std::string base64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    static const std::string base64_url_safe_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

    std::string base64_encode(const std::string& input) {
        if (input.empty()) {
            return "";
        }

        std::string out;
        int val = 0, valb = -6;
        
        for (unsigned char c : input) {
            val = (val << 8) + c;
            valb += 8;
            while (valb >= 0) {
                out.push_back(base64_chars[(val >> valb) & 0x3F]);
                valb -= 6;
            }
        }
        
        if (valb > -6) {
            out.push_back(base64_chars[((val << 8) >> (valb + 8)) & 0x3F]);
        }
        
        while (out.size() % 4) {
            out.push_back('=');
        }
        
        return out;
    }

    std::string base64_decode(const std::string& input) {
        if (input.empty()) {
            return "";
        }

        std::string inputCopy = input;
        
        // Convert URL-safe characters to standard Base64 ones (from original code)
        for (auto& c : inputCopy) {
            if (c == '-') c = '+';
            else if (c == '_') c = '/';
        }
        
        // Filter valid Base64 characters
        std::string filtered;
        for (char c : inputCopy) {
            if (isalnum(c) || c == '+' || c == '/' || c == '=') {
                filtered.push_back(c);
            }
        }
        
        if (filtered.empty()) {
            return "";
        }
        
        std::string out;
        std::vector<int> T(256, -1);
        
        // Build decode table
        for (int i = 0; i < 64; i++) {
            T[base64_chars[i]] = i;
        }
        
        int val = 0, valb = -8;
        for (unsigned char c : filtered) {
            if (c == '=') break;
            if (T[c] == -1) continue;
            val = (val << 6) + T[c];
            valb += 6;
            if (valb >= 0) {
                out.push_back(char((val >> valb) & 0xFF));
                valb -= 8;
            }
        }
        
        return out;
    }

    std::string base64_encode_binary(const void* data, size_t length) {
        if (!data || length == 0) {
            return "";
        }
        
        const unsigned char* bytes = static_cast<const unsigned char*>(data);
        std::string input(bytes, bytes + length);
        return base64_encode(input);
    }

    std::vector<uint8_t> base64_decode_binary(const std::string& input) {
        std::string decoded = base64_decode(input);
        std::vector<uint8_t> result;
        result.reserve(decoded.size());
        
        for (char c : decoded) {
            result.push_back(static_cast<uint8_t>(c));
        }
        
        return result;
    }

    std::string base64_encode_url_safe(const std::string& input) {
        std::string encoded = base64_encode(input);
        
        // Replace + with - and / with _
        std::replace(encoded.begin(), encoded.end(), '+', '-');
        std::replace(encoded.begin(), encoded.end(), '/', '_');
        
        // Remove padding for URL safety
        size_t pos = encoded.find('=');
        if (pos != std::string::npos) {
            encoded = encoded.substr(0, pos);
        }
        
        return encoded;
    }

    std::string base64_decode_url_safe(const std::string& input) {
        std::string inputCopy = input;
        
        // Replace URL-safe characters
        std::replace(inputCopy.begin(), inputCopy.end(), '-', '+');
        std::replace(inputCopy.begin(), inputCopy.end(), '_', '/');
        
        // Add padding if needed
        while (inputCopy.size() % 4) {
            inputCopy.push_back('=');
        }
        
        return base64_decode(inputCopy);
    }

    std::string hex_encode(const std::string& input, bool uppercase) {
        std::ostringstream oss;
        oss << std::hex;
        if (uppercase) {
            oss << std::uppercase;
        }
        
        for (unsigned char c : input) {
            oss << std::setw(2) << std::setfill('0') << static_cast<int>(c);
        }
        
        return oss.str();
    }

    std::string hex_decode(const std::string& input) {
        if (input.length() % 2 != 0) {
            PRINTF("[ERROR] Invalid hex string length: %zu\n", input.length());
            return "";
        }
        
        std::string result;
        result.reserve(input.length() / 2);
        
        for (size_t i = 0; i < input.length(); i += 2) {
            std::string byteString = input.substr(i, 2);
            try {
                unsigned int byte = std::stoul(byteString, nullptr, 16);
                result.push_back(static_cast<char>(byte));
            }
            catch (const std::exception& e) {
                PRINTF("[ERROR] Invalid hex character in string: %s\n", byteString.c_str());
                return "";
            }
        }
        
        return result;
    }

    std::string hex_encode_binary(const void* data, size_t length, bool uppercase) {
        if (!data || length == 0) {
            return "";
        }
        
        const unsigned char* bytes = static_cast<const unsigned char*>(data);
        std::string input(bytes, bytes + length);
        return hex_encode(input, uppercase);
    }

    std::vector<uint8_t> hex_decode_binary(const std::string& input) {
        std::string decoded = hex_decode(input);
        std::vector<uint8_t> result;
        result.reserve(decoded.size());
        
        for (char c : decoded) {
            result.push_back(static_cast<uint8_t>(c));
        }
        
        return result;
    }

    std::string xor_encode(const std::string& input, const std::string& key) {
        if (input.empty() || key.empty()) {
            return input;
        }
        
        std::string result;
        result.reserve(input.size());
        
        for (size_t i = 0; i < input.size(); ++i) {
            result.push_back(input[i] ^ key[i % key.size()]);
        }
        
        return result;
    }

    std::string url_encode(const std::string& input) {
        std::ostringstream oss;
        oss << std::hex << std::uppercase;
        
        for (unsigned char c : input) {
            if (isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
                oss << c;
            } else {
                oss << '%' << std::setw(2) << std::setfill('0') << static_cast<int>(c);
            }
        }
        
        return oss.str();
    }

    std::string url_decode(const std::string& input) {
        std::string result;
        result.reserve(input.size());
        
        for (size_t i = 0; i < input.size(); ++i) {
            if (input[i] == '%' && i + 2 < input.size()) {
                std::string hex = input.substr(i + 1, 2);
                try {
                    unsigned int byte = std::stoul(hex, nullptr, 16);
                    result.push_back(static_cast<char>(byte));
                    i += 2; // Skip the hex digits
                }
                catch (const std::exception& e) {
                    result.push_back(input[i]); // Keep original character if decode fails
                }
            }
            else if (input[i] == '+') {
                result.push_back(' '); // + represents space in URL encoding
            }
            else {
                result.push_back(input[i]);
            }
        }
        
        return result;
    }

    std::wstring string_to_wstring(const std::string& input) {
        if (input.empty()) {
            return L"";
        }
        
        int len = MultiByteToWideChar(CP_UTF8, 0, input.c_str(), -1, NULL, 0);
        if (len <= 0) {
            PRINTF("[ERROR] MultiByteToWideChar failed: %d\n", GetLastError());
            return L"";
        }
        
        std::wstring result(len, L'\0');
        MultiByteToWideChar(CP_UTF8, 0, input.c_str(), -1, &result[0], len);
        
        // Remove null terminator if present
        if (!result.empty() && result.back() == L'\0') {
            result.pop_back();
        }
        
        return result;
    }

    std::string wstring_to_string(const std::wstring& input) {
        if (input.empty()) {
            return "";
        }
        
        int len = WideCharToMultiByte(CP_UTF8, 0, input.c_str(), -1, NULL, 0, NULL, NULL);
        if (len <= 0) {
            PRINTF("[ERROR] WideCharToMultiByte failed: %d\n", GetLastError());
            return "";
        }
        
        std::string result(len, '\0');
        WideCharToMultiByte(CP_UTF8, 0, input.c_str(), -1, &result[0], len, NULL, NULL);
        
        // Remove null terminator if present
        if (!result.empty() && result.back() == '\0') {
            result.pop_back();
        }
        
        return result;
    }

    bool is_valid_base64(const std::string& input) {
        if (input.empty()) {
            return true; // Empty string is valid Base64
        }
        
        // Check length (must be multiple of 4 with padding)
        if (input.length() % 4 != 0) {
            return false;
        }
        
        // Check characters
        for (size_t i = 0; i < input.length(); ++i) {
            char c = input[i];
            
            // Check for valid Base64 characters
            if (!isalnum(c) && c != '+' && c != '/' && c != '=' && c != '-' && c != '_') {
                return false;
            }
            
            // Padding can only be at the end
            if (c == '=' && i < input.length() - 2) {
                return false;
            }
        }
        
        return true;
    }

    bool is_valid_hex(const std::string& input) {
        if (input.empty()) {
            return true; // Empty string is valid hex
        }
        
        // Check length (must be even)
        if (input.length() % 2 != 0) {
            return false;
        }
        
        // Check characters
        for (char c : input) {
            if (!std::isxdigit(c)) {
                return false;
            }
        }
        
        return true;
    }

    std::string generate_random_base64(size_t length) {
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(0, 255);
        
        std::string randomData;
        randomData.reserve(length);
        
        for (size_t i = 0; i < length; ++i) {
            randomData.push_back(static_cast<char>(dis(gen)));
        }
        
        return base64_encode(randomData);
    }

    size_t calculate_base64_encoded_size(size_t input_length) {
        return ((input_length + 2) / 3) * 4;
    }

    size_t calculate_base64_decoded_size(size_t encoded_length) {
        if (encoded_length % 4 != 0) {
            return 0; // Invalid Base64 length
        }
        
        size_t decoded_size = (encoded_length / 4) * 3;
        
        // Account for padding
        if (encoded_length >= 4) {
            // This is an approximation - actual size depends on padding
            return decoded_size;
        }
        
        return decoded_size;
    }

} // namespace Encoding
} // namespace Utils