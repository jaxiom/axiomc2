#include "config.h"
#include <windows.h>
#include <mutex>

namespace Config {

    // Global configuration state with thread safety
    static std::mutex g_config_mutex;
    static bool g_initialized = false;

    // Agent configuration
    namespace Agent {
        static std::string g_agent_id;
        
        std::string GetId() {
            std::lock_guard<std::mutex> lock(g_config_mutex);
            return g_agent_id;
        }

        void SetId(const std::string& id) {
            std::lock_guard<std::mutex> lock(g_config_mutex);
            g_agent_id = id;
            PRINTF("[CONFIG] Agent ID set: %s\n", id.c_str());
        }

        bool IsRegistered() {
            std::lock_guard<std::mutex> lock(g_config_mutex);
            return !g_agent_id.empty();
        }

        void ClearId() {
            std::lock_guard<std::mutex> lock(g_config_mutex);
            g_agent_id.clear();
            PRINTF("[CONFIG] Agent ID cleared\n");
        }
    }

    // Sleep and jitter configuration
    namespace Sleep {
        static int g_sleep_time = SLEEP_TIME;
        static int g_jitter_max = DEFAULT_JITTER_MAX;
        static int g_jitter_min = DEFAULT_JITTER_MIN;

        int GetSleepTime() {
            std::lock_guard<std::mutex> lock(g_config_mutex);
            return g_sleep_time;
        }

        void SetSleepTime(int sleepTime) {
            std::lock_guard<std::mutex> lock(g_config_mutex);
            if (sleepTime > 0) {
                g_sleep_time = sleepTime;
                PRINTF("[CONFIG] Sleep time updated: %d seconds\n", sleepTime);
            } else {
                PRINTF("[CONFIG] Invalid sleep time: %d (must be > 0)\n", sleepTime);
            }
        }

        int GetJitterMax() {
            std::lock_guard<std::mutex> lock(g_config_mutex);
            return g_jitter_max;
        }

        void SetJitterMax(int jitterMax) {
            std::lock_guard<std::mutex> lock(g_config_mutex);
            if (jitterMax >= 0 && jitterMax <= 100) {
                g_jitter_max = jitterMax;
                PRINTF("[CONFIG] Max jitter updated: %d%%\n", jitterMax);
            } else {
                PRINTF("[CONFIG] Invalid max jitter: %d%% (must be 0-100)\n", jitterMax);
            }
        }

        int GetJitterMin() {
            std::lock_guard<std::mutex> lock(g_config_mutex);
            return g_jitter_min;
        }

        void SetJitterMin(int jitterMin) {
            std::lock_guard<std::mutex> lock(g_config_mutex);
            if (jitterMin >= 0 && jitterMin <= 100) {
                g_jitter_min = jitterMin;
                PRINTF("[CONFIG] Min jitter updated: %d%%\n", jitterMin);
            } else {
                PRINTF("[CONFIG] Invalid min jitter: %d%% (must be 0-100)\n", jitterMin);
            }
        }

        void UpdateConfig(int sleepTime, int jitterMax, int jitterMin) {
            std::lock_guard<std::mutex> lock(g_config_mutex);
            
            // Validate parameters
            if (sleepTime <= 0) {
                PRINTF("[CONFIG] Invalid sleep time: %d (must be > 0)\n", sleepTime);
                return;
            }
            
            if (jitterMax < 0 || jitterMax > 100) {
                PRINTF("[CONFIG] Invalid max jitter: %d%% (must be 0-100)\n", jitterMax);
                return;
            }
            
            if (jitterMin < 0 || jitterMin > 100) {
                PRINTF("[CONFIG] Invalid min jitter: %d%% (must be 0-100)\n", jitterMin);
                return;
            }
            
            if (jitterMax < jitterMin) {
                PRINTF("[CONFIG] Max jitter (%d%%) < min jitter (%d%%), setting min to 0\n", 
                       jitterMax, jitterMin);
                jitterMin = 0;
            }
            
            g_sleep_time = sleepTime;
            g_jitter_max = jitterMax;
            g_jitter_min = jitterMin;
            
            PRINTF("[CONFIG] Sleep config updated: %ds, jitter %d%%-%d%%\n", 
                   sleepTime, jitterMin, jitterMax);
        }

        void GetConfig(int& sleepTime, int& jitterMax, int& jitterMin) {
            std::lock_guard<std::mutex> lock(g_config_mutex);
            sleepTime = g_sleep_time;
            jitterMax = g_jitter_max;
            jitterMin = g_jitter_min;
        }

        void ResetToDefaults() {
            std::lock_guard<std::mutex> lock(g_config_mutex);
            g_sleep_time = SLEEP_TIME;
            g_jitter_max = DEFAULT_JITTER_MAX;
            g_jitter_min = DEFAULT_JITTER_MIN;
            PRINTF("[CONFIG] Sleep configuration reset to defaults\n");
        }
    }

    // Crypto configuration
    namespace Crypto {
        static std::string g_rc4_key = "DefaultKey123"; // Should be overridden
        
        std::string GetRC4Key() {
            std::lock_guard<std::mutex> lock(g_config_mutex);
            return g_rc4_key;
        }

        void SetRC4Key(const std::string& key) {
            std::lock_guard<std::mutex> lock(g_config_mutex);
            if (!key.empty()) {
                g_rc4_key = key;
                PRINTF("[CONFIG] RC4 key updated (length: %zu)\n", key.length());
            } else {
                PRINTF("[CONFIG] Cannot set empty RC4 key\n");
            }
        }
    }

    // Network configuration
    namespace Network {
        static std::string g_server_ip = SERVER_IP;
        static int g_server_port = SERVER_PORT;
        static std::string g_api_endpoint = API_ENDPOINT;
        static std::string g_user_agent = USERAGENT;
        static bool g_ssl_enabled = C2SSL;
        static int g_max_retries = MAX_RETRIES;
        static int g_retry_sleep = RETRY_SLEEP;

        std::string GetServerIP() {
            std::lock_guard<std::mutex> lock(g_config_mutex);
            return g_server_ip;
        }

        int GetServerPort() {
            std::lock_guard<std::mutex> lock(g_config_mutex);
            return g_server_port;
        }

        std::string GetAPIEndpoint() {
            std::lock_guard<std::mutex> lock(g_config_mutex);
            return g_api_endpoint;
        }

        std::string GetUserAgent() {
            std::lock_guard<std::mutex> lock(g_config_mutex);
            return g_user_agent;
        }

        bool IsSSLEnabled() {
            std::lock_guard<std::mutex> lock(g_config_mutex);
            return g_ssl_enabled;
        }

        int GetMaxRetries() {
            std::lock_guard<std::mutex> lock(g_config_mutex);
            return g_max_retries;
        }

        int GetRetrySleep() {
            std::lock_guard<std::mutex> lock(g_config_mutex);
            return g_retry_sleep;
        }

        void UpdateServerConfig(const std::string& serverIP, int serverPort, bool useSSL) {
            std::lock_guard<std::mutex> lock(g_config_mutex);
            
            if (!serverIP.empty()) {
                g_server_ip = serverIP;
            }
            
            if (serverPort > 0 && serverPort <= 65535) {
                g_server_port = serverPort;
            } else {
                PRINTF("[CONFIG] Invalid server port: %d (must be 1-65535)\n", serverPort);
                return;
            }
            
            g_ssl_enabled = useSSL;
            
            PRINTF("[CONFIG] Server config updated: %s:%d (SSL: %s)\n", 
                   g_server_ip.c_str(), g_server_port, useSSL ? "ON" : "OFF");
        }
    }

    // Main configuration functions
    bool Initialize() {
        std::lock_guard<std::mutex> lock(g_config_mutex);
        
        if (g_initialized) {
            PRINTF("[CONFIG] Already initialized\n");
            return true;
        }

        PRINTF("[CONFIG] Initializing configuration system...\n");
        
        // TODO: Load configuration from external sources if needed
        // - Registry settings
        // - Environment variables  
        // - Configuration files
        // - Command line arguments
        
        // For now, we'll use compile-time defaults
        PRINTF("[CONFIG] Using compile-time configuration defaults\n");
        PRINTF("[CONFIG] Server: %s:%d (SSL: %s)\n", 
               g_server_ip.c_str(), g_server_port, g_ssl_enabled ? "ON" : "OFF");
        PRINTF("[CONFIG] Sleep: %ds, Jitter: %d%%-%d%%\n", 
               Sleep::g_sleep_time, Sleep::g_jitter_min, Sleep::g_jitter_max);
        
        g_initialized = true;
        PRINTF("[CONFIG] Configuration system initialized successfully\n");
        return true;
    }

    void Cleanup() {
        std::lock_guard<std::mutex> lock(g_config_mutex);
        
        if (!g_initialized) {
            return;
        }
        
        PRINTF("[CONFIG] Cleaning up configuration system...\n");
        
        // Clear sensitive data
        Agent::g_agent_id.clear();
        Crypto::g_rc4_key.clear();
        
        g_initialized = false;
        PRINTF("[CONFIG] Configuration system cleaned up\n");
    }

} // namespace Config