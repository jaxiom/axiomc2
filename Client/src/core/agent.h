#pragma once

#include "json.hpp"
#include <string>

using json = nlohmann::json;

namespace Core {
namespace Agent {

    /**
     * Initialize and register the agent with the C2 server
     * @return true if registration successful, false otherwise
     */
    bool RegisterWithServer();

    /**
     * Start the main agent execution loop
     * This function runs indefinitely, polling for tasks and executing them
     */
    void RunMainLoop();

    /**
     * Poll the server for available tasks
     * If a task is found, it will be executed and the result sent back
     */
    void PollForTasks();

    /**
     * Send a task response back to the server
     * @param task Original task JSON object
     * @param status Task execution status (4=Success, 5=Failure, etc.)
     * @param output Task execution output/result
     * @return true if response sent successfully
     */
    bool SendTaskResponse(const json& task, int status, const std::string& output);

    /**
     * Get the current agent ID
     * @return Agent ID string, empty if not registered
     */
    std::string GetAgentId();

    /**
     * Set the agent ID (used during registration)
     * @param id Agent ID to set
     */
    void SetAgentId(const std::string& id);

    /**
     * Check if agent is registered with server
     * @return true if agent has valid ID
     */
    bool IsRegistered();

    /**
     * Report debug status to server (anti-debugging telemetry)
     */
    void ReportDebugStatus();

    /**
     * Calculate sleep time with jitter
     * @param sleepTime Base sleep time in seconds
     * @param jitterPercentage Jitter percentage to add
     * @return Adjusted sleep time with jitter
     */
    int CalculateJitterSleep(int sleepTime, int jitterPercentage);

    /**
     * Update global sleep and jitter settings
     * @param sleepTime New sleep time in seconds
     * @param jitterMax Maximum jitter percentage
     * @param jitterMin Minimum jitter percentage
     */
    void UpdateSleepConfig(int sleepTime, int jitterMax, int jitterMin);

    /**
     * Get current sleep configuration
     * @param sleepTime Output: current sleep time
     * @param jitterMax Output: current max jitter
     * @param jitterMin Output: current min jitter
     */
    void GetSleepConfig(int& sleepTime, int& jitterMax, int& jitterMin);

} // namespace Agent
} // namespace Core