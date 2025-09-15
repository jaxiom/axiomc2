#pragma once

#include <string>
#include <windows.h>

namespace Tasks {
namespace Shell {

    /**
     * Execute a shell command and capture its output
     * @param command Command to execute
     * @param timeoutMs Timeout in milliseconds (default: 10000)
     * @return Command output, or error message if failed
     */
    std::string ExecuteCommand(const std::string& command, DWORD timeoutMs = 10000);

    /**
     * Get the current working directory
     * @return Current directory path, or error message if failed
     */
    std::string GetCurrentDirectory();

    /**
     * Change the current working directory
     * @param path Directory path to change to
     * @return Success message or error message
     */
    std::string ChangeDirectory(const std::string& path);

    /**
     * Get the current username
     * @return Username of current process
     */
    std::string GetCurrentUser();

    /**
     * Get a formatted list of running processes
     * @return Formatted process list with PID, PPID, Arch, and Name
     */
    std::string GetProcessList();

    /**
     * Get detailed process information for a specific PID
     * @param pid Process ID to query
     * @return Process information string
     */
    std::string GetProcessInfo(DWORD pid);

    /**
     * Check if a process exists by PID
     * @param pid Process ID to check
     * @return true if process exists, false otherwise
     */
    bool ProcessExists(DWORD pid);

    /**
     * Get the architecture of a process (x86/x64)
     * @param pid Process ID to check
     * @return "x86", "x64", or "N/A" if unable to determine
     */
    std::string GetProcessArchitecture(DWORD pid);

    /**
     * Kill a process by PID
     * @param pid Process ID to terminate
     * @return true if successfully terminated, false otherwise
     */
    bool KillProcess(DWORD pid);

    /**
     * Get environment variable value
     * @param varName Environment variable name
     * @return Variable value, or empty string if not found
     */
    std::string GetEnvironmentVariable(const std::string& varName);

    /**
     * Set environment variable
     * @param varName Environment variable name
     * @param value Value to set
     * @return true if successful, false otherwise
     */
    bool SetEnvironmentVariable(const std::string& varName, const std::string& value);

    /**
     * Execute a command with elevated privileges (if available)
     * @param command Command to execute
     * @return Command output or error message
     */
    std::string ExecuteElevatedCommand(const std::string& command);

    /**
     * Get system PATH environment variable
     * @return PATH variable contents
     */
    std::string GetSystemPath();

    /**
     * Check if current process is running as administrator
     * @return true if running as admin, false otherwise
     */
    bool IsRunningAsAdmin();

} // namespace Shell
} // namespace Tasks