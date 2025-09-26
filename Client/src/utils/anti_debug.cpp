#include "anti_debug.h"
#include "../core/config.h"

#include <windows.h>
#include <winternl.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <string>
#include <vector>
#include <sstream>
#include <algorithm>

// For MinGW compatibility
#ifndef _MSC_VER
#define PROCESSENTRY32A PROCESSENTRY32W
#define Process32FirstA Process32FirstW
#define Process32NextA Process32NextW
#define MODULEENTRY32A MODULEENTRY32W
#define Module32FirstA Module32FirstW
#define Module32NextA Module32NextW
#endif

namespace Utils {
namespace AntiDebug {

    std::string WideToNarrow(const WCHAR* wstr) {
        if (!wstr) return "";
        int size = WideCharToMultiByte(CP_UTF8, 0, wstr, -1, nullptr, 0, nullptr, nullptr);
        if (size <= 0) return "";
        std::string result(size - 1, 0);
        WideCharToMultiByte(CP_UTF8, 0, wstr, -1, &result[0], size, nullptr, nullptr);
        return result;
    }

    bool IsDebuggerPresent_API() {
        return ::IsDebuggerPresent() != FALSE;
    }

    bool IsDebuggerPresent_PEB() {
        return ::IsDebuggerPresent() != FALSE;
    }

    bool CheckDebugPort() {
        typedef NTSTATUS(NTAPI* pNtQueryInformationProcess)(
            HANDLE ProcessHandle,
            DWORD ProcessInformationClass,
            PVOID ProcessInformation,
            ULONG ProcessInformationLength,
            PULONG ReturnLength
        );

        const int ProcessDebugPort = 7;
        DWORD debugPort = 0;
        NTSTATUS status;

        pNtQueryInformationProcess NtQueryInformationProcess = 
            (pNtQueryInformationProcess)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess");

        if (!NtQueryInformationProcess) {
            return false;
        }

        status = NtQueryInformationProcess(
            GetCurrentProcess(),
            ProcessDebugPort,
            &debugPort,
            sizeof(debugPort),
            NULL
        );

        return (status >= 0) && (debugPort != 0);
    }

    bool CheckDebuggerTimestamp() {
        #ifdef _MSC_VER
            LARGE_INTEGER start, end, freq;
            QueryPerformanceCounter(&start);

            // Execute an instruction that is captured by debuggers
            __try {
                OutputDebugStringA("Anti-Debug Check");
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                // Exception occurred
            }

            QueryPerformanceCounter(&end);
            QueryPerformanceFrequency(&freq);

            // Calculate time in microseconds
            double time = ((double)(end.QuadPart - start.QuadPart) * 1000000.0) / (double)freq.QuadPart;

            // If time exceeds threshold, likely debugged
            return time > 100.0; // 100 microseconds threshold
        #else
            // GCC/MinGW doesn't support SEH - disable this check
            return false;
        #endif
    }

    bool CheckRemoteDebugger() {
        BOOL isRemoteDebuggerPresent = FALSE;
        HANDLE hProcess = GetCurrentProcess();
        
        typedef BOOL(WINAPI* pCheckRemoteDebuggerPresent)(HANDLE, PBOOL);
        pCheckRemoteDebuggerPresent CheckRemoteDebuggerPresent = 
            (pCheckRemoteDebuggerPresent)GetProcAddress(GetModuleHandleA("kernel32.dll"), "CheckRemoteDebuggerPresent");
        
        if (CheckRemoteDebuggerPresent) {
            CheckRemoteDebuggerPresent(hProcess, &isRemoteDebuggerPresent);
        }
        
        return isRemoteDebuggerPresent != FALSE;
    }

    bool CheckDebuggerProcesses() {
        std::vector<std::string> debuggerProcesses = {
            "ollydbg.exe", "ida.exe", "ida64.exe", "x64dbg.exe", "x32dbg.exe",
            "windbg.exe", "immunitydebugger.exe", "cheatengine.exe", "processhacker.exe",
            "procexp.exe", "procmon.exe", "wireshark.exe", "fiddler.exe",
            "regmon.exe", "filemon.exe", "vmware.exe", "vbox.exe"
        };

        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot == INVALID_HANDLE_VALUE) {
            return false;
        }

        PROCESSENTRY32A pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32A);

        if (Process32FirstA(hSnapshot, &pe32)) {
            do {
                std::string processName = WideToNarrow(pe32.szExeFile);
                std::transform(processName.begin(), processName.end(), processName.begin(), ::tolower);

                for (const auto& debugger : debuggerProcesses) {
                    if (processName.find(debugger) != std::string::npos) {
                        CloseHandle(hSnapshot);
                        PRINTF("[DEBUG] Debugger process detected: %s\n", pe32.szExeFile);
                        return true;
                    }
                }
            } while (Process32NextA(hSnapshot, &pe32));
        }

        CloseHandle(hSnapshot);
        return false;
    }

    bool CheckDebuggerWindows() {
        std::vector<std::string> debuggerWindows = {
            "ollydbg", "immunity debugger", "ida", "x64dbg", "x32dbg",
            "windbg", "cheat engine", "process hacker", "process explorer"
        };

        for (const auto& windowName : debuggerWindows) {
            if (FindWindowA(NULL, windowName.c_str()) != NULL) {
                PRINTF("[DEBUG] Debugger window detected: %s\n", windowName.c_str());
                return true;
            }
        }

        return false;
    }

    bool CheckHardwareBreakpoints() {
        CONTEXT context;
        context.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        
        if (GetThreadContext(GetCurrentThread(), &context)) {
            // Check debug registers DR0-DR3 for hardware breakpoints
            if (context.Dr0 != 0 || context.Dr1 != 0 || context.Dr2 != 0 || context.Dr3 != 0) {
                PRINTF("[DEBUG] Hardware breakpoints detected\n");
                return true;
            }
        }
        
        return false;
    }

    bool CheckSoftwareBreakpoints(void* startAddress, size_t size) {
        if (!startAddress || size == 0) {
            return false;
        }

        unsigned char* mem = (unsigned char*)startAddress;
        for (size_t i = 0; i < size; i++) {
            if (mem[i] == 0xCC) { // INT3 breakpoint
                PRINTF("[DEBUG] Software breakpoint detected at offset %zu\n", i);
                return true;
            }
        }

        return false;
    }

    bool IsRunningInVM() {
        // Check for common VM artifacts
        std::vector<std::string> vmArtifacts = {
            "vmware", "vbox", "qemu", "virtual", "xen"
        };

        // Check registry for VM indicators
        HKEY hKey;
        char buffer[256];
        DWORD bufferSize = sizeof(buffer);

        // Check BIOS
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "HARDWARE\\DESCRIPTION\\System", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            if (RegQueryValueExA(hKey, "SystemBiosVersion", NULL, NULL, (LPBYTE)buffer, &bufferSize) == ERROR_SUCCESS) {
                std::string biosVersion(buffer);
                std::transform(biosVersion.begin(), biosVersion.end(), biosVersion.begin(), ::tolower);
                
                for (const auto& artifact : vmArtifacts) {
                    if (biosVersion.find(artifact) != std::string::npos) {
                        RegCloseKey(hKey);
                        PRINTF("[DEBUG] VM artifact detected in BIOS: %s\n", artifact.c_str());
                        return true;
                    }
                }
            }
            RegCloseKey(hKey);
        }

        // Check for VM processes
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32A pe32;
            pe32.dwSize = sizeof(PROCESSENTRY32A);

            if (Process32FirstA(hSnapshot, &pe32)) {
                do {
                    std::string processName = WideToNarrow(pe32.szExeFile);
                    std::transform(processName.begin(), processName.end(), processName.begin(), ::tolower);

                    for (const auto& artifact : vmArtifacts) {
                        if (processName.find(artifact) != std::string::npos) {
                            CloseHandle(hSnapshot);
                            PRINTF("[DEBUG] VM process detected: %s\n", pe32.szExeFile);
                            return true;
                        }
                    }
                } while (Process32NextA(hSnapshot, &pe32));
            }
            CloseHandle(hSnapshot);
        }

        return false;
    }

    bool IsSandboxEnvironment() {
        // Check for common sandbox indicators
        
        // Check if running with limited time (common in sandboxes)
        DWORD tickCount = GetTickCount();
        if (tickCount < 60000) { // Less than 1 minute uptime
            PRINTF("[DEBUG] Low system uptime detected (possible sandbox)\n");
            return true;
        }

        // Check for common sandbox usernames
        std::vector<std::string> sandboxUsers = {
            "sandbox", "analyst", "malware", "virus", "sample"
        };

        char username[256];
        DWORD usernameSize = sizeof(username);
        if (GetUserNameA(username, &usernameSize)) {
            std::string user(username);
            std::transform(user.begin(), user.end(), user.begin(), ::tolower);
            
            for (const auto& sandboxUser : sandboxUsers) {
                if (user.find(sandboxUser) != std::string::npos) {
                    PRINTF("[DEBUG] Sandbox username detected: %s\n", username);
                    return true;
                }
            }
        }

        // Check for limited memory (common in VMs/sandboxes)
        MEMORYSTATUSEX memStatus;
        memStatus.dwLength = sizeof(memStatus);
        if (GlobalMemoryStatusEx(&memStatus)) {
            if (memStatus.ullTotalPhys < (1024ULL * 1024 * 1024 * 2)) { // Less than 2GB RAM
                PRINTF("[DEBUG] Low memory detected (possible sandbox)\n");
                return true;
            }
        }

        return false;
    }

    bool IsBeingDebugged(int threshold) {
        int detections = 0;

        if (IsDebuggerPresent_API()) {
            PRINTF("[DEBUG] API debugger detection triggered\n");
            detections++;
        }

        if (IsDebuggerPresent_PEB()) {
            PRINTF("[DEBUG] PEB debugger detection triggered\n");
            detections++;
        }

        if (CheckDebugPort()) {
            PRINTF("[DEBUG] Debug port detection triggered\n");
            detections++;
        }

        if (CheckDebuggerTimestamp()) {
            PRINTF("[DEBUG] Timing debugger detection triggered\n");
            detections++;
        }

        if (CheckRemoteDebugger()) {
            PRINTF("[DEBUG] Remote debugger detection triggered\n");
            detections++;
        }

        if (CheckDebuggerProcesses()) {
            PRINTF("[DEBUG] Debugger process detection triggered\n");
            detections++;
        }

        if (CheckDebuggerWindows()) {
            PRINTF("[DEBUG] Debugger window detection triggered\n");
            detections++;
        }

        if (CheckHardwareBreakpoints()) {
            PRINTF("[DEBUG] Hardware breakpoint detection triggered\n");
            detections++;
        }

        PRINTF("[DEBUG] Total detection methods triggered: %d/%d\n", detections, threshold);
        return detections >= threshold;
    }

    std::string GetDebuggingStatus() {
        std::ostringstream status;
        
        status << "=== ANTI-DEBUG STATUS ===\n";
        status << "API Check: " << (IsDebuggerPresent_API() ? "DETECTED" : "Clean") << "\n";
        status << "PEB Check: " << (IsDebuggerPresent_PEB() ? "DETECTED" : "Clean") << "\n";
        status << "Debug Port: " << (CheckDebugPort() ? "DETECTED" : "Clean") << "\n";
        status << "Timing Check: " << (CheckDebuggerTimestamp() ? "DETECTED" : "Clean") << "\n";
        status << "Remote Debugger: " << (CheckRemoteDebugger() ? "DETECTED" : "Clean") << "\n";
        status << "Debugger Processes: " << (CheckDebuggerProcesses() ? "DETECTED" : "Clean") << "\n";
        status << "Debugger Windows: " << (CheckDebuggerWindows() ? "DETECTED" : "Clean") << "\n";
        status << "Hardware Breakpoints: " << (CheckHardwareBreakpoints() ? "DETECTED" : "Clean") << "\n";
        status << "Virtual Machine: " << (IsRunningInVM() ? "DETECTED" : "Clean") << "\n";
        status << "Sandbox Environment: " << (IsSandboxEnvironment() ? "DETECTED" : "Clean") << "\n";
        status << "Overall Status: " << (IsBeingDebugged(2) ? "DEBUGGING DETECTED" : "CLEAN") << "\n";
        
        return status.str();
    }

    bool IsAnalysisEnvironment() {
        return IsRunningInVM() || IsSandboxEnvironment() || CheckDebuggerProcesses();
    }

    bool QuickDebugCheck() {
        return IsDebuggerPresent_API() || CheckDebugPort() || CheckRemoteDebugger();
    }

    bool CheckDebuggerByException() {
        #ifdef _MSC_VER
            __try {
                // Generate an exception
                RaiseException(0x40000015, 0, 0, NULL);
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                // If we reach here, no debugger is handling the exception
                return false;
            }
            
            // If we reach here, a debugger might be present
            return true;
        #else
            // GCC/MinGW doesn't support SEH - disable this check
            return false;
        #endif
    }

    bool CheckSuspiciousDLLs() {
        std::vector<std::string> suspiciousDLLs = {
            "dbghelp.dll", "dbgcore.dll", "ntdll.dll"
        };

        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetCurrentProcessId());
        if (hSnapshot == INVALID_HANDLE_VALUE) {
            return false;
        }

        MODULEENTRY32A me32;
        me32.dwSize = sizeof(MODULEENTRY32A);

        if (Module32FirstA(hSnapshot, &me32)) {
            do {
                std::string moduleName = WideToNarrow(me32.szModule);
                std::transform(moduleName.begin(), moduleName.end(), moduleName.begin(), ::tolower);

                for (const auto& suspiciousDLL : suspiciousDLLs) {
                    if (moduleName == suspiciousDLL) {
                        // Check if this DLL was loaded by us or externally
                        HMODULE hMod = GetModuleHandleW(me32.szModule);
                        if (hMod && hMod != me32.hModule) {
                            CloseHandle(hSnapshot);
                            PRINTF("[DEBUG] Suspicious DLL injection detected: %s\n", me32.szModule);
                            return true;
                        }
                    }
                }
            } while (Module32NextA(hSnapshot, &me32));
        }

        CloseHandle(hSnapshot);
        return false;
    }

    bool CheckCodeIntegrity(HMODULE moduleHandle) {
        if (!moduleHandle) {
            moduleHandle = GetModuleHandleA(NULL);
        }

        IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)moduleHandle;
        if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
            return false;
        }

        IMAGE_NT_HEADERS* ntHeaders = (IMAGE_NT_HEADERS*)((BYTE*)moduleHandle + dosHeader->e_lfanew);
        if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
            return false;
        }

        // Check for modifications in the code section
        IMAGE_SECTION_HEADER* sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);
        for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
            if (strcmp((char*)sectionHeader[i].Name, ".text") == 0) {
                // Check for INT3 breakpoints in code section
                BYTE* codeStart = (BYTE*)moduleHandle + sectionHeader[i].VirtualAddress;
                DWORD codeSize = sectionHeader[i].Misc.VirtualSize;
                
                return CheckSoftwareBreakpoints(codeStart, codeSize);
            }
        }

        return false;
    }

} // namespace AntiDebug
} // namespace Utils