#include "system_info.h"
#include "../core/config.h"

#include <windows.h>
#include <winreg.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <lm.h>
#include <sddl.h>
#include <psapi.h>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <cstdint>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "netapi32.lib")
#pragma comment(lib, "psapi.lib")

namespace Utils {
namespace SystemInfo {

    static std::string WideToNarrow(const WCHAR* wstr) {
        if (!wstr) return "";
        int size = WideCharToMultiByte(CP_UTF8, 0, wstr, -1, nullptr, 0, nullptr, nullptr);
        if (size <= 0) return "";
        std::string result(size - 1, 0);
        WideCharToMultiByte(CP_UTF8, 0, wstr, -1, &result[0], size, nullptr, nullptr);
        return result;
    }

    std::string GetUsername() {
        char username[MAX_COMPUTERNAME_LENGTH + 1] = { 0 };
        DWORD nameSize = sizeof(username);
        if (GetUserNameA(username, &nameSize)) {
            return std::string(username);
        }
        return "unknown-user";
    }

    std::string GetHostname() {
        char hostname[MAX_COMPUTERNAME_LENGTH + 1] = { 0 };
        DWORD nameSize = sizeof(hostname);
        if (GetComputerNameA(hostname, &nameSize)) {
            return std::string(hostname);
        }
        return "unknown-host";
    }

    std::string GetMachineGuid() {
        HKEY hKey;
        char guid[256] = { 0 };
        DWORD bufLen = sizeof(guid);
        
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Cryptography", 0, KEY_READ | KEY_WOW64_64KEY, &hKey) == ERROR_SUCCESS) {
            if (RegQueryValueExA(hKey, "MachineGuid", nullptr, nullptr, reinterpret_cast<LPBYTE>(guid), &bufLen) == ERROR_SUCCESS) {
                RegCloseKey(hKey);
                return std::string(guid);
            }
            RegCloseKey(hKey);
        }
        return "unknown-guid";
    }

    std::string GetOSVersion() {
        OSVERSIONINFOA info;
        ZeroMemory(&info, sizeof(info));
        info.dwOSVersionInfoSize = sizeof(info);
        
#pragma warning(push)
#pragma warning(disable:4996)
        if (GetVersionExA(&info)) {
            return std::to_string(info.dwMajorVersion) + "." + std::to_string(info.dwMinorVersion) + " (" + std::to_string(info.dwBuildNumber) + ")";
        }
#pragma warning(pop)
        
        return "unknown-version";
    }

    OSInfo GetDetailedOSInfo() {
        OSInfo osInfo;
        
        // Get basic version info
        osInfo.version = GetOSVersion();
        osInfo.architecture = GetSystemArchitecture();
        osInfo.is64Bit = Is64BitSystem();
        
        // Get Windows version name
        osInfo.productName = GetWindowsVersionName();
        
        // Get build number from registry
        HKEY hKey;
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            char buffer[256] = {0};
            DWORD bufferSize = sizeof(buffer);
            
            if (RegQueryValueExA(hKey, "CurrentBuild", NULL, NULL, (LPBYTE)buffer, &bufferSize) == ERROR_SUCCESS) {
                osInfo.buildNumber = buffer;
            }
            
            bufferSize = sizeof(buffer);
            if (RegQueryValueExA(hKey, "CSDVersion", NULL, NULL, (LPBYTE)buffer, &bufferSize) == ERROR_SUCCESS) {
                osInfo.servicePack = buffer;
            }
            
            RegCloseKey(hKey);
        }
        
        return osInfo;
    }

    int GetIntegrity() {
        BOOL isAdmin = FALSE;
        PSID adminGroup = NULL;
        SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
        
        if (AllocateAndInitializeSid(&NtAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &adminGroup)) {
            if (!CheckTokenMembership(NULL, adminGroup, &isAdmin)) {
                isAdmin = FALSE;
            }
            FreeSid(adminGroup);
        }
        
        return isAdmin ? 4 : 3;  // 4 = High integrity (Admin), 3 = Medium integrity
    }

    std::string GetInternalIP() {
        ULONG outBufLen = 15000;
        PIP_ADAPTER_ADDRESSES pAddresses = (IP_ADAPTER_ADDRESSES*)malloc(outBufLen);
        if (!pAddresses) return "unknown";

        DWORD dwRetVal = GetAdaptersAddresses(AF_INET, 0, NULL, pAddresses, &outBufLen);
        if (dwRetVal == ERROR_BUFFER_OVERFLOW) {
            free(pAddresses);
            pAddresses = (IP_ADAPTER_ADDRESSES*)malloc(outBufLen);
            dwRetVal = GetAdaptersAddresses(AF_INET, 0, NULL, pAddresses, &outBufLen);
        }

        std::string internalIP = "unknown";
        if (dwRetVal == NO_ERROR) {
            for (PIP_ADAPTER_ADDRESSES curr = pAddresses; curr; curr = curr->Next) {
                if (curr->OperStatus == IfOperStatusUp) {
                    for (PIP_ADAPTER_UNICAST_ADDRESS ua = curr->FirstUnicastAddress; ua; ua = ua->Next) {
                        SOCKADDR_IN* sa = reinterpret_cast<SOCKADDR_IN*>(ua->Address.lpSockaddr);
                        char buf[INET_ADDRSTRLEN] = { 0 };
                        inet_ntop(AF_INET, &sa->sin_addr, buf, sizeof(buf));
                        std::string ip(buf);
                        
                        // Skip loopback and prefer private addresses
                        if (ip != "127.0.0.1" && !ip.empty()) {
                            internalIP = ip;
                            break;
                        }
                    }
                    if (internalIP != "unknown") break;
                }
            }
        }
        free(pAddresses);
        return internalIP;
    }

    std::vector<NetworkAdapter> GetNetworkAdapters() {
        std::vector<NetworkAdapter> adapters;
        
        ULONG outBufLen = 15000;
        PIP_ADAPTER_ADDRESSES pAddresses = (IP_ADAPTER_ADDRESSES*)malloc(outBufLen);
        if (!pAddresses) return adapters;

        DWORD dwRetVal = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, NULL, pAddresses, &outBufLen);
        if (dwRetVal == ERROR_BUFFER_OVERFLOW) {
            free(pAddresses);
            pAddresses = (IP_ADAPTER_ADDRESSES*)malloc(outBufLen);
            dwRetVal = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, NULL, pAddresses, &outBufLen);
        }

        if (dwRetVal == NO_ERROR) {
            for (PIP_ADAPTER_ADDRESSES curr = pAddresses; curr; curr = curr->Next) {
                NetworkAdapter adapter;
                adapter.name = curr->AdapterName;
                adapter.description = WideToNarrow(curr->Description);
                adapter.isUp = (curr->OperStatus == IfOperStatusUp);
                
                // Get MAC address
                if (curr->PhysicalAddressLength > 0) {
                    std::ostringstream macStream;
                    for (DWORD i = 0; i < curr->PhysicalAddressLength; i++) {
                        if (i > 0) macStream << ":";
                        macStream << std::hex << std::setw(2) << std::setfill('0') << (int)curr->PhysicalAddress[i];
                    }
                    adapter.macAddress = macStream.str();
                }
                
                // Get IP addresses
                for (PIP_ADAPTER_UNICAST_ADDRESS ua = curr->FirstUnicastAddress; ua; ua = ua->Next) {
                    char addrStr[INET6_ADDRSTRLEN];
                    if (ua->Address.lpSockaddr->sa_family == AF_INET) {
                        SOCKADDR_IN* sa = (SOCKADDR_IN*)ua->Address.lpSockaddr;
                        inet_ntop(AF_INET, &sa->sin_addr, addrStr, sizeof(addrStr));
                        adapter.ipAddresses.push_back(std::string(addrStr));
                    }
                    else if (ua->Address.lpSockaddr->sa_family == AF_INET6) {
                        SOCKADDR_IN6* sa = (SOCKADDR_IN6*)ua->Address.lpSockaddr;
                        inet_ntop(AF_INET6, &sa->sin6_addr, addrStr, sizeof(addrStr));
                        adapter.ipAddresses.push_back(std::string(addrStr));
                    }
                }
                
                adapters.push_back(adapter);
            }
        }
        
        free(pAddresses);
        return adapters;
    }

    Architecture GetSystemArchitecture() {
        SYSTEM_INFO sysInfo;
        GetNativeSystemInfo(&sysInfo);
        
        switch (sysInfo.wProcessorArchitecture) {
            case PROCESSOR_ARCHITECTURE_AMD64:
                return Architecture::X64;
            case PROCESSOR_ARCHITECTURE_INTEL:
                return Architecture::X86;
            case PROCESSOR_ARCHITECTURE_ARM64:
                return Architecture::ARM64;
            default:
                return Architecture::UNKNOWN;
        }
    }

    bool Is64BitSystem() {
        return GetSystemArchitecture() == Architecture::X64 || GetSystemArchitecture() == Architecture::ARM64;
    }

    std::string GetProcessArchitecture() {
#ifdef _WIN64
        return "x64";
#else
        return "x86";
#endif
    }

    std::string GetSystemLocale() {
        char locale[LOCALE_NAME_MAX_LENGTH] = {0};
        if (GetUserDefaultLocaleName(reinterpret_cast<LPWSTR>(locale), LOCALE_NAME_MAX_LENGTH)) {
            // Convert wide string to regular string
            return std::string(locale, locale + strlen(locale));
        }
        return "unknown-locale";
    }

    std::string GetTimeZone() {
        TIME_ZONE_INFORMATION tzInfo;
        DWORD result = GetTimeZoneInformation(&tzInfo);
        
        if (result != TIME_ZONE_ID_INVALID) {
            // Convert wide string to regular string
            std::wstring wstr(tzInfo.StandardName);
            return std::string(wstr.begin(), wstr.end());
        }
        
        return "unknown-timezone";
    }

    std::string GetDomainInfo() {
        LPWSTR domainName = NULL;
        NETSETUP_JOIN_STATUS joinStatus;
        
        NET_API_STATUS status = NetGetJoinInformation(NULL, &domainName, &joinStatus);
        if (status == NERR_Success) {
            std::string result;
            if (joinStatus == NetSetupDomainName && domainName) {
                std::wstring wstr(domainName);
                result = std::string(wstr.begin(), wstr.end());
            } else {
                result = "WORKGROUP";
            }
            
            if (domainName) {
                NetApiBufferFree(domainName);
            }
            return result;
        }
        
        return "unknown-domain";
    }

    bool IsDomainJoined() {
        std::string domain = GetDomainInfo();
        return (domain != "WORKGROUP" && domain != "unknown-domain");
    }

    std::string GetProductKey() {
        // Note: Product key retrieval is complex and may not work on all systems
        HKEY hKey;
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            char productId[256] = {0};
            DWORD bufferSize = sizeof(productId);
            
            if (RegQueryValueExA(hKey, "ProductId", NULL, NULL, (LPBYTE)productId, &bufferSize) == ERROR_SUCCESS) {
                RegCloseKey(hKey);
                return std::string(productId);
            }
            RegCloseKey(hKey);
        }
        
        return ""; // Product key not accessible
    }

    std::string GetBootTime() {
        uint64_t uptime = GetTickCount64();
        SYSTEMTIME st;
        GetSystemTime(&st);
        
        // Calculate boot time
        FILETIME ft;
        SystemTimeToFileTime(&st, &ft);
        ULARGE_INTEGER uli;
        uli.LowPart = ft.dwLowDateTime;
        uli.HighPart = ft.dwHighDateTime;
        
        // Subtract uptime
        uli.QuadPart -= uptime * 10000ULL; // Convert ms to 100ns intervals
        
        ft.dwLowDateTime = uli.LowPart;
        ft.dwHighDateTime = uli.HighPart;
        
        FileTimeToSystemTime(&ft, &st);
        
        std::ostringstream oss;
        oss << std::setfill('0') << std::setw(4) << st.wYear << "-"
            << std::setw(2) << st.wMonth << "-" << std::setw(2) << st.wDay << " "
            << std::setw(2) << st.wHour << ":" << std::setw(2) << st.wMinute << ":" << std::setw(2) << st.wSecond;
        
        return oss.str();
    }

    uint64_t GetUptimeSeconds() {
        return GetTickCount64() / 1000;
    }

    std::string GetCPUInfo() {
        HKEY hKey;
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            char processorName[256] = {0};
            DWORD bufferSize = sizeof(processorName);
            
            if (RegQueryValueExA(hKey, "ProcessorNameString", NULL, NULL, (LPBYTE)processorName, &bufferSize) == ERROR_SUCCESS) {
                RegCloseKey(hKey);
                return std::string(processorName);
            }
            RegCloseKey(hKey);
        }
        
        return "unknown-cpu";
    }

    uint64_t GetTotalMemory() {
        MEMORYSTATUSEX memStatus;
        memStatus.dwLength = sizeof(memStatus);
        
        if (GlobalMemoryStatusEx(&memStatus)) {
            return memStatus.ullTotalPhys;
        }
        
        return 0;
    }

    uint64_t GetAvailableMemory() {
        MEMORYSTATUSEX memStatus;
        memStatus.dwLength = sizeof(memStatus);
        
        if (GlobalMemoryStatusEx(&memStatus)) {
            return memStatus.ullAvailPhys;
        }
        
        return 0;
    }

    std::string GetWindowsVersionName() {
        HKEY hKey;
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            char productName[256] = {0};
            DWORD bufferSize = sizeof(productName);
            
            if (RegQueryValueExA(hKey, "ProductName", NULL, NULL, (LPBYTE)productName, &bufferSize) == ERROR_SUCCESS) {
                RegCloseKey(hKey);
                return std::string(productName);
            }
            RegCloseKey(hKey);
        }
        
        return "Windows";
    }

    bool IsWindowsDefenderRunning() {
        // Check Windows Defender service
        SC_HANDLE hSCManager = OpenSCManagerA(NULL, NULL, SC_MANAGER_CONNECT);
        if (!hSCManager) return false;
        
        SC_HANDLE hService = OpenServiceA(hSCManager, "WinDefend", SERVICE_QUERY_STATUS);
        if (hService) {
            SERVICE_STATUS status;
            if (QueryServiceStatus(hService, &status)) {
                CloseServiceHandle(hService);
                CloseServiceHandle(hSCManager);
                return status.dwCurrentState == SERVICE_RUNNING;
            }
            CloseServiceHandle(hService);
        }
        
        CloseServiceHandle(hSCManager);
        return false;
    }

    std::vector<std::string> GetAntivirusProducts() {
        std::vector<std::string> products;
        
        // This is a simplified implementation
        // Full AV detection would require WMI queries
        if (IsWindowsDefenderRunning()) {
            products.push_back("Windows Defender");
        }
        
        return products;
    }

    bool IsUACEnabled() {
        HKEY hKey;
        DWORD uacValue = 0;
        DWORD dataSize = sizeof(DWORD);
        
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            RegQueryValueExA(hKey, "EnableLUA", NULL, NULL, (LPBYTE)&uacValue, &dataSize);
            RegCloseKey(hKey);
        }
        
        return uacValue != 0;
    }

    std::vector<std::string> GetEnvironmentVariables() {
        std::vector<std::string> variables;
        
        char* env = GetEnvironmentStringsA();
        if (env) {
            char* envVar = env;
            while (*envVar) {
                variables.push_back(std::string(envVar));
                envVar += strlen(envVar) + 1;
            }
            FreeEnvironmentStringsA(env);
        }
        
        return variables;
    }

    std::string GetCurrentUserSID() {
        HANDLE hToken;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
            return "";
        }
        
        DWORD tokenInfoLength = 0;
        GetTokenInformation(hToken, TokenUser, NULL, 0, &tokenInfoLength);
        if (tokenInfoLength == 0) {
            CloseHandle(hToken);
            return "";
        }
        
        std::vector<BYTE> tokenUserBuffer(tokenInfoLength);
        PTOKEN_USER pTokenUser = (PTOKEN_USER)tokenUserBuffer.data();
        
        if (GetTokenInformation(hToken, TokenUser, pTokenUser, tokenInfoLength, &tokenInfoLength)) {
            LPSTR sidString = NULL;
            if (ConvertSidToStringSidA(pTokenUser->User.Sid, &sidString)) {
                std::string result(sidString);
                LocalFree(sidString);
                CloseHandle(hToken);
                return result;
            }
        }
        
        CloseHandle(hToken);
        return "";
    }

    std::vector<std::string> GetCurrentUserGroups() {
        std::vector<std::string> groups;
        
        HANDLE hToken;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
            return groups;
        }
        
        DWORD tokenInfoLength = 0;
        GetTokenInformation(hToken, TokenGroups, NULL, 0, &tokenInfoLength);
        if (tokenInfoLength > 0) {
            std::vector<BYTE> tokenGroupsBuffer(tokenInfoLength);
            PTOKEN_GROUPS pTokenGroups = (PTOKEN_GROUPS)tokenGroupsBuffer.data();
            
            if (GetTokenInformation(hToken, TokenGroups, pTokenGroups, tokenInfoLength, &tokenInfoLength)) {
                for (DWORD i = 0; i < pTokenGroups->GroupCount; i++) {
                    char groupName[256] = {0};
                    char domainName[256] = {0};
                    DWORD groupNameSize = sizeof(groupName);
                    DWORD domainNameSize = sizeof(domainName);
                    SID_NAME_USE sidUse;
                    
                    if (LookupAccountSidA(NULL, pTokenGroups->Groups[i].Sid, groupName, &groupNameSize,
                                         domainName, &domainNameSize, &sidUse)) {
                        if (strlen(domainName) > 0) {
                            groups.push_back(std::string(domainName) + "\\" + std::string(groupName));
                        } else {
                            groups.push_back(std::string(groupName));
                        }
                    }
                }
            }
        }
        
        CloseHandle(hToken);
        return groups;
    }

    bool IsCurrentUserAdmin() {
        return GetIntegrity() >= 4;
    }

    std::vector<std::string> GetSystemDrives() {
        std::vector<std::string> drives;
        
        DWORD driveMask = GetLogicalDrives();
        for (char drive = 'A'; drive <= 'Z'; drive++) {
            if (driveMask & (1 << (drive - 'A'))) {
                std::string drivePath = std::string(1, drive) + ":";
                UINT driveType = GetDriveTypeA(drivePath.c_str());
                
                std::string typeStr;
                switch (driveType) {
                    case DRIVE_FIXED: typeStr = "Fixed"; break;
                    case DRIVE_REMOVABLE: typeStr = "Removable"; break;
                    case DRIVE_REMOTE: typeStr = "Network"; break;
                    case DRIVE_CDROM: typeStr = "CD/DVD"; break;
                    case DRIVE_RAMDISK: typeStr = "RAM Disk"; break;
                    default: typeStr = "Unknown"; break;
                }
                
                drives.push_back(drivePath + " (" + typeStr + ")");
            }
        }
        
        return drives;
    }

    std::string GetWindowsDir() {
        char winDir[MAX_PATH];
        if (::GetWindowsDirectoryA(winDir, MAX_PATH)) {
            return std::string(winDir);
        }
        return "C:\\Windows";
    }

    std::string GetSystemDir() {
        char sysDir[MAX_PATH];
        if (::GetSystemDirectoryA(sysDir, MAX_PATH)) {
            return std::string(sysDir);
        }
        return "C:\\Windows\\System32";
    }

    std::string GetTempDirectory() {
        char tempDir[MAX_PATH];
        if (GetTempPathA(MAX_PATH, tempDir)) {
            return std::string(tempDir);
        }
        return "C:\\Temp";
    }

    std::string GenerateSystemFingerprint() {
        std::ostringstream fingerprint;
        
        fingerprint << GetMachineGuid() << "|";
        fingerprint << GetHostname() << "|";
        fingerprint << GetUsername() << "|";
        fingerprint << GetOSVersion() << "|";
        fingerprint << GetProcessArchitecture() << "|";
        fingerprint << GetCPUInfo() << "|";
        fingerprint << GetTotalMemory() << "|";
        fingerprint << GetInternalIP();
        
        return fingerprint.str();
    }

    std::string GenerateSystemReport(bool includeNetworking, bool includeSecurity) {
        std::ostringstream report;
        
        report << "=== SYSTEM INFORMATION REPORT ===\n\n";
        
        // Basic system info
        report << "Computer Name: " << GetHostname() << "\n";
        report << "Username: " << GetUsername() << "\n";
        report << "Machine GUID: " << GetMachineGuid() << "\n";
        report << "Operating System: " << GetWindowsVersionName() << " (" << GetOSVersion() << ")\n";
        report << "Architecture: " << GetProcessArchitecture() << " process on ";
        
        Architecture arch = GetSystemArchitecture();
        switch (arch) {
            case Architecture::X86: report << "x86"; break;
            case Architecture::X64: report << "x64"; break;
            case Architecture::ARM64: report << "ARM64"; break;
            default: report << "Unknown"; break;
        }
        report << " system\n";
        
        report << "CPU: " << GetCPUInfo() << "\n";
        report << "Total Memory: " << (GetTotalMemory() / 1024 / 1024) << " MB\n";
        report << "Available Memory: " << (GetAvailableMemory() / 1024 / 1024) << " MB\n";
        report << "Uptime: " << (GetUptimeSeconds() / 3600) << " hours\n";
        report << "Boot Time: " << GetBootTime() << "\n";
        report << "Time Zone: " << GetTimeZone() << "\n";
        
        // Domain info
        report << "Domain: " << GetDomainInfo();
        if (IsDomainJoined()) {
            report << " (Domain Joined)";
        }
        report << "\n";
        
        // Drives
        report << "\nSystem Drives:\n";
        auto drives = GetSystemDrives();
        for (const auto& drive : drives) {
            report << "  " << drive << "\n";
        }
        
        if (includeSecurity) {
            report << "\nSecurity Information:\n";
            report << "User is Admin: " << (IsCurrentUserAdmin() ? "Yes" : "No") << "\n";
            report << "Integrity Level: " << GetIntegrity() << "\n";
            report << "UAC Enabled: " << (IsUACEnabled() ? "Yes" : "No") << "\n";
            report << "Windows Defender: " << (IsWindowsDefenderRunning() ? "Running" : "Not Running") << "\n";
            report << "User SID: " << GetCurrentUserSID() << "\n";
        }
        
        if (includeNetworking) {
            report << "\nNetwork Information:\n";
            report << "Primary IP: " << GetInternalIP() << "\n";
            
            auto adapters = GetNetworkAdapters();
            for (const auto& adapter : adapters) {
                if (adapter.isUp && !adapter.ipAddresses.empty()) {
                    report << "Adapter: " << adapter.description << "\n";
                    report << "  MAC: " << adapter.macAddress << "\n";
                    for (const auto& ip : adapter.ipAddresses) {
                        report << "  IP: " << ip << "\n";
                    }
                }
            }
        }
        
        report << "\n=== END REPORT ===\n";
        return report.str();
    }

} // namespace SystemInfo
} // namespace Utils