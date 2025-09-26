#pragma once

#include <string>
#include <vector>
#include <windows.h>
#include <cstdint>

namespace Utils {
namespace SystemInfo {

    // System architecture enumeration
    enum class Architecture {
        UNKNOWN,
        X86,
        X64,
        ARM64
    };

    // Operating system information structure
    struct OSInfo {
        std::string version;
        std::string buildNumber;
        std::string productName;
        std::string servicePack;
        Architecture architecture;
        bool is64Bit;
        
        OSInfo() : architecture(Architecture::UNKNOWN), is64Bit(false) {}
    };

    // Network adapter information structure
    struct NetworkAdapter {
        std::string name;
        std::string description;
        std::string macAddress;
        std::vector<std::string> ipAddresses;
        bool isUp;
        
        NetworkAdapter() : isUp(false) {}
    };

    /**
     * Get the current username
     * @return Username of current process
     */
    std::string GetUsername();

    /**
     * Get the computer hostname
     * @return Computer hostname/name
     */
    std::string GetHostname();

    /**
     * Get the machine GUID from registry
     * @return Machine GUID string, "unknown-guid" if failed
     */
    std::string GetMachineGuid();

    /**
     * Get operating system version information
     * @return OS version string (e.g., "10.0 (19044)")
     */
    std::string GetOSVersion();

    /**
     * Get detailed operating system information
     * @return OSInfo structure with detailed OS data
     */
    OSInfo GetDetailedOSInfo();

    /**
     * Get process integrity level
     * @return Integrity level (1=Low, 2=Medium, 3=High, 4=System)
     */
    int GetIntegrity();

    /**
     * Get internal IP address of primary network adapter
     * @return Internal IP address string, "unknown" if failed
     */
    std::string GetInternalIP();

    /**
     * Get all network adapters information
     * @return Vector of NetworkAdapter structures
     */
    std::vector<NetworkAdapter> GetNetworkAdapters();

    /**
     * Get system architecture
     * @return Architecture enumeration value
     */
    Architecture GetSystemArchitecture();

    /**
     * Check if system is 64-bit
     * @return true if running on 64-bit system
     */
    bool Is64BitSystem();

    /**
     * Get current process architecture
     * @return "x86" or "x64"
     */
    std::string GetProcessArchitecture();

    /**
     * Get system locale information
     * @return Locale string (e.g., "en-US")
     */
    std::string GetSystemLocale();

    /**
     * Get system timezone information
     * @return Timezone name
     */
    std::string GetTimeZone();

    /**
     * Get domain information
     * @return Domain name if joined, "WORKGROUP" if not
     */
    std::string GetDomainInfo();

    /**
     * Check if system is domain joined
     * @return true if system is joined to a domain
     */
    bool IsDomainJoined();

    /**
     * Get Windows product key (if accessible)
     * @return Product key string, empty if not accessible
     */
    std::string GetProductKey();

    /**
     * Get system boot time
     * @return Boot time as string
     */
    std::string GetBootTime();

    /**
     * Get system uptime in seconds
     * @return Uptime in seconds
     */
    uint64_t GetUptimeSeconds();

    /**
     * Get CPU information
     * @return CPU information string
     */
    std::string GetCPUInfo();

    /**
     * Get total physical memory in bytes
     * @return Total physical memory
     */
    uint64_t GetTotalMemory();

    /**
     * Get available physical memory in bytes
     * @return Available physical memory
     */
    uint64_t GetAvailableMemory();

    /**
     * Get Windows version name (Windows 10, Windows 11, etc.)
     * @return Windows version name
     */
    std::string GetWindowsVersionName();

    /**
     * Check if Windows Defender is running
     * @return true if Windows Defender is active
     */
    bool IsWindowsDefenderRunning();

    /**
     * Get installed antivirus products
     * @return Vector of antivirus product names
     */
    std::vector<std::string> GetAntivirusProducts();

    /**
     * Check if UAC (User Account Control) is enabled
     * @return true if UAC is enabled
     */
    bool IsUACEnabled();

    /**
     * Get system environment variables
     * @return Vector of environment variable strings
     */
    std::vector<std::string> GetEnvironmentVariables();

    /**
     * Get current user's SID
     * @return SID string
     */
    std::string GetCurrentUserSID();

    /**
     * Get current user's groups
     * @return Vector of group names
     */
    std::vector<std::string> GetCurrentUserGroups();

    /**
     * Check if current user is administrator
     * @return true if user has administrator privileges
     */
    bool IsCurrentUserAdmin();

    /**
     * Get system drives information
     * @return Vector of drive letters and types
     */
    std::vector<std::string> GetSystemDrives();

    /**
     * Get Windows installation directory
     * @return Windows directory path
     */
    std::string GetWindowsDirectory();

    /**
     * Get system directory
     * @return System32 directory path
     */
    std::string GetSystemDirectory();

    /**
     * Get temporary directory
     * @return Temp directory path
     */
    std::string GetTempDirectory();

    /**
     * Generate a comprehensive system fingerprint
     * @return Unique system fingerprint string
     */
    std::string GenerateSystemFingerprint();

    /**
     * Get system information as formatted report
     * @param includeNetworking Whether to include network information
     * @param includeSecurity Whether to include security information
     * @return Formatted system information report
     */
    std::string GenerateSystemReport(bool includeNetworking = true, bool includeSecurity = true);

} // namespace SystemInfo
} // namespace Utils