#pragma once

#include <windows.h>

namespace Utils {
namespace AntiDebug {

    /**
     * Check if debugger is present using Windows API
     * @return true if debugger detected
     */
    bool IsDebuggerPresent_API();

    /**
     * Check if debugger is present by examining PEB
     * @return true if debugger detected
     */
    bool IsDebuggerPresent_PEB();

    /**
     * Check for debug port using NtQueryInformationProcess
     * @return true if debug port detected
     */
    bool CheckDebugPort();

    /**
     * Check for debugger using timing-based detection
     * @return true if timing anomaly detected (possible debugger)
     */
    bool CheckDebuggerTimestamp();

    /**
     * Check for attached debugger using multiple methods
     * @return true if debugger detected by any method
     */
    bool CheckRemoteDebugger();

    /**
     * Check for common debugging tools in process list
     * @return true if debugging tools detected
     */
    bool CheckDebuggerProcesses();

    /**
     * Check for common debugging tool windows
     * @return true if debugger windows detected
     */
    bool CheckDebuggerWindows();

    /**
     * Check for hardware breakpoints
     * @return true if hardware breakpoints detected
     */
    bool CheckHardwareBreakpoints();

    /**
     * Check for software breakpoints (INT3)
     * @param startAddress Starting address to check
     * @param size Size of memory region to check
     * @return true if software breakpoints detected
     */
    bool CheckSoftwareBreakpoints(void* startAddress, size_t size);

    /**
     * Check if running in a virtual machine
     * @return true if VM detected
     */
    bool IsRunningInVM();

    /**
     * Check for common sandbox indicators
     * @return true if sandbox environment detected
     */
    bool IsSandboxEnvironment();

    /**
     * Comprehensive debugger detection using multiple techniques
     * @param threshold Minimum number of techniques that must detect debugging (default: 2)
     * @return true if debugger detected by at least 'threshold' techniques
     */
    bool IsBeingDebugged(int threshold = 2);

    /**
     * Get detailed debugging status information
     * @return String containing debugging detection results
     */
    std::string GetDebuggingStatus();

    /**
     * Check for analysis tools and environments
     * @return true if analysis environment detected
     */
    bool IsAnalysisEnvironment();

    /**
     * Simple anti-debugging check for basic protection
     * @return true if any debugging detected
     */
    bool QuickDebugCheck();

    /**
     * Anti-debugging technique: Create exception to detect debugger
     * @return true if debugger detected through exception handling
     */
    bool CheckDebuggerByException();

    /**
     * Check for common DLL injection techniques used by debuggers
     * @return true if suspicious DLLs detected
     */
    bool CheckSuspiciousDLLs();

    /**
     * Verify code integrity (check for patches/modifications)
     * @param moduleHandle Handle to module to check
     * @return true if code modifications detected
     */
    bool CheckCodeIntegrity(HMODULE moduleHandle = NULL);

} // namespace AntiDebug
} // namespace Utils