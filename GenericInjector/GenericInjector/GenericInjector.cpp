#include <windows.h>
#include <psapi.h>

#include <stdlib.h>
#include <stdio.h>
#include <conio.h>

/*****************************************************************************/
/***************************FUNCTIONS DECLARATIONS****************************/
/*****************************************************************************/
DWORD* GetProcessesWithThisName(char* szProcessName, unsigned long* plTotalProcessIds);
bool InjectDllInThisProcess(char* szDllPath_32, char* szDllPath_64, DWORD dwPID, BOOL* pbProcessWas32Bits);
bool ProcessIsAlreadyInjected(DWORD dwPID);
void AddToAlreadyInjectedProcesses(DWORD dwPID);
bool InjectDllInThisProcess_x64(char* szDllPath_64, DWORD dwPID);
bool InjectIntoProcess(DWORD dwPID, char* szDllPath);

/*****************************************************************************/
/******************************GLOBAL VARIABLES*******************************/
/*****************************************************************************/
DWORD* g_dwAlreadyInjectedProcesses = NULL;
DWORD g_dwTotalInjectedProcesses = 0;


/*****************************************************************************/
int main(int argc, char** argv)
{
	//Declare variables to use
	DWORD* pdwProcessIds = NULL;
	unsigned long lTotalProcessIds = 0;
	char* szInjectedDllPath_32 = NULL;
	char* szInjectedDllPath_64 = NULL;
	char* szProcessName = NULL;

	if (__argc > 3 && _stricmp(__argv[1], "-InjectIntoProcess") == 0) {
		InjectIntoProcess(strtoul(__argv[2], NULL, 10), __argv[3]);
		return 0;
	}

	//Do some validations
	if (argc < 4) {
		printf("Usage: SimpleInjector <process name> <32 bits dll full path to inject> <64 bits dll full path to inject>.\n");
		return 1;
	}
	szProcessName = argv[1];
	szInjectedDllPath_32 = argv[2];
	szInjectedDllPath_64 = argv[3];

	//Do this while the user does not press any key
	while (!_kbhit()) {
		//Get processes where the .dll will be injected
		pdwProcessIds = GetProcessesWithThisName(szProcessName, &lTotalProcessIds);
		if (pdwProcessIds != NULL && lTotalProcessIds > 0) {
			for (unsigned long i = 0; i < lTotalProcessIds; i++) {
				if (ProcessIsAlreadyInjected(pdwProcessIds[i]) == false) {
					AddToAlreadyInjectedProcesses(pdwProcessIds[i]);
					//Now inject dll in this process
					BOOL bWas32Bits = false;
					if (InjectDllInThisProcess(szInjectedDllPath_32, szInjectedDllPath_64, pdwProcessIds[i],&bWas32Bits)) {
						printf("Success injecting %s in PID %d\n", bWas32Bits?szInjectedDllPath_32: szInjectedDllPath_64, pdwProcessIds[i]);
					}
					else {
						printf("Error injecting library in PID %d\n", pdwProcessIds[i]);
					}
				}
			}
			free(pdwProcessIds);
		}
		Sleep(1000); //Sleep 1 second in order to avoid consuming CPU
	}
	//Free resources
	if (g_dwAlreadyInjectedProcesses != NULL) free(g_dwAlreadyInjectedProcesses);
	g_dwAlreadyInjectedProcesses = NULL;
	g_dwTotalInjectedProcesses = 0;
	return 0;
}

/*****************************************************************************/
DWORD* GetProcessesWithThisName(char* szProcessName, unsigned long* plTotalProcessIds)
{
	DWORD* pdwToReturn = NULL;
	OSVERSIONINFO osver;
	DWORD j;
	DWORD aProcesses[1024], cbNeeded, cProcesses;
	osver.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);
	*plTotalProcessIds = 0;
	//Get all processes... this shold be more robust since it assumes that there could be up to 1024 processes, but I coded it like this just to simplify the code
	if (!EnumProcesses(aProcesses, sizeof(aProcesses), &cbNeeded)) {
		return NULL;
	}
	cProcesses = cbNeeded / sizeof(DWORD);
	for (j = 0; j < cProcesses; j++) {
		char szModName[MAX_PATH];
		char* szModLastName = NULL;
		szModName[0] = 0;
		HMODULE hMods[1024];
		HANDLE hProcess;
		DWORD cbNeeded;
		hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, aProcesses[j]);
		if (NULL == hProcess) {
			continue;
		}
		//It is better if you use GetProcessImageFileNameA than EnumProcessModules
		GetProcessImageFileNameA(hProcess, szModName, sizeof(szModName));
		if (szModName[0] != 0) {
			if (strrchr(szModName, '\\')) szModLastName = strrchr(szModName, '\\') + 1;
			else if (strrchr(szModName, '/')) szModLastName = strrchr(szModName, '/') + 1;
			else szModLastName = szModName;
			if (_stricmp(szModLastName, szProcessName) == 0) {
				(*plTotalProcessIds)++;
				pdwToReturn = (DWORD*)realloc(pdwToReturn, sizeof(DWORD) * (*plTotalProcessIds));
				pdwToReturn[(*plTotalProcessIds) - 1] = aProcesses[j];
			}
		}
		CloseHandle(hProcess);
	}
	return pdwToReturn;
}

/*****************************************************************************/
bool InjectDllInThisProcess(char* szDllPath_32, char* szDllPath_64, DWORD dwPID, BOOL *pbProcessWas32Bits)
{
	void* pLibRemote;
	DWORD hLibModule;
	BOOL bRes;
	HANDLE hThread;
	*pbProcessWas32Bits = false;
	HMODULE hKernel32 = GetModuleHandleA("Kernel32");
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPID);
	if (!hProcess) return false;
	BOOL bIsWow64Result = IsWow64Process(hProcess, pbProcessWas32Bits);
	if (bIsWow64Result && *pbProcessWas32Bits == false) {
		//It is an x64 process... run the x64 version since this x86 version will not work
		CloseHandle(hProcess);
		return InjectDllInThisProcess_x64(szDllPath_64, dwPID);
	}
	pLibRemote = VirtualAllocEx(hProcess, NULL, strlen(szDllPath_32) + 1, MEM_COMMIT, PAGE_READWRITE);
	bRes = WriteProcessMemory(hProcess, pLibRemote, (void*)szDllPath_32, strlen(szDllPath_32) + 1, NULL);
	hThread = CreateRemoteThread(hProcess, NULL, 0,
		(LPTHREAD_START_ROUTINE)GetProcAddress((HINSTANCE)hKernel32, "LoadLibraryA"),
		pLibRemote, 0, NULL);
	WaitForSingleObject(hThread, INFINITE);
	GetExitCodeThread(hThread, &hLibModule);
	CloseHandle(hThread);
	VirtualFreeEx(hProcess, pLibRemote, strlen(szDllPath_32) + 1, MEM_RELEASE);
	CloseHandle(hProcess);
	return true;
}

/*************************************************************************/
bool InjectDllInThisProcess_x64(char *szDllPath_64, DWORD dwPID)
{
	char szCommandLine[1024*4];
	char szProcessId[512];
	//Format is: ThisProcessPath_x64.exe PID DllPath64
	GetModuleFileNameA(NULL, szCommandLine, sizeof(szCommandLine));
	//Skip .exe
	if (strrchr(szCommandLine, '.') == NULL) return false; //This should not happen
	*strrchr(szCommandLine, '.') = 0;
	strcat_s(szCommandLine, sizeof(szCommandLine), "_64.exe");
	//As this is a command line, add it between quotes to avoid issues with spaces in the path
	memmove(((char*)szCommandLine) + 1, szCommandLine , strlen(szCommandLine) + 1);
	szCommandLine[0] = '\"';
	strcat_s(szCommandLine, sizeof(szCommandLine), "\" -InjectIntoProcess ");
	sprintf_s(szProcessId,sizeof(szProcessId), "%u", dwPID);
	strcat_s(szCommandLine, sizeof(szCommandLine), szProcessId);
	strcat_s(szCommandLine, sizeof(szCommandLine), " \"");
	strcat_s(szCommandLine, sizeof(szCommandLine), szDllPath_64);
	strcat_s(szCommandLine, sizeof(szCommandLine), "\"");
	STARTUPINFOA si;
	PROCESS_INFORMATION pi;
	memset(&si, 0, sizeof(si));
	memset(&pi, 0, sizeof(pi));
	si.cb = sizeof(STARTUPINFOA);
	si.dwFlags = STARTF_USESHOWWINDOW | STARTF_FORCEOFFFEEDBACK;
	BOOL bProcessRet = CreateProcessA(NULL, szCommandLine, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
	if (bProcessRet == 0) {
		return false;
	}
	if (pi.hProcess == 0) {
		return false;
	}
	WaitForSingleObject(pi.hProcess, INFINITE);
	CloseHandle(pi.hProcess);
	if (pi.hThread) CloseHandle(pi.hThread);
	return true;
}

/*****************************************************************************/
bool ProcessIsAlreadyInjected(DWORD dwPID)
{
	for (DWORD i = 0; i < g_dwTotalInjectedProcesses; i++) {
		if (g_dwAlreadyInjectedProcesses[i] == dwPID) {
			return true;
		}
	}
	return false;
}

/*****************************************************************************/
void AddToAlreadyInjectedProcesses(DWORD dwPID)
{
	g_dwTotalInjectedProcesses++;
	g_dwAlreadyInjectedProcesses = (DWORD*)realloc(g_dwAlreadyInjectedProcesses, sizeof(DWORD) * g_dwTotalInjectedProcesses);
	g_dwAlreadyInjectedProcesses[g_dwTotalInjectedProcesses - 1] = dwPID;
}

/*****************************************************************************/
bool InjectIntoProcess(DWORD dwPID, char* szDllPath)
{
	char szLibPath[1024];
	void* pLibRemote;
	DWORD hLibModule;
	BOOL bRes;
	HANDLE hThread;
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPID);
	if (!hProcess) return false;
	HMODULE hKernel32 = GetModuleHandleA("Kernel32");
	strcpy_s(szLibPath, sizeof(szLibPath), szDllPath);

	pLibRemote = VirtualAllocEx(hProcess, NULL, sizeof(szLibPath),
		MEM_COMMIT, PAGE_READWRITE);
	bRes = WriteProcessMemory(hProcess, pLibRemote, (void*)szLibPath,
		sizeof(szLibPath), NULL);
	hThread = CreateRemoteThread(hProcess, NULL, 0,
		(LPTHREAD_START_ROUTINE)GetProcAddress((HINSTANCE)hKernel32, "LoadLibraryA"),
		pLibRemote, 0, NULL);
	WaitForSingleObject(hThread, INFINITE);
	GetExitCodeThread(hThread, &hLibModule);
	CloseHandle(hThread);
	VirtualFreeEx(hProcess, pLibRemote, sizeof(szLibPath), MEM_RELEASE);
	CloseHandle(hProcess);
	return true;
}
