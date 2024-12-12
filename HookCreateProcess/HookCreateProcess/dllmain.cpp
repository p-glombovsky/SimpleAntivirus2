//IMPORTANT: Compile in Release mode (else the hooking code will not work) and disable optimization (else the trampoline function will not work)
#include <windows.h>

#include <tchar.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>

const wchar_t* MemoryMappedFileName = L"Global\\AntivirusSampleServiceMemory";
const int MemoryMappedFileCapacity = 1024 * 2;
const wchar_t* EventName = L"Global\\AntivirusSampleServiceEvent";
const wchar_t* EventResponseName = L"Global\\AntivirusSampleServiceEvent_ResponseToClient";

#ifdef WIN64
BOOL PatchFunction(char* szDllPath, char* szFunctionName, BYTE* pRedirectToThisFunction, BYTE* trampolineFunctionPtr, __int64 bytesToSkip);
#else
BOOL PatchFunction(char* szDllPath, char* szFunctionName, BYTE* pRedirectToThisFunction, BYTE* trampolineFunctionPtr, int bytesToSkip);
#endif


#ifdef WIN64
BOOL UnpatchFunction(char* szDllPath, char* szFunctionName, BYTE* pRedirectToThisFunction, BYTE* trampolineFunctionPtr, int bytesToSkip);
#else
BOOL UnpatchFunction(char* szDllPath, char* szFunctionName, BYTE* pRedirectToThisFunction, BYTE* trampolineFunctionPtr, int bytesToSkip);
#endif

BOOL WINAPI DummyShellExecuteExW(SHELLEXECUTEINFOW* p);
BOOL WINAPI MyShellExecuteExW(SHELLEXECUTEINFOW* p);
void LogToDbgView(const char* format, ...);
char* ReadAnswerFromSharedMemory(HANDLE hMapFile);
bool AnalyzeFile(char* szFilePath);


/*****************************************************************************/
BOOL APIENTRY DllMain( HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
#ifdef WIN64
        PatchFunction((char*)"shell32.dll", (char*)"ShellExecuteExW", (BYTE*)MyShellExecuteExW, (BYTE*)DummyShellExecuteExW, 16);
#else
        PatchFunction((char*)"shell32.dll", (char*)"ShellExecuteExW", (BYTE*)MyShellExecuteExW, (BYTE*)DummyShellExecuteExW, 5);
#endif
        break;
    case DLL_THREAD_ATTACH:
        break;
    case DLL_THREAD_DETACH:
        break;
    case DLL_PROCESS_DETACH:
#ifdef WIN64
        UnpatchFunction((char*)"shell32.dll", (char*)"ShellExecuteExW", (BYTE*)MyShellExecuteExW, (BYTE*)DummyShellExecuteExW, 16);
#else
        UnpatchFunction((char*)"shell32.dll", (char*)"ShellExecuteExW", (BYTE*)MyShellExecuteExW, (BYTE*)DummyShellExecuteExW, 5);
#endif
        break;
    }
    return TRUE;
}

/*****************************************************************************/
#ifdef WIN64
BOOL PatchFunction(char* szDllPath, char* szFunctionName, BYTE *pRedirectToThisFunction, BYTE* trampolineFunctionPtr, __int64 bytesToSkip)
#else
BOOL PatchFunction(char* szDllPath, char* szFunctionName, BYTE *pRedirectToThisFunction, BYTE* trampolineFunctionPtr, int bytesToSkip)
#endif
{
    int i;
    DWORD dwOldProtect;
    HMODULE hModule = GetModuleHandleA(szDllPath);
    if (!hModule) hModule = LoadLibraryA(szDllPath);
    if (!hModule) return FALSE;
    BYTE *pPatchThisAddress = (BYTE*)GetProcAddress(hModule, szFunctionName);
    BYTE* pbTargetCode = (BYTE*)pPatchThisAddress;
    BYTE* pbReplaced = pRedirectToThisFunction;
    BYTE* pbTrampoline = trampolineFunctionPtr;
#ifdef WIN64
    VirtualProtect((void*)trampolineFunctionPtr, 14 + bytesToSkip, PAGE_EXECUTE_READWRITE, &dwOldProtect);
#else
    VirtualProtect((void*)trampolineFunctionPtr, 5 + bytesToSkip, PAGE_EXECUTE_READWRITE, &dwOldProtect);
#endif
    for (i = 0; i < bytesToSkip; i++) *pbTrampoline++ = *pbTargetCode++;
    pbTargetCode = (BYTE*)pPatchThisAddress;
#ifdef WIN64
    * pbTrampoline++ = 0xff; // jmp [rip+addr]
    *pbTrampoline++ = 0x25; // jmp [rip+addr]
    *((DWORD*)pbTrampoline) = 0; // addr=0
    pbTrampoline += sizeof(DWORD);
    *((ULONG_PTR*)pbTrampoline) = (ULONG_PTR)(pbTargetCode + bytesToSkip);
    VirtualProtect((void*)pPatchThisAddress, 14, PAGE_EXECUTE_READWRITE, &dwOldProtect);
    *pbTargetCode++ = 0xff; // jmp [rip+addr]
    *pbTargetCode++ = 0x25; // jmp [rip+addr]
    *((DWORD*)pbTargetCode) = 0; // addr=0
    pbTargetCode += sizeof(DWORD);
    *((ULONG_PTR*)pbTargetCode) = (ULONG_PTR)pbReplaced;
#else
    * pbTrampoline++ = 0xE9; // jump rel32
    *((signed int*)(pbTrampoline)) = (pbTargetCode + bytesToSkip) - (pbTrampoline + 4);
    VirtualProtect((void*)trampolineFunctionPtr, 5 + bytesToSkip, PAGE_EXECUTE_READWRITE, &dwOldProtect);
    VirtualProtect((void*)pPatchThisAddress, 5, PAGE_EXECUTE_READWRITE, &dwOldProtect);
    *pbTargetCode++ = 0xE9; // jump rel32
    *((signed int*)(pbTargetCode)) = pbReplaced - (pbTargetCode + 4);
    VirtualProtect((void*)pPatchThisAddress, 5, PAGE_EXECUTE_READWRITE, &dwOldProtect);
#endif
    FlushInstructionCache(GetCurrentProcess(), NULL, NULL);
    return TRUE;
}

/*****************************************************************************/
#ifdef WIN64
BOOL UnpatchFunction(char* szDllPath, char* szFunctionName, BYTE *pRedirectToThisFunction, BYTE *trampolineFunctionPtr, int bytesToSkip)
#else
BOOL UnpatchFunction(char* szDllPath, char* szFunctionName, BYTE *pRedirectToThisFunction, BYTE* trampolineFunctionPtr, int bytesToSkip)
#endif
{
    int i;
    DWORD dwOldProtect;
    HMODULE hModule = GetModuleHandleA(szDllPath);
    if (!hModule) hModule = LoadLibraryA(szDllPath);
    if (!hModule) return FALSE;
    BYTE* pPatchThisAddress = (BYTE*)GetProcAddress(hModule, szFunctionName);
    BYTE* pbTargetCode = (BYTE*)pPatchThisAddress;
    BYTE* pbReplaced = (BYTE*)pRedirectToThisFunction;
    BYTE* pbTrampoline = trampolineFunctionPtr;
#ifdef WIN64
    VirtualProtect((void*)pPatchThisAddress, 14, PAGE_EXECUTE_READWRITE, &dwOldProtect);
#else
    VirtualProtect((void*)pPatchThisAddress, 5, PAGE_EXECUTE_READWRITE, &dwOldProtect);
#endif
    for (i = 0; i < bytesToSkip; i++) *pbTargetCode++ = *pbTrampoline++;
    FlushInstructionCache(GetCurrentProcess(), NULL, NULL);
    return TRUE;
}

/*****************************************************************************/
BOOL WINAPI DummyShellExecuteExW(SHELLEXECUTEINFOW* p)
{//This is just a dummy body since I need the function to have some bytes in the implementation... the logic does not matter since it is never executed
    void* var1 = (void*)1;
    void* var2 = (void*)2;
    void* var3 = (void*)3;
    void* var4 = (void*)4;
    void* var5 = (void*)5;
    void* var6 = (void*)6;
    void* var7 = (void*)7;
    void* var8 = (void*)8;
    void* var9 = (void*)9;
    void* var10 = (void*)10;
    void* var11 = (void*)11;
    void* var12 = (void*)12;
    void* var13 = (void*)13;
    void* var14 = (void*)14;
    void* var15 = (void*)15;
    var1 = (char*)var2;
    var2 = (char*)var3;
    var3 = (char*)var4;
    var4 = (char*)var5;
    var5 = (char*)var6;
    var6 = (char*)var7;
    var7 = (char*)var8;
    var8 = (char*)var9;
    var9 = (char*)var10;
    var10 = (char*)var11;
    var11 = (char*)var12;
    var12 = (char*)var13;
    var13 = (char*)var14;
    var14 = (char*)var15;
    var15 = (char*)var15;
    unsigned char s[1024];
    strcpy_s((char*)s, sizeof(s), "Something to copy");
    return 1;
    /**/int x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12;
    x1 = 1; x1++;
    x2 = 2; x2++;
    x3 = 3; x3++;
    x4 = 4; x4++;
    x5 = 5; x5++;
    x6 = 6; x6++;
    x7 = 7; x7++;
    x8 = 8; x8++;
    x9 = 9; x9++;
    x10 = 10; x10++;
    x11 = 11; x11++;
    x12 = 12; x12++;
    char szString[512];
    strcpy_s(szString, sizeof(szString),"this is just dummy");
    if (_stricmp(szString, "something else") == 0) x12 = 7;
    else {
        char szString2[512];
        strcpy_s(szString2, sizeof(szString2), "this is just dummy else");
        if (_stricmp(szString2, "another thing") == 0) {
            x4 = 897;
        }
    }
    return 0;
}

/*****************************************************************************/
BOOL WINAPI MyShellExecuteExW(SHELLEXECUTEINFOW* p)
{
    char szFileToAnalyze[2048];
    memset(szFileToAnalyze, 0, sizeof(szFileToAnalyze));
    WideCharToMultiByte(CP_ACP, 0, p->lpFile, -1, szFileToAnalyze, sizeof(szFileToAnalyze), NULL, NULL);
    LogToDbgView("======================>Analyzing %s...", szFileToAnalyze);
    bool bIsMalware = AnalyzeFile(szFileToAnalyze);
    if (bIsMalware) {
        char szToSay[2024];
        sprintf_s(szToSay, sizeof(szToSay), "This file is a MALWARE:\n\n%s", szFileToAnalyze);
        LogToDbgView("======================>Malware detected");
        MessageBoxA(NULL, szToSay, "Malware found", MB_OK | MB_SYSTEMMODAL);
        return TRUE;
    }
    LogToDbgView("======================>File is safe");
    BOOL toReturn = DummyShellExecuteExW(p);
    return toReturn;
}

/*****************************************************************************/
void LogToDbgView(const char* format, ...)
{
    char szFormattedError[8196];
    const char* szPreffix = "Hooking: ";
    va_list arguments;
    va_start(arguments, format);
    vsprintf_s(szFormattedError, format, arguments);
    va_end(arguments);
    memmove(((char*)szFormattedError) + strlen(szPreffix), szFormattedError, strlen(szFormattedError) + 1);
    memcpy(szFormattedError, szPreffix, strlen(szPreffix));
    OutputDebugStringA(szFormattedError);
}

/*****************************************************************************/
bool AnalyzeFile(char* szFilePath)
{//Returns true if it is a malware file
    //First open the IPC objects
    HANDLE hMapFile = OpenFileMappingW(FILE_MAP_WRITE, FALSE, MemoryMappedFileName);
    if (!hMapFile) {
        return false;
    }
    void* pBuf = MapViewOfFile(hMapFile, FILE_MAP_ALL_ACCESS, 0, 0, MemoryMappedFileCapacity);
    if (!pBuf) {
        CloseHandle(hMapFile);
        return false;
    }
    //Write the path to the shared memory that will be used by the server
    char szMemoryToWrite[2048];
    sprintf_s(szMemoryToWrite, "%s|", szFilePath); //So | indicates the end of the string
    memcpy(pBuf, szMemoryToWrite, strlen(szMemoryToWrite) + 1);
    HANDLE hEvent = OpenEventW(EVENT_MODIFY_STATE, FALSE, EventName);
    if (!hEvent) {
        UnmapViewOfFile(pBuf);
        CloseHandle(hMapFile);
        return false;
    }
    //Awake server so it can scan it
    SetEvent(hEvent);
    HANDLE hEventResponse = OpenEventW(EVENT_ALL_ACCESS, FALSE, EventResponseName);
    if (!hEventResponse) {
        UnmapViewOfFile(pBuf);
        CloseHandle(hMapFile);
        CloseHandle(hEvent);
        return false;
    }
    //Now wait for the server answer
    WaitForSingleObject(hEventResponse, INFINITE);
    char* szAnswer = ReadAnswerFromSharedMemory(hMapFile);
    bool bIsAMalware = false;
    if (_stricmp(szAnswer, "MALWARE") == 0) {
        bIsAMalware = true;
    }
    else {
        bIsAMalware = false;
    }
    //Release IPC
    ResetEvent(hEventResponse);
    UnmapViewOfFile(pBuf);
    CloseHandle(hMapFile);
    CloseHandle(hEvent);
    CloseHandle(hEventResponse);
    return bIsAMalware;
}

/*****************************************************************************/
char* ReadAnswerFromSharedMemory(HANDLE hMapFile) {
    try {
        void* pBuf = MapViewOfFile(hMapFile, FILE_MAP_ALL_ACCESS, 0, 0, MemoryMappedFileCapacity);
        if (!pBuf) {
            return NULL;
        }
        char* szToRet = NULL;
        szToRet = _strdup((char*)pBuf);
        UnmapViewOfFile(pBuf);
        return szToRet;
    }
    catch (...) {
        return NULL;
    }
}
