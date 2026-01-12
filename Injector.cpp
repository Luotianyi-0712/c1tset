#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <string>

using namespace std;

DWORD FindProcess(const wchar_t* processName) {
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) {
        return 0;
    }

    PROCESSENTRY32W pe32 = { sizeof(PROCESSENTRY32W) };
    BOOL ret = Process32FirstW(hSnap, &pe32);
    
    while (ret) {
        if (wcsstr(pe32.szExeFile, processName)) {
            CloseHandle(hSnap);
            wcout << L"Found process: " << pe32.szExeFile << L" (PID: " << pe32.th32ProcessID << L")" << endl;
            return pe32.th32ProcessID;
        }
        ret = Process32NextW(hSnap, &pe32);
    }
    
    CloseHandle(hSnap);
    return 0;
}

BOOL InjectDLL(DWORD processId, const char* dllPath) {
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
    if (!hProcess) {
        cerr << "Failed to open process. Error: " << GetLastError() << endl;
        return FALSE;
    }

    size_t pathLen = strlen(dllPath) + 1;
    LPVOID pRemotePath = VirtualAllocEx(hProcess, NULL, pathLen, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!pRemotePath) {
        cerr << "VirtualAllocEx failed. Error: " << GetLastError() << endl;
        CloseHandle(hProcess);
        return FALSE;
    }

    if (!WriteProcessMemory(hProcess, pRemotePath, dllPath, pathLen, NULL)) {
        cerr << "WriteProcessMemory failed. Error: " << GetLastError() << endl;
        VirtualFreeEx(hProcess, pRemotePath, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return FALSE;
    }

    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    LPVOID pLoadLibrary = reinterpret_cast<LPVOID>(
        GetProcAddress(hKernel32, "LoadLibraryA"));

    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, 
                                       (LPTHREAD_START_ROUTINE)pLoadLibrary, 
                                       pRemotePath, 0, NULL);
    if (!hThread) {
        cerr << "CreateRemoteThread failed. Error: " << GetLastError() << endl;
        VirtualFreeEx(hProcess, pRemotePath, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return FALSE;
    }

    WaitForSingleObject(hThread, INFINITE);
    
    VirtualFreeEx(hProcess, pRemotePath, 0, MEM_RELEASE);
    CloseHandle(hThread);
    CloseHandle(hProcess);
    
    return TRUE;
}

int main(int argc, char* argv[]) {
    cout << "BrownDust II DLL Dumper" << endl;
    cout << "=======================" << endl;

    // 查找游戏进程
    DWORD pid = FindProcess(L"BrownDust II.exe");
    
    if (!pid) {
        cout << "Game not found. Please start the game first." << endl;
        cout << "Waiting for game..." << endl;
        
        while (!pid) {
            Sleep(2000);
            pid = FindProcess(L"BrownDust II.exe");
        }
    }

    // 获取 DLL 完整路径
    char dllPath[MAX_PATH];
    GetFullPathNameA("DumpDll.dll", MAX_PATH, dllPath, NULL);
    
    cout << "DLL Path: " << dllPath << endl;
    cout << "Injecting..." << endl;

    if (InjectDLL(pid, dllPath)) {
        cout << "Injection successful!" << endl;
        cout << "DLLs will be dumped to D:\\browndust2_dump\\" << endl;
    } else {
        cout << "Injection failed!" << endl;
    }

    system("pause");
    return 0;
}

