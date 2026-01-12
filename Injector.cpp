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

static string GetDirFromPath(const char* path) {
    if (!path) {
        return ".\\";
    }
    string p(path);
    size_t pos = p.find_last_of("\\/");
    if (pos == string::npos) {
        return ".\\";
    }
    return p.substr(0, pos + 1);
}

BOOL InjectDLL(DWORD processId, const char* dllPath, const char* dllDir) {
    DWORD attrs = GetFileAttributesA(dllPath);
    if (attrs == INVALID_FILE_ATTRIBUTES || (attrs & FILE_ATTRIBUTE_DIRECTORY)) {
        cerr << "DLL not found: " << dllPath << endl;
        return FALSE;
    }
    WIN32_FILE_ATTRIBUTE_DATA fad = {};
    if (GetFileAttributesExA(dllPath, GetFileExInfoStandard, &fad)) {
        ULONGLONG size = (static_cast<ULONGLONG>(fad.nFileSizeHigh) << 32) | fad.nFileSizeLow;
        cout << "DLL size: " << size << " bytes" << endl;
    }

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
    LPVOID pSetDllDirectory = reinterpret_cast<LPVOID>(
        GetProcAddress(hKernel32, "SetDllDirectoryA"));
    LPVOID pLoadLibrary = reinterpret_cast<LPVOID>(
        GetProcAddress(hKernel32, "LoadLibraryA"));
    if (!pSetDllDirectory) {
        cerr << "GetProcAddress(SetDllDirectoryA) failed. Error: " << GetLastError() << endl;
    }
    if (!pLoadLibrary) {
        cerr << "GetProcAddress(LoadLibraryA) failed. Error: " << GetLastError() << endl;
        VirtualFreeEx(hProcess, pRemotePath, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return FALSE;
    }

    if (pSetDllDirectory && dllDir && dllDir[0]) {
        const size_t dirLen = strlen(dllDir) + 1;
        LPVOID pRemoteDir = VirtualAllocEx(hProcess, NULL, dirLen, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!pRemoteDir) {
            cerr << "VirtualAllocEx(dir) failed. Error: " << GetLastError() << endl;
        } else if (!WriteProcessMemory(hProcess, pRemoteDir, dllDir, dirLen, NULL)) {
            cerr << "WriteProcessMemory(dir) failed. Error: " << GetLastError() << endl;
            VirtualFreeEx(hProcess, pRemoteDir, 0, MEM_RELEASE);
            pRemoteDir = nullptr;
        } else {
            HANDLE hDirThread = CreateRemoteThread(hProcess, NULL, 0,
                                                   (LPTHREAD_START_ROUTINE)pSetDllDirectory,
                                                   pRemoteDir, 0, NULL);
            if (!hDirThread) {
                cerr << "CreateRemoteThread(SetDllDirectoryA) failed. Error: " << GetLastError() << endl;
            } else {
                WaitForSingleObject(hDirThread, INFINITE);
                DWORD dirExit = 0;
                if (!GetExitCodeThread(hDirThread, &dirExit) || dirExit == 0) {
                    cerr << "SetDllDirectoryA failed in target process." << endl;
                } else {
                    cout << "SetDllDirectoryA OK: " << dllDir << endl;
                }
                CloseHandle(hDirThread);
            }
            VirtualFreeEx(hProcess, pRemoteDir, 0, MEM_RELEASE);
        }
    }

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

    DWORD exitCode = 0;
    if (!GetExitCodeThread(hThread, &exitCode) || exitCode == 0) {
        cerr << "LoadLibraryA failed in target process." << endl;
        VirtualFreeEx(hProcess, pRemotePath, 0, MEM_RELEASE);
        CloseHandle(hThread);
        CloseHandle(hProcess);
        return FALSE;
    }
    
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

    // 获取 DLL 完整路径（支持传参指定）
    const char* inputPath = "DumpDll.dll";
    if (argc > 1 && argv[1] && argv[1][0]) {
        inputPath = argv[1];
    }
    char dllPath[MAX_PATH];
    GetFullPathNameA(inputPath, MAX_PATH, dllPath, NULL);
    
    cout << "DLL Path: " << dllPath << endl;
    cout << "Injecting..." << endl;

    const string dllDir = GetDirFromPath(dllPath);
    cout << "DLL Dir: " << dllDir << endl;

    if (InjectDLL(pid, dllPath, dllDir.c_str())) {
        cout << "Injection successful!" << endl;
        cout << "DLLs will be dumped to current directory." << endl;
    } else {
        cout << "Injection failed!" << endl;
    }

    system("pause");
    return 0;
}
