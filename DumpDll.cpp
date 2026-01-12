#include <windows.h>
#include <string>
#include <fstream>
#include "MinHook.h"

using namespace std;

const string Dump_Path = "D:\\browndust2_dump\\";

void Log(const string& msg) {
    ofstream logFile(Dump_Path + "log.txt", ios::app);
    logFile << msg << endl;
    logFile.close();
}

// Hook mono_image_open_from_data_with_name
typedef void* (WINAPI* ptrMonoImageOpen)(const void*, unsigned int, int, void*, int, const char*);
ptrMonoImageOpen oriMonoImageOpen;

void* WINAPI my_mono_image_open_from_data_with_name(
    const void* data,
    unsigned int data_len,
    int need_copy,
    void* status,
    int refonly,
    const char* name)
{
    if (name) {
        string str_name = name;
        Log("Loading: " + str_name);

        // Dump Assembly-CSharp.dll
        if (str_name.find("Assembly-CSharp.dll") != string::npos) {
            string path = Dump_Path + "Assembly-CSharp.dll";
            HANDLE hFile = CreateFileA(path.c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
            if (hFile != INVALID_HANDLE_VALUE) {
                DWORD written;
                WriteFile(hFile, data, data_len, &written, NULL);
                CloseHandle(hFile);
                Log("Dumped Assembly-CSharp.dll (" + to_string(data_len) + " bytes)");
            }
        }
        // 也可以 dump 其他 DLL
        else if (str_name.find("Assembly-CSharp-firstpass.dll") != string::npos) {
            string path = Dump_Path + "Assembly-CSharp-firstpass.dll";
            HANDLE hFile = CreateFileA(path.c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
            if (hFile != INVALID_HANDLE_VALUE) {
                DWORD written;
                WriteFile(hFile, data, data_len, &written, NULL);
                CloseHandle(hFile);
                Log("Dumped Assembly-CSharp-firstpass.dll");
            }
        }
    }

    return oriMonoImageOpen(data, data_len, need_copy, status, refonly, name);
}

void OnMonoLoad() {
    Log("mono-2.0-bdwgc.dll loaded!");

    // 获取 mono_image_open_from_data_with_name 地址
    HMODULE hMono = GetModuleHandleA("mono-2.0-bdwgc.dll");
    if (!hMono) {
        Log("Failed to get mono-2.0-bdwgc.dll handle");
        return;
    }

    PVOID funcAddr = reinterpret_cast<PVOID>(
        GetProcAddress(hMono, "mono_image_open_from_data_with_name"));
    if (!funcAddr) {
        Log("Failed to get mono_image_open_from_data_with_name address");
        return;
    }

    char buf[256];
    sprintf_s(buf, "mono_image_open_from_data_with_name = 0x%p", funcAddr);
    Log(buf);

    // 创建 Hook
    if (MH_CreateHook(funcAddr, reinterpret_cast<LPVOID>(my_mono_image_open_from_data_with_name),
                      reinterpret_cast<LPVOID*>(&oriMonoImageOpen)) != MH_OK) {
        Log("MH_CreateHook failed");
        return;
    }

    if (MH_EnableHook(funcAddr) != MH_OK) {
        Log("MH_EnableHook failed");
        return;
    }

    Log("Hook mono_image_open_from_data_with_name success!");
}

// Hook LoadLibraryExW 来检测 mono-2.0-bdwgc.dll 加载
typedef HMODULE(WINAPI* ptrLoadLibraryExW)(LPCWSTR, HANDLE, DWORD);
ptrLoadLibraryExW oriLoadLibraryExW;

HMODULE WINAPI MyLoadLibraryExW(LPCWSTR lpLibFileName, HANDLE hFile, DWORD dwFlags) {
    if (lpLibFileName) {
        wstring wstr(lpLibFileName);
        string str(wstr.begin(), wstr.end());
        
        // 检测 mono-2.0-bdwgc.dll 加载
        if (str.find("mono-2.0-bdwgc.dll") != string::npos) {
            HMODULE res = oriLoadLibraryExW(lpLibFileName, hFile, dwFlags);
            OnMonoLoad();
            return res;
        }
    }
    
    return oriLoadLibraryExW(lpLibFileName, hFile, dwFlags);
}

BOOL HookLoadLibrary() {
    PVOID LoadLibraryAddr = reinterpret_cast<PVOID>(
        GetProcAddress(GetModuleHandleA("KernelBase.dll"), "LoadLibraryExW"));
    if (!LoadLibraryAddr) {
        Log("Failed to get LoadLibraryExW address");
        return FALSE;
    }

    if (MH_CreateHook(LoadLibraryAddr, reinterpret_cast<LPVOID>(MyLoadLibraryExW),
                      reinterpret_cast<LPVOID*>(&oriLoadLibraryExW)) != MH_OK) {
        Log("MH_CreateHook LoadLibraryExW failed");
        return FALSE;
    }

    if (MH_EnableHook(LoadLibraryAddr) != MH_OK) {
        Log("MH_EnableHook LoadLibraryExW failed");
        return FALSE;
    }

    Log("Hook LoadLibraryExW success!");
    return TRUE;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hModule);
        
        // 创建输出目录
        CreateDirectoryA(Dump_Path.c_str(), NULL);
        
        // 初始化 MinHook
        if (MH_Initialize() != MH_OK) {
            Log("MH_Initialize failed");
            return FALSE;
        }
        
        Log("DLL Injected!");
        
        // Hook LoadLibrary
        if (!HookLoadLibrary()) {
            Log("HookLoadLibrary failed");
            return FALSE;
        }
        
        break;
        
    case DLL_PROCESS_DETACH:
        MH_Uninitialize();
        break;
    }
    return TRUE;
}
