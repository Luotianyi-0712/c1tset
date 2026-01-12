#include <windows.h>
#include <string>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <cstring>
#include "MinHook.h"

static const char* kDumpRoot = "D:\\browndust2_dump\\";
static const char* kDumpDir = "D:\\browndust2_dump\\decrypt\\";

static CRITICAL_SECTION g_logLock;
static volatile LONG g_dumpedAssembly = 0;

static void Log(const std::string& msg) {
    EnterCriticalSection(&g_logLock);
    std::ofstream logFile(std::string(kDumpDir) + "decrypt_log.txt", std::ios::app);
    logFile << msg << std::endl;
    LeaveCriticalSection(&g_logLock);
}

static void EnsureDumpDir() {
    CreateDirectoryA(kDumpRoot, nullptr);
    CreateDirectoryA(kDumpDir, nullptr);
}

static bool ContainsAscii(const unsigned char* data, size_t size, const char* needle) {
    const size_t needle_len = std::strlen(needle);
    if (!data || size < needle_len) {
        return false;
    }
    for (size_t i = 0; i + needle_len <= size; ++i) {
        if (std::memcmp(data + i, needle, needle_len) == 0) {
            return true;
        }
    }
    return false;
}

static size_t ClampReadable(const void* ptr, size_t len) {
    if (!ptr || len == 0) {
        return 0;
    }
    const unsigned char* cur = static_cast<const unsigned char*>(ptr);
    size_t total = 0;
    while (total < len) {
        MEMORY_BASIC_INFORMATION mbi;
        if (!VirtualQuery(cur, &mbi, sizeof(mbi))) {
            break;
        }
        if (mbi.State != MEM_COMMIT) {
            break;
        }
        if (mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)) {
            break;
        }
        const unsigned char* region_end =
            static_cast<const unsigned char*>(mbi.BaseAddress) + mbi.RegionSize;
        const size_t region_bytes = static_cast<size_t>(region_end - cur);
        const size_t step = std::min(region_bytes, len - total);
        total += step;
        cur += step;
    }
    return total;
}

static bool WriteFileBytes(const std::string& path, const void* data, size_t size) {
    if (!data || size == 0) {
        return false;
    }
    if (size > MAXDWORD) {
        size = MAXDWORD;
    }
    HANDLE hFile = CreateFileA(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) {
        return false;
    }
    DWORD written = 0;
    const BOOL ok = WriteFile(hFile, data, static_cast<DWORD>(size), &written, nullptr);
    CloseHandle(hFile);
    return ok && written == static_cast<DWORD>(size);
}

static void DumpAssemblyOnce(const char* tag, const unsigned char* data, size_t size) {
    if (!data || size == 0) {
        return;
    }
    const size_t scan = std::min<size_t>(size, 2 * 1024 * 1024);
    if (!ContainsAscii(data, scan, "Assembly-CSharp")) {
        return;
    }
    if (InterlockedCompareExchange(&g_dumpedAssembly, 1, 0) != 0) {
        return;
    }
    std::string path = std::string(kDumpDir) + "Assembly-CSharp.dll";
    if (WriteFileBytes(path, data, size)) {
        std::ostringstream oss;
        oss << "Dumped Assembly-CSharp.dll from " << tag << " (" << size << " bytes)";
        Log(oss.str());
    } else {
        InterlockedExchange(&g_dumpedAssembly, 0);
        std::ostringstream oss;
        oss << "Dump failed from " << tag << " (" << size << " bytes)";
        Log(oss.str());
    }
}

using FnSub69FE00 = bool(*)(void* a1, long long* a2, long long a3, void* a4, unsigned long long* a5, long long a6);
using FnSub6A2590 = long long(*)(void* a1, unsigned int* a2, size_t n, unsigned long long* out_read);

static FnSub69FE00 g_origSub69FE00 = nullptr;
static FnSub6A2590 g_origSub6A2590 = nullptr;

static bool __fastcall HookSub69FE00(void* a1, long long* a2, long long a3, void* a4, unsigned long long* a5, long long a6) {
    const bool ok = g_origSub69FE00(a1, a2, a3, a4, a5, a6);
    if (ok && a4 && a5 && *a5 > 0) {
        DumpAssemblyOnce("sub_18069FE00", static_cast<const unsigned char*>(a4), static_cast<size_t>(*a5));
    }
    return ok;
}

static long long __fastcall HookSub6A2590(void* a1, unsigned int* a2, size_t n, unsigned long long* out_read) {
    const long long ret = g_origSub6A2590(a1, a2, n, out_read);
    if (out_read && *out_read > 0 && a2) {
        const unsigned char* buf = *reinterpret_cast<const unsigned char* const*>(
            reinterpret_cast<const unsigned char*>(a2) + 8);
        const size_t readable = ClampReadable(buf, static_cast<size_t>(*out_read));
        if (readable > 0) {
            DumpAssemblyOnce("sub_1806A2590", buf, readable);
        }
    }
    return ret;
}

static bool InstallHook(void* target, void* detour, void** original, const char* name) {
    if (MH_CreateHook(target, detour, reinterpret_cast<LPVOID*>(original)) != MH_OK) {
        std::ostringstream oss;
        oss << "MH_CreateHook failed: " << name;
        Log(oss.str());
        return false;
    }
    if (MH_EnableHook(target) != MH_OK) {
        std::ostringstream oss;
        oss << "MH_EnableHook failed: " << name;
        Log(oss.str());
        return false;
    }
    std::ostringstream oss;
    oss << "Hooked: " << name;
    Log(oss.str());
    return true;
}

static DWORD WINAPI HookThread(LPVOID) {
    EnsureDumpDir();
    Log("DumpDecrypt injected");

    HMODULE unity = nullptr;
    for (int i = 0; i < 120; ++i) {
        unity = GetModuleHandleA("UnityPlayer.dll");
        if (unity) {
            break;
        }
        Sleep(500);
    }
    if (!unity) {
        Log("UnityPlayer.dll not loaded");
        return 0;
    }

    const uintptr_t base = reinterpret_cast<uintptr_t>(unity);
    void* addr69fe00 = reinterpret_cast<void*>(base + 0x69FE00);
    void* addr6a2590 = reinterpret_cast<void*>(base + 0x6A2590);

    {
        std::ostringstream oss;
        oss << "UnityPlayer.dll base = 0x" << std::hex << base;
        Log(oss.str());
    }

    InstallHook(addr69fe00, reinterpret_cast<void*>(&HookSub69FE00),
                reinterpret_cast<void**>(&g_origSub69FE00), "sub_18069FE00");
    InstallHook(addr6a2590, reinterpret_cast<void*>(&HookSub6A2590),
                reinterpret_cast<void**>(&g_origSub6A2590), "sub_1806A2590");

    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);
        InitializeCriticalSection(&g_logLock);
        EnsureDumpDir();
        if (MH_Initialize() != MH_OK) {
            Log("MH_Initialize failed");
            return FALSE;
        }
        HANDLE thread = CreateThread(nullptr, 0, HookThread, nullptr, 0, nullptr);
        if (thread) {
            CloseHandle(thread);
        }
    } else if (reason == DLL_PROCESS_DETACH) {
        MH_Uninitialize();
        DeleteCriticalSection(&g_logLock);
    }
    return TRUE;
}
