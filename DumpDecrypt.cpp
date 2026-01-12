#include <windows.h>
#include <string>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <cstring>
#include "MinHook.h"

static std::string g_dumpRoot;
static std::string g_dumpDir;

static CRITICAL_SECTION g_logLock;
static CRITICAL_SECTION g_dumpLock;
static volatile LONG g_dumpedAssembly = 0;
static void* g_activeKey = nullptr;
static volatile LONG g_callCount = 0;

static std::string GetModuleDir(HMODULE module) {
    char path[MAX_PATH] = {};
    const DWORD len = GetModuleFileNameA(module, path, MAX_PATH);
    if (len == 0 || len >= MAX_PATH) {
        return ".\\";
    }
    std::string full(path);
    const size_t pos = full.find_last_of("\\/");
    if (pos == std::string::npos) {
        return ".\\";
    }
    return full.substr(0, pos + 1);
}

static void Log(const std::string& msg) {
    EnterCriticalSection(&g_logLock);
    const std::string dir = g_dumpDir.empty() ? ".\\" : g_dumpDir;
    std::ofstream logFile(dir + "decrypt_log.txt", std::ios::app);
    if (!logFile.is_open()) {
        OutputDebugStringA(("Log open failed: " + dir + "decrypt_log.txt\n").c_str());
        LeaveCriticalSection(&g_logLock);
        return;
    }
    logFile << msg << std::endl;
    LeaveCriticalSection(&g_logLock);
}

static void EnsureDumpDir() {
    if (!g_dumpRoot.empty()) {
        CreateDirectoryA(g_dumpRoot.c_str(), nullptr);
    }
    if (!g_dumpDir.empty()) {
        CreateDirectoryA(g_dumpDir.c_str(), nullptr);
    }
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

static void DumpChunkAtOffset(const std::string& path, long long offset, const void* data, size_t size) {
    if (!data || size == 0) {
        return;
    }
    HANDLE hFile = CreateFileA(path.c_str(), GENERIC_WRITE, 0, nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) {
        Log("Open dump file failed: " + path);
        return;
    }
    LARGE_INTEGER li;
    li.QuadPart = offset;
    if (offset >= 0) {
        SetFilePointerEx(hFile, li, nullptr, FILE_BEGIN);
    } else {
        SetFilePointerEx(hFile, li, nullptr, FILE_END);
    }
    DWORD written = 0;
    const BOOL ok = WriteFile(hFile, data, static_cast<DWORD>(size), &written, nullptr);
    CloseHandle(hFile);
    if (!ok || written != static_cast<DWORD>(size)) {
        Log("Write dump chunk failed");
    }
}

static std::string GetDumpPath() {
    const std::string dir = g_dumpDir.empty() ? ".\\" : g_dumpDir;
    return dir + "Assembly-CSharp.dll";
}

static void StartDump(void* streamKey, long long offset, size_t size, const char* reason) {
    if (InterlockedCompareExchange(&g_dumpedAssembly, 1, 0) != 0) {
        return;
    }
    const std::string path = GetDumpPath();
    DeleteFileA(path.c_str());
    g_activeKey = streamKey;
    std::ostringstream oss;
    oss << "Start dump Assembly-CSharp.dll offset=" << offset << " size=" << size << " reason=" << reason;
    Log(oss.str());
}

static void StopDump(const char* reason) {
    std::ostringstream oss;
    oss << "Stop dump: " << reason;
    Log(oss.str());
}

using FnSub69FE00 = bool(*)(void* a1, long long* a2, long long a3, void* a4, unsigned long long* a5, long long a6);
using FnSub6A2590 = long long(*)(void* a1, unsigned int* a2, size_t n, unsigned long long* out_read);

static FnSub69FE00 g_origSub69FE00 = nullptr;
static FnSub6A2590 g_origSub6A2590 = nullptr;

static bool __fastcall HookSub69FE00(void* a1, long long* a2, long long a3, void* a4, unsigned long long* a5, long long a6) {
    const bool ok = g_origSub69FE00(a1, a2, a3, a4, a5, a6);
    const unsigned long long readSize = (a5 ? *a5 : 0);
    if (ok && a4 && readSize > 0) {
        const size_t scan = std::min<size_t>(static_cast<size_t>(readSize), 2 * 1024 * 1024);
        const unsigned char* buf = static_cast<const unsigned char*>(a4);
        const bool hitName = ContainsAscii(buf, scan, "Assembly-CSharp");
        const bool hitBSJB = ContainsAscii(buf, scan, "BSJB");
        const bool hitMZ = (readSize >= 2 && buf[0] == 'M' && buf[1] == 'Z');
        const long long offset = (a2 ? *a2 : -1);
        void* key = reinterpret_cast<void*>(a2);

        const LONG callIndex = InterlockedIncrement(&g_callCount);
        if (callIndex <= 50) {
            std::ostringstream oss;
            oss << "sub_18069FE00 call#" << callIndex
                << " key=" << key
                << " a1=" << a1
                << " offset=" << offset
                << " size=" << readSize
                << " hitName=" << hitName
                << " hitBSJB=" << hitBSJB
                << " hitMZ=" << hitMZ;
            Log(oss.str());
        }

        EnterCriticalSection(&g_dumpLock);
        if (!g_activeKey) {
            if (hitName) {
                StartDump(key, offset, static_cast<size_t>(readSize), "name");
            } else if (hitBSJB) {
                StartDump(key, offset, static_cast<size_t>(readSize), "bsjb");
            } else if (hitMZ) {
                StartDump(key, offset, static_cast<size_t>(readSize), "mz");
            }
        }
        if (g_activeKey == key) {
            const std::string path = GetDumpPath();
            DumpChunkAtOffset(path, offset, a4, static_cast<size_t>(readSize));
            std::ostringstream oss;
            oss << "Chunk offset=" << offset << " size=" << readSize;
            Log(oss.str());
        }
        LeaveCriticalSection(&g_dumpLock);
    } else if (!ok || (a5 && *a5 == 0)) {
        EnterCriticalSection(&g_dumpLock);
        if (g_activeKey == a2) {
            g_activeKey = nullptr;
            StopDump("eof");
        }
        LeaveCriticalSection(&g_dumpLock);
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
            const size_t scan = std::min<size_t>(readable, 2 * 1024 * 1024);
            if (ContainsAscii(buf, scan, "Assembly-CSharp")) {
                std::ostringstream oss;
                oss << "Hit Assembly-CSharp in sub_1806A2590 size=" << readable;
                Log(oss.str());
            }
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
    Log("Log path: " + (g_dumpDir.empty() ? std::string(".\\decrypt_log.txt") : g_dumpDir + "decrypt_log.txt"));

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
        g_dumpRoot = GetModuleDir(hModule);
        g_dumpDir = g_dumpRoot;
        g_dumpedAssembly = 0;
        g_activeKey = nullptr;
        g_callCount = 0;
        InitializeCriticalSection(&g_logLock);
        InitializeCriticalSection(&g_dumpLock);
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
        DeleteCriticalSection(&g_dumpLock);
    }
    return TRUE;
}
