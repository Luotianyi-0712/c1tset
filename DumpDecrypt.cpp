#include <windows.h>
#include <string>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <cstring>
#include <unordered_map>
#include "MinHook.h"

static std::string g_dumpRoot;
static std::string g_dumpDir;

static CRITICAL_SECTION g_logLock;
static CRITICAL_SECTION g_dumpLock;
static volatile LONG g_callCount = 0;
static bool g_foundAssembly = false;

struct StreamState {
    std::string path;
    long long last_offset;
    bool confirmed;
};

static std::unordered_map<void*, StreamState> g_streams;
static unsigned int g_streamIndex = 0;

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

static std::string MakeTempPath(unsigned int index) {
    const std::string dir = g_dumpDir.empty() ? ".\\" : g_dumpDir;
    return dir + "Assembly-CSharp.tmp." + std::to_string(index);
}

static std::string MakeFinalPath(unsigned int index) {
    if (!g_foundAssembly) {
        return GetDumpPath();
    }
    const std::string dir = g_dumpDir.empty() ? ".\\" : g_dumpDir;
    return dir + "Assembly-CSharp_" + std::to_string(index) + ".dll";
}

static void FinalizeStream(StreamState& state, unsigned int index, const char* reason) {
    std::ostringstream oss;
    if (state.confirmed) {
        const std::string finalPath = MakeFinalPath(index);
        MoveFileExA(state.path.c_str(), finalPath.c_str(), MOVEFILE_REPLACE_EXISTING);
        g_foundAssembly = true;
        oss << "Finalize dump: " << finalPath << " reason=" << reason;
    } else {
        DeleteFileA(state.path.c_str());
        oss << "Discard dump (no signature) reason=" << reason;
    }
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
        auto it = g_streams.find(key);
        if (it == g_streams.end()) {
            StreamState state;
            state.path = MakeTempPath(++g_streamIndex);
            state.last_offset = -1;
            state.confirmed = false;
            it = g_streams.emplace(key, state).first;
            std::ostringstream created;
            created << "Create stream key=" << key << " path=" << it->second.path;
            Log(created.str());
        }

        StreamState& state = it->second;
        if (state.last_offset >= 0 && offset < state.last_offset) {
            FinalizeStream(state, g_streamIndex, "offset-reset");
            state.path = MakeTempPath(++g_streamIndex);
            state.last_offset = -1;
            state.confirmed = false;
            std::ostringstream restarted;
            restarted << "Restart stream key=" << key << " path=" << state.path;
            Log(restarted.str());
        } else if (state.last_offset > 0 && offset == 0) {
            FinalizeStream(state, g_streamIndex, "offset-zero");
            state.path = MakeTempPath(++g_streamIndex);
            state.last_offset = -1;
            state.confirmed = false;
            std::ostringstream restarted;
            restarted << "Restart stream key=" << key << " path=" << state.path;
            Log(restarted.str());
        }

        DumpChunkAtOffset(state.path, offset, a4, static_cast<size_t>(readSize));
        state.last_offset = offset;

        if (!state.confirmed && (hitName || hitBSJB || hitMZ)) {
            state.confirmed = true;
            std::ostringstream confirm;
            confirm << "Confirmed stream key=" << key
                    << " name=" << hitName
                    << " bsjb=" << hitBSJB
                    << " mz=" << hitMZ;
            Log(confirm.str());
        }

        std::ostringstream chunk;
        chunk << "Chunk key=" << key << " offset=" << offset << " size=" << readSize;
        Log(chunk.str());
        LeaveCriticalSection(&g_dumpLock);
    } else if (!ok || (a5 && *a5 == 0)) {
        EnterCriticalSection(&g_dumpLock);
        auto it = g_streams.find(a2);
        if (it != g_streams.end()) {
            FinalizeStream(it->second, g_streamIndex, "eof");
            g_streams.erase(it);
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
        g_callCount = 0;
        g_foundAssembly = false;
        g_streamIndex = 0;
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
