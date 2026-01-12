#include <windows.h>
#include <string>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <cstring>
#include <map>
#include <set>
#include "MinHook.h"

static std::string g_dumpDir;
static CRITICAL_SECTION g_logLock;
static CRITICAL_SECTION g_dumpLock;
static volatile LONG g_callCount = 0;

// 全局dump - 所有数据写入同一个文件
static std::string g_dumpPath;
static HANDLE g_dumpFile = INVALID_HANDLE_VALUE;
static std::set<long long> g_writtenOffsets;
static long long g_maxOffset = 0;
static size_t g_totalBytes = 0;

// 签名追踪
static bool g_foundName = false;
static bool g_foundBSJB = false;
static long long g_nameOffset = -1;
static long long g_bsjbOffset = -1;

static std::string GetModuleDir(HMODULE module) {
    char path[MAX_PATH] = {};
    DWORD len = GetModuleFileNameA(module, path, MAX_PATH);
    if (len == 0 || len >= MAX_PATH) return ".\\";
    std::string full(path);
    size_t pos = full.find_last_of("\\/");
    return (pos == std::string::npos) ? ".\\" : full.substr(0, pos + 1);
}

static void Log(const std::string& msg) {
    EnterCriticalSection(&g_logLock);
    std::ofstream logFile(g_dumpDir + "decrypt_log.txt", std::ios::app);
    if (logFile.is_open()) {
        logFile << msg << std::endl;
    }
    LeaveCriticalSection(&g_logLock);
}

static void EnsureDumpDir() {
    if (!g_dumpDir.empty()) {
        CreateDirectoryA(g_dumpDir.c_str(), nullptr);
    }
}

static bool ContainsAscii(const unsigned char* data, size_t size, const char* needle) {
    size_t needle_len = std::strlen(needle);
    if (!data || size < needle_len) return false;
    for (size_t i = 0; i + needle_len <= size; ++i) {
        if (std::memcmp(data + i, needle, needle_len) == 0) {
            return true;
        }
    }
    return false;
}

static bool IsMZHeader(const unsigned char* data, size_t size) {
    return size >= 64 && data[0] == 'M' && data[1] == 'Z';
}

using FnSub69FE00 = bool(*)(void* a1, long long* a2, long long a3, void* a4, unsigned long long* a5, long long a6);
static FnSub69FE00 g_origSub69FE00 = nullptr;

static bool __fastcall HookSub69FE00(void* a1, long long* a2, long long a3, void* a4, unsigned long long* a5, long long a6) {
    const bool ok = g_origSub69FE00(a1, a2, a3, a4, a5, a6);
    const unsigned long long readSize = (a5 ? *a5 : 0);
    
    if (!ok || !a4 || readSize == 0) {
        return ok;
    }
    
    const unsigned char* buf = static_cast<const unsigned char*>(a4);
    const size_t size = static_cast<size_t>(readSize);
    const long long offset = (a2 ? *a2 : -1);
    
    if (offset < 0 || offset > 200 * 1024 * 1024) {  // 忽略超过200MB的offset
        return ok;
    }
    
    const bool hitName = ContainsAscii(buf, size, "Assembly-CSharp");
    const bool hitBSJB = ContainsAscii(buf, size, "BSJB");
    const bool hitMZ = IsMZHeader(buf, size);
    
    const LONG callIndex = InterlockedIncrement(&g_callCount);
    
    EnterCriticalSection(&g_dumpLock);
    
    // 记录签名位置
    if (hitName && !g_foundName) {
        g_foundName = true;
        g_nameOffset = offset;
        Log("*** Found Assembly-CSharp at offset " + std::to_string(offset));
    }
    if (hitBSJB && !g_foundBSJB) {
        g_foundBSJB = true;
        g_bsjbOffset = offset;
        Log("*** Found BSJB at offset " + std::to_string(offset));
    }
    
    // 只有发现签名后才开始dump
    if (g_foundName || g_foundBSJB || hitName || hitBSJB) {
        // 检查是否已写入此offset
        if (g_writtenOffsets.find(offset) == g_writtenOffsets.end()) {
            if (g_dumpFile != INVALID_HANDLE_VALUE) {
                LARGE_INTEGER li;
                li.QuadPart = offset;
                SetFilePointerEx(g_dumpFile, li, nullptr, FILE_BEGIN);
                
                DWORD written = 0;
                WriteFile(g_dumpFile, buf, static_cast<DWORD>(size), &written, nullptr);
                
                g_writtenOffsets.insert(offset);
                g_totalBytes += written;
                
                if (offset + static_cast<long long>(size) > g_maxOffset) {
                    g_maxOffset = offset + static_cast<long long>(size);
                }
            }
        }
    }
    
    // 日志
    bool shouldLog = (callIndex <= 50) || hitName || hitBSJB || hitMZ;
    if (g_foundName && callIndex % 500 == 0) shouldLog = true;  // 每500次记录一次
    
    if (shouldLog) {
        std::ostringstream oss;
        oss << "#" << callIndex
            << " a1=" << a1
            << " off=" << offset
            << " sz=" << size
            << " total=" << g_totalBytes
            << " max=" << g_maxOffset
            << " chunks=" << g_writtenOffsets.size();
        if (hitMZ) oss << " [MZ]";
        if (hitBSJB) oss << " [BSJB]";
        if (hitName) oss << " [NAME]";
        Log(oss.str());
    }
    
    LeaveCriticalSection(&g_dumpLock);
    
    return ok;
}

static bool InstallHook(void* target, void* detour, void** original, const char* name) {
    if (MH_CreateHook(target, detour, reinterpret_cast<LPVOID*>(original)) != MH_OK) {
        Log(std::string("MH_CreateHook failed: ") + name);
        return false;
    }
    if (MH_EnableHook(target) != MH_OK) {
        Log(std::string("MH_EnableHook failed: ") + name);
        return false;
    }
    Log(std::string("Hooked: ") + name);
    return true;
}

static DWORD WINAPI HookThread(LPVOID) {
    EnsureDumpDir();
    
    g_dumpPath = g_dumpDir + "Assembly-CSharp_DUMP.dll";
    DeleteFileA(g_dumpPath.c_str());
    
    g_dumpFile = CreateFileA(g_dumpPath.c_str(), GENERIC_WRITE, FILE_SHARE_READ,
                             nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    
    if (g_dumpFile == INVALID_HANDLE_VALUE) {
        Log("Failed to create dump file!");
        return 0;
    }
    
    Log("=== DumpDecrypt v7 - Global Accumulation ===");
    Log("Output: " + g_dumpPath);
    Log("Target: ~62.5MB Assembly-CSharp.dll");
    
    HMODULE unity = nullptr;
    for (int i = 0; i < 120; ++i) {
        unity = GetModuleHandleA("UnityPlayer.dll");
        if (unity) break;
        Sleep(500);
    }
    
    if (!unity) {
        Log("UnityPlayer.dll not loaded");
        return 0;
    }
    
    const uintptr_t base = reinterpret_cast<uintptr_t>(unity);
    
    std::ostringstream oss;
    oss << "UnityPlayer.dll base = 0x" << std::hex << base;
    Log(oss.str());
    
    void* addr69fe00 = reinterpret_cast<void*>(base + 0x69FE00);
    
    InstallHook(addr69fe00, reinterpret_cast<void*>(&HookSub69FE00),
                reinterpret_cast<void**>(&g_origSub69FE00), "sub_18069FE00");
    
    // 监控进度
    size_t lastTotal = 0;
    int stableCount = 0;
    
    while (true) {
        Sleep(5000);
        
        EnterCriticalSection(&g_dumpLock);
        
        double sizeMB = g_totalBytes / (1024.0 * 1024.0);
        double maxMB = g_maxOffset / (1024.0 * 1024.0);
        double coverage = (g_maxOffset > 0) ? (100.0 * g_totalBytes / g_maxOffset) : 0;
        
        std::ostringstream status;
        status << "STATUS: "
               << sizeMB << "MB written, "
               << maxMB << "MB max, "
               << coverage << "% coverage, "
               << g_writtenOffsets.size() << " chunks, "
               << "NAME=" << g_foundName << " BSJB=" << g_foundBSJB;
        Log(status.str());
        
        // 检查是否完成
        if (g_totalBytes == lastTotal && g_totalBytes > 0) {
            stableCount++;
            if (stableCount >= 6) {  // 30秒无新数据
                Log("=== DUMP APPEARS COMPLETE ===");
                
                if (g_totalBytes >= 50000000 && g_totalBytes <= 80000000) {
                    Log("*** Size matches Assembly-CSharp.dll! ***");
                }
                
                stableCount = 0;
            }
        } else {
            stableCount = 0;
        }
        lastTotal = g_totalBytes;
        
        LeaveCriticalSection(&g_dumpLock);
    }
    
    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);
        g_dumpDir = GetModuleDir(hModule);
        g_callCount = 0;
        g_totalBytes = 0;
        g_maxOffset = 0;
        g_foundName = false;
        g_foundBSJB = false;
        g_nameOffset = -1;
        g_bsjbOffset = -1;
        InitializeCriticalSection(&g_logLock);
        InitializeCriticalSection(&g_dumpLock);
        EnsureDumpDir();
        
        if (MH_Initialize() != MH_OK) {
            Log("MH_Initialize failed");
            return FALSE;
        }
        
        HANDLE thread = CreateThread(nullptr, 0, HookThread, nullptr, 0, nullptr);
        if (thread) CloseHandle(thread);
        
    } else if (reason == DLL_PROCESS_DETACH) {
        EnterCriticalSection(&g_dumpLock);
        
        if (g_dumpFile != INVALID_HANDLE_VALUE) {
            FlushFileBuffers(g_dumpFile);
            CloseHandle(g_dumpFile);
            g_dumpFile = INVALID_HANDLE_VALUE;
        }
        
        std::ostringstream final_log;
        final_log << "\n=== FINAL RESULT ===" << std::endl
                  << "Total: " << g_totalBytes << " bytes (" << (g_totalBytes/1024/1024) << " MB)" << std::endl
                  << "Max offset: " << g_maxOffset << std::endl
                  << "Chunks: " << g_writtenOffsets.size() << std::endl
                  << "NAME found: " << g_foundName << " at " << g_nameOffset << std::endl
                  << "BSJB found: " << g_foundBSJB << " at " << g_bsjbOffset << std::endl
                  << "Output: " << g_dumpPath;
        Log(final_log.str());
        
        LeaveCriticalSection(&g_dumpLock);
        
        MH_Uninitialize();
        DeleteCriticalSection(&g_logLock);
        DeleteCriticalSection(&g_dumpLock);
    }
    return TRUE;
}
