#include <windows.h>
#include <string>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <cstring>
#include <map>
#include "MinHook.h"

static std::string g_dumpDir;
static CRITICAL_SECTION g_logLock;
static CRITICAL_SECTION g_dumpLock;
static volatile LONG g_callCount = 0;

// 用a1作为流标识
struct StreamInfo {
    unsigned int id;
    std::string path;
    HANDLE hFile;
    long long first_offset;
    long long last_offset;
    long long min_offset;
    long long max_offset;
    size_t total_bytes;
    size_t chunk_count;
    bool has_mz;
    bool has_bsjb;
    bool has_name;
};

static std::map<void*, StreamInfo> g_streams;  // key = a1
static unsigned int g_streamIndex = 0;

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
    
    if (offset < 0) return ok;
    
    // 用a1作为流标识！
    void* streamKey = a1;
    
    const bool hitName = ContainsAscii(buf, size, "Assembly-CSharp");
    const bool hitBSJB = ContainsAscii(buf, size, "BSJB");
    const bool hitMZ = IsMZHeader(buf, size);
    
    const LONG callIndex = InterlockedIncrement(&g_callCount);
    
    EnterCriticalSection(&g_dumpLock);
    
    // 查找或创建流
    auto it = g_streams.find(streamKey);
    if (it == g_streams.end()) {
        StreamInfo info = {};
        info.id = ++g_streamIndex;
        info.path = g_dumpDir + "stream_" + std::to_string(info.id) + ".bin";
        info.hFile = CreateFileA(info.path.c_str(), GENERIC_WRITE, FILE_SHARE_READ,
                                 nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        info.first_offset = offset;
        info.last_offset = -1;
        info.min_offset = offset;
        info.max_offset = offset;
        info.total_bytes = 0;
        info.chunk_count = 0;
        info.has_mz = false;
        info.has_bsjb = false;
        info.has_name = false;
        
        it = g_streams.emplace(streamKey, info).first;
        
        std::ostringstream oss;
        oss << "NEW STREAM #" << info.id << " a1=" << streamKey << " first_offset=" << offset;
        Log(oss.str());
    }
    
    StreamInfo& stream = it->second;
    
    // 更新签名
    if (hitMZ) stream.has_mz = true;
    if (hitBSJB) stream.has_bsjb = true;
    if (hitName) stream.has_name = true;
    
    // 更新offset范围
    if (offset < stream.min_offset) stream.min_offset = offset;
    if (offset > stream.max_offset) stream.max_offset = offset;
    
    // 写入文件（使用相对于min_offset的位置）
    if (stream.hFile != INVALID_HANDLE_VALUE) {
        long long write_offset = offset - stream.min_offset;
        
        LARGE_INTEGER li;
        li.QuadPart = write_offset;
        SetFilePointerEx(stream.hFile, li, nullptr, FILE_BEGIN);
        
        DWORD written = 0;
        WriteFile(stream.hFile, buf, static_cast<DWORD>(size), &written, nullptr);
        
        stream.total_bytes += written;
        stream.chunk_count++;
    }
    
    stream.last_offset = offset;
    
    // 日志
    if (callIndex <= 50 || hitName || hitBSJB || hitMZ || 
        (stream.has_name && stream.chunk_count % 1000 == 0)) {
        std::ostringstream oss;
        oss << "#" << callIndex
            << " stream#" << stream.id
            << " off=" << offset
            << " sz=" << size
            << " chunks=" << stream.chunk_count
            << " total=" << stream.total_bytes
            << " range=[" << stream.min_offset << "," << stream.max_offset << "]";
        if (hitMZ) oss << " [MZ]";
        if (hitBSJB) oss << " [BSJB]";
        if (hitName) oss << " [NAME]";
        Log(oss.str());
    }
    
    LeaveCriticalSection(&g_dumpLock);
    
    return ok;
}

static void PrintFinalStatus() {
    Log("\n=== FINAL STREAM STATUS ===");
    Log("Looking for: ~62.5MB file with Assembly-CSharp + BSJB");
    Log("");
    
    StreamInfo* bestMatch = nullptr;
    int bestScore = 0;
    
    for (auto& kv : g_streams) {
        StreamInfo& s = kv.second;
        
        // 计算文件大小（基于offset范围）
        long long fileSize = s.max_offset - s.min_offset + 7168;  // 估算
        
        // 评分
        int score = 0;
        if (s.has_name) score += 100;
        if (s.has_bsjb) score += 50;
        if (s.has_mz) score += 10;
        if (fileSize >= 50000000 && fileSize <= 80000000) score += 200;  // 大小匹配
        
        std::ostringstream oss;
        oss << "Stream #" << s.id
            << " | score=" << score
            << " | size~" << (fileSize / 1024 / 1024) << "MB"
            << " | chunks=" << s.chunk_count
            << " | MZ=" << s.has_mz
            << " | BSJB=" << s.has_bsjb
            << " | NAME=" << s.has_name
            << " | range=[" << s.min_offset << "," << s.max_offset << "]";
        Log(oss.str());
        
        if (score > bestScore) {
            bestScore = score;
            bestMatch = &s;
        }
    }
    
    if (bestMatch && bestScore >= 150) {
        Log("");
        Log("*** BEST MATCH: Stream #" + std::to_string(bestMatch->id) + " ***");
        
        // 关闭并重命名
        if (bestMatch->hFile != INVALID_HANDLE_VALUE) {
            FlushFileBuffers(bestMatch->hFile);
            CloseHandle(bestMatch->hFile);
            bestMatch->hFile = INVALID_HANDLE_VALUE;
        }
        
        std::string newName = g_dumpDir + "Assembly-CSharp_DUMPED.dll";
        DeleteFileA(newName.c_str());
        if (MoveFileA(bestMatch->path.c_str(), newName.c_str())) {
            Log("Renamed to: " + newName);
        }
    } else {
        Log("");
        Log("No confident match found. Check streams manually.");
    }
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
    
    Log("=== DumpDecrypt v6 - Using a1 as stream key ===");
    
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
    
    // 定期报告
    while (true) {
        Sleep(15000);
        EnterCriticalSection(&g_dumpLock);
        
        std::ostringstream status;
        status << "STATUS: " << g_streams.size() << " streams, " << g_callCount << " calls";
        Log(status.str());
        
        for (auto& kv : g_streams) {
            StreamInfo& s = kv.second;
            if (s.has_name || s.has_bsjb || s.total_bytes > 10000000) {
                std::ostringstream oss;
                oss << "  #" << s.id << ": " << (s.total_bytes/1024/1024) << "MB"
                    << " chunks=" << s.chunk_count
                    << " NAME=" << s.has_name
                    << " BSJB=" << s.has_bsjb;
                Log(oss.str());
            }
        }
        
        LeaveCriticalSection(&g_dumpLock);
    }
    
    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);
        g_dumpDir = GetModuleDir(hModule);
        g_callCount = 0;
        g_streamIndex = 0;
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
        
        PrintFinalStatus();
        
        // 关闭所有文件
        for (auto& kv : g_streams) {
            if (kv.second.hFile != INVALID_HANDLE_VALUE) {
                FlushFileBuffers(kv.second.hFile);
                CloseHandle(kv.second.hFile);
            }
        }
        
        LeaveCriticalSection(&g_dumpLock);
        
        MH_Uninitialize();
        DeleteCriticalSection(&g_logLock);
        DeleteCriticalSection(&g_dumpLock);
    }
    return TRUE;
}
