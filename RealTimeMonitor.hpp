#pragma once
#include "Utils.hpp"
#include <string>
#include <vector>
#include <thread>
#include <atomic>
#include <set>
#include <psapi.h>
#include <winternl.h>

struct DetectionEvent {
    std::string category;
    std::string message;
    std::string evidence;
    Severity severity;
    int riskPercent;
    DWORD pid;
    std::string processName;
};

class RealTimeMonitor {
public:
    RealTimeMonitor();
    ~RealTimeMonitor();
    void Start();
    void Stop();
    bool IsRunning() const { return running; }

    bool enableBlocking = false; // toggled from UI

    // Alert – definition comes from main.cpp (UI hook)
    void Alert(const std::string& category, const std::string& msg, const std::string& evidence, Severity s);

    // Extended alert with PID (used internally by monitoring threads)
    void AlertWithPID(DWORD pid, const std::string& category, const std::string& msg, const std::string& evidence, Severity s);

    // Blocking action
    void BlockProcess(DWORD pid);

    // Webhook scanner (memory scan)
    bool ScanProcessMemoryForWebhook(DWORD pid, std::string& foundUrl);

private:
    void FileWatchThread();
    void ProcessScanThread();
    DWORD GetProcessUsingFile(const std::wstring& filePath);
    bool IsBrowserProcess(const std::wstring& processName);
    bool IsSuspiciousProcessName(const std::wstring& processName);
    std::string WideToUtf8(const std::wstring& in);

    std::atomic<bool> running{ false };
    std::thread watchThread;
    std::thread processThread;
    std::vector<std::wstring> watchPaths;
    std::set<std::wstring> monitoredFiles;
    std::set<DWORD> alertedPids;
    std::mutex alertedPidsMutex;
};

// NtQuerySystemInformation / NtQueryObject helpers
typedef NTSTATUS(NTAPI* _NtQuerySystemInformation)(
    ULONG SystemInformationClass, PVOID SystemInformation,
    ULONG SystemInformationLength, PULONG ReturnLength);
typedef NTSTATUS(NTAPI* _NtQueryObject)(
    HANDLE Handle, ULONG ObjectInformationClass,
    PVOID ObjectInformation, ULONG ObjectInformationLength,
    PULONG ReturnLength);

struct SYSTEM_HANDLE_TABLE_ENTRY_INFO {
    ULONG ProcessId;
    BYTE ObjectTypeNumber;
    BYTE Flags;
    USHORT Handle;
    PVOID Object;
    ACCESS_MASK GrantedAccess;
};