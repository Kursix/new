#pragma once
#include "Utils.hpp"
#include <string>
#include <vector>
#include <thread>
#include <atomic>
#include <set>
#include <unordered_map>
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
    struct MonitorStats {
        int detections = 0;
        int blocked = 0;
        int advancedScans = 0;
    };

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
    void AddProcessExclusion(const std::wstring& processName);
    void SetScanIntervals(int processMs, int networkMs);
    void RequestOneShotScan();
    MonitorStats GetStats() const;

    struct MemoryFinding {
        std::string family;
        std::string pattern;
        std::string snippet;
        Severity severity;
    };

private:
    void FileWatchThread();
    void ProcessScanThread();
    void NetworkScanThread();
    bool ScanProcessMemoryAdvanced(DWORD pid, std::vector<MemoryFinding>& findings, size_t maxFindings);
    void AnalyzeAndAlertFindings(DWORD pid, const std::wstring& exeName, const std::vector<MemoryFinding>& findings);
    Severity EscalateSeverityFromFindingSet(const std::vector<MemoryFinding>& findings) const;
    std::string BuildFindingSummary(const std::vector<MemoryFinding>& findings, size_t maxItems) const;
    DWORD GetProcessUsingFile(const std::wstring& filePath);
    bool IsBrowserProcess(const std::wstring& processName);
    bool IsSuspiciousProcessName(const std::wstring& processName);
    bool IsTrustedSystemProcess(const std::wstring& processName, const std::wstring& processPath);
    bool IsExplicitlyExcluded(const std::wstring& processName);
    bool ShouldThrottleDetection(DWORD pid, const std::string& key, int cooldownMs);
    std::string WideToUtf8(const std::wstring& in);

    std::atomic<bool> running{ false };
    std::thread watchThread;
    std::thread processThread;
    std::thread networkThread;
    std::vector<std::wstring> watchPaths;
    std::set<std::wstring> monitoredFiles;
    std::set<DWORD> alertedPids;
    std::mutex alertedPidsMutex;
    std::unordered_map<std::string, ULONGLONG> detectionCooldowns;
    std::mutex cooldownMutex;
    std::set<std::wstring> excludedProcessNames;
    std::mutex exclusionMutex;
    std::atomic<int> processScanIntervalMs{ 1500 };
    std::atomic<int> networkScanIntervalMs{ 2200 };
    std::atomic<bool> oneShotScanRequested{ false };
    std::atomic<int> totalDetections{ 0 };
    std::atomic<int> totalBlocked{ 0 };
    std::atomic<int> totalAdvancedScans{ 0 };
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
