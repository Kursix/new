#include "RealTimeMonitor.hpp"
#include <filesystem>
#include <algorithm>
#include <vector>
#include <tlhelp32.h>
#pragma comment(lib, "ntdll.lib")

namespace fs = std::filesystem;

RealTimeMonitor::RealTimeMonitor() {
    std::wstring localAppData = _wgetenv(L"LOCALAPPDATA");
    watchPaths.push_back(localAppData + L"\\Google\\Chrome\\User Data");
    watchPaths.push_back(localAppData + L"\\Microsoft\\Edge\\User Data");
    watchPaths.push_back(localAppData + L"\\BraveSoftware\\Brave-Browser\\User Data");
    watchPaths.push_back(_wgetenv(L"APPDATA") + std::wstring(L"\\Discord\\Local Storage\\leveldb"));

    monitoredFiles.insert(L"Login Data");
    monitoredFiles.insert(L"Cookies");
    monitoredFiles.insert(L"Network\\Cookies");
    monitoredFiles.insert(L"*.ldb");
}

std::string RealTimeMonitor::WideToUtf8(const std::wstring& in) {
    if (in.empty()) return "";
    int len = WideCharToMultiByte(CP_UTF8, 0, in.c_str(), -1, nullptr, 0, nullptr, nullptr);
    std::string out(len, '\0');
    WideCharToMultiByte(CP_UTF8, 0, in.c_str(), -1, out.data(), len, nullptr, nullptr);
    out.pop_back();
    return out;
}

void RealTimeMonitor::AlertWithPID(DWORD pid, const std::string& category, const std::string& msg, const std::string& evidence, Severity s) {
    Alert(category, msg, evidence, s);
    if (enableBlocking && static_cast<int>(s) >= static_cast<int>(Severity::HIGH)) {
        BlockProcess(pid);
    }
}

void RealTimeMonitor::BlockProcess(DWORD pid) {
    HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
    if (hProcess) {
        if (TerminateProcess(hProcess, 1)) {
            std::string msg = "Process (PID=" + std::to_string(pid) + ") terminated by StealerGuard.";
            LogDetection("Blocking", msg, "", Severity::CRITICAL);
        }
        CloseHandle(hProcess);
    }
}

bool RealTimeMonitor::ScanProcessMemoryForWebhook(DWORD pid, std::string& foundUrl) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProcess) return false;

    MEMORY_BASIC_INFORMATION mbi;
    BYTE* addr = 0;
    std::vector<std::string> patterns = {
        "discord.com/api/webhooks",
        "discordapp.com/api/webhooks",
        "canary.discord.com/api/webhooks",
        "api.telegram.org/bot",
        "hooks.slack.com/services"
    };

    while (VirtualQueryEx(hProcess, addr, &mbi, sizeof(mbi))) {
        if (mbi.State == MEM_COMMIT && (mbi.Type == MEM_PRIVATE) &&
            (mbi.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE))) {
            std::vector<BYTE> buffer(mbi.RegionSize);
            SIZE_T bytesRead;
            if (ReadProcessMemory(hProcess, addr, buffer.data(), mbi.RegionSize, &bytesRead) && bytesRead > 0) {
                std::string regionStr(buffer.begin(), buffer.begin() + bytesRead);
                for (const auto& pattern : patterns) {
                    size_t pos = regionStr.find(pattern);
                    if (pos != std::string::npos) {
                        size_t start = (pos > 30) ? pos - 30 : 0;
                        size_t end = min(pos + pattern.size() + 30, regionStr.size());
                        foundUrl = regionStr.substr(start, end - start);
                        CloseHandle(hProcess);
                        return true;
                    }
                }
            }
        }
        addr += mbi.RegionSize;
    }
    CloseHandle(hProcess);
    return false;
}

DWORD RealTimeMonitor::GetProcessUsingFile(const std::wstring& filePath) {
    static _NtQuerySystemInformation NtQuerySystemInformation =
        (_NtQuerySystemInformation)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQuerySystemInformation");
    static _NtQueryObject NtQueryObject =
        (_NtQueryObject)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryObject");
    if (!NtQuerySystemInformation || !NtQueryObject) return 0;

    ULONG bufSize = 0x100000;
    std::vector<BYTE> buffer(bufSize);
    ULONG returnLength;
    NTSTATUS status;
    while ((status = NtQuerySystemInformation(16, buffer.data(), bufSize, &returnLength)) == 0xC0000004) {
        bufSize *= 2;
        buffer.resize(bufSize);
    }
    if (status != 0) return 0;

    auto* handleInfo = reinterpret_cast<SYSTEM_HANDLE_TABLE_ENTRY_INFO*>(buffer.data() + sizeof(ULONG_PTR));
    ULONG count = *(ULONG*)buffer.data();

    for (ULONG i = 0; i < count; i++) {
        if (handleInfo[i].ProcessId == 0 || handleInfo[i].ProcessId == 4) continue;
        HANDLE hProc = OpenProcess(PROCESS_DUP_HANDLE, FALSE, handleInfo[i].ProcessId);
        if (!hProc) continue;
        HANDLE dupHandle = NULL;
        if (DuplicateHandle(hProc, (HANDLE)handleInfo[i].Handle, GetCurrentProcess(), &dupHandle, 0, FALSE, DUPLICATE_SAME_ACCESS)) {
            std::vector<BYTE> nameBuf(512);
            ULONG nameLen;
            status = NtQueryObject(dupHandle, 1, nameBuf.data(), (ULONG)nameBuf.size(), &nameLen);
            if (status == 0) {
                auto* nameInfo = reinterpret_cast<UNICODE_STRING*>(nameBuf.data());
                if (nameInfo->Buffer) {
                    std::wstring handleName(nameInfo->Buffer, nameInfo->Length / sizeof(WCHAR));
                    std::wstring upperPath = filePath;
                    std::transform(upperPath.begin(), upperPath.end(), upperPath.begin(), ::towupper);
                    std::wstring upperHandleName = handleName;
                    std::transform(upperHandleName.begin(), upperHandleName.end(), upperHandleName.begin(), ::towupper);
                    if (upperHandleName.find(upperPath) != std::wstring::npos) {
                        CloseHandle(dupHandle);
                        CloseHandle(hProc);
                        return handleInfo[i].ProcessId;
                    }
                }
            }
            CloseHandle(dupHandle);
        }
        CloseHandle(hProc);
    }
    return 0;
}

bool RealTimeMonitor::IsBrowserProcess(const std::wstring& processName) {
    static const std::set<std::wstring> browsers = {
        L"chrome.exe", L"msedge.exe", L"brave.exe", L"firefox.exe",
        L"opera.exe", L"iexplore.exe"
    };
    std::wstring lower = processName;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::towlower);
    return browsers.find(lower) != browsers.end();
}

bool RealTimeMonitor::IsSuspiciousProcessName(const std::wstring& processName) {
    static const std::vector<std::wstring> suspiciousPatterns = {
        L"stealer", L"grabber", L"token", L"clipper", L"injector", L"rat", L"keylog"
    };
    std::wstring lower = processName;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::towlower);

    for (const auto& pattern : suspiciousPatterns) {
        if (lower.find(pattern) != std::wstring::npos) {
            return true;
        }
    }
    return false;
}

void RealTimeMonitor::FileWatchThread() {
    DebugLog("File watch thread started");
    for (const auto& dir : watchPaths) {
        if (!fs::exists(dir)) {
            DebugLog("Watch path does not exist: " + std::string(dir.begin(), dir.end()));
            continue;
        }
        HANDLE hDir = CreateFileW(
            dir.c_str(),
            FILE_LIST_DIRECTORY,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            NULL, OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED,
            NULL
        );
        if (hDir == INVALID_HANDLE_VALUE) {
            DebugLog("Failed to open directory: " + std::string(dir.begin(), dir.end()));
            continue;
        }

        std::vector<BYTE> buffer(64 * 1024);
        OVERLAPPED overlapped = { 0 };
        overlapped.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);

        while (running) {
            DWORD bytesReturned;
            if (ReadDirectoryChangesW(
                hDir, buffer.data(), (DWORD)buffer.size(), TRUE,
                FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_LAST_WRITE | FILE_NOTIFY_CHANGE_LAST_ACCESS,
                &bytesReturned, &overlapped, NULL)) {
                DWORD wait = WaitForSingleObject(overlapped.hEvent, 100);
                if (wait == WAIT_OBJECT_0) {
                    auto* notify = reinterpret_cast<FILE_NOTIFY_INFORMATION*>(buffer.data());
                    do {
                        std::wstring fileName(notify->FileName, notify->FileNameLength / sizeof(WCHAR));
                        bool matched = false;
                        for (const auto& target : monitoredFiles) {
                            if (target == fileName || (target[0] == L'*' && fileName.size() >= 4 && fileName.substr(fileName.size() - 4) == L".ldb")) {
                                matched = true; break;
                            }
                            if (fileName.find(target) != std::wstring::npos) {
                                matched = true; break;
                            }
                        }
                        if (matched && notify->Action != FILE_ACTION_REMOVED) {
                            std::wstring fullPath = dir + L"\\" + fileName;
                            Sleep(80);
                            DWORD pid = GetProcessUsingFile(fullPath);
                            if (pid) {
                                HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
                                if (hProc) {
                                    WCHAR procName[MAX_PATH] = { 0 };
                                    DWORD size = MAX_PATH;
                                    if (QueryFullProcessImageNameW(hProc, 0, procName, &size)) {
                                        std::wstring exeName = fs::path(procName).filename().wstring();
                                        std::string evidence = "PID: " + std::to_string(pid) + " Process: " + WideToUtf8(exeName);
                                        if (!IsBrowserProcess(exeName)) {
                                            std::string webhook;
                                            if (ScanProcessMemoryForWebhook(pid, webhook)) {
                                                AlertWithPID(pid, "Webhook Found", "Process contains webhook URL snippet", evidence + " | " + webhook, Severity::CRITICAL);
                                            }
                                            else {
                                                AlertWithPID(pid, "Real-Time File Access", "Non-browser process accessed sensitive file: " + WideToUtf8(fileName), evidence, Severity::HIGH);
                                            }
                                        }
                                    }
                                    CloseHandle(hProc);
                                }
                            }
                            else {
                                Alert("Real-Time File Access", "Sensitive file accessed by unknown process: " + WideToUtf8(fileName), WideToUtf8(fullPath), Severity::MEDIUM);
                            }
                        }
                        notify = notify->NextEntryOffset ?
                            reinterpret_cast<FILE_NOTIFY_INFORMATION*>(reinterpret_cast<BYTE*>(notify) + notify->NextEntryOffset) : nullptr;
                    } while (notify);
                }
                ResetEvent(overlapped.hEvent);
            }
        }
        CloseHandle(overlapped.hEvent);
        CloseHandle(hDir);
    }
    DebugLog("File watch thread exiting");
}

void RealTimeMonitor::ProcessScanThread() {
    while (running) {
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32W pe;
            pe.dwSize = sizeof(PROCESSENTRY32W);
            if (Process32FirstW(snap, &pe)) {
                do {
                    if (pe.th32ProcessID <= 4) continue;
                    if (!IsSuspiciousProcessName(pe.szExeFile)) continue;

                    bool alreadyAlerted = false;
                    {
                        std::lock_guard<std::mutex> guard(alertedPidsMutex);
                        alreadyAlerted = alertedPids.count(pe.th32ProcessID) > 0;
                        if (!alreadyAlerted) alertedPids.insert(pe.th32ProcessID);
                    }
                    if (alreadyAlerted) continue;

                    std::string evidence = "PID: " + std::to_string(pe.th32ProcessID) + " Process: " + WideToUtf8(pe.szExeFile);
                    std::string webhook;
                    if (ScanProcessMemoryForWebhook(pe.th32ProcessID, webhook)) {
                        AlertWithPID(pe.th32ProcessID, "Webhook Found", "Suspicious process contains webhook pattern", evidence + " | " + webhook, Severity::CRITICAL);
                    }
                    else {
                        AlertWithPID(pe.th32ProcessID, "Suspicious Process", "Suspicious process name matched stealer pattern", evidence, Severity::HIGH);
                    }
                } while (Process32NextW(snap, &pe));
            }
            CloseHandle(snap);
        }
        Sleep(1500);
    }
}

void RealTimeMonitor::Start() {
    if (running) return;
    running = true;
    watchThread = std::thread(&RealTimeMonitor::FileWatchThread, this);
    processThread = std::thread(&RealTimeMonitor::ProcessScanThread, this);
}

void RealTimeMonitor::Stop() {
    running = false;
    if (watchThread.joinable()) watchThread.join();
    if (processThread.joinable()) processThread.join();
}

RealTimeMonitor::~RealTimeMonitor() {
    Stop();
}