#include "RealTimeMonitor.hpp"
#include <filesystem>
#include <algorithm>
#include <vector>
#include <unordered_set>
#include <array>
#include <sstream>
#include <cstring>
#include <tlhelp32.h>
#pragma comment(lib, "ntdll.lib")

namespace fs = std::filesystem;

namespace {
    struct PatternDefinition {
        const char* family;
        const char* token;
        Severity severity;
    };

    std::vector<PatternDefinition> BuildPatternDefinitions() {
        return {
            {"webhook", "discord.com/api/webhooks", Severity::CRITICAL},
            {"webhook", "discordapp.com/api/webhooks", Severity::CRITICAL},
            {"webhook", "canary.discord.com/api/webhooks", Severity::CRITICAL},
            {"webhook", "api.telegram.org/bot", Severity::CRITICAL},
            {"webhook", "hooks.slack.com/services", Severity::HIGH},
            {"network_recon", "api.ipify.org", Severity::HIGH},
            {"network_recon", "ifconfig.me", Severity::HIGH},
            {"network_recon", "icanhazip.com", Severity::HIGH},
            {"dpapi", "CryptUnprotectData", Severity::CRITICAL},
            {"dpapi", "Local State", Severity::HIGH},
            {"browser_db", "\\User Data\\Default\\Login Data", Severity::HIGH},
            {"browser_db", "\\User Data\\Default\\Cookies", Severity::HIGH},
            {"discord_tokens", "\\Discord\\Local Storage\\leveldb", Severity::HIGH},
            {"wallet", "\\AppData\\Roaming\\Exodus", Severity::HIGH},
            {"wallet", "\\AppData\\Roaming\\Electrum", Severity::HIGH},
            {"telegram", "\\Telegram Desktop\\tdata", Severity::HIGH},
            {"anti_analysis", "IsDebuggerPresent", Severity::MEDIUM},
            {"anti_analysis", "CheckRemoteDebuggerPresent", Severity::MEDIUM},
            {"anti_analysis", "NtSetInformationThread", Severity::MEDIUM},
            {"anti_analysis", "ThreadHideFromDebugger", Severity::MEDIUM},
            {"anti_analysis", "VMware Tools", Severity::MEDIUM},
            {"anti_analysis", "VirtualBox Guest Additions", Severity::MEDIUM},
            {"anti_analysis", "qemu-ga.exe", Severity::MEDIUM},
            {"anti_analysis", "getmac", Severity::LOW},
            {"archive", "passwords.txt", Severity::HIGH},
            {"archive", "cookies.txt", Severity::HIGH},
            {"archive", "discord_tokens.txt", Severity::HIGH},
            {"archive", "wallets/", Severity::HIGH},
            {"archive", "login_data_", Severity::HIGH},
            {"archive", "cookies_", Severity::HIGH},
            {"archive", "history_", Severity::MEDIUM},
            {"archive", ".zip", Severity::MEDIUM},
            {"network_upload", "multipart/form-data", Severity::CRITICAL},
            {"network_upload", "Content-Disposition: form-data", Severity::CRITICAL},
            {"network_upload", "POST /api/webhooks", Severity::CRITICAL},
            {"persistence", "Software\\Microsoft\\Windows\\CurrentVersion\\Run", Severity::HIGH},
            {"persistence", "WindowsUpdate", Severity::MEDIUM},
            {"persistence", "Start Menu\\Programs\\Startup", Severity::HIGH},
            {"persistence", "__EventFilter", Severity::HIGH},
            {"persistence", "CommandLineEventConsumer", Severity::HIGH},
            {"persistence", "__FilterToConsumerBinding", Severity::HIGH},
            {"memory_patch", "AmsiScanBuffer", Severity::CRITICAL},
            {"memory_patch", "EtwEventWrite", Severity::CRITICAL},
            {"rat", "AsyncRAT", Severity::CRITICAL},
            {"rat", "njRAT", Severity::CRITICAL},
            {"rat", "QuasarRAT", Severity::CRITICAL},
            {"rat", "Remcos", Severity::CRITICAL},
            {"rat", "DarkComet", Severity::CRITICAL},
            {"rat", "reverse_tcp", Severity::HIGH},
            {"rat", "meterpreter", Severity::CRITICAL}
        };
    }

    std::string ExtractSnippet(const std::string& src, size_t center, size_t around) {
        if (src.empty()) return "";
        size_t start = (center > around) ? center - around : 0;
        size_t end = std::min(src.size(), center + around);
        std::string sub = src.substr(start, end - start);
        for (char& c : sub) {
            unsigned char uc = static_cast<unsigned char>(c);
            if (uc < 32 || uc > 126) c = ' ';
        }
        return sub;
    }
}

RealTimeMonitor::RealTimeMonitor() {
    const DWORD selfPid = GetCurrentProcessId();
    alertedPids.insert(selfPid);

    std::wstring localAppData = _wgetenv(L"LOCALAPPDATA");
    watchPaths.push_back(localAppData + L"\\Google\\Chrome\\User Data");
    watchPaths.push_back(localAppData + L"\\Microsoft\\Edge\\User Data");
    watchPaths.push_back(localAppData + L"\\BraveSoftware\\Brave-Browser\\User Data");
    watchPaths.push_back(_wgetenv(L"APPDATA") + std::wstring(L"\\Discord\\Local Storage\\leveldb"));

    monitoredFiles.insert(L"Login Data");
    monitoredFiles.insert(L"Cookies");
    monitoredFiles.insert(L"Network\\Cookies");
    monitoredFiles.insert(L"*.ldb");

    // default false-positive suppressions for common local toolchain executables
    AddProcessExclusion(L"vcpkg.exe");
    AddProcessExclusion(L"cmake.exe");
    AddProcessExclusion(L"ninja.exe");
    AddProcessExclusion(L"cl.exe");
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
    totalDetections.fetch_add(1);
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
            totalBlocked.fetch_add(1);
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
        "hooks.slack.com/services",
        "api.ipify.org",
        "ifconfig.me",
        "icanhazip.com"
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

bool RealTimeMonitor::ScanProcessMemoryAdvanced(DWORD pid, std::vector<MemoryFinding>& findings, size_t maxFindings) {
    totalAdvancedScans.fetch_add(1);
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProcess) return false;

    static const std::vector<PatternDefinition> defs = BuildPatternDefinitions();
    std::unordered_set<std::string> dedupe;
    MEMORY_BASIC_INFORMATION mbi;
    BYTE* addr = 0;
    bool anyFinding = false;

    while (VirtualQueryEx(hProcess, addr, &mbi, sizeof(mbi))) {
        if (mbi.State == MEM_COMMIT &&
            (mbi.Type == MEM_PRIVATE || mbi.Type == MEM_MAPPED) &&
            (mbi.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE))) {
            std::vector<BYTE> buffer(mbi.RegionSize);
            SIZE_T bytesRead = 0;
            if (ReadProcessMemory(hProcess, addr, buffer.data(), mbi.RegionSize, &bytesRead) && bytesRead > 0) {
                std::string region(reinterpret_cast<const char*>(buffer.data()), bytesRead);
                for (const auto& def : defs) {
                    size_t pos = 0;
                    while ((pos = region.find(def.token, pos)) != std::string::npos) {
                        std::string key = std::string(def.family) + "|" + def.token;
                        if (dedupe.insert(key).second) {
                            MemoryFinding f;
                            f.family = def.family;
                            f.pattern = def.token;
                            f.severity = def.severity;
                            f.snippet = ExtractSnippet(region, pos, 80);
                            findings.push_back(std::move(f));
                            anyFinding = true;
                            if (findings.size() >= maxFindings) {
                                CloseHandle(hProcess);
                                return true;
                            }
                        }
                        pos += strlen(def.token);
                    }
                }
            }
        }
        addr += mbi.RegionSize;
    }

    CloseHandle(hProcess);
    return anyFinding;
}

Severity RealTimeMonitor::EscalateSeverityFromFindingSet(const std::vector<MemoryFinding>& findings) const {
    int score = 0;
    bool hasWebhook = false;
    bool hasBrowserDb = false;
    bool hasDpapi = false;

    for (const auto& f : findings) {
        if (f.severity == Severity::CRITICAL) score += 5;
        else if (f.severity == Severity::HIGH) score += 3;
        else if (f.severity == Severity::MEDIUM) score += 2;
        else score += 1;

        hasWebhook |= (f.family == "webhook");
        hasBrowserDb |= (f.family == "browser_db");
        hasDpapi |= (f.family == "dpapi");
    }

    if (hasWebhook && (hasBrowserDb || hasDpapi)) return Severity::CRITICAL;
    if (score >= 10) return Severity::CRITICAL;
    if (score >= 6) return Severity::HIGH;
    if (score >= 3) return Severity::MEDIUM;
    return Severity::LOW;
}

std::string RealTimeMonitor::BuildFindingSummary(const std::vector<MemoryFinding>& findings, size_t maxItems) const {
    std::ostringstream out;
    size_t emitted = 0;
    for (const auto& f : findings) {
        if (emitted >= maxItems) break;
        if (emitted > 0) out << " || ";
        out << "[" << f.family << "] " << f.pattern;
        if (!f.snippet.empty()) out << " {" << f.snippet << "}";
        emitted++;
    }
    if (findings.size() > maxItems) {
        out << " || +" << (findings.size() - maxItems) << " more";
    }
    return out.str();
}

void RealTimeMonitor::AnalyzeAndAlertFindings(DWORD pid, const std::wstring& exeName, const std::vector<MemoryFinding>& findings) {
    if (findings.empty()) return;
    Severity sev = EscalateSeverityFromFindingSet(findings);
    std::string summary = BuildFindingSummary(findings, 4);
    std::string evidence = "PID: " + std::to_string(pid) + " Process: " + WideToUtf8(exeName) + " | " + summary;

    std::string message = "Multi-signal memory indicators detected";
    if (sev == Severity::CRITICAL) {
        message = "Critical memory indicator correlation detected (possible credential theft + exfil)";
    }
    else if (sev == Severity::HIGH) {
        message = "High-confidence suspicious in-memory patterns detected";
    }

    AlertWithPID(pid, "Advanced Memory Scan", message, evidence, sev);
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

void RealTimeMonitor::AddProcessExclusion(const std::wstring& processName) {
    if (processName.empty()) return;
    std::wstring lower = processName;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::towlower);
    std::lock_guard<std::mutex> guard(exclusionMutex);
    excludedProcessNames.insert(lower);
}

bool RealTimeMonitor::IsExplicitlyExcluded(const std::wstring& processName) {
    std::wstring lower = processName;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::towlower);
    std::lock_guard<std::mutex> guard(exclusionMutex);
    return excludedProcessNames.find(lower) != excludedProcessNames.end();
}

void RealTimeMonitor::SetScanIntervals(int processMs, int networkMs) {
    processScanIntervalMs.store(std::clamp(processMs, 400, 10000));
    networkScanIntervalMs.store(std::clamp(networkMs, 600, 15000));
}

void RealTimeMonitor::RequestOneShotScan() {
    oneShotScanRequested.store(true);
}

RealTimeMonitor::MonitorStats RealTimeMonitor::GetStats() const {
    MonitorStats s;
    s.detections = totalDetections.load();
    s.blocked = totalBlocked.load();
    s.advancedScans = totalAdvancedScans.load();
    return s;
}

void RealTimeMonitor::FileWatchThread() {
    DebugLog("File watch thread started");
    for (const auto& dir : watchPaths) {
        if (!fs::exists(dir)) {
            DebugLog("Watch path does not exist: " + WideToUtf8(dir));
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
            DebugLog("Failed to open directory: " + WideToUtf8(dir));
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
                                if (pid == GetCurrentProcessId()) {
                                    continue;
                                }
                                HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
                                if (hProc) {
                                    WCHAR procName[MAX_PATH] = { 0 };
                                    DWORD size = MAX_PATH;
                                    if (QueryFullProcessImageNameW(hProc, 0, procName, &size)) {
                                        std::wstring exeName = fs::path(procName).filename().wstring();
                                        std::string evidence = "PID: " + std::to_string(pid) + " Process: " + WideToUtf8(exeName);
                                        if (!IsBrowserProcess(exeName) && !IsTrustedSystemProcess(exeName, procName) && !IsExplicitlyExcluded(exeName)) {
                                            std::string webhook;
                                            if (ScanProcessMemoryForWebhook(pid, webhook)) {
                                                if (!ShouldThrottleDetection(pid, "webhook_mem", 7000)) {
                                                    AlertWithPID(pid, "Webhook Found", "Process contains webhook URL snippet", evidence + " | " + webhook, Severity::CRITICAL);
                                                }
                                            }
                                            else {
                                                if (!ShouldThrottleDetection(pid, "sensitive_file", 4000)) {
                                                    AlertWithPID(pid, "Real-Time File Access", "Non-browser process accessed sensitive file: " + WideToUtf8(fileName), evidence, Severity::HIGH);
                                                }
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
        bool forcePass = oneShotScanRequested.exchange(false);
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32W pe;
            pe.dwSize = sizeof(PROCESSENTRY32W);
            if (Process32FirstW(snap, &pe)) {
                do {
                    if (pe.th32ProcessID <= 4) continue;
                    if (pe.th32ProcessID == GetCurrentProcessId()) continue;
                    if (IsExplicitlyExcluded(pe.szExeFile)) continue;
                    if (!forcePass && !IsSuspiciousProcessName(pe.szExeFile)) continue;

                    HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe.th32ProcessID);
                    if (!hProc) continue;
                    WCHAR procPath[MAX_PATH] = { 0 };
                    DWORD size = MAX_PATH;
                    bool hasPath = QueryFullProcessImageNameW(hProc, 0, procPath, &size) != 0;
                    CloseHandle(hProc);
                    if (hasPath && IsTrustedSystemProcess(pe.szExeFile, procPath)) continue;

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

                    std::vector<MemoryFinding> findings;
                    if (ScanProcessMemoryAdvanced(pe.th32ProcessID, findings, 8) && !ShouldThrottleDetection(pe.th32ProcessID, "advanced_mem_name", 18000)) {
                        AnalyzeAndAlertFindings(pe.th32ProcessID, pe.szExeFile, findings);
                    }
                } while (Process32NextW(snap, &pe));
            }
            CloseHandle(snap);
        }
        Sleep(processScanIntervalMs.load());
    }
}

void RealTimeMonitor::NetworkScanThread() {
    while (running) {
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32W pe;
            pe.dwSize = sizeof(PROCESSENTRY32W);
            if (Process32FirstW(snap, &pe)) {
                do {
                    if (pe.th32ProcessID <= 4) continue;
                    if (pe.th32ProcessID == GetCurrentProcessId()) continue;
                    if (IsExplicitlyExcluded(pe.szExeFile)) continue;

                    HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe.th32ProcessID);
                    if (!hProc) continue;

                    WCHAR procPath[MAX_PATH] = { 0 };
                    DWORD size = MAX_PATH;
                    bool okPath = QueryFullProcessImageNameW(hProc, 0, procPath, &size) != 0;
                    CloseHandle(hProc);
                    if (!okPath) continue;

                    std::wstring exeName = fs::path(procPath).filename().wstring();
                    if (IsTrustedSystemProcess(exeName, procPath)) continue;

                    std::string webhook;
                    if (ScanProcessMemoryForWebhook(pe.th32ProcessID, webhook) && !ShouldThrottleDetection(pe.th32ProcessID, "network_signal", 10000)) {
                        bool likelyPost = webhook.find("POST") != std::string::npos || webhook.find("multipart") != std::string::npos;
                        Severity sev = likelyPost ? Severity::CRITICAL : Severity::HIGH;
                        std::string msg = likelyPost
                            ? "Webhook indicator found with upload context (possible POST exfil)"
                            : "Webhook or external IP lookup indicator found in memory";
                        std::string evidence = "PID: " + std::to_string(pe.th32ProcessID) + " Process: " + WideToUtf8(exeName) + " | " + webhook;
                        AlertWithPID(pe.th32ProcessID, "Network Indicator", msg, evidence, sev);

                        MessageBeep(MB_ICONWARNING);
                        if (sev == Severity::CRITICAL && !ShouldThrottleDetection(pe.th32ProcessID, "connection_prompt", 30000)) {
                            std::wstring prompt = L"Ratt1fy detected a potentially unsafe outbound connection by " + exeName +
                                L".\nAllow this connection process to continue?\nChoose NO to block the process.";
                            int res = MessageBoxW(nullptr, prompt.c_str(), L"Ratt1fy Connection Safety Prompt", MB_YESNO | MB_ICONWARNING | MB_SYSTEMMODAL);
                            if (res == IDNO) {
                                AlertWithPID(pe.th32ProcessID, "Connection Blocked", "User denied risky connection from prompt", WideToUtf8(exeName), Severity::CRITICAL);
                                BlockProcess(pe.th32ProcessID);
                            }
                        }
                    }

                    std::vector<MemoryFinding> findings;
                    if (ScanProcessMemoryAdvanced(pe.th32ProcessID, findings, 10) && !ShouldThrottleDetection(pe.th32ProcessID, "advanced_mem_net", 22000)) {
                        AnalyzeAndAlertFindings(pe.th32ProcessID, exeName, findings);
                    }
                } while (Process32NextW(snap, &pe));
            }
            CloseHandle(snap);
        }
        Sleep(networkScanIntervalMs.load());
    }
}

void RealTimeMonitor::Start() {
    if (running) return;
    running = true;
    watchThread = std::thread(&RealTimeMonitor::FileWatchThread, this);
    processThread = std::thread(&RealTimeMonitor::ProcessScanThread, this);
    networkThread = std::thread(&RealTimeMonitor::NetworkScanThread, this);
}

void RealTimeMonitor::Stop() {
    running = false;
    if (watchThread.joinable()) watchThread.join();
    if (processThread.joinable()) processThread.join();
    if (networkThread.joinable()) networkThread.join();
}

RealTimeMonitor::~RealTimeMonitor() {
    Stop();
}

bool RealTimeMonitor::IsTrustedSystemProcess(const std::wstring& processName, const std::wstring& processPath) {
    static const std::set<std::wstring> trustedNames = {
        L"svchost.exe", L"services.exe", L"lsass.exe", L"wininit.exe", L"csrss.exe", L"smss.exe", L"dwm.exe"
    };

    std::wstring nameLower = processName;
    std::wstring pathLower = processPath;
    std::transform(nameLower.begin(), nameLower.end(), nameLower.begin(), ::towlower);
    std::transform(pathLower.begin(), pathLower.end(), pathLower.begin(), ::towlower);

    if (trustedNames.count(nameLower) == 0) return false;
    return pathLower.find(L"\\windows\\system32\\") != std::wstring::npos ||
        pathLower.find(L"\\windows\\syswow64\\") != std::wstring::npos;
}

bool RealTimeMonitor::ShouldThrottleDetection(DWORD pid, const std::string& key, int cooldownMs) {
    std::string token = std::to_string(pid) + ":" + key;
    ULONGLONG now = GetTickCount64();

    std::lock_guard<std::mutex> guard(cooldownMutex);
    auto it = detectionCooldowns.find(token);
    if (it != detectionCooldowns.end() && (now - it->second) < static_cast<ULONGLONG>(cooldownMs)) {
        return true;
    }
    detectionCooldowns[token] = now;
    return false;
}
