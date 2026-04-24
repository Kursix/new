#include "Utils.hpp"

std::mutex logMutex;
bool debugMode = false;

void SetConsoleColor(WORD color) {
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), color);
}

void PrintSeverity(Severity s, const std::string& msg) {
    WORD color;
    const char* tag;
    switch (s) {
    case Severity::INFO:    color = 7; tag = "[*] "; break;
    case Severity::LOW:     color = 6; tag = "[!] "; break;
    case Severity::MEDIUM:  color = 14;tag = "[#] "; break;
    case Severity::HIGH:    color = 12;tag = "[!!]"; break;
    case Severity::CRITICAL:color = 207;tag = "[CRIT]"; break;
    }
    SetConsoleColor(color);
    std::cout << tag << msg;
    SetConsoleColor(7);
    std::cout << std::endl;
}

std::string NowString() {
    auto t = std::time(nullptr);
    char buf[30];
    struct tm timeinfo;
    localtime_s(&timeinfo, &t);
    strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &timeinfo);
    return buf;
}

void LogDetection(const std::string& category, const std::string& msg, const std::string& evidence, Severity s) {
    std::lock_guard<std::mutex> lock(logMutex);
    std::ofstream log("detections.log", std::ios::app);
    if (log) {
        log << "[" << NowString() << "] "
            << "[" << category << "] "
            << msg << " | Evidence: " << evidence << std::endl;
        log.close();
    }

    WORD color;
    const char* tag;
    switch (s) {
    case Severity::INFO:    color = 7; tag = "[*] "; break;
    case Severity::LOW:     color = 6; tag = "[!] "; break;
    case Severity::MEDIUM:  color = 14;tag = "[#] "; break;
    case Severity::HIGH:    color = 12;tag = "[!!]"; break;
    case Severity::CRITICAL:color = 207;tag = "[CRIT]"; break;
    }

    SetConsoleColor(color);
    std::cout << tag << msg << " (logged)";
    SetConsoleColor(7);
    std::cout << std::endl;
}

void DebugLog(const std::string& msg) {
    if (!debugMode) return;
    std::lock_guard<std::mutex> lock(logMutex);
    SetConsoleColor(8);
    std::cout << "[DEBUG " << NowString() << "] " << msg << std::endl;
    SetConsoleColor(7);
}

void EnableDebug(bool enable) {
    debugMode = enable;
}