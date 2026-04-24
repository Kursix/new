#pragma once
#include <windows.h>
#include <iostream>
#include <string>
#include <fstream>
#include <ctime>
#include <sstream>
#include <iomanip>
#include <mutex>

enum class Severity { INFO, LOW, MEDIUM, HIGH, CRITICAL };

void SetConsoleColor(WORD color);
void PrintSeverity(Severity s, const std::string& msg);
std::string NowString();
void LogDetection(const std::string& category, const std::string& msg, const std::string& evidence, Severity s);
void DebugLog(const std::string& msg);
void EnableDebug(bool enable);

extern std::mutex logMutex;
extern bool debugMode;