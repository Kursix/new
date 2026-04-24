#include "RealTimeMonitor.hpp"
#include "Utils.hpp"

#include "imgui/imgui.h"
#include "imgui/imgui_internal.h"
#include "imgui/imgui_impl_win32.h"
#include "imgui/imgui_impl_opengl3.h"
#include <GL/gl.h>
#pragma comment(lib, "opengl32.lib")

#include <windows.h>
#include <deque>
#include <mutex>
#include <algorithm>

extern LRESULT ImGui_ImplWin32_WndProcHandler(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

template<typename T>
T MathLerp(T a, T b, float t) { return (T)(a + (b - a) * t); }

namespace Ratt1fy {
    ImVec4 AccentColor = ImVec4(0.42f, 0.78f, 1.00f, 1.00f);
    ImVec4 BgColor = ImVec4(0.04f, 0.05f, 0.08f, 0.86f);
    ImVec4 CardBgColor = ImVec4(0.07f, 0.09f, 0.14f, 0.85f);
    ImVec4 BorderColor = ImVec4(0.20f, 0.28f, 0.36f, 0.65f);
    float WindowRounding = 20.0f;
    float ElementRounding = 12.0f;
}

struct AlertEntry {
    Severity severity;
    std::string title;
    std::string message;
    std::string time;
    int riskPercent;
    float lifeTime = 6.0f;
};

std::deque<AlertEntry> g_Alerts;
std::deque<DetectionEvent> g_Events;
std::mutex g_AlertMutex;
RealTimeMonitor* g_Monitor = nullptr;
bool g_MonitorRunning = false;
bool g_BlockingEnabled = false;
static int g_ActiveTab = 0;
static float g_OverlayOpacity = 0.0f;

int RiskFromSeverity(Severity s) {
    switch (s) {
    case Severity::INFO: return 15;
    case Severity::LOW: return 35;
    case Severity::MEDIUM: return 55;
    case Severity::HIGH: return 78;
    case Severity::CRITICAL: return 96;
    }
    return 50;
}

const char* RiskLabel(int risk) {
    if (risk >= 90) return "CRITICAL";
    if (risk >= 70) return "HIGH";
    if (risk >= 45) return "MEDIUM";
    return "LOW";
}

void ApplySmoothStyle() {
    ImGuiStyle& style = ImGui::GetStyle();

    style.WindowRounding = Ratt1fy::WindowRounding;
    style.ChildRounding = Ratt1fy::ElementRounding;
    style.FrameRounding = Ratt1fy::ElementRounding;
    style.PopupRounding = Ratt1fy::ElementRounding;
    style.ScrollbarRounding = 12.0f;
    style.GrabRounding = Ratt1fy::ElementRounding;
    style.TabRounding = Ratt1fy::ElementRounding;

    style.WindowPadding = ImVec2(16, 16);
    style.FramePadding = ImVec2(12, 9);
    style.ItemSpacing = ImVec2(12, 10);
    style.WindowBorderSize = 1.0f;

    auto* colors = style.Colors;
    colors[ImGuiCol_WindowBg] = Ratt1fy::BgColor;
    colors[ImGuiCol_ChildBg] = Ratt1fy::CardBgColor;
    colors[ImGuiCol_Border] = Ratt1fy::BorderColor;
    colors[ImGuiCol_FrameBg] = ImVec4(0.14f, 0.19f, 0.25f, 0.55f);
    colors[ImGuiCol_FrameBgHovered] = ImVec4(0.24f, 0.31f, 0.40f, 0.70f);
    colors[ImGuiCol_FrameBgActive] = ImVec4(0.28f, 0.40f, 0.53f, 0.85f);
    colors[ImGuiCol_Button] = ImVec4(0.17f, 0.24f, 0.34f, 0.65f);
    colors[ImGuiCol_ButtonHovered] = ImVec4(0.25f, 0.42f, 0.58f, 0.92f);
    colors[ImGuiCol_ButtonActive] = ImVec4(0.32f, 0.55f, 0.73f, 0.95f);
    colors[ImGuiCol_CheckMark] = Ratt1fy::AccentColor;
    colors[ImGuiCol_SliderGrab] = Ratt1fy::AccentColor;
    colors[ImGuiCol_SliderGrabActive] = ImVec4(0.52f, 0.86f, 1.00f, 1.00f);
    colors[ImGuiCol_Header] = ImVec4(0.14f, 0.21f, 0.31f, 0.58f);
    colors[ImGuiCol_HeaderHovered] = ImVec4(0.28f, 0.42f, 0.54f, 0.88f);
    colors[ImGuiCol_HeaderActive] = ImVec4(0.31f, 0.53f, 0.72f, 0.90f);
}

void RealTimeMonitor::Alert(const std::string& category, const std::string& msg,
    const std::string& evidence, Severity s) {
    LogDetection(category, msg, evidence, s);

    DetectionEvent event;
    event.category = category;
    event.message = msg;
    event.evidence = evidence;
    event.severity = s;
    event.riskPercent = RiskFromSeverity(s);
    event.pid = 0;
    event.processName = "unknown";

    std::lock_guard<std::mutex> lock(g_AlertMutex);
    g_Events.push_front(event);
    if (g_Events.size() > 300) g_Events.pop_back();

    AlertEntry toast = { s, category, msg, NowString(), event.riskPercent, 6.0f };
    g_Alerts.push_front(toast);
    if (g_Alerts.size() > 60) g_Alerts.pop_back();
}

void DrawBackgroundDecor() {
    ImGuiIO& io = ImGui::GetIO();
    ImDrawList* draw = ImGui::GetBackgroundDrawList();

    g_OverlayOpacity = MathLerp(g_OverlayOpacity, 195.0f, io.DeltaTime * 2.7f);
    draw->AddRectFilled(ImVec2(0, 0), io.DisplaySize, IM_COL32(4, 8, 14, (int)g_OverlayOpacity));

    for (int i = 0; i < 9; ++i) {
        float x = (io.DisplaySize.x / 8.0f) * i;
        draw->AddCircleFilled(ImVec2(x, 120.0f + 26.0f * i), 130.0f, IM_COL32(70, 150, 255, 10), 64);
    }
}

void DrawNotifications() {
    std::lock_guard<std::mutex> lock(g_AlertMutex);
    float dt = ImGui::GetIO().DeltaTime;
    ImVec2 viewSize = ImGui::GetIO().DisplaySize;
    float currentY = 25.0f;

    for (auto& alert : g_Alerts) {
        if (alert.lifeTime <= 0.0f) continue;

        float alpha = (alert.lifeTime < 1.0f) ? alert.lifeTime : 1.0f;
        ImGui::SetNextWindowPos(ImVec2(viewSize.x - 430, currentY), ImGuiCond_Always);
        ImGui::SetNextWindowSize(ImVec2(400, 0));
        ImGui::SetNextWindowBgAlpha(alpha * 0.88f);

        ImGui::PushStyleColor(ImGuiCol_Border, ImVec4(0.35f, 0.72f, 1.0f, 1.0f));
        ImGui::Begin((std::string("##alert_") + alert.time + alert.title).c_str(), nullptr,
            ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_AlwaysAutoResize | ImGuiWindowFlags_NoFocusOnAppearing);

        ImGui::TextColored(ImVec4(0.62f, 0.88f, 1.0f, 1.0f), "INTERCEPTED • %s", alert.title.c_str());
        ImGui::TextWrapped("%s", alert.message.c_str());
        ImGui::Separator();
        ImGui::Text("Risk: %d%% (%s)", alert.riskPercent, RiskLabel(alert.riskPercent));

        ImGui::End();
        ImGui::PopStyleColor();

        alert.lifeTime -= dt;
        currentY += ImGui::GetWindowHeight() + 12.0f;
    }
}

void RenderRattifyUI(ImFont* titleFont) {
    ImGuiIO& io = ImGui::GetIO();
    ApplySmoothStyle();
    DrawBackgroundDecor();

    ImGui::SetNextWindowSize(ImVec2(980, 620));
    ImGui::SetNextWindowPos(ImVec2((io.DisplaySize.x - 980) / 2, (io.DisplaySize.y - 620) / 2), ImGuiCond_Always);

    ImGui::Begin("Ratt1fy Main", nullptr, ImGuiWindowFlags_NoDecoration);
    {
        ImVec2 start = ImGui::GetWindowPos();
        ImVec2 sideMin = start;
        ImVec2 sideMax = ImVec2(start.x + 245, start.y + 620);

        ImDrawList* fg = ImGui::GetWindowDrawList();
        fg->AddRectFilledMultiColor(sideMin, sideMax,
            IM_COL32(28, 46, 74, 210), IM_COL32(40, 81, 121, 210),
            IM_COL32(15, 28, 48, 210), IM_COL32(22, 43, 70, 210));

        ImGui::BeginChild("Sidebar", ImVec2(245, 0), true);
        {
            ImGui::SetCursorPos(ImVec2(28, 32));
            if (titleFont) ImGui::PushFont(titleFont);
            ImGui::TextColored(ImVec4(0.70f, 0.90f, 1.0f, 1.0f), "RATT1FY");
            if (titleFont) ImGui::PopFont();
            ImGui::SetCursorPosX(28);
            ImGui::TextColored(ImVec4(0.64f, 0.72f, 0.82f, 0.92f), "Stealer Detection Console");

            ImGui::SetCursorPosY(120);
            const char* tabs[] = { "Dashboard", "Interceptor Log", "Settings", "Exit" };
            for (int i = 0; i < 4; i++) {
                ImGui::PushID(i);
                if (ImGui::Selectable(tabs[i], g_ActiveTab == i, 0, ImVec2(190, 42))) {
                    if (i == 3) PostQuitMessage(0);
                    else g_ActiveTab = i;
                }
                ImGui::PopID();
                ImGui::Spacing();
            }
        }
        ImGui::EndChild();

        ImGui::SameLine();
        ImGui::BeginChild("MainArea", ImVec2(0, 0), false);
        {
            ImGui::SetCursorPos(ImVec2(20, 26));
            if (g_ActiveTab == 0) {
                ImGui::Text("Realtime Shield:"); ImGui::SameLine();
                ImGui::TextColored(g_MonitorRunning ? ImVec4(0.36f, 1.0f, 0.72f, 1) : ImVec4(1, 0.4f, 0.4f, 1), g_MonitorRunning ? "ACTIVE" : "OFFLINE");
                ImGui::Spacing();

                if (ImGui::Button(g_MonitorRunning ? "Stop Monitoring" : "Start Monitoring", ImVec2(260, 54))) {
                    g_MonitorRunning = !g_MonitorRunning;
                    if (g_Monitor) g_MonitorRunning ? g_Monitor->Start() : g_Monitor->Stop();
                }

                ImGui::Spacing();
                ImGui::Checkbox("Auto-Block on High/Critical", &g_BlockingEnabled);
                if (g_Monitor) g_Monitor->enableBlocking = g_BlockingEnabled;

                ImGui::Spacing();
                ImGui::Separator();
                int totalEvents = 0;
                int critical = 0;
                {
                    std::lock_guard<std::mutex> lock(g_AlertMutex);
                    totalEvents = (int)g_Events.size();
                    critical = (int)std::count_if(g_Events.begin(), g_Events.end(), [](const DetectionEvent& e) { return e.severity == Severity::CRITICAL; });
                }
                ImGui::Text("Intercepted events: %d", totalEvents);
                ImGui::Text("Critical events: %d", critical);
                ImGui::TextWrapped("Enabled detections: sensitive file access, webhook patterns, suspicious process-name heuristics.");
            }
            else if (g_ActiveTab == 1) {
                ImGui::Text("INTERCEPTOR CONSOLE");
                ImGui::Separator();

                ImGui::BeginChild("LogScroll", ImVec2(0, 0), true);
                std::lock_guard<std::mutex> lock(g_AlertMutex);
                for (const auto& ev : g_Events) {
                    ImVec4 c = ImVec4(0.60f, 0.84f, 1.f, 1.f);
                    if (ev.severity == Severity::HIGH) c = ImVec4(1.0f, 0.68f, 0.28f, 1.0f);
                    if (ev.severity == Severity::CRITICAL) c = ImVec4(1.0f, 0.34f, 0.34f, 1.0f);
                    ImGui::TextColored(c, "[%s] %s", RiskLabel(ev.riskPercent), ev.category.c_str());
                    ImGui::TextWrapped("Intercepted: %s", ev.message.c_str());
                    ImGui::TextWrapped("Why flagged: %s", ev.evidence.c_str());
                    ImGui::Text("Risk Score: %d%%", ev.riskPercent);
                    ImGui::Separator();
                }
                ImGui::EndChild();
            }
            else if (g_ActiveTab == 2) {
                ImGui::Text("UI / ENGINE SETTINGS");
                ImGui::Separator();
                ImGui::ColorEdit3("Accent", (float*)&Ratt1fy::AccentColor, ImGuiColorEditFlags_NoInputs);
                ImGui::SliderFloat("Window rounding", &Ratt1fy::WindowRounding, 8.0f, 26.0f);
                ImGui::SliderFloat("Element rounding", &Ratt1fy::ElementRounding, 6.0f, 22.0f);
                ImGui::TextWrapped("Blur is simulated with transparent layered panels + glow decoration for better readability.");
            }
        }
        ImGui::EndChild();
    }
    ImGui::End();

    DrawNotifications();
}

LRESULT CALLBACK WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    if (ImGui_ImplWin32_WndProcHandler(hWnd, msg, wParam, lParam)) return true;
    if (msg == WM_DESTROY) { PostQuitMessage(0); return 0; }
    return DefWindowProc(hWnd, msg, wParam, lParam);
}

int main() {
    WNDCLASSEX wc = { sizeof(WNDCLASSEX), CS_CLASSDC, WndProc, 0L, 0L, GetModuleHandle(NULL), NULL, NULL, NULL, NULL, "RattifyClass", NULL };
    RegisterClassEx(&wc);
    HWND hwnd = CreateWindowEx(WS_EX_TOPMOST, wc.lpszClassName, "Ratt1fy Guard", WS_POPUP, 0, 0, GetSystemMetrics(SM_CXSCREEN), GetSystemMetrics(SM_CYSCREEN), NULL, NULL, wc.hInstance, NULL);

    HDC hdc = GetDC(hwnd);
    PIXELFORMATDESCRIPTOR pfd = { sizeof(pfd), 1, PFD_DRAW_TO_WINDOW | PFD_SUPPORT_OPENGL | PFD_DOUBLEBUFFER, PFD_TYPE_RGBA, 32 };
    SetPixelFormat(hdc, ChoosePixelFormat(hdc, &pfd), &pfd);
    HGLRC hrc = wglCreateContext(hdc); wglMakeCurrent(hdc, hrc);

    ShowWindow(hwnd, SW_SHOWDEFAULT);

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO();
    ImFont* titleFont = io.Fonts->AddFontFromFileTTF("C:\\Windows\\Fonts\\segoeuib.ttf", 32.0f);

    ImGui_ImplWin32_Init(hwnd);
    ImGui_ImplOpenGL3_Init("#version 130");

    RealTimeMonitor monitor;
    g_Monitor = &monitor;

    MSG msg = {};
    while (msg.message != WM_QUIT) {
        if (PeekMessage(&msg, 0, 0, 0, PM_REMOVE)) {
            TranslateMessage(&msg); DispatchMessage(&msg);
            continue;
        }

        ImGui_ImplOpenGL3_NewFrame();
        ImGui_ImplWin32_NewFrame();
        ImGui::NewFrame();

        RenderRattifyUI(titleFont);

        ImGui::Render();
        glViewport(0, 0, (int)io.DisplaySize.x, (int)io.DisplaySize.y);
        glClearColor(0, 0, 0, 0);
        glClear(GL_COLOR_BUFFER_BIT);
        ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());
        SwapBuffers(hdc);
    }

    monitor.Stop();
    ImGui_ImplOpenGL3_Shutdown();
    ImGui_ImplWin32_Shutdown();
    ImGui::DestroyContext();
    wglMakeCurrent(NULL, NULL);
    wglDeleteContext(hrc);
    ReleaseDC(hwnd, hdc);
    DestroyWindow(hwnd);
    UnregisterClass(wc.lpszClassName, wc.hInstance);
    return 0;
}