#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <string.h>

// "C2와 관련된 키워드"가 창 제목에 들어가면 차단
BOOL IsBlockedSite(const char* title) {
    return (strstr(title, "chicken") != NULL || strstr(title,"chicken") != NULL);
}

void KillProcessByName(const char* processName) {
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return;

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(hSnap, &pe)) {
        do {
            if (_stricmp(pe.szExeFile, processName) == 0) {
                HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pe.th32ProcessID);
                if (hProcess) {
                    TerminateProcess(hProcess, 0);
                    CloseHandle(hProcess);
                }
            }
        } while (Process32Next(hSnap, &pe));
    }

    CloseHandle(hSnap);
}

void MonitorBrowserAndBlock() {
    HWND hWnd = GetForegroundWindow();
    char title[256];

    if (hWnd && GetWindowTextA(hWnd, title, sizeof(title))) {
        if (IsBlockedSite(title)) {
            PostMessage(hWnd, WM_CLOSE, 0, 0);
            Sleep(500);
            KillProcessByName("chrome.exe"); //해당 악성 프로세스
        }
    }
}

int main() {
    FreeConsole();
    while (1) {
        MonitorBrowserAndBlock();
        Sleep(3000);
    }
    return 0;
}
