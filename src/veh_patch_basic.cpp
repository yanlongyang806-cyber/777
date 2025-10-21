#include <windows.h>
#include <fstream>
#include <sstream>
#include <string>

const DWORD64 TARGET_OFFSET = 0xE5EE7E;
DWORD64 g_ModuleBase = 0;

void WriteLog(const std::string& msg) {
    std::ofstream logFile("D:\\SPP-LegionV2\\Servers\\veh_patch.log", std::ios::app);
    if (logFile.is_open()) {
        SYSTEMTIME st;
        GetLocalTime(&st);
        logFile << "[" << st.wYear << "-" << st.wMonth << "-" << st.wDay << " "
                << st.wHour << ":" << st.wMinute << ":" << st.wSecond << "] "
                << msg << std::endl;
    }
}

std::string PtrToHexStr(DWORD64 ptr) {
    std::stringstream ss;
    ss << "0x" << std::hex << ptr;
    return ss.str();
}

LONG CALLBACK VehHandler(EXCEPTION_POINTERS* ExceptionInfo) {
    if (ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION) {
        DWORD64 crashAddr = (DWORD64)ExceptionInfo->ExceptionRecord->ExceptionAddress;
        DWORD64 targetAddr = g_ModuleBase + TARGET_OFFSET;

        if (crashAddr == targetAddr) {
            WriteLog("[VEH] 捕获到空指针异常，崩溃地址: " + PtrToHexStr(crashAddr) + " ，已跳过。");
            ExceptionInfo->ContextRecord->Rip += 2;
            return EXCEPTION_CONTINUE_EXECUTION;
        }
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
        HMODULE hMain = GetModuleHandleA("worldserver.exe");
        if (hMain) {
            g_ModuleBase = (DWORD64)hMain;
            WriteLog("[DllMain] veh_patch_basic.dll 注入成功，基址: " + PtrToHexStr((DWORD64)hMain));
            AddVectoredExceptionHandler(1, VehHandler);
            WriteLog("[DllMain] VEH 异常处理程序安装完成。");
        } else {
            WriteLog("[DllMain] 获取 worldserver.exe 基址失败！");
        }
    }
    return TRUE;
}
