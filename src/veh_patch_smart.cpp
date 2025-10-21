#include <windows.h>
#include <fstream>
#include <sstream>
#include <string>

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

LONG CALLBACK SmartHandler(EXCEPTION_POINTERS* ExceptionInfo) {
    if (ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION) {
        DWORD64 crashAddr = (DWORD64)ExceptionInfo->ExceptionRecord->ExceptionAddress;

        // 智能判断：如果在 worldserver.exe 地址空间内发生访问违规，就跳过指令
        HMODULE hMain = GetModuleHandleA("worldserver.exe");
        if (hMain) {
            DWORD64 base = (DWORD64)hMain;
            DWORD64 end = base + 0xFFFFFFF; // 假设主模块不超过 256 MB
            if (crashAddr >= base && crashAddr <= end) {
                WriteLog("[SmartVEH] 自动捕获异常 @ " + PtrToHexStr(crashAddr) + " ，跳过指令避免崩溃。");
                ExceptionInfo->ContextRecord->Rip += 2;
                return EXCEPTION_CONTINUE_EXECUTION;
            }
        }
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
        WriteLog("[DllMain] veh_patch.dll 智能版已注入，安装 VEH 异常处理程序...");
        AddVectoredExceptionHandler(1, SmartHandler);
        WriteLog("[DllMain] 智能版 VEH 异常处理程序安装完成。");
    }
    return TRUE;
}
