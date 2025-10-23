#include <windows.h>
#include <fstream>
#include <sstream>
#include <string>

// 固定日志路径
static const char* kLogPath = "D:\\\\SPP-LegionV2\\\\Servers\\\\veh_patch.log";

// 主模块信息
static DWORD64 gModuleBase = 0;
static DWORD64 gModuleSize = 0;

// 简单日志
static void WriteLog(const std::string& msg) {
    std::ofstream ofs(kLogPath, std::ios::app);
    if (!ofs.is_open()) return;
    SYSTEMTIME st; GetLocalTime(&st);
    ofs << "[" << st.wYear << "-" << st.wMonth << "-" << st.wDay << " "
        << st.wHour << ":" << st.wMinute << ":" << st.wSecond << "] "
        << msg << std::endl;
}

static std::string HexU64(DWORD64 v) {
    std::ostringstream oss;
    oss << "0x" << std::hex << v;
    return oss.str();
}

// 读取 PE SizeOfImage
static DWORD64 GetModuleSizeFromPE(DWORD64 base) {
    if (!base) return 0;
    auto dos = reinterpret_cast<PIMAGE_DOS_HEADER>(base);
    if (!dos || dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;
    auto nt = reinterpret_cast<PIMAGE_NT_HEADERS>(base + dos->e_lfanew);
    if (!nt || nt->Signature != IMAGE_NT_SIGNATURE) return 0;
    return static_cast<DWORD64>(nt->OptionalHeader.SizeOfImage);
}

// VEH：捕获访问违规，尽量跳过导致崩溃的指令
static LONG CALLBACK SmartVehHandler(EXCEPTION_POINTERS* ep) {
    if (!ep || !ep->ExceptionRecord || !ep->ContextRecord) return EXCEPTION_CONTINUE_SEARCH;

    const auto code = ep->ExceptionRecord->ExceptionCode;
    
    // 捕获多种异常类型
    if (code != EXCEPTION_ACCESS_VIOLATION &&
        code != EXCEPTION_ILLEGAL_INSTRUCTION &&
        code != EXCEPTION_STACK_OVERFLOW) {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    const DWORD64 crashAddr = reinterpret_cast<DWORD64>(ep->ExceptionRecord->ExceptionAddress);

    // 处理特定的崩溃地址: 0x00000000088CB07A
    if (crashAddr == 0x00000000088CB07A) {
        const DWORD64 ripBefore = ep->ContextRecord->Rip;

        // 仅在 worldserver.exe 主模块范围内尝试“跳过”
        if (gModuleBase && gModuleSize &&
            crashAddr >= gModuleBase && crashAddr < (gModuleBase + gModuleSize)) {

            // 保险起见，默认前进 2 字节（常见短指令大小）
            DWORD64 advance = 2;  // 可根据实际崩溃情况调整
            ep->ContextRecord->Rip += advance;

            WriteLog(std::string("[VEH] 捕获异常(code=") +
                     std::to_string(code) +
                     ") @" + HexU64(crashAddr) +
                     " RIP " + HexU64(ripBefore) + " -> " + HexU64(ep->ContextRecord->Rip) +
                     "，已尝试跳过指令继续执行。");

            return EXCEPTION_CONTINUE_EXECUTION;
        }
    }

    // 非主模块/不满足条件，交由系统处理
    return EXCEPTION_CONTINUE_SEARCH;
}

BOOL APIENTRY DllMain(HMODULE hMod, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hMod);

        HMODULE hMain = GetModuleHandleA("worldserver.exe");
        if (hMain) {
            gModuleBase = reinterpret_cast<DWORD64>(hMain);
            gModuleSize = GetModuleSizeFromPE(gModuleBase);
            WriteLog(std::string("[DllMain] veh_patch_smart.dll 注入成功。worldserver.exe 基址=") +
                     HexU64(gModuleBase) + " 大小=" + std::to_string(gModuleSize) + " bytes");

            PVOID handle = AddVectoredExceptionHandler(1, SmartVehHandler);
            if (handle) {
                WriteLog("[DllMain] VEH 异常处理程序安装完成。");
            } else {
                WriteLog("[DllMain] 安装 VEH 失败！");
            }
        } else {
            WriteLog("[DllMain] 获取 worldserver.exe 模块失败，未安装 VEH。");
        }
    }
    return TRUE;
}
