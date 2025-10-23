#include <windows.h>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <memory>
#include <mutex>
#include <unordered_map>

#define LOG_FILE_PATH "D:\\SPP-LegionV2\\Servers\\veh_patch.log"
#define MAX_LOG_FILE_SIZE (10 * 1024 * 1024)  // 设置日志文件大小限制为 10MB

// 日志级别
enum class LogLevel {
    INFO,
    WARNING,
    ERROR
};

// 固定日志路径
static const char* kLogPath = LOG_FILE_PATH;

// 主模块信息
static DWORD64 gModuleBase = 0;
static DWORD64 gModuleSize = 0;

// 崩溃地址历史
std::unordered_map<DWORD64, int> crashAddressHistory;  // 存储崩溃地址及其发生的次数

// 日志记录器
class Logger {
public:
    Logger(const std::string& logFilePath, LogLevel level = LogLevel::INFO)
        : logFilePath_(logFilePath), logLevel_(level) {}

    void Log(const std::string& msg, LogLevel level) {
        if (level < logLevel_) return;

        std::lock_guard<std::mutex> lock(mtx_);

        // 打开文件并判断是否超出大小
        std::ofstream ofs(logFilePath_, std::ios::app);
        if (!ofs.is_open()) {
            return;  // 如果无法打开日志文件，则直接返回
        }

        SYSTEMTIME st;
        GetLocalTime(&st);
        ofs << "[" << st.wYear << "-" << st.wMonth << "-" << st.wDay << " "
            << st.wHour << ":" << st.wMinute << ":" << st.wSecond << "] ";

        switch (level) {
        case LogLevel::INFO: ofs << "[INFO] "; break;
        case LogLevel::WARNING: ofs << "[WARNING] "; break;
        case LogLevel::ERROR: ofs << "[ERROR] "; break;
        default: break;
        }

        ofs << msg << std::endl;

        // 检查文件大小，超过限制时进行处理
        CheckLogFileSize(ofs);
    }

private:
    std::string logFilePath_;
    LogLevel logLevel_;
    std::mutex mtx_;

    void CheckLogFileSize(std::ofstream& ofs) {
        ofs.close();
        std::ifstream infile(logFilePath_, std::ios::binary | std::ios::ate);
        if (infile.is_open() && infile.tellg() > MAX_LOG_FILE_SIZE) {
            // 如果日志文件超过最大限制，则备份当前日志文件并重新创建
            std::string backupFile = logFilePath_ + ".bak";
            std::rename(logFilePath_.c_str(), backupFile.c_str());
            infile.close();
            std::ofstream ofsNew(logFilePath_, std::ios::trunc);
            if (ofsNew.is_open()) {
                ofsNew.close();
            }
        }
    }
};

Logger logger(kLogPath, LogLevel::INFO);  // 默认日志级别为 INFO

static std::string HexU64(DWORD64 v) {
    std::ostringstream oss;
    oss << "0x" << std::hex << v;
    return oss.str();
}

static DWORD64 GetModuleSizeFromPE(DWORD64 base) {
    if (!base) return 0;
    auto dos = reinterpret_cast<PIMAGE_DOS_HEADER>(base);
    if (!dos || dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;
    auto nt = reinterpret_cast<PIMAGE_NT_HEADERS>(base + dos->e_lfanew);
    if (!nt || nt->Signature != IMAGE_NT_SIGNATURE) return 0;
    return static_cast<DWORD64>(nt->OptionalHeader.SizeOfImage);
}

// 智能异常处理函数
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

    // 检查崩溃地址是否已发生
    if (crashAddressHistory.count(crashAddr) > 0) {
        crashAddressHistory[crashAddr]++;
    } else {
        crashAddressHistory[crashAddr] = 1;
    }

    // 根据历史数据，动态调整处理策略
    int crashCount = crashAddressHistory[crashAddr];
    DWORD64 advance = (crashCount > 5) ? 4 : 2;  // 如果崩溃发生次数超过5次，增加跳过字节数

    logger.Log("[VEH] 崩溃地址 " + HexU64(crashAddr) + " 已发生 " + std::to_string(crashCount) + " 次，跳过 " + std::to_string(advance) + " 字节。", LogLevel::INFO);

    // 处理特定的崩溃地址
    std::vector<DWORD64> crashAddresses = { 0x00000000088CB07A };  // 可根据需要修改为配置化
    if (std::find(crashAddresses.begin(), crashAddresses.end(), crashAddr) != crashAddresses.end()) {
        const DWORD64 ripBefore = ep->ContextRecord->Rip;

        // 仅在 worldserver.exe 主模块范围内尝试“跳过”
        if (gModuleBase && gModuleSize &&
            crashAddr >= gModuleBase && crashAddr < (gModuleBase + gModuleSize)) {

            ep->ContextRecord->Rip += advance;

            logger.Log("[VEH] 捕获异常(code=" + std::to_string(code) +
                ") @" + HexU64(crashAddr) +
                " RIP " + HexU64(ripBefore) + " -> " + HexU64(ep->ContextRecord->Rip) +
                "，已尝试跳过指令继续执行。", LogLevel::INFO);

            return EXCEPTION_CONTINUE_EXECUTION;
        }
    }

    return EXCEPTION_CONTINUE_SEARCH;
}

BOOL APIENTRY DllMain(HMODULE hMod, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hMod);

        HMODULE hMain = GetModuleHandleA("worldserver.exe");
        if (hMain) {
            gModuleBase = reinterpret_cast<DWORD64>(hMain);
            gModuleSize = GetModuleSizeFromPE(gModuleBase);
            logger.Log("veh_patch_smart.dll 注入成功。worldserver.exe 基址=" +
                HexU64(gModuleBase) + " 大小=" + std::to_string(gModuleSize) + " bytes", LogLevel::INFO);

            PVOID handle = AddVectoredExceptionHandler(1, SmartVehHandler);
            if (handle) {
                logger.Log("VEH 异常处理程序安装完成。", LogLevel::INFO);
            } else {
                logger.Log("安装 VEH 失败！", LogLevel::ERROR);
            }
        } else {
            logger.Log("获取 worldserver.exe 模块失败，未安装 VEH。", LogLevel::ERROR);
        }
    }
    return TRUE;
}
