// openqq-sso-local —— 自研 SSO 发送组件
//
// 被 OpenQQ 的 bootstrap 用 LoadLibraryW 载入 QQ 进程，自建命名管道，接受 JS 侧
// （native/sso-pipe.cjs）递进来的 SSO 包，在进程内把它送到 QQ 真正的发送链上。
//
// 为什么必须做成独立组件：QQ 只给 JS 暴露了 sendSsoCmdReqByContend，实测它是白名单
// 网关（同一个包走真实发送链能拿 pskey，走它只回 {} / 0ms）。要发任意 SSO，只能在
// 进程内动手 —— 这一层 JS 做不到。
//
// ⚠️ 发布版边界：本文件不得包含全内存扫描、任意地址批量读取、全局函数挂接。
// 定位发送入口只允许「按名字/导出查」和「按已固化的偏移表算」两条路。
// 大改动前先看同目录 README 的「安全软件边界」一节。

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstdio>
#include <cstring>
#include <cstdint>
#include <cstdlib>
#include <string>
#include <vector>

namespace {

// ===== QHP1 帧（与 native/sso-pipe.cjs 完全一致）=====
constexpr uint32_t kMagic = 0x31504851;  // "QHP1"
constexpr uint16_t kVersion = 1;
constexpr size_t kHeaderSize = 40;
constexpr size_t kMaxCmd = 0x1000;
constexpr size_t kMaxMsg = 0x10000;
constexpr size_t kMaxBody = 0x1000000;

enum Op : uint16_t {
    OP_HELLO = 1,      // dll → node
    OP_SEND = 2,       // node → dll
    OP_ACK = 3,        // 双向
    OP_REPLY = 4,      // dll → node
    OP_ERROR = 5,      // dll → node
    OP_PUSH = 6,       // dll → node
    OP_LOGIN = 7,      // dll → node
    OP_PING = 0x11,    // node → dll
    OP_SET_SESSION = 0x12,  // node → dll：把 QQ 的 session 指针递进来（msg = 16 进制指针）
};

constexpr uint32_t kFlagWantReply = 1;
constexpr uint32_t kFlagLoggedIn = 4;

struct Frame {
    uint16_t op = 0;
    uint32_t requestId = 0;
    int32_t status = 0;
    uint32_t flags = 0;
    std::string cmd;
    std::string msg;
    std::vector<uint8_t> body;
};

uint32_t readU32(const uint8_t* p) { return uint32_t(p[0]) | (uint32_t(p[1]) << 8) | (uint32_t(p[2]) << 16) | (uint32_t(p[3]) << 24); }
uint64_t readU64(const uint8_t* p) { return uint64_t(readU32(p)) | (uint64_t(readU32(p + 4)) << 32); }
void writeU32(uint8_t* p, uint32_t v) { p[0] = uint8_t(v); p[1] = uint8_t(v >> 8); p[2] = uint8_t(v >> 16); p[3] = uint8_t(v >> 24); }

bool readExact(HANDLE pipe, void* buf, DWORD want) {
    auto* p = static_cast<uint8_t*>(buf);
    DWORD got = 0;
    while (got < want) {
        DWORD n = 0;
        if (!ReadFile(pipe, p + got, want - got, &n, nullptr) || n == 0) return false;
        got += n;
    }
    return true;
}

bool writeExact(HANDLE pipe, const void* buf, DWORD len) {
    auto* p = static_cast<const uint8_t*>(buf);
    DWORD sent = 0;
    while (sent < len) {
        DWORD n = 0;
        if (!WriteFile(pipe, p + sent, len - sent, &n, nullptr) || n == 0) return false;
        sent += n;
    }
    return true;
}

std::vector<uint8_t> encodeFrame(const Frame& f) {
    std::vector<uint8_t> out(kHeaderSize + f.cmd.size() + f.msg.size() + f.body.size());
    writeU32(out.data() + 0, kMagic);
    out[4] = uint8_t(kVersion & 0xFF);
    out[5] = uint8_t(kVersion >> 8);
    out[6] = uint8_t(f.op & 0xFF);
    out[7] = uint8_t(f.op >> 8);
    writeU32(out.data() + 8, f.requestId);
    writeU32(out.data() + 12, uint32_t(f.status));
    writeU32(out.data() + 16, f.flags);
    writeU32(out.data() + 20, uint32_t(f.cmd.size()));
    writeU32(out.data() + 24, uint32_t(f.msg.size()));
    writeU32(out.data() + 28, uint32_t(f.body.size()));
    writeU32(out.data() + 32, 0);
    writeU32(out.data() + 36, 0);
    size_t off = kHeaderSize;
    if (!f.cmd.empty()) { std::memcpy(out.data() + off, f.cmd.data(), f.cmd.size()); off += f.cmd.size(); }
    if (!f.msg.empty()) { std::memcpy(out.data() + off, f.msg.data(), f.msg.size()); off += f.msg.size(); }
    if (!f.body.empty()) { std::memcpy(out.data() + off, f.body.data(), f.body.size()); }
    return out;
}

// ===== 发包层 =====
//
// 把 (cmd, body) 送到 QQ 的 SSO 发送链上。全部依据来自静态逆向，见
// .botharness\sl-re\sl-send-56d0.md 与 PLAN-sso-local.md。
//
// 允许的两条定位路径（都符合发布版边界）：
//   A. 按名字查。QQ 的模块里如果有对应的导出/符号，GetProcAddress 就够，零扫描。
//   B. 按固化的偏移表算。偏移来自调试版（openqq-bootstrap-debug.dll）在真实 QQ 进程里
//      做的一次性逆向，结果写进下面的表；发布版只做 GetModuleHandle + base+offset 的
//      一次计算，不遍历内存、不试读陌生地址。
//
// 禁止：VirtualQuery 遍历、对任意地址批量试读、往全局对象挂函数。那三条组合会被
// Defender 判成通用可疑并隔离 —— 这个代价已经付过一次。

// wrapper.node 9.9.37-54395 的固化偏移（[静态] 反汇编得出，换版本必须重算）
struct SendOffsets {
    uint32_t stringCtor;   // std::string(std::string* self, const char* text)
    uint32_t sendEntry;    // 0x268f09e(session, cmd, body, out)
    uint32_t getCtx;       // 0x2c11cc() -> ctx（无参，返回静态全局）
    uint32_t lookup;       // 0x2c122c(ctx, session) -> 节点
};
static const SendOffsets kOff = {
    0x325ae8,   // kRvaStringCtor
    0x268f09e,  // 真实发包入口（0x268b8ea 的下游）
    0x2c11cc,   // GS 检查 + 返回 ctx
    0x2c122c,   // 按 session 查节点
};

typedef void* (__fastcall* FnStringCtor)(void* self, const char* text);
typedef void  (__fastcall* FnSend)(void* session, void* cmd, void* body, void* out);
typedef void* (__fastcall* FnGetCtx)();
typedef void* (__fastcall* FnLookup)(void* ctx, void* session);

// body 形状：与 QQ 内部 / SL 0x56d0 一致的 {data, len}。
struct SsoSpan {
    const char* data;
    size_t len;
};

// MSVC std::string（x64）是 24 字节，这里给足 32 字节缓冲并 8 字节对齐，
// 内容一律用 QQ 自己的构造函数（kRvaStringCtor）写，不手搓布局。
struct StringBuf {
    alignas(8) unsigned char raw[32];
};

struct SendTarget {
    bool ready = false;
    HMODULE module = nullptr;
};

SendTarget g_sendTarget;
void* g_session = nullptr;   // 由 OP_SET_SESSION 递进来

// 按名字在已加载模块里找符号。找不到返回 nullptr（不扫内存）。
FARPROC resolveByName(const wchar_t* moduleName, const char* symbol) {
    HMODULE mod = GetModuleHandleW(moduleName);
    if (!mod) return nullptr;
    return GetProcAddress(mod, symbol);
}

// 从固化偏移算地址。只做一次模块基址加偏移，不验证、不遍历。
void* resolveByOffset(HMODULE mod, uint32_t offset) {
    if (!mod || !offset) return nullptr;
    return reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(mod) + offset);
}

bool initSendTarget() {
    // 路径 A：QQ 若暴露了符号化的发送入口，优先用它（版本无关、零维护）。
    // 目前 QQ 没有这样的导出，这一步留作将来版本直接受益的位置。
    if (resolveByName(L"wrapper.node", "SendSSORequest") != nullptr) {
        g_sendTarget = { true, GetModuleHandleW(L"wrapper.node") };
        return true;
    }

    // 路径 B：固化偏移表。当前只认 9.9.37 这一套；模块不在就当未就绪，不猜。
    HMODULE mod = GetModuleHandleW(L"wrapper.node");
    if (!mod) return false;
    g_sendTarget = { true, mod };
    return true;
}

// 诊断：不发包，只把这条链算一遍，回报每一环是否拿到。
// 第一次上真机用 dryRun=true，确认 session 解析正确后再真发。
int32_t diagnoseChain(std::string& detail) {
    if (!g_sendTarget.ready && !initSendTarget()) {
        detail = "wrapper.node not loaded";
        return -10;
    }
    if (!g_session) {
        detail = "session not set (waiting OP_SET_SESSION)";
        return -12;
    }
    char buf[256];
    auto getCtx = reinterpret_cast<FnGetCtx>(resolveByOffset(g_sendTarget.module, kOff.getCtx));
    auto lookup = reinterpret_cast<FnLookup>(resolveByOffset(g_sendTarget.module, kOff.lookup));
    if (!getCtx || !lookup) {
        detail = "offset table unresolved";
        return -13;
    }
    void* ctx = getCtx();
    void* node = lookup(ctx, g_session);
    _snprintf_s(buf, _countof(buf), _TRUNCATE,
                "session=%p ctx=%p node=%p", g_session, ctx, node);
    detail = buf;
    if (!node) return -14;
    return 0;
}

// 返回 status：0 = 已送出，其余为错误码（会原样回到 JS 侧）。
// dryRun=true 时只走诊断链、不调用发包入口。
int32_t sendViaQQ(const std::string& cmd, const std::vector<uint8_t>& body,
                  std::vector<uint8_t>& reply, std::string& err, bool dryRun) {
    reply.clear();
    std::string chain;
    const int32_t diag = diagnoseChain(chain);
    if (diag != 0) {
        err = "sso-local: " + chain;
        return diag;
    }
    if (dryRun) {
        err = "sso-local: dryRun ok (" + chain + ")";
        return 0;
    }

    // ⚠️ 真发需要复刻 SL 的 pending/promise 机制：0x10430（登记 job）、0xf860（构造 promise）、
    // 0xfd90（挂 continuation）、以及 lambda vtable 0x18003ed08。在它实现之前，
    // 直接同步调 0x268f09e 会把管道线程和 QQ 的 JS 侧一起拖死
    // （2026-11-21 实测：调用后 QQ 4→0、node 一并退出，不是崩溃而是整条链停摆）。
    // 所以这里明确拒绝，不拿 QQ 的可用性冒险。
    err = "sso-local: real send not armed yet (pending/reply plumbing missing)";
    return -20;
}

// ===== 管道服务 =====
HANDLE g_pipe = INVALID_HANDLE_VALUE;
volatile bool g_stop = false;

std::wstring pipeName() {
    wchar_t buf[128];
    _snwprintf_s(buf, _countof(buf), _TRUNCATE, L"\\\\.\\pipe\\openqq-sso.%lu.control",
                 static_cast<unsigned long>(GetCurrentProcessId()));
    return std::wstring(buf);
}

void handleClient(HANDLE pipe) {
    // hello：先把 pid 和登录态告诉对端，让 JS 侧不必猜。
    {
        Frame hello;
        hello.op = OP_HELLO;
        hello.msg = std::to_string(GetCurrentProcessId());
        hello.flags = 0;  // 登录态未知时为 0
        auto bytes = encodeFrame(hello);
        writeExact(pipe, bytes.data(), DWORD(bytes.size()));
    }

    std::vector<uint8_t> header(kHeaderSize);
    while (!g_stop) {
        if (!readExact(pipe, header.data(), DWORD(kHeaderSize))) break;
        if (readU32(header.data()) != kMagic) break;

        const uint16_t op = uint16_t(header[6] | (header[7] << 8));
        const uint32_t reqId = readU32(header.data() + 8);
        const uint32_t cmdLen = readU32(header.data() + 20);
        const uint32_t msgLen = readU32(header.data() + 24);
        const uint32_t bodyLen = readU32(header.data() + 28);
        if (cmdLen > kMaxCmd || msgLen > kMaxMsg || bodyLen > kMaxBody) break;

        Frame in;
        in.op = op;
        in.requestId = reqId;
        in.cmd.resize(cmdLen);
        in.msg.resize(msgLen);
        in.body.resize(bodyLen);
        if (cmdLen && !readExact(pipe, in.cmd.data(), cmdLen)) break;
        if (msgLen && !readExact(pipe, in.msg.data(), msgLen)) break;
        if (bodyLen && !readExact(pipe, in.body.data(), bodyLen)) break;

        Frame out;
        out.requestId = reqId;
        switch (op) {
        case OP_SET_SESSION: {
            // msg 是 16 进制指针字符串；解析失败就当没收到，不猜。
            const unsigned long long v = std::strtoull(in.msg.c_str(), nullptr, 16);
            g_session = reinterpret_cast<void*>(static_cast<uintptr_t>(v));
            out.op = OP_ACK;
            out.flags = g_session ? kFlagLoggedIn : 0;
            out.msg = g_session ? "session accepted" : "session rejected (empty)";
            break;
        }
        case OP_PING: {
            out.op = OP_ACK;
            out.flags = g_session ? kFlagLoggedIn : 0;
            break;
        }
        case OP_SEND: {
            // 先回 ack 表示"已受理"，再回真正的结果 —— 与协议里 op 语义一致。
            Frame ack;
            ack.op = OP_ACK;
            ack.requestId = reqId;
            auto ackBytes = encodeFrame(ack);
            writeExact(pipe, ackBytes.data(), DWORD(ackBytes.size()));

            // msg == "dry" 时只走诊断链，不真发 —— 第一次上真机必须这么测。
            const bool dryRun = (in.msg == "dry");
            std::vector<uint8_t> reply;
            std::string err;
            int32_t status = sendViaQQ(in.cmd, in.body, reply, err, dryRun);
            out.op = (status == 0) ? OP_REPLY : OP_ERROR;
            out.status = status;
            out.msg = err;
            if (status == 0) out.body = std::move(reply);
            break;
        }
        default: {
            out.op = OP_ERROR;
            out.status = -1;
            out.msg = "unsupported op";
            break;
        }
        }
        auto bytes = encodeFrame(out);
        if (!writeExact(pipe, bytes.data(), DWORD(bytes.size()))) break;
    }
}

DWORD WINAPI serverThread(LPVOID) {
    const std::wstring name = pipeName();
    while (!g_stop) {
        HANDLE pipe = CreateNamedPipeW(
            name.c_str(),
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
            1, 64 * 1024, 64 * 1024, 0, nullptr);
        if (pipe == INVALID_HANDLE_VALUE) { Sleep(500); continue; }

        const BOOL ok = ConnectNamedPipe(pipe, nullptr) ? TRUE : (GetLastError() == ERROR_PIPE_CONNECTED);
        if (ok) {
            g_pipe = pipe;
            handleClient(pipe);
            g_pipe = INVALID_HANDLE_VALUE;
        }
        DisconnectNamedPipe(pipe);
        CloseHandle(pipe);

        // 断开后短暂让出，避免对端已退出时忙等空转。
        Sleep(50);
    }
    return 0;
}

}  // namespace

BOOL APIENTRY DllMain(HMODULE module, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(module);
        HANDLE th = CreateThread(nullptr, 0, serverThread, nullptr, 0, nullptr);
        if (th) CloseHandle(th);
    }
    return TRUE;
}
