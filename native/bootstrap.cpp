#include "bootstrap.hpp"
#include <cstdio>
#include <cstdlib>
#include <stdexcept>
#include <string>

// 复用 SnowLuma 的 SSO 通道：把它的 hook 组件注入到同一个 QQ 进程里。
//
// 它自包含（导入表只有 KERNEL32，qq_hook.dll 是它的导出表名而不是依赖），
// 注入后会在 \\.\pipe\mojo.<pid>.control 建一个命名管道，我们的 JS 侧
// （native/sso-pipe.cjs）通过它发任意 SSO 包——这是拍一拍、内核没有的群管理、
// QZone p_skey 等「QQ JS 层全是空壳」的唯一活路。
//
// 路径解析顺序：环境变量 OPENQQ_SL_DLL → 本 DLL 同目录的 snowluma-win32-x64.dll。
// 找不到就静默跳过，不影响 OpenQQ 本身。
static void loadSsoBridge() {
    static bool attempted = false;
    if (attempted) return;
    attempted = true;
    std::wstring path;
    if (const char* raw = std::getenv("OPENQQ_SL_DLL")) {
        if (*raw) {
            wchar_t wide[32768];
            if (MultiByteToWideChar(CP_UTF8, 0, raw, -1, wide, 32768) > 0) path.assign(wide);
        }
    }
    if (path.empty()) {
        // 注意：GetModuleFileNameW(nullptr, …) 返回的是宿主 exe（QQ.exe）的路径，
        // 不是本 DLL 的。必须先用 FROM_ADDRESS 拿到自己的模块句柄。
        HMODULE self = nullptr;
        if (GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                               reinterpret_cast<LPCWSTR>(&loadSsoBridge), &self) && self) {
            wchar_t selfPath[32768];
            if (GetModuleFileNameW(self, selfPath, 32768) != 0) {
                std::wstring dir(selfPath);
                const auto pos = dir.find_last_of(L"\\/");
                if (pos != std::wstring::npos) path = dir.substr(0, pos + 1) + L"snowluma-win32-x64.dll";
            }
        }
    }
    if (path.empty()) return;
    if (GetFileAttributesW(path.c_str()) == INVALID_FILE_ATTRIBUTES) return;
    LoadLibraryW(path.c_str());
}

template<class T> static T api(HMODULE module, const char* name) {
    auto address = GetProcAddress(module, name);
    if (!address) throw std::runtime_error(name);
    return reinterpret_cast<T>(address);
}
static void check(int status) {
    if (status) throw std::runtime_error("N-API returned " + std::to_string(status));
}

extern "C" __declspec(dllexport) void* OpenQQBootstrap(void* env, void* exports, BootstrapConfig* config) {
    // Run QQ's initializer unchanged, including any pending exception it creates.
    void* result = config->original(env, exports);
    loadSsoBridge();
    void* scope = nullptr;
    bool introducedException = false;
    using Pending = int (*)(void*, bool*);
    using Clear = int (*)(void*, void**);
    using Close = int (*)(void*, void*);
    Pending pending = nullptr;
    Clear clear = nullptr;
    Close close = nullptr;
    LONG status = -1;
    try {
        const auto runtime = config->runtime;
        pending = api<Pending>(runtime, "napi_is_exception_pending");
        clear = api<Clear>(runtime, "napi_get_and_clear_last_exception");
        close = api<Close>(runtime, "napi_close_escapable_handle_scope");
        bool exception = false;
        check(pending(env, &exception));
        if (exception) throw std::runtime_error("wrapper initializer has a pending exception");
        introducedException = true;
        auto open = api<int (*)(void*, void**)>(runtime, "napi_open_escapable_handle_scope");
        auto global = api<int (*)(void*, void**)>(runtime, "napi_get_global");
        auto set = api<int (*)(void*, void*, const char*, void*)>(runtime, "napi_set_named_property");
        auto string = api<int (*)(void*, const char*, size_t, void**)>(runtime, "napi_create_string_utf8");
        auto run = api<int (*)(void*, void*, void**)>(runtime, "napi_run_script");
        auto escape = api<int (*)(void*, void*, void*, void**)>(runtime, "napi_escape_handle");
        check(open(env, &scope));
        void *object = nullptr, *source = nullptr, *value = nullptr, *escaped = nullptr;
        check(global(env, &object));
        check(set(env, object, "__openqq_exports", result ? result : exports));
        check(string(env, config->source, SIZE_MAX, &source));
        check(run(env, source, &value));
        check(escape(env, scope, value, &escaped));
        result = escaped;
        status = 1;
    } catch (const std::exception& error) {
        std::snprintf(config->error, sizeof(config->error), "%s", error.what());
        if (introducedException && pending && clear) {
            bool exception = false;
            void* ignored = nullptr;
            if (!pending(env, &exception) && exception) clear(env, &ignored);
        }
    }
    if (scope && close && close(env, scope)) {
        status = -1;
        std::snprintf(config->error, sizeof(config->error), "N-API scope close failed");
    }
    // Publish only after the escaped handle is safe and all cleanup has finished.
    InterlockedExchange(&config->status, status);
    return result;
}

BOOL WINAPI DllMain(HINSTANCE, DWORD, LPVOID) { return TRUE; }
