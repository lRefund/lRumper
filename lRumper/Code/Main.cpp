#define WIN32_LEAN_AND_MEAN

#include <Windows.h>
#include <TlHelp32.h>
#include <Psapi.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdarg>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <ios>
#include <iostream>
#include <map>
#include <mutex>
#include <set>
#include <string>
#include <thread>
#include <vector>
#include <sstream>
#include <unordered_set>
#include <unordered_map>

DWORD WINAPI Run(LPVOID lpParam);

using u8 = uint8_t;
using u64 = uint64_t;

typedef const char* (*il2cpp_class_get_namespace_t)(void* klass);
typedef const char* (*il2cpp_class_get_name_t)(void* klass);
typedef void* (*il2cpp_class_get_methods_t)(void* klass, void** iter);
typedef const char* (*il2cpp_method_get_name_t)(void* method);
typedef void* (*GetTypeInfoFromTypeDefinitionIndex_t)(uint32_t index);
typedef void* (*il2cpp_class_get_parent_t)(void* klass);
typedef void* (*il2cpp_class_get_fields_t)(void* klass, void** iter);
typedef const char* (*il2cpp_field_get_name_t)(void* field);
typedef int (*il2cpp_field_get_flags_t)(void* field);
typedef bool (*il2cpp_class_is_enum_t)(void* klass);
typedef void*       (*il2cpp_class_from_type_t)(void* type);
typedef void*       (*il2cpp_class_get_type_t)(void* klass);
typedef void        (*il2cpp_field_get_value_t)(void* obj, void* field, void* value);
typedef void        (*il2cpp_klass_setup_methods_t)(void* klass);
typedef bool        (*il2cpp_class_is_valuetype_t)(void* klass);
typedef int         (*il2cpp_class_get_flags_t)(void* klass);
typedef void*       (*il2cpp_class_get_image_t)(void* klass);
typedef void*       (*il2cpp_method_get_return_type_t)(void* method);
typedef uint32_t    (*il2cpp_method_get_param_count_t)(void* method);
typedef void*       (*il2cpp_method_get_param_t)(void* method, uint32_t index);
typedef const char* (*il2cpp_method_get_param_name_t)(void* method, uint32_t index);
typedef int         (*il2cpp_field_get_offset_t)(void* field);
typedef void*       (*il2cpp_field_get_return_type_t)(void* field);
typedef void*       (*il2cpp_class_get_props_t)(void* klass, void** iter);
typedef void*       (*il2cpp_class_get_interfaces_t)(void* klass, void** iter);
typedef const char* (*il2cpp_type_get_name_t)(void* type);
static il2cpp_class_get_namespace_t g_get_namespace = nullptr;
static il2cpp_class_get_name_t g_get_name = nullptr;
static il2cpp_class_get_methods_t g_get_methods = nullptr;
static il2cpp_method_get_name_t g_method_get_name = nullptr;
static GetTypeInfoFromTypeDefinitionIndex_t g_get_type_info = nullptr;
static il2cpp_class_get_parent_t g_get_parent = nullptr;
static il2cpp_class_get_fields_t g_get_fields = nullptr;
static il2cpp_field_get_name_t g_field_get_name = nullptr;
static il2cpp_field_get_flags_t g_field_get_flags = nullptr;
static il2cpp_class_is_enum_t g_class_is_enum = nullptr;
static il2cpp_class_from_type_t        g_class_from_type        = nullptr;
static il2cpp_class_get_type_t         g_class_get_type         = nullptr;
static il2cpp_field_get_value_t        g_field_get_value        = nullptr;
static il2cpp_klass_setup_methods_t    g_klassSetupMethods      = nullptr;
static il2cpp_class_is_valuetype_t     g_klassIsValue           = nullptr;
static il2cpp_class_get_flags_t        g_ClassGet_Flags         = nullptr;
static il2cpp_class_get_image_t        g_KlassGetImage          = nullptr;
static il2cpp_method_get_return_type_t g_methodGetReturnType    = nullptr;
static il2cpp_method_get_param_count_t g_methodGetParamCount    = nullptr;
static il2cpp_method_get_param_t       g_methodGetParam         = nullptr;
static il2cpp_method_get_param_name_t  g_methodGetParamName     = nullptr;
static il2cpp_field_get_offset_t       g_FieldGetOffset         = nullptr;
static il2cpp_field_get_return_type_t  g_FieldGetReturn_Type    = nullptr;
static il2cpp_class_get_props_t        g_KlassGetProps          = nullptr;
static il2cpp_class_get_interfaces_t   g_klassGetInterfaces     = nullptr;
static il2cpp_type_get_name_t          g_TypeGetName            = nullptr;

static uintptr_t kOff_GetTypeInfo         = 0x0; // il2cpp_MetadataCache_GetTypeInfoFromTypeDefinitionIndex
static uintptr_t kOff_get_methods         = 0x0; // il2cpp_class_get_methods
static uintptr_t kOff_get_name            = 0x0; // il2cpp_class_get_name
static uintptr_t kOff_get_namespace       = 0x0; // il2cpp_class_get_namespace
static uintptr_t kOff_method_get_name     = 0x0; // il2cpp_method_get_name
static uintptr_t kOff_get_parent          = 0x0; // il2cpp_class_get_parent
static uintptr_t kOff_class_from_type     = 0x0; // il2cpp_class_from_type
static uintptr_t kOff_class_get_type      = 0x0; // il2cpp_class_get_type
static uintptr_t kOff_is_enum             = 0x0; // il2cpp_class_is_enum
static uintptr_t kOff_get_fields          = 0x0; // il2cpp_class_get_fields
static uintptr_t kOff_field_get_name      = 0x0; // il2cpp_field_get_name
static uintptr_t kOff_field_get_flags     = 0x0; // il2cpp_field_get_flags
static uintptr_t kOff_field_get_value     = 0x0; // il2cpp_field_get_value
static uintptr_t kOff_klassSetupMethods   = 0x0; // il2cpp_klass_setup_methods
static uintptr_t kOff_KlassIsValue        = 0x0; // il2cpp_class_is_valuetype
static uintptr_t kOff_ClassGet_Flags      = 0x0; // il2cpp_class_get_flags
static uintptr_t kOff_KlassGetImage       = 0x0; // il2cpp_class_get_image
static uintptr_t kOff_methodGetReturnType = 0x0; // il2cpp_method_get_return_type
static uintptr_t kOff_methodGetParamCount = 0x0; // il2cpp_method_get_param_count
static uintptr_t kOff_methodGetParam      = 0x0; // il2cpp_method_get_param
static uintptr_t kOff_methodGetParamName  = 0x0; // il2cpp_method_get_param_name
static uintptr_t kOff_FieldGetOffset      = 0x0; // il2cpp_field_get_offset
static uintptr_t kOff_FieldGetReturn_Type = 0x0; // il2cpp_field_get_type
static uintptr_t kOff_KlassGetProps       = 0x0; // il2cpp_class_get_properties
static uintptr_t kOff_klassGetInterfaces  = 0x0; // il2cpp_class_get_interfaces
static uintptr_t kOff_TypeGetName         = 0x0; // il2cpp_type_get_name

static uintptr_t g_gameAssemblyBase = 0;
static std::string g_baseDir = "";
static std::mutex g_logMtx;
static std::FILE* g_log = nullptr;
static std::FILE* g_errorLog = nullptr;
static HANDLE g_consoleHandle = nullptr;

enum ConsoleColor {
    COLOR_LIGHT_RED = 12,
    COLOR_RED = 4,
    COLOR_DARK_RED = 128
};

static void SetConsoleColor(ConsoleColor color) {
    if (g_consoleHandle) {
        SetConsoleTextAttribute(g_consoleHandle, color);
    }
}

static bool ShouldFilterLine(const char* line) {
    if (!line) return true;
    return false;
}

static void SetupConsole() {
    AllocConsole();
    g_consoleHandle = GetStdHandle(STD_OUTPUT_HANDLE);
    FILE* pCout;
    freopen_s(&pCout, "CONOUT$", "w", stdout);
    FILE* pCerr;
    freopen_s(&pCerr, "NUL", "w", stderr);
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleTitle(L"lRumper - IL2CPP Dumper");
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    if (GetConsoleScreenBufferInfo(g_consoleHandle, &csbi)) {
        COORD newSize;
        newSize.X = csbi.dwSize.X;
        newSize.Y = 5000;
        SetConsoleScreenBufferSize(g_consoleHandle, newSize);
    }
}

static std::string OutputPath(const char* name) {
    if (g_baseDir.empty()) {
        char buf[MAX_PATH];
        GetTempPathA(MAX_PATH, buf);
        g_baseDir = buf;
        if (!g_baseDir.empty() && g_baseDir.back() != '\\') g_baseDir.push_back('\\');
    }
    std::string p = g_baseDir;
    if (!p.empty() && p.back() != '\\') p.push_back('\\');
    p += "Dump";
    CreateDirectoryA(p.c_str(), nullptr);
    if (!p.empty() && p.back() != '\\') p.push_back('\\');
    p += name;
    return p;
}

static void LogError(const char* format, ...) {
    char buffer[2048];
    va_list args;
    va_start(args, format);
    vsnprintf(buffer, sizeof(buffer), format, args);
    va_end(args);
    std::lock_guard<std::mutex> lk(g_logMtx);
    if (g_errorLog) {
        std::fputs(buffer, g_errorLog);
        std::fputc('\n', g_errorLog);
        std::fflush(g_errorLog);
    }
    if (g_log) {
        std::fputs("[ERROR] ", g_log);
        std::fputs(buffer, g_log);
        std::fputc('\n', g_log);
        std::fflush(g_log);
    }
    OutputDebugStringA((std::string("[lRumper ERROR] ") + buffer + "\n").c_str());
}

static void LogLine(const char* format, ...) {
    char buffer[2048];
    va_list args;
    va_start(args, format);
    vsnprintf(buffer, sizeof(buffer), format, args);
    va_end(args);
    std::lock_guard<std::mutex> lk(g_logMtx);
    if (g_log) {
        std::fputs(buffer, g_log);
        std::fputc('\n', g_log);
        std::fflush(g_log);
    }
    OutputDebugStringA((std::string("[lRumper] ") + buffer + "\n").c_str());
}

static void LogConsole(ConsoleColor color, const char* format, ...) {
    char buffer[2048];
    va_list args;
    va_start(args, format);
    vsnprintf(buffer, sizeof(buffer), format, args);
    va_end(args);
    if (ShouldFilterLine(buffer)) {
        return;
    }
    std::lock_guard<std::mutex> lk(g_logMtx);
    if (g_log) {
        std::fputs(buffer, g_log);
        std::fputc('\n', g_log);
        std::fflush(g_log);
    }
    if (color == COLOR_DARK_RED && g_errorLog) {
        std::fputs(buffer, g_errorLog);
        std::fputc('\n', g_errorLog);
        std::fflush(g_errorLog);
    }
    if (g_consoleHandle) {
        DWORD written = 0;
        if (SetConsoleTextAttribute(g_consoleHandle, (WORD)color)) {
            std::string line = std::string(buffer) + "\n";
            WriteConsoleA(g_consoleHandle, line.c_str(), (DWORD)line.length(), &written, nullptr);
        }
    }
    OutputDebugStringA((std::string("[lRumper] ") + buffer + "\n").c_str());
}

struct Il2CppMethodInfo {
    void* methodPointer;
    void* invoker_method;
    const char* name;
};

struct ClassData {
    std::string ns;
    std::string name;
    std::string parent;
    bool isEnum;
    std::vector<std::string> fields;
    std::vector<std::string> methods;
    uintptr_t address;
};

static std::vector<ClassData> g_capturedClassesList;
static std::vector<ClassData> g_dumpBuffer;
static const size_t BUFFER_FLUSH_SIZE = 1000;

static std::atomic<int> g_processedClasses(0);
static std::atomic<int> g_totalErrors(0);
static std::atomic<int> g_currentIndex(0);
static std::chrono::steady_clock::time_point g_startTime;
static std::mutex g_statusMutex;
static std::mutex g_bufferMutex;

static bool SafeCopyCharBuffer(const char* ptr, char* buffer, size_t size) {
    if (!ptr || !buffer || size == 0) return false;

    bool success = false;
    __try {
        size_t i = 0;
        for (; i < size - 1; i++) {
            char c = ptr[i];
            if (c == 0) break;
            buffer[i] = c;
        }
        buffer[i] = 0;
        success = true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        success = false;
    }
    return success;
}

static std::string SafeStringCopy(const char* ptr) {
    if (!ptr) return "";
    char buffer[1024];
    buffer[0] = 0;
    if (SafeCopyCharBuffer(ptr, buffer, sizeof(buffer))) {
        return std::string(buffer);
    }
    else {
        return "<bad_string_ptr>";
    }
}

static const char* SafeGetNamespace(void* klass) {
    if (!g_get_namespace) return "";

    const char* result = "";
    __try {
        result = g_get_namespace(klass);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        result = "";
    }
    return result;
}

static const char* SafeGetName(void* klass) {
    if (!g_get_name) return nullptr;

    const char* result = nullptr;
    __try {
        result = g_get_name(klass);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        result = nullptr;
    }
    return result;
}

static void* SafeGetParent(void* klass) {
    if (!g_get_parent) return nullptr;

    void* result = nullptr;
    __try {
        result = g_get_parent(klass);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        result = nullptr;
    }
    return result;
}

static bool SafeIsEnum(void* klass) {
    if (!g_class_is_enum) return false;

    bool result = false;
    __try {
        result = g_class_is_enum(klass);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        result = false;
    }
    return result;
}

static bool SafeGetNextMethod(void* klass, void** iter, const char** name, void** ptr) {
    if (!klass || !iter || !g_get_methods) return false;

    bool result = false;
    __try {
        void* method = g_get_methods(klass, iter);
        if (method) {
            *name = nullptr;
            if (g_method_get_name) {
                __try {
                    *name = g_method_get_name(method);
                }
                __except (EXCEPTION_EXECUTE_HANDLER) {
                    *name = nullptr;
                }
            }

            __try {
                Il2CppMethodInfo* mInfo = (Il2CppMethodInfo*)method;
                *ptr = mInfo->methodPointer;
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                *ptr = nullptr;
            }

            result = true;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        result = false;
    }
    return result;
}

static bool SafeGetNextField(void* klass, void** iter, const char** name, int* flags) {
    if (!klass || !iter || !g_get_fields) return false;

    bool result = false;
    __try {
        void* field = g_get_fields(klass, iter);
        if (field) {
            *name = nullptr;
            if (g_field_get_name) {
                __try {
                    *name = g_field_get_name(field);
                }
                __except (EXCEPTION_EXECUTE_HANDLER) {
                    *name = nullptr;
                }
            }

            *flags = 0;
            if (g_field_get_flags) {
                __try {
                    *flags = g_field_get_flags(field);
                }
                __except (EXCEPTION_EXECUTE_HANDLER) {
                    *flags = 0;
                }
            }

            result = true;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        result = false;
    }
    return result;
}

static void DumpMethodsForClass(void* klass, std::vector<std::string>& outMethods) {
    if (!g_get_methods) return;

    void* iter = nullptr;
    int limit = 0;

    while (limit++ < 200) {
        const char* mName = nullptr;
        void* mPtr = nullptr;

        if (SafeGetNextMethod(klass, &iter, &mName, &mPtr)) {
            std::ostringstream ss;
            uintptr_t realRva = (uintptr_t)mPtr - g_gameAssemblyBase;
            std::string safeName = SafeStringCopy(mName);
            if (safeName.empty()) {
                std::ostringstream ns;
                ns << "Method_0x" << std::hex << realRva;
                safeName = ns.str();
            }
            ss << "    // RVA: 0x" << std::hex << realRva << " VA: 0x" << std::hex << (uintptr_t)mPtr << std::endl;
            ss << "    public System.Void " << safeName << "() { }";
            outMethods.push_back(ss.str());
        }
        else {
            break;
        }
    }
}

static void DumpFieldsForClass(void* klass, std::vector<std::string>& outFields) {
    if (!g_get_fields) return;

    void* iter = nullptr;
    int limit = 0;

    while (limit++ < 200) {
        const char* fName = nullptr;
        int fFlags = 0;

        if (SafeGetNextField(klass, &iter, &fName, &fFlags)) {
            std::string safeName = SafeStringCopy(fName);
            if (safeName.empty()) {
                static int unkCount = 0;
                std::ostringstream ns;
                ns << "UnknownField_" << unkCount++;
                safeName = ns.str();
            }
            std::ostringstream ss;
            ss << "    public System.Int32 " << safeName << "; // [Flags: 0x" << std::hex << fFlags << "]";
            outFields.push_back(ss.str());
        }
        else {
            break;
        }
    }
}

static std::unordered_set<void*> g_dumpedClasses;
static std::mutex g_dumpMutex;
static int g_lastStatusLine = -1;

static void UpdateStatusDisplay() {
    int processed = g_processedClasses.load();
    int errors = g_totalErrors.load();
    int currentIdx = g_currentIndex.load();
    auto now = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - g_startTime).count();

    if (processed > 0 && elapsed > 0 && g_consoleHandle) {
        double rate = (double)processed / elapsed;
        int remaining = currentIdx > 0 ? (currentIdx - processed) : 0;
        int estSeconds = rate > 0 ? (int)(remaining / rate) : 0;
        int hours = estSeconds / 3600;
        int minutes = (estSeconds % 3600) / 60;
        int seconds = estSeconds % 60;

        CONSOLE_SCREEN_BUFFER_INFO csbi;
        if (GetConsoleScreenBufferInfo(g_consoleHandle, &csbi)) {
            if (g_lastStatusLine >= 0) {
                for (int line = g_lastStatusLine; line < g_lastStatusLine + 3; line++) {
                    COORD pos = { 0, (SHORT)line };
                    DWORD written;
                    FillConsoleOutputCharacterA(g_consoleHandle, ' ', csbi.dwSize.X, pos, &written);
                }
            }

            COORD cursorPos = csbi.dwCursorPosition;
            g_lastStatusLine = cursorPos.Y;
            SetConsoleCursorPosition(g_consoleHandle, cursorPos);

            SetConsoleColor(COLOR_LIGHT_RED);
            std::cout << "[Status] ";
            SetConsoleColor(COLOR_RED);
            std::cout << "Processed Classes: " << processed;
            std::cout << std::endl;

            SetConsoleColor(COLOR_LIGHT_RED);
            std::cout << "[Status] ";
            SetConsoleColor(COLOR_RED);
            std::cout << "Errors: " << errors;
            std::cout << std::endl;

            SetConsoleColor(COLOR_LIGHT_RED);
            std::cout << "[Status] ";
            SetConsoleColor(COLOR_RED);
            std::cout << "Estimated Time Remaining: ";
            if (hours > 0) {
                std::cout << hours << "h " << minutes << "m";
            }
            else if (minutes > 0) {
                std::cout << minutes << "m " << seconds << "s";
            }
            else {
                std::cout << seconds << "s";
            }
            std::cout << std::endl;
            std::cout << std::flush;
        }
    }
}

static void OnClassCaptured(void* klass, const char* name) {
    if (!klass || !name) return;

    {
        std::lock_guard<std::mutex> lock(g_dumpMutex);
        if (g_dumpedClasses.count(klass) > 0) return;
        g_dumpedClasses.insert(klass);
    }

    ClassData data;
    data.address = (uintptr_t)klass;
    data.name = SafeStringCopy(name);
    data.ns = SafeStringCopy(SafeGetNamespace(klass));
    data.isEnum = SafeIsEnum(klass);
    data.parent = "";

    void* parent = SafeGetParent(klass);
    if (parent) {
        const char* pName = SafeGetName(parent);
        if (pName) data.parent = SafeStringCopy(pName);
    }

    DumpMethodsForClass(klass, data.methods);
    DumpFieldsForClass(klass, data.fields);

    {
        std::lock_guard<std::mutex> lock(g_bufferMutex);
        g_dumpBuffer.push_back(data);
        if (g_dumpBuffer.size() >= BUFFER_FLUSH_SIZE) {
            g_capturedClassesList.insert(g_capturedClassesList.end(), g_dumpBuffer.begin(), g_dumpBuffer.end());
            g_dumpBuffer.clear();
        }
    }

    g_processedClasses++;

    if (g_processedClasses.load() % 10 == 0) {
        UpdateStatusDisplay();
    }
}

static void SaveDump() {
    LogConsole(COLOR_LIGHT_RED, "[Status] Sorting and saving dump...");

    {
        std::lock_guard<std::mutex> lock(g_bufferMutex);
        if (!g_dumpBuffer.empty()) {
            g_capturedClassesList.insert(g_capturedClassesList.end(), g_dumpBuffer.begin(), g_dumpBuffer.end());
            g_dumpBuffer.clear();
        }
    }

    std::sort(g_capturedClassesList.begin(), g_capturedClassesList.end(),
        [](const ClassData& a, const ClassData& b) {
            if (a.ns != b.ns) return a.ns < b.ns;
            return a.name < b.name;
        });

    std::string outPath = OutputPath("dump.cs");
    std::ofstream file(outPath, std::ofstream::out | std::ofstream::binary);

    if (!file.is_open()) {
        LogConsole(COLOR_DARK_RED, "[Error] Failed to open dump.cs for writing!");
        return;
    }

    file << "// Generated by lRumper" << std::endl << std::endl;

    size_t classCount = 0;
    const size_t BATCH_SIZE = 200;
    std::vector<std::string> batchBuffer;
    batchBuffer.reserve(BATCH_SIZE);

    for (const auto& c : g_capturedClassesList) {
        std::ostringstream classStream;
        classStream << "// Namespace: " << c.ns << std::endl;
        classStream << "public class " << c.name;
        if (!c.parent.empty()) {
            classStream << " : " << c.parent;
        }
        else {
            classStream << " : Object";
        }
        classStream << std::endl << "{" << std::endl;

        if (!c.fields.empty()) {
            classStream << "    // Fields" << std::endl;
            for (const auto& f : c.fields) {
                classStream << f << std::endl;
            }
            classStream << std::endl;
        }

        if (!c.methods.empty()) {
            classStream << "    // Methods" << std::endl;
            for (const auto& m : c.methods) {
                classStream << m << std::endl;
            }
        }

        classStream << "}" << std::endl << std::endl << std::endl;
        batchBuffer.push_back(classStream.str());

        if (batchBuffer.size() >= BATCH_SIZE) {
            for (const auto& str : batchBuffer) {
                file << str;
            }
            file.flush();
            batchBuffer.clear();
            SwitchToThread();
        }

        classCount++;
    }

    if (!batchBuffer.empty()) {
        for (const auto& str : batchBuffer) {
            file << str;
        }
        file.flush();
    }

    file.close();
    LogConsole(COLOR_RED, "[Success] Dump saved: %s (Total classes: %zu)", outPath.c_str(), g_capturedClassesList.size());
}

static void* SafeGetTypeInfo(uint32_t index) {
    if (!g_get_type_info) return nullptr;

    void* result = nullptr;
    __try {
        result = g_get_type_info(index);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        result = nullptr;
    }
    return result;
}

static void ActiveDump() {
    LogConsole(COLOR_LIGHT_RED, "[Status] Starting active dump...");

    if (!g_get_type_info) {
        LogConsole(COLOR_DARK_RED, "[Error] Cannot start dump: GetTypeInfo is missing.");
        return;
    }

    g_startTime = std::chrono::steady_clock::now();
    g_processedClasses = 0;
    g_totalErrors = 0;
    g_currentIndex = 0;
    g_lastStatusLine = -1;

    const int BATCH_SIZE = 64;
    const int MAX_CLASSES = 300000;
    const int YIELD_INTERVAL = 8;

    int failCount = 0;
    int consecutiveErrors = 0;
    int lastLoggedClass = 0;
    int yieldCounter = 0;

    std::vector<void*> batchKlasses;
    std::vector<const char*> batchNames;
    batchKlasses.reserve(BATCH_SIZE);
    batchNames.reserve(BATCH_SIZE);

    for (uint32_t i = 0; i < MAX_CLASSES; i++) {
        g_currentIndex = i;

        void* klass = SafeGetTypeInfo(i);

        if (!klass) {
            consecutiveErrors++;
            g_totalErrors++;

            if (consecutiveErrors > 100) {
                LogConsole(COLOR_DARK_RED, "[Warning] Too many consecutive errors at index %d", i);
                break;
            }
        }

        if (klass) {
            batchKlasses.push_back(klass);
            const char* kName = SafeGetName(klass);
            batchNames.push_back(kName);

            consecutiveErrors = 0;

            if (batchKlasses.size() >= BATCH_SIZE) {
                for (size_t j = 0; j < batchKlasses.size(); j++) {
                    if (batchNames[j]) {
                        OnClassCaptured(batchKlasses[j], batchNames[j]);
                    }
                    else {
                        failCount++;
                        g_totalErrors++;
                    }
                }

                batchKlasses.clear();
                batchNames.clear();
                failCount = 0;

                int processed = g_processedClasses.load();
                if (processed - lastLoggedClass >= 250) {
                    auto now = std::chrono::steady_clock::now();
                    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - g_startTime).count();
                    double rate = elapsed > 0 ? (processed * 1000.0) / elapsed : 0;

                    LogConsole(COLOR_RED, "[Progress] %d classes | Rate: %.1f cls/sec | Errors: %d",
                        processed, rate, g_totalErrors.load());
                    lastLoggedClass = processed;
                }
            }
        }
        else {
            failCount++;
            if (failCount > 500) {
                LogConsole(COLOR_DARK_RED, "[Warning] High failure rate at index %d. Scanning next chunk...", i);

                if (!batchKlasses.empty()) {
                    for (size_t j = 0; j < batchKlasses.size(); j++) {
                        if (batchNames[j]) {
                            OnClassCaptured(batchKlasses[j], batchNames[j]);
                        }
                    }
                    batchKlasses.clear();
                    batchNames.clear();
                }

                i += 10000;
                failCount = 0;
                continue;
            }
        }

        yieldCounter++;
        if (yieldCounter >= YIELD_INTERVAL) {
            SwitchToThread();
            yieldCounter = 0;
        }

        if (i % 50 == 0) {
            UpdateStatusDisplay();
        }

        if (i % 5000 == 0 && i > 0) {
            Sleep(5);
        }
    }

    if (!batchKlasses.empty()) {
        for (size_t j = 0; j < batchKlasses.size(); j++) {
            if (batchNames[j]) {
                OnClassCaptured(batchKlasses[j], batchNames[j]);
            }
        }
    }

    UpdateStatusDisplay();

    int finalCount = g_processedClasses.load();
    int finalErrors = g_totalErrors.load();
    auto endTime = std::chrono::steady_clock::now();
    auto totalElapsed = std::chrono::duration_cast<std::chrono::seconds>(endTime - g_startTime).count();

    double avgRate = totalElapsed > 0 ? finalCount / (double)totalElapsed : 0;

    LogConsole(COLOR_RED, "[Success] Dump completed in %d seconds", totalElapsed);
    LogConsole(COLOR_RED, "[Success] Total classes: %d | Errors: %d | Avg rate: %.1f cls/sec",
        finalCount, finalErrors, avgRate);

    SaveDump();

    LogConsole(COLOR_RED, "[Success] All operations completed!");

    if (g_consoleHandle) {
        wchar_t finalTitle[256];
        swprintf_s(finalTitle, L"lRumper - COMPLETED | Classes: %d | Errors: %d", finalCount, finalErrors);
        SetConsoleTitle(finalTitle);
    }
}

static DWORD WINAPI DumpThreadProc(LPVOID) {
    ActiveDump();
    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
        char path[MAX_PATH];
        if (GetModuleFileNameA(hModule, path, MAX_PATH)) {
            std::string fullPath(path);
            std::string dllDir = fullPath.substr(0, fullPath.find_last_of("\\/"));
            size_t lastSlash = dllDir.find_last_of("\\/");
            if (lastSlash != std::string::npos) {
                g_baseDir = dllDir.substr(0, lastSlash);
            }
            else {
                g_baseDir = dllDir;
            }
        }
        DisableThreadLibraryCalls(hModule);
        CreateThread(nullptr, 0, Run, nullptr, 0, nullptr);
    }
    return TRUE;
}

DWORD WINAPI Run(LPVOID) {
    SetupConsole();
    LogConsole(COLOR_LIGHT_RED, "=~= lRumper - https://github/lRefund/lRumper/ =~=");
    LogConsole(COLOR_LIGHT_RED, "[Status] Dumper loaded. Waiting 20 seconds for game initialization...");
    Sleep(20000);

    std::string outPath = OutputPath("lRumper_log.txt");
    if (fopen_s(&g_log, outPath.c_str(), "wb") != 0) g_log = nullptr;

    std::string errorPath = OutputPath("lRumper_errors.txt");
    if (fopen_s(&g_errorLog, errorPath.c_str(), "wb") != 0) g_errorLog = nullptr;

    if (g_errorLog) {
        LogConsole(COLOR_LIGHT_RED, "[Status] Error log file: %s", errorPath.c_str());
    }

    LogLine("=== lRumper - IL2CPP Dumper ===");

    HMODULE gameModule = GetModuleHandleA("GameAssembly.dll");
    if (!gameModule) {
        gameModule = GetModuleHandleA(NULL);
        LogConsole(COLOR_RED, "[Warning] GameAssembly.dll not found, using main module.");
    }

    if (!gameModule) {
        LogConsole(COLOR_DARK_RED, "[Error] Failed to find game module!");
        return 1;
    }

    g_gameAssemblyBase = (uintptr_t)gameModule;
    LogConsole(COLOR_LIGHT_RED, "[Status] Module base address: 0x%p", (void*)g_gameAssemblyBase);

    auto Resolve = [&](const char* name, uintptr_t offset) -> void* {
        void* addr = nullptr;

        MODULEINFO modInfo = { 0 };
        bool hasModInfo = GetModuleInformation(GetCurrentProcess(), gameModule, &modInfo, sizeof(modInfo)) != 0;
        uintptr_t baseVal = (uintptr_t)modInfo.lpBaseOfDll;
        uintptr_t endVal = baseVal + modInfo.SizeOfImage;

        if (gameModule) {
            addr = (void*)GetProcAddress(gameModule, name);
            if (addr) {
                if (hasModInfo) {
                    uintptr_t addrVal = (uintptr_t)addr;
                    if (addrVal >= baseVal && addrVal < endVal) {
                        LogConsole(COLOR_RED, "[Success] %s resolved via Export: 0x%p", name, addr);
                        return addr;
                    }
                    else {
                        LogConsole(COLOR_RED, "[Warning] %s found via Export but outside module bounds. Using offset.", name);
                        addr = nullptr;
                    }
                }
                else {
                    LogConsole(COLOR_RED, "[Success] %s resolved via Export: 0x%p", name, addr);
                    return addr;
                }
            }
        }

        if (offset != 0) {
            addr = (void*)(g_gameAssemblyBase + offset);

            if (hasModInfo) {
                uintptr_t addrVal = (uintptr_t)addr;
                if (addrVal >= baseVal && addrVal < endVal) {
                    if ((addrVal & 0xFFF) == 0 || (addrVal & 0xFFF) < 0x100) {
                        LogConsole(COLOR_RED, "[Success] %s resolved via Offset: 0x%p", name, addr);
                        return addr;
                    }
                    else {
                        LogConsole(COLOR_RED, "[Warning] %s offset resolved to 0x%p", name, addr);
                        return addr;
                    }
                }
                else {
                    LogConsole(COLOR_DARK_RED, "[Error] %s: offset points outside module bounds!", name);
                    return nullptr;
                }
            }
            else {
                LogConsole(COLOR_RED, "[Warning] %s resolved via Offset without validation: 0x%p", name, addr);
                return addr;
            }
        }

        LogConsole(COLOR_DARK_RED, "[Error] Failed to resolve %s", name);
        return nullptr;
        };

    g_get_namespace = (il2cpp_class_get_namespace_t)Resolve("il2cpp_class_get_namespace", kOff_get_namespace);
    g_get_name = (il2cpp_class_get_name_t)Resolve("il2cpp_class_get_name", kOff_get_name);
    g_get_methods = (il2cpp_class_get_methods_t)Resolve("il2cpp_class_get_methods", kOff_get_methods);
    g_method_get_name = (il2cpp_method_get_name_t)Resolve("il2cpp_method_get_name", kOff_method_get_name);
    g_get_type_info = (GetTypeInfoFromTypeDefinitionIndex_t)Resolve("il2cpp_MetadataCache_GetTypeInfoFromTypeDefinitionIndex", kOff_GetTypeInfo);
    g_get_parent = (il2cpp_class_get_parent_t)Resolve("il2cpp_class_get_parent", kOff_get_parent);
    g_get_fields = (il2cpp_class_get_fields_t)Resolve("il2cpp_class_get_fields", kOff_get_fields);
    g_field_get_name = (il2cpp_field_get_name_t)Resolve("il2cpp_field_get_name", kOff_field_get_name);
    g_field_get_flags = (il2cpp_field_get_flags_t)Resolve("il2cpp_field_get_flags", kOff_field_get_flags);
    g_class_is_enum = (il2cpp_class_is_enum_t)Resolve("il2cpp_class_is_enum", kOff_is_enum);
    g_class_from_type     = (il2cpp_class_from_type_t)Resolve("il2cpp_class_from_type", kOff_class_from_type);
    g_class_get_type      = (il2cpp_class_get_type_t)Resolve("il2cpp_class_get_type", kOff_class_get_type);
    g_field_get_value     = (il2cpp_field_get_value_t)Resolve("il2cpp_field_get_value", kOff_field_get_value);
    g_klassSetupMethods   = (il2cpp_klass_setup_methods_t)Resolve("il2cpp_klass_setup_methods", kOff_klassSetupMethods);
    g_klassIsValue        = (il2cpp_class_is_valuetype_t)Resolve("il2cpp_class_is_valuetype", kOff_KlassIsValue);
    g_ClassGet_Flags      = (il2cpp_class_get_flags_t)Resolve("il2cpp_class_get_flags", kOff_ClassGet_Flags);
    g_KlassGetImage       = (il2cpp_class_get_image_t)Resolve("il2cpp_class_get_image", kOff_KlassGetImage);
    g_methodGetReturnType = (il2cpp_method_get_return_type_t)Resolve("il2cpp_method_get_return_type", kOff_methodGetReturnType);
    g_methodGetParamCount = (il2cpp_method_get_param_count_t)Resolve("il2cpp_method_get_param_count", kOff_methodGetParamCount);
    g_methodGetParam      = (il2cpp_method_get_param_t)Resolve("il2cpp_method_get_param", kOff_methodGetParam);
    g_methodGetParamName  = (il2cpp_method_get_param_name_t)Resolve("il2cpp_method_get_param_name", kOff_methodGetParamName);
    g_FieldGetOffset      = (il2cpp_field_get_offset_t)Resolve("il2cpp_field_get_offset", kOff_FieldGetOffset);
    g_FieldGetReturn_Type = (il2cpp_field_get_return_type_t)Resolve("il2cpp_field_get_type", kOff_FieldGetReturn_Type);
    g_KlassGetProps       = (il2cpp_class_get_props_t)Resolve("il2cpp_class_get_properties", kOff_KlassGetProps);
    g_klassGetInterfaces  = (il2cpp_class_get_interfaces_t)Resolve("il2cpp_class_get_interfaces", kOff_klassGetInterfaces);
    g_TypeGetName         = (il2cpp_type_get_name_t)Resolve("il2cpp_type_get_name", kOff_TypeGetName);

    struct HookReport {
        const char*  funcName;
        const char*  fieldName;
        uintptr_t    offset;
        void*        funcPtr;
        bool         critical;
    };

    HookReport reports[] = {
        { "il2cpp_class_get_namespace", "g_get_namespace",        kOff_get_namespace,       (void*)g_get_namespace,        false },
        { "il2cpp_class_get_name",      "g_get_name",             kOff_get_name,            (void*)g_get_name,             true  },
        { "il2cpp_class_get_methods",   "g_get_methods",          kOff_get_methods,         (void*)g_get_methods,          true  },
        { "il2cpp_method_get_name",     "g_method_get_name",      kOff_method_get_name,     (void*)g_method_get_name,      true  },
        { "GetTypeInfoFromTypeDefinitionIndex", "g_get_type_info", kOff_GetTypeInfo,        (void*)g_get_type_info,        true  },
        { "il2cpp_class_get_parent",    "g_get_parent",           kOff_get_parent,          (void*)g_get_parent,           false },
        { "il2cpp_class_get_fields",    "g_get_fields",           kOff_get_fields,          (void*)g_get_fields,           false },
        { "il2cpp_field_get_name",      "g_field_get_name",       kOff_field_get_name,      (void*)g_field_get_name,       false },
        { "il2cpp_field_get_flags",     "g_field_get_flags",      kOff_field_get_flags,     (void*)g_field_get_flags,      false },
        { "il2cpp_class_is_enum",       "g_class_is_enum",        kOff_is_enum,             (void*)g_class_is_enum,        false },
        { "il2cpp_class_from_type",         "g_class_from_type",        kOff_class_from_type,     (void*)g_class_from_type,        false },
        { "il2cpp_class_get_type",          "g_class_get_type",         kOff_class_get_type,      (void*)g_class_get_type,         false },
        { "il2cpp_field_get_value",         "g_field_get_value",        kOff_field_get_value,     (void*)g_field_get_value,        false },
        { "il2cpp_klass_setup_methods",     "g_klassSetupMethods",      kOff_klassSetupMethods,   (void*)g_klassSetupMethods,      false },
        { "il2cpp_class_is_valuetype",      "g_klassIsValue",           kOff_KlassIsValue,        (void*)g_klassIsValue,           false },
        { "il2cpp_class_get_flags",         "g_ClassGet_Flags",         kOff_ClassGet_Flags,      (void*)g_ClassGet_Flags,         false },
        { "il2cpp_class_get_image",         "g_KlassGetImage",          kOff_KlassGetImage,       (void*)g_KlassGetImage,          false },
        { "il2cpp_method_get_return_type",  "g_methodGetReturnType",    kOff_methodGetReturnType, (void*)g_methodGetReturnType,    false },
        { "il2cpp_method_get_param_count",  "g_methodGetParamCount",    kOff_methodGetParamCount, (void*)g_methodGetParamCount,    false },
        { "il2cpp_method_get_param",        "g_methodGetParam",         kOff_methodGetParam,      (void*)g_methodGetParam,         false },
        { "il2cpp_method_get_param_name",   "g_methodGetParamName",     kOff_methodGetParamName,  (void*)g_methodGetParamName,     false },
        { "il2cpp_field_get_offset",        "g_FieldGetOffset",         kOff_FieldGetOffset,      (void*)g_FieldGetOffset,         false },
        { "il2cpp_field_get_type",          "g_FieldGetReturn_Type",    kOff_FieldGetReturn_Type, (void*)g_FieldGetReturn_Type,    false },
        { "il2cpp_class_get_properties",    "g_KlassGetProps",          kOff_KlassGetProps,       (void*)g_KlassGetProps,          false },
        { "il2cpp_class_get_interfaces",    "g_klassGetInterfaces",     kOff_klassGetInterfaces,  (void*)g_klassGetInterfaces,     false },
        { "il2cpp_type_get_name",           "g_TypeGetName",            kOff_TypeGetName,         (void*)g_TypeGetName,            false },
    };

    int totalFunctions = sizeof(reports) / sizeof(reports[0]);
    int resolvedCount = 0;
    int missingOffset = 0;
    int failedResolve = 0;

    LogConsole(COLOR_LIGHT_RED, "[Status] ===== Offset / Hook report =====");

    for (int i = 0; i < totalFunctions; ++i) {
        const HookReport& r = reports[i];

        if (r.offset == 0) {
            if (r.funcPtr) {
                ++resolvedCount;
                LogConsole(COLOR_LIGHT_RED,
                    "[Offset] %-28s | %-16s | offset: 0x0 (NOT SET) | ptr: 0x%p%s",
                    r.funcName, r.fieldName,
                    r.funcPtr,
                    r.critical ? " | CRITICAL (EXPORT ONLY)" : " (EXPORT ONLY)");
            } else {
                ++missingOffset;
                LogConsole(COLOR_DARK_RED,
                    "[Offset] %-28s | %-16s | offset: 0x0 (NOT SET) | ptr: NULL%s",
                    r.funcName, r.fieldName,
                    r.critical ? " | CRITICAL" : "");
            }
            continue;
        }

        if (r.funcPtr) {
            ++resolvedCount;
            LogConsole(COLOR_LIGHT_RED,
                "[Offset] %-28s | %-16s | offset: 0x%p | ptr: 0x%p%s",
                r.funcName, r.fieldName,
                (void*)(g_gameAssemblyBase + r.offset),
                r.funcPtr,
                r.critical ? " | CRITICAL" : "");
        }
        else {
            ++failedResolve;
            LogConsole(COLOR_DARK_RED,
                "[Offset] %-28s | %-16s | offset: 0x%p | ptr: NULL%s",
                r.funcName, r.fieldName,
                (void*)(g_gameAssemblyBase + r.offset),
                r.critical ? " | CRITICAL" : "");
        }
    }

    LogConsole(COLOR_LIGHT_RED,
        "[Status] Offsets summary: total=%d, resolved=%d, missing_offset=%d, failed_resolve=%d",
        totalFunctions, resolvedCount, missingOffset, failedResolve);

    bool hasCriticalFunctions = true;

    if (!g_get_name) {
        LogConsole(COLOR_DARK_RED, "[Error] Critical function get_name not resolved!");
        hasCriticalFunctions = false;
    }
    if (!g_get_type_info) {
        LogConsole(COLOR_DARK_RED, "[Error] Critical function get_type_info not resolved!");
        hasCriticalFunctions = false;
    }

    if (!hasCriticalFunctions) {
        LogConsole(COLOR_DARK_RED, "[Error] Critical functions missing. Please check offsets!");
        LogConsole(COLOR_LIGHT_RED, "[Status] Waiting...");
        while (true) {
            Sleep(1000);
        }
        return 1;
    }

    if (g_get_name) {
        LogConsole(COLOR_RED, "[Warning] Passive hook skipped: function may be too small for safe hooking.");
    }

    if (g_get_type_info) {
        LogConsole(COLOR_LIGHT_RED, "[Status] Starting active dump in 2 seconds...");
        LogConsole(COLOR_LIGHT_RED, "[Status] Dump will run in background - game should remain responsive");
        Sleep(2000);

        HANDLE dumpThread = CreateThread(nullptr, 0, DumpThreadProc, nullptr, 0, nullptr);

        if (dumpThread) {
            LogConsole(COLOR_RED, "[Status] Dump thread started. You can continue playing.");
            CloseHandle(dumpThread);
        }
        else {
            LogConsole(COLOR_RED, "[Warning] Failed to create dump thread, running in current thread");
            ActiveDump();
        }
    }
    else {
        LogConsole(COLOR_DARK_RED, "[Error] Skipping active dump (TypeInfo offset missing)");
    }

    LogConsole(COLOR_RED, "[Success] Dumping completed. Console remains open for monitoring.");

    while (true) {
        Sleep(1000);
        if (g_consoleHandle) {
            int processed = g_processedClasses.load();
            int errors = g_totalErrors.load();
            wchar_t title[256];
            swprintf_s(title, L"lRumper - Classes: %d | Errors: %d", processed, errors);
            SetConsoleTitle(title);
        }
    }

    return 0;

}

