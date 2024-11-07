#include <windows.h>
#include <string>
#include <string_view>
#include <optional>
#include <cstdint>
#include <strsafe.h>
#include "MinHook/MinHook.h"
#include "NCSIOverride.h"

HINSTANCE hModule;
HINSTANCE hNcsiDLL = nullptr;

static void MySetCapability(NCSI_INTERFACE_ATTRIBUTES *attributes, int family, int cap, int reason);
static decltype(MySetCapability) *addrSetCapability;
static decltype(MySetCapability) *originalSetCapability;

static std::optional<uintptr_t> GetSymbolOffset() {
    HKEY hk;
    auto ls = RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\NlaSvc\\Parameters\\Internet\\NCSIOverride\\Offsets", 0, KEY_READ, &hk);
    if (ls != 0) return {};

    DWORD type;
    uintptr_t offset;
    DWORD cb = sizeof(offset);
    ls = RegQueryValueExW(hk, L"NCSI_INTERFACE_ATTRIBUTES_SetCapability", nullptr, &type, reinterpret_cast<LPBYTE>(&offset), &cb);
    RegCloseKey(hk);
    if (ls != 0) return {};
    if (type != REG_TYPE_PTR) return {};

    return offset;
}

static std::optional<void *> GetSymbolAddress(HMODULE base) {
    auto offset = GetSymbolOffset();
    if (!offset) {
        OutputDebugStringA("GetSymbolOffset failed");
        return {};
    }
    auto ptr = reinterpret_cast<void *>(reinterpret_cast<uintptr_t>(base) + offset.value());
    return ptr;
}

static std::wstring GetInterfaceGUIDString(const NCSI_INTERFACE_ATTRIBUTES *attributes) {
    return std::wstring(reinterpret_cast<const wchar_t *>(reinterpret_cast<const uint8_t *>(attributes) + 72), 38);
}

static GUID GetInterfaceGUID(const NCSI_INTERFACE_ATTRIBUTES *attributes) {
    auto guidstr = GetInterfaceGUIDString(attributes);
    GUID result{};
    if (SUCCEEDED(CLSIDFromString(guidstr.c_str(), &result))) {
        return result;
    } else {
        return GUID{};
    }
}

static std::optional<int> GetCapabilityForInterface(const GUID& interfaceGuid, int family) {
    wchar_t subkey[256];
    StringCchPrintfW(subkey, 256, L"SYSTEM\\CurrentControlSet\\Services\\NlaSvc\\Parameters\\Internet\\NCSIOverride\\InterfaceOverride\\" FORMAT_GUID, GUID_ARG(interfaceGuid));

    HKEY hk;
    auto ls = RegOpenKeyExW(HKEY_LOCAL_MACHINE, subkey, 0, KEY_READ, &hk);
    if (ls != 0) return {};

    DWORD regtype;
    int result;
    DWORD buflen = 4;
    ls = RegQueryValueExW(hk, family == 0 ? L"OverrideV4" : L"OverrideV6", nullptr, &regtype, reinterpret_cast<LPBYTE>(&result), &buflen);
    RegCloseKey(hk);

    if (ls == 0 && regtype == REG_DWORD) return result;
    return {};
}

static std::optional<int> GetDefaultCapabilityOverride(int family) {
    HKEY hk;
    auto ls = RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\NlaSvc\\Parameters\\Internet\\NCSIOverride", 0, KEY_READ, &hk);
    if (ls != 0) return {};

    DWORD regtype;
    int result;
    DWORD buflen = 4;
    ls = RegQueryValueExW(hk, family == 0 ? L"DefaultOverrideV4" : L"DefaultOverrideV6", nullptr, &regtype, reinterpret_cast<LPBYTE>(&result), &buflen);
    RegCloseKey(hk);

    if (ls == 0 && regtype == REG_DWORD) return result;
    return {};
}

static std::optional<int> GetResultantCapabilityOverride(const GUID &interfaceGuid, int family) {
    auto ifcap = GetCapabilityForInterface(interfaceGuid, family);
    if (ifcap) return ifcap;
    auto defaultcap = GetDefaultCapabilityOverride(family);
    if (defaultcap) return defaultcap;
    return {};
}

static void MySetCapability(NCSI_INTERFACE_ATTRIBUTES *attributes, int family, int cap, int reason) {
    char buf[256];
    auto ifguid = GetInterfaceGUID(attributes);
    auto origcap = cap;
    auto optcap = GetResultantCapabilityOverride(ifguid, family);
    if (optcap) {
        cap = *optcap;
        StringCbPrintfA(buf, 512, "NCSI_INTERFACE_ATTRIBUTES::SetCapability(%p = " FORMAT_GUID ", %d, %d -> %d, %d)", attributes, GUID_ARG(ifguid), family, origcap, cap, reason);
    } else {
        StringCbPrintfA(buf, 512, "NCSI_INTERFACE_ATTRIBUTES::SetCapability(%p = " FORMAT_GUID ", %d, %d, %d)", attributes, GUID_ARG(ifguid), family, cap, reason);
    }
    OutputDebugStringA(buf);
    addrSetCapability(attributes, family, cap, reason);
}

static bool SetupHook() {
    hNcsiDLL = LoadLibrary("ncsi.dll");
    BOOL_CHECK_NULL(hNcsiDLL, "Failed to load ncsi.dll");

    auto optSetCapability = GetSymbolAddress(hNcsiDLL);
    BOOL_CHECK_NULL(optSetCapability, "GetSymbolAddress returned null");
    addrSetCapability = reinterpret_cast<decltype(addrSetCapability)>(optSetCapability.value());
    if (*reinterpret_cast<uint16_t *>(addrSetCapability) != 0x5540) {  // Check for "push rbp" prolog
        OutputDebugStringA("NCSI_INTERFACE_ATTRIBUTES::SetCapability prolog check failed.");
        return false;
    }

    MH_STATUS MHResult;
    MHResult = MH_Initialize();
    BOOL_CHECK_MH_RESULT(MHResult);
    MHResult = MH_CreateHook(reinterpret_cast<void *>(addrSetCapability), reinterpret_cast<void *>(MySetCapability), reinterpret_cast<void **>(&originalSetCapability));
    BOOL_CHECK_MH_RESULT(MHResult);
    MHResult = MH_EnableHook(MH_ALL_HOOKS);
    BOOL_CHECK_MH_RESULT(MHResult);

    OutputDebugStringA("NCSI_INTERFACE_ATTRIBUTES::SetCapability hooked");
    return true;
}

static DWORD WINAPI ThreadProcessAttaching(LPVOID lpThreadParameter) {
    OutputDebugStringA("NCSIOverride loaded");
    SetupHook();
    return 0;
}

static bool UnloadHook() {
    if (!hNcsiDLL) return false;

    MH_STATUS MHResult;
    MHResult = MH_Uninitialize();
    if (MHResult != MH_OK) OutputDebugStringA(MH_StatusToString(MHResult));

    BOOL result = FreeLibrary(hNcsiDLL);
    hNcsiDLL = nullptr;
    if (!result) OutputDebugStringA("Failed to free ncsi.dll");

    return true;
}

static DWORD WINAPI ThreadProcessDetaching(LPVOID lpThreadParameter) {
    OutputDebugStringA("NCSIOverride detaching from process");
    UnloadHook();
    return 0;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved) {
    switch (fdwReason) {
        case DLL_PROCESS_ATTACH:
            hModule = hinstDLL;
            CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE) ThreadProcessAttaching, NULL, 0, NULL);
            break;
        case DLL_THREAD_ATTACH:
            break;
        case DLL_THREAD_DETACH:
            break;
        case DLL_PROCESS_DETACH:
            CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE) ThreadProcessDetaching, NULL, 0, NULL);
            break;
    }
    return TRUE;
}
