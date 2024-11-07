#pragma once

#include <windows.h>

#pragma comment(linker, "/export:ServiceMain=netprofmsvc.ServiceMain")
#pragma comment(linker, "/export:SvchostPushServiceGlobalsEx=netprofmsvc.SvchostPushServiceGlobalsEx")

#ifdef __cplusplus
extern "C" {
    struct NCSI_INTERFACE_ATTRIBUTES;
}
#endif

#ifdef _WIN64
#define REG_TYPE_PTR REG_QWORD
#else
#define REG_TYPE_PTR REG_DWORD
#endif

#define FORMAT_GUID "{%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}"
#define GUID_ARG(guid) guid.Data1, guid.Data2, guid.Data3, guid.Data4[0], guid.Data4[1], guid.Data4[2], guid.Data4[3], guid.Data4[4], guid.Data4[5], guid.Data4[6], guid.Data4[7]

#define BOOL_CHECK_NULL(val, msg)     \
    do {                              \
        if (!val) {                   \
            OutputDebugStringA(msg);  \
            return false;             \
        }                             \
    } while (0)

#define BOOL_CHECK_MH_RESULT(MHResult)                        \
    do {                                                      \
        if (MHResult != MH_OK) {                              \
            OutputDebugStringA(MH_StatusToString(MHResult));  \
            return false;                                     \
        }                                                     \
    } while (0)
