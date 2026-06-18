#pragma once

// Portable PE/COFF type definitions — replaces <Windows.h> for the structures
// rop_scanner needs to parse. Layout follows Microsoft's PE/COFF specification
// (open spec, not Windows-only). All sizes are validated with static_assert.
//
// Keep this header self-contained: do NOT include <Windows.h> here.

#include <cstdint>
#include <cstddef>

namespace rop {
namespace pe {

using BYTE      = uint8_t;
using WORD      = uint16_t;
using DWORD     = uint32_t;
using LONG      = int32_t;
using ULONGLONG = uint64_t;

// ---- Signatures & magic constants ----------------------------------------
constexpr WORD  IMAGE_DOS_SIGNATURE             = 0x5A4D;       // "MZ"
constexpr DWORD IMAGE_NT_SIGNATURE              = 0x00004550;   // "PE\0\0"
constexpr WORD  IMAGE_NT_OPTIONAL_HDR32_MAGIC   = 0x010B;
constexpr WORD  IMAGE_NT_OPTIONAL_HDR64_MAGIC   = 0x020B;

constexpr WORD  IMAGE_FILE_MACHINE_I386         = 0x014C;
constexpr WORD  IMAGE_FILE_MACHINE_AMD64        = 0x8664;

constexpr DWORD IMAGE_SCN_MEM_EXECUTE           = 0x20000000;

constexpr DWORD IMAGE_DIRECTORY_ENTRY_EXPORT      = 0;
constexpr DWORD IMAGE_DIRECTORY_ENTRY_EXCEPTION   = 3;
constexpr DWORD IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG = 10;

constexpr size_t IMAGE_NUMBEROF_DIRECTORY_ENTRIES = 16;

#pragma pack(push, 1)

// ---- DOS header ----------------------------------------------------------
struct IMAGE_DOS_HEADER {
    WORD  e_magic;
    WORD  e_cblp;
    WORD  e_cp;
    WORD  e_crlc;
    WORD  e_cparhdr;
    WORD  e_minalloc;
    WORD  e_maxalloc;
    WORD  e_ss;
    WORD  e_sp;
    WORD  e_csum;
    WORD  e_ip;
    WORD  e_cs;
    WORD  e_lfarlc;
    WORD  e_ovno;
    WORD  e_res[4];
    WORD  e_oemid;
    WORD  e_oeminfo;
    WORD  e_res2[10];
    LONG  e_lfanew;
};
static_assert(sizeof(IMAGE_DOS_HEADER) == 64, "IMAGE_DOS_HEADER must be 64 bytes");

// ---- File header ---------------------------------------------------------
struct IMAGE_FILE_HEADER {
    WORD  Machine;
    WORD  NumberOfSections;
    DWORD TimeDateStamp;
    DWORD PointerToSymbolTable;
    DWORD NumberOfSymbols;
    WORD  SizeOfOptionalHeader;
    WORD  Characteristics;
};
static_assert(sizeof(IMAGE_FILE_HEADER) == 20, "IMAGE_FILE_HEADER must be 20 bytes");

struct IMAGE_DATA_DIRECTORY {
    DWORD VirtualAddress;
    DWORD Size;
};
static_assert(sizeof(IMAGE_DATA_DIRECTORY) == 8, "");

// ---- Optional headers ----------------------------------------------------
struct IMAGE_OPTIONAL_HEADER32 {
    WORD  Magic;
    BYTE  MajorLinkerVersion;
    BYTE  MinorLinkerVersion;
    DWORD SizeOfCode;
    DWORD SizeOfInitializedData;
    DWORD SizeOfUninitializedData;
    DWORD AddressOfEntryPoint;
    DWORD BaseOfCode;
    DWORD BaseOfData;
    DWORD ImageBase;
    DWORD SectionAlignment;
    DWORD FileAlignment;
    WORD  MajorOperatingSystemVersion;
    WORD  MinorOperatingSystemVersion;
    WORD  MajorImageVersion;
    WORD  MinorImageVersion;
    WORD  MajorSubsystemVersion;
    WORD  MinorSubsystemVersion;
    DWORD Win32VersionValue;
    DWORD SizeOfImage;
    DWORD SizeOfHeaders;
    DWORD CheckSum;
    WORD  Subsystem;
    WORD  DllCharacteristics;
    DWORD SizeOfStackReserve;
    DWORD SizeOfStackCommit;
    DWORD SizeOfHeapReserve;
    DWORD SizeOfHeapCommit;
    DWORD LoaderFlags;
    DWORD NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
};
static_assert(sizeof(IMAGE_OPTIONAL_HEADER32) == 224, "");

struct IMAGE_OPTIONAL_HEADER64 {
    WORD      Magic;
    BYTE      MajorLinkerVersion;
    BYTE      MinorLinkerVersion;
    DWORD     SizeOfCode;
    DWORD     SizeOfInitializedData;
    DWORD     SizeOfUninitializedData;
    DWORD     AddressOfEntryPoint;
    DWORD     BaseOfCode;
    ULONGLONG ImageBase;
    DWORD     SectionAlignment;
    DWORD     FileAlignment;
    WORD      MajorOperatingSystemVersion;
    WORD      MinorOperatingSystemVersion;
    WORD      MajorImageVersion;
    WORD      MinorImageVersion;
    WORD      MajorSubsystemVersion;
    WORD      MinorSubsystemVersion;
    DWORD     Win32VersionValue;
    DWORD     SizeOfImage;
    DWORD     SizeOfHeaders;
    DWORD     CheckSum;
    WORD      Subsystem;
    WORD      DllCharacteristics;
    ULONGLONG SizeOfStackReserve;
    ULONGLONG SizeOfStackCommit;
    ULONGLONG SizeOfHeapReserve;
    ULONGLONG SizeOfHeapCommit;
    DWORD     LoaderFlags;
    DWORD     NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
};
static_assert(sizeof(IMAGE_OPTIONAL_HEADER64) == 240, "");

// ---- Section header ------------------------------------------------------
struct IMAGE_SECTION_HEADER {
    BYTE  Name[8];
    union {
        DWORD PhysicalAddress;
        DWORD VirtualSize;
    } Misc;
    DWORD VirtualAddress;
    DWORD SizeOfRawData;
    DWORD PointerToRawData;
    DWORD PointerToRelocations;
    DWORD PointerToLinenumbers;
    WORD  NumberOfRelocations;
    WORD  NumberOfLinenumbers;
    DWORD Characteristics;
};
static_assert(sizeof(IMAGE_SECTION_HEADER) == 40, "");

// ---- Export directory ----------------------------------------------------
struct IMAGE_EXPORT_DIRECTORY {
    DWORD Characteristics;
    DWORD TimeDateStamp;
    WORD  MajorVersion;
    WORD  MinorVersion;
    DWORD Name;
    DWORD Base;
    DWORD NumberOfFunctions;
    DWORD NumberOfNames;
    DWORD AddressOfFunctions;
    DWORD AddressOfNames;
    DWORD AddressOfNameOrdinals;
};
static_assert(sizeof(IMAGE_EXPORT_DIRECTORY) == 40, "");

// ---- Exception / .pdata --------------------------------------------------
// x64 only — PE32+ uses fixed-size RUNTIME_FUNCTION records in .pdata.
struct RUNTIME_FUNCTION {
    DWORD BeginAddress;
    DWORD EndAddress;
    DWORD UnwindData;
};
static_assert(sizeof(RUNTIME_FUNCTION) == 12, "");

// ---- Load config directory (truncated at GuardFlags) ---------------------
// Microsoft's full struct grows with each Windows release (XFG, CET, etc.).
// We only need fields through GuardFlags for CFG support; the trailing fields
// in real binaries don't hurt us because we just don't read them.
struct IMAGE_LOAD_CONFIG_DIRECTORY32 {
    DWORD     Size;
    DWORD     TimeDateStamp;
    WORD      MajorVersion;
    WORD      MinorVersion;
    DWORD     GlobalFlagsClear;
    DWORD     GlobalFlagsSet;
    DWORD     CriticalSectionDefaultTimeout;
    DWORD     DeCommitFreeBlockThreshold;
    DWORD     DeCommitTotalFreeThreshold;
    DWORD     LockPrefixTable;
    DWORD     MaximumAllocationSize;
    DWORD     VirtualMemoryThreshold;
    DWORD     ProcessHeapFlags;
    DWORD     ProcessAffinityMask;
    WORD      CSDVersion;
    WORD      DependentLoadFlags;
    DWORD     EditList;
    DWORD     SecurityCookie;
    DWORD     SEHandlerTable;
    DWORD     SEHandlerCount;
    DWORD     GuardCFCheckFunctionPointer;
    DWORD     GuardCFDispatchFunctionPointer;
    DWORD     GuardCFFunctionTable;
    DWORD     GuardCFFunctionCount;
    DWORD     GuardFlags;
};

struct IMAGE_LOAD_CONFIG_DIRECTORY64 {
    DWORD     Size;
    DWORD     TimeDateStamp;
    WORD      MajorVersion;
    WORD      MinorVersion;
    DWORD     GlobalFlagsClear;
    DWORD     GlobalFlagsSet;
    DWORD     CriticalSectionDefaultTimeout;
    ULONGLONG DeCommitFreeBlockThreshold;
    ULONGLONG DeCommitTotalFreeThreshold;
    ULONGLONG LockPrefixTable;
    ULONGLONG MaximumAllocationSize;
    ULONGLONG VirtualMemoryThreshold;
    ULONGLONG ProcessAffinityMask;
    DWORD     ProcessHeapFlags;
    WORD      CSDVersion;
    WORD      DependentLoadFlags;
    ULONGLONG EditList;
    ULONGLONG SecurityCookie;
    ULONGLONG SEHandlerTable;
    ULONGLONG SEHandlerCount;
    ULONGLONG GuardCFCheckFunctionPointer;
    ULONGLONG GuardCFDispatchFunctionPointer;
    ULONGLONG GuardCFFunctionTable;
    ULONGLONG GuardCFFunctionCount;
    DWORD     GuardFlags;
};

#pragma pack(pop)

} // namespace pe
} // namespace rop
