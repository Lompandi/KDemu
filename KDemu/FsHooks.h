#pragma once

#include "Global.h"
#include "NtType.hpp"

#include <span>
#include <string>
#include <memory>
#include <cstdint>
#include <unordered_map>

// using NTSTATUS = ULONG;

typedef struct _UNICODE_STRING_EMU {
    USHORT		Length;
    USHORT		MaximumLength;
    char16_t* Buffer;
} UNICODE_STRING_EMU, * PUNICODE_STRING_EMU;

/*typedef struct _IO_STATUS_BLOCK {
    union {
        ULONG	 Status;
        PVOID    Pointer;
    };
    ULONG_PTR Information;
} IO_STATUS_BLOCK, * PIO_STATUS_BLOCK;*/

struct OBJECT_ATTRIBUTES_EMU {
public:
    ~OBJECT_ATTRIBUTES_EMU();

    bool ReadFromGuest(uc_engine* uc, std::uint64_t Address);

    std::shared_ptr<char16_t[]> GetObjectName() const;

private:
    ULONG           Length;
    HANDLE          RootDirectory;
    UNICODE_STRING_EMU* ObjectName;
    ULONG           Attributes;
    PVOID           SecurityDescriptor;
    PVOID           SecurityQualityOfService;
};

typedef enum _FILE_INFORMATION_CLASS {
    FileDirectoryInformation = 1,
    FileFullDirectoryInformation = 2,
    FileBothDirectoryInformation = 3,
    FileBasicInformation = 4,
    FileStandardInformation = 5,
    FileInternalInformation = 6,
    FileEaInformation = 7,
    FileAccessInformation = 8,
    FileNameInformation = 9,
    FileRenameInformation = 10,
    FileLinkInformation = 11,
    FileNamesInformation = 12,
    FileDispositionInformation = 13,
    FilePositionInformation = 14,
    FileFullEaInformation = 15,
    FileModeInformation = 16,
    FileAlignmentInformation = 17,
    FileAllInformation = 18,
    FileAllocationInformation = 19,
    FileEndOfFileInformation = 20,
    FileAlternateNameInformation = 21,
    FileStreamInformation = 22,
    FilePipeInformation = 23,
    FilePipeLocalInformation = 24,
    FilePipeRemoteInformation = 25,
    FileMailslotQueryInformation = 26,
    FileMailslotSetInformation = 27,
    FileCompressionInformation = 28,
    FileObjectIdInformation = 29,
    FileCompletionInformation = 30,
    FileMoveClusterInformation = 31,
    FileQuotaInformation = 32,
    FileReparsePointInformation = 33,
    FileNetworkOpenInformation = 34,
    FileAttributeTagInformation = 35,
    FileTrackingInformation = 36,
    FileIdBothDirectoryInformation = 37,
    FileIdFullDirectoryInformation = 38,
    FileValidDataLengthInformation = 39,
    FileShortNameInformation = 40,
    FileIoCompletionNotificationInformation = 41,
    FileIoStatusBlockRangeInformation = 42,
    FileIoPriorityHintInformation = 43,
    FileSfioReserveInformation = 44,
    FileSfioVolumeInformation = 45,
    FileHardLinkInformation = 46,
    FileProcessIdsUsingFileInformation = 47,
    FileNormalizedNameInformation = 48,
    FileNetworkPhysicalNameInformation = 49,
    FileIdGlobalTxDirectoryInformation = 50,
    FileIsRemoteDeviceInformation = 51,
    FileUnusedInformation = 52,
    FileNumaNodeInformation = 53,
    FileStandardLinkInformation = 54,
    FileRemoteProtocolInformation = 55,
    FileRenameInformationBypassAccessCheck = 56,
    FileLinkInformationBypassAccessCheck = 57,
    FileVolumeNameInformation = 58,
    FileIdInformation = 59,
    FileIdExtdDirectoryInformation = 60,
    FileReplaceCompletionInformation = 61,
    FileHardLinkFullIdInformation = 62,
    FileIdExtdBothDirectoryInformation = 63,
    FileDispositionInformationEx = 64,
    FileRenameInformationEx = 65,
    FileRenameInformationExBypassAccessCheck = 66,
    FileDesiredStorageClassInformation = 67,
    FileStatInformation = 68,
    FileMemoryPartitionInformation = 69,
    FileStatLxInformation = 70,
    FileCaseSensitiveInformation = 71,
    FileLinkInformationEx = 72,
    FileLinkInformationExBypassAccessCheck = 73,
    FileStorageReserveIdInformation = 74,
    FileCaseSensitiveInformationForceAccessCheck = 75,
    FileKnownFolderInformation = 76,
    FileStatBasicInformation = 77,
    FileId64ExtdDirectoryInformation = 78,
    FileId64ExtdBothDirectoryInformation = 79,
    FileIdAllExtdDirectoryInformation = 80,
    FileIdAllExtdBothDirectoryInformation = 81,
    FileStreamReservationInformation,
    FileMupProviderInfo,
    FileMaximumInformation
} FILE_INFORMATION_CLASS, * PFILE_INFORMATION_CLASS;

namespace hooks {

    // bool FsSetup(uc_engine* Emu);

    void FsCreateFile(uc_engine* Emu);

    void FsCloseFile(uc_engine* Emu);

    void FsWriteFile(uc_engine* Emu);

    void FsReadFile(uc_engine* Emu);

    void FsQueryFileInfo(uc_engine* Emu);
}


class FsHandleTable {
public:
    FsHandleTable(std::u16string FsRootPath) : FsRootPath_(FsRootPath), CurrentHandle_(0x100) {}

    bool AddFsHandle(HANDLE handle, const std::u16string& name);

    bool CloseFsHandle(HANDLE handle);

    bool ReadFsFile(HANDLE handle, NTSTATUS& status, IO_STATUS_BLOCK* host_io_status_block, std::uint8_t* buffer, const std::uint32_t length, const std::uint64_t byte_offset = 0);

    bool WriteFsFile(HANDLE handle, std::span<std::uint8_t> data, const std::uint64_t offset = 0);

    HANDLE CreateFsFile(const std::u16string& path, const std::size_t desire_size = 0);

    bool FileExist(const std::u16string& path) const;

    bool FileActive(const HANDLE handle) const;

    bool QueryFileInformation(const HANDLE handle, NTSTATUS& status, IO_STATUS_BLOCK* io_status_block, const uint8_t* HostFileInformation, const uint32_t Length,
        const FILE_INFORMATION_CLASS FileInformationClass) const;

    std::u16string GetName(const HANDLE handle) const;

    std::u16string TranslateRootfs(const std::u16string& path) const;
private:
    HANDLE AllocateHandle();

    std::uint64_t CurrentHandle_;

    std::u16string FsRootPath_;

    std::unordered_map<HANDLE, std::u16string> ActiveFiles_;
};

struct FILE_BASIC_INFORMATION {
    uint64_t CreationTime;
    uint64_t LastAccessTime;
    uint64_t LastWriteTime;
    uint64_t ChangeTime;
    uint32_t FileAttributes;
};

static_assert(sizeof(FILE_BASIC_INFORMATION) == 0x28);

struct FILE_DISPOSITION_INFORMATION {
    uint8_t DeleteFile;
};

static_assert(sizeof(FILE_DISPOSITION_INFORMATION) == 1);

struct FILE_POSITION_INFORMATION {
    uint64_t CurrentByteOffset;
};

static_assert(sizeof(FILE_POSITION_INFORMATION) == 8);

struct FILE_FS_DEVICE_INFORMATION {
    uint32_t DeviceType;
    int32_t MaximumComponentNameLength;
};

static_assert(sizeof(FILE_FS_DEVICE_INFORMATION) == 8);

struct FILE_ATTRIBUTE_TAG_INFORMATION {
    uint32_t FileAttributes;
    uint32_t ReparseTag;
};

static_assert(sizeof(FILE_ATTRIBUTE_TAG_INFORMATION) == 8);

/*struct FILE_STANDARD_INFORMATION {
    uint64_t AllocationSize;
    uint64_t EndOfFile;
    uint32_t NumberOfLinks;
    uint8_t DeletePending;
    uint8_t Directory;
};

static_assert(sizeof(FILE_STANDARD_INFORMATION) == 0x18);*/

struct FILE_END_OF_FILE_INFORMATION {
    uint64_t EndOfFile;
};

static_assert(sizeof(FILE_END_OF_FILE_INFORMATION) == 8);

struct FILE_ALLOCATION_INFORMATION {
    uint64_t AllocationSize;
};

static_assert(sizeof(FILE_ALLOCATION_INFORMATION) == 8);

#define FILE_SUPERSEDE 0x00000000
#define FILE_OPEN 0x00000001
#define FILE_CREATE 0x00000002
#define FILE_OPEN_IF 0x00000003
#define FILE_OVERWRITE 0x00000004
#define FILE_OVERWRITE_IF 0x00000005

#define FILE_DIRECTORY_FILE 0x00000001
#define FILE_WRITE_THROUGH 0x00000002
#define FILE_SEQUENTIAL_ONLY 0x00000004
#define FILE_NO_INTERMEDIATE_BUFFERING 0x00000008
#define FILE_SYNCHRONOUS_IO_ALERT 0x00000010
#define FILE_SYNCHRONOUS_IO_NONALERT 0x00000020
#define FILE_NON_DIRECTORY_FILE 0x00000040
#define FILE_CREATE_TREE_CONNECTION 0x00000080
#define FILE_COMPLETE_IF_OPLOCKED 0x00000100
#define FILE_NO_EA_KNOWLEDGE 0x00000200
#define FILE_OPEN_FOR_RECOVERY 0x00000400
#define FILE_RANDOM_ACCESS 0x00000800
#define FILE_DELETE_ON_CLOSE 0x00001000
#define FILE_OPEN_BY_FILE_ID 0x00002000
#define FILE_OPEN_FOR_BACKUP_INTENT 0x00004000
#define FILE_NO_COMPRESSION 0x00008000
#define FILE_OPEN_REQUIRING_OPLOCK 0x00010000
#define FILE_DISALLOW_EXCLUSIVE 0x00020000
#define FILE_SESSION_AWARE 0x00040000
#define FILE_RESERVE_OPFILTER 0x00100000
#define FILE_OPEN_REPARSE_POINT 0x00200000
#define FILE_OPEN_NO_RECALL 0x00400000
#define FILE_OPEN_FOR_FREE_SPACE_QUERY 0x00800000

#define FILE_SUPERSEDED 0x00000000
#define FILE_OPENED 0x00000001
#define FILE_CREATED 0x00000002
#define FILE_OVERWRITTEN 0x00000003
#define FILE_EXISTS 0x00000004
#define FILE_DOES_NOT_EXIST 0x00000005

extern FsHandleTable g_FsHandleTable;