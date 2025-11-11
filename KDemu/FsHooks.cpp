
#include "FsHooks.h"
#include "UnicornEmu.hpp"

#include <fstream>
#include <filesystem>
#include <ntstatus.h>

class FsHandleTable g_FsHandleTable(u"D:\\ve-windows-rootfs-new");

namespace fs = std::filesystem;

const static uint32_t CreateDispositionToIob(const uint32_t CreateDisposition) {
    switch (CreateDisposition) {
    case FILE_SUPERSEDE: {
        return FILE_SUPERSEDE;
    }
    case FILE_OPEN: {
        return FILE_OPENED;
    }
    case FILE_OPEN_IF:
    case FILE_CREATE: {
        return FILE_CREATED;
    }
    case FILE_OVERWRITE:
    case FILE_OVERWRITE_IF: {
        return FILE_OVERWRITTEN;
    }
    default: {
        Logger::Log(true, ConsoleColor::YELLOW, "fs:Unknown disposition: 0x%lx\n", CreateDisposition);
    }
    }

    // std::unreachable();
}

namespace hooks {

    /*bool FsSetup(Emulator_t* Emu) {
        Emu->AddHook("nt!IoCreateFileEx", [](Emulator_t* Emu) { FsCreateFile(Emu); });
        Emu->AddHook("nt!ZwClose", [](Emulator_t* Emu) { FsCloseFile(Emu); });
        Emu->AddHook("nt!ZwReadFile", [](Emulator_t* Emu) { FsReadFile(Emu); });
        Emu->AddHook("nt!ZwWriteFile", [](Emulator_t* Emu) { FsWriteFile(Emu); });
        Emu->AddHook("nt!ZwQueryInformationFile", [](Emulator_t* Emu) { FsQueryFileInfo(Emu); });

        return true;
    }*/

    void FsCreateFile(uc_engine* uc) {

        /*
        NTSTATUS IoCreateFileEx(
            [out]          PHANDLE                   FileHandle,
            [in]           ACCESS_MASK               DesiredAccess,
            [in]           POBJECT_ATTRIBUTES_EMU        ObjectAttributes,
            [out]          PIO_STATUS_BLOCK          IoStatusBlock,
            [in, optional] PLARGE_INTEGER            AllocationSize,
            [in]           ULONG                     FileAttributes,
            [in]           ULONG                     ShareAccess,
            [in]           ULONG                     Disposition,
            [in]           ULONG                     CreateOptions,
            [in, optional] PVOID                     EaBuffer,
            [in]           ULONG                     EaLength,
            [in]           CREATE_FILE_TYPE          CreateFileType,
            [in, optional] PVOID                     InternalParameters,
            [in]           ULONG                     Options,
            [in, optional] PIO_DRIVER_CREATE_CONTEXT DriverContext
        );
        */
        
        auto emu = Emu(uc);

        std::uint64_t FileHandle = emu->get_arg(0);
        std::uint64_t DesiredAccess = emu->get_arg(1);
        std::uint64_t ObjectAttributes = emu->get_arg(2);
        std::uint64_t IoStatusBlock = emu->get_arg(3);
        std::uint64_t AllocationSize = emu->get_arg(4);
        std::uint64_t FileAttributes = emu->get_arg(5);
        std::uint64_t ShareAccess = emu->get_arg(6);
        std::uint64_t Disposition = emu->get_arg(7);
        std::uint64_t CreateOptions = emu->get_arg(8);
        std::uint64_t EaBuffer = emu->get_arg(9);
        std::uint64_t EaLength = emu->get_arg(10);
        std::uint64_t CreateFileType = emu->get_arg(11);
        std::uint64_t InternalParameters = emu->get_arg(12);
        std::uint64_t Options = emu->get_arg(13);
        std::uint64_t DriverContext = emu->get_arg(14);

        OBJECT_ATTRIBUTES_EMU HostObjectAttributes;
        if (!HostObjectAttributes.ReadFromGuest(uc, ObjectAttributes)) {
            Logger::Log(true, RED, "Failed to read OBJECT_ATTRIBUTES_EMU from emulator.\n");
            exit(0);
        }

        std::u16string file_name(HostObjectAttributes.GetObjectName().get());

        Logger::Log(true, GREEN, "\tFile Name : %s\n", U16StringToString(file_name).c_str());

        IO_STATUS_BLOCK HostIoStatusBlock;
        emu->try_read(IoStatusBlock, &HostIoStatusBlock, sizeof(IoStatusBlock));

        const bool exist = g_FsHandleTable.FileExist(file_name);
        const bool failed_request = (exist && Disposition == FILE_CREATE) ||
            (!exist && Disposition == FILE_OPEN);

        if (failed_request) {
            const NTSTATUS status = STATUS_OBJECT_NAME_NOT_FOUND;
            HostIoStatusBlock.Status = status;
            HostIoStatusBlock.Information = 0;
            emu->try_write(IoStatusBlock, &HostIoStatusBlock, sizeof(HostIoStatusBlock));

            emu->rax(status);
            RetHook(uc);
            return;
        }

        std::uint64_t desire_allocation_size = 0;
        if (AllocationSize) {
            desire_allocation_size = emu->qword(AllocationSize);
        }

        if (DesiredAccess & FILE_APPEND_DATA) {
            Logger::Log(true, RED, "fs: FILE_APPEND_DATA hasn't been implemented.\n");
            exit(0);
        }

        const HANDLE guest_handle = g_FsHandleTable.CreateFsFile(file_name, desire_allocation_size);
        Logger::Log(true, GREEN, "fs: Opening 0x%lx for %s\n", (uint64_t)guest_handle,
            U16StringToString(file_name).c_str());

        const NTSTATUS status = STATUS_SUCCESS;
        HostIoStatusBlock.Status = status;
        HostIoStatusBlock.Information
            = CreateDispositionToIob(Disposition);

        emu->try_write(FileHandle, &guest_handle, sizeof(guest_handle));
        emu->try_write(IoStatusBlock, &HostIoStatusBlock, sizeof(HostIoStatusBlock));

        emu->rax(status);
        RetHook(uc);
    }

    void FsCloseFile(uc_engine* uc) {
        /*
        NTSYSAPI NTSTATUS ZwClose(
            [in] HANDLE Handle
        );
        */

        auto emu = Emu(uc);

        const HANDLE handle = HANDLE(emu->get_arg(0));

        if (handle == INVALID_HANDLE_VALUE || !g_FsHandleTable.FileActive(handle)) {
            //
            // We will still retunr SUCCESS for these cases
            //
            const NTSTATUS Status = STATUS_SUCCESS;
            emu->rax(Status);
            RetHook(uc);
            return;
        }

        const NTSTATUS Status = STATUS_SUCCESS;
        g_FsHandleTable.CloseFsHandle(handle);
        emu->rax(Status);
        RetHook(uc);
        return;
    }

    void FsWriteFile(uc_engine* uc) {
        /*
        NTSYSAPI NTSTATUS ZwWriteFile(
            [in]           HANDLE           FileHandle,
            [in, optional] HANDLE           Event,
            [in, optional] PIO_APC_ROUTINE  ApcRoutine,
            [in, optional] PVOID            ApcContext,
            [out]          PIO_STATUS_BLOCK IoStatusBlock,
            [in]           PVOID            Buffer,
            [in]           ULONG            Length,
            [in, optional] PLARGE_INTEGER   ByteOffset,
            [in, optional] PULONG           Key
        );
        */

        auto emu = Emu(uc);

        const auto FileHandle = HANDLE(emu->get_arg(0));
        const std::uint64_t Event = emu->get_arg(1);
        const std::uint64_t ApcRoutine = emu->get_arg(2);
        const std::uint64_t ApcContext = emu->get_arg(3);
        const std::uint64_t IoStatusBlock = emu->get_arg(4);
        const std::uint64_t Buffer = emu->get_arg(5);
        const std::uint32_t Length = emu->get_arg(6);
        const std::uint64_t ByteOffset = emu->get_arg(7);
        const std::uint64_t Key = emu->get_arg(8);

        const std::uint64_t HostByteOffset = ByteOffset ? emu->qword(ByteOffset) : 0;

        IO_STATUS_BLOCK HostIoStatusBlock;
        emu->try_read(IoStatusBlock, &HostIoStatusBlock, sizeof(HostIoStatusBlock));

        if (!g_FsHandleTable.FileActive(FileHandle)) {
            const NTSTATUS status = STATUS_FILE_NOT_AVAILABLE;

            HostIoStatusBlock.Status = status;
            HostIoStatusBlock.Information = 0;

            emu->try_read(IoStatusBlock, &HostIoStatusBlock, sizeof(HostIoStatusBlock));
            emu->rax(status);
            RetHook(uc);
            return;
        }

        const NTSTATUS Status = STATUS_SUCCESS;
        HostIoStatusBlock.Status = Status;

        Logger::Log(true, GREEN, "fs: Writing file: %s\n", U16StringToString(g_FsHandleTable.GetName(FileHandle)).c_str());

        if (!Length) {
            Logger::Log(true, YELLOW, "fs: Writing empty file\n");
        }
        else {
            auto HostBuffer = std::make_unique<std::uint8_t[]>(Length);
            emu->try_read(Buffer, HostBuffer.get(), Length);

            g_FsHandleTable.WriteFsFile(FileHandle, { HostBuffer.get(), Length }, HostByteOffset);
        }

        emu->try_read(IoStatusBlock, &HostIoStatusBlock, sizeof(HostIoStatusBlock));
        emu->rax(Status);
        RetHook(uc);
    }

    void FsReadFile(uc_engine* uc) {
        /*
       NTSYSAPI NTSTATUS ZwReadFile(
           [in]           HANDLE           FileHandle,
           [in, optional] HANDLE           Event,
           [in, optional] PIO_APC_ROUTINE  ApcRoutine,
           [in, optional] PVOID            ApcContext,
           [out]          PIO_STATUS_BLOCK IoStatusBlock,
           [out]          PVOID            Buffer,
           [in]           ULONG            Length,
           [in, optional] PLARGE_INTEGER   ByteOffset,
           [in, optional] PULONG           Key
       );
       */

        auto emu = Emu(uc);

        const auto file_handle = HANDLE(emu->get_arg(0));
        const auto event = HANDLE(emu->get_arg(1));
        const std::uint64_t apc_routine = emu->get_arg(2);
        const std::uint64_t apc_context = emu->get_arg(3);
        const std::uint64_t io_status_block = emu->get_arg(4);
        const std::uint64_t buffer = emu->get_arg(5);
        const std::uint32_t length = emu->get_arg(6);
        const std::uint64_t pbyte_offset = emu->get_arg(7);
        const std::uint64_t key = emu->get_arg(8);

        std::uint64_t byte_offset = pbyte_offset ? emu->qword(pbyte_offset) : 0;

        if (!g_FsHandleTable.FileActive(file_handle)) {
            return;
        }

        IO_STATUS_BLOCK host_io_status_block;
        emu->try_read(io_status_block, &host_io_status_block, sizeof(host_io_status_block));

        auto host_buffer = std::make_unique<std::uint8_t[]>(length);

        NTSTATUS status;
        g_FsHandleTable.ReadFsFile(file_handle, status, &host_io_status_block, host_buffer.get(), length, byte_offset);

        emu->try_write(buffer, host_buffer.get(), length);
        emu->try_write(io_status_block, &host_io_status_block, sizeof(host_io_status_block));

        emu->rax(status);
        RetHook(uc);
    }

    void FsQueryFileInfo(uc_engine* uc) {
        /*
        NTSYSAPI NTSTATUS ZwQueryInformationFile(
            [in]  HANDLE                 FileHandle,
            [out] PIO_STATUS_BLOCK       IoStatusBlock,
            [out] PVOID                  FileInformation,
            [in]  ULONG                  Length,
            [in]  FILE_INFORMATION_CLASS FileInformationClass
        );
        */

        auto emu = Emu(uc);

        const auto file_handle = HANDLE(emu->get_arg(0));
        const std::uint64_t guest_io_status_block = emu->get_arg(1);
        const std::uint64_t guest_file_info = emu->get_arg(2);
        const std::uint32_t length = emu->get_arg(3);
        const FILE_INFORMATION_CLASS file_information_class
            = FILE_INFORMATION_CLASS(emu->get_arg(4));

        if (!g_FsHandleTable.FileActive(file_handle)) {
            return;
        }

        IO_STATUS_BLOCK host_io_status_block;
        emu->try_read(guest_io_status_block, &host_io_status_block, sizeof(host_io_status_block));

        auto host_file_info = std::make_unique<std::uint8_t[]>(length);

        NTSTATUS status;
        const bool syscall_success = g_FsHandleTable.QueryFileInformation(
            file_handle, status, &host_io_status_block, host_file_info.get(), length,
            file_information_class);

        emu->try_write(guest_file_info, host_file_info.get(), length);
        emu->try_write(guest_io_status_block, &host_io_status_block, sizeof(host_io_status_block));

        emu->rax(status);
        RetHook(uc);
    }
}

bool FsHandleTable::AddFsHandle(HANDLE handle, const std::u16string& name) {
    ActiveFiles_[handle] = name;
    return true;
}

bool FsHandleTable::CloseFsHandle(HANDLE handle) {
    if (!ActiveFiles_.contains(handle)) {
        Logger::Log(true, ConsoleColor::RED, "fs: Cannot close non - active file handle : 0x%lx\n", (uint64_t)handle);
        return false;
    }

    ActiveFiles_.erase(handle);
    return true;
}

bool FsHandleTable::ReadFsFile(HANDLE handle, NTSTATUS& status, IO_STATUS_BLOCK* host_io_status_block,
    std::uint8_t* buffer, const std::uint32_t length,
    const std::uint64_t byte_offset) {
    const fs::path file_path(ActiveFiles_.at(handle));
    if (!fs::exists(file_path)) {
        return false;
    }

    const std::size_t file_size = fs::file_size(file_path);

    const std::uint64_t remaining_bytes = file_size - byte_offset;
    const std::uint64_t size_to_read = std::min<std::uint64_t>(length, remaining_bytes);

    if (size_to_read == 0) {
        Logger::Log(true, ConsoleColor::RED, "Invalid size and offset being passed into the function\n");
        status = STATUS_END_OF_FILE;
    }
    else {
        std::ifstream file(file_path, std::ios::binary);
        file.seekg(byte_offset, std::ios::beg);
        file.read(std::bit_cast<char*>(buffer), size_to_read);

        status = STATUS_SUCCESS;
    }

    host_io_status_block->Status = status;
    host_io_status_block->Information = size_to_read;
    return true;
}

bool FsHandleTable::WriteFsFile(HANDLE handle, std::span<std::uint8_t> data, const std::uint64_t offset) {
    if (!ActiveFiles_.contains(handle)) {
        Logger::Log(true, ConsoleColor::RED, "fs: Cannot write to non-active file handle: 0x%lx\n", (uint64_t)handle);
        return false;
    }

    const fs::path file_path(ActiveFiles_.at(handle));
    if (!fs::exists(file_path)) {
        return false;
    }

    // Open for read/write without truncating existing content
    std::fstream fs(file_path, std::ios::in | std::ios::out | std::ios::binary);
    if (!fs) {
        // If file does not exist yet, create it
        fs.open(file_path, std::ios::out | std::ios::binary);
        fs.close();

        fs.open(file_path, std::ios::in | std::ios::out | std::ios::binary);
        if (!fs) {
            Logger::Log(true, ConsoleColor::RED, "fs: Failed to open or create file for writing.\n");
            return false;
        }
    }

    fs.seekp(static_cast<std::streamoff>(offset));
    if (!fs) {
        Logger::Log(true, ConsoleColor::RED, "fs: Failed to seek to offset %d\n", offset);
        return false;
    }

    fs.write(std::bit_cast<char*>(data.data()), static_cast<std::streamsize>(data.size()));
    if (!fs) {
        Logger::Log(true, ConsoleColor::RED, "fs: Failed to write to file at offset %d\n", offset);
        return false;
    }

    fs.close();
    return true;
}

bool FsHandleTable::FileExist(const std::u16string& path) const {
    const std::u16string& translated_path = TranslateRootfs(path);

    fs::path fs_path(translated_path);
    return fs::exists(fs_path);
}


HANDLE FsHandleTable::CreateFsFile(const std::u16string& path, const std::size_t desire_size) {
    const fs::path file_path(TranslateRootfs(path));

    if (!fs::exists(file_path)) {
        if (file_path.has_parent_path()) {
            std::error_code ec;
            fs::create_directories(file_path.parent_path(), ec);
            if (ec) {
                Logger::Log(true, ConsoleColor::RED, "fs: Failed to create directories: %s\n", ec.message().c_str());
                return INVALID_HANDLE_VALUE;
            }
        }

        // Open file in binary + truncate mode
        std::ofstream ofs(file_path, std::ios::binary | std::ios::trunc);
        if (!ofs) {
            return INVALID_HANDLE_VALUE;
        }

        // Resize the file while keeping it open
        if (desire_size > 0) {
            ofs.seekp(desire_size - 1);  // Move to desired position
            ofs.put('\0');               // Write a null byte to force expansion
            ofs.flush();                 // Ensure changes are committed
        }
    }
    else {
        Logger::Log(true, ConsoleColor::YELLOW, "fs: Creating existing file: %s\n", file_path.string().c_str());
    }

    auto file_handle = AllocateHandle();
    ActiveFiles_[file_handle] = file_path.u16string();

    return file_handle;
}

std::u16string FsHandleTable::GetName(const HANDLE handle) const {
    return ActiveFiles_.contains(handle) ? ActiveFiles_.at(handle) : u"";
}

std::u16string FsHandleTable::TranslateRootfs(const std::u16string& path) const {
    std::u16string working_path = path;

    const std::u16string nt_prefix = u"\\??\\";
    if (working_path.compare(0, nt_prefix.size(), nt_prefix) == 0) {
        working_path = working_path.substr(nt_prefix.size());
    }

    std::filesystem::path original(working_path);
    std::filesystem::path rootfs(FsRootPath_);

    std::filesystem::path relative = original.relative_path();
    std::filesystem::path final_path = rootfs / relative;

    return final_path.u16string();  // std::u16string on Windows
}

bool FsHandleTable::FileActive(const HANDLE handle) const {
    return ActiveFiles_.contains(handle);
}

bool FsHandleTable::QueryFileInformation(const HANDLE handle, NTSTATUS& status, IO_STATUS_BLOCK* io_status_block, const uint8_t* HostFileInformation, const uint32_t Length,
    const FILE_INFORMATION_CLASS FileInformationClass) const {

    auto AlignUp = [](std::size_t N, std::size_t Alignment) -> std::size_t {
        return ((N + Alignment - 1) / Alignment) * Alignment;
    };

    status = STATUS_INVALID_PARAMETER;

    const auto& file_path = GetName(handle);

    if (file_path.empty()) {
        Logger::Log(true, ConsoleColor::RED, "Failed to locate file\n");
        return false;
    }

    std::size_t file_size = fs::file_size(file_path);
    Logger::Log(true, ConsoleColor::GREEN, "Querying file information for : %s\n", U16StringToString(file_path).c_str());

    const bool IsFileAttributeTagInfo =
        FileInformationClass ==
        FILE_INFORMATION_CLASS::FileAttributeTagInformation &&
        Length == sizeof(FILE_ATTRIBUTE_TAG_INFORMATION);

    const bool IsFilePositionInfo =
        FileInformationClass ==
        FILE_INFORMATION_CLASS::FilePositionInformation &&
        Length == sizeof(FILE_POSITION_INFORMATION);

    const bool IsFileStandardInfo =
        FileInformationClass ==
        FILE_INFORMATION_CLASS::FileStandardInformation &&
        Length == sizeof(FILE_STANDARD_INFORMATION);

    if (IsFileAttributeTagInfo) {
        Logger::Log(true, ConsoleColor::GREEN, "\tInformation class: FileAttributeTagInformation.\n");
        const auto FileAttributeTagInfo =
            (FILE_ATTRIBUTE_TAG_INFORMATION*)HostFileInformation;

        FileAttributeTagInfo->FileAttributes = 0;
        FileAttributeTagInfo->ReparseTag = 0;
    }
    else if (IsFilePositionInfo) {
        const auto FilePositionInfo =
            (FILE_POSITION_INFORMATION*)HostFileInformation;

        const uint64_t Offset = 0;
        FilePositionInfo->CurrentByteOffset = Offset;
        Logger::Log(true, ConsoleColor::GREEN, "\tInformation class: FilePositionInformation({:#x}).\n", Offset);
    }
    else if (IsFileStandardInfo) {
        const auto FileStandardInfo =
            (FILE_STANDARD_INFORMATION*)HostFileInformation;
        FileStandardInfo->AllocationSize = AlignUp(file_size, 0x1000);
        FileStandardInfo->EndOfFile = file_size;
        FileStandardInfo->NumberOfLinks = 1;
        FileStandardInfo->DeletePending = false; //DEBUG
        FileStandardInfo->Directory = 0;

        Logger::Log(true, ConsoleColor::GREEN,
            "FileStandardInformation(AllocationSize={:#x}, EndOfFile={:#x}).\n",
            FileStandardInfo->AllocationSize, FileStandardInfo->EndOfFile);
    }
    else {
        Logger::Log(true, ConsoleColor::YELLOW, "\tUnsupported class.\n");
        return false;
    }

    //
    // Populate the IOB.
    //

    status = STATUS_SUCCESS;
    io_status_block->Status = status;
    io_status_block->Information = Length;
    return true;
}

HANDLE FsHandleTable::AllocateHandle() {
    HANDLE target = reinterpret_cast<HANDLE>(CurrentHandle_);
    CurrentHandle_ += 1;
    return target;
}

bool OBJECT_ATTRIBUTES_EMU::ReadFromGuest(uc_engine* uc, std::uint64_t Address) {
    auto emu = Emu(uc);
    if (uc_mem_read(uc, Address, this, sizeof(OBJECT_ATTRIBUTES_EMU)) != UC_ERR_OK) {
        Logger::Log(true, RED, "OBJECT_ATTRIBUTES_EMU::ReadFromGuest : Read of OBJECT_ATTRIBUTES_EMU failed\n");
        return false;
    }

    auto object_name = static_cast<UNICODE_STRING_EMU*>(std::malloc(sizeof(UNICODE_STRING_EMU)));
    if (object_name == nullptr) {
        Logger::Log(true, RED, "Allocation of UNICODE_STRING_EMU failed\n");
        return false;
    }

    if (uc_mem_read(uc, reinterpret_cast<std::uint64_t>(this->ObjectName), object_name, sizeof(UNICODE_STRING_EMU)) != UC_ERR_OK) {
        Logger::Log(true, RED, "Read of UNICODE_STRING_EMU failed\n");
        std::free(object_name);
        return false;
    }

    auto object_name_buffer = static_cast<char16_t*>(std::malloc(object_name->Length));
    if (object_name_buffer == nullptr) {
        Logger::Log(true, RED, "Allocation of ObjectNameBuffer failed\n");
        std::free(object_name);
        return false;
    }

    if (uc_mem_read(uc, reinterpret_cast<std::uint64_t>(object_name->Buffer), object_name_buffer, object_name->Length) != UC_ERR_OK) {
        Logger::Log(true, RED, "Read of ObjectNameBuffer failed\n");
        std::free(object_name_buffer);
        std::free(object_name);
        return false;
    }

    object_name->Buffer = object_name_buffer;
    this->ObjectName = object_name;

    return true;
}

OBJECT_ATTRIBUTES_EMU::~OBJECT_ATTRIBUTES_EMU() {
    if (ObjectName) {
        std::free(ObjectName->Buffer);
        std::free(ObjectName);
        ObjectName = nullptr;
    }
}

std::shared_ptr<char16_t[]> OBJECT_ATTRIBUTES_EMU::GetObjectName() const {
    if (!ObjectName || !ObjectName->Buffer || ObjectName->Length == 0)
        return nullptr;

    std::size_t char_count = ObjectName->Length / sizeof(char16_t);
    auto buffer = std::make_shared<char16_t[]>(char_count + 1);

    std::memcpy(buffer.get(), ObjectName->Buffer, ObjectName->Length);
    buffer[char_count] = u'\0';

    return buffer;
}