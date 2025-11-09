
#include "Global.h"

#include "Debugger.h"

Debugger_t* g_Debugger = nullptr;

Debugger_t::~Debugger_t() {
    if (Client_) {
        Client_->EndSession(DEBUG_END_ACTIVE_DETACH);
        Client_->Release();
    }

    if (Control_) {
        Control_->Release();
    }

    if (Registers_) {
        Registers_->Release();
    }

    if (Symbols_) {
        Symbols_->Release();
    }
}

[[nodiscard]] bool Debugger_t::Initialize(const fs::path& DumpPath) {
    Logger::Log(true, ConsoleColor::DARK_GREEN, "[*] Initializing the debugger instance..\n");

    char ExePathBuffer[MAX_PATH];
    if (!GetModuleFileNameA(nullptr, &ExePathBuffer[0],
        sizeof(ExePathBuffer))) {
        Logger::Log(true, ConsoleColor::RED, "GetModuleFileNameA failed.\n");
        return false;
    }

    const fs::path ExePath(ExePathBuffer);
    const fs::path ParentDir(ExePath.parent_path());
    const std::vector<std::string_view> Dlls = { "dbghelp.dll", "symsrv.dll",
                                                "dbgeng.dll", "dbgcore.dll" };
    const fs::path DefaultDbgDllLocation(
        R"(c:\program Files (x86)\windows kits\10\debuggers\x64)");

    for (const auto& Dll : Dlls) {
        if (fs::exists(ParentDir / Dll)) {
            continue;
        }

        const fs::path DbgDllLocation(DefaultDbgDllLocation / Dll);
        if (!fs::exists(DbgDllLocation)) {
            Logger::Log(true, ConsoleColor::RED, "Cannot find required dll needed for dbgeng\n");
            return false;
        }

        fs::copy(DbgDllLocation, ParentDir);
        Logger::Log(true, ConsoleColor::GREEN, "Copied {} into the "
            "executable directory..\n",
            DbgDllLocation.generic_string());
    }

    HRESULT Status = DebugCreate(__uuidof(IDebugClient), (void**)&Client_);
    if (FAILED(Status)) {
        Logger::Log(true, ConsoleColor::RED, "[-] DebugCreate failed with hr={:#x}\n", Status);
        return false;
    }

    Status =
        Client_->QueryInterface(__uuidof(IDebugControl), (void**)&Control_);
    if (FAILED(Status)) {
        Logger::Log(true, ConsoleColor::RED, "[-] QueryInterface/IDebugControl failed with hr={:#x}\n", Status);
        return false;
    }

    Status = Client_->QueryInterface(__uuidof(IDebugRegisters),
        (void**)&Registers_);
    if (FAILED(Status)) {
        Logger::Log(true, ConsoleColor::RED, "[-] QueryInterface/IDebugRegisters failed with hr={:#x}\n",
            Status);
        return false;
    }

    Status =
        Client_->QueryInterface(__uuidof(IDebugSymbols3), (void**)&Symbols_);
    if (FAILED(Status)) {
        Logger::Log(true, ConsoleColor::RED, "[-] QueryInterface/IDebugSymbols failed with hr={:#x}\n", Status);
        return false;
    }

    Status =
        Client_->QueryInterface(__uuidof(IDebugDataSpaces4), (void**)&DataSpaces_);
    if (FAILED(Status)) {
        Logger::Log(true, ConsoleColor::RED, "[-] QueryInterface/IDebugDataSpaces4 failed with hr={:#x}\n", Status);
        return false;
    }

    const std::string& DumpFileString = DumpPath.string();
    const char* DumpFileA = DumpFileString.c_str();

    Logger::Log(true, ConsoleColor::DARK_GREEN, "[*] Processing dump file...\n");

    Status = Client_->OpenDumpFile(DumpFileA);
    if (FAILED(Status)) {
        Logger::Log(true, ConsoleColor::RED, "[-] OpenDumpFile({}) failed with hr={:#x}\n", DumpFileString,
            Status);
        return false;
    }

    Logger::Log(true, ConsoleColor::DARK_GREEN, "[*] Dump file opened.\n");

    Status = Control_->WaitForEvent(DEBUG_WAIT_DEFAULT, INFINITE);
    if (FAILED(Status)) {
        Logger::Log(true, ConsoleColor::RED, "[-] WaitForEvent for OpenDumpFile failed with hr={:#x}\n",
            Status);
        return false;
    }

    //
    // initialize modules
    //

    ULONG loaded, unloaded;
    if (FAILED(this->Symbols_->GetNumberModules(&loaded, &unloaded)))
        return false;

    for (ULONG i = 0; i < loaded; i++) {
        DEBUG_MODULE_PARAMETERS params{};
        if (FAILED(this->Symbols_->GetModuleParameters(1, nullptr, i, &params)))
            continue;

        char name[MAX_PATH] = {};
        char image[MAX_PATH] = {};

        if (FAILED(this->Symbols_->GetModuleNameString(DEBUG_MODNAME_MODULE, i, 0, name, sizeof(name), nullptr)))
            strcpy_s(name, "unknown");

        if (FAILED(this->Symbols_->GetModuleNameString(DEBUG_MODNAME_IMAGE, i, 0, image, sizeof(image), nullptr)))
            strcpy_s(image, "unknown");

        ModuleInfo info{
            .Name = name,
            .ImageName = image,
            .BaseAddress = params.Base,
            .Size = params.Size
        };
        Modules_.emplace_back(std::move(info));
    }

    Logger::Log(true, ConsoleColor::DARK_GREEN, "[*] Debugger initialized\n");

    return true;
}

const std::vector<ModuleInfo>& Debugger_t::GetModules() const {
    return Modules_;
}

std::uint64_t Debugger_t::GetSymbol(std::string_view Name) const {
    uint64_t Offset = 0;
    HRESULT Status = Symbols_->GetOffsetByName(Name.data(), &Offset);
    if (FAILED(Status)) {
        if (Status == S_FALSE) {
            return 0ull;
        }
    }

    return Offset;
}

std::string Debugger_t::GetName(std::uint64_t SymbolAddress, bool Symbolized) const {
    const size_t NameSizeMax = MAX_PATH;
    char Buffer[NameSizeMax];
    uint64_t Offset = 0;

    if (Symbolized) {
        const HRESULT Status = Symbols_->GetNameByOffset(
            SymbolAddress, Buffer, NameSizeMax, nullptr, &Offset);
        if (FAILED(Status)) {
            return "";
        }
    }
    else {
        ULONG Index;
        ULONG64 Base;
        HRESULT Status =
            Symbols_->GetModuleByOffset(SymbolAddress, 0, &Index, &Base);

        if (FAILED(Status)) {
            return "";
        }

        ULONG NameSize;
        Status = Symbols_->GetModuleNameString(DEBUG_MODNAME_MODULE, Index, Base,
            Buffer, NameSizeMax, &NameSize);

        if (FAILED(Status)) {
            return "";
        }

        Offset = SymbolAddress - Base;
    }

    return std::format("{}{}", Buffer, Offset ? std::format("+{:#x}", Offset) : "");
}

std::uint64_t Debugger_t::Evaluate64(const char* Expr) const {
    DEBUG_VALUE Value;
    Control_->Evaluate(Expr, DEBUG_VALUE_INT64, &Value, NULL);
    return Value.I64;
}

const std::uint8_t* Debugger_t::GetVirtualPage(std::uint64_t VirtualAddress) {
    std::uint64_t PageAddress = VirtualAddress & ~0xfff;
    if (DumpedPages_.contains(PageAddress)) {
        return DumpedPages_.at(PageAddress).get();
    }

    auto Page = std::make_unique<std::uint8_t[]>(0x1000);

    ULONG BytesRead = 0;
    HRESULT hr = DataSpaces_->ReadVirtual(PageAddress, Page.get(), 0x1000, &BytesRead);
    if (FAILED(hr) || BytesRead != 0x1000) {
        std::memset(Page.get(), 0, 0x1000);
    }

    DumpedPages_[PageAddress] = std::move(Page);
    return DumpedPages_.at(PageAddress).get();
}