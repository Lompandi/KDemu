#pragma once

#include <dbgeng.h>
#include <filesystem>
#include <unordered_map>

#pragma comment(lib, "dbgeng.lib")

namespace fs = std::filesystem;

struct ModuleInfo {
	std::string Name;
	std::string ImageName;
	std::uint64_t BaseAddress;
	std::uint64_t Size;
};

class Debugger_t {
public:
	Debugger_t() = default;

	~Debugger_t();

	Debugger_t(const Debugger_t&) = delete;
	Debugger_t& operator=(const Debugger_t&) = delete;

	[[nodiscard]] bool Initialize(const fs::path& DumpPath);

	std::uint64_t GetSymbol(std::string_view Name) const;

	std::string GetName(std::uint64_t SymbolAddress, bool Symbolized) const;

	const std::vector<ModuleInfo>& GetModules() const;

	const std::uint8_t* GetVirtualPage(std::uint64_t Gva);

	std::uint64_t Evaluate64(const char* Expr) const;

private:
	IDebugClient4* Client_;
	IDebugControl4* Control_;
	IDebugRegisters2* Registers_;
	IDebugDataSpaces4* DataSpaces_;
	IDebugSymbols3* Symbols_;

	std::vector<ModuleInfo> Modules_;

	std::unordered_map<std::string, uint64_t> SymbolCache_;

	std::unordered_map<std::uint64_t, std::unique_ptr<std::uint8_t[]>> DumpedPages_;
};

extern Debugger_t* g_Debugger;