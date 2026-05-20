#include "ByteSearch.h"
#include "Log.h"
#include <atomic>
#include <cstdint>
#include <psapi.h>
#include <string>
#include <thread>
#include <vector>

// Populated by dllmain.cpp / InitThread from steam.exe!GetBootstrapperVersion.
// Empty before init or when the export is unavailable. Under the strict
// matching policy below, an empty or unmatched build id is treated as an
// unsupported Steam version.
extern std::string g_steamBuildId;

// Show an "unsupported Steam version" popup at most once per process.
// Triggered when ByteSearch cannot find a signature whose label matches
// the currently running Steam build id (or g_steamBuildId is empty).
// We deliberately do NOT fall back to "try every signature in order",
// because mis-locating an exported function leads to undefined behaviour
// and hard-to-debug crashes inside Steam.
static void ShowUnsupportedBuildPopupOnce()
{
    static std::atomic<bool> shown{false};
    bool expected = false;
    if (!shown.compare_exchange_strong(expected, true)) return;

    // Snapshot the build id at the moment of failure so the user can
    // include it in their bug report.
    std::string buildId = g_steamBuildId.empty() ? "unknown" : g_steamBuildId;

    // Detach so we never block the Steam process / hook init path.
    std::thread([buildId]() {
        std::string msg =
            "OpenSteamTool: unsupported Steam version.\n\n"
            "Detected Steam build id: " + buildId + "\n\n"
            "No matching signature was found for this Steam build, so "
            "OpenSteamTool cannot safely hook the required functions and "
            "will be disabled for this session.\n\n"
            "Please report this build id at:\n"
            "https://github.com/OpenSteam001/OpenSteamTool/issues";
        MessageBoxA(nullptr, msg.c_str(),
                    "OpenSteamTool - Unsupported Steam Version",
                    MB_OK | MB_ICONWARNING | MB_TOPMOST);
    }).detach();
}

// ---- parse "48 8B ?? C4" → bytes + mask ----
static bool ParseSignature(const char* str, std::vector<uint8_t>& bytes, std::vector<uint8_t>& mask)
{
    bytes.clear();
    mask.clear();

    for (const char* p = str; *p; ) {
        // skip delimiters
        if (*p == ' ' || *p == '\t' || *p == ',') { ++p; continue; }

        if (p[0] == '?' && p[1] == '?') {
            bytes.push_back(0);
            mask.push_back(0);       // 0 = wildcard
            p += 2;
            continue;
        }

        // expect two hex digits
        char hi = p[0], lo = p[1];
        if (!hi || !lo) return false;

        auto nib = [](char c) -> int {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            return -1;
        };
        int h = nib(hi), l = nib(lo);
        if (h < 0 || l < 0) return false;

        bytes.push_back((uint8_t)((h << 4) | l));
        mask.push_back(1);           // 1 = must match
        p += 2;
    }
    return !bytes.empty();
}

// ---- internal: single-sig scan with parsed bytes ----
static void* ScanOne(HMODULE module, const std::vector<uint8_t>& bytes,
                     const std::vector<uint8_t>& mask, int matchIndex)
{
    MODULEINFO modInfo{};
    if (!GetModuleInformation(GetCurrentProcess(), module, &modInfo, sizeof(MODULEINFO)))
        return nullptr;

    auto* base = static_cast<uint8_t*>(modInfo.lpBaseOfDll);
    SIZE_T size = modInfo.SizeOfImage;
    SIZE_T patLen = bytes.size();

    if (size < patLen) return nullptr;

    int currentMatch = 0;
    for (SIZE_T i = 0; i <= size - patLen; ++i) {
        bool found = true;
        for (SIZE_T j = 0; j < patLen; ++j) {
            if (mask[j] && base[i + j] != bytes[j]) {
                found = false;
                break;
            }
        }
        if (found && ++currentMatch == matchIndex) {
            return base + i;
        }
    }
    return nullptr;
}

// ---- try a single Signature against the module ----
static void* TrySig(HMODULE module, const char* funcName, const Signature& sig)
{
    std::vector<uint8_t> bytes, mask;
    if (!ParseSignature(sig.signature, bytes, mask)) {
        LOG_WARN("ByteSearch: {} — bad signature '{}'", funcName ? funcName : "", sig.label);
        return nullptr;
    }
    return ScanOne(module, bytes, mask, sig.matchIndex);
}

// ---- core multi-sig dispatcher ----
// Strict policy: Patterns.h labels are Steam build ids (e.g. "1778803745").
// A signature is only considered if its label exactly matches the currently
// running Steam build id. If g_steamBuildId is empty (pre-init or older
// Steam without the export), or no label matches, or the matching signature
// fails to locate the function in memory, we treat the Steam version as
// UNSUPPORTED, show a one-time popup, and return nullptr.
//
// Rationale: falling back to "try any signature that happens to match"
// risks locating the wrong function and corrupting Steam at hook time.
// A clean failure is safer than a silent mis-hook.
static void* ByteSearchImpl(HMODULE module, const char* funcName,
                            const Signature* sigs, size_t count)
{
    if (!g_steamBuildId.empty()) {
        for (size_t i = 0; i < count; ++i) {
            if (!sigs[i].label || g_steamBuildId != sigs[i].label) continue;

            if (void* addr = TrySig(module, funcName, sigs[i])) {
                if (funcName) {
                    // HMODULE on Windows is the loaded image base, so
                    // (addr - module) gives the RVA directly.
                    uintptr_t rva = reinterpret_cast<uintptr_t>(addr) -
                                    reinterpret_cast<uintptr_t>(module);
                    LOG_DEBUG("ByteSearch: {} matched build-id '{}' @ RVA 0x{:X}",
                              funcName, sigs[i].label, rva);
                }
                return addr;
            }

            // Label matched, but the byte pattern didn't hit memory —
            // treat as unsupported (the signature for this build is stale).
            LOG_WARN("ByteSearch: {} — signature for build '{}' did not match in memory",
                     funcName ? funcName : "", sigs[i].label);
            break;  // at most one entry per build id
        }
    }

    // No matching label (or matching signature didn't hit). Unsupported build.
    if (funcName) {
        LOG_WARN("ByteSearch FAILED: {} (build={}) — no signature available for this Steam version",
                 funcName,
                 g_steamBuildId.empty() ? "unknown" : g_steamBuildId.c_str());
    }
    ShowUnsupportedBuildPopupOnce();
    return nullptr;
}

// ---- multi-signature search (initializer_list) ----
void* ByteSearch(HMODULE module, const char* funcName, std::initializer_list<Signature> sigs)
{
    return ByteSearchImpl(module, funcName, sigs.begin(), sigs.size());
}

// ---- pointer + count overload ----
void* ByteSearch(HMODULE module, const char* funcName, const Signature* sigs, size_t count)
{
    return ByteSearchImpl(module, funcName, sigs, count);
}

// ---- memory patching ----
int PatchMemoryBytes(void* pAddress, const void* pNewBytes, SIZE_T nSize)
{
    if (!pAddress || !pNewBytes || nSize == 0) return 0;

    DWORD oldProtect = 0;
    if (!VirtualProtect(pAddress, nSize, PAGE_EXECUTE_READWRITE, &oldProtect))
        return 0;

    memcpy(pAddress, pNewBytes, nSize);
    FlushInstructionCache(GetCurrentProcess(), pAddress, nSize);

    DWORD tmp = 0;
    VirtualProtect(pAddress, nSize, oldProtect, &tmp);
    return 1;
}
