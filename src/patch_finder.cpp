#include "patch_finder.hpp"

#include <fstream>
#include <cinttypes>
#include <name.hpp>
#include <streambuf>
#include <filesystem>

#include "pe_parser.hpp"

#include "ida_sdk.hpp"

namespace momo
{
    namespace
    {
        qvector<modinfo_t> get_loaded_modules()
        {
            qvector<modinfo_t> modules;

            modinfo_t modinfo{};
            bool ok = get_first_module(&modinfo);

            while (ok)
            {
                modules.push_back(modinfo);
                ok = get_next_module(&modinfo);
            }

            return modules;
        }

        std::string read_module(const std::filesystem::path& module_path)
        {
            std::ifstream stream(module_path, std::ios::binary);
            if (!stream)
            {
                return {};
            }

            return {std::istreambuf_iterator<char>(stream), std::istreambuf_iterator<char>()};
        }

        std::string read_module(const modinfo_t& modinfo)
        {
            std::string_view mod_name(modinfo.name.c_str(), modinfo.name.size());
            return read_module(mod_name);
        }

        utils::safe_buffer_accessor<const std::byte> make_accessor(const std::string_view data)
        {
            std::span view(reinterpret_cast<const std::byte*>(data.data()), data.size());
            return {view};
        }

        std::vector<uint8_t> read_section_data(ea_t start, size_t size)
        {
            std::vector<uint8_t> data(size);

            ssize_t bytes_read = get_bytes(data.data(), static_cast<ssize_t>(size), start);

            if (bytes_read == static_cast<ssize_t>(size))
            {
                return data;
            }

            if (bytes_read <= 0)
            {
                return {};
            }

            data.resize(bytes_read);
            return data;
        }

        bool is_similar_enough_for_analysis(const std::span<const uint8_t> buffer1, const std::span<const uint8_t> buffer2)
        {
            if (buffer1.size() != buffer2.size())
            {
                return false;
            }

            size_t equal_bytes = 0;

            for (size_t i = 0; i < buffer1.size(); ++i)
            {
                if (buffer1[i] == buffer2[i])
                {
                    ++equal_bytes;
                }
            }

            // Must be at least 90% equal
            return equal_bytes > ((buffer1.size() / 10) * 9);
        }

        struct patch
        {
            uint64_t address{};
            uint64_t length{};
        };

        std::vector<patch> find_patches_in_section(const section_map::value_type& section)
        {
            const auto runtime_data = read_section_data(section.first, section.second.size());
            if (!is_similar_enough_for_analysis(section.second, runtime_data))
            {
                return {};
            }

            std::vector<patch> patches{};
            std::optional<patch> current_diff{};

            const auto finish_diff = [&](const uint64_t address) {
                if (!current_diff)
                {
                    return;
                }

                current_diff->length = address - current_diff->address;
                current_diff->address += section.first;

                patches.emplace_back(*current_diff);
                current_diff.reset();
            };

            for (size_t i = 0; i < section.second.size(); ++i)
            {
                if (section.second[i] == runtime_data[i])
                {
                    if (current_diff)
                    {
                        finish_diff(i);
                    }
                }
                else if (!current_diff)
                {
                    current_diff.emplace(i);
                }
            }

            finish_diff(section.second.size());

            return patches;
        }

        void find_patches_in_module(const modinfo_t& modinfo)
        {
            const auto data = read_module(modinfo);
            const auto buffer = make_accessor(data);
            const auto sections = parse_pe_file(buffer, modinfo.base);

            std::vector<patch> patches{};

            for (const auto& section : sections)
            {
                const auto section_patches = find_patches_in_section(section);
                if (!section_patches.empty())
                {
                    patches.insert(patches.end(), section_patches.begin(), section_patches.end());
                }
            }

            for (const auto& patch : patches)
            {
                qstring symbol{};
                get_ea_name(&symbol, patch.address, GN_DEMANGLED | GN_VISIBLE | GN_SHORT);
                msg("0x%" PRIX64 " (%s) (size: 0x%" PRIX64 ") in %s\n", patch.address, symbol.c_str(), patch.length, modinfo.name.c_str());
            }
        }
    }

    void find_patches()
    {
        msg("Finding patches...\n");

        if (!is_debugger_on())
        {
            msg("Debugger is not active\n");
            return;
        }

        for (const auto& module : get_loaded_modules())
        {
            try
            {
                find_patches_in_module(module);
            }
            catch (...)
            {
                // Just ignore all issues
            }
        }

        msg("Done finding patches!\n");
    }
}
