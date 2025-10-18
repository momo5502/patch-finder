#include "patch_finder.hpp"

#include <fstream>
#include <cinttypes>
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

            return std::string(std::istreambuf_iterator<char>(stream), std::istreambuf_iterator<char>());
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

        void find_patches_in_section(const section_map::value_type& section)
        {
get_fileregion_ea()
            
            
            msg("Module: %s at 0x%" PRIX64 " (size: %d)\n", module.name.c_str(), module.base, module.size);
        }

        void find_patches_in_module(const modinfo_t& modinfo)
        {
            const auto data = read_module(modinfo);
            const auto buffer = make_accessor(data);
            const auto sections = parse_pe_file(buffer, modinfo.base);

            for (const auto& section : sections)
            {
                find_patches_in_section(section);
            }
        }
    }

    void find_patches()
    {
        msg("Hello from plugin\n");

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
    }
}
