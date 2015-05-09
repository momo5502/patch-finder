#include "ida_sdk.hpp"
#include "patch_finder.hpp"

namespace momo
{
    namespace
    {
        namespace plugin
        {
            constexpr const char* name = "Patch Finder";

            plugmod_t* idaapi initialize()
            {
                return PLUGIN_OK;
            }

            void idaapi terminate()
            {
            }

            bool idaapi run(size_t /*arg*/)
            {
                find_patches();
                return true;
            }

            consteval plugin_t create()
            {
                return {
                    .version = IDP_INTERFACE_VERSION,
                    .flags = PLUGIN_UNL,
                    .init = plugin::initialize,
                    .term = plugin::terminate,
                    .run = plugin::run,
                    .comment = plugin::name,
                    .help = plugin::name,
                    .wanted_name = plugin::name,
                    .wanted_hotkey = nullptr,
                };
            }
        }
    }
}

plugin_t PLUGIN = momo::plugin::create();
