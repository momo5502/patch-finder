#include "patch_finder.hpp"
#include "ida_sdk.hpp"

namespace momo
{
    namespace
    {

    }

    void find_patches()
    {
        msg("Hello from plugin\n");

        if (dbg)
        {
            msg("Debugger is active\n");
        }
        else
        {
            msg("Debugger is not active\n");
        }
    }
}
