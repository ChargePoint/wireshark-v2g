/*
 * Do not modify this file. Changes will be overwritten.
 *
 * Generated automatically from make-plugin-reg.py.
 */

/* plugins are DLLs on Windows */
#define WS_BUILD_DLL
#include "ws_symbol_export.h"

#include <wireshark.h>
#include <epan/packet.h>
#include <epan/proto.h>

void proto_register_v2gdin(void);
void proto_register_v2gexi(void);
void proto_register_v2giso2(void);
void proto_register_v2giso20(void);
void proto_reg_handoff_v2gdin(void);
void proto_reg_handoff_v2gexi(void);
void proto_reg_handoff_v2giso2(void);
void proto_reg_handoff_v2giso20(void);

WS_DLL_PUBLIC_DEF const gchar plugin_version[] = VERSION;
WS_DLL_PUBLIC_DEF const int plugin_want_major = WIRESHARK_VERSION_MAJOR;
WS_DLL_PUBLIC_DEF const int plugin_want_minor = WIRESHARK_VERSION_MINOR;

WS_DLL_PUBLIC void plugin_register(void);

void plugin_register(void)
{
    static proto_plugin plug_v2gdin;

    plug_v2gdin.register_protoinfo = proto_register_v2gdin;
    plug_v2gdin.register_handoff = proto_reg_handoff_v2gdin;
    proto_register_plugin(&plug_v2gdin);
    static proto_plugin plug_v2gexi;

    plug_v2gexi.register_protoinfo = proto_register_v2gexi;
    plug_v2gexi.register_handoff = proto_reg_handoff_v2gexi;
    proto_register_plugin(&plug_v2gexi);
    static proto_plugin plug_v2giso2;

    plug_v2giso2.register_protoinfo = proto_register_v2giso2;
    plug_v2giso2.register_handoff = proto_reg_handoff_v2giso2;
    proto_register_plugin(&plug_v2giso2);
    static proto_plugin plug_v2giso20;

    plug_v2giso20.register_protoinfo = proto_register_v2giso20;
    plug_v2giso20.register_handoff = proto_reg_handoff_v2giso20;
    proto_register_plugin(&plug_v2giso20);
}
