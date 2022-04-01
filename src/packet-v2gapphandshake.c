/*
 * V2G AppHandshake
 */

#include "config.h"

#include <inttypes.h>
#include <stdlib.h>

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/expert.h>
#include <epan/wmem/wmem.h>

#define V2GAHS_PORT 1234

static int proto_v2gahs = -1;

static int
dissect_v2gahs(tvbuff_t *tvb,
	       packet_info *pinfo, proto_tree *tree _U_, void *data _U_)
{
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "FOO");
	/* Clear the info column */
	col_clear(pinfo->cinfo,COL_INFO);

	return tvb_captured_length(tvb);
}

void
proto_register_v2gahs(void)
{
	proto_v2gahs = proto_register_protocol (
		"V2G EXI AppHandshake",
		"V2GAHS",
		"v2gahs"
	);
}

void
proto_reg_handoff_v2gahs(void)
{
	static dissector_handle_t v2gahs_handle;

	v2gahs_handle = create_dissector_handle(dissect_v2gahs, proto_v2gahs);
	dissector_add_uint("udp.port", V2GAHS_PORT, v2gahs_handle);
}
