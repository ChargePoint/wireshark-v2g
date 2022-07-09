/*
 * Copyright (c) 2022 ChargePoint, Inc.
 * All rights reserved.
 *
 * See LICENSE file
 */

#include "config.h"

#include <inttypes.h>
#include <stdlib.h>

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/expert.h>

/* openv2g */
#include <codec/EXITypes.h>
#include <iso2/iso2EXIDatatypes.h>
#include <iso2/iso2EXIDatatypesDecoder.h>

#include "v2gexi.h"


/* forward declare */
void proto_register_v2giso2(void);
void proto_reg_handoff_v2giso2(void);


static dissector_handle_t v2gexi_handle;

static int proto_v2giso2 = -1;

static int hf_v2giso2_struct_iso2MessageHeaderType_SessionID = -1;

/* Initialize the subtree pointers */
static gint ett_v2giso2 = -1;
static gint ett_v2giso2_header = -1;
static gint ett_v2giso2_body = -1;
static gint ett_v2giso2_array = -1;
static gint ett_v2giso2_array_i = -1;


static void
dissect_v2giso2_header(const struct iso2MessageHeaderType *header,
		       tvbuff_t *tvb,
		       proto_tree *tree,
		       gint idx,
		       const char *subtree_name)
{
	proto_tree *subtree;

	subtree = proto_tree_add_subtree(tree,
		tvb, 0, 0, idx, NULL, subtree_name);

	exi_add_bytes(subtree,
		hf_v2giso2_struct_iso2MessageHeaderType_SessionID,
		tvb,
		header->SessionID.bytes,
		header->SessionID.bytesLen,
		sizeof(header->SessionID.bytes));

	if (header->Signature_isUsed) {
		/* Notification */
		proto_tree_add_debug_text(subtree, "TODO - Signature");
	}

	return;
}

static void
dissect_v2giso2_body(const struct iso2BodyType *body,
		     tvbuff_t *tvb,
		     packet_info *pinfo,
		     proto_tree *tree,
		     gint idx,
		     const char *subtree_name)
{
	proto_tree *subtree;

	subtree = proto_tree_add_subtree(tree,
		tvb, 0, 0, idx, NULL, subtree_name);

	proto_tree_add_debug_text(subtree, "TODO");
	return;
}

static int
dissect_v2giso2(tvbuff_t *tvb,
		packet_info *pinfo, proto_tree *tree _U_, void *data _U_)
{
	size_t pos;
	bitstream_t stream;
	int errn;
	struct iso2EXIDocument *exiiso2;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "ISO2");
	/* Clear the info column */
	col_clear(pinfo->cinfo, COL_INFO);

	pos = 0;
	stream.size = tvb_reported_length(tvb);
	stream.pos = &pos;
	stream.data = tvb_memdup(wmem_packet_scope(),
				 tvb, 0, stream.size);

	exiiso2 = wmem_alloc(pinfo->pool, sizeof(*exiiso2));
	errn = decode_iso2ExiDocument(&stream, exiiso2);
	if (errn != 0) {
		wmem_free(pinfo->pool, exiiso2);
		/* decode failed */
		return 0;
	}

	/*
	 * Everything in ISO2 should come in as a messagge
	 * - Header
	 * - Body
	 */
	if (exiiso2->V2G_Message_isUsed) {
		proto_tree *v2giso2_tree;

		v2giso2_tree = proto_tree_add_subtree(tree,
			tvb, 0, 0, ett_v2giso2, NULL, "V2G ISO2 Message");

		dissect_v2giso2_header(&exiiso2->V2G_Message.Header,
			tvb, v2giso2_tree, ett_v2giso2_header, "Header");
		dissect_v2giso2_body(& exiiso2->V2G_Message.Body,
			tvb, pinfo, v2giso2_tree, ett_v2giso2_body, "Body");
	}

	wmem_free(pinfo->pool, exiiso2);
	return tvb_captured_length(tvb);
}

void
proto_register_v2giso2(void)
{

	static hf_register_info hf[] = {
		/* struct iso2MessageHeaderType */
		{ &hf_v2giso2_struct_iso2MessageHeaderType_SessionID,
		  { "SessionID", "v2giso2.struct.messageheader.sessionid",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		}
	};

	static gint *ett[] = {
		&ett_v2giso2,
		&ett_v2giso2_header,
		&ett_v2giso2_body,
		&ett_v2giso2_array,
		&ett_v2giso2_array_i,
	};

	proto_v2giso2 = proto_register_protocol(
		"V2G Efficient XML Interchange (ISO2)",
		"V2GISO2",
		"v2giso2"
	);
	proto_register_field_array(proto_v2giso2, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	register_dissector("v2giso2", dissect_v2giso2, proto_v2giso2);
}

void
proto_reg_handoff_v2giso2(void)
{

	/* add a handle for the connection oriented V2G EXI */
	v2gexi_handle = find_dissector_add_dependency("v2gexi", proto_v2giso2);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=8 tabstop=8 expandtab:
 * :indentSize=8:tabSize=8:noTabs=true:
 */
