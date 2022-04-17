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
#include <iso1/iso1EXIDatatypes.h>
#include <iso1/iso1EXIDatatypesDecoder.h>

#include "v2gexi.h"


/* forward declare */
void proto_register_v2giso1(void);
void proto_reg_handoff_v2giso1(void);


static dissector_handle_t v2gexi_handle;

static int proto_v2giso1 = -1;

static int hf_v2giso1_struct_iso1MessageHeaderType_SessionID = -1;

/* Initialize the subtree pointers */
static gint ett_v2giso1 = -1;
static gint ett_v2giso1_header = -1;
static gint ett_v2giso1_body = -1;
static gint ett_v2giso1_array = -1;
static gint ett_v2giso1_array_i = -1;


static void
dissect_v2giso1_header(const struct iso1MessageHeaderType *header,
		       tvbuff_t *tvb,
		       proto_tree *tree,
		       gint idx,
		       const char *subtree_name)
{
	proto_tree *subtree;

	subtree = proto_tree_add_subtree(tree,
		tvb, 0, 0, idx, NULL, subtree_name);

	exi_add_bytes(subtree,
		hf_v2giso1_struct_iso1MessageHeaderType_SessionID,
		tvb,
		header->SessionID.bytes,
		header->SessionID.bytesLen,
		sizeof(header->SessionID.bytes));

	if (header->Notification_isUsed) {
		/* Notification */
		proto_tree_add_debug_text(subtree, "TODO - Notification");
	}

	if (header->Signature_isUsed) {
		/* Notification */
		proto_tree_add_debug_text(subtree, "TODO - Signature");
	}

	return;
}

static void
dissect_v2giso1_body(const struct iso1BodyType *body,
		     tvbuff_t *tvb,
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
dissect_v2giso1(tvbuff_t *tvb,
		packet_info *pinfo, proto_tree *tree _U_, void *data _U_)
{
	size_t pos;
	bitstream_t stream;
	int errn;
	struct iso1EXIDocument exiiso1;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "ISO1");
	/* Clear the info column */
	col_clear(pinfo->cinfo, COL_INFO);

	pos = 0;
	stream.size = tvb_reported_length(tvb);
	stream.pos = &pos;
	stream.data = tvb_memdup(wmem_packet_scope(),
				 tvb, pos, stream.size);
	errn = decode_iso1ExiDocument(&stream, &exiiso1);
	if (errn != 0) {
		/* decode failed */
		return 0;
	}

	/*
	 * Everything in ISO1 should come in as a messagge
	 * - Header
	 * - Body
	 */
	if (exiiso1.V2G_Message_isUsed) {
		proto_tree *v2giso1_tree;

		v2giso1_tree = proto_tree_add_subtree(tree,
			tvb, 0, 0, ett_v2giso1, NULL, "V2G Message");

		dissect_v2giso1_header(&exiiso1.V2G_Message.Header,
			tvb, v2giso1_tree, ett_v2giso1_header, "Header");
		dissect_v2giso1_body(& exiiso1.V2G_Message.Body,
			tvb, v2giso1_tree, ett_v2giso1_body, "Body");
	}

	return tvb_captured_length(tvb);
}

void
proto_register_v2giso1(void)
{

	static hf_register_info hf[] = {
		/* struct iso1MessageHeaderType */
		{ &hf_v2giso1_struct_iso1MessageHeaderType_SessionID,
		  { "SessionID", "v2giso1.struct.messageheader.sessionid",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		}
	};

	static gint *ett[] = {
		&ett_v2giso1,
		&ett_v2giso1_header,
		&ett_v2giso1_body,
		&ett_v2giso1_array,
		&ett_v2giso1_array_i,
	};

	proto_v2giso1 = proto_register_protocol(
		"V2G Efficient XML Interchange (ISO1)",
		"V2GISO1",
		"v2giso1"
	);
	proto_register_field_array(proto_v2giso1, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	register_dissector("v2giso1", dissect_v2giso1, proto_v2giso1);
}

void
proto_reg_handoff_v2giso1(void)
{

	/* add a handle for the connection oriented V2G EXI */
	v2gexi_handle = find_dissector_add_dependency("v2gexi", proto_v2giso1);
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
