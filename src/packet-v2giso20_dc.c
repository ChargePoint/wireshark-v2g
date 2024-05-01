/*
 * Copyright (c) 2022-2024 ChargePoint, Inc.
 * All rights reserved.
 *
 * See LICENSE file
 */

#include <inttypes.h>
#include <stdlib.h>

#include <wireshark.h>
#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/expert.h>

/* libcbv2g */
#include <cbv2g/iso_20/iso20_DC_Datatypes.h>
#include <cbv2g/iso_20/iso20_DC_Decoder.h>

#include "v2gexi.h"


/* forward declare */
void proto_register_v2giso20_dc(void);
void proto_reg_handoff_v2giso20_dc(void);


static dissector_handle_t v2gexi_handle;
static dissector_handle_t v2gber_handle;

static int proto_v2giso20_dc = -1;

/* Initialize the subtree pointers */
static gint ett_v2giso20_dc = -1;
static gint ett_v2giso20_dc_document = -1;
static gint ett_v2giso20_dc_header = -1;
static gint ett_v2giso20_dc_array = -1;
static gint ett_v2giso20_dc_array_i = -1;
static gint ett_v2giso20_dc_asn1 = -1;


static void
dissect_v2giso20_dc_document(
	const struct iso20_dc_exiDocument *doc _U_,
	tvbuff_t *tvb _U_,
	packet_info *pinfo _U_,
	proto_tree *tree _U_,
	gint idx _U_,
	const char *subtree_name _U_)
{
	return;
}

static int
dissect_v2giso20_dc(tvbuff_t *tvb,
		    packet_info *pinfo, proto_tree *tree _U_, void *data _U_)
{
	proto_tree *v2giso20_dc_tree;
	size_t size;
	exi_bitstream_t stream;
	int errn;
	struct iso20_dc_exiDocument *exiiso20_dc;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "ISO20_DC");
	/* Clear the info column */
	col_clear(pinfo->cinfo, COL_INFO);

	size = tvb_reported_length(tvb);
	exi_bitstream_init(&stream,
			   tvb_memdup(wmem_packet_scope(), tvb, 0, size),
			   size, 0, NULL);

	exiiso20_dc = wmem_alloc(pinfo->pool, sizeof(*exiiso20_dc));
	errn = decode_iso20_dc_exiDocument(&stream, exiiso20_dc);
	if (errn != 0) {
		wmem_free(pinfo->pool, exiiso20_dc);
		/* decode failed */
		return 0;
	}

	/*
	 * Everything in ISO20 DC should come in as a document
	 */
	v2giso20_dc_tree = proto_tree_add_subtree(tree,
		tvb, 0, 0, ett_v2giso20_dc, NULL, "V2G ISO20 DC");

	dissect_v2giso20_dc_document(exiiso20_dc,
		tvb, pinfo, v2giso20_dc_tree,
		ett_v2giso20_dc_document, "Document");

	wmem_free(pinfo->pool, exiiso20_dc);
	return tvb_captured_length(tvb);
}

void
proto_register_v2giso20_dc(void)
{

	static hf_register_info hf[] = {
	};

	static gint *ett[] = {
		&ett_v2giso20_dc,
		&ett_v2giso20_dc_document,
		&ett_v2giso20_dc_header,
		&ett_v2giso20_dc_array,
		&ett_v2giso20_dc_array_i,
		&ett_v2giso20_dc_asn1,
	};

	proto_v2giso20_dc = proto_register_protocol(
		"V2G Efficient XML Interchange (ISO20 DC)",
		"V2GISO20_DC",
		"v2giso20_dc"
	);
	proto_register_field_array(proto_v2giso20_dc, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	register_dissector("v2giso20_dc", dissect_v2giso20_dc, proto_v2giso20_dc);
}

void
proto_reg_handoff_v2giso20_dc(void)
{

	/* add a handle for the connection oriented V2G EXI */
	v2gexi_handle = find_dissector_add_dependency("v2gexi", proto_v2giso20_dc);
	v2gber_handle = find_dissector("ber");
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
