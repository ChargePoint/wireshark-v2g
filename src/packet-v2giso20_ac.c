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
#include <cbv2g/iso_20/iso20_AC_Datatypes.h>
#include <cbv2g/iso_20/iso20_AC_Decoder.h>

#include "v2gexi.h"


/* forward declare */
void proto_register_v2giso20_ac(void);
void proto_reg_handoff_v2giso20_ac(void);


static dissector_handle_t v2gexi_handle;
static dissector_handle_t v2gber_handle;

static int proto_v2giso20_ac = -1;

/* Initialize the subtree pointers */
static gint ett_v2giso20_ac = -1;
static gint ett_v2giso20_ac_document = -1;
static gint ett_v2giso20_ac_header = -1;
static gint ett_v2giso20_ac_array = -1;
static gint ett_v2giso20_ac_array_i = -1;
static gint ett_v2giso20_ac_asn1 = -1;

static gint ett_struct_iso20_ac_AC_ChargeParameterDiscoveryReqType = -1;
static gint ett_struct_iso20_ac_AC_ChargeParameterDiscoveryResType = -1;
static gint ett_struct_iso20_ac_AC_ChargeLoopReqType = -1;
static gint ett_struct_iso20_ac_AC_ChargeLoopResType = -1;
static gint ett_struct_iso20_ac_AC_CPDReqEnergyTransferModeType = -1;
static gint ett_struct_iso20_ac_AC_CPDResEnergyTransferModeType = -1;
static gint ett_struct_iso20_ac_BPT_AC_CPDReqEnergyTransferModeType = -1;
static gint ett_struct_iso20_ac_BPT_AC_CPDResEnergyTransferModeType = -1;
static gint ett_struct_iso20_ac_Scheduled_AC_CLReqControlModeType = -1;
static gint ett_struct_iso20_ac_Scheduled_AC_CLResControlModeType = -1;
static gint ett_struct_iso20_ac_BPT_Scheduled_AC_CLReqControlModeType = -1;
static gint ett_struct_iso20_ac_BPT_Scheduled_AC_CLResControlModeType = -1;
static gint ett_struct_iso20_ac_Dynamic_AC_CLReqControlModeType = -1;
static gint ett_struct_iso20_ac_Dynamic_AC_CLResControlModeType = -1;
static gint ett_struct_iso20_ac_BPT_Dynamic_AC_CLReqControlModeType = -1;
static gint ett_struct_iso20_ac_BPT_Dynamic_AC_CLResControlModeType = -1;
static gint ett_struct_iso20_ac_CLReqControlModeType = -1;
static gint ett_struct_iso20_ac_CLResControlModeType = -1;


static void
dissect_iso20_ac_AC_ChargeParameterDiscoveryReqType(
	const struct iso20_ac_AC_ChargeParameterDiscoveryReqType *req _U_,
	tvbuff_t *tvb _U_,
	packet_info *pinfo _U_,
	proto_tree *tree _U_,
	gint idx _U_,
	const char *subtree_name _U_)
{
	/* TODO */
	return;
}

static void
dissect_iso20_ac_AC_ChargeParameterDiscoveryResType(
	const struct iso20_ac_AC_ChargeParameterDiscoveryResType *res _U_,
	tvbuff_t *tvb _U_,
	packet_info *pinfo _U_,
	proto_tree *tree _U_,
	gint idx _U_,
	const char *subtree_name _U_)
{
	/* TODO */
	return;
}


static void
dissect_iso20_ac_AC_ChargeLoopReqType(
	const struct iso20_ac_AC_ChargeLoopReqType *req _U_,
	tvbuff_t *tvb _U_,
	packet_info *pinfo _U_,
	proto_tree *tree _U_,
	gint idx _U_,
	const char *subtree_name _U_)
{
	/* TODO */
	return;
}

static void
dissect_iso20_ac_AC_ChargeLoopResType(
	const struct iso20_ac_AC_ChargeLoopResType *res _U_,
	tvbuff_t *tvb _U_,
	packet_info *pinfo _U_,
	proto_tree *tree _U_,
	gint idx _U_,
	const char *subtree_name _U_)
{
	/* TODO */
	return;
}


static void
dissect_iso20_ac_AC_CPDReqEnergyTransferModeType(
	const struct iso20_ac_AC_CPDReqEnergyTransferModeType *req _U_,
	tvbuff_t *tvb _U_,
	packet_info *pinfo _U_,
	proto_tree *tree _U_,
	gint idx _U_,
	const char *subtree_name _U_)
{
	/* TODO */
	return;
}

static void
dissect_iso20_ac_AC_CPDResEnergyTransferModeType(
	const struct iso20_ac_AC_CPDResEnergyTransferModeType *res _U_,
	tvbuff_t *tvb _U_,
	packet_info *pinfo _U_,
	proto_tree *tree _U_,
	gint idx _U_,
	const char *subtree_name _U_)
{
	/* TODO */
	return;
}


static void
dissect_iso20_ac_BPT_AC_CPDReqEnergyTransferModeType(
	const struct iso20_ac_BPT_AC_CPDReqEnergyTransferModeType *req _U_,
	tvbuff_t *tvb _U_,
	packet_info *pinfo _U_,
	proto_tree *tree _U_,
	gint idx _U_,
	const char *subtree_name _U_)
{
	/* TODO */
	return;
}

static void
dissect_iso20_ac_BPT_AC_CPDResEnergyTransferModeType(
	const struct iso20_ac_BPT_AC_CPDResEnergyTransferModeType *res _U_,
	tvbuff_t *tvb _U_,
	packet_info *pinfo _U_,
	proto_tree *tree _U_,
	gint idx _U_,
	const char *subtree_name _U_)
{
	/* TODO */
	return;
}


static void
dissect_iso20_ac_Scheduled_AC_CLReqControlModeType(
	const struct iso20_ac_Scheduled_AC_CLReqControlModeType *req _U_,
	tvbuff_t *tvb _U_,
	packet_info *pinfo _U_,
	proto_tree *tree _U_,
	gint idx _U_,
	const char *subtree_name _U_)
{
	/* TODO */
	return;
}

static void
dissect_iso20_ac_Scheduled_AC_CLResControlModeType(
	const struct iso20_ac_Scheduled_AC_CLResControlModeType *res _U_,
	tvbuff_t *tvb _U_,
	packet_info *pinfo _U_,
	proto_tree *tree _U_,
	gint idx _U_,
	const char *subtree_name _U_)
{
	/* TODO */
	return;
}


static void
dissect_iso20_ac_BPT_Scheduled_AC_CLReqControlModeType(
	const struct iso20_ac_BPT_Scheduled_AC_CLReqControlModeType *req _U_,
	tvbuff_t *tvb _U_,
	packet_info *pinfo _U_,
	proto_tree *tree _U_,
	gint idx _U_,
	const char *subtree_name _U_)
{
	/* TODO */
	return;
}

static void
dissect_iso20_ac_BPT_Scheduled_AC_CLResControlModeType(
	const struct iso20_ac_BPT_Scheduled_AC_CLResControlModeType *res _U_,
	tvbuff_t *tvb _U_,
	packet_info *pinfo _U_,
	proto_tree *tree _U_,
	gint idx _U_,
	const char *subtree_name _U_)
{
	/* TODO */
	return;
}


static void
dissect_iso20_ac_Dynamic_AC_CLReqControlModeType(
	const struct iso20_ac_Dynamic_AC_CLReqControlModeType *req _U_,
	tvbuff_t *tvb _U_,
	packet_info *pinfo _U_,
	proto_tree *tree _U_,
	gint idx _U_,
	const char *subtree_name _U_)
{
	/* TODO */
	return;
}

static void
dissect_iso20_ac_Dynamic_AC_CLResControlModeType(
	const struct iso20_ac_Dynamic_AC_CLResControlModeType *res _U_,
	tvbuff_t *tvb _U_,
	packet_info *pinfo _U_,
	proto_tree *tree _U_,
	gint idx _U_,
	const char *subtree_name _U_)
{
	/* TODO */
	return;
}


static void
dissect_iso20_ac_BPT_Dynamic_AC_CLReqControlModeType(
	const struct iso20_ac_BPT_Dynamic_AC_CLReqControlModeType *req _U_,
	tvbuff_t *tvb _U_,
	packet_info *pinfo _U_,
	proto_tree *tree _U_,
	gint idx _U_,
	const char *subtree_name _U_)
{
	/* TODO */
	return;
}

static void
dissect_iso20_ac_BPT_Dynamic_AC_CLResControlModeType(
	const struct iso20_ac_BPT_Dynamic_AC_CLResControlModeType *res _U_,
	tvbuff_t *tvb _U_,
	packet_info *pinfo _U_,
	proto_tree *tree _U_,
	gint idx _U_,
	const char *subtree_name _U_)
{
	/* TODO */
	return;
}


static void
dissect_iso20_ac_CLReqControlModeType(
	const struct iso20_ac_CLReqControlModeType *req _U_,
	tvbuff_t *tvb _U_,
	packet_info *pinfo _U_,
	proto_tree *tree _U_,
	gint idx _U_,
	const char *subtree_name _U_)
{
	/* TODO */
	return;
}

static void
dissect_iso20_ac_CLResControlModeType(
	const struct iso20_ac_CLResControlModeType *res _U_,
	tvbuff_t *tvb _U_,
	packet_info *pinfo _U_,
	proto_tree *tree _U_,
	gint idx _U_,
	const char *subtree_name _U_)
{
	/* TODO */
	return;
}


static void
dissect_v2giso20_ac_document(
	const struct iso20_ac_exiDocument *doc,
	tvbuff_t *tvb,
	packet_info *pinfo,
	proto_tree *tree,
	gint idx,
	const char *subtree_name)
{
	proto_tree *subtree;

	subtree = proto_tree_add_subtree(tree,
		tvb, 0, 0, idx, NULL, subtree_name);

	if (doc->AC_ChargeParameterDiscoveryReq_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO,
			"AC_ChargeParameterDiscoveryReq");
		dissect_iso20_ac_AC_ChargeParameterDiscoveryReqType(
			&doc->AC_ChargeParameterDiscoveryReq,
			tvb, pinfo, subtree,
			ett_struct_iso20_ac_AC_ChargeParameterDiscoveryReqType,
			"AC_ChargeParameterDiscoveryReq");
	}
	if (doc->AC_ChargeParameterDiscoveryRes_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO,
			"AC_ChargeParameterDiscoveryRes");
		dissect_iso20_ac_AC_ChargeParameterDiscoveryResType(
			&doc->AC_ChargeParameterDiscoveryRes,
			tvb, pinfo, subtree,
			ett_struct_iso20_ac_AC_ChargeParameterDiscoveryResType,
			"AC_ChargeParameterDiscoveryRes");
	}

	if (doc->AC_ChargeLoopReq_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO,
			"AC_ChargeLoopReq");
		dissect_iso20_ac_AC_ChargeLoopReqType(
			&doc->AC_ChargeLoopReq,
			tvb, pinfo, subtree,
			ett_struct_iso20_ac_AC_ChargeLoopReqType,
			"AC_ChargeLoopReq");
	}
	if (doc->AC_ChargeLoopRes_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO,
			"AC_ChargeLoopRes");
		dissect_iso20_ac_AC_ChargeLoopResType(
			&doc->AC_ChargeLoopRes,
			tvb, pinfo, subtree,
			ett_struct_iso20_ac_AC_ChargeLoopResType,
			"AC_ChargeLoopRes");
	}

	if (doc->AC_CPDReqEnergyTransferMode_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO,
			"AC_CPDReqEnergyTransferMode");
		dissect_iso20_ac_AC_CPDReqEnergyTransferModeType(
			&doc->AC_CPDReqEnergyTransferMode,
			tvb, pinfo, subtree,
			ett_struct_iso20_ac_AC_CPDReqEnergyTransferModeType,
			"AC_CPDReqEnergyTransferMode");
	}
	if (doc->AC_CPDResEnergyTransferMode_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO,
			"AC_CPDResEnergyTransferMode");
		dissect_iso20_ac_AC_CPDResEnergyTransferModeType(
			&doc->AC_CPDResEnergyTransferMode,
			tvb, pinfo, subtree,
			ett_struct_iso20_ac_AC_CPDResEnergyTransferModeType,
			"AC_CPDResEnergyTransferMode");
	}

	if (doc->BPT_AC_CPDReqEnergyTransferMode_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO,
			"BPT_AC_CPDReqEnergyTransferMode");
		dissect_iso20_ac_BPT_AC_CPDReqEnergyTransferModeType(
			&doc->BPT_AC_CPDReqEnergyTransferMode,
			tvb, pinfo, subtree,
			ett_struct_iso20_ac_BPT_AC_CPDReqEnergyTransferModeType,
			"BPT_AC_CPDReqEnergyTransferMode");
	}
	if (doc->BPT_AC_CPDResEnergyTransferMode_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO,
			"BPT_AC_CPDResEnergyTransferMode");
		dissect_iso20_ac_BPT_AC_CPDResEnergyTransferModeType(
			&doc->BPT_AC_CPDResEnergyTransferMode,
			tvb, pinfo, subtree,
			ett_struct_iso20_ac_BPT_AC_CPDResEnergyTransferModeType,
			"BPT_AC_CPDResEnergyTransferMode");
	}

	if (doc->Scheduled_AC_CLReqControlMode_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO,
			"Scheduled_AC_CLReqControlMode");
		dissect_iso20_ac_Scheduled_AC_CLReqControlModeType(
			&doc->Scheduled_AC_CLReqControlMode,
			tvb, pinfo, subtree,
			ett_struct_iso20_ac_Scheduled_AC_CLReqControlModeType,
			"Scheduled_AC_CLReqControlMode");
	}
	if (doc->Scheduled_AC_CLResControlMode_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO,
			"Scheduled_AC_CLResControlMode");
		dissect_iso20_ac_Scheduled_AC_CLResControlModeType(
			&doc->Scheduled_AC_CLResControlMode,
			tvb, pinfo, subtree,
			ett_struct_iso20_ac_Scheduled_AC_CLResControlModeType,
			"Scheduled_AC_CLResControlMode");
	}

	if (doc->BPT_Scheduled_AC_CLReqControlMode_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO,
			"BPT_Scheduled_AC_CLReqControlMode");
		dissect_iso20_ac_BPT_Scheduled_AC_CLReqControlModeType(
			&doc->BPT_Scheduled_AC_CLReqControlMode,
			tvb, pinfo, subtree,
			ett_struct_iso20_ac_BPT_Scheduled_AC_CLReqControlModeType,
			"BPT_Scheduled_AC_CLReqControlMode");
	}
	if (doc->BPT_Scheduled_AC_CLResControlMode_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO,
			"BPT_Scheduled_AC_CLResControlMode");
		dissect_iso20_ac_BPT_Scheduled_AC_CLResControlModeType(
			&doc->BPT_Scheduled_AC_CLResControlMode,
			tvb, pinfo, subtree,
			ett_struct_iso20_ac_BPT_Scheduled_AC_CLResControlModeType,
			"BPT_Scheduled_AC_CLResControlMode");
	}

	if (doc->Dynamic_AC_CLReqControlMode_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO,
			"Dynamic_AC_CLReqControlMode");
		dissect_iso20_ac_Dynamic_AC_CLReqControlModeType(
			&doc->Dynamic_AC_CLReqControlMode,
			tvb, pinfo, subtree,
			ett_struct_iso20_ac_Dynamic_AC_CLReqControlModeType,
			"Dynamic_AC_CLReqControlMode");
	}
	if (doc->Dynamic_AC_CLResControlMode_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO,
			"Dynamic_AC_CLResControlMode");
		dissect_iso20_ac_Dynamic_AC_CLResControlModeType(
			&doc->Dynamic_AC_CLResControlMode,
			tvb, pinfo, subtree,
			ett_struct_iso20_ac_Dynamic_AC_CLResControlModeType,
			"Dynamic_AC_CLResControlMode");
	}

	if (doc->BPT_Dynamic_AC_CLReqControlMode_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO,
			"BPT_Dynamic_AC_CLReqControlMode");
		dissect_iso20_ac_BPT_Dynamic_AC_CLReqControlModeType(
			&doc->BPT_Dynamic_AC_CLReqControlMode,
			tvb, pinfo, subtree,
			ett_struct_iso20_ac_BPT_Dynamic_AC_CLReqControlModeType,
			"BPT_Dynamic_AC_CLReqControlMode");
	}
	if (doc->BPT_Dynamic_AC_CLResControlMode_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO,
			"BPT_Dynamic_AC_CLResControlMode");
		dissect_iso20_ac_BPT_Dynamic_AC_CLResControlModeType(
			&doc->BPT_Dynamic_AC_CLResControlMode,
			tvb, pinfo, subtree,
			ett_struct_iso20_ac_BPT_Dynamic_AC_CLResControlModeType,
			"BPT_Dynamic_AC_CLResControlMode");
	}

	if (doc->CLReqControlMode_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO,
			"CLReqControlMode");
		dissect_iso20_ac_CLReqControlModeType(
			&doc->CLReqControlMode,
			tvb, pinfo, subtree,
			ett_struct_iso20_ac_CLReqControlModeType,
			"CLReqControlMode");
	}
	if (doc->CLResControlMode_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO,
			"CLResControlMode");
		dissect_iso20_ac_CLResControlModeType(
			&doc->CLResControlMode,
			tvb, pinfo, subtree,
			ett_struct_iso20_ac_CLResControlModeType,
			"CLResControlMode");
	}

	return;
}

static int
dissect_v2giso20_ac(tvbuff_t *tvb,
		    packet_info *pinfo, proto_tree *tree _U_, void *data _U_)
{
	proto_tree *v2giso20_ac_tree;
	size_t size;
	exi_bitstream_t stream;
	int errn;
	struct iso20_ac_exiDocument *exiiso20_ac;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "ISO20_AC");
	/* Clear the info column */
	col_clear(pinfo->cinfo, COL_INFO);

	size = tvb_reported_length(tvb);
	exi_bitstream_init(&stream,
			   tvb_memdup(wmem_packet_scope(), tvb, 0, size),
			   size, 0, NULL);

	exiiso20_ac = wmem_alloc(pinfo->pool, sizeof(*exiiso20_ac));
	errn = decode_iso20_ac_exiDocument(&stream, exiiso20_ac);
	if (errn != 0) {
		wmem_free(pinfo->pool, exiiso20_ac);
		/* decode failed */
		return 0;
	}

	/*
	 * Everything in ISO20 AC should come in as a document
	 */
	v2giso20_ac_tree = proto_tree_add_subtree(tree,
		tvb, 0, 0, ett_v2giso20_ac, NULL, "V2G ISO20 AC");

	dissect_v2giso20_ac_document(exiiso20_ac,
		tvb, pinfo, v2giso20_ac_tree,
		ett_v2giso20_ac_document, "Document");

	wmem_free(pinfo->pool, exiiso20_ac);
	return tvb_captured_length(tvb);
}

void
proto_register_v2giso20_ac(void)
{

	static hf_register_info hf[] = {
	};

	static gint *ett[] = {
		&ett_v2giso20_ac,
		&ett_v2giso20_ac_document,
		&ett_v2giso20_ac_header,
		&ett_v2giso20_ac_array,
		&ett_v2giso20_ac_array_i,
		&ett_v2giso20_ac_asn1,

		&ett_struct_iso20_ac_AC_ChargeParameterDiscoveryReqType,
		&ett_struct_iso20_ac_AC_ChargeParameterDiscoveryResType,
		&ett_struct_iso20_ac_AC_ChargeLoopReqType,
		&ett_struct_iso20_ac_AC_ChargeLoopResType,
		&ett_struct_iso20_ac_AC_CPDReqEnergyTransferModeType,
		&ett_struct_iso20_ac_AC_CPDResEnergyTransferModeType,
		&ett_struct_iso20_ac_BPT_AC_CPDReqEnergyTransferModeType,
		&ett_struct_iso20_ac_BPT_AC_CPDResEnergyTransferModeType,
		&ett_struct_iso20_ac_Scheduled_AC_CLReqControlModeType,
		&ett_struct_iso20_ac_Scheduled_AC_CLResControlModeType,
		&ett_struct_iso20_ac_BPT_Scheduled_AC_CLReqControlModeType,
		&ett_struct_iso20_ac_BPT_Scheduled_AC_CLResControlModeType,
		&ett_struct_iso20_ac_Dynamic_AC_CLReqControlModeType,
		&ett_struct_iso20_ac_Dynamic_AC_CLResControlModeType,
		&ett_struct_iso20_ac_BPT_Dynamic_AC_CLReqControlModeType,
		&ett_struct_iso20_ac_BPT_Dynamic_AC_CLResControlModeType,
		&ett_struct_iso20_ac_CLReqControlModeType,
		&ett_struct_iso20_ac_CLResControlModeType,
	};

	proto_v2giso20_ac = proto_register_protocol(
		"V2G Efficient XML Interchange (ISO20 AC)",
		"V2GISO20_AC",
		"v2giso20_ac"
	);
	proto_register_field_array(proto_v2giso20_ac, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	register_dissector("v2giso20_ac", dissect_v2giso20_ac, proto_v2giso20_ac);
}

void
proto_reg_handoff_v2giso20_ac(void)
{

	/* add a handle for the connection oriented V2G EXI */
	v2gexi_handle = find_dissector_add_dependency("v2gexi", proto_v2giso20_ac);
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
