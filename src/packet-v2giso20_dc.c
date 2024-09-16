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

static gint ett_struct_iso20_dc_DC_ChargeParameterDiscoveryReqType = -1;
static gint ett_struct_iso20_dc_DC_ChargeParameterDiscoveryResType = -1;
static gint ett_struct_iso20_dc_DC_CableCheckReqType = -1;
static gint ett_struct_iso20_dc_DC_CableCheckResType = -1;
static gint ett_struct_iso20_dc_DC_PreChargeReqType = -1;
static gint ett_struct_iso20_dc_DC_PreChargeResType = -1;
static gint ett_struct_iso20_dc_DC_ChargeLoopReqType = -1;
static gint ett_struct_iso20_dc_DC_ChargeLoopResType = -1;
static gint ett_struct_iso20_dc_DC_WeldingDetectionReqType = -1;
static gint ett_struct_iso20_dc_DC_WeldingDetectionResType = -1;
static gint ett_struct_iso20_dc_DC_CPDReqEnergyTransferModeType = -1;
static gint ett_struct_iso20_dc_DC_CPDResEnergyTransferModeType = -1;
static gint ett_struct_iso20_dc_BPT_DC_CPDReqEnergyTransferModeType = -1;
static gint ett_struct_iso20_dc_BPT_DC_CPDResEnergyTransferModeType = -1;
static gint ett_struct_iso20_dc_Scheduled_DC_CLReqControlModeType = -1;
static gint ett_struct_iso20_dc_Scheduled_DC_CLResControlModeType = -1;
static gint ett_struct_iso20_dc_BPT_Scheduled_DC_CLReqControlModeType = -1;
static gint ett_struct_iso20_dc_BPT_Scheduled_DC_CLResControlModeType = -1;
static gint ett_struct_iso20_dc_Dynamic_DC_CLReqControlModeType = -1;
static gint ett_struct_iso20_dc_Dynamic_DC_CLResControlModeType = -1;
static gint ett_struct_iso20_dc_BPT_Dynamic_DC_CLReqControlModeType = -1;
static gint ett_struct_iso20_dc_BPT_Dynamic_DC_CLResControlModeType = -1;
static gint ett_struct_iso20_dc_CLReqControlModeType = -1;
static gint ett_struct_iso20_dc_CLResControlModeType = -1;


static void
dissect_iso20_dc_DC_ChargeParameterDiscoveryReqType(
	const struct iso20_dc_DC_ChargeParameterDiscoveryReqType *req _U_,
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
dissect_iso20_dc_DC_ChargeParameterDiscoveryResType(
	const struct iso20_dc_DC_ChargeParameterDiscoveryResType *res _U_,
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
dissect_iso20_dc_DC_CableCheckReqType(
	const struct iso20_dc_DC_CableCheckReqType *req _U_,
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
dissect_iso20_dc_DC_CableCheckResType(
	const struct iso20_dc_DC_CableCheckResType *res _U_,
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
dissect_iso20_dc_DC_PreChargeReqType(
	const struct iso20_dc_DC_PreChargeReqType *req _U_,
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
dissect_iso20_dc_DC_PreChargeResType(
	const struct iso20_dc_DC_PreChargeResType *res _U_,
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
dissect_iso20_dc_DC_ChargeLoopReqType(
	const struct iso20_dc_DC_ChargeLoopReqType *req _U_,
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
dissect_iso20_dc_DC_ChargeLoopResType(
	const struct iso20_dc_DC_ChargeLoopResType *res _U_,
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
dissect_iso20_dc_DC_WeldingDetectionReqType(
	const struct iso20_dc_DC_WeldingDetectionReqType *req _U_,
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
dissect_iso20_dc_DC_WeldingDetectionResType(
	const struct iso20_dc_DC_WeldingDetectionResType *res _U_,
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
dissect_iso20_dc_DC_CPDReqEnergyTransferModeType(
	const struct iso20_dc_DC_CPDReqEnergyTransferModeType *req _U_,
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
dissect_iso20_dc_DC_CPDResEnergyTransferModeType(
	const struct iso20_dc_DC_CPDResEnergyTransferModeType *res _U_,
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
dissect_iso20_dc_BPT_DC_CPDReqEnergyTransferModeType(
	const struct iso20_dc_BPT_DC_CPDReqEnergyTransferModeType *req _U_,
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
dissect_iso20_dc_BPT_DC_CPDResEnergyTransferModeType(
	const struct iso20_dc_BPT_DC_CPDResEnergyTransferModeType *res _U_,
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
dissect_iso20_dc_Scheduled_DC_CLReqControlModeType(
	const struct iso20_dc_Scheduled_DC_CLReqControlModeType *req _U_,
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
dissect_iso20_dc_Scheduled_DC_CLResControlModeType(
	const struct iso20_dc_Scheduled_DC_CLResControlModeType *res _U_,
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
dissect_iso20_dc_BPT_Scheduled_DC_CLReqControlModeType(
	const struct iso20_dc_BPT_Scheduled_DC_CLReqControlModeType *req _U_,
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
dissect_iso20_dc_BPT_Scheduled_DC_CLResControlModeType(
	const struct iso20_dc_BPT_Scheduled_DC_CLResControlModeType *res _U_,
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
dissect_iso20_dc_Dynamic_DC_CLReqControlModeType(
	const struct iso20_dc_Dynamic_DC_CLReqControlModeType *req _U_,
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
dissect_iso20_dc_Dynamic_DC_CLResControlModeType(
	const struct iso20_dc_Dynamic_DC_CLResControlModeType *res _U_,
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
dissect_iso20_dc_BPT_Dynamic_DC_CLReqControlModeType(
	const struct iso20_dc_BPT_Dynamic_DC_CLReqControlModeType *req _U_,
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
dissect_iso20_dc_BPT_Dynamic_DC_CLResControlModeType(
	const struct iso20_dc_BPT_Dynamic_DC_CLResControlModeType *res _U_,
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
dissect_iso20_dc_CLReqControlModeType(
	const struct iso20_dc_CLReqControlModeType *req _U_,
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
dissect_iso20_dc_CLResControlModeType(
	const struct iso20_dc_CLResControlModeType *res _U_,
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
dissect_v2giso20_dc_document(
	const struct iso20_dc_exiDocument *doc,
	tvbuff_t *tvb,
	packet_info *pinfo,
	proto_tree *tree,
	gint idx,
	const char *subtree_name)
{
	proto_tree *subtree;

	subtree = proto_tree_add_subtree(tree,
		tvb, 0, 0, idx, NULL, subtree_name);

	if (doc->DC_ChargeParameterDiscoveryReq_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO,
			"DC_ChargeParameterDiscoveryReq");
		dissect_iso20_dc_DC_ChargeParameterDiscoveryReqType(
			&doc->DC_ChargeParameterDiscoveryReq,
			tvb, pinfo, subtree,
			ett_struct_iso20_dc_DC_ChargeParameterDiscoveryReqType,
			"DC_ChargeParameterDiscoveryReq");
	}
	if (doc->DC_ChargeParameterDiscoveryRes_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO,
			"DC_ChargeParameterDiscoveryRes");
		dissect_iso20_dc_DC_ChargeParameterDiscoveryResType(
			&doc->DC_ChargeParameterDiscoveryRes,
			tvb, pinfo, subtree,
			ett_struct_iso20_dc_DC_ChargeParameterDiscoveryResType,
			"DC_ChargeParameterDiscoveryRes");
	}

	if (doc->DC_CableCheckReq_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO,
			"DC_CableCheckReq");
		dissect_iso20_dc_DC_CableCheckReqType(
			&doc->DC_CableCheckReq,
			tvb, pinfo, subtree,
			ett_struct_iso20_dc_DC_CableCheckReqType,
			"DC_CableCheckReq");
	}
	if (doc->DC_CableCheckRes_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO,
			"DC_CableCheckRes");
		dissect_iso20_dc_DC_CableCheckResType(
			&doc->DC_CableCheckRes,
			tvb, pinfo, subtree,
			ett_struct_iso20_dc_DC_CableCheckResType,
			"DC_CableCheckRes");
	}

	if (doc->DC_PreChargeReq_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO,
			"DC_PreChargeReq");
		dissect_iso20_dc_DC_PreChargeReqType(
			&doc->DC_PreChargeReq,
			tvb, pinfo, subtree,
			ett_struct_iso20_dc_DC_PreChargeReqType,
			"DC_PreChargeReq");

	}
	if (doc->DC_PreChargeRes_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO,
			"DC_PreChargeRes");
		dissect_iso20_dc_DC_PreChargeResType(
			&doc->DC_PreChargeRes,
			tvb, pinfo, subtree,
			ett_struct_iso20_dc_DC_PreChargeResType,
			"DC_PreChargeRes");
	}

	if (doc->DC_ChargeLoopReq_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO,
			"DC_ChargeLoopReq");
		dissect_iso20_dc_DC_ChargeLoopReqType(
			&doc->DC_ChargeLoopReq,
			tvb, pinfo, subtree,
			ett_struct_iso20_dc_DC_ChargeLoopReqType,
			"DC_ChargeLoopReq");
	}
	if (doc->DC_ChargeLoopRes_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO,
			"DC_ChargeLoopRes");
		dissect_iso20_dc_DC_ChargeLoopResType(
			&doc->DC_ChargeLoopRes,
			tvb, pinfo, subtree,
			ett_struct_iso20_dc_DC_ChargeLoopResType,
			"DC_ChargeLoopRes");
	}

	if (doc->DC_WeldingDetectionReq_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO,
			"DC_WeldingDetectionReq");
		dissect_iso20_dc_DC_WeldingDetectionReqType(
			&doc->DC_WeldingDetectionReq,
			tvb, pinfo, subtree,
			ett_struct_iso20_dc_DC_WeldingDetectionReqType,
			"DC_WeldingDetectionReq");
	}
	if (doc->DC_WeldingDetectionRes_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO,
			"DC_WeldingDetectionRes");
		dissect_iso20_dc_DC_WeldingDetectionResType(
			&doc->DC_WeldingDetectionRes,
			tvb, pinfo, subtree,
			ett_struct_iso20_dc_DC_WeldingDetectionResType,
			"DC_WeldingDetectionRes");
	}

	if (doc->DC_CPDReqEnergyTransferMode_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO,
			"DC_CPDReqEnergyTransferMode");
		dissect_iso20_dc_DC_CPDReqEnergyTransferModeType(
			&doc->DC_CPDReqEnergyTransferMode,
			tvb, pinfo, subtree,
			ett_struct_iso20_dc_DC_CPDReqEnergyTransferModeType,
			"DC_CPDReqEnergyTransferMode");
	}
	if (doc->DC_CPDResEnergyTransferMode_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO,
			"DC_CPDResEnergyTransferMode");
		dissect_iso20_dc_DC_CPDResEnergyTransferModeType(
			&doc->DC_CPDResEnergyTransferMode,
			tvb, pinfo, subtree,
			ett_struct_iso20_dc_DC_CPDResEnergyTransferModeType,
			"DC_CPDResEnergyTransferMode");
	}

	if (doc->BPT_DC_CPDReqEnergyTransferMode_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO,
			"BPT_DC_CPDReqEnergyTransferMode");
		dissect_iso20_dc_BPT_DC_CPDReqEnergyTransferModeType(
			&doc->BPT_DC_CPDReqEnergyTransferMode,
			tvb, pinfo, subtree,
			ett_struct_iso20_dc_BPT_DC_CPDReqEnergyTransferModeType,
			"BPT_DC_CPDReqEnergyTransferMode");
	}
	if (doc->BPT_DC_CPDResEnergyTransferMode_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO,
			"BPT_DC_CPDResEnergyTransferMode");
		dissect_iso20_dc_BPT_DC_CPDResEnergyTransferModeType(
			&doc->BPT_DC_CPDResEnergyTransferMode,
			tvb, pinfo, subtree,
			ett_struct_iso20_dc_BPT_DC_CPDResEnergyTransferModeType,
			"BPT_DC_CPDResEnergyTransferMode");
	}

	if (doc->Scheduled_DC_CLReqControlMode_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO,
			"Scheduled_DC_CLReqControlMode");
		dissect_iso20_dc_Scheduled_DC_CLReqControlModeType(
			&doc->Scheduled_DC_CLReqControlMode,
			tvb, pinfo, subtree,
			ett_struct_iso20_dc_Scheduled_DC_CLReqControlModeType,
			"Scheduled_DC_CLReqControlMode");
	}
	if (doc->Scheduled_DC_CLResControlMode_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO,
			"Scheduled_DC_CLResControlMode");
		dissect_iso20_dc_Scheduled_DC_CLResControlModeType(
			&doc->Scheduled_DC_CLResControlMode,
			tvb, pinfo, subtree,
			ett_struct_iso20_dc_Scheduled_DC_CLResControlModeType,
			"Scheduled_DC_CLResControlMode");
	}

	if (doc->BPT_Scheduled_DC_CLReqControlMode_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO,
			"BPT_Scheduled_DC_CLReqControlMode");
		dissect_iso20_dc_BPT_Scheduled_DC_CLReqControlModeType(
			&doc->BPT_Scheduled_DC_CLReqControlMode,
			tvb, pinfo, subtree,
			ett_struct_iso20_dc_BPT_Scheduled_DC_CLReqControlModeType,
			"BPT_Scheduled_DC_CLReqControlMode");
	}
	if (doc->BPT_Scheduled_DC_CLResControlMode_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO,
			"BPT_Scheduled_DC_CLResControlMode");
		dissect_iso20_dc_BPT_Scheduled_DC_CLResControlModeType(
			&doc->BPT_Scheduled_DC_CLResControlMode,
			tvb, pinfo, subtree,
			ett_struct_iso20_dc_BPT_Scheduled_DC_CLResControlModeType,
			"BPT_Scheduled_DC_CLResControlMode");
	}

	if (doc->Dynamic_DC_CLReqControlMode_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO,
			"Dynamic_DC_CLReqControlMode");
		dissect_iso20_dc_Dynamic_DC_CLReqControlModeType(
			&doc->Dynamic_DC_CLReqControlMode,
			tvb, pinfo, subtree,
			ett_struct_iso20_dc_Dynamic_DC_CLReqControlModeType,
			"Dynamic_DC_CLReqControlMode");
	}
	if (doc->Dynamic_DC_CLResControlMode_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO,
			"Dynamic_DC_CLResControlMode");
		dissect_iso20_dc_Dynamic_DC_CLResControlModeType(
			&doc->Dynamic_DC_CLResControlMode,
			tvb, pinfo, subtree,
			ett_struct_iso20_dc_Dynamic_DC_CLResControlModeType,
			"Dynamic_DC_CLResControlMode");
	}

	if (doc->BPT_Dynamic_DC_CLReqControlMode_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO,
			"BPT_Dynamic_DC_CLReqControlMode");
		dissect_iso20_dc_BPT_Dynamic_DC_CLReqControlModeType(
			&doc->BPT_Dynamic_DC_CLReqControlMode,
			tvb, pinfo, subtree,
			ett_struct_iso20_dc_BPT_Dynamic_DC_CLReqControlModeType,
			"BPT_Dynamic_DC_CLReqControlMode");
	}
	if (doc->BPT_Dynamic_DC_CLResControlMode_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO,
			"BPT_Dynamic_DC_CLResControlMode");
		dissect_iso20_dc_BPT_Dynamic_DC_CLResControlModeType(
			&doc->BPT_Dynamic_DC_CLResControlMode,
			tvb, pinfo, subtree,
			ett_struct_iso20_dc_BPT_Dynamic_DC_CLResControlModeType,
			"BPT_Dynamic_DC_CLResControlMode");
	}

	if (doc->CLReqControlMode_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO,
			"CLReqControlMode");
		dissect_iso20_dc_CLReqControlModeType(
			&doc->CLReqControlMode,
			tvb, pinfo, subtree,
			ett_struct_iso20_dc_CLReqControlModeType,
			"CLReqControlMode");
	}
	if (doc->CLResControlMode_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO,
			"CLResControlMode");
		dissect_iso20_dc_CLResControlModeType(
			&doc->CLResControlMode,
			tvb, pinfo, subtree,
			ett_struct_iso20_dc_CLResControlModeType,
			"CLResControlMode");
	}

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

		&ett_struct_iso20_dc_DC_ChargeParameterDiscoveryReqType,
		&ett_struct_iso20_dc_DC_ChargeParameterDiscoveryResType,
		&ett_struct_iso20_dc_DC_CableCheckReqType,
		&ett_struct_iso20_dc_DC_CableCheckResType,
		&ett_struct_iso20_dc_DC_PreChargeReqType,
		&ett_struct_iso20_dc_DC_PreChargeResType,
		&ett_struct_iso20_dc_DC_ChargeLoopReqType,
		&ett_struct_iso20_dc_DC_ChargeLoopResType,
		&ett_struct_iso20_dc_DC_WeldingDetectionReqType,
		&ett_struct_iso20_dc_DC_WeldingDetectionResType,
		&ett_struct_iso20_dc_DC_CPDReqEnergyTransferModeType,
		&ett_struct_iso20_dc_DC_CPDResEnergyTransferModeType,
		&ett_struct_iso20_dc_BPT_DC_CPDReqEnergyTransferModeType,
		&ett_struct_iso20_dc_BPT_DC_CPDResEnergyTransferModeType,
		&ett_struct_iso20_dc_Scheduled_DC_CLReqControlModeType,
		&ett_struct_iso20_dc_Scheduled_DC_CLResControlModeType,
		&ett_struct_iso20_dc_BPT_Scheduled_DC_CLReqControlModeType,
		&ett_struct_iso20_dc_BPT_Scheduled_DC_CLResControlModeType,
		&ett_struct_iso20_dc_Dynamic_DC_CLReqControlModeType,
		&ett_struct_iso20_dc_Dynamic_DC_CLResControlModeType,
		&ett_struct_iso20_dc_BPT_Dynamic_DC_CLReqControlModeType,
		&ett_struct_iso20_dc_BPT_Dynamic_DC_CLResControlModeType,
		&ett_struct_iso20_dc_CLReqControlModeType,
		&ett_struct_iso20_dc_CLResControlModeType,
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
