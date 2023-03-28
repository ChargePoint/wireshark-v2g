/*
 * Copyright (c) 2022 ChargePoint, Inc.
 * All rights reserved.
 *
 * See LICENSE file
 */
/**
 * V2G EXI Dissector
 *
 * This is the entry point from the exi encoded packets that need
 * to be tracked using the first hardshake to determine which
 * namespace to use for the subsequent stream.
 */

#include <inttypes.h>
#include <stdlib.h>

#include <wireshark.h>
#include <epan/packet.h>
#include <epan/conversation.h>
#include <epan/prefs.h>
#include <epan/expert.h>

/* openv2g */
#include <codec/EXITypes.h>
#include <appHandshake/appHandEXIDatatypes.h>
#include <appHandshake/appHandEXIDatatypesDecoder.h>

#include "v2gexi.h"


/* forward declare */
void proto_register_v2gexi(void);
void proto_reg_handoff_v2gexi(void);


static dissector_handle_t v2g_handle;
static dissector_handle_t v2gexi_handle;
static dissector_handle_t v2gdin_handle;
static dissector_handle_t v2giso1_handle;
static dissector_handle_t v2giso2_handle;

static int proto_v2gexi = -1;

static int hf_v2gexi_mode = -1;

static int hf_v2gexi_handshake_request = -1;
static int hf_v2gexi_struct_appHandAppProtocolType_ProtocolNamespace = -1;
static int hf_v2gexi_struct_appHandAppProtocolType_VersionNumberMajor = -1;
static int hf_v2gexi_struct_appHandAppProtocolType_VersionNumberMinor = -1;
static int hf_v2gexi_struct_appHandAppProtocolType_SchemaID = -1;
static int hf_v2gexi_struct_appHandAppProtocolType_Priority = -1;

static int hf_v2gexi_handshake_response = -1;
static int hf_v2gexi_struct_supportedAppProtocolRes_ResponseCode = -1;
static int hf_v2gexi_struct_supportedAppProtocolRes_SchemaID = -1;

/* Initialize the subtree pointers */
static gint ett_v2gexi = -1;
static gint ett_v2gexi_array = -1;
static gint ett_v2gexi_struct_supportedAppProtocolReq = -1;
static gint ett_v2gexi_struct_supportedAppProtocolRes = -1;
static gint ett_v2gexi_struct_appHandAppProtocolType = -1;


typedef enum _v2gexi_mode {
	V2GEXI_UNKNOWN = 0,

	V2GEXI_HANDSHAKE,
	V2GEXI_DIN,
	V2GEXI_ISO1,
	V2GEXI_ISO2
} v2gexi_mode_t;

typedef struct _v2gexi_schemaid_mode {
	guint schemaid;
	v2gexi_mode_t mode;
} v2gexi_schemaid_mode_t;

typedef struct _v2gexi_conv {
	guint32 handshake_request;
	guint32 handshake_response;
	v2gexi_mode_t mode;
	wmem_map_t *schemaid_mode;
	wmem_map_t *pdus;
} v2gexi_conv_t;


static const value_string v2gexi_mode_names[] = {
	{ V2GEXI_HANDSHAKE, "Handshake" },
	{ V2GEXI_DIN, "DIN" },
	{ V2GEXI_ISO1, "ISO1" },
	{ V2GEXI_ISO2, "ISO2" },
	{ 0, NULL }
};

static const value_string v2gexi_response_code_names[] = {
	{ appHandresponseCodeType_OK_SuccessfulNegotiation, "Success" },
	{ appHandresponseCodeType_OK_SuccessfulNegotiationWithMinorDeviation,
	  "SuccessWithMinorDeviation" },
	{ appHandresponseCodeType_Failed_NoNegotiation, "Failed" },
	{ 0, NULL }
};


static void
dissect_v2gexi_apphandappprotocoltype(
	v2gexi_conv_t *v2gexi_conv,
	const struct appHandAppProtocolType *apphandappprotocol,
	tvbuff_t *tvb,
	proto_tree *tree,
	gint idx,
	const char *subtree_name)
{
	proto_tree *subtree;
	proto_item *it;
	v2gexi_schemaid_mode_t *vsm;

	subtree = proto_tree_add_subtree(tree,
		tvb, 0, 0, idx, NULL, subtree_name);

	exi_add_characters(subtree,
		hf_v2gexi_struct_appHandAppProtocolType_ProtocolNamespace,
		tvb,
		apphandappprotocol->ProtocolNamespace.characters,
		apphandappprotocol->ProtocolNamespace.charactersLen,
		sizeof(apphandappprotocol->ProtocolNamespace.characters));

	it = proto_tree_add_uint(subtree,
		hf_v2gexi_struct_appHandAppProtocolType_VersionNumberMajor,
		tvb, 0, 0,
		apphandappprotocol->VersionNumberMajor);
	proto_item_set_generated(it);
	it = proto_tree_add_uint(subtree,
		hf_v2gexi_struct_appHandAppProtocolType_VersionNumberMinor,
		tvb, 0, 0,
		apphandappprotocol->VersionNumberMinor);
	proto_item_set_generated(it);

	it = proto_tree_add_uint(subtree,
		hf_v2gexi_struct_appHandAppProtocolType_SchemaID,
		tvb, 0, 0,
		apphandappprotocol->SchemaID);
	proto_item_set_generated(it);

	it = proto_tree_add_uint(subtree,
		hf_v2gexi_struct_appHandAppProtocolType_Priority,
		tvb, 0, 0,
		apphandappprotocol->Priority);
	proto_item_set_generated(it);

	/* DIN */
	const char ns0[] = "urn:din:70121:2012:MsgDef";
	if ((strlen(ns0) <=
	     apphandappprotocol->ProtocolNamespace.charactersLen) &&
	    (exi_strncasecmp(apphandappprotocol->ProtocolNamespace.characters,
			     ns0, strlen(ns0)) == 0)) {
		vsm = wmem_new0(wmem_file_scope(), v2gexi_schemaid_mode_t);
		vsm->schemaid = apphandappprotocol->SchemaID;
		vsm->mode = V2GEXI_DIN;
		wmem_map_insert(v2gexi_conv->schemaid_mode,
			&(vsm->schemaid), vsm);
	}

	/* ISO1 */
	const char ns1[] = "urn:iso:15118:2:2013:MsgDef";
	if ((strlen(ns1) <=
	     apphandappprotocol->ProtocolNamespace.charactersLen) &&
	    (exi_strncasecmp(apphandappprotocol->ProtocolNamespace.characters,
			     ns1, strlen(ns1)) == 0)) {
		vsm = wmem_new0(wmem_file_scope(), v2gexi_schemaid_mode_t);
		vsm->schemaid = apphandappprotocol->SchemaID;
		vsm->mode = V2GEXI_ISO1;
		wmem_map_insert(v2gexi_conv->schemaid_mode,
			&(vsm->schemaid), vsm);
	}

	/* ISO2 */
	const char ns2[] = "urn:iso:15118:2:2016:MsgDef";
	if ((strlen(ns2) <=
	     apphandappprotocol->ProtocolNamespace.charactersLen) &&
	    (exi_strncasecmp(apphandappprotocol->ProtocolNamespace.characters,
			     ns2, strlen(ns2)) == 0)) {
		vsm = wmem_new0(wmem_file_scope(), v2gexi_schemaid_mode_t);
		vsm->schemaid = apphandappprotocol->SchemaID;
		vsm->mode = V2GEXI_ISO2;
		wmem_map_insert(v2gexi_conv->schemaid_mode,
			&(vsm->schemaid), vsm);
	}

	return;
}

static void
dissect_v2gexi_supportedappprotocolreq(
	v2gexi_conv_t *v2gexi_conv,
	const struct appHandAnonType_supportedAppProtocolReq
		*supportedappprotocolreq,
	tvbuff_t *tvb,
	proto_tree *tree,
	gint idx,
	const char *subtree_name)
{
	unsigned int i;
	proto_tree *subtree;
	proto_tree *appprotocol_tree;

	subtree = proto_tree_add_subtree(tree,
		tvb, 0, 0, idx, NULL, subtree_name);

	appprotocol_tree = proto_tree_add_subtree(subtree,
		tvb, 0, 0, ett_v2gexi_array, NULL, "AppProtocol");
	for (i = 0; i < supportedappprotocolreq->AppProtocol.arrayLen; i++) {
		char index[sizeof("[65536]")];

		snprintf(index, sizeof(index), "[%u]", i);
		dissect_v2gexi_apphandappprotocoltype(v2gexi_conv,
			&supportedappprotocolreq->AppProtocol.array[i],
			tvb, appprotocol_tree,
			ett_v2gexi_struct_appHandAppProtocolType, index);
	}

	return;
}

static void
dissect_v2gexi_supportedappprotocolres(
	v2gexi_conv_t *v2gexi_conv,
	struct appHandAnonType_supportedAppProtocolRes *supportedappprotocolres,
	tvbuff_t *tvb,
	proto_tree *tree,
	gint idx,
	const char *subtree_name)
{
	proto_tree *subtree;
	proto_item *it;
	v2gexi_schemaid_mode_t *vsm;

	subtree = proto_tree_add_subtree(tree,
		tvb, 0, 0, idx, NULL, subtree_name);

	it = proto_tree_add_uint(subtree,
		hf_v2gexi_struct_supportedAppProtocolRes_ResponseCode,
		tvb, 0, 0,
		supportedappprotocolres->ResponseCode);
	proto_item_set_generated(it);

	if (supportedappprotocolres->SchemaID_isUsed) {
		guint schemaid;

		schemaid = supportedappprotocolres->SchemaID;

		it = proto_tree_add_uint(subtree,
			hf_v2gexi_struct_supportedAppProtocolRes_SchemaID,
			tvb, 0, 0,
			supportedappprotocolres->SchemaID);
		proto_item_set_generated(it);

		vsm = wmem_map_lookup(v2gexi_conv->schemaid_mode, &schemaid);
		v2gexi_conv->mode = (vsm != NULL) ? vsm->mode : -1;
	}

	return;
}

static int
dissect_v2gexi_hs(v2gexi_conv_t *v2gexi_conv,
		  tvbuff_t *tvb,
		  packet_info *pinfo,
		  proto_tree *v2gexi_tree)
{
	size_t pos;
	bitstream_t stream;
	int errn;
	struct appHandEXIDocument ahexi;

	pos = 0;
	stream.size = tvb_reported_length(tvb);
	stream.pos = &pos;
	stream.data = tvb_memdup(wmem_packet_scope(),
				 tvb, 0, stream.size);

	errn = decode_appHandExiDocument(&stream, &ahexi);
	if (errn != 0) {
		return 0;
	}

	if (ahexi.supportedAppProtocolReq_isUsed) {
		proto_item *it;
		col_clear(pinfo->cinfo, COL_INFO);
		col_append_str(pinfo->cinfo, COL_INFO,
				"supportedAppProtocolReq");

		if (!PINFO_FD_VISITED(pinfo)) {
			v2gexi_conv->handshake_request = pinfo->num;
		}
		it = proto_tree_add_uint(v2gexi_tree,
					 hf_v2gexi_handshake_request,
					 tvb, 0, 0, pinfo->num);
		proto_item_set_generated(it);

		dissect_v2gexi_supportedappprotocolreq(v2gexi_conv,
			&ahexi.supportedAppProtocolReq, tvb, v2gexi_tree,
			ett_v2gexi_struct_supportedAppProtocolReq,
			"supportedAppProtocolReq");
	} else if (ahexi.supportedAppProtocolRes_isUsed) {
		proto_item *it;
		col_clear(pinfo->cinfo, COL_INFO);
		col_append_str(pinfo->cinfo, COL_INFO,
				"supportedAppProtocolRes");

		if (!PINFO_FD_VISITED(pinfo)) {
			v2gexi_conv->handshake_response = pinfo->num;
		}
		it = proto_tree_add_uint(v2gexi_tree,
					 hf_v2gexi_handshake_response,
					 tvb, 0, 0, pinfo->num);
		proto_item_set_generated(it);

		dissect_v2gexi_supportedappprotocolres(v2gexi_conv,
			&ahexi.supportedAppProtocolRes, tvb, v2gexi_tree,
			ett_v2gexi_struct_supportedAppProtocolRes,
			"supportedAppProtocolRes");
	}

	return tvb_captured_length(tvb);
}

static int
dissect_v2gexi(tvbuff_t *tvb,
	       packet_info *pinfo, proto_tree *tree _U_, void *data _U_)
{
	proto_tree *v2gexi_tree;
	conversation_t *conversation;
	v2gexi_conv_t *v2gexi_conv;
	v2gexi_mode_t v2gexi_mode;
	gint offset;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "V2GEXI");
	col_clear(pinfo->cinfo, COL_INFO);

	/* Make the protocol tree */
	if (tree != NULL) {
		proto_item *ti;
		ti = proto_tree_add_item(tree, proto_v2gexi, tvb, 0, -1, ENC_NA);
		v2gexi_tree = proto_item_add_subtree(ti, ett_v2gexi);
	} else {
		v2gexi_tree = NULL;
	}

	/*
	 * Track state of this decode on a per conversation basis so that
	 * we can determine the parser to use and namespaces.
	 */
	conversation = find_or_create_conversation(pinfo);
	v2gexi_conv = conversation_get_proto_data(conversation, proto_v2gexi);
	if (v2gexi_conv == NULL) {
		/* attach to the conversation */
		v2gexi_conv = wmem_new0(wmem_file_scope(), v2gexi_conv_t);
		v2gexi_conv->mode = V2GEXI_HANDSHAKE;
		v2gexi_conv->schemaid_mode = wmem_map_new(wmem_file_scope(),
			g_int_hash, g_int_equal);
		v2gexi_conv->pdus = wmem_map_new(wmem_file_scope(),
			g_direct_hash, g_direct_equal);
		conversation_add_proto_data(conversation,
			proto_v2gexi, v2gexi_conv);
	}

	offset = 0;
	v2gexi_mode = v2gexi_conv->mode;
	if (PINFO_FD_VISITED(pinfo) &&
	    ((v2gexi_conv->handshake_request == pinfo->num) ||
	     (v2gexi_conv->handshake_response == pinfo->num))) {
		v2gexi_mode = V2GEXI_HANDSHAKE;
	}
	col_append_fstr(pinfo->cinfo, COL_INFO, "%s",
		val_to_str(v2gexi_mode, v2gexi_mode_names, "Unknown"));

	switch(v2gexi_mode) {
	default:
		/* unknown mode - stop dissection */
		break;
	case V2GEXI_HANDSHAKE:
		offset += dissect_v2gexi_hs(v2gexi_conv, tvb, pinfo,
					    v2gexi_tree);
		break;
	case V2GEXI_DIN:
		call_dissector(v2gdin_handle, tvb, pinfo, v2gexi_tree);
		offset += tvb_captured_length(tvb);
		break;
	case V2GEXI_ISO1:
		call_dissector(v2giso1_handle, tvb, pinfo, v2gexi_tree);
		offset += tvb_captured_length(tvb);
		break;
	case V2GEXI_ISO2:
		call_dissector(v2giso2_handle, tvb, pinfo, v2gexi_tree);
		offset += tvb_captured_length(tvb);
		break;
	}

	return offset;
}

void
proto_register_v2gexi(void)
{

	static hf_register_info hf[] = {
		{ &hf_v2gexi_mode,
		  { "Protocol Decode", "v2gexi.mode",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2gexi_handshake_request,
		  { "Handshake Request", "v2gexi.handshake.request",
		    FT_FRAMENUM, BASE_NONE, NULL, 0x0,
		    "The handshake request for this V2GEXI is in this frame", HFILL }
		},
		{ &hf_v2gexi_handshake_response,
		  { "Handshake Response", "v2gexi.handshake.response",
		    FT_FRAMENUM, BASE_NONE, NULL, 0x0,
		    "The handshake response for this V2GEXI is in this frame", HFILL }
		},

		/* struct appHandAppProtocolType */
		{ &hf_v2gexi_struct_appHandAppProtocolType_ProtocolNamespace,
		  { "ProtocolNamespace",
		    "v2gexi.struct.apphandappprotocoltype.protocolnamespace",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2gexi_struct_appHandAppProtocolType_VersionNumberMajor,
		  { "VersionNumberMajor",
		    "v2gexi.struct.apphandappprotocoltype.versionnumbermajor",
		    FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2gexi_struct_appHandAppProtocolType_VersionNumberMinor,
		  { "VersionNumberMinor",
		    "v2gexi.struct.apphandappprotocoltype.versionnumberminor",
		    FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2gexi_struct_appHandAppProtocolType_SchemaID,
		  { "SchemaID",
		    "v2gexi.struct.apphandappprotocoltype.schemaid",
		    FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2gexi_struct_appHandAppProtocolType_Priority,
		  { "Priority",
		    "v2gexi.struct.apphandappprotocoltype.priority",
		    FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},

		/* struct appHandAnonType_supportedAppProtocolRes */
		{ &hf_v2gexi_struct_supportedAppProtocolRes_ResponseCode,
		  { "ResponseCode",
		    "v2gexi.struct.supportedappprotocolres.responsecode",
		    FT_UINT16, BASE_DEC, VALS(v2gexi_response_code_names),
		    0x0, NULL, HFILL }
		},
		{ &hf_v2gexi_struct_supportedAppProtocolRes_SchemaID,
		  { "SchemaID",
		    "v2gexi.struct.supportedappprotocolres.schemaid",
		    FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		}
	};

	static gint *ett[] = {
		&ett_v2gexi,
		&ett_v2gexi_array,
		&ett_v2gexi_struct_supportedAppProtocolReq,
		&ett_v2gexi_struct_supportedAppProtocolRes,
		&ett_v2gexi_struct_appHandAppProtocolType
	};

	proto_v2gexi = proto_register_protocol (
		"V2G Efficient XML Interchange",
		"V2GEXI",
		"v2gexi"
	);
	proto_register_field_array(proto_v2gexi, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	v2gexi_handle = register_dissector("v2gexi",
		dissect_v2gexi, proto_v2gexi);
}

void
proto_reg_handoff_v2gexi(void)
{
	/* add the dependency to the parent v2g dissector */
	v2g_handle = find_dissector_add_dependency("v2g", proto_v2gexi);

	/* lookup the handles for the dissection after the handshake */
	v2gdin_handle = find_dissector_add_dependency("v2gdin", proto_v2gexi);
	v2giso1_handle = find_dissector_add_dependency("v2giso1", proto_v2gexi);
	v2giso2_handle = find_dissector_add_dependency("v2giso2", proto_v2gexi);

	dissector_add_for_decode_as_with_preference("udp.port", v2gexi_handle);
	dissector_add_for_decode_as_with_preference("tcp.port", v2gexi_handle);
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
