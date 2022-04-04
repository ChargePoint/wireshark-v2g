/*
 * V2G EXI
 */

#include "config.h"

#include <inttypes.h>
#include <stdlib.h>
#include <ctype.h>

#include <epan/packet.h>
#include <epan/conversation.h>
#include <epan/prefs.h>
#include <epan/expert.h>
#include <epan/wmem/wmem.h>

/* openv2g */
#include <codec/EXITypes.h>
#include <appHandshake/appHandEXIDatatypes.h>
#include <appHandshake/appHandEXIDatatypesDecoder.h>


void proto_register_v2gexi(void);
void proto_reg_handoff_pana(void);

static dissector_handle_t v2g_handle;

static int proto_v2gexi = -1;
static int hf_v2gexi_mode = -1;

static int hf_v2gexi_handshake_request = -1;
static int hf_v2gexi_handshake_request_ap_arraylen = -1;
static int hf_v2gexi_handshake_request_ap_array_i_entry = -1;
static int hf_v2gexi_handshake_request_ap_array_i_protocolnamespace = -1;
static int hf_v2gexi_handshake_request_ap_array_i_version_major = -1;
static int hf_v2gexi_handshake_request_ap_array_i_version_minor = -1;
static int hf_v2gexi_handshake_request_ap_array_i_schemaid = -1;
static int hf_v2gexi_handshake_request_ap_array_i_priority = -1;

static int hf_v2gexi_handshake_response = -1;
static int hf_v2gexi_handshake_response_code = -1;
static int hf_v2gexi_handshake_response_schemaid = -1;

static int hf_v2gexi_response_in = -1;
static int hf_v2gexi_response_to = -1;
static int hf_v2gexi_response_time = -1;

/* Initialize the subtree pointers */
static gint ett_v2gexi = -1;
static gint ett_v2gexi_handshake_request_ap_array = -1;
static gint ett_v2gexi_handshake_request_ap_array_i = -1;


typedef enum _v2gexi_mode {
	V2GEXI_UNKNOWN = 0,

	V2GEXI_HANDSHAKE,
	V2GEXI_DIN,
	V2GEXI_ISO1,
	V2GEXI_ISO2
} v2gexi_mode_t;

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
	{ appHandresponseCodeType_Failed_NoNegotiation, "Failed" }
};

typedef struct _v2gexi_schemaid_mode {
	guint schemaid;
	v2gexi_mode_t mode;
} v2gexi_schemaid_mode_t;

typedef struct _v2gexi_conv {
	v2gexi_mode_t mode;
	wmem_map_t *schemaid_mode;
	wmem_map_t *pdus;
} v2gexi_conv_t;

struct _v2gexi_rr {
	nstime_t req_time;
	guint32	req_frame;
	guint32 rep_frame;
};

static int
exi_strncasecmp(const exi_string_character_t *s1, const char *s2, size_t n)
{
	size_t pos;

	if (n == 0)
		return 0;

	for (pos = 0; pos < n; pos++) {
		unsigned char c1;
		unsigned char c2;

		c1 = s1[pos];
		c2 = s2[pos];
		if (tolower(c1) != tolower(c2)) {
			return c1 - (c2 - 1);
		}
		if (c1 == '\0')
			break;
	}
	return 0;
}

static int
dissect_v2gexi_hs(tvbuff_t *tvb, packet_info *pinfo,
		  proto_tree *v2gexi_tree, v2gexi_conv_t *v2gexi_conv)
{
	size_t pos;
	bitstream_t stream;
	int errn;
	unsigned int i, j;
	struct appHandEXIDocument ahexi;

	pos = 0;
	stream.size = tvb_reported_length(tvb);
	stream.pos = &pos;
	stream.data = tvb_memdup(wmem_packet_scope(),
				 tvb, pos, stream.size);

	errn = decode_appHandExiDocument(&stream, &ahexi);
	if (errn != 0) {
		return 0;
	}

	if (ahexi.supportedAppProtocolReq_isUsed) {
		proto_item *it;
		proto_tree *ap_array_tree;
		proto_tree *ap_array_i_tree;
		v2gexi_schemaid_mode_t *vsm;

		it = proto_tree_add_uint(v2gexi_tree,
					 hf_v2gexi_handshake_request,
					 tvb, 0, 0, pinfo->num);
		proto_item_set_generated(it);

		it = proto_tree_add_uint(v2gexi_tree,
					 hf_v2gexi_handshake_request_ap_arraylen,
					 tvb, 0, 0,
					 ahexi.supportedAppProtocolReq.AppProtocol.arrayLen);
		proto_item_set_generated(it);

		ap_array_tree = proto_tree_add_subtree(v2gexi_tree,
			tvb, 0, 0, ett_v2gexi_handshake_request_ap_array, NULL,
			"AppProtocols Array");
		for (i = 0; i < ahexi.supportedAppProtocolReq.AppProtocol.arrayLen; i++) {
			ap_array_i_tree = proto_tree_add_subtree(ap_array_tree,
				tvb, 0, 0, ett_v2gexi_handshake_request_ap_array_i,
				NULL, "AppProtocol");

			it = proto_tree_add_uint(ap_array_i_tree,
				hf_v2gexi_handshake_request_ap_array_i_entry,
				tvb, 0, 0, i+1);
			proto_item_set_generated(it);

			char protocolnamespace[appHandAppProtocolType_ProtocolNamespace_CHARACTERS_SIZE + 1];
			for (j = 0; j < ahexi.supportedAppProtocolReq.AppProtocol.array[i].ProtocolNamespace.charactersLen; j++) {
				protocolnamespace[j] =
					ahexi.supportedAppProtocolReq.AppProtocol.array[i].ProtocolNamespace.characters[j];
			}
			protocolnamespace[j] = '\0';
			it = proto_tree_add_string(ap_array_i_tree,
				hf_v2gexi_handshake_request_ap_array_i_protocolnamespace,
				tvb, 0, 0, protocolnamespace);
			proto_item_set_generated(it);

			it = proto_tree_add_uint(ap_array_i_tree,
				hf_v2gexi_handshake_request_ap_array_i_version_major,
				tvb, 0, 0,
				ahexi.supportedAppProtocolReq.AppProtocol.array[i].VersionNumberMajor);
			proto_item_set_generated(it);
			it = proto_tree_add_uint(ap_array_i_tree,
				hf_v2gexi_handshake_request_ap_array_i_version_minor,
				tvb, 0, 0,
				ahexi.supportedAppProtocolReq.AppProtocol.array[i].VersionNumberMinor);
			proto_item_set_generated(it);

			it = proto_tree_add_uint(ap_array_i_tree,
				hf_v2gexi_handshake_request_ap_array_i_schemaid,
				tvb, 0, 0,
				ahexi.supportedAppProtocolReq.AppProtocol.array[i].SchemaID);
			proto_item_set_generated(it);

			it = proto_tree_add_uint(ap_array_i_tree,
				hf_v2gexi_handshake_request_ap_array_i_priority,
				tvb, 0, 0,
				ahexi.supportedAppProtocolReq.AppProtocol.array[i].Priority);
			proto_item_set_generated(it);

			/* DIN */
			const char ns0[] = "urn:din:70121:2012:MsgDef";
			if ((strlen(ns0) ==
			     ahexi.supportedAppProtocolReq.AppProtocol.array[i].ProtocolNamespace.charactersLen) &&
			    (exi_strncasecmp(ahexi.supportedAppProtocolReq.AppProtocol.array[i].ProtocolNamespace.characters, ns0, strlen(ns0)) == 0)) {
				vsm = wmem_new0(wmem_file_scope(), v2gexi_schemaid_mode_t);
				vsm->schemaid = ahexi.supportedAppProtocolReq.AppProtocol.array[i].SchemaID;
				vsm->mode = V2GEXI_DIN;
				wmem_map_insert(v2gexi_conv->schemaid_mode, &(vsm->schemaid), vsm);
			}

			/* ISO1 */
			const char ns1[] = "urn:iso:15118:2:2010:MsgDef";
			if ((strlen(ns1) ==
			     ahexi.supportedAppProtocolReq.AppProtocol.array[i].ProtocolNamespace.charactersLen) &&
			    (exi_strncasecmp(ahexi.supportedAppProtocolReq.AppProtocol.array[i].ProtocolNamespace.characters, ns1, strlen(ns1)) == 0)) {
				vsm = wmem_new0(wmem_file_scope(), v2gexi_schemaid_mode_t);
				vsm->schemaid = ahexi.supportedAppProtocolReq.AppProtocol.array[i].SchemaID;
				vsm->mode = V2GEXI_ISO1;
				wmem_map_insert(v2gexi_conv->schemaid_mode, &(vsm->schemaid), vsm);
			}

			/* ISO2 */
			const char ns2[] = "urn:iso:15118:2:2016:MsgDef";
			if ((strlen(ns2) ==
			     ahexi.supportedAppProtocolReq.AppProtocol.array[i].ProtocolNamespace.charactersLen) &&
			    (exi_strncasecmp(ahexi.supportedAppProtocolReq.AppProtocol.array[i].ProtocolNamespace.characters, ns2, strlen(ns2)) == 0)) {
				vsm = wmem_new0(wmem_file_scope(), v2gexi_schemaid_mode_t);
				vsm->schemaid = ahexi.supportedAppProtocolReq.AppProtocol.array[i].SchemaID;
				vsm->mode = V2GEXI_ISO2;
				wmem_map_insert(v2gexi_conv->schemaid_mode, &(vsm->schemaid), vsm);
			}
		}
	} else if (ahexi.supportedAppProtocolRes_isUsed) {
		proto_item *it;
		v2gexi_schemaid_mode_t *vsm;

		it = proto_tree_add_uint(v2gexi_tree,
					 hf_v2gexi_handshake_response,
					 tvb, 0, 0, pinfo->num);
		proto_item_set_generated(it);

		proto_tree_add_uint(v2gexi_tree,
				    hf_v2gexi_handshake_response_code,
				    tvb, 0, 0,
				    ahexi.supportedAppProtocolRes.ResponseCode);
		proto_item_set_generated(it);

		if (ahexi.supportedAppProtocolRes.SchemaID_isUsed) {
			guint schemaid;

			schemaid = ahexi.supportedAppProtocolRes.SchemaID;

			proto_tree_add_uint(v2gexi_tree,
					    hf_v2gexi_handshake_response_schemaid,
					    tvb, 0, 0,
				            ahexi.supportedAppProtocolRes.SchemaID);
			proto_item_set_generated(it);

			vsm = wmem_map_lookup(v2gexi_conv->schemaid_mode, &schemaid);
			fprintf(stderr, "\tresponse schemaid=%d mode=%d\n",
				schemaid, (vsm != NULL) ? vsm->mode : -1);
			v2gexi_conv->mode = (vsm != NULL) ? vsm->mode : -1;
		}
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
	 * we can determine the parser to use and namesapces.
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

	col_add_fstr(pinfo->cinfo, COL_INFO, "Mode %s",
		     val_to_str(v2gexi_conv->mode, v2gexi_mode_names, "Unknown (%d)"));

	offset = 0;
	if (!pinfo->fd->visited) {
		switch(v2gexi_conv->mode) {
		default:
			/* unknown mode - stop dissection */
			break;
		case V2GEXI_HANDSHAKE:
			offset += dissect_v2gexi_hs(tvb, pinfo,
						    v2gexi_tree, v2gexi_conv);
			break;
		}
	} else {
		/* lookup this transaction */
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
		{ &hf_v2gexi_handshake_request_ap_arraylen,
		  { "AppProtocol Array Len",
		    "v2gexi.handshake.request.appprotocol.arraylen",
		    FT_UINT16, BASE_DEC, NULL, 0x0, NULL }
		},
		{ &hf_v2gexi_handshake_request_ap_array_i_entry,
		  { "AppProtocol Entry",
		    "v2gexi.handshake.request.appprotocol.array.entry",
		    FT_UINT16, BASE_DEC, NULL, 0x0, NULL }
		},
		{ &hf_v2gexi_handshake_request_ap_array_i_protocolnamespace,
		  { "AppProtocol Namespace",
		    "v2gexi.handshake.request.appprotocol.array.namespace",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL }
		},
		{ &hf_v2gexi_handshake_request_ap_array_i_version_major,
		  { "AppProtocol Version Major",
		    "v2gexi.handshake.request.appprotocol.array.versionmajor",
		    FT_UINT32, BASE_DEC, NULL, 0x0, NULL }
		},
		{ &hf_v2gexi_handshake_request_ap_array_i_version_minor,
		  { "AppProtocol Version Minor",
		    "v2gexi.handshake.request.appprotocol.array.versionminor",
		    FT_UINT32, BASE_DEC, NULL, 0x0, NULL }
		},
		{ &hf_v2gexi_handshake_request_ap_array_i_schemaid,
		  { "AppProtocol SchemaID",
		    "v2gexi.handshake.request.appprotocol.array.schemaid",
		    FT_UINT8, BASE_DEC, NULL, 0x0, NULL }
		},
		{ &hf_v2gexi_handshake_request_ap_array_i_priority,
		  { "AppProtocol Priority",
		    "v2gexi.handshake.request.appprotocol.array.priority",
		    FT_UINT8, BASE_DEC, NULL, 0x0, NULL }
		},
		{ &hf_v2gexi_handshake_response,
		  { "Handshake Response", "v2gexi.handshake.response",
		    FT_FRAMENUM, BASE_NONE, NULL, 0x0,
		    "The handshake response for this V2GEXI is in this frame", HFILL }
		},
		{ &hf_v2gexi_handshake_response_code,
		  { "Handshake ResponseCode", "v2gexi.handshake.response_code",
		    FT_UINT16, BASE_DEC, VALS(v2gexi_response_code_names), 0x0,
		    "The handshake response code", HFILL }
		},
		{ &hf_v2gexi_handshake_response_schemaid,
		  { "Handshake ResponseSchemaID",
		    "v2gexi.handshake.response_schemaid",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    "The handshake response schemaid", HFILL }
		}
	};

	static gint *ett[] = {
		&ett_v2gexi,
		&ett_v2gexi_handshake_request_ap_array,
		&ett_v2gexi_handshake_request_ap_array_i
	};

	proto_v2gexi = proto_register_protocol (
		"V2G Efficient XML Interchange",
		"V2GEXI",
		"v2gexi"
	);
	proto_register_field_array(proto_v2gexi, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	register_dissector("v2gexi", dissect_v2gexi, proto_v2gexi);
}

void
proto_reg_handoff_v2gexi(void)
{
	dissector_handle_t v2gexi_handle;

	v2gexi_handle = create_dissector_handle(dissect_v2gexi, proto_v2gexi);
	dissector_add_for_decode_as_with_preference("udp.port", v2gexi_handle);
	dissector_add_for_decode_as_with_preference("tcp.port", v2gexi_handle);

	v2g_handle = find_dissector_add_dependency("v2g", proto_v2gexi);
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
