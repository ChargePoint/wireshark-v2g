/*
 * Copyright (c) 2022 ChargePoint, Inc.
 * All rights reserved.
 *
 * See LICENSE file
 */
/**
 * V2G DIN Dissector
 *
 * After the handshake is completed, the subsequent messages are now
 * decoded using the DIN namespace.
 */

#include "config.h"

#include <inttypes.h>
#include <stdlib.h>

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/expert.h>

/* openv2g */
#include <codec/EXITypes.h>
#include <din/dinEXIDatatypes.h>
#include <din/dinEXIDatatypesDecoder.h>

/* forward declare */
void proto_register_v2gdin(void);
void proto_reg_handoff_v2gdin(void);


static dissector_handle_t v2gexi_handle;

static int proto_v2gdin = -1;
static int hf_v2gdin_header_sessionid = -1;
static int hf_v2gdin_header_notification_faultcode = -1;
static int hf_v2gdin_header_notification_faultmsg = -1;
static int hf_v2gdin_header_signature_id = -1;

static int hf_v2gdin_body_sessionsetupreq_evccid = -1;

/* Initialize the subtree pointers */
static gint ett_v2gdin = -1;
static gint ett_v2gdin_header = -1;
static gint ett_v2gdin_header_notification = -1;
static gint ett_v2gdin_header_signature = -1;
static gint ett_v2gdin_body = -1;
static gint ett_v2gdin_body_sessionsetupreq = -1;
static gint ett_v2gdin_body_sessionsetupres = -1;
static gint ett_v2gdin_body_sessiondiscoveryreq = -1;
static gint ett_v2gdin_body_sessiondiscoveryres = -1;
static gint ett_v2gdin_body_sessiondetailreq = -1;
static gint ett_v2gdin_body_sessiondetailres = -1;
static gint ett_v2gdin_body_servicepaymentselectionreq = -1;
static gint ett_v2gdin_body_servicepaymentselectionres = -1;
static gint ett_v2gdin_body_paymentdetailsreq = -1;
static gint ett_v2gdin_body_paymentdetailsres = -1;
static gint ett_v2gdin_body_contractauthenticationreq = -1;
static gint ett_v2gdin_body_contractauthenticationres = -1;
static gint ett_v2gdin_body_chargeparameterdiscoveryreq = -1;
static gint ett_v2gdin_body_chargeparameterdiscoveryres = -1;
static gint ett_v2gdin_body_powerdeliveryreq = -1;
static gint ett_v2gdin_body_powerdeliveryres = -1;
static gint ett_v2gdin_body_chargingstatusreq = -1;
static gint ett_v2gdin_body_chargingstatusres = -1;
static gint ett_v2gdin_body_meteringreceiptreq = -1;
static gint ett_v2gdin_body_meteringreceiptres = -1;
static gint ett_v2gdin_body_sessionstopreq = -1;
static gint ett_v2gdin_body_sessionstopres = -1;
static gint ett_v2gdin_body_certificateupdatereq = -1;
static gint ett_v2gdin_body_certificateupdateres = -1;
static gint ett_v2gdin_body_certificateinstallationreq = -1;
static gint ett_v2gdin_body_certificateinstallationres = -1;
static gint ett_v2gdin_body_cablecheckreq = -1;
static gint ett_v2gdin_body_cablecheckres = -1;
static gint ett_v2gdin_body_prechargereq = -1;
static gint ett_v2gdin_body_prechargeres = -1;
static gint ett_v2gdin_body_currentdemandreq = -1;
static gint ett_v2gdin_body_currentdemandres = -1;
static gint ett_v2gdin_body_weldingdetectionreq = -1;
static gint ett_v2gdin_body_weldingdetectionres = -1;

static const value_string v2gdin_fault_code_names[] = {
	{ dinfaultCodeType_ParsingError, "ParsingError" },
        { dinfaultCodeType_NoTLSRootCertificatAvailable,
	  "NoTLSRootCertificatAvailable" },
	{ dinfaultCodeType_UnknownError, "UnknownError" }
};

static void
dissect_v2gdin_header(tvbuff_t *tvb, packet_info *pinfo,
		      proto_tree *v2gdin_tree, struct dinMessageHeaderType *hdr)
{
	unsigned int i;
	proto_item *it;
	proto_tree *hdr_tree;

	hdr_tree = proto_tree_add_subtree(v2gdin_tree,
		tvb, 0, 0, ett_v2gdin_header, NULL, "Header");

	char sessionid[2*dinMessageHeaderType_SessionID_BYTES_SIZE + 1];
	for (i = 0; i < hdr->SessionID.bytesLen; i++) {
		snprintf(&sessionid[2*i], sizeof(sessionid) - 2*i,
			"%02X", hdr->SessionID.bytes[i]);
	}
	sessionid[2*i] = '\0';
	it = proto_tree_add_string(hdr_tree,
		hf_v2gdin_header_sessionid, tvb, 0, 0, sessionid);
	proto_item_set_generated(it);

	if (hdr->Notification_isUsed) {
		proto_tree *notification_tree;

		notification_tree = proto_tree_add_subtree(hdr_tree,
			tvb, 0, 0, ett_v2gdin_header_notification,
			NULL, "Notification");

		it = proto_tree_add_uint(notification_tree,
			hf_v2gdin_header_notification_faultcode,
			tvb, 0, 0, hdr->Notification.FaultCode);
		proto_item_set_generated(it);

		if (hdr->Notification.FaultMsg_isUsed) {
			char faultmsg[dinNotificationType_FaultMsg_CHARACTERS_SIZE + 1];
			for (i = 0; i < hdr->Notification.FaultMsg.charactersLen; i++) {
				faultmsg[i] = hdr->Notification.FaultMsg.characters[i];
			}
			faultmsg[i] = '\0';
			it = proto_tree_add_string(notification_tree,
				hf_v2gdin_header_notification_faultmsg,
				tvb, 0, 0, faultmsg);
			proto_item_set_generated(it);
		}
	}

	if (hdr->Signature_isUsed) {
		proto_tree *signature_tree;

		signature_tree = proto_tree_add_subtree(hdr_tree,
			tvb, 0, 0, ett_v2gdin_header_signature,
			NULL, "Signature");

		if (hdr->Signature.Id_isUsed) {
			char id[dinSignatureType_Id_CHARACTERS_SIZE + 1];
			for (i = 0; i < hdr->Signature.Id.charactersLen; i++) {
				id[i] = hdr->Signature.Id.characters[i];
			}
			id[i] = '\0';
			it = proto_tree_add_string(signature_tree,
				hf_v2gdin_header_signature_id,
				tvb, 0, 0, id);
			proto_item_set_generated(it);
		}

		if (hdr->Signature.KeyInfo_isUsed) {
		}
	}

	return;
}

static void
dissect_v2gdin_body(tvbuff_t *tvb, packet_info *pinfo,
		    proto_tree *v2gdin_tree, struct dinBodyType *body)
{
	unsigned int i;
	proto_item *it;
	proto_tree *body_tree;

	body_tree = proto_tree_add_subtree(v2gdin_tree,
		tvb, 0, 0, ett_v2gdin_body, NULL, "Body");

	if (body->SessionSetupReq_isUsed) {
		proto_tree *req_tree;

		req_tree = proto_tree_add_subtree(body_tree,
			tvb, 0, 0, ett_v2gdin_body_sessionsetupreq,
			NULL, "SessionSetupReq");

		char evccid[2*dinSessionSetupReqType_EVCCID_BYTES_SIZE + 1];
		for (i = 0; i < body->SessionSetupReq.EVCCID.bytesLen; i++) {
			snprintf(&evccid[2*i], sizeof(evccid) - 2*i,
				"%02X", body->SessionSetupReq.EVCCID.bytes[i]);
		}
		evccid[2*i] = '\0';
		it = proto_tree_add_string(req_tree,
			hf_v2gdin_body_sessionsetupreq_evccid,
			tvb, 0, 0, evccid);
		proto_item_set_generated(it);
	}
	if (body->SessionSetupRes_isUsed) {
		proto_tree_add_subtree(body_tree,
			tvb, 0, 0, ett_v2gdin_body_sessionsetupres,
			NULL, "SessionSetupRes");
	}

	if (body->ServiceDiscoveryReq_isUsed) {
		proto_tree_add_subtree(body_tree,
			tvb, 0, 0, ett_v2gdin_body_sessiondiscoveryreq,
			NULL, "SessionDiscoveryReq");
	}
	if (body->ServiceDiscoveryRes_isUsed) {
		proto_tree_add_subtree(body_tree,
			tvb, 0, 0, ett_v2gdin_body_sessiondiscoveryres,
			NULL, "SessionDiscoveryRes");
	}

	if (body->ServiceDetailReq_isUsed) {
		proto_tree_add_subtree(body_tree,
			tvb, 0, 0, ett_v2gdin_body_sessiondetailreq,
			NULL, "SessionDetailReq");
	}
	if (body->ServiceDetailRes_isUsed) {
		proto_tree_add_subtree(body_tree,
			tvb, 0, 0, ett_v2gdin_body_sessiondetailres,
			NULL, "SessionDetailRes");
	}

	if (body->ServicePaymentSelectionReq_isUsed) {
		proto_tree_add_subtree(body_tree,
			tvb, 0, 0, ett_v2gdin_body_servicepaymentselectionreq,
			NULL, "ServicePaymentSelectionReq");
	}
	if (body->ServicePaymentSelectionRes_isUsed) {
		proto_tree_add_subtree(body_tree,
			tvb, 0, 0, ett_v2gdin_body_servicepaymentselectionres,
			NULL, "ServicePaymentSelectionRes");
	}

	if (body->PaymentDetailsReq_isUsed) {
		proto_tree_add_subtree(body_tree,
			tvb, 0, 0, ett_v2gdin_body_paymentdetailsreq,
			NULL, "PaymentDetailsReq");
	}
	if (body->PaymentDetailsRes_isUsed) {
		proto_tree_add_subtree(body_tree,
			tvb, 0, 0, ett_v2gdin_body_paymentdetailsres,
			NULL, "PaymentDetailsRes");
	}

	if (body->ContractAuthenticationReq_isUsed) {
		proto_tree_add_subtree(body_tree,
			tvb, 0, 0, ett_v2gdin_body_contractauthenticationreq,
			NULL, "ContractAuthenticationReq");
	}
	if (body->ContractAuthenticationRes_isUsed) {
		proto_tree_add_subtree(body_tree,
			tvb, 0, 0, ett_v2gdin_body_contractauthenticationres,
			NULL, "ContractAuthenticationRes");
	}

	if (body->ChargeParameterDiscoveryReq_isUsed) {
		proto_tree_add_subtree(body_tree,
			tvb, 0, 0, ett_v2gdin_body_chargeparameterdiscoveryreq,
			NULL, "ChargeParameterDiscoveryReq");
	}
	if (body->ChargeParameterDiscoveryRes_isUsed) {
		proto_tree_add_subtree(body_tree,
			tvb, 0, 0, ett_v2gdin_body_chargeparameterdiscoveryres,
			NULL, "ChargeParameterDiscoveryRes");
	}

	if (body->PowerDeliveryReq_isUsed) {
		proto_tree_add_subtree(body_tree,
			tvb, 0, 0, ett_v2gdin_body_powerdeliveryreq,
			NULL, "PowerDeliveryReq");
	}
	if (body->PowerDeliveryRes_isUsed) {
		proto_tree_add_subtree(body_tree,
			tvb, 0, 0, ett_v2gdin_body_powerdeliveryres,
			NULL, "PowerDeliveryRes");
	}

	if (body->ChargingStatusReq_isUsed) {
		proto_tree_add_subtree(body_tree,
			tvb, 0, 0, ett_v2gdin_body_chargingstatusreq,
			NULL, "ChargingStatusReq");
	}
	if (body->ChargingStatusRes_isUsed) {
		proto_tree_add_subtree(body_tree,
			tvb, 0, 0, ett_v2gdin_body_chargingstatusres,
			NULL, "ChargingStatusRes");
	}

	if (body->MeteringReceiptReq_isUsed) {
		proto_tree_add_subtree(body_tree,
			tvb, 0, 0, ett_v2gdin_body_meteringreceiptreq,
			NULL, "MeteringReceiptReq");
	}
	if (body->MeteringReceiptRes_isUsed) {
		proto_tree_add_subtree(body_tree,
			tvb, 0, 0, ett_v2gdin_body_meteringreceiptres,
			NULL, "MeteringReceiptRes");
	}

	if (body->SessionStopReq_isUsed) {
		proto_tree_add_subtree(body_tree,
			tvb, 0, 0, ett_v2gdin_body_sessionstopreq,
			NULL, "SessionStopReq");
	}
	if (body->SessionStopRes_isUsed) {
		proto_tree_add_subtree(body_tree,
			tvb, 0, 0, ett_v2gdin_body_sessionstopres,
			NULL, "SessionStopRes");
	}

	if (body->CertificateUpdateReq_isUsed) {
		proto_tree_add_subtree(body_tree,
			tvb, 0, 0, ett_v2gdin_body_certificateupdatereq,
			NULL, "CertificateUpdateReq");
	}
	if (body->CertificateUpdateRes_isUsed) {
		proto_tree_add_subtree(body_tree,
			tvb, 0, 0, ett_v2gdin_body_certificateupdateres,
			NULL, "CertificateUpdateRes");
	}

	if (body->CertificateInstallationReq_isUsed) {
		proto_tree_add_subtree(body_tree,
			tvb, 0, 0, ett_v2gdin_body_certificateinstallationreq,
			NULL, "CertificateInstallationReq");
	}
	if (body->CertificateInstallationRes_isUsed) {
		proto_tree_add_subtree(body_tree,
			tvb, 0, 0, ett_v2gdin_body_certificateinstallationres,
			NULL, "CertificateInstallationRes");
	}

	if (body->CableCheckReq_isUsed) {
		proto_tree_add_subtree(body_tree,
			tvb, 0, 0, ett_v2gdin_body_cablecheckreq,
			NULL, "CableCheckReq");
	}
	if (body->CableCheckRes_isUsed) {
		proto_tree_add_subtree(body_tree,
			tvb, 0, 0, ett_v2gdin_body_cablecheckres,
			NULL, "CableCheckRes");
	}

	if (body->PreChargeReq_isUsed) {
		proto_tree_add_subtree(body_tree,
			tvb, 0, 0, ett_v2gdin_body_prechargereq,
			NULL, "PreChargeReq");
	}
	if (body->PreChargeRes_isUsed) {
		proto_tree_add_subtree(body_tree,
			tvb, 0, 0, ett_v2gdin_body_prechargeres,
			NULL, "PreChargeRes");
	}

	if (body->CurrentDemandReq_isUsed) {
		proto_tree_add_subtree(body_tree,
			tvb, 0, 0, ett_v2gdin_body_currentdemandreq,
			NULL, "CurrentDemandReq");
	}
	if (body->CurrentDemandRes_isUsed) {
		proto_tree_add_subtree(body_tree,
			tvb, 0, 0, ett_v2gdin_body_currentdemandres,
			NULL, "CurrentDemandRes");
	}

	if (body->WeldingDetectionReq_isUsed) {
		proto_tree_add_subtree(body_tree,
			tvb, 0, 0, ett_v2gdin_body_weldingdetectionreq,
			NULL, "WeldingDetectionReq");
	}
	if (body->WeldingDetectionRes_isUsed) {
		proto_tree_add_subtree(body_tree,
			tvb, 0, 0, ett_v2gdin_body_weldingdetectionres,
			NULL, "WeldingDetectionRes");
	}

	return;
}

static int
dissect_v2gdin(tvbuff_t *tvb,
	       packet_info *pinfo, proto_tree *tree _U_, void *data _U_)
{
	proto_tree *v2gdin_tree;
	size_t pos;
	bitstream_t stream;
	int errn;
	struct dinEXIDocument exidin;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "DIN");
	/* Clear the info column */
	col_clear(pinfo->cinfo, COL_INFO);

	pos = 0;
	stream.size = tvb_reported_length(tvb);
	stream.pos = &pos;
	stream.data = tvb_memdup(wmem_packet_scope(),
				 tvb, pos, stream.size);
	errn = decode_dinExiDocument(&stream, &exidin);
	if (errn != 0) {
		/* decode failed */
		return 0;
	}

	/*
	 * Everything in DIN should come in as a message
	 * - Header
	 * - Body
	 */
	if (exidin.V2G_Message_isUsed) {
		v2gdin_tree = proto_tree_add_subtree(tree,
			tvb, 0, 0, ett_v2gdin, NULL, "V2G Message");

		dissect_v2gdin_header(tvb, pinfo, v2gdin_tree,
			&exidin.V2G_Message.Header);
		dissect_v2gdin_body(tvb, pinfo, v2gdin_tree,
			&exidin.V2G_Message.Body);
	}

	return tvb_captured_length(tvb);
}

void
proto_register_v2gdin(void)
{

	static hf_register_info hf[] = {
		{ &hf_v2gdin_header_sessionid,
		  { "SessionID", "v2gdin.header.sessionid",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_header_notification_faultcode,
		  { "FaultCode", "v2gdin.header.notification.faultcode",
		    FT_UINT16, BASE_DEC, VALS(v2gdin_fault_code_names),
		    0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_header_notification_faultmsg,
		  { "FaultMsg", "v2gdin.header.notification.faultmsg",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_header_signature_id,
		  { "SignatureId", "v2gdin.header.signature.id",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_body_sessionsetupreq_evccid,
		  { "EVCCID", "v2gdin.body.sessionsetupreq.evccid",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		}
	};

	static gint *ett[] = {
		&ett_v2gdin,
		&ett_v2gdin_header,
		&ett_v2gdin_header_notification,
		&ett_v2gdin_header_signature,
		&ett_v2gdin_body,
		&ett_v2gdin_body_sessionsetupreq,
		&ett_v2gdin_body_sessionsetupres,
		&ett_v2gdin_body_sessiondiscoveryreq,
		&ett_v2gdin_body_sessiondiscoveryres,
		&ett_v2gdin_body_sessiondetailreq,
		&ett_v2gdin_body_sessiondetailres,
		&ett_v2gdin_body_servicepaymentselectionreq,
		&ett_v2gdin_body_servicepaymentselectionres,
		&ett_v2gdin_body_paymentdetailsreq,
		&ett_v2gdin_body_paymentdetailsres,
		&ett_v2gdin_body_contractauthenticationreq,
		&ett_v2gdin_body_contractauthenticationres,
		&ett_v2gdin_body_chargeparameterdiscoveryreq,
		&ett_v2gdin_body_chargeparameterdiscoveryres,
		&ett_v2gdin_body_powerdeliveryreq,
		&ett_v2gdin_body_powerdeliveryres,
		&ett_v2gdin_body_chargingstatusreq,
		&ett_v2gdin_body_chargingstatusres,
		&ett_v2gdin_body_meteringreceiptreq,
		&ett_v2gdin_body_meteringreceiptres,
		&ett_v2gdin_body_sessionstopreq,
		&ett_v2gdin_body_sessionstopres,
		&ett_v2gdin_body_certificateupdatereq,
		&ett_v2gdin_body_certificateupdateres,
		&ett_v2gdin_body_certificateinstallationreq,
		&ett_v2gdin_body_certificateinstallationres,
		&ett_v2gdin_body_cablecheckreq,
		&ett_v2gdin_body_cablecheckres,
		&ett_v2gdin_body_prechargereq,
		&ett_v2gdin_body_prechargeres,
		&ett_v2gdin_body_currentdemandreq,
		&ett_v2gdin_body_currentdemandres,
		&ett_v2gdin_body_weldingdetectionreq,
		&ett_v2gdin_body_weldingdetectionres
	};

	proto_v2gdin = proto_register_protocol (
		"V2G Efficient XML Interchange (DIN)",
		"V2GDIN",
		"v2gdin"
	);
	proto_register_field_array(proto_v2gdin, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	register_dissector("v2gdin", dissect_v2gdin, proto_v2gdin);
}

void
proto_reg_handoff_v2gdin(void)
{

	/* add a handle for the connection oriented V2G EXI */
	v2gexi_handle = find_dissector_add_dependency("v2gexi", proto_v2gdin);
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
