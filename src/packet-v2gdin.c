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
static int hf_v2gdin_header_SessionID = -1;
static int hf_v2gdin_header_Notification_FaultCode = -1;
static int hf_v2gdin_header_Notification_FaultMsg = -1;
static int hf_v2gdin_header_Signature_Id = -1;

static int hf_v2gdin_body_sessionsetupreq_evccid = -1;
static int hf_v2gdin_body_CurrentDemandReq_DC_EVStatus_EVReady = -1;
static int hf_v2gdin_body_CurrentDemandReq_DC_EVStatus_EVCabinConditioning = -1;
static int hf_v2gdin_body_CurrentDemandReq_DC_EVStatus_EVRESSConditioning = -1;
static int hf_v2gdin_body_CurrentDemandReq_DC_EVStatus_EVErrorCode = -1;
static int hf_v2gdin_body_CurrentDemandReq_DC_EVStatus_EVRESSSOC = -1;
static int hf_v2gdin_body_CurrentDemandReq_EVTargetVoltage_Multiplier = -1;
static int hf_v2gdin_body_CurrentDemandReq_EVTargetVoltage_Unit = -1;
static int hf_v2gdin_body_CurrentDemandReq_EVTargetVoltage_Value = -1;
static int hf_v2gdin_body_CurrentDemandReq_EVTargetCurrent_Multiplier = -1;
static int hf_v2gdin_body_CurrentDemandReq_EVTargetCurrent_Unit = -1;
static int hf_v2gdin_body_CurrentDemandReq_EVTargetCurrent_Value = -1;
static int hf_v2gdin_body_CurrentDemandReq_ChargingComplete = -1;
static int hf_v2gdin_body_CurrentDemandReq_BulkChargingComplete = -1;
static int hf_v2gdin_body_CurrentDemandReq_EVMaximumVoltageLimit_Multiplier = -1;
static int hf_v2gdin_body_CurrentDemandReq_EVMaximumVoltageLimit_Unit = -1;
static int hf_v2gdin_body_CurrentDemandReq_EVMaximumVoltageLimit_Value = -1;
static int hf_v2gdin_body_CurrentDemandReq_EVMaximumCurrentLimit_Multiplier = -1;
static int hf_v2gdin_body_CurrentDemandReq_EVMaximumCurrentLimit_Unit = -1;
static int hf_v2gdin_body_CurrentDemandReq_EVMaximumCurrentLimit_Value = -1;
static int hf_v2gdin_body_CurrentDemandReq_EVMaximumPowerLimit_Multiplier = -1;
static int hf_v2gdin_body_CurrentDemandReq_EVMaximumPowerLimit_Unit = -1;
static int hf_v2gdin_body_CurrentDemandReq_EVMaximumPowerLimit_Value = -1;
static int hf_v2gdin_body_CurrentDemandReq_RemainingTimeToFullSoC_Multiplier = -1;
static int hf_v2gdin_body_CurrentDemandReq_RemainingTimeToFullSoC_Unit = -1;
static int hf_v2gdin_body_CurrentDemandReq_RemainingTimeToFullSoC_Value = -1;
static int hf_v2gdin_body_CurrentDemandReq_RemainingTimeToBulkSoC_Multiplier = -1;
static int hf_v2gdin_body_CurrentDemandReq_RemainingTimeToBulkSoC_Unit = -1;
static int hf_v2gdin_body_CurrentDemandReq_RemainingTimeToBulkSoC_Value = -1;
static int hf_v2gdin_body_CurrentDemandRes_ResponseCode = -1;
static int hf_v2gdin_body_CurrentDemandRes_DC_EVSEStatus_EVSEIsolationStatus = -1;
static int hf_v2gdin_body_CurrentDemandRes_DC_EVSEStatus_EVSEStatusCode = -1;
static int hf_v2gdin_body_CurrentDemandRes_DC_EVSEStatus_NotificationMaxDelay = -1;
static int hf_v2gdin_body_CurrentDemandRes_DC_EVSEStatus_EVSENotification = -1;
static int hf_v2gdin_body_CurrentDemandRes_EVSEPresentVoltage_Multiplier = -1;
static int hf_v2gdin_body_CurrentDemandRes_EVSEPresentVoltage_Unit = -1;
static int hf_v2gdin_body_CurrentDemandRes_EVSEPresentVoltage_Value = -1;
static int hf_v2gdin_body_CurrentDemandRes_EVSEPresentCurrent_Multiplier = -1;
static int hf_v2gdin_body_CurrentDemandRes_EVSEPresentCurrent_Unit = -1;
static int hf_v2gdin_body_CurrentDemandRes_EVSEPresentCurrent_Value = -1;
static int hf_v2gdin_body_CurrentDemandRes_EVSECurrentLimitAchieved = -1;
static int hf_v2gdin_body_CurrentDemandRes_EVSEVoltageLimitAchieved = -1;
static int hf_v2gdin_body_CurrentDemandRes_EVSEPowerLimitAchieved = -1;
static int hf_v2gdin_body_CurrentDemandRes_EVSEMaximumVoltageLimit_Multiplier = -1;
static int hf_v2gdin_body_CurrentDemandRes_EVSEMaximumVoltageLimit_Unit = -1;
static int hf_v2gdin_body_CurrentDemandRes_EVSEMaximumVoltageLimit_Value = -1;
static int hf_v2gdin_body_CurrentDemandRes_EVSEMaximumCurrentLimit_Multiplier = -1;
static int hf_v2gdin_body_CurrentDemandRes_EVSEMaximumCurrentLimit_Unit = -1;
static int hf_v2gdin_body_CurrentDemandRes_EVSEMaximumCurrentLimit_Value = -1;
static int hf_v2gdin_body_CurrentDemandRes_EVSEMaximumPowerLimit_Multiplier = -1;
static int hf_v2gdin_body_CurrentDemandRes_EVSEMaximumPowerLimit_Unit = -1;
static int hf_v2gdin_body_CurrentDemandRes_EVSEMaximumPowerLimit_Value = -1;

/* Initialize the subtree pointers */
static gint ett_v2gdin = -1;
static gint ett_v2gdin_header = -1;
static gint ett_v2gdin_header_Notification = -1;
static gint ett_v2gdin_header_Signature = -1;
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
static gint ett_v2gdin_body_CurrentDemandReq = -1;
static gint ett_v2gdin_body_CurrentDemandReq_DC_EVStatus = -1;
static gint ett_v2gdin_body_CurrentDemandReq_EVTargetVoltage = -1;
static gint ett_v2gdin_body_CurrentDemandReq_EVTargetCurrent = -1;
static gint ett_v2gdin_body_CurrentDemandReq_EVMaximumVoltageLimit = -1;
static gint ett_v2gdin_body_CurrentDemandReq_EVMaximumCurrentLimit = -1;
static gint ett_v2gdin_body_CurrentDemandReq_EVMaximumPowerLimit = -1;
static gint ett_v2gdin_body_CurrentDemandReq_RemainingTimeToFullSoC = -1;
static gint ett_v2gdin_body_CurrentDemandReq_RemainingTimeToBulkSoC = -1;
static gint ett_v2gdin_body_CurrentDemandRes = -1;
static gint ett_v2gdin_body_CurrentDemandRes_DC_EVSEStatus = -1;
static gint ett_v2gdin_body_CurrentDemandRes_EVSEPresentVoltage = -1;
static gint ett_v2gdin_body_CurrentDemandRes_EVSEPresentCurrent = -1;
static gint ett_v2gdin_body_CurrentDemandRes_EVSEMaximumVoltageLimit = -1;
static gint ett_v2gdin_body_CurrentDemandRes_EVSEMaximumCurrentLimit = -1;
static gint ett_v2gdin_body_CurrentDemandRes_EVSEMaximumPowerLimit = -1;
static gint ett_v2gdin_body_weldingdetectionreq = -1;
static gint ett_v2gdin_body_weldingdetectionres = -1;

static const value_string v2gdin_fault_code_names[] = {
	{ dinfaultCodeType_ParsingError, "ParsingError" },
        { dinfaultCodeType_NoTLSRootCertificatAvailable,
	  "NoTLSRootCertificatAvailable" },
	{ dinfaultCodeType_UnknownError, "UnknownError" }
};

static const value_string v2gdin_response_code_names[] = {
	{ dinresponseCodeType_OK, "OK" },
	{ dinresponseCodeType_OK_NewSessionEstablished,
	  "OK (NewSessionEstablished)" },
	{ dinresponseCodeType_OK_OldSessionJoined,
	  "OK (OldSessionJoined) " },
	{ dinresponseCodeType_OK_CertificateExpiresSoon,
	  "OK (CertificateExpiresSoon)" },
	{ dinresponseCodeType_FAILED, "FAILED" },
	{ dinresponseCodeType_FAILED_SequenceError,
	  "FAILED (SequenceError)" },
	{ dinresponseCodeType_FAILED_ServiceIDInvalid,
	  "FAILED (ServiceIDInvalid)" },
	{ dinresponseCodeType_FAILED_UnknownSession,
	  "FAILED (UnknownSession)" },
	{ dinresponseCodeType_FAILED_ServiceSelectionInvalid,
	  "FAILED (ServiceSelectionInvalid)" },
	{ dinresponseCodeType_FAILED_PaymentSelectionInvalid,
	  "FAILED (PaymentSelectionInvalid)" },
	{ dinresponseCodeType_FAILED_CertificateExpired,
	  "FAILED (CertificateExpired)" },
	{ dinresponseCodeType_FAILED_SignatureError,
	  "FAILED (SignatureError)" },
	{ dinresponseCodeType_FAILED_NoCertificateAvailable,
	  "FAILED (NoCertificateAvailable)" },
	{ dinresponseCodeType_FAILED_CertChainError,
	  "FAILED (CertChainError)" },
	{ dinresponseCodeType_FAILED_ChallengeInvalid,
	  "FAILED (ChallengeInvalid)" },
	{ dinresponseCodeType_FAILED_ContractCanceled,
	  "FAILED (ContractCanceled)" },
	{ dinresponseCodeType_FAILED_WrongChargeParameter,
	  "FAILED (WrongChargeParameter)" },
	{ dinresponseCodeType_FAILED_PowerDeliveryNotApplied,
	  "FAILED (PowerDeliveryNotApplied)" },
	{ dinresponseCodeType_FAILED_TariffSelectionInvalid,
	  "FAILED (TariffSelectionInvalid)" },
	{ dinresponseCodeType_FAILED_ChargingProfileInvalid,
	  "FAILED (ChargingProfileInvalid)" },
	{ dinresponseCodeType_FAILED_EVSEPresentVoltageToLow,
	  "FAILED (EVSEPresentVoltageToLow)" },
	{ dinresponseCodeType_FAILED_MeteringSignatureNotValid,
	  "FAILED (MeteringSignatureNotValid)" },
	{ dinresponseCodeType_FAILED_WrongEnergyTransferType,
	  "FAILED (WrongEnergyTransferType)" }
};

static const value_string v2gdin_isolation_level_names[] = {
	{ dinisolationLevelType_Invalid, "Invalid" },
	{ dinisolationLevelType_Valid, "Valid" },
	{ dinisolationLevelType_Warning, "Warning" },
	{ dinisolationLevelType_Fault, "Fault" }
};

static const value_string v2gdin_dc_everrorcode_names[] = {
	{ dinDC_EVErrorCodeType_NO_ERROR, "NO ERROR" },
	{ dinDC_EVErrorCodeType_FAILED_RESSTemperatureInhibit,
          "FAILED (RESSTemperatureInhibit)" },
	{ dinDC_EVErrorCodeType_FAILED_EVShiftPosition,
	  "FAILED (EVShiftPosition)" },
	{ dinDC_EVErrorCodeType_FAILED_ChargerConnectorLockFault,
	  "FAILED (ChargerConnectorLockFault)" },
	{ dinDC_EVErrorCodeType_FAILED_EVRESSMalfunction,
	  "FAILED (EVRESSMalfunction)" },
	{ dinDC_EVErrorCodeType_FAILED_ChargingCurrentdifferential,
	  "FAILED (ChargingCurrentdifferential)" },
	{ dinDC_EVErrorCodeType_FAILED_ChargingVoltageOutOfRange,
	  "FAILED (ChargingVoltageOutOfRange)" },
	{ dinDC_EVErrorCodeType_Reserved_A, "Reserved A" },
	{ dinDC_EVErrorCodeType_Reserved_B, "Reserved B" },
	{ dinDC_EVErrorCodeType_Reserved_C, "Reserved C" },
	{ dinDC_EVErrorCodeType_FAILED_ChargingSystemIncompatibility,
	  "FAILED (ChargingSystemIncompatibility)" },
	{ dinDC_EVErrorCodeType_NoData, "NoData" }
};

static const value_string v2gdin_dc_evsestatuscode_names[] = {
	{ dinDC_EVSEStatusCodeType_EVSE_NotReady, "EVSE NotReady" },
	{ dinDC_EVSEStatusCodeType_EVSE_Ready, "EVSE Ready" },
	{ dinDC_EVSEStatusCodeType_EVSE_Shutdown, "EVSE Shutdown" },
	{ dinDC_EVSEStatusCodeType_EVSE_UtilityInterruptEvent,
	  "EVSE UtilityInterruptEvent" },
	{ dinDC_EVSEStatusCodeType_EVSE_IsolationMonitoringActive,
	  "EVSE IsolationMonitoringActive" },
	{ dinDC_EVSEStatusCodeType_EVSE_EmergencyShutdown,
	  "EVSE EmergencyShutdown" },
	{ dinDC_EVSEStatusCodeType_EVSE_Malfunction,
	  "EVSE Malfunction" },
	{ dinDC_EVSEStatusCodeType_Reserved_8, "Reserved 8" },
	{ dinDC_EVSEStatusCodeType_Reserved_9, "Reserved 9" },
	{ dinDC_EVSEStatusCodeType_Reserved_A, "Reserved A" },
	{ dinDC_EVSEStatusCodeType_Reserved_B, "Reserved B" },
	{ dinDC_EVSEStatusCodeType_Reserved_C, "Reserved C" }
};

static const value_string v2gdin_evsenotification_names[] = {
	{ dinEVSENotificationType_None, "None" },
	{ dinEVSENotificationType_StopCharging, "StopCharging" },
	{ dinEVSENotificationType_ReNegotiation, "ReNegotiation" }
};

static const value_string v2gdin_unitsymbol_names[] = {
	{ dinunitSymbolType_h, "h" },
	{ dinunitSymbolType_m, "m" },
	{ dinunitSymbolType_s, "s" },
	{ dinunitSymbolType_A, "A" },
	{ dinunitSymbolType_Ah, "Ah" },
	{ dinunitSymbolType_V, "V" },
	{ dinunitSymbolType_VA, "VA" },
	{ dinunitSymbolType_W, "W" },
	{ dinunitSymbolType_W_s, "W_s" },
	{ dinunitSymbolType_Wh, "Wh" }
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
		hf_v2gdin_header_SessionID, tvb, 0, 0, sessionid);
	proto_item_set_generated(it);

	if (hdr->Notification_isUsed) {
		proto_tree *notification_tree;

		notification_tree = proto_tree_add_subtree(hdr_tree,
			tvb, 0, 0, ett_v2gdin_header_Notification,
			NULL, "Notification");

		it = proto_tree_add_uint(notification_tree,
			hf_v2gdin_header_Notification_FaultCode,
			tvb, 0, 0, hdr->Notification.FaultCode);
		proto_item_set_generated(it);

		if (hdr->Notification.FaultMsg_isUsed) {
			char faultmsg[dinNotificationType_FaultMsg_CHARACTERS_SIZE + 1];
			for (i = 0; i < hdr->Notification.FaultMsg.charactersLen; i++) {
				faultmsg[i] = hdr->Notification.FaultMsg.characters[i];
			}
			faultmsg[i] = '\0';
			it = proto_tree_add_string(notification_tree,
				hf_v2gdin_header_Notification_FaultMsg,
				tvb, 0, 0, faultmsg);
			proto_item_set_generated(it);
		}
	}

	if (hdr->Signature_isUsed) {
		proto_tree *signature_tree;

		signature_tree = proto_tree_add_subtree(hdr_tree,
			tvb, 0, 0, ett_v2gdin_header_Signature,
			NULL, "Signature");

		if (hdr->Signature.Id_isUsed) {
			char id[dinSignatureType_Id_CHARACTERS_SIZE + 1];
			for (i = 0; i < hdr->Signature.Id.charactersLen; i++) {
				id[i] = hdr->Signature.Id.characters[i];
			}
			id[i] = '\0';
			it = proto_tree_add_string(signature_tree,
				hf_v2gdin_header_Signature_Id,
				tvb, 0, 0, id);
			proto_item_set_generated(it);
		}

		if (hdr->Signature.KeyInfo_isUsed) {
		}
	}

	return;
}

static void
dissect_v2gdin_dc_evstatus(const struct dinDC_EVStatusType *dc_evstatus,
			   tvbuff_t *tvb,
			   proto_tree *tree,
			   gint idx,
			   const char *subtree_name,
			   int hfindex_evready,
			   int hfindex_evcabinconditioning,
			   int hfindex_evressconditioning,
			   int hfindex_everrorcode,
			   int hfindex_evresssoc)
{
	proto_tree *subtree;
	proto_item *it;

	subtree = proto_tree_add_subtree(tree, tvb, 0, 0,
		idx, NULL, subtree_name);

	it = proto_tree_add_int(subtree,
		hfindex_evready, tvb, 0, 0,
		dc_evstatus->EVReady);
	proto_item_set_generated(it);

	if (dc_evstatus->EVCabinConditioning_isUsed) {
		it = proto_tree_add_int(subtree,
			hfindex_evcabinconditioning, tvb, 0, 0,
			dc_evstatus->EVCabinConditioning);
		proto_item_set_generated(it);
	}

	if (dc_evstatus->EVRESSConditioning_isUsed) {
		it = proto_tree_add_int(subtree,
			hfindex_evressconditioning, tvb, 0, 0,
			dc_evstatus->EVRESSConditioning);
		proto_item_set_generated(it);
	}

	it = proto_tree_add_uint(subtree,
		hfindex_everrorcode, tvb, 0, 0,
		dc_evstatus->EVErrorCode);
	proto_item_set_generated(it);

	it = proto_tree_add_int(subtree,
		hfindex_evresssoc, tvb, 0, 0,
		dc_evstatus->EVRESSSOC);
	proto_item_set_generated(it);

	return;
}

static void
dissect_v2gdin_dc_evsestatus(const struct dinDC_EVSEStatusType *dc_evsestatus,
			     tvbuff_t *tvb,
			     proto_tree *tree,
			     gint idx,
			     const char *subtree_name,
			     int hfindex_evseisolationstatus,
			     int hfindex_evsestatuscode,
			     int hfindex_notificationmaxdelay,
			     int hfindex_evsenotification)
{
	proto_tree *subtree;
	proto_item *it;

	subtree = proto_tree_add_subtree(tree, tvb, 0, 0,
		idx, NULL, subtree_name);

	if (dc_evsestatus->EVSEIsolationStatus_isUsed) {
		it = proto_tree_add_uint(subtree,
			hfindex_evseisolationstatus, tvb, 0, 0,
			dc_evsestatus->EVSEIsolationStatus);
		proto_item_set_generated(it);
	}

	it = proto_tree_add_uint(subtree,
		hfindex_evsestatuscode, tvb, 0, 0,
		dc_evsestatus->EVSEStatusCode);
	proto_item_set_generated(it);

	it = proto_tree_add_uint(subtree,
		hfindex_notificationmaxdelay, tvb, 0, 0,
		dc_evsestatus->NotificationMaxDelay);
	proto_item_set_generated(it);

	it = proto_tree_add_uint(subtree,
		hfindex_evsenotification, tvb, 0, 0,
		dc_evsestatus->EVSENotification);
	proto_item_set_generated(it);

	return;
};

static void
dissect_v2gdin_physicalvalue(const struct dinPhysicalValueType *physicalvalue,
			     tvbuff_t *tvb,
			     proto_tree *tree,
			     gint idx,
			     const char *subtree_name,
			     int hfindex_multiplier,
			     int hfindex_unit,
			     int hfindex_value)
{
	proto_tree *subtree;
	proto_item *it;

	subtree = proto_tree_add_subtree(tree, tvb, 0, 0,
		idx, NULL, subtree_name);

	it = proto_tree_add_int(subtree, hfindex_multiplier,
		tvb, 0, 0, physicalvalue->Multiplier);
	proto_item_set_generated(it);

	if (physicalvalue->Unit_isUsed) {
		it = proto_tree_add_uint(subtree, hfindex_unit,
			tvb, 0, 0, physicalvalue->Unit);
		proto_item_set_generated(it);
	}

	it = proto_tree_add_int(subtree, hfindex_value,
		tvb, 0, 0, physicalvalue->Value);
	proto_item_set_generated(it);

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
		proto_tree *currentdemandreq_tree;

		currentdemandreq_tree = proto_tree_add_subtree(body_tree,
			tvb, 0, 0, ett_v2gdin_body_CurrentDemandReq,
			NULL, "CurrentDemandReq");

		dissect_v2gdin_dc_evstatus(
			&body->CurrentDemandReq.DC_EVStatus,
			tvb, currentdemandreq_tree,
			ett_v2gdin_body_CurrentDemandReq_DC_EVStatus,
			"DC_EVStatus",
			hf_v2gdin_body_CurrentDemandReq_DC_EVStatus_EVReady,
			hf_v2gdin_body_CurrentDemandReq_DC_EVStatus_EVCabinConditioning,
			hf_v2gdin_body_CurrentDemandReq_DC_EVStatus_EVRESSConditioning,
			hf_v2gdin_body_CurrentDemandReq_DC_EVStatus_EVErrorCode,
			hf_v2gdin_body_CurrentDemandReq_DC_EVStatus_EVRESSSOC);

		dissect_v2gdin_physicalvalue(
			&body->CurrentDemandReq.EVTargetVoltage,
			tvb, currentdemandreq_tree,
			ett_v2gdin_body_CurrentDemandReq_EVTargetVoltage,
			"EVTargetVoltage",
			hf_v2gdin_body_CurrentDemandReq_EVTargetVoltage_Multiplier,
			hf_v2gdin_body_CurrentDemandReq_EVTargetVoltage_Unit,
			hf_v2gdin_body_CurrentDemandReq_EVTargetVoltage_Value);

		dissect_v2gdin_physicalvalue(
			&body->CurrentDemandReq.EVTargetCurrent,
			tvb, currentdemandreq_tree,
			ett_v2gdin_body_CurrentDemandReq_EVTargetCurrent,
			"EVTargetCurrent",
			hf_v2gdin_body_CurrentDemandReq_EVTargetCurrent_Multiplier,
			hf_v2gdin_body_CurrentDemandReq_EVTargetCurrent_Unit,
			hf_v2gdin_body_CurrentDemandReq_EVTargetCurrent_Value);

		it = proto_tree_add_int(currentdemandreq_tree,
			hf_v2gdin_body_CurrentDemandReq_ChargingComplete,
			tvb, 0, 0, body->CurrentDemandReq.ChargingComplete);
		proto_item_set_generated(it);

		if (body->CurrentDemandReq.BulkChargingComplete_isUsed) {
			it = proto_tree_add_int(currentdemandreq_tree,
				hf_v2gdin_body_CurrentDemandReq_BulkChargingComplete,
				tvb, 0, 0, body->CurrentDemandReq.BulkChargingComplete);
			proto_item_set_generated(it);
		}

		if (body->CurrentDemandReq.EVMaximumVoltageLimit_isUsed) {
			dissect_v2gdin_physicalvalue(
				&body->CurrentDemandReq.EVMaximumVoltageLimit,
				tvb, currentdemandreq_tree,
				ett_v2gdin_body_CurrentDemandReq_EVMaximumVoltageLimit,
				"EVMaximumVoltageLimit",
				hf_v2gdin_body_CurrentDemandReq_EVMaximumVoltageLimit_Multiplier,
				hf_v2gdin_body_CurrentDemandReq_EVMaximumVoltageLimit_Unit,
				hf_v2gdin_body_CurrentDemandReq_EVMaximumVoltageLimit_Value);
		}

		if (body->CurrentDemandReq.EVMaximumCurrentLimit_isUsed) {
			dissect_v2gdin_physicalvalue(
				&body->CurrentDemandReq.EVMaximumCurrentLimit,
				tvb, currentdemandreq_tree,
				ett_v2gdin_body_CurrentDemandReq_EVMaximumCurrentLimit,
				"EVMaximumCurrentLimit",
				hf_v2gdin_body_CurrentDemandReq_EVMaximumCurrentLimit_Multiplier,
				hf_v2gdin_body_CurrentDemandReq_EVMaximumCurrentLimit_Unit,
				hf_v2gdin_body_CurrentDemandReq_EVMaximumCurrentLimit_Value);
		}

		if (body->CurrentDemandReq.EVMaximumPowerLimit_isUsed) {
			dissect_v2gdin_physicalvalue(
				&body->CurrentDemandReq.EVMaximumPowerLimit,
				tvb, currentdemandreq_tree,
				ett_v2gdin_body_CurrentDemandReq_EVMaximumPowerLimit,
				"EVMaximumPowerLimit",
				hf_v2gdin_body_CurrentDemandReq_EVMaximumPowerLimit_Multiplier,
				hf_v2gdin_body_CurrentDemandReq_EVMaximumPowerLimit_Unit,
				hf_v2gdin_body_CurrentDemandReq_EVMaximumPowerLimit_Value);
		}

		if (body->CurrentDemandReq.RemainingTimeToFullSoC_isUsed) {
			dissect_v2gdin_physicalvalue(
				&body->CurrentDemandReq.RemainingTimeToFullSoC,
				tvb, currentdemandreq_tree,
				ett_v2gdin_body_CurrentDemandReq_RemainingTimeToFullSoC,
				"RemainingTimeToFullSoC",
				hf_v2gdin_body_CurrentDemandReq_RemainingTimeToFullSoC_Multiplier,
				hf_v2gdin_body_CurrentDemandReq_RemainingTimeToFullSoC_Unit,
				hf_v2gdin_body_CurrentDemandReq_RemainingTimeToFullSoC_Value);
		}

		if (body->CurrentDemandReq.RemainingTimeToBulkSoC_isUsed) {
			dissect_v2gdin_physicalvalue(
				&body->CurrentDemandReq.RemainingTimeToBulkSoC,
				tvb, currentdemandreq_tree,
				ett_v2gdin_body_CurrentDemandReq_RemainingTimeToBulkSoC,
				"RemainingTimeToBulkSoC",
				hf_v2gdin_body_CurrentDemandReq_RemainingTimeToBulkSoC_Multiplier,
				hf_v2gdin_body_CurrentDemandReq_RemainingTimeToBulkSoC_Unit,
				hf_v2gdin_body_CurrentDemandReq_RemainingTimeToBulkSoC_Value);
		}
	}
	if (body->CurrentDemandRes_isUsed) {
		proto_tree *currentdemandres_tree;

		currentdemandres_tree = proto_tree_add_subtree(body_tree,
			tvb, 0, 0, ett_v2gdin_body_CurrentDemandRes,
			NULL, "CurrentDemandRes");

		it = proto_tree_add_uint(currentdemandres_tree,
			hf_v2gdin_body_CurrentDemandRes_ResponseCode,
			tvb, 0, 0, body->CurrentDemandRes.ResponseCode);
		proto_item_set_generated(it);

		dissect_v2gdin_dc_evsestatus(
			&body->CurrentDemandRes.DC_EVSEStatus,
			tvb, currentdemandres_tree,
			ett_v2gdin_body_CurrentDemandRes_DC_EVSEStatus,
			"DC_EVSEStatus",
			hf_v2gdin_body_CurrentDemandRes_DC_EVSEStatus_EVSEIsolationStatus,
			hf_v2gdin_body_CurrentDemandRes_DC_EVSEStatus_EVSEStatusCode,
			hf_v2gdin_body_CurrentDemandRes_DC_EVSEStatus_NotificationMaxDelay,
			hf_v2gdin_body_CurrentDemandRes_DC_EVSEStatus_EVSENotification);

		dissect_v2gdin_physicalvalue(
			&body->CurrentDemandRes.EVSEPresentVoltage,
			tvb, currentdemandres_tree,
			ett_v2gdin_body_CurrentDemandRes_EVSEPresentVoltage,
			"EVSEPresentVoltage",
			hf_v2gdin_body_CurrentDemandRes_EVSEPresentVoltage_Multiplier,
			hf_v2gdin_body_CurrentDemandRes_EVSEPresentVoltage_Unit,
			hf_v2gdin_body_CurrentDemandRes_EVSEPresentVoltage_Value);

		dissect_v2gdin_physicalvalue(
			&body->CurrentDemandRes.EVSEPresentCurrent,
			tvb, currentdemandres_tree,
			ett_v2gdin_body_CurrentDemandRes_EVSEPresentCurrent,
			"EVSEPresentCurrent",
			hf_v2gdin_body_CurrentDemandRes_EVSEPresentCurrent_Multiplier,
			hf_v2gdin_body_CurrentDemandRes_EVSEPresentCurrent_Unit,
			hf_v2gdin_body_CurrentDemandRes_EVSEPresentCurrent_Value);

		it = proto_tree_add_int(currentdemandres_tree,
			hf_v2gdin_body_CurrentDemandRes_EVSECurrentLimitAchieved,
			tvb, 0, 0, body->CurrentDemandRes.EVSECurrentLimitAchieved);
		proto_item_set_generated(it);

		it = proto_tree_add_int(currentdemandres_tree,
			hf_v2gdin_body_CurrentDemandRes_EVSEVoltageLimitAchieved,
			tvb, 0, 0, body->CurrentDemandRes.EVSEVoltageLimitAchieved);
		proto_item_set_generated(it);

		it = proto_tree_add_int(currentdemandres_tree,
			hf_v2gdin_body_CurrentDemandRes_EVSEPowerLimitAchieved,
			tvb, 0, 0, body->CurrentDemandRes.EVSEPowerLimitAchieved);
		proto_item_set_generated(it);

		if (body->CurrentDemandRes.EVSEMaximumVoltageLimit_isUsed) {
			dissect_v2gdin_physicalvalue(
				&body->CurrentDemandRes.EVSEMaximumVoltageLimit,
				tvb, currentdemandres_tree,
				ett_v2gdin_body_CurrentDemandRes_EVSEMaximumVoltageLimit,
				"EVSEMaximumVoltageLimit",
				hf_v2gdin_body_CurrentDemandRes_EVSEMaximumVoltageLimit_Multiplier,
				hf_v2gdin_body_CurrentDemandRes_EVSEMaximumVoltageLimit_Unit,
				hf_v2gdin_body_CurrentDemandRes_EVSEMaximumVoltageLimit_Value);
		}
		if (body->CurrentDemandRes.EVSEMaximumCurrentLimit_isUsed) {
			dissect_v2gdin_physicalvalue(
				&body->CurrentDemandRes.EVSEMaximumCurrentLimit,
				tvb, currentdemandres_tree,
				ett_v2gdin_body_CurrentDemandRes_EVSEMaximumCurrentLimit,
				"EVSEMaximumCurrentLimit",
				hf_v2gdin_body_CurrentDemandRes_EVSEMaximumCurrentLimit_Multiplier,
				hf_v2gdin_body_CurrentDemandRes_EVSEMaximumCurrentLimit_Unit,
				hf_v2gdin_body_CurrentDemandRes_EVSEMaximumCurrentLimit_Value);
		}
		if (body->CurrentDemandRes.EVSEMaximumPowerLimit_isUsed) {
			dissect_v2gdin_physicalvalue(
				&body->CurrentDemandRes.EVSEMaximumPowerLimit,
				tvb, currentdemandres_tree,
				ett_v2gdin_body_CurrentDemandRes_EVSEMaximumPowerLimit,
				"EVSEMaximumPowerLimit",
				hf_v2gdin_body_CurrentDemandRes_EVSEMaximumPowerLimit_Multiplier,
				hf_v2gdin_body_CurrentDemandRes_EVSEMaximumPowerLimit_Unit,
				hf_v2gdin_body_CurrentDemandRes_EVSEMaximumPowerLimit_Value);
		}
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
		{ &hf_v2gdin_header_SessionID,
		  { "SessionID", "v2gdin.header.sessionid",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_header_Notification_FaultCode,
		  { "FaultCode", "v2gdin.header.notification.faultcode",
		    FT_UINT16, BASE_DEC, VALS(v2gdin_fault_code_names),
		    0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_header_Notification_FaultMsg,
		  { "FaultMsg", "v2gdin.header.notification.faultmsg",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_header_Signature_Id,
		  { "SignatureId", "v2gdin.header.signature.id",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_body_sessionsetupreq_evccid,
		  { "EVCCID", "v2gdin.body.sessionsetupreq.evccid",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* CurrentDemandReq */
		{ &hf_v2gdin_body_CurrentDemandReq_DC_EVStatus_EVReady,
		  { "EVReady",
		    "v2gdin.body.currentdemandreq.dc_evstatus.evready",
		    FT_INT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_body_CurrentDemandReq_DC_EVStatus_EVCabinConditioning,
		  { "EVCabinConditioning",
		    "v2gdin.body.currentdemandreq.dc_evstatus.evcabinconditioning",
		    FT_INT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_body_CurrentDemandReq_DC_EVStatus_EVRESSConditioning,
		  { "EVRESSConditioning",
		    "v2gdin.body.currentdemandreq.dc_evstatus.evressconditioning",
		    FT_INT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_body_CurrentDemandReq_DC_EVStatus_EVErrorCode,
		  { "EVErrorCode",
		    "v2gdin.body.currentdemandreq.dc_evstatus.everrorcode",
		    FT_UINT32, BASE_DEC, VALS(v2gdin_dc_everrorcode_names),
		    0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_body_CurrentDemandReq_DC_EVStatus_EVRESSSOC,
		  { "EVRESSSOC",
		    "v2gdin.body.currentdemandreq.dc_evstatus.evresssoc",
		    FT_INT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_body_CurrentDemandReq_EVTargetVoltage_Multiplier,
		  { "Multiplier",
		    "v2gdin.body.currentdemandreq.evtargetvoltage.multiplier",
		    FT_INT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_body_CurrentDemandReq_EVTargetVoltage_Unit,
		  { "Unit",
		    "v2gdin.body.currentdemandreq.evtargetvoltage.unit",
		    FT_UINT32, BASE_DEC, VALS(v2gdin_unitsymbol_names),
		    0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_body_CurrentDemandReq_EVTargetVoltage_Value,
		  { "Value",
		    "v2gdin.body.currentdemandreq.evtargetvoltage.value",
		    FT_INT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_body_CurrentDemandReq_EVTargetCurrent_Multiplier,
		  { "Multiplier",
		    "v2gdin.body.currentdemandreq.evtargetcurrent.multiplier",
		    FT_INT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_body_CurrentDemandReq_EVTargetCurrent_Unit,
		  { "Unit",
		    "v2gdin.body.currentdemandreq.evtargetcurrent.unit",
		    FT_UINT32, BASE_DEC, VALS(v2gdin_unitsymbol_names),
		    0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_body_CurrentDemandReq_EVTargetCurrent_Value,
		  { "Value",
		    "v2gdin.body.currentdemandreq.evtargetcurrent.value",
		    FT_INT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_body_CurrentDemandReq_ChargingComplete,
		  { "ChargingComplete",
		    "v2gdin.body.currentdemandreq.chargingcomplete",
		    FT_INT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_body_CurrentDemandReq_BulkChargingComplete,
		  { "BulkChargingComplete",
		    "v2gdin.body.currentdemandreq.bulkchargingcomplete",
		    FT_INT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_body_CurrentDemandReq_EVMaximumVoltageLimit_Multiplier,
		  { "Multiplier",
		    "v2gdin.body.currentdemandreq.evmaximumvoltagelimit.multiplier",
		    FT_INT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_body_CurrentDemandReq_EVMaximumVoltageLimit_Unit,
		  { "Unit",
		    "v2gdin.body.currentdemandreq.evmaximumvoltagelimit.unit",
		    FT_UINT32, BASE_DEC, VALS(v2gdin_unitsymbol_names),
		    0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_body_CurrentDemandReq_EVMaximumVoltageLimit_Value,
		  { "Value",
		    "v2gdin.body.currentdemandreq.evmaximumvoltagelimit.value",
		    FT_INT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_body_CurrentDemandReq_EVMaximumCurrentLimit_Multiplier,
		  { "Multiplier",
		    "v2gdin.body.currentdemandreq.evmaximumcurrentlimit.multiplier",
		    FT_INT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_body_CurrentDemandReq_EVMaximumCurrentLimit_Unit,
		  { "Unit",
		    "v2gdin.body.currentdemandreq.evmaximumcurrentlimit.unit",
		    FT_UINT32, BASE_DEC, VALS(v2gdin_unitsymbol_names),
		    0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_body_CurrentDemandReq_EVMaximumCurrentLimit_Value,
		  { "Value",
		    "v2gdin.body.currentdemandreq.evmaximumcurrentlimit.value",
		    FT_INT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_body_CurrentDemandReq_EVMaximumPowerLimit_Multiplier,
		  { "Multiplier",
		    "v2gdin.body.currentdemandreq.evmaximumpowerlimit.multiplier",
		    FT_INT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_body_CurrentDemandReq_EVMaximumPowerLimit_Unit,
		  { "Unit",
		    "v2gdin.body.currentdemandreq.evmaximumpowerlimit.unit",
		    FT_UINT32, BASE_DEC, VALS(v2gdin_unitsymbol_names),
		    0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_body_CurrentDemandReq_EVMaximumPowerLimit_Value,
		  { "Value",
		    "v2gdin.body.currentdemandreq.evmaximumpowerlimit.value",
		    FT_INT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_body_CurrentDemandReq_RemainingTimeToFullSoC_Multiplier,
		  { "Multiplier",
		    "v2gdin.body.currentdemandreq.remainingtimetofullsoc.multiplier",
		    FT_INT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_body_CurrentDemandReq_RemainingTimeToFullSoC_Unit,
		  { "Unit",
		    "v2gdin.body.currentdemandreq.remainingtimetofullsoc.unit",
		    FT_UINT32, BASE_DEC, VALS(v2gdin_unitsymbol_names),
		    0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_body_CurrentDemandReq_RemainingTimeToFullSoC_Value,
		  { "Value",
		    "v2gdin.body.currentdemandreq.remainingtimetofullsoc.value",
		    FT_INT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_body_CurrentDemandReq_RemainingTimeToBulkSoC_Multiplier,
		  { "Multiplier",
		    "v2gdin.body.currentdemandreq.remainingtimetobulksoc.multiplier",
		    FT_INT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_body_CurrentDemandReq_RemainingTimeToBulkSoC_Unit,
		  { "Unit",
		    "v2gdin.body.currentdemandreq.remainingtimetobulksoc.unit",
		    FT_UINT32, BASE_DEC, VALS(v2gdin_unitsymbol_names),
		    0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_body_CurrentDemandReq_RemainingTimeToBulkSoC_Value,
		  { "Value",
		    "v2gdin.body.currentdemandreq.remainingtimetobulksoc.value",
		    FT_INT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},

		/* CurrentDemandRes */
		{ &hf_v2gdin_body_CurrentDemandRes_ResponseCode,
		  { "ResponseCode", "v2gdin.body.currentdemandres.responsecode",
		    FT_UINT32, BASE_DEC, VALS(v2gdin_response_code_names),
		    0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_body_CurrentDemandRes_DC_EVSEStatus_EVSEIsolationStatus,
		  { "EVSEIsolationStatus",
		    "v2gdin.body.currentdemandres.dc_evsestatus.evseisolationstatus",
		    FT_UINT32, BASE_DEC, VALS(v2gdin_isolation_level_names),
		    0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_body_CurrentDemandRes_DC_EVSEStatus_EVSEStatusCode,
		  { "EVSEStatusCode",
		    "v2gdin.body.currentdemandres.dc_evsestatus.evsestatuscode",
		    FT_UINT32, BASE_DEC, VALS(v2gdin_dc_evsestatuscode_names),
		    0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_body_CurrentDemandRes_DC_EVSEStatus_NotificationMaxDelay,
		  { "NotificationMaxDelay",
		    "v2gdin.body.currentdemandres.dc_evsestatus.notificationmaxdelay",
		    FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_body_CurrentDemandRes_DC_EVSEStatus_EVSENotification,
		  { "EVSENotification",
		    "v2gdin.body.currentdemandres.dc_evsestatus.evsenotification",
		    FT_UINT32, BASE_DEC, VALS(v2gdin_evsenotification_names),
		    0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_body_CurrentDemandRes_EVSEPresentVoltage_Multiplier,
		  { "Multiplier",
		    "v2gdin.body.currentdemandres.evsepresentvoltage.multiplier",
		    FT_INT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_body_CurrentDemandRes_EVSEPresentVoltage_Unit,
		  { "Unit",
		    "v2gdin.body.currentdemandres.evsepresentvoltage.unit",
		    FT_UINT32, BASE_DEC, VALS(v2gdin_unitsymbol_names),
		    0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_body_CurrentDemandRes_EVSEPresentVoltage_Value,
		  { "Value",
		    "v2gdin.body.currentdemandres.evsepresentvoltage.value",
		    FT_INT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_body_CurrentDemandRes_EVSEPresentCurrent_Multiplier,
		  { "Multiplier",
		    "v2gdin.body.currentdemandres.evsepresentcurrent.multiplier",
		    FT_INT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_body_CurrentDemandRes_EVSEPresentCurrent_Unit,
		  { "Unit",
		    "v2gdin.body.currentdemandres.evsepresentcurrent.unit",
		    FT_UINT32, BASE_DEC, VALS(v2gdin_unitsymbol_names),
		    0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_body_CurrentDemandRes_EVSEPresentCurrent_Value,
		  { "Value",
		    "v2gdin.body.currentdemandres.evsepresentcurrent.value",
		    FT_INT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_body_CurrentDemandRes_EVSECurrentLimitAchieved,
		  { "EVSECurrentLimitAchieved",
		    "v2gdin.body.currentdemandres.evsecurrentlimitachieved",
		    FT_INT32, BASE_DEC, 0,
		    0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_body_CurrentDemandRes_EVSEVoltageLimitAchieved,
		  { "EVSEVoltageLimitAchieved",
		    "v2gdin.body.currentdemandres.evsevoltagelimitachieved",
		    FT_INT32, BASE_DEC, 0,
		    0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_body_CurrentDemandRes_EVSEPowerLimitAchieved,
		  { "EVSEPowerLimitAchieved",
		    "v2gdin.body.currentdemandres.evsepowerlimitachieved",
		    FT_INT32, BASE_DEC, 0,
		    0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_body_CurrentDemandRes_EVSEMaximumVoltageLimit_Multiplier,
		  { "Multiplier",
		    "v2gdin.body.currentdemandres.evsemaximumvoltagelimit.multiplier",
		    FT_INT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_body_CurrentDemandRes_EVSEMaximumVoltageLimit_Unit,
		  { "Unit",
		    "v2gdin.body.currentdemandres.evsemaximumvoltagelimit.unit",
		    FT_UINT32, BASE_DEC, VALS(v2gdin_unitsymbol_names),
		    0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_body_CurrentDemandRes_EVSEMaximumVoltageLimit_Value,
		  { "Value",
		    "v2gdin.body.currentdemandres.evsemaximumvoltagelimit.value",
		    FT_INT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_body_CurrentDemandRes_EVSEMaximumCurrentLimit_Multiplier,
		  { "Multiplier",
		    "v2gdin.body.currentdemandres.evsemaximumcurrentlimit.multiplier",
		    FT_INT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_body_CurrentDemandRes_EVSEMaximumCurrentLimit_Unit,
		  { "Unit",
		    "v2gdin.body.currentdemandres.evsemaximumcurrentlimit.unit",
		    FT_UINT32, BASE_DEC, VALS(v2gdin_unitsymbol_names),
		    0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_body_CurrentDemandRes_EVSEMaximumCurrentLimit_Value,
		  { "Value",
		    "v2gdin.body.currentdemandres.evsemaximumcurrentlimit.value",
		    FT_INT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_body_CurrentDemandRes_EVSEMaximumPowerLimit_Multiplier,
		  { "Multiplier",
		    "v2gdin.body.currentdemandres.evsemaximumpowerlimit.multiplier",
		    FT_INT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_body_CurrentDemandRes_EVSEMaximumPowerLimit_Unit,
		  { "Unit",
		    "v2gdin.body.currentdemandres.evsemaximumpowerlimit.unit",
		    FT_UINT32, BASE_DEC, VALS(v2gdin_unitsymbol_names),
		    0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_body_CurrentDemandRes_EVSEMaximumPowerLimit_Value,
		  { "Value",
		    "v2gdin.body.currentdemandres.evsemaximumpowerlimit.value",
		    FT_INT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
	};

	static gint *ett[] = {
		&ett_v2gdin,
		&ett_v2gdin_header,
		&ett_v2gdin_header_Notification,
		&ett_v2gdin_header_Signature,
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
		&ett_v2gdin_body_CurrentDemandReq,
		&ett_v2gdin_body_CurrentDemandReq_DC_EVStatus,
		&ett_v2gdin_body_CurrentDemandReq_EVTargetVoltage,
		&ett_v2gdin_body_CurrentDemandReq_EVTargetCurrent,
		&ett_v2gdin_body_CurrentDemandReq_EVMaximumVoltageLimit,
		&ett_v2gdin_body_CurrentDemandReq_EVMaximumCurrentLimit,
		&ett_v2gdin_body_CurrentDemandReq_EVMaximumPowerLimit,
		&ett_v2gdin_body_CurrentDemandReq_RemainingTimeToFullSoC,
		&ett_v2gdin_body_CurrentDemandReq_RemainingTimeToBulkSoC,
		&ett_v2gdin_body_CurrentDemandRes,
		&ett_v2gdin_body_CurrentDemandRes_DC_EVSEStatus,
		&ett_v2gdin_body_CurrentDemandRes_EVSEPresentVoltage,
		&ett_v2gdin_body_CurrentDemandRes_EVSEPresentCurrent,
		&ett_v2gdin_body_CurrentDemandRes_EVSEMaximumVoltageLimit,
		&ett_v2gdin_body_CurrentDemandRes_EVSEMaximumCurrentLimit,
		&ett_v2gdin_body_CurrentDemandRes_EVSEMaximumPowerLimit,
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
