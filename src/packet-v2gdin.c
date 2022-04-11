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

static int hf_v2gdin_struct_dinNotificationType_FaultCode = -1;
static int hf_v2gdin_struct_dinNotificationType_FaultMsg = -1;

static int hf_v2gdin_struct_dinSignatureType_Id = -1;
static int hf_v2gdin_struct_dinSignedInfoType_Id = -1;
static int hf_v2gdin_struct_dinSignatureValueType_Id = -1;
static int hf_v2gdin_struct_dinSignatureValueType_CONTENT = -1;

static int hf_v2gdin_struct_dinKeyInfoType_Id = -1;
static int hf_v2gdin_struct_dinKeyInfoType_KeyName = -1;
static int hf_v2gdin_struct_dinKeyInfoType_MgmtData = -1;
static int hf_v2gdin_struct_dinKeyInfoType_ANY = -1;
static int hf_v2gdin_struct_dinKeyValueType_ANY = -1;
static int hf_v2gdin_struct_dinDSAKeyValueType_P = -1;
static int hf_v2gdin_struct_dinDSAKeyValueType_Q = -1;
static int hf_v2gdin_struct_dinDSAKeyValueType_G = -1;
static int hf_v2gdin_struct_dinDSAKeyValueType_Y = -1;
static int hf_v2gdin_struct_dinDSAKeyValueType_J = -1;
static int hf_v2gdin_struct_dinDSAKeyValueType_Seed = -1;
static int hf_v2gdin_struct_dinDSAKeyValueType_PgenCounter = -1;
static int hf_v2gdin_struct_dinRSAKeyValueType_Modulus = -1;
static int hf_v2gdin_struct_dinRSAKeyValueType_Exponent = -1;

static int hf_v2gdin_struct_dinRetrievalMethodType_URI = -1;
static int hf_v2gdin_struct_dinRetrievalMethodType_Type = -1;

static int hf_v2gdin_struct_dinX509DataType_X509SKI = -1;
static int hf_v2gdin_struct_dinX509DataType_X509SubjectName = -1;
static int hf_v2gdin_struct_dinX509DataType_X509Certificate = -1;
static int hf_v2gdin_struct_dinX509DataType_X509CRL = -1;
static int hf_v2gdin_struct_dinX509DataType_ANY = -1;

static int hf_v2gdin_struct_dinX509IssuerSerialType_X509IssuerName = -1;
static int hf_v2gdin_struct_dinX509IssuerSerialType_X509SerialNumber = -1;

static int hf_v2gdin_struct_dinPGPDataType_PGPKeyID = -1;
static int hf_v2gdin_struct_dinPGPDataType_PGPKeyPacket = -1;
static int hf_v2gdin_struct_dinPGPDataType_ANY = -1;

static int hf_v2gdin_struct_dinSPKIDataType_SPKISexp = -1;
static int hf_v2gdin_struct_dinSPKIDataType_ANY = -1;

static int hf_v2gdin_struct_dinCanonicalizationMethodType_Algorithm = -1;
static int hf_v2gdin_struct_dinCanonicalizationMethodType_ANY = -1;

static int hf_v2gdin_struct_dinDigestMethodType_Algorithm = -1;
static int hf_v2gdin_struct_dinDigestMethodType_ANY = -1;

static int hf_v2gdin_struct_dinSignatureMethodType_Algorithm = -1;
static int hf_v2gdin_struct_dinSignatureMethodType_HMACOutputLength = -1;
static int hf_v2gdin_struct_dinSignatureMethodType_ANY = -1;

static int hf_v2gdin_struct_dinTransformType_Algorithm = -1;
static int hf_v2gdin_struct_dinTransformType_ANY = -1;
static int hf_v2gdin_struct_dinTransformType_XPath = -1;

static int hf_v2gdin_struct_dinReferenceType_Id = -1;
static int hf_v2gdin_struct_dinReferenceType_URI = -1;
static int hf_v2gdin_struct_dinReferenceType_Type = -1;
static int hf_v2gdin_struct_dinReferenceType_DigestValue = -1;

static int hf_v2gdin_struct_dinObjectType_Id = -1;
static int hf_v2gdin_struct_dinObjectType_MimeType = -1;
static int hf_v2gdin_struct_dinObjectType_Encoding = -1;
static int hf_v2gdin_struct_dinObjectType_ANY = -1;

static int hf_v2gdin_struct_dinServiceTagType_ServiceID = -1;
static int hf_v2gdin_struct_dinServiceTagType_ServiceName = -1;
static int hf_v2gdin_struct_dinServiceTagType_ServiceCategory = -1;
static int hf_v2gdin_struct_dinServiceTagType_ServiceScope = -1;

static int hf_v2gdin_struct_dinServiceChargeType_FreeService = -1;
static int hf_v2gdin_struct_dinServiceChargeType_EnergyTransferType = -1;

static int hf_v2gdin_struct_dinServiceType_FreeService = -1;

static int hf_v2gdin_struct_dinSelectedServiceType_ServiceID = -1;
static int hf_v2gdin_struct_dinSelectedServiceType_ParameterSetID = -1;

static int hf_v2gdin_struct_dinParameterSetType_ParameterSetID = -1;

static int hf_v2gdin_struct_dinParameterType_Name = -1;
static int hf_v2gdin_struct_dinParameterType_ValueType = -1;
static int hf_v2gdin_struct_dinParameterType_boolValue = -1;
static int hf_v2gdin_struct_dinParameterType_byteValue = -1;
static int hf_v2gdin_struct_dinParameterType_shortValue = -1;
static int hf_v2gdin_struct_dinParameterType_intValue = -1;
static int hf_v2gdin_struct_dinParameterType_stringValue = -1;

static int hf_v2gdin_struct_dinPaymentOptionsType_PaymentOption = -1;

static int hf_v2gdin_struct_dinPhysicalValueType_Multiplier = -1;
static int hf_v2gdin_struct_dinPhysicalValueType_Unit = -1;
static int hf_v2gdin_struct_dinPhysicalValueType_Value = -1;

static int hf_v2gdin_struct_dinCertificateChainType_Certificate = -1;
static int hf_v2gdin_struct_dinSubCertificatesType_Certificate = -1;

static int hf_v2gdin_struct_dinDC_EVStatusType_EVReady = -1;
static int hf_v2gdin_struct_dinDC_EVStatusType_EVCabinConditioning = -1;
static int hf_v2gdin_struct_dinDC_EVStatusType_EVRESSConditioning = -1;
static int hf_v2gdin_struct_dinDC_EVStatusType_EVErrorCode = -1;
static int hf_v2gdin_struct_dinDC_EVStatusType_EVRESSSOC = -1;

static int hf_v2gdin_struct_dinDC_EVSEStatusType_EVSEIsolationStatus = -1;
static int hf_v2gdin_struct_dinDC_EVSEStatusType_EVSEStatusCode = -1;
static int hf_v2gdin_struct_dinDC_EVSEStatusType_NotificationMaxDelay = -1;
static int hf_v2gdin_struct_dinDC_EVSEStatusType_EVSENotification = -1;

static int hf_v2gdin_header_SessionID = -1;

static int hf_v2gdin_body_SessionSetupReq_EVCCID = -1;
static int hf_v2gdin_body_SessionSetupRes_ResponseCode = -1;
static int hf_v2gdin_body_SessionSetupRes_EVSEID = -1;
static int hf_v2gdin_body_SessionSetupRes_DateTimeNow = -1;
static int hf_v2gdin_body_ServiceDiscoveryReq_ServiceScope = -1;
static int hf_v2gdin_body_ServiceDiscoveryReq_ServiceCategory = -1;
static int hf_v2gdin_body_ServiceDiscoveryRes_ResponseCode = -1;
static int hf_v2gdin_body_ServiceDetailReq_ServiceID = -1;
static int hf_v2gdin_body_ServiceDetailRes_ResponseCode = -1;
static int hf_v2gdin_body_ServiceDetailRes_ServiceID = -1;
static int hf_v2gdin_body_ServicePaymentSelectionReq_SelectedPaymentOption = -1;
static int hf_v2gdin_body_ServicePaymentSelectionRes_ResponseCode = -1;
static int hf_v2gdin_body_PaymentDetailsReq_ContractID = -1;
static int hf_v2gdin_body_PaymentDetailsRes_ResponseCode = -1;
static int hf_v2gdin_body_PaymentDetailsRes_GenChallenge = -1;
static int hf_v2gdin_body_PaymentDetailsRes_DateTimeNow = -1;
static int hf_v2gdin_body_ContractAuthenticationReq_Id = -1;
static int hf_v2gdin_body_ContractAuthenticationReq_GenChallenge = -1;
static int hf_v2gdin_body_ContractAuthenticationRes_ResponseCode = -1;
static int hf_v2gdin_body_ContractAuthenticationRes_EVSEProcessing = -1;
static int hf_v2gdin_body_CurrentDemandReq_ChargingComplete = -1;
static int hf_v2gdin_body_CurrentDemandReq_BulkChargingComplete = -1;
static int hf_v2gdin_body_CurrentDemandRes_ResponseCode = -1;
static int hf_v2gdin_body_CurrentDemandRes_EVSECurrentLimitAchieved = -1;
static int hf_v2gdin_body_CurrentDemandRes_EVSEVoltageLimitAchieved = -1;
static int hf_v2gdin_body_CurrentDemandRes_EVSEPowerLimitAchieved = -1;

/* Initialize the subtree pointers */
static gint ett_v2gdin = -1;
static gint ett_v2gdin_array = -1;
static gint ett_v2gdin_array_i = -1;

static gint ett_v2gdin_struct_dinNotificationType = -1;
static gint ett_v2gdin_struct_dinSignatureType = -1;
static gint ett_v2gdin_struct_dinSignedInfoType = -1;
static gint ett_v2gdin_struct_dinCanonicalizationMethodType = -1;
static gint ett_v2gdin_struct_dinDigestMethodType = -1;
static gint ett_v2gdin_struct_dinSignatureMethodType = -1;
static gint ett_v2gdin_struct_dinReferenceType = -1;
static gint ett_v2gdin_struct_dinTransformsType = -1;
static gint ett_v2gdin_struct_dinTransformType = -1;
static gint ett_v2gdin_struct_dinSignatureValueType = -1;
static gint ett_v2gdin_struct_dinKeyInfoType = -1;
static gint ett_v2gdin_struct_dinKeyValueType = -1;
static gint ett_v2gdin_struct_dinDSAKeyValueType = -1;
static gint ett_v2gdin_struct_dinRSAKeyValueType = -1;
static gint ett_v2gdin_struct_dinRetrievalMethodType = -1;
static gint ett_v2gdin_struct_dinX509IssuerSerialType = -1;
static gint ett_v2gdin_struct_dinX509DataType = -1;
static gint ett_v2gdin_struct_dinPGPDataType = -1;
static gint ett_v2gdin_struct_dinSPKIDataType = -1;
static gint ett_v2gdin_struct_dinObjectType = -1;
static gint ett_v2gdin_struct_dinServiceParameterListType = -1;
static gint ett_v2gdin_struct_dinServiceTagListType = -1;
static gint ett_v2gdin_struct_dinServiceTagType = -1;
static gint ett_v2gdin_struct_dinServiceChargeType = -1;
static gint ett_v2gdin_struct_dinServiceType = -1;
static gint ett_v2gdin_struct_dinSelectedServiceType = -1;
static gint ett_v2gdin_struct_dinSelectedServiceListType = -1;
static gint ett_v2gdin_struct_dinParameterSetType = -1;
static gint ett_v2gdin_struct_dinParameterType = -1;
static gint ett_v2gdin_struct_dinPhysicalValueType = -1;
static gint ett_v2gdin_struct_dinPaymentOptionsType = -1;
static gint ett_v2gdin_struct_dinCertificateChainType = -1;
static gint ett_v2gdin_struct_dinSubCertificatesType = -1;
static gint ett_v2gdin_struct_dinDC_EVStatusType = -1;
static gint ett_v2gdin_struct_dinDC_EVSEStatusType = -1;

static gint ett_v2gdin_header = -1;
static gint ett_v2gdin_body = -1;
static gint ett_v2gdin_body_SessionSetupReq = -1;
static gint ett_v2gdin_body_SessionSetupRes = -1;
static gint ett_v2gdin_body_ServiceDiscoveryReq = -1;
static gint ett_v2gdin_body_ServiceDiscoveryRes = -1;
static gint ett_v2gdin_body_ServiceDetailReq = -1;
static gint ett_v2gdin_body_ServiceDetailRes = -1;
static gint ett_v2gdin_body_ServicePaymentSelectionReq = -1;
static gint ett_v2gdin_body_ServicePaymentSelectionRes = -1;
static gint ett_v2gdin_body_PaymentDetailsReq = -1;
static gint ett_v2gdin_body_PaymentDetailsRes = -1;
static gint ett_v2gdin_body_ContractAuthenticationReq = -1;
static gint ett_v2gdin_body_ContractAuthenticationRes = -1;
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
static gint ett_v2gdin_body_CurrentDemandRes = -1;
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

static const value_string v2gdin_service_category_names[] = {
	{ dinserviceCategoryType_EVCharging, "EVCharging" },
	{ dinserviceCategoryType_Internet, "Internet" },
	{ dinserviceCategoryType_ContractCertificate, "ContractCertificate" },
	{ dinserviceCategoryType_OtherCustom, "OtherCustom" }
};

static const value_string v2gdin_payment_option_names[] = {
	{ dinpaymentOptionType_Contract, "Contract" },
	{ dinpaymentOptionType_ExternalPayment, "ExternalPayment" }
};

static const value_string v2gdin_energy_transfer_type_names[] = {
	{ dinEVSESupportedEnergyTransferType_AC_single_phase_core,
	  "AC_single_phase_core" },
	{ dinEVSESupportedEnergyTransferType_AC_three_phase_core,
	  "AC_three_phase_core" },
	{ dinEVSESupportedEnergyTransferType_DC_core,
	  "DC_core" },
	{ dinEVSESupportedEnergyTransferType_DC_extended,
	  "DC_extended" },
	{ dinEVSESupportedEnergyTransferType_DC_combo_core,
	  "DC_combo_core" },
	{ dinEVSESupportedEnergyTransferType_DC_dual,
	  "DC_dual" },
	{ dinEVSESupportedEnergyTransferType_AC_core1p_DC_extended,
	  "AC_core1p_DC_extended" },
	{ dinEVSESupportedEnergyTransferType_AC_single_DC_core,
	  "AC_single_DC_core" },
	{ dinEVSESupportedEnergyTransferType_AC_single_phase_three_phase_core_DC_extended,
	  "AC_single_phase_three_phase_core_DC_extended" },
	{ dinEVSESupportedEnergyTransferType_AC_core3p_DC_extended,
	  "AC_core3p_DC_extended" }
};

static const value_string v2gdin_isolation_level_names[] = {
	{ dinisolationLevelType_Invalid, "Invalid" },
	{ dinisolationLevelType_Valid, "Valid" },
	{ dinisolationLevelType_Warning, "Warning" },
	{ dinisolationLevelType_Fault, "Fault" }
};

static const value_string v2gdin_evse_processing_names[] = {
	{ dinEVSEProcessingType_Finished, "Finished" },
	{ dinEVSEProcessingType_Ongoing, "Ongoing" }
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


/*
 * Decode the exi string character (int) into a c string
 */
static inline void
exi_add_characters(proto_tree *tree,
		   int hfindex,
		   tvbuff_t *tvb,
		   const exi_string_character_t *characters,
		   unsigned int characterslen,
		   size_t charactersmaxsize)
{
	unsigned int i;
	char *str;
	proto_item *it;

	if (characterslen > charactersmaxsize) {
		proto_tree_add_debug_text(tree,
					  "characterslen %u > maxsize %zu",
					  characterslen, charactersmaxsize);
		return;
	}

	str = alloca(characterslen + 1);
	if (str == NULL) {
		return;
	}

	for (i = 0; i < characterslen; i++) {
		str[i] = characters[i];
	}
	str[i] = '\0';

	/*
	 * internally the proto string is a g_strdup - so, it's ok
	 * to use the alloca stack reference from above
	 */
	it = proto_tree_add_string(tree, hfindex, tvb, 0, 0, str);
	proto_item_set_generated(it);

	return;
}

/*
 * Decode the exi bytes into a c string
 */
static inline void
exi_add_bytes(proto_tree *tree,
	      int hfindex,
	      tvbuff_t *tvb,
	      const uint8_t *bytes,
	      unsigned int byteslen,
	      size_t bytesmaxsize)
{
	unsigned int i;
	char *str;
	proto_item *it;

	if (byteslen > bytesmaxsize) {
		proto_tree_add_debug_text(tree, "byteslen %u > maxsize %zu",
					  byteslen, bytesmaxsize);
		return;
	}

	str = alloca(2*byteslen + 1);
	if (str == NULL) {
		return;
	}

	for (i = 0; i < byteslen; i++) {
		snprintf(&str[2*i], bytesmaxsize - 2*i, "%02X", bytes[i]);
	}
	str[2*i] = '\0';

	/*
	 * internally the proto string is a g_strdup - so, it's ok
	 * to use the alloca stack reference from above
	 */
	it = proto_tree_add_string(tree, hfindex, tvb, 0, 0, str);
	proto_item_set_generated(it);

	return;
}


static void
dissect_v2gdin_notification(const struct dinNotificationType *notification,
			    tvbuff_t *tvb,
			    proto_tree *tree,
			    gint idx,
			    const char *subtree_name)
{
	proto_tree *subtree;
	proto_item *it;

	subtree = proto_tree_add_subtree(tree,
		tvb, 0, 0, idx, NULL, subtree_name);

	it = proto_tree_add_uint(subtree,
		hf_v2gdin_struct_dinNotificationType_FaultCode,
		tvb, 0, 0, notification->FaultCode);
	proto_item_set_generated(it);

	if (notification->FaultMsg_isUsed) {
		exi_add_characters(subtree,
			hf_v2gdin_struct_dinNotificationType_FaultMsg,
			tvb,
			notification->FaultMsg.characters,
			notification->FaultMsg.charactersLen,
			sizeof(notification->FaultMsg.characters));
	}

	return;
}

static void
dissect_v2gdin_object(const struct dinObjectType *object,
		      tvbuff_t *tvb,
		      proto_tree *tree,
		      gint idx,
		      const char *subtree_name)
{
	proto_tree *subtree;

	subtree = proto_tree_add_subtree(tree,
		tvb, 0, 0, idx, NULL, subtree_name);

	if (object->Id_isUsed) {
		exi_add_characters(subtree,
			hf_v2gdin_struct_dinObjectType_Id,
			tvb,
			object->Id.characters,
			object->Id.charactersLen,
			sizeof(object->Id.characters));
	}
	if (object->MimeType_isUsed) {
		exi_add_characters(subtree,
			hf_v2gdin_struct_dinObjectType_MimeType,
			tvb,
			object->MimeType.characters,
			object->MimeType.charactersLen,
			sizeof(object->MimeType.characters));
	}
	if (object->Encoding_isUsed) {
		exi_add_characters(subtree,
			hf_v2gdin_struct_dinObjectType_Encoding,
			tvb,
			object->Encoding.characters,
			object->Encoding.charactersLen,
			sizeof(object->Encoding.characters));
	}
	if (object->ANY_isUsed) {
		exi_add_characters(subtree,
			hf_v2gdin_struct_dinObjectType_ANY,
			tvb,
			object->ANY.characters,
			object->ANY.charactersLen,
			sizeof(object->ANY.characters));
	}

	return;
}

static void
dissect_v2gdin_transform(const struct dinTransformType *transform,
			 tvbuff_t *tvb,
			 proto_tree *tree,
			 gint idx,
			 const char *subtree_name)
{
	unsigned int i;
	proto_tree *subtree;
	proto_tree *xpath_tree;
	proto_tree *xpath_i_tree;

	subtree = proto_tree_add_subtree(tree,
		tvb, 0, 0, idx, NULL, subtree_name);

	exi_add_characters(subtree,
		hf_v2gdin_struct_dinTransformType_Algorithm,
		tvb,
		transform->Algorithm.characters,
		transform->Algorithm.charactersLen,
		sizeof(transform->Algorithm.characters));

	if (transform->ANY_isUsed) {
		exi_add_characters(subtree,
			hf_v2gdin_struct_dinTransformType_ANY,
			tvb,
			transform->ANY.characters,
			transform->ANY.charactersLen,
			sizeof(transform->ANY.characters));
	}

	xpath_tree = proto_tree_add_subtree(subtree,
		tvb, 0, 0, ett_v2gdin_array, NULL, "XPath");
	for (i = 0; i < transform->XPath.arrayLen; i++) {
		xpath_i_tree = proto_tree_add_subtree_format(xpath_tree,
			tvb, 0, 0, ett_v2gdin_array_i, NULL, "[%u]", i);
		exi_add_characters(xpath_i_tree,
			hf_v2gdin_struct_dinTransformType_XPath,
			tvb,
			transform->XPath.array[i].characters,
			transform->XPath.array[i].charactersLen,
			sizeof(transform->XPath.array[i].characters));
	}

	return;
}

static void
dissect_v2gdin_transforms(const struct dinTransformsType *transforms,
			  tvbuff_t *tvb,
			  proto_tree *tree,
			  gint idx,
			  const char *subtree_name)
{
	unsigned int i;
	proto_tree *subtree;
	proto_tree *transform_tree;

	subtree = proto_tree_add_subtree(tree,
		tvb, 0, 0, idx, NULL, subtree_name);

	transform_tree = proto_tree_add_subtree(subtree,
		tvb, 0, 0, ett_v2gdin_array, NULL, "Transform");
	for (i = 0; i < transforms->Transform.arrayLen; i++) {
		char index[sizeof("[65536]")];

		snprintf(index, sizeof(index), "[%u]", i);
		dissect_v2gdin_transform(&transforms->Transform.array[i], tvb,
			transform_tree, ett_v2gdin_struct_dinTransformType,
			index);
	}

	return;
}

static void
dissect_v2gdin_digestmethod(const struct dinDigestMethodType *digestmethod,
			    tvbuff_t *tvb,
			    proto_tree *tree,
			    gint idx,
			    const char *subtree_name)
{
	proto_tree *subtree;

	subtree = proto_tree_add_subtree(tree,
		tvb, 0, 0, idx, NULL, subtree_name);

	exi_add_characters(subtree,
		hf_v2gdin_struct_dinDigestMethodType_Algorithm,
		tvb,
		digestmethod->Algorithm.characters,
		digestmethod->Algorithm.charactersLen,
		sizeof(digestmethod->Algorithm.characters));

	if (digestmethod->ANY_isUsed) {
		exi_add_characters(subtree,
			hf_v2gdin_struct_dinDigestMethodType_ANY,
			tvb,
			digestmethod->ANY.characters,
			digestmethod->ANY.charactersLen,
			sizeof(digestmethod->ANY.characters));
	}

	return;
}

static void
dissect_v2gdin_reference(const struct dinReferenceType *reference,
			 tvbuff_t *tvb,
			 proto_tree *tree,
			 gint idx,
			 const char *subtree_name)
{
	proto_tree *subtree;

	subtree = proto_tree_add_subtree(tree,
		tvb, 0, 0, idx, NULL, subtree_name);

	if (reference->Id_isUsed) {
		exi_add_characters(subtree,
			hf_v2gdin_struct_dinReferenceType_Id,
			tvb,
			reference->Id.characters,
			reference->Id.charactersLen,
			sizeof(reference->Id.characters));
	}
	if (reference->URI_isUsed) {
		exi_add_characters(subtree,
			hf_v2gdin_struct_dinReferenceType_URI,
			tvb,
			reference->URI.characters,
			reference->URI.charactersLen,
			sizeof(reference->URI.characters));
	}
	if (reference->Type_isUsed) {
		exi_add_characters(subtree,
			hf_v2gdin_struct_dinReferenceType_Type,
			tvb,
			reference->Type.characters,
			reference->Type.charactersLen,
			sizeof(reference->Type.characters));
	}
	if (reference->Transforms_isUsed) {
		dissect_v2gdin_transforms(&reference->Transforms,
			tvb, subtree, ett_v2gdin_struct_dinTransformsType,
			"Transforms");
	}

	dissect_v2gdin_digestmethod(&reference->DigestMethod,
			tvb, subtree, ett_v2gdin_struct_dinDigestMethodType,
			"DigestMethod");

	exi_add_bytes(subtree,
		hf_v2gdin_struct_dinReferenceType_DigestValue,
		tvb,
		reference->DigestValue.bytes,
		reference->DigestValue.bytesLen,
		sizeof(reference->DigestValue.bytes));

	return;
}

static void
dissect_v2gdin_canonicalizationmethod(
	const struct dinCanonicalizationMethodType *canonicalizationmethod,
	tvbuff_t *tvb,
	proto_tree *tree,
	gint idx,
	const char *subtree_name)
{
	proto_tree *subtree;

	subtree = proto_tree_add_subtree(tree,
		tvb, 0, 0, idx, NULL, subtree_name);

	exi_add_characters(subtree,
		hf_v2gdin_struct_dinCanonicalizationMethodType_Algorithm,
		tvb,
		canonicalizationmethod->Algorithm.characters,
		canonicalizationmethod->Algorithm.charactersLen,
		sizeof(canonicalizationmethod->Algorithm.characters));

	if (canonicalizationmethod->ANY_isUsed) {
		exi_add_characters(subtree,
			hf_v2gdin_struct_dinCanonicalizationMethodType_ANY,
			tvb,
			canonicalizationmethod->ANY.characters,
			canonicalizationmethod->ANY.charactersLen,
			sizeof(canonicalizationmethod->ANY.characters));
	}

	return;
}

static void
dissect_v2gdin_signaturemethod(
	const struct dinSignatureMethodType *signaturemethod,
	tvbuff_t *tvb,
	proto_tree *tree,
	gint idx,
	const char *subtree_name)
{
	proto_tree *subtree;
	proto_item *it;

	subtree = proto_tree_add_subtree(tree,
		tvb, 0, 0, idx, NULL, subtree_name);

	exi_add_characters(subtree,
		hf_v2gdin_struct_dinSignatureMethodType_Algorithm,
		tvb,
		signaturemethod->Algorithm.characters,
		signaturemethod->Algorithm.charactersLen,
		sizeof(signaturemethod->Algorithm.characters));

	if (signaturemethod->HMACOutputLength_isUsed) {
		it = proto_tree_add_int64(subtree,
			hf_v2gdin_struct_dinSignatureMethodType_HMACOutputLength,
			tvb, 0, 0, signaturemethod->HMACOutputLength);
		proto_item_set_generated(it);
	}

	if (signaturemethod->ANY_isUsed) {
		exi_add_characters(subtree,
			hf_v2gdin_struct_dinSignatureMethodType_ANY,
			tvb,
			signaturemethod->ANY.characters,
			signaturemethod->ANY.charactersLen,
			sizeof(signaturemethod->ANY.characters));
	}

	return;
}

static void
dissect_v2gdin_signaturevalue(
	const struct dinSignatureValueType *signaturevalue,
	tvbuff_t *tvb,
	proto_tree *tree,
	gint idx,
	const char *subtree_name)
{
	proto_tree *subtree;

	subtree = proto_tree_add_subtree(tree,
		tvb, 0, 0, idx, NULL, subtree_name);

	if (signaturevalue->Id_isUsed) {
		exi_add_characters(subtree,
			hf_v2gdin_struct_dinSignatureValueType_Id,
			tvb,
			signaturevalue->Id.characters,
			signaturevalue->Id.charactersLen,
			sizeof(signaturevalue->Id.characters));
	}

	exi_add_bytes(subtree,
		hf_v2gdin_struct_dinSignatureValueType_CONTENT,
		tvb,
		signaturevalue->CONTENT.bytes,
		signaturevalue->CONTENT.bytesLen,
		sizeof(signaturevalue->CONTENT.bytes));

	return;
}

static void
dissect_v2gdin_signedinfo(const struct dinSignedInfoType *signedinfo,
			  tvbuff_t *tvb,
			  proto_tree *tree,
			  gint idx,
			  const char *subtree_name)
{
	unsigned int i;
	proto_tree *subtree;
	proto_tree *reference_tree;

	subtree = proto_tree_add_subtree(tree,
		tvb, 0, 0, idx, NULL, subtree_name);

	if (signedinfo->Id_isUsed) {
		exi_add_characters(subtree,
			hf_v2gdin_struct_dinSignedInfoType_Id,
			tvb,
			signedinfo->Id.characters,
			signedinfo->Id.charactersLen,
			sizeof(signedinfo->Id.characters));
	}

	dissect_v2gdin_canonicalizationmethod(
		&signedinfo->CanonicalizationMethod, tvb, subtree,
		ett_v2gdin_struct_dinCanonicalizationMethodType,
		"CanonicalizationMethod");
	dissect_v2gdin_signaturemethod(
		&signedinfo->SignatureMethod, tvb, subtree,
		ett_v2gdin_struct_dinSignatureMethodType,
		"SignatureMethod");

	reference_tree = proto_tree_add_subtree(subtree,
		tvb, 0, 0, ett_v2gdin_array, NULL, "Reference");
	for (i = 0; i < signedinfo->Reference.arrayLen; i++) {
		char index[sizeof("[65536]")];

		snprintf(index, sizeof(index), "[%u]", i);
		dissect_v2gdin_reference(&signedinfo->Reference.array[i], tvb,
			reference_tree, ett_v2gdin_struct_dinReferenceType,
			index);
	}

	return;
}

static void
dissect_v2gdin_dsakeyvalue(const struct dinDSAKeyValueType *dsakeyvalue,
			   tvbuff_t *tvb,
			   proto_tree *tree,
			   gint idx,
			   const char *subtree_name)
{
	proto_tree *subtree;

	subtree = proto_tree_add_subtree(tree,
		tvb, 0, 0, idx, NULL, subtree_name);

	if (dsakeyvalue->P_isUsed) {
		exi_add_bytes(subtree,
			hf_v2gdin_struct_dinDSAKeyValueType_P,
			tvb,
			dsakeyvalue->P.bytes,
			dsakeyvalue->P.bytesLen,
			sizeof(dsakeyvalue->P.bytes));
	}
	if (dsakeyvalue->Q_isUsed) {
		exi_add_bytes(subtree,
			hf_v2gdin_struct_dinDSAKeyValueType_Q,
			tvb,
			dsakeyvalue->Q.bytes,
			dsakeyvalue->Q.bytesLen,
			sizeof(dsakeyvalue->Q.bytes));
	}
	if (dsakeyvalue->G_isUsed) {
		exi_add_bytes(subtree,
			hf_v2gdin_struct_dinDSAKeyValueType_G,
			tvb,
			dsakeyvalue->G.bytes,
			dsakeyvalue->G.bytesLen,
			sizeof(dsakeyvalue->G.bytes));
	}
	exi_add_bytes(subtree,
		hf_v2gdin_struct_dinDSAKeyValueType_Y,
		tvb,
		dsakeyvalue->Y.bytes,
		dsakeyvalue->Y.bytesLen,
		sizeof(dsakeyvalue->Y.bytes));
	if (dsakeyvalue->J_isUsed) {
		exi_add_bytes(subtree,
			hf_v2gdin_struct_dinDSAKeyValueType_J,
			tvb,
			dsakeyvalue->J.bytes,
			dsakeyvalue->J.bytesLen,
			sizeof(dsakeyvalue->J.bytes));
	}
	if (dsakeyvalue->Seed_isUsed) {
		exi_add_bytes(subtree,
			hf_v2gdin_struct_dinDSAKeyValueType_Seed,
			tvb,
			dsakeyvalue->Seed.bytes,
			dsakeyvalue->Seed.bytesLen,
			sizeof(dsakeyvalue->Seed.bytes));
	}
	if (dsakeyvalue->PgenCounter_isUsed) {
		exi_add_bytes(subtree,
			hf_v2gdin_struct_dinDSAKeyValueType_PgenCounter,
			tvb,
			dsakeyvalue->PgenCounter.bytes,
			dsakeyvalue->PgenCounter.bytesLen,
			sizeof(dsakeyvalue->PgenCounter.bytes));
	}

	return;
}

static void
dissect_v2gdin_rsakeyvalue(const struct dinRSAKeyValueType *rsakeyvalue,
			   tvbuff_t *tvb,
			   proto_tree *tree,
			   gint idx,
			   const char *subtree_name)
{
	proto_tree *subtree;

	subtree = proto_tree_add_subtree(tree,
		tvb, 0, 0, idx, NULL, subtree_name);

	exi_add_bytes(subtree,
		hf_v2gdin_struct_dinRSAKeyValueType_Modulus,
		tvb,
		rsakeyvalue->Modulus.bytes,
		rsakeyvalue->Modulus.bytesLen,
		sizeof(rsakeyvalue->Modulus.bytes));

	exi_add_bytes(subtree,
		hf_v2gdin_struct_dinRSAKeyValueType_Exponent,
		tvb,
		rsakeyvalue->Exponent.bytes,
		rsakeyvalue->Exponent.bytesLen,
		sizeof(rsakeyvalue->Exponent.bytes));

	return;
}

static void
dissect_v2gdin_keyvalue(const struct dinKeyValueType *keyvalue,
			tvbuff_t *tvb,
			proto_tree *tree,
			gint idx,
			const char *subtree_name)
{
	proto_tree *subtree;

	subtree = proto_tree_add_subtree(tree,
		tvb, 0, 0, idx, NULL, subtree_name);

	if (keyvalue->DSAKeyValue_isUsed) {
		dissect_v2gdin_dsakeyvalue(&keyvalue->DSAKeyValue,
			tvb, subtree, ett_v2gdin_struct_dinDSAKeyValueType,
			"DSAKeyValue");
	}
	if (keyvalue->RSAKeyValue_isUsed) {
		dissect_v2gdin_rsakeyvalue(&keyvalue->RSAKeyValue,
			tvb, subtree, ett_v2gdin_struct_dinRSAKeyValueType,
			"RSAKeyValue");
	}

	exi_add_characters(subtree,
		hf_v2gdin_struct_dinKeyValueType_ANY,
		tvb,
		keyvalue->ANY.characters,
		keyvalue->ANY.charactersLen,
		sizeof(keyvalue->ANY.characters));

	return;
}

static void
dissect_v2gdin_retrievalmethod(
	const struct dinRetrievalMethodType *retrievalmethod,
	tvbuff_t *tvb,
	proto_tree *tree,
	gint idx,
	const char *subtree_name)
{
	proto_tree *subtree;

	subtree = proto_tree_add_subtree(tree,
		tvb, 0, 0, idx, NULL, subtree_name);

	if (retrievalmethod->URI_isUsed) {
		exi_add_characters(subtree,
			hf_v2gdin_struct_dinRetrievalMethodType_URI,
			tvb,
			retrievalmethod->URI.characters,
			retrievalmethod->URI.charactersLen,
			sizeof(retrievalmethod->URI.characters));
	}
	if (retrievalmethod->Type_isUsed) {
		exi_add_characters(subtree,
			hf_v2gdin_struct_dinRetrievalMethodType_Type,
			tvb,
			retrievalmethod->Type.characters,
			retrievalmethod->Type.charactersLen,
			sizeof(retrievalmethod->Type.characters));
	}
	if (retrievalmethod->Transforms_isUsed) {
		dissect_v2gdin_transforms(&retrievalmethod->Transforms,
			tvb, subtree, ett_v2gdin_struct_dinTransformsType,
			"Transforms");
	}

	return;
}

static void
dissect_v2gdin_x509issuerserial(
	const struct dinX509IssuerSerialType *x509issuerserial,
	tvbuff_t *tvb,
	proto_tree *tree,
	gint idx,
	const char *subtree_name)
{
	proto_tree *subtree;
	proto_item *it;

	subtree = proto_tree_add_subtree(tree,
		tvb, 0, 0, idx, NULL, subtree_name);

	exi_add_characters(subtree,
		hf_v2gdin_struct_dinX509IssuerSerialType_X509IssuerName,
		tvb,
		x509issuerserial->X509IssuerName.characters,
		x509issuerserial->X509IssuerName.charactersLen,
		sizeof(x509issuerserial->X509IssuerName.characters));

	it = proto_tree_add_int64(subtree,
		hf_v2gdin_struct_dinX509IssuerSerialType_X509SerialNumber,
		tvb, 0, 0, x509issuerserial->X509SerialNumber);
	proto_item_set_generated(it);

	return;
}

static void
dissect_v2gdin_x509data(const struct dinX509DataType *x509data,
			tvbuff_t *tvb,
			proto_tree *tree,
			gint idx,
			const char *subtree_name)
{
	unsigned int i;
	proto_tree *subtree;
	proto_tree *x509issuerserial_tree;
	proto_tree *x509ski_tree;
	proto_tree *x509ski_i_tree;
	proto_tree *x509subjectname_tree;
	proto_tree *x509subjectname_i_tree;
	proto_tree *x509certificate_tree;
	proto_tree *x509certificate_i_tree;
	proto_tree *x509crl_tree;
	proto_tree *x509crl_i_tree;

	subtree = proto_tree_add_subtree(tree,
		tvb, 0, 0, idx, NULL, subtree_name);

	x509issuerserial_tree = proto_tree_add_subtree(subtree,
		tvb, 0, 0, ett_v2gdin_array, NULL, "X509IssuerSerial");
	for (i = 0; i < x509data->X509IssuerSerial.arrayLen; i++) {
		char index[sizeof("[65536]")];

		snprintf(index, sizeof(index), "[%u]", i);
		dissect_v2gdin_x509issuerserial(
			&x509data->X509IssuerSerial.array[i],
			tvb, x509issuerserial_tree,
			ett_v2gdin_struct_dinX509IssuerSerialType, index);
	}

	x509ski_tree = proto_tree_add_subtree(subtree,
		tvb, 0, 0, ett_v2gdin_array, NULL, "X509SKI");
	for (i = 0; i < x509data->X509SKI.arrayLen; i++) {
		x509ski_i_tree = proto_tree_add_subtree_format(x509ski_tree,
			tvb, 0, 0, ett_v2gdin_array_i, NULL, "[%u]", i);
		exi_add_bytes(x509ski_i_tree,
			hf_v2gdin_struct_dinX509DataType_X509SKI,
			tvb,
			x509data->X509SKI.array[i].bytes,
			x509data->X509SKI.array[i].bytesLen,
			sizeof(x509data->X509SKI.array[i].bytes));
	}

	x509subjectname_tree = proto_tree_add_subtree(subtree,
		tvb, 0, 0, ett_v2gdin_array, NULL, "X509SKI");
	for (i = 0; i < x509data->X509SubjectName.arrayLen; i++) {
		x509subjectname_i_tree = proto_tree_add_subtree_format(
			x509subjectname_tree,
			tvb, 0, 0, ett_v2gdin_array_i, NULL, "[%u]", i);
		exi_add_characters(x509subjectname_i_tree,
			hf_v2gdin_struct_dinX509DataType_X509SubjectName,
			tvb,
			x509data->X509SubjectName.array[i].characters,
			x509data->X509SubjectName.array[i].charactersLen,
			sizeof(x509data->X509SubjectName.array[i].characters));
	}

	x509certificate_tree = proto_tree_add_subtree(subtree,
		tvb, 0, 0, ett_v2gdin_array, NULL, "X509SKI");
	for (i = 0; i < x509data->X509Certificate.arrayLen; i++) {
		x509certificate_i_tree = proto_tree_add_subtree_format(
			x509certificate_tree,
			tvb, 0, 0, ett_v2gdin_array_i, NULL, "[%u]", i);
		exi_add_bytes(x509certificate_i_tree,
			hf_v2gdin_struct_dinX509DataType_X509Certificate,
			tvb,
			x509data->X509Certificate.array[i].bytes,
			x509data->X509Certificate.array[i].bytesLen,
			sizeof(x509data->X509Certificate.array[i].bytes));
	}

	x509crl_tree = proto_tree_add_subtree(subtree,
		tvb, 0, 0, ett_v2gdin_array, NULL, "X509CRL");
	for (i = 0; i < x509data->X509CRL.arrayLen; i++) {
		x509crl_i_tree = proto_tree_add_subtree_format(x509crl_tree,
			tvb, 0, 0, ett_v2gdin_array_i, NULL, "[%u]", i);
		exi_add_bytes(x509crl_i_tree,
			hf_v2gdin_struct_dinX509DataType_X509CRL,
			tvb,
			x509data->X509CRL.array[i].bytes,
			x509data->X509CRL.array[i].bytesLen,
			sizeof(x509data->X509CRL.array[i].bytes));
	}

	if (x509data->ANY_isUsed) {
		exi_add_characters(subtree,
			hf_v2gdin_struct_dinX509DataType_ANY,
			tvb,
			x509data->ANY.characters,
			x509data->ANY.charactersLen,
			sizeof(x509data->ANY.characters));
	}

	return;
}

static void
dissect_v2gdin_pgpdata(const struct dinPGPDataType *pgpdata,
		       tvbuff_t *tvb,
		       proto_tree *tree,
		       gint idx,
		       const char *subtree_name)
{
	proto_tree *subtree;

	subtree = proto_tree_add_subtree(tree,
		tvb, 0, 0, idx, NULL, subtree_name);

	if (pgpdata->PGPKeyID_isUsed) {
		exi_add_bytes(subtree,
			hf_v2gdin_struct_dinPGPDataType_PGPKeyID,
			tvb,
			pgpdata->PGPKeyID.bytes,
			pgpdata->PGPKeyID.bytesLen,
			sizeof(pgpdata->PGPKeyID.bytes));
	}

	if (pgpdata->PGPKeyPacket_isUsed) {
		exi_add_bytes(subtree,
			hf_v2gdin_struct_dinPGPDataType_PGPKeyPacket,
			tvb,
			pgpdata->PGPKeyPacket.bytes,
			pgpdata->PGPKeyPacket.bytesLen,
			sizeof(pgpdata->PGPKeyPacket.bytes));
	}

	if (pgpdata->ANY_isUsed) {
		exi_add_characters(subtree,
			hf_v2gdin_struct_dinPGPDataType_ANY,
			tvb,
			pgpdata->ANY.characters,
			pgpdata->ANY.charactersLen,
			sizeof(pgpdata->ANY.characters));
	}

	return;
}

static void
dissect_v2gdin_spkidata(const struct dinSPKIDataType *spkidata,
			tvbuff_t *tvb,
			proto_tree *tree,
			gint idx,
			const char *subtree_name)
{
	unsigned int i;
	proto_tree *subtree;
	proto_tree *spkisexp_tree;
	proto_tree *spkisexp_i_tree;

	subtree = proto_tree_add_subtree(tree,
		tvb, 0, 0, idx, NULL, subtree_name);

	spkisexp_tree = proto_tree_add_subtree(subtree,
		tvb, 0, 0, ett_v2gdin_array, NULL, "SPKISexp");
	for (i = 0; i < spkidata->SPKISexp.arrayLen; i++) {
		spkisexp_i_tree = proto_tree_add_subtree_format(spkisexp_tree,
			tvb, 0, 0, ett_v2gdin_array_i, NULL, "[%u]", i);
		exi_add_bytes(spkisexp_i_tree,
			hf_v2gdin_struct_dinSPKIDataType_SPKISexp,
			tvb,
			spkidata->SPKISexp.array[i].bytes,
			spkidata->SPKISexp.array[i].bytesLen,
			sizeof(spkidata->SPKISexp.array[i].bytes));
	}

	if (spkidata->ANY_isUsed) {
		exi_add_characters(subtree,
			hf_v2gdin_struct_dinSPKIDataType_ANY,
			tvb,
			spkidata->ANY.characters,
			spkidata->ANY.charactersLen,
			sizeof(spkidata->ANY.characters));
	}
	return;
}

static void
dissect_v2gdin_keyinfo(const struct dinKeyInfoType *keyinfo,
		       tvbuff_t *tvb,
		       proto_tree *tree,
		       gint idx,
		       const char *subtree_name)
{
	unsigned int i;
	proto_tree *subtree;
	proto_tree *keyname_tree;
	proto_tree *keyname_i_tree;
	proto_tree *keyvalue_tree;
	proto_tree *retrievalmethod_tree;
	proto_tree *x509data_tree;
	proto_tree *pgpdata_tree;
	proto_tree *spkidata_tree;
	proto_tree *mgmtdata_tree;
	proto_tree *mgmtdata_i_tree;

	subtree = proto_tree_add_subtree(tree,
		tvb, 0, 0, idx, NULL, subtree_name);

	if (keyinfo->Id_isUsed) {
		exi_add_characters(subtree,
			hf_v2gdin_struct_dinKeyInfoType_Id,
			tvb,
			keyinfo->Id.characters,
			keyinfo->Id.charactersLen,
			sizeof(keyinfo->Id.characters));
	}

	keyname_tree = proto_tree_add_subtree(subtree,
		tvb, 0, 0, ett_v2gdin_array, NULL, "KeyName");
	for (i = 0; i < keyinfo->KeyName.arrayLen; i++) {
		keyname_i_tree = proto_tree_add_subtree_format(keyname_tree,
			tvb, 0, 0, ett_v2gdin_array_i, NULL, "[%u]", i);
		exi_add_characters(keyname_i_tree,
			hf_v2gdin_struct_dinKeyInfoType_KeyName,
			tvb,
			keyinfo->KeyName.array[i].characters,
			keyinfo->KeyName.array[i].charactersLen,
			sizeof(keyinfo->KeyName.array[i].characters));
	}

	keyvalue_tree = proto_tree_add_subtree(subtree,
		tvb, 0, 0, ett_v2gdin_array, NULL, "KeyValue");
	for (i = 0; i < keyinfo->KeyValue.arrayLen; i++) {
		char index[sizeof("[65536]")];

		snprintf(index, sizeof(index), "[%u]", i);
		dissect_v2gdin_keyvalue(&keyinfo->KeyValue.array[i],
					tvb, keyvalue_tree,
					ett_v2gdin_struct_dinKeyValueType,
					index);
	}

	retrievalmethod_tree = proto_tree_add_subtree(subtree,
		tvb, 0, 0, ett_v2gdin_array, NULL, "RetrievalMethod");
	for (i = 0; i < keyinfo->RetrievalMethod.arrayLen; i++) {
		char index[sizeof("[65536]")];

		snprintf(index, sizeof(index), "[%u]", i);
		dissect_v2gdin_retrievalmethod(
			&keyinfo->RetrievalMethod.array[i],
			tvb, retrievalmethod_tree,
			ett_v2gdin_struct_dinRetrievalMethodType,
			index);
	}

	x509data_tree = proto_tree_add_subtree(subtree,
		tvb, 0, 0, ett_v2gdin_array, NULL, "X509Data");
	for (i = 0; i < keyinfo->X509Data.arrayLen; i++) {
		char index[sizeof("[65536]")];

		snprintf(index, sizeof(index), "[%u]", i);
		dissect_v2gdin_x509data(&keyinfo->X509Data.array[i],
					tvb, x509data_tree,
					ett_v2gdin_struct_dinX509DataType,
					index);
	}

	pgpdata_tree = proto_tree_add_subtree(subtree,
		tvb, 0, 0, ett_v2gdin_array, NULL, "PGPData");
	for (i = 0; i < keyinfo->PGPData.arrayLen; i++) {
		char index[sizeof("[65536]")];

		snprintf(index, sizeof(index), "[%u]", i);
		dissect_v2gdin_pgpdata(&keyinfo->PGPData.array[i],
				       tvb, pgpdata_tree,
				       ett_v2gdin_struct_dinPGPDataType,
				       index);
	}

	spkidata_tree = proto_tree_add_subtree(subtree,
		tvb, 0, 0, ett_v2gdin_array, NULL, "SPKIData");
	for (i = 0; i < keyinfo->SPKIData.arrayLen; i++) {
		char index[sizeof("[65536]")];

		snprintf(index, sizeof(index), "[%u]", i);
		dissect_v2gdin_spkidata(&keyinfo->SPKIData.array[i],
					tvb, spkidata_tree,
					ett_v2gdin_struct_dinSPKIDataType,
					index);
	}

	mgmtdata_tree = proto_tree_add_subtree(subtree,
		tvb, 0, 0, ett_v2gdin_array, NULL, "MgmtData");
	for (i = 0; i < keyinfo->MgmtData.arrayLen; i++) {
		mgmtdata_i_tree = proto_tree_add_subtree_format(mgmtdata_tree,
			tvb, 0, 0, ett_v2gdin_array_i, NULL, "[%u]", i);
		exi_add_characters(mgmtdata_i_tree,
			hf_v2gdin_struct_dinKeyInfoType_MgmtData,
			tvb,
			keyinfo->MgmtData.array[i].characters,
			keyinfo->MgmtData.array[i].charactersLen,
			sizeof(keyinfo->MgmtData.array[i].characters));
	}

	if (keyinfo->ANY_isUsed) {
		exi_add_characters(subtree,
			hf_v2gdin_struct_dinKeyInfoType_ANY,
			tvb,
			keyinfo->ANY.characters,
			keyinfo->ANY.charactersLen,
			sizeof(keyinfo->ANY.characters));
	}

	return;
}

static void
dissect_v2gdin_signature(const struct dinSignatureType *signature,
			 tvbuff_t *tvb,
			 proto_tree *tree,
			 gint idx,
			 const char *subtree_name)
{
	unsigned int i;
	proto_tree *subtree;
	proto_tree *object_tree;

	subtree = proto_tree_add_subtree(tree,
		tvb, 0, 0, idx, NULL, subtree_name);

	if (signature->Id_isUsed) {
		exi_add_characters(subtree,
			hf_v2gdin_struct_dinSignatureType_Id,
			tvb,
			signature->Id.characters,
			signature->Id.charactersLen,
			sizeof(signature->Id.characters));
	}

	dissect_v2gdin_signedinfo(&signature->SignedInfo, tvb,
		subtree, ett_v2gdin_struct_dinSignedInfoType, "SignedInfo");
	dissect_v2gdin_signaturevalue(&signature->SignatureValue, tvb,
		subtree, ett_v2gdin_struct_dinSignatureValueType,
		"SignatureValue");

	if (signature->KeyInfo_isUsed) {
		dissect_v2gdin_keyinfo(&signature->KeyInfo, tvb,
			subtree, ett_v2gdin_struct_dinKeyInfoType, "KeyInfo");
	}

	object_tree = proto_tree_add_subtree(subtree,
		tvb, 0, 0, ett_v2gdin_array, NULL, "Object");
	for (i = 0; i < signature->Object.arrayLen; i++) {
		char index[sizeof("[65536]")];

		snprintf(index, sizeof(index), "[%u]", i);
		dissect_v2gdin_object(&signature->Object.array[i], tvb,
			object_tree, ett_v2gdin_struct_dinObjectType, index);
	}

	return;
}

static void
dissect_v2gdin_paymentoptions(
	const struct dinPaymentOptionsType *paymentoptions,
	tvbuff_t *tvb,
	proto_tree *tree,
	gint idx,
	const char *subtree_name)
{
	unsigned int i;
	proto_tree *subtree;
	proto_tree *paymentoption_tree;
	proto_tree *paymentoption_i_tree;
	proto_item *it;

	subtree = proto_tree_add_subtree(tree, tvb, 0, 0,
		idx, NULL, subtree_name);

	paymentoption_tree = proto_tree_add_subtree(subtree,
		tvb, 0, 0, ett_v2gdin_array, NULL, "PaymentOption");
	for (i = 0; i < paymentoptions->PaymentOption.arrayLen; i++) {
		char index[sizeof("[65536]")];

		snprintf(index, sizeof(index), "[%u]", i);
		paymentoption_i_tree = proto_tree_add_subtree(
			paymentoption_tree, tvb, 0, 0,
			ett_v2gdin_array_i, NULL, index);

		it = proto_tree_add_uint(paymentoption_i_tree,
			hf_v2gdin_struct_dinPaymentOptionsType_PaymentOption,
			tvb, 0, 0,
			paymentoptions->PaymentOption.array[i]);
		proto_item_set_generated(it);
	}

	return;
}

static void
dissect_v2gdin_servicetag(const struct dinServiceTagType *servicetag,
			  tvbuff_t *tvb,
			  proto_tree *tree,
			  gint idx,
			  const char *subtree_name)
{
	proto_tree *subtree;
	proto_item *it;

	subtree = proto_tree_add_subtree(tree, tvb, 0, 0,
		idx, NULL, subtree_name);

	it = proto_tree_add_uint(subtree,
		hf_v2gdin_struct_dinServiceTagType_ServiceID, tvb, 0, 0,
		servicetag->ServiceID);
	proto_item_set_generated(it);

	if (servicetag->ServiceName_isUsed) {
		exi_add_characters(subtree,
			hf_v2gdin_struct_dinServiceTagType_ServiceName,
			tvb,
			servicetag->ServiceName.characters,
			servicetag->ServiceName.charactersLen,
			sizeof(servicetag->ServiceName.characters));
	}

	it = proto_tree_add_uint(subtree,
		hf_v2gdin_struct_dinServiceTagType_ServiceCategory, tvb, 0, 0,
		servicetag->ServiceCategory);
	proto_item_set_generated(it);

	if (servicetag->ServiceScope_isUsed) {
		exi_add_characters(subtree,
			hf_v2gdin_struct_dinServiceTagType_ServiceScope,
			tvb,
			servicetag->ServiceScope.characters,
			servicetag->ServiceScope.charactersLen,
			sizeof(servicetag->ServiceScope.characters));
	}

	return;
}

static void
dissect_v2gdin_servicecharge(const struct dinServiceChargeType *servicecharge,
			     tvbuff_t *tvb,
			     proto_tree *tree,
			     gint idx,
			     const char *subtree_name)
{
	proto_tree *subtree;
	proto_item *it;

	subtree = proto_tree_add_subtree(tree, tvb, 0, 0,
		idx, NULL, subtree_name);

	dissect_v2gdin_servicetag(&servicecharge->ServiceTag,
		tvb, subtree, ett_v2gdin_struct_dinServiceTagType,
		"ServiceTag");

	it = proto_tree_add_int(subtree,
		hf_v2gdin_struct_dinServiceChargeType_FreeService,
		tvb, 0, 0, servicecharge->FreeService);
	proto_item_set_generated(it);

	it = proto_tree_add_uint(subtree,
		hf_v2gdin_struct_dinServiceChargeType_EnergyTransferType,
		tvb, 0, 0, servicecharge->EnergyTransferType);
	proto_item_set_generated(it);

	return;
}

static void
dissect_v2gdin_service(const struct dinServiceType *service,
		       tvbuff_t *tvb,
		       proto_tree *tree,
		       gint idx,
		       const char *subtree_name)
{
	proto_tree *subtree;
	proto_item *it;

	subtree = proto_tree_add_subtree(tree, tvb, 0, 0,
		idx, NULL, subtree_name);

	dissect_v2gdin_servicetag(&service->ServiceTag,
		tvb, subtree, ett_v2gdin_struct_dinServiceTagType,
		"ServiceTag");

	it = proto_tree_add_int(subtree,
		hf_v2gdin_struct_dinServiceType_FreeService, tvb, 0, 0,
		service->FreeService);
	proto_item_set_generated(it);

	return;
}

static void
dissect_v2gdin_servicetaglist(
	const struct dinServiceTagListType *servicetaglist,
	tvbuff_t *tvb,
	proto_tree *tree,
	gint idx,
	const char *subtree_name)
{
	unsigned int i;
	proto_tree *subtree;
	proto_tree *service_tree;

	subtree = proto_tree_add_subtree(tree, tvb, 0, 0,
		idx, NULL, subtree_name);

	service_tree = proto_tree_add_subtree(subtree,
		tvb, 0, 0, ett_v2gdin_array, NULL, "Service");
	for (i = 0; i < servicetaglist->Service.arrayLen; i++) {
		char index[sizeof("[65536]")];

		dissect_v2gdin_service(
			&servicetaglist->Service.array[i],
			tvb, service_tree, ett_v2gdin_struct_dinServiceType,
			index);
	}

	return;
}

static void
dissect_v2gdin_physicalvalue(const struct dinPhysicalValueType *physicalvalue,
			     tvbuff_t *tvb,
			     proto_tree *tree,
			     gint idx,
			     const char *subtree_name)
{
	proto_tree *subtree;
	proto_item *it;

	subtree = proto_tree_add_subtree(tree, tvb, 0, 0,
		idx, NULL, subtree_name);

	it = proto_tree_add_int(subtree,
		hf_v2gdin_struct_dinPhysicalValueType_Multiplier,
		tvb, 0, 0, physicalvalue->Multiplier);
	proto_item_set_generated(it);

	if (physicalvalue->Unit_isUsed) {
		it = proto_tree_add_uint(subtree,
			hf_v2gdin_struct_dinPhysicalValueType_Unit,
			tvb, 0, 0, physicalvalue->Unit);
		proto_item_set_generated(it);
	}

	it = proto_tree_add_int(subtree,
		hf_v2gdin_struct_dinPhysicalValueType_Value,
		tvb, 0, 0, physicalvalue->Value);
	proto_item_set_generated(it);

	return;
}

static void
dissect_v2gdin_parameter(
	const struct dinParameterType *parameter,
	tvbuff_t *tvb,
	proto_tree *tree,
	gint idx,
	const char *subtree_name)
{
	proto_tree *subtree;
	proto_item *it;

	subtree = proto_tree_add_subtree(tree, tvb, 0, 0,
		idx, NULL, subtree_name);

	exi_add_characters(subtree,
		hf_v2gdin_struct_dinParameterType_Name,
		tvb,
		parameter->Name.characters,
		parameter->Name.charactersLen,
		sizeof(parameter->Name.characters));

	it = proto_tree_add_uint(subtree,
		hf_v2gdin_struct_dinParameterType_ValueType,
		tvb, 0, 0, parameter->ValueType);
	proto_item_set_generated(it);

	if (parameter->boolValue_isUsed) {
		it = proto_tree_add_int(subtree,
			hf_v2gdin_struct_dinParameterType_boolValue,
			tvb, 0, 0, parameter->boolValue);
		proto_item_set_generated(it);
	}
	if (parameter->byteValue_isUsed) {
		it = proto_tree_add_int(subtree,
			hf_v2gdin_struct_dinParameterType_byteValue,
			tvb, 0, 0, parameter->byteValue);
		proto_item_set_generated(it);
	}
	if (parameter->shortValue_isUsed) {
		it = proto_tree_add_int(subtree,
			hf_v2gdin_struct_dinParameterType_shortValue,
			tvb, 0, 0, parameter->shortValue);
		proto_item_set_generated(it);
	}
	if (parameter->intValue_isUsed) {
		it = proto_tree_add_int(subtree,
			hf_v2gdin_struct_dinParameterType_intValue,
			tvb, 0, 0, parameter->intValue);
		proto_item_set_generated(it);
	}
	if (parameter->physicalValue_isUsed) {
		dissect_v2gdin_physicalvalue(&parameter->physicalValue,
			tvb, subtree, ett_v2gdin_struct_dinPhysicalValueType,
			"physicalValue");
	}
	if (parameter->stringValue_isUsed) {
		exi_add_characters(subtree,
			hf_v2gdin_struct_dinParameterType_stringValue,
			tvb,
			parameter->stringValue.characters,
			parameter->stringValue.charactersLen,
			sizeof(parameter->stringValue.characters));
	}

	return;
}

static void
dissect_v2gdin_parameterset(
	const struct dinParameterSetType *parameterset,
	tvbuff_t *tvb,
	proto_tree *tree,
	gint idx,
	const char *subtree_name)
{
	unsigned int i;
	proto_tree *subtree;
	proto_tree *parameter_tree;
	proto_item *it;

	subtree = proto_tree_add_subtree(tree, tvb, 0, 0,
		idx, NULL, subtree_name);

	it = proto_tree_add_int(subtree,
		hf_v2gdin_struct_dinParameterSetType_ParameterSetID,
		tvb, 0, 0, parameterset->ParameterSetID);
	proto_item_set_generated(it);

	parameter_tree = proto_tree_add_subtree(subtree,
		tvb, 0, 0, ett_v2gdin_array, NULL, "Parameter");
	for (i = 0; i < parameterset->Parameter.arrayLen; i++) {
		char index[sizeof("[65536]")];

		dissect_v2gdin_parameter(
			&parameterset->Parameter.array[i],
			tvb, parameter_tree,
			ett_v2gdin_struct_dinParameterType, index);
	}

	return;
}

static void
dissect_v2gdin_serviceparameterlist(
	const struct dinServiceParameterListType *serviceparameterlist,
	tvbuff_t *tvb,
	proto_tree *tree,
	gint idx,
	const char *subtree_name)
{
	unsigned int i;
	proto_tree *subtree;
	proto_tree *parameterset_tree;

	subtree = proto_tree_add_subtree(tree, tvb, 0, 0,
		idx, NULL, subtree_name);

	parameterset_tree = proto_tree_add_subtree(subtree,
		tvb, 0, 0, ett_v2gdin_array, NULL, "ParameterSet");
	for (i = 0; i < serviceparameterlist->ParameterSet.arrayLen; i++) {
		char index[sizeof("[65536]")];

		dissect_v2gdin_parameterset(
			&serviceparameterlist->ParameterSet.array[i],
			tvb, parameterset_tree,
			ett_v2gdin_struct_dinParameterSetType, index);
	}

	return;
}

static void
dissect_v2gdin_selectedservice(
	const struct dinSelectedServiceType *selectedservice,
	tvbuff_t *tvb,
	proto_tree *tree,
	gint idx,
	const char *subtree_name)
{
	proto_tree *subtree;
	proto_item *it;

	subtree = proto_tree_add_subtree(tree, tvb, 0, 0,
		idx, NULL, subtree_name);

	it = proto_tree_add_uint(subtree,
		hf_v2gdin_struct_dinSelectedServiceType_ServiceID,
		tvb, 0, 0, selectedservice->ServiceID);
	proto_item_set_generated(it);

	if (selectedservice->ParameterSetID_isUsed) {
		it = proto_tree_add_int(subtree,
			hf_v2gdin_struct_dinSelectedServiceType_ParameterSetID,
			tvb, 0, 0, selectedservice->ParameterSetID);
		proto_item_set_generated(it);
	}

	return;
}

static void
dissect_v2gdin_selectedservicelist(
	const struct dinSelectedServiceListType *selectedservicelist,
	tvbuff_t *tvb,
	proto_tree *tree,
	gint idx,
	const char *subtree_name)
{
	unsigned int i;
	proto_tree *subtree;
	proto_tree *selectedservicelist_tree;

	subtree = proto_tree_add_subtree(tree, tvb, 0, 0,
		idx, NULL, subtree_name);

	selectedservicelist_tree = proto_tree_add_subtree(subtree,
		tvb, 0, 0, ett_v2gdin_array, NULL, "SelectedServiceList");
	for (i = 0; i < selectedservicelist->SelectedService.arrayLen; i++) {
		char index[sizeof("[65536]")];

		dissect_v2gdin_selectedservice(
			&selectedservicelist->SelectedService.array[i],
			tvb, selectedservicelist_tree,
			ett_v2gdin_struct_dinSelectedServiceType, index);
	}

	return;
}

static void
dissect_v2gdin_subcertificates(
	const struct dinSubCertificatesType *subcertificates,
	tvbuff_t *tvb,
	proto_tree *tree,
	gint idx,
	const char *subtree_name)
{
	unsigned int i;
	proto_tree *subtree;
	proto_tree *certificate_tree;
	proto_tree *certificate_i_tree;

	subtree = proto_tree_add_subtree(tree, tvb, 0, 0,
		idx, NULL, subtree_name);

	certificate_tree = proto_tree_add_subtree(subtree,
		tvb, 0, 0, ett_v2gdin_array, NULL, "Certificate");
	for (i = 0; i < subcertificates->Certificate.arrayLen; i++) {
		certificate_i_tree = proto_tree_add_subtree_format(
			certificate_tree,
			tvb, 0, 0, ett_v2gdin_array_i, NULL, "[%u]", i);
		exi_add_bytes(certificate_i_tree,
			hf_v2gdin_struct_dinSubCertificatesType_Certificate,
			tvb,
			subcertificates->Certificate.array[i].bytes,
			subcertificates->Certificate.array[i].bytesLen,
			sizeof(subcertificates->Certificate.array[i].bytes));
	}

	return;
}

static void
dissect_v2gdin_certificatechain(
	const struct dinCertificateChainType *certificatechain,
	tvbuff_t *tvb,
	proto_tree *tree,
	gint idx,
	const char *subtree_name)
{
	proto_tree *subtree;

	subtree = proto_tree_add_subtree(tree, tvb, 0, 0,
		idx, NULL, subtree_name);

	exi_add_bytes(subtree,
		hf_v2gdin_struct_dinCertificateChainType_Certificate,
		tvb,
		certificatechain->Certificate.bytes,
		certificatechain->Certificate.bytesLen,
		sizeof(certificatechain->Certificate.bytes));

	if (certificatechain->SubCertificates_isUsed) {
		dissect_v2gdin_subcertificates(
			&certificatechain->SubCertificates,
			tvb, subtree,
			ett_v2gdin_struct_dinSubCertificatesType,
			"SubCertificates");
	}

	return;
}

static void
dissect_v2gdin_dc_evstatus(const struct dinDC_EVStatusType *dc_evstatus,
			   tvbuff_t *tvb,
			   proto_tree *tree,
			   gint idx,
			   const char *subtree_name)
{
	proto_tree *subtree;
	proto_item *it;

	subtree = proto_tree_add_subtree(tree, tvb, 0, 0,
		idx, NULL, subtree_name);

	it = proto_tree_add_int(subtree,
		hf_v2gdin_struct_dinDC_EVStatusType_EVReady,
		tvb, 0, 0, dc_evstatus->EVReady);
	proto_item_set_generated(it);

	if (dc_evstatus->EVCabinConditioning_isUsed) {
		it = proto_tree_add_int(subtree,
			hf_v2gdin_struct_dinDC_EVStatusType_EVCabinConditioning,
			tvb, 0, 0, dc_evstatus->EVCabinConditioning);
		proto_item_set_generated(it);
	}

	if (dc_evstatus->EVRESSConditioning_isUsed) {
		it = proto_tree_add_int(subtree,
			hf_v2gdin_struct_dinDC_EVStatusType_EVRESSConditioning,
			tvb, 0, 0, dc_evstatus->EVRESSConditioning);
		proto_item_set_generated(it);
	}

	it = proto_tree_add_uint(subtree,
		hf_v2gdin_struct_dinDC_EVStatusType_EVErrorCode,
		tvb, 0, 0, dc_evstatus->EVErrorCode);
	proto_item_set_generated(it);

	it = proto_tree_add_int(subtree,
		hf_v2gdin_struct_dinDC_EVStatusType_EVRESSSOC,
		tvb, 0, 0, dc_evstatus->EVRESSSOC);
	proto_item_set_generated(it);

	return;
}

static void
dissect_v2gdin_dc_evsestatus(const struct dinDC_EVSEStatusType *dc_evsestatus,
			     tvbuff_t *tvb,
			     proto_tree *tree,
			     gint idx,
			     const char *subtree_name)
{
	proto_tree *subtree;
	proto_item *it;

	subtree = proto_tree_add_subtree(tree, tvb, 0, 0,
		idx, NULL, subtree_name);

	if (dc_evsestatus->EVSEIsolationStatus_isUsed) {
		it = proto_tree_add_uint(subtree,
			hf_v2gdin_struct_dinDC_EVSEStatusType_EVSEIsolationStatus,
			tvb, 0, 0, dc_evsestatus->EVSEIsolationStatus);
		proto_item_set_generated(it);
	}

	it = proto_tree_add_uint(subtree,
		hf_v2gdin_struct_dinDC_EVSEStatusType_EVSEStatusCode,
		tvb, 0, 0, dc_evsestatus->EVSEStatusCode);
	proto_item_set_generated(it);

	it = proto_tree_add_uint(subtree,
		hf_v2gdin_struct_dinDC_EVSEStatusType_NotificationMaxDelay,
		tvb, 0, 0, dc_evsestatus->NotificationMaxDelay);
	proto_item_set_generated(it);

	it = proto_tree_add_uint(subtree,
		hf_v2gdin_struct_dinDC_EVSEStatusType_EVSENotification,
		tvb, 0, 0, dc_evsestatus->EVSENotification);
	proto_item_set_generated(it);

	return;
};

static void
dissect_v2gdin_header(tvbuff_t *tvb, packet_info *pinfo,
		      proto_tree *v2gdin_tree, struct dinMessageHeaderType *hdr)
{
	unsigned int i;
	proto_tree *hdr_tree;
	proto_item *it;

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
		dissect_v2gdin_notification(
			&hdr->Notification, tvb, hdr_tree,
			ett_v2gdin_struct_dinNotificationType,
			"Notification");
	}

	if (hdr->Signature_isUsed) {
		dissect_v2gdin_signature(
			&hdr->Signature, tvb, hdr_tree,
			ett_v2gdin_struct_dinSignatureType,
			"Signature");
	}

	return;
}

static void
dissect_v2gdin_body(tvbuff_t *tvb, packet_info *pinfo,
		    proto_tree *v2gdin_tree, struct dinBodyType *body)
{
	unsigned int i;
	proto_tree *body_tree;

	body_tree = proto_tree_add_subtree(v2gdin_tree,
		tvb, 0, 0, ett_v2gdin_body, NULL, "Body");

	if (body->SessionSetupReq_isUsed) {
		proto_tree *req_tree;

		req_tree = proto_tree_add_subtree(body_tree,
			tvb, 0, 0, ett_v2gdin_body_SessionSetupReq,
			NULL, "SessionSetupReq");

		exi_add_bytes(req_tree,
			hf_v2gdin_body_SessionSetupReq_EVCCID,
			tvb,
			body->SessionSetupReq.EVCCID.bytes,
			body->SessionSetupReq.EVCCID.bytesLen,
			sizeof(body->SessionSetupReq.EVCCID.bytes));
	}
	if (body->SessionSetupRes_isUsed) {
		proto_tree *res_tree;
		proto_item *it;

		res_tree = proto_tree_add_subtree(body_tree,
			tvb, 0, 0, ett_v2gdin_body_SessionSetupRes,
			NULL, "SessionSetupRes");

		it = proto_tree_add_uint(res_tree,
			hf_v2gdin_body_SessionSetupRes_ResponseCode,
			tvb, 0, 0, body->SessionSetupRes.ResponseCode);
		proto_item_set_generated(it);

		char evseid[2*dinSessionSetupResType_EVSEID_BYTES_SIZE + 1];
		for (i = 0; i < body->SessionSetupRes.EVSEID.bytesLen; i++) {
			snprintf(&evseid[2*i], sizeof(evseid) - 2*i,
				"%02X", body->SessionSetupRes.EVSEID.bytes[i]);
		}
		evseid[2*i] = '\0';
		it = proto_tree_add_string(res_tree,
			hf_v2gdin_body_SessionSetupRes_EVSEID,
			tvb, 0, 0, evseid);
		proto_item_set_generated(it);

		if (body->SessionSetupRes.DateTimeNow_isUsed) {
			it = proto_tree_add_int64(res_tree,
				hf_v2gdin_body_SessionSetupRes_DateTimeNow,
				tvb, 0, 0, body->SessionSetupRes.DateTimeNow);
			proto_item_set_generated(it);
		}
	}

	if (body->ServiceDiscoveryReq_isUsed) {
		proto_tree *req_tree;
		proto_item *it;

		req_tree = proto_tree_add_subtree(body_tree,
			tvb, 0, 0, ett_v2gdin_body_ServiceDiscoveryReq,
			NULL, "ServiceDiscoveryReq");

		if (body->ServiceDiscoveryReq.ServiceScope_isUsed) {
			exi_add_characters(req_tree,
				hf_v2gdin_body_ServiceDiscoveryReq_ServiceScope,
				tvb,
				body->ServiceDiscoveryReq.ServiceScope.characters,
				body->ServiceDiscoveryReq.ServiceScope.charactersLen,
				sizeof(body->ServiceDiscoveryReq.ServiceScope.characters));
		}

		if (body->ServiceDiscoveryReq.ServiceCategory_isUsed) {
			it = proto_tree_add_uint(req_tree,
				hf_v2gdin_body_ServiceDiscoveryReq_ServiceCategory,
				tvb, 0, 0, body->ServiceDiscoveryReq.ServiceCategory);
			proto_item_set_generated(it);
		}
	}
	if (body->ServiceDiscoveryRes_isUsed) {
		proto_tree *res_tree;
		proto_item *it;

		res_tree = proto_tree_add_subtree(body_tree,
			tvb, 0, 0, ett_v2gdin_body_ServiceDiscoveryRes,
			NULL, "ServiceDiscoveryRes");

		it = proto_tree_add_uint(res_tree,
			hf_v2gdin_body_ServiceDiscoveryRes_ResponseCode,
			tvb, 0, 0, body->ServiceDiscoveryRes.ResponseCode);
		proto_item_set_generated(it);

		dissect_v2gdin_paymentoptions(
			&body->ServiceDiscoveryRes.PaymentOptions,
			tvb, res_tree,
			ett_v2gdin_struct_dinPaymentOptionsType,
			"PaymentOptions");

		dissect_v2gdin_servicecharge(
			&body->ServiceDiscoveryRes.ChargeService,
			tvb, res_tree,
			ett_v2gdin_struct_dinServiceChargeType,
			"ChargeService");

		if (body->ServiceDiscoveryRes.ServiceList_isUsed) {
			dissect_v2gdin_servicetaglist(
				&body->ServiceDiscoveryRes.ServiceList,
				tvb, res_tree,
				ett_v2gdin_struct_dinServiceTagListType,
				"ServiceList");
		}
	}

	if (body->ServiceDetailReq_isUsed) {
		proto_tree *req_tree;
		proto_item *it;

		req_tree = proto_tree_add_subtree(body_tree,
			tvb, 0, 0, ett_v2gdin_body_ServiceDetailReq,
			NULL, "ServiceDetailReq");

		it = proto_tree_add_uint(req_tree,
			hf_v2gdin_body_ServiceDetailReq_ServiceID,
			tvb, 0, 0, body->ServiceDetailReq.ServiceID);
		proto_item_set_generated(it);
	}
	if (body->ServiceDetailRes_isUsed) {
		proto_tree *res_tree;
		proto_item *it;

		res_tree = proto_tree_add_subtree(body_tree,
			tvb, 0, 0, ett_v2gdin_body_ServiceDetailRes,
			NULL, "ServiceDetailRes");

		it = proto_tree_add_uint(res_tree,
			hf_v2gdin_body_ServiceDetailRes_ResponseCode,
			tvb, 0, 0, body->ServiceDetailRes.ResponseCode);
		proto_item_set_generated(it);

		it = proto_tree_add_uint(res_tree,
			hf_v2gdin_body_ServiceDetailRes_ServiceID,
			tvb, 0, 0, body->ServiceDetailRes.ServiceID);
		proto_item_set_generated(it);

		if (body->ServiceDetailRes.ServiceParameterList_isUsed) {
			dissect_v2gdin_serviceparameterlist(
				&body->ServiceDetailRes.ServiceParameterList,
				tvb, res_tree,
				ett_v2gdin_struct_dinServiceParameterListType,
				"ServiceParameterList");
		}
	}

	if (body->ServicePaymentSelectionReq_isUsed) {
		proto_tree *req_tree;
		proto_item *it;

		req_tree = proto_tree_add_subtree(body_tree,
			tvb, 0, 0, ett_v2gdin_body_ServicePaymentSelectionReq,
			NULL, "ServicePaymentSelectionReq");

		it = proto_tree_add_uint(req_tree,
			hf_v2gdin_body_ServicePaymentSelectionReq_SelectedPaymentOption,
			tvb, 0, 0, body->ServicePaymentSelectionReq.SelectedPaymentOption);
		proto_item_set_generated(it);

		dissect_v2gdin_selectedservicelist(
			&body->ServicePaymentSelectionReq.SelectedServiceList,
			tvb, req_tree,
			ett_v2gdin_struct_dinSelectedServiceListType,
			"SelectedServiceList");
	}
	if (body->ServicePaymentSelectionRes_isUsed) {
		proto_tree *res_tree;
		proto_item *it;

		res_tree = proto_tree_add_subtree(body_tree,
			tvb, 0, 0, ett_v2gdin_body_ServicePaymentSelectionRes,
			NULL, "ServicePaymentSelectionRes");

		it = proto_tree_add_uint(res_tree,
			hf_v2gdin_body_ServicePaymentSelectionRes_ResponseCode,
			tvb, 0, 0,
			body->ServicePaymentSelectionRes.ResponseCode);
		proto_item_set_generated(it);
	}

	if (body->PaymentDetailsReq_isUsed) {
		proto_tree *req_tree;

		req_tree = proto_tree_add_subtree(body_tree,
			tvb, 0, 0, ett_v2gdin_body_PaymentDetailsReq,
			NULL, "PaymentDetailsReq");

		exi_add_characters(req_tree,
			hf_v2gdin_body_PaymentDetailsReq_ContractID,
			tvb,
			body->PaymentDetailsReq.ContractID.characters,
			body->PaymentDetailsReq.ContractID.charactersLen,
			sizeof(body->PaymentDetailsReq.ContractID.characters));

		dissect_v2gdin_certificatechain(
			&body->PaymentDetailsReq.ContractSignatureCertChain,
			tvb, req_tree,
			ett_v2gdin_struct_dinCertificateChainType,
			"ContractSignatureCertChain");
	}
	if (body->PaymentDetailsRes_isUsed) {
		proto_tree *res_tree;
		proto_item *it;

		res_tree = proto_tree_add_subtree(body_tree,
			tvb, 0, 0, ett_v2gdin_body_PaymentDetailsRes,
			NULL, "PaymentDetailsRes");

		it = proto_tree_add_uint(res_tree,
			hf_v2gdin_body_PaymentDetailsRes_ResponseCode,
			tvb, 0, 0,
			body->PaymentDetailsRes.ResponseCode);
		proto_item_set_generated(it);

		exi_add_characters(res_tree,
			hf_v2gdin_body_PaymentDetailsRes_GenChallenge,
			tvb,
			body->PaymentDetailsRes.GenChallenge.characters,
			body->PaymentDetailsRes.GenChallenge.charactersLen,
			sizeof(body->PaymentDetailsRes.GenChallenge.characters));

		it = proto_tree_add_int64(res_tree,
			hf_v2gdin_body_PaymentDetailsRes_DateTimeNow,
			tvb, 0, 0,
			body->PaymentDetailsRes.DateTimeNow);
		proto_item_set_generated(it);
	}

	if (body->ContractAuthenticationReq_isUsed) {
		proto_tree *req_tree;

		req_tree = proto_tree_add_subtree(body_tree,
			tvb, 0, 0, ett_v2gdin_body_ContractAuthenticationReq,
			NULL, "ContractAuthenticationReq");

		if (body->ContractAuthenticationReq.Id_isUsed) {
			exi_add_characters(req_tree,
				hf_v2gdin_body_ContractAuthenticationReq_Id,
				tvb,
				body->ContractAuthenticationReq.Id.characters,
				body->ContractAuthenticationReq.Id.charactersLen,
				sizeof(body->ContractAuthenticationReq.Id.characters));
		}
		if (body->ContractAuthenticationReq.GenChallenge_isUsed) {
			exi_add_characters(req_tree,
				hf_v2gdin_body_ContractAuthenticationReq_GenChallenge,
				tvb,
				body->ContractAuthenticationReq.GenChallenge.characters,
				body->ContractAuthenticationReq.GenChallenge.charactersLen,
				sizeof(body->ContractAuthenticationReq.GenChallenge.characters));
		}
	}
	if (body->ContractAuthenticationRes_isUsed) {
		proto_tree *res_tree;
		proto_item *it;

		res_tree = proto_tree_add_subtree(body_tree,
			tvb, 0, 0, ett_v2gdin_body_ContractAuthenticationRes,
			NULL, "ContractAuthenticationRes");

		it = proto_tree_add_uint(res_tree,
			hf_v2gdin_body_ContractAuthenticationRes_ResponseCode,
			tvb, 0, 0,
			body->ContractAuthenticationRes.ResponseCode);
		proto_item_set_generated(it);

		it = proto_tree_add_uint(res_tree,
			hf_v2gdin_body_ContractAuthenticationRes_EVSEProcessing,
			tvb, 0, 0,
			body->ContractAuthenticationRes.EVSEProcessing);
		proto_item_set_generated(it);
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
		proto_tree *req_tree;
		proto_item *it;

		req_tree = proto_tree_add_subtree(body_tree,
			tvb, 0, 0, ett_v2gdin_body_CurrentDemandReq,
			NULL, "CurrentDemandReq");

		dissect_v2gdin_dc_evstatus(
			&body->CurrentDemandReq.DC_EVStatus,
			tvb, req_tree,
			ett_v2gdin_struct_dinDC_EVStatusType,
			"DC_EVStatus");

		dissect_v2gdin_physicalvalue(
			&body->CurrentDemandReq.EVTargetVoltage,
			tvb, req_tree,
			ett_v2gdin_struct_dinPhysicalValueType,
			"EVTargetVoltage");

		dissect_v2gdin_physicalvalue(
			&body->CurrentDemandReq.EVTargetCurrent,
			tvb, req_tree,
			ett_v2gdin_struct_dinPhysicalValueType,
			"EVTargetCurrent");

		it = proto_tree_add_int(req_tree,
			hf_v2gdin_body_CurrentDemandReq_ChargingComplete,
			tvb, 0, 0, body->CurrentDemandReq.ChargingComplete);
		proto_item_set_generated(it);

		if (body->CurrentDemandReq.BulkChargingComplete_isUsed) {
			it = proto_tree_add_int(req_tree,
				hf_v2gdin_body_CurrentDemandReq_BulkChargingComplete,
				tvb, 0, 0, body->CurrentDemandReq.BulkChargingComplete);
			proto_item_set_generated(it);
		}

		if (body->CurrentDemandReq.EVMaximumVoltageLimit_isUsed) {
			dissect_v2gdin_physicalvalue(
				&body->CurrentDemandReq.EVMaximumVoltageLimit,
				tvb, req_tree,
				ett_v2gdin_struct_dinPhysicalValueType,
				"EVMaximumVoltageLimit");
		}

		if (body->CurrentDemandReq.EVMaximumCurrentLimit_isUsed) {
			dissect_v2gdin_physicalvalue(
				&body->CurrentDemandReq.EVMaximumCurrentLimit,
				tvb, req_tree,
				ett_v2gdin_struct_dinPhysicalValueType,
				"EVMaximumCurrentLimit");
		}

		if (body->CurrentDemandReq.EVMaximumPowerLimit_isUsed) {
			dissect_v2gdin_physicalvalue(
				&body->CurrentDemandReq.EVMaximumPowerLimit,
				tvb, req_tree,
				ett_v2gdin_struct_dinPhysicalValueType,
				"EVMaximumPowerLimit");
		}

		if (body->CurrentDemandReq.RemainingTimeToFullSoC_isUsed) {
			dissect_v2gdin_physicalvalue(
				&body->CurrentDemandReq.RemainingTimeToFullSoC,
				tvb, req_tree,
				ett_v2gdin_struct_dinPhysicalValueType,
				"RemainingTimeToFullSoC");
		}

		if (body->CurrentDemandReq.RemainingTimeToBulkSoC_isUsed) {
			dissect_v2gdin_physicalvalue(
				&body->CurrentDemandReq.RemainingTimeToBulkSoC,
				tvb, req_tree,
				ett_v2gdin_struct_dinPhysicalValueType,
				"RemainingTimeToBulkSoC");
		}
	}
	if (body->CurrentDemandRes_isUsed) {
		proto_tree *res_tree;
		proto_item *it;

		res_tree = proto_tree_add_subtree(body_tree,
			tvb, 0, 0, ett_v2gdin_body_CurrentDemandRes,
			NULL, "CurrentDemandRes");

		it = proto_tree_add_uint(res_tree,
			hf_v2gdin_body_CurrentDemandRes_ResponseCode,
			tvb, 0, 0, body->CurrentDemandRes.ResponseCode);
		proto_item_set_generated(it);

		dissect_v2gdin_dc_evsestatus(
			&body->CurrentDemandRes.DC_EVSEStatus,
			tvb, res_tree,
			ett_v2gdin_struct_dinDC_EVSEStatusType,
			"DC_EVSEStatus");

		dissect_v2gdin_physicalvalue(
			&body->CurrentDemandRes.EVSEPresentVoltage,
			tvb, res_tree,
			ett_v2gdin_struct_dinPhysicalValueType,
			"EVSEPresentVoltage");

		dissect_v2gdin_physicalvalue(
			&body->CurrentDemandRes.EVSEPresentCurrent,
			tvb, res_tree,
			ett_v2gdin_struct_dinPhysicalValueType,
			"EVSEPresentCurrent");

		it = proto_tree_add_int(res_tree,
			hf_v2gdin_body_CurrentDemandRes_EVSECurrentLimitAchieved,
			tvb, 0, 0, body->CurrentDemandRes.EVSECurrentLimitAchieved);
		proto_item_set_generated(it);

		it = proto_tree_add_int(res_tree,
			hf_v2gdin_body_CurrentDemandRes_EVSEVoltageLimitAchieved,
			tvb, 0, 0, body->CurrentDemandRes.EVSEVoltageLimitAchieved);
		proto_item_set_generated(it);

		it = proto_tree_add_int(res_tree,
			hf_v2gdin_body_CurrentDemandRes_EVSEPowerLimitAchieved,
			tvb, 0, 0, body->CurrentDemandRes.EVSEPowerLimitAchieved);
		proto_item_set_generated(it);

		if (body->CurrentDemandRes.EVSEMaximumVoltageLimit_isUsed) {
			dissect_v2gdin_physicalvalue(
				&body->CurrentDemandRes.EVSEMaximumVoltageLimit,
				tvb, res_tree,
				ett_v2gdin_struct_dinPhysicalValueType,
				"EVSEMaximumVoltageLimit");
		}
		if (body->CurrentDemandRes.EVSEMaximumCurrentLimit_isUsed) {
			dissect_v2gdin_physicalvalue(
				&body->CurrentDemandRes.EVSEMaximumCurrentLimit,
				tvb, res_tree,
				ett_v2gdin_struct_dinPhysicalValueType,
				"EVSEMaximumCurrentLimit");
		}
		if (body->CurrentDemandRes.EVSEMaximumPowerLimit_isUsed) {
			dissect_v2gdin_physicalvalue(
				&body->CurrentDemandRes.EVSEMaximumPowerLimit,
				tvb, res_tree,
				ett_v2gdin_struct_dinPhysicalValueType,
				"EVSEMaximumPowerLimit");
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
		/* struct dinNotificationType */
		{ &hf_v2gdin_struct_dinNotificationType_FaultCode,
		  { "FaultCode", "v2gdin.struct.notification.faultcode",
		    FT_UINT16, BASE_DEC, VALS(v2gdin_fault_code_names),
		    0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_struct_dinNotificationType_FaultMsg,
		  { "FaultMsg", "v2gdin.struct.notification.faultmsg",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* struct dinSignatureType */
		{ &hf_v2gdin_struct_dinSignatureType_Id,
		  { "Id", "v2gdin.struct.signature.id",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* struct dinSignedInfoType */
		{ &hf_v2gdin_struct_dinSignedInfoType_Id,
		  { "Id", "v2gdin.struct.signedinfo.id",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* struct dinKeyInfoType */
		{ &hf_v2gdin_struct_dinKeyInfoType_Id,
		  { "Id", "v2gdin.struct.keyinfo.id",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_struct_dinKeyInfoType_KeyName,
		  { "KeyName", "v2gdin.struct.keyinfo.keyname",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_struct_dinKeyInfoType_MgmtData,
		  { "MgmtData", "v2gdin.struct.keyinfo.mgmtdata",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_struct_dinKeyInfoType_ANY,
		  { "ANY", "v2gdin.struct.keyinfo.any",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* struct dinKeyValueType */
		{ &hf_v2gdin_struct_dinKeyValueType_ANY,
		  { "ANY", "v2gdin.struct.keyvalue.any",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* struct dinDSAKeyValueType */
		{ &hf_v2gdin_struct_dinDSAKeyValueType_P,
		  { "P", "v2gdin.struct.dsakeyvalue.p",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_struct_dinDSAKeyValueType_Q,
		  { "Q", "v2gdin.struct.dsakeyvalue.q",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_struct_dinDSAKeyValueType_G,
		  { "G", "v2gdin.struct.dsakeyvalue.g",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_struct_dinDSAKeyValueType_Y,
		  { "Y", "v2gdin.struct.dsakeyvalue.y",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_struct_dinDSAKeyValueType_J,
		  { "J", "v2gdin.struct.dsakeyvalue.j",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_struct_dinDSAKeyValueType_Seed,
		  { "Seed", "v2gdin.struct.dsakeyvalue.seed",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_struct_dinDSAKeyValueType_PgenCounter,
		  { "PgenCounter", "v2gdin.struct.dsakeyvalue.pgencounter",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* struct dinRSAKeyValueType */
		{ &hf_v2gdin_struct_dinRSAKeyValueType_Modulus,
		  { "Modulus", "v2gdin.struct.rsakeyvalue.modulus",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_struct_dinRSAKeyValueType_Exponent,
		  { "Exponent", "v2gdin.struct.rsakeyvalue.exponent",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* struct dinX509DataType */
		{ &hf_v2gdin_struct_dinX509DataType_X509SKI,
		  { "X509SKI", "v2gdin.struct.x509data.x509ski",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_struct_dinX509DataType_X509SubjectName,
		  { "X509SubjectName",
		    "v2gdin.struct.x509data.x509subjectname",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_struct_dinX509DataType_X509Certificate,
		  { "X509Certificate",
		    "v2gdin.struct.x509data.x509certificate",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_struct_dinX509DataType_X509CRL,
		  { "X509CRL", "v2gdin.struct.x509data.x509crl",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_struct_dinX509DataType_ANY,
		  { "ANY", "v2gdin.struct.x509data.any",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* struct dinX509IssuerSerialType */
		{ &hf_v2gdin_struct_dinX509IssuerSerialType_X509IssuerName,
		  { "X509IssuerName",
		    "v2gdin.struct.x509issuerserial.x509issuername",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_struct_dinX509IssuerSerialType_X509SerialNumber,
		  { "X509SerialNumber",
		    "v2gdin.struct.x509issuerserial.x509serialnumber",
		    FT_INT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},

		/* struct dinPGPDataType */
		{ &hf_v2gdin_struct_dinPGPDataType_PGPKeyID,
		  { "PGPKeyID", "v2gdin.struct.pgpdata.pgpkeyid",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_struct_dinPGPDataType_PGPKeyPacket,
		  { "PGPKeyPacket", "v2gdin.struct.pgpdata.pgpkeypacket",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_struct_dinPGPDataType_ANY,
		  { "ANY", "v2gdin.struct.pgpdata.any",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* struct dinSPKIDataType */
		{ &hf_v2gdin_struct_dinSPKIDataType_SPKISexp,
		  { "SPKISexp", "v2gdin.struct.spkidata.spkisexp",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_struct_dinSPKIDataType_ANY,
		  { "ANY", "v2gdin.struct.spkidata.any",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* struct dinRetrievalMethodType */
		{ &hf_v2gdin_struct_dinRetrievalMethodType_URI,
		  { "URI", "v2gdin.struct.retrievalmethod.uri",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_struct_dinRetrievalMethodType_Type,
		  { "Type", "v2gdin.struct.retrievalmethod.type",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* struct dinSignatureValueType */
		{ &hf_v2gdin_struct_dinSignatureValueType_Id,
		  { "Id", "v2gdin.struct.signavturevalue.id",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_struct_dinSignatureValueType_CONTENT,
		  { "CONTENT", "v2gdin.struct.signaturevalue.content",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* struct dinCanonicalizationMethodType */
		{ &hf_v2gdin_struct_dinCanonicalizationMethodType_Algorithm,
		  { "Algorithm",
		    "v2gdin.struct.canonicalizationmethod.algorithm",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_struct_dinCanonicalizationMethodType_ANY,
		  { "ANY",
		    "v2gdin.struct.canonicalizationmethod.any",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* struct dinDigestMethodType */
		{ &hf_v2gdin_struct_dinDigestMethodType_Algorithm,
		  { "Algorithm", "v2gdin.struct.digestmethod.algorithm",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_struct_dinDigestMethodType_ANY,
		  { "ANY", "v2gdin.struct.digestmethod.any",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* struct dinSignatureMethodType */
		{ &hf_v2gdin_struct_dinSignatureMethodType_Algorithm,
		  { "Algorithm", "v2gdin.struct.signaturemethod.algorithm",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_struct_dinSignatureMethodType_HMACOutputLength,
		  { "HMACOutputLength",
		    "v2gdin.struct.signaturemethod.hmacoutputlength",
		    FT_INT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_struct_dinSignatureMethodType_ANY,
		  { "ANY", "v2gdin.struct.signaturemethod.any",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* struct dinTransformType */
		{ &hf_v2gdin_struct_dinTransformType_Algorithm,
		  { "Algorithm", "v2gdin.struct.transform.algorithm",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_struct_dinTransformType_ANY,
		  { "ANY", "v2gdin.struct.transform.any",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_struct_dinTransformType_XPath,
		  { "XPath", "v2gdin.struct.transform.xpath",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* struct dinReferenceType */
		{ &hf_v2gdin_struct_dinReferenceType_Id,
		  { "Id", "v2gdin.struct.reference.id",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_struct_dinReferenceType_URI,
		  { "URI", "v2gdin.struct.reference.uri",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_struct_dinReferenceType_Type,
		  { "Type", "v2gdin.struct.reference.type",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_struct_dinReferenceType_DigestValue,
		  { "DigestValue", "v2gdin.struct.reference.digestvalue",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* struct dinObjectType */
		{ &hf_v2gdin_struct_dinObjectType_Id,
		  { "Id", "v2gdin.struct.object.id",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_struct_dinObjectType_MimeType,
		  { "MimeType", "v2gdin.struct.object.mimetype",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_struct_dinObjectType_Encoding,
		  { "Encoding", "v2gdin.struct.object.encoding",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_struct_dinObjectType_ANY,
		  { "ANY", "v2gdin.struct.object.any",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* struct dinServiceTagType */
		{ &hf_v2gdin_struct_dinServiceTagType_ServiceID,
		  { "ServiceID",
		    "v2gdin.struct.servicetag.serviceid",
		    FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_struct_dinServiceTagType_ServiceName,
		  { "ServiceName",
		    "v2gdin.struct.servicetag.servicename",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_struct_dinServiceTagType_ServiceCategory,
		  { "ServiceCategory",
		    "v2gdin.struct.servicetag.servicecategory",
		    FT_UINT32, BASE_DEC, VALS(v2gdin_service_category_names),
		    0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_struct_dinServiceTagType_ServiceScope,
		  { "ServiceScope",
		    "v2gdin.struct.servicetag.servicescope",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* struct dinServiceChargeType */
		{ &hf_v2gdin_struct_dinServiceChargeType_FreeService,
		  { "FreeService",
		    "v2gdin.struct.servicecharge.freeservice",
		    FT_INT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_struct_dinServiceChargeType_EnergyTransferType,
		  { "EnergyTransferType",
		    "v2gdin.struct.servicechargee.energytransfertype",
		    FT_UINT32, BASE_DEC, VALS(v2gdin_energy_transfer_type_names),
		    0x0, NULL, HFILL }
		},

		/* struct dinServiceType */
		{ &hf_v2gdin_struct_dinServiceType_FreeService,
		  { "FreeService",
		    "v2gdin.struct.service.freeservice",
		    FT_INT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},

		/* struct dinSelectedServiceType */
		{ &hf_v2gdin_struct_dinSelectedServiceType_ServiceID,
		  { "ServiceID", "v2gdin.struct.selectedservice.serviceid",
		    FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_struct_dinSelectedServiceType_ParameterSetID,
		  { "ParameterSetID",
		    "v2gdin.struct.selectedservicetype.parametersetid",
		    FT_INT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},

		/* struct dinParameterSetType */
		{ &hf_v2gdin_struct_dinParameterSetType_ParameterSetID,
		  { "ParameterSetID",
		    "v2gdin.struct.parameterset.parametersetid",
		    FT_INT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},

		/* struct dinPhysicalValueType */
		{ &hf_v2gdin_struct_dinPhysicalValueType_Multiplier,
		  { "Multiplier",
		    "v2gdin.struct.physicalvalue.multiplier",
		    FT_INT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_struct_dinPhysicalValueType_Unit,
		  { "Unit",
		    "v2gdin.struct.physicalvalue.unit",
		    FT_UINT32, BASE_DEC, VALS(v2gdin_unitsymbol_names),
		    0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_struct_dinPhysicalValueType_Value,
		  { "Value",
		    "v2gdin.struct.physicalvalue.value",
		    FT_INT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},

		/* struct dinPaymentOptionsType */
		{ &hf_v2gdin_struct_dinPaymentOptionsType_PaymentOption,
		  { "PaymentOption",
		    "v2gdin.struct.paymentoptions.paymentoption",
		    FT_UINT32, BASE_DEC, VALS(v2gdin_payment_option_names),
		    0x0, NULL, HFILL }
		},

		/* struct dinCertificateChainType */
		{ &hf_v2gdin_struct_dinCertificateChainType_Certificate,
		  { "Certificate",
		    "v2gdin.struct.certificatechain.certificate",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* struct dinSubCertificatesType */
		{ &hf_v2gdin_struct_dinSubCertificatesType_Certificate,
		  { "Certificate",
		    "v2gdin.struct.subcertificates.certificate",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* struct struct dinDC_EVStatusType */
		{ &hf_v2gdin_struct_dinDC_EVStatusType_EVReady,
		  { "EVReady",
		    "v2gdin.struct.dc_evstatus.evready",
		    FT_INT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_struct_dinDC_EVStatusType_EVCabinConditioning,
		  { "EVCabinConditioning",
		    "v2gdin.struct.dc_evstatus.evcabinconditioning",
		    FT_INT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_struct_dinDC_EVStatusType_EVRESSConditioning,
		  { "EVRESSConditioning",
		    "v2gdin.struct.dc_evstatus.evressconditioning",
		    FT_INT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_struct_dinDC_EVStatusType_EVErrorCode,
		  { "EVErrorCode",
		    "v2gdin.struct.dc_evstatus.everrorcode",
		    FT_UINT32, BASE_DEC, VALS(v2gdin_dc_everrorcode_names),
		    0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_struct_dinDC_EVStatusType_EVRESSSOC,
		  { "EVRESSSOC",
		    "v2gdin.struct.dc_evstatus.evresssoc",
		    FT_INT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},

		/* struct dinDC_EVSEStatusType */
		{ &hf_v2gdin_struct_dinDC_EVSEStatusType_EVSEIsolationStatus,
		  { "EVSEIsolationStatus",
		    "v2gdinstruct.dc_evsestatus.evseisolationstatus",
		    FT_UINT32, BASE_DEC, VALS(v2gdin_isolation_level_names),
		    0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_struct_dinDC_EVSEStatusType_EVSEStatusCode,
		  { "EVSEStatusCode",
		    "v2gdinstruct.dc_evsestatus.evsestatuscode",
		    FT_UINT32, BASE_DEC, VALS(v2gdin_dc_evsestatuscode_names),
		    0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_struct_dinDC_EVSEStatusType_NotificationMaxDelay,
		  { "NotificationMaxDelay",
		    "v2gdinstruct.dc_evsestatus.notificationmaxdelay",
		    FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_struct_dinDC_EVSEStatusType_EVSENotification,
		  { "EVSENotification",
		    "v2gdinstruct.dc_evsestatus.evsenotification",
		    FT_UINT32, BASE_DEC, VALS(v2gdin_evsenotification_names),
		    0x0, NULL, HFILL }
		},

		{ &hf_v2gdin_header_SessionID,
		  { "SessionID", "v2gdin.header.sessionid",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* SessionSetupReq */
		{ &hf_v2gdin_body_SessionSetupReq_EVCCID,
		  { "EVCCID", "v2gdin.body.sessionsetupreq.evccid",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		/* SessionSetupRes */
		{ &hf_v2gdin_body_SessionSetupRes_ResponseCode,
		  { "ResponseCode", "v2gdin.body.sessionsetupres.responsecode",
		    FT_UINT32, BASE_DEC, VALS(v2gdin_response_code_names),
		    0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_body_SessionSetupRes_EVSEID,
		  { "EVSEID", "v2gdin.body.sessionsetupres.evseid",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_body_SessionSetupRes_DateTimeNow,
		  { "DateTimeNow", "v2gdin.body.sessionsetupres.datetimenow",
		    FT_INT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},

		/* ServiceDiscoveryReq */
		{ &hf_v2gdin_body_ServiceDiscoveryReq_ServiceScope,
		  { "ServiceScope", "v2gdin.body.servicediscoveryreq.servicescope",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_body_ServiceDiscoveryReq_ServiceCategory,
		  { "ServiceCategory", "v2gdin.body.servicediscoveryreq.servicecategory",
		    FT_UINT32, BASE_DEC, VALS(v2gdin_service_category_names),
		    0x0, NULL, HFILL }
		},
		/* ServiceDiscoveryRes */
		{ &hf_v2gdin_body_ServiceDiscoveryRes_ResponseCode,
		  { "ResponseCode", "v2gdin.body.servicediscoveryres.responsecode",
		    FT_UINT32, BASE_DEC, VALS(v2gdin_response_code_names),
		    0x0, NULL, HFILL }
		},

		/* ServiceDetailReq */
		{ &hf_v2gdin_body_ServiceDetailReq_ServiceID,
		  { "ServiceID",
		    "v2gdin.body.servicedetailreq.serviceid",
		    FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }
		},
		/* ServiceDiscoveryRes */
		{ &hf_v2gdin_body_ServiceDetailRes_ResponseCode,
		  { "ResponseCode", "v2gdin.body.servicedetailres.responsecode",
		    FT_UINT32, BASE_DEC, VALS(v2gdin_response_code_names),
		    0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_body_ServiceDetailRes_ServiceID,
		  { "ServiceID",
		    "v2gdin.body.servicedetailres.serviceid",
		    FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }
		},

		/* ServicePaymentSelectionReq */
		{ &hf_v2gdin_body_ServicePaymentSelectionReq_SelectedPaymentOption,
		  { "SelectedPaymentOption",
		    "v2gdin.body.servicepaymentselectionreq.selectedpaymentoption",
		    FT_UINT32, BASE_DEC, VALS(v2gdin_payment_option_names),
		    0x0, NULL, HFILL }
		},
		/* ServicePaymentSelectionRes */
		{ &hf_v2gdin_body_ServicePaymentSelectionRes_ResponseCode,
		  { "ResponseCode",
		    "v2gdin.body.servicepaymentselectionres.responsecode",
		    FT_UINT32, BASE_DEC, VALS(v2gdin_response_code_names),
		    0x0, NULL, HFILL }
		},

		/* PaymentDetailsReq */
		{ &hf_v2gdin_body_PaymentDetailsReq_ContractID,
		  { "ContractID", "v2gdin.body.paymentdetailsreq.contractid",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		/* PaymentDetailsRes */
		{ &hf_v2gdin_body_PaymentDetailsRes_ResponseCode,
		  { "ResponseCode",
		    "v2gdin.body.paymentdetailsres.responsecode",
		    FT_UINT32, BASE_DEC, VALS(v2gdin_response_code_names),
		    0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_body_PaymentDetailsRes_GenChallenge,
		  { "GenChallenge",
		    "v2gdin.body.paymentdetailsres.genchallenge",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_body_PaymentDetailsRes_DateTimeNow,
		  { "DateTimeNow", "v2gdin.body.paymentdetailsress.datetimenow",
		    FT_INT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},

		/* ContractAuthenticationReq */
		{ &hf_v2gdin_body_ContractAuthenticationReq_Id,
		  { "Id", "v2gdin.body.paymentdetailsreq.id",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_body_ContractAuthenticationReq_GenChallenge,
		  { "GenChallenge",
		    "v2gdin.body.paymentdetailsreq.genchallenge",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		/* ContractAuthenticationRes */
		{ &hf_v2gdin_body_ContractAuthenticationRes_ResponseCode,
		  { "ResponseCode",
		    "v2gdin.body.contractauthenticationres.responsecode",
		    FT_UINT32, BASE_DEC, VALS(v2gdin_response_code_names),
		    0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_body_ContractAuthenticationRes_EVSEProcessing,
		  { "EVSEProcessing",
		    "v2gdin.body.contractauthenticationres.evseprocessing",
		    FT_UINT32, BASE_DEC, VALS(v2gdin_evse_processing_names),
		    0x0, NULL, HFILL }
		},

		/* CurrentDemandReq */
		{ &hf_v2gdin_body_CurrentDemandReq_ChargingComplete,
		  { "ChargingComplete",
		    "v2gdin.body.currentdemandreq.chargingcomplete",
		    FT_INT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_body_CurrentDemandReq_BulkChargingComplete,
		  { "BulkChargingComplete",
		    "v2gdin.body.currentdemandreq.bulkchargingcomplete",
		    FT_INT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		/* CurrentDemandRes */
		{ &hf_v2gdin_body_CurrentDemandRes_ResponseCode,
		  { "ResponseCode", "v2gdin.body.currentdemandres.responsecode",
		    FT_UINT32, BASE_DEC, VALS(v2gdin_response_code_names),
		    0x0, NULL, HFILL }
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
	};

	static gint *ett[] = {
		&ett_v2gdin,
		&ett_v2gdin_array,
		&ett_v2gdin_array_i,

		&ett_v2gdin_struct_dinNotificationType,
		&ett_v2gdin_struct_dinSignatureType,
		&ett_v2gdin_struct_dinSignedInfoType,
		&ett_v2gdin_struct_dinCanonicalizationMethodType,
		&ett_v2gdin_struct_dinSignatureMethodType,
		&ett_v2gdin_struct_dinReferenceType,
		&ett_v2gdin_struct_dinTransformsType,
		&ett_v2gdin_struct_dinTransformType,
		&ett_v2gdin_struct_dinDigestMethodType,
		&ett_v2gdin_struct_dinSignatureValueType,
		&ett_v2gdin_struct_dinKeyInfoType,
		&ett_v2gdin_struct_dinKeyValueType,
		&ett_v2gdin_struct_dinDSAKeyValueType,
		&ett_v2gdin_struct_dinRSAKeyValueType,
		&ett_v2gdin_struct_dinRetrievalMethodType,
		&ett_v2gdin_struct_dinX509IssuerSerialType,
		&ett_v2gdin_struct_dinX509DataType,
		&ett_v2gdin_struct_dinPGPDataType,
		&ett_v2gdin_struct_dinSPKIDataType,
		&ett_v2gdin_struct_dinObjectType,
		&ett_v2gdin_struct_dinServiceParameterListType,
		&ett_v2gdin_struct_dinServiceTagListType,
		&ett_v2gdin_struct_dinServiceTagType,
		&ett_v2gdin_struct_dinServiceChargeType,
		&ett_v2gdin_struct_dinServiceType,
		&ett_v2gdin_struct_dinSelectedServiceType,
		&ett_v2gdin_struct_dinSelectedServiceListType,
		&ett_v2gdin_struct_dinParameterSetType,
		&ett_v2gdin_struct_dinParameterType,
		&ett_v2gdin_struct_dinPhysicalValueType,
		&ett_v2gdin_struct_dinPaymentOptionsType,
		&ett_v2gdin_struct_dinCertificateChainType,
		&ett_v2gdin_struct_dinSubCertificatesType,
		&ett_v2gdin_struct_dinDC_EVStatusType,
		&ett_v2gdin_struct_dinDC_EVSEStatusType,

		&ett_v2gdin_header,
		&ett_v2gdin_body,
		&ett_v2gdin_body_SessionSetupReq,
		&ett_v2gdin_body_SessionSetupRes,
		&ett_v2gdin_body_ServiceDiscoveryReq,
		&ett_v2gdin_body_ServiceDiscoveryRes,
		&ett_v2gdin_body_ServiceDetailReq,
		&ett_v2gdin_body_ServiceDetailRes,
		&ett_v2gdin_body_ServicePaymentSelectionReq,
		&ett_v2gdin_body_ServicePaymentSelectionRes,
		&ett_v2gdin_body_PaymentDetailsReq,
		&ett_v2gdin_body_PaymentDetailsRes,
		&ett_v2gdin_body_ContractAuthenticationReq,
		&ett_v2gdin_body_ContractAuthenticationRes,
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
		&ett_v2gdin_body_CurrentDemandRes,
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
