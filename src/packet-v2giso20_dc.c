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

static int hf_struct_iso20_dc_MessageHeaderType_SessionID = -1;
static int hf_struct_iso20_dc_MessageHeaderType_TimeStamp = -1;
static int hf_struct_iso20_dc_SignatureType_Id = -1;
static int hf_struct_iso20_dc_SignedInfoType_Id = -1;
static int hf_struct_iso20_dc_CanonicalizationMethodType_Algorithm = -1;
static int hf_struct_iso20_dc_CanonicalizationMethodType_ANY = -1;
static int hf_struct_iso20_dc_SignatureMethodType_Algorithm = -1;
static int hf_struct_iso20_dc_SignatureMethodType_HMACOutputLength = -1;
static int hf_struct_iso20_dc_SignatureMethodType_ANY = -1;
static int hf_struct_iso20_dc_ReferenceType_Id = -1;
static int hf_struct_iso20_dc_ReferenceType_Type = -1;
static int hf_struct_iso20_dc_ReferenceType_URI = -1;
static int hf_struct_iso20_dc_ReferenceType_DigestValue = -1;
static int hf_struct_iso20_dc_TransformType_Algorithm = -1;
static int hf_struct_iso20_dc_TransformType_ANY = -1;
static int hf_struct_iso20_dc_TransformType_XPath = -1;
static int hf_struct_iso20_dc_DigestMethodType_Algorithm = -1;
static int hf_struct_iso20_dc_DigestMethodType_ANY = -1;
static int hf_struct_iso20_dc_SignatureValueType_Id = -1;
static int hf_struct_iso20_dc_SignatureValueType_CONTENT = -1;
static int hf_struct_iso20_dc_KeyInfoType_Id = -1;
static int hf_struct_iso20_dc_KeyInfoType_KeyName = -1;
static int hf_struct_iso20_dc_KeyInfoType_MgmtData = -1;
static int hf_struct_iso20_dc_KeyInfoType_ANY = -1;
static int hf_struct_iso20_dc_KeyValueType_ANY = -1;
static int hf_struct_iso20_dc_DSAKeyValueType_P = -1;
static int hf_struct_iso20_dc_DSAKeyValueType_Q = -1;
static int hf_struct_iso20_dc_DSAKeyValueType_G = -1;
static int hf_struct_iso20_dc_DSAKeyValueType_Y = -1;
static int hf_struct_iso20_dc_DSAKeyValueType_J = -1;
static int hf_struct_iso20_dc_DSAKeyValueType_Seed = -1;
static int hf_struct_iso20_dc_DSAKeyValueType_PgenCounter = -1;
static int hf_struct_iso20_dc_RSAKeyValueType_Exponent = -1;
static int hf_struct_iso20_dc_RSAKeyValueType_Modulus = -1;
static int hf_struct_iso20_dc_RetrievalMethodType_Type = -1;
static int hf_struct_iso20_dc_RetrievalMethodType_URI = -1;
static int hf_struct_iso20_dc_X509DataType_X509SKI = -1;
static int hf_struct_iso20_dc_X509DataType_X509SubjectName = -1;
static int hf_struct_iso20_dc_X509DataType_X509Certificate = -1;
static int hf_struct_iso20_dc_X509DataType_X509CRL = -1;
static int hf_struct_iso20_dc_X509DataType_ANY = -1;
static int hf_struct_iso20_dc_X509IssuerSerialType_X509IssuerName = -1;
static int hf_struct_iso20_dc_X509IssuerSerialType_X509SerialNumber = -1;
static int hf_struct_iso20_dc_PGPDataType_PGPKeyID = -1;
static int hf_struct_iso20_dc_PGPDataType_PGPKeyPacket = -1;
static int hf_struct_iso20_dc_PGPDataType_ANY = -1;
static int hf_struct_iso20_dc_SPKIDataType_SPKISexp = -1;
static int hf_struct_iso20_dc_SPKIDataType_ANY = -1;
static int hf_struct_iso20_dc_ObjectType_Id = -1;
static int hf_struct_iso20_dc_ObjectType_MimeType = -1;
static int hf_struct_iso20_dc_ObjectType_Encoding = -1;
static int hf_struct_iso20_dc_ObjectType_ANY = -1;

/* DC_ChargeParameterDiscovery */
static int hf_struct_iso20_dc_DC_ChargeParameterDiscoveryResType_ResponseCode = -1;

/* DC_CableCheck */
static int hf_struct_iso20_dc_DC_CableCheckResType_ResponseCode = -1;
static int hf_struct_iso20_dc_DC_CableCheckResType_EVSEProcessing = -1;

/* DC_PreCharge */
static int hf_struct_iso20_dc_DC_PreChargeReqType_EVProcessing = -1;
static int hf_struct_iso20_dc_DC_PreChargeResType_ResponseCode = -1;

/* DC_ChargeLoop */
static int hf_struct_iso20_dc_DC_ChargeLoopReqType_MeterInfoRequested = -1;
static int hf_struct_iso20_dc_DC_ChargeLoopResType_ResponseCode = -1;
static int hf_struct_iso20_dc_DC_ChargeLoopResType_EVSEPowerLimitAchieved = -1;
static int hf_struct_iso20_dc_DC_ChargeLoopResType_EVSECurrentLimitAchieved = -1;
static int hf_struct_iso20_dc_DC_ChargeLoopResType_EVSEVoltageLimitAchieved = -1;

/* DC_WeldingDetection */
static int hf_struct_iso20_dc_DC_WeldingDetectionReqType_EVProcessing = -1;
static int hf_struct_iso20_dc_DC_WeldingDetectionResType_ResponseCode = -1;

/* other */
static int hf_struct_iso20_dc_RationalNumberType_Exponent = -1;
static int hf_struct_iso20_dc_RationalNumberType_Value = -1;

static int hf_struct_iso20_dc_DC_CPDReqEnergyTransferModeType_TargetSOC = -1;

static int hf_struct_iso20_dc_BPT_DC_CPDReqEnergyTransferModeType_TargetSOC = -1;

/* Initialize the subtree pointers */
static gint ett_v2giso20_dc = -1;
static gint ett_v2giso20_dc_document = -1;
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
static gint ett_struct_iso20_dc_SignatureType = -1;
static gint ett_struct_iso20_dc_SignatureValueType = -1;
static gint ett_struct_iso20_dc_SignedInfoType = -1;
static gint ett_struct_iso20_dc_CanonicalizationMethodType = -1;
static gint ett_struct_iso20_dc_SignatureMethodType = -1;
static gint ett_struct_iso20_dc_ReferenceType = -1;
static gint ett_struct_iso20_dc_TransformsType = -1;
static gint ett_struct_iso20_dc_TransformType = -1;
static gint ett_struct_iso20_dc_DigestMethodType = -1;
static gint ett_struct_iso20_dc_KeyInfoType = -1;
static gint ett_struct_iso20_dc_KeyValueType = -1;
static gint ett_struct_iso20_dc_RetrievalMethodType = -1;
static gint ett_struct_iso20_dc_X509DataType = -1;
static gint ett_struct_iso20_dc_PGPDataType = -1;
static gint ett_struct_iso20_dc_SPKIDataType = -1;
static gint ett_struct_iso20_dc_ObjectType = -1;
static gint ett_struct_iso20_dc_ManifestType = -1;
static gint ett_struct_iso20_dc_SignaturePropertiesType = -1;
static gint ett_struct_iso20_dc_SignaturePropertyType = -1;
static gint ett_struct_iso20_dc_DSAKeyValueType = -1;
static gint ett_struct_iso20_dc_RSAKeyValueType = -1;

static gint ett_struct_iso20_dc_MessageHeaderType = -1;
static gint ett_struct_iso20_dc_X509IssuerSerialType = -1;

static gint ett_struct_iso20_dc_DisplayParametersType = -1;
static gint ett_struct_iso20_dc_EVSEStatusType = -1;
static gint ett_struct_iso20_dc_MeterInfoType = -1;
static gint ett_struct_iso20_dc_ReceiptType = -1;
static gint ett_struct_iso20_dc_RationalNumberType = -1;


static const value_string v2giso20_dc_enum_iso20_dc_responseCodeType_names[] = {
	{ iso20_dc_responseCodeType_OK, "OK" },
	{ iso20_dc_responseCodeType_OK_CertificateExpiresSoon,
	  "OK (CertificateExpiresSoon)" },
	{ iso20_dc_responseCodeType_OK_NewSessionEstablished,
	  "OK (NewSessionEstablished)" },
	{ iso20_dc_responseCodeType_OK_OldSessionJoined,
	  "OK (OldSessionJoined)" },
	{ iso20_dc_responseCodeType_OK_PowerToleranceConfirmed,
	  "OK (PowerToleranceConfirmed)" },
	{ iso20_dc_responseCodeType_WARNING_AuthorizationSelectionInvalid,
	  "WARNING (AuthorizationSelectionInvalid)" },
	{ iso20_dc_responseCodeType_WARNING_CertificateExpired,
	  "WARNING (CertificateExpired)" },
	{ iso20_dc_responseCodeType_WARNING_CertificateNotYetValid,
	  "WARNING (CertificateNotYetValid)" },
	{ iso20_dc_responseCodeType_WARNING_CertificateRevoked,
	  "WARNING (CertificateRevoked)" },
	{ iso20_dc_responseCodeType_WARNING_CertificateValidationError,
	  "WARNING (CertificateValidationError)" },
	{ iso20_dc_responseCodeType_WARNING_ChallengeInvalid,
	  "WARNING (ChallengeInvalid)" },
	{ iso20_dc_responseCodeType_WARNING_EIMAuthorizationFailure,
	  "WARNING (EIMAuthorizationFailure)" },
	{ iso20_dc_responseCodeType_WARNING_eMSPUnknown,
	  "WARNING (eMSPUnknown)" },
	{ iso20_dc_responseCodeType_WARNING_EVPowerProfileViolation,
	  "WARNING (EVPowerProfileViolation)" },
	{ iso20_dc_responseCodeType_WARNING_GeneralPnCAuthorizationError,
	  "WARNING (GeneralPnCAuthorizationError)" },
	{ iso20_dc_responseCodeType_WARNING_NoCertificateAvailable,
	  "WARNING (NoCertificateAvailable)" },
	{ iso20_dc_responseCodeType_WARNING_NoContractMatchingPCIDFound,
	  "WARNING (NoContractMatchingPCIDFound)" },
	{ iso20_dc_responseCodeType_WARNING_PowerToleranceNotConfirmed,
	  "WARNING (PowerToleranceNotConfirmed)" },
	{ iso20_dc_responseCodeType_WARNING_ScheduleRenegotiationFailed,
	  "WARNING (ScheduleRenegotiationFailed)" },
	{ iso20_dc_responseCodeType_WARNING_StandbyNotAllowed,
	  "WARNING (StandbyNotAllowed)" },
	{ iso20_dc_responseCodeType_WARNING_WPT, "WARNING (WPT)" },
	{ iso20_dc_responseCodeType_FAILED, "FAILED" },
	{ iso20_dc_responseCodeType_FAILED_AssociationError,
	  "FAILED (AssociationError)" },
	{ iso20_dc_responseCodeType_FAILED_ContactorError,
	  "FAILED (ContactorError)" },
	{ iso20_dc_responseCodeType_FAILED_EVPowerProfileInvalid,
	  "FAILED (EVPowerProfileInvalid)" },
	{ iso20_dc_responseCodeType_FAILED_EVPowerProfileViolation,
	  "FAILED (EVPowerProfileViolation)" },
	{ iso20_dc_responseCodeType_FAILED_MeteringSignatureNotValid,
	  "FAILED (MeteringSignatureNotValid)" },
	{ iso20_dc_responseCodeType_FAILED_NoEnergyTransferServiceSelected,
	  "FAILED (NoEnergyTransferServiceSelected)" },
	{ iso20_dc_responseCodeType_FAILED_NoServiceRenegotiationSupported,
	  "FAILED (NoServiceRenegotiationSupported)" },
	{ iso20_dc_responseCodeType_FAILED_PauseNotAllowed,
	  "FAILED (PauseNotAllowed)" },
	{ iso20_dc_responseCodeType_FAILED_PowerDeliveryNotApplied,
	  "FAILED (PowerDeliveryNotApplied)" },
	{ iso20_dc_responseCodeType_FAILED_PowerToleranceNotConfirmed,
	  "FAILED (PowerToleranceNotConfirmed)" },
	{ iso20_dc_responseCodeType_FAILED_ScheduleRenegotiation,
	  "FAILED (ScheduleRenegotiation)" },
	{ iso20_dc_responseCodeType_FAILED_ScheduleSelectionInvalid,
	  "FAILED (ScheduleSelectionInvalid)" },
	{ iso20_dc_responseCodeType_FAILED_SequenceError,
	  "FAILED (SequenceError)" },
	{ iso20_dc_responseCodeType_FAILED_ServiceIDInvalid,
	  "FAILED (ServiceIDInvalid)" },
	{ iso20_dc_responseCodeType_FAILED_ServiceSelectionInvalid,
	  "FAILED (ServiceSelectionInvalid)" },
	{ iso20_dc_responseCodeType_FAILED_SignatureError,
	  "FAILED (SignatureError)" },
	{ iso20_dc_responseCodeType_FAILED_UnknownSession,
	  "FAILED (UnknownSession)" },
	{ iso20_dc_responseCodeType_FAILED_WrongChargeParameter,
	  "FAILED (WrongChargeParameter)" },
	{ 0, NULL }
};

static const value_string v2giso20_dc_enum_iso20_dc_processingType_names[] = {
	{ iso20_dc_processingType_Finished, "Finished" },
	{ iso20_dc_processingType_Ongoing, "Ongoing" },
	{ iso20_dc_processingType_Ongoing_WaitingForCustomerInteraction,
	  "WaitingForCustomerInteraction" },
	{ 0, NULL }
};

/* header node dissectors - each node is represented by a struct */
static void dissect_iso20_dc_SignatureType(
	const struct iso20_dc_SignatureType *node,
	tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
	gint idx, const char *subtree_name);
static void dissect_iso20_dc_SignatureValueType(
	const struct iso20_dc_SignatureValueType *node,
	tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
	gint idx, const char *subtree_name);
static void dissect_iso20_dc_SignedInfoType(
	const struct iso20_dc_SignedInfoType *node,
	tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
	gint idx, const char *subtree_name);
static void dissect_iso20_dc_CanonicalizationMethodType(
	const struct iso20_dc_CanonicalizationMethodType *node,
	tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
	gint idx, const char *subtree_name);
static void dissect_iso20_dc_SignatureMethodType(
	const struct iso20_dc_SignatureMethodType *node,
	tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
	gint idx, const char *subtree_name);
static void dissect_iso20_dc_ReferenceType(
	const struct iso20_dc_ReferenceType *node,
	tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
	gint idx, const char *subtree_name);
static void dissect_iso20_dc_TransformsType(
	const struct iso20_dc_TransformsType *node,
	tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
	gint idx, const char *subtree_name);
static void dissect_iso20_dc_TransformType(
	const struct iso20_dc_TransformType *node,
	tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
	gint idx, const char *subtree_name);
static void dissect_iso20_dc_DigestMethodType(
	const struct iso20_dc_DigestMethodType *node,
	tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
	gint idx, const char *subtree_name);
static void dissect_iso20_dc_KeyInfoType(
	const struct iso20_dc_KeyInfoType *node,
	tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
	gint idx, const char *subtree_name);
static void dissect_iso20_dc_KeyValueType(
	const struct iso20_dc_KeyValueType *node,
	tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
	gint idx, const char *subtree_name);
static void dissect_iso20_dc_RetrievalMethodType(
	const struct iso20_dc_RetrievalMethodType *node,
	tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
	gint idx, const char *subtree_name);
static void dissect_iso20_dc_X509DataType(
	const struct iso20_dc_X509DataType *node,
	tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
	gint idx, const char *subtree_name);
static void dissect_iso20_dc_PGPDataType(
	const struct iso20_dc_PGPDataType *node,
	tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
	gint idx, const char *subtree_name);
static void dissect_iso20_dc_SPKIDataType(
	const struct iso20_dc_SPKIDataType *node,
	tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
	gint idx, const char *subtree_name);
static void dissect_iso20_dc_ObjectType(
	const struct iso20_dc_ObjectType *node,
	tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
	gint idx, const char *subtree_name);
#ifdef notyet
static void dissect_iso20_dc_ManifestType(
	const struct iso20_dc_ManifestType *node,
	tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
	gint idx, const char *subtree_name);
#endif
#ifdef notyet
static void dissect_iso20_dc_SignaturePropertiesType(
	const struct iso20_dc_SignaturePropertiesType *node,
	tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
	gint idx, const char *subtree_name);
#endif
#ifdef notyet
static void dissect_iso20_dc_SignaturePropertyType(
	const struct iso20_dc_SignaturePropertyType *node,
	tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
	gint idx, const char *subtree_name);
#endif
static void dissect_iso20_dc_DSAKeyValueType(
	const struct iso20_dc_DSAKeyValueType *node,
	tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
	gint idx, const char *subtree_name);
static void dissect_iso20_dc_RSAKeyValueType(
	const struct iso20_dc_RSAKeyValueType *node,
	tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
	gint idx, const char *subtree_name);

static void dissect_iso20_dc_MessageHeaderType(
	const struct iso20_dc_MessageHeaderType *node,
	tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
	gint idx, const char *subtree_name);
static void dissect_iso20_dc_X509IssuerSerialType(
	const struct iso20_dc_X509IssuerSerialType *node,
	tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
	gint idx, const char *subtree_name);


static void
dissect_iso20_dc_SignatureType(
	const struct iso20_dc_SignatureType *node,
	tvbuff_t *tvb,
	packet_info *pinfo _U_,
	proto_tree *tree,
	gint idx,
	const char *subtree_name)
{
	proto_tree *subtree;

	subtree = proto_tree_add_subtree(tree,
		tvb, 0, 0, idx, NULL, subtree_name);

	if (node->Id_isUsed) {
		exi_add_characters(subtree,
			hf_struct_iso20_dc_SignatureType_Id,
			tvb,
			node->Id.characters,
			node->Id.charactersLen,
			sizeof(node->Id.characters));
	}

	dissect_iso20_dc_SignedInfoType(&node->SignedInfo,
		tvb, pinfo, subtree,
		ett_struct_iso20_dc_SignedInfoType, "SignedInfo");
	dissect_iso20_dc_SignatureValueType(&node->SignatureValue,
		tvb, pinfo, subtree,
		ett_struct_iso20_dc_SignatureValueType, "SignatureValue");

	if (node->KeyInfo_isUsed) {
		dissect_iso20_dc_KeyInfoType(&node->KeyInfo,
			tvb, pinfo, subtree,
			ett_struct_iso20_dc_KeyInfoType, "KeyInfo");
	}

	if (node->Object_isUsed) {
		dissect_iso20_dc_ObjectType(&node->Object,
			tvb, pinfo, subtree,
			ett_struct_iso20_dc_ObjectType, "Object");
	}

	return;
}

static void
dissect_iso20_dc_SignatureValueType(
	const struct iso20_dc_SignatureValueType *node,
	tvbuff_t *tvb,
	packet_info *pinfo _U_,
	proto_tree *tree,
	gint idx,
	const char *subtree_name)
{
	proto_tree *subtree;

	subtree = proto_tree_add_subtree(tree,
		tvb, 0, 0, idx, NULL, subtree_name);

	if (node->Id_isUsed) {
		exi_add_characters(subtree,
			hf_struct_iso20_dc_SignatureValueType_Id,
			tvb,
			node->Id.characters,
			node->Id.charactersLen,
			sizeof(node->Id.characters));
	}

	exi_add_bytes(subtree,
		hf_struct_iso20_dc_SignatureValueType_CONTENT,
		tvb,
		node->CONTENT.bytes,
		node->CONTENT.bytesLen,
		sizeof(node->CONTENT.bytes));

	return;
}

static void
dissect_iso20_dc_SignedInfoType(
	const struct iso20_dc_SignedInfoType *node,
	tvbuff_t *tvb,
	packet_info *pinfo _U_,
	proto_tree *tree,
	gint idx,
	const char *subtree_name)
{
	unsigned int i;
	proto_tree *subtree;
	proto_tree *reference_tree;

	subtree = proto_tree_add_subtree(tree,
		tvb, 0, 0, idx, NULL, subtree_name);

	if (node->Id_isUsed) {
		exi_add_characters(subtree,
			hf_struct_iso20_dc_SignedInfoType_Id,
			tvb,
			node->Id.characters,
			node->Id.charactersLen,
			sizeof(node->Id.characters));
	}

	dissect_iso20_dc_CanonicalizationMethodType(
		&node->CanonicalizationMethod,
		tvb, pinfo, subtree,
		ett_struct_iso20_dc_CanonicalizationMethodType,
		"CanonicalizationMethod");
	dissect_iso20_dc_SignatureMethodType(
		&node->SignatureMethod,
		tvb, pinfo, subtree,
		ett_struct_iso20_dc_SignatureMethodType,
		"SignatureMethod");

	reference_tree = proto_tree_add_subtree(subtree,
		tvb, 0, 0, ett_v2giso20_dc_array, NULL, "Reference");
	for (i = 0; i < node->Reference.arrayLen; i++) {
		char index[sizeof("[65536]")];

		snprintf(index, sizeof(index), "[%u]", i);
		dissect_iso20_dc_ReferenceType(&node->Reference.array[i],
			tvb, pinfo, reference_tree,
			ett_struct_iso20_dc_ReferenceType, index);
	}

	return;
}

static void
dissect_iso20_dc_CanonicalizationMethodType(
	const struct iso20_dc_CanonicalizationMethodType *node,
	tvbuff_t *tvb,
	packet_info *pinfo _U_,
	proto_tree *tree,
	gint idx,
	const char *subtree_name)
{
	proto_tree *subtree;

	subtree = proto_tree_add_subtree(tree,
		tvb, 0, 0, idx, NULL, subtree_name);

	exi_add_characters(subtree,
		hf_struct_iso20_dc_CanonicalizationMethodType_Algorithm,
		tvb,
		node->Algorithm.characters,
		node->Algorithm.charactersLen,
		sizeof(node->Algorithm.characters));

	if (node->ANY_isUsed) {
		exi_add_bytes(subtree,
			hf_struct_iso20_dc_CanonicalizationMethodType_ANY,
			tvb,
			node->ANY.bytes,
			node->ANY.bytesLen,
			sizeof(node->ANY.bytes));
	}

	return;
}

static void
dissect_iso20_dc_SignatureMethodType(
	const struct iso20_dc_SignatureMethodType *node,
	tvbuff_t *tvb,
	packet_info *pinfo _U_,
	proto_tree *tree,
	gint idx,
	const char *subtree_name)
{
	proto_tree *subtree;
	proto_item *it;

	subtree = proto_tree_add_subtree(tree,
		tvb, 0, 0, idx, NULL, subtree_name);

	exi_add_characters(subtree,
		hf_struct_iso20_dc_SignatureMethodType_Algorithm,
		tvb,
		node->Algorithm.characters,
		node->Algorithm.charactersLen,
		sizeof(node->Algorithm.characters));

	if (node->HMACOutputLength_isUsed) {
		it = proto_tree_add_int(subtree,
			hf_struct_iso20_dc_SignatureMethodType_HMACOutputLength,
			tvb, 0, 0, node->HMACOutputLength);
		proto_item_set_generated(it);
	}

	if (node->ANY_isUsed) {
		exi_add_bytes(subtree,
			hf_struct_iso20_dc_SignatureMethodType_ANY,
			tvb,
			node->ANY.bytes,
			node->ANY.bytesLen,
			sizeof(node->ANY.bytes));
	}

	return;
}

static void
dissect_iso20_dc_ReferenceType(
	const struct iso20_dc_ReferenceType *node,
	tvbuff_t *tvb,
	packet_info *pinfo _U_,
	proto_tree *tree,
	gint idx,
	const char *subtree_name)
{
	proto_tree *subtree;

	subtree = proto_tree_add_subtree(tree,
		tvb, 0, 0, idx, NULL, subtree_name);

	if (node->Id_isUsed) {
		exi_add_characters(subtree,
			hf_struct_iso20_dc_ReferenceType_Id,
			tvb,
			node->Id.characters,
			node->Id.charactersLen,
			sizeof(node->Id.characters));
	}
	if (node->Type_isUsed) {
		exi_add_characters(subtree,
			hf_struct_iso20_dc_ReferenceType_Type,
			tvb,
			node->Type.characters,
			node->Type.charactersLen,
			sizeof(node->Type.characters));
	}
	if (node->URI_isUsed) {
		exi_add_characters(subtree,
			hf_struct_iso20_dc_ReferenceType_URI,
			tvb,
			node->URI.characters,
			node->URI.charactersLen,
			sizeof(node->URI.characters));
	}
	if (node->Transforms_isUsed) {
		dissect_iso20_dc_TransformsType(&node->Transforms,
			tvb, pinfo, subtree,
			ett_struct_iso20_dc_TransformsType,
			"Transforms");
	}

	dissect_iso20_dc_DigestMethodType(&node->DigestMethod,
			tvb, pinfo, subtree,
			ett_struct_iso20_dc_DigestMethodType,
			"DigestMethod");

	exi_add_bytes(subtree,
		hf_struct_iso20_dc_ReferenceType_DigestValue,
		tvb,
		node->DigestValue.bytes,
		node->DigestValue.bytesLen,
		sizeof(node->DigestValue.bytes));

	return;
}

static void
dissect_iso20_dc_TransformsType(
	const struct iso20_dc_TransformsType *node,
	tvbuff_t *tvb,
	packet_info *pinfo _U_,
	proto_tree *tree,
	gint idx,
	const char *subtree_name)
{
	proto_tree *subtree;

	subtree = proto_tree_add_subtree(tree,
		tvb, 0, 0, idx, NULL, subtree_name);

	dissect_iso20_dc_TransformType(&node->Transform,
		tvb, pinfo, subtree,
		ett_struct_iso20_dc_TransformType, "Transform");

	return;
}

static void
dissect_iso20_dc_TransformType(
	const struct iso20_dc_TransformType *node,
	tvbuff_t *tvb,
	packet_info *pinfo _U_,
	proto_tree *tree,
	gint idx,
	const char *subtree_name)
{
	proto_tree *subtree;

	subtree = proto_tree_add_subtree(tree,
		tvb, 0, 0, idx, NULL, subtree_name);

	exi_add_characters(subtree,
		hf_struct_iso20_dc_TransformType_Algorithm,
		tvb,
		node->Algorithm.characters,
		node->Algorithm.charactersLen,
		sizeof(node->Algorithm.characters));

	if (node->ANY_isUsed) {
		exi_add_bytes(subtree,
			hf_struct_iso20_dc_TransformType_ANY,
			tvb,
			node->ANY.bytes,
			node->ANY.bytesLen,
			sizeof(node->ANY.bytes));
	}

	if (node->XPath_isUsed) {
		exi_add_characters(subtree,
			hf_struct_iso20_dc_TransformType_XPath,
			tvb,
			node->XPath.characters,
			node->XPath.charactersLen,
			sizeof(node->XPath.characters));
	}

	return;
}

static void
dissect_iso20_dc_DigestMethodType(
	const struct iso20_dc_DigestMethodType *node,
	tvbuff_t *tvb,
	packet_info *pinfo _U_,
	proto_tree *tree,
	gint idx,
	const char *subtree_name)
{
	proto_tree *subtree;

	subtree = proto_tree_add_subtree(tree,
		tvb, 0, 0, idx, NULL, subtree_name);

	exi_add_characters(subtree,
		hf_struct_iso20_dc_DigestMethodType_Algorithm,
		tvb,
		node->Algorithm.characters,
		node->Algorithm.charactersLen,
		sizeof(node->Algorithm.characters));

	if (node->ANY_isUsed) {
		exi_add_bytes(subtree,
			hf_struct_iso20_dc_DigestMethodType_ANY,
			tvb,
			node->ANY.bytes,
			node->ANY.bytesLen,
			sizeof(node->ANY.bytes));
	}

	return;
}

static void
dissect_iso20_dc_KeyInfoType(
	const struct iso20_dc_KeyInfoType *node,
	tvbuff_t *tvb,
	packet_info *pinfo _U_,
	proto_tree *tree,
	gint idx,
	const char *subtree_name)
{
	proto_tree *subtree;

	subtree = proto_tree_add_subtree(tree,
		tvb, 0, 0, idx, NULL, subtree_name);

	if (node->Id_isUsed) {
		exi_add_characters(subtree,
			hf_struct_iso20_dc_KeyInfoType_Id,
			tvb,
			node->Id.characters,
			node->Id.charactersLen,
			sizeof(node->Id.characters));
	}

	if (node->KeyName_isUsed) {
		exi_add_characters(subtree,
			hf_struct_iso20_dc_KeyInfoType_KeyName,
			tvb,
			node->KeyName.characters,
			node->KeyName.charactersLen,
			sizeof(node->KeyName.characters));
	}

	if (node->KeyValue_isUsed) {
		dissect_iso20_dc_KeyValueType(&node->KeyValue,
			tvb, pinfo, subtree,
			ett_struct_iso20_dc_KeyValueType,
			"KeyValue");
	}

	if (node->RetrievalMethod_isUsed) {
		dissect_iso20_dc_RetrievalMethodType(
			&node->RetrievalMethod,
			tvb, pinfo, subtree,
			ett_struct_iso20_dc_RetrievalMethodType,
			"RetrievalMethod");
	}

	if (node->X509Data_isUsed) {
		dissect_iso20_dc_X509DataType(&node->X509Data,
			tvb, pinfo, subtree,
			ett_struct_iso20_dc_X509DataType, "X509Data");
	}

	if (node->PGPData_isUsed) {
		dissect_iso20_dc_PGPDataType(&node->PGPData,
			tvb, pinfo, subtree,
			ett_struct_iso20_dc_PGPDataType, "PGPData");
	}

	if (node->SPKIData_isUsed) {
		dissect_iso20_dc_SPKIDataType(&node->SPKIData,
			tvb, pinfo, subtree,
			ett_struct_iso20_dc_SPKIDataType, "SPKIData");
	}

	if (node->MgmtData_isUsed) {
		exi_add_characters(subtree,
			hf_struct_iso20_dc_KeyInfoType_MgmtData,
			tvb,
			node->MgmtData.characters,
			node->MgmtData.charactersLen,
			sizeof(node->MgmtData.characters));
	}

	if (node->ANY_isUsed) {
		exi_add_bytes(subtree,
			hf_struct_iso20_dc_KeyInfoType_ANY,
			tvb,
			node->ANY.bytes,
			node->ANY.bytesLen,
			sizeof(node->ANY.bytes));
	}

	return;
}

static void
dissect_iso20_dc_KeyValueType(
	const struct iso20_dc_KeyValueType *node,
	tvbuff_t *tvb,
	packet_info *pinfo _U_,
	proto_tree *tree,
	gint idx,
	const char *subtree_name)
{
	proto_tree *subtree;

	subtree = proto_tree_add_subtree(tree,
		tvb, 0, 0, idx, NULL, subtree_name);

	if (node->DSAKeyValue_isUsed) {
		dissect_iso20_dc_DSAKeyValueType(&node->DSAKeyValue,
			tvb, pinfo, subtree,
			ett_struct_iso20_dc_DSAKeyValueType,
			"DSAKeyValue");
	}
	if (node->RSAKeyValue_isUsed) {
		dissect_iso20_dc_RSAKeyValueType(&node->RSAKeyValue,
			tvb, pinfo, subtree,
			ett_struct_iso20_dc_RSAKeyValueType,
			"RSAKeyValue");
	}

	exi_add_bytes(subtree,
		hf_struct_iso20_dc_KeyValueType_ANY,
		tvb,
		node->ANY.bytes,
		node->ANY.bytesLen,
		sizeof(node->ANY.bytes));

	return;
}

static void
dissect_iso20_dc_RetrievalMethodType(
	const struct iso20_dc_RetrievalMethodType *node,
	tvbuff_t *tvb,
	packet_info *pinfo _U_,
	proto_tree *tree,
	gint idx,
	const char *subtree_name)
{
	proto_tree *subtree;

	subtree = proto_tree_add_subtree(tree,
		tvb, 0, 0, idx, NULL, subtree_name);

	if (node->Type_isUsed) {
		exi_add_characters(subtree,
			hf_struct_iso20_dc_RetrievalMethodType_Type,
			tvb,
			node->Type.characters,
			node->Type.charactersLen,
			sizeof(node->Type.characters));
	}
	if (node->URI_isUsed) {
		exi_add_characters(subtree,
			hf_struct_iso20_dc_RetrievalMethodType_URI,
			tvb,
			node->URI.characters,
			node->URI.charactersLen,
			sizeof(node->URI.characters));
	}
	if (node->Transforms_isUsed) {
		dissect_iso20_dc_TransformsType(&node->Transforms,
			tvb, pinfo, subtree,
			ett_struct_iso20_dc_TransformsType,
			"Transforms");
	}

	return;
}

static void
dissect_iso20_dc_X509DataType(
	const struct iso20_dc_X509DataType *node,
	tvbuff_t *tvb,
	packet_info *pinfo _U_,
	proto_tree *tree,
	gint idx,
	const char *subtree_name)
{
	proto_tree *subtree;

	subtree = proto_tree_add_subtree(tree,
		tvb, 0, 0, idx, NULL, subtree_name);

	if (node->X509IssuerSerial_isUsed) {
		dissect_iso20_dc_X509IssuerSerialType(
			&node->X509IssuerSerial,
			tvb, pinfo, subtree,
			ett_struct_iso20_dc_X509IssuerSerialType,
			"X509IssuerSerial");
	}
	if (node->X509SKI_isUsed) {
		exi_add_bytes(subtree,
			hf_struct_iso20_dc_X509DataType_X509SKI,
			tvb,
			node->X509SKI.bytes,
			node->X509SKI.bytesLen,
			sizeof(node->X509SKI.bytes));
	}
	if (node->X509SubjectName_isUsed) {
		exi_add_characters(subtree,
			hf_struct_iso20_dc_X509DataType_X509SubjectName,
			tvb,
			node->X509SubjectName.characters,
			node->X509SubjectName.charactersLen,
			sizeof(node->X509SubjectName.characters));
	}

	if (node->X509Certificate_isUsed) {
		if (v2gber_handle == NULL) {
			exi_add_bytes(subtree,
				hf_struct_iso20_dc_X509DataType_X509Certificate,
				tvb,
				node->X509Certificate.bytes,
				node->X509Certificate.bytesLen,
				sizeof(node->X509Certificate.bytes));
		} else {
			tvbuff_t *child;
			proto_tree *asn1_tree;

			child = tvb_new_child_real_data(tvb,
				node->X509Certificate.bytes,
				sizeof(node->X509Certificate.bytes),
				node->X509Certificate.bytesLen);

			asn1_tree = proto_tree_add_subtree(subtree,
				child, 0, tvb_reported_length(child),
				ett_v2giso20_dc_asn1, NULL,
				"X509Certificate ASN1");
			call_dissector(v2gber_handle, child, pinfo, asn1_tree);
		}
	}

	if (node->X509CRL_isUsed) {
		exi_add_bytes(subtree,
			hf_struct_iso20_dc_X509DataType_X509CRL,
			tvb,
			node->X509CRL.bytes,
			node->X509CRL.bytesLen,
			sizeof(node->X509CRL.bytes));
	}

	if (node->ANY_isUsed) {
		exi_add_bytes(subtree,
			hf_struct_iso20_dc_X509DataType_ANY,
			tvb,
			node->ANY.bytes,
			node->ANY.bytesLen,
			sizeof(node->ANY.bytes));
	}

	return;
}

static void
dissect_iso20_dc_PGPDataType(
	const struct iso20_dc_PGPDataType *node,
	tvbuff_t *tvb,
	packet_info *pinfo _U_,
	proto_tree *tree,
	gint idx,
	const char *subtree_name)
{
	proto_tree *subtree;

	subtree = proto_tree_add_subtree(tree,
		tvb, 0, 0, idx, NULL, subtree_name);

	if (node->choice_1_isUsed) {
		exi_add_bytes(subtree,
			hf_struct_iso20_dc_PGPDataType_PGPKeyID,
			tvb,
			node->choice_1.PGPKeyID.bytes,
			node->choice_1.PGPKeyID.bytesLen,
			sizeof(node->choice_1.PGPKeyID.bytes));

		if (node->choice_1.PGPKeyPacket_isUsed) {
			exi_add_bytes(subtree,
				hf_struct_iso20_dc_PGPDataType_PGPKeyPacket,
				tvb,
				node->choice_1.PGPKeyPacket.bytes,
				node->choice_1.PGPKeyPacket.bytesLen,
				sizeof(node->choice_1.PGPKeyPacket.bytes));
		}

		if (node->choice_1.ANY_isUsed) {
			exi_add_bytes(subtree,
				hf_struct_iso20_dc_PGPDataType_ANY,
				tvb,
				node->choice_1.ANY.bytes,
				node->choice_1.ANY.bytesLen,
				sizeof(node->choice_1.ANY.bytes));
		}
	}

	if (node->choice_2_isUsed) {
		exi_add_bytes(subtree,
			hf_struct_iso20_dc_PGPDataType_PGPKeyPacket,
			tvb,
			node->choice_2.PGPKeyPacket.bytes,
			node->choice_2.PGPKeyPacket.bytesLen,
			sizeof(node->choice_2.PGPKeyPacket.bytes));

		if (node->choice_2.ANY_isUsed) {
			exi_add_bytes(subtree,
				hf_struct_iso20_dc_PGPDataType_ANY,
				tvb,
				node->choice_2.ANY.bytes,
				node->choice_2.ANY.bytesLen,
				sizeof(node->choice_2.ANY.bytes));
		}
	}

	return;
}

static void
dissect_iso20_dc_SPKIDataType(
	const struct iso20_dc_SPKIDataType *node,
	tvbuff_t *tvb,
	packet_info *pinfo _U_,
	proto_tree *tree,
	gint idx,
	const char *subtree_name)
{
	proto_tree *subtree;

	subtree = proto_tree_add_subtree(tree,
		tvb, 0, 0, idx, NULL, subtree_name);

	exi_add_bytes(subtree,
		hf_struct_iso20_dc_SPKIDataType_SPKISexp,
		tvb,
		node->SPKISexp.bytes,
		node->SPKISexp.bytesLen,
		sizeof(node->SPKISexp.bytes));

	if (node->ANY_isUsed) {
		exi_add_bytes(subtree,
			hf_struct_iso20_dc_SPKIDataType_ANY,
			tvb,
			node->ANY.bytes,
			node->ANY.bytesLen,
			sizeof(node->ANY.bytes));
	}

	return;
}

static void
dissect_iso20_dc_ObjectType(
	const struct iso20_dc_ObjectType *node,
	tvbuff_t *tvb,
	packet_info *pinfo _U_,
	proto_tree *tree,
	gint idx,
	const char *subtree_name)
{
	proto_tree *subtree;

	subtree = proto_tree_add_subtree(tree,
		tvb, 0, 0, idx, NULL, subtree_name);

	if (node->Id_isUsed) {
		exi_add_characters(subtree,
			hf_struct_iso20_dc_ObjectType_Id,
			tvb,
			node->Id.characters,
			node->Id.charactersLen,
			sizeof(node->Id.characters));
	}
	if (node->MimeType_isUsed) {
		exi_add_characters(subtree,
			hf_struct_iso20_dc_ObjectType_MimeType,
			tvb,
			node->MimeType.characters,
			node->MimeType.charactersLen,
			sizeof(node->MimeType.characters));
	}
	if (node->Encoding_isUsed) {
		exi_add_characters(subtree,
			hf_struct_iso20_dc_ObjectType_Encoding,
			tvb,
			node->Encoding.characters,
			node->Encoding.charactersLen,
			sizeof(node->Encoding.characters));
	}
	if (node->ANY_isUsed) {
		exi_add_bytes(subtree,
			hf_struct_iso20_dc_ObjectType_ANY,
			tvb,
			node->ANY.bytes,
			node->ANY.bytesLen,
			sizeof(node->ANY.bytes));
	}

	return;
}

static void
dissect_iso20_dc_DSAKeyValueType(
	const struct iso20_dc_DSAKeyValueType *node,
	tvbuff_t *tvb,
	packet_info *pinfo _U_,
	proto_tree *tree,
	gint idx,
	const char *subtree_name)
{
	proto_tree *subtree;

	subtree = proto_tree_add_subtree(tree,
		tvb, 0, 0, idx, NULL, subtree_name);

	if (node->P_isUsed) {
		exi_add_bytes(subtree,
			hf_struct_iso20_dc_DSAKeyValueType_P,
			tvb,
			node->P.bytes,
			node->P.bytesLen,
			sizeof(node->P.bytes));
	}
	if (node->Q_isUsed) {
		exi_add_bytes(subtree,
			hf_struct_iso20_dc_DSAKeyValueType_Q,
			tvb,
			node->Q.bytes,
			node->Q.bytesLen,
			sizeof(node->Q.bytes));
	}
	if (node->G_isUsed) {
		exi_add_bytes(subtree,
			hf_struct_iso20_dc_DSAKeyValueType_G,
			tvb,
			node->G.bytes,
			node->G.bytesLen,
			sizeof(node->G.bytes));
	}
	exi_add_bytes(subtree,
		hf_struct_iso20_dc_DSAKeyValueType_Y,
		tvb,
		node->Y.bytes,
		node->Y.bytesLen,
		sizeof(node->Y.bytes));
	if (node->J_isUsed) {
		exi_add_bytes(subtree,
			hf_struct_iso20_dc_DSAKeyValueType_J,
			tvb,
			node->J.bytes,
			node->J.bytesLen,
			sizeof(node->J.bytes));
	}
	if (node->Seed_isUsed) {
		exi_add_bytes(subtree,
			hf_struct_iso20_dc_DSAKeyValueType_Seed,
			tvb,
			node->Seed.bytes,
			node->Seed.bytesLen,
			sizeof(node->Seed.bytes));
	}
	if (node->PgenCounter_isUsed) {
		exi_add_bytes(subtree,
			hf_struct_iso20_dc_DSAKeyValueType_PgenCounter,
			tvb,
			node->PgenCounter.bytes,
			node->PgenCounter.bytesLen,
			sizeof(node->PgenCounter.bytes));
	}

	return;
}

static void
dissect_iso20_dc_RSAKeyValueType(
	const struct iso20_dc_RSAKeyValueType *node,
	tvbuff_t *tvb,
	packet_info *pinfo _U_,
	proto_tree *tree,
	gint idx,
	const char *subtree_name)
{
	proto_tree *subtree;

	subtree = proto_tree_add_subtree(tree,
		tvb, 0, 0, idx, NULL, subtree_name);

	exi_add_bytes(subtree,
		hf_struct_iso20_dc_RSAKeyValueType_Modulus,
		tvb,
		node->Modulus.bytes,
		node->Modulus.bytesLen,
		sizeof(node->Modulus.bytes));

	exi_add_bytes(subtree,
		hf_struct_iso20_dc_RSAKeyValueType_Exponent,
		tvb,
		node->Exponent.bytes,
		node->Exponent.bytesLen,
		sizeof(node->Exponent.bytes));

	return;
}


static void
dissect_iso20_dc_MessageHeaderType(
	const struct iso20_dc_MessageHeaderType *node,
	tvbuff_t *tvb,
	packet_info *pinfo,
	proto_tree *tree,
	gint idx,
	const char *subtree_name)
{
	proto_tree *subtree;
	proto_item *it;

	subtree = proto_tree_add_subtree(tree,
		tvb, 0, 0, idx, NULL, subtree_name);

	exi_add_bytes(subtree,
		hf_struct_iso20_dc_MessageHeaderType_SessionID,
		tvb,
		node->SessionID.bytes,
		node->SessionID.bytesLen,
		sizeof(node->SessionID.bytes));

	it = proto_tree_add_uint64(subtree,
		hf_struct_iso20_dc_MessageHeaderType_TimeStamp,
		tvb, 0, 0, node->TimeStamp);
	proto_item_set_generated(it);

	if (node->Signature_isUsed) {
		dissect_iso20_dc_SignatureType(
			&node->Signature, tvb, pinfo, subtree,
			ett_struct_iso20_dc_SignatureType,
			"Signature");
	}

	return;
}

static void
dissect_iso20_dc_X509IssuerSerialType(
	const struct iso20_dc_X509IssuerSerialType *node,
	tvbuff_t *tvb,
	packet_info *pinfo _U_,
	proto_tree *tree,
	gint idx,
	const char *subtree_name)
{
	proto_tree *subtree;
	proto_item *it;

	subtree = proto_tree_add_subtree(tree,
		tvb, 0, 0, idx, NULL, subtree_name);

	exi_add_characters(subtree,
		hf_struct_iso20_dc_X509IssuerSerialType_X509IssuerName,
		tvb,
		node->X509IssuerName.characters,
		node->X509IssuerName.charactersLen,
		sizeof(node->X509IssuerName.characters));

	it = proto_tree_add_int64(subtree,
		hf_struct_iso20_dc_X509IssuerSerialType_X509SerialNumber,
		tvb, 0, 0, node->X509SerialNumber);
	proto_item_set_generated(it);

	return;
}


/* other node dissectors - each node is represented by a struct */
static void dissect_iso20_dc_DC_CPDReqEnergyTransferModeType(
	const struct iso20_dc_DC_CPDReqEnergyTransferModeType *node,
	tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
	gint idx, const char *subtree_name);
static void dissect_iso20_dc_DC_CPDResEnergyTransferModeType(
	const struct iso20_dc_DC_CPDResEnergyTransferModeType *node,
	tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
	gint idx, const char *subtree_name);
static void dissect_iso20_dc_BPT_DC_CPDReqEnergyTransferModeType(
	const struct iso20_dc_BPT_DC_CPDReqEnergyTransferModeType *node,
	tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
	gint idx, const char *subtree_name);
static void dissect_iso20_dc_BPT_DC_CPDResEnergyTransferModeType(
	const struct iso20_dc_BPT_DC_CPDResEnergyTransferModeType *node,
	tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
	gint idx, const char *subtree_name);
static void dissect_iso20_dc_Scheduled_DC_CLReqControlModeType(
	const struct iso20_dc_Scheduled_DC_CLReqControlModeType *node,
	tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
	gint idx, const char *subtree_name);
static void dissect_iso20_dc_Scheduled_DC_CLResControlModeType(
	const struct iso20_dc_Scheduled_DC_CLResControlModeType *node,
	tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
	gint idx, const char *subtree_name);
static void dissect_iso20_dc_BPT_Scheduled_DC_CLReqControlModeType(
	const struct iso20_dc_BPT_Scheduled_DC_CLReqControlModeType *node,
	tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
	gint idx, const char *subtree_name);
static void dissect_iso20_dc_BPT_Scheduled_DC_CLResControlModeType(
	const struct iso20_dc_BPT_Scheduled_DC_CLResControlModeType *node,
	tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
	gint idx, const char *subtree_name);
static void dissect_iso20_dc_Dynamic_DC_CLReqControlModeType(
	const struct iso20_dc_Dynamic_DC_CLReqControlModeType *node,
	tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
	gint idx, const char *subtree_name);
static void dissect_iso20_dc_Dynamic_DC_CLResControlModeType(
	const struct iso20_dc_Dynamic_DC_CLResControlModeType *node,
	tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
	gint idx, const char *subtree_name);
static void dissect_iso20_dc_BPT_Dynamic_DC_CLReqControlModeType(
	const struct iso20_dc_BPT_Dynamic_DC_CLReqControlModeType *node,
	tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
	gint idx, const char *subtree_name);
static void dissect_iso20_dc_BPT_Dynamic_DC_CLResControlModeType(
	const struct iso20_dc_BPT_Dynamic_DC_CLResControlModeType *node,
	tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
	gint idx, const char *subtree_name);
static void dissect_iso20_dc_CLReqControlModeType(
	const struct iso20_dc_CLReqControlModeType *node,
	tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
	gint idx, const char *subtree_name);
static void dissect_iso20_dc_CLResControlModeType(
	const struct iso20_dc_CLResControlModeType *node,
	tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
	gint idx, const char *subtree_name);
static void dissect_iso20_dc_RationalNumberType(
	const struct iso20_dc_RationalNumberType *node,
	tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
	gint idx, const char *subtree_name);


static void
dissect_iso20_dc_DC_CPDReqEnergyTransferModeType(
	const struct iso20_dc_DC_CPDReqEnergyTransferModeType *node _U_,
	tvbuff_t *tvb _U_,
	packet_info *pinfo _U_,
	proto_tree *tree _U_,
	gint idx _U_,
	const char *subtree_name _U_)
{
	proto_tree *subtree;
	proto_item *it;

	subtree = proto_tree_add_subtree(tree,
		tvb, 0, 0, idx, NULL, subtree_name);

	dissect_iso20_dc_RationalNumberType(&node->EVMaximumChargePower,
		tvb, pinfo, subtree,
		ett_struct_iso20_dc_RationalNumberType,
		"EVMaximumChargePower");

	dissect_iso20_dc_RationalNumberType(&node->EVMinimumChargePower,
		tvb, pinfo, subtree,
		ett_struct_iso20_dc_RationalNumberType,
		"EVMinimumChargePower");

	dissect_iso20_dc_RationalNumberType(&node->EVMaximumChargeCurrent,
		tvb, pinfo, subtree,
		ett_struct_iso20_dc_RationalNumberType,
		"EVMaximumChargeCurrent");

	dissect_iso20_dc_RationalNumberType(&node->EVMinimumChargeCurrent,
		tvb, pinfo, subtree,
		ett_struct_iso20_dc_RationalNumberType,
		"EVMinimumChargeCurrent");

	dissect_iso20_dc_RationalNumberType(&node->EVMaximumVoltage,
		tvb, pinfo, subtree,
		ett_struct_iso20_dc_RationalNumberType,
		"EVMaximumVoltage");

	dissect_iso20_dc_RationalNumberType(&node->EVMinimumVoltage,
		tvb, pinfo, subtree,
		ett_struct_iso20_dc_RationalNumberType,
		"EVMinimumVoltage");

	if (node->TargetSOC_isUsed) {
		it = proto_tree_add_int(subtree,
			hf_struct_iso20_dc_DC_CPDReqEnergyTransferModeType_TargetSOC,
			tvb, 0, 0, node->TargetSOC);
		proto_item_set_generated(it);
	}

	return;
}

static void
dissect_iso20_dc_DC_CPDResEnergyTransferModeType(
	const struct iso20_dc_DC_CPDResEnergyTransferModeType *node,
	tvbuff_t *tvb,
	packet_info *pinfo,
	proto_tree *tree,
	gint idx,
	const char *subtree_name)
{
	proto_tree *subtree;

	subtree = proto_tree_add_subtree(tree,
		tvb, 0, 0, idx, NULL, subtree_name);

	dissect_iso20_dc_RationalNumberType(&node->EVSEMaximumChargePower,
		tvb, pinfo, subtree,
		ett_struct_iso20_dc_RationalNumberType,
		"EVSEMaximumChargePower");

	dissect_iso20_dc_RationalNumberType(&node->EVSEMinimumChargePower,
		tvb, pinfo, subtree,
		ett_struct_iso20_dc_RationalNumberType,
		"EVSEMinimumChargePower");

	dissect_iso20_dc_RationalNumberType(&node->EVSEMaximumChargeCurrent,
		tvb, pinfo, subtree,
		ett_struct_iso20_dc_RationalNumberType,
		"EVSEMaximumChargeCurrent");

	dissect_iso20_dc_RationalNumberType(&node->EVSEMinimumChargeCurrent,
		tvb, pinfo, subtree,
		ett_struct_iso20_dc_RationalNumberType,
		"EVSEMinimumChargeCurrent");

	dissect_iso20_dc_RationalNumberType(&node->EVSEMaximumVoltage,
		tvb, pinfo, subtree,
		ett_struct_iso20_dc_RationalNumberType,
		"EVSEMaximumVoltage");

	dissect_iso20_dc_RationalNumberType(&node->EVSEMinimumVoltage,
		tvb, pinfo, subtree,
		ett_struct_iso20_dc_RationalNumberType,
		"EVSEMinimumVoltage");

	if (node->EVSEPowerRampLimitation_isUsed) {
		dissect_iso20_dc_RationalNumberType(
			&node->EVSEPowerRampLimitation,
			tvb, pinfo, subtree,
			ett_struct_iso20_dc_RationalNumberType,
			"EVSEPowerRampLimitation");
	}

	return;
}

static void
dissect_iso20_dc_BPT_DC_CPDReqEnergyTransferModeType(
	const struct iso20_dc_BPT_DC_CPDReqEnergyTransferModeType *node,
	tvbuff_t *tvb,
	packet_info *pinfo,
	proto_tree *tree,
	gint idx,
	const char *subtree_name)
{
	proto_tree *subtree;
	proto_item *it;

	subtree = proto_tree_add_subtree(tree,
		tvb, 0, 0, idx, NULL, subtree_name);

	dissect_iso20_dc_RationalNumberType(&node->EVMaximumChargePower,
		tvb, pinfo, subtree,
		ett_struct_iso20_dc_RationalNumberType,
		"EVMaximumChargePower");

	dissect_iso20_dc_RationalNumberType(&node->EVMinimumChargePower,
		tvb, pinfo, subtree,
		ett_struct_iso20_dc_RationalNumberType,
		"EVMinimumChargePower");

	dissect_iso20_dc_RationalNumberType(&node->EVMaximumChargeCurrent,
		tvb, pinfo, subtree,
		ett_struct_iso20_dc_RationalNumberType,
		"EVMaximumChargeCurrent");

	dissect_iso20_dc_RationalNumberType(&node->EVMinimumChargeCurrent,
		tvb, pinfo, subtree,
		ett_struct_iso20_dc_RationalNumberType,
		"EVMinimumChargeCurrent");

	dissect_iso20_dc_RationalNumberType(&node->EVMaximumVoltage,
		tvb, pinfo, subtree,
		ett_struct_iso20_dc_RationalNumberType,
		"EVMaximumVoltage");

	dissect_iso20_dc_RationalNumberType(&node->EVMinimumVoltage,
		tvb, pinfo, subtree,
		ett_struct_iso20_dc_RationalNumberType,
		"EVMinimumVoltage");

	if (node->TargetSOC_isUsed) {
		it = proto_tree_add_int(subtree,
			hf_struct_iso20_dc_BPT_DC_CPDReqEnergyTransferModeType_TargetSOC,
			tvb, 0, 0, node->TargetSOC);
		proto_item_set_generated(it);
	}

	dissect_iso20_dc_RationalNumberType(&node->EVMaximumDischargePower,
		tvb, pinfo, subtree,
		ett_struct_iso20_dc_RationalNumberType,
		"EVMaximumDischargePower");

	dissect_iso20_dc_RationalNumberType(&node->EVMinimumDischargePower,
		tvb, pinfo, subtree,
		ett_struct_iso20_dc_RationalNumberType,
		"EVMinimumDischargePower");

	dissect_iso20_dc_RationalNumberType(&node->EVMaximumDischargeCurrent,
		tvb, pinfo, subtree,
		ett_struct_iso20_dc_RationalNumberType,
		"EVMaximumDischargeCurrent");

	dissect_iso20_dc_RationalNumberType(&node->EVMinimumDischargeCurrent,
		tvb, pinfo, subtree,
		ett_struct_iso20_dc_RationalNumberType,
		"EVMinimumDischargeCurrent");

	return;
}

static void
dissect_iso20_dc_BPT_DC_CPDResEnergyTransferModeType(
	const struct iso20_dc_BPT_DC_CPDResEnergyTransferModeType *node,
	tvbuff_t *tvb,
	packet_info *pinfo,
	proto_tree *tree,
	gint idx,
	const char *subtree_name)
{
	proto_tree *subtree;

	subtree = proto_tree_add_subtree(tree,
		tvb, 0, 0, idx, NULL, subtree_name);

	dissect_iso20_dc_RationalNumberType(&node->EVSEMaximumChargePower,
		tvb, pinfo, subtree,
		ett_struct_iso20_dc_RationalNumberType,
		"EVSEMaximumChargePower");

	dissect_iso20_dc_RationalNumberType(&node->EVSEMinimumChargePower,
		tvb, pinfo, subtree,
		ett_struct_iso20_dc_RationalNumberType,
		"EVSEMinimumChargePower");

	dissect_iso20_dc_RationalNumberType(&node->EVSEMaximumChargeCurrent,
		tvb, pinfo, subtree,
		ett_struct_iso20_dc_RationalNumberType,
		"EVSEMaximumChargeCurrent");

	dissect_iso20_dc_RationalNumberType(&node->EVSEMinimumChargeCurrent,
		tvb, pinfo, subtree,
		ett_struct_iso20_dc_RationalNumberType,
		"EVSEMinimumChargeCurrent");

	dissect_iso20_dc_RationalNumberType(&node->EVSEMaximumVoltage,
		tvb, pinfo, subtree,
		ett_struct_iso20_dc_RationalNumberType,
		"EVSEMaximumVoltage");

	dissect_iso20_dc_RationalNumberType(&node->EVSEMinimumVoltage,
		tvb, pinfo, subtree,
		ett_struct_iso20_dc_RationalNumberType,
		"EVSEMinimumVoltage");

	if (node->EVSEPowerRampLimitation_isUsed) {
		dissect_iso20_dc_RationalNumberType(
			&node->EVSEPowerRampLimitation,
			tvb, pinfo, subtree,
			ett_struct_iso20_dc_RationalNumberType,
			"EVSEPowerRampLimitation");
	}

	dissect_iso20_dc_RationalNumberType(&node->EVSEMaximumDischargePower,
		tvb, pinfo, subtree,
		ett_struct_iso20_dc_RationalNumberType,
		"EVSEMaximumDischargePower");

	dissect_iso20_dc_RationalNumberType(&node->EVSEMinimumDischargePower,
		tvb, pinfo, subtree,
		ett_struct_iso20_dc_RationalNumberType,
		"EVSEMinimumDischargePower");

	dissect_iso20_dc_RationalNumberType(&node->EVSEMaximumDischargeCurrent,
		tvb, pinfo, subtree,
		ett_struct_iso20_dc_RationalNumberType,
		"EVSEMaximumDischargeCurrent");

	dissect_iso20_dc_RationalNumberType(&node->EVSEMinimumDischargeCurrent,
		tvb, pinfo, subtree,
		ett_struct_iso20_dc_RationalNumberType,
		"EVSEMinimumDischargeCurrent");

	return;
}

static void
dissect_iso20_dc_Scheduled_DC_CLReqControlModeType(
	const struct iso20_dc_Scheduled_DC_CLReqControlModeType *node,
	tvbuff_t *tvb,
	packet_info *pinfo,
	proto_tree *tree,
	gint idx,
	const char *subtree_name)
{
	proto_tree *subtree;

	subtree = proto_tree_add_subtree(tree,
		tvb, 0, 0, idx, NULL, subtree_name);

	if (node->EVTargetEnergyRequest_isUsed) {
		dissect_iso20_dc_RationalNumberType(
			&node->EVTargetEnergyRequest,
			tvb, pinfo, subtree,
			ett_struct_iso20_dc_RationalNumberType,
			"EVTargetEnergyRequest");
	}
	if (node->EVMaximumEnergyRequest_isUsed) {
		dissect_iso20_dc_RationalNumberType(
			&node->EVMaximumEnergyRequest,
			tvb, pinfo, subtree,
			ett_struct_iso20_dc_RationalNumberType,
			"EVMaximumEnergyRequest");
	}
	if (node->EVMaximumEnergyRequest_isUsed) {
		dissect_iso20_dc_RationalNumberType(
			&node->EVMaximumEnergyRequest,
			tvb, pinfo, subtree,
			ett_struct_iso20_dc_RationalNumberType,
			"EVMaximumEnergyRequest");
	}

	dissect_iso20_dc_RationalNumberType(&node->EVTargetCurrent,
		tvb, pinfo, subtree,
		ett_struct_iso20_dc_RationalNumberType,
		"EVTargetCurrent");

	dissect_iso20_dc_RationalNumberType(&node->EVTargetVoltage,
		tvb, pinfo, subtree,
		ett_struct_iso20_dc_RationalNumberType,
		"EVTargetVoltage");

	if (node->EVMaximumChargePower_isUsed) {
		dissect_iso20_dc_RationalNumberType(
			&node->EVMaximumChargePower,
			tvb, pinfo, subtree,
			ett_struct_iso20_dc_RationalNumberType,
			"EVMaximumChargePower");
	}
	if (node->EVMinimumChargePower_isUsed) {
		dissect_iso20_dc_RationalNumberType(
			&node->EVMinimumChargePower,
			tvb, pinfo, subtree,
			ett_struct_iso20_dc_RationalNumberType,
			"EVMinimumChargePower");
	}
	if (node->EVMaximumChargeCurrent_isUsed) {
		dissect_iso20_dc_RationalNumberType(
			&node->EVMaximumChargeCurrent,
			tvb, pinfo, subtree,
			ett_struct_iso20_dc_RationalNumberType,
			"EVMaximumChargeCurrent");
	}
	if (node->EVMaximumVoltage_isUsed) {
		dissect_iso20_dc_RationalNumberType(
			&node->EVMaximumVoltage,
			tvb, pinfo, subtree,
			ett_struct_iso20_dc_RationalNumberType,
			"EVMaximumVoltage");
	}
	if (node->EVMinimumVoltage_isUsed) {
		dissect_iso20_dc_RationalNumberType(
			&node->EVMinimumVoltage,
			tvb, pinfo, subtree,
			ett_struct_iso20_dc_RationalNumberType,
			"EVMinimumVoltage");
	}

	return;
}

static void
dissect_iso20_dc_Scheduled_DC_CLResControlModeType(
	const struct iso20_dc_Scheduled_DC_CLResControlModeType *node _U_,
	tvbuff_t *tvb _U_,
	packet_info *pinfo _U_,
	proto_tree *tree _U_,
	gint idx _U_,
	const char *subtree_name _U_)
{
	proto_tree *subtree;

	subtree = proto_tree_add_subtree(tree,
		tvb, 0, 0, idx, NULL, subtree_name);

	if (node->EVSEMaximumChargePower_isUsed) {
		dissect_iso20_dc_RationalNumberType(
			&node->EVSEMaximumChargePower,
			tvb, pinfo, subtree,
			ett_struct_iso20_dc_RationalNumberType,
			"EVSEMaximumChargePower");
	}
	if (node->EVSEMinimumChargePower_isUsed) {
		dissect_iso20_dc_RationalNumberType(
			&node->EVSEMinimumChargePower,
			tvb, pinfo, subtree,
			ett_struct_iso20_dc_RationalNumberType,
			"EVSEMinimumChargePower");
	}
	if (node->EVSEMaximumChargeCurrent_isUsed) {
		dissect_iso20_dc_RationalNumberType(
			&node->EVSEMaximumChargeCurrent,
			tvb, pinfo, subtree,
			ett_struct_iso20_dc_RationalNumberType,
			"EVSEMaximumChargeCurrent");
	}
	if (node->EVSEMaximumVoltage_isUsed) {
		dissect_iso20_dc_RationalNumberType(
			&node->EVSEMaximumVoltage,
			tvb, pinfo, subtree,
			ett_struct_iso20_dc_RationalNumberType,
			"EVSEMaximumVoltage");
	}

	return;
}

static void
dissect_iso20_dc_BPT_Scheduled_DC_CLReqControlModeType(
	const struct iso20_dc_BPT_Scheduled_DC_CLReqControlModeType *node _U_,
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
	const struct iso20_dc_BPT_Scheduled_DC_CLResControlModeType *node _U_,
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
	const struct iso20_dc_Dynamic_DC_CLReqControlModeType *node _U_,
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
	const struct iso20_dc_Dynamic_DC_CLResControlModeType *node _U_,
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
	const struct iso20_dc_BPT_Dynamic_DC_CLReqControlModeType *node _U_,
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
	const struct iso20_dc_BPT_Dynamic_DC_CLResControlModeType *node _U_,
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
	const struct iso20_dc_CLReqControlModeType *node _U_,
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
	const struct iso20_dc_CLResControlModeType *node _U_,
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
dissect_iso20_dc_DisplayParametersType(
	const struct iso20_dc_DisplayParametersType *node _U_,
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
dissect_iso20_dc_EVSEStatusType(
	const struct iso20_dc_EVSEStatusType *node _U_,
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
dissect_iso20_dc_MeterInfoType(
	const struct iso20_dc_MeterInfoType *node _U_,
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
dissect_iso20_dc_ReceiptType(
	const struct iso20_dc_ReceiptType *node _U_,
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
dissect_iso20_dc_RationalNumberType(
	const struct iso20_dc_RationalNumberType *node,
	tvbuff_t *tvb,
	packet_info *pinfo _U_,
	proto_tree *tree,
	gint idx,
	const char *subtree_name)
{
	proto_tree *subtree;
	proto_item *it;

	subtree = proto_tree_add_subtree(tree, tvb, 0, 0,
		idx, NULL, subtree_name);

	it = proto_tree_add_int(subtree,
		hf_struct_iso20_dc_RationalNumberType_Exponent,
		tvb, 0, 0, node->Exponent);
	proto_item_set_generated(it);

	it = proto_tree_add_int(subtree,
		hf_struct_iso20_dc_RationalNumberType_Value,
		tvb, 0, 0, node->Value);
	proto_item_set_generated(it);

	return;
}


/* request/response dissectors */
static void
dissect_iso20_dc_DC_ChargeParameterDiscoveryReqType(
	const struct iso20_dc_DC_ChargeParameterDiscoveryReqType *req,
	tvbuff_t *tvb,
	packet_info *pinfo,
	proto_tree *tree,
	gint idx,
	const char *subtree_name)
{
	proto_tree *subtree;

	subtree = proto_tree_add_subtree(tree,
		tvb, 0, 0, idx, NULL, subtree_name);

	dissect_iso20_dc_MessageHeaderType(&req->Header,
		tvb, pinfo, subtree,
		ett_struct_iso20_dc_MessageHeaderType, "Header");

	if (req->BPT_DC_CPDReqEnergyTransferMode_isUsed) {
		dissect_iso20_dc_BPT_DC_CPDReqEnergyTransferModeType(
			&req->BPT_DC_CPDReqEnergyTransferMode,
			tvb, pinfo, subtree,
			ett_struct_iso20_dc_BPT_DC_CPDReqEnergyTransferModeType,
			"BPT_DC_CPDReqEnergyTransferMode");
	}
	if (req->DC_CPDReqEnergyTransferMode_isUsed) {
		dissect_iso20_dc_DC_CPDReqEnergyTransferModeType(
			&req->DC_CPDReqEnergyTransferMode,
			tvb, pinfo, subtree,
			ett_struct_iso20_dc_DC_CPDReqEnergyTransferModeType,
			"DC_CPDReqEnergyTransferMode");
	}

	return;
}

static void
dissect_iso20_dc_DC_ChargeParameterDiscoveryResType(
	const struct iso20_dc_DC_ChargeParameterDiscoveryResType *res,
	tvbuff_t *tvb,
	packet_info *pinfo,
	proto_tree *tree,
	gint idx,
	const char *subtree_name)
{
	proto_tree *subtree;
	proto_item *it;

	subtree = proto_tree_add_subtree(tree,
		tvb, 0, 0, idx, NULL, subtree_name);

	dissect_iso20_dc_MessageHeaderType(&res->Header,
		tvb, pinfo, subtree,
		ett_struct_iso20_dc_MessageHeaderType, "Header");

	it = proto_tree_add_uint(subtree,
		hf_struct_iso20_dc_DC_ChargeParameterDiscoveryResType_ResponseCode,
		tvb, 0, 0, res->ResponseCode);
	proto_item_set_generated(it);

	if (res->BPT_DC_CPDResEnergyTransferMode_isUsed) {
		dissect_iso20_dc_BPT_DC_CPDResEnergyTransferModeType(
			&res->BPT_DC_CPDResEnergyTransferMode,
			tvb, pinfo, subtree,
			ett_struct_iso20_dc_BPT_DC_CPDResEnergyTransferModeType,
			"BPT_DC_CPDResEnergyTransferMode");
	}
	if (res->DC_CPDResEnergyTransferMode_isUsed) {
		dissect_iso20_dc_DC_CPDResEnergyTransferModeType(
			&res->DC_CPDResEnergyTransferMode,
			tvb, pinfo, subtree,
			ett_struct_iso20_dc_DC_CPDResEnergyTransferModeType,
			"DC_CPDResEnergyTransferMode");
	}

	return;
}


static void
dissect_iso20_dc_DC_CableCheckReqType(
	const struct iso20_dc_DC_CableCheckReqType *req,
	tvbuff_t *tvb,
	packet_info *pinfo,
	proto_tree *tree,
	gint idx,
	const char *subtree_name)
{
	proto_tree *subtree;

	subtree = proto_tree_add_subtree(tree,
		tvb, 0, 0, idx, NULL, subtree_name);

	dissect_iso20_dc_MessageHeaderType(&req->Header,
		tvb, pinfo, subtree,
		ett_struct_iso20_dc_MessageHeaderType, "Header");

	return;
}

static void
dissect_iso20_dc_DC_CableCheckResType(
	const struct iso20_dc_DC_CableCheckResType *res,
	tvbuff_t *tvb,
	packet_info *pinfo,
	proto_tree *tree,
	gint idx,
	const char *subtree_name)
{
	proto_tree *subtree;
	proto_item *it;

	subtree = proto_tree_add_subtree(tree,
		tvb, 0, 0, idx, NULL, subtree_name);

	dissect_iso20_dc_MessageHeaderType(&res->Header,
		tvb, pinfo, subtree,
		ett_struct_iso20_dc_MessageHeaderType, "Header");

	it = proto_tree_add_uint(subtree,
		hf_struct_iso20_dc_DC_CableCheckResType_ResponseCode,
		tvb, 0, 0, res->ResponseCode);
	proto_item_set_generated(it);

	it = proto_tree_add_uint(subtree,
		hf_struct_iso20_dc_DC_CableCheckResType_EVSEProcessing,
		tvb, 0, 0, res->EVSEProcessing);
	proto_item_set_generated(it);

	return;
}


static void
dissect_iso20_dc_DC_PreChargeReqType(
	const struct iso20_dc_DC_PreChargeReqType *req,
	tvbuff_t *tvb,
	packet_info *pinfo,
	proto_tree *tree,
	gint idx,
	const char *subtree_name)
{
	proto_tree *subtree;
	proto_item *it;

	subtree = proto_tree_add_subtree(tree,
		tvb, 0, 0, idx, NULL, subtree_name);

	dissect_iso20_dc_MessageHeaderType(&req->Header,
		tvb, pinfo, subtree,
		ett_struct_iso20_dc_MessageHeaderType, "Header");

	it = proto_tree_add_uint(subtree,
		hf_struct_iso20_dc_DC_PreChargeReqType_EVProcessing,
		tvb, 0, 0, req->EVProcessing);
	proto_item_set_generated(it);

	dissect_iso20_dc_RationalNumberType(
		&req->EVPresentVoltage,
		tvb, pinfo, subtree,
		ett_struct_iso20_dc_RationalNumberType,
		"EVPresentVoltage");

	dissect_iso20_dc_RationalNumberType(
		&req->EVTargetVoltage,
		tvb, pinfo, subtree,
		ett_struct_iso20_dc_RationalNumberType,
		"EVTargetVoltage");

	return;
}

static void
dissect_iso20_dc_DC_PreChargeResType(
	const struct iso20_dc_DC_PreChargeResType *res,
	tvbuff_t *tvb,
	packet_info *pinfo,
	proto_tree *tree,
	gint idx,
	const char *subtree_name)
{
	proto_tree *subtree;
	proto_item *it;

	subtree = proto_tree_add_subtree(tree,
		tvb, 0, 0, idx, NULL, subtree_name);

	dissect_iso20_dc_MessageHeaderType(&res->Header,
		tvb, pinfo, subtree,
		ett_struct_iso20_dc_MessageHeaderType, "Header");

	it = proto_tree_add_uint(subtree,
		hf_struct_iso20_dc_DC_PreChargeResType_ResponseCode,
		tvb, 0, 0, res->ResponseCode);
	proto_item_set_generated(it);

	dissect_iso20_dc_RationalNumberType(&res->EVSEPresentVoltage,
		tvb, pinfo, subtree,
		ett_struct_iso20_dc_RationalNumberType,
		"EVSEPresentVoltage");

	return;
}


static void
dissect_iso20_dc_DC_ChargeLoopReqType(
	const struct iso20_dc_DC_ChargeLoopReqType *req,
	tvbuff_t *tvb,
	packet_info *pinfo,
	proto_tree *tree,
	gint idx,
	const char *subtree_name)
{
	proto_tree *subtree;
	proto_item *it;

	subtree = proto_tree_add_subtree(tree,
		tvb, 0, 0, idx, NULL, subtree_name);

	dissect_iso20_dc_MessageHeaderType(&req->Header,
		tvb, pinfo, subtree,
		ett_struct_iso20_dc_MessageHeaderType, "Header");

	if (req->DisplayParameters_isUsed) {
		dissect_iso20_dc_DisplayParametersType(
			&req->DisplayParameters,
			tvb, pinfo, subtree,
			ett_struct_iso20_dc_DisplayParametersType,
			"DisplayParameters");
	}

	it = proto_tree_add_uint(subtree,
		hf_struct_iso20_dc_DC_ChargeLoopReqType_MeterInfoRequested,
		tvb, 0, 0, req->MeterInfoRequested);
	proto_item_set_generated(it);

	dissect_iso20_dc_RationalNumberType(
		&req->EVPresentVoltage,
		tvb, pinfo, subtree,
		ett_struct_iso20_dc_RationalNumberType,
		"EVPresentVoltage");

	if (req->BPT_Dynamic_DC_CLReqControlMode_isUsed) {
		dissect_iso20_dc_BPT_Dynamic_DC_CLReqControlModeType(
			&req->BPT_Dynamic_DC_CLReqControlMode,
			tvb, pinfo, subtree,
			ett_struct_iso20_dc_BPT_Dynamic_DC_CLReqControlModeType,
			"BPT_Dynamic_DC_CLReqControlMode");
	}
	if (req->BPT_Scheduled_DC_CLReqControlMode_isUsed) {
		dissect_iso20_dc_BPT_Scheduled_DC_CLReqControlModeType(
			&req->BPT_Scheduled_DC_CLReqControlMode,
			tvb, pinfo, subtree,
			ett_struct_iso20_dc_BPT_Scheduled_DC_CLReqControlModeType,
			"BPT_Scheduled_DC_CLReqControlMode");
	}
	if (req->CLReqControlMode_isUsed) {
		dissect_iso20_dc_CLReqControlModeType(
			&req->CLReqControlMode,
			tvb, pinfo, subtree,
			ett_struct_iso20_dc_CLReqControlModeType,
			"CLReqControlMode");
	}
	if (req->Dynamic_DC_CLReqControlMode_isUsed) {
		dissect_iso20_dc_Dynamic_DC_CLReqControlModeType(
			&req->Dynamic_DC_CLReqControlMode,
			tvb, pinfo, subtree,
			ett_struct_iso20_dc_Dynamic_DC_CLReqControlModeType,
			"Dynamic_DC_CLReqControlMode");
	}
	if (req->Scheduled_DC_CLReqControlMode_isUsed) {
		dissect_iso20_dc_Scheduled_DC_CLReqControlModeType(
			&req->Scheduled_DC_CLReqControlMode,
			tvb, pinfo, subtree,
			ett_struct_iso20_dc_Scheduled_DC_CLReqControlModeType,
			"Scheduled_DC_CLReqControlMode");
	}

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
	proto_tree *subtree;
	proto_item *it;

	subtree = proto_tree_add_subtree(tree,
		tvb, 0, 0, idx, NULL, subtree_name);

	dissect_iso20_dc_MessageHeaderType(&res->Header,
		tvb, pinfo, subtree,
		ett_struct_iso20_dc_MessageHeaderType, "Header");

	it = proto_tree_add_uint(subtree,
		hf_struct_iso20_dc_DC_ChargeLoopResType_ResponseCode,
		tvb, 0, 0, res->ResponseCode);
	proto_item_set_generated(it);

	if (res->EVSEStatus_isUsed) {
		dissect_iso20_dc_EVSEStatusType(
			&res->EVSEStatus,
			tvb, pinfo, subtree,
			ett_struct_iso20_dc_EVSEStatusType, "EVSEStatus");
	}
	if (res->MeterInfo_isUsed) {
		dissect_iso20_dc_MeterInfoType(
			&res->MeterInfo,
			tvb, pinfo, subtree,
			ett_struct_iso20_dc_MeterInfoType, "MeterInfo");
	}
	if (res->Receipt_isUsed) {
		dissect_iso20_dc_ReceiptType(
			&res->Receipt,
			tvb, pinfo, subtree,
			ett_struct_iso20_dc_ReceiptType, "Receipt");
	}

	dissect_iso20_dc_RationalNumberType(
		&res->EVSEPresentCurrent,
		tvb, pinfo, subtree,
		ett_struct_iso20_dc_RationalNumberType,
		"EVSEPresentCurrent");

	dissect_iso20_dc_RationalNumberType(
		&res->EVSEPresentVoltage,
		tvb, pinfo, subtree,
		ett_struct_iso20_dc_RationalNumberType,
		"EVSEPresentVoltage");

	it = proto_tree_add_uint(subtree,
		hf_struct_iso20_dc_DC_ChargeLoopResType_EVSEPowerLimitAchieved,
		tvb, 0, 0, res->EVSEPowerLimitAchieved);
	proto_item_set_generated(it);

	it = proto_tree_add_uint(subtree,
		hf_struct_iso20_dc_DC_ChargeLoopResType_EVSECurrentLimitAchieved,
		tvb, 0, 0, res->EVSECurrentLimitAchieved);
	proto_item_set_generated(it);

	it = proto_tree_add_uint(subtree,
		hf_struct_iso20_dc_DC_ChargeLoopResType_EVSEVoltageLimitAchieved,
		tvb, 0, 0, res->EVSEVoltageLimitAchieved);
	proto_item_set_generated(it);

	if (res->BPT_Dynamic_DC_CLResControlMode_isUsed) {
		dissect_iso20_dc_BPT_Dynamic_DC_CLResControlModeType(
			&res->BPT_Dynamic_DC_CLResControlMode,
			tvb, pinfo, subtree,
			ett_struct_iso20_dc_BPT_Dynamic_DC_CLResControlModeType,
			"BPT_Dynamic_DC_CLResControlMode");
	}
	if (res->BPT_Scheduled_DC_CLResControlMode_isUsed) {
		dissect_iso20_dc_BPT_Scheduled_DC_CLResControlModeType(
			&res->BPT_Scheduled_DC_CLResControlMode,
			tvb, pinfo, subtree,
			ett_struct_iso20_dc_BPT_Scheduled_DC_CLResControlModeType,
			"BPT_Scheduled_DC_CLResControlMode");
	}
	if (res->CLResControlMode_isUsed) {
		dissect_iso20_dc_CLResControlModeType(
			&res->CLResControlMode,
			tvb, pinfo, subtree,
			ett_struct_iso20_dc_CLResControlModeType,
			"CLResControlMode");
	}
	if (res->Dynamic_DC_CLResControlMode_isUsed) {
		dissect_iso20_dc_Dynamic_DC_CLResControlModeType(
			&res->Dynamic_DC_CLResControlMode,
			tvb, pinfo, subtree,
			ett_struct_iso20_dc_Dynamic_DC_CLResControlModeType,
			"Dynamic_DC_CLResControlMode");
	}
	if (res->Scheduled_DC_CLResControlMode_isUsed) {
		dissect_iso20_dc_Scheduled_DC_CLResControlModeType(
			&res->Scheduled_DC_CLResControlMode,
			tvb, pinfo, subtree,
			ett_struct_iso20_dc_Scheduled_DC_CLResControlModeType,
			"Scheduled_DC_CLResControlMode");
	}

	return;
}


static void
dissect_iso20_dc_DC_WeldingDetectionReqType(
	const struct iso20_dc_DC_WeldingDetectionReqType *req,
	tvbuff_t *tvb,
	packet_info *pinfo,
	proto_tree *tree,
	gint idx,
	const char *subtree_name)
{
	proto_tree *subtree;
	proto_item *it;

	subtree = proto_tree_add_subtree(tree,
		tvb, 0, 0, idx, NULL, subtree_name);

	dissect_iso20_dc_MessageHeaderType(&req->Header,
		tvb, pinfo, subtree,
		ett_struct_iso20_dc_MessageHeaderType, "Header");

	it = proto_tree_add_uint(subtree,
		hf_struct_iso20_dc_DC_WeldingDetectionReqType_EVProcessing,
		tvb, 0, 0, req->EVProcessing);
	proto_item_set_generated(it);

	return;
}

static void
dissect_iso20_dc_DC_WeldingDetectionResType(
	const struct iso20_dc_DC_WeldingDetectionResType *res,
	tvbuff_t *tvb,
	packet_info *pinfo,
	proto_tree *tree,
	gint idx,
	const char *subtree_name)
{
	proto_tree *subtree;
	proto_item *it;

	subtree = proto_tree_add_subtree(tree,
		tvb, 0, 0, idx, NULL, subtree_name);

	dissect_iso20_dc_MessageHeaderType(&res->Header,
		tvb, pinfo, subtree,
		ett_struct_iso20_dc_MessageHeaderType, "Header");

	it = proto_tree_add_uint(subtree,
		hf_struct_iso20_dc_DC_WeldingDetectionResType_ResponseCode,
		tvb, 0, 0, res->ResponseCode);
	proto_item_set_generated(it);

	dissect_iso20_dc_RationalNumberType(
		&res->EVSEPresentVoltage,
		tvb, pinfo, subtree,
		ett_struct_iso20_dc_RationalNumberType,
		"EVSEPresentVoltage");

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
		/* struct iso20_dc_MessageHeaderType */
		{ &hf_struct_iso20_dc_MessageHeaderType_SessionID,
		  { "SessionID", "v2giso20_dc.struct.messageheader.sessionid",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_struct_iso20_dc_MessageHeaderType_TimeStamp,
		  { "TimeStamp", "v2giso20_dc.struct.messageheader.timestamp",
		    FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso20_dc_SignatureType */
		{ &hf_struct_iso20_dc_SignatureType_Id,
		  { "Id", "v2giso20.dc.struct.signature.id",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso20_dc_SignedInfoType */
		{ &hf_struct_iso20_dc_SignedInfoType_Id,
		  { "Id", "v2giso20.dc.struct.signedinfo.id",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso20_dc_CanonicalizationMethodType */
		{ &hf_struct_iso20_dc_CanonicalizationMethodType_Algorithm,
		  { "Algorithm",
		    "v2giso20.dc.struct.canonicalizationmethod.algorithm",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_struct_iso20_dc_CanonicalizationMethodType_ANY,
		  { "ANY",
		    "v2giso20.dc.struct.canonicalizationmethod.any",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso20_dc_SignatureMethodType */
		{ &hf_struct_iso20_dc_SignatureMethodType_Algorithm,
		  { "Algorithm", "v2giso20.dc.struct.signaturemethod.algorithm",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_struct_iso20_dc_SignatureMethodType_HMACOutputLength,
		  { "HMACOutputLength",
		    "v2giso20.dc.struct.signaturemethod.hmacoutputlength",
		    FT_INT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_struct_iso20_dc_SignatureMethodType_ANY,
		  { "ANY", "v2giso20.dc.struct.signaturemethod.any",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso20_dc_ReferenceType */
		{ &hf_struct_iso20_dc_ReferenceType_Id,
		  { "Id", "v2giso20.dc.struct.reference.id",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_struct_iso20_dc_ReferenceType_Type,
		  { "Type", "v2giso20.dc.struct.reference.type",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_struct_iso20_dc_ReferenceType_URI,
		  { "URI", "v2giso20.dc.struct.reference.uri",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_struct_iso20_dc_ReferenceType_DigestValue,
		  { "DigestValue", "v2giso20.dc.struct.reference.digestvalue",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso20_dc_TransformType */
		{ &hf_struct_iso20_dc_TransformType_Algorithm,
		  { "Algorithm", "v2giso20.dc.struct.transform.algorithm",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_struct_iso20_dc_TransformType_ANY,
		  { "ANY", "v2giso20.dc.struct.transform.any",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_struct_iso20_dc_TransformType_XPath,
		  { "XPath", "v2giso20.dc.struct.transform.xpath",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso20_dc_DigestMethodType */
		{ &hf_struct_iso20_dc_DigestMethodType_Algorithm,
		  { "Algorithm", "v2giso20.dc.struct.digestmethod.algorithm",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_struct_iso20_dc_DigestMethodType_ANY,
		  { "ANY", "v2giso20.dc.struct.digestmethod.any",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso20_dc_SignatureValueType */
		{ &hf_struct_iso20_dc_SignatureValueType_Id,
		  { "Id", "v2giso20.dc.struct.signaturevalue.id",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_struct_iso20_dc_SignatureValueType_CONTENT,
		  { "CONTENT", "v2giso20.dc.struct.signaturevalue.content",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso20_dc_KeyInfoType */
		{ &hf_struct_iso20_dc_KeyInfoType_Id,
		  { "Id", "v2giso20.dc.struct.keyinfo.id",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_struct_iso20_dc_KeyInfoType_KeyName,
		  { "KeyName", "v2giso20.dc.struct.keyinfo.keyname",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_struct_iso20_dc_KeyInfoType_MgmtData,
		  { "MgmtData", "v2giso20.dc.struct.keyinfo.mgmtdata",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_struct_iso20_dc_KeyInfoType_ANY,
		  { "ANY", "v2giso20.dc.struct.keyinfo.any",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso20_KeyValueType */
		{ &hf_struct_iso20_dc_KeyValueType_ANY,
		  { "ANY", "v2giso20.dc.struct.keyvalue.any",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso20_dc_DSAKeyValueType */
		{ &hf_struct_iso20_dc_DSAKeyValueType_P,
		  { "P", "v2giso20.dc.struct.dsakeyvalue.p",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_struct_iso20_dc_DSAKeyValueType_Q,
		  { "Q", "v2giso20.dc.struct.dsakeyvalue.q",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_struct_iso20_dc_DSAKeyValueType_G,
		  { "G", "v2giso20.dc.struct.dsakeyvalue.g",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_struct_iso20_dc_DSAKeyValueType_Y,
		  { "Y", "v2giso20.dc.struct.dsakeyvalue.y",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_struct_iso20_dc_DSAKeyValueType_J,
		  { "J", "v2giso20.dc.struct.dsakeyvalue.j",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_struct_iso20_dc_DSAKeyValueType_Seed,
		  { "Seed", "v2giso20.dc.struct.dsakeyvalue.seed",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_struct_iso20_dc_DSAKeyValueType_PgenCounter,
		  { "PgenCounter", "v2giso20.dc.struct.dsakeyvalue.pgencounter",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso20_dc_RSAKeyValueType */
		{ &hf_struct_iso20_dc_RSAKeyValueType_Modulus,
		  { "Modulus", "v2giso20.dc.struct.rsakeyvalue.modulus",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_struct_iso20_dc_RSAKeyValueType_Exponent,
		  { "Exponent", "v2giso20.dc.struct.rsakeyvalue.exponent",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso20_dc_RetrievalMethodType */
		{ &hf_struct_iso20_dc_RetrievalMethodType_URI,
		  { "URI", "v2giso20.dc.struct.retrievalmethod.uri",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_struct_iso20_dc_RetrievalMethodType_Type,
		  { "Type", "v2giso20.dc.struct.retrievalmethod.type",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso20_dc_X509DataType */
		{ &hf_struct_iso20_dc_X509DataType_X509SKI,
		  { "X509SKI", "v2giso20.dc.struct.x509data.x509ski",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_struct_iso20_dc_X509DataType_X509SubjectName,
		  { "X509SubjectName",
		    "v2giso20.dc.struct.x509data.x509subjectname",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_struct_iso20_dc_X509DataType_X509Certificate,
		  { "X509Certificate",
		    "v2giso20.dc.struct.x509data.x509certificate",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_struct_iso20_dc_X509DataType_X509CRL,
		  { "X509CRL", "v2giso20.dc.struct.x509data.x509crl",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_struct_iso20_dc_X509DataType_ANY,
		  { "ANY", "v2giso20.dc.struct.x509data.any",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso20_X509IssuerSerialType */
		{ &hf_struct_iso20_dc_X509IssuerSerialType_X509IssuerName,
		  { "X509IssuerName",
		    "v2giso20.dc.struct.x509issuerserial.x509issuername",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_struct_iso20_dc_X509IssuerSerialType_X509SerialNumber,
		  { "X509SerialNumber",
		    "v2giso20.dc.struct.x509issuerserial.x509serialnumber",
		    FT_INT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso20_dc_PGPDataType */
		{ &hf_struct_iso20_dc_PGPDataType_PGPKeyID,
		  { "PGPKeyID", "v2giso20.dc.struct.pgpdata.pgpkeyid",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_struct_iso20_dc_PGPDataType_PGPKeyPacket,
		  { "PGPKeyPacket", "v2giso20.dc.struct.pgpdata.pgpkeypacket",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_struct_iso20_dc_PGPDataType_ANY,
		  { "ANY", "v2giso20.dc.struct.pgpdata.any",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso20_dc_SPKIDataType */
		{ &hf_struct_iso20_dc_SPKIDataType_SPKISexp,
		  { "SPKISexp", "v2giso20.dc.struct.spkidata.spkisexp",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_struct_iso20_dc_SPKIDataType_ANY,
		  { "ANY", "v2giso20.dc.struct.spkidata.any",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso20_dc_ObjectType */
		{ &hf_struct_iso20_dc_ObjectType_Id,
		  { "Id", "v2giso20.dc.struct.object.id",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_struct_iso20_dc_ObjectType_MimeType,
		  { "MimeType", "v2giso20.dc.struct.object.mimetype",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_struct_iso20_dc_ObjectType_Encoding,
		  { "Encoding", "v2giso20.dc.struct.object.encoding",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_struct_iso20_dc_ObjectType_ANY,
		  { "ANY", "v2giso20.dc.struct.object.any",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso20_dc_DC_ChargeParameterDiscoveryReqType */
		/* struct iso20_dc_DC_ChargeParameterDiscoveryResType */
		{ &hf_struct_iso20_dc_DC_ChargeParameterDiscoveryResType_ResponseCode,
		  { "ResponseCode",
		    "v2giso20.dc.struct.dc_chargeparameterdiscoveryres.responsecode",
		    FT_UINT16, BASE_DEC,
		    VALS(v2giso20_dc_enum_iso20_dc_responseCodeType_names),
		    0x0, NULL, HFILL }
		},

		/* struct iso20_dc_DC_CableCheckReqType */
		/* struct iso20_dc_DC_CableCheckResType */
		{ &hf_struct_iso20_dc_DC_CableCheckResType_ResponseCode,
		  { "ResponseCode",
		    "v2giso20.dc.struct.dc_cablecheckres.responsecode",
		    FT_UINT16, BASE_DEC,
		    VALS(v2giso20_dc_enum_iso20_dc_responseCodeType_names),
		    0x0, NULL, HFILL }
		},
		{ &hf_struct_iso20_dc_DC_CableCheckResType_EVSEProcessing,
		  { "ResponseCode",
		    "v2giso20.dc.struct.dc_cablecheckres.evseprocessing",
		    FT_UINT16, BASE_DEC,
		    VALS(v2giso20_dc_enum_iso20_dc_processingType_names),
		    0x0, NULL, HFILL }
		},

		/* struct iso20_dc_DC_PreChargeReqType */
		{ &hf_struct_iso20_dc_DC_PreChargeReqType_EVProcessing,
		  { "EVProcessing",
		    "v2giso20.dc.struct.dc_prechargereq.evprocessing",
		    FT_UINT16, BASE_DEC,
		    VALS(v2giso20_dc_enum_iso20_dc_processingType_names),
		    0x0, NULL, HFILL }
		},
		/* struct iso20_dc_DC_PreChargeResType */
		{ &hf_struct_iso20_dc_DC_PreChargeResType_ResponseCode,
		  { "ResponseCode",
		    "v2giso20.dc.struct.dc_prechargeres.responsecode",
		    FT_UINT16, BASE_DEC,
		    VALS(v2giso20_dc_enum_iso20_dc_responseCodeType_names),
		    0x0, NULL, HFILL }
		},

		/* struct iso20_dc_DC_ChargeLoopReqType */
		{ &hf_struct_iso20_dc_DC_ChargeLoopReqType_MeterInfoRequested,
		  { "MeterInfoRequested",
		    "v2giso20.dc.struct.dc_chargeloopreq.meterinforequested",
		    FT_INT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		/* struct iso20_dc_DC_ChargeLoopResType */
		{ &hf_struct_iso20_dc_DC_ChargeLoopResType_ResponseCode,
		  { "ResponseCode",
		    "v2giso20.dc.struct.dc_chargeloopres.responsecode",
		    FT_UINT16, BASE_DEC,
		    VALS(v2giso20_dc_enum_iso20_dc_responseCodeType_names),
		    0x0, NULL, HFILL }
		},
		{ &hf_struct_iso20_dc_DC_ChargeLoopResType_EVSEPowerLimitAchieved,
		  { "EVSEPowerLimitAchieved",
		    "v2giso20.dc.struct.dc_chargeloopres.evsepowerlimitachieved",
		    FT_INT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_struct_iso20_dc_DC_ChargeLoopResType_EVSECurrentLimitAchieved,
		  { "EVSECurrentLimitAchieved",
		    "v2giso20.dc.struct.dc_chargeloopres.evsecurrentlimitachieved",
		    FT_INT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_struct_iso20_dc_DC_ChargeLoopResType_EVSEVoltageLimitAchieved,
		  { "EVSEVoltageLimitAchieved",
		    "v2giso20.dc.struct.dc_chargeloopres.evsevoltagelimitachieved",
		    FT_INT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso20_dc_DC_WeldingDetectionReqType */
		{ &hf_struct_iso20_dc_DC_WeldingDetectionReqType_EVProcessing,
		  { "EVProcessing",
		    "v2giso20.dc.struct.dc_weldingdetectionreq.evprocessing",
		    FT_UINT16, BASE_DEC,
		    VALS(v2giso20_dc_enum_iso20_dc_processingType_names),
		    0x0, NULL, HFILL }
		},
		/* struct iso20_dc_DC_WeldingDetectionResType */
		{ &hf_struct_iso20_dc_DC_WeldingDetectionResType_ResponseCode,
		  { "ResponseCode",
		    "v2giso20.dc.struct.dc_weldingdetectionres.responsecode",
		    FT_UINT16, BASE_DEC,
		    VALS(v2giso20_dc_enum_iso20_dc_responseCodeType_names),
		    0x0, NULL, HFILL }
		},

		/* struct iso20_dc_DC_CPDReqEnergyTransferModeType */
		{ &hf_struct_iso20_dc_DC_CPDReqEnergyTransferModeType_TargetSOC,
		  { "TargetSOC",
		    "v2giso20.dc.struct.dc_cpdreqenergytransfermode.targetsoc",
		    FT_INT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso20_dc_BPT_DC_CPDReqEnergyTransferModeType */
		{ &hf_struct_iso20_dc_BPT_DC_CPDReqEnergyTransferModeType_TargetSOC,
		  { "TargetSOC",
		    "v2giso20.dc.struct.bpt_dc_cpdreqenergytransfermode.targetsoc",
		    FT_INT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso20_dc_RationalNumberType */
		{ &hf_struct_iso20_dc_RationalNumberType_Exponent,
		  { "Exponent", "v2giso20.struct.dc_rationalnumber.exponent",
		    FT_INT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_struct_iso20_dc_RationalNumberType_Value,
		  { "Value", "v2giso20.struct.dc_rationalnumber.value",
		    FT_INT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
	};

	static gint *ett[] = {
		&ett_v2giso20_dc,
		&ett_v2giso20_dc_document,
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
		&ett_struct_iso20_dc_SignatureType,
		&ett_struct_iso20_dc_SignatureValueType,
		&ett_struct_iso20_dc_SignedInfoType,
		&ett_struct_iso20_dc_CanonicalizationMethodType,
		&ett_struct_iso20_dc_SignatureMethodType,
		&ett_struct_iso20_dc_ReferenceType,
		&ett_struct_iso20_dc_TransformsType,
		&ett_struct_iso20_dc_TransformType,
		&ett_struct_iso20_dc_DigestMethodType,
		&ett_struct_iso20_dc_KeyInfoType,
		&ett_struct_iso20_dc_KeyValueType,
		&ett_struct_iso20_dc_RetrievalMethodType,
		&ett_struct_iso20_dc_X509DataType,
		&ett_struct_iso20_dc_PGPDataType,
		&ett_struct_iso20_dc_SPKIDataType,
		&ett_struct_iso20_dc_ObjectType,
		&ett_struct_iso20_dc_ManifestType,
		&ett_struct_iso20_dc_SignaturePropertiesType,
		&ett_struct_iso20_dc_SignaturePropertyType,
		&ett_struct_iso20_dc_DSAKeyValueType,
		&ett_struct_iso20_dc_RSAKeyValueType,

		&ett_struct_iso20_dc_MessageHeaderType,
		&ett_struct_iso20_dc_X509IssuerSerialType,

		&ett_struct_iso20_dc_DisplayParametersType,
		&ett_struct_iso20_dc_EVSEStatusType,
		&ett_struct_iso20_dc_MeterInfoType,
		&ett_struct_iso20_dc_ReceiptType,
		&ett_struct_iso20_dc_RationalNumberType,
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
