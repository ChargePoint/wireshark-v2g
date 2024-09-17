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

static int hf_struct_iso20_ac_MessageHeaderType_SessionID = -1;
static int hf_struct_iso20_ac_MessageHeaderType_TimeStamp = -1;
static int hf_struct_iso20_ac_SignatureType_Id = -1;
static int hf_struct_iso20_ac_SignedInfoType_Id = -1;
static int hf_struct_iso20_ac_CanonicalizationMethodType_Algorithm = -1;
static int hf_struct_iso20_ac_CanonicalizationMethodType_ANY = -1;
static int hf_struct_iso20_ac_SignatureMethodType_Algorithm = -1;
static int hf_struct_iso20_ac_SignatureMethodType_HMACOutputLength = -1;
static int hf_struct_iso20_ac_SignatureMethodType_ANY = -1;
static int hf_struct_iso20_ac_ReferenceType_Id = -1;
static int hf_struct_iso20_ac_ReferenceType_Type = -1;
static int hf_struct_iso20_ac_ReferenceType_URI = -1;
static int hf_struct_iso20_ac_ReferenceType_DigestValue = -1;
static int hf_struct_iso20_ac_TransformType_Algorithm = -1;
static int hf_struct_iso20_ac_TransformType_ANY = -1;
static int hf_struct_iso20_ac_TransformType_XPath = -1;
static int hf_struct_iso20_ac_DigestMethodType_Algorithm = -1;
static int hf_struct_iso20_ac_DigestMethodType_ANY = -1;
static int hf_struct_iso20_ac_SignatureValueType_Id = -1;
static int hf_struct_iso20_ac_SignatureValueType_CONTENT = -1;
static int hf_struct_iso20_ac_KeyInfoType_Id = -1;
static int hf_struct_iso20_ac_KeyInfoType_KeyName = -1;
static int hf_struct_iso20_ac_KeyInfoType_MgmtData = -1;
static int hf_struct_iso20_ac_KeyInfoType_ANY = -1;
static int hf_struct_iso20_ac_KeyValueType_ANY = -1;
static int hf_struct_iso20_ac_DSAKeyValueType_P = -1;
static int hf_struct_iso20_ac_DSAKeyValueType_Q = -1;
static int hf_struct_iso20_ac_DSAKeyValueType_G = -1;
static int hf_struct_iso20_ac_DSAKeyValueType_Y = -1;
static int hf_struct_iso20_ac_DSAKeyValueType_J = -1;
static int hf_struct_iso20_ac_DSAKeyValueType_Seed = -1;
static int hf_struct_iso20_ac_DSAKeyValueType_PgenCounter = -1;
static int hf_struct_iso20_ac_RSAKeyValueType_Exponent = -1;
static int hf_struct_iso20_ac_RSAKeyValueType_Modulus = -1;
static int hf_struct_iso20_ac_RetrievalMethodType_Type = -1;
static int hf_struct_iso20_ac_RetrievalMethodType_URI = -1;
static int hf_struct_iso20_ac_X509DataType_X509SKI = -1;
static int hf_struct_iso20_ac_X509DataType_X509SubjectName = -1;
static int hf_struct_iso20_ac_X509DataType_X509Certificate = -1;
static int hf_struct_iso20_ac_X509DataType_X509CRL = -1;
static int hf_struct_iso20_ac_X509DataType_ANY = -1;
static int hf_struct_iso20_ac_X509IssuerSerialType_X509IssuerName = -1;
static int hf_struct_iso20_ac_X509IssuerSerialType_X509SerialNumber = -1;
static int hf_struct_iso20_ac_PGPDataType_PGPKeyID = -1;
static int hf_struct_iso20_ac_PGPDataType_PGPKeyPacket = -1;
static int hf_struct_iso20_ac_PGPDataType_ANY = -1;
static int hf_struct_iso20_ac_SPKIDataType_SPKISexp = -1;
static int hf_struct_iso20_ac_SPKIDataType_ANY = -1;
static int hf_struct_iso20_ac_ObjectType_Id = -1;
static int hf_struct_iso20_ac_ObjectType_MimeType = -1;
static int hf_struct_iso20_ac_ObjectType_Encoding = -1;
static int hf_struct_iso20_ac_ObjectType_ANY = -1;

/* AC_ChargeParameterDiscovery */
static int hf_struct_iso20_ac_AC_ChargeParameterDiscoveryResType_ResponseCode = -1;

/* AC_ChargeLoop */
static int hf_struct_iso20_ac_AC_ChargeLoopReqType_MeterInfoRequested = -1;
static int hf_struct_iso20_ac_AC_ChargeLoopResType_ResponseCode = -1;


/* Initialize the subtree pointers */
static gint ett_v2giso20_ac = -1;
static gint ett_v2giso20_ac_document = -1;
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
static gint ett_struct_iso20_ac_SignatureType = -1;
static gint ett_struct_iso20_ac_SignatureValueType = -1;
static gint ett_struct_iso20_ac_SignedInfoType = -1;
static gint ett_struct_iso20_ac_CanonicalizationMethodType = -1;
static gint ett_struct_iso20_ac_SignatureMethodType = -1;
static gint ett_struct_iso20_ac_ReferenceType = -1;
static gint ett_struct_iso20_ac_TransformsType = -1;
static gint ett_struct_iso20_ac_TransformType = -1;
static gint ett_struct_iso20_ac_DigestMethodType = -1;
static gint ett_struct_iso20_ac_KeyInfoType = -1;
static gint ett_struct_iso20_ac_KeyValueType = -1;
static gint ett_struct_iso20_ac_RetrievalMethodType = -1;
static gint ett_struct_iso20_ac_X509DataType = -1;
static gint ett_struct_iso20_ac_PGPDataType = -1;
static gint ett_struct_iso20_ac_SPKIDataType = -1;
static gint ett_struct_iso20_ac_ObjectType = -1;
static gint ett_struct_iso20_ac_ManifestType = -1;
static gint ett_struct_iso20_ac_SignaturePropertiesType = -1;
static gint ett_struct_iso20_ac_SignaturePropertyType = -1;
static gint ett_struct_iso20_ac_DSAKeyValueType = -1;
static gint ett_struct_iso20_ac_RSAKeyValueType = -1;

static gint ett_struct_iso20_ac_MessageHeaderType = -1;
static gint ett_struct_iso20_ac_X509IssuerSerialType = -1;

static gint ett_struct_iso20_ac_DisplayParametersType = -1;
static gint ett_struct_iso20_ac_EVSEStatusType = -1;
static gint ett_struct_iso20_ac_MeterInfoType = -1;
static gint ett_struct_iso20_ac_ReceiptType = -1;
static gint ett_struct_iso20_ac_RationalNumberType = -1;


static const value_string v2giso20_ac_enum_iso20_ac_responseCodeType_names[] = {
	{ iso20_ac_responseCodeType_OK, "OK" },
	{ iso20_ac_responseCodeType_OK_CertificateExpiresSoon,
	  "OK (CertificateExpiresSoon)" },
	{ iso20_ac_responseCodeType_OK_NewSessionEstablished,
	  "OK (NewSessionEstablished)" },
	{ iso20_ac_responseCodeType_OK_OldSessionJoined,
	  "OK (OldSessionJoined)" },
	{ iso20_ac_responseCodeType_OK_PowerToleranceConfirmed,
	  "OK (PowerToleranceConfirmed)" },
	{ iso20_ac_responseCodeType_WARNING_AuthorizationSelectionInvalid,
	  "WARNING (AuthorizationSelectionInvalid)" },
	{ iso20_ac_responseCodeType_WARNING_CertificateExpired,
	  "WARNING (CertificateExpired)" },
	{ iso20_ac_responseCodeType_WARNING_CertificateNotYetValid,
	  "WARNING (CertificateNotYetValid)" },
	{ iso20_ac_responseCodeType_WARNING_CertificateRevoked,
	  "WARNING (CertificateRevoked)" },
	{ iso20_ac_responseCodeType_WARNING_CertificateValidationError,
	  "WARNING (CertificateValidationError)" },
	{ iso20_ac_responseCodeType_WARNING_ChallengeInvalid,
	  "WARNING (ChallengeInvalid)" },
	{ iso20_ac_responseCodeType_WARNING_EIMAuthorizationFailure,
	  "WARNING (EIMAuthorizationFailure)" },
	{ iso20_ac_responseCodeType_WARNING_eMSPUnknown,
	  "WARNING (eMSPUnknown)" },
	{ iso20_ac_responseCodeType_WARNING_EVPowerProfileViolation,
	  "WARNING (EVPowerProfileViolation)" },
	{ iso20_ac_responseCodeType_WARNING_GeneralPnCAuthorizationError,
	  "WARNING (GeneralPnCAuthorizationError)" },
	{ iso20_ac_responseCodeType_WARNING_NoCertificateAvailable,
	  "WARNING (NoCertificateAvailable)" },
	{ iso20_ac_responseCodeType_WARNING_NoContractMatchingPCIDFound,
	  "WARNING (NoContractMatchingPCIDFound)" },
	{ iso20_ac_responseCodeType_WARNING_PowerToleranceNotConfirmed,
	  "WARNING (PowerToleranceNotConfirmed)" },
	{ iso20_ac_responseCodeType_WARNING_ScheduleRenegotiationFailed,
	  "WARNING (ScheduleRenegotiationFailed)" },
	{ iso20_ac_responseCodeType_WARNING_StandbyNotAllowed,
	  "WARNING (StandbyNotAllowed)" },
	{ iso20_ac_responseCodeType_WARNING_WPT, "WARNING (WPT)" },
	{ iso20_ac_responseCodeType_FAILED, "FAILED" },
	{ iso20_ac_responseCodeType_FAILED_AssociationError,
	  "FAILED (AssociationError)" },
	{ iso20_ac_responseCodeType_FAILED_ContactorError,
	  "FAILED (ContactorError)" },
	{ iso20_ac_responseCodeType_FAILED_EVPowerProfileInvalid,
	  "FAILED (EVPowerProfileInvalid)" },
	{ iso20_ac_responseCodeType_FAILED_EVPowerProfileViolation,
	  "FAILED (EVPowerProfileViolation)" },
	{ iso20_ac_responseCodeType_FAILED_MeteringSignatureNotValid,
	  "FAILED (MeteringSignatureNotValid)" },
	{ iso20_ac_responseCodeType_FAILED_NoEnergyTransferServiceSelected,
	  "FAILED (NoEnergyTransferServiceSelected)" },
	{ iso20_ac_responseCodeType_FAILED_NoServiceRenegotiationSupported,
	  "FAILED (NoServiceRenegotiationSupported)" },
	{ iso20_ac_responseCodeType_FAILED_PauseNotAllowed,
	  "FAILED (PauseNotAllowed)" },
	{ iso20_ac_responseCodeType_FAILED_PowerDeliveryNotApplied,
	  "FAILED (PowerDeliveryNotApplied)" },
	{ iso20_ac_responseCodeType_FAILED_PowerToleranceNotConfirmed,
	  "FAILED (PowerToleranceNotConfirmed)" },
	{ iso20_ac_responseCodeType_FAILED_ScheduleRenegotiation,
	  "FAILED (ScheduleRenegotiation)" },
	{ iso20_ac_responseCodeType_FAILED_ScheduleSelectionInvalid,
	  "FAILED (ScheduleSelectionInvalid)" },
	{ iso20_ac_responseCodeType_FAILED_SequenceError,
	  "FAILED (SequenceError)" },
	{ iso20_ac_responseCodeType_FAILED_ServiceIDInvalid,
	  "FAILED (ServiceIDInvalid)" },
	{ iso20_ac_responseCodeType_FAILED_ServiceSelectionInvalid,
	  "FAILED (ServiceSelectionInvalid)" },
	{ iso20_ac_responseCodeType_FAILED_SignatureError,
	  "FAILED (SignatureError)" },
	{ iso20_ac_responseCodeType_FAILED_UnknownSession,
	  "FAILED (UnknownSession)" },
	{ iso20_ac_responseCodeType_FAILED_WrongChargeParameter,
	  "FAILED (WrongChargeParameter)" },
	{ 0, NULL }
};


/* header node dissectors - each node is represented by a struct */
static void dissect_iso20_ac_SignatureType(
	const struct iso20_ac_SignatureType *node,
	tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
	gint idx, const char *subtree_name);
static void dissect_iso20_ac_SignatureValueType(
	const struct iso20_ac_SignatureValueType *node,
	tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
	gint idx, const char *subtree_name);
static void dissect_iso20_ac_SignedInfoType(
	const struct iso20_ac_SignedInfoType *node,
	tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
	gint idx, const char *subtree_name);
static void dissect_iso20_ac_CanonicalizationMethodType(
	const struct iso20_ac_CanonicalizationMethodType *node,
	tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
	gint idx, const char *subtree_name);
static void dissect_iso20_ac_SignatureMethodType(
	const struct iso20_ac_SignatureMethodType *node,
	tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
	gint idx, const char *subtree_name);
static void dissect_iso20_ac_ReferenceType(
	const struct iso20_ac_ReferenceType *node,
	tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
	gint idx, const char *subtree_name);
static void dissect_iso20_ac_TransformsType(
	const struct iso20_ac_TransformsType *node,
	tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
	gint idx, const char *subtree_name);
static void dissect_iso20_ac_TransformType(
	const struct iso20_ac_TransformType *node,
	tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
	gint idx, const char *subtree_name);
static void dissect_iso20_ac_DigestMethodType(
	const struct iso20_ac_DigestMethodType *node,
	tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
	gint idx, const char *subtree_name);
static void dissect_iso20_ac_KeyInfoType(
	const struct iso20_ac_KeyInfoType *node,
	tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
	gint idx, const char *subtree_name);
static void dissect_iso20_ac_KeyValueType(
	const struct iso20_ac_KeyValueType *node,
	tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
	gint idx, const char *subtree_name);
static void dissect_iso20_ac_RetrievalMethodType(
	const struct iso20_ac_RetrievalMethodType *node,
	tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
	gint idx, const char *subtree_name);
static void dissect_iso20_ac_X509DataType(
	const struct iso20_ac_X509DataType *node,
	tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
	gint idx, const char *subtree_name);
static void dissect_iso20_ac_PGPDataType(
	const struct iso20_ac_PGPDataType *node,
	tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
	gint idx, const char *subtree_name);
static void dissect_iso20_ac_SPKIDataType(
	const struct iso20_ac_SPKIDataType *node,
	tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
	gint idx, const char *subtree_name);
static void dissect_iso20_ac_ObjectType(
	const struct iso20_ac_ObjectType *node,
	tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
	gint idx, const char *subtree_name);
#ifdef notyet
static void dissect_iso20_ac_ManifestType(
	const struct iso20_ac_ManifestType *node,
	tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
	gint idx, const char *subtree_name);
#endif
#ifdef notyet
static void dissect_iso20_ac_SignaturePropertiesType(
	const struct iso20_ac_SignaturePropertiesType *node,
	tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
	gint idx, const char *subtree_name);
#endif
#ifdef notyet
static void dissect_iso20_ac_SignaturePropertyType(
	const struct iso20_ac_SignaturePropertyType *node,
	tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
	gint idx, const char *subtree_name);
#endif
static void dissect_iso20_ac_DSAKeyValueType(
	const struct iso20_ac_DSAKeyValueType *node,
	tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
	gint idx, const char *subtree_name);
static void dissect_iso20_ac_RSAKeyValueType(
	const struct iso20_ac_RSAKeyValueType *node,
	tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
	gint idx, const char *subtree_name);

static void dissect_iso20_ac_MessageHeaderType(
	const struct iso20_ac_MessageHeaderType *node,
	tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
	gint idx, const char *subtree_name);
static void dissect_iso20_ac_X509IssuerSerialType(
	const struct iso20_ac_X509IssuerSerialType *node,
	tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
	gint idx, const char *subtree_name);


static void
dissect_iso20_ac_SignatureType(
	const struct iso20_ac_SignatureType *node,
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
			hf_struct_iso20_ac_SignatureType_Id,
			tvb,
			node->Id.characters,
			node->Id.charactersLen,
			sizeof(node->Id.characters));
	}

	dissect_iso20_ac_SignedInfoType(&node->SignedInfo,
		tvb, pinfo, subtree,
		ett_struct_iso20_ac_SignedInfoType, "SignedInfo");
	dissect_iso20_ac_SignatureValueType(&node->SignatureValue,
		tvb, pinfo, subtree,
		ett_struct_iso20_ac_SignatureValueType, "SignatureValue");

	if (node->KeyInfo_isUsed) {
		dissect_iso20_ac_KeyInfoType(&node->KeyInfo,
			tvb, pinfo, subtree,
			ett_struct_iso20_ac_KeyInfoType, "KeyInfo");
	}

	if (node->Object_isUsed) {
		dissect_iso20_ac_ObjectType(&node->Object,
			tvb, pinfo, subtree,
			ett_struct_iso20_ac_ObjectType, "Object");
	}

	return;
}

static void
dissect_iso20_ac_SignatureValueType(
	const struct iso20_ac_SignatureValueType *node,
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
			hf_struct_iso20_ac_SignatureValueType_Id,
			tvb,
			node->Id.characters,
			node->Id.charactersLen,
			sizeof(node->Id.characters));
	}

	exi_add_bytes(subtree,
		hf_struct_iso20_ac_SignatureValueType_CONTENT,
		tvb,
		node->CONTENT.bytes,
		node->CONTENT.bytesLen,
		sizeof(node->CONTENT.bytes));

	return;
}

static void
dissect_iso20_ac_SignedInfoType(
	const struct iso20_ac_SignedInfoType *node,
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
			hf_struct_iso20_ac_SignedInfoType_Id,
			tvb,
			node->Id.characters,
			node->Id.charactersLen,
			sizeof(node->Id.characters));
	}

	dissect_iso20_ac_CanonicalizationMethodType(
		&node->CanonicalizationMethod,
		tvb, pinfo, subtree,
		ett_struct_iso20_ac_CanonicalizationMethodType,
		"CanonicalizationMethod");
	dissect_iso20_ac_SignatureMethodType(
		&node->SignatureMethod,
		tvb, pinfo, subtree,
		ett_struct_iso20_ac_SignatureMethodType,
		"SignatureMethod");

	reference_tree = proto_tree_add_subtree(subtree,
		tvb, 0, 0, ett_v2giso20_ac_array, NULL, "Reference");
	for (i = 0; i < node->Reference.arrayLen; i++) {
		char index[sizeof("[65536]")];

		snprintf(index, sizeof(index), "[%u]", i);
		dissect_iso20_ac_ReferenceType(&node->Reference.array[i],
			tvb, pinfo, reference_tree,
			ett_struct_iso20_ac_ReferenceType, index);
	}

	return;
}

static void
dissect_iso20_ac_CanonicalizationMethodType(
	const struct iso20_ac_CanonicalizationMethodType *node,
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
		hf_struct_iso20_ac_CanonicalizationMethodType_Algorithm,
		tvb,
		node->Algorithm.characters,
		node->Algorithm.charactersLen,
		sizeof(node->Algorithm.characters));

	if (node->ANY_isUsed) {
		exi_add_bytes(subtree,
			hf_struct_iso20_ac_CanonicalizationMethodType_ANY,
			tvb,
			node->ANY.bytes,
			node->ANY.bytesLen,
			sizeof(node->ANY.bytes));
	}

	return;
}

static void
dissect_iso20_ac_SignatureMethodType(
	const struct iso20_ac_SignatureMethodType *node,
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
		hf_struct_iso20_ac_SignatureMethodType_Algorithm,
		tvb,
		node->Algorithm.characters,
		node->Algorithm.charactersLen,
		sizeof(node->Algorithm.characters));

	if (node->HMACOutputLength_isUsed) {
		it = proto_tree_add_int(subtree,
			hf_struct_iso20_ac_SignatureMethodType_HMACOutputLength,
			tvb, 0, 0, node->HMACOutputLength);
		proto_item_set_generated(it);
	}

	if (node->ANY_isUsed) {
		exi_add_bytes(subtree,
			hf_struct_iso20_ac_SignatureMethodType_ANY,
			tvb,
			node->ANY.bytes,
			node->ANY.bytesLen,
			sizeof(node->ANY.bytes));
	}

	return;
}

static void
dissect_iso20_ac_ReferenceType(
	const struct iso20_ac_ReferenceType *node,
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
			hf_struct_iso20_ac_ReferenceType_Id,
			tvb,
			node->Id.characters,
			node->Id.charactersLen,
			sizeof(node->Id.characters));
	}
	if (node->Type_isUsed) {
		exi_add_characters(subtree,
			hf_struct_iso20_ac_ReferenceType_Type,
			tvb,
			node->Type.characters,
			node->Type.charactersLen,
			sizeof(node->Type.characters));
	}
	if (node->URI_isUsed) {
		exi_add_characters(subtree,
			hf_struct_iso20_ac_ReferenceType_URI,
			tvb,
			node->URI.characters,
			node->URI.charactersLen,
			sizeof(node->URI.characters));
	}
	if (node->Transforms_isUsed) {
		dissect_iso20_ac_TransformsType(&node->Transforms,
			tvb, pinfo, subtree,
			ett_struct_iso20_ac_TransformsType,
			"Transforms");
	}

	dissect_iso20_ac_DigestMethodType(&node->DigestMethod,
			tvb, pinfo, subtree,
			ett_struct_iso20_ac_DigestMethodType,
			"DigestMethod");

	exi_add_bytes(subtree,
		hf_struct_iso20_ac_ReferenceType_DigestValue,
		tvb,
		node->DigestValue.bytes,
		node->DigestValue.bytesLen,
		sizeof(node->DigestValue.bytes));

	return;
}

static void
dissect_iso20_ac_TransformsType(
	const struct iso20_ac_TransformsType *node,
	tvbuff_t *tvb,
	packet_info *pinfo _U_,
	proto_tree *tree,
	gint idx,
	const char *subtree_name)
{
	proto_tree *subtree;

	subtree = proto_tree_add_subtree(tree,
		tvb, 0, 0, idx, NULL, subtree_name);

	dissect_iso20_ac_TransformType(&node->Transform,
		tvb, pinfo, subtree,
		ett_struct_iso20_ac_TransformType, "Transform");

	return;
}

static void
dissect_iso20_ac_TransformType(
	const struct iso20_ac_TransformType *node,
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
		hf_struct_iso20_ac_TransformType_Algorithm,
		tvb,
		node->Algorithm.characters,
		node->Algorithm.charactersLen,
		sizeof(node->Algorithm.characters));

	if (node->ANY_isUsed) {
		exi_add_bytes(subtree,
			hf_struct_iso20_ac_TransformType_ANY,
			tvb,
			node->ANY.bytes,
			node->ANY.bytesLen,
			sizeof(node->ANY.bytes));
	}

	if (node->XPath_isUsed) {
		exi_add_characters(subtree,
			hf_struct_iso20_ac_TransformType_XPath,
			tvb,
			node->XPath.characters,
			node->XPath.charactersLen,
			sizeof(node->XPath.characters));
	}

	return;
}

static void
dissect_iso20_ac_DigestMethodType(
	const struct iso20_ac_DigestMethodType *node,
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
		hf_struct_iso20_ac_DigestMethodType_Algorithm,
		tvb,
		node->Algorithm.characters,
		node->Algorithm.charactersLen,
		sizeof(node->Algorithm.characters));

	if (node->ANY_isUsed) {
		exi_add_bytes(subtree,
			hf_struct_iso20_ac_DigestMethodType_ANY,
			tvb,
			node->ANY.bytes,
			node->ANY.bytesLen,
			sizeof(node->ANY.bytes));
	}

	return;
}

static void
dissect_iso20_ac_KeyInfoType(
	const struct iso20_ac_KeyInfoType *node,
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
			hf_struct_iso20_ac_KeyInfoType_Id,
			tvb,
			node->Id.characters,
			node->Id.charactersLen,
			sizeof(node->Id.characters));
	}

	if (node->KeyName_isUsed) {
		exi_add_characters(subtree,
			hf_struct_iso20_ac_KeyInfoType_KeyName,
			tvb,
			node->KeyName.characters,
			node->KeyName.charactersLen,
			sizeof(node->KeyName.characters));
	}

	if (node->KeyValue_isUsed) {
		dissect_iso20_ac_KeyValueType(&node->KeyValue,
			tvb, pinfo, subtree,
			ett_struct_iso20_ac_KeyValueType,
			"KeyValue");
	}

	if (node->RetrievalMethod_isUsed) {
		dissect_iso20_ac_RetrievalMethodType(
			&node->RetrievalMethod,
			tvb, pinfo, subtree,
			ett_struct_iso20_ac_RetrievalMethodType,
			"RetrievalMethod");
	}

	if (node->X509Data_isUsed) {
		dissect_iso20_ac_X509DataType(&node->X509Data,
			tvb, pinfo, subtree,
			ett_struct_iso20_ac_X509DataType, "X509Data");
	}

	if (node->PGPData_isUsed) {
		dissect_iso20_ac_PGPDataType(&node->PGPData,
			tvb, pinfo, subtree,
			ett_struct_iso20_ac_PGPDataType, "PGPData");
	}

	if (node->SPKIData_isUsed) {
		dissect_iso20_ac_SPKIDataType(&node->SPKIData,
			tvb, pinfo, subtree,
			ett_struct_iso20_ac_SPKIDataType, "SPKIData");
	}

	if (node->MgmtData_isUsed) {
		exi_add_characters(subtree,
			hf_struct_iso20_ac_KeyInfoType_MgmtData,
			tvb,
			node->MgmtData.characters,
			node->MgmtData.charactersLen,
			sizeof(node->MgmtData.characters));
	}

	if (node->ANY_isUsed) {
		exi_add_bytes(subtree,
			hf_struct_iso20_ac_KeyInfoType_ANY,
			tvb,
			node->ANY.bytes,
			node->ANY.bytesLen,
			sizeof(node->ANY.bytes));
	}

	return;
}

static void
dissect_iso20_ac_KeyValueType(
	const struct iso20_ac_KeyValueType *node,
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
		dissect_iso20_ac_DSAKeyValueType(&node->DSAKeyValue,
			tvb, pinfo, subtree,
			ett_struct_iso20_ac_DSAKeyValueType,
			"DSAKeyValue");
	}
	if (node->RSAKeyValue_isUsed) {
		dissect_iso20_ac_RSAKeyValueType(&node->RSAKeyValue,
			tvb, pinfo, subtree,
			ett_struct_iso20_ac_RSAKeyValueType,
			"RSAKeyValue");
	}

	exi_add_bytes(subtree,
		hf_struct_iso20_ac_KeyValueType_ANY,
		tvb,
		node->ANY.bytes,
		node->ANY.bytesLen,
		sizeof(node->ANY.bytes));

	return;
}

static void
dissect_iso20_ac_RetrievalMethodType(
	const struct iso20_ac_RetrievalMethodType *node,
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
			hf_struct_iso20_ac_RetrievalMethodType_Type,
			tvb,
			node->Type.characters,
			node->Type.charactersLen,
			sizeof(node->Type.characters));
	}
	if (node->URI_isUsed) {
		exi_add_characters(subtree,
			hf_struct_iso20_ac_RetrievalMethodType_URI,
			tvb,
			node->URI.characters,
			node->URI.charactersLen,
			sizeof(node->URI.characters));
	}
	if (node->Transforms_isUsed) {
		dissect_iso20_ac_TransformsType(&node->Transforms,
			tvb, pinfo, subtree,
			ett_struct_iso20_ac_TransformsType,
			"Transforms");
	}

	return;
}

static void
dissect_iso20_ac_X509DataType(
	const struct iso20_ac_X509DataType *node,
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
		dissect_iso20_ac_X509IssuerSerialType(
			&node->X509IssuerSerial,
			tvb, pinfo, subtree,
			ett_struct_iso20_ac_X509IssuerSerialType,
			"X509IssuerSerial");
	}
	if (node->X509SKI_isUsed) {
		exi_add_bytes(subtree,
			hf_struct_iso20_ac_X509DataType_X509SKI,
			tvb,
			node->X509SKI.bytes,
			node->X509SKI.bytesLen,
			sizeof(node->X509SKI.bytes));
	}
	if (node->X509SubjectName_isUsed) {
		exi_add_characters(subtree,
			hf_struct_iso20_ac_X509DataType_X509SubjectName,
			tvb,
			node->X509SubjectName.characters,
			node->X509SubjectName.charactersLen,
			sizeof(node->X509SubjectName.characters));
	}

	if (node->X509Certificate_isUsed) {
		if (v2gber_handle == NULL) {
			exi_add_bytes(subtree,
				hf_struct_iso20_ac_X509DataType_X509Certificate,
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
				ett_v2giso20_ac_asn1, NULL,
				"X509Certificate ASN1");
			call_dissector(v2gber_handle, child, pinfo, asn1_tree);
		}
	}

	if (node->X509CRL_isUsed) {
		exi_add_bytes(subtree,
			hf_struct_iso20_ac_X509DataType_X509CRL,
			tvb,
			node->X509CRL.bytes,
			node->X509CRL.bytesLen,
			sizeof(node->X509CRL.bytes));
	}

	if (node->ANY_isUsed) {
		exi_add_bytes(subtree,
			hf_struct_iso20_ac_X509DataType_ANY,
			tvb,
			node->ANY.bytes,
			node->ANY.bytesLen,
			sizeof(node->ANY.bytes));
	}

	return;
}

static void
dissect_iso20_ac_PGPDataType(
	const struct iso20_ac_PGPDataType *node,
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
			hf_struct_iso20_ac_PGPDataType_PGPKeyID,
			tvb,
			node->choice_1.PGPKeyID.bytes,
			node->choice_1.PGPKeyID.bytesLen,
			sizeof(node->choice_1.PGPKeyID.bytes));

		if (node->choice_1.PGPKeyPacket_isUsed) {
			exi_add_bytes(subtree,
				hf_struct_iso20_ac_PGPDataType_PGPKeyPacket,
				tvb,
				node->choice_1.PGPKeyPacket.bytes,
				node->choice_1.PGPKeyPacket.bytesLen,
				sizeof(node->choice_1.PGPKeyPacket.bytes));
		}

		if (node->choice_1.ANY_isUsed) {
			exi_add_bytes(subtree,
				hf_struct_iso20_ac_PGPDataType_ANY,
				tvb,
				node->choice_1.ANY.bytes,
				node->choice_1.ANY.bytesLen,
				sizeof(node->choice_1.ANY.bytes));
		}
	}

	if (node->choice_2_isUsed) {
		exi_add_bytes(subtree,
			hf_struct_iso20_ac_PGPDataType_PGPKeyPacket,
			tvb,
			node->choice_2.PGPKeyPacket.bytes,
			node->choice_2.PGPKeyPacket.bytesLen,
			sizeof(node->choice_2.PGPKeyPacket.bytes));

		if (node->choice_2.ANY_isUsed) {
			exi_add_bytes(subtree,
				hf_struct_iso20_ac_PGPDataType_ANY,
				tvb,
				node->choice_2.ANY.bytes,
				node->choice_2.ANY.bytesLen,
				sizeof(node->choice_2.ANY.bytes));
		}
	}

	return;
}

static void
dissect_iso20_ac_SPKIDataType(
	const struct iso20_ac_SPKIDataType *node,
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
		hf_struct_iso20_ac_SPKIDataType_SPKISexp,
		tvb,
		node->SPKISexp.bytes,
		node->SPKISexp.bytesLen,
		sizeof(node->SPKISexp.bytes));

	if (node->ANY_isUsed) {
		exi_add_bytes(subtree,
			hf_struct_iso20_ac_SPKIDataType_ANY,
			tvb,
			node->ANY.bytes,
			node->ANY.bytesLen,
			sizeof(node->ANY.bytes));
	}

	return;
}

static void
dissect_iso20_ac_ObjectType(
	const struct iso20_ac_ObjectType *node,
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
			hf_struct_iso20_ac_ObjectType_Id,
			tvb,
			node->Id.characters,
			node->Id.charactersLen,
			sizeof(node->Id.characters));
	}
	if (node->MimeType_isUsed) {
		exi_add_characters(subtree,
			hf_struct_iso20_ac_ObjectType_MimeType,
			tvb,
			node->MimeType.characters,
			node->MimeType.charactersLen,
			sizeof(node->MimeType.characters));
	}
	if (node->Encoding_isUsed) {
		exi_add_characters(subtree,
			hf_struct_iso20_ac_ObjectType_Encoding,
			tvb,
			node->Encoding.characters,
			node->Encoding.charactersLen,
			sizeof(node->Encoding.characters));
	}
	if (node->ANY_isUsed) {
		exi_add_bytes(subtree,
			hf_struct_iso20_ac_ObjectType_ANY,
			tvb,
			node->ANY.bytes,
			node->ANY.bytesLen,
			sizeof(node->ANY.bytes));
	}

	return;
}

#ifdef notyet
static void
dissect_iso20_ac_ManifestType(
	const struct iso20_ac_ManifestType *node _U_,
	tvbuff_t *tvb _U_,
	packet_info *pinfo _U_,
	proto_tree *tree _U_,
	gint idx _U_,
	const char *subtree_name _U_)
{
	/* TODO */
	return;
}
#endif

#ifdef notyet
static void
dissect_iso20_ac_SignaturePropertiesType(
	const struct iso20_ac_SignaturePropertiesType *node _U_,
	tvbuff_t *tvb _U_,
	packet_info *pinfo _U_,
	proto_tree *tree _U_,
	gint idx _U_,
	const char *subtree_name _U_)
{
	/* TODO */
	return;
}
#endif

#ifdef notyet
static void
dissect_iso20_ac_SignaturePropertyType(
	const struct iso20_ac_SignaturePropertyType *node _U_,
	tvbuff_t *tvb _U_,
	packet_info *pinfo _U_,
	proto_tree *tree _U_,
	gint idx _U_,
	const char *subtree_name _U_)
{
	/* TODO */
	return;
}
#endif

static void
dissect_iso20_ac_DSAKeyValueType(
	const struct iso20_ac_DSAKeyValueType *node,
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
			hf_struct_iso20_ac_DSAKeyValueType_P,
			tvb,
			node->P.bytes,
			node->P.bytesLen,
			sizeof(node->P.bytes));
	}
	if (node->Q_isUsed) {
		exi_add_bytes(subtree,
			hf_struct_iso20_ac_DSAKeyValueType_Q,
			tvb,
			node->Q.bytes,
			node->Q.bytesLen,
			sizeof(node->Q.bytes));
	}
	if (node->G_isUsed) {
		exi_add_bytes(subtree,
			hf_struct_iso20_ac_DSAKeyValueType_G,
			tvb,
			node->G.bytes,
			node->G.bytesLen,
			sizeof(node->G.bytes));
	}
	exi_add_bytes(subtree,
		hf_struct_iso20_ac_DSAKeyValueType_Y,
		tvb,
		node->Y.bytes,
		node->Y.bytesLen,
		sizeof(node->Y.bytes));
	if (node->J_isUsed) {
		exi_add_bytes(subtree,
			hf_struct_iso20_ac_DSAKeyValueType_J,
			tvb,
			node->J.bytes,
			node->J.bytesLen,
			sizeof(node->J.bytes));
	}
	if (node->Seed_isUsed) {
		exi_add_bytes(subtree,
			hf_struct_iso20_ac_DSAKeyValueType_Seed,
			tvb,
			node->Seed.bytes,
			node->Seed.bytesLen,
			sizeof(node->Seed.bytes));
	}
	if (node->PgenCounter_isUsed) {
		exi_add_bytes(subtree,
			hf_struct_iso20_ac_DSAKeyValueType_PgenCounter,
			tvb,
			node->PgenCounter.bytes,
			node->PgenCounter.bytesLen,
			sizeof(node->PgenCounter.bytes));
	}

	return;
}

static void
dissect_iso20_ac_RSAKeyValueType(
	const struct iso20_ac_RSAKeyValueType *node,
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
		hf_struct_iso20_ac_RSAKeyValueType_Modulus,
		tvb,
		node->Modulus.bytes,
		node->Modulus.bytesLen,
		sizeof(node->Modulus.bytes));

	exi_add_bytes(subtree,
		hf_struct_iso20_ac_RSAKeyValueType_Exponent,
		tvb,
		node->Exponent.bytes,
		node->Exponent.bytesLen,
		sizeof(node->Exponent.bytes));

	return;
}


static void
dissect_iso20_ac_MessageHeaderType(
	const struct iso20_ac_MessageHeaderType *node,
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
		hf_struct_iso20_ac_MessageHeaderType_SessionID,
		tvb,
		node->SessionID.bytes,
		node->SessionID.bytesLen,
		sizeof(node->SessionID.bytes));

	it = proto_tree_add_uint64(subtree,
		hf_struct_iso20_ac_MessageHeaderType_TimeStamp,
		tvb, 0, 0, node->TimeStamp);
	proto_item_set_generated(it);

	if (node->Signature_isUsed) {
		dissect_iso20_ac_SignatureType(
			&node->Signature, tvb, pinfo, subtree,
			ett_struct_iso20_ac_SignatureType,
			"Signature");
	}

	return;
}

static void
dissect_iso20_ac_X509IssuerSerialType(
	const struct iso20_ac_X509IssuerSerialType *node,
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
		hf_struct_iso20_ac_X509IssuerSerialType_X509IssuerName,
		tvb,
		node->X509IssuerName.characters,
		node->X509IssuerName.charactersLen,
		sizeof(node->X509IssuerName.characters));

	it = proto_tree_add_int64(subtree,
		hf_struct_iso20_ac_X509IssuerSerialType_X509SerialNumber,
		tvb, 0, 0, node->X509SerialNumber);
	proto_item_set_generated(it);

	return;
}


/* other node dissectors - each node is represented by a struct */
static void dissect_iso20_ac_AC_CPDReqEnergyTransferModeType(
	const struct iso20_ac_AC_CPDReqEnergyTransferModeType *node,
	tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
	gint idx, const char *subtree_name);
static void dissect_iso20_ac_AC_CPDResEnergyTransferModeType(
	const struct iso20_ac_AC_CPDResEnergyTransferModeType *node,
	tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
	gint idx, const char *subtree_name);
static void dissect_iso20_ac_BPT_AC_CPDReqEnergyTransferModeType(
	const struct iso20_ac_BPT_AC_CPDReqEnergyTransferModeType *node,
	tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
	gint idx, const char *subtree_name);
static void dissect_iso20_ac_BPT_AC_CPDResEnergyTransferModeType(
	const struct iso20_ac_BPT_AC_CPDResEnergyTransferModeType *node,
	tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
	gint idx, const char *subtree_name);
static void dissect_iso20_ac_Scheduled_AC_CLReqControlModeType(
	const struct iso20_ac_Scheduled_AC_CLReqControlModeType *node,
	tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
	gint idx, const char *subtree_name);
static void dissect_iso20_ac_Scheduled_AC_CLResControlModeType(
	const struct iso20_ac_Scheduled_AC_CLResControlModeType *node,
	tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
	gint idx, const char *subtree_name);
static void dissect_iso20_ac_BPT_Scheduled_AC_CLReqControlModeType(
	const struct iso20_ac_BPT_Scheduled_AC_CLReqControlModeType *node,
	tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
	gint idx, const char *subtree_name);
static void dissect_iso20_ac_BPT_Scheduled_AC_CLResControlModeType(
	const struct iso20_ac_BPT_Scheduled_AC_CLResControlModeType *node,
	tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
	gint idx, const char *subtree_name);
static void dissect_iso20_ac_Dynamic_AC_CLReqControlModeType(
	const struct iso20_ac_Dynamic_AC_CLReqControlModeType *node,
	tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
	gint idx, const char *subtree_name);
static void dissect_iso20_ac_Dynamic_AC_CLResControlModeType(
	const struct iso20_ac_Dynamic_AC_CLResControlModeType *node,
	tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
	gint idx, const char *subtree_name);
static void dissect_iso20_ac_BPT_Dynamic_AC_CLReqControlModeType(
	const struct iso20_ac_BPT_Dynamic_AC_CLReqControlModeType *node,
	tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
	gint idx, const char *subtree_name);
static void dissect_iso20_ac_BPT_Dynamic_AC_CLResControlModeType(
	const struct iso20_ac_BPT_Dynamic_AC_CLResControlModeType *node,
	tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
	gint idx, const char *subtree_name);
static void dissect_iso20_ac_CLReqControlModeType(
	const struct iso20_ac_CLReqControlModeType *node,
	tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
	gint idx, const char *subtree_name);
static void dissect_iso20_ac_CLResControlModeType(
	const struct iso20_ac_CLResControlModeType *node,
	tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
	gint idx, const char *subtree_name);


static void
dissect_iso20_ac_AC_CPDReqEnergyTransferModeType(
	const struct iso20_ac_AC_CPDReqEnergyTransferModeType *node _U_,
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
	const struct iso20_ac_AC_CPDResEnergyTransferModeType *node _U_,
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
	const struct iso20_ac_BPT_AC_CPDReqEnergyTransferModeType *node _U_,
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
	const struct iso20_ac_BPT_AC_CPDResEnergyTransferModeType *node _U_,
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
	const struct iso20_ac_Scheduled_AC_CLReqControlModeType *node _U_,
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
	const struct iso20_ac_Scheduled_AC_CLResControlModeType *node _U_,
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
	const struct iso20_ac_BPT_Scheduled_AC_CLReqControlModeType *node _U_,
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
	const struct iso20_ac_BPT_Scheduled_AC_CLResControlModeType *node _U_,
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
	const struct iso20_ac_Dynamic_AC_CLReqControlModeType *node _U_,
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
	const struct iso20_ac_Dynamic_AC_CLResControlModeType *node _U_,
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
	const struct iso20_ac_BPT_Dynamic_AC_CLReqControlModeType *node _U_,
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
	const struct iso20_ac_BPT_Dynamic_AC_CLResControlModeType *node _U_,
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
	const struct iso20_ac_CLReqControlModeType *node _U_,
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
	const struct iso20_ac_CLResControlModeType *node _U_,
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
dissect_iso20_ac_DisplayParametersType(
	const struct iso20_ac_DisplayParametersType *node _U_,
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
dissect_iso20_ac_EVSEStatusType(
	const struct iso20_ac_EVSEStatusType *node _U_,
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
dissect_iso20_ac_MeterInfoType(
	const struct iso20_ac_MeterInfoType *node _U_,
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
dissect_iso20_ac_ReceiptType(
	const struct iso20_ac_ReceiptType *node _U_,
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
dissect_iso20_ac_RationalNumberType(
	const struct iso20_ac_RationalNumberType *node _U_,
	tvbuff_t *tvb _U_,
	packet_info *pinfo _U_,
	proto_tree *tree _U_,
	gint idx _U_,
	const char *subtree_name _U_)
{
	/* TODO */
	return;
}


/* request/response dissectors */
static void
dissect_iso20_ac_AC_ChargeParameterDiscoveryReqType(
	const struct iso20_ac_AC_ChargeParameterDiscoveryReqType *req _U_,
	tvbuff_t *tvb _U_,
	packet_info *pinfo _U_,
	proto_tree *tree _U_,
	gint idx _U_,
	const char *subtree_name _U_)
{
	proto_tree *subtree;

	subtree = proto_tree_add_subtree(tree,
		tvb, 0, 0, idx, NULL, subtree_name);

	dissect_iso20_ac_MessageHeaderType(&req->Header,
		tvb, pinfo, subtree,
		ett_struct_iso20_ac_MessageHeaderType, "Header");

	if (req->AC_CPDReqEnergyTransferMode_isUsed) {
		dissect_iso20_ac_AC_CPDReqEnergyTransferModeType(
			&req->AC_CPDReqEnergyTransferMode,
			tvb, pinfo, subtree,
			ett_struct_iso20_ac_AC_CPDReqEnergyTransferModeType,
			"AC_CPDReqEnergyTransferMode");
	}
	if (req->BPT_AC_CPDReqEnergyTransferMode_isUsed) {
		dissect_iso20_ac_BPT_AC_CPDReqEnergyTransferModeType(
			&req->BPT_AC_CPDReqEnergyTransferMode,
			tvb, pinfo, subtree,
			ett_struct_iso20_ac_BPT_AC_CPDReqEnergyTransferModeType,
			"BPT_AC_CPDReqEnergyTransferMode");
	}

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
	proto_tree *subtree;
	proto_item *it;

	subtree = proto_tree_add_subtree(tree,
		tvb, 0, 0, idx, NULL, subtree_name);

	dissect_iso20_ac_MessageHeaderType(&res->Header,
		tvb, pinfo, subtree,
		ett_struct_iso20_ac_MessageHeaderType, "Header");

	it = proto_tree_add_uint(subtree,
		hf_struct_iso20_ac_AC_ChargeParameterDiscoveryResType_ResponseCode,
		tvb, 0, 0, res->ResponseCode);
	proto_item_set_generated(it);

	if (res->AC_CPDResEnergyTransferMode_isUsed) {
		dissect_iso20_ac_AC_CPDResEnergyTransferModeType(
			&res->AC_CPDResEnergyTransferMode,
			tvb, pinfo, subtree,
			ett_struct_iso20_ac_AC_CPDResEnergyTransferModeType,
			"AC_CPDResEnergyTransferMode");
	}

	if (res->BPT_AC_CPDResEnergyTransferMode_isUsed) {
		dissect_iso20_ac_BPT_AC_CPDResEnergyTransferModeType(
			&res->BPT_AC_CPDResEnergyTransferMode,
			tvb, pinfo, subtree,
			ett_struct_iso20_ac_BPT_AC_CPDResEnergyTransferModeType,
			"BPT_AC_CPDResEnergyTransferMode");
	}

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
	proto_tree *subtree;
	proto_item *it;

	subtree = proto_tree_add_subtree(tree,
		tvb, 0, 0, idx, NULL, subtree_name);

	dissect_iso20_ac_MessageHeaderType(&req->Header,
		tvb, pinfo, subtree,
		ett_struct_iso20_ac_MessageHeaderType, "Header");

	if (req->DisplayParameters_isUsed) {
		dissect_iso20_ac_DisplayParametersType(
			&req->DisplayParameters,
			tvb, pinfo, subtree,
			ett_struct_iso20_ac_DisplayParametersType,
			"DisplayParameters");
	}

	it = proto_tree_add_uint(subtree,
		hf_struct_iso20_ac_AC_ChargeLoopReqType_MeterInfoRequested,
		tvb, 0, 0, req->MeterInfoRequested);
	proto_item_set_generated(it);

	if (req->BPT_Dynamic_AC_CLReqControlMode_isUsed) {
		dissect_iso20_ac_BPT_Dynamic_AC_CLReqControlModeType(
			&req->BPT_Dynamic_AC_CLReqControlMode,
			tvb, pinfo, subtree,
			ett_struct_iso20_ac_BPT_Dynamic_AC_CLReqControlModeType,
			"BPT_Dynamic_AC_CLReqControlMode");
	}
	if (req->BPT_Scheduled_AC_CLReqControlMode_isUsed) {
		dissect_iso20_ac_BPT_Scheduled_AC_CLReqControlModeType(
			&req->BPT_Scheduled_AC_CLReqControlMode,
			tvb, pinfo, subtree,
			ett_struct_iso20_ac_BPT_Scheduled_AC_CLReqControlModeType,
			"BPT_Scheduled_AC_CLReqControlMode");
	}
	if (req->CLReqControlMode_isUsed) {
		dissect_iso20_ac_CLReqControlModeType(
			&req->CLReqControlMode,
			tvb, pinfo, subtree,
			ett_struct_iso20_ac_CLReqControlModeType,
			"CLReqControlMode");
	}
	if (req->Dynamic_AC_CLReqControlMode_isUsed) {
		dissect_iso20_ac_Dynamic_AC_CLReqControlModeType(
			&req->Dynamic_AC_CLReqControlMode,
			tvb, pinfo, subtree,
			ett_struct_iso20_ac_Dynamic_AC_CLReqControlModeType,
			"Dynamic_AC_CLReqControlMode");
	}
	if (req->Scheduled_AC_CLReqControlMode_isUsed) {
		dissect_iso20_ac_Scheduled_AC_CLReqControlModeType(
			&req->Scheduled_AC_CLReqControlMode,
			tvb, pinfo, subtree,
			ett_struct_iso20_ac_Scheduled_AC_CLReqControlModeType,
			"Scheduled_AC_CLReqControlMode");
	}

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
	proto_tree *subtree;
	proto_item *it;

	subtree = proto_tree_add_subtree(tree,
		tvb, 0, 0, idx, NULL, subtree_name);

	dissect_iso20_ac_MessageHeaderType(&res->Header,
		tvb, pinfo, subtree,
		ett_struct_iso20_ac_MessageHeaderType, "Header");

	it = proto_tree_add_uint(subtree,
		hf_struct_iso20_ac_AC_ChargeLoopResType_ResponseCode,
		tvb, 0, 0, res->ResponseCode);
	proto_item_set_generated(it);

	if (res->EVSEStatus_isUsed) {
		dissect_iso20_ac_EVSEStatusType(
			&res->EVSEStatus,
			tvb, pinfo, subtree,
			ett_struct_iso20_ac_EVSEStatusType, "EVSEStatus");
	}
	if (res->MeterInfo_isUsed) {
		dissect_iso20_ac_MeterInfoType(
			&res->MeterInfo,
			tvb, pinfo, subtree,
			ett_struct_iso20_ac_MeterInfoType, "MeterInfo");
	}
	if (res->Receipt_isUsed) {
		dissect_iso20_ac_ReceiptType(
			&res->Receipt,
			tvb, pinfo, subtree,
			ett_struct_iso20_ac_ReceiptType, "Receipt");
	}
	if (res->EVSETargetFrequency_isUsed) {
		dissect_iso20_ac_RationalNumberType(
			&res->EVSETargetFrequency,
			tvb, pinfo, subtree,
			ett_struct_iso20_ac_RationalNumberType,
			"EVSETargetFrequency");
	}
	if (res->BPT_Dynamic_AC_CLResControlMode_isUsed) {
		dissect_iso20_ac_BPT_Dynamic_AC_CLResControlModeType(
			&res->BPT_Dynamic_AC_CLResControlMode,
			tvb, pinfo, subtree,
			ett_struct_iso20_ac_BPT_Dynamic_AC_CLResControlModeType,
			"BPT_Dynamic_AC_CLResControlMode");
	}
	if (res->BPT_Scheduled_AC_CLResControlMode_isUsed) {
		dissect_iso20_ac_BPT_Scheduled_AC_CLResControlModeType(
			&res->BPT_Scheduled_AC_CLResControlMode,
			tvb, pinfo, subtree,
			ett_struct_iso20_ac_BPT_Scheduled_AC_CLResControlModeType,
			"BPT_Scheduled_AC_CLResControlMode");
	}
	if (res->CLResControlMode_isUsed) {
		dissect_iso20_ac_CLResControlModeType(
			&res->CLResControlMode,
			tvb, pinfo, subtree,
			ett_struct_iso20_ac_CLResControlModeType,
			"CLResControlMode");
	}
	if (res->Dynamic_AC_CLResControlMode_isUsed) {
		dissect_iso20_ac_Dynamic_AC_CLResControlModeType(
			&res->Dynamic_AC_CLResControlMode,
			tvb, pinfo, subtree,
			ett_struct_iso20_ac_Dynamic_AC_CLResControlModeType,
			"Dynamic_AC_CLResControlMode");
	}
	if (res->Scheduled_AC_CLResControlMode_isUsed) {
		dissect_iso20_ac_Scheduled_AC_CLResControlModeType(
			&res->Scheduled_AC_CLResControlMode,
			tvb, pinfo, subtree,
			ett_struct_iso20_ac_Scheduled_AC_CLResControlModeType,
			"Scheduled_AC_CLResControlMode");
	}

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
		/* struct iso20_ac_MessageHeaderType */
		{ &hf_struct_iso20_ac_MessageHeaderType_SessionID,
		  { "SessionID", "v2giso20.ac.struct.messageheader.sessionid",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_struct_iso20_ac_MessageHeaderType_TimeStamp,
		  { "TimeStamp", "v2giso20.ac.struct.messageheader.timestamp",
		    FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso20_ac_SignatureType */
		{ &hf_struct_iso20_ac_SignatureType_Id,
		  { "Id", "v2giso20.ac.struct.signature.id",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso20_ac_SignedInfoType */
		{ &hf_struct_iso20_ac_SignedInfoType_Id,
		  { "Id", "v2giso20.ac.struct.signedinfo.id",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso20_ac_CanonicalizationMethodType */
		{ &hf_struct_iso20_ac_CanonicalizationMethodType_Algorithm,
		  { "Algorithm",
		    "v2giso20.ac.struct.canonicalizationmethod.algorithm",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_struct_iso20_ac_CanonicalizationMethodType_ANY,
		  { "ANY",
		    "v2giso20.ac.struct.canonicalizationmethod.any",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso20_ac_SignatureMethodType */
		{ &hf_struct_iso20_ac_SignatureMethodType_Algorithm,
		  { "Algorithm", "v2giso20.ac.struct.signaturemethod.algorithm",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_struct_iso20_ac_SignatureMethodType_HMACOutputLength,
		  { "HMACOutputLength",
		    "v2giso20.ac.struct.signaturemethod.hmacoutputlength",
		    FT_INT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_struct_iso20_ac_SignatureMethodType_ANY,
		  { "ANY", "v2giso20.ac.struct.signaturemethod.any",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso20_ac_ReferenceType */
		{ &hf_struct_iso20_ac_ReferenceType_Id,
		  { "Id", "v2giso20.ac.struct.reference.id",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_struct_iso20_ac_ReferenceType_Type,
		  { "Type", "v2giso20.ac.struct.reference.type",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_struct_iso20_ac_ReferenceType_URI,
		  { "URI", "v2giso20.ac.struct.reference.uri",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_struct_iso20_ac_ReferenceType_DigestValue,
		  { "DigestValue", "v2giso20.ac.struct.reference.digestvalue",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso20_ac_TransformType */
		{ &hf_struct_iso20_ac_TransformType_Algorithm,
		  { "Algorithm", "v2giso20.ac.struct.transform.algorithm",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_struct_iso20_ac_TransformType_ANY,
		  { "ANY", "v2giso20.ac.struct.transform.any",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_struct_iso20_ac_TransformType_XPath,
		  { "XPath", "v2giso20.ac.struct.transform.xpath",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso20_ac_DigestMethodType */
		{ &hf_struct_iso20_ac_DigestMethodType_Algorithm,
		  { "Algorithm", "v2giso20.ac.struct.digestmethod.algorithm",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_struct_iso20_ac_DigestMethodType_ANY,
		  { "ANY", "v2giso20.ac.struct.digestmethod.any",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso20_ac_SignatureValueType */
		{ &hf_struct_iso20_ac_SignatureValueType_Id,
		  { "Id", "v2giso20.ac.struct.signaturevalue.id",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_struct_iso20_ac_SignatureValueType_CONTENT,
		  { "CONTENT", "v2giso20.ac.struct.signaturevalue.content",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso20_ac_KeyInfoType */
		{ &hf_struct_iso20_ac_KeyInfoType_Id,
		  { "Id", "v2giso20.ac.struct.keyinfo.id",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_struct_iso20_ac_KeyInfoType_KeyName,
		  { "KeyName", "v2giso20.ac.struct.keyinfo.keyname",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_struct_iso20_ac_KeyInfoType_MgmtData,
		  { "MgmtData", "v2giso20.ac.struct.keyinfo.mgmtdata",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_struct_iso20_ac_KeyInfoType_ANY,
		  { "ANY", "v2giso20.ac.struct.keyinfo.any",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso20_KeyValueType */
		{ &hf_struct_iso20_ac_KeyValueType_ANY,
		  { "ANY", "v2giso20.ac.struct.keyvalue.any",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso20_ac_DSAKeyValueType */
		{ &hf_struct_iso20_ac_DSAKeyValueType_P,
		  { "P", "v2giso20.ac.struct.dsakeyvalue.p",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_struct_iso20_ac_DSAKeyValueType_Q,
		  { "Q", "v2giso20.ac.struct.dsakeyvalue.q",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_struct_iso20_ac_DSAKeyValueType_G,
		  { "G", "v2giso20.ac.struct.dsakeyvalue.g",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_struct_iso20_ac_DSAKeyValueType_Y,
		  { "Y", "v2giso20.ac.struct.dsakeyvalue.y",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_struct_iso20_ac_DSAKeyValueType_J,
		  { "J", "v2giso20.ac.struct.dsakeyvalue.j",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_struct_iso20_ac_DSAKeyValueType_Seed,
		  { "Seed", "v2giso20.ac.struct.dsakeyvalue.seed",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_struct_iso20_ac_DSAKeyValueType_PgenCounter,
		  { "PgenCounter", "v2giso20.ac.struct.dsakeyvalue.pgencounter",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso20_ac_RSAKeyValueType */
		{ &hf_struct_iso20_ac_RSAKeyValueType_Modulus,
		  { "Modulus", "v2giso20.ac.struct.rsakeyvalue.modulus",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_struct_iso20_ac_RSAKeyValueType_Exponent,
		  { "Exponent", "v2giso20.ac.struct.rsakeyvalue.exponent",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso20_ac_RetrievalMethodType */
		{ &hf_struct_iso20_ac_RetrievalMethodType_URI,
		  { "URI", "v2giso20.ac.struct.retrievalmethod.uri",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_struct_iso20_ac_RetrievalMethodType_Type,
		  { "Type", "v2giso20.ac.struct.retrievalmethod.type",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso20_ac_X509DataType */
		{ &hf_struct_iso20_ac_X509DataType_X509SKI,
		  { "X509SKI", "v2giso20.ac.struct.x509data.x509ski",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_struct_iso20_ac_X509DataType_X509SubjectName,
		  { "X509SubjectName",
		    "v2giso20.ac.struct.x509data.x509subjectname",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_struct_iso20_ac_X509DataType_X509Certificate,
		  { "X509Certificate",
		    "v2giso20.ac.struct.x509data.x509certificate",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_struct_iso20_ac_X509DataType_X509CRL,
		  { "X509CRL", "v2giso20.ac.struct.x509data.x509crl",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_struct_iso20_ac_X509DataType_ANY,
		  { "ANY", "v2giso20.ac.struct.x509data.any",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso20_X509IssuerSerialType */
		{ &hf_struct_iso20_ac_X509IssuerSerialType_X509IssuerName,
		  { "X509IssuerName",
		    "v2giso20.ac.struct.x509issuerserial.x509issuername",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_struct_iso20_ac_X509IssuerSerialType_X509SerialNumber,
		  { "X509SerialNumber",
		    "v2giso20.ac.struct.x509issuerserial.x509serialnumber",
		    FT_INT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso20_ac_PGPDataType */
		{ &hf_struct_iso20_ac_PGPDataType_PGPKeyID,
		  { "PGPKeyID", "v2giso20.ac.struct.pgpdata.pgpkeyid",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_struct_iso20_ac_PGPDataType_PGPKeyPacket,
		  { "PGPKeyPacket", "v2giso20.ac.struct.pgpdata.pgpkeypacket",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_struct_iso20_ac_PGPDataType_ANY,
		  { "ANY", "v2giso20.ac.struct.pgpdata.any",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso20_ac_SPKIDataType */
		{ &hf_struct_iso20_ac_SPKIDataType_SPKISexp,
		  { "SPKISexp", "v2giso20.ac.struct.spkidata.spkisexp",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_struct_iso20_ac_SPKIDataType_ANY,
		  { "ANY", "v2giso20.ac.struct.spkidata.any",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso20_ac_ObjectType */
		{ &hf_struct_iso20_ac_ObjectType_Id,
		  { "Id", "v2giso20.ac.struct.object.id",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_struct_iso20_ac_ObjectType_MimeType,
		  { "MimeType", "v2giso20.ac.struct.object.mimetype",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_struct_iso20_ac_ObjectType_Encoding,
		  { "Encoding", "v2giso20.ac.struct.object.encoding",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_struct_iso20_ac_ObjectType_ANY,
		  { "ANY", "v2giso20.ac.struct.object.any",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso20_ac_AC_ChargeParameterDiscoveryReqType */
		/* struct iso20_ac_AC_ChargeParameterDiscoveryResType */
		{ &hf_struct_iso20_ac_AC_ChargeParameterDiscoveryResType_ResponseCode,
		  { "ResponseCode",
		    "v2giso20.ac.struct.ac_chargeparameterdiscoveryres.responsecode",
		    FT_UINT16, BASE_DEC,
		    VALS(v2giso20_ac_enum_iso20_ac_responseCodeType_names),
		    0x0, NULL, HFILL }
		},

		/* iso20_ac_AC_ChargeLoopReqType */
		{ &hf_struct_iso20_ac_AC_ChargeLoopReqType_MeterInfoRequested,
		  { "MeterInfoRequested",
		    "v2giso20.ac.struct.ac_chargeloopreq.meterinforequested",
		    FT_INT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		/* iso20_ac_AC_ChargeLoopResType */
		{ &hf_struct_iso20_ac_AC_ChargeLoopResType_ResponseCode,
		  { "ResponseCode",
		    "v2giso20.ac.struct.ac_chargeloopres.responsecode",
		    FT_UINT16, BASE_DEC,
		    VALS(v2giso20_ac_enum_iso20_ac_responseCodeType_names),
		    0x0, NULL, HFILL }
		},
	};

	static gint *ett[] = {
		&ett_v2giso20_ac,
		&ett_v2giso20_ac_document,
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
		&ett_struct_iso20_ac_SignatureType,
		&ett_struct_iso20_ac_SignatureValueType,
		&ett_struct_iso20_ac_SignedInfoType,
		&ett_struct_iso20_ac_CanonicalizationMethodType,
		&ett_struct_iso20_ac_SignatureMethodType,
		&ett_struct_iso20_ac_ReferenceType,
		&ett_struct_iso20_ac_TransformsType,
		&ett_struct_iso20_ac_TransformType,
		&ett_struct_iso20_ac_DigestMethodType,
		&ett_struct_iso20_ac_KeyInfoType,
		&ett_struct_iso20_ac_KeyValueType,
		&ett_struct_iso20_ac_RetrievalMethodType,
		&ett_struct_iso20_ac_X509DataType,
		&ett_struct_iso20_ac_PGPDataType,
		&ett_struct_iso20_ac_SPKIDataType,
		&ett_struct_iso20_ac_ObjectType,
		&ett_struct_iso20_ac_ManifestType,
		&ett_struct_iso20_ac_SignaturePropertiesType,
		&ett_struct_iso20_ac_SignaturePropertyType,
		&ett_struct_iso20_ac_DSAKeyValueType,
		&ett_struct_iso20_ac_RSAKeyValueType,

		&ett_struct_iso20_ac_MessageHeaderType,
		&ett_struct_iso20_ac_X509IssuerSerialType,

		&ett_struct_iso20_ac_DisplayParametersType,
		&ett_struct_iso20_ac_EVSEStatusType,
		&ett_struct_iso20_ac_MeterInfoType,
		&ett_struct_iso20_ac_ReceiptType,
		&ett_struct_iso20_ac_RationalNumberType,
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
