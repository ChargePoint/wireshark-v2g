/*
 * Copyright (c) 2022 ChargePoint, Inc.
 * All rights reserved.
 *
 * See LICENSE file
 */

#include "config.h"

#include <inttypes.h>
#include <stdlib.h>

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/expert.h>

/* openv2g */
#include <codec/EXITypes.h>
#include <iso2/iso2EXIDatatypes.h>
#include <iso2/iso2EXIDatatypesDecoder.h>

#include "v2gexi.h"


/* forward declare */
void proto_register_v2giso2(void);
void proto_reg_handoff_v2giso2(void);


static dissector_handle_t v2gexi_handle;
static dissector_handle_t v2gber_handle;

static int proto_v2giso2 = -1;

static int hf_v2giso2_struct_iso2MessageHeaderType_SessionID = -1;

static int hf_v2giso2_struct_iso2SignatureType_Id = -1;
static int hf_v2giso2_struct_iso2SignedInfoType_Id = -1;
static int hf_v2giso2_struct_iso2CanonicalizationMethodType_Algorithm = -1;
static int hf_v2giso2_struct_iso2CanonicalizationMethodType_ANY = -1;
static int hf_v2giso2_struct_iso2SignatureMethodType_Algorithm = -1;
static int hf_v2giso2_struct_iso2SignatureMethodType_HMACOutputLength = -1;
static int hf_v2giso2_struct_iso2SignatureMethodType_ANY = -1;
static int hf_v2giso2_struct_iso2ReferenceType_Id = -1;
static int hf_v2giso2_struct_iso2ReferenceType_URI = -1;
static int hf_v2giso2_struct_iso2ReferenceType_Type = -1;
static int hf_v2giso2_struct_iso2ReferenceType_DigestValue = -1;
static int hf_v2giso2_struct_iso2SignatureValueType_Id = -1;
static int hf_v2giso2_struct_iso2SignatureValueType_CONTENT = -1;
static int hf_v2giso2_struct_iso2ObjectType_Id = -1;
static int hf_v2giso2_struct_iso2ObjectType_MimeType = -1;
static int hf_v2giso2_struct_iso2ObjectType_Encoding = -1;
static int hf_v2giso2_struct_iso2ObjectType_ANY = -1;
static int hf_v2giso2_struct_iso2TransformType_Algorithm = -1;
static int hf_v2giso2_struct_iso2TransformType_ANY = -1;
static int hf_v2giso2_struct_iso2TransformType_XPath = -1;
static int hf_v2giso2_struct_iso2DigestMethodType_Algorithm = -1;
static int hf_v2giso2_struct_iso2DigestMethodType_ANY = -1;
static int hf_v2giso2_struct_iso2KeyInfoType_Id = -1;
static int hf_v2giso2_struct_iso2KeyInfoType_KeyName = -1;
static int hf_v2giso2_struct_iso2KeyInfoType_MgmtData = -1;
static int hf_v2giso2_struct_iso2KeyInfoType_ANY = -1;
static int hf_v2giso2_struct_iso2RetrievalMethodType_URI = -1;
static int hf_v2giso2_struct_iso2RetrievalMethodType_Type = -1;
static int hf_v2giso2_struct_iso2KeyValueType_ANY = -1;
static int hf_v2giso2_struct_iso2DSAKeyValueType_P = -1;
static int hf_v2giso2_struct_iso2DSAKeyValueType_Q = -1;
static int hf_v2giso2_struct_iso2DSAKeyValueType_G = -1;
static int hf_v2giso2_struct_iso2DSAKeyValueType_Y = -1;
static int hf_v2giso2_struct_iso2DSAKeyValueType_J = -1;
static int hf_v2giso2_struct_iso2DSAKeyValueType_Seed = -1;
static int hf_v2giso2_struct_iso2DSAKeyValueType_PgenCounter = -1;
static int hf_v2giso2_struct_iso2RSAKeyValueType_Exponent = -1;
static int hf_v2giso2_struct_iso2RSAKeyValueType_Modulus = -1;
static int hf_v2giso2_struct_iso2X509DataType_X509SKI = -1;
static int hf_v2giso2_struct_iso2X509DataType_X509SubjectName = -1;
static int hf_v2giso2_struct_iso2X509DataType_X509Certificate = -1;
static int hf_v2giso2_struct_iso2X509DataType_X509CRL = -1;
static int hf_v2giso2_struct_iso2X509DataType_ANY = -1;
static int hf_v2giso2_struct_iso2X509IssuerSerialType_X509IssuerName = -1;
static int hf_v2giso2_struct_iso2X509IssuerSerialType_X509SerialNumber = -1;
static int hf_v2giso2_struct_iso2PGPDataType_PGPKeyID = -1;
static int hf_v2giso2_struct_iso2PGPDataType_PGPKeyPacket = -1;
static int hf_v2giso2_struct_iso2PGPDataType_ANY = -1;
static int hf_v2giso2_struct_iso2SPKIDataType_SPKISexp = -1;
static int hf_v2giso2_struct_iso2SPKIDataType_ANY = -1;

/* Initialize the subtree pointers */
static gint ett_v2giso2 = -1;
static gint ett_v2giso2_header = -1;
static gint ett_v2giso2_body = -1;
static gint ett_v2giso2_array = -1;
static gint ett_v2giso2_array_i = -1;
static gint ett_v2giso2_asn1 = -1;

static gint ett_v2giso2_struct_iso2SignatureType = -1;
static gint ett_v2giso2_struct_iso2SignedInfoType = -1;
static gint ett_v2giso2_struct_iso2SignatureValueType = -1;
static gint ett_v2giso2_struct_iso2ObjectType = -1;
static gint ett_v2giso2_struct_iso2CanonicalizationMethodType = -1;
static gint ett_v2giso2_struct_iso2SignatureMethodType = -1;
static gint ett_v2giso2_struct_iso2DigestMethodType = -1;
static gint ett_v2giso2_struct_iso2ReferenceType = -1;
static gint ett_v2giso2_struct_iso2TransformsType = -1;
static gint ett_v2giso2_struct_iso2TransformType = -1;
static gint ett_v2giso2_struct_iso2KeyInfoType = -1;
static gint ett_v2giso2_struct_iso2KeyValueType = -1;
static gint ett_v2giso2_struct_iso2DSAKeyValueType = -1;
static gint ett_v2giso2_struct_iso2RSAKeyValueType = -1;
static gint ett_v2giso2_struct_iso2RetrievalMethodType = -1;
static gint ett_v2giso2_struct_iso2X509DataType = -1;
static gint ett_v2giso2_struct_iso2X509IssuerSerialType = -1;
static gint ett_v2giso2_struct_iso2PGPDataType = -1;
static gint ett_v2giso2_struct_iso2SPKIDataType = -1;


static void
dissect_v2giso2_object(const struct iso2ObjectType *object,
		       tvbuff_t *tvb,
		       packet_info *pinfo _U_,
		       proto_tree *tree,
		       gint idx,
		       const char *subtree_name)
{
	proto_tree *subtree;

	subtree = proto_tree_add_subtree(tree,
		tvb, 0, 0, idx, NULL, subtree_name);

	if (object->Id_isUsed) {
		exi_add_characters(subtree,
			hf_v2giso2_struct_iso2ObjectType_Id,
			tvb,
			object->Id.characters,
			object->Id.charactersLen,
			sizeof(object->Id.characters));
	}
	if (object->MimeType_isUsed) {
		exi_add_characters(subtree,
			hf_v2giso2_struct_iso2ObjectType_MimeType,
			tvb,
			object->MimeType.characters,
			object->MimeType.charactersLen,
			sizeof(object->MimeType.characters));
	}
	if (object->Encoding_isUsed) {
		exi_add_characters(subtree,
			hf_v2giso2_struct_iso2ObjectType_Encoding,
			tvb,
			object->Encoding.characters,
			object->Encoding.charactersLen,
			sizeof(object->Encoding.characters));
	}
	if (object->ANY_isUsed) {
		exi_add_characters(subtree,
			hf_v2giso2_struct_iso2ObjectType_ANY,
			tvb,
			object->ANY.characters,
			object->ANY.charactersLen,
			sizeof(object->ANY.characters));
	}

	return;
}

static void
dissect_v2giso2_transform(const struct iso2TransformType *transform,
			  tvbuff_t *tvb,
			  packet_info *pinfo _U_,
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
		hf_v2giso2_struct_iso2TransformType_Algorithm,
		tvb,
		transform->Algorithm.characters,
		transform->Algorithm.charactersLen,
		sizeof(transform->Algorithm.characters));

	if (transform->ANY_isUsed) {
		exi_add_characters(subtree,
			hf_v2giso2_struct_iso2TransformType_ANY,
			tvb,
			transform->ANY.characters,
			transform->ANY.charactersLen,
			sizeof(transform->ANY.characters));
	}

	xpath_tree = proto_tree_add_subtree(subtree,
		tvb, 0, 0, ett_v2giso2_array, NULL, "XPath");
	for (i = 0; i < transform->XPath.arrayLen; i++) {
		xpath_i_tree = proto_tree_add_subtree_format(xpath_tree,
			tvb, 0, 0, ett_v2giso2_array_i, NULL, "[%u]", i);
		exi_add_characters(xpath_i_tree,
			hf_v2giso2_struct_iso2TransformType_XPath,
			tvb,
			transform->XPath.array[i].characters,
			transform->XPath.array[i].charactersLen,
			sizeof(transform->XPath.array[i].characters));
	}

	return;
}

static void
dissect_v2giso2_transforms(const struct iso2TransformsType *transforms,
			   tvbuff_t *tvb,
			   packet_info *pinfo,
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
		tvb, 0, 0, ett_v2giso2_array, NULL, "Transform");
	for (i = 0; i < transforms->Transform.arrayLen; i++) {
		char index[sizeof("[65536]")];

		snprintf(index, sizeof(index), "[%u]", i);
		dissect_v2giso2_transform(&transforms->Transform.array[i],
			tvb, pinfo, transform_tree,
			ett_v2giso2_struct_iso2TransformType, index);
	}

	return;
}

static void
dissect_v2giso2_digestmethod(const struct iso2DigestMethodType *digestmethod,
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
		hf_v2giso2_struct_iso2DigestMethodType_Algorithm,
		tvb,
		digestmethod->Algorithm.characters,
		digestmethod->Algorithm.charactersLen,
		sizeof(digestmethod->Algorithm.characters));

	if (digestmethod->ANY_isUsed) {
		exi_add_characters(subtree,
			hf_v2giso2_struct_iso2DigestMethodType_ANY,
			tvb,
			digestmethod->ANY.characters,
			digestmethod->ANY.charactersLen,
			sizeof(digestmethod->ANY.characters));
	}

	return;
}

static void
dissect_v2giso2_reference(const struct iso2ReferenceType *reference,
			  tvbuff_t *tvb,
			  packet_info *pinfo,
			  proto_tree *tree,
			  gint idx,
			  const char *subtree_name)
{
	proto_tree *subtree;

	subtree = proto_tree_add_subtree(tree,
		tvb, 0, 0, idx, NULL, subtree_name);

	if (reference->Id_isUsed) {
		exi_add_characters(subtree,
			hf_v2giso2_struct_iso2ReferenceType_Id,
			tvb,
			reference->Id.characters,
			reference->Id.charactersLen,
			sizeof(reference->Id.characters));
	}
	if (reference->URI_isUsed) {
		exi_add_characters(subtree,
			hf_v2giso2_struct_iso2ReferenceType_URI,
			tvb,
			reference->URI.characters,
			reference->URI.charactersLen,
			sizeof(reference->URI.characters));
	}
	if (reference->Type_isUsed) {
		exi_add_characters(subtree,
			hf_v2giso2_struct_iso2ReferenceType_Type,
			tvb,
			reference->Type.characters,
			reference->Type.charactersLen,
			sizeof(reference->Type.characters));
	}
	if (reference->Transforms_isUsed) {
		dissect_v2giso2_transforms(&reference->Transforms,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2TransformsType,
			"Transforms");
	}

	dissect_v2giso2_digestmethod(&reference->DigestMethod,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2DigestMethodType,
			"DigestMethod");

	exi_add_bytes(subtree,
		hf_v2giso2_struct_iso2ReferenceType_DigestValue,
		tvb,
		reference->DigestValue.bytes,
		reference->DigestValue.bytesLen,
		sizeof(reference->DigestValue.bytes));

	return;
}

static void
dissect_v2giso2_canonicalizationmethod(
	const struct iso2CanonicalizationMethodType *canonicalizationmethod,
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
		hf_v2giso2_struct_iso2CanonicalizationMethodType_Algorithm,
		tvb,
		canonicalizationmethod->Algorithm.characters,
		canonicalizationmethod->Algorithm.charactersLen,
		sizeof(canonicalizationmethod->Algorithm.characters));

	if (canonicalizationmethod->ANY_isUsed) {
		exi_add_characters(subtree,
			hf_v2giso2_struct_iso2CanonicalizationMethodType_ANY,
			tvb,
			canonicalizationmethod->ANY.characters,
			canonicalizationmethod->ANY.charactersLen,
			sizeof(canonicalizationmethod->ANY.characters));
	}

	return;
}

static void
dissect_v2giso2_signaturemethod(
	const struct iso2SignatureMethodType *signaturemethod,
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
		hf_v2giso2_struct_iso2SignatureMethodType_Algorithm,
		tvb,
		signaturemethod->Algorithm.characters,
		signaturemethod->Algorithm.charactersLen,
		sizeof(signaturemethod->Algorithm.characters));

	if (signaturemethod->HMACOutputLength_isUsed) {
		it = proto_tree_add_int64(subtree,
			hf_v2giso2_struct_iso2SignatureMethodType_HMACOutputLength,
			tvb, 0, 0, signaturemethod->HMACOutputLength);
		proto_item_set_generated(it);
	}

	if (signaturemethod->ANY_isUsed) {
		exi_add_characters(subtree,
			hf_v2giso2_struct_iso2SignatureMethodType_ANY,
			tvb,
			signaturemethod->ANY.characters,
			signaturemethod->ANY.charactersLen,
			sizeof(signaturemethod->ANY.characters));
	}

	return;
}

static void
dissect_v2giso2_signaturevalue(
	const struct iso2SignatureValueType *signaturevalue,
	tvbuff_t *tvb,
	packet_info *pinfo _U_,
	proto_tree *tree,
	gint idx,
	const char *subtree_name)
{
	proto_tree *subtree;

	subtree = proto_tree_add_subtree(tree,
		tvb, 0, 0, idx, NULL, subtree_name);

	if (signaturevalue->Id_isUsed) {
		exi_add_characters(subtree,
			hf_v2giso2_struct_iso2SignatureValueType_Id,
			tvb,
			signaturevalue->Id.characters,
			signaturevalue->Id.charactersLen,
			sizeof(signaturevalue->Id.characters));
	}

	exi_add_bytes(subtree,
		hf_v2giso2_struct_iso2SignatureValueType_CONTENT,
		tvb,
		signaturevalue->CONTENT.bytes,
		signaturevalue->CONTENT.bytesLen,
		sizeof(signaturevalue->CONTENT.bytes));

	return;
}

static void
dissect_v2giso2_signedinfo(const struct iso2SignedInfoType *signedinfo,
			   tvbuff_t *tvb,
			   packet_info *pinfo,
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
			hf_v2giso2_struct_iso2SignedInfoType_Id,
			tvb,
			signedinfo->Id.characters,
			signedinfo->Id.charactersLen,
			sizeof(signedinfo->Id.characters));
	}

	dissect_v2giso2_canonicalizationmethod(
		&signedinfo->CanonicalizationMethod,
		tvb, pinfo, subtree,
		ett_v2giso2_struct_iso2CanonicalizationMethodType,
		"CanonicalizationMethod");
	dissect_v2giso2_signaturemethod(
		&signedinfo->SignatureMethod,
		tvb, pinfo, subtree,
		ett_v2giso2_struct_iso2SignatureMethodType,
		"SignatureMethod");

	reference_tree = proto_tree_add_subtree(subtree,
		tvb, 0, 0, ett_v2giso2_array, NULL, "Reference");
	for (i = 0; i < signedinfo->Reference.arrayLen; i++) {
		char index[sizeof("[65536]")];

		snprintf(index, sizeof(index), "[%u]", i);
		dissect_v2giso2_reference(&signedinfo->Reference.array[i],
			tvb, pinfo, reference_tree,
			ett_v2giso2_struct_iso2ReferenceType, index);
	}

	return;
}

static void
dissect_v2giso2_dsakeyvalue(const struct iso2DSAKeyValueType *dsakeyvalue,
			    tvbuff_t *tvb,
			    packet_info *pinfo _U_,
			    proto_tree *tree,
			    gint idx,
			    const char *subtree_name)
{
	proto_tree *subtree;

	subtree = proto_tree_add_subtree(tree,
		tvb, 0, 0, idx, NULL, subtree_name);

	if (dsakeyvalue->P_isUsed) {
		exi_add_bytes(subtree,
			hf_v2giso2_struct_iso2DSAKeyValueType_P,
			tvb,
			dsakeyvalue->P.bytes,
			dsakeyvalue->P.bytesLen,
			sizeof(dsakeyvalue->P.bytes));
	}
	if (dsakeyvalue->Q_isUsed) {
		exi_add_bytes(subtree,
			hf_v2giso2_struct_iso2DSAKeyValueType_Q,
			tvb,
			dsakeyvalue->Q.bytes,
			dsakeyvalue->Q.bytesLen,
			sizeof(dsakeyvalue->Q.bytes));
	}
	if (dsakeyvalue->G_isUsed) {
		exi_add_bytes(subtree,
			hf_v2giso2_struct_iso2DSAKeyValueType_G,
			tvb,
			dsakeyvalue->G.bytes,
			dsakeyvalue->G.bytesLen,
			sizeof(dsakeyvalue->G.bytes));
	}
	exi_add_bytes(subtree,
		hf_v2giso2_struct_iso2DSAKeyValueType_Y,
		tvb,
		dsakeyvalue->Y.bytes,
		dsakeyvalue->Y.bytesLen,
		sizeof(dsakeyvalue->Y.bytes));
	if (dsakeyvalue->J_isUsed) {
		exi_add_bytes(subtree,
			hf_v2giso2_struct_iso2DSAKeyValueType_J,
			tvb,
			dsakeyvalue->J.bytes,
			dsakeyvalue->J.bytesLen,
			sizeof(dsakeyvalue->J.bytes));
	}
	if (dsakeyvalue->Seed_isUsed) {
		exi_add_bytes(subtree,
			hf_v2giso2_struct_iso2DSAKeyValueType_Seed,
			tvb,
			dsakeyvalue->Seed.bytes,
			dsakeyvalue->Seed.bytesLen,
			sizeof(dsakeyvalue->Seed.bytes));
	}
	if (dsakeyvalue->PgenCounter_isUsed) {
		exi_add_bytes(subtree,
			hf_v2giso2_struct_iso2DSAKeyValueType_PgenCounter,
			tvb,
			dsakeyvalue->PgenCounter.bytes,
			dsakeyvalue->PgenCounter.bytesLen,
			sizeof(dsakeyvalue->PgenCounter.bytes));
	}

	return;
}

static void
dissect_v2giso2_rsakeyvalue(const struct iso2RSAKeyValueType *rsakeyvalue,
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
		hf_v2giso2_struct_iso2RSAKeyValueType_Modulus,
		tvb,
		rsakeyvalue->Modulus.bytes,
		rsakeyvalue->Modulus.bytesLen,
		sizeof(rsakeyvalue->Modulus.bytes));

	exi_add_bytes(subtree,
		hf_v2giso2_struct_iso2RSAKeyValueType_Exponent,
		tvb,
		rsakeyvalue->Exponent.bytes,
		rsakeyvalue->Exponent.bytesLen,
		sizeof(rsakeyvalue->Exponent.bytes));

	return;
}

static void
dissect_v2giso2_keyvalue(const struct iso2KeyValueType *keyvalue,
			 tvbuff_t *tvb,
			 packet_info *pinfo,
			 proto_tree *tree,
			 gint idx,
			 const char *subtree_name)
{
	proto_tree *subtree;

	subtree = proto_tree_add_subtree(tree,
		tvb, 0, 0, idx, NULL, subtree_name);

	if (keyvalue->DSAKeyValue_isUsed) {
		dissect_v2giso2_dsakeyvalue(&keyvalue->DSAKeyValue,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2DSAKeyValueType,
			"DSAKeyValue");
	}
	if (keyvalue->RSAKeyValue_isUsed) {
		dissect_v2giso2_rsakeyvalue(&keyvalue->RSAKeyValue,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2RSAKeyValueType,
			"RSAKeyValue");
	}

	exi_add_characters(subtree,
		hf_v2giso2_struct_iso2KeyValueType_ANY,
		tvb,
		keyvalue->ANY.characters,
		keyvalue->ANY.charactersLen,
		sizeof(keyvalue->ANY.characters));

	return;
}

static void
dissect_v2giso2_retrievalmethod(
	const struct iso2RetrievalMethodType *retrievalmethod,
	tvbuff_t *tvb,
	packet_info *pinfo,
	proto_tree *tree,
	gint idx,
	const char *subtree_name)
{
	proto_tree *subtree;

	subtree = proto_tree_add_subtree(tree,
		tvb, 0, 0, idx, NULL, subtree_name);

	if (retrievalmethod->URI_isUsed) {
		exi_add_characters(subtree,
			hf_v2giso2_struct_iso2RetrievalMethodType_URI,
			tvb,
			retrievalmethod->URI.characters,
			retrievalmethod->URI.charactersLen,
			sizeof(retrievalmethod->URI.characters));
	}
	if (retrievalmethod->Type_isUsed) {
		exi_add_characters(subtree,
			hf_v2giso2_struct_iso2RetrievalMethodType_Type,
			tvb,
			retrievalmethod->Type.characters,
			retrievalmethod->Type.charactersLen,
			sizeof(retrievalmethod->Type.characters));
	}
	if (retrievalmethod->Transforms_isUsed) {
		dissect_v2giso2_transforms(&retrievalmethod->Transforms,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2TransformsType,
			"Transforms");
	}

	return;
}

static void
dissect_v2giso2_x509issuerserial(
	const struct iso2X509IssuerSerialType *x509issuerserial,
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
		hf_v2giso2_struct_iso2X509IssuerSerialType_X509IssuerName,
		tvb,
		x509issuerserial->X509IssuerName.characters,
		x509issuerserial->X509IssuerName.charactersLen,
		sizeof(x509issuerserial->X509IssuerName.characters));

	it = proto_tree_add_int64(subtree,
		hf_v2giso2_struct_iso2X509IssuerSerialType_X509SerialNumber,
		tvb, 0, 0, x509issuerserial->X509SerialNumber);
	proto_item_set_generated(it);

	return;
}

static void
dissect_v2giso2_x509data(const struct iso2X509DataType *x509data,
			 tvbuff_t *tvb,
			 packet_info *pinfo,
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
		tvb, 0, 0, ett_v2giso2_array, NULL, "X509IssuerSerial");
	for (i = 0; i < x509data->X509IssuerSerial.arrayLen; i++) {
		char index[sizeof("[65536]")];

		snprintf(index, sizeof(index), "[%u]", i);
		dissect_v2giso2_x509issuerserial(
			&x509data->X509IssuerSerial.array[i],
			tvb, pinfo, x509issuerserial_tree,
			ett_v2giso2_struct_iso2X509IssuerSerialType, index);
	}

	x509ski_tree = proto_tree_add_subtree(subtree,
		tvb, 0, 0, ett_v2giso2_array, NULL, "X509SKI");
	for (i = 0; i < x509data->X509SKI.arrayLen; i++) {
		x509ski_i_tree = proto_tree_add_subtree_format(x509ski_tree,
			tvb, 0, 0, ett_v2giso2_array_i, NULL, "[%u]", i);
		exi_add_bytes(x509ski_i_tree,
			hf_v2giso2_struct_iso2X509DataType_X509SKI,
			tvb,
			x509data->X509SKI.array[i].bytes,
			x509data->X509SKI.array[i].bytesLen,
			sizeof(x509data->X509SKI.array[i].bytes));
	}

	x509subjectname_tree = proto_tree_add_subtree(subtree,
		tvb, 0, 0, ett_v2giso2_array, NULL, "X509SKI");
	for (i = 0; i < x509data->X509SubjectName.arrayLen; i++) {
		x509subjectname_i_tree = proto_tree_add_subtree_format(
			x509subjectname_tree,
			tvb, 0, 0, ett_v2giso2_array_i, NULL, "[%u]", i);
		exi_add_characters(x509subjectname_i_tree,
			hf_v2giso2_struct_iso2X509DataType_X509SubjectName,
			tvb,
			x509data->X509SubjectName.array[i].characters,
			x509data->X509SubjectName.array[i].charactersLen,
			sizeof(x509data->X509SubjectName.array[i].characters));
	}

	x509certificate_tree = proto_tree_add_subtree(subtree,
		tvb, 0, 0, ett_v2giso2_array, NULL, "X509SKI");
	for (i = 0; i < x509data->X509Certificate.arrayLen; i++) {
		x509certificate_i_tree = proto_tree_add_subtree_format(
			x509certificate_tree,
			tvb, 0, 0, ett_v2giso2_array_i, NULL, "[%u]", i);

		if (v2gber_handle == NULL) {
			exi_add_bytes(x509certificate_i_tree,
				hf_v2giso2_struct_iso2X509DataType_X509Certificate,
				tvb,
				x509data->X509Certificate.array[i].bytes,
				x509data->X509Certificate.array[i].bytesLen,
				sizeof(x509data->X509Certificate.array[i].bytes));
		} else {
			tvbuff_t *child;
			proto_tree *asn1_tree;

			child = tvb_new_child_real_data(tvb,
				x509data->X509Certificate.array[i].bytes,
				sizeof(x509data->X509Certificate.array[i].bytes),
				x509data->X509Certificate.array[i].bytesLen);

			asn1_tree = proto_tree_add_subtree(x509certificate_i_tree,
				child, 0, tvb_reported_length(child),
				ett_v2giso2_asn1, NULL, "X509Certificate ASN1");
			call_dissector(v2gber_handle, child, pinfo, asn1_tree);
		}
	}

	x509crl_tree = proto_tree_add_subtree(subtree,
		tvb, 0, 0, ett_v2giso2_array, NULL, "X509CRL");
	for (i = 0; i < x509data->X509CRL.arrayLen; i++) {
		x509crl_i_tree = proto_tree_add_subtree_format(x509crl_tree,
			tvb, 0, 0, ett_v2giso2_array_i, NULL, "[%u]", i);
		exi_add_bytes(x509crl_i_tree,
			hf_v2giso2_struct_iso2X509DataType_X509CRL,
			tvb,
			x509data->X509CRL.array[i].bytes,
			x509data->X509CRL.array[i].bytesLen,
			sizeof(x509data->X509CRL.array[i].bytes));
	}

	if (x509data->ANY_isUsed) {
		exi_add_characters(subtree,
			hf_v2giso2_struct_iso2X509DataType_ANY,
			tvb,
			x509data->ANY.characters,
			x509data->ANY.charactersLen,
			sizeof(x509data->ANY.characters));
	}

	return;
}

static void
dissect_v2giso2_pgpdata(const struct iso2PGPDataType *pgpdata,
			tvbuff_t *tvb,
			packet_info *pinfo _U_,
			proto_tree *tree,
			gint idx,
			const char *subtree_name)
{
	proto_tree *subtree;

	subtree = proto_tree_add_subtree(tree,
		tvb, 0, 0, idx, NULL, subtree_name);

	if (pgpdata->PGPKeyID_isUsed) {
		exi_add_bytes(subtree,
			hf_v2giso2_struct_iso2PGPDataType_PGPKeyID,
			tvb,
			pgpdata->PGPKeyID.bytes,
			pgpdata->PGPKeyID.bytesLen,
			sizeof(pgpdata->PGPKeyID.bytes));
	}

	if (pgpdata->PGPKeyPacket_isUsed) {
		exi_add_bytes(subtree,
			hf_v2giso2_struct_iso2PGPDataType_PGPKeyPacket,
			tvb,
			pgpdata->PGPKeyPacket.bytes,
			pgpdata->PGPKeyPacket.bytesLen,
			sizeof(pgpdata->PGPKeyPacket.bytes));
	}

	if (pgpdata->ANY_isUsed) {
		exi_add_characters(subtree,
			hf_v2giso2_struct_iso2PGPDataType_ANY,
			tvb,
			pgpdata->ANY.characters,
			pgpdata->ANY.charactersLen,
			sizeof(pgpdata->ANY.characters));
	}

	return;
}

static void
dissect_v2giso2_spkidata(const struct iso2SPKIDataType *spkidata,
			 tvbuff_t *tvb,
			 packet_info *pinfo _U_,
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
		tvb, 0, 0, ett_v2giso2_array, NULL, "SPKISexp");
	for (i = 0; i < spkidata->SPKISexp.arrayLen; i++) {
		spkisexp_i_tree = proto_tree_add_subtree_format(spkisexp_tree,
			tvb, 0, 0, ett_v2giso2_array_i, NULL, "[%u]", i);
		exi_add_bytes(spkisexp_i_tree,
			hf_v2giso2_struct_iso2SPKIDataType_SPKISexp,
			tvb,
			spkidata->SPKISexp.array[i].bytes,
			spkidata->SPKISexp.array[i].bytesLen,
			sizeof(spkidata->SPKISexp.array[i].bytes));
	}

	if (spkidata->ANY_isUsed) {
		exi_add_characters(subtree,
			hf_v2giso2_struct_iso2SPKIDataType_ANY,
			tvb,
			spkidata->ANY.characters,
			spkidata->ANY.charactersLen,
			sizeof(spkidata->ANY.characters));
	}

	return;
}

static void
dissect_v2giso2_keyinfo(const struct iso2KeyInfoType *keyinfo,
			tvbuff_t *tvb,
			packet_info *pinfo,
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
			hf_v2giso2_struct_iso2KeyInfoType_Id,
			tvb,
			keyinfo->Id.characters,
			keyinfo->Id.charactersLen,
			sizeof(keyinfo->Id.characters));
	}

	keyname_tree = proto_tree_add_subtree(subtree,
		tvb, 0, 0, ett_v2giso2_array, NULL, "KeyName");
	for (i = 0; i < keyinfo->KeyName.arrayLen; i++) {
		keyname_i_tree = proto_tree_add_subtree_format(keyname_tree,
			tvb, 0, 0, ett_v2giso2_array_i, NULL, "[%u]", i);
		exi_add_characters(keyname_i_tree,
			hf_v2giso2_struct_iso2KeyInfoType_KeyName,
			tvb,
			keyinfo->KeyName.array[i].characters,
			keyinfo->KeyName.array[i].charactersLen,
			sizeof(keyinfo->KeyName.array[i].characters));
	}

	keyvalue_tree = proto_tree_add_subtree(subtree,
		tvb, 0, 0, ett_v2giso2_array, NULL, "KeyValue");
	for (i = 0; i < keyinfo->KeyValue.arrayLen; i++) {
		char index[sizeof("[65536]")];

		snprintf(index, sizeof(index), "[%u]", i);
		dissect_v2giso2_keyvalue(&keyinfo->KeyValue.array[i],
			tvb, pinfo, keyvalue_tree,
			ett_v2giso2_struct_iso2KeyValueType,
			index);
	}

	retrievalmethod_tree = proto_tree_add_subtree(subtree,
		tvb, 0, 0, ett_v2giso2_array, NULL, "RetrievalMethod");
	for (i = 0; i < keyinfo->RetrievalMethod.arrayLen; i++) {
		char index[sizeof("[65536]")];

		snprintf(index, sizeof(index), "[%u]", i);
		dissect_v2giso2_retrievalmethod(
			&keyinfo->RetrievalMethod.array[i],
			tvb, pinfo, retrievalmethod_tree,
			ett_v2giso2_struct_iso2RetrievalMethodType, index);
	}

	x509data_tree = proto_tree_add_subtree(subtree,
		tvb, 0, 0, ett_v2giso2_array, NULL, "X509Data");
	for (i = 0; i < keyinfo->X509Data.arrayLen; i++) {
		char index[sizeof("[65536]")];

		snprintf(index, sizeof(index), "[%u]", i);
		dissect_v2giso2_x509data(&keyinfo->X509Data.array[i],
			tvb, pinfo, x509data_tree,
			ett_v2giso2_struct_iso2X509DataType, index);
	}

	pgpdata_tree = proto_tree_add_subtree(subtree,
		tvb, 0, 0, ett_v2giso2_array, NULL, "PGPData");
	for (i = 0; i < keyinfo->PGPData.arrayLen; i++) {
		char index[sizeof("[65536]")];

		snprintf(index, sizeof(index), "[%u]", i);
		dissect_v2giso2_pgpdata(&keyinfo->PGPData.array[i],
			tvb, pinfo, pgpdata_tree,
			ett_v2giso2_struct_iso2PGPDataType, index);
	}

	spkidata_tree = proto_tree_add_subtree(subtree,
		tvb, 0, 0, ett_v2giso2_array, NULL, "SPKIData");
	for (i = 0; i < keyinfo->SPKIData.arrayLen; i++) {
		char index[sizeof("[65536]")];

		snprintf(index, sizeof(index), "[%u]", i);
		dissect_v2giso2_spkidata(&keyinfo->SPKIData.array[i],
			tvb, pinfo, spkidata_tree,
			ett_v2giso2_struct_iso2SPKIDataType, index);
	}

	mgmtdata_tree = proto_tree_add_subtree(subtree,
		tvb, 0, 0, ett_v2giso2_array, NULL, "MgmtData");
	for (i = 0; i < keyinfo->MgmtData.arrayLen; i++) {
		mgmtdata_i_tree = proto_tree_add_subtree_format(mgmtdata_tree,
			tvb, 0, 0, ett_v2giso2_array_i, NULL, "[%u]", i);
		exi_add_characters(mgmtdata_i_tree,
			hf_v2giso2_struct_iso2KeyInfoType_MgmtData,
			tvb,
			keyinfo->MgmtData.array[i].characters,
			keyinfo->MgmtData.array[i].charactersLen,
			sizeof(keyinfo->MgmtData.array[i].characters));
	}

	if (keyinfo->ANY_isUsed) {
		exi_add_characters(subtree,
			hf_v2giso2_struct_iso2KeyInfoType_ANY,
			tvb,
			keyinfo->ANY.characters,
			keyinfo->ANY.charactersLen,
			sizeof(keyinfo->ANY.characters));
	}

	return;
}

static void
dissect_v2giso2_signature(const struct iso2SignatureType *signature,
			 tvbuff_t *tvb,
			 packet_info *pinfo,
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
			hf_v2giso2_struct_iso2SignatureType_Id,
			tvb,
			signature->Id.characters,
			signature->Id.charactersLen,
			sizeof(signature->Id.characters));
	}

	dissect_v2giso2_signedinfo(&signature->SignedInfo,
		tvb, pinfo, subtree,
		ett_v2giso2_struct_iso2SignedInfoType, "SignedInfo");
	dissect_v2giso2_signaturevalue(&signature->SignatureValue,
		tvb, pinfo, subtree,
		ett_v2giso2_struct_iso2SignatureValueType, "SignatureValue");

	if (signature->KeyInfo_isUsed) {
		dissect_v2giso2_keyinfo(&signature->KeyInfo,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2KeyInfoType, "KeyInfo");
	}

	object_tree = proto_tree_add_subtree(subtree,
		tvb, 0, 0, ett_v2giso2_array, NULL, "Object");
	for (i = 0; i < signature->Object.arrayLen; i++) {
		char index[sizeof("[65536]")];

		snprintf(index, sizeof(index), "[%u]", i);
		dissect_v2giso2_object(&signature->Object.array[i],
			tvb, pinfo, object_tree,
			ett_v2giso2_struct_iso2ObjectType, index);
	}

	return;
}


static void
dissect_v2giso2_header(const struct iso2MessageHeaderType *header,
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
		hf_v2giso2_struct_iso2MessageHeaderType_SessionID,
		tvb,
		header->SessionID.bytes,
		header->SessionID.bytesLen,
		sizeof(header->SessionID.bytes));

	if (header->Signature_isUsed) {
		dissect_v2giso2_signature(
			&header->Signature, tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2SignatureType,
			"Signature");
	}

	return;
}


static void
dissect_v2giso2_body(const struct iso2BodyType *body _U_,
		     tvbuff_t *tvb,
		     packet_info *pinfo _U_,
		     proto_tree *tree,
		     gint idx,
		     const char *subtree_name)
{
	proto_tree *subtree;

	subtree = proto_tree_add_subtree(tree,
		tvb, 0, 0, idx, NULL, subtree_name);

	proto_tree_add_debug_text(subtree, "TODO");
	return;
}

static int
dissect_v2giso2(tvbuff_t *tvb,
		packet_info *pinfo, proto_tree *tree _U_, void *data _U_)
{
	size_t pos;
	bitstream_t stream;
	int errn;
	struct iso2EXIDocument *exiiso2;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "ISO2");
	/* Clear the info column */
	col_clear(pinfo->cinfo, COL_INFO);

	pos = 0;
	stream.size = tvb_reported_length(tvb);
	stream.pos = &pos;
	stream.data = tvb_memdup(wmem_packet_scope(),
				 tvb, 0, stream.size);

	exiiso2 = wmem_alloc(pinfo->pool, sizeof(*exiiso2));
	errn = decode_iso2ExiDocument(&stream, exiiso2);
	if (errn != 0) {
		wmem_free(pinfo->pool, exiiso2);
		/* decode failed */
		return 0;
	}

	/*
	 * Everything in ISO2 should come in as a messagge
	 * - Header
	 * - Body
	 */
	if (exiiso2->V2G_Message_isUsed) {
		proto_tree *v2giso2_tree;

		v2giso2_tree = proto_tree_add_subtree(tree,
			tvb, 0, 0, ett_v2giso2, NULL, "V2G ISO2 Message");

		dissect_v2giso2_header(&exiiso2->V2G_Message.Header,
			tvb, pinfo, v2giso2_tree,
			ett_v2giso2_header, "Header");
		dissect_v2giso2_body(& exiiso2->V2G_Message.Body,
			tvb, pinfo, v2giso2_tree,
			ett_v2giso2_body, "Body");
	}

	wmem_free(pinfo->pool, exiiso2);
	return tvb_captured_length(tvb);
}

void
proto_register_v2giso2(void)
{

	static hf_register_info hf[] = {
		/* struct iso2MessageHeaderType */
		{ &hf_v2giso2_struct_iso2MessageHeaderType_SessionID,
		  { "SessionID", "v2giso2.struct.messageheader.sessionid",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso2SignatureType */
		{ &hf_v2giso2_struct_iso2SignatureType_Id,
		  { "Id", "v2giso2.struct.signature.id",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso2SignedInfoType */
		{ &hf_v2giso2_struct_iso2SignedInfoType_Id,
		  { "Id", "v2giso2.struct.signedinfo.id",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso2CanonicalizationMethodType */
		{ &hf_v2giso2_struct_iso2CanonicalizationMethodType_Algorithm,
		  { "Algorithm",
		    "v2giso2.struct.canonicalizationmethod.algorithm",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2CanonicalizationMethodType_ANY,
		  { "ANY",
		    "v2giso2.struct.canonicalizationmethod.any",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso2SignatureMethodType */
		{ &hf_v2giso2_struct_iso2SignatureMethodType_Algorithm,
		  { "Algorithm", "v2giso2.struct.signaturemethod.algorithm",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2SignatureMethodType_HMACOutputLength,
		  { "HMACOutputLength",
		    "v2giso2.struct.signaturemethod.hmacoutputlength",
		    FT_INT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2SignatureMethodType_ANY,
		  { "ANY", "v2giso2.struct.signaturemethod.any",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso2ReferenceType */
		{ &hf_v2giso2_struct_iso2ReferenceType_Id,
		  { "Id", "v2giso2.struct.reference.id",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2ReferenceType_URI,
		  { "URI", "v2giso2.struct.reference.uri",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2ReferenceType_Type,
		  { "Type", "v2giso2.struct.reference.type",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2ReferenceType_DigestValue,
		  { "DigestValue", "v2giso2.struct.reference.digestvalue",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso2SignatureValueType */
		{ &hf_v2giso2_struct_iso2SignatureValueType_Id,
		  { "Id", "v2giso2.struct.signavturevalue.id",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2SignatureValueType_CONTENT,
		  { "CONTENT", "v2giso2.struct.signaturevalue.content",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso2ObjectType */
		{ &hf_v2giso2_struct_iso2ObjectType_Id,
		  { "Id", "v2giso2.struct.object.id",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2ObjectType_MimeType,
		  { "MimeType", "v2giso2.struct.object.mimetype",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2ObjectType_Encoding,
		  { "Encoding", "v2giso2.struct.object.encoiso2g",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2ObjectType_ANY,
		  { "ANY", "v2giso2.struct.object.any",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso2TransformType */
		{ &hf_v2giso2_struct_iso2TransformType_Algorithm,
		  { "Algorithm", "v2giso2.struct.transform.algorithm",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2TransformType_ANY,
		  { "ANY", "v2giso2.struct.transform.any",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2TransformType_XPath,
		  { "XPath", "v2giso2.struct.transform.xpath",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso2DigestMethodType */
		{ &hf_v2giso2_struct_iso2DigestMethodType_Algorithm,
		  { "Algorithm", "v2giso2.struct.digestmethod.algorithm",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2DigestMethodType_ANY,
		  { "ANY", "v2giso2.struct.digestmethod.any",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso2KeyInfoType */
		{ &hf_v2giso2_struct_iso2KeyInfoType_Id,
		  { "Id", "v2giso2.struct.keyinfo.id",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2KeyInfoType_KeyName,
		  { "KeyName", "v2giso2.struct.keyinfo.keyname",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2KeyInfoType_MgmtData,
		  { "MgmtData", "v2giso2.struct.keyinfo.mgmtdata",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2KeyInfoType_ANY,
		  { "ANY", "v2giso2.struct.keyinfo.any",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso2RetrievalMethodType */
		{ &hf_v2giso2_struct_iso2RetrievalMethodType_URI,
		  { "URI", "v2giso2.struct.retrievalmethod.uri",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2RetrievalMethodType_Type,
		  { "Type", "v2giso2.struct.retrievalmethod.type",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso2KeyValueType */
		{ &hf_v2giso2_struct_iso2KeyValueType_ANY,
		  { "ANY", "v2giso2.struct.keyvalue.any",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso2DSAKeyValueType */
		{ &hf_v2giso2_struct_iso2DSAKeyValueType_P,
		  { "P", "v2giso2.struct.dsakeyvalue.p",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2DSAKeyValueType_Q,
		  { "Q", "v2giso2.struct.dsakeyvalue.q",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2DSAKeyValueType_G,
		  { "G", "v2giso2.struct.dsakeyvalue.g",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2DSAKeyValueType_Y,
		  { "Y", "v2giso2.struct.dsakeyvalue.y",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2DSAKeyValueType_J,
		  { "J", "v2giso2.struct.dsakeyvalue.j",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2DSAKeyValueType_Seed,
		  { "Seed", "v2giso2.struct.dsakeyvalue.seed",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2DSAKeyValueType_PgenCounter,
		  { "PgenCounter", "v2giso2.struct.dsakeyvalue.pgencounter",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso2RSAKeyValueType */
		{ &hf_v2giso2_struct_iso2RSAKeyValueType_Modulus,
		  { "Modulus", "v2giso2.struct.rsakeyvalue.modulus",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2RSAKeyValueType_Exponent,
		  { "Exponent", "v2giso2.struct.rsakeyvalue.exponent",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso2X509DataType */
		{ &hf_v2giso2_struct_iso2X509DataType_X509SKI,
		  { "X509SKI", "v2giso2.struct.x509data.x509ski",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2X509DataType_X509SubjectName,
		  { "X509SubjectName",
		    "v2giso2.struct.x509data.x509subjectname",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2X509DataType_X509Certificate,
		  { "X509Certificate",
		    "v2giso2.struct.x509data.x509certificate",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2X509DataType_X509CRL,
		  { "X509CRL", "v2giso2.struct.x509data.x509crl",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2X509DataType_ANY,
		  { "ANY", "v2giso2.struct.x509data.any",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso2X509IssuerSerialType */
		{ &hf_v2giso2_struct_iso2X509IssuerSerialType_X509IssuerName,
		  { "X509IssuerName",
		    "v2giso2.struct.x509issuerserial.x509issuername",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2X509IssuerSerialType_X509SerialNumber,
		  { "X509SerialNumber",
		    "v2giso2.struct.x509issuerserial.x509serialnumber",
		    FT_INT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso2PGPDataType */
		{ &hf_v2giso2_struct_iso2PGPDataType_PGPKeyID,
		  { "PGPKeyID", "v2giso2.struct.pgpdata.pgpkeyid",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2PGPDataType_PGPKeyPacket,
		  { "PGPKeyPacket", "v2giso2.struct.pgpdata.pgpkeypacket",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2PGPDataType_ANY,
		  { "ANY", "v2giso2.struct.pgpdata.any",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso2SPKIDataType */
		{ &hf_v2giso2_struct_iso2SPKIDataType_SPKISexp,
		  { "SPKISexp", "v2giso2.struct.spkidata.spkisexp",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2SPKIDataType_ANY,
		  { "ANY", "v2giso2.struct.spkidata.any",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		}
	};

	static gint *ett[] = {
		&ett_v2giso2,
		&ett_v2giso2_header,
		&ett_v2giso2_body,
		&ett_v2giso2_array,
		&ett_v2giso2_array_i,
		&ett_v2giso2_asn1,

		&ett_v2giso2_struct_iso2SignatureType,
		&ett_v2giso2_struct_iso2SignedInfoType,
		&ett_v2giso2_struct_iso2SignatureValueType,
		&ett_v2giso2_struct_iso2ObjectType,
		&ett_v2giso2_struct_iso2CanonicalizationMethodType,
		&ett_v2giso2_struct_iso2SignatureMethodType,
		&ett_v2giso2_struct_iso2DigestMethodType,
		&ett_v2giso2_struct_iso2ReferenceType,
		&ett_v2giso2_struct_iso2TransformsType,
		&ett_v2giso2_struct_iso2TransformType,
		&ett_v2giso2_struct_iso2KeyInfoType,
		&ett_v2giso2_struct_iso2KeyValueType,
		&ett_v2giso2_struct_iso2DSAKeyValueType,
		&ett_v2giso2_struct_iso2RSAKeyValueType,
		&ett_v2giso2_struct_iso2RetrievalMethodType,
		&ett_v2giso2_struct_iso2X509DataType,
		&ett_v2giso2_struct_iso2X509IssuerSerialType,
		&ett_v2giso2_struct_iso2PGPDataType,
		&ett_v2giso2_struct_iso2SPKIDataType,
	};

	proto_v2giso2 = proto_register_protocol(
		"V2G Efficient XML Interchange (ISO2)",
		"V2GISO2",
		"v2giso2"
	);
	proto_register_field_array(proto_v2giso2, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	register_dissector("v2giso2", dissect_v2giso2, proto_v2giso2);
}

void
proto_reg_handoff_v2giso2(void)
{

	/* add a handle for the connection oriented V2G EXI */
	v2gexi_handle = find_dissector_add_dependency("v2gexi", proto_v2giso2);
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
