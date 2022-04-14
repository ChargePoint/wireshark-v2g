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
static int hf_v2gdin_struct_dinListOfRootCertificateIDsType_RootCertificateID = -1;

static int hf_v2gdin_struct_dinAC_EVChargeParameterType_DepartureTime = -1;

static int hf_v2gdin_struct_dinAC_EVSEStatusType_PowerSwitchClosed = -1;
static int hf_v2gdin_struct_dinAC_EVSEStatusType_RCD = -1;
static int hf_v2gdin_struct_dinAC_EVSEStatusType_NotificationMaxDelay = -1;
static int hf_v2gdin_struct_dinAC_EVSEStatusType_EVSENotification = -1;

static int hf_v2gdin_struct_dinDC_EVStatusType_EVReady = -1;
static int hf_v2gdin_struct_dinDC_EVStatusType_EVCabinConditioning = -1;
static int hf_v2gdin_struct_dinDC_EVStatusType_EVRESSConditioning = -1;
static int hf_v2gdin_struct_dinDC_EVStatusType_EVErrorCode = -1;
static int hf_v2gdin_struct_dinDC_EVStatusType_EVRESSSOC = -1;

static int hf_v2gdin_struct_dinDC_EVSEStatusType_EVSEIsolationStatus = -1;
static int hf_v2gdin_struct_dinDC_EVSEStatusType_EVSEStatusCode = -1;
static int hf_v2gdin_struct_dinDC_EVSEStatusType_NotificationMaxDelay = -1;
static int hf_v2gdin_struct_dinDC_EVSEStatusType_EVSENotification = -1;

static int hf_v2gdin_struct_dinDC_EVChargeParameterType_FullSOC = -1;
static int hf_v2gdin_struct_dinDC_EVChargeParameterType_BulkSOC = -1;

static int hf_v2gdin_struct_dinSAScheduleTupleType_SAScheduleTupleID = -1;

static int hf_v2gdin_struct_dinPMaxScheduleType_PMaxScheduleID = -1;
static int hf_v2gdin_struct_dinPMaxScheduleEntryType_PMax = -1;

static int hf_v2gdin_struct_dinRelativeTimeIntervalType_start = -1;
static int hf_v2gdin_struct_dinRelativeTimeIntervalType_duration = -1;

static int hf_v2gdin_struct_dinSalesTariffType_Id = -1;
static int hf_v2gdin_struct_dinSalesTariffType_SalesTariffDescription = -1;
static int hf_v2gdin_struct_dinSalesTariffType_NumEPriceLevels = -1;
static int hf_v2gdin_struct_dinSalesTariffEntryType_EPriceLevel = -1;
static int hf_v2gdin_struct_dinConsumptionCostType_startValue = -1;
static int hf_v2gdin_struct_dinCostType_costKind = -1;
static int hf_v2gdin_struct_dinCostType_amount = -1;
static int hf_v2gdin_struct_dinCostType_amountMultiplier = -1;

static int hf_v2gdin_struct_dinChargingProfileType_SAScheduleTupleID = -1;

static int hf_v2gdin_struct_dinProfileEntryType_ChargingProfileEntryStart = -1;
static int hf_v2gdin_struct_dinProfileEntryType_ChargingProfileEntryMaxPower = -1;

static int hf_v2gdin_struct_dinDC_EVPowerDeliveryParameterType_BulkChargingComplete = -1;
static int hf_v2gdin_struct_dinDC_EVPowerDeliveryParameterType_ChargingComplete = -1;

static int hf_v2gdin_struct_dinMeterInfoType_MeterID = -1;
static int hf_v2gdin_struct_dinMeterInfoType_SigMeterReading = -1;
static int hf_v2gdin_struct_dinMeterInfoType_MeterStatus = -1;
static int hf_v2gdin_struct_dinMeterInfoType_TMeter = -1;

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
static int hf_v2gdin_body_ChargeParameterDiscoveryReq_EVRequestedEnergyTransferType = -1;
static int hf_v2gdin_body_ChargeParameterDiscoveryRes_ResponseCode = -1;
static int hf_v2gdin_body_ChargeParameterDiscoveryRes_EVSEProcessing = -1;

static int hf_v2gdin_body_PowerDeliveryReq_ReadyToChargeState = -1;
static int hf_v2gdin_body_PowerDeliveryRes_ResponseCode = -1;

static int hf_v2gdin_body_ChargingStatusRes_ResponseCode = -1;
static int hf_v2gdin_body_ChargingStatusRes_EVSEID = -1;
static int hf_v2gdin_body_ChargingStatusRes_SAScheduleTupleID = -1;
static int hf_v2gdin_body_ChargingStatusRes_ReceiptRequired = -1;

static int hf_v2gdin_body_MeteringReceiptReq_Id = -1;
static int hf_v2gdin_body_MeteringReceiptReq_SessionID = -1;
static int hf_v2gdin_body_MeteringReceiptReq_SAScheduleTupleID = -1;
static int hf_v2gdin_body_MeteringReceiptRes_ResponseCode = -1;

static int hf_v2gdin_body_SessionStopRes_ResponseCode = -1;

static int hf_v2gdin_body_CertificateUpdateReq_Id = -1;
static int hf_v2gdin_body_CertificateUpdateReq_ContractID = -1;
static int hf_v2gdin_body_CertificateUpdateReq_DHParams = -1;
static int hf_v2gdin_body_CertificateUpdateRes_Id = -1;
static int hf_v2gdin_body_CertificateUpdateRes_ResponseCode = -1;
static int hf_v2gdin_body_CertificateUpdateRes_ContractID = -1;
static int hf_v2gdin_body_CertificateUpdateRes_DHParams = -1;
static int hf_v2gdin_body_CertificateUpdateRes_RetryCounter = -1;
static int hf_v2gdin_body_CertificateUpdateRes_ContractSignatureEncryptedPrivateKey = -1;

static int hf_v2gdin_body_CertificateInstallationReq_Id = -1;
static int hf_v2gdin_body_CertificateInstallationReq_OEMProvisioningCert = -1;
static int hf_v2gdin_body_CertificateInstallationReq_DHParams = -1;
static int hf_v2gdin_body_CertificateInstallationRes_Id = -1;
static int hf_v2gdin_body_CertificateInstallationRes_ResponseCode = -1;
static int hf_v2gdin_body_CertificateInstallationRes_ContractSignatureEncryptedPrivateKey = -1;
static int hf_v2gdin_body_CertificateInstallationRes_DHParams = -1;
static int hf_v2gdin_body_CertificateInstallationRes_ContractID = -1;

static int hf_v2gdin_body_CableCheckRes_ResponseCode = -1;
static int hf_v2gdin_body_CableCheckRes_EVSEProcessing = -1;

static int hf_v2gdin_body_PreChargeRes_ResponseCode = -1;

static int hf_v2gdin_body_CurrentDemandReq_ChargingComplete = -1;
static int hf_v2gdin_body_CurrentDemandReq_BulkChargingComplete = -1;
static int hf_v2gdin_body_CurrentDemandRes_ResponseCode = -1;
static int hf_v2gdin_body_CurrentDemandRes_EVSECurrentLimitAchieved = -1;
static int hf_v2gdin_body_CurrentDemandRes_EVSEVoltageLimitAchieved = -1;
static int hf_v2gdin_body_CurrentDemandRes_EVSEPowerLimitAchieved = -1;

static int hf_v2gdin_body_WeldingDetectionRes_ResponseCode = -1;


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
static gint ett_v2gdin_struct_dinListOfRootCertificateIDsType = -1;
static gint ett_v2gdin_struct_dinEVChargeParameterType = -1;
static gint ett_v2gdin_struct_dinAC_EVChargeParameterType = -1;
static gint ett_v2gdin_struct_dinDC_EVChargeParameterType = -1;
static gint ett_v2gdin_struct_dinDC_EVStatusType = -1;
static gint ett_v2gdin_struct_dinEVSEChargeParameterType = -1;
static gint ett_v2gdin_struct_dinEVSEStatusType = -1;
static gint ett_v2gdin_struct_dinAC_EVSEChargeParameterType = -1;
static gint ett_v2gdin_struct_dinAC_EVSEStatusType = -1;
static gint ett_v2gdin_struct_dinDC_EVSEChargeParameterType = -1;
static gint ett_v2gdin_struct_dinDC_EVSEStatusType = -1;
static gint ett_v2gdin_struct_dinSASchedulesType = -1;
static gint ett_v2gdin_struct_dinSAScheduleListType = -1;
static gint ett_v2gdin_struct_dinSAScheduleTupleType = -1;
static gint ett_v2gdin_struct_dinPMaxScheduleType = -1;
static gint ett_v2gdin_struct_dinPMaxScheduleEntryType = -1;
static gint ett_v2gdin_struct_dinRelativeTimeIntervalType = -1;
static gint ett_v2gdin_struct_dinIntervalType = -1;
static gint ett_v2gdin_struct_dinSalesTariffType = -1;
static gint ett_v2gdin_struct_dinSalesTariffEntryType = -1;
static gint ett_v2gdin_struct_dinConsumptionCostType = -1;
static gint ett_v2gdin_struct_dinCostType = -1;
static gint ett_v2gdin_struct_dinChargingProfileType = -1;
static gint ett_v2gdin_struct_dinEVPowerDeliveryParameterType = -1;
static gint ett_v2gdin_struct_dinDC_EVPowerDeliveryParameterType = -1;
static gint ett_v2gdin_struct_dinProfileEntryType = -1;
static gint ett_v2gdin_struct_dinMeterInfoType = -1;

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
static gint ett_v2gdin_body_ChargeParameterDiscoveryReq = -1;
static gint ett_v2gdin_body_ChargeParameterDiscoveryRes = -1;
static gint ett_v2gdin_body_PowerDeliveryReq = -1;
static gint ett_v2gdin_body_PowerDeliveryRes = -1;
static gint ett_v2gdin_body_ChargingStatusReq = -1;
static gint ett_v2gdin_body_ChargingStatusRes = -1;
static gint ett_v2gdin_body_MeteringReceiptReq = -1;
static gint ett_v2gdin_body_MeteringReceiptRes = -1;
static gint ett_v2gdin_body_SessionStopReq = -1;
static gint ett_v2gdin_body_SessionStopRes = -1;
static gint ett_v2gdin_body_CertificateUpdateReq = -1;
static gint ett_v2gdin_body_CertificateUpdateRes = -1;
static gint ett_v2gdin_body_CertificateInstallationReq = -1;
static gint ett_v2gdin_body_CertificateInstallationRes = -1;
static gint ett_v2gdin_body_CableCheckReq = -1;
static gint ett_v2gdin_body_CableCheckRes = -1;
static gint ett_v2gdin_body_PreChargeReq = -1;
static gint ett_v2gdin_body_PreChargeRes = -1;
static gint ett_v2gdin_body_CurrentDemandReq = -1;
static gint ett_v2gdin_body_CurrentDemandRes = -1;
static gint ett_v2gdin_body_WeldingDetectionReq = -1;
static gint ett_v2gdin_body_WeldingDetectionRes = -1;

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

static const value_string v2gdin_ev_requested_energy_transfer[] = {
	{ dinEVRequestedEnergyTransferType_AC_single_phase_core,
	  "AC_single_phase_core" },
	{ dinEVRequestedEnergyTransferType_AC_three_phase_core,
	  "AC_three_phase_core" },
	{ dinEVRequestedEnergyTransferType_DC_core, "DC_core" },
	{ dinEVRequestedEnergyTransferType_DC_extended, "DC_extended" },
	{ dinEVRequestedEnergyTransferType_DC_combo_core, "DC_combo_core" },
	{ dinEVRequestedEnergyTransferType_DC_unique, "DC_unique" }
};

static const value_string v2gdin_evse_supported_energy_transfer_names[] = {
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

static const value_string v2gdin_cost_kind_names[] = {
	{ dincostKindType_relativePricePercentage, "relativePricePercentage" },
	{ dincostKindType_RenewableGenerationPercentage,
	  "RenewableGenerationPercentage" },
	{ dincostKindType_CarbonDioxideEmission, "CarbonDioxideEmission" }
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

		snprintf(index, sizeof(index), "[%u]", i);
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
dissect_v2gdin_listofrootcertificateids(
	const struct dinListOfRootCertificateIDsType *listofrootcertificateids,
	tvbuff_t *tvb,
	proto_tree *tree,
	gint idx,
	const char *subtree_name)
{
	unsigned int i;
	proto_tree *subtree;
	proto_tree *rootcertificateid_tree;
	proto_tree *rootcertificateid_i_tree;

	subtree = proto_tree_add_subtree(tree, tvb, 0, 0,
		idx, NULL, subtree_name);

	rootcertificateid_tree = proto_tree_add_subtree(subtree,
		tvb, 0, 0, ett_v2gdin_array, NULL, "RootCertificateID");
	for (i = 0; i < listofrootcertificateids->RootCertificateID.arrayLen; i++) {
		rootcertificateid_i_tree = proto_tree_add_subtree_format(
			rootcertificateid_tree,
			tvb, 0, 0, ett_v2gdin_array_i, NULL, "[%u]", i);
		exi_add_characters(rootcertificateid_i_tree,
			hf_v2gdin_struct_dinListOfRootCertificateIDsType_RootCertificateID,
			tvb,
			listofrootcertificateids->RootCertificateID.array[i].characters,
			listofrootcertificateids->RootCertificateID.array[i].charactersLen,
			sizeof(listofrootcertificateids->RootCertificateID.array[i].characters));
	}
	return;
}

static void
dissect_v2gdin_evchargeparameter(
	const struct dinEVChargeParameterType *evchargeparameter,
	tvbuff_t *tvb,
	proto_tree *tree,
	gint idx,
	const char *subtree_name)
{
	/* no content */
	return;
}

static void
dissect_v2gdin_ac_evchargeparameter(
	const struct dinAC_EVChargeParameterType *ac_evchargeparameter,
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
		hf_v2gdin_struct_dinAC_EVChargeParameterType_DepartureTime,
		tvb, 0, 0, ac_evchargeparameter->DepartureTime);
	proto_item_set_generated(it);

	dissect_v2gdin_physicalvalue(&ac_evchargeparameter->EAmount,
		tvb, subtree, ett_v2gdin_struct_dinPhysicalValueType,
		"EAmount");

	dissect_v2gdin_physicalvalue(&ac_evchargeparameter->EVMaxVoltage,
		tvb, subtree, ett_v2gdin_struct_dinPhysicalValueType,
		"EVMaxVoltage");

	dissect_v2gdin_physicalvalue(&ac_evchargeparameter->EVMaxCurrent,
		tvb, subtree, ett_v2gdin_struct_dinPhysicalValueType,
		"EVMaxCurrent");

	dissect_v2gdin_physicalvalue(&ac_evchargeparameter->EVMinCurrent,
		tvb, subtree, ett_v2gdin_struct_dinPhysicalValueType,
		"EVMinCurrent");

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
dissect_v2gdin_dc_evchargeparameter(
	const struct dinDC_EVChargeParameterType *dc_evchargeparameter,
	tvbuff_t *tvb,
	proto_tree *tree,
	gint idx,
	const char *subtree_name)
{
	proto_tree *subtree;
	proto_item *it;

	subtree = proto_tree_add_subtree(tree, tvb, 0, 0,
		idx, NULL, subtree_name);

	dissect_v2gdin_dc_evstatus(&dc_evchargeparameter->DC_EVStatus,
		tvb, subtree, ett_v2gdin_struct_dinDC_EVStatusType,
		"DC_EVStatus");

	dissect_v2gdin_physicalvalue(
		&dc_evchargeparameter->EVMaximumVoltageLimit,
		tvb, subtree, ett_v2gdin_struct_dinPhysicalValueType,
		"EVMaximumVoltageLimit");

	dissect_v2gdin_physicalvalue(
		&dc_evchargeparameter->EVMaximumCurrentLimit,
		tvb, subtree, ett_v2gdin_struct_dinPhysicalValueType,
		"EVMaximumCurrentLimit");

	if (dc_evchargeparameter->EVMaximumPowerLimit_isUsed) {
		dissect_v2gdin_physicalvalue(
			&dc_evchargeparameter->EVMaximumPowerLimit,
			tvb, subtree, ett_v2gdin_struct_dinPhysicalValueType,
			"EVMaximumPowertLimit");
	}

	if (dc_evchargeparameter->EVEnergyCapacity_isUsed) {
		dissect_v2gdin_physicalvalue(
			&dc_evchargeparameter->EVEnergyCapacity,
			tvb, subtree, ett_v2gdin_struct_dinPhysicalValueType,
			"EVEnergyCapacity");
	}

	if (dc_evchargeparameter->EVEnergyRequest_isUsed) {
		dissect_v2gdin_physicalvalue(
			&dc_evchargeparameter->EVEnergyRequest,
			tvb, subtree, ett_v2gdin_struct_dinPhysicalValueType,
			"EVEnergyRequest");
	}

	if (dc_evchargeparameter->FullSOC_isUsed) {
		it = proto_tree_add_int(subtree,
			hf_v2gdin_struct_dinDC_EVChargeParameterType_FullSOC,
			tvb, 0, 0, dc_evchargeparameter->FullSOC);
		proto_item_set_generated(it);
	}

	if (dc_evchargeparameter->BulkSOC_isUsed) {
		it = proto_tree_add_int(subtree,
			hf_v2gdin_struct_dinDC_EVChargeParameterType_BulkSOC,
			tvb, 0, 0, dc_evchargeparameter->BulkSOC);
		proto_item_set_generated(it);
	}

	return;
}

static void
dissect_v2gdin_evsestatus(const struct dinEVSEStatusType *evsestatus,
			  tvbuff_t *tvb,
			  proto_tree *tree,
			  gint idx,
			  const char *subtree_name)
{
	/* no content */
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
dissect_v2gdin_evsechargeparameter(
	const struct dinEVSEChargeParameterType *evsechargeparameter,
	tvbuff_t *tvb,
	proto_tree *tree,
	gint idx,
	const char *subtree_name)
{
	/* no content */
	return;
}

static void
dissect_v2gdin_ac_evsestatus(const struct dinAC_EVSEStatusType *ac_evsestatus,
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
		hf_v2gdin_struct_dinAC_EVSEStatusType_PowerSwitchClosed,
		tvb, 0, 0, ac_evsestatus->PowerSwitchClosed);
	proto_item_set_generated(it);

	it = proto_tree_add_int(subtree,
		hf_v2gdin_struct_dinAC_EVSEStatusType_RCD,
		tvb, 0, 0, ac_evsestatus->RCD);
	proto_item_set_generated(it);

	it = proto_tree_add_uint(subtree,
		hf_v2gdin_struct_dinAC_EVSEStatusType_NotificationMaxDelay,
		tvb, 0, 0, ac_evsestatus->NotificationMaxDelay);
	proto_item_set_generated(it);

	it = proto_tree_add_uint(subtree,
		hf_v2gdin_struct_dinAC_EVSEStatusType_EVSENotification,
		tvb, 0, 0, ac_evsestatus->EVSENotification);
	proto_item_set_generated(it);

	return;
}

static void
dissect_v2gdin_ac_evsechargeparameter(
	const struct dinAC_EVSEChargeParameterType *ac_evsechargeparameter,
	tvbuff_t *tvb,
	proto_tree *tree,
	gint idx,
	const char *subtree_name)
{
	proto_tree *subtree;

	subtree = proto_tree_add_subtree(tree, tvb, 0, 0,
		idx, NULL, subtree_name);

	dissect_v2gdin_ac_evsestatus(&ac_evsechargeparameter->AC_EVSEStatus,
		tvb, subtree, ett_v2gdin_struct_dinAC_EVSEStatusType,
		"AC_EVSEStatus");

	dissect_v2gdin_physicalvalue(&ac_evsechargeparameter->EVSEMaxVoltage,
		tvb, subtree, ett_v2gdin_struct_dinPhysicalValueType,
		"EVSEMaxVoltage");

	dissect_v2gdin_physicalvalue(&ac_evsechargeparameter->EVSEMaxCurrent,
		tvb, subtree, ett_v2gdin_struct_dinPhysicalValueType,
		"EVSEMaxCurrent");

	dissect_v2gdin_physicalvalue(&ac_evsechargeparameter->EVSEMaxCurrent,
		tvb, subtree, ett_v2gdin_struct_dinPhysicalValueType,
		"EVSEMinCurrent");

	return;
}

static void
dissect_v2gdin_dc_evsechargeparameter(
	const struct dinDC_EVSEChargeParameterType *dc_evsechargeparameter,
	tvbuff_t *tvb,
	proto_tree *tree,
	gint idx,
	const char *subtree_name)
{
	proto_tree *subtree;

	subtree = proto_tree_add_subtree(tree, tvb, 0, 0,
		idx, NULL, subtree_name);

	dissect_v2gdin_dc_evsestatus(&dc_evsechargeparameter->DC_EVSEStatus,
		tvb, subtree, ett_v2gdin_struct_dinDC_EVSEStatusType,
		"DC_EVSEStatus");

	dissect_v2gdin_physicalvalue(
		&dc_evsechargeparameter->EVSEMaximumVoltageLimit,
		tvb, subtree, ett_v2gdin_struct_dinPhysicalValueType,
		"EVSEMaximumVoltageLimit");

	dissect_v2gdin_physicalvalue(
		&dc_evsechargeparameter->EVSEMinimumVoltageLimit,
		tvb, subtree, ett_v2gdin_struct_dinPhysicalValueType,
		"EVSEMinimumVoltageLimit");

	dissect_v2gdin_physicalvalue(
		&dc_evsechargeparameter->EVSEMaximumCurrentLimit,
		tvb, subtree, ett_v2gdin_struct_dinPhysicalValueType,
		"EVSEMaximumCurrentLimit");

	dissect_v2gdin_physicalvalue(
		&dc_evsechargeparameter->EVSEMinimumCurrentLimit,
		tvb, subtree, ett_v2gdin_struct_dinPhysicalValueType,
		"EVSEMinimumCurrentLimit");

	if (dc_evsechargeparameter->EVSEMaximumPowerLimit_isUsed) {
		dissect_v2gdin_physicalvalue(
			&dc_evsechargeparameter->EVSEMaximumPowerLimit,
			tvb, subtree, ett_v2gdin_struct_dinPhysicalValueType,
			"EVSEMaximumPowerLimit");
	}

	if (dc_evsechargeparameter->EVSECurrentRegulationTolerance_isUsed) {
		dissect_v2gdin_physicalvalue(
			&dc_evsechargeparameter->EVSECurrentRegulationTolerance,
			tvb, subtree, ett_v2gdin_struct_dinPhysicalValueType,
			"EVSECurrentRegulationTolerance");
	}

	dissect_v2gdin_physicalvalue(
		&dc_evsechargeparameter->EVSEPeakCurrentRipple,
		tvb, subtree, ett_v2gdin_struct_dinPhysicalValueType,
		"EVSEPeakCurrentRipple");

	if (dc_evsechargeparameter->EVSEEnergyToBeDelivered_isUsed) {
		dissect_v2gdin_physicalvalue(
			&dc_evsechargeparameter->EVSEEnergyToBeDelivered,
			tvb, subtree, ett_v2gdin_struct_dinPhysicalValueType,
			"EVSEEnergyToBeDelivered");
	}

	return;
}

static void
dissect_v2gdin_interval(const struct dinIntervalType *interval,
			tvbuff_t *tvb,
			proto_tree *tree,
			gint idx,
			const char *subtree_name)
{
	/* no content */
	return;
}

static void
dissect_v2gdin_relativetimeinterval(
	const struct dinRelativeTimeIntervalType *relativetimeinterval,
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
		hf_v2gdin_struct_dinRelativeTimeIntervalType_start,
		tvb, 0, 0, relativetimeinterval->start);
	proto_item_set_generated(it);

	if (relativetimeinterval->duration_isUsed) {
		it = proto_tree_add_uint(subtree,
			hf_v2gdin_struct_dinRelativeTimeIntervalType_duration,
			tvb, 0, 0, relativetimeinterval->duration);
		proto_item_set_generated(it);
	}

	return;
}

static void
dissect_v2gdin_pmaxscheduleentry(
	const struct dinPMaxScheduleEntryType *pmaxscheduleentry,
	tvbuff_t *tvb,
	proto_tree *tree,
	gint idx,
	const char *subtree_name)
{
	proto_tree *subtree;
	proto_item *it;

	subtree = proto_tree_add_subtree(tree, tvb, 0, 0,
		idx, NULL, subtree_name);

	if (pmaxscheduleentry->TimeInterval_isUsed) {
		dissect_v2gdin_interval(&pmaxscheduleentry->TimeInterval,
			tvb, subtree, ett_v2gdin_struct_dinIntervalType,
			"TimeInterval");
	}

	if (pmaxscheduleentry->RelativeTimeInterval_isUsed) {
		dissect_v2gdin_relativetimeinterval(
			&pmaxscheduleentry->RelativeTimeInterval,
			tvb, subtree,
			ett_v2gdin_struct_dinRelativeTimeIntervalType,
			"RelativeTimeInterval");
	}

	it = proto_tree_add_int(subtree,
		hf_v2gdin_struct_dinPMaxScheduleEntryType_PMax,
		tvb, 0, 0, pmaxscheduleentry->PMax);
	proto_item_set_generated(it);

	return;
}

static void
dissect_v2gdin_pmaxschedule(const struct dinPMaxScheduleType *pmaxschedule,
			    tvbuff_t *tvb,
			    proto_tree *tree,
			    gint idx,
			    const char *subtree_name)
{
	unsigned int i;
	proto_tree *subtree;
	proto_tree *pmaxscheduleentry_tree;
	proto_item *it;

	subtree = proto_tree_add_subtree(tree, tvb, 0, 0,
		idx, NULL, subtree_name);

	it = proto_tree_add_int(subtree,
		hf_v2gdin_struct_dinPMaxScheduleType_PMaxScheduleID,
		tvb, 0, 0, pmaxschedule->PMaxScheduleID);
	proto_item_set_generated(it);

	pmaxscheduleentry_tree = proto_tree_add_subtree(subtree,
		tvb, 0, 0, ett_v2gdin_array, NULL, "PMaxScheduleEntry");
	for (i = 0; i < pmaxschedule->PMaxScheduleEntry.arrayLen; i++) {
		char index[sizeof("[65536]")];

		snprintf(index, sizeof(index), "[%u]", i);
		dissect_v2gdin_pmaxscheduleentry(
			&pmaxschedule->PMaxScheduleEntry.array[i],
			tvb, pmaxscheduleentry_tree,
			ett_v2gdin_struct_dinPMaxScheduleEntryType, index);
	}

	return;
}

static void
dissect_v2gdin_cost(const struct dinCostType *cost,
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
		hf_v2gdin_struct_dinCostType_costKind,
		tvb, 0, 0, cost->costKind);
	proto_item_set_generated(it);

	it = proto_tree_add_uint(subtree,
		hf_v2gdin_struct_dinCostType_amount,
		tvb, 0, 0, cost->amount);
	proto_item_set_generated(it);

	if (cost->amountMultiplier_isUsed) {
		it = proto_tree_add_int(subtree,
			hf_v2gdin_struct_dinCostType_amountMultiplier,
			tvb, 0, 0, cost->amount);
		proto_item_set_generated(it);
	}

	return;
}


static void
dissect_v2gdin_consumptioncost(
	const struct dinConsumptionCostType *consumptioncost,
	tvbuff_t *tvb,
	proto_tree *tree,
	gint idx,
	const char *subtree_name)
{
	unsigned int i;
	proto_tree *subtree;
	proto_tree *cost_tree;
	proto_item *it;

	subtree = proto_tree_add_subtree(tree, tvb, 0, 0,
		idx, NULL, subtree_name);

	it = proto_tree_add_uint(subtree,
		hf_v2gdin_struct_dinConsumptionCostType_startValue,
		tvb, 0, 0, consumptioncost->startValue);
	proto_item_set_generated(it);

	cost_tree = proto_tree_add_subtree(subtree,
		tvb, 0, 0, ett_v2gdin_array, NULL, "Cost");
	for (i = 0; i < consumptioncost->Cost.arrayLen; i++) {
		char index[sizeof("[65536]")];

		snprintf(index, sizeof(index), "[%u]", i);
		dissect_v2gdin_cost(
			&consumptioncost->Cost.array[i], tvb, cost_tree,
			ett_v2gdin_struct_dinCostType, index);
	}

	return;
}

static void
dissect_v2gdin_salestariffentry(
	const struct dinSalesTariffEntryType *salestariffentry,
	tvbuff_t *tvb,
	proto_tree *tree,
	gint idx,
	const char *subtree_name)
{
	unsigned int i;
	proto_tree *subtree;
	proto_tree *consumptioncost_tree;
	proto_item *it;

	subtree = proto_tree_add_subtree(tree, tvb, 0, 0,
		idx, NULL, subtree_name);

	if (salestariffentry->TimeInterval_isUsed) {
		dissect_v2gdin_interval(&salestariffentry->TimeInterval,
			tvb, subtree, ett_v2gdin_struct_dinIntervalType,
			"TimeInterval");
	}

	if (salestariffentry->RelativeTimeInterval_isUsed) {
		dissect_v2gdin_relativetimeinterval(
			&salestariffentry->RelativeTimeInterval,
			tvb, subtree,
			ett_v2gdin_struct_dinRelativeTimeIntervalType,
			"RelativeTimeInterval");
	}

	it = proto_tree_add_uint(subtree,
		hf_v2gdin_struct_dinSalesTariffEntryType_EPriceLevel,
		tvb, 0, 0, salestariffentry->EPriceLevel);
	proto_item_set_generated(it);

	consumptioncost_tree = proto_tree_add_subtree(subtree,
		tvb, 0, 0, ett_v2gdin_array, NULL, "ConsumptionCost");
	for (i = 0; i < salestariffentry->ConsumptionCost.arrayLen; i++) {
		char index[sizeof("[65536]")];

		snprintf(index, sizeof(index), "[%u]", i);
		dissect_v2gdin_consumptioncost(
			&salestariffentry->ConsumptionCost.array[i], tvb,
			consumptioncost_tree,
			ett_v2gdin_struct_dinConsumptionCostType, index);
	}

	return;
}

static void
dissect_v2gdin_salestariff(const struct dinSalesTariffType *salestariff,
			   tvbuff_t *tvb,
			   proto_tree *tree,
			   gint idx,
			   const char *subtree_name)
{
	unsigned int i;
	proto_tree *subtree;
	proto_tree *salestariffentry_tree;
	proto_item *it;

	subtree = proto_tree_add_subtree(tree, tvb, 0, 0,
		idx, NULL, subtree_name);

	exi_add_characters(subtree,
		hf_v2gdin_struct_dinSalesTariffType_Id,
		tvb,
		salestariff->Id.characters,
		salestariff->Id.charactersLen,
		sizeof(salestariff->Id.characters));

	if (salestariff->SalesTariffDescription_isUsed) {
		exi_add_characters(subtree,
			hf_v2gdin_struct_dinSalesTariffType_SalesTariffDescription,
			tvb,
			salestariff->SalesTariffDescription.characters,
			salestariff->SalesTariffDescription.charactersLen,
			sizeof(salestariff->SalesTariffDescription.characters));
	}

	it = proto_tree_add_uint(subtree,
		hf_v2gdin_struct_dinSalesTariffType_NumEPriceLevels,
		tvb, 0, 0, salestariff->NumEPriceLevels);
	proto_item_set_generated(it);

	salestariffentry_tree = proto_tree_add_subtree(subtree,
		tvb, 0, 0, ett_v2gdin_array, NULL, "SalesTariffEntry");
	for (i = 0; i < salestariff->SalesTariffEntry.arrayLen; i++) {
		char index[sizeof("[65536]")];

		snprintf(index, sizeof(index), "[%u]", i);
		dissect_v2gdin_salestariffentry(
			&salestariff->SalesTariffEntry.array[i], tvb,
			salestariffentry_tree,
			ett_v2gdin_struct_dinSalesTariffEntryType, index);
	}

	return;
}

static void
dissect_v2gdin_saschedules(const struct dinSASchedulesType *saschedules,
			   tvbuff_t *tvb,
			   proto_tree *tree,
			   gint idx,
			   const char *subtree_name)
{
	/* no content */
	return;
}

static void
dissect_v2gdin_sascheduletuple(
	const struct dinSAScheduleTupleType *sascheduletuple,
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
		hf_v2gdin_struct_dinSAScheduleTupleType_SAScheduleTupleID,
		tvb, 0, 0, sascheduletuple->SAScheduleTupleID);
	proto_item_set_generated(it);

	dissect_v2gdin_pmaxschedule(&sascheduletuple->PMaxSchedule,
		tvb, subtree, ett_v2gdin_struct_dinPMaxScheduleType,
		"PMaxSchedule");

	if (sascheduletuple->SalesTariff_isUsed) {
		dissect_v2gdin_salestariff(&sascheduletuple->SalesTariff,
			tvb, subtree, ett_v2gdin_struct_dinSalesTariffType,
			"SalesTariff");
	}

	return;
}

static void
dissect_v2gdin_saschedulelist(
	const struct dinSAScheduleListType *saschedulelist,
	tvbuff_t *tvb,
	proto_tree *tree,
	gint idx,
	const char *subtree_name)
{
	unsigned int i;
	proto_tree *subtree;
	proto_tree *sascheduletuple_tree;

	subtree = proto_tree_add_subtree(tree, tvb, 0, 0,
		idx, NULL, subtree_name);

	sascheduletuple_tree = proto_tree_add_subtree(subtree,
		tvb, 0, 0, ett_v2gdin_array, NULL, "SAScheduleTuple");
	for (i = 0; i < saschedulelist->SAScheduleTuple.arrayLen; i++) {
		char index[sizeof("[65536]")];

		snprintf(index, sizeof(index), "[%u]", i);
		dissect_v2gdin_sascheduletuple(
			&saschedulelist->SAScheduleTuple.array[i], tvb,
			sascheduletuple_tree,
			ett_v2gdin_struct_dinSAScheduleTupleType, index);
	}

	return;
}

static void
dissect_v2gdin_profileentry(
	const struct dinProfileEntryType *profileentry,
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
		hf_v2gdin_struct_dinProfileEntryType_ChargingProfileEntryStart,
		tvb, 0, 0, profileentry->ChargingProfileEntryStart);
	proto_item_set_generated(it);

	it = proto_tree_add_int(subtree,
		hf_v2gdin_struct_dinProfileEntryType_ChargingProfileEntryMaxPower,
		tvb, 0, 0, profileentry->ChargingProfileEntryMaxPower);
	proto_item_set_generated(it);

	return;
}

static void
dissect_v2gdin_chargingprofile(
	const struct dinChargingProfileType *chargingprofile,
	tvbuff_t *tvb,
	proto_tree *tree,
	gint idx,
	const char *subtree_name)
{
	unsigned int i;
	proto_tree *subtree;
	proto_tree *profileentry_tree;
	proto_item *it;

	subtree = proto_tree_add_subtree(tree, tvb, 0, 0,
		idx, NULL, subtree_name);

	it = proto_tree_add_int(subtree,
		hf_v2gdin_struct_dinChargingProfileType_SAScheduleTupleID,
		tvb, 0, 0, chargingprofile->SAScheduleTupleID);
	proto_item_set_generated(it);

	profileentry_tree = proto_tree_add_subtree(subtree,
		tvb, 0, 0, ett_v2gdin_array, NULL, "ProfileEntry");
	for (i = 0; i < chargingprofile->ProfileEntry.arrayLen; i++) {
		char index[sizeof("[65536]")];

		snprintf(index, sizeof(index), "[%u]", i);
		dissect_v2gdin_profileentry(
			&chargingprofile->ProfileEntry.array[i], tvb,
			profileentry_tree,
			ett_v2gdin_struct_dinProfileEntryType, index);
	}

	return;
}

static void
dissect_v2gdin_meterinfo(const struct dinMeterInfoType *meterinfo,
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
		hf_v2gdin_struct_dinMeterInfoType_MeterID,
		tvb,
		meterinfo->MeterID.characters,
		meterinfo->MeterID.charactersLen,
		sizeof(meterinfo->MeterID.characters));

	if (meterinfo->MeterReading_isUsed) {
		dissect_v2gdin_physicalvalue(&meterinfo->MeterReading,
			tvb, subtree, ett_v2gdin_struct_dinPhysicalValueType,
			"MeterReading");
	}

	if (meterinfo->SigMeterReading_isUsed) {
		exi_add_bytes(subtree,
			hf_v2gdin_struct_dinMeterInfoType_SigMeterReading,
			tvb,
			meterinfo->SigMeterReading.bytes,
			meterinfo->SigMeterReading.bytesLen,
			sizeof(meterinfo->SigMeterReading.bytes));
	}

	if (meterinfo->MeterStatus_isUsed) {
		it = proto_tree_add_int(subtree,
			hf_v2gdin_struct_dinMeterInfoType_MeterStatus,
			tvb, 0, 0, meterinfo->MeterStatus);
		proto_item_set_generated(it);
	}

	if (meterinfo->TMeter_isUsed) {
		it = proto_tree_add_int(subtree,
			hf_v2gdin_struct_dinMeterInfoType_TMeter,
			tvb, 0, 0, meterinfo->TMeter);
		proto_item_set_generated(it);
	}

	return;
}

static void
dissect_v2gdin_evpowerdeliveryparameter(
	const struct dinEVPowerDeliveryParameterType *evpowerdeliveryparameter,
	tvbuff_t *tvb,
	proto_tree *tree,
	gint idx,
	const char *subtree_name)
{
	/* no content */
	return;
}

static void
dissect_v2gdin_dc_evpowerdeliveryparameter(
	const struct dinDC_EVPowerDeliveryParameterType *dc_evpowerdeliveryparameter,
	tvbuff_t *tvb,
	proto_tree *tree,
	gint idx,
	const char *subtree_name)
{
	proto_tree *subtree;
	proto_item *it;

	subtree = proto_tree_add_subtree(tree, tvb, 0, 0,
		idx, NULL, subtree_name);

	dissect_v2gdin_dc_evstatus(&dc_evpowerdeliveryparameter->DC_EVStatus,
		tvb, subtree, ett_v2gdin_struct_dinDC_EVStatusType,
		"DC_EVStatus");

	if (dc_evpowerdeliveryparameter->BulkChargingComplete_isUsed) {
		it = proto_tree_add_int(subtree,
			hf_v2gdin_struct_dinDC_EVPowerDeliveryParameterType_BulkChargingComplete,
			tvb, 0, 0,
			dc_evpowerdeliveryparameter->BulkChargingComplete);
		proto_item_set_generated(it);
	}

	it = proto_tree_add_int(subtree,
		hf_v2gdin_struct_dinDC_EVPowerDeliveryParameterType_ChargingComplete,
		tvb, 0, 0,
		dc_evpowerdeliveryparameter->ChargingComplete);
		proto_item_set_generated(it);

	return;
}


static void
dissect_v2gdin_header(tvbuff_t *tvb, packet_info *pinfo,
		      proto_tree *v2gdin_tree, struct dinMessageHeaderType *hdr)
{
	proto_tree *hdr_tree;

	hdr_tree = proto_tree_add_subtree(v2gdin_tree,
		tvb, 0, 0, ett_v2gdin_header, NULL, "Header");

	exi_add_bytes(hdr_tree, hf_v2gdin_header_SessionID, tvb,
		hdr->SessionID.bytes,
		hdr->SessionID.bytesLen,
		sizeof(hdr->SessionID.bytes));

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
		proto_tree *req_tree;
		proto_item *it;

		req_tree = proto_tree_add_subtree(body_tree,
			tvb, 0, 0, ett_v2gdin_body_ChargeParameterDiscoveryReq,
			NULL, "ChargeParameterDiscoveryReq");

		it = proto_tree_add_uint(req_tree,
			hf_v2gdin_body_ChargeParameterDiscoveryReq_EVRequestedEnergyTransferType,
			tvb, 0, 0,
			body->ChargeParameterDiscoveryReq.EVRequestedEnergyTransferType);
		proto_item_set_generated(it);

		if (body->ChargeParameterDiscoveryReq.EVChargeParameter_isUsed) {

			dissect_v2gdin_evchargeparameter(
				&body->ChargeParameterDiscoveryReq.EVChargeParameter,
				tvb, req_tree,
				ett_v2gdin_struct_dinEVChargeParameterType,
				"EVChargeParameter");
		}

		if (body->ChargeParameterDiscoveryReq.AC_EVChargeParameter_isUsed) {
			dissect_v2gdin_ac_evchargeparameter(
				&body->ChargeParameterDiscoveryReq.AC_EVChargeParameter,
				tvb, req_tree,
				ett_v2gdin_struct_dinAC_EVChargeParameterType,
				"AC_EVChargeParameter");
		}

		if (body->ChargeParameterDiscoveryReq.DC_EVChargeParameter_isUsed) {
			dissect_v2gdin_dc_evchargeparameter(
				&body->ChargeParameterDiscoveryReq.DC_EVChargeParameter,
				tvb, req_tree,
				ett_v2gdin_struct_dinDC_EVChargeParameterType,
				"DC_EVChargeParameter");
		}
	}
	if (body->ChargeParameterDiscoveryRes_isUsed) {
		proto_tree *res_tree;
		proto_item *it;

		res_tree = proto_tree_add_subtree(body_tree,
			tvb, 0, 0, ett_v2gdin_body_ChargeParameterDiscoveryRes,
			NULL, "ChargeParameterDiscoveryRes");

		it = proto_tree_add_uint(res_tree,
			hf_v2gdin_body_ChargeParameterDiscoveryRes_ResponseCode,
			tvb, 0, 0,
			body->ChargeParameterDiscoveryRes.ResponseCode);
		proto_item_set_generated(it);

		it = proto_tree_add_uint(res_tree,
			hf_v2gdin_body_ChargeParameterDiscoveryRes_EVSEProcessing,
			tvb, 0, 0,
			body->ChargeParameterDiscoveryRes.EVSEProcessing);
		proto_item_set_generated(it);

		if (body->ChargeParameterDiscoveryRes.SASchedules_isUsed) {
			dissect_v2gdin_saschedules(
				&body->ChargeParameterDiscoveryRes.SASchedules,
				tvb, res_tree,
				ett_v2gdin_struct_dinSASchedulesType,
				"SASchedules");
		}
		if (body->ChargeParameterDiscoveryRes.SAScheduleList_isUsed) {
			dissect_v2gdin_saschedulelist(
				&body->ChargeParameterDiscoveryRes.SAScheduleList,
				tvb, res_tree,
				ett_v2gdin_struct_dinSAScheduleListType,
				"SAScheduleList");
		}
		if (body->ChargeParameterDiscoveryRes.EVSEChargeParameter_isUsed) {
			dissect_v2gdin_evsechargeparameter(&body->ChargeParameterDiscoveryRes.EVSEChargeParameter,
				tvb, res_tree,
				ett_v2gdin_struct_dinEVSEChargeParameterType,
				"EVSEChargeParameter");
		}
		if (body->ChargeParameterDiscoveryRes.AC_EVSEChargeParameter_isUsed) {
			dissect_v2gdin_ac_evsechargeparameter(
				&body->ChargeParameterDiscoveryRes.AC_EVSEChargeParameter,
				tvb, res_tree,
				ett_v2gdin_struct_dinAC_EVSEChargeParameterType,
				"AC_EVSEChargeParameter");
		}
		if (body->ChargeParameterDiscoveryRes.DC_EVSEChargeParameter_isUsed) {
			dissect_v2gdin_dc_evsechargeparameter(
				&body->ChargeParameterDiscoveryRes.DC_EVSEChargeParameter,
				tvb, res_tree,
				ett_v2gdin_struct_dinDC_EVSEChargeParameterType,
				"DC_EVSEChargeParameter");
		}
	}

	if (body->PowerDeliveryReq_isUsed) {
		proto_tree *req_tree;
		proto_item *it;

		req_tree = proto_tree_add_subtree(body_tree,
			tvb, 0, 0, ett_v2gdin_body_PowerDeliveryReq,
			NULL, "PowerDeliveryReq");

		it = proto_tree_add_int(req_tree,
			hf_v2gdin_body_PowerDeliveryReq_ReadyToChargeState,
			tvb, 0, 0, body->PowerDeliveryReq.ReadyToChargeState);
		proto_item_set_generated(it);

		if (body->PowerDeliveryReq.ChargingProfile_isUsed) {
			dissect_v2gdin_chargingprofile(
				&body->PowerDeliveryReq.ChargingProfile,
				tvb, req_tree,
				ett_v2gdin_struct_dinChargingProfileType,
				"ChargingProfile");
		}
		if (body->PowerDeliveryReq.EVPowerDeliveryParameter_isUsed) {
			dissect_v2gdin_evpowerdeliveryparameter(
				&body->PowerDeliveryReq.EVPowerDeliveryParameter,
				tvb, req_tree,
				ett_v2gdin_struct_dinEVPowerDeliveryParameterType,
				"EVPowerDeliveryParameter");
		}
		if (body->PowerDeliveryReq.DC_EVPowerDeliveryParameter_isUsed) {
			dissect_v2gdin_dc_evpowerdeliveryparameter(
				&body->PowerDeliveryReq.DC_EVPowerDeliveryParameter,
				tvb, req_tree,
				ett_v2gdin_struct_dinDC_EVPowerDeliveryParameterType,
				"DC_EVPowerDeliveryParameter");
		}
	}
	if (body->PowerDeliveryRes_isUsed) {
		proto_tree *res_tree;
		proto_item *it;

		res_tree = proto_tree_add_subtree(body_tree,
			tvb, 0, 0, ett_v2gdin_body_PowerDeliveryRes,
			NULL, "PowerDeliveryRes");

		it = proto_tree_add_uint(res_tree,
			hf_v2gdin_body_PowerDeliveryRes_ResponseCode,
			tvb, 0, 0,
			body->PowerDeliveryRes.ResponseCode);
		proto_item_set_generated(it);

		if (body->PowerDeliveryRes.EVSEStatus_isUsed) {
			dissect_v2gdin_evsestatus(
				&body->PowerDeliveryRes.EVSEStatus,
				tvb, res_tree,
				ett_v2gdin_struct_dinEVSEStatusType,
				"EVSEStatus");
		}
		if (body->PowerDeliveryRes.AC_EVSEStatus_isUsed) {
			dissect_v2gdin_ac_evsestatus(
				&body->PowerDeliveryRes.AC_EVSEStatus,
				tvb, res_tree,
				ett_v2gdin_struct_dinAC_EVSEStatusType,
				"AC_EVSEStatus");
		}
		if (body->PowerDeliveryRes.DC_EVSEStatus_isUsed) {
			dissect_v2gdin_dc_evsestatus(
				&body->PowerDeliveryRes.DC_EVSEStatus,
				tvb, res_tree,
				ett_v2gdin_struct_dinDC_EVSEStatusType,
				"DC_EVSEStatus");
		}
	}

	if (body->ChargingStatusReq_isUsed) {
		proto_tree_add_subtree(body_tree,
			tvb, 0, 0, ett_v2gdin_body_ChargingStatusReq,
			NULL, "ChargingStatusReq");

		/* no content */
	}
	if (body->ChargingStatusRes_isUsed) {
		proto_tree *res_tree;
		proto_item *it;

		res_tree = proto_tree_add_subtree(body_tree,
			tvb, 0, 0, ett_v2gdin_body_ChargingStatusRes,
			NULL, "ChargingStatusRes");

		it = proto_tree_add_uint(res_tree,
			hf_v2gdin_body_ChargingStatusRes_ResponseCode,
			tvb, 0, 0,
			body->ChargingStatusRes.ResponseCode);
		proto_item_set_generated(it);

		exi_add_bytes(res_tree,
			hf_v2gdin_body_ChargingStatusRes_EVSEID,
			tvb,
			body->ChargingStatusRes.EVSEID.bytes,
			body->ChargingStatusRes.EVSEID.bytesLen,
			sizeof(body->ChargingStatusRes.EVSEID.bytes));

		it = proto_tree_add_int(res_tree,
			hf_v2gdin_body_ChargingStatusRes_SAScheduleTupleID,
			tvb, 0, 0,
			body->ChargingStatusRes.SAScheduleTupleID);
		proto_item_set_generated(it);

		if (body->ChargingStatusRes.EVSEMaxCurrent_isUsed) {
			dissect_v2gdin_physicalvalue(
				&body->ChargingStatusRes.EVSEMaxCurrent,
				tvb, res_tree,
				ett_v2gdin_struct_dinPhysicalValueType,
				"EVSEMaxCurrent");
		}
		if (body->ChargingStatusRes.MeterInfo_isUsed) {
			dissect_v2gdin_meterinfo(
				&body->ChargingStatusRes.MeterInfo,
				tvb, res_tree,
				ett_v2gdin_struct_dinMeterInfoType,
				"MeterInfo");
		}

		it = proto_tree_add_int(res_tree,
			hf_v2gdin_body_ChargingStatusRes_ReceiptRequired,
			tvb, 0, 0,
			body->ChargingStatusRes.ReceiptRequired);
		proto_item_set_generated(it);

		dissect_v2gdin_ac_evsestatus(
			&body->ChargingStatusRes.AC_EVSEStatus,
			tvb, res_tree,
			ett_v2gdin_struct_dinAC_EVSEStatusType,
			"AC_EVSEStatus");
	}

	if (body->MeteringReceiptReq_isUsed) {
		proto_tree *req_tree;
		proto_item *it;

		req_tree = proto_tree_add_subtree(body_tree,
			tvb, 0, 0, ett_v2gdin_body_MeteringReceiptReq,
			NULL, "MeteringReceiptReq");

		if (body->MeteringReceiptReq.Id_isUsed) {
			exi_add_characters(req_tree,
				hf_v2gdin_body_MeteringReceiptReq_Id,
				tvb,
				body->MeteringReceiptReq.Id.characters,
				body->MeteringReceiptReq.Id.charactersLen,
				sizeof(body->MeteringReceiptReq.Id.characters));
		}

		exi_add_bytes(req_tree,
			hf_v2gdin_body_MeteringReceiptReq_SessionID,
			tvb,
			body->MeteringReceiptReq.SessionID.bytes,
			body->MeteringReceiptReq.SessionID.bytesLen,
			sizeof(body->MeteringReceiptReq.SessionID.bytes));

		if (body->MeteringReceiptReq.SAScheduleTupleID_isUsed) {
			it = proto_tree_add_int(req_tree,
				hf_v2gdin_body_MeteringReceiptReq_SAScheduleTupleID,
				tvb, 0, 0,
				body->MeteringReceiptReq.SAScheduleTupleID);
			proto_item_set_generated(it);
		}

		dissect_v2gdin_meterinfo(
			&body->MeteringReceiptReq.MeterInfo,
			tvb, req_tree,
			ett_v2gdin_struct_dinMeterInfoType,
			"MeterInfo");
	}
	if (body->MeteringReceiptRes_isUsed) {
		proto_tree *res_tree;
		proto_item *it;

		res_tree = proto_tree_add_subtree(body_tree,
			tvb, 0, 0, ett_v2gdin_body_MeteringReceiptRes,
			NULL, "MeteringReceiptRes");

		it = proto_tree_add_uint(res_tree,
			hf_v2gdin_body_MeteringReceiptRes_ResponseCode,
			tvb, 0, 0,
			body->MeteringReceiptRes.ResponseCode);
		proto_item_set_generated(it);

		dissect_v2gdin_ac_evsestatus(
			&body->MeteringReceiptRes.AC_EVSEStatus,
			tvb, res_tree,
			ett_v2gdin_struct_dinAC_EVSEStatusType,
			"AC_EVSEStatus");
	}

	if (body->SessionStopReq_isUsed) {
		proto_tree_add_subtree(body_tree,
			tvb, 0, 0, ett_v2gdin_body_SessionStopReq,
			NULL, "SessionStopReq");

		/* no content */
	}
	if (body->SessionStopRes_isUsed) {
		proto_tree *res_tree;
		proto_item *it;

		res_tree = proto_tree_add_subtree(body_tree,
			tvb, 0, 0, ett_v2gdin_body_SessionStopRes,
			NULL, "SessionStopRes");

		it = proto_tree_add_uint(res_tree,
			hf_v2gdin_body_SessionStopRes_ResponseCode,
			tvb, 0, 0, body->SessionStopRes.ResponseCode);
		proto_item_set_generated(it);
	}

	if (body->CertificateUpdateReq_isUsed) {
		proto_tree *req_tree;

		req_tree = proto_tree_add_subtree(body_tree,
			tvb, 0, 0, ett_v2gdin_body_CertificateUpdateReq,
			NULL, "CertificateUpdateReq");

		exi_add_characters(req_tree,
			hf_v2gdin_body_CertificateUpdateReq_Id,
			tvb,
			body->CertificateUpdateReq.Id.characters,
			body->CertificateUpdateReq.Id.charactersLen,
			sizeof(body->CertificateUpdateReq.Id.characters));

		dissect_v2gdin_certificatechain(
			&body->CertificateUpdateReq.ContractSignatureCertChain,
			tvb, req_tree,
			ett_v2gdin_struct_dinCertificateChainType,
			"ContractSignatureCertChain");

		exi_add_characters(req_tree,
			hf_v2gdin_body_CertificateUpdateReq_ContractID,
			tvb,
			body->CertificateUpdateReq.ContractID.characters,
			body->CertificateUpdateReq.ContractID.charactersLen,
			sizeof(body->CertificateUpdateReq.ContractID.characters));

		dissect_v2gdin_listofrootcertificateids(
			&body->CertificateUpdateReq.ListOfRootCertificateIDs,
			tvb, req_tree,
			ett_v2gdin_struct_dinListOfRootCertificateIDsType,
			"ListOfRootCertificateIDs");

		exi_add_bytes(req_tree,
			hf_v2gdin_body_CertificateUpdateReq_DHParams,
			tvb,
			body->CertificateUpdateReq.DHParams.bytes,
			body->CertificateUpdateReq.DHParams.bytesLen,
			sizeof(body->CertificateUpdateReq.DHParams.bytes));
	}
	if (body->CertificateUpdateRes_isUsed) {
		proto_tree *res_tree;
		proto_item *it;

		res_tree = proto_tree_add_subtree(body_tree,
			tvb, 0, 0, ett_v2gdin_body_CertificateUpdateRes,
			NULL, "CertificateUpdateRes");

		exi_add_characters(res_tree,
			hf_v2gdin_body_CertificateUpdateRes_Id,
			tvb,
			body->CertificateUpdateRes.Id.characters,
			body->CertificateUpdateRes.Id.charactersLen,
			sizeof(body->CertificateUpdateRes.Id.characters));

		it = proto_tree_add_uint(res_tree,
			hf_v2gdin_body_CertificateUpdateRes_ResponseCode,
			tvb, 0, 0, body->CertificateUpdateRes.ResponseCode);
		proto_item_set_generated(it);

		dissect_v2gdin_certificatechain(
			&body->CertificateUpdateRes.ContractSignatureCertChain,
			tvb, res_tree,
			ett_v2gdin_struct_dinCertificateChainType,
			"ContractSignatureCertChain");

		exi_add_bytes(res_tree,
			hf_v2gdin_body_CertificateUpdateRes_ContractSignatureEncryptedPrivateKey,
			tvb,
			body->CertificateUpdateRes.ContractSignatureEncryptedPrivateKey.bytes,
			body->CertificateUpdateRes.ContractSignatureEncryptedPrivateKey.bytesLen,
			sizeof(body->CertificateUpdateRes.ContractSignatureEncryptedPrivateKey.bytes));

		exi_add_bytes(res_tree,
			hf_v2gdin_body_CertificateUpdateRes_DHParams,
			tvb,
			body->CertificateUpdateRes.DHParams.bytes,
			body->CertificateUpdateRes.DHParams.bytesLen,
			sizeof(body->CertificateUpdateRes.DHParams.bytes));

		exi_add_characters(res_tree,
			hf_v2gdin_body_CertificateUpdateRes_ContractID,
			tvb,
			body->CertificateUpdateRes.ContractID.characters,
			body->CertificateUpdateRes.ContractID.charactersLen,
			sizeof(body->CertificateUpdateRes.ContractID.characters));

		it = proto_tree_add_uint(res_tree,
			hf_v2gdin_body_CertificateUpdateRes_RetryCounter,
			tvb, 0, 0, body->CertificateUpdateRes.RetryCounter);
		proto_item_set_generated(it);
	}

	if (body->CertificateInstallationReq_isUsed) {
		proto_tree *req_tree;

		req_tree = proto_tree_add_subtree(body_tree,
			tvb, 0, 0, ett_v2gdin_body_CertificateInstallationReq,
			NULL, "CertificateInstallationReq");

		if (body->CertificateInstallationReq.Id_isUsed) {
			exi_add_characters(req_tree,
				hf_v2gdin_body_CertificateInstallationReq_Id,
				tvb,
				body->CertificateInstallationRes.Id.characters,
				body->CertificateInstallationRes.Id.charactersLen,
				sizeof(body->CertificateInstallationRes.Id.characters));
		}

		exi_add_bytes(req_tree,
			hf_v2gdin_body_CertificateInstallationReq_OEMProvisioningCert,
			tvb,
			body->CertificateInstallationReq.OEMProvisioningCert.bytes,
			body->CertificateInstallationReq.OEMProvisioningCert.bytesLen,
			sizeof(body->CertificateInstallationReq.OEMProvisioningCert.bytes));
		dissect_v2gdin_listofrootcertificateids(
			&body->CertificateInstallationReq.ListOfRootCertificateIDs,
			tvb, req_tree,
			ett_v2gdin_struct_dinListOfRootCertificateIDsType,
			"ListOfRootCertificateIDs");

		exi_add_bytes(req_tree,
			hf_v2gdin_body_CertificateInstallationReq_DHParams,
			tvb,
			body->CertificateInstallationReq.DHParams.bytes,
			body->CertificateInstallationReq.DHParams.bytesLen,
			sizeof(body->CertificateInstallationReq.DHParams.bytes));
	}
	if (body->CertificateInstallationRes_isUsed) {
		proto_tree *res_tree;
		proto_item *it;

		res_tree = proto_tree_add_subtree(body_tree,
			tvb, 0, 0, ett_v2gdin_body_CertificateInstallationRes,
			NULL, "CertificateInstallationRes");

		exi_add_characters(res_tree,
			hf_v2gdin_body_CertificateInstallationRes_Id,
			tvb,
			body->CertificateInstallationRes.Id.characters,
			body->CertificateInstallationRes.Id.charactersLen,
			sizeof(body->CertificateInstallationRes.Id.characters));

		it = proto_tree_add_uint(res_tree,
			hf_v2gdin_body_CertificateInstallationRes_ResponseCode,
			tvb, 0, 0, body->CertificateInstallationRes.ResponseCode);
		proto_item_set_generated(it);

		dissect_v2gdin_certificatechain(
			&body->CertificateInstallationRes.ContractSignatureCertChain,
			tvb, res_tree,
			ett_v2gdin_struct_dinCertificateChainType,
			"ContractSignatureCertChain");

		exi_add_bytes(res_tree,
			hf_v2gdin_body_CertificateInstallationRes_ContractSignatureEncryptedPrivateKey,
			tvb,
			body->CertificateInstallationRes.ContractSignatureEncryptedPrivateKey.bytes,
			body->CertificateInstallationRes.ContractSignatureEncryptedPrivateKey.bytesLen,
			sizeof(body->CertificateInstallationRes.ContractSignatureEncryptedPrivateKey.bytes));

		exi_add_bytes(res_tree,
			hf_v2gdin_body_CertificateInstallationRes_DHParams,
			tvb,
			body->CertificateInstallationRes.DHParams.bytes,
			body->CertificateInstallationRes.DHParams.bytesLen,
			sizeof(body->CertificateInstallationRes.DHParams.bytes));

		exi_add_characters(res_tree,
			hf_v2gdin_body_CertificateInstallationRes_ContractID,
			tvb,
			body->CertificateInstallationRes.ContractID.characters,
			body->CertificateInstallationRes.ContractID.charactersLen,
			sizeof(body->CertificateInstallationRes.ContractID.characters));
	}

	if (body->CableCheckReq_isUsed) {
		proto_tree *req_tree;

		req_tree = proto_tree_add_subtree(body_tree,
			tvb, 0, 0, ett_v2gdin_body_CableCheckReq,
			NULL, "CableCheckReq");

		dissect_v2gdin_dc_evstatus(
			&body->CableCheckReq.DC_EVStatus,
			tvb, req_tree,
			ett_v2gdin_struct_dinDC_EVStatusType,
			"DC_EVStatus");
	}
	if (body->CableCheckRes_isUsed) {
		proto_tree *res_tree;
		proto_item *it;

		res_tree = proto_tree_add_subtree(body_tree,
			tvb, 0, 0, ett_v2gdin_body_CableCheckRes,
			NULL, "CableCheckRes");

		it = proto_tree_add_uint(res_tree,
			hf_v2gdin_body_CableCheckRes_ResponseCode,
			tvb, 0, 0, body->CableCheckRes.ResponseCode);
		proto_item_set_generated(it);

		dissect_v2gdin_dc_evsestatus(
			&body->CableCheckRes.DC_EVSEStatus,
			tvb, res_tree,
			ett_v2gdin_struct_dinDC_EVSEStatusType,
			"DC_EVSEStatus");

		it = proto_tree_add_uint(res_tree,
			hf_v2gdin_body_CableCheckRes_EVSEProcessing,
			tvb, 0, 0, body->CableCheckRes.EVSEProcessing);
		proto_item_set_generated(it);
	}

	if (body->PreChargeReq_isUsed) {
		proto_tree *req_tree;

		req_tree = proto_tree_add_subtree(body_tree,
			tvb, 0, 0, ett_v2gdin_body_PreChargeReq,
			NULL, "PreChargeReq");

		dissect_v2gdin_dc_evstatus(
			&body->PreChargeReq.DC_EVStatus,
			tvb, req_tree,
			ett_v2gdin_struct_dinDC_EVStatusType,
			"DC_EVStatus");

		dissect_v2gdin_physicalvalue(
			&body->PreChargeReq.EVTargetVoltage,
			tvb, req_tree,
			ett_v2gdin_struct_dinPhysicalValueType,
			"EVTargetVoltage");

		dissect_v2gdin_physicalvalue(
			&body->PreChargeReq.EVTargetCurrent,
			tvb, req_tree,
			ett_v2gdin_struct_dinPhysicalValueType,
			"EVTargetCurrent");
	}
	if (body->PreChargeRes_isUsed) {
		proto_tree *res_tree;
		proto_item *it;

		res_tree = proto_tree_add_subtree(body_tree,
			tvb, 0, 0, ett_v2gdin_body_PreChargeRes,
			NULL, "PreChargeRes");

		it = proto_tree_add_uint(res_tree,
			hf_v2gdin_body_PreChargeRes_ResponseCode,
			tvb, 0, 0, body->PreChargeRes.ResponseCode);
		proto_item_set_generated(it);

		dissect_v2gdin_dc_evsestatus(
			&body->PreChargeRes.DC_EVSEStatus,
			tvb, res_tree,
			ett_v2gdin_struct_dinDC_EVSEStatusType,
			"DC_EVSEStatus");

		dissect_v2gdin_physicalvalue(
			&body->PreChargeRes.EVSEPresentVoltage,
			tvb, res_tree,
			ett_v2gdin_struct_dinPhysicalValueType,
			"EVSEPresentVoltage");
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
		proto_tree *req_tree;

		req_tree = proto_tree_add_subtree(body_tree,
			tvb, 0, 0, ett_v2gdin_body_WeldingDetectionReq,
			NULL, "WeldingDetectionReq");

		dissect_v2gdin_dc_evstatus(
			&body->WeldingDetectionReq.DC_EVStatus,
			tvb, req_tree, ett_v2gdin_struct_dinDC_EVStatusType,
			"DC_EVStatus");
	}
	if (body->WeldingDetectionRes_isUsed) {
		proto_tree *res_tree;
		proto_item *it;

		res_tree = proto_tree_add_subtree(body_tree,
			tvb, 0, 0, ett_v2gdin_body_WeldingDetectionRes,
			NULL, "WeldingDetectionRes");

		it = proto_tree_add_uint(res_tree,
			hf_v2gdin_body_WeldingDetectionRes_ResponseCode,
			tvb, 0, 0, body->WeldingDetectionRes.ResponseCode);
		proto_item_set_generated(it);

		dissect_v2gdin_dc_evsestatus(
			&body->WeldingDetectionRes.DC_EVSEStatus,
			tvb, res_tree, ett_v2gdin_struct_dinDC_EVSEStatusType,
			"DC_EVSEStatus");

		dissect_v2gdin_physicalvalue(
			&body->WeldingDetectionRes.EVSEPresentVoltage,
			tvb, res_tree, ett_v2gdin_struct_dinPhysicalValueType,
			"EVSEPresentVoltage");
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
		    FT_UINT32, BASE_DEC,
		    VALS(v2gdin_evse_supported_energy_transfer_names),
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

		/* struct dinListOfRootCertificateIDsType */
		{ &hf_v2gdin_struct_dinListOfRootCertificateIDsType_RootCertificateID,
		  { "RootCertificateID",
		    "v2gdin.struct.listofrootcertificateids.rootcertificateid",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* struct dinAC_EVChargeParameterType */
		{ &hf_v2gdin_struct_dinAC_EVChargeParameterType_DepartureTime,
		  { "DepartureTime",
		    "v2gdin.struct.ac_evchargeparameter.departuretime",
		    FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},

		/* struct dinAC_EVSEStatusType */
		{ &hf_v2gdin_struct_dinAC_EVSEStatusType_PowerSwitchClosed,
		  { "PowerSwitchClosed",
		    "v2gdin.struct.ac_evsestatus.powerswitchclosed",
		    FT_INT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_struct_dinAC_EVSEStatusType_RCD,
		  { "RCD", "v2gdin.struct.ac_evsestatus.rcd",
		    FT_INT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_struct_dinAC_EVSEStatusType_NotificationMaxDelay,
		  { "NotificationMaxDelay",
		    "v2gdin.struct.ac_evsestatus.notificationmaxdelay",
		    FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_struct_dinAC_EVSEStatusType_EVSENotification,
		  { "EVSENotification",
		    "v2gdinstruct.ac_evsestatus.evsenotification",
		    FT_UINT32, BASE_DEC, VALS(v2gdin_evsenotification_names),
		    0x0, NULL, HFILL }
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

		/* struct dinDC_EVChargeParameterType */
		{ &hf_v2gdin_struct_dinDC_EVChargeParameterType_FullSOC,
		  { "FullSOC", "v2gdin.struct.dc_evchargeparameter.fullsoc",
		    FT_INT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_struct_dinDC_EVChargeParameterType_BulkSOC,
		  { "BulkSOC", "v2gdin.struct.dc_evchargeparameter.bulksoc",
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

		/* struct dinSAScheduleTupleType */
		{ &hf_v2gdin_struct_dinSAScheduleTupleType_SAScheduleTupleID,
		  { "SAScheduleTupleID",
		    "v2gdin.struct.sascheduletuple.sascheduletupleid",
		    FT_INT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},

		/* struct dinPMaxScheduleType */
		{ &hf_v2gdin_struct_dinPMaxScheduleType_PMaxScheduleID,
		  { "PMaxScheduleID",
		    "v2gdin.struct.pmaxschedule.pmaxscheduleid",
		    FT_INT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},

		/* struct dinPMaxScheduleEntryType */
		{ &hf_v2gdin_struct_dinPMaxScheduleEntryType_PMax,
		  { "PMax", "v2gdin.struct.pmaxscheduleentry.pmax",
		    FT_INT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},

		/* struct dinRelativeTimeIntervalType */
		{ &hf_v2gdin_struct_dinRelativeTimeIntervalType_start,
		  { "start", "v2gdin.struct.relativetimeinterval.start",
		    FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_struct_dinRelativeTimeIntervalType_duration,
		  { "duration", "v2gdin.struct.relativetimeinterval.duration",
		    FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},

		/* struct dinSalesTariffType */
		{ &hf_v2gdin_struct_dinSalesTariffType_Id,
		  { "Id", "v2gdin.struct.salestariff.id",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_struct_dinSalesTariffType_SalesTariffDescription,
		  { "SalesTariffDescription",
		    "v2gdin.struct.salestariff.salestariffdescription",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_struct_dinSalesTariffType_NumEPriceLevels,
		  { "NumEPriceLevels",
		    "v2gdin.struct.salestariff.numepricelevels",
		    FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},

		/* struct hf_v2gdin_struct_dinSalesTariffEntryType */
		{ &hf_v2gdin_struct_dinSalesTariffEntryType_EPriceLevel,
		  { "EPriceLevel", "v2gdin.struct.salestariffentry.epricelevel",
		    FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},

		/* struct dinConsumptionCostType */
		{ &hf_v2gdin_struct_dinConsumptionCostType_startValue,
		  { "startValue", "v2gdin.struct.consumptioncost.startvalue",
		    FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},

		/* struct dinCostType */
		{ &hf_v2gdin_struct_dinCostType_costKind,
		  { "costKind", "v2gdin.struct.cost.costkind",
		    FT_UINT32, BASE_DEC, VALS(v2gdin_cost_kind_names),
		    0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_struct_dinCostType_amount,
		  { "amount", "v2gdin.struct.cost.amount",
		    FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_struct_dinCostType_amountMultiplier,
		  { "amountMultiplier", "v2gdin.struct.cost.amountmultiplier",
		    FT_INT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},

		/* struct dinChargingProfileType */
		{ &hf_v2gdin_struct_dinChargingProfileType_SAScheduleTupleID,
		  { "SAScheduleTupleID",
		    "v2gdin.struct.chargingprofile.sascheduletupleid",
		    FT_INT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_struct_dinProfileEntryType_ChargingProfileEntryStart,
		  { "ChargingProfileEntryStart",
		    "v2gdin.struct.profileentry.chargingprofileentrystart",
		    FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_struct_dinProfileEntryType_ChargingProfileEntryMaxPower,
		  { "ChargingProfileEntryMaxPower",
		    "v2gdin.struct.profileentry.chargingprofileentrymaxpower",
		    FT_INT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},

		/* struct dinDC_EVPowerDeliveryParameterType */
		{ &hf_v2gdin_struct_dinDC_EVPowerDeliveryParameterType_BulkChargingComplete,
		  { "BulkChargingComplete",
		    "v2gdin.struct.dc_evpowerdeliveryparameter.bulkchargingcomplete",
		    FT_INT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_struct_dinDC_EVPowerDeliveryParameterType_ChargingComplete,
		  { "ChargingComplete",
		    "v2gdin.struct.dc_evpowerdeliveryparameter.chargingcomplete",
		    FT_INT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},

		/* struct dinMeterInfoType */
		{ &hf_v2gdin_struct_dinMeterInfoType_MeterID,
		  { "MeterID", "v2gdin.struct.meterinfo.meterid",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_struct_dinMeterInfoType_SigMeterReading,
		  { "SigMeterReading",
		    "v2gdin.struct.meterinfo.sigmeterreading",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_struct_dinMeterInfoType_MeterStatus,
		  { "MeterStatus", "v2gdin.struct.meterinfo.meterstatus",
		    FT_INT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_struct_dinMeterInfoType_TMeter,
		  { "TMeter", "v2gdin.struct.meterinfo.tmeter",
		    FT_INT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
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

		/* ChargeParameterDiscoveryReq */
		{ &hf_v2gdin_body_ChargeParameterDiscoveryReq_EVRequestedEnergyTransferType,
		  { "EVRequestedEnergyTransferType",
		    "v2gdin.body.chargeparameterdiscoveryreq.evrequestenergytransfer",
		    FT_UINT32, BASE_DEC,
		    VALS(v2gdin_ev_requested_energy_transfer),
		    0x0, NULL, HFILL }
		},
		/* ChargeParameterDiscoveryRes */
		{ &hf_v2gdin_body_ChargeParameterDiscoveryRes_ResponseCode,
		  { "ResponseCode",
		    "v2gdin.body.chargeparametersdiscoveryres.responsecode",
		    FT_UINT32, BASE_DEC, VALS(v2gdin_response_code_names),
		    0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_body_ChargeParameterDiscoveryRes_EVSEProcessing,
		  { "EVSEProcessing",
		    "v2gdin.body.chargeparametersdiscoveryres.evseprocessing",
		    FT_UINT32, BASE_DEC, VALS(v2gdin_evse_processing_names),
		    0x0, NULL, HFILL }
		},

		/* PowerDeliveryReq */
		{ &hf_v2gdin_body_PowerDeliveryReq_ReadyToChargeState,
		  { "_ReadyToChargeState",
		    "v2gdin.body.powerdeliveryreq.readytochargestate",
		    FT_INT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		/* PowerDeliveryRes */
		{ &hf_v2gdin_body_PowerDeliveryRes_ResponseCode,
		  { "ResponseCode",
		    "v2gdin.body.powerdeliveryres.responsecode",
		    FT_UINT32, BASE_DEC, VALS(v2gdin_response_code_names),
		    0x0, NULL, HFILL }
		},

		/* ChargingStatusRes */
		{ &hf_v2gdin_body_ChargingStatusRes_ResponseCode,
		  { "ResponseCode",
		    "v2gdin.body.chargingstatusres.responsecode",
		    FT_UINT32, BASE_DEC, VALS(v2gdin_response_code_names),
		    0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_body_ChargingStatusRes_EVSEID,
		  { "EVSEID", "v2gdin.body.chargingstatusres.evseid",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_body_ChargingStatusRes_SAScheduleTupleID,
		  { "SAScheduleTupleID",
		    "v2gdin.body.chargingstatusres.sascheduletupleid",
		    FT_INT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_body_ChargingStatusRes_ReceiptRequired,
		  { "ReceiptRequired",
		    "v2gdin.body.chargingstatusres.receiptrequired",
		    FT_INT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},

		/* MeteringReceiptReq */
		{ &hf_v2gdin_body_MeteringReceiptReq_Id,
		  { "Id", "v2gdin.body.meteringreceiptreq.id",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_body_MeteringReceiptReq_SessionID,
		  { "SessionID", "v2gdin.body.meteringreceiptreq.sessionid",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_body_MeteringReceiptReq_SAScheduleTupleID,
		  { "SAScheduleTupleID",
		    "v2gdin.body.meteringreceiptreq.sascheduletupleid",
		    FT_INT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		/* MeteringReceiptRes */
		{ &hf_v2gdin_body_MeteringReceiptRes_ResponseCode,
		  { "ResponseCode",
		    "v2gdin.body.meteringreceiptres.responsecode",
		    FT_UINT32, BASE_DEC, VALS(v2gdin_response_code_names),
		    0x0, NULL, HFILL }
		},

		/* SessionStopRes */
		{ &hf_v2gdin_body_SessionStopRes_ResponseCode,
		  { "ResponseCode",
		    "v2gdin.body.sessionstopres.responsecode",
		    FT_UINT32, BASE_DEC, VALS(v2gdin_response_code_names),
		    0x0, NULL, HFILL }
		},

		/* CertificateUpdateReq */
		{ &hf_v2gdin_body_CertificateUpdateReq_Id,
		  { "Id", "v2gdin.body.certificateupdatereq.id",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_body_CertificateUpdateReq_ContractID,
		  { "ContractID",
		    "v2gdin.body.certificateupdatereq.contractid",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_body_CertificateUpdateReq_DHParams,
		  { "DHParams", "v2gdin.body.certificateupdatereq.dhparams",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		/* CertificateUpdateRes */
		{ &hf_v2gdin_body_CertificateUpdateRes_Id,
		  { "Id", "v2gdin.body.certificateupdateres.id",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_body_CertificateUpdateRes_ResponseCode,
		  { "ResponseCode",
		    "v2gdin.body.certificateupdateres.responsecode",
		    FT_UINT32, BASE_DEC, VALS(v2gdin_response_code_names),
		    0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_body_CertificateUpdateRes_ContractSignatureEncryptedPrivateKey,
		  { "ContractSignatureEncryptedPrivateKey",
		    "v2gdin.body.certificateupdateres.contractsignatureencryptedprivatekey",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_body_CertificateUpdateRes_DHParams,
		  { "DHParams",
		    "v2gdin.body.certificateupdateres.dhparams",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_body_CertificateUpdateRes_ContractID,
		  { "ContractID", "v2gdin.body.certificateupdateres.contractid",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_body_CertificateUpdateRes_RetryCounter,
		  { "RetryCounter",
		    "v2gdin.body.certificateupdateres.retrycounts",
		    FT_INT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},

		/* CertificateInstallationReq */
		{ &hf_v2gdin_body_CertificateInstallationReq_Id,
		  { "Id", "v2gdin.body.certificateinstallationreq.id",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_body_CertificateInstallationReq_OEMProvisioningCert,
		  { "OEMProvisioningCert",
		    "v2gdin.body.certificateinstallationreq.oemprovisioningcert",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_body_CertificateInstallationReq_DHParams,
		  { "DHParams", "v2gdin.body.certificateinstallationreq.dhparams",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		/* CertificateInstallationRes */
		{ &hf_v2gdin_body_CertificateInstallationRes_Id,
		  { "Id", "v2gdin.body.certificateinstallationres.id",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_body_CertificateInstallationRes_ResponseCode,
		  { "ResponseCode",
		    "v2gdin.body.certificateinstallationres.responsecode",
		    FT_UINT32, BASE_DEC, VALS(v2gdin_response_code_names),
		    0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_body_CertificateInstallationRes_ContractSignatureEncryptedPrivateKey,
		  { "ContractSignatureEncryptedPrivateKey",
		    "v2gdin.body.certificateinstallationres.contractsignatureencryptedprivatekey",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_body_CertificateInstallationRes_DHParams,
		  { "DHParams",
		    "v2gdin.body.certificateinstallationres.dhparams",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_body_CertificateInstallationRes_ContractID,
		  { "ContractID",
		    "v2gdin.body.certificateinstallationres.contractid",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* CableCheckRes */
		{ &hf_v2gdin_body_CableCheckRes_ResponseCode,
		  { "ResponseCode",
		    "v2gdin.body.cablecheckres.responsecode",
		    FT_UINT32, BASE_DEC, VALS(v2gdin_response_code_names),
		    0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_body_CableCheckRes_EVSEProcessing,
		  { "EVSEProcessing",
		    "v2gdin.body.cablecheckres.evseprocessing",
		    FT_UINT32, BASE_DEC, VALS(v2gdin_evse_processing_names),
		    0x0, NULL, HFILL }
		},

		/* PreChargeRes */
		{ &hf_v2gdin_body_PreChargeRes_ResponseCode,
		  { "ResponseCode",
		    "v2gdin.body.prechargeres.responsecode",
		    FT_UINT32, BASE_DEC, VALS(v2gdin_response_code_names),
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

		/* WeldingDetectionRes */
		{ &hf_v2gdin_body_WeldingDetectionRes_ResponseCode,
		  { "ResponseCode",
		    "v2gdin.body.weldingdetectionres.responsecode",
		    FT_UINT32, BASE_DEC, VALS(v2gdin_response_code_names),
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
		&ett_v2gdin_struct_dinEVChargeParameterType,
		&ett_v2gdin_struct_dinAC_EVChargeParameterType,
		&ett_v2gdin_struct_dinDC_EVChargeParameterType,
		&ett_v2gdin_struct_dinDC_EVStatusType,
		&ett_v2gdin_struct_dinEVSEChargeParameterType,
		&ett_v2gdin_struct_dinEVSEStatusType,
		&ett_v2gdin_struct_dinAC_EVSEChargeParameterType,
		&ett_v2gdin_struct_dinAC_EVSEStatusType,
		&ett_v2gdin_struct_dinDC_EVSEChargeParameterType,
		&ett_v2gdin_struct_dinDC_EVSEStatusType,
		&ett_v2gdin_struct_dinSASchedulesType,
		&ett_v2gdin_struct_dinSAScheduleListType,
		&ett_v2gdin_struct_dinSAScheduleTupleType,
		&ett_v2gdin_struct_dinPMaxScheduleType,
		&ett_v2gdin_struct_dinPMaxScheduleEntryType,
		&ett_v2gdin_struct_dinRelativeTimeIntervalType,
		&ett_v2gdin_struct_dinIntervalType,
		&ett_v2gdin_struct_dinSalesTariffType,
		&ett_v2gdin_struct_dinSalesTariffEntryType,
		&ett_v2gdin_struct_dinConsumptionCostType,
		&ett_v2gdin_struct_dinCostType,
		&ett_v2gdin_struct_dinChargingProfileType,
		&ett_v2gdin_struct_dinEVPowerDeliveryParameterType,
		&ett_v2gdin_struct_dinDC_EVPowerDeliveryParameterType,
		&ett_v2gdin_struct_dinProfileEntryType,

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
		&ett_v2gdin_body_ChargeParameterDiscoveryReq,
		&ett_v2gdin_body_ChargeParameterDiscoveryRes,
		&ett_v2gdin_body_PowerDeliveryReq,
		&ett_v2gdin_body_PowerDeliveryRes,
		&ett_v2gdin_body_ChargingStatusReq,
		&ett_v2gdin_body_ChargingStatusRes,
		&ett_v2gdin_body_MeteringReceiptReq,
		&ett_v2gdin_body_MeteringReceiptRes,
		&ett_v2gdin_body_SessionStopReq,
		&ett_v2gdin_body_SessionStopRes,
		&ett_v2gdin_body_CertificateUpdateReq,
		&ett_v2gdin_body_CertificateUpdateRes,
		&ett_v2gdin_body_CertificateInstallationReq,
		&ett_v2gdin_body_CertificateInstallationRes,
		&ett_v2gdin_body_CableCheckReq,
		&ett_v2gdin_body_CableCheckRes,
		&ett_v2gdin_body_PreChargeReq,
		&ett_v2gdin_body_PreChargeRes,
		&ett_v2gdin_body_CurrentDemandReq,
		&ett_v2gdin_body_CurrentDemandRes,
		&ett_v2gdin_body_WeldingDetectionReq,
		&ett_v2gdin_body_WeldingDetectionRes
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
