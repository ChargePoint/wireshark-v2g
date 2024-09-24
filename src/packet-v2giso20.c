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
#include <cbv2g/iso_20/iso20_CommonMessages_Datatypes.h>
#include <cbv2g/iso_20/iso20_CommonMessages_Decoder.h>

#include "v2gexi.h"


/* forward declare */
void proto_register_v2giso20(void);
void proto_reg_handoff_v2giso20(void);


static dissector_handle_t v2gexi_handle;
static dissector_handle_t v2gber_handle;

static int proto_v2giso20 = -1;

static int hf_struct_iso20_MessageHeaderType_SessionID = -1;
static int hf_struct_iso20_MessageHeaderType_TimeStamp = -1;
static int hf_struct_iso20_SignatureType_Id = -1;
static int hf_struct_iso20_SignedInfoType_Id = -1;
static int hf_struct_iso20_CanonicalizationMethodType_Algorithm = -1;
static int hf_struct_iso20_CanonicalizationMethodType_ANY = -1;
static int hf_struct_iso20_SignatureMethodType_Algorithm = -1;
static int hf_struct_iso20_SignatureMethodType_HMACOutputLength = -1;
static int hf_struct_iso20_SignatureMethodType_ANY = -1;
static int hf_struct_iso20_ReferenceType_Id = -1;
static int hf_struct_iso20_ReferenceType_Type = -1;
static int hf_struct_iso20_ReferenceType_URI = -1;
static int hf_struct_iso20_ReferenceType_DigestValue = -1;
static int hf_struct_iso20_TransformType_Algorithm = -1;
static int hf_struct_iso20_TransformType_ANY = -1;
static int hf_struct_iso20_TransformType_XPath = -1;
static int hf_struct_iso20_DigestMethodType_Algorithm = -1;
static int hf_struct_iso20_DigestMethodType_ANY = -1;
static int hf_struct_iso20_SignatureValueType_Id = -1;
static int hf_struct_iso20_SignatureValueType_CONTENT = -1;
static int hf_struct_iso20_KeyInfoType_Id = -1;
static int hf_struct_iso20_KeyInfoType_KeyName = -1;
static int hf_struct_iso20_KeyInfoType_MgmtData = -1;
static int hf_struct_iso20_KeyInfoType_ANY = -1;
static int hf_struct_iso20_KeyValueType_ANY = -1;
static int hf_struct_iso20_DSAKeyValueType_P = -1;
static int hf_struct_iso20_DSAKeyValueType_Q = -1;
static int hf_struct_iso20_DSAKeyValueType_G = -1;
static int hf_struct_iso20_DSAKeyValueType_Y = -1;
static int hf_struct_iso20_DSAKeyValueType_J = -1;
static int hf_struct_iso20_DSAKeyValueType_Seed = -1;
static int hf_struct_iso20_DSAKeyValueType_PgenCounter = -1;
static int hf_struct_iso20_RSAKeyValueType_Exponent = -1;
static int hf_struct_iso20_RSAKeyValueType_Modulus = -1;
static int hf_struct_iso20_RetrievalMethodType_Type = -1;
static int hf_struct_iso20_RetrievalMethodType_URI = -1;
static int hf_struct_iso20_X509DataType_X509SKI = -1;
static int hf_struct_iso20_X509DataType_X509SubjectName = -1;
static int hf_struct_iso20_X509DataType_X509Certificate = -1;
static int hf_struct_iso20_X509DataType_X509CRL = -1;
static int hf_struct_iso20_X509DataType_ANY = -1;
static int hf_struct_iso20_X509IssuerSerialType_X509IssuerName = -1;
static int hf_struct_iso20_X509IssuerSerialType_X509SerialNumber = -1;
static int hf_struct_iso20_PGPDataType_PGPKeyID = -1;
static int hf_struct_iso20_PGPDataType_PGPKeyPacket = -1;
static int hf_struct_iso20_PGPDataType_ANY = -1;
static int hf_struct_iso20_SPKIDataType_SPKISexp = -1;
static int hf_struct_iso20_SPKIDataType_ANY = -1;
static int hf_struct_iso20_ObjectType_Id = -1;
static int hf_struct_iso20_ObjectType_MimeType = -1;
static int hf_struct_iso20_ObjectType_Encoding = -1;
static int hf_struct_iso20_ObjectType_ANY = -1;

/* SessionSetup */
static int hf_struct_iso20_SessionSetupReqType_EVCCID = -1;
static int hf_struct_iso20_SessionSetupResType_ResponseCode = -1;
static int hf_struct_iso20_SessionSetupResType_EVSEID = -1;

/* AuthorizationSetup */
static int hf_struct_iso20_AuthorizationSetupResType_ResponseCode = -1;
static int hf_struct_iso20_AuthorizationSetupResType_Authorization = -1;
static int hf_struct_iso20_AuthorizationSetupResType_CertificateInstallationService = -1;

static int hf_struct_iso20_PnC_ASResAuthorizationModeType_GenChallenge = -1;
static int hf_struct_iso20_SupportedProvidersListType_ProviderID = -1;

/* Authorization */
static int hf_struct_iso20_AuthorizationReqType_SelectedAuthorizationService = -1;
static int hf_struct_iso20_AuthorizationResType_ResponseCode = -1;
static int hf_struct_iso20_AuthorizationResType_EVSEProcessing = -1;

static int hf_struct_iso20_PnC_AReqAuthorizationModeType_Id = -1;
static int hf_struct_iso20_PnC_AReqAuthorizationModeType_GenChallenge = -1;

static int hf_struct_iso20_ContractCertificateChainType_Certificate = -1;

static int hf_struct_iso20_SubCertificatesType_Certificate = -1;

/* ServiceDiscovery */
static int hf_struct_iso20_ServiceDiscoveryResType_ResponseCode = -1;
static int hf_struct_iso20_ServiceDiscoveryResType_ServiceRenegotiationSupported = -1;

static int hf_struct_iso20_ServiceIDListType_ServiceID = -1;

static int hf_struct_iso20_ServiceType_ServiceID = -1;
static int hf_struct_iso20_ServiceType_FreeService = -1;

/* ServiceDetail */
static int hf_struct_iso20_ServiceDetailReqType_ServiceID = -1;
static int hf_struct_iso20_ServiceDetailResType_ResponseCode = -1;
static int hf_struct_iso20_ServiceDetailResType_ServiceID = -1;

static int hf_struct_iso20_ParameterSetType_ParameterSetID = -1;

static int hf_struct_iso20_ParameterType_Name = -1;
static int hf_struct_iso20_ParameterType_boolValue = -1;
static int hf_struct_iso20_ParameterType_byteValue = -1;
static int hf_struct_iso20_ParameterType_shortValue = -1;
static int hf_struct_iso20_ParameterType_intValue = -1;
static int hf_struct_iso20_ParameterType_finiteString = -1;

static int hf_struct_iso20_RationalNumberType_Exponent = -1;
static int hf_struct_iso20_RationalNumberType_Value = -1;

/* ServiceSelection */
static int hf_struct_iso20_ServiceSelectionResType_ResponseCode = -1;

/* ScheduleExchange */
static int hf_struct_iso20_ScheduleExchangeReqType_MaximumSupportingPoints = -1;
static int hf_struct_iso20_ScheduleExchangeResType_ResponseCode = -1;
static int hf_struct_iso20_ScheduleExchangeResType_EVSEProcessing = -1;
static int hf_struct_iso20_ScheduleExchangeResType_GoToPause = -1;

/* PowerDelivery */
static int hf_struct_iso20_PowerDeliveryReqType_EVProcessing = -1;
static int hf_struct_iso20_PowerDeliveryReqType_ChargeProgress = -1;
static int hf_struct_iso20_PowerDeliveryReqType_BPT_ChannelSelection = -1;
static int hf_struct_iso20_PowerDeliveryResType_ResponseCode = -1;
static int hf_struct_iso20_PowerDeliveryResType_EVSEProcessing = -1;

/* TBD */
static int hf_struct_iso20_EVSEStatusType_NotificationMaxDelay = -1;
static int hf_struct_iso20_EVSEStatusType_EVSENotification = -1;

static int hf_struct_iso20_DetailedTaxType_TaxRuleID = -1;

static int hf_struct_iso20_ReceiptType_TimeAnchor = -1;

static int hf_struct_iso20_MeterInfoType_MeterID = -1;
static int hf_struct_iso20_MeterInfoType_ChargedEnergyReadingWh = -1;
static int hf_struct_iso20_MeterInfoType_BPT_DischargedEnergyReadingWh = -1;
static int hf_struct_iso20_MeterInfoType_CapacitiveEnergyReadingVARh = -1;
static int hf_struct_iso20_MeterInfoType_BPT_InductiveEnergyReadingVARh = -1;
static int hf_struct_iso20_MeterInfoType_MeterSignature = -1;
static int hf_struct_iso20_MeterInfoType_MeterStatus = -1;
static int hf_struct_iso20_MeterInfoType_MeterTimestamp = -1;

static int hf_struct_iso20_SignedMeteringDataType_Id = -1;
static int hf_struct_iso20_SignedMeteringDataType_SessionID = -1;

static int hf_struct_iso20_MeasurementDataListType_MeasurementData = -1;

static int hf_struct_iso20_CertificateChainType_Id = -1;
static int hf_struct_iso20_CertificateChainType_Certificate = -1;

static int hf_struct_iso20_SignedCertificateChainType_Id = -1;
static int hf_struct_iso20_SignedCertificateChainType_Certificate = -1;

static int hf_struct_iso20_EMAIDListType_EMAID = -1;

static int hf_struct_iso20_RelativeTimeIntervalType_start = -1;
static int hf_struct_iso20_RelativeTimeIntervalType_duration = -1;

static int hf_struct_iso20_SAScheduleTupleType_SAScheduleTupleID = -1;

static int hf_struct_iso20_SelectedServiceType_ServiceID = -1;
static int hf_struct_iso20_SelectedServiceType_ParameterSetID = -1;

static int hf_struct_iso20_VehicleCheckOutReqType_EVCheckOutStatus = -1;
static int hf_struct_iso20_VehicleCheckOutReqType_CheckOutTime = -1;
static int hf_struct_iso20_VehicleCheckOutResType_ResponseCode = -1;
static int hf_struct_iso20_VehicleCheckOutResType_EVSECheckOutStatus = -1;

static int hf_struct_iso20_VehicleCheckInReqType_EVCheckInStatus = -1;
static int hf_struct_iso20_VehicleCheckInReqType_ParkingMethod = -1;
static int hf_struct_iso20_VehicleCheckInReqType_VehicleFrame = -1;
static int hf_struct_iso20_VehicleCheckInReqType_DeviceOffset = -1;
static int hf_struct_iso20_VehicleCheckInReqType_VehicleTravel = -1;
static int hf_struct_iso20_VehicleCheckInResType_ResponseCode = -1;
static int hf_struct_iso20_VehicleCheckInResType_ParkingSpace = -1;
static int hf_struct_iso20_VehicleCheckInResType_DeviceLocation = -1;
static int hf_struct_iso20_VehicleCheckInResType_TargetDistance = -1;

static int hf_struct_iso20_PowerScheduleEntryType_Duration = -1;

static int hf_struct_iso20_EVPowerScheduleEntryType_Duration = -1;

static int hf_struct_iso20_EVPowerProfileType_TimeAnchor = -1;

static int hf_struct_iso20_PowerDemandResType_ResponseCode = -1;
static int hf_struct_iso20_PowerDemandResType_EVSEID = -1;
static int hf_struct_iso20_PowerDemandResType_SAScheduleTupleID = -1;
static int hf_struct_iso20_PowerDemandResType_ReceiptRequired = -1;

static int hf_struct_iso20_CurrentDemandResType_ResponseCode = -1;
static int hf_struct_iso20_CurrentDemandResType_EVSEPowerLimitAchieved = -1;
static int hf_struct_iso20_CurrentDemandResType_EVSECurrentLimitAchieved = -1;
static int hf_struct_iso20_CurrentDemandResType_EVSEID = -1;
static int hf_struct_iso20_CurrentDemandResType_SAScheduleTupleID = -1;
static int hf_struct_iso20_CurrentDemandResType_ReceiptRequired = -1;

static int hf_struct_iso20_CertificateInstallationReqType_MaximumContractCertificateChains = -1;
static int hf_struct_iso20_CertificateInstallationResType_ResponseCode = -1;
static int hf_struct_iso20_CertificateInstallationResType_EVSEProcessing = -1;
static int hf_struct_iso20_CertificateInstallationResType_RemainingContractCertificateChains = -1;

static int hf_struct_iso20_SessionStopReqType_ChargingSession = -1;
static int hf_struct_iso20_SessionStopReqType_EVTerminationCode = -1;
static int hf_struct_iso20_SessionStopReqType_EVTerminationExplanation = -1;
static int hf_struct_iso20_SessionStopResType_ResponseCode = -1;

static int hf_struct_iso20_MeteringReceiptReqType_Id = -1;
static int hf_struct_iso20_MeteringReceiptReqType_SessionID = -1;
static int hf_struct_iso20_MeteringReceiptReqType_SAScheduleTupleID = -1;
static int hf_struct_iso20_MeteringReceiptResType_ResponseCode = -1;

static int hf_struct_iso20_ChargeParameterDiscoveryReqType_MaxSupportingPoints = -1;
static int hf_struct_iso20_ChargeParameterDiscoveryResType_ResponseCode = -1;
static int hf_struct_iso20_ChargeParameterDiscoveryResType_EVSEProcessing = -1;


/* Initialize the subtree pointers */
static gint ett_v2giso20 = -1;
static gint ett_v2giso20_document = -1;
static gint ett_v2giso20_array = -1;
static gint ett_v2giso20_array_i = -1;
static gint ett_v2giso20_asn1 = -1;

static gint ett_struct_iso20_SessionSetupReqType = -1;
static gint ett_struct_iso20_SessionSetupResType = -1;
static gint ett_struct_iso20_AuthorizationSetupReqType = -1;
static gint ett_struct_iso20_AuthorizationSetupResType = -1;
static gint ett_struct_iso20_AuthorizationReqType = -1;
static gint ett_struct_iso20_AuthorizationResType = -1;
static gint ett_struct_iso20_ServiceDiscoveryReqType = -1;
static gint ett_struct_iso20_ServiceDiscoveryResType = -1;
static gint ett_struct_iso20_ServiceDetailReqType = -1;
static gint ett_struct_iso20_ServiceDetailResType = -1;
static gint ett_struct_iso20_ServiceSelectionReqType = -1;
static gint ett_struct_iso20_ServiceSelectionResType = -1;
static gint ett_struct_iso20_ScheduleExchangeReqType = -1;
static gint ett_struct_iso20_ScheduleExchangeResType = -1;
static gint ett_struct_iso20_PowerDeliveryReqType = -1;
static gint ett_struct_iso20_PowerDeliveryResType = -1;
static gint ett_struct_iso20_MeteringConfirmationReqType = -1;
static gint ett_struct_iso20_MeteringConfirmationResType = -1;
static gint ett_struct_iso20_SessionStopReqType = -1;
static gint ett_struct_iso20_SessionStopResType = -1;
static gint ett_struct_iso20_CertificateInstallationReqType = -1;
static gint ett_struct_iso20_CertificateInstallationResType = -1;
static gint ett_struct_iso20_VehicleCheckInReqType = -1;
static gint ett_struct_iso20_VehicleCheckInResType = -1;
static gint ett_struct_iso20_VehicleCheckOutReqType = -1;
static gint ett_struct_iso20_VehicleCheckOutResType = -1;

static gint ett_struct_iso20_SignedInstallationDataType = -1;
static gint ett_struct_iso20_SignedMeteringDataType = -1;
static gint ett_struct_iso20_CLReqControlModeType = -1;
static gint ett_struct_iso20_CLResControlModeType = -1;
static gint ett_struct_iso20_SignatureType = -1;
static gint ett_struct_iso20_SignatureValueType = -1;
static gint ett_struct_iso20_SignedInfoType = -1;
static gint ett_struct_iso20_CanonicalizationMethodType = -1;
static gint ett_struct_iso20_SignatureMethodType = -1;
static gint ett_struct_iso20_ReferenceType = -1;
static gint ett_struct_iso20_TransformsType = -1;
static gint ett_struct_iso20_TransformType = -1;
static gint ett_struct_iso20_DigestMethodType = -1;
static gint ett_struct_iso20_KeyInfoType = -1;
static gint ett_struct_iso20_KeyValueType = -1;
static gint ett_struct_iso20_RetrievalMethodType = -1;
static gint ett_struct_iso20_X509DataType = -1;
static gint ett_struct_iso20_PGPDataType = -1;
static gint ett_struct_iso20_SPKIDataType = -1;
static gint ett_struct_iso20_ObjectType = -1;
static gint ett_struct_iso20_ManifestType = -1;
static gint ett_struct_iso20_SignaturePropertiesType = -1;
static gint ett_struct_iso20_SignaturePropertyType = -1;
static gint ett_struct_iso20_DSAKeyValueType = -1;
static gint ett_struct_iso20_RSAKeyValueType = -1;

static gint ett_struct_iso20_MessageHeaderType = -1;
static gint ett_struct_iso20_X509IssuerSerialType = -1;

static gint ett_struct_iso20_EIM_AReqAuthorizationModeType = -1;
static gint ett_struct_iso20_PnC_AReqAuthorizationModeType = -1;
static gint ett_struct_iso20_EIM_ASResAuthorizationModeType = -1;
static gint ett_struct_iso20_PnC_ASResAuthorizationModeType = -1;
static gint ett_struct_iso20_EVPowerProfileType = -1;
static gint ett_struct_iso20_EVPowerProfileEntryListType = -1;
static gint ett_struct_iso20_PowerScheduleEntryListType = -1;
static gint ett_struct_iso20_EVSEStatusType = -1;
static gint ett_struct_iso20_RationalNumberType = -1;
static gint ett_struct_iso20_DetailedCostType = -1;
static gint ett_struct_iso20_DetailedTaxType = -1;
static gint ett_struct_iso20_ReceiptType = -1;
static gint ett_struct_iso20_MeterInfoType = -1;
static gint ett_struct_iso20_TargetPositionType = -1;
static gint ett_struct_iso20_ParameterType = -1;
static gint ett_struct_iso20_ParameterSetType = -1;
static gint ett_struct_iso20_MeasurementDataListType = -1;
static gint ett_struct_iso20_ListOfRootCertificateIDsType = -1;
static gint ett_struct_iso20_SubCertificatesType = -1;
static gint ett_struct_iso20_CertificateChainType = -1;
static gint ett_struct_iso20_ContractCertificateChainType = -1;
static gint ett_struct_iso20_SignedCertificateChainType = -1;
static gint ett_struct_iso20_EMAIDListType = -1;
static gint ett_struct_iso20_ChargingProfileType = -1;
static gint ett_struct_iso20_RelativeTimeIntervalType = -1;
static gint ett_struct_iso20_SAScheduleTupleType = -1;
static gint ett_struct_iso20_SAScheduleListType = -1;
static gint ett_struct_iso20_SelectedServiceType = -1;
static gint ett_struct_iso20_SelectedServiceListType = -1;
static gint ett_struct_iso20_ServiceParameterListType = -1;
static gint ett_struct_iso20_ServiceIDListType = -1;
static gint ett_struct_iso20_ServiceType = -1;
static gint ett_struct_iso20_ServiceListType = -1;
static gint ett_struct_iso20_SupportedProvidersListType = -1;
static gint ett_struct_iso20_Dynamic_SEReqControlModeType = -1;
static gint ett_struct_iso20_Scheduled_SEReqControlModeType = -1;
static gint ett_struct_iso20_Dynamic_SEResControlModeType = -1;
static gint ett_struct_iso20_Scheduled_SEResControlModeType = -1;
static gint ett_struct_iso20_Dynamic_EVPPTControlModeType = -1;
static gint ett_struct_iso20_Scheduled_EVPPTControlModeType = -1;
static gint ett_struct_iso20_Dynamic_SMDTControlModeType = -1;
static gint ett_struct_iso20_Scheduled_SMDTControlModeType = -1;


static const value_string v2giso20_enum_iso20_responseCodeType_names[] = {
	{ iso20_responseCodeType_OK, "OK" },
	{ iso20_responseCodeType_OK_CertificateExpiresSoon,
	  "OK (CertificateExpiresSoon)" },
	{ iso20_responseCodeType_OK_NewSessionEstablished,
	  "OK (NewSessionEstablished)" },
	{ iso20_responseCodeType_OK_OldSessionJoined, "OK (OldSessionJoined)" },
	{ iso20_responseCodeType_OK_PowerToleranceConfirmed,
	  "OK (PowerToleranceConfirmed)" },
	{ iso20_responseCodeType_WARNING_AuthorizationSelectionInvalid,
	  "WARNING (AuthorizationSelectionInvalid)" },
	{ iso20_responseCodeType_WARNING_CertificateExpired,
	  "WARNING (CertificateExpired)" },
	{ iso20_responseCodeType_WARNING_CertificateNotYetValid,
	  "WARNING (CertificateNotYetValid)" },
	{ iso20_responseCodeType_WARNING_CertificateRevoked,
	  "WARNING (CertificateRevoked)" },
	{ iso20_responseCodeType_WARNING_CertificateValidationError,
	  "WARNING (CertificateValidationError)" },
	{ iso20_responseCodeType_WARNING_ChallengeInvalid,
	  "WARNING (ChallengeInvalid)" },
	{ iso20_responseCodeType_WARNING_EIMAuthorizationFailure,
	  "WARNING (EIMAuthorizationFailure)" },
	{ iso20_responseCodeType_WARNING_eMSPUnknown,
	  "WARNING (eMSPUnknown)" },
	{ iso20_responseCodeType_WARNING_EVPowerProfileViolation,
	  "WARNING (EVPowerProfileViolation)" },
	{ iso20_responseCodeType_WARNING_GeneralPnCAuthorizationError,
	  "WARNING (GeneralPnCAuthorizationError)" },
	{ iso20_responseCodeType_WARNING_NoCertificateAvailable,
	  "WARNING (NoCertificateAvailable)" },
	{ iso20_responseCodeType_WARNING_NoContractMatchingPCIDFound,
	  "WARNING (NoContractMatchingPCIDFound)" },
	{ iso20_responseCodeType_WARNING_PowerToleranceNotConfirmed,
	  "WARNING (PowerToleranceNotConfirmed)" },
	{ iso20_responseCodeType_WARNING_ScheduleRenegotiationFailed,
	  "WARNING (ScheduleRenegotiationFailed)" },
	{ iso20_responseCodeType_WARNING_StandbyNotAllowed,
	  "WARNING (StandbyNotAllowed)" },
	{ iso20_responseCodeType_WARNING_WPT, "WARNING (WPT)" },
	{ iso20_responseCodeType_FAILED, "FAILED" },
	{ iso20_responseCodeType_FAILED_AssociationError,
	  "FAILED (AssociationError)" },
	{ iso20_responseCodeType_FAILED_ContactorError,
	  "FAILED (ContactorError)" },
	{ iso20_responseCodeType_FAILED_EVPowerProfileInvalid,
	  "FAILED (EVPowerProfileInvalid)" },
	{ iso20_responseCodeType_FAILED_EVPowerProfileViolation,
	  "FAILED (EVPowerProfileViolation)" },
	{ iso20_responseCodeType_FAILED_MeteringSignatureNotValid,
	  "FAILED (MeteringSignatureNotValid)" },
	{ iso20_responseCodeType_FAILED_NoEnergyTransferServiceSelected,
	  "FAILED (NoEnergyTransferServiceSelected)" },
	{ iso20_responseCodeType_FAILED_NoServiceRenegotiationSupported,
	  "FAILED (NoServiceRenegotiationSupported)" },
	{ iso20_responseCodeType_FAILED_PauseNotAllowed,
	  "FAILED (PauseNotAllowed)" },
	{ iso20_responseCodeType_FAILED_PowerDeliveryNotApplied,
	  "FAILED (PowerDeliveryNotApplied)" },
	{ iso20_responseCodeType_FAILED_PowerToleranceNotConfirmed,
	  "FAILED (PowerToleranceNotConfirmed)" },
	{ iso20_responseCodeType_FAILED_ScheduleRenegotiation,
	  "FAILED (ScheduleRenegotiation)" },
	{ iso20_responseCodeType_FAILED_ScheduleSelectionInvalid,
	  "FAILED (ScheduleSelectionInvalid)" },
	{ iso20_responseCodeType_FAILED_SequenceError,
	  "FAILED (SequenceError)" },
	{ iso20_responseCodeType_FAILED_ServiceIDInvalid,
	  "FAILED (ServiceIDInvalid)" },
	{ iso20_responseCodeType_FAILED_ServiceSelectionInvalid,
	  "FAILED (ServiceSelectionInvalid)" },
	{ iso20_responseCodeType_FAILED_SignatureError,
	  "FAILED (SignatureError)" },
	{ iso20_responseCodeType_FAILED_UnknownSession,
	  "FAILED (UnknownSession)" },
	{ iso20_responseCodeType_FAILED_WrongChargeParameter,
	  "FAILED (WrongChargeParameter)" },
	{ 0, NULL }
};

static const value_string v2giso20_enum_iso20_authorizationType_names[] = {
	{ iso20_authorizationType_EIM, "EIM" },
	{ iso20_authorizationType_PnC, "PnC" },
	{ 0, NULL }
};

static const value_string v2giso20_enum_iso20_processingType_names[] = {
	{ iso20_processingType_Finished, "Finished" },
	{ iso20_processingType_Ongoing, "Ongoing" },
	{ iso20_processingType_Ongoing_WaitingForCustomerInteraction,
	  "Ongoing (WaitingForCustomerInteraction)" },
	{ 0, NULL }
};

static const value_string v2giso20_enum_iso20_evseNotificationType_names[] = {
	{ iso20_evseNotificationType_Pause, "Pause" },
	{ iso20_evseNotificationType_ExitStandby, "ExitStandby" },
	{ iso20_evseNotificationType_Terminate, "Terminate" },
	{ iso20_evseNotificationType_ScheduleRenegotiation,
	  "ScheduleRenegotiation" },
	{ iso20_evseNotificationType_ServiceRenegotiation,
	  "ServiceRenegotiation" },
	{ iso20_evseNotificationType_MeteringConfirmation,
	  "MeteringConfirmation" },
	{ 0, NULL }
};

static const value_string v2giso20_enum_iso20_evCheckOutStatusType_names[] = {
	{ iso20_evCheckOutStatusType_CheckOut, "CheckOut" },
	{ iso20_evCheckOutStatusType_Processing, "Processing" },
	{ iso20_evCheckOutStatusType_Completed, "Completed" },
	{ 0, NULL }
};

static const value_string v2giso20_enum_iso20_evseCheckOutStatusType_names[] = {
	{ iso20_evseCheckOutStatusType_Scheduled, "Scheduled" },
	{ iso20_evseCheckOutStatusType_Completed, "Completed" },
	{ 0, NULL }
};

static const value_string v2giso20_enum_iso20_evCheckInStatusType_names[] = {
	{ iso20_evCheckInStatusType_CheckIn, "CheckIn" },
	{ iso20_evCheckInStatusType_Processing, "Processing" },
	{ iso20_evCheckInStatusType_Completed, "Completed" },
	{ 0, NULL }
};

static const value_string v2giso20_enum_iso20_parkingMethodType_names[] = {
	{ iso20_parkingMethodType_AutoParking, "AutoParking" },
	{ iso20_parkingMethodType_MVGuideManual, "MVGuideManual" },
	{ iso20_parkingMethodType_Manual, "Manual" },
	{ 0, NULL }
};

static const value_string v2giso20_enum_iso20_channelSelectionType_names[] = {
	{ iso20_channelSelectionType_Charge, "Charge" },
	{ iso20_channelSelectionType_Discharge, "Discharge" },
	{ 0, NULL }
};

static const value_string v2giso20_enum_iso20_chargingSessionType_names[] = {
	{ iso20_chargingSessionType_Pause, "Pause" },
	{ iso20_chargingSessionType_Terminate, "Terminate" },
	{ iso20_chargingSessionType_ServiceRenegotiation,
	  "ServiceRenegotiation" },
	{ 0, NULL }
};

static const value_string v2giso20_enum_iso20_chargeProgressType_names[] = {
	{ iso20_chargeProgressType_Start, "Start" },
	{ iso20_chargeProgressType_Stop, "Stop" },
	{ iso20_chargeProgressType_Standby, "Standby" },
	{ iso20_chargeProgressType_ScheduleRenegotiation,
	  "ScheduleRenegotiation" },
	{ 0, NULL }
};


/* header node dissectors - each node is represented by a struct */
static void dissect_iso20_SignatureType(
	const struct iso20_SignatureType *node,
	tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
	gint idx, const char *subtree_name);
static void dissect_iso20_SignatureValueType(
	const struct iso20_SignatureValueType *node,
	tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
	gint idx, const char *subtree_name);
static void dissect_iso20_SignedInfoType(
	const struct iso20_SignedInfoType *node,
	tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
	gint idx, const char *subtree_name);
static void dissect_iso20_CanonicalizationMethodType(
	const struct iso20_CanonicalizationMethodType *node,
	tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
	gint idx, const char *subtree_name);
static void dissect_iso20_SignatureMethodType(
	const struct iso20_SignatureMethodType *node,
	tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
	gint idx, const char *subtree_name);
static void dissect_iso20_ReferenceType(
	const struct iso20_ReferenceType *node,
	tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
	gint idx, const char *subtree_name);
static void dissect_iso20_TransformsType(
	const struct iso20_TransformsType *node,
	tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
	gint idx, const char *subtree_name);
static void dissect_iso20_TransformType(
	const struct iso20_TransformType *node,
	tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
	gint idx, const char *subtree_name);
static void dissect_iso20_DigestMethodType(
	const struct iso20_DigestMethodType *node,
	tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
	gint idx, const char *subtree_name);
static void dissect_iso20_KeyInfoType(
	const struct iso20_KeyInfoType *node,
	tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
	gint idx, const char *subtree_name);
static void dissect_iso20_KeyValueType(
	const struct iso20_KeyValueType *node,
	tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
	gint idx, const char *subtree_name);
static void dissect_iso20_RetrievalMethodType(
	const struct iso20_RetrievalMethodType *node,
	tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
	gint idx, const char *subtree_name);
static void dissect_iso20_X509DataType(
	const struct iso20_X509DataType *node,
	tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
	gint idx, const char *subtree_name);
static void dissect_iso20_PGPDataType(
	const struct iso20_PGPDataType *node,
	tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
	gint idx, const char *subtree_name);
static void dissect_iso20_SPKIDataType(
	const struct iso20_SPKIDataType *node,
	tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
	gint idx, const char *subtree_name);
static void dissect_iso20_ObjectType(
	const struct iso20_ObjectType *node,
	tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
	gint idx, const char *subtree_name);
static void dissect_iso20_DSAKeyValueType(
	const struct iso20_DSAKeyValueType *node,
	tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
	gint idx, const char *subtree_name);
static void dissect_iso20_RSAKeyValueType(
	const struct iso20_RSAKeyValueType *node,
	tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
	gint idx, const char *subtree_name);

static void dissect_iso20_MessageHeaderType(
	const struct iso20_MessageHeaderType *node,
	tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
	gint idx, const char *subtree_name);
static void dissect_iso20_X509IssuerSerialType(
	const struct iso20_X509IssuerSerialType *node,
	tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
	gint idx, const char *subtree_name);


static void
dissect_iso20_SignatureType(
	const struct iso20_SignatureType *node,
	tvbuff_t *tvb,
	packet_info *pinfo,
	proto_tree *tree,
	gint idx,
	const char *subtree_name)
{
	proto_tree *subtree;

	subtree = proto_tree_add_subtree(tree,
		tvb, 0, 0, idx, NULL, subtree_name);

	if (node->Id_isUsed) {
		exi_add_characters(subtree,
			hf_struct_iso20_SignatureType_Id,
			tvb,
			node->Id.characters,
			node->Id.charactersLen,
			sizeof(node->Id.characters));
	}

	dissect_iso20_SignedInfoType(&node->SignedInfo,
		tvb, pinfo, subtree,
		ett_struct_iso20_SignedInfoType, "SignedInfo");
	dissect_iso20_SignatureValueType(&node->SignatureValue,
		tvb, pinfo, subtree,
		ett_struct_iso20_SignatureValueType, "SignatureValue");

	if (node->KeyInfo_isUsed) {
		dissect_iso20_KeyInfoType(&node->KeyInfo,
			tvb, pinfo, subtree,
			ett_struct_iso20_KeyInfoType, "KeyInfo");
	}

	if (node->Object_isUsed) {
		dissect_iso20_ObjectType(&node->Object,
			tvb, pinfo, subtree,
			ett_struct_iso20_ObjectType, "Object");
	}

	return;
}

static void
dissect_iso20_SignatureValueType(
	const struct iso20_SignatureValueType *node,
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
			hf_struct_iso20_SignatureValueType_Id,
			tvb,
			node->Id.characters,
			node->Id.charactersLen,
			sizeof(node->Id.characters));
	}

	exi_add_bytes(subtree,
		hf_struct_iso20_SignatureValueType_CONTENT,
		tvb,
		node->CONTENT.bytes,
		node->CONTENT.bytesLen,
		sizeof(node->CONTENT.bytes));

	return;
}

static void
dissect_iso20_SignedInfoType(
	const struct iso20_SignedInfoType *node,
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
			hf_struct_iso20_SignedInfoType_Id,
			tvb,
			node->Id.characters,
			node->Id.charactersLen,
			sizeof(node->Id.characters));
	}

	dissect_iso20_CanonicalizationMethodType(
		&node->CanonicalizationMethod,
		tvb, pinfo, subtree,
		ett_struct_iso20_CanonicalizationMethodType,
		"CanonicalizationMethod");
	dissect_iso20_SignatureMethodType(
		&node->SignatureMethod,
		tvb, pinfo, subtree,
		ett_struct_iso20_SignatureMethodType,
		"SignatureMethod");

	reference_tree = proto_tree_add_subtree(subtree,
		tvb, 0, 0, ett_v2giso20_array, NULL, "Reference");
	for (i = 0; i < node->Reference.arrayLen; i++) {
		char index[sizeof("[65536]")];

		snprintf(index, sizeof(index), "[%u]", i);
		dissect_iso20_ReferenceType(&node->Reference.array[i],
			tvb, pinfo, reference_tree,
			ett_struct_iso20_ReferenceType, index);
	}

	return;
}

static void
dissect_iso20_CanonicalizationMethodType(
	const struct iso20_CanonicalizationMethodType *node,
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
		hf_struct_iso20_CanonicalizationMethodType_Algorithm,
		tvb,
		node->Algorithm.characters,
		node->Algorithm.charactersLen,
		sizeof(node->Algorithm.characters));

	if (node->ANY_isUsed) {
		exi_add_bytes(subtree,
			hf_struct_iso20_CanonicalizationMethodType_ANY,
			tvb,
			node->ANY.bytes,
			node->ANY.bytesLen,
			sizeof(node->ANY.bytes));
	}

	return;
}

static void
dissect_iso20_SignatureMethodType(
	const struct iso20_SignatureMethodType *node,
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
		hf_struct_iso20_SignatureMethodType_Algorithm,
		tvb,
		node->Algorithm.characters,
		node->Algorithm.charactersLen,
		sizeof(node->Algorithm.characters));

	if (node->HMACOutputLength_isUsed) {
		it = proto_tree_add_int(subtree,
			hf_struct_iso20_SignatureMethodType_HMACOutputLength,
			tvb, 0, 0, node->HMACOutputLength);
		proto_item_set_generated(it);
	}

	if (node->ANY_isUsed) {
		exi_add_bytes(subtree,
			hf_struct_iso20_SignatureMethodType_ANY,
			tvb,
			node->ANY.bytes,
			node->ANY.bytesLen,
			sizeof(node->ANY.bytes));
	}

	return;
}

static void
dissect_iso20_ReferenceType(
	const struct iso20_ReferenceType *node,
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
			hf_struct_iso20_ReferenceType_Id,
			tvb,
			node->Id.characters,
			node->Id.charactersLen,
			sizeof(node->Id.characters));
	}
	if (node->Type_isUsed) {
		exi_add_characters(subtree,
			hf_struct_iso20_ReferenceType_Type,
			tvb,
			node->Type.characters,
			node->Type.charactersLen,
			sizeof(node->Type.characters));
	}
	if (node->URI_isUsed) {
		exi_add_characters(subtree,
			hf_struct_iso20_ReferenceType_URI,
			tvb,
			node->URI.characters,
			node->URI.charactersLen,
			sizeof(node->URI.characters));
	}
	if (node->Transforms_isUsed) {
		dissect_iso20_TransformsType(&node->Transforms,
			tvb, pinfo, subtree,
			ett_struct_iso20_TransformsType,
			"Transforms");
	}

	dissect_iso20_DigestMethodType(&node->DigestMethod,
			tvb, pinfo, subtree,
			ett_struct_iso20_DigestMethodType,
			"DigestMethod");

	exi_add_bytes(subtree,
		hf_struct_iso20_ReferenceType_DigestValue,
		tvb,
		node->DigestValue.bytes,
		node->DigestValue.bytesLen,
		sizeof(node->DigestValue.bytes));

	return;
}

static void
dissect_iso20_TransformsType(
	const struct iso20_TransformsType *node,
	tvbuff_t *tvb,
	packet_info *pinfo _U_,
	proto_tree *tree,
	gint idx,
	const char *subtree_name)
{
	proto_tree *subtree;

	subtree = proto_tree_add_subtree(tree,
		tvb, 0, 0, idx, NULL, subtree_name);

	dissect_iso20_TransformType(&node->Transform,
		tvb, pinfo, subtree,
		ett_struct_iso20_TransformType, "Transform");

	return;
}

static void
dissect_iso20_TransformType(
	const struct iso20_TransformType *node,
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
		hf_struct_iso20_TransformType_Algorithm,
		tvb,
		node->Algorithm.characters,
		node->Algorithm.charactersLen,
		sizeof(node->Algorithm.characters));

	if (node->ANY_isUsed) {
		exi_add_bytes(subtree,
			hf_struct_iso20_TransformType_ANY,
			tvb,
			node->ANY.bytes,
			node->ANY.bytesLen,
			sizeof(node->ANY.bytes));
	}

	if (node->XPath_isUsed) {
		exi_add_characters(subtree,
			hf_struct_iso20_TransformType_XPath,
			tvb,
			node->XPath.characters,
			node->XPath.charactersLen,
			sizeof(node->XPath.characters));
	}

	return;
}

static void
dissect_iso20_DigestMethodType(
	const struct iso20_DigestMethodType *node,
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
		hf_struct_iso20_DigestMethodType_Algorithm,
		tvb,
		node->Algorithm.characters,
		node->Algorithm.charactersLen,
		sizeof(node->Algorithm.characters));

	if (node->ANY_isUsed) {
		exi_add_bytes(subtree,
			hf_struct_iso20_DigestMethodType_ANY,
			tvb,
			node->ANY.bytes,
			node->ANY.bytesLen,
			sizeof(node->ANY.bytes));
	}

	return;
}

static void
dissect_iso20_KeyInfoType(
	const struct iso20_KeyInfoType *node,
	tvbuff_t *tvb,
	packet_info *pinfo,
	proto_tree *tree,
	gint idx,
	const char *subtree_name)
{
	proto_tree *subtree;

	subtree = proto_tree_add_subtree(tree,
		tvb, 0, 0, idx, NULL, subtree_name);

	if (node->Id_isUsed) {
		exi_add_characters(subtree,
			hf_struct_iso20_KeyInfoType_Id,
			tvb,
			node->Id.characters,
			node->Id.charactersLen,
			sizeof(node->Id.characters));
	}

	if (node->KeyName_isUsed) {
		exi_add_characters(subtree,
			hf_struct_iso20_KeyInfoType_KeyName,
			tvb,
			node->KeyName.characters,
			node->KeyName.charactersLen,
			sizeof(node->KeyName.characters));
	}

	if (node->KeyValue_isUsed) {
		dissect_iso20_KeyValueType(&node->KeyValue,
			tvb, pinfo, subtree,
			ett_struct_iso20_KeyValueType,
			"KeyValue");
	}

	if (node->RetrievalMethod_isUsed) {
		dissect_iso20_RetrievalMethodType(
			&node->RetrievalMethod,
			tvb, pinfo, subtree,
			ett_struct_iso20_RetrievalMethodType,
			"RetrievalMethod");
	}

	if (node->X509Data_isUsed) {
		dissect_iso20_X509DataType(&node->X509Data,
			tvb, pinfo, subtree,
			ett_struct_iso20_X509DataType, "X509Data");
	}

	if (node->PGPData_isUsed) {
		dissect_iso20_PGPDataType(&node->PGPData,
			tvb, pinfo, subtree,
			ett_struct_iso20_PGPDataType, "PGPData");
	}

	if (node->SPKIData_isUsed) {
		dissect_iso20_SPKIDataType(&node->SPKIData,
			tvb, pinfo, subtree,
			ett_struct_iso20_SPKIDataType, "SPKIData");
	}

	if (node->MgmtData_isUsed) {
		exi_add_characters(subtree,
			hf_struct_iso20_KeyInfoType_MgmtData,
			tvb,
			node->MgmtData.characters,
			node->MgmtData.charactersLen,
			sizeof(node->MgmtData.characters));
	}

	if (node->ANY_isUsed) {
		exi_add_bytes(subtree,
			hf_struct_iso20_KeyInfoType_ANY,
			tvb,
			node->ANY.bytes,
			node->ANY.bytesLen,
			sizeof(node->ANY.bytes));
	}

	return;
}

static void
dissect_iso20_KeyValueType(
	const struct iso20_KeyValueType *node,
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
		dissect_iso20_DSAKeyValueType(&node->DSAKeyValue,
			tvb, pinfo, subtree,
			ett_struct_iso20_DSAKeyValueType,
			"DSAKeyValue");
	}
	if (node->RSAKeyValue_isUsed) {
		dissect_iso20_RSAKeyValueType(&node->RSAKeyValue,
			tvb, pinfo, subtree,
			ett_struct_iso20_RSAKeyValueType,
			"RSAKeyValue");
	}

	exi_add_bytes(subtree,
		hf_struct_iso20_KeyValueType_ANY,
		tvb,
		node->ANY.bytes,
		node->ANY.bytesLen,
		sizeof(node->ANY.bytes));

	return;
}

static void
dissect_iso20_RetrievalMethodType(
	const struct iso20_RetrievalMethodType *node,
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
			hf_struct_iso20_RetrievalMethodType_Type,
			tvb,
			node->Type.characters,
			node->Type.charactersLen,
			sizeof(node->Type.characters));
	}
	if (node->URI_isUsed) {
		exi_add_characters(subtree,
			hf_struct_iso20_RetrievalMethodType_URI,
			tvb,
			node->URI.characters,
			node->URI.charactersLen,
			sizeof(node->URI.characters));
	}
	if (node->Transforms_isUsed) {
		dissect_iso20_TransformsType(&node->Transforms,
			tvb, pinfo, subtree,
			ett_struct_iso20_TransformsType,
			"Transforms");
	}

	return;
}

static void
dissect_iso20_X509DataType(
	const struct iso20_X509DataType *node,
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
		dissect_iso20_X509IssuerSerialType(
			&node->X509IssuerSerial,
			tvb, pinfo, subtree,
			ett_struct_iso20_X509IssuerSerialType,
			"X509IssuerSerial");
	}
	if (node->X509SKI_isUsed) {
		exi_add_bytes(subtree,
			hf_struct_iso20_X509DataType_X509SKI,
			tvb,
			node->X509SKI.bytes,
			node->X509SKI.bytesLen,
			sizeof(node->X509SKI.bytes));
	}
	if (node->X509SubjectName_isUsed) {
		exi_add_characters(subtree,
			hf_struct_iso20_X509DataType_X509SubjectName,
			tvb,
			node->X509SubjectName.characters,
			node->X509SubjectName.charactersLen,
			sizeof(node->X509SubjectName.characters));
	}

	if (node->X509Certificate_isUsed) {
		if (v2gber_handle == NULL) {
			exi_add_bytes(subtree,
				hf_struct_iso20_X509DataType_X509Certificate,
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
				ett_v2giso20_asn1, NULL,
				"X509Certificate ASN1");
			call_dissector(v2gber_handle, child, pinfo, asn1_tree);
		}
	}

	if (node->X509CRL_isUsed) {
		exi_add_bytes(subtree,
			hf_struct_iso20_X509DataType_X509CRL,
			tvb,
			node->X509CRL.bytes,
			node->X509CRL.bytesLen,
			sizeof(node->X509CRL.bytes));
	}

	if (node->ANY_isUsed) {
		exi_add_bytes(subtree,
			hf_struct_iso20_X509DataType_ANY,
			tvb,
			node->ANY.bytes,
			node->ANY.bytesLen,
			sizeof(node->ANY.bytes));
	}

	return;
}

static void
dissect_iso20_PGPDataType(
	const struct iso20_PGPDataType *node,
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
			hf_struct_iso20_PGPDataType_PGPKeyID,
			tvb,
			node->choice_1.PGPKeyID.bytes,
			node->choice_1.PGPKeyID.bytesLen,
			sizeof(node->choice_1.PGPKeyID.bytes));

		if (node->choice_1.PGPKeyPacket_isUsed) {
			exi_add_bytes(subtree,
				hf_struct_iso20_PGPDataType_PGPKeyPacket,
				tvb,
				node->choice_1.PGPKeyPacket.bytes,
				node->choice_1.PGPKeyPacket.bytesLen,
				sizeof(node->choice_1.PGPKeyPacket.bytes));
		}

		if (node->choice_1.ANY_isUsed) {
			exi_add_bytes(subtree,
				hf_struct_iso20_PGPDataType_ANY,
				tvb,
				node->choice_1.ANY.bytes,
				node->choice_1.ANY.bytesLen,
				sizeof(node->choice_1.ANY.bytes));
		}
	}

	if (node->choice_2_isUsed) {
		exi_add_bytes(subtree,
			hf_struct_iso20_PGPDataType_PGPKeyPacket,
			tvb,
			node->choice_2.PGPKeyPacket.bytes,
			node->choice_2.PGPKeyPacket.bytesLen,
			sizeof(node->choice_2.PGPKeyPacket.bytes));

		if (node->choice_2.ANY_isUsed) {
			exi_add_bytes(subtree,
				hf_struct_iso20_PGPDataType_ANY,
				tvb,
				node->choice_2.ANY.bytes,
				node->choice_2.ANY.bytesLen,
				sizeof(node->choice_2.ANY.bytes));
		}
	}

	return;
}

static void
dissect_iso20_SPKIDataType(
	const struct iso20_SPKIDataType *node,
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
		hf_struct_iso20_SPKIDataType_SPKISexp,
		tvb,
		node->SPKISexp.bytes,
		node->SPKISexp.bytesLen,
		sizeof(node->SPKISexp.bytes));

	if (node->ANY_isUsed) {
		exi_add_bytes(subtree,
			hf_struct_iso20_SPKIDataType_ANY,
			tvb,
			node->ANY.bytes,
			node->ANY.bytesLen,
			sizeof(node->ANY.bytes));
	}

	return;
}

static void
dissect_iso20_ObjectType(
	const struct iso20_ObjectType *node,
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
			hf_struct_iso20_ObjectType_Id,
			tvb,
			node->Id.characters,
			node->Id.charactersLen,
			sizeof(node->Id.characters));
	}
	if (node->MimeType_isUsed) {
		exi_add_characters(subtree,
			hf_struct_iso20_ObjectType_MimeType,
			tvb,
			node->MimeType.characters,
			node->MimeType.charactersLen,
			sizeof(node->MimeType.characters));
	}
	if (node->Encoding_isUsed) {
		exi_add_characters(subtree,
			hf_struct_iso20_ObjectType_Encoding,
			tvb,
			node->Encoding.characters,
			node->Encoding.charactersLen,
			sizeof(node->Encoding.characters));
	}
	if (node->ANY_isUsed) {
		exi_add_bytes(subtree,
			hf_struct_iso20_ObjectType_ANY,
			tvb,
			node->ANY.bytes,
			node->ANY.bytesLen,
			sizeof(node->ANY.bytes));
	}

	return;
}

static void
dissect_iso20_DSAKeyValueType(
	const struct iso20_DSAKeyValueType *node,
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
			hf_struct_iso20_DSAKeyValueType_P,
			tvb,
			node->P.bytes,
			node->P.bytesLen,
			sizeof(node->P.bytes));
	}
	if (node->Q_isUsed) {
		exi_add_bytes(subtree,
			hf_struct_iso20_DSAKeyValueType_Q,
			tvb,
			node->Q.bytes,
			node->Q.bytesLen,
			sizeof(node->Q.bytes));
	}
	if (node->G_isUsed) {
		exi_add_bytes(subtree,
			hf_struct_iso20_DSAKeyValueType_G,
			tvb,
			node->G.bytes,
			node->G.bytesLen,
			sizeof(node->G.bytes));
	}
	exi_add_bytes(subtree,
		hf_struct_iso20_DSAKeyValueType_Y,
		tvb,
		node->Y.bytes,
		node->Y.bytesLen,
		sizeof(node->Y.bytes));
	if (node->J_isUsed) {
		exi_add_bytes(subtree,
			hf_struct_iso20_DSAKeyValueType_J,
			tvb,
			node->J.bytes,
			node->J.bytesLen,
			sizeof(node->J.bytes));
	}
	if (node->Seed_isUsed) {
		exi_add_bytes(subtree,
			hf_struct_iso20_DSAKeyValueType_Seed,
			tvb,
			node->Seed.bytes,
			node->Seed.bytesLen,
			sizeof(node->Seed.bytes));
	}
	if (node->PgenCounter_isUsed) {
		exi_add_bytes(subtree,
			hf_struct_iso20_DSAKeyValueType_PgenCounter,
			tvb,
			node->PgenCounter.bytes,
			node->PgenCounter.bytesLen,
			sizeof(node->PgenCounter.bytes));
	}

	return;
}

static void
dissect_iso20_RSAKeyValueType(
	const struct iso20_RSAKeyValueType *node,
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
		hf_struct_iso20_RSAKeyValueType_Modulus,
		tvb,
		node->Modulus.bytes,
		node->Modulus.bytesLen,
		sizeof(node->Modulus.bytes));

	exi_add_bytes(subtree,
		hf_struct_iso20_RSAKeyValueType_Exponent,
		tvb,
		node->Exponent.bytes,
		node->Exponent.bytesLen,
		sizeof(node->Exponent.bytes));

	return;
}


static void
dissect_iso20_MessageHeaderType(
	const struct iso20_MessageHeaderType *node,
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
		hf_struct_iso20_MessageHeaderType_SessionID,
		tvb,
		node->SessionID.bytes,
		node->SessionID.bytesLen,
		sizeof(node->SessionID.bytes));

	it = proto_tree_add_uint64(subtree,
		hf_struct_iso20_MessageHeaderType_TimeStamp,
		tvb, 0, 0, node->TimeStamp);
	proto_item_set_generated(it);

	if (node->Signature_isUsed) {
		dissect_iso20_SignatureType(
			&node->Signature, tvb, pinfo, subtree,
			ett_struct_iso20_SignatureType,
			"Signature");
	}

	return;
}

static void
dissect_iso20_X509IssuerSerialType(
	const struct iso20_X509IssuerSerialType *node,
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
		hf_struct_iso20_X509IssuerSerialType_X509IssuerName,
		tvb,
		node->X509IssuerName.characters,
		node->X509IssuerName.charactersLen,
		sizeof(node->X509IssuerName.characters));

	it = proto_tree_add_int64(subtree,
		hf_struct_iso20_X509IssuerSerialType_X509SerialNumber,
		tvb, 0, 0, node->X509SerialNumber);
	proto_item_set_generated(it);

	return;
}


/* other node dissectors - each node is represented by a struct */
static void dissect_iso20_RationalNumberType(
	const struct iso20_RationalNumberType *node,
	tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
	gint idx, const char *subtree_name);
static void dissect_iso20_DetailedCostType(
	const struct iso20_DetailedCostType *node,
	tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
	gint idx, const char *subtree_name);
static void dissect_iso20_DetailedTaxType(
	const struct iso20_DetailedTaxType *node,
	tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
	gint idx, const char *subtree_name);
static void dissect_iso20_ReceiptType(
        const struct iso20_ReceiptType *node,
        tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
        gint idx, const char *subtree_name);
static void dissect_iso20_Dynamic_EVPPTControlModeType(
	const struct iso20_Dynamic_EVPPTControlModeType *node,
	tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
	gint idx, const char *subtree_name);
static void dissect_iso20_Scheduled_EVPPTControlModeType(
	const struct iso20_Scheduled_EVPPTControlModeType *node,
	tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
	gint idx, const char *subtree_name);
static void dissect_iso20_Dynamic_SMDTControlModeType(
	const struct iso20_Dynamic_SMDTControlModeType *node,
	tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
	gint idx, const char *subtree_name);
static void dissect_iso20_Scheduled_SMDTControlModeType(
	const struct iso20_Scheduled_SMDTControlModeType *node,
	tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
	gint idx, const char *subtree_name);


static void
dissect_iso20_PowerScheduleEntryType(
	const struct iso20_PowerScheduleEntryType *node,
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

	it = proto_tree_add_uint(subtree,
		hf_struct_iso20_PowerScheduleEntryType_Duration,
		tvb, 0, 0, node->Duration);
	proto_item_set_generated(it);

	dissect_iso20_RationalNumberType(&node->Power,
		tvb, pinfo, subtree,
		ett_struct_iso20_RationalNumberType,
		"Power");

	if (node->Power_L2_isUsed) {
		dissect_iso20_RationalNumberType(&node->Power_L2,
			tvb, pinfo, subtree,
			ett_struct_iso20_RationalNumberType,
			"Power_L2");
	}

	if (node->Power_L3_isUsed) {
		dissect_iso20_RationalNumberType(&node->Power_L3,
			tvb, pinfo, subtree,
			ett_struct_iso20_RationalNumberType,
			"Power_L3");
	}

	return;
}


static void
dissect_iso20_EVPowerProfileEntryListType(
	const struct iso20_EVPowerProfileEntryListType *node,
	tvbuff_t *tvb,
	packet_info *pinfo _U_,
	proto_tree *tree,
	gint idx,
	const char *subtree_name)
{
	unsigned int i;
	proto_tree *subtree;
	proto_tree *evpowerprofileentry_tree;

	subtree = proto_tree_add_subtree(tree,
		tvb, 0, 0, idx, NULL, subtree_name);

	evpowerprofileentry_tree = proto_tree_add_subtree(subtree,
		tvb, 0, 0, ett_v2giso20_array, NULL, "EVPowerProfileEntry");
	for (i = 0; i < node->EVPowerProfileEntry.arrayLen; i++) {
		char index[sizeof("[65536]")];

		snprintf(index, sizeof(index), "[%u]", i);
		dissect_iso20_PowerScheduleEntryType(
			&node->EVPowerProfileEntry.array[i],
			tvb, pinfo, evpowerprofileentry_tree,
			ett_struct_iso20_PowerScheduleEntryListType,
			index);
	}

	return;
}


static void
dissect_iso20_EVPowerProfileType(
	const struct iso20_EVPowerProfileType *node,
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

	it = proto_tree_add_uint64(subtree,
		hf_struct_iso20_EVPowerProfileType_TimeAnchor,
		tvb, 0, 0, node->TimeAnchor);
	proto_item_set_generated(it);

	if (node->Dynamic_EVPPTControlMode_isUsed) {
		dissect_iso20_Dynamic_EVPPTControlModeType(
			&node->Dynamic_EVPPTControlMode,
			tvb, pinfo, subtree,
			ett_struct_iso20_Dynamic_EVPPTControlModeType,
			"Dynamic_EVPPTControlMode");
	}

	if (node->Scheduled_EVPPTControlMode_isUsed) {
		dissect_iso20_Scheduled_EVPPTControlModeType(
			&node->Scheduled_EVPPTControlMode,
			tvb, pinfo, subtree,
			ett_struct_iso20_Scheduled_EVPPTControlModeType,
			"Scheduled_EVPPTControlMode");
	}

	dissect_iso20_EVPowerProfileEntryListType(
		&node->EVPowerProfileEntries,
		tvb, pinfo, subtree,
		ett_struct_iso20_EVPowerProfileEntryListType,
		"EVPowerProfileEntries");

	return;
}


static void
dissect_iso20_EVSEStatusType(
	const struct iso20_EVSEStatusType *node,
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

	it = proto_tree_add_uint(subtree,
		hf_struct_iso20_EVSEStatusType_NotificationMaxDelay,
		tvb, 0, 0, node->NotificationMaxDelay);
	proto_item_set_generated(it);

	it = proto_tree_add_uint(subtree,
		hf_struct_iso20_EVSEStatusType_EVSENotification,
		tvb, 0, 0, node->EVSENotification);
	proto_item_set_generated(it);

	return;
}

static void
dissect_iso20_RationalNumberType(
	const struct iso20_RationalNumberType *rationalnumber,
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
		hf_struct_iso20_RationalNumberType_Exponent,
		tvb, 0, 0, rationalnumber->Exponent);
	proto_item_set_generated(it);

	it = proto_tree_add_int(subtree,
		hf_struct_iso20_RationalNumberType_Value,
		tvb, 0, 0, rationalnumber->Value);
	proto_item_set_generated(it);

	return;
}


static void
dissect_iso20_MeterInfoType(
	const struct iso20_MeterInfoType *node,
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
		hf_struct_iso20_MeterInfoType_MeterID,
		tvb,
		node->MeterID.characters,
		node->MeterID.charactersLen,
		sizeof(node->MeterID.characters));

	it = proto_tree_add_uint64(subtree,
		hf_struct_iso20_MeterInfoType_ChargedEnergyReadingWh,
		tvb, 0, 0, node->ChargedEnergyReadingWh);
	proto_item_set_generated(it);

	if (node->BPT_DischargedEnergyReadingWh_isUsed) {
		it = proto_tree_add_uint64(subtree,
			hf_struct_iso20_MeterInfoType_BPT_DischargedEnergyReadingWh,
			tvb, 0, 0, node->BPT_DischargedEnergyReadingWh);
		proto_item_set_generated(it);
	}

	if (node->CapacitiveEnergyReadingVARh_isUsed) {
		it = proto_tree_add_uint64(subtree,
			hf_struct_iso20_MeterInfoType_CapacitiveEnergyReadingVARh,
			tvb, 0, 0, node->CapacitiveEnergyReadingVARh);
		proto_item_set_generated(it);
	}

	if (node->BPT_InductiveEnergyReadingVARh_isUsed) {
		it = proto_tree_add_uint64(subtree,
			hf_struct_iso20_MeterInfoType_BPT_InductiveEnergyReadingVARh,
			tvb, 0, 0, node->BPT_InductiveEnergyReadingVARh);
		proto_item_set_generated(it);
	}

	if (node->MeterSignature_isUsed) {
		exi_add_bytes(subtree,
			hf_struct_iso20_MeterInfoType_MeterSignature,
			tvb,
			node->MeterSignature.bytes,
			node->MeterSignature.bytesLen,
			sizeof(node->MeterSignature.bytes));
	}

	if (node->MeterStatus_isUsed) {
		it = proto_tree_add_int(subtree,
			hf_struct_iso20_MeterInfoType_MeterStatus,
			tvb, 0, 0, node->MeterStatus);
		proto_item_set_generated(it);
	}

	if (node->MeterTimestamp_isUsed) {
		it = proto_tree_add_int64(subtree,
			hf_struct_iso20_MeterInfoType_MeterTimestamp,
			tvb, 0, 0, node->MeterTimestamp);
		proto_item_set_generated(it);
	}

	return;
}


static void
dissect_iso20_SignedMeteringDataType(
	const struct  iso20_SignedMeteringDataType *node,
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
		hf_struct_iso20_SignedMeteringDataType_Id,
		tvb,
		node->Id.characters,
		node->Id.charactersLen,
		sizeof(node->Id.characters));

	exi_add_bytes(subtree,
		hf_struct_iso20_SignedMeteringDataType_SessionID,
		tvb,
		node->SessionID.bytes,
		node->SessionID.bytesLen,
		sizeof(node->SessionID.bytes));

	dissect_iso20_MeterInfoType(&node->MeterInfo,
		tvb, pinfo, subtree,
		ett_struct_iso20_MeterInfoType,
		"MeterInfo");

	if (node->Receipt_isUsed) {
		dissect_iso20_ReceiptType(
			&node->Receipt,
			tvb, pinfo, subtree,
			ett_struct_iso20_ReceiptType,
			"Receipt");
	}

	if (node->Dynamic_SMDTControlMode_isUsed) {
		dissect_iso20_Dynamic_SMDTControlModeType(
			&node->Dynamic_SMDTControlMode,
			tvb, pinfo, subtree,
			ett_struct_iso20_Dynamic_SMDTControlModeType,
			"Dynamic_SMDTControlMode");
	}

	if (node->Scheduled_SMDTControlMode_isUsed) {
		dissect_iso20_Scheduled_SMDTControlModeType(
			&node->Scheduled_SMDTControlMode,
			tvb, pinfo, subtree,
			ett_struct_iso20_Scheduled_SMDTControlModeType,
			"Scheduled_SMDTControlMode");
	}

	return;
}


static void
dissect_iso20_ParameterType(
	const struct iso20_ParameterType *parameter,
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

	exi_add_characters(subtree,
		hf_struct_iso20_ParameterType_Name,
		tvb,
		parameter->Name.characters,
		parameter->Name.charactersLen,
		sizeof(parameter->Name.characters));

	if (parameter->boolValue_isUsed) {
		it = proto_tree_add_int(subtree,
			hf_struct_iso20_ParameterType_boolValue,
			tvb, 0, 0, parameter->boolValue);
		proto_item_set_generated(it);
	}
	if (parameter->byteValue_isUsed) {
		it = proto_tree_add_int(subtree,
			hf_struct_iso20_ParameterType_byteValue,
			tvb, 0, 0, parameter->byteValue);
		proto_item_set_generated(it);
	}
	if (parameter->shortValue_isUsed) {
		it = proto_tree_add_int(subtree,
			hf_struct_iso20_ParameterType_shortValue,
			tvb, 0, 0, parameter->shortValue);
		proto_item_set_generated(it);
	}
	if (parameter->intValue_isUsed) {
		it = proto_tree_add_int(subtree,
			hf_struct_iso20_ParameterType_intValue,
			tvb, 0, 0, parameter->intValue);
		proto_item_set_generated(it);
	}
	if (parameter->rationalNumber_isUsed) {
		dissect_iso20_RationalNumberType(&parameter->rationalNumber,
			tvb, pinfo, subtree,
			ett_struct_iso20_RationalNumberType,
			"rationalNumber");
	}
	if (parameter->finiteString_isUsed) {
		exi_add_characters(subtree,
			hf_struct_iso20_ParameterType_finiteString,
			tvb,
			parameter->finiteString.characters,
			parameter->finiteString.charactersLen,
			sizeof(parameter->finiteString.characters));
	}

	return;
}


static void
dissect_iso20_ParameterSetType(
	const struct iso20_ParameterSetType *node,
	tvbuff_t *tvb,
	packet_info *pinfo _U_,
	proto_tree *tree,
	gint idx,
	const char *subtree_name)
{
	unsigned int i;
	proto_tree *subtree;
	proto_tree *parameter_tree;
	proto_item *it;

	subtree = proto_tree_add_subtree(tree,
		tvb, 0, 0, idx, NULL, subtree_name);

	it = proto_tree_add_uint(subtree,
		hf_struct_iso20_ParameterSetType_ParameterSetID,
		tvb, 0, 0, node->ParameterSetID);
	proto_item_set_generated(it);

	parameter_tree = proto_tree_add_subtree(subtree,
		tvb, 0, 0, ett_v2giso20_array, NULL, "Parameter");
	for (i = 0; i < node->Parameter.arrayLen; i++) {
		char index[sizeof("[65536]")];

		snprintf(index, sizeof(index), "[%u]", i);
		dissect_iso20_ParameterType(
			&node->Parameter.array[i],
			tvb, pinfo, parameter_tree,
			ett_struct_iso20_ParameterType, index);
	}

	return;
}

static void
dissect_iso20_ListOfRootCertificateIDsType(
	const struct iso20_ListOfRootCertificateIDsType *node,
	tvbuff_t *tvb,
	packet_info *pinfo,
	proto_tree *tree,
	gint idx,
	const char *subtree_name)
{
	unsigned int i;
	proto_tree *subtree;
	proto_tree *rootcertificateid_tree;

	subtree = proto_tree_add_subtree(tree, tvb, 0, 0,
		idx, NULL, subtree_name);

	rootcertificateid_tree = proto_tree_add_subtree(subtree,
		tvb, 0, 0, ett_v2giso20_array, NULL, "RootCertificateID");
	for (i = 0; i < node->RootCertificateID.arrayLen; i++) {
		char index[sizeof("[65536]")];

		snprintf(index, sizeof(index), "[%u]", i);
		dissect_iso20_X509IssuerSerialType(
			&node->RootCertificateID.array[i],
			tvb, pinfo, rootcertificateid_tree,
			ett_struct_iso20_X509IssuerSerialType,
			index);
	}

	return;
}

static void
dissect_iso20_SubCertificatesType(
	const struct iso20_SubCertificatesType *node,
	tvbuff_t *tvb,
	packet_info *pinfo,
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
		tvb, 0, 0, ett_v2giso20_array, NULL, "Certificate");
	for (i = 0; i < node->Certificate.arrayLen; i++) {
		certificate_i_tree = proto_tree_add_subtree_format(
			certificate_tree,
			tvb, 0, 0, ett_v2giso20_array_i, NULL, "[%u]", i);

		if (v2gber_handle == NULL) {
			exi_add_bytes(certificate_i_tree,
				hf_struct_iso20_SubCertificatesType_Certificate,
				tvb,
				node->Certificate.array[i].bytes,
				node->Certificate.array[i].bytesLen,
				sizeof(node->Certificate.array[i].bytes));
		} else {
			tvbuff_t *child;
			proto_tree *asn1_tree;

			child = tvb_new_child_real_data(tvb,
				node->Certificate.array[i].bytes,
				sizeof(node->Certificate.array[i].bytes),
				node->Certificate.array[i].bytesLen);

			asn1_tree = proto_tree_add_subtree(certificate_i_tree,
				child, 0, tvb_reported_length(child),
				ett_v2giso20_asn1, NULL, "Certificate ASN1");
			call_dissector(v2gber_handle, child, pinfo, asn1_tree);
		}
	}

	return;
}


static void
dissect_iso20_CertificateChainType(
	const struct iso20_CertificateChainType *node,
	tvbuff_t *tvb,
	packet_info *pinfo,
	proto_tree *tree,
	gint idx,
	const char *subtree_name)
{
	proto_tree *subtree;

	subtree = proto_tree_add_subtree(tree, tvb, 0, 0,
		idx, NULL, subtree_name);

	if (v2gber_handle == NULL) {
		exi_add_bytes(subtree,
			hf_struct_iso20_CertificateChainType_Certificate,
			tvb,
			node->Certificate.bytes,
			node->Certificate.bytesLen,
			sizeof(node->Certificate.bytes));
	} else {
		tvbuff_t *child;
		proto_tree *asn1_tree;

		child = tvb_new_child_real_data(tvb,
			node->Certificate.bytes,
			sizeof(node->Certificate.bytes),
			node->Certificate.bytesLen);

		asn1_tree = proto_tree_add_subtree(subtree,
			child, 0, tvb_reported_length(child),
			ett_v2giso20_asn1, NULL, "Certificate ASN1");
		call_dissector(v2gber_handle, child, pinfo, asn1_tree);
	}

	if (node->SubCertificates_isUsed) {
		dissect_iso20_SubCertificatesType(
			&node->SubCertificates,
			tvb, pinfo, subtree,
			ett_struct_iso20_SubCertificatesType,
			"SubCertificates");
	}

	return;
}


static void
dissect_iso20_ContractCertificateChainType(
	const struct iso20_ContractCertificateChainType *node,
	tvbuff_t *tvb,
	packet_info *pinfo,
	proto_tree *tree,
	gint idx,
	const char *subtree_name)
{
	proto_tree *subtree;

	subtree = proto_tree_add_subtree(tree, tvb, 0, 0,
		idx, NULL, subtree_name);

	if (v2gber_handle == NULL) {
		exi_add_bytes(subtree,
			hf_struct_iso20_ContractCertificateChainType_Certificate,
			tvb,
			node->Certificate.bytes,
			node->Certificate.bytesLen,
			sizeof(node->Certificate.bytes));
	} else {
		tvbuff_t *child;
		proto_tree *asn1_tree;

		child = tvb_new_child_real_data(tvb,
			node->Certificate.bytes,
			sizeof(node->Certificate.bytes),
			node->Certificate.bytesLen);

		asn1_tree = proto_tree_add_subtree(subtree,
			child, 0, tvb_reported_length(child),
			ett_v2giso20_asn1, NULL, "Certificate ASN1");
		call_dissector(v2gber_handle, child, pinfo, asn1_tree);
	}

	dissect_iso20_SubCertificatesType(
		&node->SubCertificates,
		tvb, pinfo, subtree,
		ett_struct_iso20_SubCertificatesType,
		"SubCertificates");

	return;
}


static void
dissect_iso20_SignedCertificateChainType(
	const struct iso20_SignedCertificateChainType *node,
	tvbuff_t *tvb,
	packet_info *pinfo,
	proto_tree *tree,
	gint idx,
	const char *subtree_name)
{
	proto_tree *subtree;

	subtree = proto_tree_add_subtree(tree, tvb, 0, 0,
		idx, NULL, subtree_name);

	exi_add_characters(subtree,
		hf_struct_iso20_SignedCertificateChainType_Id,
		tvb,
		node->Id.characters,
		node->Id.charactersLen,
		sizeof(node->Id.characters));

	if (v2gber_handle == NULL) {
		exi_add_bytes(subtree,
			hf_struct_iso20_SignedCertificateChainType_Certificate,
			tvb,
			node->Certificate.bytes,
			node->Certificate.bytesLen,
			sizeof(node->Certificate.bytes));
	} else {
		tvbuff_t *child;
		proto_tree *asn1_tree;

		child = tvb_new_child_real_data(tvb,
			node->Certificate.bytes,
			sizeof(node->Certificate.bytes),
			node->Certificate.bytesLen);

		asn1_tree = proto_tree_add_subtree(subtree,
			child, 0, tvb_reported_length(child),
			ett_v2giso20_asn1, NULL, "Certificate ASN1");
		call_dissector(v2gber_handle, child, pinfo, asn1_tree);
	}

	if (node->SubCertificates_isUsed) {
		dissect_iso20_SubCertificatesType(
			&node->SubCertificates,
			tvb, pinfo, subtree,
			ett_struct_iso20_SubCertificatesType,
			"SubCertificates");
	}

	return;
}

static void
dissect_iso20_SignedInstallationDataType(
	const struct iso20_SignedInstallationDataType *node _U_,
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
dissect_iso20_EMAIDListType(
	const struct iso20_EMAIDListType *node,
	tvbuff_t *tvb,
	packet_info *pinfo _U_,
	proto_tree *tree,
	gint idx,
	const char *subtree_name)
{
	unsigned int i;
	proto_tree *subtree;
	proto_tree *emaid_tree;
	proto_tree *emaid_i_tree;

	subtree = proto_tree_add_subtree(tree,
		tvb, 0, 0, idx, NULL, subtree_name);

	emaid_tree = proto_tree_add_subtree(subtree,
		tvb, 0, 0, ett_v2giso20_array, NULL, "EMAID");
	for (i = 0; i < node->EMAID.arrayLen; i++) {
		char index[sizeof("[65536]")];

		snprintf(index, sizeof(index), "[%u]", i);
		emaid_i_tree = proto_tree_add_subtree(
			emaid_tree, tvb, 0, 0,
			ett_v2giso20_array_i, NULL, index);

		exi_add_characters(emaid_i_tree,
			hf_struct_iso20_EMAIDListType_EMAID,
			tvb,
			node->EMAID.array[i].characters,
			node->EMAID.array[i].charactersLen,
			sizeof(node->EMAID.array[i].characters));
	}

	return;
}


static void
dissect_iso20_SupportedProvidersListType(
	const struct iso20_SupportedProvidersListType *node,
	tvbuff_t *tvb,
	packet_info *pinfo _U_,
	proto_tree *tree,
	gint idx,
	const char *subtree_name)
{
	unsigned int i;
	proto_tree *subtree;
	proto_tree *providerid_tree;
	proto_tree *providerid_i_tree;

	subtree = proto_tree_add_subtree(tree,
		tvb, 0, 0, idx, NULL, subtree_name);

	providerid_tree = proto_tree_add_subtree(subtree,
		tvb, 0, 0, ett_v2giso20_array, NULL, "ProviderID");
	for (i = 0; i < node->ProviderID.arrayLen; i++) {
		char index[sizeof("[65536]")];

		snprintf(index, sizeof(index), "[%u]", i);
		providerid_i_tree = proto_tree_add_subtree(
			providerid_tree, tvb, 0, 0,
			ett_v2giso20_array_i, NULL, index);

		exi_add_characters(providerid_i_tree,
			hf_struct_iso20_SupportedProvidersListType_ProviderID,
			tvb,
			node->ProviderID.array[i].characters,
			node->ProviderID.array[i].charactersLen,
			sizeof(node->ProviderID.array[i].characters));
	}

	return;
}


static void
dissect_iso20_EIM_AReqAuthorizationModeType(
	const struct iso20_EIM_AReqAuthorizationModeType *node _U_,
	tvbuff_t *tvb _U_,
	packet_info *pinfo _U_,
	proto_tree *tree _U_,
	gint idx _U_,
	const char *subtree_name _U_)
{
	/* unused */
	return;
}


static void
dissect_iso20_PnC_AReqAuthorizationModeType(
	const struct iso20_PnC_AReqAuthorizationModeType *node,
	tvbuff_t *tvb,
	packet_info *pinfo,
	proto_tree *tree,
	gint idx,
	const char *subtree_name)
{
	proto_tree *subtree;

	subtree = proto_tree_add_subtree(tree,
		tvb, 0, 0, idx, NULL, subtree_name);

	exi_add_characters(subtree,
		hf_struct_iso20_PnC_AReqAuthorizationModeType_Id,
		tvb,
		node->Id.characters,
		node->Id.charactersLen,
		sizeof(node->Id.characters));

	exi_add_bytes(subtree,
		hf_struct_iso20_PnC_AReqAuthorizationModeType_GenChallenge,
		tvb,
		node->GenChallenge.bytes,
		node->GenChallenge.bytesLen,
		sizeof(node->GenChallenge.bytes));

	dissect_iso20_ContractCertificateChainType(
		&node->ContractCertificateChain,
		tvb, pinfo, subtree,
		ett_struct_iso20_ContractCertificateChainType,
		"ContractCertificateChain");

	return;
}


static void
dissect_iso20_EIM_ASResAuthorizationModeType(
	const struct iso20_EIM_ASResAuthorizationModeType *node _U_,
	tvbuff_t *tvb _U_,
	packet_info *pinfo _U_,
	proto_tree *tree _U_,
	gint idx _U_,
	const char *subtree_name _U_)
{
	/* unused */
	return;
}


static void
dissect_iso20_PnC_ASResAuthorizationModeType(
	const struct iso20_PnC_ASResAuthorizationModeType *node,
	tvbuff_t *tvb,
	packet_info *pinfo,
	proto_tree *tree,
	gint idx,
	const char *subtree_name)
{
	proto_tree *subtree;

	subtree = proto_tree_add_subtree(tree,
		tvb, 0, 0, idx, NULL, subtree_name);

	exi_add_bytes(subtree,
		hf_struct_iso20_PnC_ASResAuthorizationModeType_GenChallenge,
		tvb,
		node->GenChallenge.bytes,
		node->GenChallenge.bytesLen,
		sizeof(node->GenChallenge.bytes));

	if (node->SupportedProviders_isUsed) {
		dissect_iso20_SupportedProvidersListType(
			&node->SupportedProviders,
			tvb, pinfo, subtree,
			ett_struct_iso20_SupportedProvidersListType,
			"SupportedProviders");
	}

	return;
}

static void
dissect_iso20_SelectedServiceType(
	const struct iso20_SelectedServiceType *node,
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

	it = proto_tree_add_uint(subtree,
		hf_struct_iso20_SelectedServiceType_ServiceID,
		tvb, 0, 0, node->ServiceID);
	proto_item_set_generated(it);

	it = proto_tree_add_uint(subtree,
		hf_struct_iso20_SelectedServiceType_ParameterSetID,
		tvb, 0, 0, node->ParameterSetID);
	proto_item_set_generated(it);

	return;
}

static void
dissect_iso20_SelectedServiceListType(
	const struct iso20_SelectedServiceListType *node,
	tvbuff_t *tvb,
	packet_info *pinfo _U_,
	proto_tree *tree,
	gint idx,
	const char *subtree_name)
{
	unsigned int i;
	proto_tree *subtree;
	proto_tree *selectedservice_tree;

	subtree = proto_tree_add_subtree(tree,
		tvb, 0, 0, idx, NULL, subtree_name);

	selectedservice_tree = proto_tree_add_subtree(subtree,
		tvb, 0, 0, ett_v2giso20_array, NULL, "SelectedService");
	for (i = 0; i < node->SelectedService.arrayLen; i++) {
		char index[sizeof("[65536]")];

		snprintf(index, sizeof(index), "[%u]", i);
		dissect_iso20_SelectedServiceType(
			&node->SelectedService.array[i],
			tvb, pinfo, selectedservice_tree,
			ett_struct_iso20_SelectedServiceType,
			index);
	}

	return;
}

static void
dissect_iso20_ServiceParameterListType(
	const struct iso20_ServiceParameterListType *node,
	tvbuff_t *tvb,
	packet_info *pinfo _U_,
	proto_tree *tree,
	gint idx,
	const char *subtree_name)
{
	unsigned int i;
	proto_tree *subtree;
	proto_tree *parameterset_tree;

	subtree = proto_tree_add_subtree(tree,
		tvb, 0, 0, idx, NULL, subtree_name);

	parameterset_tree = proto_tree_add_subtree(subtree,
		tvb, 0, 0, ett_v2giso20_array, NULL, "Service");
	for (i = 0; i < node->ParameterSet.arrayLen; i++) {
		char index[sizeof("[65536]")];

		snprintf(index, sizeof(index), "[%u]", i);
		dissect_iso20_ParameterSetType(
			&node->ParameterSet.array[i],
			tvb, pinfo, parameterset_tree,
			ett_struct_iso20_ParameterSetType,
			index);
	}

	return;
}

static void
dissect_iso20_ServiceIDListType(
	const struct iso20_ServiceIDListType *serviceidlist,
	tvbuff_t *tvb,
	packet_info *pinfo _U_,
	proto_tree *tree,
	gint idx,
	const char *subtree_name)
{
	unsigned int i;
	proto_tree *subtree;
	proto_tree *serviceidlist_tree;
	proto_tree *serviceidlist_i_tree;
	proto_item *it;

	subtree = proto_tree_add_subtree(tree,
		tvb, 0, 0, idx, NULL, subtree_name);

	serviceidlist_tree = proto_tree_add_subtree(subtree,
		tvb, 0, 0, ett_v2giso20_array, NULL, "ServiceID");
	for (i = 0; i < serviceidlist->ServiceID.arrayLen; i++) {
		char index[sizeof("[65536]")];

		snprintf(index, sizeof(index), "[%u]", i);
		serviceidlist_i_tree = proto_tree_add_subtree(
			serviceidlist_tree, tvb, 0, 0,
			ett_v2giso20_array_i, NULL, index);

		it = proto_tree_add_uint(serviceidlist_i_tree,
			hf_struct_iso20_ServiceIDListType_ServiceID,
			tvb, 0, 0,
			serviceidlist->ServiceID.array[i]);
		proto_item_set_generated(it);
	}

	return;
}

static void
dissect_iso20_ServiceType(
	const struct iso20_ServiceType *service,
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

	it = proto_tree_add_uint(subtree,
		hf_struct_iso20_ServiceType_ServiceID,
		tvb, 0, 0, service->ServiceID);
	proto_item_set_generated(it);

	it = proto_tree_add_int(subtree,
		hf_struct_iso20_ServiceType_FreeService,
		tvb, 0, 0, service->FreeService);
	proto_item_set_generated(it);

	return;
}

static void
dissect_iso20_ServiceListType(
	const struct iso20_ServiceListType *node,
	tvbuff_t *tvb,
	packet_info *pinfo,
	proto_tree *tree,
	gint idx,
	const char *subtree_name)
{
	unsigned int i;
	proto_tree *subtree;
	proto_tree *service_tree;

	subtree = proto_tree_add_subtree(tree,
		tvb, 0, 0, idx, NULL, subtree_name);

	service_tree = proto_tree_add_subtree(subtree,
		tvb, 0, 0, ett_v2giso20_array, NULL, "Service");
	for (i = 0; i < node->Service.arrayLen; i++) {
		char index[sizeof("[65536]")];

		snprintf(index, sizeof(index), "[%u]", i);
		dissect_iso20_ServiceType(
			&node->Service.array[i],
			tvb, pinfo, service_tree,
			ett_struct_iso20_ServiceType,
			index);
	}

	return;
}

static void
dissect_iso20_DetailedCostType(
	const struct iso20_DetailedCostType *node,
	tvbuff_t *tvb,
	packet_info *pinfo,
	proto_tree *tree,
	gint idx,
	const char *subtree_name)
{
	proto_tree *subtree;

	subtree = proto_tree_add_subtree(tree,
		tvb, 0, 0, idx, NULL, subtree_name);

	dissect_iso20_RationalNumberType(
		&node->Amount,
		tvb, pinfo, subtree,
		ett_struct_iso20_RationalNumberType,
		"Amount");

	dissect_iso20_RationalNumberType(
		&node->CostPerUnit,
		tvb, pinfo, subtree,
		ett_struct_iso20_RationalNumberType,
		"CostPerUnit");

	return;
}

static void
dissect_iso20_DetailedTaxType(
	const struct iso20_DetailedTaxType *node,
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

	it = proto_tree_add_uint(subtree,
		hf_struct_iso20_DetailedTaxType_TaxRuleID,
		tvb, 0, 0, node->TaxRuleID);
	proto_item_set_generated(it);

	dissect_iso20_RationalNumberType(
		&node->Amount,
		tvb, pinfo, subtree,
		ett_struct_iso20_RationalNumberType,
		"Amount");

	return;
}

static void
dissect_iso20_ReceiptType(
	const struct iso20_ReceiptType *node,
	tvbuff_t *tvb,
	packet_info *pinfo,
	proto_tree *tree,
	gint idx,
	const char *subtree_name)
{
	unsigned int i;
	proto_tree *subtree;
	proto_item *it;
	proto_tree *taxcosts_tree;

	subtree = proto_tree_add_subtree(tree,
		tvb, 0, 0, idx, NULL, subtree_name);

	it = proto_tree_add_uint64(subtree,
		hf_struct_iso20_ReceiptType_TimeAnchor,
		tvb, 0, 0, node->TimeAnchor);
	proto_item_set_generated(it);

	if (node->EnergyCosts_isUsed) {
		dissect_iso20_DetailedCostType(&node->EnergyCosts,
			tvb, pinfo, subtree,
			ett_struct_iso20_DetailedCostType,
			"EnergyCosts");
	}
	if (node->OccupancyCosts_isUsed) {
		dissect_iso20_DetailedCostType(&node->OccupancyCosts,
			tvb, pinfo, subtree,
			ett_struct_iso20_DetailedCostType,
			"OccupancyCosts");
	}
	if (node->AdditionalServicesCosts_isUsed) {
		dissect_iso20_DetailedCostType(&node->AdditionalServicesCosts,
			tvb, pinfo, subtree,
			ett_struct_iso20_DetailedCostType,
			"AdditionalServicesCosts");
	}
	if (node->OverstayCosts_isUsed) {
		dissect_iso20_DetailedCostType(&node->OverstayCosts,
			tvb, pinfo, subtree,
			ett_struct_iso20_DetailedCostType,
			"OverstayCosts");
	}

	taxcosts_tree = proto_tree_add_subtree(subtree,
		tvb, 0, 0, ett_v2giso20_array, NULL, "TaxCosts");
	for (i = 0; i < node->TaxCosts.arrayLen; i++) {
		char index[sizeof("[65536]")];

		snprintf(index, sizeof(index), "[%u]", i);
		dissect_iso20_DetailedTaxType(&node->TaxCosts.array[i],
			tvb, pinfo, taxcosts_tree,
			ett_struct_iso20_DetailedTaxType, index);
	}

	return;
}

static void
dissect_iso20_Dynamic_SEReqControlModeType(
	const struct iso20_Dynamic_SEReqControlModeType *node _U_,
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
dissect_iso20_Scheduled_SEReqControlModeType(
	const struct iso20_Scheduled_SEReqControlModeType *node _U_,
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
dissect_iso20_Dynamic_SEResControlModeType(
	const struct iso20_Dynamic_SEResControlModeType *node _U_,
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
dissect_iso20_Scheduled_SEResControlModeType(
	const struct iso20_Scheduled_SEResControlModeType *node _U_,
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
dissect_iso20_Dynamic_EVPPTControlModeType(
	const struct iso20_Dynamic_EVPPTControlModeType *node _U_,
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
dissect_iso20_Scheduled_EVPPTControlModeType(
	const struct iso20_Scheduled_EVPPTControlModeType *node _U_,
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
dissect_iso20_Dynamic_SMDTControlModeType(
	const struct iso20_Dynamic_SMDTControlModeType *node _U_,
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
dissect_iso20_Scheduled_SMDTControlModeType(
	const struct iso20_Scheduled_SMDTControlModeType *node _U_,
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
dissect_iso20_SessionSetupReqType(
	const struct iso20_SessionSetupReqType *req,
	tvbuff_t *tvb,
	packet_info *pinfo _U_,
	proto_tree *tree,
	gint idx,
	const char *subtree_name)
{
	proto_tree *subtree;

	subtree = proto_tree_add_subtree(tree,
		tvb, 0, 0, idx, NULL, subtree_name);

	dissect_iso20_MessageHeaderType(&req->Header,
		tvb, pinfo, subtree,
		ett_struct_iso20_MessageHeaderType, "Header");

	exi_add_characters(subtree,
		hf_struct_iso20_SessionSetupReqType_EVCCID,
		tvb,
		req->EVCCID.characters,
		req->EVCCID.charactersLen,
		sizeof(req->EVCCID.characters));

	return;
}

static void
dissect_iso20_SessionSetupResType(
	const struct iso20_SessionSetupResType *res,
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

	dissect_iso20_MessageHeaderType(&res->Header,
		tvb, pinfo, subtree,
		ett_struct_iso20_MessageHeaderType, "Header");

	it = proto_tree_add_uint(subtree,
		hf_struct_iso20_SessionSetupResType_ResponseCode,
		tvb, 0, 0, res->ResponseCode);
	proto_item_set_generated(it);

	exi_add_characters(subtree,
		hf_struct_iso20_SessionSetupResType_EVSEID,
		tvb,
		res->EVSEID.characters,
		res->EVSEID.charactersLen,
		sizeof(res->EVSEID.characters));

	return;
}


static void
dissect_iso20_AuthorizationSetupReqType(
	const struct iso20_AuthorizationSetupReqType *req,
	tvbuff_t *tvb,
	packet_info *pinfo _U_,
	proto_tree *tree,
	gint idx,
	const char *subtree_name)
{
	proto_tree *subtree;

	subtree = proto_tree_add_subtree(tree,
		tvb, 0, 0, idx, NULL, subtree_name);

	dissect_iso20_MessageHeaderType(&req->Header,
		tvb, pinfo, subtree,
		ett_struct_iso20_MessageHeaderType, "Header");

	return;
}

static void
dissect_iso20_AuthorizationSetupResType(
	const struct iso20_AuthorizationSetupResType *res,
	tvbuff_t *tvb,
	packet_info *pinfo _U_,
	proto_tree *tree,
	gint idx,
	const char *subtree_name)
{
	unsigned int i;
	proto_tree *subtree;
	proto_tree *authorizationservices_tree;
	proto_tree *authorizationservices_i_tree;
	proto_item *it;

	subtree = proto_tree_add_subtree(tree,
		tvb, 0, 0, idx, NULL, subtree_name);

	dissect_iso20_MessageHeaderType(&res->Header,
		tvb, pinfo, subtree,
		ett_struct_iso20_MessageHeaderType, "Header");

	it = proto_tree_add_uint(subtree,
		hf_struct_iso20_AuthorizationSetupResType_ResponseCode,
		tvb, 0, 0, res->ResponseCode);

	authorizationservices_tree = proto_tree_add_subtree(subtree,
		tvb, 0, 0, ett_v2giso20_array, NULL, "AuthorizationServices");
	for (i = 0; i < res->AuthorizationServices.arrayLen; i++) {
		char index[sizeof("[65536]")];

		snprintf(index, sizeof(index), "[%u]", i);
		authorizationservices_i_tree = proto_tree_add_subtree(
			authorizationservices_tree, tvb, 0, 0,
			ett_v2giso20_array_i, NULL, index);

		it = proto_tree_add_uint(authorizationservices_i_tree,
			hf_struct_iso20_AuthorizationSetupResType_Authorization,
			tvb, 0, 0,
			res->AuthorizationServices.array[i]);
		proto_item_set_generated(it);
	}

	it = proto_tree_add_int(subtree,
		hf_struct_iso20_AuthorizationSetupResType_CertificateInstallationService,
		tvb, 0, 0, res->CertificateInstallationService);
	proto_item_set_generated(it);

	if (res->EIM_ASResAuthorizationMode_isUsed) {
		dissect_iso20_EIM_ASResAuthorizationModeType(
			&res->EIM_ASResAuthorizationMode,
			tvb, pinfo, subtree,
			ett_struct_iso20_EIM_ASResAuthorizationModeType,
			"EIM_ASResAuthorizationMode");
	}

	if (res->PnC_ASResAuthorizationMode_isUsed) {
		dissect_iso20_PnC_ASResAuthorizationModeType(
			&res->PnC_ASResAuthorizationMode,
			tvb, pinfo, subtree,
			ett_struct_iso20_PnC_ASResAuthorizationModeType,
			"PnC_ASResAuthorizationMode");
	}

	return;
}


static void
dissect_iso20_AuthorizationReqType(
	const struct iso20_AuthorizationReqType *authorizationreq,
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

	dissect_iso20_MessageHeaderType(&authorizationreq->Header,
		tvb, pinfo, subtree,
		ett_struct_iso20_MessageHeaderType, "Header");

	it = proto_tree_add_uint(subtree,
		hf_struct_iso20_AuthorizationReqType_SelectedAuthorizationService,
		tvb, 0, 0, authorizationreq->SelectedAuthorizationService);
	proto_item_set_generated(it);

	if (authorizationreq->EIM_AReqAuthorizationMode_isUsed) {
		dissect_iso20_EIM_AReqAuthorizationModeType(
			&authorizationreq->EIM_AReqAuthorizationMode,
			tvb, pinfo, subtree,
			ett_struct_iso20_EIM_AReqAuthorizationModeType,
			"EIM_AReqAuthorizationMode");
	}

	if (authorizationreq->PnC_AReqAuthorizationMode_isUsed) {
		dissect_iso20_PnC_AReqAuthorizationModeType(
			&authorizationreq->PnC_AReqAuthorizationMode,
			tvb, pinfo, subtree,
			ett_struct_iso20_PnC_AReqAuthorizationModeType,
			"PnC_AReqAuthorizationMode");
	}

	return;
}

static void
dissect_iso20_AuthorizationResType(
	const struct iso20_AuthorizationResType *authorizationres,
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

	dissect_iso20_MessageHeaderType(&authorizationres->Header,
		tvb, pinfo, subtree,
		ett_struct_iso20_MessageHeaderType, "Header");

	it = proto_tree_add_uint(subtree,
		hf_struct_iso20_AuthorizationResType_ResponseCode,
		tvb, 0, 0, authorizationres->ResponseCode);
	proto_item_set_generated(it);

	it = proto_tree_add_uint(subtree,
		hf_struct_iso20_AuthorizationResType_EVSEProcessing,
		tvb, 0, 0, authorizationres->EVSEProcessing);
	proto_item_set_generated(it);

	return;
}


static void
dissect_iso20_ServiceDiscoveryReqType(
	const struct iso20_ServiceDiscoveryReqType *req,
	tvbuff_t *tvb,
	packet_info *pinfo,
	proto_tree *tree,
	gint idx,
	const char *subtree_name)
{
	proto_tree *subtree;

	subtree = proto_tree_add_subtree(tree,
		tvb, 0, 0, idx, NULL, subtree_name);

	dissect_iso20_MessageHeaderType(&req->Header,
		tvb, pinfo, subtree,
		ett_struct_iso20_MessageHeaderType, "Header");

	if (req->SupportedServiceIDs_isUsed) {
		dissect_iso20_ServiceIDListType(
			&req->SupportedServiceIDs,
			tvb, pinfo, subtree,
			ett_struct_iso20_ServiceIDListType,
			"SupportedServiceIDs");
	}

	return;
}

static void
dissect_iso20_ServiceDiscoveryResType(
	const struct iso20_ServiceDiscoveryResType *res,
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

	dissect_iso20_MessageHeaderType(&res->Header,
		tvb, pinfo, subtree,
		ett_struct_iso20_MessageHeaderType, "Header");

	it = proto_tree_add_uint(subtree,
		hf_struct_iso20_ServiceDiscoveryResType_ResponseCode,
		tvb, 0, 0, res->ResponseCode);
	proto_item_set_generated(it);

	it = proto_tree_add_int(subtree,
		hf_struct_iso20_ServiceDiscoveryResType_ServiceRenegotiationSupported,
		tvb, 0, 0, res->ServiceRenegotiationSupported);
	proto_item_set_generated(it);

	dissect_iso20_ServiceListType(
		&res->EnergyTransferServiceList,
		tvb, pinfo, subtree,
		ett_struct_iso20_ServiceListType,
		"EnergyTransferServiceList");

	if (res->VASList_isUsed) {
		dissect_iso20_ServiceListType(
			&res->VASList,
			tvb, pinfo, subtree,
			ett_struct_iso20_ServiceListType,
			"VASList");
	}

	return;
}

static void
dissect_iso20_ServiceDetailReqType(
	const struct iso20_ServiceDetailReqType *req,
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

	dissect_iso20_MessageHeaderType(&req->Header,
		tvb, pinfo, subtree,
		ett_struct_iso20_MessageHeaderType, "Header");

	it = proto_tree_add_uint(subtree,
		hf_struct_iso20_ServiceDetailReqType_ServiceID,
		tvb, 0, 0, req->ServiceID);
	proto_item_set_generated(it);

	return;
}

static void
dissect_iso20_ServiceDetailResType(
	const struct iso20_ServiceDetailResType *res,
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

	dissect_iso20_MessageHeaderType(&res->Header,
		tvb, pinfo, subtree,
		ett_struct_iso20_MessageHeaderType, "Header");

	it = proto_tree_add_uint(subtree,
		hf_struct_iso20_ServiceDetailResType_ResponseCode,
		tvb, 0, 0, res->ResponseCode);
	proto_item_set_generated(it);

	it = proto_tree_add_uint(subtree,
		hf_struct_iso20_ServiceDetailResType_ServiceID,
		tvb, 0, 0, res->ServiceID);
	proto_item_set_generated(it);

	dissect_iso20_ServiceParameterListType(
		&res->ServiceParameterList,
		tvb, pinfo, subtree,
		ett_struct_iso20_ServiceParameterListType,
		"ServiceParameterList");

	return;
}


static void
dissect_iso20_ServiceSelectionReqType(
	const struct iso20_ServiceSelectionReqType *req,
	tvbuff_t *tvb,
	packet_info *pinfo,
	proto_tree *tree,
	gint idx,
	const char *subtree_name)
{
	proto_tree *subtree;

	subtree = proto_tree_add_subtree(tree,
		tvb, 0, 0, idx, NULL, subtree_name);

	dissect_iso20_MessageHeaderType(&req->Header,
		tvb, pinfo, subtree,
		ett_struct_iso20_MessageHeaderType, "Header");

	dissect_iso20_SelectedServiceType(&req->SelectedEnergyTransferService,
		tvb, pinfo, subtree,
		ett_struct_iso20_SelectedServiceType,
		"SelectedEnergyTransferService");

	if (req->SelectedVASList_isUsed) {
		dissect_iso20_SelectedServiceListType(&req->SelectedVASList,
			tvb, pinfo, subtree,
			ett_struct_iso20_SelectedServiceListType,
			"SelectedVASList");
	}

	return;
}

static void
dissect_iso20_ServiceSelectionResType(
	const struct iso20_ServiceSelectionResType *res,
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

	dissect_iso20_MessageHeaderType(&res->Header,
		tvb, pinfo, subtree,
		ett_struct_iso20_MessageHeaderType, "Header");

	it = proto_tree_add_uint(subtree,
		hf_struct_iso20_ServiceSelectionResType_ResponseCode,
		tvb, 0, 0, res->ResponseCode);
	proto_item_set_generated(it);

	return;
}


static void
dissect_iso20_ScheduleExchangeReqType(
	const struct iso20_ScheduleExchangeReqType *req,
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

	dissect_iso20_MessageHeaderType(&req->Header,
		tvb, pinfo, subtree,
		ett_struct_iso20_MessageHeaderType, "Header");

	it = proto_tree_add_uint(subtree,
		hf_struct_iso20_ScheduleExchangeReqType_MaximumSupportingPoints,
		tvb, 0, 0, req->MaximumSupportingPoints);
	proto_item_set_generated(it);

	if (req->Dynamic_SEReqControlMode_isUsed) {
		dissect_iso20_Dynamic_SEReqControlModeType(
			&req->Dynamic_SEReqControlMode,
			tvb, pinfo, subtree,
			ett_struct_iso20_Dynamic_SEReqControlModeType,
			"Dynamic_SEReqControlMode");
	}

	if (req->Scheduled_SEReqControlMode_isUsed) {
		dissect_iso20_Scheduled_SEReqControlModeType(
			&req->Scheduled_SEReqControlMode,
			tvb, pinfo, subtree,
			ett_struct_iso20_Scheduled_SEReqControlModeType,
			"Scheduled_SEReqControlMode");
	}

	return;
}

static void
dissect_iso20_ScheduleExchangeResType(
	const struct iso20_ScheduleExchangeResType *res,
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

	dissect_iso20_MessageHeaderType(&res->Header,
		tvb, pinfo, subtree,
		ett_struct_iso20_MessageHeaderType, "Header");

	it = proto_tree_add_uint(subtree,
		hf_struct_iso20_ScheduleExchangeResType_ResponseCode,
		tvb, 0, 0, res->ResponseCode);
	proto_item_set_generated(it);

	it = proto_tree_add_uint(subtree,
		hf_struct_iso20_ScheduleExchangeResType_EVSEProcessing,
		tvb, 0, 0, res->EVSEProcessing);
	proto_item_set_generated(it);

	it = proto_tree_add_uint(subtree,
		hf_struct_iso20_ScheduleExchangeResType_GoToPause,
		tvb, 0, 0, res->GoToPause);
	proto_item_set_generated(it);

	if (res->Dynamic_SEResControlMode_isUsed) {
		dissect_iso20_Dynamic_SEResControlModeType(
			&res->Dynamic_SEResControlMode,
			tvb, pinfo, subtree,
			ett_struct_iso20_Dynamic_SEResControlModeType,
			"Dynamic_SEResControlMode");
	}

	if (res->Scheduled_SEResControlMode_isUsed) {
		dissect_iso20_Scheduled_SEResControlModeType(
			&res->Scheduled_SEResControlMode,
			tvb, pinfo, subtree,
			ett_struct_iso20_Scheduled_SEResControlModeType,
			"Scheduled_SEResControlMode");
	}

	return;
}


static void
dissect_iso20_PowerDeliveryReqType(
	const struct iso20_PowerDeliveryReqType *powerdeliveryreq,
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

	dissect_iso20_MessageHeaderType(&powerdeliveryreq->Header,
		tvb, pinfo, subtree,
		ett_struct_iso20_MessageHeaderType, "Header");

	it = proto_tree_add_uint(subtree,
		hf_struct_iso20_PowerDeliveryReqType_EVProcessing,
		tvb, 0, 0, powerdeliveryreq->EVProcessing);
	proto_item_set_generated(it);

	it = proto_tree_add_uint(subtree,
		hf_struct_iso20_PowerDeliveryReqType_ChargeProgress,
		tvb, 0, 0, powerdeliveryreq->ChargeProgress);
	proto_item_set_generated(it);

	if (powerdeliveryreq->EVPowerProfile_isUsed) {
		dissect_iso20_EVPowerProfileType(
			&powerdeliveryreq->EVPowerProfile,
			tvb, pinfo, subtree,
			ett_struct_iso20_EVPowerProfileType,
			"EVPowerProfile");
	}

	if (powerdeliveryreq->BPT_ChannelSelection_isUsed) {
		it = proto_tree_add_uint(subtree,
			hf_struct_iso20_PowerDeliveryReqType_BPT_ChannelSelection,
			tvb, 0, 0, powerdeliveryreq->BPT_ChannelSelection);
		proto_item_set_generated(it);
	}

	return;
}

static void
dissect_iso20_PowerDeliveryResType(
	const struct iso20_PowerDeliveryResType *powerdeliveryres,
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

	it = proto_tree_add_uint(subtree,
		hf_struct_iso20_PowerDeliveryResType_ResponseCode,
		tvb, 0, 0, powerdeliveryres->ResponseCode);
	proto_item_set_generated(it);

	if (powerdeliveryres->EVSEStatus_isUsed) {
		dissect_iso20_EVSEStatusType(
			&powerdeliveryres->EVSEStatus,
			tvb, pinfo, subtree,
			ett_struct_iso20_EVSEStatusType,
			"EVSEStatus");
	}

	return;
}


static void
dissect_iso20_MeteringConfirmationReqType(
	const struct iso20_MeteringConfirmationReqType *req,
	tvbuff_t *tvb,
	packet_info *pinfo _U_,
	proto_tree *tree,
	gint idx,
	const char *subtree_name)
{
	proto_tree *subtree;

	subtree = proto_tree_add_subtree(tree,
		tvb, 0, 0, idx, NULL, subtree_name);

	dissect_iso20_MessageHeaderType(&req->Header,
		tvb, pinfo, subtree,
		ett_struct_iso20_MessageHeaderType, "Header");

	dissect_iso20_SignedMeteringDataType(
		&req->SignedMeteringData,
		tvb, pinfo, subtree,
		ett_struct_iso20_SignedMeteringDataType,
		"SignedMeteringData");

	return;
}

static void
dissect_iso20_MeteringConfirmationResType(
	const struct iso20_MeteringConfirmationResType
	    *meteringconfirmationres _U_,
	tvbuff_t *tvb _U_,
	packet_info *pinfo _U_,
	proto_tree *tree _U_,
	gint idx _U_,
	const char *subtree_name _U_)
{
	return;
}


static void
dissect_iso20_SessionStopReqType(
	const struct iso20_SessionStopReqType *sessionstopreq,
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

	dissect_iso20_MessageHeaderType(&sessionstopreq->Header,
		tvb, pinfo, subtree,
		ett_struct_iso20_MessageHeaderType, "Header");

	it = proto_tree_add_uint(subtree,
		hf_struct_iso20_SessionStopReqType_ChargingSession,
		tvb, 0, 0, sessionstopreq->ChargingSession);
	proto_item_set_generated(it);

	if (sessionstopreq->EVTerminationCode_isUsed) {
		exi_add_characters(subtree,
			hf_struct_iso20_SessionStopReqType_EVTerminationCode,
			tvb,
			sessionstopreq->EVTerminationCode.characters,
			sessionstopreq->EVTerminationCode.charactersLen,
			sizeof(sessionstopreq->EVTerminationCode.characters));
	}

	if (sessionstopreq->EVTerminationExplanation_isUsed) {
		exi_add_characters(subtree,
			hf_struct_iso20_SessionStopReqType_EVTerminationExplanation,
			tvb,
			sessionstopreq->EVTerminationExplanation.characters,
			sessionstopreq->EVTerminationExplanation.charactersLen,
			sizeof(sessionstopreq->EVTerminationExplanation.characters));
	}

	return;
}

static void
dissect_iso20_SessionStopResType(
	const struct iso20_SessionStopResType *sessionstopres,
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

	dissect_iso20_MessageHeaderType(&sessionstopres->Header,
		tvb, pinfo, subtree,
		ett_struct_iso20_MessageHeaderType, "Header");

	it = proto_tree_add_uint(subtree,
		hf_struct_iso20_SessionStopResType_ResponseCode,
		tvb, 0, 0, sessionstopres->ResponseCode);
	proto_item_set_generated(it);

	return;
}


static void
dissect_iso20_CertificateInstallationReqType(
	const struct iso20_CertificateInstallationReqType
		*certificateinstallationreq,
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

	dissect_iso20_MessageHeaderType(&certificateinstallationreq->Header,
		tvb, pinfo, subtree,
		ett_struct_iso20_MessageHeaderType, "Header");

	dissect_iso20_SignedCertificateChainType(
		&certificateinstallationreq->OEMProvisioningCertificateChain,
		tvb, pinfo, subtree,
		ett_struct_iso20_SignedCertificateChainType,
		"OEMProvisioningCertificateChain");

	dissect_iso20_ListOfRootCertificateIDsType(
		&certificateinstallationreq->ListOfRootCertificateIDs,
		tvb, pinfo, subtree,
		ett_struct_iso20_ListOfRootCertificateIDsType,
		"ListOfRootCertificateIDs");

	it = proto_tree_add_uint(subtree,
		hf_struct_iso20_CertificateInstallationReqType_MaximumContractCertificateChains,
		tvb, 0, 0, certificateinstallationreq->MaximumContractCertificateChains);
	proto_item_set_generated(it);

	if (certificateinstallationreq->PrioritizedEMAIDs_isUsed) {
		dissect_iso20_EMAIDListType(
			&certificateinstallationreq->PrioritizedEMAIDs,
			tvb, pinfo, subtree,
			ett_struct_iso20_EMAIDListType,
			"PrioritizedEMAIDs");
	}

	return;
}

static void
dissect_iso20_CertificateInstallationResType(
	const struct iso20_CertificateInstallationResType
		*certificateinstallationres,
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

	dissect_iso20_MessageHeaderType(&certificateinstallationres->Header,
		tvb, pinfo, subtree,
		ett_struct_iso20_MessageHeaderType, "Header");

	it = proto_tree_add_uint(subtree,
		hf_struct_iso20_CertificateInstallationResType_ResponseCode,
		tvb, 0, 0, certificateinstallationres->ResponseCode);
	proto_item_set_generated(it);

	it = proto_tree_add_uint(subtree,
		hf_struct_iso20_CertificateInstallationResType_EVSEProcessing,
		tvb, 0, 0, certificateinstallationres->EVSEProcessing);
	proto_item_set_generated(it);

	dissect_iso20_CertificateChainType(
		&certificateinstallationres->CPSCertificateChain,
		tvb, pinfo, subtree,
		ett_struct_iso20_CertificateChainType,
		"CPSCertificateChain");

	dissect_iso20_SignedInstallationDataType(
		&certificateinstallationres->SignedInstallationData,
		tvb, pinfo, subtree,
		ett_struct_iso20_SignedInstallationDataType,
		"SignedInstallationData");

	it = proto_tree_add_uint(subtree,
		hf_struct_iso20_CertificateInstallationResType_RemainingContractCertificateChains,
		tvb, 0, 0,
		certificateinstallationres->RemainingContractCertificateChains);
	proto_item_set_generated(it);

	return;
}


static void
dissect_iso20_VehicleCheckInReqType(
	const struct iso20_VehicleCheckInReqType *vehiclecheckinreq,
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

	dissect_iso20_MessageHeaderType(&vehiclecheckinreq->Header,
		tvb, pinfo, subtree,
		ett_struct_iso20_MessageHeaderType, "Header");

	it = proto_tree_add_uint(subtree,
		hf_struct_iso20_VehicleCheckInReqType_EVCheckInStatus,
		tvb, 0, 0, vehiclecheckinreq->EVCheckInStatus);
	proto_item_set_generated(it);

	it = proto_tree_add_uint(subtree,
		hf_struct_iso20_VehicleCheckInReqType_ParkingMethod,
		tvb, 0, 0, vehiclecheckinreq->ParkingMethod);
	proto_item_set_generated(it);

	if (vehiclecheckinreq->VehicleFrame_isUsed) {
		it = proto_tree_add_int(subtree,
			hf_struct_iso20_VehicleCheckInReqType_VehicleFrame,
			tvb, 0, 0, vehiclecheckinreq->VehicleFrame);
		proto_item_set_generated(it);
	}

	if (vehiclecheckinreq->DeviceOffset_isUsed) {
		it = proto_tree_add_int(subtree,
			hf_struct_iso20_VehicleCheckInReqType_DeviceOffset,
			tvb, 0, 0, vehiclecheckinreq->DeviceOffset);
		proto_item_set_generated(it);
	}

	if (vehiclecheckinreq->VehicleTravel_isUsed) {
		it = proto_tree_add_int(subtree,
			hf_struct_iso20_VehicleCheckInReqType_VehicleTravel,
			tvb, 0, 0, vehiclecheckinreq->VehicleTravel);
		proto_item_set_generated(it);
	}

	return;
}

static void
dissect_iso20_VehicleCheckInResType(
	const struct iso20_VehicleCheckInResType *vehiclecheckinres,
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

	dissect_iso20_MessageHeaderType(&vehiclecheckinres->Header,
		tvb, pinfo, subtree,
		ett_struct_iso20_MessageHeaderType, "Header");

	it = proto_tree_add_uint(subtree,
		hf_struct_iso20_VehicleCheckInResType_ResponseCode,
		tvb, 0, 0, vehiclecheckinres->ResponseCode);
	proto_item_set_generated(it);

	if (vehiclecheckinres->ParkingSpace_isUsed) {
		it = proto_tree_add_int(subtree,
			hf_struct_iso20_VehicleCheckInResType_ParkingSpace,
			tvb, 0, 0, vehiclecheckinres->ParkingSpace);
		proto_item_set_generated(it);
	}

	if (vehiclecheckinres->DeviceLocation_isUsed) {
		it = proto_tree_add_int(subtree,
			hf_struct_iso20_VehicleCheckInResType_DeviceLocation,
			tvb, 0, 0, vehiclecheckinres->DeviceLocation);
		proto_item_set_generated(it);
	}

	if (vehiclecheckinres->TargetDistance_isUsed) {
		it = proto_tree_add_int(subtree,
			hf_struct_iso20_VehicleCheckInResType_TargetDistance,
			tvb, 0, 0, vehiclecheckinres->TargetDistance);
		proto_item_set_generated(it);
	}

	return;
}


static void
dissect_iso20_VehicleCheckOutReqType(
	const struct iso20_VehicleCheckOutReqType *vehiclecheckoutreq,
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

	dissect_iso20_MessageHeaderType(&vehiclecheckoutreq->Header,
		tvb, pinfo, subtree,
		ett_struct_iso20_MessageHeaderType, "Header");

	it = proto_tree_add_uint(subtree,
		hf_struct_iso20_VehicleCheckOutReqType_EVCheckOutStatus,
		tvb, 0, 0, vehiclecheckoutreq->EVCheckOutStatus);
	proto_item_set_generated(it);

	it = proto_tree_add_uint64(subtree,
		hf_struct_iso20_VehicleCheckOutReqType_CheckOutTime,
		tvb, 0, 0, vehiclecheckoutreq->CheckOutTime);
	proto_item_set_generated(it);

	return;
}

static void
dissect_iso20_VehicleCheckOutResType(
	const struct iso20_VehicleCheckOutResType *vehiclecheckoutres,
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

	dissect_iso20_MessageHeaderType(&vehiclecheckoutres->Header,
		tvb, pinfo, subtree,
		ett_struct_iso20_MessageHeaderType, "Header");

	it = proto_tree_add_uint(subtree,
		hf_struct_iso20_VehicleCheckOutResType_ResponseCode,
		tvb, 0, 0, vehiclecheckoutres->ResponseCode);
	proto_item_set_generated(it);

	it = proto_tree_add_uint(subtree,
		hf_struct_iso20_VehicleCheckOutResType_EVSECheckOutStatus,
		tvb, 0, 0, vehiclecheckoutres->EVSECheckOutStatus);
	proto_item_set_generated(it);

	return;
}


static void
dissect_v2giso20_document(
	const struct iso20_exiDocument *doc,
	tvbuff_t *tvb,
	packet_info *pinfo,
	proto_tree *tree,
	gint idx,
	const char *subtree_name)
{
	proto_tree *subtree;

	subtree = proto_tree_add_subtree(tree,
		tvb, 0, 0, idx, NULL, subtree_name);

	if (doc->SessionSetupReq_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO,
			"SessionSetupReq");
		dissect_iso20_SessionSetupReqType(
			&doc->SessionSetupReq,
			tvb, pinfo, subtree,
			ett_struct_iso20_SessionSetupReqType,
			"SessionSetupReq");
	}
	if (doc->SessionSetupRes_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO,
			"SessionSetupRes");
		dissect_iso20_SessionSetupResType(
			&doc->SessionSetupRes,
			tvb, pinfo, subtree,
			ett_struct_iso20_SessionSetupResType,
			"SessionSetupRes");
	}

	if (doc->AuthorizationSetupReq_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO,
			"AuthorizationSetupReq");
		dissect_iso20_AuthorizationSetupReqType(
			&doc->AuthorizationSetupReq,
			tvb, pinfo, subtree,
			ett_struct_iso20_AuthorizationSetupReqType,
			"AuthorizationSetupReq");
	}
	if (doc->AuthorizationSetupRes_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO,
			"AuthorizationSetupRes");
		dissect_iso20_AuthorizationSetupResType(
			&doc->AuthorizationSetupRes,
			tvb, pinfo, subtree,
			ett_struct_iso20_AuthorizationSetupResType,
			"AuthorizationSetupRes");
	}

	if (doc->AuthorizationReq_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO,
			"AuthorizationReq");
		dissect_iso20_AuthorizationReqType(
			&doc->AuthorizationReq,
			tvb, pinfo, subtree,
			ett_struct_iso20_AuthorizationReqType,
			"AuthorizationReq");
	}
	if (doc->AuthorizationRes_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO,
			"AuthorizationRes");
		dissect_iso20_AuthorizationResType(
			&doc->AuthorizationRes,
			tvb, pinfo, subtree,
			ett_struct_iso20_AuthorizationResType,
			"AuthorizationRes");
	}

	if (doc->ServiceDiscoveryReq_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO,
			"ServiceDiscoveryReq");
		dissect_iso20_ServiceDiscoveryReqType(
			&doc->ServiceDiscoveryReq,
			tvb, pinfo, subtree,
			ett_struct_iso20_ServiceDiscoveryReqType,
			"ServiceDiscoveryReq");
	}
	if (doc->ServiceDiscoveryRes_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO,
			"ServiceDiscoveryRes");
		dissect_iso20_ServiceDiscoveryResType(
			&doc->ServiceDiscoveryRes,
			tvb, pinfo, subtree,
			ett_struct_iso20_ServiceDiscoveryResType,
			"ServiceDiscoveryRes");
	}

	if (doc->ServiceDetailReq_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO,
			"ServiceDetailReq");
		dissect_iso20_ServiceDetailReqType(
			&doc->ServiceDetailReq,
			tvb, pinfo, subtree,
			ett_struct_iso20_ServiceDetailReqType,
			"ServiceDetailReq");
	}
	if (doc->ServiceDetailRes_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO,
			"ServiceDetailRes");
		dissect_iso20_ServiceDetailResType(
			&doc->ServiceDetailRes,
			tvb, pinfo, subtree,
			ett_struct_iso20_ServiceDetailResType,
			"ServiceDetailRes");
	}

	if (doc->ServiceSelectionReq_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO,
			"ServiceSelectionReq");
		dissect_iso20_ServiceSelectionReqType(
			&doc->ServiceSelectionReq,
			tvb, pinfo, subtree,
			ett_struct_iso20_ServiceSelectionReqType,
			"ServiceSelectionReq");
	}
	if (doc->ServiceSelectionRes_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO,
			"ServiceSelectionRes");
		dissect_iso20_ServiceSelectionResType(
			&doc->ServiceSelectionRes,
			tvb, pinfo, subtree,
			ett_struct_iso20_ServiceSelectionResType,
			"ServiceSelectionRes");
	}

	if (doc->ScheduleExchangeReq_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO,
			"ScheduleExchangeReq");
		dissect_iso20_ScheduleExchangeReqType(
			&doc->ScheduleExchangeReq,
			tvb, pinfo, subtree,
			ett_struct_iso20_ScheduleExchangeReqType,
			"ScheduleExchangeReq");
	}
	if (doc->ScheduleExchangeRes_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO,
			"ScheduleExchangeRes");
		dissect_iso20_ScheduleExchangeResType(
			&doc->ScheduleExchangeRes,
			tvb, pinfo, subtree,
			ett_struct_iso20_ScheduleExchangeResType,
			"ScheduleExchangeRes");
	}

	if (doc->PowerDeliveryReq_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO,
			"PowerDeliveryReq");
		dissect_iso20_PowerDeliveryReqType(
			&doc->PowerDeliveryReq,
			tvb, pinfo, subtree,
			ett_struct_iso20_PowerDeliveryReqType,
			"PowerDeliveryReq");
	}
	if (doc->PowerDeliveryRes_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO,
			"PowerDeliveryRes");
		dissect_iso20_PowerDeliveryResType(
			&doc->PowerDeliveryRes,
			tvb, pinfo, subtree,
			ett_struct_iso20_PowerDeliveryResType,
			"PowerDeliveryRes");
	}

	if (doc->MeteringConfirmationReq_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO,
			"MeteringConfirmationReq");
		dissect_iso20_MeteringConfirmationReqType(
			&doc->MeteringConfirmationReq,
			tvb, pinfo, subtree,
			ett_struct_iso20_MeteringConfirmationReqType,
			"MeteringConfirmationReq");
	}
	if (doc->MeteringConfirmationRes_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO,
			"MeteringConfirmationRes");
		dissect_iso20_MeteringConfirmationResType(
			&doc->MeteringConfirmationRes,
			tvb, pinfo, subtree,
			ett_struct_iso20_MeteringConfirmationResType,
			"MeteringConfirmationRes");
	}

	if (doc->SessionStopReq_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO,
			"SessionStopReq");
		dissect_iso20_SessionStopReqType(
			&doc->SessionStopReq,
			tvb, pinfo, subtree,
			ett_struct_iso20_SessionStopReqType,
			"SessionStopReq");
	}
	if (doc->SessionStopRes_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO,
			"SessionStopRes");
		dissect_iso20_SessionStopResType(
			&doc->SessionStopRes,
			tvb, pinfo, subtree,
			ett_struct_iso20_SessionStopResType,
			"SessionStopRes");
	}

	if (doc->CertificateInstallationReq_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO,
			"CertificateInstallationReq");
		dissect_iso20_CertificateInstallationReqType(
			&doc->CertificateInstallationReq,
			tvb, pinfo, subtree,
			ett_struct_iso20_CertificateInstallationReqType,
			"CertificateInstallationReq");
	}
	if (doc->CertificateInstallationRes_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO,
			"CertificateInstallationRes");
		dissect_iso20_CertificateInstallationResType(
			&doc->CertificateInstallationRes,
			tvb, pinfo, subtree,
			ett_struct_iso20_CertificateInstallationResType,
			"CertificateInstallationRes");
	}

	if (doc->VehicleCheckInReq_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO,
			"VehicleCheckInReq");
		dissect_iso20_VehicleCheckInReqType(
			&doc->VehicleCheckInReq,
			tvb, pinfo, subtree,
			ett_struct_iso20_VehicleCheckInReqType,
			"VehicleCheckInReq");
	}
	if (doc->VehicleCheckInRes_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO,
			"VehicleCheckInRes");
		dissect_iso20_VehicleCheckInResType(
			&doc->VehicleCheckInRes,
			tvb, pinfo, subtree,
			ett_struct_iso20_VehicleCheckInResType,
			"VehicleCheckInRes");
	}

	if (doc->VehicleCheckOutReq_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO,
			"VehicleCheckOutReq");
		dissect_iso20_VehicleCheckOutReqType(
			&doc->VehicleCheckOutReq,
			tvb, pinfo, subtree,
			ett_struct_iso20_VehicleCheckOutReqType,
			"VehicleCheckOutReq");
	}
	if (doc->VehicleCheckOutRes_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO,
			"VehicleCheckOutRes");
		dissect_iso20_VehicleCheckOutResType(
			&doc->VehicleCheckOutRes,
			tvb, pinfo, subtree,
			ett_struct_iso20_VehicleCheckOutResType,
			"VehicleCheckOutRes");
	}

	return;
}

static int
dissect_v2giso20(tvbuff_t *tvb,
		packet_info *pinfo, proto_tree *tree _U_, void *data _U_)
{
	proto_tree *v2giso20_tree;
	size_t size;
	exi_bitstream_t stream;
	int errn;
	struct iso20_exiDocument *exiiso20;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "ISO20");
	/* Clear the info column */
	col_clear(pinfo->cinfo, COL_INFO);

	size = tvb_reported_length(tvb);
	exi_bitstream_init(&stream,
			   tvb_memdup(wmem_packet_scope(), tvb, 0, size),
			   size, 0, NULL);

	exiiso20 = wmem_alloc(pinfo->pool, sizeof(*exiiso20));
	errn = decode_iso20_exiDocument(&stream, exiiso20);
	if (errn != 0) {
		wmem_free(pinfo->pool, exiiso20);
		/* decode failed */
		return 0;
	}

	/*
	 * Everything in ISO20 should come in as a document
	 */
	v2giso20_tree = proto_tree_add_subtree(tree,
		tvb, 0, 0, ett_v2giso20, NULL, "V2G ISO20 Common");

	dissect_v2giso20_document(exiiso20,
		tvb, pinfo, v2giso20_tree,
		ett_v2giso20_document, "Document");

	wmem_free(pinfo->pool, exiiso20);
	return tvb_captured_length(tvb);
}

void
proto_register_v2giso20(void)
{

	static hf_register_info hf[] = {
		/* struct iso20_MessageHeaderType */
		{ &hf_struct_iso20_MessageHeaderType_SessionID,
		  { "SessionID", "v2giso20.struct.messageheader.sessionid",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_struct_iso20_MessageHeaderType_TimeStamp,
		  { "TimeStamp", "v2giso20.struct.messageheader.timestamp",
		    FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso20_SignatureType */
		{ &hf_struct_iso20_SignatureType_Id,
		  { "Id", "v2giso20.struct.signature.id",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso20_SignedInfoType */
		{ &hf_struct_iso20_SignedInfoType_Id,
		  { "Id", "v2giso20.struct.signedinfo.id",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso20_CanonicalizationMethodType */
		{ &hf_struct_iso20_CanonicalizationMethodType_Algorithm,
		  { "Algorithm",
		    "v2giso20.struct.canonicalizationmethod.algorithm",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_struct_iso20_CanonicalizationMethodType_ANY,
		  { "ANY",
		    "v2giso20.struct.canonicalizationmethod.any",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso20_SignatureMethodType */
		{ &hf_struct_iso20_SignatureMethodType_Algorithm,
		  { "Algorithm", "v2giso20.struct.signaturemethod.algorithm",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_struct_iso20_SignatureMethodType_HMACOutputLength,
		  { "HMACOutputLength",
		    "v2giso20.struct.signaturemethod.hmacoutputlength",
		    FT_INT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_struct_iso20_SignatureMethodType_ANY,
		  { "ANY", "v2giso20.struct.signaturemethod.any",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso20_ReferenceType */
		{ &hf_struct_iso20_ReferenceType_Id,
		  { "Id", "v2giso20.struct.reference.id",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_struct_iso20_ReferenceType_Type,
		  { "Type", "v2giso20.struct.reference.type",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_struct_iso20_ReferenceType_URI,
		  { "URI", "v2giso20.struct.reference.uri",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_struct_iso20_ReferenceType_DigestValue,
		  { "DigestValue", "v2giso20.struct.reference.digestvalue",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso20_TransformType */
		{ &hf_struct_iso20_TransformType_Algorithm,
		  { "Algorithm", "v2giso20.struct.transform.algorithm",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_struct_iso20_TransformType_ANY,
		  { "ANY", "v2giso20.struct.transform.any",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_struct_iso20_TransformType_XPath,
		  { "XPath", "v2giso20.struct.transform.xpath",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso20_DigestMethodType */
		{ &hf_struct_iso20_DigestMethodType_Algorithm,
		  { "Algorithm", "v2giso20.struct.digestmethod.algorithm",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_struct_iso20_DigestMethodType_ANY,
		  { "ANY", "v2giso20.struct.digestmethod.any",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso20_SignatureValueType */
		{ &hf_struct_iso20_SignatureValueType_Id,
		  { "Id", "v2giso20.struct.signaturevalue.id",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_struct_iso20_SignatureValueType_CONTENT,
		  { "CONTENT", "v2giso20.struct.signaturevalue.content",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso20_KeyInfoType */
		{ &hf_struct_iso20_KeyInfoType_Id,
		  { "Id", "v2giso20.struct.keyinfo.id",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_struct_iso20_KeyInfoType_KeyName,
		  { "KeyName", "v2giso20.struct.keyinfo.keyname",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_struct_iso20_KeyInfoType_MgmtData,
		  { "MgmtData", "v2giso20.struct.keyinfo.mgmtdata",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_struct_iso20_KeyInfoType_ANY,
		  { "ANY", "v2giso20.struct.keyinfo.any",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso20_KeyValueType */
		{ &hf_struct_iso20_KeyValueType_ANY,
		  { "ANY", "v2giso20.struct.keyvalue.any",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso20_DSAKeyValueType */
		{ &hf_struct_iso20_DSAKeyValueType_P,
		  { "P", "v2giso20.struct.dsakeyvalue.p",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_struct_iso20_DSAKeyValueType_Q,
		  { "Q", "v2giso20.struct.dsakeyvalue.q",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_struct_iso20_DSAKeyValueType_G,
		  { "G", "v2giso20.struct.dsakeyvalue.g",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_struct_iso20_DSAKeyValueType_Y,
		  { "Y", "v2giso20.struct.dsakeyvalue.y",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_struct_iso20_DSAKeyValueType_J,
		  { "J", "v2giso20.struct.dsakeyvalue.j",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_struct_iso20_DSAKeyValueType_Seed,
		  { "Seed", "v2giso20.struct.dsakeyvalue.seed",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_struct_iso20_DSAKeyValueType_PgenCounter,
		  { "PgenCounter", "v2giso20.struct.dsakeyvalue.pgencounter",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso20_RSAKeyValueType */
		{ &hf_struct_iso20_RSAKeyValueType_Modulus,
		  { "Modulus", "v2giso20.struct.rsakeyvalue.modulus",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_struct_iso20_RSAKeyValueType_Exponent,
		  { "Exponent", "v2giso20.struct.rsakeyvalue.exponent",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso20_RetrievalMethodType */
		{ &hf_struct_iso20_RetrievalMethodType_URI,
		  { "URI", "v2giso20.struct.retrievalmethod.uri",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_struct_iso20_RetrievalMethodType_Type,
		  { "Type", "v2giso20.struct.retrievalmethod.type",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso20_X509DataType */
		{ &hf_struct_iso20_X509DataType_X509SKI,
		  { "X509SKI", "v2giso20.struct.x509data.x509ski",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_struct_iso20_X509DataType_X509SubjectName,
		  { "X509SubjectName",
		    "v2giso20.struct.x509data.x509subjectname",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_struct_iso20_X509DataType_X509Certificate,
		  { "X509Certificate",
		    "v2giso20.struct.x509data.x509certificate",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_struct_iso20_X509DataType_X509CRL,
		  { "X509CRL", "v2giso20.struct.x509data.x509crl",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_struct_iso20_X509DataType_ANY,
		  { "ANY", "v2giso20.struct.x509data.any",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso20_X509IssuerSerialType */
		{ &hf_struct_iso20_X509IssuerSerialType_X509IssuerName,
		  { "X509IssuerName",
		    "v2giso20.struct.x509issuerserial.x509issuername",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_struct_iso20_X509IssuerSerialType_X509SerialNumber,
		  { "X509SerialNumber",
		    "v2giso20.struct.x509issuerserial.x509serialnumber",
		    FT_INT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso20_PGPDataType */
		{ &hf_struct_iso20_PGPDataType_PGPKeyID,
		  { "PGPKeyID", "v2giso20.struct.pgpdata.pgpkeyid",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_struct_iso20_PGPDataType_PGPKeyPacket,
		  { "PGPKeyPacket", "v2giso20.struct.pgpdata.pgpkeypacket",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_struct_iso20_PGPDataType_ANY,
		  { "ANY", "v2giso20.struct.pgpdata.any",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso20_SPKIDataType */
		{ &hf_struct_iso20_SPKIDataType_SPKISexp,
		  { "SPKISexp", "v2giso20.struct.spkidata.spkisexp",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_struct_iso20_SPKIDataType_ANY,
		  { "ANY", "v2giso20.struct.spkidata.any",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso20_ObjectType */
		{ &hf_struct_iso20_ObjectType_Id,
		  { "Id", "v2giso20.struct.object.id",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_struct_iso20_ObjectType_MimeType,
		  { "MimeType", "v2giso20.struct.object.mimetype",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_struct_iso20_ObjectType_Encoding,
		  { "Encoding", "v2giso20.struct.object.encoding",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_struct_iso20_ObjectType_ANY,
		  { "ANY", "v2giso20.struct.object.any",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso20_SessionSetupReqType */
		{ &hf_struct_iso20_SessionSetupReqType_EVCCID,
		  { "EVCCID",
		    "v2giso20.struct.paymentdetailsreq.evccid",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		/* struct iso20_SessionSetupResType */
		{ &hf_struct_iso20_SessionSetupResType_ResponseCode,
		  { "ResponseCode",
		    "v2giso20.struct.sessionsetupres.responsecode",
		    FT_UINT16, BASE_DEC,
		    VALS(v2giso20_enum_iso20_responseCodeType_names),
		    0x0, NULL, HFILL }
		},
		{ &hf_struct_iso20_SessionSetupResType_EVSEID,
		  { "EVSEID",
		    "v2giso20.struct.paymentdetailsres.evseid",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso20_AuthorizationSetupReqType */
		/* struct iso20_AuthorizationSetupResType */
		{ &hf_struct_iso20_AuthorizationSetupResType_ResponseCode,
		  { "ResponseCode",
		    "v2giso20.struct.authorizationsetupres.responsecode",
		    FT_UINT16, BASE_DEC,
		    VALS(v2giso20_enum_iso20_responseCodeType_names),
		    0x0, NULL, HFILL }
		},
		{ &hf_struct_iso20_AuthorizationSetupResType_Authorization,
		  { "ResponseCode",
		    "v2giso20.struct.authorizationsetupres.authorization",
		    FT_UINT16, BASE_DEC,
		    VALS(v2giso20_enum_iso20_authorizationType_names),
		    0x0, NULL, HFILL }
		},
		{ &hf_struct_iso20_AuthorizationSetupResType_CertificateInstallationService,
		  { "CertificateInstallationService",
		    "v2giso20.struct.authorizationsetupres.certificateinstallationservice",
		    FT_INT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso20_PnC_ASResAuthorizationModeType */
		{ &hf_struct_iso20_PnC_ASResAuthorizationModeType_GenChallenge,
		  { "GenChallenge",
		    "v2giso20.struct.pnc_asresauthorizationmode.genchallenge",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso20_SupportedProvidersListType */
		{ &hf_struct_iso20_SupportedProvidersListType_ProviderID,
		  { "ProviderID",
		    "v2giso20.struct.supportedproviderslist.providerid",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso20_AuthorizationReqType */
		{ &hf_struct_iso20_AuthorizationReqType_SelectedAuthorizationService,
		  { "SelectedAuthorizationService",
		    "v2giso20.struct.authorizationreq.selectedauthorizationservice",
		    FT_UINT16, BASE_DEC,
		    VALS(v2giso20_enum_iso20_authorizationType_names),
		    0x0, NULL, HFILL }
		},
		/* struct iso20_AuthorizationResType */
		{ &hf_struct_iso20_AuthorizationResType_ResponseCode,
		  { "ResponseCode",
		    "v2giso20.struct.authorizationres.responsecode",
		    FT_UINT16, BASE_DEC,
		    VALS(v2giso20_enum_iso20_responseCodeType_names),
		    0x0, NULL, HFILL }
		},
		{ &hf_struct_iso20_AuthorizationResType_EVSEProcessing,
		  { "EVSEProcessing",
		    "v2giso20.struct.authorizationres.evseprocessing",
		    FT_UINT16, BASE_DEC,
		    VALS(v2giso20_enum_iso20_processingType_names),
		    0x0, NULL, HFILL }
		},

		/* struct iso20_PnC_AReqAuthorizationModeType */
		{ &hf_struct_iso20_PnC_AReqAuthorizationModeType_Id,
		  { "Id",
		    "v2giso20.struct.pnc_areqauthorizationmode.id",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_struct_iso20_PnC_AReqAuthorizationModeType_GenChallenge,
		  { "GenChallenge",
		    "v2giso20.struct.pnc_areqauthorizationmode.genchallenge",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso20_ContractCertificateChainType */
		{ &hf_struct_iso20_ContractCertificateChainType_Certificate,
		  { "Certificate",
		    "v2giso20.struct.contractcertificatechain.certificate",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso20_SubCertificatesType */
		{ &hf_struct_iso20_SubCertificatesType_Certificate,
		  { "Certificate",
		    "v2giso20.struct.subcertificates.certificate",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso20_ServiceDiscoveryReqType */
		/* struct iso20_ServiceDiscoveryResType */
		{ &hf_struct_iso20_ServiceDiscoveryResType_ResponseCode,
		  { "ResponseCode",
		    "v2giso20.struct.servicediscoveryres.responsecode",
		    FT_UINT16, BASE_DEC,
		    VALS(v2giso20_enum_iso20_responseCodeType_names),
		    0x0, NULL, HFILL }
		},
		{ &hf_struct_iso20_ServiceDiscoveryResType_ServiceRenegotiationSupported,
		  { "ServiceRenegotiationSupported",
		    "v2giso20.struct.servicediscoveryres.servicerenegotiationsupported",
		    FT_INT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso20_ServiceIDListType */
		{ &hf_struct_iso20_ServiceIDListType_ServiceID,
		  { "ServiceID",
		    "vgiso20.struct.serviceidlist.serviceid",
		    FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso20_ServiceType */
		{ &hf_struct_iso20_ServiceType_ServiceID,
		  { "ServiceID", "vgiso20.struct.service.serviceid",
		    FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_struct_iso20_ServiceType_FreeService,
		  { "FreeService", "vgiso20.struct.service.freeservice",
		    FT_INT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso20_ServiceDetailReqType */
		{ &hf_struct_iso20_ServiceDetailReqType_ServiceID,
		  { "ServiceID",
		    "v2giso20.struct.servicedetailreq.serviceid",
		    FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		/* struct iso20_ServiceDetailResType */
		{ &hf_struct_iso20_ServiceDetailResType_ResponseCode,
		  { "ResponseCode",
		    "v2giso20.struct.servicedetailres.responsecode",
		    FT_UINT16, BASE_DEC,
		    VALS(v2giso20_enum_iso20_responseCodeType_names),
		    0x0, NULL, HFILL }
		},
		{ &hf_struct_iso20_ServiceDetailResType_ServiceID,
		  { "ServiceID",
		    "v2giso20.struct.servicedetailres.serviceid",
		    FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso20_ParameterSetType */
		{ &hf_struct_iso20_ParameterSetType_ParameterSetID,
		  { "ParameterSetID",
		    "v2giso20.struct.parameterset.parametersetid",
		    FT_INT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso20_ParameterType */
		{ &hf_struct_iso20_ParameterType_Name,
		  { "Name", "v2giso20.struct.parameter.name",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_struct_iso20_ParameterType_boolValue,
		  { "boolValue", "v2giso20.struct.parameter.boolvalue",
		    FT_INT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_struct_iso20_ParameterType_byteValue,
		  { "byteValue", "v2giso20.struct.parameter.bytevalue",
		    FT_INT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_struct_iso20_ParameterType_shortValue,
		  { "shortValue", "v2giso20.struct.parameter.shortvalue",
		    FT_INT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_struct_iso20_ParameterType_intValue,
		  { "intValue", "v2giso20.struct.parameter.intvalue",
		    FT_INT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_struct_iso20_ParameterType_finiteString,
		  { "stringValue", "v2giso20.struct.parameter.finiteString",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso20_RationalNumberType */
		{ &hf_struct_iso20_RationalNumberType_Exponent,
		  { "Exponent", "v2giso20.struct.rationalnumber.exponent",
		    FT_INT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_struct_iso20_RationalNumberType_Value,
		  { "Value", "v2giso20.struct.rationalnumber.value",
		    FT_INT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso20_PowerScheduleEntryType */
		{ &hf_struct_iso20_PowerScheduleEntryType_Duration,
		  { "Duration",
		    "v2giso20.struct.powerscheduleentry.duration",
		    FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso20_EVPowerScheduleEntryType */
		{ &hf_struct_iso20_EVPowerScheduleEntryType_Duration,
		  { "Duration",
		    "v2giso20.struct.evpowerscheduleentry.duration",
		    FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso20_ServiceSelectionReqType */
		/* struct iso20_ServiceSelectionResType */
		{ &hf_struct_iso20_ServiceSelectionResType_ResponseCode,
		  { "ResponseCode",
		    "v2giso20.struct.serviceselectionres.responsecode",
		    FT_UINT16, BASE_DEC,
		    VALS(v2giso20_enum_iso20_responseCodeType_names),
		    0x0, NULL, HFILL }
		},

		/* struct iso20_PowerDeliveryReqType */
		{ &hf_struct_iso20_PowerDeliveryReqType_EVProcessing,
		  { "EVProcessing",
		    "v2giso20.struct.powerdeliveryreq.evoperation",
		    FT_UINT16, BASE_DEC,
		    VALS(v2giso20_enum_iso20_processingType_names),
		    0x0, NULL, HFILL }
		},
		{ &hf_struct_iso20_PowerDeliveryReqType_ChargeProgress,
		  { "ChargeProgress",
		    "v2giso20.struct.powerdeliveryreq.chargeprogress",
		    FT_UINT16, BASE_DEC,
		    VALS(v2giso20_enum_iso20_chargeProgressType_names),
		    0x0, NULL, HFILL }
		},
		{ &hf_struct_iso20_PowerDeliveryReqType_BPT_ChannelSelection,
		  { "BPT_ChannelSelection",
		    "v2giso20.struct.powerdeliveryreq.bpt_channelselection",
		    FT_UINT16, BASE_DEC,
		    VALS(v2giso20_enum_iso20_channelSelectionType_names),
		    0x0, NULL, HFILL }
		},
		/* struct iso20_PowerDeliveryResType */
		{ &hf_struct_iso20_PowerDeliveryResType_ResponseCode,
		  { "ResponseCode",
		    "v2giso20.struct.powerdeliveryres.responsecode",
		    FT_UINT16, BASE_DEC,
		    VALS(v2giso20_enum_iso20_responseCodeType_names),
		    0x0, NULL, HFILL }
		},
		{ &hf_struct_iso20_PowerDeliveryResType_EVSEProcessing,
		  { "EVSEProcessing",
		    "v2giso20.struct.powerdeliveryres.evseprocessing",
		    FT_UINT16, BASE_DEC,
		    VALS(v2giso20_enum_iso20_processingType_names),
		    0x0, NULL, HFILL }
		},


		/* struct iso20_EVSEStatusType */
		{ &hf_struct_iso20_EVSEStatusType_NotificationMaxDelay,
		  { "NotificationMaxDelay",
		    "v2giso20.struct.evsestatus.notificationmaxdelay",
		    FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_struct_iso20_EVSEStatusType_EVSENotification,
		  { "EVSENotification",
		    "v2giso20.struct.evsestatus.evsenotification",
		    FT_UINT16, BASE_DEC,
		    VALS(v2giso20_enum_iso20_evseNotificationType_names),
		    0x0, NULL, HFILL }
		},

		/* struct iso20_DetailedTaxType */
		{ &hf_struct_iso20_DetailedTaxType_TaxRuleID,
		  { "TaxRuleID",
		    "v2giso20.struct.detailedtax.taxruleid",
		    FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso20_ReceiptType */
		{ &hf_struct_iso20_ReceiptType_TimeAnchor,
		  { "TimeAnchor",
		    "v2giso20.struct.receipt.timeanchor",
		    FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso20_MeasurementDataListType */
		{ &hf_struct_iso20_MeasurementDataListType_MeasurementData,
		  { "MeasurementData",
		    "v2giso20.struct.measurementdatalist.measurementdata",
		    FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso20_CertificateChainType */
		{ &hf_struct_iso20_CertificateChainType_Id,
		  { "Id", "v2giso20.struct.certificatechain.id",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_struct_iso20_CertificateChainType_Certificate,
		  { "Certificate",
		    "v2giso20.struct.certificatechain.certificate",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso20_SignedCertificateChainType */
		{ &hf_struct_iso20_SignedCertificateChainType_Id,
		  { "Id", "v2giso20.struct.signedcertificatechain.id",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_struct_iso20_SignedCertificateChainType_Certificate,
		  { "Certificate",
		    "v2giso20.struct.signedcertificatechain.certificate",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso20_EMAIDListType */
		{ &hf_struct_iso20_EMAIDListType_EMAID,
		  { "Id", "v2giso20.struct.emaidlist.emaid",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso20_RelativeTimeIntervalType */
		{ &hf_struct_iso20_RelativeTimeIntervalType_start,
		  { "start",
		    "v2giso20.struct.relativetimeinterval.start",
		    FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_struct_iso20_RelativeTimeIntervalType_duration,
		  { "duration",
		    "v2giso20.struct.relativetimeinterval.start",
		    FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso20_SAScheduleTupleType */
		{ &hf_struct_iso20_SAScheduleTupleType_SAScheduleTupleID,
		  { "SAScheduleTupleID",
		    "v2giso20.struct.sascheduletuple.sascheduletupleid",
		    FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso20_SelectedServiceType */
		{ &hf_struct_iso20_SelectedServiceType_ServiceID,
		  { "ServiceID", "vgiso20.struct.selectedservice.serviceid",
		    FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_struct_iso20_SelectedServiceType_ParameterSetID,
		  { "ParameterSetID",
		    "vgiso20.struct.selectedservice.parametersetid",
		    FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso20_VehicleCheckOutReqType */
		{ &hf_struct_iso20_VehicleCheckOutReqType_EVCheckOutStatus,
		  { "EVCheckOutStatus",
		    "v2giso20.struct.vehichlecheckoutreq.evcheckoutstatus",
		    FT_UINT16, BASE_DEC,
		    VALS(v2giso20_enum_iso20_evCheckOutStatusType_names),
		    0x0, NULL, HFILL }
		},
		{ &hf_struct_iso20_VehicleCheckOutReqType_CheckOutTime,
		  { "CheckOutTime",
		    "v2giso20.struct.vehichlecheckoutreq.checkouttime",
		    FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		/* struct iso20_VehicleCheckOutResType */
		{ &hf_struct_iso20_VehicleCheckOutResType_ResponseCode,
		  { "ResponseCode",
		    "v2giso20.struct.vehichlecheckoutres.responsecode",
		    FT_UINT16, BASE_DEC,
		    VALS(v2giso20_enum_iso20_responseCodeType_names),
		    0x0, NULL, HFILL }
		},
		{ &hf_struct_iso20_VehicleCheckOutResType_EVSECheckOutStatus,
		  { "EVSECheckOutStatus",
		    "v2giso20.struct.vehichlecheckoutres.evsecheckoutstatus",
		    FT_UINT16, BASE_DEC,
		    VALS(v2giso20_enum_iso20_evseCheckOutStatusType_names),
		    0x0, NULL, HFILL }
		},

		/* struct iso20_VehicleCheckInReqType */
		{ &hf_struct_iso20_VehicleCheckInReqType_EVCheckInStatus,
		  { "EVCheckInStatus",
		    "v2giso20.struct.vehichlecheckinreq.evcheckinstatus",
		    FT_UINT16, BASE_DEC,
		    VALS(v2giso20_enum_iso20_evCheckInStatusType_names),
		    0x0, NULL, HFILL }
		},
		{ &hf_struct_iso20_VehicleCheckInReqType_ParkingMethod,
		  { "ParkingMethod",
		    "v2giso20.struct.vehichlecheckinreq.parkingmethod",
		    FT_UINT16, BASE_DEC,
		    VALS(v2giso20_enum_iso20_parkingMethodType_names),
		    0x0, NULL, HFILL }
		},
		/* struct iso20_VehicleCheckInResType */
		{ &hf_struct_iso20_VehicleCheckInResType_ResponseCode,
		  { "ResponseCode",
		    "v2giso20.struct.vehichlecheckinres.responsecode",
		    FT_UINT16, BASE_DEC,
		    VALS(v2giso20_enum_iso20_responseCodeType_names),
		    0x0, NULL, HFILL }
		},
		{ &hf_struct_iso20_VehicleCheckInResType_ParkingSpace,
		  { "ParkingSpace",
		    "v2giso20.struct.vehichlecheckinres.parkingspace",
		    FT_INT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_struct_iso20_VehicleCheckInResType_DeviceLocation,
		  { "DeviceLocation",
		    "v2giso20.struct.vehichlecheckinres.devicelocation",
		    FT_INT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_struct_iso20_VehicleCheckInResType_TargetDistance,
		  { "TargetDistance",
		    "v2giso20.struct.vehichlecheckinres.targetdistance",
		    FT_INT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso20_PowerDemandReqType */
		/* struct iso20_PowerDemandResType */
		{ &hf_struct_iso20_PowerDemandResType_ResponseCode,
		  { "ResponseCode",
		    "v2giso20.struct.powerdemandres.responsecode",
		    FT_UINT16, BASE_DEC,
		    VALS(v2giso20_enum_iso20_responseCodeType_names),
		    0x0, NULL, HFILL }
		},
		{ &hf_struct_iso20_PowerDemandResType_EVSEID,
		  { "EVSEID",
		    "v2giso20.struct.powerdemandres.evseid",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_struct_iso20_PowerDemandResType_SAScheduleTupleID,
		  { "SAScheduleTupleID",
		    "v2giso20.struct.powerdemandres.sascheduletupleid",
		    FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_struct_iso20_PowerDemandResType_ReceiptRequired,
		  { "ReceiptRequired",
		    "v2giso20.struct.powerdemandres.receiptrequired",
		    FT_INT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso20_CurrentDemandReqType */
		/* struct iso20_CurrentDemandResType */
		{ &hf_struct_iso20_CurrentDemandResType_ResponseCode,
		  { "ResponseCode",
		    "v2giso20.struct.currentdemandres.responsecode",
		    FT_UINT16, BASE_DEC,
		    VALS(v2giso20_enum_iso20_responseCodeType_names),
		    0x0, NULL, HFILL }
		},
		{ &hf_struct_iso20_CurrentDemandResType_EVSEPowerLimitAchieved,
		  { "EVSEPowerLimitAchieved",
		    "v2giso20.struct.currentdemandres.evsepowerlimitachieved",
		    FT_INT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_struct_iso20_CurrentDemandResType_EVSECurrentLimitAchieved,
		  { "EVSECurrentLimitAchieved",
		    "v2giso20.struct.currentdemandres.evsecurrentlimitachieved",
		    FT_INT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_struct_iso20_CurrentDemandResType_EVSEID,
		  { "EVSEID",
		    "v2giso20.struct.currentdemandres.evseid",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_struct_iso20_CurrentDemandResType_SAScheduleTupleID,
		  { "SAScheduleTupleID",
		    "v2giso20.struct.currentdemandres.sascheduletupleid",
		    FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_struct_iso20_CurrentDemandResType_ReceiptRequired,
		  { "ReceiptRequired",
		    "v2giso20.struct.currentdemandres.receiptrequired",
		    FT_INT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso20_CertificateInstallationReqType */
		{ &hf_struct_iso20_CertificateInstallationReqType_MaximumContractCertificateChains,
		  { "MaximumContractCertificateChains",
		    "v2giso20.struct.certificateinstallationreq.maximumcontractcertificatechains",
		    FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		/* struct iso20_CertificateInstallationResType */
		{ &hf_struct_iso20_CertificateInstallationResType_ResponseCode,
		  { "ResponseCode",
		    "v2giso20.struct.certificateinstallationres.responsecode",
		    FT_UINT16, BASE_DEC,
		    VALS(v2giso20_enum_iso20_responseCodeType_names),
		    0x0, NULL, HFILL }
		},

		/* struct iso20_SessionStopReqType */
		{ &hf_struct_iso20_SessionStopReqType_ChargingSession,
		  { "ChargingSession",
		    "v2giso20.struct.sessionstopreq.chargingsession",
		    FT_UINT16, BASE_DEC,
		    VALS(v2giso20_enum_iso20_chargingSessionType_names),
		    0x0, NULL, HFILL }
		},
		/* struct iso20_SessionStopResType */
		{ &hf_struct_iso20_SessionStopResType_ResponseCode,
		  { "ResponseCode",
		    "v2giso20.struct.sessionstopres.responsecode",
		    FT_UINT16, BASE_DEC,
		    VALS(v2giso20_enum_iso20_responseCodeType_names),
		    0x0, NULL, HFILL }
		},

		/* struct iso20_MeteringReceiptReqType */
		{ &hf_struct_iso20_MeteringReceiptReqType_Id,
		  { "Id", "v2giso20.struct.meteringreceiptreq.id",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_struct_iso20_MeteringReceiptReqType_SessionID,
		  { "SessionID",
		    "v2giso20.struct.meteringreceiptreq.sessionid",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_struct_iso20_MeteringReceiptReqType_SAScheduleTupleID,
		  { "SAScheduleTupleID",
		    "v2giso20.struct.meteringreceiptreq.sascheduletupleid",
		    FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		/* struct iso20_MeteringReceiptResType */
		{ &hf_struct_iso20_MeteringReceiptResType_ResponseCode,
		  { "ResponseCode",
		    "v2giso20.struct.meteringreceiptres.responsecode",
		    FT_UINT16, BASE_DEC,
		    VALS(v2giso20_enum_iso20_responseCodeType_names),
		    0x0, NULL, HFILL }
		},

		/* struct iso20_ChargeParameterDiscoveryReqType */
		{ &hf_struct_iso20_ChargeParameterDiscoveryReqType_MaxSupportingPoints,
		  { "MaxSupportingPoints",
		    "v2giso20.struct.chargeparameterdiscoveryreq.maxsupportingpoints",
		    FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		/* struct iso20_ChargeParameterDiscoveryResType */
		{ &hf_struct_iso20_ChargeParameterDiscoveryResType_ResponseCode,
		  { "ResponseCode",
		    "v2giso20.struct.chargeparameterdiscoveryres.responsecode",
		    FT_UINT16, BASE_DEC,
		    VALS(v2giso20_enum_iso20_responseCodeType_names),
		    0x0, NULL, HFILL }
		},
		{ &hf_struct_iso20_ChargeParameterDiscoveryResType_EVSEProcessing,
		  { "EVSEProcessing",
		    "v2giso20.struct.chargeparameterdiscoveryres.evseprocessing",
		    FT_UINT16, BASE_DEC,
		    VALS(v2giso20_enum_iso20_processingType_names),
		    0x0, NULL, HFILL }
		},
	};

	static gint *ett[] = {
		&ett_v2giso20,
		&ett_v2giso20_document,
		&ett_v2giso20_array,
		&ett_v2giso20_array_i,
		&ett_v2giso20_asn1,

		&ett_struct_iso20_SessionSetupReqType,
		&ett_struct_iso20_SessionSetupResType,
		&ett_struct_iso20_AuthorizationSetupReqType,
		&ett_struct_iso20_AuthorizationSetupResType,
		&ett_struct_iso20_AuthorizationReqType,
		&ett_struct_iso20_AuthorizationResType,
		&ett_struct_iso20_ServiceDiscoveryReqType,
		&ett_struct_iso20_ServiceDiscoveryResType,
		&ett_struct_iso20_ServiceDetailReqType,
		&ett_struct_iso20_ServiceDetailResType,
		&ett_struct_iso20_ServiceSelectionReqType,
		&ett_struct_iso20_ServiceSelectionResType,
		&ett_struct_iso20_ScheduleExchangeReqType,
		&ett_struct_iso20_ScheduleExchangeResType,
		&ett_struct_iso20_PowerDeliveryReqType,
		&ett_struct_iso20_PowerDeliveryResType,
		&ett_struct_iso20_MeteringConfirmationReqType,
		&ett_struct_iso20_MeteringConfirmationResType,
		&ett_struct_iso20_SessionStopReqType,
		&ett_struct_iso20_SessionStopResType,
		&ett_struct_iso20_CertificateInstallationReqType,
		&ett_struct_iso20_CertificateInstallationResType,
		&ett_struct_iso20_VehicleCheckInReqType,
		&ett_struct_iso20_VehicleCheckInResType,
		&ett_struct_iso20_VehicleCheckOutReqType,
		&ett_struct_iso20_VehicleCheckOutResType,

		&ett_struct_iso20_SignedInstallationDataType,
		&ett_struct_iso20_SignedMeteringDataType,
		&ett_struct_iso20_CLReqControlModeType,
		&ett_struct_iso20_CLResControlModeType,
		&ett_struct_iso20_SignatureType,
		&ett_struct_iso20_SignatureValueType,
		&ett_struct_iso20_SignedInfoType,
		&ett_struct_iso20_CanonicalizationMethodType,
		&ett_struct_iso20_SignatureMethodType,
		&ett_struct_iso20_ReferenceType,
		&ett_struct_iso20_TransformsType,
		&ett_struct_iso20_TransformType,
		&ett_struct_iso20_DigestMethodType,
		&ett_struct_iso20_KeyInfoType,
		&ett_struct_iso20_KeyValueType,
		&ett_struct_iso20_RetrievalMethodType,
		&ett_struct_iso20_X509DataType,
		&ett_struct_iso20_PGPDataType,
		&ett_struct_iso20_SPKIDataType,
		&ett_struct_iso20_ObjectType,
		&ett_struct_iso20_ManifestType,
		&ett_struct_iso20_SignaturePropertiesType,
		&ett_struct_iso20_SignaturePropertyType,
		&ett_struct_iso20_DSAKeyValueType,
		&ett_struct_iso20_RSAKeyValueType,

		&ett_struct_iso20_MessageHeaderType,
		&ett_struct_iso20_X509IssuerSerialType,

		&ett_struct_iso20_EVSEStatusType,
		&ett_struct_iso20_RationalNumberType,
		&ett_struct_iso20_DetailedCostType,
		&ett_struct_iso20_DetailedTaxType,
		&ett_struct_iso20_ReceiptType,
		&ett_struct_iso20_MeterInfoType,
		&ett_struct_iso20_TargetPositionType,
		&ett_struct_iso20_ParameterType,
		&ett_struct_iso20_ParameterSetType,
		&ett_struct_iso20_MeasurementDataListType,
		&ett_struct_iso20_ListOfRootCertificateIDsType,
		&ett_struct_iso20_SubCertificatesType,
		&ett_struct_iso20_CertificateChainType,
		&ett_struct_iso20_SignedCertificateChainType,
		&ett_struct_iso20_EMAIDListType,
		&ett_struct_iso20_ChargingProfileType,
		&ett_struct_iso20_RelativeTimeIntervalType,
		&ett_struct_iso20_SAScheduleTupleType,
		&ett_struct_iso20_SAScheduleListType,
		&ett_struct_iso20_SelectedServiceType,
		&ett_struct_iso20_SelectedServiceListType,
		&ett_struct_iso20_ServiceParameterListType,
		&ett_struct_iso20_ServiceIDListType,
		&ett_struct_iso20_ServiceType,
		&ett_struct_iso20_ServiceListType,
		&ett_struct_iso20_Dynamic_SEReqControlModeType,
		&ett_struct_iso20_Scheduled_SEReqControlModeType,
		&ett_struct_iso20_Dynamic_SEResControlModeType,
		&ett_struct_iso20_Scheduled_SEResControlModeType,
		&ett_struct_iso20_Dynamic_EVPPTControlModeType,
		&ett_struct_iso20_Scheduled_EVPPTControlModeType,
		&ett_struct_iso20_Dynamic_SMDTControlModeType,
		&ett_struct_iso20_Scheduled_SMDTControlModeType,
	};

	proto_v2giso20 = proto_register_protocol(
		"V2G Efficient XML Interchange (ISO20)",
		"V2GISO20",
		"v2giso20"
	);
	proto_register_field_array(proto_v2giso20, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	register_dissector("v2giso20", dissect_v2giso20, proto_v2giso20);
}

void
proto_reg_handoff_v2giso20(void)
{

	/* add a handle for the connection oriented V2G EXI */
	v2gexi_handle = find_dissector_add_dependency("v2gexi", proto_v2giso20);
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
