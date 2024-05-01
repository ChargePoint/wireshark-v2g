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

static int hf_v2giso20_struct_iso20_MessageHeaderType_SessionID = -1;
static int hf_v2giso20_struct_iso20_MessageHeaderType_TimeStamp = -1;

static int hf_v2giso20_struct_iso20_SignatureType_Id = -1;
static int hf_v2giso20_struct_iso20_SignedInfoType_Id = -1;
static int hf_v2giso20_struct_iso20_CanonicalizationMethodType_Algorithm = -1;
static int hf_v2giso20_struct_iso20_CanonicalizationMethodType_ANY = -1;
static int hf_v2giso20_struct_iso20_SignatureMethodType_Algorithm = -1;
static int hf_v2giso20_struct_iso20_SignatureMethodType_HMACOutputLength = -1;
static int hf_v2giso20_struct_iso20_SignatureMethodType_ANY = -1;
static int hf_v2giso20_struct_iso20_ReferenceType_Id = -1;
static int hf_v2giso20_struct_iso20_ReferenceType_URI = -1;
static int hf_v2giso20_struct_iso20_ReferenceType_Type = -1;
static int hf_v2giso20_struct_iso20_ReferenceType_DigestValue = -1;
static int hf_v2giso20_struct_iso20_SignatureValueType_Id = -1;
static int hf_v2giso20_struct_iso20_SignatureValueType_CONTENT = -1;
static int hf_v2giso20_struct_iso20_ObjectType_Id = -1;
static int hf_v2giso20_struct_iso20_ObjectType_MimeType = -1;
static int hf_v2giso20_struct_iso20_ObjectType_Encoding = -1;
static int hf_v2giso20_struct_iso20_ObjectType_ANY = -1;
static int hf_v2giso20_struct_iso20_TransformType_Algorithm = -1;
static int hf_v2giso20_struct_iso20_TransformType_ANY = -1;
static int hf_v2giso20_struct_iso20_TransformType_XPath = -1;
static int hf_v2giso20_struct_iso20_DigestMethodType_Algorithm = -1;
static int hf_v2giso20_struct_iso20_DigestMethodType_ANY = -1;
static int hf_v2giso20_struct_iso20_KeyInfoType_Id = -1;
static int hf_v2giso20_struct_iso20_KeyInfoType_KeyName = -1;
static int hf_v2giso20_struct_iso20_KeyInfoType_MgmtData = -1;
static int hf_v2giso20_struct_iso20_KeyInfoType_ANY = -1;
static int hf_v2giso20_struct_iso20_RetrievalMethodType_URI = -1;
static int hf_v2giso20_struct_iso20_RetrievalMethodType_Type = -1;
static int hf_v2giso20_struct_iso20_KeyValueType_ANY = -1;
static int hf_v2giso20_struct_iso20_DSAKeyValueType_P = -1;
static int hf_v2giso20_struct_iso20_DSAKeyValueType_Q = -1;
static int hf_v2giso20_struct_iso20_DSAKeyValueType_G = -1;
static int hf_v2giso20_struct_iso20_DSAKeyValueType_Y = -1;
static int hf_v2giso20_struct_iso20_DSAKeyValueType_J = -1;
static int hf_v2giso20_struct_iso20_DSAKeyValueType_Seed = -1;
static int hf_v2giso20_struct_iso20_DSAKeyValueType_PgenCounter = -1;
static int hf_v2giso20_struct_iso20_RSAKeyValueType_Exponent = -1;
static int hf_v2giso20_struct_iso20_RSAKeyValueType_Modulus = -1;
static int hf_v2giso20_struct_iso20_X509DataType_X509SKI = -1;
static int hf_v2giso20_struct_iso20_X509DataType_X509SubjectName = -1;
static int hf_v2giso20_struct_iso20_X509DataType_X509Certificate = -1;
static int hf_v2giso20_struct_iso20_X509DataType_X509CRL = -1;
static int hf_v2giso20_struct_iso20_X509DataType_ANY = -1;
static int hf_v2giso20_struct_iso20_X509IssuerSerialType_X509IssuerName = -1;
static int hf_v2giso20_struct_iso20_X509IssuerSerialType_X509SerialNumber = -1;
static int hf_v2giso20_struct_iso20_PGPDataType_PGPKeyID = -1;
static int hf_v2giso20_struct_iso20_PGPDataType_PGPKeyPacket = -1;
static int hf_v2giso20_struct_iso20_PGPDataType_ANY = -1;
static int hf_v2giso20_struct_iso20_SPKIDataType_SPKISexp = -1;
static int hf_v2giso20_struct_iso20_SPKIDataType_ANY = -1;

static int hf_v2giso20_struct_iso20_EVSEStatusType_NotificationMaxDelay = -1;
static int hf_v2giso20_struct_iso20_EVSEStatusType_EVSENotification = -1;

static int hf_v2giso20_struct_iso20_RationalNumberType_Exponent = -1;
static int hf_v2giso20_struct_iso20_RationalNumberType_Value = -1;

static int hf_v2giso20_struct_iso20_MeterInfoType_MeterID = -1;
static int hf_v2giso20_struct_iso20_MeterInfoType_ChargedEnergyReadingWh = -1;
static int hf_v2giso20_struct_iso20_MeterInfoType_BPT_DischargedEnergyReadingWh = -1;
static int hf_v2giso20_struct_iso20_MeterInfoType_CapacitiveEnergyReadingVARh = -1;
static int hf_v2giso20_struct_iso20_MeterInfoType_BPT_InductiveEnergyReadingVARh = -1;
static int hf_v2giso20_struct_iso20_MeterInfoType_MeterSignature = -1;
static int hf_v2giso20_struct_iso20_MeterInfoType_MeterStatus = -1;
static int hf_v2giso20_struct_iso20_MeterInfoType_MeterTimestamp = -1;

static int hf_v2giso20_struct_iso20_SignedMeteringDataType_Id = -1;
static int hf_v2giso20_struct_iso20_SignedMeteringDataType_SessionID = -1;

static int hf_v2giso20_struct_iso20_ParameterType_Name = -1;
static int hf_v2giso20_struct_iso20_ParameterType_boolValue = -1;
static int hf_v2giso20_struct_iso20_ParameterType_byteValue = -1;
static int hf_v2giso20_struct_iso20_ParameterType_shortValue = -1;
static int hf_v2giso20_struct_iso20_ParameterType_intValue = -1;
static int hf_v2giso20_struct_iso20_ParameterType_finiteString = -1;

static int hf_v2giso20_struct_iso20_ParameterSetType_ParameterSetID = -1;

static int hf_v2giso20_struct_iso20_MeasurementDataListType_MeasurementData = -1;

static int hf_v2giso20_struct_iso20_SubCertificatesType_Certificate = -1;

static int hf_v2giso20_struct_iso20_CertificateChainType_Id = -1;
static int hf_v2giso20_struct_iso20_CertificateChainType_Certificate = -1;

static int hf_v2giso20_struct_iso20_ContractCertificateChainType_Certificate = -1;

static int hf_v2giso20_struct_iso20_SignedCertificateChainType_Id = -1;
static int hf_v2giso20_struct_iso20_SignedCertificateChainType_Certificate = -1;

static int hf_v2giso20_struct_iso20_EMAIDListType_EMAID = -1;

static int hf_v2giso20_struct_iso20_PnC_AReqAuthorizationModeType_Id = -1;
static int hf_v2giso20_struct_iso20_PnC_AReqAuthorizationModeType_GenChallenge = -1;
static int hf_v2giso20_struct_iso20_PnC_ASResAuthorizationModeType_GenChallenge = -1;

static int hf_v2giso20_struct_iso20_RelativeTimeIntervalType_start = -1;
static int hf_v2giso20_struct_iso20_RelativeTimeIntervalType_duration = -1;

static int hf_v2giso20_struct_iso20_SAScheduleTupleType_SAScheduleTupleID = -1;

static int hf_v2giso20_struct_iso20_SelectedServiceType_ServiceID = -1;
static int hf_v2giso20_struct_iso20_SelectedServiceType_ParameterSetID = -1;

static int hf_v2giso20_struct_iso20_ServiceIDListType_ServiceID = -1;

static int hf_v2giso20_struct_iso20_ServiceType_ServiceID = -1;
static int hf_v2giso20_struct_iso20_ServiceType_FreeService = -1;

static int hf_v2giso20_struct_iso20_VehicleCheckOutReqType_EVCheckOutStatus = -1;
static int hf_v2giso20_struct_iso20_VehicleCheckOutReqType_CheckOutTime = -1;
static int hf_v2giso20_struct_iso20_VehicleCheckOutResType_ResponseCode = -1;
static int hf_v2giso20_struct_iso20_VehicleCheckOutResType_EVSECheckOutStatus = -1;

static int hf_v2giso20_struct_iso20_VehicleCheckInReqType_EVCheckInStatus = -1;
static int hf_v2giso20_struct_iso20_VehicleCheckInReqType_ParkingMethod = -1;
static int hf_v2giso20_struct_iso20_VehicleCheckInReqType_VehicleFrame = -1;
static int hf_v2giso20_struct_iso20_VehicleCheckInReqType_DeviceOffset = -1;
static int hf_v2giso20_struct_iso20_VehicleCheckInReqType_VehicleTravel = -1;
static int hf_v2giso20_struct_iso20_VehicleCheckInResType_ResponseCode = -1;
static int hf_v2giso20_struct_iso20_VehicleCheckInResType_ParkingSpace = -1;
static int hf_v2giso20_struct_iso20_VehicleCheckInResType_DeviceLocation = -1;
static int hf_v2giso20_struct_iso20_VehicleCheckInResType_TargetDistance = -1;

static int hf_v2giso20_struct_iso20_EVPowerProfileType_TimeAnchor = -1;

static int hf_v2giso20_struct_iso20_PowerDemandResType_ResponseCode = -1;
static int hf_v2giso20_struct_iso20_PowerDemandResType_EVSEID = -1;
static int hf_v2giso20_struct_iso20_PowerDemandResType_SAScheduleTupleID = -1;
static int hf_v2giso20_struct_iso20_PowerDemandResType_ReceiptRequired = -1;

static int hf_v2giso20_struct_iso20_CurrentDemandResType_ResponseCode = -1;
static int hf_v2giso20_struct_iso20_CurrentDemandResType_EVSEPowerLimitAchieved = -1;
static int hf_v2giso20_struct_iso20_CurrentDemandResType_EVSECurrentLimitAchieved = -1;
static int hf_v2giso20_struct_iso20_CurrentDemandResType_EVSEID = -1;
static int hf_v2giso20_struct_iso20_CurrentDemandResType_SAScheduleTupleID = -1;
static int hf_v2giso20_struct_iso20_CurrentDemandResType_ReceiptRequired = -1;

static int hf_v2giso20_struct_iso20_CertificateInstallationReqType_MaximumContractCertificateChains = -1;
static int hf_v2giso20_struct_iso20_CertificateInstallationResType_ResponseCode = -1;
static int hf_v2giso20_struct_iso20_CertificateInstallationResType_EVSEProcessing = -1;
static int hf_v2giso20_struct_iso20_CertificateInstallationResType_RemainingContractCertificateChains = -1;

static int hf_v2giso20_struct_iso20_SessionStopReqType_ChargingSession = -1;
static int hf_v2giso20_struct_iso20_SessionStopReqType_EVTerminationCode = -1;
static int hf_v2giso20_struct_iso20_SessionStopReqType_EVTerminationExplanation = -1;
static int hf_v2giso20_struct_iso20_SessionStopResType_ResponseCode = -1;

static int hf_v2giso20_struct_iso20_MeteringReceiptReqType_Id = -1;
static int hf_v2giso20_struct_iso20_MeteringReceiptReqType_SessionID = -1;
static int hf_v2giso20_struct_iso20_MeteringReceiptReqType_SAScheduleTupleID = -1;
static int hf_v2giso20_struct_iso20_MeteringReceiptResType_ResponseCode = -1;

static int hf_v2giso20_struct_iso20_PowerDeliveryReqType_EVProcessing = -1;
static int hf_v2giso20_struct_iso20_PowerDeliveryReqType_ChargeProgress = -1;
static int hf_v2giso20_struct_iso20_PowerDeliveryReqType_BPT_ChannelSelection = -1;
static int hf_v2giso20_struct_iso20_PowerDeliveryResType_ResponseCode = -1;
static int hf_v2giso20_struct_iso20_PowerDeliveryResType_EVSEProcessing = -1;

static int hf_v2giso20_struct_iso20_ChargeParameterDiscoveryReqType_MaxSupportingPoints = -1;
static int hf_v2giso20_struct_iso20_ChargeParameterDiscoveryResType_ResponseCode = -1;
static int hf_v2giso20_struct_iso20_ChargeParameterDiscoveryResType_EVSEProcessing = -1;

static int hf_v2giso20_struct_iso20_AuthorizationReqType_SelectedAuthorizationService = -1;
static int hf_v2giso20_struct_iso20_AuthorizationResType_ResponseCode = -1;
static int hf_v2giso20_struct_iso20_AuthorizationResType_EVSEProcessing = -1;

static int hf_v2giso20_struct_iso20_AuthorizationSetupResType_ResponseCode = -1;
static int hf_v2giso20_struct_iso20_AuthorizationSetupResType_Authorization = -1;
static int hf_v2giso20_struct_iso20_AuthorizationSetupResType_CertificateInstallationService = -1;

static int hf_v2giso20_struct_iso20_PaymentServiceSelectionResType_ResponseCode = -1;

static int hf_v2giso20_struct_iso20_ServiceDetailReqType_ServiceID = -1;
static int hf_v2giso20_struct_iso20_ServiceDetailResType_ResponseCode = -1;
static int hf_v2giso20_struct_iso20_ServiceDetailResType_ServiceID = -1;

static int hf_v2giso20_struct_iso20_ServiceDiscoveryResType_ResponseCode = -1;
static int hf_v2giso20_struct_iso20_ServiceDiscoveryResType_ServiceRenegotiationSupported = -1;

static int hf_v2giso20_struct_iso20_SessionSetupReqType_EVCCID = -1;
static int hf_v2giso20_struct_iso20_SessionSetupResType_ResponseCode = -1;
static int hf_v2giso20_struct_iso20_SessionSetupResType_EVSEID = -1;
static int hf_v2giso20_struct_iso20_SessionSetupResType_EVSETimeStamp = -1;

/* Specifically track voltage and current for graphing */
static int hf_v2giso20_ev_target_voltage = -1;
static int hf_v2giso20_ev_target_current = -1;
static int hf_v2giso20_ev_maximum_voltage = -1;
static int hf_v2giso20_ev_maximum_current = -1;
static int hf_v2giso20_ev_maximum_power = -1;
static int hf_v2giso20_evse_present_voltage = -1;
static int hf_v2giso20_evse_present_current = -1;
static int hf_v2giso20_evse_maximum_voltage = -1;
static int hf_v2giso20_evse_maximum_current = -1;
static int hf_v2giso20_evse_maximum_power = -1;

/* Initialize the subtree pointers */
static gint ett_v2giso20 = -1;
static gint ett_v2giso20_document = -1;
static gint ett_v2giso20_header = -1;
static gint ett_v2giso20_array = -1;
static gint ett_v2giso20_array_i = -1;
static gint ett_v2giso20_asn1 = -1;

static gint ett_v2giso20_struct_iso20_SignatureType = -1;
static gint ett_v2giso20_struct_iso20_SignedInfoType = -1;
static gint ett_v2giso20_struct_iso20_SignedInstallationDataType = -1;
static gint ett_v2giso20_struct_iso20_SignatureValueType = -1;
static gint ett_v2giso20_struct_iso20_ObjectType = -1;
static gint ett_v2giso20_struct_iso20_CanonicalizationMethodType = -1;
static gint ett_v2giso20_struct_iso20_SignatureMethodType = -1;
static gint ett_v2giso20_struct_iso20_DigestMethodType = -1;
static gint ett_v2giso20_struct_iso20_ReferenceType = -1;
static gint ett_v2giso20_struct_iso20_TransformsType = -1;
static gint ett_v2giso20_struct_iso20_TransformType = -1;
static gint ett_v2giso20_struct_iso20_KeyInfoType = -1;
static gint ett_v2giso20_struct_iso20_KeyValueType = -1;
static gint ett_v2giso20_struct_iso20_DSAKeyValueType = -1;
static gint ett_v2giso20_struct_iso20_RSAKeyValueType = -1;
static gint ett_v2giso20_struct_iso20_RetrievalMethodType = -1;
static gint ett_v2giso20_struct_iso20_X509DataType = -1;
static gint ett_v2giso20_struct_iso20_X509IssuerSerialType = -1;
static gint ett_v2giso20_struct_iso20_PGPDataType = -1;
static gint ett_v2giso20_struct_iso20_SPKIDataType = -1;

static gint ett_v2giso20_struct_iso20_EIM_AReqAuthorizationModeType = -1;
static gint ett_v2giso20_struct_iso20_PnC_AReqAuthorizationModeType = -1;
static gint ett_v2giso20_struct_iso20_EIM_ASResAuthorizationModeType = -1;
static gint ett_v2giso20_struct_iso20_PnC_ASResAuthorizationModeType = -1;
static gint ett_v2giso20_struct_iso20_EVPowerProfileType = -1;
static gint ett_v2giso20_struct_iso20_EVPowerProfileEntryListType = -1;
static gint ett_v2giso20_struct_iso20_PowerScheduleEntryListType = -1;
static gint ett_v2giso20_struct_iso20_EVSEStatusType = -1;
static gint ett_v2giso20_struct_iso20_RationalNumberType = -1;
static gint ett_v2giso20_struct_iso20_MeterInfoType = -1;
static gint ett_v2giso20_struct_iso20_SignedMeteringDataType = -1;
static gint ett_v2giso20_struct_iso20_TargetPositionType = -1;
static gint ett_v2giso20_struct_iso20_ParameterType = -1;
static gint ett_v2giso20_struct_iso20_ParameterSetType = -1;
static gint ett_v2giso20_struct_iso20_MeasurementDataListType = -1;
static gint ett_v2giso20_struct_iso20_ListOfRootCertificateIDsType = -1;
static gint ett_v2giso20_struct_iso20_SubCertificatesType = -1;
static gint ett_v2giso20_struct_iso20_CertificateChainType = -1;
static gint ett_v2giso20_struct_iso20_ContractCertificateChainType = -1;
static gint ett_v2giso20_struct_iso20_SignedCertificateChainType = -1;
static gint ett_v2giso20_struct_iso20_EMAIDListType = -1;
static gint ett_v2giso20_struct_iso20_ChargingProfileType = -1;
static gint ett_v2giso20_struct_iso20_RelativeTimeIntervalType = -1;
static gint ett_v2giso20_struct_iso20_SAScheduleTupleType = -1;
static gint ett_v2giso20_struct_iso20_SAScheduleListType = -1;
static gint ett_v2giso20_struct_iso20_SelectedServiceType = -1;
static gint ett_v2giso20_struct_iso20_SelectedServiceListType = -1;
static gint ett_v2giso20_struct_iso20_ServiceParameterListType = -1;
static gint ett_v2giso20_struct_iso20_ServiceIDListType = -1;
static gint ett_v2giso20_struct_iso20_ServiceType = -1;
static gint ett_v2giso20_struct_iso20_ServiceListType = -1;
static gint ett_v2giso20_struct_iso20_SupportedProvidersListType = -1;

static gint ett_v2giso20_struct_iso20_SessionSetupReqType = -1;
static gint ett_v2giso20_struct_iso20_SessionSetupResType = -1;
static gint ett_v2giso20_struct_iso20_AuthorizationSetupReqType = -1;
static gint ett_v2giso20_struct_iso20_AuthorizationSetupResType = -1;
static gint ett_v2giso20_struct_iso20_AuthorizationReqType = -1;
static gint ett_v2giso20_struct_iso20_AuthorizationResType = -1;
static gint ett_v2giso20_struct_iso20_ServiceDiscoveryReqType = -1;
static gint ett_v2giso20_struct_iso20_ServiceDiscoveryResType = -1;
static gint ett_v2giso20_struct_iso20_ServiceDetailReqType = -1;
static gint ett_v2giso20_struct_iso20_ServiceDetailResType = -1;
static gint ett_v2giso20_struct_iso20_ServiceSelectionReqType = -1;
static gint ett_v2giso20_struct_iso20_ServiceSelectionResType = -1;
static gint ett_v2giso20_struct_iso20_ScheduleExchangeReqType = -1;
static gint ett_v2giso20_struct_iso20_ScheduleExchangeResType = -1;
static gint ett_v2giso20_struct_iso20_PowerDeliveryReqType = -1;
static gint ett_v2giso20_struct_iso20_PowerDeliveryResType = -1;
static gint ett_v2giso20_struct_iso20_MeteringConfirmationReqType = -1;
static gint ett_v2giso20_struct_iso20_MeteringConfirmationResType = -1;
static gint ett_v2giso20_struct_iso20_SessionStopReqType = -1;
static gint ett_v2giso20_struct_iso20_SessionStopResType = -1;
static gint ett_v2giso20_struct_iso20_CertificateInstallationReqType = -1;
static gint ett_v2giso20_struct_iso20_CertificateInstallationResType = -1;
static gint ett_v2giso20_struct_iso20_VehicleCheckInReqType = -1;
static gint ett_v2giso20_struct_iso20_VehicleCheckInResType = -1;
static gint ett_v2giso20_struct_iso20_VehicleCheckOutReqType = -1;
static gint ett_v2giso20_struct_iso20_VehicleCheckOutResType = -1;


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


static void
dissect_v2giso20_object(const struct iso20_ObjectType *object,
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
			hf_v2giso20_struct_iso20_ObjectType_Id,
			tvb,
			object->Id.characters,
			object->Id.charactersLen,
			sizeof(object->Id.characters));
	}
	if (object->MimeType_isUsed) {
		exi_add_characters(subtree,
			hf_v2giso20_struct_iso20_ObjectType_MimeType,
			tvb,
			object->MimeType.characters,
			object->MimeType.charactersLen,
			sizeof(object->MimeType.characters));
	}
	if (object->Encoding_isUsed) {
		exi_add_characters(subtree,
			hf_v2giso20_struct_iso20_ObjectType_Encoding,
			tvb,
			object->Encoding.characters,
			object->Encoding.charactersLen,
			sizeof(object->Encoding.characters));
	}
	if (object->ANY_isUsed) {
		exi_add_bytes(subtree,
			hf_v2giso20_struct_iso20_ObjectType_ANY,
			tvb,
			object->ANY.bytes,
			object->ANY.bytesLen,
			sizeof(object->ANY.bytes));
	}

	return;
}

static void
dissect_v2giso20_transform(const struct iso20_TransformType *transform,
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
		hf_v2giso20_struct_iso20_TransformType_Algorithm,
		tvb,
		transform->Algorithm.characters,
		transform->Algorithm.charactersLen,
		sizeof(transform->Algorithm.characters));

	if (transform->ANY_isUsed) {
		exi_add_bytes(subtree,
			hf_v2giso20_struct_iso20_TransformType_ANY,
			tvb,
			transform->ANY.bytes,
			transform->ANY.bytesLen,
			sizeof(transform->ANY.bytes));
	}

	if (transform->XPath_isUsed) {
		exi_add_characters(subtree,
			hf_v2giso20_struct_iso20_TransformType_XPath,
			tvb,
			transform->XPath.characters,
			transform->XPath.charactersLen,
			sizeof(transform->XPath.characters));
	}

	return;
}

static void
dissect_v2giso20_transforms(const struct iso20_TransformsType *transforms,
			    tvbuff_t *tvb,
			    packet_info *pinfo,
			    proto_tree *tree,
			    gint idx,
			    const char *subtree_name)
{
	proto_tree *subtree;

	subtree = proto_tree_add_subtree(tree,
		tvb, 0, 0, idx, NULL, subtree_name);

	dissect_v2giso20_transform(&transforms->Transform,
		tvb, pinfo, subtree,
		ett_v2giso20_struct_iso20_TransformType, "Transform");

	return;
}

static void
dissect_v2giso20_digestmethod(const struct iso20_DigestMethodType *digestmethod,
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
		hf_v2giso20_struct_iso20_DigestMethodType_Algorithm,
		tvb,
		digestmethod->Algorithm.characters,
		digestmethod->Algorithm.charactersLen,
		sizeof(digestmethod->Algorithm.characters));

	if (digestmethod->ANY_isUsed) {
		exi_add_bytes(subtree,
			hf_v2giso20_struct_iso20_DigestMethodType_ANY,
			tvb,
			digestmethod->ANY.bytes,
			digestmethod->ANY.bytesLen,
			sizeof(digestmethod->ANY.bytes));
	}

	return;
}

static void
dissect_v2giso20_reference(const struct iso20_ReferenceType *reference,
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
			hf_v2giso20_struct_iso20_ReferenceType_Id,
			tvb,
			reference->Id.characters,
			reference->Id.charactersLen,
			sizeof(reference->Id.characters));
	}
	if (reference->URI_isUsed) {
		exi_add_characters(subtree,
			hf_v2giso20_struct_iso20_ReferenceType_URI,
			tvb,
			reference->URI.characters,
			reference->URI.charactersLen,
			sizeof(reference->URI.characters));
	}
	if (reference->Type_isUsed) {
		exi_add_characters(subtree,
			hf_v2giso20_struct_iso20_ReferenceType_Type,
			tvb,
			reference->Type.characters,
			reference->Type.charactersLen,
			sizeof(reference->Type.characters));
	}
	if (reference->Transforms_isUsed) {
		dissect_v2giso20_transforms(&reference->Transforms,
			tvb, pinfo, subtree,
			ett_v2giso20_struct_iso20_TransformsType,
			"Transforms");
	}

	dissect_v2giso20_digestmethod(&reference->DigestMethod,
			tvb, pinfo, subtree,
			ett_v2giso20_struct_iso20_DigestMethodType,
			"DigestMethod");

	exi_add_bytes(subtree,
		hf_v2giso20_struct_iso20_ReferenceType_DigestValue,
		tvb,
		reference->DigestValue.bytes,
		reference->DigestValue.bytesLen,
		sizeof(reference->DigestValue.bytes));

	return;
}

static void
dissect_v2giso20_canonicalizationmethod(
	const struct iso20_CanonicalizationMethodType *canonicalizationmethod,
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
		hf_v2giso20_struct_iso20_CanonicalizationMethodType_Algorithm,
		tvb,
		canonicalizationmethod->Algorithm.characters,
		canonicalizationmethod->Algorithm.charactersLen,
		sizeof(canonicalizationmethod->Algorithm.characters));

	if (canonicalizationmethod->ANY_isUsed) {
		exi_add_bytes(subtree,
			hf_v2giso20_struct_iso20_CanonicalizationMethodType_ANY,
			tvb,
			canonicalizationmethod->ANY.bytes,
			canonicalizationmethod->ANY.bytesLen,
			sizeof(canonicalizationmethod->ANY.bytes));
	}

	return;
}

static void
dissect_v2giso20_signaturemethod(
	const struct iso20_SignatureMethodType *signaturemethod,
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
		hf_v2giso20_struct_iso20_SignatureMethodType_Algorithm,
		tvb,
		signaturemethod->Algorithm.characters,
		signaturemethod->Algorithm.charactersLen,
		sizeof(signaturemethod->Algorithm.characters));

	if (signaturemethod->HMACOutputLength_isUsed) {
		it = proto_tree_add_int64(subtree,
			hf_v2giso20_struct_iso20_SignatureMethodType_HMACOutputLength,
			tvb, 0, 0, signaturemethod->HMACOutputLength);
		proto_item_set_generated(it);
	}

	if (signaturemethod->ANY_isUsed) {
		exi_add_bytes(subtree,
			hf_v2giso20_struct_iso20_SignatureMethodType_ANY,
			tvb,
			signaturemethod->ANY.bytes,
			signaturemethod->ANY.bytesLen,
			sizeof(signaturemethod->ANY.bytes));
	}

	return;
}

static void
dissect_v2giso20_signaturevalue(
	const struct iso20_SignatureValueType *signaturevalue,
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
			hf_v2giso20_struct_iso20_SignatureValueType_Id,
			tvb,
			signaturevalue->Id.characters,
			signaturevalue->Id.charactersLen,
			sizeof(signaturevalue->Id.characters));
	}

	exi_add_bytes(subtree,
		hf_v2giso20_struct_iso20_SignatureValueType_CONTENT,
		tvb,
		signaturevalue->CONTENT.bytes,
		signaturevalue->CONTENT.bytesLen,
		sizeof(signaturevalue->CONTENT.bytes));

	return;
}

static void
dissect_v2giso20_signedinfo(const struct iso20_SignedInfoType *signedinfo,
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
			hf_v2giso20_struct_iso20_SignedInfoType_Id,
			tvb,
			signedinfo->Id.characters,
			signedinfo->Id.charactersLen,
			sizeof(signedinfo->Id.characters));
	}

	dissect_v2giso20_canonicalizationmethod(
		&signedinfo->CanonicalizationMethod,
		tvb, pinfo, subtree,
		ett_v2giso20_struct_iso20_CanonicalizationMethodType,
		"CanonicalizationMethod");
	dissect_v2giso20_signaturemethod(
		&signedinfo->SignatureMethod,
		tvb, pinfo, subtree,
		ett_v2giso20_struct_iso20_SignatureMethodType,
		"SignatureMethod");

	reference_tree = proto_tree_add_subtree(subtree,
		tvb, 0, 0, ett_v2giso20_array, NULL, "Reference");
	for (i = 0; i < signedinfo->Reference.arrayLen; i++) {
		char index[sizeof("[65536]")];

		snprintf(index, sizeof(index), "[%u]", i);
		dissect_v2giso20_reference(&signedinfo->Reference.array[i],
			tvb, pinfo, reference_tree,
			ett_v2giso20_struct_iso20_ReferenceType, index);
	}

	return;
}

static void
dissect_v2giso20_dsakeyvalue(const struct iso20_DSAKeyValueType *dsakeyvalue,
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
			hf_v2giso20_struct_iso20_DSAKeyValueType_P,
			tvb,
			dsakeyvalue->P.bytes,
			dsakeyvalue->P.bytesLen,
			sizeof(dsakeyvalue->P.bytes));
	}
	if (dsakeyvalue->Q_isUsed) {
		exi_add_bytes(subtree,
			hf_v2giso20_struct_iso20_DSAKeyValueType_Q,
			tvb,
			dsakeyvalue->Q.bytes,
			dsakeyvalue->Q.bytesLen,
			sizeof(dsakeyvalue->Q.bytes));
	}
	if (dsakeyvalue->G_isUsed) {
		exi_add_bytes(subtree,
			hf_v2giso20_struct_iso20_DSAKeyValueType_G,
			tvb,
			dsakeyvalue->G.bytes,
			dsakeyvalue->G.bytesLen,
			sizeof(dsakeyvalue->G.bytes));
	}
	exi_add_bytes(subtree,
		hf_v2giso20_struct_iso20_DSAKeyValueType_Y,
		tvb,
		dsakeyvalue->Y.bytes,
		dsakeyvalue->Y.bytesLen,
		sizeof(dsakeyvalue->Y.bytes));
	if (dsakeyvalue->J_isUsed) {
		exi_add_bytes(subtree,
			hf_v2giso20_struct_iso20_DSAKeyValueType_J,
			tvb,
			dsakeyvalue->J.bytes,
			dsakeyvalue->J.bytesLen,
			sizeof(dsakeyvalue->J.bytes));
	}
	if (dsakeyvalue->Seed_isUsed) {
		exi_add_bytes(subtree,
			hf_v2giso20_struct_iso20_DSAKeyValueType_Seed,
			tvb,
			dsakeyvalue->Seed.bytes,
			dsakeyvalue->Seed.bytesLen,
			sizeof(dsakeyvalue->Seed.bytes));
	}
	if (dsakeyvalue->PgenCounter_isUsed) {
		exi_add_bytes(subtree,
			hf_v2giso20_struct_iso20_DSAKeyValueType_PgenCounter,
			tvb,
			dsakeyvalue->PgenCounter.bytes,
			dsakeyvalue->PgenCounter.bytesLen,
			sizeof(dsakeyvalue->PgenCounter.bytes));
	}

	return;
}

static void
dissect_v2giso20_rsakeyvalue(const struct iso20_RSAKeyValueType *rsakeyvalue,
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
		hf_v2giso20_struct_iso20_RSAKeyValueType_Modulus,
		tvb,
		rsakeyvalue->Modulus.bytes,
		rsakeyvalue->Modulus.bytesLen,
		sizeof(rsakeyvalue->Modulus.bytes));

	exi_add_bytes(subtree,
		hf_v2giso20_struct_iso20_RSAKeyValueType_Exponent,
		tvb,
		rsakeyvalue->Exponent.bytes,
		rsakeyvalue->Exponent.bytesLen,
		sizeof(rsakeyvalue->Exponent.bytes));

	return;
}

static void
dissect_v2giso20_keyvalue(const struct iso20_KeyValueType *keyvalue,
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
		dissect_v2giso20_dsakeyvalue(&keyvalue->DSAKeyValue,
			tvb, pinfo, subtree,
			ett_v2giso20_struct_iso20_DSAKeyValueType,
			"DSAKeyValue");
	}
	if (keyvalue->RSAKeyValue_isUsed) {
		dissect_v2giso20_rsakeyvalue(&keyvalue->RSAKeyValue,
			tvb, pinfo, subtree,
			ett_v2giso20_struct_iso20_RSAKeyValueType,
			"RSAKeyValue");
	}

	exi_add_bytes(subtree,
		hf_v2giso20_struct_iso20_KeyValueType_ANY,
		tvb,
		keyvalue->ANY.bytes,
		keyvalue->ANY.bytesLen,
		sizeof(keyvalue->ANY.bytes));

	return;
}

static void
dissect_v2giso20_retrievalmethod(
	const struct iso20_RetrievalMethodType *retrievalmethod,
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
			hf_v2giso20_struct_iso20_RetrievalMethodType_URI,
			tvb,
			retrievalmethod->URI.characters,
			retrievalmethod->URI.charactersLen,
			sizeof(retrievalmethod->URI.characters));
	}
	if (retrievalmethod->Type_isUsed) {
		exi_add_characters(subtree,
			hf_v2giso20_struct_iso20_RetrievalMethodType_Type,
			tvb,
			retrievalmethod->Type.characters,
			retrievalmethod->Type.charactersLen,
			sizeof(retrievalmethod->Type.characters));
	}
	if (retrievalmethod->Transforms_isUsed) {
		dissect_v2giso20_transforms(&retrievalmethod->Transforms,
			tvb, pinfo, subtree,
			ett_v2giso20_struct_iso20_TransformsType,
			"Transforms");
	}

	return;
}

static void
dissect_v2giso20_x509issuerserial(
	const struct iso20_X509IssuerSerialType *x509issuerserial,
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
		hf_v2giso20_struct_iso20_X509IssuerSerialType_X509IssuerName,
		tvb,
		x509issuerserial->X509IssuerName.characters,
		x509issuerserial->X509IssuerName.charactersLen,
		sizeof(x509issuerserial->X509IssuerName.characters));

	it = proto_tree_add_int64(subtree,
		hf_v2giso20_struct_iso20_X509IssuerSerialType_X509SerialNumber,
		tvb, 0, 0, x509issuerserial->X509SerialNumber);
	proto_item_set_generated(it);

	return;
}

static void
dissect_v2giso20_x509data(const struct iso20_X509DataType *x509data,
			 tvbuff_t *tvb,
			 packet_info *pinfo,
			 proto_tree *tree,
			 gint idx,
			 const char *subtree_name)
{
	proto_tree *subtree;

	subtree = proto_tree_add_subtree(tree,
		tvb, 0, 0, idx, NULL, subtree_name);

	if (x509data->X509IssuerSerial_isUsed) {
		dissect_v2giso20_x509issuerserial(
			&x509data->X509IssuerSerial,
			tvb, pinfo, subtree,
			ett_v2giso20_struct_iso20_X509IssuerSerialType,
			"X509IssuerSerial");
	}

	if (x509data->X509SKI_isUsed) {
		exi_add_bytes(subtree,
			hf_v2giso20_struct_iso20_X509DataType_X509SKI,
			tvb,
			x509data->X509SKI.bytes,
			x509data->X509SKI.bytesLen,
			sizeof(x509data->X509SKI.bytes));
	}

	if (x509data->X509SubjectName_isUsed) {
		exi_add_characters(subtree,
			hf_v2giso20_struct_iso20_X509DataType_X509SubjectName,
			tvb,
			x509data->X509SubjectName.characters,
			x509data->X509SubjectName.charactersLen,
			sizeof(x509data->X509SubjectName.characters));
	}

	if (x509data->X509Certificate_isUsed) {
		if (v2gber_handle == NULL) {
			exi_add_bytes(subtree,
				hf_v2giso20_struct_iso20_X509DataType_X509Certificate,
				tvb,
				x509data->X509Certificate.bytes,
				x509data->X509Certificate.bytesLen,
				sizeof(x509data->X509Certificate.bytes));
		} else {
			tvbuff_t *child;
			proto_tree *asn1_tree;

			child = tvb_new_child_real_data(tvb,
				x509data->X509Certificate.bytes,
				sizeof(x509data->X509Certificate.bytes),
				x509data->X509Certificate.bytesLen);

			asn1_tree = proto_tree_add_subtree(subtree,
				child, 0, tvb_reported_length(child),
				ett_v2giso20_asn1, NULL, "X509Certificate ASN1");
			call_dissector(v2gber_handle, child, pinfo, asn1_tree);
		}
	}

	if (x509data->X509CRL_isUsed) {
		exi_add_bytes(subtree,
			hf_v2giso20_struct_iso20_X509DataType_X509CRL,
			tvb,
			x509data->X509CRL.bytes,
			x509data->X509CRL.bytesLen,
			sizeof(x509data->X509CRL.bytes));
	}

	if (x509data->ANY_isUsed) {
		exi_add_bytes(subtree,
			hf_v2giso20_struct_iso20_X509DataType_ANY,
			tvb,
			x509data->ANY.bytes,
			x509data->ANY.bytesLen,
			sizeof(x509data->ANY.bytes));
	}

	return;
}

static void
dissect_v2giso20_pgpdata(const struct iso20_PGPDataType *pgpdata,
			tvbuff_t *tvb,
			packet_info *pinfo _U_,
			proto_tree *tree,
			gint idx,
			const char *subtree_name)
{
	proto_tree *subtree;

	subtree = proto_tree_add_subtree(tree,
		tvb, 0, 0, idx, NULL, subtree_name);

	if (pgpdata->choice_1_isUsed) {
		exi_add_bytes(subtree,
			hf_v2giso20_struct_iso20_PGPDataType_PGPKeyID,
			tvb,
			pgpdata->choice_1.PGPKeyID.bytes,
			pgpdata->choice_1.PGPKeyID.bytesLen,
			sizeof(pgpdata->choice_1.PGPKeyID.bytes));

		if (pgpdata->choice_1.PGPKeyPacket_isUsed) {
			exi_add_bytes(subtree,
				hf_v2giso20_struct_iso20_PGPDataType_PGPKeyPacket,
				tvb,
				pgpdata->choice_1.PGPKeyPacket.bytes,
				pgpdata->choice_1.PGPKeyPacket.bytesLen,
				sizeof(pgpdata->choice_1.PGPKeyPacket.bytes));
		}

		if (pgpdata->choice_1.ANY_isUsed) {
			exi_add_bytes(subtree,
				hf_v2giso20_struct_iso20_PGPDataType_ANY,
				tvb,
				pgpdata->choice_1.ANY.bytes,
				pgpdata->choice_1.ANY.bytesLen,
				sizeof(pgpdata->choice_1.ANY.bytes));
		}
	}

	if (pgpdata->choice_2_isUsed) {
		exi_add_bytes(subtree,
			hf_v2giso20_struct_iso20_PGPDataType_PGPKeyPacket,
			tvb,
			pgpdata->choice_2.PGPKeyPacket.bytes,
			pgpdata->choice_2.PGPKeyPacket.bytesLen,
			sizeof(pgpdata->choice_2.PGPKeyPacket.bytes));

		if (pgpdata->choice_2.ANY_isUsed) {
			exi_add_bytes(subtree,
				hf_v2giso20_struct_iso20_PGPDataType_ANY,
				tvb,
				pgpdata->choice_2.ANY.bytes,
				pgpdata->choice_2.ANY.bytesLen,
				sizeof(pgpdata->choice_2.ANY.bytes));
		}
	}

	return;
}

static void
dissect_v2giso20_spkidata(const struct iso20_SPKIDataType *spkidata,
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
		hf_v2giso20_struct_iso20_SPKIDataType_SPKISexp,
		tvb,
		spkidata->SPKISexp.bytes,
		spkidata->SPKISexp.bytesLen,
		sizeof(spkidata->SPKISexp.bytes));

	if (spkidata->ANY_isUsed) {
		exi_add_bytes(subtree,
			hf_v2giso20_struct_iso20_SPKIDataType_ANY,
			tvb,
			spkidata->ANY.bytes,
			spkidata->ANY.bytesLen,
			sizeof(spkidata->ANY.bytes));
	}

	return;
}

static void
dissect_v2giso20_keyinfo(const struct iso20_KeyInfoType *keyinfo,
			tvbuff_t *tvb,
			packet_info *pinfo,
			proto_tree *tree,
			gint idx,
			const char *subtree_name)
{
	proto_tree *subtree;

	subtree = proto_tree_add_subtree(tree,
		tvb, 0, 0, idx, NULL, subtree_name);

	if (keyinfo->Id_isUsed) {
		exi_add_characters(subtree,
			hf_v2giso20_struct_iso20_KeyInfoType_Id,
			tvb,
			keyinfo->Id.characters,
			keyinfo->Id.charactersLen,
			sizeof(keyinfo->Id.characters));
	}

	if (keyinfo->KeyName_isUsed) {
		exi_add_characters(subtree,
			hf_v2giso20_struct_iso20_KeyInfoType_KeyName,
			tvb,
			keyinfo->KeyName.characters,
			keyinfo->KeyName.charactersLen,
			sizeof(keyinfo->KeyName.characters));
	}

	if (keyinfo->KeyValue_isUsed) {
		dissect_v2giso20_keyvalue(&keyinfo->KeyValue,
			tvb, pinfo, subtree,
			ett_v2giso20_struct_iso20_KeyValueType,
			"KeyValue");
	}

	if (keyinfo->RetrievalMethod_isUsed) {
		dissect_v2giso20_retrievalmethod(
			&keyinfo->RetrievalMethod,
			tvb, pinfo, subtree,
			ett_v2giso20_struct_iso20_RetrievalMethodType,
			"RetrievalMethod");
	}

	if (keyinfo->X509Data_isUsed) {
		dissect_v2giso20_x509data(&keyinfo->X509Data,
			tvb, pinfo, subtree,
			ett_v2giso20_struct_iso20_X509DataType, "X509Data");
	}

	if (keyinfo->PGPData_isUsed) {
		dissect_v2giso20_pgpdata(&keyinfo->PGPData,
			tvb, pinfo, subtree,
			ett_v2giso20_struct_iso20_PGPDataType, "PGPData");
	}

	if (keyinfo->SPKIData_isUsed) {
		dissect_v2giso20_spkidata(&keyinfo->SPKIData,
			tvb, pinfo, subtree,
			ett_v2giso20_struct_iso20_SPKIDataType, "SPKIData");
	}

	if (keyinfo->MgmtData_isUsed) {
		exi_add_characters(subtree,
			hf_v2giso20_struct_iso20_KeyInfoType_MgmtData,
			tvb,
			keyinfo->MgmtData.characters,
			keyinfo->MgmtData.charactersLen,
			sizeof(keyinfo->MgmtData.characters));
	}

	if (keyinfo->ANY_isUsed) {
		exi_add_bytes(subtree,
			hf_v2giso20_struct_iso20_KeyInfoType_ANY,
			tvb,
			keyinfo->ANY.bytes,
			keyinfo->ANY.bytesLen,
			sizeof(keyinfo->ANY.bytes));
	}

	return;
}

static void
dissect_v2giso20_signature(const struct iso20_SignatureType *signature,
			  tvbuff_t *tvb,
			  packet_info *pinfo,
			  proto_tree *tree,
			  gint idx,
			  const char *subtree_name)
{
	proto_tree *subtree;

	subtree = proto_tree_add_subtree(tree,
		tvb, 0, 0, idx, NULL, subtree_name);

	if (signature->Id_isUsed) {
		exi_add_characters(subtree,
			hf_v2giso20_struct_iso20_SignatureType_Id,
			tvb,
			signature->Id.characters,
			signature->Id.charactersLen,
			sizeof(signature->Id.characters));
	}

	dissect_v2giso20_signedinfo(&signature->SignedInfo,
		tvb, pinfo, subtree,
		ett_v2giso20_struct_iso20_SignedInfoType, "SignedInfo");
	dissect_v2giso20_signaturevalue(&signature->SignatureValue,
		tvb, pinfo, subtree,
		ett_v2giso20_struct_iso20_SignatureValueType, "SignatureValue");

	if (signature->KeyInfo_isUsed) {
		dissect_v2giso20_keyinfo(&signature->KeyInfo,
			tvb, pinfo, subtree,
			ett_v2giso20_struct_iso20_KeyInfoType, "KeyInfo");
	}

	if (signature->Object_isUsed) {
		dissect_v2giso20_object(&signature->Object,
			tvb, pinfo, subtree,
			ett_v2giso20_struct_iso20_ObjectType, "Object");
	}

	return;
}


static void
dissect_v2giso20_header(const struct iso20_MessageHeaderType *header,
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

	exi_add_bytes(subtree,
		hf_v2giso20_struct_iso20_MessageHeaderType_SessionID,
		tvb,
		header->SessionID.bytes,
		header->SessionID.bytesLen,
		sizeof(header->SessionID.bytes));

	it = proto_tree_add_uint64(subtree,
		hf_v2giso20_struct_iso20_MessageHeaderType_TimeStamp,
		tvb, 0, 0, header->TimeStamp);
	proto_item_set_generated(it);

	if (header->Signature_isUsed) {
		dissect_v2giso20_signature(
			&header->Signature, tvb, pinfo, subtree,
			ett_v2giso20_struct_iso20_SignatureType,
			"Signature");
	}

	return;
}


static void
dissect_v2giso20_powerscheduleentrylist(
	const struct iso20_PowerScheduleEntryType *powerscheduleentry _U_,
	tvbuff_t *tvb _U_,
	packet_info *pinfo _U_,
	proto_tree *tree _U_,
	gint idx _U_,
	const char *subtree_name _U_)
{
	return;
}


static void
dissect_v2giso20_evpowerprofileentrylist(
	const struct iso20_EVPowerProfileEntryListType
	    *evpowerprofileentrylist,
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
	for (i = 0; i < evpowerprofileentrylist->EVPowerProfileEntry.arrayLen; i++) {
		char index[sizeof("[65536]")];

		snprintf(index, sizeof(index), "[%u]", i);
		dissect_v2giso20_powerscheduleentrylist(
			&evpowerprofileentrylist->EVPowerProfileEntry.array[i],
			tvb, pinfo, evpowerprofileentry_tree,
			ett_v2giso20_struct_iso20_PowerScheduleEntryListType,
			index);
	}

	return;
}


static void
dissect_v2giso20_evpowerprofile(
	const struct iso20_EVPowerProfileType *evpowerprofile,
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
		hf_v2giso20_struct_iso20_EVPowerProfileType_TimeAnchor,
		tvb, 0, 0, evpowerprofile->TimeAnchor);
	proto_item_set_generated(it);

	if (evpowerprofile->Dynamic_EVPPTControlMode_isUsed) {
	}

	if (evpowerprofile->Scheduled_EVPPTControlMode_isUsed) {
	}

	dissect_v2giso20_evpowerprofileentrylist(
		&evpowerprofile->EVPowerProfileEntries,
		tvb, pinfo, subtree,
		ett_v2giso20_struct_iso20_EVPowerProfileEntryListType,
		"EVPowerProfileEntries");

	return;
}


static void
dissect_v2giso20_evsestatus(
	const struct iso20_EVSEStatusType *evsestatus,
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
		hf_v2giso20_struct_iso20_EVSEStatusType_NotificationMaxDelay,
		tvb, 0, 0, evsestatus->NotificationMaxDelay);
	proto_item_set_generated(it);

	it = proto_tree_add_uint(subtree,
		hf_v2giso20_struct_iso20_EVSEStatusType_EVSENotification,
		tvb, 0, 0, evsestatus->EVSENotification);
	proto_item_set_generated(it);

	return;
}

#ifdef notyet
static inline double
v2giso20_rationalnumber_to_double(
	const struct iso20_RationalNumberType *rationalnumber)
{
	double value;
	int32_t exponent;

	value = (double)rationalnumber->Value;
	exponent = rationalnumber->Exponent;
	if (exponent > 0) {
		for (; exponent != 0; exponent--) {
			value *= 10.0;
		}
	}
	if (exponent < 0) {
		for (; exponent != 0; exponent++) {
			value /= 10.0;
		}
	}

	return value;
}
#endif

static void
dissect_v2giso20_rationalnumber(
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
		hf_v2giso20_struct_iso20_RationalNumberType_Exponent,
		tvb, 0, 0, rationalnumber->Exponent);
	proto_item_set_generated(it);

	it = proto_tree_add_int(subtree,
		hf_v2giso20_struct_iso20_RationalNumberType_Value,
		tvb, 0, 0, rationalnumber->Value);
	proto_item_set_generated(it);

	return;
}


static void
dissect_v2giso20_meterinfo(
	const struct iso20_MeterInfoType *meterinfo,
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
		hf_v2giso20_struct_iso20_MeterInfoType_MeterID,
		tvb,
		meterinfo->MeterID.characters,
		meterinfo->MeterID.charactersLen,
		sizeof(meterinfo->MeterID.characters));

	it = proto_tree_add_uint64(subtree,
		hf_v2giso20_struct_iso20_MeterInfoType_ChargedEnergyReadingWh,
		tvb, 0, 0, meterinfo->ChargedEnergyReadingWh);
	proto_item_set_generated(it);

	if (meterinfo->BPT_DischargedEnergyReadingWh_isUsed) {
		it = proto_tree_add_uint64(subtree,
			hf_v2giso20_struct_iso20_MeterInfoType_BPT_DischargedEnergyReadingWh,
			tvb, 0, 0, meterinfo->BPT_DischargedEnergyReadingWh);
		proto_item_set_generated(it);
	}

	if (meterinfo->CapacitiveEnergyReadingVARh_isUsed) {
		it = proto_tree_add_uint64(subtree,
			hf_v2giso20_struct_iso20_MeterInfoType_CapacitiveEnergyReadingVARh,
			tvb, 0, 0, meterinfo->CapacitiveEnergyReadingVARh);
		proto_item_set_generated(it);
	}

	if (meterinfo->BPT_InductiveEnergyReadingVARh_isUsed) {
		it = proto_tree_add_uint64(subtree,
			hf_v2giso20_struct_iso20_MeterInfoType_BPT_InductiveEnergyReadingVARh,
			tvb, 0, 0, meterinfo->BPT_InductiveEnergyReadingVARh);
		proto_item_set_generated(it);
	}

	if (meterinfo->MeterSignature_isUsed) {
		exi_add_bytes(subtree,
			hf_v2giso20_struct_iso20_MeterInfoType_MeterSignature,
			tvb,
			meterinfo->MeterSignature.bytes,
			meterinfo->MeterSignature.bytesLen,
			sizeof(meterinfo->MeterSignature.bytes));
	}

	if (meterinfo->MeterStatus_isUsed) {
		it = proto_tree_add_int(subtree,
			hf_v2giso20_struct_iso20_MeterInfoType_MeterStatus,
			tvb, 0, 0, meterinfo->MeterStatus);
		proto_item_set_generated(it);
	}

	if (meterinfo->MeterTimestamp_isUsed) {
		it = proto_tree_add_int64(subtree,
			hf_v2giso20_struct_iso20_MeterInfoType_MeterTimestamp,
			tvb, 0, 0, meterinfo->MeterTimestamp);
		proto_item_set_generated(it);
	}

	return;
}


static void
dissect_v2giso20_signedmeteringdata(
	const struct  iso20_SignedMeteringDataType *signedmeteringdata,
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
		hf_v2giso20_struct_iso20_SignedMeteringDataType_Id,
		tvb,
		signedmeteringdata->Id.characters,
		signedmeteringdata->Id.charactersLen,
		sizeof(signedmeteringdata->Id.characters));

	exi_add_bytes(subtree,
		hf_v2giso20_struct_iso20_SignedMeteringDataType_SessionID,
		tvb,
		signedmeteringdata->SessionID.bytes,
		signedmeteringdata->SessionID.bytesLen,
		sizeof(signedmeteringdata->SessionID.bytes));

	dissect_v2giso20_meterinfo(&signedmeteringdata->MeterInfo,
		tvb, pinfo, subtree,
		ett_v2giso20_struct_iso20_MeterInfoType,
		"MeterInfo");

	/* TODO */

	return;
}


static void
dissect_v2giso20_parameter(
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
		hf_v2giso20_struct_iso20_ParameterType_Name,
		tvb,
		parameter->Name.characters,
		parameter->Name.charactersLen,
		sizeof(parameter->Name.characters));

	if (parameter->boolValue_isUsed) {
		it = proto_tree_add_int(subtree,
			hf_v2giso20_struct_iso20_ParameterType_boolValue,
			tvb, 0, 0, parameter->boolValue);
		proto_item_set_generated(it);
	}
	if (parameter->byteValue_isUsed) {
		it = proto_tree_add_int(subtree,
			hf_v2giso20_struct_iso20_ParameterType_byteValue,
			tvb, 0, 0, parameter->byteValue);
		proto_item_set_generated(it);
	}
	if (parameter->shortValue_isUsed) {
		it = proto_tree_add_int(subtree,
			hf_v2giso20_struct_iso20_ParameterType_shortValue,
			tvb, 0, 0, parameter->shortValue);
		proto_item_set_generated(it);
	}
	if (parameter->intValue_isUsed) {
		it = proto_tree_add_int(subtree,
			hf_v2giso20_struct_iso20_ParameterType_intValue,
			tvb, 0, 0, parameter->intValue);
		proto_item_set_generated(it);
	}
	if (parameter->rationalNumber_isUsed) {
		dissect_v2giso20_rationalnumber(&parameter->rationalNumber,
			tvb, pinfo, subtree,
			ett_v2giso20_struct_iso20_RationalNumberType,
			"rationalNumber");
	}
	if (parameter->finiteString_isUsed) {
		exi_add_characters(subtree,
			hf_v2giso20_struct_iso20_ParameterType_finiteString,
			tvb,
			parameter->finiteString.characters,
			parameter->finiteString.charactersLen,
			sizeof(parameter->finiteString.characters));
	}

	return;
}


static void
dissect_v2giso20_parameterset(
	const struct iso20_ParameterSetType *parameterset,
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
		hf_v2giso20_struct_iso20_ParameterSetType_ParameterSetID,
		tvb, 0, 0, parameterset->ParameterSetID);
	proto_item_set_generated(it);

	parameter_tree = proto_tree_add_subtree(subtree,
		tvb, 0, 0, ett_v2giso20_array, NULL, "Parameter");
	for (i = 0; i < parameterset->Parameter.arrayLen; i++) {
		char index[sizeof("[65536]")];

		snprintf(index, sizeof(index), "[%u]", i);
		dissect_v2giso20_parameter(
			&parameterset->Parameter.array[i],
			tvb, pinfo, parameter_tree,
			ett_v2giso20_struct_iso20_ParameterType, index);
	}

	return;
}

static void
dissect_v2giso20_listofrootcertificateids(
	const struct iso20_ListOfRootCertificateIDsType
		*listofrootcertificateids,
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
	for (i = 0; i < listofrootcertificateids->RootCertificateID.arrayLen; i++) {
		char index[sizeof("[65536]")];

		snprintf(index, sizeof(index), "[%u]", i);
		dissect_v2giso20_x509issuerserial(
			&listofrootcertificateids->RootCertificateID.array[i],
			tvb, pinfo, rootcertificateid_tree,
			ett_v2giso20_struct_iso20_X509IssuerSerialType,
			index);
	}

	return;
}

static void
dissect_v2giso20_subcertificates(
	const struct iso20_SubCertificatesType *subcertificates,
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
	for (i = 0; i < subcertificates->Certificate.arrayLen; i++) {
		certificate_i_tree = proto_tree_add_subtree_format(
			certificate_tree,
			tvb, 0, 0, ett_v2giso20_array_i, NULL, "[%u]", i);

		if (v2gber_handle == NULL) {
			exi_add_bytes(certificate_i_tree,
				hf_v2giso20_struct_iso20_SubCertificatesType_Certificate,
				tvb,
				subcertificates->Certificate.array[i].bytes,
				subcertificates->Certificate.array[i].bytesLen,
				sizeof(subcertificates->Certificate.array[i].bytes));
		} else {
			tvbuff_t *child;
			proto_tree *asn1_tree;

			child = tvb_new_child_real_data(tvb,
				subcertificates->Certificate.array[i].bytes,
				sizeof(subcertificates->Certificate.array[i].bytes),
				subcertificates->Certificate.array[i].bytesLen);


			asn1_tree = proto_tree_add_subtree(certificate_i_tree,
				child, 0, tvb_reported_length(child),
				ett_v2giso20_asn1, NULL, "Certificate ASN1");
			call_dissector(v2gber_handle, child, pinfo, asn1_tree);
		}
	}

	return;
}


static void
dissect_v2giso20_certificatechain(
	const struct iso20_CertificateChainType *certificatechain,
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
			hf_v2giso20_struct_iso20_CertificateChainType_Certificate,
			tvb,
			certificatechain->Certificate.bytes,
			certificatechain->Certificate.bytesLen,
			sizeof(certificatechain->Certificate.bytes));
	} else {
		tvbuff_t *child;
		proto_tree *asn1_tree;

		child = tvb_new_child_real_data(tvb,
			certificatechain->Certificate.bytes,
			sizeof(certificatechain->Certificate.bytes),
			certificatechain->Certificate.bytesLen);

		asn1_tree = proto_tree_add_subtree(subtree,
			child, 0, tvb_reported_length(child),
			ett_v2giso20_asn1, NULL, "Certificate ASN1");
		call_dissector(v2gber_handle, child, pinfo, asn1_tree);
	}

	if (certificatechain->SubCertificates_isUsed) {
		dissect_v2giso20_subcertificates(
			&certificatechain->SubCertificates,
			tvb, pinfo, subtree,
			ett_v2giso20_struct_iso20_SubCertificatesType,
			"SubCertificates");
	}

	return;
}


static void
dissect_v2giso20_contractcertificatechain(
	const struct iso20_ContractCertificateChainType
	    *contractcertificatechain,
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
			hf_v2giso20_struct_iso20_ContractCertificateChainType_Certificate,
			tvb,
			contractcertificatechain->Certificate.bytes,
			contractcertificatechain->Certificate.bytesLen,
			sizeof(contractcertificatechain->Certificate.bytes));
	} else {
		tvbuff_t *child;
		proto_tree *asn1_tree;

		child = tvb_new_child_real_data(tvb,
			contractcertificatechain->Certificate.bytes,
			sizeof(contractcertificatechain->Certificate.bytes),
			contractcertificatechain->Certificate.bytesLen);

		asn1_tree = proto_tree_add_subtree(subtree,
			child, 0, tvb_reported_length(child),
			ett_v2giso20_asn1, NULL, "Certificate ASN1");
		call_dissector(v2gber_handle, child, pinfo, asn1_tree);
	}

	dissect_v2giso20_subcertificates(
		&contractcertificatechain->SubCertificates,
		tvb, pinfo, subtree,
		ett_v2giso20_struct_iso20_SubCertificatesType,
		"SubCertificates");

	return;
}


static void
dissect_v2giso20_signedcertificatechain(
	const struct iso20_SignedCertificateChainType *signedcertificatechain,
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
		hf_v2giso20_struct_iso20_SignedCertificateChainType_Id,
		tvb,
		signedcertificatechain->Id.characters,
		signedcertificatechain->Id.charactersLen,
		sizeof(signedcertificatechain->Id.characters));

	if (v2gber_handle == NULL) {
		exi_add_bytes(subtree,
			hf_v2giso20_struct_iso20_SignedCertificateChainType_Certificate,
			tvb,
			signedcertificatechain->Certificate.bytes,
			signedcertificatechain->Certificate.bytesLen,
			sizeof(signedcertificatechain->Certificate.bytes));
	} else {
		tvbuff_t *child;
		proto_tree *asn1_tree;

		child = tvb_new_child_real_data(tvb,
			signedcertificatechain->Certificate.bytes,
			sizeof(signedcertificatechain->Certificate.bytes),
			signedcertificatechain->Certificate.bytesLen);

		asn1_tree = proto_tree_add_subtree(subtree,
			child, 0, tvb_reported_length(child),
			ett_v2giso20_asn1, NULL, "Certificate ASN1");
		call_dissector(v2gber_handle, child, pinfo, asn1_tree);
	}

	if (signedcertificatechain->SubCertificates_isUsed) {
		dissect_v2giso20_subcertificates(
			&signedcertificatechain->SubCertificates,
			tvb, pinfo, subtree,
			ett_v2giso20_struct_iso20_SubCertificatesType,
			"SubCertificates");
	}

	return;
}


static void
dissect_v2giso20_signedinstallationdata(
	const struct iso20_SignedInstallationDataType
	    *signedinstallationdata _U_,
	tvbuff_t *tvb _U_,
	packet_info *pinfo _U_,
	proto_tree *tree _U_,
	gint idx _U_,
	const char *subtree_name _U_)
{
	return;
}


static void
dissect_v2giso20_emaidlist(
	const struct iso20_EMAIDListType *emaidlist,
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
	for (i = 0; i < emaidlist->EMAID.arrayLen; i++) {
		char index[sizeof("[65536]")];

		snprintf(index, sizeof(index), "[%u]", i);
		emaid_i_tree = proto_tree_add_subtree(
			emaid_tree, tvb, 0, 0,
			ett_v2giso20_array_i, NULL, index);

		exi_add_characters(emaid_i_tree,
			hf_v2giso20_struct_iso20_EMAIDListType_EMAID,
			tvb,
			emaidlist->EMAID.array[i].characters,
			emaidlist->EMAID.array[i].charactersLen,
			sizeof(emaidlist->EMAID.array[i].characters));
	}

	return;
}


static void
dissect_v2giso20_supportedproviderslist(
	const struct iso20_SupportedProvidersListType
	    *supportedproviderslist _U_,
	tvbuff_t *tvb _U_,
	packet_info *pinfo _U_,
	proto_tree *tree _U_,
	gint idx _U_,
	const char *subtree_name _U_)
{
	return;
}


static void
dissect_v2giso20_eim_areqauthorizationmode(
	const struct iso20_EIM_AReqAuthorizationModeType *eim_areqauthorizationmode _U_,
	tvbuff_t *tvb _U_,
	packet_info *pinfo _U_,
	proto_tree *tree _U_,
	gint idx _U_,
	const char *subtree_name _U_)
{
	return;
}


static void
dissect_v2giso20_pnc_areqauthorizationmode(
	const struct iso20_PnC_AReqAuthorizationModeType *pnc_areqauthorizationmode,
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
		hf_v2giso20_struct_iso20_PnC_AReqAuthorizationModeType_Id,
		tvb,
		pnc_areqauthorizationmode->Id.characters,
		pnc_areqauthorizationmode->Id.charactersLen,
		sizeof(pnc_areqauthorizationmode->Id.characters));

	exi_add_bytes(subtree,
		hf_v2giso20_struct_iso20_PnC_AReqAuthorizationModeType_GenChallenge,
		tvb,
		pnc_areqauthorizationmode->GenChallenge.bytes,
		pnc_areqauthorizationmode->GenChallenge.bytesLen,
		sizeof(pnc_areqauthorizationmode->GenChallenge.bytes));

	dissect_v2giso20_contractcertificatechain(
		&pnc_areqauthorizationmode->ContractCertificateChain,
		tvb, pinfo, subtree,
		ett_v2giso20_struct_iso20_ContractCertificateChainType,
		"ContractCertificateChain");

	return;
}


static void
dissect_v2giso20_eim_asresauthorizationmode(
	const struct iso20_EIM_ASResAuthorizationModeType *eim_asresauthorizationmode _U_,
	tvbuff_t *tvb _U_,
	packet_info *pinfo _U_,
	proto_tree *tree _U_,
	gint idx _U_,
	const char *subtree_name _U_)
{
	return;
}


static void
dissect_v2giso20_pnc_asresauthorizationmode(
	const struct iso20_PnC_ASResAuthorizationModeType *pnc_asresauthorizationmode,
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
		hf_v2giso20_struct_iso20_PnC_ASResAuthorizationModeType_GenChallenge,
		tvb,
		pnc_asresauthorizationmode->GenChallenge.bytes,
		pnc_asresauthorizationmode->GenChallenge.bytesLen,
		sizeof(pnc_asresauthorizationmode->GenChallenge.bytes));

	if (pnc_asresauthorizationmode->SupportedProviders_isUsed) {
		dissect_v2giso20_supportedproviderslist(
			&pnc_asresauthorizationmode->SupportedProviders,
			tvb, pinfo, subtree,
			ett_v2giso20_struct_iso20_SupportedProvidersListType,
			"SupportedProviders");
	}

	return;
}

#ifdef notyet
static void
dissect_v2giso20_selectedservice(
	const struct iso20_SelectedServiceType *selectedservice,
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
		hf_v2giso20_struct_iso20_SelectedServiceType_ServiceID,
		tvb, 0, 0, selectedservice->ServiceID);
	proto_item_set_generated(it);

	it = proto_tree_add_uint(subtree,
		hf_v2giso20_struct_iso20_SelectedServiceType_ParameterSetID,
		tvb, 0, 0, selectedservice->ParameterSetID);
	proto_item_set_generated(it);

	return;
}

static void
dissect_v2giso20_selectedservicelist(
	const struct iso20_SelectedServiceListType *selectedservicelist,
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
	for (i = 0; i < selectedservicelist->SelectedService.arrayLen; i++) {
		char index[sizeof("[65536]")];

		snprintf(index, sizeof(index), "[%u]", i);
		dissect_v2giso20_selectedservice(
			&selectedservicelist->SelectedService.array[i],
			tvb, pinfo, selectedservice_tree,
			ett_v2giso20_struct_iso20_SelectedServiceType,
			index);
	}

	return;
}
#endif

static void
dissect_v2giso20_serviceparameterlist(
	const struct iso20_ServiceParameterListType *serviceparameterlist,
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
	for (i = 0; i < serviceparameterlist->ParameterSet.arrayLen; i++) {
		char index[sizeof("[65536]")];

		snprintf(index, sizeof(index), "[%u]", i);
		dissect_v2giso20_parameterset(
			&serviceparameterlist->ParameterSet.array[i],
			tvb, pinfo, parameterset_tree,
			ett_v2giso20_struct_iso20_ParameterSetType,
			index);
	}

	return;
}

static void
dissect_v2giso20_serviceidlist(
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
			hf_v2giso20_struct_iso20_ServiceIDListType_ServiceID,
			tvb, 0, 0,
			serviceidlist->ServiceID.array[i]);
		proto_item_set_generated(it);
	}

	return;
}

static void
dissect_v2giso20_service(
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
		hf_v2giso20_struct_iso20_ServiceType_ServiceID,
		tvb, 0, 0, service->ServiceID);
	proto_item_set_generated(it);

	it = proto_tree_add_int(subtree,
		hf_v2giso20_struct_iso20_ServiceType_FreeService,
		tvb, 0, 0, service->FreeService);
	proto_item_set_generated(it);

	return;
}

static void
dissect_v2giso20_servicelist(
	const struct iso20_ServiceListType *servicelist,
	tvbuff_t *tvb,
	packet_info *pinfo _U_,
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
	for (i = 0; i < servicelist->Service.arrayLen; i++) {
		char index[sizeof("[65536]")];

		snprintf(index, sizeof(index), "[%u]", i);
		dissect_v2giso20_service(
			&servicelist->Service.array[i],
			tvb, pinfo, service_tree,
			ett_v2giso20_struct_iso20_ServiceType,
			index);
	}

	return;
}


static void
dissect_v2giso20_sessionsetupreq(
	const struct iso20_SessionSetupReqType *sessionsetupreq,
	tvbuff_t *tvb,
	packet_info *pinfo _U_,
	proto_tree *tree,
	gint idx,
	const char *subtree_name)
{
	proto_tree *subtree;

	subtree = proto_tree_add_subtree(tree,
		tvb, 0, 0, idx, NULL, subtree_name);

	dissect_v2giso20_header(&sessionsetupreq->Header,
		tvb, pinfo, subtree,
		ett_v2giso20_header, "Header");

	exi_add_characters(subtree,
		hf_v2giso20_struct_iso20_SessionSetupReqType_EVCCID,
		tvb,
		sessionsetupreq->EVCCID.characters,
		sessionsetupreq->EVCCID.charactersLen,
		sizeof(sessionsetupreq->EVCCID.characters));

	return;
}

static void
dissect_v2giso20_sessionsetupres(
	const struct iso20_SessionSetupResType *sessionsetupres,
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

	dissect_v2giso20_header(&sessionsetupres->Header,
		tvb, pinfo, subtree,
		ett_v2giso20_header, "Header");

	it = proto_tree_add_uint(subtree,
		hf_v2giso20_struct_iso20_SessionSetupResType_ResponseCode,
		tvb, 0, 0, sessionsetupres->ResponseCode);
	proto_item_set_generated(it);

	exi_add_characters(subtree,
		hf_v2giso20_struct_iso20_SessionSetupResType_EVSEID,
		tvb,
		sessionsetupres->EVSEID.characters,
		sessionsetupres->EVSEID.charactersLen,
		sizeof(sessionsetupres->EVSEID.characters));

	return;
}


static void
dissect_v2giso20_authorizationsetupreq(
	const struct iso20_AuthorizationSetupReqType *authorizationsetupreq,
	tvbuff_t *tvb,
	packet_info *pinfo _U_,
	proto_tree *tree,
	gint idx,
	const char *subtree_name)
{
	proto_tree *subtree;

	subtree = proto_tree_add_subtree(tree,
		tvb, 0, 0, idx, NULL, subtree_name);

	dissect_v2giso20_header(&authorizationsetupreq->Header,
		tvb, pinfo, subtree,
		ett_v2giso20_header, "Header");

	return;
}

static void
dissect_v2giso20_authorizationsetupres(
	const struct iso20_AuthorizationSetupResType *authorizationsetupres,
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

	dissect_v2giso20_header(&authorizationsetupres->Header,
		tvb, pinfo, subtree,
		ett_v2giso20_header, "Header");

	it = proto_tree_add_uint(subtree,
		hf_v2giso20_struct_iso20_AuthorizationSetupResType_ResponseCode,
		tvb, 0, 0, authorizationsetupres->ResponseCode);

	authorizationservices_tree = proto_tree_add_subtree(subtree,
		tvb, 0, 0, ett_v2giso20_array, NULL, "AuthorizationServices");
	for (i = 0; i < authorizationsetupres->AuthorizationServices.arrayLen; i++) {
		char index[sizeof("[65536]")];

		snprintf(index, sizeof(index), "[%u]", i);
		authorizationservices_i_tree = proto_tree_add_subtree(
			authorizationservices_tree, tvb, 0, 0,
			ett_v2giso20_array_i, NULL, index);

		it = proto_tree_add_uint(authorizationservices_i_tree,
			hf_v2giso20_struct_iso20_AuthorizationSetupResType_Authorization,
			tvb, 0, 0,
			authorizationsetupres->AuthorizationServices.array[i]);
		proto_item_set_generated(it);
	}

	it = proto_tree_add_int(subtree,
		hf_v2giso20_struct_iso20_AuthorizationSetupResType_CertificateInstallationService,
		tvb, 0, 0, authorizationsetupres->CertificateInstallationService);
	proto_item_set_generated(it);

	if (authorizationsetupres->EIM_ASResAuthorizationMode_isUsed) {
		dissect_v2giso20_eim_asresauthorizationmode(
			&authorizationsetupres->EIM_ASResAuthorizationMode,
			tvb, pinfo, subtree,
			ett_v2giso20_struct_iso20_EIM_ASResAuthorizationModeType,
			"EIM_ASResAuthorizationMode");
	}

	if (authorizationsetupres->PnC_ASResAuthorizationMode_isUsed) {
		dissect_v2giso20_pnc_asresauthorizationmode(
			&authorizationsetupres->PnC_ASResAuthorizationMode,
			tvb, pinfo, subtree,
			ett_v2giso20_struct_iso20_PnC_ASResAuthorizationModeType,
			"PnC_ASResAuthorizationMode");
	}

	return;
}


static void
dissect_v2giso20_authorizationreq(
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

	dissect_v2giso20_header(&authorizationreq->Header,
		tvb, pinfo, subtree,
		ett_v2giso20_header, "Header");

	it = proto_tree_add_uint(subtree,
		hf_v2giso20_struct_iso20_AuthorizationReqType_SelectedAuthorizationService,
		tvb, 0, 0, authorizationreq->SelectedAuthorizationService);
	proto_item_set_generated(it);

	if (authorizationreq->EIM_AReqAuthorizationMode_isUsed) {
		dissect_v2giso20_eim_areqauthorizationmode(
			&authorizationreq->EIM_AReqAuthorizationMode,
			tvb, pinfo, subtree,
			ett_v2giso20_struct_iso20_EIM_AReqAuthorizationModeType,
			"EIM_AReqAuthorizationMode");
	}

	if (authorizationreq->PnC_AReqAuthorizationMode_isUsed) {
		dissect_v2giso20_pnc_areqauthorizationmode(
			&authorizationreq->PnC_AReqAuthorizationMode,
			tvb, pinfo, subtree,
			ett_v2giso20_struct_iso20_PnC_AReqAuthorizationModeType,
			"PnC_AReqAuthorizationMode");
	}

	return;
}

static void
dissect_v2giso20_authorizationres(
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

	dissect_v2giso20_header(&authorizationres->Header,
		tvb, pinfo, subtree,
		ett_v2giso20_header, "Header");

	it = proto_tree_add_uint(subtree,
		hf_v2giso20_struct_iso20_AuthorizationResType_ResponseCode,
		tvb, 0, 0, authorizationres->ResponseCode);
	proto_item_set_generated(it);

	it = proto_tree_add_uint(subtree,
		hf_v2giso20_struct_iso20_AuthorizationResType_EVSEProcessing,
		tvb, 0, 0, authorizationres->EVSEProcessing);
	proto_item_set_generated(it);

	return;
}


static void
dissect_v2giso20_servicediscoveryreq(
	const struct iso20_ServiceDiscoveryReqType *servicediscoveryreq,
	tvbuff_t *tvb,
	packet_info *pinfo _U_,
	proto_tree *tree,
	gint idx,
	const char *subtree_name)
{
	proto_tree *subtree;

	subtree = proto_tree_add_subtree(tree,
		tvb, 0, 0, idx, NULL, subtree_name);

	dissect_v2giso20_header(&servicediscoveryreq->Header,
		tvb, pinfo, subtree,
		ett_v2giso20_header, "Header");

	if (servicediscoveryreq->SupportedServiceIDs_isUsed) {
		dissect_v2giso20_serviceidlist(
			&servicediscoveryreq->SupportedServiceIDs,
			tvb, pinfo, subtree,
			ett_v2giso20_struct_iso20_ServiceIDListType,
			"SupportedServiceIDs");
	}

	return;
}

static void
dissect_v2giso20_servicediscoveryres(
	const struct iso20_ServiceDiscoveryResType *servicediscoveryres,
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

	dissect_v2giso20_header(&servicediscoveryres->Header,
		tvb, pinfo, subtree,
		ett_v2giso20_header, "Header");

	it = proto_tree_add_uint(subtree,
		hf_v2giso20_struct_iso20_ServiceDiscoveryResType_ResponseCode,
		tvb, 0, 0, servicediscoveryres->ResponseCode);
	proto_item_set_generated(it);

	it = proto_tree_add_int(subtree,
		hf_v2giso20_struct_iso20_ServiceDiscoveryResType_ServiceRenegotiationSupported,
		tvb, 0, 0, servicediscoveryres->ServiceRenegotiationSupported);
	proto_item_set_generated(it);

	dissect_v2giso20_servicelist(
		&servicediscoveryres->EnergyTransferServiceList,
		tvb, pinfo, subtree,
		ett_v2giso20_struct_iso20_ServiceListType,
		"EnergyTransferServiceList");

	if (servicediscoveryres->VASList_isUsed) {
		dissect_v2giso20_servicelist(
			&servicediscoveryres->VASList,
			tvb, pinfo, subtree,
			ett_v2giso20_struct_iso20_ServiceListType,
			"VASList");
	}

	return;
}

static void
dissect_v2giso20_servicedetailreq(
	const struct iso20_ServiceDetailReqType *servicedetailreq,
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

	dissect_v2giso20_header(&servicedetailreq->Header,
		tvb, pinfo, subtree,
		ett_v2giso20_header, "Header");

	it = proto_tree_add_uint(subtree,
		hf_v2giso20_struct_iso20_ServiceDetailReqType_ServiceID,
		tvb, 0, 0, servicedetailreq->ServiceID);
	proto_item_set_generated(it);

	return;
}

static void
dissect_v2giso20_servicedetailres(
	const struct iso20_ServiceDetailResType *servicedetailres,
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

	dissect_v2giso20_header(&servicedetailres->Header,
		tvb, pinfo, subtree,
		ett_v2giso20_header, "Header");

	it = proto_tree_add_uint(subtree,
		hf_v2giso20_struct_iso20_ServiceDetailResType_ResponseCode,
		tvb, 0, 0, servicedetailres->ResponseCode);
	proto_item_set_generated(it);

	it = proto_tree_add_uint(subtree,
		hf_v2giso20_struct_iso20_ServiceDetailResType_ServiceID,
		tvb, 0, 0, servicedetailres->ServiceID);
	proto_item_set_generated(it);

	dissect_v2giso20_serviceparameterlist(
		&servicedetailres->ServiceParameterList,
		tvb, pinfo, subtree,
		ett_v2giso20_struct_iso20_ServiceParameterListType,
		"ServiceParameterList");

	return;
}


static void
dissect_v2giso20_serviceselectionreq(
	const struct iso20_ServiceSelectionReqType *serviceselectionreq _U_,
	tvbuff_t *tvb _U_,
	packet_info *pinfo _U_,
	proto_tree *tree _U_,
	gint idx _U_,
	const char *subtree_name _U_)
{
	return;
}

static void
dissect_v2giso20_serviceselectionres(
	const struct iso20_ServiceSelectionResType *serviceselectionres _U_,
	tvbuff_t *tvb _U_,
	packet_info *pinfo _U_,
	proto_tree *tree _U_,
	gint idx _U_,
	const char *subtree_name _U_)
{
	return;
}


static void
dissect_v2giso20_scheduleexchangereq(
	const struct iso20_ScheduleExchangeReqType *scheduleexchangereq _U_,
	tvbuff_t *tvb _U_,
	packet_info *pinfo _U_,
	proto_tree *tree _U_,
	gint idx _U_,
	const char *subtree_name _U_)
{
	return;
}

static void
dissect_v2giso20_scheduleexchangeres(
	const struct iso20_ScheduleExchangeResType *scheduleexchangeres _U_,
	tvbuff_t *tvb _U_,
	packet_info *pinfo _U_,
	proto_tree *tree _U_,
	gint idx _U_,
	const char *subtree_name _U_)
{
	return;
}


static void
dissect_v2giso20_powerdeliveryreq(
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

	dissect_v2giso20_header(&powerdeliveryreq->Header,
		tvb, pinfo, subtree,
		ett_v2giso20_header, "Header");

	it = proto_tree_add_uint(subtree,
		hf_v2giso20_struct_iso20_PowerDeliveryReqType_EVProcessing,
		tvb, 0, 0, powerdeliveryreq->EVProcessing);
	proto_item_set_generated(it);

	it = proto_tree_add_uint(subtree,
		hf_v2giso20_struct_iso20_PowerDeliveryReqType_ChargeProgress,
		tvb, 0, 0, powerdeliveryreq->ChargeProgress);
	proto_item_set_generated(it);

	if (powerdeliveryreq->EVPowerProfile_isUsed) {
		dissect_v2giso20_evpowerprofile(
			&powerdeliveryreq->EVPowerProfile,
			tvb, pinfo, subtree,
			ett_v2giso20_struct_iso20_EVPowerProfileType,
			"EVPowerProfile");
	}

	if (powerdeliveryreq->BPT_ChannelSelection_isUsed) {
		it = proto_tree_add_uint(subtree,
			hf_v2giso20_struct_iso20_PowerDeliveryReqType_BPT_ChannelSelection,
			tvb, 0, 0, powerdeliveryreq->BPT_ChannelSelection);
		proto_item_set_generated(it);
	}

	return;
}

static void
dissect_v2giso20_powerdeliveryres(
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
		hf_v2giso20_struct_iso20_PowerDeliveryResType_ResponseCode,
		tvb, 0, 0, powerdeliveryres->ResponseCode);
	proto_item_set_generated(it);

	if (powerdeliveryres->EVSEStatus_isUsed) {
		dissect_v2giso20_evsestatus(
			&powerdeliveryres->EVSEStatus,
			tvb, pinfo, subtree,
			ett_v2giso20_struct_iso20_EVSEStatusType,
			"EVSEStatus");
	}

	return;
}


static void
dissect_v2giso20_meteringconfirmationreq(
	const struct iso20_MeteringConfirmationReqType
	    *meteringconfirmationreq,
	tvbuff_t *tvb,
	packet_info *pinfo _U_,
	proto_tree *tree,
	gint idx,
	const char *subtree_name)
{
	proto_tree *subtree;

	subtree = proto_tree_add_subtree(tree,
		tvb, 0, 0, idx, NULL, subtree_name);

	dissect_v2giso20_header(&meteringconfirmationreq->Header,
		tvb, pinfo, subtree,
		ett_v2giso20_header, "Header");

	dissect_v2giso20_signedmeteringdata(
		&meteringconfirmationreq->SignedMeteringData,
		tvb, pinfo, subtree,
		ett_v2giso20_struct_iso20_SignedMeteringDataType,
		"SignedMeteringData");

	return;
}

static void
dissect_v2giso20_meteringconfirmationres(
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
dissect_v2giso20_sessionstopreq(
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

	dissect_v2giso20_header(&sessionstopreq->Header,
		tvb, pinfo, subtree,
		ett_v2giso20_header, "Header");

	it = proto_tree_add_uint(subtree,
		hf_v2giso20_struct_iso20_SessionStopReqType_ChargingSession,
		tvb, 0, 0, sessionstopreq->ChargingSession);
	proto_item_set_generated(it);

	if (sessionstopreq->EVTerminationCode_isUsed) {
		exi_add_characters(subtree,
			hf_v2giso20_struct_iso20_SessionStopReqType_EVTerminationCode,
			tvb,
			sessionstopreq->EVTerminationCode.characters,
			sessionstopreq->EVTerminationCode.charactersLen,
			sizeof(sessionstopreq->EVTerminationCode.characters));
	}

	if (sessionstopreq->EVTerminationExplanation_isUsed) {
		exi_add_characters(subtree,
			hf_v2giso20_struct_iso20_SessionStopReqType_EVTerminationExplanation,
			tvb,
			sessionstopreq->EVTerminationExplanation.characters,
			sessionstopreq->EVTerminationExplanation.charactersLen,
			sizeof(sessionstopreq->EVTerminationExplanation.characters));
	}

	return;
}

static void
dissect_v2giso20_sessionstopres(
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

	dissect_v2giso20_header(&sessionstopres->Header,
		tvb, pinfo, subtree,
		ett_v2giso20_header, "Header");

	it = proto_tree_add_uint(subtree,
		hf_v2giso20_struct_iso20_SessionStopResType_ResponseCode,
		tvb, 0, 0, sessionstopres->ResponseCode);
	proto_item_set_generated(it);

	return;
}


static void
dissect_v2giso20_certificateinstallationreq(
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

	dissect_v2giso20_header(&certificateinstallationreq->Header,
		tvb, pinfo, subtree,
		ett_v2giso20_header, "Header");

	dissect_v2giso20_signedcertificatechain(
		&certificateinstallationreq->OEMProvisioningCertificateChain,
		tvb, pinfo, subtree,
		ett_v2giso20_struct_iso20_SignedCertificateChainType,
		"OEMProvisioningCertificateChain");

	dissect_v2giso20_listofrootcertificateids(
		&certificateinstallationreq->ListOfRootCertificateIDs,
		tvb, pinfo, subtree,
		ett_v2giso20_struct_iso20_ListOfRootCertificateIDsType,
		"ListOfRootCertificateIDs");

	it = proto_tree_add_uint(subtree,
		hf_v2giso20_struct_iso20_CertificateInstallationReqType_MaximumContractCertificateChains,
		tvb, 0, 0, certificateinstallationreq->MaximumContractCertificateChains);
	proto_item_set_generated(it);

	if (certificateinstallationreq->PrioritizedEMAIDs_isUsed) {
		dissect_v2giso20_emaidlist(
			&certificateinstallationreq->PrioritizedEMAIDs,
			tvb, pinfo, subtree,
			ett_v2giso20_struct_iso20_EMAIDListType,
			"PrioritizedEMAIDs");
	}

	return;
}

static void
dissect_v2giso20_certificateinstallationres(
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

	dissect_v2giso20_header(&certificateinstallationres->Header,
		tvb, pinfo, subtree,
		ett_v2giso20_header, "Header");

	it = proto_tree_add_uint(subtree,
		hf_v2giso20_struct_iso20_CertificateInstallationResType_ResponseCode,
		tvb, 0, 0, certificateinstallationres->ResponseCode);
	proto_item_set_generated(it);

	it = proto_tree_add_uint(subtree,
		hf_v2giso20_struct_iso20_CertificateInstallationResType_EVSEProcessing,
		tvb, 0, 0, certificateinstallationres->EVSEProcessing);
	proto_item_set_generated(it);

	dissect_v2giso20_certificatechain(
		&certificateinstallationres->CPSCertificateChain,
		tvb, pinfo, subtree,
		ett_v2giso20_struct_iso20_CertificateChainType,
		"CPSCertificateChain");

	dissect_v2giso20_signedinstallationdata(
		&certificateinstallationres->SignedInstallationData,
		tvb, pinfo, subtree,
		ett_v2giso20_struct_iso20_SignedInstallationDataType,
		"SignedInstallationData");

	it = proto_tree_add_uint(subtree,
		hf_v2giso20_struct_iso20_CertificateInstallationResType_RemainingContractCertificateChains,
		tvb, 0, 0,
		certificateinstallationres->RemainingContractCertificateChains);
	proto_item_set_generated(it);

	return;
}


static void
dissect_v2giso20_vehiclecheckinreq(
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

	dissect_v2giso20_header(&vehiclecheckinreq->Header,
		tvb, pinfo, subtree,
		ett_v2giso20_header, "Header");

	it = proto_tree_add_uint(subtree,
		hf_v2giso20_struct_iso20_VehicleCheckInReqType_EVCheckInStatus,
		tvb, 0, 0, vehiclecheckinreq->EVCheckInStatus);
	proto_item_set_generated(it);

	it = proto_tree_add_uint(subtree,
		hf_v2giso20_struct_iso20_VehicleCheckInReqType_ParkingMethod,
		tvb, 0, 0, vehiclecheckinreq->ParkingMethod);
	proto_item_set_generated(it);

	if (vehiclecheckinreq->VehicleFrame_isUsed) {
		it = proto_tree_add_int(subtree,
			hf_v2giso20_struct_iso20_VehicleCheckInReqType_VehicleFrame,
			tvb, 0, 0, vehiclecheckinreq->VehicleFrame);
		proto_item_set_generated(it);
	}

	if (vehiclecheckinreq->DeviceOffset_isUsed) {
		it = proto_tree_add_int(subtree,
			hf_v2giso20_struct_iso20_VehicleCheckInReqType_DeviceOffset,
			tvb, 0, 0, vehiclecheckinreq->DeviceOffset);
		proto_item_set_generated(it);
	}

	if (vehiclecheckinreq->VehicleTravel_isUsed) {
		it = proto_tree_add_int(subtree,
			hf_v2giso20_struct_iso20_VehicleCheckInReqType_VehicleTravel,
			tvb, 0, 0, vehiclecheckinreq->VehicleTravel);
		proto_item_set_generated(it);
	}

	return;
}

static void
dissect_v2giso20_vehiclecheckinres(
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

	dissect_v2giso20_header(&vehiclecheckinres->Header,
		tvb, pinfo, subtree,
		ett_v2giso20_header, "Header");

	it = proto_tree_add_uint(subtree,
		hf_v2giso20_struct_iso20_VehicleCheckInResType_ResponseCode,
		tvb, 0, 0, vehiclecheckinres->ResponseCode);
	proto_item_set_generated(it);

	if (vehiclecheckinres->ParkingSpace_isUsed) {
		it = proto_tree_add_int(subtree,
			hf_v2giso20_struct_iso20_VehicleCheckInResType_ParkingSpace,
			tvb, 0, 0, vehiclecheckinres->ParkingSpace);
		proto_item_set_generated(it);
	}

	if (vehiclecheckinres->DeviceLocation_isUsed) {
		it = proto_tree_add_int(subtree,
			hf_v2giso20_struct_iso20_VehicleCheckInResType_DeviceLocation,
			tvb, 0, 0, vehiclecheckinres->DeviceLocation);
		proto_item_set_generated(it);
	}

	if (vehiclecheckinres->TargetDistance_isUsed) {
		it = proto_tree_add_int(subtree,
			hf_v2giso20_struct_iso20_VehicleCheckInResType_TargetDistance,
			tvb, 0, 0, vehiclecheckinres->TargetDistance);
		proto_item_set_generated(it);
	}

	return;
}


static void
dissect_v2giso20_vehiclecheckoutreq(
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

	dissect_v2giso20_header(&vehiclecheckoutreq->Header,
		tvb, pinfo, subtree,
		ett_v2giso20_header, "Header");

	it = proto_tree_add_uint(subtree,
		hf_v2giso20_struct_iso20_VehicleCheckOutReqType_EVCheckOutStatus,
		tvb, 0, 0, vehiclecheckoutreq->EVCheckOutStatus);
	proto_item_set_generated(it);

	it = proto_tree_add_uint64(subtree,
		hf_v2giso20_struct_iso20_VehicleCheckOutReqType_CheckOutTime,
		tvb, 0, 0, vehiclecheckoutreq->CheckOutTime);
	proto_item_set_generated(it);

	return;
}

static void
dissect_v2giso20_vehiclecheckoutres(
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

	dissect_v2giso20_header(&vehiclecheckoutres->Header,
		tvb, pinfo, subtree,
		ett_v2giso20_header, "Header");

	it = proto_tree_add_uint(subtree,
		hf_v2giso20_struct_iso20_VehicleCheckOutResType_ResponseCode,
		tvb, 0, 0, vehiclecheckoutres->ResponseCode);
	proto_item_set_generated(it);

	it = proto_tree_add_uint(subtree,
		hf_v2giso20_struct_iso20_VehicleCheckOutResType_EVSECheckOutStatus,
		tvb, 0, 0, vehiclecheckoutres->EVSECheckOutStatus);
	proto_item_set_generated(it);

	return;
}


static void
dissect_v2giso20_document(
	const struct iso20_exiDocument *doc,
	tvbuff_t *tvb,
	packet_info *pinfo _U_,
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
		dissect_v2giso20_sessionsetupreq(
			&doc->SessionSetupReq,
			tvb, pinfo, subtree,
			ett_v2giso20_struct_iso20_SessionSetupReqType,
			"SessionSetupReq");
	}
	if (doc->SessionSetupRes_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO,
			"SessionSetupRes");
		dissect_v2giso20_sessionsetupres(
			&doc->SessionSetupRes,
			tvb, pinfo, subtree,
			ett_v2giso20_struct_iso20_SessionSetupResType,
			"SessionSetupRes");
	}

	if (doc->AuthorizationSetupReq_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO,
			"AuthorizationSetupReq");
		dissect_v2giso20_authorizationsetupreq(
			&doc->AuthorizationSetupReq,
			tvb, pinfo, subtree,
			ett_v2giso20_struct_iso20_AuthorizationSetupReqType,
			"AuthorizationSetupReq");
	}
	if (doc->AuthorizationSetupRes_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO,
			"AuthorizationSetupRes");
		dissect_v2giso20_authorizationsetupres(
			&doc->AuthorizationSetupRes,
			tvb, pinfo, subtree,
			ett_v2giso20_struct_iso20_AuthorizationSetupResType,
			"AuthorizationSetupRes");
	}

	if (doc->AuthorizationReq_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO,
			"AuthorizationReq");
		dissect_v2giso20_authorizationreq(
			&doc->AuthorizationReq,
			tvb, pinfo, subtree,
			ett_v2giso20_struct_iso20_AuthorizationReqType,
			"AuthorizationReq");
	}
	if (doc->AuthorizationRes_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO,
			"AuthorizationRes");
		dissect_v2giso20_authorizationres(
			&doc->AuthorizationRes,
			tvb, pinfo, subtree,
			ett_v2giso20_struct_iso20_AuthorizationResType,
			"AuthorizationRes");
	}

	if (doc->ServiceDiscoveryReq_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO,
			"ServiceDiscoveryReq");
		dissect_v2giso20_servicediscoveryreq(
			&doc->ServiceDiscoveryReq,
			tvb, pinfo, subtree,
			ett_v2giso20_struct_iso20_ServiceDiscoveryReqType,
			"ServiceDiscoveryReq");
	}
	if (doc->ServiceDiscoveryRes_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO,
			"ServiceDiscoveryRes");
		dissect_v2giso20_servicediscoveryres(
			&doc->ServiceDiscoveryRes,
			tvb, pinfo, subtree,
			ett_v2giso20_struct_iso20_ServiceDiscoveryResType,
			"ServiceDiscoveryRes");
	}

	if (doc->ServiceDetailReq_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO,
			"ServiceDetailReq");
		dissect_v2giso20_servicedetailreq(
			&doc->ServiceDetailReq,
			tvb, pinfo, subtree,
			ett_v2giso20_struct_iso20_ServiceDetailReqType,
			"ServiceDetailReq");
	}
	if (doc->ServiceDetailRes_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO,
			"ServiceDetailRes");
		dissect_v2giso20_servicedetailres(
			&doc->ServiceDetailRes,
			tvb, pinfo, subtree,
			ett_v2giso20_struct_iso20_ServiceDetailResType,
			"ServiceDetailRes");
	}

	if (doc->ServiceSelectionReq_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO,
			"ServiceSelectionReq");
		dissect_v2giso20_serviceselectionreq(
			&doc->ServiceSelectionReq,
			tvb, pinfo, subtree,
			ett_v2giso20_struct_iso20_ServiceSelectionReqType,
			"ServiceSelectionReq");
	}
	if (doc->ServiceSelectionRes_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO,
			"ServiceSelectionRes");
		dissect_v2giso20_serviceselectionres(
			&doc->ServiceSelectionRes,
			tvb, pinfo, subtree,
			ett_v2giso20_struct_iso20_ServiceSelectionResType,
			"ServiceSelectionRes");
	}

	if (doc->ScheduleExchangeReq_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO,
			"ScheduleExchangeReq");
		dissect_v2giso20_scheduleexchangereq(
			&doc->ScheduleExchangeReq,
			tvb, pinfo, subtree,
			ett_v2giso20_struct_iso20_ScheduleExchangeReqType,
			"ScheduleExchangeReq");
	}
	if (doc->ScheduleExchangeRes_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO,
			"ScheduleExchangeRes");
		dissect_v2giso20_scheduleexchangeres(
			&doc->ScheduleExchangeRes,
			tvb, pinfo, subtree,
			ett_v2giso20_struct_iso20_ScheduleExchangeResType,
			"ScheduleExchangeRes");
	}

	if (doc->PowerDeliveryReq_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO,
			"PowerDeliveryReq");
		dissect_v2giso20_powerdeliveryreq(
			&doc->PowerDeliveryReq,
			tvb, pinfo, subtree,
			ett_v2giso20_struct_iso20_PowerDeliveryReqType,
			"PowerDeliveryReq");
	}
	if (doc->PowerDeliveryRes_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO,
			"PowerDeliveryRes");
		dissect_v2giso20_powerdeliveryres(
			&doc->PowerDeliveryRes,
			tvb, pinfo, subtree,
			ett_v2giso20_struct_iso20_PowerDeliveryResType,
			"PowerDeliveryRes");
	}

	if (doc->MeteringConfirmationReq_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO,
			"MeteringConfirmationReq");
		dissect_v2giso20_meteringconfirmationreq(
			&doc->MeteringConfirmationReq,
			tvb, pinfo, subtree,
			ett_v2giso20_struct_iso20_MeteringConfirmationReqType,
			"MeteringConfirmationReq");
	}
	if (doc->MeteringConfirmationRes_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO,
			"MeteringConfirmationRes");
		dissect_v2giso20_meteringconfirmationres(
			&doc->MeteringConfirmationRes,
			tvb, pinfo, subtree,
			ett_v2giso20_struct_iso20_MeteringConfirmationResType,
			"MeteringConfirmationRes");
	}

	if (doc->SessionStopReq_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO,
			"SessionStopReq");
		dissect_v2giso20_sessionstopreq(
			&doc->SessionStopReq,
			tvb, pinfo, subtree,
			ett_v2giso20_struct_iso20_SessionStopReqType,
			"SessionStopReq");
	}
	if (doc->SessionStopRes_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO,
			"SessionStopRes");
		dissect_v2giso20_sessionstopres(
			&doc->SessionStopRes,
			tvb, pinfo, subtree,
			ett_v2giso20_struct_iso20_SessionStopResType,
			"SessionStopRes");
	}

	if (doc->CertificateInstallationReq_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO,
			"CertificateInstallationReq");
		dissect_v2giso20_certificateinstallationreq(
			&doc->CertificateInstallationReq,
			tvb, pinfo, subtree,
			ett_v2giso20_struct_iso20_CertificateInstallationReqType,
			"CertificateInstallationReq");
	}
	if (doc->CertificateInstallationRes_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO,
			"CertificateInstallationRes");
		dissect_v2giso20_certificateinstallationres(
			&doc->CertificateInstallationRes,
			tvb, pinfo, subtree,
			ett_v2giso20_struct_iso20_CertificateInstallationResType,
			"CertificateInstallationRes");
	}

	if (doc->VehicleCheckInReq_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO,
			"VehicleCheckInReq");
		dissect_v2giso20_vehiclecheckinreq(
			&doc->VehicleCheckInReq,
			tvb, pinfo, subtree,
			ett_v2giso20_struct_iso20_VehicleCheckInReqType,
			"VehicleCheckInReq");
	}
	if (doc->VehicleCheckInRes_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO,
			"VehicleCheckInRes");
		dissect_v2giso20_vehiclecheckinres(
			&doc->VehicleCheckInRes,
			tvb, pinfo, subtree,
			ett_v2giso20_struct_iso20_VehicleCheckInResType,
			"VehicleCheckInRes");
	}

	if (doc->VehicleCheckOutReq_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO,
			"VehicleCheckOutReq");
		dissect_v2giso20_vehiclecheckoutreq(
			&doc->VehicleCheckOutReq,
			tvb, pinfo, subtree,
			ett_v2giso20_struct_iso20_VehicleCheckOutReqType,
			"VehicleCheckOutReq");
	}
	if (doc->VehicleCheckOutRes_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO,
			"VehicleCheckOutRes");
		dissect_v2giso20_vehiclecheckoutres(
			&doc->VehicleCheckOutRes,
			tvb, pinfo, subtree,
			ett_v2giso20_struct_iso20_VehicleCheckOutResType,
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
		{ &hf_v2giso20_struct_iso20_MessageHeaderType_SessionID,
		  { "SessionID", "v2giso20.struct.messageheader.sessionid",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso20_struct_iso20_MessageHeaderType_TimeStamp,
		  { "TimeStamp", "v2giso20.struct.messageheader.timestamp",
		    FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso20_SignatureType */
		{ &hf_v2giso20_struct_iso20_SignatureType_Id,
		  { "Id", "v2giso20.struct.signature.id",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso20_SignedInfoType */
		{ &hf_v2giso20_struct_iso20_SignedInfoType_Id,
		  { "Id", "v2giso20.struct.signedinfo.id",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso20_CanonicalizationMethodType */
		{ &hf_v2giso20_struct_iso20_CanonicalizationMethodType_Algorithm,
		  { "Algorithm",
		    "v2giso20.struct.canonicalizationmethod.algorithm",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso20_struct_iso20_CanonicalizationMethodType_ANY,
		  { "ANY",
		    "v2giso20.struct.canonicalizationmethod.any",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso20_SignatureMethodType */
		{ &hf_v2giso20_struct_iso20_SignatureMethodType_Algorithm,
		  { "Algorithm", "v2giso20.struct.signaturemethod.algorithm",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso20_struct_iso20_SignatureMethodType_HMACOutputLength,
		  { "HMACOutputLength",
		    "v2giso20.struct.signaturemethod.hmacoutputlength",
		    FT_INT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso20_struct_iso20_SignatureMethodType_ANY,
		  { "ANY", "v2giso20.struct.signaturemethod.any",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso20_ReferenceType */
		{ &hf_v2giso20_struct_iso20_ReferenceType_Id,
		  { "Id", "v2giso20.struct.reference.id",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso20_struct_iso20_ReferenceType_URI,
		  { "URI", "v2giso20.struct.reference.uri",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso20_struct_iso20_ReferenceType_Type,
		  { "Type", "v2giso20.struct.reference.type",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso20_struct_iso20_ReferenceType_DigestValue,
		  { "DigestValue", "v2giso20.struct.reference.digestvalue",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso20_SignatureValueType */
		{ &hf_v2giso20_struct_iso20_SignatureValueType_Id,
		  { "Id", "v2giso20.struct.signavturevalue.id",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso20_struct_iso20_SignatureValueType_CONTENT,
		  { "CONTENT", "v2giso20.struct.signaturevalue.content",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso20_ObjectType */
		{ &hf_v2giso20_struct_iso20_ObjectType_Id,
		  { "Id", "v2giso20.struct.object.id",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso20_struct_iso20_ObjectType_MimeType,
		  { "MimeType", "v2giso20.struct.object.mimetype",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso20_struct_iso20_ObjectType_Encoding,
		  { "Encoding", "v2giso20.struct.object.encoiso20g",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso20_struct_iso20_ObjectType_ANY,
		  { "ANY", "v2giso20.struct.object.any",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso20_TransformType */
		{ &hf_v2giso20_struct_iso20_TransformType_Algorithm,
		  { "Algorithm", "v2giso20.struct.transform.algorithm",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso20_struct_iso20_TransformType_ANY,
		  { "ANY", "v2giso20.struct.transform.any",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso20_struct_iso20_TransformType_XPath,
		  { "XPath", "v2giso20.struct.transform.xpath",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso20_DigestMethodType */
		{ &hf_v2giso20_struct_iso20_DigestMethodType_Algorithm,
		  { "Algorithm", "v2giso20.struct.digestmethod.algorithm",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso20_struct_iso20_DigestMethodType_ANY,
		  { "ANY", "v2giso20.struct.digestmethod.any",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso20_KeyInfoType */
		{ &hf_v2giso20_struct_iso20_KeyInfoType_Id,
		  { "Id", "v2giso20.struct.keyinfo.id",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso20_struct_iso20_KeyInfoType_KeyName,
		  { "KeyName", "v2giso20.struct.keyinfo.keyname",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso20_struct_iso20_KeyInfoType_MgmtData,
		  { "MgmtData", "v2giso20.struct.keyinfo.mgmtdata",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso20_struct_iso20_KeyInfoType_ANY,
		  { "ANY", "v2giso20.struct.keyinfo.any",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso20_RetrievalMethodType */
		{ &hf_v2giso20_struct_iso20_RetrievalMethodType_URI,
		  { "URI", "v2giso20.struct.retrievalmethod.uri",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso20_struct_iso20_RetrievalMethodType_Type,
		  { "Type", "v2giso20.struct.retrievalmethod.type",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso20_KeyValueType */
		{ &hf_v2giso20_struct_iso20_KeyValueType_ANY,
		  { "ANY", "v2giso20.struct.keyvalue.any",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso20_DSAKeyValueType */
		{ &hf_v2giso20_struct_iso20_DSAKeyValueType_P,
		  { "P", "v2giso20.struct.dsakeyvalue.p",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso20_struct_iso20_DSAKeyValueType_Q,
		  { "Q", "v2giso20.struct.dsakeyvalue.q",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso20_struct_iso20_DSAKeyValueType_G,
		  { "G", "v2giso20.struct.dsakeyvalue.g",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso20_struct_iso20_DSAKeyValueType_Y,
		  { "Y", "v2giso20.struct.dsakeyvalue.y",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso20_struct_iso20_DSAKeyValueType_J,
		  { "J", "v2giso20.struct.dsakeyvalue.j",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso20_struct_iso20_DSAKeyValueType_Seed,
		  { "Seed", "v2giso20.struct.dsakeyvalue.seed",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso20_struct_iso20_DSAKeyValueType_PgenCounter,
		  { "PgenCounter", "v2giso20.struct.dsakeyvalue.pgencounter",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso20_RSAKeyValueType */
		{ &hf_v2giso20_struct_iso20_RSAKeyValueType_Modulus,
		  { "Modulus", "v2giso20.struct.rsakeyvalue.modulus",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso20_struct_iso20_RSAKeyValueType_Exponent,
		  { "Exponent", "v2giso20.struct.rsakeyvalue.exponent",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso20_X509DataType */
		{ &hf_v2giso20_struct_iso20_X509DataType_X509SKI,
		  { "X509SKI", "v2giso20.struct.x509data.x509ski",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso20_struct_iso20_X509DataType_X509SubjectName,
		  { "X509SubjectName",
		    "v2giso20.struct.x509data.x509subjectname",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso20_struct_iso20_X509DataType_X509Certificate,
		  { "X509Certificate",
		    "v2giso20.struct.x509data.x509certificate",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso20_struct_iso20_X509DataType_X509CRL,
		  { "X509CRL", "v2giso20.struct.x509data.x509crl",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso20_struct_iso20_X509DataType_ANY,
		  { "ANY", "v2giso20.struct.x509data.any",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso20_X509IssuerSerialType */
		{ &hf_v2giso20_struct_iso20_X509IssuerSerialType_X509IssuerName,
		  { "X509IssuerName",
		    "v2giso20.struct.x509issuerserial.x509issuername",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso20_struct_iso20_X509IssuerSerialType_X509SerialNumber,
		  { "X509SerialNumber",
		    "v2giso20.struct.x509issuerserial.x509serialnumber",
		    FT_INT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso20_PGPDataType */
		{ &hf_v2giso20_struct_iso20_PGPDataType_PGPKeyID,
		  { "PGPKeyID", "v2giso20.struct.pgpdata.pgpkeyid",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso20_struct_iso20_PGPDataType_PGPKeyPacket,
		  { "PGPKeyPacket", "v2giso20.struct.pgpdata.pgpkeypacket",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso20_struct_iso20_PGPDataType_ANY,
		  { "ANY", "v2giso20.struct.pgpdata.any",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso20_SPKIDataType */
		{ &hf_v2giso20_struct_iso20_SPKIDataType_SPKISexp,
		  { "SPKISexp", "v2giso20.struct.spkidata.spkisexp",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso20_struct_iso20_SPKIDataType_ANY,
		  { "ANY", "v2giso20.struct.spkidata.any",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso20_EVSEStatusType */
		{ &hf_v2giso20_struct_iso20_EVSEStatusType_NotificationMaxDelay,
		  { "NotificationMaxDelay",
		    "v2giso20.struct.evsestatus.notificationmaxdelay",
		    FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso20_struct_iso20_EVSEStatusType_EVSENotification,
		  { "EVSENotification",
		    "v2giso20.struct.evsestatus.evsenotification",
		    FT_UINT16, BASE_DEC,
		    VALS(v2giso20_enum_iso20_evseNotificationType_names),
		    0x0, NULL, HFILL }
		},

		/* struct iso20_RationalNumberType */
		{ &hf_v2giso20_struct_iso20_RationalNumberType_Exponent,
		  { "Exponent", "v2giso20.struct.rationalnumber.exponent",
		    FT_INT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso20_struct_iso20_RationalNumberType_Value,
		  { "Value", "v2giso20.struct.rationalnumber.value",
		    FT_INT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso20_ParameterType */
		{ &hf_v2giso20_struct_iso20_ParameterType_Name,
		  { "Name", "v2giso20.struct.parameter.name",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso20_struct_iso20_ParameterType_boolValue,
		  { "boolValue", "v2giso20.struct.parameter.boolvalue",
		    FT_INT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso20_struct_iso20_ParameterType_byteValue,
		  { "byteValue", "v2giso20.struct.parameter.bytevalue",
		    FT_INT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso20_struct_iso20_ParameterType_shortValue,
		  { "shortValue", "v2giso20.struct.parameter.shortvalue",
		    FT_INT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso20_struct_iso20_ParameterType_intValue,
		  { "intValue", "v2giso20.struct.parameter.intvalue",
		    FT_INT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso20_struct_iso20_ParameterType_finiteString,
		  { "stringValue", "v2giso20.struct.parameter.finiteString",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso20_ParameterSetType */
		{ &hf_v2giso20_struct_iso20_ParameterSetType_ParameterSetID,
		  { "ParameterSetID",
		    "v2giso20.struct.parameterset.parametersetid",
		    FT_INT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso20_MeasurementDataListType */
		{ &hf_v2giso20_struct_iso20_MeasurementDataListType_MeasurementData,
		  { "MeasurementData",
		    "v2giso20.struct.measurementdatalist.measurementdata",
		    FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso20_SubCertificatesType */
		{ &hf_v2giso20_struct_iso20_SubCertificatesType_Certificate,
		  { "Certificate",
		    "v2giso20.struct.subcertificates.certificate",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso20_CertificateChainType */
		{ &hf_v2giso20_struct_iso20_CertificateChainType_Id,
		  { "Id", "v2giso20.struct.certificatechain.id",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso20_struct_iso20_CertificateChainType_Certificate,
		  { "Certificate",
		    "v2giso20.struct.certificatechain.certificate",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso20_SignedCertificateChainType */
		{ &hf_v2giso20_struct_iso20_SignedCertificateChainType_Id,
		  { "Id", "v2giso20.struct.signedcertificatechain.id",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso20_struct_iso20_SignedCertificateChainType_Certificate,
		  { "Certificate",
		    "v2giso20.struct.signedcertificatechain.certificate",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso20_EMAIDListType */
		{ &hf_v2giso20_struct_iso20_EMAIDListType_EMAID,
		  { "Id", "v2giso20.struct.emaidlist.emaid",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso20_RelativeTimeIntervalType */
		{ &hf_v2giso20_struct_iso20_RelativeTimeIntervalType_start,
		  { "start",
		    "v2giso20.struct.relativetimeinterval.start",
		    FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso20_struct_iso20_RelativeTimeIntervalType_duration,
		  { "duration",
		    "v2giso20.struct.relativetimeinterval.start",
		    FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso20_SAScheduleTupleType */
		{ &hf_v2giso20_struct_iso20_SAScheduleTupleType_SAScheduleTupleID,
		  { "SAScheduleTupleID",
		    "v2giso20.struct.sascheduletuple.sascheduletupleid",
		    FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso20_SelectedServiceType */
		{ &hf_v2giso20_struct_iso20_SelectedServiceType_ServiceID,
		  { "ServiceID", "vgiso20.struct.selectedservice.serviceid",
		    FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso20_struct_iso20_SelectedServiceType_ParameterSetID,
		  { "ParameterSetID",
		    "vgiso20.struct.selectedservice.parametersetid",
		    FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso20_ServiceIDListType */
		{ &hf_v2giso20_struct_iso20_ServiceIDListType_ServiceID,
		  { "ServiceID", "vgiso20.struct.serviceidlist.serviceid",
		    FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso20_ServiceType */
		{ &hf_v2giso20_struct_iso20_ServiceType_ServiceID,
		  { "ServiceID", "vgiso20.struct.service.serviceid",
		    FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso20_struct_iso20_ServiceType_FreeService,
		  { "FreeService", "vgiso20.struct.service.freeservice",
		    FT_INT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso20_VehicleCheckOutReqType */
		{ &hf_v2giso20_struct_iso20_VehicleCheckOutReqType_EVCheckOutStatus,
		  { "EVCheckOutStatus",
		    "v2giso20.struct.vehichlecheckoutreq.evcheckoutstatus",
		    FT_UINT16, BASE_DEC,
		    VALS(v2giso20_enum_iso20_evCheckOutStatusType_names),
		    0x0, NULL, HFILL }
		},
		{ &hf_v2giso20_struct_iso20_VehicleCheckOutReqType_CheckOutTime,
		  { "CheckOutTime",
		    "v2giso20.struct.vehichlecheckoutreq.checkouttime",
		    FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		/* struct iso20_VehicleCheckOutResType */
		{ &hf_v2giso20_struct_iso20_VehicleCheckOutResType_ResponseCode,
		  { "ResponseCode",
		    "v2giso20.struct.vehichlecheckoutres.responsecode",
		    FT_UINT16, BASE_DEC,
		    VALS(v2giso20_enum_iso20_responseCodeType_names),
		    0x0, NULL, HFILL }
		},
		{ &hf_v2giso20_struct_iso20_VehicleCheckOutResType_EVSECheckOutStatus,
		  { "EVSECheckOutStatus",
		    "v2giso20.struct.vehichlecheckoutres.evsecheckoutstatus",
		    FT_UINT16, BASE_DEC,
		    VALS(v2giso20_enum_iso20_evseCheckOutStatusType_names),
		    0x0, NULL, HFILL }
		},

		/* struct iso20_VehicleCheckInReqType */
		{ &hf_v2giso20_struct_iso20_VehicleCheckInReqType_EVCheckInStatus,
		  { "EVCheckInStatus",
		    "v2giso20.struct.vehichlecheckinreq.evcheckinstatus",
		    FT_UINT16, BASE_DEC,
		    VALS(v2giso20_enum_iso20_evCheckInStatusType_names),
		    0x0, NULL, HFILL }
		},
		{ &hf_v2giso20_struct_iso20_VehicleCheckInReqType_ParkingMethod,
		  { "ParkingMethod",
		    "v2giso20.struct.vehichlecheckinreq.parkingmethod",
		    FT_UINT16, BASE_DEC,
		    VALS(v2giso20_enum_iso20_parkingMethodType_names),
		    0x0, NULL, HFILL }
		},
		/* struct iso20_VehicleCheckInResType */
		{ &hf_v2giso20_struct_iso20_VehicleCheckInResType_ResponseCode,
		  { "ResponseCode",
		    "v2giso20.struct.vehichlecheckinres.responsecode",
		    FT_UINT16, BASE_DEC,
		    VALS(v2giso20_enum_iso20_responseCodeType_names),
		    0x0, NULL, HFILL }
		},
		{ &hf_v2giso20_struct_iso20_VehicleCheckInResType_ParkingSpace,
		  { "ParkingSpace",
		    "v2giso20.struct.vehichlecheckinres.parkingspace",
		    FT_INT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso20_struct_iso20_VehicleCheckInResType_DeviceLocation,
		  { "DeviceLocation",
		    "v2giso20.struct.vehichlecheckinres.devicelocation",
		    FT_INT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso20_struct_iso20_VehicleCheckInResType_TargetDistance,
		  { "TargetDistance",
		    "v2giso20.struct.vehichlecheckinres.targetdistance",
		    FT_INT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso20_PowerDemandReqType */
		/* struct iso20_PowerDemandResType */
		{ &hf_v2giso20_struct_iso20_PowerDemandResType_ResponseCode,
		  { "ResponseCode",
		    "v2giso20.struct.powerdemandres.responsecode",
		    FT_UINT16, BASE_DEC,
		    VALS(v2giso20_enum_iso20_responseCodeType_names),
		    0x0, NULL, HFILL }
		},
		{ &hf_v2giso20_struct_iso20_PowerDemandResType_EVSEID,
		  { "EVSEID",
		    "v2giso20.struct.powerdemandres.evseid",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso20_struct_iso20_PowerDemandResType_SAScheduleTupleID,
		  { "SAScheduleTupleID",
		    "v2giso20.struct.powerdemandres.sascheduletupleid",
		    FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso20_struct_iso20_PowerDemandResType_ReceiptRequired,
		  { "ReceiptRequired",
		    "v2giso20.struct.powerdemandres.receiptrequired",
		    FT_INT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso20_CurrentDemandReqType */
		/* struct iso20_CurrentDemandResType */
		{ &hf_v2giso20_struct_iso20_CurrentDemandResType_ResponseCode,
		  { "ResponseCode",
		    "v2giso20.struct.currentdemandres.responsecode",
		    FT_UINT16, BASE_DEC,
		    VALS(v2giso20_enum_iso20_responseCodeType_names),
		    0x0, NULL, HFILL }
		},
		{ &hf_v2giso20_struct_iso20_CurrentDemandResType_EVSEPowerLimitAchieved,
		  { "EVSEPowerLimitAchieved",
		    "v2giso20.struct.currentdemandres.evsepowerlimitachieved",
		    FT_INT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso20_struct_iso20_CurrentDemandResType_EVSECurrentLimitAchieved,
		  { "EVSECurrentLimitAchieved",
		    "v2giso20.struct.currentdemandres.evsecurrentlimitachieved",
		    FT_INT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso20_struct_iso20_CurrentDemandResType_EVSEID,
		  { "EVSEID",
		    "v2giso20.struct.currentdemandres.evseid",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso20_struct_iso20_CurrentDemandResType_SAScheduleTupleID,
		  { "SAScheduleTupleID",
		    "v2giso20.struct.currentdemandres.sascheduletupleid",
		    FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso20_struct_iso20_CurrentDemandResType_ReceiptRequired,
		  { "ReceiptRequired",
		    "v2giso20.struct.currentdemandres.receiptrequired",
		    FT_INT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso20_CertificateInstallationReqType */
		{ &hf_v2giso20_struct_iso20_CertificateInstallationReqType_MaximumContractCertificateChains,
		  { "MaximumContractCertificateChains", "v2giso20.struct.certificateinstallationreq.maximumcontractcertificatechains",
		    FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		/* struct iso20_CertificateInstallationResType */
		{ &hf_v2giso20_struct_iso20_CertificateInstallationResType_ResponseCode,
		  { "ResponseCode",
		    "v2giso20.struct.certificateinstallationres.responsecode",
		    FT_UINT16, BASE_DEC,
		    VALS(v2giso20_enum_iso20_responseCodeType_names),
		    0x0, NULL, HFILL }
		},

		/* struct iso20_SessionStopReqType */
		{ &hf_v2giso20_struct_iso20_SessionStopReqType_ChargingSession,
		  { "ChargingSession",
		    "v2giso20.struct.sessionstopreq.chargingsession",
		    FT_UINT16, BASE_DEC,
		    VALS(v2giso20_enum_iso20_chargingSessionType_names),
		    0x0, NULL, HFILL }
		},
		/* struct iso20_SessionStopResType */
		{ &hf_v2giso20_struct_iso20_SessionStopResType_ResponseCode,
		  { "ResponseCode",
		    "v2giso20.struct.sessionstopres.responsecode",
		    FT_UINT16, BASE_DEC,
		    VALS(v2giso20_enum_iso20_responseCodeType_names),
		    0x0, NULL, HFILL }
		},

		/* struct iso20_MeteringReceiptReqType */
		{ &hf_v2giso20_struct_iso20_MeteringReceiptReqType_Id,
		  { "Id", "v2giso20.struct.meteringreceiptreq.id",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso20_struct_iso20_MeteringReceiptReqType_SessionID,
		  { "SessionID", "v2giso20.struct.meteringreceiptreq.sessionid",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso20_struct_iso20_MeteringReceiptReqType_SAScheduleTupleID,
		  { "SAScheduleTupleID",
		    "v2giso20.struct.meteringreceiptreq.sascheduletupleid",
		    FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		/* struct iso20_MeteringReceiptResType */
		{ &hf_v2giso20_struct_iso20_MeteringReceiptResType_ResponseCode,
		  { "ResponseCode",
		    "v2giso20.struct.meteringreceiptres.responsecode",
		    FT_UINT16, BASE_DEC,
		    VALS(v2giso20_enum_iso20_responseCodeType_names),
		    0x0, NULL, HFILL }
		},

		/* struct iso20_PowerDeliveryReqType */
		{ &hf_v2giso20_struct_iso20_PowerDeliveryReqType_EVProcessing,
		  { "EVProcessing",
		    "v2giso20.struct.powerdeliveryreq.evoperation",
		    FT_UINT16, BASE_DEC,
		    VALS(v2giso20_enum_iso20_processingType_names),
		    0x0, NULL, HFILL }
		},
		{ &hf_v2giso20_struct_iso20_PowerDeliveryReqType_ChargeProgress,
		  { "ChargeProgress",
		    "v2giso20.struct.powerdeliveryreq.chargeprogress",
		    FT_UINT16, BASE_DEC,
		    VALS(v2giso20_enum_iso20_chargeProgressType_names),
		    0x0, NULL, HFILL }
		},
		{ &hf_v2giso20_struct_iso20_PowerDeliveryReqType_BPT_ChannelSelection,
		  { "BPT_ChannelSelection",
		    "v2giso20.struct.powerdeliveryreq.bpt_channelselection",
		    FT_UINT16, BASE_DEC,
		    VALS(v2giso20_enum_iso20_channelSelectionType_names),
		    0x0, NULL, HFILL }
		},
		/* struct iso20_PowerDeliveryResType */
		{ &hf_v2giso20_struct_iso20_PowerDeliveryResType_ResponseCode,
		  { "ResponseCode",
		    "v2giso20.struct.powerdeliveryres.responsecode",
		    FT_UINT16, BASE_DEC,
		    VALS(v2giso20_enum_iso20_responseCodeType_names),
		    0x0, NULL, HFILL }
		},
		{ &hf_v2giso20_struct_iso20_PowerDeliveryResType_EVSEProcessing,
		  { "EVSEProcessing",
		    "v2giso20.struct.powerdeliveryres.evseprocessing",
		    FT_UINT16, BASE_DEC,
		    VALS(v2giso20_enum_iso20_processingType_names),
		    0x0, NULL, HFILL }
		},

		/* struct iso20_ChargeParameterDiscoveryReqType */
		{ &hf_v2giso20_struct_iso20_ChargeParameterDiscoveryReqType_MaxSupportingPoints,
		  { "MaxSupportingPoints",
		    "v2giso20.struct.chargeparameterdiscoveryreq.maxsupportingpoints",
		    FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		/* struct iso20_ChargeParameterDiscoveryResType */
		{ &hf_v2giso20_struct_iso20_ChargeParameterDiscoveryResType_ResponseCode,
		  { "ResponseCode",
		    "v2giso20.struct.chargeparameterdiscoveryres.responsecode",
		    FT_UINT16, BASE_DEC,
		    VALS(v2giso20_enum_iso20_responseCodeType_names),
		    0x0, NULL, HFILL }
		},
		{ &hf_v2giso20_struct_iso20_ChargeParameterDiscoveryResType_EVSEProcessing,
		  { "EVSEProcessing",
		    "v2giso20.struct.chargeparameterdiscoveryres.evseprocessing",
		    FT_UINT16, BASE_DEC,
		    VALS(v2giso20_enum_iso20_processingType_names),
		    0x0, NULL, HFILL }
		},

		/* struct iso20_AuthorizationReqType */
		{ &hf_v2giso20_struct_iso20_AuthorizationReqType_SelectedAuthorizationService,
		  { "SelectedAuthorizationService",
		    "v2giso20.struct.authorizationreq.selectedauthorizationservice",
		    FT_UINT16, BASE_DEC,
		    VALS(v2giso20_enum_iso20_authorizationType_names),
		    0x0, NULL, HFILL }
		},
		/* struct iso20_AuthorizationResType */
		{ &hf_v2giso20_struct_iso20_AuthorizationResType_ResponseCode,
		  { "ResponseCode",
		    "v2giso20.struct.authorizationres.responsecode",
		    FT_UINT16, BASE_DEC,
		    VALS(v2giso20_enum_iso20_responseCodeType_names),
		    0x0, NULL, HFILL }
		},
		{ &hf_v2giso20_struct_iso20_AuthorizationResType_EVSEProcessing,
		  { "EVSEProcessing",
		    "v2giso20.struct.authorizationres.evseprocessing",
		    FT_UINT16, BASE_DEC,
		    VALS(v2giso20_enum_iso20_processingType_names),
		    0x0, NULL, HFILL }
		},

		/* struct iso20_ServiceSelectionReqType */
		/* struct iso20_ServiceSelectionResType */
		{ &hf_v2giso20_struct_iso20_PaymentServiceSelectionResType_ResponseCode,
		  { "ResponseCode",
		    "v2giso20.struct.serviceselectionres.responsecode",
		    FT_UINT16, BASE_DEC,
		    VALS(v2giso20_enum_iso20_responseCodeType_names),
		    0x0, NULL, HFILL }
		},

		/* struct iso20_ServiceDetailReqType */
		{ &hf_v2giso20_struct_iso20_ServiceDetailReqType_ServiceID,
		  { "ServiceID",
		    "v2giso20.struct.servicedetailreq.serviceid",
		    FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		/* struct iso20_ServiceDetailResType */
		{ &hf_v2giso20_struct_iso20_ServiceDetailResType_ResponseCode,
		  { "ResponseCode",
		    "v2giso20.struct.servicedetailres.responsecode",
		    FT_UINT16, BASE_DEC,
		    VALS(v2giso20_enum_iso20_responseCodeType_names),
		    0x0, NULL, HFILL }
		},
		{ &hf_v2giso20_struct_iso20_ServiceDetailResType_ServiceID,
		  { "ServiceID",
		    "v2giso20.struct.servicedetailres.serviceid",
		    FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso20_ServiceDiscoveryReqType */
		/* struct iso20_ServiceDiscoveryResType */
		{ &hf_v2giso20_struct_iso20_ServiceDiscoveryResType_ResponseCode,
		  { "ResponseCode",
		    "v2giso20.struct.servicediscoveryres.responsecode",
		    FT_UINT16, BASE_DEC,
		    VALS(v2giso20_enum_iso20_responseCodeType_names),
		    0x0, NULL, HFILL }
		},

		/* struct iso20_SessionSetupReqType */
		{ &hf_v2giso20_struct_iso20_SessionSetupReqType_EVCCID,
		  { "EVCCID",
		    "v2giso20.struct.paymentdetailsreq.evccid",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		/* struct iso20_SessionSetupResType */
		{ &hf_v2giso20_struct_iso20_SessionSetupResType_ResponseCode,
		  { "ResponseCode",
		    "v2giso20.struct.sessionsetupres.responsecode",
		    FT_UINT16, BASE_DEC,
		    VALS(v2giso20_enum_iso20_responseCodeType_names),
		    0x0, NULL, HFILL }
		},
		{ &hf_v2giso20_struct_iso20_SessionSetupResType_EVSEID,
		  { "EVSEID",
		    "v2giso20.struct.paymentdetailsres.evseid",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso20_struct_iso20_SessionSetupResType_EVSETimeStamp,
		  { "EVSETimeStamp",
		    "v2giso20.struct.sessionsetupres.evsetimestamp",
		    FT_INT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},

		/* Derived values for graphing */
		{ &hf_v2giso20_ev_target_voltage,
		  { "EV Target Voltage (derived)", "v2giso20.ev.target.voltage",
		    FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso20_ev_target_current,
		  { "EV Target Current (derived)", "v2giso20.ev.target.current",
		    FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso20_ev_maximum_voltage,
		  { "EV Maximum Voltage (derived)",
		    "v2giso20.ev.maximum.voltage",
		    FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso20_ev_maximum_current,
		  { "EV Maximum Current (derived)",
		    "v2giso20.ev.maximum.current",
		    FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso20_ev_maximum_power,
		  { "EV Maximum Power (derived)",
		    "v2giso20.ev.maximum.power",
		    FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso20_evse_present_voltage,
		  { "EVSE Present Voltage (derived)",
		    "v2giso20.evse.present.voltage",
		    FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso20_evse_present_current,
		  { "EVSE Present Current (derived)",
		    "v2giso20.evse.present.current",
		    FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso20_evse_maximum_voltage,
		  { "EVSE Maximum Voltage (derived)",
		    "v2giso20.evse.maximum.voltage",
		    FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso20_evse_maximum_current,
		  { "EVSE Maximum Current (derived)",
		    "v2giso20.evse.maximum.current",
		    FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso20_evse_maximum_power,
		  { "EVSE Maximum Power (derived)",
		    "v2giso20.evse.maximum.power",
		    FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL }
		}
	};

	static gint *ett[] = {
		&ett_v2giso20,
		&ett_v2giso20_document,
		&ett_v2giso20_header,
		&ett_v2giso20_array,
		&ett_v2giso20_array_i,
		&ett_v2giso20_asn1,

		&ett_v2giso20_struct_iso20_SignatureType,
		&ett_v2giso20_struct_iso20_SignedInfoType,
		&ett_v2giso20_struct_iso20_SignatureValueType,
		&ett_v2giso20_struct_iso20_ObjectType,
		&ett_v2giso20_struct_iso20_CanonicalizationMethodType,
		&ett_v2giso20_struct_iso20_SignatureMethodType,
		&ett_v2giso20_struct_iso20_DigestMethodType,
		&ett_v2giso20_struct_iso20_ReferenceType,
		&ett_v2giso20_struct_iso20_TransformsType,
		&ett_v2giso20_struct_iso20_TransformType,
		&ett_v2giso20_struct_iso20_KeyInfoType,
		&ett_v2giso20_struct_iso20_KeyValueType,
		&ett_v2giso20_struct_iso20_DSAKeyValueType,
		&ett_v2giso20_struct_iso20_RSAKeyValueType,
		&ett_v2giso20_struct_iso20_RetrievalMethodType,
		&ett_v2giso20_struct_iso20_X509DataType,
		&ett_v2giso20_struct_iso20_X509IssuerSerialType,
		&ett_v2giso20_struct_iso20_PGPDataType,
		&ett_v2giso20_struct_iso20_SPKIDataType,

		&ett_v2giso20_struct_iso20_EVSEStatusType,
		&ett_v2giso20_struct_iso20_RationalNumberType,
		&ett_v2giso20_struct_iso20_MeterInfoType,
		&ett_v2giso20_struct_iso20_TargetPositionType,
		&ett_v2giso20_struct_iso20_ParameterType,
		&ett_v2giso20_struct_iso20_ParameterSetType,
		&ett_v2giso20_struct_iso20_MeasurementDataListType,
		&ett_v2giso20_struct_iso20_ListOfRootCertificateIDsType,
		&ett_v2giso20_struct_iso20_SubCertificatesType,
		&ett_v2giso20_struct_iso20_CertificateChainType,
		&ett_v2giso20_struct_iso20_SignedCertificateChainType,
		&ett_v2giso20_struct_iso20_EMAIDListType,
		&ett_v2giso20_struct_iso20_ChargingProfileType,
		&ett_v2giso20_struct_iso20_RelativeTimeIntervalType,
		&ett_v2giso20_struct_iso20_SAScheduleTupleType,
		&ett_v2giso20_struct_iso20_SAScheduleListType,
		&ett_v2giso20_struct_iso20_SelectedServiceType,
		&ett_v2giso20_struct_iso20_SelectedServiceListType,
		&ett_v2giso20_struct_iso20_ServiceParameterListType,
		&ett_v2giso20_struct_iso20_ServiceIDListType,
		&ett_v2giso20_struct_iso20_ServiceType,
		&ett_v2giso20_struct_iso20_ServiceListType,

		&ett_v2giso20_struct_iso20_SessionSetupReqType,
		&ett_v2giso20_struct_iso20_SessionSetupResType,
		&ett_v2giso20_struct_iso20_AuthorizationSetupReqType,
		&ett_v2giso20_struct_iso20_AuthorizationSetupResType,
		&ett_v2giso20_struct_iso20_AuthorizationReqType,
		&ett_v2giso20_struct_iso20_AuthorizationResType,
		&ett_v2giso20_struct_iso20_ServiceDiscoveryReqType,
		&ett_v2giso20_struct_iso20_ServiceDiscoveryResType,
		&ett_v2giso20_struct_iso20_ServiceDetailReqType,
		&ett_v2giso20_struct_iso20_ServiceDetailResType,
		&ett_v2giso20_struct_iso20_ServiceSelectionReqType,
		&ett_v2giso20_struct_iso20_ServiceSelectionResType,
		&ett_v2giso20_struct_iso20_ScheduleExchangeReqType,
		&ett_v2giso20_struct_iso20_ScheduleExchangeResType,
		&ett_v2giso20_struct_iso20_PowerDeliveryReqType,
		&ett_v2giso20_struct_iso20_PowerDeliveryResType,
		&ett_v2giso20_struct_iso20_MeteringConfirmationReqType,
		&ett_v2giso20_struct_iso20_MeteringConfirmationResType,
		&ett_v2giso20_struct_iso20_SessionStopReqType,
		&ett_v2giso20_struct_iso20_SessionStopResType,
		&ett_v2giso20_struct_iso20_CertificateInstallationReqType,
		&ett_v2giso20_struct_iso20_CertificateInstallationResType,
		&ett_v2giso20_struct_iso20_VehicleCheckInReqType,
		&ett_v2giso20_struct_iso20_VehicleCheckInResType,
		&ett_v2giso20_struct_iso20_VehicleCheckOutReqType,
		&ett_v2giso20_struct_iso20_VehicleCheckOutResType,
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
