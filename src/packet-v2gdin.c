/*
 * Copyright (c) 2022-2024 ChargePoint, Inc.
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

#include <inttypes.h>
#include <stdlib.h>

#include <wireshark.h>
#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/expert.h>

/* libcbv2g */
#include <cbv2g/din/din_msgDefDatatypes.h>
#include <cbv2g/din/din_msgDefDecoder.h>

#include "v2gexi.h"


/* forward declare */
void proto_register_v2gdin(void);
void proto_reg_handoff_v2gdin(void);


static dissector_handle_t v2gexi_handle;

static int proto_v2gdin = -1;

static int hf_v2gdin_struct_din_NotificationType_FaultCode = -1;
static int hf_v2gdin_struct_din_NotificationType_FaultMsg = -1;

static int hf_v2gdin_struct_din_SignatureType_Id = -1;
static int hf_v2gdin_struct_din_SignedInfoType_Id = -1;
static int hf_v2gdin_struct_din_SignatureValueType_Id = -1;
static int hf_v2gdin_struct_din_SignatureValueType_CONTENT = -1;

static int hf_v2gdin_struct_din_KeyInfoType_Id = -1;
static int hf_v2gdin_struct_din_KeyInfoType_KeyName = -1;
static int hf_v2gdin_struct_din_KeyInfoType_MgmtData = -1;
static int hf_v2gdin_struct_din_KeyInfoType_ANY = -1;
static int hf_v2gdin_struct_din_KeyValueType_ANY = -1;
static int hf_v2gdin_struct_din_DSAKeyValueType_P = -1;
static int hf_v2gdin_struct_din_DSAKeyValueType_Q = -1;
static int hf_v2gdin_struct_din_DSAKeyValueType_G = -1;
static int hf_v2gdin_struct_din_DSAKeyValueType_Y = -1;
static int hf_v2gdin_struct_din_DSAKeyValueType_J = -1;
static int hf_v2gdin_struct_din_DSAKeyValueType_Seed = -1;
static int hf_v2gdin_struct_din_DSAKeyValueType_PgenCounter = -1;
static int hf_v2gdin_struct_din_RSAKeyValueType_Modulus = -1;
static int hf_v2gdin_struct_din_RSAKeyValueType_Exponent = -1;

static int hf_v2gdin_struct_din_RetrievalMethodType_URI = -1;
static int hf_v2gdin_struct_din_RetrievalMethodType_Type = -1;

static int hf_v2gdin_struct_din_X509DataType_X509SKI = -1;
static int hf_v2gdin_struct_din_X509DataType_X509SubjectName = -1;
static int hf_v2gdin_struct_din_X509DataType_X509Certificate = -1;
static int hf_v2gdin_struct_din_X509DataType_X509CRL = -1;
static int hf_v2gdin_struct_din_X509DataType_ANY = -1;

static int hf_v2gdin_struct_din_X509IssuerSerialType_X509IssuerName = -1;
static int hf_v2gdin_struct_din_X509IssuerSerialType_X509SerialNumber = -1;

static int hf_v2gdin_struct_din_PGPDataType_PGPKeyID = -1;
static int hf_v2gdin_struct_din_PGPDataType_PGPKeyPacket = -1;
static int hf_v2gdin_struct_din_PGPDataType_ANY = -1;

static int hf_v2gdin_struct_din_SPKIDataType_SPKISexp = -1;
static int hf_v2gdin_struct_din_SPKIDataType_ANY = -1;

static int hf_v2gdin_struct_din_CanonicalizationMethodType_Algorithm = -1;
static int hf_v2gdin_struct_din_CanonicalizationMethodType_ANY = -1;

static int hf_v2gdin_struct_din_DigestMethodType_Algorithm = -1;
static int hf_v2gdin_struct_din_DigestMethodType_ANY = -1;

static int hf_v2gdin_struct_din_SignatureMethodType_Algorithm = -1;
static int hf_v2gdin_struct_din_SignatureMethodType_HMACOutputLength = -1;
static int hf_v2gdin_struct_din_SignatureMethodType_ANY = -1;

static int hf_v2gdin_struct_din_TransformType_Algorithm = -1;
static int hf_v2gdin_struct_din_TransformType_ANY = -1;
static int hf_v2gdin_struct_din_TransformType_XPath = -1;

static int hf_v2gdin_struct_din_ReferenceType_Id = -1;
static int hf_v2gdin_struct_din_ReferenceType_URI = -1;
static int hf_v2gdin_struct_din_ReferenceType_Type = -1;
static int hf_v2gdin_struct_din_ReferenceType_DigestValue = -1;

static int hf_v2gdin_struct_din_ObjectType_Id = -1;
static int hf_v2gdin_struct_din_ObjectType_MimeType = -1;
static int hf_v2gdin_struct_din_ObjectType_Encoding = -1;
static int hf_v2gdin_struct_din_ObjectType_ANY = -1;

static int hf_v2gdin_struct_din_ServiceTagType_ServiceID = -1;
static int hf_v2gdin_struct_din_ServiceTagType_ServiceName = -1;
static int hf_v2gdin_struct_din_ServiceTagType_ServiceCategory = -1;
static int hf_v2gdin_struct_din_ServiceTagType_ServiceScope = -1;

static int hf_v2gdin_struct_din_ServiceChargeType_FreeService = -1;
static int hf_v2gdin_struct_din_ServiceChargeType_EnergyTransferType = -1;

static int hf_v2gdin_struct_din_ServiceType_FreeService = -1;

static int hf_v2gdin_struct_din_SelectedServiceType_ServiceID = -1;
static int hf_v2gdin_struct_din_SelectedServiceType_ParameterSetID = -1;

static int hf_v2gdin_struct_din_ParameterSetType_ParameterSetID = -1;

static int hf_v2gdin_struct_din_ParameterType_Name = -1;
static int hf_v2gdin_struct_din_ParameterType_ValueType = -1;
static int hf_v2gdin_struct_din_ParameterType_boolValue = -1;
static int hf_v2gdin_struct_din_ParameterType_byteValue = -1;
static int hf_v2gdin_struct_din_ParameterType_shortValue = -1;
static int hf_v2gdin_struct_din_ParameterType_intValue = -1;
static int hf_v2gdin_struct_din_ParameterType_stringValue = -1;

static int hf_v2gdin_struct_din_PaymentOptionsType_PaymentOption = -1;

static int hf_v2gdin_struct_din_PhysicalValueType_Multiplier = -1;
static int hf_v2gdin_struct_din_PhysicalValueType_Unit = -1;
static int hf_v2gdin_struct_din_PhysicalValueType_Value = -1;

static int hf_v2gdin_struct_din_CertificateChainType_Certificate = -1;
static int hf_v2gdin_struct_din_SubCertificatesType_Certificate = -1;
static int hf_v2gdin_struct_din_ListOfRootCertificateIDsType_RootCertificateID = -1;

static int hf_v2gdin_struct_din_AC_EVChargeParameterType_DepartureTime = -1;

static int hf_v2gdin_struct_din_AC_EVSEStatusType_PowerSwitchClosed = -1;
static int hf_v2gdin_struct_din_AC_EVSEStatusType_RCD = -1;
static int hf_v2gdin_struct_din_AC_EVSEStatusType_NotificationMaxDelay = -1;
static int hf_v2gdin_struct_din_AC_EVSEStatusType_EVSENotification = -1;

static int hf_v2gdin_struct_din_DC_EVStatusType_EVReady = -1;
static int hf_v2gdin_struct_din_DC_EVStatusType_EVCabinConditioning = -1;
static int hf_v2gdin_struct_din_DC_EVStatusType_EVRESSConditioning = -1;
static int hf_v2gdin_struct_din_DC_EVStatusType_EVErrorCode = -1;
static int hf_v2gdin_struct_din_DC_EVStatusType_EVRESSSOC = -1;

static int hf_v2gdin_struct_din_DC_EVSEStatusType_EVSEIsolationStatus = -1;
static int hf_v2gdin_struct_din_DC_EVSEStatusType_EVSEStatusCode = -1;
static int hf_v2gdin_struct_din_DC_EVSEStatusType_NotificationMaxDelay = -1;
static int hf_v2gdin_struct_din_DC_EVSEStatusType_EVSENotification = -1;

static int hf_v2gdin_struct_din_DC_EVChargeParameterType_FullSOC = -1;
static int hf_v2gdin_struct_din_DC_EVChargeParameterType_BulkSOC = -1;

static int hf_v2gdin_struct_din_SAScheduleTupleType_SAScheduleTupleID = -1;

static int hf_v2gdin_struct_din_PMaxScheduleType_PMaxScheduleID = -1;
static int hf_v2gdin_struct_din_PMaxScheduleEntryType_PMax = -1;

static int hf_v2gdin_struct_din_RelativeTimeIntervalType_start = -1;
static int hf_v2gdin_struct_din_RelativeTimeIntervalType_duration = -1;

static int hf_v2gdin_struct_din_SalesTariffType_Id = -1;
static int hf_v2gdin_struct_din_SalesTariffType_SalesTariffDescription = -1;
static int hf_v2gdin_struct_din_SalesTariffType_NumEPriceLevels = -1;
static int hf_v2gdin_struct_din_SalesTariffEntryType_EPriceLevel = -1;
static int hf_v2gdin_struct_din_ConsumptionCostType_startValue = -1;
static int hf_v2gdin_struct_din_CostType_costKind = -1;
static int hf_v2gdin_struct_din_CostType_amount = -1;
static int hf_v2gdin_struct_din_CostType_amountMultiplier = -1;

static int hf_v2gdin_struct_din_ChargingProfileType_SAScheduleTupleID = -1;

static int hf_v2gdin_struct_din_ProfileEntryType_ChargingProfileEntryStart = -1;
static int hf_v2gdin_struct_din_ProfileEntryType_ChargingProfileEntryMaxPower = -1;

static int hf_v2gdin_struct_din_DC_EVPowerDeliveryParameterType_BulkChargingComplete = -1;
static int hf_v2gdin_struct_din_DC_EVPowerDeliveryParameterType_ChargingComplete = -1;

static int hf_v2gdin_struct_din_MeterInfoType_MeterID = -1;
static int hf_v2gdin_struct_din_MeterInfoType_SigMeterReading = -1;
static int hf_v2gdin_struct_din_MeterInfoType_MeterStatus = -1;
static int hf_v2gdin_struct_din_MeterInfoType_TMeter = -1;

static int hf_v2gdin_struct_din_MessageHeaderType_SessionID = -1;

static int hf_v2gdin_struct_din_SessionSetupReqType_EVCCID = -1;
static int hf_v2gdin_struct_din_SessionSetupResType_ResponseCode = -1;
static int hf_v2gdin_struct_din_SessionSetupResType_EVSEID = -1;
static int hf_v2gdin_struct_din_SessionSetupResType_DateTimeNow = -1;
static int hf_v2gdin_struct_din_ServiceDiscoveryReqType_ServiceScope = -1;
static int hf_v2gdin_struct_din_ServiceDiscoveryReqType_ServiceCategory = -1;
static int hf_v2gdin_struct_din_ServiceDiscoveryResType_ResponseCode = -1;
static int hf_v2gdin_struct_din_ServiceDetailReqType_ServiceID = -1;
static int hf_v2gdin_struct_din_ServiceDetailResType_ResponseCode = -1;
static int hf_v2gdin_struct_din_ServiceDetailResType_ServiceID = -1;
static int hf_v2gdin_struct_din_ServicePaymentSelectionReqType_SelectedPaymentOption = -1;
static int hf_v2gdin_struct_din_ServicePaymentSelectionResType_ResponseCode = -1;
static int hf_v2gdin_struct_din_PaymentDetailsReqType_ContractID = -1;
static int hf_v2gdin_struct_din_PaymentDetailsResType_ResponseCode = -1;
static int hf_v2gdin_struct_din_PaymentDetailsResType_GenChallenge = -1;
static int hf_v2gdin_struct_din_PaymentDetailsResType_DateTimeNow = -1;
static int hf_v2gdin_struct_din_ContractAuthenticationReqType_Id = -1;
static int hf_v2gdin_struct_din_ContractAuthenticationReqType_GenChallenge = -1;
static int hf_v2gdin_struct_din_ContractAuthenticationResType_ResponseCode = -1;
static int hf_v2gdin_struct_din_ContractAuthenticationResType_EVSEProcessing = -1;
static int hf_v2gdin_struct_din_ChargeParameterDiscoveryReqType_EVRequestedEnergyTransferType = -1;
static int hf_v2gdin_struct_din_ChargeParameterDiscoveryResType_ResponseCode = -1;
static int hf_v2gdin_struct_din_ChargeParameterDiscoveryResType_EVSEProcessing = -1;

static int hf_v2gdin_struct_din_PowerDeliveryReqType_ReadyToChargeState = -1;
static int hf_v2gdin_struct_din_PowerDeliveryResType_ResponseCode = -1;

static int hf_v2gdin_struct_din_ChargingStatusResType_ResponseCode = -1;
static int hf_v2gdin_struct_din_ChargingStatusResType_EVSEID = -1;
static int hf_v2gdin_struct_din_ChargingStatusResType_SAScheduleTupleID = -1;
static int hf_v2gdin_struct_din_ChargingStatusResType_ReceiptRequired = -1;

static int hf_v2gdin_struct_din_MeteringReceiptReqType_Id = -1;
static int hf_v2gdin_struct_din_MeteringReceiptReqType_SessionID = -1;
static int hf_v2gdin_struct_din_MeteringReceiptReqType_SAScheduleTupleID = -1;
static int hf_v2gdin_struct_din_MeteringReceiptResType_ResponseCode = -1;

static int hf_v2gdin_struct_din_SessionStopResType_ResponseCode = -1;

static int hf_v2gdin_struct_din_CertificateUpdateReqType_Id = -1;
static int hf_v2gdin_struct_din_CertificateUpdateReqType_ContractID = -1;
static int hf_v2gdin_struct_din_CertificateUpdateReqType_DHParams = -1;
static int hf_v2gdin_struct_din_CertificateUpdateResType_Id = -1;
static int hf_v2gdin_struct_din_CertificateUpdateResType_ResponseCode = -1;
static int hf_v2gdin_struct_din_CertificateUpdateResType_ContractID = -1;
static int hf_v2gdin_struct_din_CertificateUpdateResType_DHParams = -1;
static int hf_v2gdin_struct_din_CertificateUpdateResType_RetryCounter = -1;
static int hf_v2gdin_struct_din_CertificateUpdateResType_ContractSignatureEncryptedPrivateKey = -1;

static int hf_v2gdin_struct_din_CertificateInstallationReqType_Id = -1;
static int hf_v2gdin_struct_din_CertificateInstallationReqType_OEMProvisioningCert = -1;
static int hf_v2gdin_struct_din_CertificateInstallationReqType_DHParams = -1;
static int hf_v2gdin_struct_din_CertificateInstallationResType_Id = -1;
static int hf_v2gdin_struct_din_CertificateInstallationResType_ResponseCode = -1;
static int hf_v2gdin_struct_din_CertificateInstallationResType_ContractSignatureEncryptedPrivateKey = -1;
static int hf_v2gdin_struct_din_CertificateInstallationResType_DHParams = -1;
static int hf_v2gdin_struct_din_CertificateInstallationResType_ContractID = -1;

static int hf_v2gdin_struct_din_CableCheckResType_ResponseCode = -1;
static int hf_v2gdin_struct_din_CableCheckResType_EVSEProcessing = -1;

static int hf_v2gdin_struct_din_PreChargeResType_ResponseCode = -1;

static int hf_v2gdin_struct_din_CurrentDemandReqType_ChargingComplete = -1;
static int hf_v2gdin_struct_din_CurrentDemandReqType_BulkChargingComplete = -1;
static int hf_v2gdin_struct_din_CurrentDemandResType_ResponseCode = -1;
static int hf_v2gdin_struct_din_CurrentDemandResType_EVSECurrentLimitAchieved = -1;
static int hf_v2gdin_struct_din_CurrentDemandResType_EVSEVoltageLimitAchieved = -1;
static int hf_v2gdin_struct_din_CurrentDemandResType_EVSEPowerLimitAchieved = -1;

static int hf_v2gdin_struct_din_WeldingDetectionResType_ResponseCode = -1;

/* Specifically track voltage and current for graphing */
static int hf_v2gdin_ev_target_voltage = -1;
static int hf_v2gdin_ev_target_current = -1;
static int hf_v2gdin_ev_maximum_voltage_limit = -1;
static int hf_v2gdin_ev_maximum_current_limit = -1;
static int hf_v2gdin_ev_maximum_power_limit = -1;
static int hf_v2gdin_remaining_time_to_full_soc = -1;
static int hf_v2gdin_remaining_time_to_bulk_soc = -1;
static int hf_v2gdin_evse_present_voltage = -1;
static int hf_v2gdin_evse_present_current = -1;
static int hf_v2gdin_evse_maximum_voltage_limit = -1;
static int hf_v2gdin_evse_maximum_current_limit = -1;
static int hf_v2gdin_evse_maximum_power_limit = -1;

/* Initialize the subtree pointers */
static gint ett_v2gdin = -1;
static gint ett_v2gdin_header = -1;
static gint ett_v2gdin_body = -1;
static gint ett_v2gdin_array = -1;
static gint ett_v2gdin_array_i = -1;

static gint ett_v2gdin_struct_din_NotificationType = -1;
static gint ett_v2gdin_struct_din_SignatureType = -1;
static gint ett_v2gdin_struct_din_SignedInfoType = -1;
static gint ett_v2gdin_struct_din_CanonicalizationMethodType = -1;
static gint ett_v2gdin_struct_din_DigestMethodType = -1;
static gint ett_v2gdin_struct_din_SignatureMethodType = -1;
static gint ett_v2gdin_struct_din_ReferenceType = -1;
static gint ett_v2gdin_struct_din_TransformsType = -1;
static gint ett_v2gdin_struct_din_TransformType = -1;
static gint ett_v2gdin_struct_din_SignatureValueType = -1;
static gint ett_v2gdin_struct_din_KeyInfoType = -1;
static gint ett_v2gdin_struct_din_KeyValueType = -1;
static gint ett_v2gdin_struct_din_DSAKeyValueType = -1;
static gint ett_v2gdin_struct_din_RSAKeyValueType = -1;
static gint ett_v2gdin_struct_din_RetrievalMethodType = -1;
static gint ett_v2gdin_struct_din_X509IssuerSerialType = -1;
static gint ett_v2gdin_struct_din_X509DataType = -1;
static gint ett_v2gdin_struct_din_PGPDataType = -1;
static gint ett_v2gdin_struct_din_SPKIDataType = -1;
static gint ett_v2gdin_struct_din_ObjectType = -1;
static gint ett_v2gdin_struct_din_ServiceParameterListType = -1;
static gint ett_v2gdin_struct_din_ServiceTagListType = -1;
static gint ett_v2gdin_struct_din_ServiceTagType = -1;
static gint ett_v2gdin_struct_din_ServiceChargeType = -1;
static gint ett_v2gdin_struct_din_ServiceType = -1;
static gint ett_v2gdin_struct_din_SelectedServiceType = -1;
static gint ett_v2gdin_struct_din_SelectedServiceListType = -1;
static gint ett_v2gdin_struct_din_ParameterSetType = -1;
static gint ett_v2gdin_struct_din_ParameterType = -1;
static gint ett_v2gdin_struct_din_PhysicalValueType = -1;
static gint ett_v2gdin_struct_din_PaymentOptionsType = -1;
static gint ett_v2gdin_struct_din_CertificateChainType = -1;
static gint ett_v2gdin_struct_din_SubCertificatesType = -1;
static gint ett_v2gdin_struct_din_ListOfRootCertificateIDsType = -1;
static gint ett_v2gdin_struct_din_EVChargeParameterType = -1;
static gint ett_v2gdin_struct_din_AC_EVChargeParameterType = -1;
static gint ett_v2gdin_struct_din_DC_EVChargeParameterType = -1;
static gint ett_v2gdin_struct_din_DC_EVStatusType = -1;
static gint ett_v2gdin_struct_din_EVSEChargeParameterType = -1;
static gint ett_v2gdin_struct_din_EVSEStatusType = -1;
static gint ett_v2gdin_struct_din_AC_EVSEChargeParameterType = -1;
static gint ett_v2gdin_struct_din_AC_EVSEStatusType = -1;
static gint ett_v2gdin_struct_din_DC_EVSEChargeParameterType = -1;
static gint ett_v2gdin_struct_din_DC_EVSEStatusType = -1;
static gint ett_v2gdin_struct_din_SASchedulesType = -1;
static gint ett_v2gdin_struct_din_SAScheduleListType = -1;
static gint ett_v2gdin_struct_din_SAScheduleTupleType = -1;
static gint ett_v2gdin_struct_din_PMaxScheduleType = -1;
static gint ett_v2gdin_struct_din_PMaxScheduleEntryType = -1;
static gint ett_v2gdin_struct_din_RelativeTimeIntervalType = -1;
static gint ett_v2gdin_struct_din_IntervalType = -1;
static gint ett_v2gdin_struct_din_SalesTariffType = -1;
static gint ett_v2gdin_struct_din_SalesTariffEntryType = -1;
static gint ett_v2gdin_struct_din_ConsumptionCostType = -1;
static gint ett_v2gdin_struct_din_CostType = -1;
static gint ett_v2gdin_struct_din_ChargingProfileType = -1;
static gint ett_v2gdin_struct_din_EVPowerDeliveryParameterType = -1;
static gint ett_v2gdin_struct_din_DC_EVPowerDeliveryParameterType = -1;
static gint ett_v2gdin_struct_din_ProfileEntryType = -1;
static gint ett_v2gdin_struct_din_MeterInfoType = -1;

static gint ett_v2gdin_struct_din_SessionSetupReqType = -1;
static gint ett_v2gdin_struct_din_SessionSetupResType = -1;
static gint ett_v2gdin_struct_din_ServiceDiscoveryReqType = -1;
static gint ett_v2gdin_struct_din_ServiceDiscoveryResType = -1;
static gint ett_v2gdin_struct_din_ServiceDetailReqType = -1;
static gint ett_v2gdin_struct_din_ServiceDetailResType = -1;
static gint ett_v2gdin_struct_din_ServicePaymentSelectionReqType = -1;
static gint ett_v2gdin_struct_din_ServicePaymentSelectionResType = -1;
static gint ett_v2gdin_struct_din_PaymentDetailsReqType = -1;
static gint ett_v2gdin_struct_din_PaymentDetailsResType = -1;
static gint ett_v2gdin_struct_din_ContractAuthenticationReqType = -1;
static gint ett_v2gdin_struct_din_ContractAuthenticationResType = -1;
static gint ett_v2gdin_struct_din_ChargeParameterDiscoveryReqType = -1;
static gint ett_v2gdin_struct_din_ChargeParameterDiscoveryResType = -1;
static gint ett_v2gdin_struct_din_PowerDeliveryReqType = -1;
static gint ett_v2gdin_struct_din_PowerDeliveryResType = -1;
static gint ett_v2gdin_struct_din_ChargingStatusReqType = -1;
static gint ett_v2gdin_struct_din_ChargingStatusResType = -1;
static gint ett_v2gdin_struct_din_MeteringReceiptReqType = -1;
static gint ett_v2gdin_struct_din_MeteringReceiptResType = -1;
static gint ett_v2gdin_struct_din_SessionStopType = -1;
static gint ett_v2gdin_struct_din_SessionStopResType = -1;
static gint ett_v2gdin_struct_din_CertificateUpdateReqType = -1;
static gint ett_v2gdin_struct_din_CertificateUpdateResType = -1;
static gint ett_v2gdin_struct_din_CertificateInstallationReqType = -1;
static gint ett_v2gdin_struct_din_CertificateInstallationResType = -1;
static gint ett_v2gdin_struct_din_CableCheckReqType = -1;
static gint ett_v2gdin_struct_din_CableCheckResType = -1;
static gint ett_v2gdin_struct_din_PreChargeReqType = -1;
static gint ett_v2gdin_struct_din_PreChargeResType = -1;
static gint ett_v2gdin_struct_din_CurrentDemandReqType = -1;
static gint ett_v2gdin_struct_din_CurrentDemandResType = -1;
static gint ett_v2gdin_struct_din_WeldingDetectionReqType = -1;
static gint ett_v2gdin_struct_din_WeldingDetectionResType = -1;

static const value_string v2gdin_fault_code_names[] = {
	{ din_faultCodeType_ParsingError, "ParsingError" },
	{ din_faultCodeType_NoTLSRootCertificatAvailable,
	  "NoTLSRootCertificatAvailable" },
	{ din_faultCodeType_UnknownError, "UnknownError" },
	{ 0, NULL }
};

static const value_string v2gdin_response_code_names[] = {
	{ din_responseCodeType_OK, "OK" },
	{ din_responseCodeType_OK_NewSessionEstablished,
	  "OK (NewSessionEstablished)" },
	{ din_responseCodeType_OK_OldSessionJoined,
	  "OK (OldSessionJoined) " },
	{ din_responseCodeType_OK_CertificateExpiresSoon,
	  "OK (CertificateExpiresSoon)" },
	{ din_responseCodeType_FAILED, "FAILED" },
	{ din_responseCodeType_FAILED_SequenceError,
	  "FAILED (SequenceError)" },
	{ din_responseCodeType_FAILED_ServiceIDInvalid,
	  "FAILED (ServiceIDInvalid)" },
	{ din_responseCodeType_FAILED_UnknownSession,
	  "FAILED (UnknownSession)" },
	{ din_responseCodeType_FAILED_ServiceSelectionInvalid,
	  "FAILED (ServiceSelectionInvalid)" },
	{ din_responseCodeType_FAILED_PaymentSelectionInvalid,
	  "FAILED (PaymentSelectionInvalid)" },
	{ din_responseCodeType_FAILED_CertificateExpired,
	  "FAILED (CertificateExpired)" },
	{ din_responseCodeType_FAILED_SignatureError,
	  "FAILED (SignatureError)" },
	{ din_responseCodeType_FAILED_NoCertificateAvailable,
	  "FAILED (NoCertificateAvailable)" },
	{ din_responseCodeType_FAILED_CertChainError,
	  "FAILED (CertChainError)" },
	{ din_responseCodeType_FAILED_ChallengeInvalid,
	  "FAILED (ChallengeInvalid)" },
	{ din_responseCodeType_FAILED_ContractCanceled,
	  "FAILED (ContractCanceled)" },
	{ din_responseCodeType_FAILED_WrongChargeParameter,
	  "FAILED (WrongChargeParameter)" },
	{ din_responseCodeType_FAILED_PowerDeliveryNotApplied,
	  "FAILED (PowerDeliveryNotApplied)" },
	{ din_responseCodeType_FAILED_TariffSelectionInvalid,
	  "FAILED (TariffSelectionInvalid)" },
	{ din_responseCodeType_FAILED_ChargingProfileInvalid,
	  "FAILED (ChargingProfileInvalid)" },
	{ din_responseCodeType_FAILED_EVSEPresentVoltageToLow,
	  "FAILED (EVSEPresentVoltageToLow)" },
	{ din_responseCodeType_FAILED_MeteringSignatureNotValid,
	  "FAILED (MeteringSignatureNotValid)" },
	{ din_responseCodeType_FAILED_WrongEnergyTransferType,
	  "FAILED (WrongEnergyTransferType)" },
	{ 0, NULL }
};

static const value_string v2gdin_service_category_names[] = {
	{ din_serviceCategoryType_EVCharging, "EVCharging" },
	{ din_serviceCategoryType_Internet, "Internet" },
	{ din_serviceCategoryType_ContractCertificate, "ContractCertificate" },
	{ din_serviceCategoryType_OtherCustom, "OtherCustom" },
	{ 0, NULL }
};

static const value_string v2gdin_payment_option_names[] = {
	{ din_paymentOptionType_Contract, "Contract" },
	{ din_paymentOptionType_ExternalPayment, "ExternalPayment" },
	{ 0, NULL }
};

static const value_string v2gdin_ev_requested_energy_transfer[] = {
	{ din_EVRequestedEnergyTransferType_AC_single_phase_core,
	  "AC_single_phase_core" },
	{ din_EVRequestedEnergyTransferType_AC_three_phase_core,
	  "AC_three_phase_core" },
	{ din_EVRequestedEnergyTransferType_DC_core, "DC_core" },
	{ din_EVRequestedEnergyTransferType_DC_extended, "DC_extended" },
	{ din_EVRequestedEnergyTransferType_DC_combo_core, "DC_combo_core" },
	{ din_EVRequestedEnergyTransferType_DC_unique, "DC_unique" },
	{ 0, NULL }
};

static const value_string v2gdin_evse_supported_energy_transfer_names[] = {
	{ din_EVSESupportedEnergyTransferType_AC_single_phase_core,
	  "AC_single_phase_core" },
	{ din_EVSESupportedEnergyTransferType_AC_three_phase_core,
	  "AC_three_phase_core" },
	{ din_EVSESupportedEnergyTransferType_DC_core,
	  "DC_core" },
	{ din_EVSESupportedEnergyTransferType_DC_extended,
	  "DC_extended" },
	{ din_EVSESupportedEnergyTransferType_DC_combo_core,
	  "DC_combo_core" },
	{ din_EVSESupportedEnergyTransferType_DC_dual,
	  "DC_dual" },
	{ din_EVSESupportedEnergyTransferType_AC_core1p_DC_extended,
	  "AC_core1p_DC_extended" },
	{ din_EVSESupportedEnergyTransferType_AC_single_DC_core,
	  "AC_single_DC_core" },
	{ din_EVSESupportedEnergyTransferType_AC_single_phase_three_phase_core_DC_extended,
	  "AC_single_phase_three_phase_core_DC_extended" },
	{ din_EVSESupportedEnergyTransferType_AC_core3p_DC_extended,
	  "AC_core3p_DC_extended" },
	{ 0, NULL }
};

static const value_string v2gdin_isolation_level_names[] = {
	{ din_isolationLevelType_Invalid, "Invalid" },
	{ din_isolationLevelType_Valid, "Valid" },
	{ din_isolationLevelType_Warning, "Warning" },
	{ din_isolationLevelType_Fault, "Fault" },
	{ 0, NULL }
};

static const value_string v2gdin_evse_processing_names[] = {
	{ din_EVSEProcessingType_Finished, "Finished" },
	{ din_EVSEProcessingType_Ongoing, "Ongoing" },
	{ 0, NULL }
};

static const value_string v2gdin_dc_everrorcode_names[] = {
	{ din_DC_EVErrorCodeType_NO_ERROR, "NO ERROR" },
	{ din_DC_EVErrorCodeType_FAILED_RESSTemperatureInhibit,
	  "FAILED (RESSTemperatureInhibit)" },
	{ din_DC_EVErrorCodeType_FAILED_EVShiftPosition,
	  "FAILED (EVShiftPosition)" },
	{ din_DC_EVErrorCodeType_FAILED_ChargerConnectorLockFault,
	  "FAILED (ChargerConnectorLockFault)" },
	{ din_DC_EVErrorCodeType_FAILED_EVRESSMalfunction,
	  "FAILED (EVRESSMalfunction)" },
	{ din_DC_EVErrorCodeType_FAILED_ChargingCurrentdifferential,
	  "FAILED (ChargingCurrentdifferential)" },
	{ din_DC_EVErrorCodeType_FAILED_ChargingVoltageOutOfRange,
	  "FAILED (ChargingVoltageOutOfRange)" },
	{ din_DC_EVErrorCodeType_Reserved_A, "Reserved A" },
	{ din_DC_EVErrorCodeType_Reserved_B, "Reserved B" },
	{ din_DC_EVErrorCodeType_Reserved_C, "Reserved C" },
	{ din_DC_EVErrorCodeType_FAILED_ChargingSystemIncompatibility,
	  "FAILED (ChargingSystemIncompatibility)" },
	{ din_DC_EVErrorCodeType_NoData, "NoData" },
	{ 0, NULL }
};

static const value_string v2gdin_dc_evsestatuscode_names[] = {
	{ din_DC_EVSEStatusCodeType_EVSE_NotReady, "EVSE NotReady" },
	{ din_DC_EVSEStatusCodeType_EVSE_Ready, "EVSE Ready" },
	{ din_DC_EVSEStatusCodeType_EVSE_Shutdown, "EVSE Shutdown" },
	{ din_DC_EVSEStatusCodeType_EVSE_UtilityInterruptEvent,
	  "EVSE UtilityInterruptEvent" },
	{ din_DC_EVSEStatusCodeType_EVSE_IsolationMonitoringActive,
	  "EVSE IsolationMonitoringActive" },
	{ din_DC_EVSEStatusCodeType_EVSE_EmergencyShutdown,
	  "EVSE EmergencyShutdown" },
	{ din_DC_EVSEStatusCodeType_EVSE_Malfunction,
	  "EVSE Malfunction" },
	{ din_DC_EVSEStatusCodeType_Reserved_8, "Reserved 8" },
	{ din_DC_EVSEStatusCodeType_Reserved_9, "Reserved 9" },
	{ din_DC_EVSEStatusCodeType_Reserved_A, "Reserved A" },
	{ din_DC_EVSEStatusCodeType_Reserved_B, "Reserved B" },
	{ din_DC_EVSEStatusCodeType_Reserved_C, "Reserved C" },
	{ 0, NULL }
};

static const value_string v2gdin_evsenotification_names[] = {
	{ din_EVSENotificationType_None, "None" },
	{ din_EVSENotificationType_StopCharging, "StopCharging" },
	{ din_EVSENotificationType_ReNegotiation, "ReNegotiation" },
	{ 0, NULL }
};

static const value_string v2gdin_unitsymbol_names[] = {
	{ din_unitSymbolType_h, "h" },
	{ din_unitSymbolType_m, "m" },
	{ din_unitSymbolType_s, "s" },
	{ din_unitSymbolType_A, "A" },
	{ din_unitSymbolType_Ah, "Ah" },
	{ din_unitSymbolType_V, "V" },
	{ din_unitSymbolType_VA, "VA" },
	{ din_unitSymbolType_W, "W" },
	{ din_unitSymbolType_W_s, "W_s" },
	{ din_unitSymbolType_Wh, "Wh" },
	{ 0, NULL }
};

static const value_string v2gdin_cost_kind_names[] = {
	{ din_costKindType_relativePricePercentage, "relativePricePercentage" },
	{ din_costKindType_RenewableGenerationPercentage,
	  "RenewableGenerationPercentage" },
	{ din_costKindType_CarbonDioxideEmission, "CarbonDioxideEmission" },
	{ 0, NULL }
};


static void
dissect_v2gdin_notification(const struct din_NotificationType *notification,
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
		hf_v2gdin_struct_din_NotificationType_FaultCode,
		tvb, 0, 0, notification->FaultCode);
	proto_item_set_generated(it);

	if (notification->FaultMsg_isUsed) {
		exi_add_characters(subtree,
			hf_v2gdin_struct_din_NotificationType_FaultMsg,
			tvb,
			notification->FaultMsg.characters,
			notification->FaultMsg.charactersLen,
			sizeof(notification->FaultMsg.characters));
	}

	return;
}

static void
dissect_v2gdin_object(const struct din_ObjectType *object,
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
			hf_v2gdin_struct_din_ObjectType_Id,
			tvb,
			object->Id.characters,
			object->Id.charactersLen,
			sizeof(object->Id.characters));
	}
	if (object->MimeType_isUsed) {
		exi_add_characters(subtree,
			hf_v2gdin_struct_din_ObjectType_MimeType,
			tvb,
			object->MimeType.characters,
			object->MimeType.charactersLen,
			sizeof(object->MimeType.characters));
	}
	if (object->Encoding_isUsed) {
		exi_add_characters(subtree,
			hf_v2gdin_struct_din_ObjectType_Encoding,
			tvb,
			object->Encoding.characters,
			object->Encoding.charactersLen,
			sizeof(object->Encoding.characters));
	}
	if (object->ANY_isUsed) {
		exi_add_bytes(subtree,
			hf_v2gdin_struct_din_ObjectType_ANY,
			tvb,
			object->ANY.bytes,
			object->ANY.bytesLen,
			sizeof(object->ANY.bytes));
	}

	return;
}

static void
dissect_v2gdin_transform(const struct din_TransformType *transform,
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
		hf_v2gdin_struct_din_TransformType_Algorithm,
		tvb,
		transform->Algorithm.characters,
		transform->Algorithm.charactersLen,
		sizeof(transform->Algorithm.characters));

	if (transform->ANY_isUsed) {
		exi_add_bytes(subtree,
			hf_v2gdin_struct_din_TransformType_ANY,
			tvb,
			transform->ANY.bytes,
			transform->ANY.bytesLen,
			sizeof(transform->ANY.bytes));
	}

	if (transform->XPath_isUsed) {
		exi_add_characters(subtree,
			hf_v2gdin_struct_din_TransformType_XPath,
			tvb,
			transform->XPath.characters,
			transform->XPath.charactersLen,
			sizeof(transform->XPath.characters));
	}

	return;
}

static void
dissect_v2gdin_transforms(const struct din_TransformsType *transforms,
			  tvbuff_t *tvb,
			  packet_info *pinfo,
			  proto_tree *tree,
			  gint idx,
			  const char *subtree_name)
{
	proto_tree *subtree;

	subtree = proto_tree_add_subtree(tree,
		tvb, 0, 0, idx, NULL, subtree_name);

	dissect_v2gdin_transform(&transforms->Transform,
		tvb, pinfo, subtree,
		ett_v2gdin_struct_din_TransformType, "Transform");

	return;
}

static void
dissect_v2gdin_digestmethod(const struct din_DigestMethodType *digestmethod,
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
		hf_v2gdin_struct_din_DigestMethodType_Algorithm,
		tvb,
		digestmethod->Algorithm.characters,
		digestmethod->Algorithm.charactersLen,
		sizeof(digestmethod->Algorithm.characters));

	if (digestmethod->ANY_isUsed) {
		exi_add_bytes(subtree,
			hf_v2gdin_struct_din_DigestMethodType_ANY,
			tvb,
			digestmethod->ANY.bytes,
			digestmethod->ANY.bytesLen,
			sizeof(digestmethod->ANY.bytes));
	}

	return;
}

static void
dissect_v2gdin_reference(const struct din_ReferenceType *reference,
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
			hf_v2gdin_struct_din_ReferenceType_Id,
			tvb,
			reference->Id.characters,
			reference->Id.charactersLen,
			sizeof(reference->Id.characters));
	}
	if (reference->URI_isUsed) {
		exi_add_characters(subtree,
			hf_v2gdin_struct_din_ReferenceType_URI,
			tvb,
			reference->URI.characters,
			reference->URI.charactersLen,
			sizeof(reference->URI.characters));
	}
	if (reference->Type_isUsed) {
		exi_add_characters(subtree,
			hf_v2gdin_struct_din_ReferenceType_Type,
			tvb,
			reference->Type.characters,
			reference->Type.charactersLen,
			sizeof(reference->Type.characters));
	}
	if (reference->Transforms_isUsed) {
		dissect_v2gdin_transforms(&reference->Transforms,
			tvb, pinfo, subtree,
			ett_v2gdin_struct_din_TransformsType,
			"Transforms");
	}

	dissect_v2gdin_digestmethod(&reference->DigestMethod,
			tvb, pinfo, subtree,
			ett_v2gdin_struct_din_DigestMethodType,
			"DigestMethod");

	exi_add_bytes(subtree,
		hf_v2gdin_struct_din_ReferenceType_DigestValue,
		tvb,
		reference->DigestValue.bytes,
		reference->DigestValue.bytesLen,
		sizeof(reference->DigestValue.bytes));

	return;
}

static void
dissect_v2gdin_canonicalizationmethod(
	const struct din_CanonicalizationMethodType *canonicalizationmethod,
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
		hf_v2gdin_struct_din_CanonicalizationMethodType_Algorithm,
		tvb,
		canonicalizationmethod->Algorithm.characters,
		canonicalizationmethod->Algorithm.charactersLen,
		sizeof(canonicalizationmethod->Algorithm.characters));

	if (canonicalizationmethod->ANY_isUsed) {
		exi_add_bytes(subtree,
			hf_v2gdin_struct_din_CanonicalizationMethodType_ANY,
			tvb,
			canonicalizationmethod->ANY.bytes,
			canonicalizationmethod->ANY.bytesLen,
			sizeof(canonicalizationmethod->ANY.bytes));
	}

	return;
}

static void
dissect_v2gdin_signaturemethod(
	const struct din_SignatureMethodType *signaturemethod,
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
		hf_v2gdin_struct_din_SignatureMethodType_Algorithm,
		tvb,
		signaturemethod->Algorithm.characters,
		signaturemethod->Algorithm.charactersLen,
		sizeof(signaturemethod->Algorithm.characters));

	if (signaturemethod->HMACOutputLength_isUsed) {
		it = proto_tree_add_int64(subtree,
			hf_v2gdin_struct_din_SignatureMethodType_HMACOutputLength,
			tvb, 0, 0, signaturemethod->HMACOutputLength);
		proto_item_set_generated(it);
	}

	if (signaturemethod->ANY_isUsed) {
		exi_add_bytes(subtree,
			hf_v2gdin_struct_din_SignatureMethodType_ANY,
			tvb,
			signaturemethod->ANY.bytes,
			signaturemethod->ANY.bytesLen,
			sizeof(signaturemethod->ANY.bytes));
	}

	return;
}

static void
dissect_v2gdin_signaturevalue(
	const struct din_SignatureValueType *signaturevalue,
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
			hf_v2gdin_struct_din_SignatureValueType_Id,
			tvb,
			signaturevalue->Id.characters,
			signaturevalue->Id.charactersLen,
			sizeof(signaturevalue->Id.characters));
	}

	exi_add_bytes(subtree,
		hf_v2gdin_struct_din_SignatureValueType_CONTENT,
		tvb,
		signaturevalue->CONTENT.bytes,
		signaturevalue->CONTENT.bytesLen,
		sizeof(signaturevalue->CONTENT.bytes));

	return;
}

static void
dissect_v2gdin_signedinfo(const struct din_SignedInfoType *signedinfo,
			  tvbuff_t *tvb,
			  packet_info *pinfo,
			  proto_tree *tree,
			  gint idx,
			  const char *subtree_name)
{
	proto_tree *subtree;

	subtree = proto_tree_add_subtree(tree,
		tvb, 0, 0, idx, NULL, subtree_name);

	if (signedinfo->Id_isUsed) {
		exi_add_characters(subtree,
			hf_v2gdin_struct_din_SignedInfoType_Id,
			tvb,
			signedinfo->Id.characters,
			signedinfo->Id.charactersLen,
			sizeof(signedinfo->Id.characters));
	}

	dissect_v2gdin_canonicalizationmethod(
		&signedinfo->CanonicalizationMethod,
		tvb, pinfo, subtree,
		ett_v2gdin_struct_din_CanonicalizationMethodType,
		"CanonicalizationMethod");
	dissect_v2gdin_signaturemethod(
		&signedinfo->SignatureMethod,
		tvb, pinfo, subtree,
		ett_v2gdin_struct_din_SignatureMethodType,
		"SignatureMethod");
	dissect_v2gdin_reference(&signedinfo->Reference,
		tvb, pinfo, subtree,
		ett_v2gdin_struct_din_ReferenceType,
		"Reference");

	return;
}

static void
dissect_v2gdin_dsakeyvalue(const struct din_DSAKeyValueType *dsakeyvalue,
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
			hf_v2gdin_struct_din_DSAKeyValueType_P,
			tvb,
			dsakeyvalue->P.bytes,
			dsakeyvalue->P.bytesLen,
			sizeof(dsakeyvalue->P.bytes));
	}
	if (dsakeyvalue->Q_isUsed) {
		exi_add_bytes(subtree,
			hf_v2gdin_struct_din_DSAKeyValueType_Q,
			tvb,
			dsakeyvalue->Q.bytes,
			dsakeyvalue->Q.bytesLen,
			sizeof(dsakeyvalue->Q.bytes));
	}
	if (dsakeyvalue->G_isUsed) {
		exi_add_bytes(subtree,
			hf_v2gdin_struct_din_DSAKeyValueType_G,
			tvb,
			dsakeyvalue->G.bytes,
			dsakeyvalue->G.bytesLen,
			sizeof(dsakeyvalue->G.bytes));
	}
	exi_add_bytes(subtree,
		hf_v2gdin_struct_din_DSAKeyValueType_Y,
		tvb,
		dsakeyvalue->Y.bytes,
		dsakeyvalue->Y.bytesLen,
		sizeof(dsakeyvalue->Y.bytes));
	if (dsakeyvalue->J_isUsed) {
		exi_add_bytes(subtree,
			hf_v2gdin_struct_din_DSAKeyValueType_J,
			tvb,
			dsakeyvalue->J.bytes,
			dsakeyvalue->J.bytesLen,
			sizeof(dsakeyvalue->J.bytes));
	}
	if (dsakeyvalue->Seed_isUsed) {
		exi_add_bytes(subtree,
			hf_v2gdin_struct_din_DSAKeyValueType_Seed,
			tvb,
			dsakeyvalue->Seed.bytes,
			dsakeyvalue->Seed.bytesLen,
			sizeof(dsakeyvalue->Seed.bytes));
	}
	if (dsakeyvalue->PgenCounter_isUsed) {
		exi_add_bytes(subtree,
			hf_v2gdin_struct_din_DSAKeyValueType_PgenCounter,
			tvb,
			dsakeyvalue->PgenCounter.bytes,
			dsakeyvalue->PgenCounter.bytesLen,
			sizeof(dsakeyvalue->PgenCounter.bytes));
	}

	return;
}

static void
dissect_v2gdin_rsakeyvalue(const struct din_RSAKeyValueType *rsakeyvalue,
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
		hf_v2gdin_struct_din_RSAKeyValueType_Modulus,
		tvb,
		rsakeyvalue->Modulus.bytes,
		rsakeyvalue->Modulus.bytesLen,
		sizeof(rsakeyvalue->Modulus.bytes));

	exi_add_bytes(subtree,
		hf_v2gdin_struct_din_RSAKeyValueType_Exponent,
		tvb,
		rsakeyvalue->Exponent.bytes,
		rsakeyvalue->Exponent.bytesLen,
		sizeof(rsakeyvalue->Exponent.bytes));

	return;
}

static void
dissect_v2gdin_keyvalue(const struct din_KeyValueType *keyvalue,
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
		dissect_v2gdin_dsakeyvalue(&keyvalue->DSAKeyValue,
			tvb, pinfo, subtree,
			ett_v2gdin_struct_din_DSAKeyValueType,
			"DSAKeyValue");
	}
	if (keyvalue->RSAKeyValue_isUsed) {
		dissect_v2gdin_rsakeyvalue(&keyvalue->RSAKeyValue,
			tvb, pinfo, subtree,
			ett_v2gdin_struct_din_RSAKeyValueType,
			"RSAKeyValue");
	}

	exi_add_bytes(subtree,
		hf_v2gdin_struct_din_KeyValueType_ANY,
		tvb,
		keyvalue->ANY.bytes,
		keyvalue->ANY.bytesLen,
		sizeof(keyvalue->ANY.bytes));

	return;
}

static void
dissect_v2gdin_retrievalmethod(
	const struct din_RetrievalMethodType *retrievalmethod,
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
			hf_v2gdin_struct_din_RetrievalMethodType_URI,
			tvb,
			retrievalmethod->URI.characters,
			retrievalmethod->URI.charactersLen,
			sizeof(retrievalmethod->URI.characters));
	}
	if (retrievalmethod->Type_isUsed) {
		exi_add_characters(subtree,
			hf_v2gdin_struct_din_RetrievalMethodType_Type,
			tvb,
			retrievalmethod->Type.characters,
			retrievalmethod->Type.charactersLen,
			sizeof(retrievalmethod->Type.characters));
	}
	if (retrievalmethod->Transforms_isUsed) {
		dissect_v2gdin_transforms(&retrievalmethod->Transforms,
			tvb, pinfo, subtree,
			ett_v2gdin_struct_din_TransformsType,
			"Transforms");
	}

	return;
}

static void
dissect_v2gdin_x509issuerserial(
	const struct din_X509IssuerSerialType *x509issuerserial,
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
		hf_v2gdin_struct_din_X509IssuerSerialType_X509IssuerName,
		tvb,
		x509issuerserial->X509IssuerName.characters,
		x509issuerserial->X509IssuerName.charactersLen,
		sizeof(x509issuerserial->X509IssuerName.characters));

	it = proto_tree_add_int64(subtree,
		hf_v2gdin_struct_din_X509IssuerSerialType_X509SerialNumber,
		tvb, 0, 0, x509issuerserial->X509SerialNumber);
	proto_item_set_generated(it);

	return;
}

static void
dissect_v2gdin_x509data(const struct din_X509DataType *x509data,
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
		dissect_v2gdin_x509issuerserial(
			&x509data->X509IssuerSerial,
			tvb, pinfo, subtree,
			ett_v2gdin_struct_din_X509IssuerSerialType,
			"X509IssuerSerial");
	}

	if (x509data->X509SKI_isUsed) {
		exi_add_bytes(subtree,
			hf_v2gdin_struct_din_X509DataType_X509SKI,
			tvb,
			x509data->X509SKI.bytes,
			x509data->X509SKI.bytesLen,
			sizeof(x509data->X509SKI.bytes));
	}

	if (x509data->X509SubjectName_isUsed) {
		exi_add_characters(subtree,
			hf_v2gdin_struct_din_X509DataType_X509SubjectName,
			tvb,
			x509data->X509SubjectName.characters,
			x509data->X509SubjectName.charactersLen,
			sizeof(x509data->X509SubjectName.characters));
	}

	if (x509data->X509Certificate_isUsed) {
		exi_add_bytes(subtree,
			hf_v2gdin_struct_din_X509DataType_X509Certificate,
			tvb,
			x509data->X509Certificate.bytes,
			x509data->X509Certificate.bytesLen,
			sizeof(x509data->X509Certificate.bytes));
	}

	if (x509data->X509CRL_isUsed) {
		exi_add_bytes(subtree,
			hf_v2gdin_struct_din_X509DataType_X509CRL,
			tvb,
			x509data->X509CRL.bytes,
			x509data->X509CRL.bytesLen,
			sizeof(x509data->X509CRL.bytes));
	}

	if (x509data->ANY_isUsed) {
		exi_add_bytes(subtree,
			hf_v2gdin_struct_din_X509DataType_ANY,
			tvb,
			x509data->ANY.bytes,
			x509data->ANY.bytesLen,
			sizeof(x509data->ANY.bytes));
	}

	return;
}

static void
dissect_v2gdin_pgpdata(const struct din_PGPDataType *pgpdata,
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
			hf_v2gdin_struct_din_PGPDataType_PGPKeyID,
			tvb,
			pgpdata->choice_1.PGPKeyID.bytes,
			pgpdata->choice_1.PGPKeyID.bytesLen,
			sizeof(pgpdata->choice_1.PGPKeyID.bytes));

		if (pgpdata->choice_1.PGPKeyPacket_isUsed) {
			exi_add_bytes(subtree,
				hf_v2gdin_struct_din_PGPDataType_PGPKeyPacket,
				tvb,
				pgpdata->choice_1.PGPKeyPacket.bytes,
				pgpdata->choice_1.PGPKeyPacket.bytesLen,
				sizeof(pgpdata->choice_1.PGPKeyPacket.bytes));
		}

		if (pgpdata->choice_1.ANY_isUsed) {
			exi_add_bytes(subtree,
				hf_v2gdin_struct_din_PGPDataType_ANY,
				tvb,
				pgpdata->choice_1.ANY.bytes,
				pgpdata->choice_1.ANY.bytesLen,
				sizeof(pgpdata->choice_1.ANY.bytes));
		}
	}

	if (pgpdata->choice_2_isUsed) {
		exi_add_bytes(subtree,
			hf_v2gdin_struct_din_PGPDataType_PGPKeyPacket,
			tvb,
			pgpdata->choice_2.PGPKeyPacket.bytes,
			pgpdata->choice_2.PGPKeyPacket.bytesLen,
			sizeof(pgpdata->choice_2.PGPKeyPacket.bytes));

		if (pgpdata->choice_2.ANY_isUsed) {
			exi_add_bytes(subtree,
				hf_v2gdin_struct_din_PGPDataType_ANY,
				tvb,
				pgpdata->choice_2.ANY.bytes,
				pgpdata->choice_2.ANY.bytesLen,
				sizeof(pgpdata->choice_2.ANY.bytes));
		}
	}

	return;
}

static void
dissect_v2gdin_spkidata(const struct din_SPKIDataType *spkidata,
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
		hf_v2gdin_struct_din_SPKIDataType_SPKISexp,
		tvb,
		spkidata->SPKISexp.bytes,
		spkidata->SPKISexp.bytesLen,
		sizeof(spkidata->SPKISexp.bytes));

	if (spkidata->ANY_isUsed) {
		exi_add_bytes(subtree,
			hf_v2gdin_struct_din_SPKIDataType_ANY,
			tvb,
			spkidata->ANY.bytes,
			spkidata->ANY.bytesLen,
			sizeof(spkidata->ANY.bytes));
	}

	return;
}

static void
dissect_v2gdin_keyinfo(const struct din_KeyInfoType *keyinfo,
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
			hf_v2gdin_struct_din_KeyInfoType_Id,
			tvb,
			keyinfo->Id.characters,
			keyinfo->Id.charactersLen,
			sizeof(keyinfo->Id.characters));
	}

	if (keyinfo->KeyName_isUsed) {
		exi_add_characters(subtree,
			hf_v2gdin_struct_din_KeyInfoType_KeyName,
			tvb,
			keyinfo->KeyName.characters,
			keyinfo->KeyName.charactersLen,
			sizeof(keyinfo->KeyName.characters));
	}

	if (keyinfo->KeyValue_isUsed) {
		dissect_v2gdin_keyvalue(&keyinfo->KeyValue,
					tvb, pinfo, subtree,
					ett_v2gdin_struct_din_KeyValueType,
					"KeyValue");
	}

	if (keyinfo->RetrievalMethod_isUsed) {
		dissect_v2gdin_retrievalmethod(
			&keyinfo->RetrievalMethod,
			tvb, pinfo, subtree,
			ett_v2gdin_struct_din_RetrievalMethodType,
			"RetrievalMethod");
	}

	if (keyinfo->X509Data_isUsed) {
		dissect_v2gdin_x509data(&keyinfo->X509Data,
					tvb, pinfo, subtree,
					ett_v2gdin_struct_din_X509DataType,
					"X509Data");
	}

	if (keyinfo->PGPData_isUsed) {
		dissect_v2gdin_pgpdata(&keyinfo->PGPData,
				       tvb, pinfo, subtree,
				       ett_v2gdin_struct_din_PGPDataType,
				       "PGPData");
	}

	if (keyinfo->SPKIData_isUsed) {
		dissect_v2gdin_spkidata(&keyinfo->SPKIData,
					tvb, pinfo, subtree,
					ett_v2gdin_struct_din_SPKIDataType,
					"SPKIData");
	}

	if (keyinfo->MgmtData_isUsed) {
		exi_add_characters(subtree,
			hf_v2gdin_struct_din_KeyInfoType_MgmtData,
			tvb,
			keyinfo->MgmtData.characters,
			keyinfo->MgmtData.charactersLen,
			sizeof(keyinfo->MgmtData.characters));
	}

	if (keyinfo->ANY_isUsed) {
		exi_add_bytes(subtree,
			hf_v2gdin_struct_din_KeyInfoType_ANY,
			tvb,
			keyinfo->ANY.bytes,
			keyinfo->ANY.bytesLen,
			sizeof(keyinfo->ANY.bytes));
	}

	return;
}

static void
dissect_v2gdin_signature(const struct din_SignatureType *signature,
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
			hf_v2gdin_struct_din_SignatureType_Id,
			tvb,
			signature->Id.characters,
			signature->Id.charactersLen,
			sizeof(signature->Id.characters));
	}

	dissect_v2gdin_signedinfo(&signature->SignedInfo,
		tvb, pinfo, subtree,
		ett_v2gdin_struct_din_SignedInfoType, "SignedInfo");
	dissect_v2gdin_signaturevalue(&signature->SignatureValue,
		tvb, pinfo, subtree,
		ett_v2gdin_struct_din_SignatureValueType,
		"SignatureValue");

	if (signature->KeyInfo_isUsed) {
		dissect_v2gdin_keyinfo(&signature->KeyInfo,
			tvb, pinfo, subtree,
			ett_v2gdin_struct_din_KeyInfoType, "KeyInfo");
	}

	if (signature->Object_isUsed) {
		dissect_v2gdin_object(&signature->Object,
			tvb, pinfo, subtree,
			ett_v2gdin_struct_din_ObjectType, "Object");
	}

	return;
}

static void
dissect_v2gdin_paymentoptions(
	const struct din_PaymentOptionsType *paymentoptions,
	tvbuff_t *tvb,
	packet_info *pinfo _U_,
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
			hf_v2gdin_struct_din_PaymentOptionsType_PaymentOption,
			tvb, 0, 0,
			paymentoptions->PaymentOption.array[i]);
		proto_item_set_generated(it);
	}

	return;
}

static void
dissect_v2gdin_servicetag(const struct din_ServiceTagType *servicetag,
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

	it = proto_tree_add_uint(subtree,
		hf_v2gdin_struct_din_ServiceTagType_ServiceID, tvb, 0, 0,
		servicetag->ServiceID);
	proto_item_set_generated(it);

	if (servicetag->ServiceName_isUsed) {
		exi_add_characters(subtree,
			hf_v2gdin_struct_din_ServiceTagType_ServiceName,
			tvb,
			servicetag->ServiceName.characters,
			servicetag->ServiceName.charactersLen,
			sizeof(servicetag->ServiceName.characters));
	}

	it = proto_tree_add_uint(subtree,
		hf_v2gdin_struct_din_ServiceTagType_ServiceCategory, tvb, 0, 0,
		servicetag->ServiceCategory);
	proto_item_set_generated(it);

	if (servicetag->ServiceScope_isUsed) {
		exi_add_characters(subtree,
			hf_v2gdin_struct_din_ServiceTagType_ServiceScope,
			tvb,
			servicetag->ServiceScope.characters,
			servicetag->ServiceScope.charactersLen,
			sizeof(servicetag->ServiceScope.characters));
	}

	return;
}

static void
dissect_v2gdin_servicecharge(const struct din_ServiceChargeType *servicecharge,
			     tvbuff_t *tvb,
			     packet_info *pinfo,
			     proto_tree *tree,
			     gint idx,
			     const char *subtree_name)
{
	proto_tree *subtree;
	proto_item *it;

	subtree = proto_tree_add_subtree(tree, tvb, 0, 0,
		idx, NULL, subtree_name);

	dissect_v2gdin_servicetag(&servicecharge->ServiceTag,
		tvb, pinfo, subtree,
		ett_v2gdin_struct_din_ServiceTagType,
		"ServiceTag");

	it = proto_tree_add_int(subtree,
		hf_v2gdin_struct_din_ServiceChargeType_FreeService,
		tvb, 0, 0, servicecharge->FreeService);
	proto_item_set_generated(it);

	it = proto_tree_add_uint(subtree,
		hf_v2gdin_struct_din_ServiceChargeType_EnergyTransferType,
		tvb, 0, 0, servicecharge->EnergyTransferType);
	proto_item_set_generated(it);

	return;
}

static void
dissect_v2gdin_service(const struct din_ServiceType *service,
		       tvbuff_t *tvb,
		       packet_info *pinfo,
		       proto_tree *tree,
		       gint idx,
		       const char *subtree_name)
{
	proto_tree *subtree;
	proto_item *it;

	subtree = proto_tree_add_subtree(tree, tvb, 0, 0,
		idx, NULL, subtree_name);

	dissect_v2gdin_servicetag(&service->ServiceTag,
		tvb, pinfo, subtree,
		ett_v2gdin_struct_din_ServiceTagType,
		"ServiceTag");

	it = proto_tree_add_int(subtree,
		hf_v2gdin_struct_din_ServiceType_FreeService, tvb, 0, 0,
		service->FreeService);
	proto_item_set_generated(it);

	return;
}

static void
dissect_v2gdin_servicetaglist(
	const struct din_ServiceTagListType *servicetaglist,
	tvbuff_t *tvb,
	packet_info *pinfo,
	proto_tree *tree,
	gint idx,
	const char *subtree_name)
{
	proto_tree *subtree;

	subtree = proto_tree_add_subtree(tree, tvb, 0, 0,
		idx, NULL, subtree_name);

	dissect_v2gdin_service(
		&servicetaglist->Service,
		tvb, pinfo, subtree,
		ett_v2gdin_struct_din_ServiceType, "Service");

	return;
}

static inline double
v2gdin_physicalvalue_to_double(
	const struct din_PhysicalValueType *physicalvalue)
{
	double value;
	int32_t multiplier;

	value = (double)physicalvalue->Value;
	multiplier = physicalvalue->Multiplier;
	if (multiplier > 0) {
		for (; multiplier != 0; multiplier--) {
			value *= 10.0;
		}
	}
	if (multiplier < 0) {
		for (; multiplier != 0; multiplier++) {
			value /= 10.0;
		}
	}

	return value;
}

static void
dissect_v2gdin_physicalvalue(const struct din_PhysicalValueType *physicalvalue,
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
		hf_v2gdin_struct_din_PhysicalValueType_Multiplier,
		tvb, 0, 0, physicalvalue->Multiplier);
	proto_item_set_generated(it);

	if (physicalvalue->Unit_isUsed) {
		it = proto_tree_add_uint(subtree,
			hf_v2gdin_struct_din_PhysicalValueType_Unit,
			tvb, 0, 0, physicalvalue->Unit);
		proto_item_set_generated(it);
	}

	it = proto_tree_add_int(subtree,
		hf_v2gdin_struct_din_PhysicalValueType_Value,
		tvb, 0, 0, physicalvalue->Value);
	proto_item_set_generated(it);

	return;
}

static void
dissect_v2gdin_parameter(
	const struct din_ParameterType *parameter,
	tvbuff_t *tvb,
	packet_info *pinfo,
	proto_tree *tree,
	gint idx,
	const char *subtree_name)
{
	proto_tree *subtree;
	proto_item *it;

	subtree = proto_tree_add_subtree(tree, tvb, 0, 0,
		idx, NULL, subtree_name);

	exi_add_characters(subtree,
		hf_v2gdin_struct_din_ParameterType_Name,
		tvb,
		parameter->Name.characters,
		parameter->Name.charactersLen,
		sizeof(parameter->Name.characters));

	it = proto_tree_add_uint(subtree,
		hf_v2gdin_struct_din_ParameterType_ValueType,
		tvb, 0, 0, parameter->ValueType);
	proto_item_set_generated(it);

	if (parameter->boolValue_isUsed) {
		it = proto_tree_add_int(subtree,
			hf_v2gdin_struct_din_ParameterType_boolValue,
			tvb, 0, 0, parameter->boolValue);
		proto_item_set_generated(it);
	}
	if (parameter->byteValue_isUsed) {
		it = proto_tree_add_int(subtree,
			hf_v2gdin_struct_din_ParameterType_byteValue,
			tvb, 0, 0, parameter->byteValue);
		proto_item_set_generated(it);
	}
	if (parameter->shortValue_isUsed) {
		it = proto_tree_add_int(subtree,
			hf_v2gdin_struct_din_ParameterType_shortValue,
			tvb, 0, 0, parameter->shortValue);
		proto_item_set_generated(it);
	}
	if (parameter->intValue_isUsed) {
		it = proto_tree_add_int(subtree,
			hf_v2gdin_struct_din_ParameterType_intValue,
			tvb, 0, 0, parameter->intValue);
		proto_item_set_generated(it);
	}
	if (parameter->physicalValue_isUsed) {
		dissect_v2gdin_physicalvalue(&parameter->physicalValue,
			tvb, pinfo, subtree,
			ett_v2gdin_struct_din_PhysicalValueType,
			"physicalValue");
	}
	if (parameter->stringValue_isUsed) {
		exi_add_characters(subtree,
			hf_v2gdin_struct_din_ParameterType_stringValue,
			tvb,
			parameter->stringValue.characters,
			parameter->stringValue.charactersLen,
			sizeof(parameter->stringValue.characters));
	}

	return;
}

static void
dissect_v2gdin_parameterset(
	const struct din_ParameterSetType *parameterset,
	tvbuff_t *tvb,
	packet_info *pinfo,
	proto_tree *tree,
	gint idx,
	const char *subtree_name)
{
	proto_tree *subtree;
	proto_item *it;

	subtree = proto_tree_add_subtree(tree, tvb, 0, 0,
		idx, NULL, subtree_name);

	it = proto_tree_add_int(subtree,
		hf_v2gdin_struct_din_ParameterSetType_ParameterSetID,
		tvb, 0, 0, parameterset->ParameterSetID);
	proto_item_set_generated(it);

	dissect_v2gdin_parameter(
		&parameterset->Parameter,
		tvb, pinfo, subtree,
		ett_v2gdin_struct_din_ParameterType, "Parameter");

	return;
}

static void
dissect_v2gdin_serviceparameterlist(
	const struct din_ServiceParameterListType *serviceparameterlist,
	tvbuff_t *tvb,
	packet_info *pinfo,
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

		snprintf(index, sizeof(index), "[%u]", i);
		dissect_v2gdin_parameterset(
			&serviceparameterlist->ParameterSet.array[i],
			tvb, pinfo, parameterset_tree,
			ett_v2gdin_struct_din_ParameterSetType, index);
	}

	return;
}

static void
dissect_v2gdin_selectedservice(
	const struct din_SelectedServiceType *selectedservice,
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

	it = proto_tree_add_uint(subtree,
		hf_v2gdin_struct_din_SelectedServiceType_ServiceID,
		tvb, 0, 0, selectedservice->ServiceID);
	proto_item_set_generated(it);

	if (selectedservice->ParameterSetID_isUsed) {
		it = proto_tree_add_int(subtree,
			hf_v2gdin_struct_din_SelectedServiceType_ParameterSetID,
			tvb, 0, 0, selectedservice->ParameterSetID);
		proto_item_set_generated(it);
	}

	return;
}

static void
dissect_v2gdin_selectedservicelist(
	const struct din_SelectedServiceListType *selectedservicelist,
	tvbuff_t *tvb,
	packet_info *pinfo,
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
			tvb, pinfo, selectedservicelist_tree,
			ett_v2gdin_struct_din_SelectedServiceType, index);
	}

	return;
}

static void
dissect_v2gdin_subcertificates(
	const struct din_SubCertificatesType *subcertificates,
	tvbuff_t *tvb,
	packet_info *pinfo _U_,
	proto_tree *tree,
	gint idx,
	const char *subtree_name)
{
	proto_tree *subtree;

	subtree = proto_tree_add_subtree(tree, tvb, 0, 0,
		idx, NULL, subtree_name);

	exi_add_bytes(subtree,
		hf_v2gdin_struct_din_SubCertificatesType_Certificate,
		tvb,
		subcertificates->Certificate.bytes,
		subcertificates->Certificate.bytesLen,
		sizeof(subcertificates->Certificate.bytes));

	return;
}

static void
dissect_v2gdin_certificatechain(
	const struct din_CertificateChainType *certificatechain,
	tvbuff_t *tvb,
	packet_info *pinfo,
	proto_tree *tree,
	gint idx,
	const char *subtree_name)
{
	proto_tree *subtree;

	subtree = proto_tree_add_subtree(tree, tvb, 0, 0,
		idx, NULL, subtree_name);

	exi_add_bytes(subtree,
		hf_v2gdin_struct_din_CertificateChainType_Certificate,
		tvb,
		certificatechain->Certificate.bytes,
		certificatechain->Certificate.bytesLen,
		sizeof(certificatechain->Certificate.bytes));

	if (certificatechain->SubCertificates_isUsed) {
		dissect_v2gdin_subcertificates(
			&certificatechain->SubCertificates,
			tvb, pinfo, subtree,
			ett_v2gdin_struct_din_SubCertificatesType,
			"SubCertificates");
	}

	return;
}

static void
dissect_v2gdin_listofrootcertificateids(
	const struct din_ListOfRootCertificateIDsType *listofrootcertificateids,
	tvbuff_t *tvb,
	packet_info *pinfo _U_,
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
			hf_v2gdin_struct_din_ListOfRootCertificateIDsType_RootCertificateID,
			tvb,
			listofrootcertificateids->RootCertificateID.array[i].characters,
			listofrootcertificateids->RootCertificateID.array[i].charactersLen,
			sizeof(listofrootcertificateids->RootCertificateID.array[i].characters));
	}

	return;
}

static void
dissect_v2gdin_evchargeparameter(
	const struct din_EVChargeParameterType *evchargeparameter _U_,
	tvbuff_t *tvb _U_,
	packet_info *pinfo _U_,
	proto_tree *tree _U_,
	gint idx _U_,
	const char *subtree_name _U_)
{
	/* no content */
	return;
}

static void
dissect_v2gdin_ac_evchargeparameter(
	const struct din_AC_EVChargeParameterType *ac_evchargeparameter,
	tvbuff_t *tvb,
	packet_info *pinfo,
	proto_tree *tree,
	gint idx,
	const char *subtree_name)
{
	proto_tree *subtree;
	proto_item *it;

	subtree = proto_tree_add_subtree(tree, tvb, 0, 0,
		idx, NULL, subtree_name);

	it = proto_tree_add_uint(subtree,
		hf_v2gdin_struct_din_AC_EVChargeParameterType_DepartureTime,
		tvb, 0, 0, ac_evchargeparameter->DepartureTime);
	proto_item_set_generated(it);

	dissect_v2gdin_physicalvalue(&ac_evchargeparameter->EAmount,
		tvb, pinfo, subtree,
		ett_v2gdin_struct_din_PhysicalValueType, "EAmount");

	dissect_v2gdin_physicalvalue(&ac_evchargeparameter->EVMaxVoltage,
		tvb, pinfo, subtree,
		ett_v2gdin_struct_din_PhysicalValueType, "EVMaxVoltage");

	dissect_v2gdin_physicalvalue(&ac_evchargeparameter->EVMaxCurrent,
		tvb, pinfo, subtree,
		ett_v2gdin_struct_din_PhysicalValueType, "EVMaxCurrent");

	dissect_v2gdin_physicalvalue(&ac_evchargeparameter->EVMinCurrent,
		tvb, pinfo, subtree,
		ett_v2gdin_struct_din_PhysicalValueType, "EVMinCurrent");

	return;
}

static void
dissect_v2gdin_dc_evstatus(const struct din_DC_EVStatusType *dc_evstatus,
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
		hf_v2gdin_struct_din_DC_EVStatusType_EVReady,
		tvb, 0, 0, dc_evstatus->EVReady);
	proto_item_set_generated(it);

	if (dc_evstatus->EVCabinConditioning_isUsed) {
		it = proto_tree_add_int(subtree,
			hf_v2gdin_struct_din_DC_EVStatusType_EVCabinConditioning,
			tvb, 0, 0, dc_evstatus->EVCabinConditioning);
		proto_item_set_generated(it);
	}

	if (dc_evstatus->EVRESSConditioning_isUsed) {
		it = proto_tree_add_int(subtree,
			hf_v2gdin_struct_din_DC_EVStatusType_EVRESSConditioning,
			tvb, 0, 0, dc_evstatus->EVRESSConditioning);
		proto_item_set_generated(it);
	}

	it = proto_tree_add_uint(subtree,
		hf_v2gdin_struct_din_DC_EVStatusType_EVErrorCode,
		tvb, 0, 0, dc_evstatus->EVErrorCode);
	proto_item_set_generated(it);

	it = proto_tree_add_int(subtree,
		hf_v2gdin_struct_din_DC_EVStatusType_EVRESSSOC,
		tvb, 0, 0, dc_evstatus->EVRESSSOC);
	proto_item_set_generated(it);

	return;
}

static void
dissect_v2gdin_dc_evchargeparameter(
	const struct din_DC_EVChargeParameterType *dc_evchargeparameter,
	tvbuff_t *tvb,
	packet_info *pinfo,
	proto_tree *tree,
	gint idx,
	const char *subtree_name)
{
	proto_tree *subtree;
	proto_item *it;
	double value;

	subtree = proto_tree_add_subtree(tree, tvb, 0, 0,
		idx, NULL, subtree_name);

	dissect_v2gdin_dc_evstatus(&dc_evchargeparameter->DC_EVStatus,
		tvb, pinfo, subtree,
		ett_v2gdin_struct_din_DC_EVStatusType,
		"DC_EVStatus");

	dissect_v2gdin_physicalvalue(
		&dc_evchargeparameter->EVMaximumVoltageLimit,
		tvb, pinfo, subtree,
		ett_v2gdin_struct_din_PhysicalValueType,
		"EVMaximumVoltageLimit");
	value = v2gdin_physicalvalue_to_double(
		&dc_evchargeparameter->EVMaximumVoltageLimit);
	it = proto_tree_add_double(subtree,
		hf_v2gdin_ev_maximum_voltage_limit,
		tvb, 0, 0, value);
	proto_item_set_generated(it);

	dissect_v2gdin_physicalvalue(
		&dc_evchargeparameter->EVMaximumCurrentLimit,
		tvb, pinfo, subtree,
		ett_v2gdin_struct_din_PhysicalValueType,
		"EVMaximumCurrentLimit");
	value = v2gdin_physicalvalue_to_double(
		&dc_evchargeparameter->EVMaximumCurrentLimit);
	it = proto_tree_add_double(subtree,
		hf_v2gdin_ev_maximum_current_limit,
		tvb, 0, 0, value);
	proto_item_set_generated(it);

	if (dc_evchargeparameter->EVMaximumPowerLimit_isUsed) {
		dissect_v2gdin_physicalvalue(
			&dc_evchargeparameter->EVMaximumPowerLimit,
			tvb, pinfo, subtree,
			ett_v2gdin_struct_din_PhysicalValueType,
			"EVMaximumPowerLimit");
		value = v2gdin_physicalvalue_to_double(
			&dc_evchargeparameter->EVMaximumPowerLimit);
		it = proto_tree_add_double(subtree,
			hf_v2gdin_ev_maximum_power_limit,
			tvb, 0, 0, value);
		proto_item_set_generated(it);
	}

	if (dc_evchargeparameter->EVEnergyCapacity_isUsed) {
		dissect_v2gdin_physicalvalue(
			&dc_evchargeparameter->EVEnergyCapacity,
			tvb, pinfo, subtree,
			ett_v2gdin_struct_din_PhysicalValueType,
			"EVEnergyCapacity");
	}

	if (dc_evchargeparameter->EVEnergyRequest_isUsed) {
		dissect_v2gdin_physicalvalue(
			&dc_evchargeparameter->EVEnergyRequest,
			tvb, pinfo, subtree,
			ett_v2gdin_struct_din_PhysicalValueType,
			"EVEnergyRequest");
	}

	if (dc_evchargeparameter->FullSOC_isUsed) {
		it = proto_tree_add_int(subtree,
			hf_v2gdin_struct_din_DC_EVChargeParameterType_FullSOC,
			tvb, 0, 0, dc_evchargeparameter->FullSOC);
		proto_item_set_generated(it);
	}

	if (dc_evchargeparameter->BulkSOC_isUsed) {
		it = proto_tree_add_int(subtree,
			hf_v2gdin_struct_din_DC_EVChargeParameterType_BulkSOC,
			tvb, 0, 0, dc_evchargeparameter->BulkSOC);
		proto_item_set_generated(it);
	}

	return;
}

static void
dissect_v2gdin_evsestatus(const struct din_EVSEStatusType *evsestatus _U_,
			  tvbuff_t *tvb _U_,
			  packet_info *pinfo _U_,
			  proto_tree *tree _U_,
			  gint idx _U_,
			  const char *subtree_name _U_)
{
	/* no content */
	return;
}

static void
dissect_v2gdin_dc_evsestatus(const struct din_DC_EVSEStatusType *dc_evsestatus,
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

	if (dc_evsestatus->EVSEIsolationStatus_isUsed) {
		it = proto_tree_add_uint(subtree,
			hf_v2gdin_struct_din_DC_EVSEStatusType_EVSEIsolationStatus,
			tvb, 0, 0, dc_evsestatus->EVSEIsolationStatus);
		proto_item_set_generated(it);
	}

	it = proto_tree_add_uint(subtree,
		hf_v2gdin_struct_din_DC_EVSEStatusType_EVSEStatusCode,
		tvb, 0, 0, dc_evsestatus->EVSEStatusCode);
	proto_item_set_generated(it);

	it = proto_tree_add_uint(subtree,
		hf_v2gdin_struct_din_DC_EVSEStatusType_NotificationMaxDelay,
		tvb, 0, 0, dc_evsestatus->NotificationMaxDelay);
	proto_item_set_generated(it);

	it = proto_tree_add_uint(subtree,
		hf_v2gdin_struct_din_DC_EVSEStatusType_EVSENotification,
		tvb, 0, 0, dc_evsestatus->EVSENotification);
	proto_item_set_generated(it);

	return;
};

static void
dissect_v2gdin_evsechargeparameter(
	const struct din_EVSEChargeParameterType *evsechargeparameter _U_,
	tvbuff_t *tvb _U_,
	packet_info *pinfo _U_,
	proto_tree *tree _U_,
	gint idx _U_,
	const char *subtree_name _U_)
{
	/* no content */
	return;
}

static void
dissect_v2gdin_ac_evsestatus(const struct din_AC_EVSEStatusType *ac_evsestatus,
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
		hf_v2gdin_struct_din_AC_EVSEStatusType_PowerSwitchClosed,
		tvb, 0, 0, ac_evsestatus->PowerSwitchClosed);
	proto_item_set_generated(it);

	it = proto_tree_add_int(subtree,
		hf_v2gdin_struct_din_AC_EVSEStatusType_RCD,
		tvb, 0, 0, ac_evsestatus->RCD);
	proto_item_set_generated(it);

	it = proto_tree_add_uint(subtree,
		hf_v2gdin_struct_din_AC_EVSEStatusType_NotificationMaxDelay,
		tvb, 0, 0, ac_evsestatus->NotificationMaxDelay);
	proto_item_set_generated(it);

	it = proto_tree_add_uint(subtree,
		hf_v2gdin_struct_din_AC_EVSEStatusType_EVSENotification,
		tvb, 0, 0, ac_evsestatus->EVSENotification);
	proto_item_set_generated(it);

	return;
}

static void
dissect_v2gdin_ac_evsechargeparameter(
	const struct din_AC_EVSEChargeParameterType *ac_evsechargeparameter,
	tvbuff_t *tvb,
	packet_info *pinfo,
	proto_tree *tree,
	gint idx,
	const char *subtree_name)
{
	proto_tree *subtree;

	subtree = proto_tree_add_subtree(tree, tvb, 0, 0,
		idx, NULL, subtree_name);

	dissect_v2gdin_ac_evsestatus(&ac_evsechargeparameter->AC_EVSEStatus,
		tvb, pinfo, subtree,
		ett_v2gdin_struct_din_AC_EVSEStatusType, "AC_EVSEStatus");

	dissect_v2gdin_physicalvalue(&ac_evsechargeparameter->EVSEMaxVoltage,
		tvb, pinfo, subtree,
		ett_v2gdin_struct_din_PhysicalValueType, "EVSEMaxVoltage");

	dissect_v2gdin_physicalvalue(&ac_evsechargeparameter->EVSEMaxCurrent,
		tvb, pinfo, subtree,
		ett_v2gdin_struct_din_PhysicalValueType, "EVSEMaxCurrent");

	dissect_v2gdin_physicalvalue(&ac_evsechargeparameter->EVSEMaxCurrent,
		tvb, pinfo, subtree,
		ett_v2gdin_struct_din_PhysicalValueType, "EVSEMinCurrent");

	return;
}

static void
dissect_v2gdin_dc_evsechargeparameter(
	const struct din_DC_EVSEChargeParameterType *dc_evsechargeparameter,
	tvbuff_t *tvb,
	packet_info *pinfo,
	proto_tree *tree,
	gint idx,
	const char *subtree_name)
{
	proto_tree *subtree;
	proto_item *it;
	double value;

	subtree = proto_tree_add_subtree(tree, tvb, 0, 0,
		idx, NULL, subtree_name);

	dissect_v2gdin_dc_evsestatus(&dc_evsechargeparameter->DC_EVSEStatus,
		tvb, pinfo, subtree,
		ett_v2gdin_struct_din_DC_EVSEStatusType, "DC_EVSEStatus");

	dissect_v2gdin_physicalvalue(
		&dc_evsechargeparameter->EVSEMaximumVoltageLimit,
		tvb, pinfo, subtree,
		ett_v2gdin_struct_din_PhysicalValueType,
		"EVSEMaximumVoltageLimit");
	value = v2gdin_physicalvalue_to_double(
		&dc_evsechargeparameter->EVSEMaximumVoltageLimit);
	it = proto_tree_add_double(subtree,
		hf_v2gdin_evse_maximum_voltage_limit,
		tvb, 0, 0, value);
	proto_item_set_generated(it);

	dissect_v2gdin_physicalvalue(
		&dc_evsechargeparameter->EVSEMinimumVoltageLimit,
		tvb, pinfo, subtree,
		ett_v2gdin_struct_din_PhysicalValueType,
		"EVSEMinimumVoltageLimit");

	dissect_v2gdin_physicalvalue(
		&dc_evsechargeparameter->EVSEMaximumCurrentLimit,
		tvb, pinfo, subtree,
		ett_v2gdin_struct_din_PhysicalValueType,
		"EVSEMaximumCurrentLimit");
	value = v2gdin_physicalvalue_to_double(
		&dc_evsechargeparameter->EVSEMaximumCurrentLimit);
	it = proto_tree_add_double(subtree,
		hf_v2gdin_evse_maximum_current_limit,
		tvb, 0, 0, value);
	proto_item_set_generated(it);

	dissect_v2gdin_physicalvalue(
		&dc_evsechargeparameter->EVSEMinimumCurrentLimit,
		tvb, pinfo, subtree,
		ett_v2gdin_struct_din_PhysicalValueType,
		"EVSEMinimumCurrentLimit");

	if (dc_evsechargeparameter->EVSEMaximumPowerLimit_isUsed) {
		dissect_v2gdin_physicalvalue(
			&dc_evsechargeparameter->EVSEMaximumPowerLimit,
			tvb, pinfo, subtree,
			ett_v2gdin_struct_din_PhysicalValueType,
			"EVSEMaximumPowerLimit");
		value = v2gdin_physicalvalue_to_double(
			&dc_evsechargeparameter->EVSEMaximumPowerLimit);
		it = proto_tree_add_double(subtree,
			hf_v2gdin_evse_maximum_power_limit,
			tvb, 0, 0, value);
		proto_item_set_generated(it);
	}

	if (dc_evsechargeparameter->EVSECurrentRegulationTolerance_isUsed) {
		dissect_v2gdin_physicalvalue(
			&dc_evsechargeparameter->EVSECurrentRegulationTolerance,
			tvb, pinfo, subtree,
			ett_v2gdin_struct_din_PhysicalValueType,
			"EVSECurrentRegulationTolerance");
	}

	dissect_v2gdin_physicalvalue(
		&dc_evsechargeparameter->EVSEPeakCurrentRipple,
		tvb, pinfo, subtree,
		ett_v2gdin_struct_din_PhysicalValueType,
		"EVSEPeakCurrentRipple");

	if (dc_evsechargeparameter->EVSEEnergyToBeDelivered_isUsed) {
		dissect_v2gdin_physicalvalue(
			&dc_evsechargeparameter->EVSEEnergyToBeDelivered,
			tvb, pinfo, subtree,
			ett_v2gdin_struct_din_PhysicalValueType,
			"EVSEEnergyToBeDelivered");
	}

	return;
}

static void
dissect_v2gdin_interval(const struct din_IntervalType *interval _U_,
			tvbuff_t *tvb _U_,
			packet_info *pinfo _U_,
			proto_tree *tree _U_,
			gint idx _U_,
			const char *subtree_name _U_)
{
	/* no content */
	return;
}

static void
dissect_v2gdin_relativetimeinterval(
	const struct din_RelativeTimeIntervalType *relativetimeinterval,
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

	it = proto_tree_add_uint(subtree,
		hf_v2gdin_struct_din_RelativeTimeIntervalType_start,
		tvb, 0, 0, relativetimeinterval->start);
	proto_item_set_generated(it);

	if (relativetimeinterval->duration_isUsed) {
		it = proto_tree_add_uint(subtree,
			hf_v2gdin_struct_din_RelativeTimeIntervalType_duration,
			tvb, 0, 0, relativetimeinterval->duration);
		proto_item_set_generated(it);
	}

	return;
}

static void
dissect_v2gdin_pmaxscheduleentry(
	const struct din_PMaxScheduleEntryType *pmaxscheduleentry,
	tvbuff_t *tvb,
	packet_info *pinfo,
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
			tvb, pinfo, subtree,
			ett_v2gdin_struct_din_IntervalType,
			"TimeInterval");
	}

	if (pmaxscheduleentry->RelativeTimeInterval_isUsed) {
		dissect_v2gdin_relativetimeinterval(
			&pmaxscheduleentry->RelativeTimeInterval,
			tvb, pinfo, subtree,
			ett_v2gdin_struct_din_RelativeTimeIntervalType,
			"RelativeTimeInterval");
	}

	it = proto_tree_add_int(subtree,
		hf_v2gdin_struct_din_PMaxScheduleEntryType_PMax,
		tvb, 0, 0, pmaxscheduleentry->PMax);
	proto_item_set_generated(it);

	return;
}

static void
dissect_v2gdin_pmaxschedule(const struct din_PMaxScheduleType *pmaxschedule,
			    tvbuff_t *tvb,
			    packet_info *pinfo,
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
		hf_v2gdin_struct_din_PMaxScheduleType_PMaxScheduleID,
		tvb, 0, 0, pmaxschedule->PMaxScheduleID);
	proto_item_set_generated(it);

	pmaxscheduleentry_tree = proto_tree_add_subtree(subtree,
		tvb, 0, 0, ett_v2gdin_array, NULL, "PMaxScheduleEntry");
	for (i = 0; i < pmaxschedule->PMaxScheduleEntry.arrayLen; i++) {
		char index[sizeof("[65536]")];

		snprintf(index, sizeof(index), "[%u]", i);
		dissect_v2gdin_pmaxscheduleentry(
			&pmaxschedule->PMaxScheduleEntry.array[i],
			tvb, pinfo, pmaxscheduleentry_tree,
			ett_v2gdin_struct_din_PMaxScheduleEntryType, index);
	}

	return;
}

static void
dissect_v2gdin_cost(const struct din_CostType *cost,
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

	it = proto_tree_add_uint(subtree,
		hf_v2gdin_struct_din_CostType_costKind,
		tvb, 0, 0, cost->costKind);
	proto_item_set_generated(it);

	it = proto_tree_add_uint(subtree,
		hf_v2gdin_struct_din_CostType_amount,
		tvb, 0, 0, cost->amount);
	proto_item_set_generated(it);

	if (cost->amountMultiplier_isUsed) {
		it = proto_tree_add_int(subtree,
			hf_v2gdin_struct_din_CostType_amountMultiplier,
			tvb, 0, 0, cost->amount);
		proto_item_set_generated(it);
	}

	return;
}

static void
dissect_v2gdin_consumptioncost(
	const struct din_ConsumptionCostType *consumptioncost,
	tvbuff_t *tvb,
	packet_info *pinfo,
	proto_tree *tree,
	gint idx,
	const char *subtree_name)
{
	proto_tree *subtree;
	proto_item *it;

	subtree = proto_tree_add_subtree(tree, tvb, 0, 0,
		idx, NULL, subtree_name);

	it = proto_tree_add_uint(subtree,
		hf_v2gdin_struct_din_ConsumptionCostType_startValue,
		tvb, 0, 0, consumptioncost->startValue);
	proto_item_set_generated(it);

	if (consumptioncost->Cost_isUsed) {
		dissect_v2gdin_cost(
			&consumptioncost->Cost,
			tvb, pinfo, subtree,
			ett_v2gdin_struct_din_CostType, "Cost");
	}

	return;
}

static void
dissect_v2gdin_salestariffentry(
	const struct din_SalesTariffEntryType *salestariffentry,
	tvbuff_t *tvb,
	packet_info *pinfo,
	proto_tree *tree,
	gint idx,
	const char *subtree_name)
{
	proto_tree *subtree;
	proto_item *it;

	subtree = proto_tree_add_subtree(tree, tvb, 0, 0,
		idx, NULL, subtree_name);

	if (salestariffentry->RelativeTimeInterval_isUsed) {
		dissect_v2gdin_relativetimeinterval(
			&salestariffentry->RelativeTimeInterval,
			tvb, pinfo, subtree,
			ett_v2gdin_struct_din_RelativeTimeIntervalType,
			"RelativeTimeInterval");
	}

	if (salestariffentry->TimeInterval_isUsed) {
		dissect_v2gdin_interval(&salestariffentry->TimeInterval,
			tvb, pinfo, subtree,
			ett_v2gdin_struct_din_IntervalType,
			"TimeInterval");
	}

	it = proto_tree_add_uint(subtree,
		hf_v2gdin_struct_din_SalesTariffEntryType_EPriceLevel,
		tvb, 0, 0, salestariffentry->EPriceLevel);
	proto_item_set_generated(it);

	if (salestariffentry->ConsumptionCost_isUsed) {
		dissect_v2gdin_consumptioncost(
			&salestariffentry->ConsumptionCost,
			tvb, pinfo, subtree,
			ett_v2gdin_struct_din_ConsumptionCostType,
			"ConsumptionCost");
	}

	return;
}

static void
dissect_v2gdin_salestariff(const struct din_SalesTariffType *salestariff,
			   tvbuff_t *tvb,
			   packet_info *pinfo,
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
		hf_v2gdin_struct_din_SalesTariffType_Id,
		tvb,
		salestariff->Id.characters,
		salestariff->Id.charactersLen,
		sizeof(salestariff->Id.characters));

	if (salestariff->SalesTariffDescription_isUsed) {
		exi_add_characters(subtree,
			hf_v2gdin_struct_din_SalesTariffType_SalesTariffDescription,
			tvb,
			salestariff->SalesTariffDescription.characters,
			salestariff->SalesTariffDescription.charactersLen,
			sizeof(salestariff->SalesTariffDescription.characters));
	}

	it = proto_tree_add_uint(subtree,
		hf_v2gdin_struct_din_SalesTariffType_NumEPriceLevels,
		tvb, 0, 0, salestariff->NumEPriceLevels);
	proto_item_set_generated(it);

	salestariffentry_tree = proto_tree_add_subtree(subtree,
		tvb, 0, 0, ett_v2gdin_array, NULL, "SalesTariffEntry");
	for (i = 0; i < salestariff->SalesTariffEntry.arrayLen; i++) {
		char index[sizeof("[65536]")];

		snprintf(index, sizeof(index), "[%u]", i);
		dissect_v2gdin_salestariffentry(
			&salestariff->SalesTariffEntry.array[i],
			tvb, pinfo, salestariffentry_tree,
			ett_v2gdin_struct_din_SalesTariffEntryType, index);
	}

	return;
}

static void
dissect_v2gdin_saschedules(const struct din_SASchedulesType *saschedules _U_,
			   tvbuff_t *tvb _U_,
			   packet_info *pinfo _U_,
			   proto_tree *tree _U_,
			   gint idx _U_,
			   const char *subtree_name _U_)
{
	/* no content */
	return;
}

static void
dissect_v2gdin_sascheduletuple(
	const struct din_SAScheduleTupleType *sascheduletuple,
	tvbuff_t *tvb,
	packet_info *pinfo,
	proto_tree *tree,
	gint idx,
	const char *subtree_name)
{
	proto_tree *subtree;
	proto_item *it;

	subtree = proto_tree_add_subtree(tree, tvb, 0, 0,
		idx, NULL, subtree_name);

	it = proto_tree_add_int(subtree,
		hf_v2gdin_struct_din_SAScheduleTupleType_SAScheduleTupleID,
		tvb, 0, 0, sascheduletuple->SAScheduleTupleID);
	proto_item_set_generated(it);

	dissect_v2gdin_pmaxschedule(&sascheduletuple->PMaxSchedule,
		tvb, pinfo, subtree,
		ett_v2gdin_struct_din_PMaxScheduleType,
		"PMaxSchedule");

	if (sascheduletuple->SalesTariff_isUsed) {
		dissect_v2gdin_salestariff(&sascheduletuple->SalesTariff,
			tvb, pinfo, subtree,
			ett_v2gdin_struct_din_SalesTariffType,
			"SalesTariff");
	}

	return;
}

static void
dissect_v2gdin_saschedulelist(
	const struct din_SAScheduleListType *saschedulelist,
	tvbuff_t *tvb,
	packet_info *pinfo,
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
			&saschedulelist->SAScheduleTuple.array[i],
			tvb, pinfo, sascheduletuple_tree,
			ett_v2gdin_struct_din_SAScheduleTupleType, index);
	}

	return;
}

static void
dissect_v2gdin_profileentry(
	const struct din_ProfileEntryType *profileentry,
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

	it = proto_tree_add_uint(subtree,
		hf_v2gdin_struct_din_ProfileEntryType_ChargingProfileEntryStart,
		tvb, 0, 0, profileentry->ChargingProfileEntryStart);
	proto_item_set_generated(it);

	it = proto_tree_add_int(subtree,
		hf_v2gdin_struct_din_ProfileEntryType_ChargingProfileEntryMaxPower,
		tvb, 0, 0, profileentry->ChargingProfileEntryMaxPower);
	proto_item_set_generated(it);

	return;
}

static void
dissect_v2gdin_chargingprofile(
	const struct din_ChargingProfileType *chargingprofile,
	tvbuff_t *tvb,
	packet_info *pinfo,
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
		hf_v2gdin_struct_din_ChargingProfileType_SAScheduleTupleID,
		tvb, 0, 0, chargingprofile->SAScheduleTupleID);
	proto_item_set_generated(it);

	profileentry_tree = proto_tree_add_subtree(subtree,
		tvb, 0, 0, ett_v2gdin_array, NULL, "ProfileEntry");
	for (i = 0; i < chargingprofile->ProfileEntry.arrayLen; i++) {
		char index[sizeof("[65536]")];

		snprintf(index, sizeof(index), "[%u]", i);
		dissect_v2gdin_profileentry(
			&chargingprofile->ProfileEntry.array[i],
			tvb, pinfo, profileentry_tree,
			ett_v2gdin_struct_din_ProfileEntryType, index);
	}

	return;
}

static void
dissect_v2gdin_meterinfo(const struct din_MeterInfoType *meterinfo,
			 tvbuff_t *tvb,
			 packet_info *pinfo,
			 proto_tree *tree,
			 gint idx,
			 const char *subtree_name)
{
	proto_tree *subtree;
	proto_item *it;

	subtree = proto_tree_add_subtree(tree, tvb, 0, 0,
		idx, NULL, subtree_name);

	exi_add_characters(subtree,
		hf_v2gdin_struct_din_MeterInfoType_MeterID,
		tvb,
		meterinfo->MeterID.characters,
		meterinfo->MeterID.charactersLen,
		sizeof(meterinfo->MeterID.characters));

	if (meterinfo->MeterReading_isUsed) {
		dissect_v2gdin_physicalvalue(&meterinfo->MeterReading,
			tvb, pinfo, subtree,
			ett_v2gdin_struct_din_PhysicalValueType,
			"MeterReading");
	}

	if (meterinfo->SigMeterReading_isUsed) {
		exi_add_bytes(subtree,
			hf_v2gdin_struct_din_MeterInfoType_SigMeterReading,
			tvb,
			meterinfo->SigMeterReading.bytes,
			meterinfo->SigMeterReading.bytesLen,
			sizeof(meterinfo->SigMeterReading.bytes));
	}

	if (meterinfo->MeterStatus_isUsed) {
		it = proto_tree_add_int(subtree,
			hf_v2gdin_struct_din_MeterInfoType_MeterStatus,
			tvb, 0, 0, meterinfo->MeterStatus);
		proto_item_set_generated(it);
	}

	if (meterinfo->TMeter_isUsed) {
		it = proto_tree_add_int64(subtree,
			hf_v2gdin_struct_din_MeterInfoType_TMeter,
			tvb, 0, 0, meterinfo->TMeter);
		proto_item_set_generated(it);
	}

	return;
}

static void
dissect_v2gdin_evpowerdeliveryparameter(
	const struct din_EVPowerDeliveryParameterType *evpowerdeliveryparameter _U_,
	tvbuff_t *tvb _U_,
	packet_info *pinfo _U_,
	proto_tree *tree _U_,
	gint idx _U_,
	const char *subtree_name _U_)
{
	/* no content */
	return;
}

static void
dissect_v2gdin_dc_evpowerdeliveryparameter(
	const struct din_DC_EVPowerDeliveryParameterType *dc_evpowerdeliveryparameter,
	tvbuff_t *tvb,
	packet_info *pinfo,
	proto_tree *tree,
	gint idx,
	const char *subtree_name)
{
	proto_tree *subtree;
	proto_item *it;

	subtree = proto_tree_add_subtree(tree, tvb, 0, 0,
		idx, NULL, subtree_name);

	dissect_v2gdin_dc_evstatus(&dc_evpowerdeliveryparameter->DC_EVStatus,
		tvb, pinfo, subtree,
		ett_v2gdin_struct_din_DC_EVStatusType,
		"DC_EVStatus");

	if (dc_evpowerdeliveryparameter->BulkChargingComplete_isUsed) {
		it = proto_tree_add_int(subtree,
			hf_v2gdin_struct_din_DC_EVPowerDeliveryParameterType_BulkChargingComplete,
			tvb, 0, 0,
			dc_evpowerdeliveryparameter->BulkChargingComplete);
		proto_item_set_generated(it);
	}

	it = proto_tree_add_int(subtree,
		hf_v2gdin_struct_din_DC_EVPowerDeliveryParameterType_ChargingComplete,
		tvb, 0, 0,
		dc_evpowerdeliveryparameter->ChargingComplete);
		proto_item_set_generated(it);

	return;
}


static void
dissect_v2gdin_header(const struct din_MessageHeaderType *header,
		      tvbuff_t *tvb,
		      packet_info *pinfo,
		      proto_tree *tree,
		      gint idx,
		      const char *subtree_name)
{
	proto_tree *subtree;

	subtree = proto_tree_add_subtree(tree,
		tvb, 0, 0, idx, NULL, subtree_name);

	exi_add_bytes(subtree, hf_v2gdin_struct_din_MessageHeaderType_SessionID, tvb,
		header->SessionID.bytes,
		header->SessionID.bytesLen,
		sizeof(header->SessionID.bytes));

	if (header->Notification_isUsed) {
		dissect_v2gdin_notification(
			&header->Notification, tvb, pinfo, subtree,
			ett_v2gdin_struct_din_NotificationType,
			"Notification");
	}

	if (header->Signature_isUsed) {
		dissect_v2gdin_signature(
			&header->Signature, tvb, pinfo, subtree,
			ett_v2gdin_struct_din_SignatureType,
			"Signature");
	}

	return;
}


static void
dissect_v2gdin_sessionsetupreq(
	const struct din_SessionSetupReqType *sessionsetupreq,
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
		hf_v2gdin_struct_din_SessionSetupReqType_EVCCID,
		tvb,
		sessionsetupreq->EVCCID.bytes,
		sessionsetupreq->EVCCID.bytesLen,
		sizeof(sessionsetupreq->EVCCID.bytes));

	return;
}

static void
dissect_v2gdin_sessionsetupres(
	const struct din_SessionSetupResType *sessionsetupres,
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
		hf_v2gdin_struct_din_SessionSetupResType_ResponseCode,
		tvb, 0, 0, sessionsetupres->ResponseCode);
	proto_item_set_generated(it);

	exi_add_bytes(subtree,
		hf_v2gdin_struct_din_SessionSetupResType_EVSEID,
		tvb,
		sessionsetupres->EVSEID.bytes,
		sessionsetupres->EVSEID.bytesLen,
		sizeof(sessionsetupres->EVSEID.bytes));

	if (sessionsetupres->DateTimeNow_isUsed) {
		it = proto_tree_add_int64(subtree,
			hf_v2gdin_struct_din_SessionSetupResType_DateTimeNow,
			tvb, 0, 0, sessionsetupres->DateTimeNow);
		proto_item_set_generated(it);
	}

	return;
}

static void
dissect_v2gdin_servicediscoveryreq(
	const struct din_ServiceDiscoveryReqType *servicediscoveryreq,
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

	if (servicediscoveryreq->ServiceScope_isUsed) {
		exi_add_characters(subtree,
			hf_v2gdin_struct_din_ServiceDiscoveryReqType_ServiceScope,
			tvb,
			servicediscoveryreq->ServiceScope.characters,
			servicediscoveryreq->ServiceScope.charactersLen,
			sizeof(servicediscoveryreq->ServiceScope.characters));
	}

	if (servicediscoveryreq->ServiceCategory_isUsed) {
		it = proto_tree_add_uint(subtree,
			hf_v2gdin_struct_din_ServiceDiscoveryReqType_ServiceCategory,
			tvb, 0, 0, servicediscoveryreq->ServiceCategory);
		proto_item_set_generated(it);
	}

	return;
}

static void
dissect_v2gdin_servicediscoveryres(
	const struct din_ServiceDiscoveryResType *servicediscoveryres,
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
		hf_v2gdin_struct_din_ServiceDiscoveryResType_ResponseCode,
		tvb, 0, 0, servicediscoveryres->ResponseCode);
	proto_item_set_generated(it);

	dissect_v2gdin_paymentoptions(
		&servicediscoveryres->PaymentOptions,
		tvb, pinfo, subtree,
		ett_v2gdin_struct_din_PaymentOptionsType,
		"PaymentOptions");

	dissect_v2gdin_servicecharge(
		&servicediscoveryres->ChargeService,
		tvb, pinfo, subtree,
		ett_v2gdin_struct_din_ServiceChargeType,
		"ChargeService");

	if (servicediscoveryres->ServiceList_isUsed) {
		dissect_v2gdin_servicetaglist(
			&servicediscoveryres->ServiceList,
			tvb, pinfo, subtree,
			ett_v2gdin_struct_din_ServiceTagListType,
			"ServiceList");
	}

	return;
}

static void
dissect_v2gdin_servicedetailreq(
	const struct din_ServiceDetailReqType *servicedetailreq,
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
		hf_v2gdin_struct_din_ServiceDetailReqType_ServiceID,
		tvb, 0, 0, servicedetailreq->ServiceID);
	proto_item_set_generated(it);

	return;
}

static void
dissect_v2gdin_servicedetailres(
	const struct din_ServiceDetailResType *servicedetailres,
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
		hf_v2gdin_struct_din_ServiceDetailResType_ResponseCode,
		tvb, 0, 0, servicedetailres->ResponseCode);
	proto_item_set_generated(it);

	it = proto_tree_add_uint(subtree,
		hf_v2gdin_struct_din_ServiceDetailResType_ServiceID,
		tvb, 0, 0, servicedetailres->ServiceID);
	proto_item_set_generated(it);

	if (servicedetailres->ServiceParameterList_isUsed) {
		dissect_v2gdin_serviceparameterlist(
			&servicedetailres->ServiceParameterList,
			tvb, pinfo, subtree,
			ett_v2gdin_struct_din_ServiceParameterListType,
			"ServiceParameterList");
	}

	return;
}

static void
dissect_v2gdin_servicepaymentselectionreq(
	const struct din_ServicePaymentSelectionReqType
		*servicepaymentselectionreq,
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
		hf_v2gdin_struct_din_ServicePaymentSelectionReqType_SelectedPaymentOption,
		tvb, 0, 0, servicepaymentselectionreq->SelectedPaymentOption);
	proto_item_set_generated(it);

	dissect_v2gdin_selectedservicelist(
		&servicepaymentselectionreq->SelectedServiceList,
		tvb, pinfo, subtree,
		ett_v2gdin_struct_din_SelectedServiceListType,
		"SelectedServiceList");

	return;
}

static void
dissect_v2gdin_servicepaymentselectionres(
	const struct din_ServicePaymentSelectionResType
		*servicepaymentselectionres,
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
		hf_v2gdin_struct_din_ServicePaymentSelectionResType_ResponseCode,
		tvb, 0, 0,
		servicepaymentselectionres->ResponseCode);
	proto_item_set_generated(it);

	return;
}

static void
dissect_v2gdin_paymentdetailsreq(
	const struct din_PaymentDetailsReqType *paymentdetailsreq,
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
		hf_v2gdin_struct_din_PaymentDetailsReqType_ContractID,
		tvb,
		paymentdetailsreq->ContractID.characters,
		paymentdetailsreq->ContractID.charactersLen,
		sizeof(paymentdetailsreq->ContractID.characters));

	dissect_v2gdin_certificatechain(
		&paymentdetailsreq->ContractSignatureCertChain,
		tvb, pinfo, subtree,
		ett_v2gdin_struct_din_CertificateChainType,
		"ContractSignatureCertChain");

	return;
}

static void
dissect_v2gdin_paymentdetailsres(
	const struct din_PaymentDetailsResType *paymentdetailsres,
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
		hf_v2gdin_struct_din_PaymentDetailsResType_ResponseCode,
		tvb, 0, 0,
		paymentdetailsres->ResponseCode);
	proto_item_set_generated(it);

	exi_add_characters(subtree,
		hf_v2gdin_struct_din_PaymentDetailsResType_GenChallenge,
		tvb,
		paymentdetailsres->GenChallenge.characters,
		paymentdetailsres->GenChallenge.charactersLen,
		sizeof(paymentdetailsres->GenChallenge.characters));

	it = proto_tree_add_int64(subtree,
		hf_v2gdin_struct_din_PaymentDetailsResType_DateTimeNow,
		tvb, 0, 0,
		paymentdetailsres->DateTimeNow);
	proto_item_set_generated(it);

	return;
}

static void
dissect_v2gdin_contractauthenticationreq(
	const struct din_ContractAuthenticationReqType
		*contractauthenticationreq,
	tvbuff_t *tvb,
	packet_info *pinfo _U_,
	proto_tree *tree,
	gint idx,
	const char *subtree_name)
{
	proto_tree *subtree;

	subtree = proto_tree_add_subtree(tree,
		tvb, 0, 0, idx, NULL, subtree_name);

	if (contractauthenticationreq->Id_isUsed) {
		exi_add_characters(subtree,
			hf_v2gdin_struct_din_ContractAuthenticationReqType_Id,
			tvb,
			contractauthenticationreq->Id.characters,
			contractauthenticationreq->Id.charactersLen,
			sizeof(contractauthenticationreq->Id.characters));
	}
	if (contractauthenticationreq->GenChallenge_isUsed) {
		exi_add_characters(subtree,
			hf_v2gdin_struct_din_ContractAuthenticationReqType_GenChallenge,
			tvb,
			contractauthenticationreq->GenChallenge.characters,
			contractauthenticationreq->GenChallenge.charactersLen,
			sizeof(contractauthenticationreq->GenChallenge.characters));
	}

	return;
}

static void
dissect_v2gdin_contractauthenticationres(
	const struct din_ContractAuthenticationResType
		*contractauthenticationres,
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
		hf_v2gdin_struct_din_ContractAuthenticationResType_ResponseCode,
		tvb, 0, 0,
		contractauthenticationres->ResponseCode);
	proto_item_set_generated(it);

	it = proto_tree_add_uint(subtree,
		hf_v2gdin_struct_din_ContractAuthenticationResType_EVSEProcessing,
		tvb, 0, 0,
		contractauthenticationres->EVSEProcessing);
	proto_item_set_generated(it);

	return;
}

static void
dissect_v2gdin_chargeparameterdiscoveryreq(
	const struct din_ChargeParameterDiscoveryReqType
		*chargeparameterdiscoveryreq,
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
		hf_v2gdin_struct_din_ChargeParameterDiscoveryReqType_EVRequestedEnergyTransferType,
		tvb, 0, 0,
		chargeparameterdiscoveryreq->EVRequestedEnergyTransferType);
	proto_item_set_generated(it);

	if (chargeparameterdiscoveryreq->EVChargeParameter_isUsed) {
		dissect_v2gdin_evchargeparameter(
			&chargeparameterdiscoveryreq->EVChargeParameter,
			tvb, pinfo, subtree,
			ett_v2gdin_struct_din_EVChargeParameterType,
			"EVChargeParameter");
	}

	if (chargeparameterdiscoveryreq->AC_EVChargeParameter_isUsed) {
		dissect_v2gdin_ac_evchargeparameter(
			&chargeparameterdiscoveryreq->AC_EVChargeParameter,
			tvb, pinfo, subtree,
			ett_v2gdin_struct_din_AC_EVChargeParameterType,
			"AC_EVChargeParameter");
	}

	if (chargeparameterdiscoveryreq->DC_EVChargeParameter_isUsed) {
		dissect_v2gdin_dc_evchargeparameter(
			&chargeparameterdiscoveryreq->DC_EVChargeParameter,
			tvb, pinfo, subtree,
			ett_v2gdin_struct_din_DC_EVChargeParameterType,
			"DC_EVChargeParameter");
	}

	return;
}

static void
dissect_v2gdin_chargeparameterdiscoveryres(
	const struct din_ChargeParameterDiscoveryResType
		*chargeparameterdiscoveryres,
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
		hf_v2gdin_struct_din_ChargeParameterDiscoveryResType_ResponseCode,
		tvb, 0, 0,
		chargeparameterdiscoveryres->ResponseCode);
	proto_item_set_generated(it);

	it = proto_tree_add_uint(subtree,
		hf_v2gdin_struct_din_ChargeParameterDiscoveryResType_EVSEProcessing,
		tvb, 0, 0,
		chargeparameterdiscoveryres->EVSEProcessing);
	proto_item_set_generated(it);

	if (chargeparameterdiscoveryres->SASchedules_isUsed) {
		dissect_v2gdin_saschedules(
			&chargeparameterdiscoveryres->SASchedules,
			tvb, pinfo, subtree,
			ett_v2gdin_struct_din_SASchedulesType,
			"SASchedules");
	}
	if (chargeparameterdiscoveryres->SAScheduleList_isUsed) {
		dissect_v2gdin_saschedulelist(
			&chargeparameterdiscoveryres->SAScheduleList,
			tvb, pinfo, subtree,
			ett_v2gdin_struct_din_SAScheduleListType,
			"SAScheduleList");
	}
	if (chargeparameterdiscoveryres->EVSEChargeParameter_isUsed) {
		dissect_v2gdin_evsechargeparameter(&chargeparameterdiscoveryres->EVSEChargeParameter,
			tvb, pinfo, subtree,
			ett_v2gdin_struct_din_EVSEChargeParameterType,
			"EVSEChargeParameter");
	}
	if (chargeparameterdiscoveryres->AC_EVSEChargeParameter_isUsed) {
		dissect_v2gdin_ac_evsechargeparameter(
			&chargeparameterdiscoveryres->AC_EVSEChargeParameter,
			tvb, pinfo, subtree,
			ett_v2gdin_struct_din_AC_EVSEChargeParameterType,
			"AC_EVSEChargeParameter");
	}
	if (chargeparameterdiscoveryres->DC_EVSEChargeParameter_isUsed) {
		dissect_v2gdin_dc_evsechargeparameter(
			&chargeparameterdiscoveryres->DC_EVSEChargeParameter,
			tvb, pinfo, subtree,
			ett_v2gdin_struct_din_DC_EVSEChargeParameterType,
			"DC_EVSEChargeParameter");
	}

	return;
}

static void
dissect_v2gdin_powerdeliveryreq(
	const struct din_PowerDeliveryReqType *powerdeliveryreq,
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

	it = proto_tree_add_int(subtree,
		hf_v2gdin_struct_din_PowerDeliveryReqType_ReadyToChargeState,
		tvb, 0, 0, powerdeliveryreq->ReadyToChargeState);
	proto_item_set_generated(it);

	if (powerdeliveryreq->ChargingProfile_isUsed) {
		dissect_v2gdin_chargingprofile(
			&powerdeliveryreq->ChargingProfile,
			tvb, pinfo, subtree,
			ett_v2gdin_struct_din_ChargingProfileType,
			"ChargingProfile");
	}
	if (powerdeliveryreq->EVPowerDeliveryParameter_isUsed) {
		dissect_v2gdin_evpowerdeliveryparameter(
			&powerdeliveryreq->EVPowerDeliveryParameter,
			tvb, pinfo, subtree,
			ett_v2gdin_struct_din_EVPowerDeliveryParameterType,
			"EVPowerDeliveryParameter");
	}
	if (powerdeliveryreq->DC_EVPowerDeliveryParameter_isUsed) {
		dissect_v2gdin_dc_evpowerdeliveryparameter(
			&powerdeliveryreq->DC_EVPowerDeliveryParameter,
			tvb, pinfo, subtree,
			ett_v2gdin_struct_din_DC_EVPowerDeliveryParameterType,
			"DC_EVPowerDeliveryParameter");
	}

	return;
}

static void
dissect_v2gdin_powerdeliveryres(
	const struct din_PowerDeliveryResType *powerdeliveryres,
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
		hf_v2gdin_struct_din_PowerDeliveryResType_ResponseCode,
		tvb, 0, 0,
		powerdeliveryres->ResponseCode);
	proto_item_set_generated(it);

	if (powerdeliveryres->EVSEStatus_isUsed) {
		dissect_v2gdin_evsestatus(
			&powerdeliveryres->EVSEStatus,
			tvb, pinfo, subtree,
			ett_v2gdin_struct_din_EVSEStatusType,
			"EVSEStatus");
	}
	if (powerdeliveryres->AC_EVSEStatus_isUsed) {
		dissect_v2gdin_ac_evsestatus(
			&powerdeliveryres->AC_EVSEStatus,
			tvb, pinfo, subtree,
			ett_v2gdin_struct_din_AC_EVSEStatusType,
			"AC_EVSEStatus");
	}
	if (powerdeliveryres->DC_EVSEStatus_isUsed) {
		dissect_v2gdin_dc_evsestatus(
			&powerdeliveryres->DC_EVSEStatus,
			tvb, pinfo, subtree,
			ett_v2gdin_struct_din_DC_EVSEStatusType,
			"DC_EVSEStatus");
	}

	return;
}

static void
dissect_v2gdin_chargingstatusreq(
	const struct din_ChargingStatusReqType *chargingstatusreq _U_,
	tvbuff_t *tvb _U_,
	packet_info *pinfo _U_,
	proto_tree *tree _U_,
	gint idx _U_,
	const char *subtree_name _U_)
{
	proto_tree_add_subtree(tree,
		tvb, 0, 0, idx, NULL, subtree_name);

	/* no content */
	return;
}

static void
dissect_v2gdin_chargingstatusres(
	const struct din_ChargingStatusResType *chargingstatusres,
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
		hf_v2gdin_struct_din_ChargingStatusResType_ResponseCode,
		tvb, 0, 0,
		chargingstatusres->ResponseCode);
	proto_item_set_generated(it);

	exi_add_bytes(subtree,
		hf_v2gdin_struct_din_ChargingStatusResType_EVSEID,
		tvb,
		chargingstatusres->EVSEID.bytes,
		chargingstatusres->EVSEID.bytesLen,
		sizeof(chargingstatusres->EVSEID.bytes));

	it = proto_tree_add_int(subtree,
		hf_v2gdin_struct_din_ChargingStatusResType_SAScheduleTupleID,
		tvb, 0, 0,
		chargingstatusres->SAScheduleTupleID);
	proto_item_set_generated(it);

	if (chargingstatusres->EVSEMaxCurrent_isUsed) {
		dissect_v2gdin_physicalvalue(
			&chargingstatusres->EVSEMaxCurrent,
			tvb, pinfo, subtree,
			ett_v2gdin_struct_din_PhysicalValueType,
			"EVSEMaxCurrent");
	}

	if (chargingstatusres->MeterInfo_isUsed) {
		dissect_v2gdin_meterinfo(
			&chargingstatusres->MeterInfo,
			tvb, pinfo, subtree,
			ett_v2gdin_struct_din_MeterInfoType,
			"MeterInfo");
	}

	it = proto_tree_add_int(subtree,
		hf_v2gdin_struct_din_ChargingStatusResType_ReceiptRequired,
		tvb, 0, 0,
		chargingstatusres->ReceiptRequired);
	proto_item_set_generated(it);

	dissect_v2gdin_ac_evsestatus(
		&chargingstatusres->AC_EVSEStatus,
		tvb, pinfo, subtree,
		ett_v2gdin_struct_din_AC_EVSEStatusType,
		"AC_EVSEStatus");

	return;
}

static void
dissect_v2gdin_meteringreceiptreq(
	const struct din_MeteringReceiptReqType *meteringreceiptreq,
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

	if (meteringreceiptreq->Id_isUsed) {
		exi_add_characters(subtree,
			hf_v2gdin_struct_din_MeteringReceiptReqType_Id,
			tvb,
			meteringreceiptreq->Id.characters,
			meteringreceiptreq->Id.charactersLen,
			sizeof(meteringreceiptreq->Id.characters));
	}

	exi_add_bytes(subtree,
		hf_v2gdin_struct_din_MeteringReceiptReqType_SessionID,
		tvb,
		meteringreceiptreq->SessionID.bytes,
		meteringreceiptreq->SessionID.bytesLen,
		sizeof(meteringreceiptreq->SessionID.bytes));

	if (meteringreceiptreq->SAScheduleTupleID_isUsed) {
		it = proto_tree_add_int(subtree,
			hf_v2gdin_struct_din_MeteringReceiptReqType_SAScheduleTupleID,
			tvb, 0, 0,
			meteringreceiptreq->SAScheduleTupleID);
		proto_item_set_generated(it);
	}

	dissect_v2gdin_meterinfo(
		&meteringreceiptreq->MeterInfo,
		tvb, pinfo, subtree,
		ett_v2gdin_struct_din_MeterInfoType,
		"MeterInfo");

	return;
}

static void
dissect_v2gdin_meteringreceiptres(
	const struct din_MeteringReceiptResType *meteringreceiptres,
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
		hf_v2gdin_struct_din_MeteringReceiptResType_ResponseCode,
		tvb, 0, 0,
		meteringreceiptres->ResponseCode);
	proto_item_set_generated(it);

	dissect_v2gdin_ac_evsestatus(
		&meteringreceiptres->AC_EVSEStatus,
		tvb, pinfo, subtree,
		ett_v2gdin_struct_din_AC_EVSEStatusType,
		"AC_EVSEStatus");

	return;
}

static void
dissect_v2gdin_sessionstop(
	const struct din_SessionStopType *sessionstop _U_,
	tvbuff_t *tvb _U_,
	packet_info *pinfo _U_,
	proto_tree *tree _U_,
	gint idx _U_,
	const char *subtree_name _U_)
{
	proto_tree_add_subtree(tree,
		tvb, 0, 0, idx, NULL, subtree_name);

	/* no content */
	return;
}

static void
dissect_v2gdin_sessionstopres(
	const struct din_SessionStopResType *sessionstopres,
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
		hf_v2gdin_struct_din_SessionStopResType_ResponseCode,
		tvb, 0, 0, sessionstopres->ResponseCode);
	proto_item_set_generated(it);

	return;
}

static void
dissect_v2gdin_certificateupdatereq(
	const struct din_CertificateUpdateReqType *req,
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
		hf_v2gdin_struct_din_CertificateUpdateReqType_Id,
		tvb,
		req->Id.characters,
		req->Id.charactersLen,
		sizeof(req->Id.characters));

	dissect_v2gdin_certificatechain(
		&req->ContractSignatureCertChain,
		tvb, pinfo, subtree,
		ett_v2gdin_struct_din_CertificateChainType,
		"ContractSignatureCertChain");

	exi_add_characters(subtree,
		hf_v2gdin_struct_din_CertificateUpdateReqType_ContractID,
		tvb,
		req->ContractID.characters,
		req->ContractID.charactersLen,
		sizeof(req->ContractID.characters));

	dissect_v2gdin_listofrootcertificateids(
		&req->ListOfRootCertificateIDs,
		tvb, pinfo, subtree,
		ett_v2gdin_struct_din_ListOfRootCertificateIDsType,
		"ListOfRootCertificateIDs");

	exi_add_bytes(subtree,
		hf_v2gdin_struct_din_CertificateUpdateReqType_DHParams,
		tvb,
		req->DHParams.bytes,
		req->DHParams.bytesLen,
		sizeof(req->DHParams.bytes));

	return;
}

static void
dissect_v2gdin_certificateupdateres(
	const struct din_CertificateUpdateResType *res,
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

	exi_add_characters(subtree,
		hf_v2gdin_struct_din_CertificateUpdateResType_Id,
		tvb,
		res->Id.characters,
		res->Id.charactersLen,
		sizeof(res->Id.characters));

	it = proto_tree_add_uint(subtree,
		hf_v2gdin_struct_din_CertificateUpdateResType_ResponseCode,
		tvb, 0, 0, res->ResponseCode);
	proto_item_set_generated(it);

	dissect_v2gdin_certificatechain(
		&res->ContractSignatureCertChain,
		tvb, pinfo, subtree,
		ett_v2gdin_struct_din_CertificateChainType,
		"ContractSignatureCertChain");

	exi_add_bytes(subtree,
		hf_v2gdin_struct_din_CertificateUpdateResType_ContractSignatureEncryptedPrivateKey,
		tvb,
		res->ContractSignatureEncryptedPrivateKey.bytes,
		res->ContractSignatureEncryptedPrivateKey.bytesLen,
		sizeof(res->ContractSignatureEncryptedPrivateKey.bytes));

	exi_add_bytes(subtree,
		hf_v2gdin_struct_din_CertificateUpdateResType_DHParams,
		tvb,
		res->DHParams.bytes,
		res->DHParams.bytesLen,
		sizeof(res->DHParams.bytes));

	exi_add_characters(subtree,
		hf_v2gdin_struct_din_CertificateUpdateResType_ContractID,
		tvb,
		res->ContractID.characters,
		res->ContractID.charactersLen,
		sizeof(res->ContractID.characters));

	it = proto_tree_add_uint(subtree,
		hf_v2gdin_struct_din_CertificateUpdateResType_RetryCounter,
		tvb, 0, 0, res->RetryCounter);
	proto_item_set_generated(it);

	return;
}

static void
dissect_v2gdin_certificateinstallationreq(
	const struct din_CertificateInstallationReqType *req,
	tvbuff_t *tvb,
	packet_info *pinfo,
	proto_tree *tree,
	gint idx,
	const char *subtree_name)
{
	proto_tree *subtree;

	subtree = proto_tree_add_subtree(tree,
		tvb, 0, 0, idx, NULL, subtree_name);

	if (req->Id_isUsed) {
		exi_add_characters(subtree,
			hf_v2gdin_struct_din_CertificateInstallationReqType_Id,
			tvb,
			req->Id.characters,
			req->Id.charactersLen,
			sizeof(req->Id.characters));
	}

	exi_add_bytes(subtree,
		hf_v2gdin_struct_din_CertificateInstallationReqType_OEMProvisioningCert,
		tvb,
		req->OEMProvisioningCert.bytes,
		req->OEMProvisioningCert.bytesLen,
		sizeof(req->OEMProvisioningCert.bytes));
	dissect_v2gdin_listofrootcertificateids(
		&req->ListOfRootCertificateIDs,
		tvb, pinfo, subtree,
		ett_v2gdin_struct_din_ListOfRootCertificateIDsType,
		"ListOfRootCertificateIDs");

	exi_add_bytes(subtree,
		hf_v2gdin_struct_din_CertificateInstallationReqType_DHParams,
		tvb,
		req->DHParams.bytes,
		req->DHParams.bytesLen,
		sizeof(req->DHParams.bytes));

	return;
}

static void
dissect_v2gdin_certificateinstallationres(
	const struct din_CertificateInstallationResType *res,
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

	exi_add_characters(subtree,
		hf_v2gdin_struct_din_CertificateInstallationResType_Id,
		tvb,
		res->Id.characters,
		res->Id.charactersLen,
		sizeof(res->Id.characters));

	it = proto_tree_add_uint(subtree,
		hf_v2gdin_struct_din_CertificateInstallationResType_ResponseCode,
		tvb, 0, 0, res->ResponseCode);
	proto_item_set_generated(it);

	dissect_v2gdin_certificatechain(
		&res->ContractSignatureCertChain,
		tvb, pinfo, subtree,
		ett_v2gdin_struct_din_CertificateChainType,
		"ContractSignatureCertChain");

	exi_add_bytes(subtree,
		hf_v2gdin_struct_din_CertificateInstallationResType_ContractSignatureEncryptedPrivateKey,
		tvb,
		res->ContractSignatureEncryptedPrivateKey.bytes,
		res->ContractSignatureEncryptedPrivateKey.bytesLen,
		sizeof(res->ContractSignatureEncryptedPrivateKey.bytes));

	exi_add_bytes(subtree,
		hf_v2gdin_struct_din_CertificateInstallationResType_DHParams,
		tvb,
		res->DHParams.bytes,
		res->DHParams.bytesLen,
		sizeof(res->DHParams.bytes));

	exi_add_characters(subtree,
		hf_v2gdin_struct_din_CertificateInstallationResType_ContractID,
		tvb,
		res->ContractID.characters,
		res->ContractID.charactersLen,
		sizeof(res->ContractID.characters));

	return;
}

static void
dissect_v2gdin_cablecheckreq(
	const struct din_CableCheckReqType *req,
	tvbuff_t *tvb,
	packet_info *pinfo,
	proto_tree *tree,
	gint idx,
	const char *subtree_name)
{
	proto_tree *subtree;

	subtree = proto_tree_add_subtree(tree,
		tvb, 0, 0, idx, NULL, subtree_name);

	dissect_v2gdin_dc_evstatus(
		&req->DC_EVStatus,
		tvb, pinfo, subtree,
		ett_v2gdin_struct_din_DC_EVStatusType,
		"DC_EVStatus");

	return;
}

static void
dissect_v2gdin_cablecheckres(
	const struct din_CableCheckResType *res,
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
		hf_v2gdin_struct_din_CableCheckResType_ResponseCode,
		tvb, 0, 0, res->ResponseCode);
	proto_item_set_generated(it);

	dissect_v2gdin_dc_evsestatus(
		&res->DC_EVSEStatus,
		tvb, pinfo, subtree,
		ett_v2gdin_struct_din_DC_EVSEStatusType,
		"DC_EVSEStatus");

	it = proto_tree_add_uint(subtree,
		hf_v2gdin_struct_din_CableCheckResType_EVSEProcessing,
		tvb, 0, 0, res->EVSEProcessing);
	proto_item_set_generated(it);

	return;
}

static void
dissect_v2gdin_prechargereq(
	const struct din_PreChargeReqType *req,
	tvbuff_t *tvb,
	packet_info *pinfo,
	proto_tree *tree,
	gint idx,
	const char *subtree_name)
{
	proto_tree *subtree;
	proto_item *it;
	double value;

	subtree = proto_tree_add_subtree(tree,
		tvb, 0, 0, idx, NULL, subtree_name);

	dissect_v2gdin_dc_evstatus(
		&req->DC_EVStatus,
		tvb, pinfo, subtree,
		ett_v2gdin_struct_din_DC_EVStatusType,
		"DC_EVStatus");

	dissect_v2gdin_physicalvalue(
		&req->EVTargetVoltage,
		tvb, pinfo, subtree,
		ett_v2gdin_struct_din_PhysicalValueType,
		"EVTargetVoltage");
	value = v2gdin_physicalvalue_to_double(&req->EVTargetVoltage);
	it = proto_tree_add_double(subtree,
		hf_v2gdin_ev_target_voltage,
		tvb, 0, 0, value);
	proto_item_set_generated(it);

	dissect_v2gdin_physicalvalue(
		&req->EVTargetCurrent,
		tvb, pinfo, subtree,
		ett_v2gdin_struct_din_PhysicalValueType,
		"EVTargetCurrent");
	value = v2gdin_physicalvalue_to_double(&req->EVTargetCurrent);
	it = proto_tree_add_double(subtree,
		hf_v2gdin_ev_target_current,
		tvb, 0, 0, value);
	proto_item_set_generated(it);

	return;
}

static void
dissect_v2gdin_prechargeres(
	const struct din_PreChargeResType *res,
	tvbuff_t *tvb,
	packet_info *pinfo,
	proto_tree *tree,
	gint idx,
	const char *subtree_name)
{
	proto_tree *subtree;
	proto_item *it;
	double value;

	subtree = proto_tree_add_subtree(tree,
		tvb, 0, 0, idx, NULL, subtree_name);

	it = proto_tree_add_uint(subtree,
		hf_v2gdin_struct_din_PreChargeResType_ResponseCode,
		tvb, 0, 0, res->ResponseCode);
	proto_item_set_generated(it);

	dissect_v2gdin_dc_evsestatus(
		&res->DC_EVSEStatus,
		tvb, pinfo, subtree,
		ett_v2gdin_struct_din_DC_EVSEStatusType,
		"DC_EVSEStatus");

	dissect_v2gdin_physicalvalue(
		&res->EVSEPresentVoltage,
		tvb, pinfo, subtree,
		ett_v2gdin_struct_din_PhysicalValueType,
		"EVSEPresentVoltage");
	value = v2gdin_physicalvalue_to_double(&res->EVSEPresentVoltage);
	it = proto_tree_add_double(subtree,
		hf_v2gdin_evse_present_voltage,
		tvb, 0, 0, value);
	proto_item_set_generated(it);

	return;
}

static void
dissect_v2gdin_currentdemandreq(
	const struct din_CurrentDemandReqType *req,
	tvbuff_t *tvb,
	packet_info *pinfo,
	proto_tree *tree,
	gint idx,
	const char *subtree_name)
{
	proto_tree *subtree;
	proto_item *it;
	double value;

	subtree = proto_tree_add_subtree(tree,
		tvb, 0, 0, idx, NULL, subtree_name);

	dissect_v2gdin_dc_evstatus(
		&req->DC_EVStatus,
		tvb, pinfo, subtree,
		ett_v2gdin_struct_din_DC_EVStatusType,
		"DC_EVStatus");

	dissect_v2gdin_physicalvalue(
		&req->EVTargetVoltage,
		tvb, pinfo, subtree,
		ett_v2gdin_struct_din_PhysicalValueType,
		"EVTargetVoltage");
	value = v2gdin_physicalvalue_to_double(&req->EVTargetVoltage);
	it = proto_tree_add_double(subtree,
		hf_v2gdin_ev_target_voltage,
		tvb, 0, 0, value);
	proto_item_set_generated(it);

	dissect_v2gdin_physicalvalue(
		&req->EVTargetCurrent,
		tvb, pinfo, subtree,
		ett_v2gdin_struct_din_PhysicalValueType,
		"EVTargetCurrent");
	value = v2gdin_physicalvalue_to_double(&req->EVTargetCurrent);
	it = proto_tree_add_double(subtree,
		hf_v2gdin_ev_target_current,
		tvb, 0, 0, value);
	proto_item_set_generated(it);

	it = proto_tree_add_int(subtree,
		hf_v2gdin_struct_din_CurrentDemandReqType_ChargingComplete,
		tvb, 0, 0, req->ChargingComplete);
	proto_item_set_generated(it);

	if (req->BulkChargingComplete_isUsed) {
		it = proto_tree_add_int(subtree,
			hf_v2gdin_struct_din_CurrentDemandReqType_BulkChargingComplete,
			tvb, 0, 0, req->BulkChargingComplete);
		proto_item_set_generated(it);
	}

	if (req->EVMaximumVoltageLimit_isUsed) {
		dissect_v2gdin_physicalvalue(
			&req->EVMaximumVoltageLimit,
			tvb, pinfo, subtree,
			ett_v2gdin_struct_din_PhysicalValueType,
			"EVMaximumVoltageLimit");
		value = v2gdin_physicalvalue_to_double(&req->EVMaximumVoltageLimit);
		it = proto_tree_add_double(subtree,
			hf_v2gdin_ev_maximum_voltage_limit,
			tvb, 0, 0, value);
		proto_item_set_generated(it);
	}

	if (req->EVMaximumCurrentLimit_isUsed) {
		dissect_v2gdin_physicalvalue(
			&req->EVMaximumCurrentLimit,
			tvb, pinfo, subtree,
			ett_v2gdin_struct_din_PhysicalValueType,
			"EVMaximumCurrentLimit");
		value = v2gdin_physicalvalue_to_double(&req->EVMaximumCurrentLimit);
		it = proto_tree_add_double(subtree,
			hf_v2gdin_ev_maximum_current_limit,
			tvb, 0, 0, value);
		proto_item_set_generated(it);
	}

	if (req->EVMaximumPowerLimit_isUsed) {
		dissect_v2gdin_physicalvalue(
			&req->EVMaximumPowerLimit,
			tvb, pinfo, subtree,
			ett_v2gdin_struct_din_PhysicalValueType,
			"EVMaximumPowerLimit");
		value = v2gdin_physicalvalue_to_double(&req->EVMaximumPowerLimit);
		it = proto_tree_add_double(subtree,
			hf_v2gdin_ev_maximum_power_limit,
			tvb, 0, 0, value);
		proto_item_set_generated(it);
	}

	if (req->RemainingTimeToFullSoC_isUsed) {
		dissect_v2gdin_physicalvalue(
			&req->RemainingTimeToFullSoC,
			tvb, pinfo, subtree,
			ett_v2gdin_struct_din_PhysicalValueType,
			"RemainingTimeToFullSoC");
		value = v2gdin_physicalvalue_to_double(&req->RemainingTimeToFullSoC);
		it = proto_tree_add_double(subtree,
			hf_v2gdin_remaining_time_to_full_soc,
			tvb, 0, 0, value);
		proto_item_set_generated(it);
	}

	if (req->RemainingTimeToBulkSoC_isUsed) {
		dissect_v2gdin_physicalvalue(
			&req->RemainingTimeToBulkSoC,
			tvb, pinfo, subtree,
			ett_v2gdin_struct_din_PhysicalValueType,
			"RemainingTimeToBulkSoC");
		value = v2gdin_physicalvalue_to_double(&req->RemainingTimeToBulkSoC);
		it = proto_tree_add_double(subtree,
			hf_v2gdin_remaining_time_to_bulk_soc,
			tvb, 0, 0, value);
		proto_item_set_generated(it);
	}

	return;
}

static void
dissect_v2gdin_currentdemandres(
	const struct din_CurrentDemandResType *res,
	tvbuff_t *tvb,
	packet_info *pinfo,
	proto_tree *tree,
	gint idx,
	const char *subtree_name)
{
	proto_tree *subtree;
	proto_item *it;
	double value;

	subtree = proto_tree_add_subtree(tree,
		tvb, 0, 0, idx, NULL, subtree_name);

	it = proto_tree_add_uint(subtree,
		hf_v2gdin_struct_din_CurrentDemandResType_ResponseCode,
		tvb, 0, 0, res->ResponseCode);
	proto_item_set_generated(it);

	dissect_v2gdin_dc_evsestatus(
		&res->DC_EVSEStatus,
		tvb, pinfo, subtree,
		ett_v2gdin_struct_din_DC_EVSEStatusType,
		"DC_EVSEStatus");

	dissect_v2gdin_physicalvalue(
		&res->EVSEPresentVoltage,
		tvb, pinfo, subtree,
		ett_v2gdin_struct_din_PhysicalValueType,
		"EVSEPresentVoltage");
	value = v2gdin_physicalvalue_to_double(&res->EVSEPresentVoltage);
	it = proto_tree_add_double(subtree,
		hf_v2gdin_evse_present_voltage,
		tvb, 0, 0, value);
	proto_item_set_generated(it);

	dissect_v2gdin_physicalvalue(
		&res->EVSEPresentCurrent,
		tvb, pinfo, subtree,
		ett_v2gdin_struct_din_PhysicalValueType,
		"EVSEPresentCurrent");
	value = v2gdin_physicalvalue_to_double(&res->EVSEPresentCurrent);
	it = proto_tree_add_double(subtree,
		hf_v2gdin_evse_present_current,
		tvb, 0, 0, value);
	proto_item_set_generated(it);

	it = proto_tree_add_int(subtree,
		hf_v2gdin_struct_din_CurrentDemandResType_EVSECurrentLimitAchieved,
		tvb, 0, 0, res->EVSECurrentLimitAchieved);
	proto_item_set_generated(it);

	it = proto_tree_add_int(subtree,
		hf_v2gdin_struct_din_CurrentDemandResType_EVSEVoltageLimitAchieved,
		tvb, 0, 0, res->EVSEVoltageLimitAchieved);
	proto_item_set_generated(it);

	it = proto_tree_add_int(subtree,
		hf_v2gdin_struct_din_CurrentDemandResType_EVSEPowerLimitAchieved,
		tvb, 0, 0, res->EVSEPowerLimitAchieved);
	proto_item_set_generated(it);

	if (res->EVSEMaximumVoltageLimit_isUsed) {
		dissect_v2gdin_physicalvalue(
			&res->EVSEMaximumVoltageLimit,
			tvb, pinfo, subtree,
			ett_v2gdin_struct_din_PhysicalValueType,
			"EVSEMaximumVoltageLimit");
		value = v2gdin_physicalvalue_to_double(&res->EVSEMaximumVoltageLimit);
		it = proto_tree_add_double(subtree,
			hf_v2gdin_evse_maximum_voltage_limit,
			tvb, 0, 0, value);
		proto_item_set_generated(it);
	}
	if (res->EVSEMaximumCurrentLimit_isUsed) {
		dissect_v2gdin_physicalvalue(
			&res->EVSEMaximumCurrentLimit,
			tvb, pinfo, subtree,
			ett_v2gdin_struct_din_PhysicalValueType,
			"EVSEMaximumCurrentLimit");
		value = v2gdin_physicalvalue_to_double(&res->EVSEMaximumCurrentLimit);
		it = proto_tree_add_double(subtree,
			hf_v2gdin_evse_maximum_current_limit,
			tvb, 0, 0, value);
		proto_item_set_generated(it);
	}
	if (res->EVSEMaximumPowerLimit_isUsed) {
		dissect_v2gdin_physicalvalue(
			&res->EVSEMaximumPowerLimit,
			tvb, pinfo, subtree,
			ett_v2gdin_struct_din_PhysicalValueType,
			"EVSEMaximumPowerLimit");
		value = v2gdin_physicalvalue_to_double(&res->EVSEMaximumPowerLimit);
		it = proto_tree_add_double(subtree,
			hf_v2gdin_evse_maximum_power_limit,
			tvb, 0, 0, value);
		proto_item_set_generated(it);
	}

	return;
}

static void
dissect_v2gdin_weldingdetectionreq(
	const struct din_WeldingDetectionReqType *req,
	tvbuff_t *tvb,
	packet_info *pinfo,
	proto_tree *tree,
	gint idx,
	const char *subtree_name)
{
	proto_tree *subtree;

	subtree = proto_tree_add_subtree(tree,
		tvb, 0, 0, idx, NULL, subtree_name);

	dissect_v2gdin_dc_evstatus(
		&req->DC_EVStatus,
		tvb, pinfo, subtree,
		ett_v2gdin_struct_din_DC_EVStatusType, "DC_EVStatus");

	return;
}

static void
dissect_v2gdin_weldingdetectionres(
	const struct din_WeldingDetectionResType *res,
	tvbuff_t *tvb,
	packet_info *pinfo,
	proto_tree *tree,
	gint idx,
	const char *subtree_name)
{
	proto_tree *subtree;
	proto_item *it;
	double value;

	subtree = proto_tree_add_subtree(tree,
		tvb, 0, 0, idx, NULL, subtree_name);

	it = proto_tree_add_uint(subtree,
		hf_v2gdin_struct_din_WeldingDetectionResType_ResponseCode,
		tvb, 0, 0, res->ResponseCode);
	proto_item_set_generated(it);

	dissect_v2gdin_dc_evsestatus(
		&res->DC_EVSEStatus,
		tvb, pinfo, subtree,
		ett_v2gdin_struct_din_DC_EVSEStatusType,
		"DC_EVSEStatus");

	dissect_v2gdin_physicalvalue(
		&res->EVSEPresentVoltage,
		tvb, pinfo, subtree,
		ett_v2gdin_struct_din_PhysicalValueType,
		"EVSEPresentVoltage");
	value = v2gdin_physicalvalue_to_double(&res->EVSEPresentVoltage);
	it = proto_tree_add_double(subtree,
		hf_v2gdin_evse_present_voltage,
		tvb, 0, 0, value);
	proto_item_set_generated(it);

	return;
}


static void
dissect_v2gdin_body(const struct din_BodyType *body,
		    tvbuff_t *tvb,
		    packet_info *pinfo,
		    proto_tree *tree,
		    gint idx,
		    const char *subtree_name)
{
	proto_tree *body_tree;

	body_tree = proto_tree_add_subtree(tree,
		tvb, 0, 0, idx, NULL, subtree_name);

	if (body->SessionSetupReq_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO, "SessionSetupReq");
		dissect_v2gdin_sessionsetupreq(
			&body->SessionSetupReq,
			tvb, pinfo, body_tree,
			ett_v2gdin_struct_din_SessionSetupReqType,
			"SessionSetupReq");
	}
	if (body->SessionSetupRes_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO, "SessionSetupRes");
		dissect_v2gdin_sessionsetupres(
			&body->SessionSetupRes,
			tvb, pinfo, body_tree,
			ett_v2gdin_struct_din_SessionSetupResType,
			"SessionSetupRes");
	}

	if (body->ServiceDiscoveryReq_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO, "ServiceDiscoveryReq");
		dissect_v2gdin_servicediscoveryreq(
			&body->ServiceDiscoveryReq,
			tvb, pinfo, body_tree,
			ett_v2gdin_struct_din_ServiceDiscoveryReqType,
			"ServiceDiscoveryReq");
	}
	if (body->ServiceDiscoveryRes_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO, "ServiceDiscoveryRes");
		dissect_v2gdin_servicediscoveryres(
			&body->ServiceDiscoveryRes,
			tvb, pinfo, body_tree,
			ett_v2gdin_struct_din_ServiceDiscoveryResType,
			"ServiceDiscoveryRes");
	}

	if (body->ServiceDetailReq_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO, "ServiceDetailReq");
		dissect_v2gdin_servicedetailreq(
			&body->ServiceDetailReq,
			tvb, pinfo, body_tree,
			ett_v2gdin_struct_din_ServiceDetailReqType,
			"ServiceDetailReq");
	}
	if (body->ServiceDetailRes_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO, "ServiceDetailRes");
		dissect_v2gdin_servicedetailres(
			&body->ServiceDetailRes,
			tvb, pinfo, body_tree,
			ett_v2gdin_struct_din_ServiceDetailResType,
			"ServiceDetailRes");
	}

	if (body->ServicePaymentSelectionReq_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO,
			"ServicePaymentSelectionReq");
		dissect_v2gdin_servicepaymentselectionreq(
			&body->ServicePaymentSelectionReq,
			tvb, pinfo, body_tree,
			ett_v2gdin_struct_din_ServicePaymentSelectionReqType,
			"ServicePaymentSelectionReq");
	}
	if (body->ServicePaymentSelectionRes_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO,
			"ServicePaymentSelectionRes");
		dissect_v2gdin_servicepaymentselectionres(
			&body->ServicePaymentSelectionRes,
			tvb, pinfo, body_tree,
			ett_v2gdin_struct_din_ServicePaymentSelectionResType,
			"ServicePaymentSelectionRes");
	}

	if (body->PaymentDetailsReq_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO, "PaymentDetailsReq");
		dissect_v2gdin_paymentdetailsreq(
			&body->PaymentDetailsReq,
			tvb, pinfo, body_tree,
			ett_v2gdin_struct_din_PaymentDetailsReqType,
			"PaymentDetailsReq");
	}
	if (body->PaymentDetailsRes_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO, "PaymentDetailsRes");
		dissect_v2gdin_paymentdetailsres(
			&body->PaymentDetailsRes,
			tvb, pinfo, body_tree,
			ett_v2gdin_struct_din_PaymentDetailsResType,
			"PaymentDetailsRes");
	}

	if (body->ContractAuthenticationReq_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO,
			"ContractAuthenticationReq");
		dissect_v2gdin_contractauthenticationreq(
			&body->ContractAuthenticationReq,
			tvb, pinfo, body_tree,
			ett_v2gdin_struct_din_ContractAuthenticationReqType,
			"ContractAuthenticationReq");
	}
	if (body->ContractAuthenticationRes_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO,
			"ContractAuthenticationRes");
		dissect_v2gdin_contractauthenticationres(
			&body->ContractAuthenticationRes,
			tvb, pinfo, body_tree,
			ett_v2gdin_struct_din_ContractAuthenticationResType,
			"ContractAuthenticationRes");
	}

	if (body->ChargeParameterDiscoveryReq_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO,
			"ChargeParameterDiscoveryReq");
		dissect_v2gdin_chargeparameterdiscoveryreq(
			&body->ChargeParameterDiscoveryReq,
			tvb, pinfo, body_tree,
			ett_v2gdin_struct_din_ChargeParameterDiscoveryReqType,
			"ChargeParameterDiscoveryReq");
	}
	if (body->ChargeParameterDiscoveryRes_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO,
			"ChargeParameterDiscoveryRes");
		dissect_v2gdin_chargeparameterdiscoveryres(
			&body->ChargeParameterDiscoveryRes,
			tvb, pinfo, body_tree,
			ett_v2gdin_struct_din_ChargeParameterDiscoveryResType,
			"ChargeParameterDiscoveryRes");
	}

	if (body->PowerDeliveryReq_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO, "PowerDeliveryReq");
		dissect_v2gdin_powerdeliveryreq(
			&body->PowerDeliveryReq,
			tvb, pinfo, body_tree,
			ett_v2gdin_struct_din_PowerDeliveryReqType,
			"PowerDeliveryReq");
	}
	if (body->PowerDeliveryRes_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO, "PowerDeliveryRes");
		dissect_v2gdin_powerdeliveryres(
			&body->PowerDeliveryRes,
			tvb, pinfo, body_tree,
			ett_v2gdin_struct_din_PowerDeliveryResType,
			"PowerDeliveryRes");
	}

	if (body->ChargingStatusReq_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO, "ChargingStatusReq");
		dissect_v2gdin_chargingstatusreq(
			&body->ChargingStatusReq,
			tvb, pinfo, body_tree,
			ett_v2gdin_struct_din_ChargingStatusReqType,
			"ChargingStatusReq");
	}
	if (body->ChargingStatusRes_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO, "ChargingStatusRes");
		dissect_v2gdin_chargingstatusres(
			&body->ChargingStatusRes,
			tvb, pinfo, body_tree,
			ett_v2gdin_struct_din_ChargingStatusResType,
			"ChargingStatusRes");
	}

	if (body->MeteringReceiptReq_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO, "MeteringReceiptReq");
		dissect_v2gdin_meteringreceiptreq(
			&body->MeteringReceiptReq,
			tvb, pinfo, body_tree,
			ett_v2gdin_struct_din_MeteringReceiptReqType,
			"MeteringReceiptReq");
	}
	if (body->MeteringReceiptRes_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO, "MeteringReceiptRes");
		dissect_v2gdin_meteringreceiptres(
			&body->MeteringReceiptRes,
			tvb, pinfo, body_tree,
			ett_v2gdin_struct_din_MeteringReceiptResType,
			"MeteringReceiptRes");
	}

	if (body->SessionStopReq_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO, "SessionStopReq");
		dissect_v2gdin_sessionstop(
			&body->SessionStopReq,
			tvb, pinfo, body_tree,
			ett_v2gdin_struct_din_SessionStopType,
			"SessionStopReq");
	}
	if (body->SessionStopRes_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO, "SessionStopRes");
		dissect_v2gdin_sessionstopres(
			&body->SessionStopRes,
			tvb, pinfo, body_tree,
			ett_v2gdin_struct_din_SessionStopResType,
			"SessionStopRes");
	}

	if (body->CertificateUpdateReq_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO, "CertificateUpdateReq");
		dissect_v2gdin_certificateupdatereq(
			&body->CertificateUpdateReq,
			tvb, pinfo, body_tree,
			ett_v2gdin_struct_din_CertificateUpdateReqType,
			"CertificateUpdateReq");
	}
	if (body->CertificateUpdateRes_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO, "CertificateUpdateRes");
		dissect_v2gdin_certificateupdateres(
			&body->CertificateUpdateRes,
			tvb, pinfo, body_tree,
			ett_v2gdin_struct_din_CertificateUpdateResType,
			"CertificateUpdateRes");
	}

	if (body->CertificateInstallationReq_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO,
			"CertificateInstallationReq");
		dissect_v2gdin_certificateinstallationreq(
			&body->CertificateInstallationReq,
			tvb, pinfo, body_tree,
			ett_v2gdin_struct_din_CertificateInstallationReqType,
			"CertificateInstallationReq");
	}
	if (body->CertificateInstallationRes_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO,
			"CertificateInstallationRes");
		dissect_v2gdin_certificateinstallationres(
			&body->CertificateInstallationRes,
			tvb, pinfo, body_tree,
			ett_v2gdin_struct_din_CertificateInstallationResType,
			"CertificateInstallationRes");
	}

	if (body->CableCheckReq_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO, "CableCheckReq");
		dissect_v2gdin_cablecheckreq(
			&body->CableCheckReq,
			tvb, pinfo, body_tree,
			ett_v2gdin_struct_din_CableCheckReqType,
			"CableCheckReq");
	}
	if (body->CableCheckRes_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO, "CableCheckRes");
		dissect_v2gdin_cablecheckres(
			&body->CableCheckRes,
			tvb, pinfo, body_tree,
			ett_v2gdin_struct_din_CableCheckResType,
			"CableCheckRes");
	}

	if (body->PreChargeReq_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO, "PreChargeReq");
		dissect_v2gdin_prechargereq(
			&body->PreChargeReq,
			tvb, pinfo, body_tree,
			ett_v2gdin_struct_din_PreChargeReqType,
			"PreChargeReq");
	}
	if (body->PreChargeRes_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO, "PreChargeRes");
		dissect_v2gdin_prechargeres(
			&body->PreChargeRes,
			tvb, pinfo, body_tree,
			ett_v2gdin_struct_din_PreChargeResType,
			"PreChargeRes");
	}

	if (body->CurrentDemandReq_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO, "CurrentDemandReq");
		dissect_v2gdin_currentdemandreq(
			&body->CurrentDemandReq,
			tvb, pinfo, body_tree,
			ett_v2gdin_struct_din_CurrentDemandReqType,
			"CurrentDemandReq");
	}
	if (body->CurrentDemandRes_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO, "CurrentDemandRes");
		dissect_v2gdin_currentdemandres(
			&body->CurrentDemandRes,
			tvb, pinfo, body_tree,
			ett_v2gdin_struct_din_CurrentDemandResType,
			"CurrentDemandRes");
	}

	if (body->WeldingDetectionReq_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO, "WeldingDetectionReq");
		dissect_v2gdin_weldingdetectionreq(
			&body->WeldingDetectionReq,
			tvb, pinfo, body_tree,
			ett_v2gdin_struct_din_WeldingDetectionReqType,
			"WeldingDetectionReq");
	}
	if (body->WeldingDetectionRes_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO, "WeldingDetectionRes");
		dissect_v2gdin_weldingdetectionres(
			&body->WeldingDetectionRes,
			tvb, pinfo, body_tree,
			ett_v2gdin_struct_din_WeldingDetectionResType,
			"WeldingDetectionRes");
	}

	return;
}


static int
dissect_v2gdin(tvbuff_t *tvb,
	       packet_info *pinfo, proto_tree *tree _U_, void *data _U_)
{
	proto_tree *v2gdin_tree;
	size_t size;
	exi_bitstream_t stream;
	int errn;
	struct din_exiDocument *exidin;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "DIN");
	/* Clear the info column */
	col_clear(pinfo->cinfo, COL_INFO);

	size = tvb_reported_length(tvb);
	exi_bitstream_init(&stream,
			   tvb_memdup(wmem_packet_scope(), tvb, 0, size),
			   size, 0, NULL);

	exidin = wmem_alloc(pinfo->pool, sizeof(*exidin));
	errn = decode_din_exiDocument(&stream, exidin);
	if (errn != 0) {
		wmem_free(pinfo->pool, exidin);
		/* decode failed */
		return 0;
	}

	/*
	 * Everything in DIN should come in as a message
	 * - Header
	 * - Body
	 */
	v2gdin_tree = proto_tree_add_subtree(tree,
		tvb, 0, 0, ett_v2gdin, NULL, "V2G DIN Message");

	dissect_v2gdin_header(&exidin->V2G_Message.Header,
		tvb, pinfo, v2gdin_tree, ett_v2gdin_header, "Header");
	dissect_v2gdin_body(&exidin->V2G_Message.Body,
		tvb, pinfo, v2gdin_tree, ett_v2gdin_body, "Body");

	wmem_free(pinfo->pool, exidin);
	return tvb_captured_length(tvb);
}


void
proto_register_v2gdin(void)
{

	static hf_register_info hf[] = {
		/* struct din_NotificationType */
		{ &hf_v2gdin_struct_din_NotificationType_FaultCode,
		  { "FaultCode", "v2gdin.struct.notification.faultcode",
		    FT_UINT16, BASE_DEC, VALS(v2gdin_fault_code_names),
		    0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_struct_din_NotificationType_FaultMsg,
		  { "FaultMsg", "v2gdin.struct.notification.faultmsg",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* struct din_SignatureType */
		{ &hf_v2gdin_struct_din_SignatureType_Id,
		  { "Id", "v2gdin.struct.signature.id",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* struct din_SignedInfoType */
		{ &hf_v2gdin_struct_din_SignedInfoType_Id,
		  { "Id", "v2gdin.struct.signedinfo.id",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* struct din_KeyInfoType */
		{ &hf_v2gdin_struct_din_KeyInfoType_Id,
		  { "Id", "v2gdin.struct.keyinfo.id",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_struct_din_KeyInfoType_KeyName,
		  { "KeyName", "v2gdin.struct.keyinfo.keyname",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_struct_din_KeyInfoType_MgmtData,
		  { "MgmtData", "v2gdin.struct.keyinfo.mgmtdata",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_struct_din_KeyInfoType_ANY,
		  { "ANY", "v2gdin.struct.keyinfo.any",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* struct din_KeyValueType */
		{ &hf_v2gdin_struct_din_KeyValueType_ANY,
		  { "ANY", "v2gdin.struct.keyvalue.any",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* struct din_DSAKeyValueType */
		{ &hf_v2gdin_struct_din_DSAKeyValueType_P,
		  { "P", "v2gdin.struct.dsakeyvalue.p",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_struct_din_DSAKeyValueType_Q,
		  { "Q", "v2gdin.struct.dsakeyvalue.q",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_struct_din_DSAKeyValueType_G,
		  { "G", "v2gdin.struct.dsakeyvalue.g",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_struct_din_DSAKeyValueType_Y,
		  { "Y", "v2gdin.struct.dsakeyvalue.y",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_struct_din_DSAKeyValueType_J,
		  { "J", "v2gdin.struct.dsakeyvalue.j",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_struct_din_DSAKeyValueType_Seed,
		  { "Seed", "v2gdin.struct.dsakeyvalue.seed",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_struct_din_DSAKeyValueType_PgenCounter,
		  { "PgenCounter", "v2gdin.struct.dsakeyvalue.pgencounter",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* struct din_RSAKeyValueType */
		{ &hf_v2gdin_struct_din_RSAKeyValueType_Modulus,
		  { "Modulus", "v2gdin.struct.rsakeyvalue.modulus",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_struct_din_RSAKeyValueType_Exponent,
		  { "Exponent", "v2gdin.struct.rsakeyvalue.exponent",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* struct din_X509DataType */
		{ &hf_v2gdin_struct_din_X509DataType_X509SKI,
		  { "X509SKI", "v2gdin.struct.x509data.x509ski",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_struct_din_X509DataType_X509SubjectName,
		  { "X509SubjectName",
		    "v2gdin.struct.x509data.x509subjectname",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_struct_din_X509DataType_X509Certificate,
		  { "X509Certificate",
		    "v2gdin.struct.x509data.x509certificate",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_struct_din_X509DataType_X509CRL,
		  { "X509CRL", "v2gdin.struct.x509data.x509crl",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_struct_din_X509DataType_ANY,
		  { "ANY", "v2gdin.struct.x509data.any",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* struct din_X509IssuerSerialType */
		{ &hf_v2gdin_struct_din_X509IssuerSerialType_X509IssuerName,
		  { "X509IssuerName",
		    "v2gdin.struct.x509issuerserial.x509issuername",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_struct_din_X509IssuerSerialType_X509SerialNumber,
		  { "X509SerialNumber",
		    "v2gdin.struct.x509issuerserial.x509serialnumber",
		    FT_INT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},

		/* struct din_PGPDataType */
		{ &hf_v2gdin_struct_din_PGPDataType_PGPKeyID,
		  { "PGPKeyID", "v2gdin.struct.pgpdata.pgpkeyid",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_struct_din_PGPDataType_PGPKeyPacket,
		  { "PGPKeyPacket", "v2gdin.struct.pgpdata.pgpkeypacket",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_struct_din_PGPDataType_ANY,
		  { "ANY", "v2gdin.struct.pgpdata.any",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* struct din_SPKIDataType */
		{ &hf_v2gdin_struct_din_SPKIDataType_SPKISexp,
		  { "SPKISexp", "v2gdin.struct.spkidata.spkisexp",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_struct_din_SPKIDataType_ANY,
		  { "ANY", "v2gdin.struct.spkidata.any",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* struct din_RetrievalMethodType */
		{ &hf_v2gdin_struct_din_RetrievalMethodType_URI,
		  { "URI", "v2gdin.struct.retrievalmethod.uri",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_struct_din_RetrievalMethodType_Type,
		  { "Type", "v2gdin.struct.retrievalmethod.type",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* struct din_SignatureValueType */
		{ &hf_v2gdin_struct_din_SignatureValueType_Id,
		  { "Id", "v2gdin.struct.signavturevalue.id",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_struct_din_SignatureValueType_CONTENT,
		  { "CONTENT", "v2gdin.struct.signaturevalue.content",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* struct din_CanonicalizationMethodType */
		{ &hf_v2gdin_struct_din_CanonicalizationMethodType_Algorithm,
		  { "Algorithm",
		    "v2gdin.struct.canonicalizationmethod.algorithm",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_struct_din_CanonicalizationMethodType_ANY,
		  { "ANY",
		    "v2gdin.struct.canonicalizationmethod.any",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* struct din_DigestMethodType */
		{ &hf_v2gdin_struct_din_DigestMethodType_Algorithm,
		  { "Algorithm", "v2gdin.struct.digestmethod.algorithm",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_struct_din_DigestMethodType_ANY,
		  { "ANY", "v2gdin.struct.digestmethod.any",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* struct din_SignatureMethodType */
		{ &hf_v2gdin_struct_din_SignatureMethodType_Algorithm,
		  { "Algorithm", "v2gdin.struct.signaturemethod.algorithm",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_struct_din_SignatureMethodType_HMACOutputLength,
		  { "HMACOutputLength",
		    "v2gdin.struct.signaturemethod.hmacoutputlength",
		    FT_INT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_struct_din_SignatureMethodType_ANY,
		  { "ANY", "v2gdin.struct.signaturemethod.any",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* struct din_TransformType */
		{ &hf_v2gdin_struct_din_TransformType_Algorithm,
		  { "Algorithm", "v2gdin.struct.transform.algorithm",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_struct_din_TransformType_ANY,
		  { "ANY", "v2gdin.struct.transform.any",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_struct_din_TransformType_XPath,
		  { "XPath", "v2gdin.struct.transform.xpath",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* struct din_ReferenceType */
		{ &hf_v2gdin_struct_din_ReferenceType_Id,
		  { "Id", "v2gdin.struct.reference.id",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_struct_din_ReferenceType_URI,
		  { "URI", "v2gdin.struct.reference.uri",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_struct_din_ReferenceType_Type,
		  { "Type", "v2gdin.struct.reference.type",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_struct_din_ReferenceType_DigestValue,
		  { "DigestValue", "v2gdin.struct.reference.digestvalue",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* struct din_ObjectType */
		{ &hf_v2gdin_struct_din_ObjectType_Id,
		  { "Id", "v2gdin.struct.object.id",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_struct_din_ObjectType_MimeType,
		  { "MimeType", "v2gdin.struct.object.mimetype",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_struct_din_ObjectType_Encoding,
		  { "Encoding", "v2gdin.struct.object.encoding",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_struct_din_ObjectType_ANY,
		  { "ANY", "v2gdin.struct.object.any",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* struct din_ServiceTagType */
		{ &hf_v2gdin_struct_din_ServiceTagType_ServiceID,
		  { "ServiceID",
		    "v2gdin.struct.servicetag.serviceid",
		    FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_struct_din_ServiceTagType_ServiceName,
		  { "ServiceName",
		    "v2gdin.struct.servicetag.servicename",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_struct_din_ServiceTagType_ServiceCategory,
		  { "ServiceCategory",
		    "v2gdin.struct.servicetag.servicecategory",
		    FT_UINT32, BASE_DEC, VALS(v2gdin_service_category_names),
		    0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_struct_din_ServiceTagType_ServiceScope,
		  { "ServiceScope",
		    "v2gdin.struct.servicetag.servicescope",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* struct din_ServiceChargeType */
		{ &hf_v2gdin_struct_din_ServiceChargeType_FreeService,
		  { "FreeService",
		    "v2gdin.struct.servicecharge.freeservice",
		    FT_INT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_struct_din_ServiceChargeType_EnergyTransferType,
		  { "EnergyTransferType",
		    "v2gdin.struct.servicechargee.energytransfertype",
		    FT_UINT32, BASE_DEC,
		    VALS(v2gdin_evse_supported_energy_transfer_names),
		    0x0, NULL, HFILL }
		},

		/* struct din_ServiceType */
		{ &hf_v2gdin_struct_din_ServiceType_FreeService,
		  { "FreeService",
		    "v2gdin.struct.service.freeservice",
		    FT_INT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},

		/* struct din_SelectedServiceType */
		{ &hf_v2gdin_struct_din_SelectedServiceType_ServiceID,
		  { "ServiceID", "v2gdin.struct.selectedservice.serviceid",
		    FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_struct_din_SelectedServiceType_ParameterSetID,
		  { "ParameterSetID",
		    "v2gdin.struct.selectedservicetype.parametersetid",
		    FT_INT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},

		/* struct din_ParameterSetType */
		{ &hf_v2gdin_struct_din_ParameterSetType_ParameterSetID,
		  { "ParameterSetID",
		    "v2gdin.struct.parameterset.parametersetid",
		    FT_INT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},

		/* struct din_PhysicalValueType */
		{ &hf_v2gdin_struct_din_PhysicalValueType_Multiplier,
		  { "Multiplier",
		    "v2gdin.struct.physicalvalue.multiplier",
		    FT_INT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_struct_din_PhysicalValueType_Unit,
		  { "Unit",
		    "v2gdin.struct.physicalvalue.unit",
		    FT_UINT32, BASE_DEC, VALS(v2gdin_unitsymbol_names),
		    0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_struct_din_PhysicalValueType_Value,
		  { "Value",
		    "v2gdin.struct.physicalvalue.value",
		    FT_INT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},

		/* struct din_PaymentOptionsType */
		{ &hf_v2gdin_struct_din_PaymentOptionsType_PaymentOption,
		  { "PaymentOption",
		    "v2gdin.struct.paymentoptions.paymentoption",
		    FT_UINT32, BASE_DEC, VALS(v2gdin_payment_option_names),
		    0x0, NULL, HFILL }
		},

		/* struct din_CertificateChainType */
		{ &hf_v2gdin_struct_din_CertificateChainType_Certificate,
		  { "Certificate",
		    "v2gdin.struct.certificatechain.certificate",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* struct din_SubCertificatesType */
		{ &hf_v2gdin_struct_din_SubCertificatesType_Certificate,
		  { "Certificate",
		    "v2gdin.struct.subcertificates.certificate",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* struct din_ListOfRootCertificateIDsType */
		{ &hf_v2gdin_struct_din_ListOfRootCertificateIDsType_RootCertificateID,
		  { "RootCertificateID",
		    "v2gdin.struct.listofrootcertificateids.rootcertificateid",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* struct din_AC_EVChargeParameterType */
		{ &hf_v2gdin_struct_din_AC_EVChargeParameterType_DepartureTime,
		  { "DepartureTime",
		    "v2gdin.struct.ac_evchargeparameter.departuretime",
		    FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},

		/* struct din_AC_EVSEStatusType */
		{ &hf_v2gdin_struct_din_AC_EVSEStatusType_PowerSwitchClosed,
		  { "PowerSwitchClosed",
		    "v2gdin.struct.ac_evsestatus.powerswitchclosed",
		    FT_INT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_struct_din_AC_EVSEStatusType_RCD,
		  { "RCD", "v2gdin.struct.ac_evsestatus.rcd",
		    FT_INT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_struct_din_AC_EVSEStatusType_NotificationMaxDelay,
		  { "NotificationMaxDelay",
		    "v2gdin.struct.ac_evsestatus.notificationmaxdelay",
		    FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_struct_din_AC_EVSEStatusType_EVSENotification,
		  { "EVSENotification",
		    "v2gdinstruct.ac_evsestatus.evsenotification",
		    FT_UINT32, BASE_DEC, VALS(v2gdin_evsenotification_names),
		    0x0, NULL, HFILL }
		},

		/* struct struct din_DC_EVStatusType */
		{ &hf_v2gdin_struct_din_DC_EVStatusType_EVReady,
		  { "EVReady",
		    "v2gdin.struct.dc_evstatus.evready",
		    FT_INT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_struct_din_DC_EVStatusType_EVCabinConditioning,
		  { "EVCabinConditioning",
		    "v2gdin.struct.dc_evstatus.evcabinconditioning",
		    FT_INT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_struct_din_DC_EVStatusType_EVRESSConditioning,
		  { "EVRESSConditioning",
		    "v2gdin.struct.dc_evstatus.evressconditioning",
		    FT_INT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_struct_din_DC_EVStatusType_EVErrorCode,
		  { "EVErrorCode",
		    "v2gdin.struct.dc_evstatus.everrorcode",
		    FT_UINT32, BASE_DEC, VALS(v2gdin_dc_everrorcode_names),
		    0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_struct_din_DC_EVStatusType_EVRESSSOC,
		  { "EVRESSSOC",
		    "v2gdin.struct.dc_evstatus.evresssoc",
		    FT_INT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},

		/* struct din_DC_EVChargeParameterType */
		{ &hf_v2gdin_struct_din_DC_EVChargeParameterType_FullSOC,
		  { "FullSOC", "v2gdin.struct.dc_evchargeparameter.fullsoc",
		    FT_INT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_struct_din_DC_EVChargeParameterType_BulkSOC,
		  { "BulkSOC", "v2gdin.struct.dc_evchargeparameter.bulksoc",
		    FT_INT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},

		/* struct din_DC_EVSEStatusType */
		{ &hf_v2gdin_struct_din_DC_EVSEStatusType_EVSEIsolationStatus,
		  { "EVSEIsolationStatus",
		    "v2gdinstruct.dc_evsestatus.evseisolationstatus",
		    FT_UINT32, BASE_DEC, VALS(v2gdin_isolation_level_names),
		    0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_struct_din_DC_EVSEStatusType_EVSEStatusCode,
		  { "EVSEStatusCode",
		    "v2gdinstruct.dc_evsestatus.evsestatuscode",
		    FT_UINT32, BASE_DEC, VALS(v2gdin_dc_evsestatuscode_names),
		    0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_struct_din_DC_EVSEStatusType_NotificationMaxDelay,
		  { "NotificationMaxDelay",
		    "v2gdinstruct.dc_evsestatus.notificationmaxdelay",
		    FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_struct_din_DC_EVSEStatusType_EVSENotification,
		  { "EVSENotification",
		    "v2gdinstruct.dc_evsestatus.evsenotification",
		    FT_UINT32, BASE_DEC, VALS(v2gdin_evsenotification_names),
		    0x0, NULL, HFILL }
		},

		/* struct din_SAScheduleTupleType */
		{ &hf_v2gdin_struct_din_SAScheduleTupleType_SAScheduleTupleID,
		  { "SAScheduleTupleID",
		    "v2gdin.struct.sascheduletuple.sascheduletupleid",
		    FT_INT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},

		/* struct din_PMaxScheduleType */
		{ &hf_v2gdin_struct_din_PMaxScheduleType_PMaxScheduleID,
		  { "PMaxScheduleID",
		    "v2gdin.struct.pmaxschedule.pmaxscheduleid",
		    FT_INT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},

		/* struct din_PMaxScheduleEntryType */
		{ &hf_v2gdin_struct_din_PMaxScheduleEntryType_PMax,
		  { "PMax", "v2gdin.struct.pmaxscheduleentry.pmax",
		    FT_INT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},

		/* struct din_RelativeTimeIntervalType */
		{ &hf_v2gdin_struct_din_RelativeTimeIntervalType_start,
		  { "start", "v2gdin.struct.relativetimeinterval.start",
		    FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_struct_din_RelativeTimeIntervalType_duration,
		  { "duration", "v2gdin.struct.relativetimeinterval.duration",
		    FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},

		/* struct din_SalesTariffType */
		{ &hf_v2gdin_struct_din_SalesTariffType_Id,
		  { "Id", "v2gdin.struct.salestariff.id",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_struct_din_SalesTariffType_SalesTariffDescription,
		  { "SalesTariffDescription",
		    "v2gdin.struct.salestariff.salestariffdescription",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_struct_din_SalesTariffType_NumEPriceLevels,
		  { "NumEPriceLevels",
		    "v2gdin.struct.salestariff.numepricelevels",
		    FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},

		/* struct hf_v2gdin_struct_din_SalesTariffEntryType */
		{ &hf_v2gdin_struct_din_SalesTariffEntryType_EPriceLevel,
		  { "EPriceLevel", "v2gdin.struct.salestariffentry.epricelevel",
		    FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},

		/* struct din_ConsumptionCostType */
		{ &hf_v2gdin_struct_din_ConsumptionCostType_startValue,
		  { "startValue", "v2gdin.struct.consumptioncost.startvalue",
		    FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},

		/* struct din_CostType */
		{ &hf_v2gdin_struct_din_CostType_costKind,
		  { "costKind", "v2gdin.struct.cost.costkind",
		    FT_UINT32, BASE_DEC, VALS(v2gdin_cost_kind_names),
		    0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_struct_din_CostType_amount,
		  { "amount", "v2gdin.struct.cost.amount",
		    FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_struct_din_CostType_amountMultiplier,
		  { "amountMultiplier", "v2gdin.struct.cost.amountmultiplier",
		    FT_INT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},

		/* struct din_ChargingProfileType */
		{ &hf_v2gdin_struct_din_ChargingProfileType_SAScheduleTupleID,
		  { "SAScheduleTupleID",
		    "v2gdin.struct.chargingprofile.sascheduletupleid",
		    FT_INT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_struct_din_ProfileEntryType_ChargingProfileEntryStart,
		  { "ChargingProfileEntryStart",
		    "v2gdin.struct.profileentry.chargingprofileentrystart",
		    FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_struct_din_ProfileEntryType_ChargingProfileEntryMaxPower,
		  { "ChargingProfileEntryMaxPower",
		    "v2gdin.struct.profileentry.chargingprofileentrymaxpower",
		    FT_INT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},

		/* struct din_DC_EVPowerDeliveryParameterType */
		{ &hf_v2gdin_struct_din_DC_EVPowerDeliveryParameterType_BulkChargingComplete,
		  { "BulkChargingComplete",
		    "v2gdin.struct.dc_evpowerdeliveryparameter.bulkchargingcomplete",
		    FT_INT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_struct_din_DC_EVPowerDeliveryParameterType_ChargingComplete,
		  { "ChargingComplete",
		    "v2gdin.struct.dc_evpowerdeliveryparameter.chargingcomplete",
		    FT_INT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},

		/* struct din_MeterInfoType */
		{ &hf_v2gdin_struct_din_MeterInfoType_MeterID,
		  { "MeterID", "v2gdin.struct.meterinfo.meterid",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_struct_din_MeterInfoType_SigMeterReading,
		  { "SigMeterReading",
		    "v2gdin.struct.meterinfo.sigmeterreading",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_struct_din_MeterInfoType_MeterStatus,
		  { "MeterStatus", "v2gdin.struct.meterinfo.meterstatus",
		    FT_INT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_struct_din_MeterInfoType_TMeter,
		  { "TMeter", "v2gdin.struct.meterinfo.tmeter",
		    FT_INT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},

		/* struct din_MessageHeaderType */
		{ &hf_v2gdin_struct_din_MessageHeaderType_SessionID,
		  { "SessionID", "v2gdin.struct.messageheader.sessionid",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* SessionSetupReq */
		{ &hf_v2gdin_struct_din_SessionSetupReqType_EVCCID,
		  { "EVCCID", "v2gdin.body.sessionsetupreq.evccid",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		/* SessionSetupRes */
		{ &hf_v2gdin_struct_din_SessionSetupResType_ResponseCode,
		  { "ResponseCode", "v2gdin.body.sessionsetupres.responsecode",
		    FT_UINT32, BASE_DEC, VALS(v2gdin_response_code_names),
		    0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_struct_din_SessionSetupResType_EVSEID,
		  { "EVSEID", "v2gdin.body.sessionsetupres.evseid",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_struct_din_SessionSetupResType_DateTimeNow,
		  { "DateTimeNow", "v2gdin.body.sessionsetupres.datetimenow",
		    FT_INT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},

		/* ServiceDiscoveryReq */
		{ &hf_v2gdin_struct_din_ServiceDiscoveryReqType_ServiceScope,
		  { "ServiceScope", "v2gdin.body.servicediscoveryreq.servicescope",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_struct_din_ServiceDiscoveryReqType_ServiceCategory,
		  { "ServiceCategory", "v2gdin.body.servicediscoveryreq.servicecategory",
		    FT_UINT32, BASE_DEC, VALS(v2gdin_service_category_names),
		    0x0, NULL, HFILL }
		},
		/* ServiceDiscoveryRes */
		{ &hf_v2gdin_struct_din_ServiceDiscoveryResType_ResponseCode,
		  { "ResponseCode", "v2gdin.body.servicediscoveryres.responsecode",
		    FT_UINT32, BASE_DEC, VALS(v2gdin_response_code_names),
		    0x0, NULL, HFILL }
		},

		/* ServiceDetailReq */
		{ &hf_v2gdin_struct_din_ServiceDetailReqType_ServiceID,
		  { "ServiceID",
		    "v2gdin.body.servicedetailreq.serviceid",
		    FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }
		},
		/* ServiceDiscoveryRes */
		{ &hf_v2gdin_struct_din_ServiceDetailResType_ResponseCode,
		  { "ResponseCode", "v2gdin.body.servicedetailres.responsecode",
		    FT_UINT32, BASE_DEC, VALS(v2gdin_response_code_names),
		    0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_struct_din_ServiceDetailResType_ServiceID,
		  { "ServiceID",
		    "v2gdin.body.servicedetailres.serviceid",
		    FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }
		},

		/* ServicePaymentSelectionReq */
		{ &hf_v2gdin_struct_din_ServicePaymentSelectionReqType_SelectedPaymentOption,
		  { "SelectedPaymentOption",
		    "v2gdin.body.servicepaymentselectionreq.selectedpaymentoption",
		    FT_UINT32, BASE_DEC, VALS(v2gdin_payment_option_names),
		    0x0, NULL, HFILL }
		},
		/* ServicePaymentSelectionRes */
		{ &hf_v2gdin_struct_din_ServicePaymentSelectionResType_ResponseCode,
		  { "ResponseCode",
		    "v2gdin.body.servicepaymentselectionres.responsecode",
		    FT_UINT32, BASE_DEC, VALS(v2gdin_response_code_names),
		    0x0, NULL, HFILL }
		},

		/* PaymentDetailsReq */
		{ &hf_v2gdin_struct_din_PaymentDetailsReqType_ContractID,
		  { "ContractID", "v2gdin.body.paymentdetailsreq.contractid",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		/* PaymentDetailsRes */
		{ &hf_v2gdin_struct_din_PaymentDetailsResType_ResponseCode,
		  { "ResponseCode",
		    "v2gdin.body.paymentdetailsres.responsecode",
		    FT_UINT32, BASE_DEC, VALS(v2gdin_response_code_names),
		    0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_struct_din_PaymentDetailsResType_GenChallenge,
		  { "GenChallenge",
		    "v2gdin.body.paymentdetailsres.genchallenge",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_struct_din_PaymentDetailsResType_DateTimeNow,
		  { "DateTimeNow", "v2gdin.body.paymentdetailsress.datetimenow",
		    FT_INT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},

		/* ContractAuthenticationReq */
		{ &hf_v2gdin_struct_din_ContractAuthenticationReqType_Id,
		  { "Id", "v2gdin.body.paymentdetailsreq.id",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_struct_din_ContractAuthenticationReqType_GenChallenge,
		  { "GenChallenge",
		    "v2gdin.body.paymentdetailsreq.genchallenge",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		/* ContractAuthenticationRes */
		{ &hf_v2gdin_struct_din_ContractAuthenticationResType_ResponseCode,
		  { "ResponseCode",
		    "v2gdin.body.contractauthenticationres.responsecode",
		    FT_UINT32, BASE_DEC, VALS(v2gdin_response_code_names),
		    0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_struct_din_ContractAuthenticationResType_EVSEProcessing,
		  { "EVSEProcessing",
		    "v2gdin.body.contractauthenticationres.evseprocessing",
		    FT_UINT32, BASE_DEC, VALS(v2gdin_evse_processing_names),
		    0x0, NULL, HFILL }
		},

		/* ChargeParameterDiscoveryReq */
		{ &hf_v2gdin_struct_din_ChargeParameterDiscoveryReqType_EVRequestedEnergyTransferType,
		  { "EVRequestedEnergyTransferType",
		    "v2gdin.body.chargeparameterdiscoveryreq.evrequestenergytransfer",
		    FT_UINT32, BASE_DEC,
		    VALS(v2gdin_ev_requested_energy_transfer),
		    0x0, NULL, HFILL }
		},
		/* ChargeParameterDiscoveryRes */
		{ &hf_v2gdin_struct_din_ChargeParameterDiscoveryResType_ResponseCode,
		  { "ResponseCode",
		    "v2gdin.body.chargeparametersdiscoveryres.responsecode",
		    FT_UINT32, BASE_DEC, VALS(v2gdin_response_code_names),
		    0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_struct_din_ChargeParameterDiscoveryResType_EVSEProcessing,
		  { "EVSEProcessing",
		    "v2gdin.body.chargeparametersdiscoveryres.evseprocessing",
		    FT_UINT32, BASE_DEC, VALS(v2gdin_evse_processing_names),
		    0x0, NULL, HFILL }
		},

		/* PowerDeliveryReq */
		{ &hf_v2gdin_struct_din_PowerDeliveryReqType_ReadyToChargeState,
		  { "_ReadyToChargeState",
		    "v2gdin.body.powerdeliveryreq.readytochargestate",
		    FT_INT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		/* PowerDeliveryRes */
		{ &hf_v2gdin_struct_din_PowerDeliveryResType_ResponseCode,
		  { "ResponseCode",
		    "v2gdin.body.powerdeliveryres.responsecode",
		    FT_UINT32, BASE_DEC, VALS(v2gdin_response_code_names),
		    0x0, NULL, HFILL }
		},

		/* ChargingStatusRes */
		{ &hf_v2gdin_struct_din_ChargingStatusResType_ResponseCode,
		  { "ResponseCode",
		    "v2gdin.body.chargingstatusres.responsecode",
		    FT_UINT32, BASE_DEC, VALS(v2gdin_response_code_names),
		    0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_struct_din_ChargingStatusResType_EVSEID,
		  { "EVSEID", "v2gdin.body.chargingstatusres.evseid",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_struct_din_ChargingStatusResType_SAScheduleTupleID,
		  { "SAScheduleTupleID",
		    "v2gdin.body.chargingstatusres.sascheduletupleid",
		    FT_INT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_struct_din_ChargingStatusResType_ReceiptRequired,
		  { "ReceiptRequired",
		    "v2gdin.body.chargingstatusres.receiptrequired",
		    FT_INT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},

		/* MeteringReceiptReq */
		{ &hf_v2gdin_struct_din_MeteringReceiptReqType_Id,
		  { "Id", "v2gdin.body.meteringreceiptreq.id",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_struct_din_MeteringReceiptReqType_SessionID,
		  { "SessionID", "v2gdin.body.meteringreceiptreq.sessionid",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_struct_din_MeteringReceiptReqType_SAScheduleTupleID,
		  { "SAScheduleTupleID",
		    "v2gdin.body.meteringreceiptreq.sascheduletupleid",
		    FT_INT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		/* MeteringReceiptRes */
		{ &hf_v2gdin_struct_din_MeteringReceiptResType_ResponseCode,
		  { "ResponseCode",
		    "v2gdin.body.meteringreceiptres.responsecode",
		    FT_UINT32, BASE_DEC, VALS(v2gdin_response_code_names),
		    0x0, NULL, HFILL }
		},

		/* SessionStopRes */
		{ &hf_v2gdin_struct_din_SessionStopResType_ResponseCode,
		  { "ResponseCode",
		    "v2gdin.body.sessionstopres.responsecode",
		    FT_UINT32, BASE_DEC, VALS(v2gdin_response_code_names),
		    0x0, NULL, HFILL }
		},

		/* CertificateUpdateReq */
		{ &hf_v2gdin_struct_din_CertificateUpdateReqType_Id,
		  { "Id", "v2gdin.body.certificateupdatereq.id",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_struct_din_CertificateUpdateReqType_ContractID,
		  { "ContractID",
		    "v2gdin.body.certificateupdatereq.contractid",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_struct_din_CertificateUpdateReqType_DHParams,
		  { "DHParams", "v2gdin.body.certificateupdatereq.dhparams",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		/* CertificateUpdateRes */
		{ &hf_v2gdin_struct_din_CertificateUpdateResType_Id,
		  { "Id", "v2gdin.body.certificateupdateres.id",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_struct_din_CertificateUpdateResType_ResponseCode,
		  { "ResponseCode",
		    "v2gdin.body.certificateupdateres.responsecode",
		    FT_UINT32, BASE_DEC, VALS(v2gdin_response_code_names),
		    0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_struct_din_CertificateUpdateResType_ContractSignatureEncryptedPrivateKey,
		  { "ContractSignatureEncryptedPrivateKey",
		    "v2gdin.body.certificateupdateres.contractsignatureencryptedprivatekey",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_struct_din_CertificateUpdateResType_DHParams,
		  { "DHParams",
		    "v2gdin.body.certificateupdateres.dhparams",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_struct_din_CertificateUpdateResType_ContractID,
		  { "ContractID", "v2gdin.body.certificateupdateres.contractid",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_struct_din_CertificateUpdateResType_RetryCounter,
		  { "RetryCounter",
		    "v2gdin.body.certificateupdateres.retrycounts",
		    FT_INT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},

		/* CertificateInstallationReq */
		{ &hf_v2gdin_struct_din_CertificateInstallationReqType_Id,
		  { "Id", "v2gdin.body.certificateinstallationreq.id",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_struct_din_CertificateInstallationReqType_OEMProvisioningCert,
		  { "OEMProvisioningCert",
		    "v2gdin.body.certificateinstallationreq.oemprovisioningcert",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_struct_din_CertificateInstallationReqType_DHParams,
		  { "DHParams", "v2gdin.body.certificateinstallationreq.dhparams",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		/* CertificateInstallationRes */
		{ &hf_v2gdin_struct_din_CertificateInstallationResType_Id,
		  { "Id", "v2gdin.body.certificateinstallationres.id",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_struct_din_CertificateInstallationResType_ResponseCode,
		  { "ResponseCode",
		    "v2gdin.body.certificateinstallationres.responsecode",
		    FT_UINT32, BASE_DEC, VALS(v2gdin_response_code_names),
		    0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_struct_din_CertificateInstallationResType_ContractSignatureEncryptedPrivateKey,
		  { "ContractSignatureEncryptedPrivateKey",
		    "v2gdin.body.certificateinstallationres.contractsignatureencryptedprivatekey",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_struct_din_CertificateInstallationResType_DHParams,
		  { "DHParams",
		    "v2gdin.body.certificateinstallationres.dhparams",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_struct_din_CertificateInstallationResType_ContractID,
		  { "ContractID",
		    "v2gdin.body.certificateinstallationres.contractid",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* CableCheckRes */
		{ &hf_v2gdin_struct_din_CableCheckResType_ResponseCode,
		  { "ResponseCode",
		    "v2gdin.body.cablecheckres.responsecode",
		    FT_UINT32, BASE_DEC, VALS(v2gdin_response_code_names),
		    0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_struct_din_CableCheckResType_EVSEProcessing,
		  { "EVSEProcessing",
		    "v2gdin.body.cablecheckres.evseprocessing",
		    FT_UINT32, BASE_DEC, VALS(v2gdin_evse_processing_names),
		    0x0, NULL, HFILL }
		},

		/* PreChargeRes */
		{ &hf_v2gdin_struct_din_PreChargeResType_ResponseCode,
		  { "ResponseCode",
		    "v2gdin.body.prechargeres.responsecode",
		    FT_UINT32, BASE_DEC, VALS(v2gdin_response_code_names),
		    0x0, NULL, HFILL }
		},

		/* CurrentDemandReq */
		{ &hf_v2gdin_struct_din_CurrentDemandReqType_ChargingComplete,
		  { "ChargingComplete",
		    "v2gdin.body.currentdemandreq.chargingcomplete",
		    FT_INT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_struct_din_CurrentDemandReqType_BulkChargingComplete,
		  { "BulkChargingComplete",
		    "v2gdin.body.currentdemandreq.bulkchargingcomplete",
		    FT_INT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		/* CurrentDemandRes */
		{ &hf_v2gdin_struct_din_CurrentDemandResType_ResponseCode,
		  { "ResponseCode", "v2gdin.body.currentdemandres.responsecode",
		    FT_UINT32, BASE_DEC, VALS(v2gdin_response_code_names),
		    0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_struct_din_CurrentDemandResType_EVSECurrentLimitAchieved,
		  { "EVSECurrentLimitAchieved",
		    "v2gdin.body.currentdemandres.evsecurrentlimitachieved",
		    FT_INT32, BASE_DEC, 0,
		    0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_struct_din_CurrentDemandResType_EVSEVoltageLimitAchieved,
		  { "EVSEVoltageLimitAchieved",
		    "v2gdin.body.currentdemandres.evsevoltagelimitachieved",
		    FT_INT32, BASE_DEC, 0,
		    0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_struct_din_CurrentDemandResType_EVSEPowerLimitAchieved,
		  { "EVSEPowerLimitAchieved",
		    "v2gdin.body.currentdemandres.evsepowerlimitachieved",
		    FT_INT32, BASE_DEC, 0,
		    0x0, NULL, HFILL }
		},

		/* WeldingDetectionRes */
		{ &hf_v2gdin_struct_din_WeldingDetectionResType_ResponseCode,
		  { "ResponseCode",
		    "v2gdin.body.weldingdetectionres.responsecode",
		    FT_UINT32, BASE_DEC, VALS(v2gdin_response_code_names),
		    0x0, NULL, HFILL }
		},

		/* Derived values for graphing */
		{ &hf_v2gdin_ev_target_voltage,
		  { "EV Target Voltage (derived)", "v2gdin.ev.target.voltage",
		    FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_ev_target_current,
		  { "EV Target Current (derived)", "v2gdin.ev.target.current",
		    FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_ev_maximum_voltage_limit,
		  { "EV Maximum Voltage Limit (derived)",
		    "v2gdin.ev.maximum.voltage.limit",
		    FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_ev_maximum_current_limit,
		  { "EV Maximum Current Limit (derived)",
		    "v2gdin.ev.maximum.current.limit",
		    FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_ev_maximum_power_limit,
		  { "EV Maximum Power Limit (derived)",
		    "v2gdin.ev.maximum.power.limit",
		    FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_remaining_time_to_full_soc,
		  { "Remaining Time to Full SOC (derived)",
		    "v2gdin.remaining.time.to.full.soc",
		    FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_remaining_time_to_bulk_soc,
		  { "Remaining Time to Bulk SOC (derived)",
		    "v2gdin.remaining.time.to.bulk.soc",
		    FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_evse_present_voltage,
		  { "EVSE Present Voltage (derived)",
		    "v2gdin.evse.present.voltage",
		    FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_evse_present_current,
		  { "EVSE Present Current (derived)",
		    "v2gdin.evse.present.current",
		    FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_evse_maximum_voltage_limit,
		  { "EVSE Maximum Voltage Limit (derived)",
		    "v2gdin.evse.maximum.voltage.limit",
		    FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_evse_maximum_current_limit,
		  { "EVSE Maximum Current Limit (derived)",
		    "v2gdin.evse.maximum.current.limit",
		    FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2gdin_evse_maximum_power_limit,
		  { "EVSE Maximum Power Limit (derived)",
		    "v2gdin.evse.maximum.power.limit",
		    FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL }
		}
	};

	static gint *ett[] = {
		&ett_v2gdin,
		&ett_v2gdin_header,
		&ett_v2gdin_body,
		&ett_v2gdin_array,
		&ett_v2gdin_array_i,

		&ett_v2gdin_struct_din_NotificationType,
		&ett_v2gdin_struct_din_SignatureType,
		&ett_v2gdin_struct_din_SignedInfoType,
		&ett_v2gdin_struct_din_CanonicalizationMethodType,
		&ett_v2gdin_struct_din_SignatureMethodType,
		&ett_v2gdin_struct_din_ReferenceType,
		&ett_v2gdin_struct_din_TransformsType,
		&ett_v2gdin_struct_din_TransformType,
		&ett_v2gdin_struct_din_DigestMethodType,
		&ett_v2gdin_struct_din_SignatureValueType,
		&ett_v2gdin_struct_din_KeyInfoType,
		&ett_v2gdin_struct_din_KeyValueType,
		&ett_v2gdin_struct_din_DSAKeyValueType,
		&ett_v2gdin_struct_din_RSAKeyValueType,
		&ett_v2gdin_struct_din_RetrievalMethodType,
		&ett_v2gdin_struct_din_X509IssuerSerialType,
		&ett_v2gdin_struct_din_X509DataType,
		&ett_v2gdin_struct_din_PGPDataType,
		&ett_v2gdin_struct_din_SPKIDataType,
		&ett_v2gdin_struct_din_ObjectType,
		&ett_v2gdin_struct_din_ServiceParameterListType,
		&ett_v2gdin_struct_din_ServiceTagListType,
		&ett_v2gdin_struct_din_ServiceTagType,
		&ett_v2gdin_struct_din_ServiceChargeType,
		&ett_v2gdin_struct_din_ServiceType,
		&ett_v2gdin_struct_din_SelectedServiceType,
		&ett_v2gdin_struct_din_SelectedServiceListType,
		&ett_v2gdin_struct_din_ParameterSetType,
		&ett_v2gdin_struct_din_ParameterType,
		&ett_v2gdin_struct_din_PhysicalValueType,
		&ett_v2gdin_struct_din_PaymentOptionsType,
		&ett_v2gdin_struct_din_CertificateChainType,
		&ett_v2gdin_struct_din_SubCertificatesType,
		&ett_v2gdin_struct_din_EVChargeParameterType,
		&ett_v2gdin_struct_din_AC_EVChargeParameterType,
		&ett_v2gdin_struct_din_DC_EVChargeParameterType,
		&ett_v2gdin_struct_din_DC_EVStatusType,
		&ett_v2gdin_struct_din_EVSEChargeParameterType,
		&ett_v2gdin_struct_din_EVSEStatusType,
		&ett_v2gdin_struct_din_AC_EVSEChargeParameterType,
		&ett_v2gdin_struct_din_AC_EVSEStatusType,
		&ett_v2gdin_struct_din_DC_EVSEChargeParameterType,
		&ett_v2gdin_struct_din_DC_EVSEStatusType,
		&ett_v2gdin_struct_din_SASchedulesType,
		&ett_v2gdin_struct_din_SAScheduleListType,
		&ett_v2gdin_struct_din_SAScheduleTupleType,
		&ett_v2gdin_struct_din_PMaxScheduleType,
		&ett_v2gdin_struct_din_PMaxScheduleEntryType,
		&ett_v2gdin_struct_din_RelativeTimeIntervalType,
		&ett_v2gdin_struct_din_IntervalType,
		&ett_v2gdin_struct_din_SalesTariffType,
		&ett_v2gdin_struct_din_SalesTariffEntryType,
		&ett_v2gdin_struct_din_ConsumptionCostType,
		&ett_v2gdin_struct_din_CostType,
		&ett_v2gdin_struct_din_ChargingProfileType,
		&ett_v2gdin_struct_din_EVPowerDeliveryParameterType,
		&ett_v2gdin_struct_din_DC_EVPowerDeliveryParameterType,
		&ett_v2gdin_struct_din_ProfileEntryType,

		&ett_v2gdin_struct_din_SessionSetupReqType,
		&ett_v2gdin_struct_din_SessionSetupResType,
		&ett_v2gdin_struct_din_ServiceDiscoveryReqType,
		&ett_v2gdin_struct_din_ServiceDiscoveryResType,
		&ett_v2gdin_struct_din_ServiceDetailReqType,
		&ett_v2gdin_struct_din_ServiceDetailResType,
		&ett_v2gdin_struct_din_ServicePaymentSelectionReqType,
		&ett_v2gdin_struct_din_ServicePaymentSelectionResType,
		&ett_v2gdin_struct_din_PaymentDetailsReqType,
		&ett_v2gdin_struct_din_PaymentDetailsResType,
		&ett_v2gdin_struct_din_ContractAuthenticationReqType,
		&ett_v2gdin_struct_din_ContractAuthenticationResType,
		&ett_v2gdin_struct_din_ChargeParameterDiscoveryReqType,
		&ett_v2gdin_struct_din_ChargeParameterDiscoveryResType,
		&ett_v2gdin_struct_din_PowerDeliveryReqType,
		&ett_v2gdin_struct_din_PowerDeliveryResType,
		&ett_v2gdin_struct_din_ChargingStatusReqType,
		&ett_v2gdin_struct_din_ChargingStatusResType,
		&ett_v2gdin_struct_din_MeteringReceiptReqType,
		&ett_v2gdin_struct_din_MeteringReceiptResType,
		&ett_v2gdin_struct_din_SessionStopType,
		&ett_v2gdin_struct_din_SessionStopResType,
		&ett_v2gdin_struct_din_CertificateUpdateReqType,
		&ett_v2gdin_struct_din_CertificateUpdateResType,
		&ett_v2gdin_struct_din_CertificateInstallationReqType,
		&ett_v2gdin_struct_din_CertificateInstallationResType,
		&ett_v2gdin_struct_din_CableCheckReqType,
		&ett_v2gdin_struct_din_CableCheckResType,
		&ett_v2gdin_struct_din_PreChargeReqType,
		&ett_v2gdin_struct_din_PreChargeResType,
		&ett_v2gdin_struct_din_CurrentDemandReqType,
		&ett_v2gdin_struct_din_CurrentDemandResType,
		&ett_v2gdin_struct_din_WeldingDetectionReqType,
		&ett_v2gdin_struct_din_WeldingDetectionResType
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
