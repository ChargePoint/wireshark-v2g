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
#include <cbv2g/iso_2/iso2_msgDefDatatypes.h>
#include <cbv2g/iso_2/iso2_msgDefDecoder.h>

#include "v2gexi.h"


/* forward declare */
void proto_register_v2giso2(void);
void proto_reg_handoff_v2giso2(void);


static dissector_handle_t v2gexi_handle;
static dissector_handle_t v2gber_handle;

static int proto_v2giso2 = -1;

static int hf_v2giso2_struct_iso2_MessageHeaderType_SessionID = -1;

static int hf_v2giso2_struct_iso2_NotificationType_FaultCode = -1;
static int hf_v2giso2_struct_iso2_NotificationType_FaultMsg = -1;
static int hf_v2giso2_struct_iso2_SignatureType_Id = -1;
static int hf_v2giso2_struct_iso2_SignedInfoType_Id = -1;
static int hf_v2giso2_struct_iso2_CanonicalizationMethodType_Algorithm = -1;
static int hf_v2giso2_struct_iso2_CanonicalizationMethodType_ANY = -1;
static int hf_v2giso2_struct_iso2_SignatureMethodType_Algorithm = -1;
static int hf_v2giso2_struct_iso2_SignatureMethodType_HMACOutputLength = -1;
static int hf_v2giso2_struct_iso2_SignatureMethodType_ANY = -1;
static int hf_v2giso2_struct_iso2_ReferenceType_Id = -1;
static int hf_v2giso2_struct_iso2_ReferenceType_URI = -1;
static int hf_v2giso2_struct_iso2_ReferenceType_Type = -1;
static int hf_v2giso2_struct_iso2_ReferenceType_DigestValue = -1;
static int hf_v2giso2_struct_iso2_SignatureValueType_Id = -1;
static int hf_v2giso2_struct_iso2_SignatureValueType_CONTENT = -1;
static int hf_v2giso2_struct_iso2_ObjectType_Id = -1;
static int hf_v2giso2_struct_iso2_ObjectType_MimeType = -1;
static int hf_v2giso2_struct_iso2_ObjectType_Encoding = -1;
static int hf_v2giso2_struct_iso2_ObjectType_ANY = -1;
static int hf_v2giso2_struct_iso2_TransformType_Algorithm = -1;
static int hf_v2giso2_struct_iso2_TransformType_ANY = -1;
static int hf_v2giso2_struct_iso2_TransformType_XPath = -1;
static int hf_v2giso2_struct_iso2_DigestMethodType_Algorithm = -1;
static int hf_v2giso2_struct_iso2_DigestMethodType_ANY = -1;
static int hf_v2giso2_struct_iso2_KeyInfoType_Id = -1;
static int hf_v2giso2_struct_iso2_KeyInfoType_KeyName = -1;
static int hf_v2giso2_struct_iso2_KeyInfoType_MgmtData = -1;
static int hf_v2giso2_struct_iso2_KeyInfoType_ANY = -1;
static int hf_v2giso2_struct_iso2_RetrievalMethodType_URI = -1;
static int hf_v2giso2_struct_iso2_RetrievalMethodType_Type = -1;
static int hf_v2giso2_struct_iso2_KeyValueType_ANY = -1;
static int hf_v2giso2_struct_iso2_DSAKeyValueType_P = -1;
static int hf_v2giso2_struct_iso2_DSAKeyValueType_Q = -1;
static int hf_v2giso2_struct_iso2_DSAKeyValueType_G = -1;
static int hf_v2giso2_struct_iso2_DSAKeyValueType_Y = -1;
static int hf_v2giso2_struct_iso2_DSAKeyValueType_J = -1;
static int hf_v2giso2_struct_iso2_DSAKeyValueType_Seed = -1;
static int hf_v2giso2_struct_iso2_DSAKeyValueType_PgenCounter = -1;
static int hf_v2giso2_struct_iso2_RSAKeyValueType_Exponent = -1;
static int hf_v2giso2_struct_iso2_RSAKeyValueType_Modulus = -1;
static int hf_v2giso2_struct_iso2_X509DataType_X509SKI = -1;
static int hf_v2giso2_struct_iso2_X509DataType_X509SubjectName = -1;
static int hf_v2giso2_struct_iso2_X509DataType_X509Certificate = -1;
static int hf_v2giso2_struct_iso2_X509DataType_X509CRL = -1;
static int hf_v2giso2_struct_iso2_X509DataType_ANY = -1;
static int hf_v2giso2_struct_iso2_X509IssuerSerialType_X509IssuerName = -1;
static int hf_v2giso2_struct_iso2_X509IssuerSerialType_X509SerialNumber = -1;
static int hf_v2giso2_struct_iso2_PGPDataType_PGPKeyID = -1;
static int hf_v2giso2_struct_iso2_PGPDataType_PGPKeyPacket = -1;
static int hf_v2giso2_struct_iso2_PGPDataType_ANY = -1;
static int hf_v2giso2_struct_iso2_SPKIDataType_SPKISexp = -1;
static int hf_v2giso2_struct_iso2_SPKIDataType_ANY = -1;

static int hf_v2giso2_struct_iso2_ChargeServiceType_ServiceID = -1;
static int hf_v2giso2_struct_iso2_ChargeServiceType_ServiceName = -1;
static int hf_v2giso2_struct_iso2_ChargeServiceType_ServiceCategory = -1;
static int hf_v2giso2_struct_iso2_ChargeServiceType_ServiceScope = -1;
static int hf_v2giso2_struct_iso2_ChargeServiceType_FreeService = -1;

static int hf_v2giso2_struct_iso2_PaymentOptionLstType_PaymentOption = -1;

static int hf_v2giso2_struct_iso2_SupportedEnergyTransferModeType_EnergyTransferMode = -1;

static int hf_v2giso2_struct_iso2_ServiceType_ServiceID = -1;
static int hf_v2giso2_struct_iso2_ServiceType_ServiceName = -1;
static int hf_v2giso2_struct_iso2_ServiceType_ServiceCategory = -1;
static int hf_v2giso2_struct_iso2_ServiceType_ServiceScope = -1;
static int hf_v2giso2_struct_iso2_ServiceType_FreeService = -1;

static int hf_v2giso2_struct_iso2_ParameterSetType_ParameterSetID = -1;

static int hf_v2giso2_struct_iso2_ParameterType_Name = -1;
static int hf_v2giso2_struct_iso2_ParameterType_boolValue = -1;
static int hf_v2giso2_struct_iso2_ParameterType_byteValue = -1;
static int hf_v2giso2_struct_iso2_ParameterType_shortValue = -1;
static int hf_v2giso2_struct_iso2_ParameterType_intValue = -1;
static int hf_v2giso2_struct_iso2_ParameterType_stringValue = -1;

static int hf_v2giso2_struct_iso2_PhysicalValueType_Multiplier = -1;
static int hf_v2giso2_struct_iso2_PhysicalValueType_Unit = -1;
static int hf_v2giso2_struct_iso2_PhysicalValueType_Value = -1;

static int hf_v2giso2_struct_iso2_SelectedServiceType_ServiceID = -1;
static int hf_v2giso2_struct_iso2_SelectedServiceType_ParameterSetID = -1;

static int hf_v2giso2_struct_iso2_CertificateChainType_Id = -1;
static int hf_v2giso2_struct_iso2_CertificateChainType_Certificate = -1;

static int hf_v2giso2_struct_iso2_SubCertificatesType_Certificate = -1;

static int hf_v2giso2_struct_iso2_AC_EVChargeParameterType_DepartureTime = -1;

static int hf_v2giso2_struct_iso2_DC_EVChargeParameterType_DepartureTime = -1;
static int hf_v2giso2_struct_iso2_DC_EVChargeParameterType_FullSOC = -1;
static int hf_v2giso2_struct_iso2_DC_EVChargeParameterType_BulkSOC = -1;

static int hf_v2giso2_struct_iso2_DC_EVStatusType_EVReady = -1;
static int hf_v2giso2_struct_iso2_DC_EVStatusType_EVErrorCode = -1;
static int hf_v2giso2_struct_iso2_DC_EVStatusType_EVRESSSOC = -1;

static int hf_v2giso2_struct_iso2_EVSEStatusType_NotificationMaxDelay = -1;
static int hf_v2giso2_struct_iso2_EVSEStatusType_EVSENotification = -1;

static int hf_v2giso2_struct_iso2_AC_EVSEStatusType_NotificationMaxDelay = -1;
static int hf_v2giso2_struct_iso2_AC_EVSEStatusType_EVSENotification = -1;
static int hf_v2giso2_struct_iso2_AC_EVSEStatusType_RCD = -1;

static int hf_v2giso2_struct_iso2_DC_EVSEStatusType_NotificationMaxDelay = -1;
static int hf_v2giso2_struct_iso2_DC_EVSEStatusType_EVSENotification = -1;
static int hf_v2giso2_struct_iso2_DC_EVSEStatusType_EVSEIsolationStatus = -1;
static int hf_v2giso2_struct_iso2_DC_EVSEStatusType_EVSEStatusCode = -1;

static int hf_v2giso2_struct_iso2_SAScheduleTupleType_SAScheduleTupleID = -1;

static int hf_v2giso2_struct_iso2_SalesTariffType_Id = -1;
static int hf_v2giso2_struct_iso2_SalesTariffType_SalesTariffDescription = -1;
static int hf_v2giso2_struct_iso2_SalesTariffType_NumEPriceLevels = -1;
static int hf_v2giso2_struct_iso2_SalesTariffEntryType_EPriceLevel = -1;

static int hf_v2giso2_struct_iso2_RelativeTimeIntervalType_start = -1;
static int hf_v2giso2_struct_iso2_RelativeTimeIntervalType_duration = -1;

static int hf_v2giso2_struct_iso2_CostType_costKind = -1;
static int hf_v2giso2_struct_iso2_CostType_amount = -1;
static int hf_v2giso2_struct_iso2_CostType_amountMultiplier = -1;

static int hf_v2giso2_struct_iso2_ProfileEntryType_ChargingProfileEntryStart = -1;
static int hf_v2giso2_struct_iso2_ProfileEntryType_ChargingProfileEntryMaxNumberOfPhasesInUse = -1;

static int hf_v2giso2_struct_iso2_DC_EVPowerDeliveryParameterType_BulkChargingComplete = -1;
static int hf_v2giso2_struct_iso2_DC_EVPowerDeliveryParameterType_ChargingComplete = -1;

static int hf_v2giso2_struct_iso2_MeterInfoType_MeterID = -1;
static int hf_v2giso2_struct_iso2_MeterInfoType_MeterReading = -1;
static int hf_v2giso2_struct_iso2_MeterInfoType_SigMeterReading = -1;
static int hf_v2giso2_struct_iso2_MeterInfoType_MeterStatus = -1;
static int hf_v2giso2_struct_iso2_MeterInfoType_TMeter = -1;

static int hf_v2giso2_struct_iso2_ContractSignatureEncryptedPrivateKeyType_Id = -1;
static int hf_v2giso2_struct_iso2_ContractSignatureEncryptedPrivateKeyType_CONTENT = -1;

static int hf_v2giso2_struct_iso2_DiffieHellmanPublickeyType_Id = -1;
static int hf_v2giso2_struct_iso2_DiffieHellmanPublickeyType_CONTENT = -1;

static int hf_v2giso2_struct_iso2_EMAIDType_Id = -1;
static int hf_v2giso2_struct_iso2_EMAIDType_CONTENT = -1;

static int hf_v2giso2_struct_iso2_SessionSetupReqType_EVCCID = -1;
static int hf_v2giso2_struct_iso2_SessionSetupResType_ResponseCode = -1;
static int hf_v2giso2_struct_iso2_SessionSetupResType_EVSEID = -1;
static int hf_v2giso2_struct_iso2_SessionSetupResType_EVSETimeStamp = -1;

static int hf_v2giso2_struct_iso2_ServiceDiscoveryReqType_ServiceScope = -1;
static int hf_v2giso2_struct_iso2_ServiceDiscoveryReqType_ServiceCategory = -1;
static int hf_v2giso2_struct_iso2_ServiceDiscoveryResType_ResponseCode = -1;

static int hf_v2giso2_struct_iso2_ServiceDetailReqType_ServiceID = -1;
static int hf_v2giso2_struct_iso2_ServiceDetailResType_ResponseCode = -1;
static int hf_v2giso2_struct_iso2_ServiceDetailResType_ServiceID = -1;

static int hf_v2giso2_struct_iso2_PaymentServiceSelectionReqType_SelectedPaymentOption = -1;
static int hf_v2giso2_struct_iso2_PaymentServiceSelectionResType_ResponseCode = -1;

static int hf_v2giso2_struct_iso2_PaymentDetailsReqType_eMAID = -1;
static int hf_v2giso2_struct_iso2_PaymentDetailsResType_ResponseCode = -1;
static int hf_v2giso2_struct_iso2_PaymentDetailsResType_GenChallenge = -1;
static int hf_v2giso2_struct_iso2_PaymentDetailsResType_EVSETimeStamp = -1;

static int hf_v2giso2_struct_iso2_AuthorizationReqType_Id = -1;
static int hf_v2giso2_struct_iso2_AuthorizationReqType_GenChallenge = -1;
static int hf_v2giso2_struct_iso2_AuthorizationResType_ResponseCode = -1;
static int hf_v2giso2_struct_iso2_AuthorizationResType_EVSEProcessing = -1;

static int hf_v2giso2_struct_iso2_ChargeParameterDiscoveryReqType_MaxEntriesSAScheduleTuple = -1;
static int hf_v2giso2_struct_iso2_ChargeParameterDiscoveryReqType_RequestedEnergyTransferType = -1;
static int hf_v2giso2_struct_iso2_ChargeParameterDiscoveryResType_ResponseCode = -1;
static int hf_v2giso2_struct_iso2_ChargeParameterDiscoveryResType_EVSEProcessing = -1;

static int hf_v2giso2_struct_iso2_PowerDeliveryReqType_ChargeProgress = -1;
static int hf_v2giso2_struct_iso2_PowerDeliveryReqType_SAScheduleTupleID = -1;
static int hf_v2giso2_struct_iso2_PowerDeliveryResType_ResponseCode = -1;

static int hf_v2giso2_struct_iso2_MeteringReceiptReqType_Id = -1;
static int hf_v2giso2_struct_iso2_MeteringReceiptReqType_SessionID = -1;
static int hf_v2giso2_struct_iso2_MeteringReceiptReqType_SAScheduleTupleID = -1;
static int hf_v2giso2_struct_iso2_MeteringReceiptResType_ResponseCode = -1;

static int hf_v2giso2_struct_iso2_SessionStopReqType_ChargingSession = -1;
static int hf_v2giso2_struct_iso2_SessionStopResType_ResponseCode = -1;

static int hf_v2giso2_struct_iso2_CertificateUpdateReqType_Id = -1;
static int hf_v2giso2_struct_iso2_CertificateUpdateReqType_eMAID = -1;
static int hf_v2giso2_struct_iso2_CertificateUpdateResType_ResponseCode = -1;
static int hf_v2giso2_struct_iso2_CertificateUpdateResType_RetryCounter = -1;

static int hf_v2giso2_struct_iso2_CertificateInstallationReqType_Id = -1;
static int hf_v2giso2_struct_iso2_CertificateInstallationReqType_OEMProvisioningCert = -1;
static int hf_v2giso2_struct_iso2_CertificateInstallationResType_ResponseCode = -1;

static int hf_v2giso2_struct_iso2_ChargingStatusResType_ResponseCode = -1;
static int hf_v2giso2_struct_iso2_ChargingStatusResType_EVSEID = -1;
static int hf_v2giso2_struct_iso2_ChargingStatusResType_SAScheduleTupleID = -1;
static int hf_v2giso2_struct_iso2_ChargingStatusResType_ReceiptRequired = -1;

static int hf_v2giso2_struct_iso2_CableCheckResType_ResponseCode = -1;
static int hf_v2giso2_struct_iso2_CableCheckResType_EVSEProcessing = -1;

static int hf_v2giso2_struct_iso2_PreChargeResType_ResponseCode = -1;

static int hf_v2giso2_struct_iso2_CurrentDemandReqType_BulkChargingComplete = -1;
static int hf_v2giso2_struct_iso2_CurrentDemandReqType_ChargingComplete = -1;
static int hf_v2giso2_struct_iso2_CurrentDemandResType_ResponseCode = -1;
static int hf_v2giso2_struct_iso2_CurrentDemandResType_EVSECurrentLimitAchieved = -1;
static int hf_v2giso2_struct_iso2_CurrentDemandResType_EVSEVoltageLimitAchieved = -1;
static int hf_v2giso2_struct_iso2_CurrentDemandResType_EVSEPowerLimitAchieved = -1;
static int hf_v2giso2_struct_iso2_CurrentDemandResType_EVSEID = -1;
static int hf_v2giso2_struct_iso2_CurrentDemandResType_SAScheduleTupleID = -1;
static int hf_v2giso2_struct_iso2_CurrentDemandResType_ReceiptRequired = -1;

static int hf_v2giso2_struct_iso2_WeldingDetectionResType_ResponseCode = -1;

/* Specifically track voltage and current for graphing */
static int hf_v2giso2_ev_target_voltage = -1;
static int hf_v2giso2_ev_target_current = -1;
static int hf_v2giso2_ev_maximum_voltage_limit = -1;
static int hf_v2giso2_ev_maximum_current_limit = -1;
static int hf_v2giso2_ev_maximum_power_limit = -1;
static int hf_v2giso2_remaining_time_to_full_soc = -1;
static int hf_v2giso2_remaining_time_to_bulk_soc = -1;
static int hf_v2giso2_evse_present_voltage = -1;
static int hf_v2giso2_evse_present_current = -1;
static int hf_v2giso2_evse_maximum_voltage_limit = -1;
static int hf_v2giso2_evse_maximum_current_limit = -1;
static int hf_v2giso2_evse_maximum_power_limit = -1;

/* Initialize the subtree pointers */
static gint ett_v2giso2 = -1;
static gint ett_v2giso2_header = -1;
static gint ett_v2giso2_body = -1;
static gint ett_v2giso2_array = -1;
static gint ett_v2giso2_array_i = -1;
static gint ett_v2giso2_asn1 = -1;

static gint ett_v2giso2_struct_iso2_NotificationType = -1;
static gint ett_v2giso2_struct_iso2_SignatureType = -1;
static gint ett_v2giso2_struct_iso2_SignedInfoType = -1;
static gint ett_v2giso2_struct_iso2_SignatureValueType = -1;
static gint ett_v2giso2_struct_iso2_ObjectType = -1;
static gint ett_v2giso2_struct_iso2_CanonicalizationMethodType = -1;
static gint ett_v2giso2_struct_iso2_SignatureMethodType = -1;
static gint ett_v2giso2_struct_iso2_DigestMethodType = -1;
static gint ett_v2giso2_struct_iso2_ReferenceType = -1;
static gint ett_v2giso2_struct_iso2_TransformsType = -1;
static gint ett_v2giso2_struct_iso2_TransformType = -1;
static gint ett_v2giso2_struct_iso2_KeyInfoType = -1;
static gint ett_v2giso2_struct_iso2_KeyValueType = -1;
static gint ett_v2giso2_struct_iso2_DSAKeyValueType = -1;
static gint ett_v2giso2_struct_iso2_RSAKeyValueType = -1;
static gint ett_v2giso2_struct_iso2_RetrievalMethodType = -1;
static gint ett_v2giso2_struct_iso2_X509DataType = -1;
static gint ett_v2giso2_struct_iso2_X509IssuerSerialType = -1;
static gint ett_v2giso2_struct_iso2_PGPDataType = -1;
static gint ett_v2giso2_struct_iso2_SPKIDataType = -1;

static gint ett_v2giso2_struct_iso2_ServiceType = -1;
static gint ett_v2giso2_struct_iso2_SupportedEnergyTransferModeType = -1;
static gint ett_v2giso2_struct_iso2_PaymentOptionListType = -1;
static gint ett_v2giso2_struct_iso2_ChargeServiceType = -1;
static gint ett_v2giso2_struct_iso2_ServiceListType = -1;
static gint ett_v2giso2_struct_iso2_ServiceParameterListType = -1;
static gint ett_v2giso2_struct_iso2_ParameterSetType = -1;
static gint ett_v2giso2_struct_iso2_ParameterType = -1;
static gint ett_v2giso2_struct_iso2_PhysicalValueType = -1;
static gint ett_v2giso2_struct_iso2_SelectedServiceListType = -1;
static gint ett_v2giso2_struct_iso2_SelectedServiceType = -1;
static gint ett_v2giso2_struct_iso2_CertificateChainType = -1;
static gint ett_v2giso2_struct_iso2_SubCertificatesType = -1;
static gint ett_v2giso2_struct_iso2_EVChargeParameterType = -1;
static gint ett_v2giso2_struct_iso2_AC_EVChargeParameterType = -1;
static gint ett_v2giso2_struct_iso2_DC_EVChargeParameterType = -1;
static gint ett_v2giso2_struct_iso2_DC_EVStatusType = -1;
static gint ett_v2giso2_struct_iso2_EVSEChargeParameterType = -1;
static gint ett_v2giso2_struct_iso2_AC_EVSEChargeParameterType = -1;
static gint ett_v2giso2_struct_iso2_DC_EVSEChargeParameterType = -1;
static gint ett_v2giso2_struct_iso2_EVSEStatusType = -1;
static gint ett_v2giso2_struct_iso2_AC_EVSEStatusType = -1;
static gint ett_v2giso2_struct_iso2_DC_EVSEStatusType = -1;
static gint ett_v2giso2_struct_iso2_SASchedulesType = -1;
static gint ett_v2giso2_struct_iso2_SAScheduleListType = -1;
static gint ett_v2giso2_struct_iso2_SAScheduleTupleType = -1;
static gint ett_v2giso2_struct_iso2_PMaxScheduleType = -1;
static gint ett_v2giso2_struct_iso2_PMaxScheduleEntryType = -1;
static gint ett_v2giso2_struct_iso2_SalesTariffType = -1;
static gint ett_v2giso2_struct_iso2_SalesTariffEntryType = -1;
static gint ett_v2giso2_struct_iso2_ConsumptionCostType = -1;
static gint ett_v2giso2_struct_iso2_CostType = -1;
static gint ett_v2giso2_struct_iso2_RelativeTimeIntervalType = -1;
static gint ett_v2giso2_struct_iso2_IntervalType = -1;
static gint ett_v2giso2_struct_iso2_ChargingProfileType = -1;
static gint ett_v2giso2_struct_iso2_ProfileEntryType = -1;
static gint ett_v2giso2_struct_iso2_EVPowerDeliveryParameterType = -1;
static gint ett_v2giso2_struct_iso2_DC_EVPowerDeliveryParameterType = -1;
static gint ett_v2giso2_struct_iso2_MeterInfoType = -1;
static gint ett_v2giso2_struct_iso2_ListOfRootCertificateIDsType = -1;
static gint ett_v2giso2_struct_iso2_ContractSignatureEncryptedPrivateKeyType = -1;
static gint ett_v2giso2_struct_iso2_DiffieHellmanPublickeyType = -1;
static gint ett_v2giso2_struct_iso2_EMAIDType = -1;

static gint ett_v2giso2_struct_iso2_SessionSetupReqType = -1;
static gint ett_v2giso2_struct_iso2_SessionSetupResType = -1;
static gint ett_v2giso2_struct_iso2_ServiceDiscoveryReqType = -1;
static gint ett_v2giso2_struct_iso2_ServiceDiscoveryResType = -1;
static gint ett_v2giso2_struct_iso2_ServiceDetailReqType = -1;
static gint ett_v2giso2_struct_iso2_ServiceDetailResType = -1;
static gint ett_v2giso2_struct_iso2_PaymentServiceSelectionReqType = -1;
static gint ett_v2giso2_struct_iso2_PaymentServiceSelectionResType = -1;
static gint ett_v2giso2_struct_iso2_PaymentDetailsReqType = -1;
static gint ett_v2giso2_struct_iso2_PaymentDetailsResType = -1;
static gint ett_v2giso2_struct_iso2_AuthorizationReqType = -1;
static gint ett_v2giso2_struct_iso2_AuthorizationResType = -1;
static gint ett_v2giso2_struct_iso2_ChargeParameterDiscoveryReqType = -1;
static gint ett_v2giso2_struct_iso2_ChargeParameterDiscoveryResType = -1;
static gint ett_v2giso2_struct_iso2_PowerDeliveryReqType = -1;
static gint ett_v2giso2_struct_iso2_PowerDeliveryResType = -1;
static gint ett_v2giso2_struct_iso2_MeteringReceiptReqType = -1;
static gint ett_v2giso2_struct_iso2_MeteringReceiptResType = -1;
static gint ett_v2giso2_struct_iso2_SessionStopReqType = -1;
static gint ett_v2giso2_struct_iso2_SessionStopResType = -1;
static gint ett_v2giso2_struct_iso2_CertificateUpdateReqType = -1;
static gint ett_v2giso2_struct_iso2_CertificateUpdateResType = -1;
static gint ett_v2giso2_struct_iso2_CertificateInstallationReqType = -1;
static gint ett_v2giso2_struct_iso2_CertificateInstallationResType = -1;
static gint ett_v2giso2_struct_iso2_ChargingStatusReqType = -1;
static gint ett_v2giso2_struct_iso2_ChargingStatusResType = -1;
static gint ett_v2giso2_struct_iso2_CableCheckReqType = -1;
static gint ett_v2giso2_struct_iso2_CableCheckResType = -1;
static gint ett_v2giso2_struct_iso2_PreChargeReqType = -1;
static gint ett_v2giso2_struct_iso2_PreChargeResType = -1;
static gint ett_v2giso2_struct_iso2_CurrentDemandReqType = -1;
static gint ett_v2giso2_struct_iso2_CurrentDemandResType = -1;
static gint ett_v2giso2_struct_iso2_WeldingDetectionReqType = -1;
static gint ett_v2giso2_struct_iso2_WeldingDetectionResType = -1;

static const value_string v2giso2_fault_code_names[] = {
	{ iso2_faultCodeType_ParsingError, "ParsingError" },
	{ iso2_faultCodeType_NoTLSRootCertificatAvailable,
	  "NoTLSRootCertificatAvailable" },
	{ iso2_faultCodeType_UnknownError, "UnknownError" },
	{ 0, NULL }
};

static const value_string v2giso2_service_category_names[] = {
	{ iso2_serviceCategoryType_EVCharging, "EVCharging" },
	{ iso2_serviceCategoryType_Internet, "Internet" },
	{ iso2_serviceCategoryType_ContractCertificate, "ContractCertificate" },
	{ iso2_serviceCategoryType_OtherCustom, "OtherCustom" },
	{ 0, NULL }
};

static const value_string v2giso2_payment_option_names[] = {
	{ iso2_paymentOptionType_Contract, "Contract" },
	{ iso2_paymentOptionType_ExternalPayment, "ExternalPayment" },
	{ 0, NULL }
};

static const value_string v2giso2_energy_transfer_mode_names[] = {
	{ iso2_EnergyTransferModeType_AC_single_phase_core,
	  "AC_single_phase_core" },
	{ iso2_EnergyTransferModeType_AC_three_phase_core,
	  "AC_three_phase_core" },
	{ iso2_EnergyTransferModeType_DC_core, "DC_core" },
	{ iso2_EnergyTransferModeType_DC_extended, "DC_extended" },
	{ iso2_EnergyTransferModeType_DC_combo_core, "DC_combo_core" },
	{ iso2_EnergyTransferModeType_DC_unique, "DC_unique" },
	{ 0, NULL }
};

static const value_string v2giso2_unit_symbol_names[] = {
	{ iso2_unitSymbolType_h, "h" },
	{ iso2_unitSymbolType_m, "m" },
	{ iso2_unitSymbolType_s, "s" },
	{ iso2_unitSymbolType_A, "A" },
	{ iso2_unitSymbolType_V, "V" },
	{ iso2_unitSymbolType_W, "W" },
	{ iso2_unitSymbolType_Wh, "Wh" },
	{ 0, NULL }
};

static const value_string v2giso2_dc_everrorcode_names[] = {
	{ iso2_DC_EVErrorCodeType_NO_ERROR, "NO ERROR" },
	{ iso2_DC_EVErrorCodeType_FAILED_RESSTemperatureInhibit,
	  "FAILED (RESSTemperatureInhibit)" },
	{ iso2_DC_EVErrorCodeType_FAILED_EVShiftPosition,
	  "FAILED (EVShiftPosition)" },
	{ iso2_DC_EVErrorCodeType_FAILED_ChargerConnectorLockFault,
	  "FAILED (ChargerConnectorLockFault)" },
	{ iso2_DC_EVErrorCodeType_FAILED_EVRESSMalfunction,
	  "FAILED (EVRESSMalfunction)" },
	{ iso2_DC_EVErrorCodeType_FAILED_ChargingCurrentdifferential,
	  "FAILED (ChargingCurrentdifferential)" },
	{ iso2_DC_EVErrorCodeType_FAILED_ChargingVoltageOutOfRange,
	  "FAILED (ChargingVoltageOutOfRange)" },
	{ iso2_DC_EVErrorCodeType_Reserved_A, "Reserved A" },
	{ iso2_DC_EVErrorCodeType_Reserved_B, "Reserved B" },
	{ iso2_DC_EVErrorCodeType_Reserved_C, "Reserved C" },
	{ iso2_DC_EVErrorCodeType_FAILED_ChargingSystemIncompatibility,
	  "FAILED (ChargingSystemIncompatibility)" },
	{ iso2_DC_EVErrorCodeType_NoData, "NoData" },
	{ 0, NULL }
};

static const value_string v2giso2_evsenotification_names[] = {
	{ iso2_EVSENotificationType_None, "None" },
	{ iso2_EVSENotificationType_StopCharging, "StopCharging" },
	{ iso2_EVSENotificationType_ReNegotiation, "ReNegotiation" },
	{ 0, NULL }
};

static const value_string v2giso2_evseisolation_level_names[] = {
	{ iso2_isolationLevelType_Invalid, "Invalid" },
	{ iso2_isolationLevelType_Valid, "Valid" },
	{ iso2_isolationLevelType_Warning, "Warning" },
	{ iso2_isolationLevelType_Fault, "Fault" },
	{ iso2_isolationLevelType_No_IMD, "No IMD" },
	{ 0, NULL }
};

static const value_string v2giso2_dc_evsestatuscode_names[] = {
	{ iso2_DC_EVSEStatusCodeType_EVSE_NotReady, "EVSE NotReady" },
	{ iso2_DC_EVSEStatusCodeType_EVSE_Ready, "EVSE Ready" },
	{ iso2_DC_EVSEStatusCodeType_EVSE_Shutdown, "EVSE Shutdown" },
	{ iso2_DC_EVSEStatusCodeType_EVSE_UtilityInterruptEvent,
	  "EVSE UtilityInterruptEvent" },
	{ iso2_DC_EVSEStatusCodeType_EVSE_IsolationMonitoringActive,
	  "EVSE IsolationMonitoringActive" },
	{ iso2_DC_EVSEStatusCodeType_EVSE_EmergencyShutdown,
	  "EVSE EmergencyShutdown" },
	{ iso2_DC_EVSEStatusCodeType_EVSE_Malfunction, "EVSE Malfunction" },
	{ iso2_DC_EVSEStatusCodeType_Reserved_8, "Reserved_8" },
	{ iso2_DC_EVSEStatusCodeType_Reserved_9, "Reserved_9" },
	{ iso2_DC_EVSEStatusCodeType_Reserved_A, "Reserved_A" },
	{ iso2_DC_EVSEStatusCodeType_Reserved_B, "Reserved_B" },
	{ iso2_DC_EVSEStatusCodeType_Reserved_C, "Reserved_C" },
	{ 0, NULL }
};

static const value_string v2giso2_cost_kind_names[] = {
	{ iso2_costKindType_relativePricePercentage,
	  "relativePricePercentage" },
	{ iso2_costKindType_RenewableGenerationPercentage,
	  "RenewableGenerationPercentage" },
	{ iso2_costKindType_CarbonDioxideEmission,
	  "CarbonDioxideEmission" },
	{ 0, NULL }
};

static const value_string v2giso2_response_code_names[] = {
	{ iso2_responseCodeType_OK, "OK" },
	{ iso2_responseCodeType_OK_NewSessionEstablished,
	  "OK (NewSessionEstablished" },
	{ iso2_responseCodeType_OK_OldSessionJoined,
	  "OK (OldSessionJoined)" },
	{ iso2_responseCodeType_OK_CertificateExpiresSoon,
	  "OK (CertificateExpiresSoon)" },
	{ iso2_responseCodeType_FAILED, "FAILED" },
	{ iso2_responseCodeType_FAILED_SequenceError,
	  "FAILED (SequenceError)" },
	{ iso2_responseCodeType_FAILED_ServiceIDInvalid,
	  "FAILED (ServiceIDInvalid)" },
	{ iso2_responseCodeType_FAILED_UnknownSession,
	  "FAILED (UnknownSession)" },
	{ iso2_responseCodeType_FAILED_ServiceSelectionInvalid,
	  "FAILED (ServiceSelectionInvalid)" },
	{ iso2_responseCodeType_FAILED_PaymentSelectionInvalid,
	  "FAILED (PaymentSelectionInvalid)" },
	{ iso2_responseCodeType_FAILED_CertificateExpired,
	  "FAILED (CertificateExpired)" },
	{ iso2_responseCodeType_FAILED_SignatureError,
	  "FAILED (SignatureError)" },
	{ iso2_responseCodeType_FAILED_NoCertificateAvailable,
	  "FAILED (NoCertificateAvailable)" },
	{ iso2_responseCodeType_FAILED_CertChainError,
	  "FAILED (CertChainError)" },
	{ iso2_responseCodeType_FAILED_ChallengeInvalid,
	  "FAILED (ChallengeInvalid)" },
	{ iso2_responseCodeType_FAILED_ContractCanceled,
	  "FAILED (ContractCanceled)" },
	{ iso2_responseCodeType_FAILED_WrongChargeParameter,
	  "FAILED (WrongChargeParameter)" },
	{ iso2_responseCodeType_FAILED_PowerDeliveryNotApplied,
	  "FAILED (PowerDeliveryNotApplied)" },
	{ iso2_responseCodeType_FAILED_TariffSelectionInvalid,
	  "FAILED (TariffSelectionInvalid)" },
	{ iso2_responseCodeType_FAILED_ChargingProfileInvalid,
	  "FAILED (ChargingProfileInvalid)" },
	{ iso2_responseCodeType_FAILED_MeteringSignatureNotValid,
	  "FAILED (MeteringSignatureNotValid)" },
	{ iso2_responseCodeType_FAILED_NoChargeServiceSelected,
	  "FAILED (NoChargeServiceSelected)" },
	{ iso2_responseCodeType_FAILED_WrongEnergyTransferMode,
	  "FAILED (WrongEnergyTransferMode)" },
	{ iso2_responseCodeType_FAILED_ContactorError,
	  "FAILED (ContactorError)" },
	{ iso2_responseCodeType_FAILED_CertificateNotAllowedAtThisEVSE,
	  "FAILED (CertificateNotAllowedAtThisEVSE)" },
	{ iso2_responseCodeType_FAILED_CertificateRevoked,
	  "FAILED (CertificateRevoked)" },
	{ 0, NULL }
};

static const value_string v2giso2_evse_processing_names[] = {
	{ iso2_EVSEProcessingType_Finished, "Finished" },
	{ iso2_EVSEProcessingType_Ongoing, "Ongoing" },
	{ iso2_EVSEProcessingType_Ongoing_WaitingForCustomerInteraction,
	  "Ongoing (WaitingForCustomerInteraction)" },
	{ 0, NULL }
};

static const value_string v2giso2_charge_progress_names[] = {
	{ iso2_chargeProgressType_Start, "Start" },
	{ iso2_chargeProgressType_Stop, "Stop" },
	{ iso2_chargeProgressType_Renegotiate, "Renegotiate" },
	{ 0, NULL }
};

static const value_string v2giso2_charging_session_names[] = {
	{ iso2_chargingSessionType_Terminate, "Terminate" },
	{ iso2_chargingSessionType_Pause, "Pause" },
	{ 0, NULL }
};


static void
dissect_v2giso2_notification(const struct iso2_NotificationType *notification,
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
		hf_v2giso2_struct_iso2_NotificationType_FaultCode,
		tvb, 0, 0, notification->FaultCode);
	proto_item_set_generated(it);

	if (notification->FaultMsg_isUsed) {
		exi_add_characters(subtree,
			hf_v2giso2_struct_iso2_NotificationType_FaultMsg,
			tvb,
			notification->FaultMsg.characters,
			notification->FaultMsg.charactersLen,
			sizeof(notification->FaultMsg.characters));
	}

	return;
}

static void
dissect_v2giso2_object(const struct iso2_ObjectType *object,
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
			hf_v2giso2_struct_iso2_ObjectType_Id,
			tvb,
			object->Id.characters,
			object->Id.charactersLen,
			sizeof(object->Id.characters));
	}
	if (object->MimeType_isUsed) {
		exi_add_characters(subtree,
			hf_v2giso2_struct_iso2_ObjectType_MimeType,
			tvb,
			object->MimeType.characters,
			object->MimeType.charactersLen,
			sizeof(object->MimeType.characters));
	}
	if (object->Encoding_isUsed) {
		exi_add_characters(subtree,
			hf_v2giso2_struct_iso2_ObjectType_Encoding,
			tvb,
			object->Encoding.characters,
			object->Encoding.charactersLen,
			sizeof(object->Encoding.characters));
	}
	if (object->ANY_isUsed) {
		exi_add_bytes(subtree,
			hf_v2giso2_struct_iso2_ObjectType_ANY,
			tvb,
			object->ANY.bytes,
			object->ANY.bytesLen,
			sizeof(object->ANY.bytes));
	}

	return;
}

static void
dissect_v2giso2_transform(const struct iso2_TransformType *transform,
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
		hf_v2giso2_struct_iso2_TransformType_Algorithm,
		tvb,
		transform->Algorithm.characters,
		transform->Algorithm.charactersLen,
		sizeof(transform->Algorithm.characters));

	if (transform->ANY_isUsed) {
		exi_add_bytes(subtree,
			hf_v2giso2_struct_iso2_TransformType_ANY,
			tvb,
			transform->ANY.bytes,
			transform->ANY.bytesLen,
			sizeof(transform->ANY.bytes));
	}
	if (transform->XPath_isUsed) {
		exi_add_characters(subtree,
			hf_v2giso2_struct_iso2_TransformType_XPath,
			tvb,
			transform->XPath.characters,
			transform->XPath.charactersLen,
			sizeof(transform->XPath.characters));
	}

	return;
}

static void
dissect_v2giso2_transforms(const struct iso2_TransformsType *transforms,
			   tvbuff_t *tvb,
			   packet_info *pinfo,
			   proto_tree *tree,
			   gint idx,
			   const char *subtree_name)
{
	proto_tree *subtree;

	subtree = proto_tree_add_subtree(tree,
		tvb, 0, 0, idx, NULL, subtree_name);

	dissect_v2giso2_transform(&transforms->Transform,
		tvb, pinfo, subtree,
		ett_v2giso2_struct_iso2_TransformType, "Transform");

	return;
}

static void
dissect_v2giso2_digestmethod(const struct iso2_DigestMethodType *digestmethod,
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
		hf_v2giso2_struct_iso2_DigestMethodType_Algorithm,
		tvb,
		digestmethod->Algorithm.characters,
		digestmethod->Algorithm.charactersLen,
		sizeof(digestmethod->Algorithm.characters));

	if (digestmethod->ANY_isUsed) {
		exi_add_bytes(subtree,
			hf_v2giso2_struct_iso2_DigestMethodType_ANY,
			tvb,
			digestmethod->ANY.bytes,
			digestmethod->ANY.bytesLen,
			sizeof(digestmethod->ANY.bytes));
	}

	return;
}

static void
dissect_v2giso2_reference(const struct iso2_ReferenceType *reference,
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
			hf_v2giso2_struct_iso2_ReferenceType_Id,
			tvb,
			reference->Id.characters,
			reference->Id.charactersLen,
			sizeof(reference->Id.characters));
	}
	if (reference->URI_isUsed) {
		exi_add_characters(subtree,
			hf_v2giso2_struct_iso2_ReferenceType_URI,
			tvb,
			reference->URI.characters,
			reference->URI.charactersLen,
			sizeof(reference->URI.characters));
	}
	if (reference->Type_isUsed) {
		exi_add_characters(subtree,
			hf_v2giso2_struct_iso2_ReferenceType_Type,
			tvb,
			reference->Type.characters,
			reference->Type.charactersLen,
			sizeof(reference->Type.characters));
	}
	if (reference->Transforms_isUsed) {
		dissect_v2giso2_transforms(&reference->Transforms,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2_TransformsType,
			"Transforms");
	}

	dissect_v2giso2_digestmethod(&reference->DigestMethod,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2_DigestMethodType,
			"DigestMethod");

	exi_add_bytes(subtree,
		hf_v2giso2_struct_iso2_ReferenceType_DigestValue,
		tvb,
		reference->DigestValue.bytes,
		reference->DigestValue.bytesLen,
		sizeof(reference->DigestValue.bytes));

	return;
}

static void
dissect_v2giso2_canonicalizationmethod(
	const struct iso2_CanonicalizationMethodType *canonicalizationmethod,
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
		hf_v2giso2_struct_iso2_CanonicalizationMethodType_Algorithm,
		tvb,
		canonicalizationmethod->Algorithm.characters,
		canonicalizationmethod->Algorithm.charactersLen,
		sizeof(canonicalizationmethod->Algorithm.characters));

	if (canonicalizationmethod->ANY_isUsed) {
		exi_add_bytes(subtree,
			hf_v2giso2_struct_iso2_CanonicalizationMethodType_ANY,
			tvb,
			canonicalizationmethod->ANY.bytes,
			canonicalizationmethod->ANY.bytesLen,
			sizeof(canonicalizationmethod->ANY.bytes));
	}

	return;
}

static void
dissect_v2giso2_signaturemethod(
	const struct iso2_SignatureMethodType *signaturemethod,
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
		hf_v2giso2_struct_iso2_SignatureMethodType_Algorithm,
		tvb,
		signaturemethod->Algorithm.characters,
		signaturemethod->Algorithm.charactersLen,
		sizeof(signaturemethod->Algorithm.characters));

	if (signaturemethod->HMACOutputLength_isUsed) {
		it = proto_tree_add_int64(subtree,
			hf_v2giso2_struct_iso2_SignatureMethodType_HMACOutputLength,
			tvb, 0, 0, signaturemethod->HMACOutputLength);
		proto_item_set_generated(it);
	}

	if (signaturemethod->ANY_isUsed) {
		exi_add_bytes(subtree,
			hf_v2giso2_struct_iso2_SignatureMethodType_ANY,
			tvb,
			signaturemethod->ANY.bytes,
			signaturemethod->ANY.bytesLen,
			sizeof(signaturemethod->ANY.bytes));
	}

	return;
}

static void
dissect_v2giso2_signaturevalue(
	const struct iso2_SignatureValueType *signaturevalue,
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
			hf_v2giso2_struct_iso2_SignatureValueType_Id,
			tvb,
			signaturevalue->Id.characters,
			signaturevalue->Id.charactersLen,
			sizeof(signaturevalue->Id.characters));
	}

	exi_add_bytes(subtree,
		hf_v2giso2_struct_iso2_SignatureValueType_CONTENT,
		tvb,
		signaturevalue->CONTENT.bytes,
		signaturevalue->CONTENT.bytesLen,
		sizeof(signaturevalue->CONTENT.bytes));

	return;
}

static void
dissect_v2giso2_signedinfo(const struct iso2_SignedInfoType *signedinfo,
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
			hf_v2giso2_struct_iso2_SignedInfoType_Id,
			tvb,
			signedinfo->Id.characters,
			signedinfo->Id.charactersLen,
			sizeof(signedinfo->Id.characters));
	}

	dissect_v2giso2_canonicalizationmethod(
		&signedinfo->CanonicalizationMethod,
		tvb, pinfo, subtree,
		ett_v2giso2_struct_iso2_CanonicalizationMethodType,
		"CanonicalizationMethod");
	dissect_v2giso2_signaturemethod(
		&signedinfo->SignatureMethod,
		tvb, pinfo, subtree,
		ett_v2giso2_struct_iso2_SignatureMethodType,
		"SignatureMethod");

	reference_tree = proto_tree_add_subtree(subtree,
		tvb, 0, 0, ett_v2giso2_array, NULL, "Reference");
	for (i = 0; i < signedinfo->Reference.arrayLen; i++) {
		char index[sizeof("[65536]")];

		snprintf(index, sizeof(index), "[%u]", i);
		dissect_v2giso2_reference(&signedinfo->Reference.array[i],
			tvb, pinfo, reference_tree,
			ett_v2giso2_struct_iso2_ReferenceType, index);
	}

	return;
}

static void
dissect_v2giso2_dsakeyvalue(const struct iso2_DSAKeyValueType *dsakeyvalue,
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
			hf_v2giso2_struct_iso2_DSAKeyValueType_P,
			tvb,
			dsakeyvalue->P.bytes,
			dsakeyvalue->P.bytesLen,
			sizeof(dsakeyvalue->P.bytes));
	}
	if (dsakeyvalue->Q_isUsed) {
		exi_add_bytes(subtree,
			hf_v2giso2_struct_iso2_DSAKeyValueType_Q,
			tvb,
			dsakeyvalue->Q.bytes,
			dsakeyvalue->Q.bytesLen,
			sizeof(dsakeyvalue->Q.bytes));
	}
	if (dsakeyvalue->G_isUsed) {
		exi_add_bytes(subtree,
			hf_v2giso2_struct_iso2_DSAKeyValueType_G,
			tvb,
			dsakeyvalue->G.bytes,
			dsakeyvalue->G.bytesLen,
			sizeof(dsakeyvalue->G.bytes));
	}
	exi_add_bytes(subtree,
		hf_v2giso2_struct_iso2_DSAKeyValueType_Y,
		tvb,
		dsakeyvalue->Y.bytes,
		dsakeyvalue->Y.bytesLen,
		sizeof(dsakeyvalue->Y.bytes));
	if (dsakeyvalue->J_isUsed) {
		exi_add_bytes(subtree,
			hf_v2giso2_struct_iso2_DSAKeyValueType_J,
			tvb,
			dsakeyvalue->J.bytes,
			dsakeyvalue->J.bytesLen,
			sizeof(dsakeyvalue->J.bytes));
	}
	if (dsakeyvalue->Seed_isUsed) {
		exi_add_bytes(subtree,
			hf_v2giso2_struct_iso2_DSAKeyValueType_Seed,
			tvb,
			dsakeyvalue->Seed.bytes,
			dsakeyvalue->Seed.bytesLen,
			sizeof(dsakeyvalue->Seed.bytes));
	}
	if (dsakeyvalue->PgenCounter_isUsed) {
		exi_add_bytes(subtree,
			hf_v2giso2_struct_iso2_DSAKeyValueType_PgenCounter,
			tvb,
			dsakeyvalue->PgenCounter.bytes,
			dsakeyvalue->PgenCounter.bytesLen,
			sizeof(dsakeyvalue->PgenCounter.bytes));
	}

	return;
}

static void
dissect_v2giso2_rsakeyvalue(const struct iso2_RSAKeyValueType *rsakeyvalue,
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
		hf_v2giso2_struct_iso2_RSAKeyValueType_Modulus,
		tvb,
		rsakeyvalue->Modulus.bytes,
		rsakeyvalue->Modulus.bytesLen,
		sizeof(rsakeyvalue->Modulus.bytes));

	exi_add_bytes(subtree,
		hf_v2giso2_struct_iso2_RSAKeyValueType_Exponent,
		tvb,
		rsakeyvalue->Exponent.bytes,
		rsakeyvalue->Exponent.bytesLen,
		sizeof(rsakeyvalue->Exponent.bytes));

	return;
}

static void
dissect_v2giso2_keyvalue(const struct iso2_KeyValueType *keyvalue,
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
			ett_v2giso2_struct_iso2_DSAKeyValueType,
			"DSAKeyValue");
	}
	if (keyvalue->RSAKeyValue_isUsed) {
		dissect_v2giso2_rsakeyvalue(&keyvalue->RSAKeyValue,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2_RSAKeyValueType,
			"RSAKeyValue");
	}

	exi_add_bytes(subtree,
		hf_v2giso2_struct_iso2_KeyValueType_ANY,
		tvb,
		keyvalue->ANY.bytes,
		keyvalue->ANY.bytesLen,
		sizeof(keyvalue->ANY.bytes));

	return;
}

static void
dissect_v2giso2_retrievalmethod(
	const struct iso2_RetrievalMethodType *retrievalmethod,
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
			hf_v2giso2_struct_iso2_RetrievalMethodType_URI,
			tvb,
			retrievalmethod->URI.characters,
			retrievalmethod->URI.charactersLen,
			sizeof(retrievalmethod->URI.characters));
	}
	if (retrievalmethod->Type_isUsed) {
		exi_add_characters(subtree,
			hf_v2giso2_struct_iso2_RetrievalMethodType_Type,
			tvb,
			retrievalmethod->Type.characters,
			retrievalmethod->Type.charactersLen,
			sizeof(retrievalmethod->Type.characters));
	}
	if (retrievalmethod->Transforms_isUsed) {
		dissect_v2giso2_transforms(&retrievalmethod->Transforms,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2_TransformsType,
			"Transforms");
	}

	return;
}

static void
dissect_v2giso2_x509issuerserial(
	const struct iso2_X509IssuerSerialType *x509issuerserial,
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
		hf_v2giso2_struct_iso2_X509IssuerSerialType_X509IssuerName,
		tvb,
		x509issuerserial->X509IssuerName.characters,
		x509issuerserial->X509IssuerName.charactersLen,
		sizeof(x509issuerserial->X509IssuerName.characters));

	it = proto_tree_add_int(subtree,
		hf_v2giso2_struct_iso2_X509IssuerSerialType_X509SerialNumber,
		tvb, 0, 0, x509issuerserial->X509SerialNumber);
	proto_item_set_generated(it);

	return;
}

static void
dissect_v2giso2_x509data(const struct iso2_X509DataType *x509data,
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
		dissect_v2giso2_x509issuerserial(
			&x509data->X509IssuerSerial,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2_X509IssuerSerialType,
			"X509IssuerSerial");
	}

	if (x509data->X509SKI_isUsed) {
		exi_add_bytes(subtree,
			hf_v2giso2_struct_iso2_X509DataType_X509SKI,
			tvb,
			x509data->X509SKI.bytes,
			x509data->X509SKI.bytesLen,
			sizeof(x509data->X509SKI.bytes));
	}

	if (x509data->X509SubjectName_isUsed) {
		exi_add_characters(subtree,
			hf_v2giso2_struct_iso2_X509DataType_X509SubjectName,
			tvb,
			x509data->X509SubjectName.characters,
			x509data->X509SubjectName.charactersLen,
			sizeof(x509data->X509SubjectName.characters));
	}

	if (x509data->X509Certificate_isUsed) {
		if (v2gber_handle == NULL) {
			exi_add_bytes(subtree,
				hf_v2giso2_struct_iso2_X509DataType_X509Certificate,
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
				ett_v2giso2_asn1, NULL, "X509Certificate ASN1");
			call_dissector(v2gber_handle, child, pinfo, asn1_tree);
		}
	}

	if (x509data->X509CRL_isUsed) {
		exi_add_bytes(subtree,
			hf_v2giso2_struct_iso2_X509DataType_X509CRL,
			tvb,
			x509data->X509CRL.bytes,
			x509data->X509CRL.bytesLen,
			sizeof(x509data->X509CRL.bytes));
	}

	if (x509data->ANY_isUsed) {
		exi_add_bytes(subtree,
			hf_v2giso2_struct_iso2_X509DataType_ANY,
			tvb,
			x509data->ANY.bytes,
			x509data->ANY.bytesLen,
			sizeof(x509data->ANY.bytes));
	}

	return;
}

static void
dissect_v2giso2_pgpdata(const struct iso2_PGPDataType *pgpdata,
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
			hf_v2giso2_struct_iso2_PGPDataType_PGPKeyID,
			tvb,
			pgpdata->choice_1.PGPKeyID.bytes,
			pgpdata->choice_1.PGPKeyID.bytesLen,
			sizeof(pgpdata->choice_1.PGPKeyID.bytes));

		if (pgpdata->choice_1.PGPKeyPacket_isUsed) {
			exi_add_bytes(subtree,
				hf_v2giso2_struct_iso2_PGPDataType_PGPKeyPacket,
				tvb,
				pgpdata->choice_1.PGPKeyPacket.bytes,
				pgpdata->choice_1.PGPKeyPacket.bytesLen,
				sizeof(pgpdata->choice_1.PGPKeyPacket.bytes));
		}

		if (pgpdata->choice_1.ANY_isUsed) {
			exi_add_bytes(subtree,
				hf_v2giso2_struct_iso2_PGPDataType_ANY,
				tvb,
				pgpdata->choice_1.ANY.bytes,
				pgpdata->choice_1.ANY.bytesLen,
				sizeof(pgpdata->choice_1.ANY.bytes));
		}
	}
	if (pgpdata->choice_2_isUsed) {
		exi_add_bytes(subtree,
			hf_v2giso2_struct_iso2_PGPDataType_PGPKeyPacket,
			tvb,
			pgpdata->choice_2.PGPKeyPacket.bytes,
			pgpdata->choice_2.PGPKeyPacket.bytesLen,
			sizeof(pgpdata->choice_2.PGPKeyPacket.bytes));

		if (pgpdata->choice_2.ANY_isUsed) {
			exi_add_bytes(subtree,
				hf_v2giso2_struct_iso2_PGPDataType_ANY,
				tvb,
				pgpdata->choice_2.ANY.bytes,
				pgpdata->choice_2.ANY.bytesLen,
				sizeof(pgpdata->choice_2.ANY.bytes));
		}
	}

	return;
}

static void
dissect_v2giso2_spkidata(const struct iso2_SPKIDataType *spkidata,
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
		hf_v2giso2_struct_iso2_SPKIDataType_SPKISexp,
		tvb,
		spkidata->SPKISexp.bytes,
		spkidata->SPKISexp.bytesLen,
		sizeof(spkidata->SPKISexp.bytes));

	if (spkidata->ANY_isUsed) {
		exi_add_bytes(subtree,
			hf_v2giso2_struct_iso2_SPKIDataType_ANY,
			tvb,
			spkidata->ANY.bytes,
			spkidata->ANY.bytesLen,
			sizeof(spkidata->ANY.bytes));
	}

	return;
}

static void
dissect_v2giso2_keyinfo(const struct iso2_KeyInfoType *keyinfo,
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
			hf_v2giso2_struct_iso2_KeyInfoType_Id,
			tvb,
			keyinfo->Id.characters,
			keyinfo->Id.charactersLen,
			sizeof(keyinfo->Id.characters));
	}

	if (keyinfo->KeyName_isUsed) {
		exi_add_characters(subtree,
			hf_v2giso2_struct_iso2_KeyInfoType_KeyName,
			tvb,
			keyinfo->KeyName.characters,
			keyinfo->KeyName.charactersLen,
			sizeof(keyinfo->KeyName.characters));
	}

	if (keyinfo->KeyValue_isUsed) {
		dissect_v2giso2_keyvalue(&keyinfo->KeyValue,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2_KeyValueType,
			"KeyValue");
	}

	if (keyinfo->RetrievalMethod_isUsed) {
		dissect_v2giso2_retrievalmethod(
			&keyinfo->RetrievalMethod,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2_RetrievalMethodType,
			"RetrievalMethod");
	}

	if (keyinfo->X509Data_isUsed) {
		dissect_v2giso2_x509data(&keyinfo->X509Data,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2_X509DataType, "X509Data");
	}

	if (keyinfo->PGPData_isUsed) {
		dissect_v2giso2_pgpdata(&keyinfo->PGPData,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2_PGPDataType, "PGPData");
	}

	if (keyinfo->SPKIData_isUsed) {
		dissect_v2giso2_spkidata(&keyinfo->SPKIData,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2_SPKIDataType, "SPKIData");
	}

	if (keyinfo->MgmtData_isUsed) {
		exi_add_characters(subtree,
			hf_v2giso2_struct_iso2_KeyInfoType_MgmtData,
			tvb,
			keyinfo->MgmtData.characters,
			keyinfo->MgmtData.charactersLen,
			sizeof(keyinfo->MgmtData.characters));
	}

	if (keyinfo->ANY_isUsed) {
		exi_add_bytes(subtree,
			hf_v2giso2_struct_iso2_KeyInfoType_ANY,
			tvb,
			keyinfo->ANY.bytes,
			keyinfo->ANY.bytesLen,
			sizeof(keyinfo->ANY.bytes));
	}

	return;
}

static void
dissect_v2giso2_signature(const struct iso2_SignatureType *signature,
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
			hf_v2giso2_struct_iso2_SignatureType_Id,
			tvb,
			signature->Id.characters,
			signature->Id.charactersLen,
			sizeof(signature->Id.characters));
	}

	dissect_v2giso2_signedinfo(&signature->SignedInfo,
		tvb, pinfo, subtree,
		ett_v2giso2_struct_iso2_SignedInfoType, "SignedInfo");
	dissect_v2giso2_signaturevalue(&signature->SignatureValue,
		tvb, pinfo, subtree,
		ett_v2giso2_struct_iso2_SignatureValueType, "SignatureValue");

	if (signature->KeyInfo_isUsed) {
		dissect_v2giso2_keyinfo(&signature->KeyInfo,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2_KeyInfoType, "KeyInfo");
	}

	if (signature->Object_isUsed) {
		dissect_v2giso2_object(&signature->Object,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2_ObjectType, "Object");
	}

	return;
}


static void
dissect_v2giso2_header(const struct iso2_MessageHeaderType *header,
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
		hf_v2giso2_struct_iso2_MessageHeaderType_SessionID,
		tvb,
		header->SessionID.bytes,
		header->SessionID.bytesLen,
		sizeof(header->SessionID.bytes));

	if (header->Notification_isUsed) {
		dissect_v2giso2_notification(
			&header->Notification, tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2_NotificationType,
			"Notification");
	}

	if (header->Signature_isUsed) {
		dissect_v2giso2_signature(
			&header->Signature, tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2_SignatureType,
			"Signature");
	}

	return;
}


static void
dissect_v2giso2_paymentoptionlist(
	const struct iso2_PaymentOptionListType *paymentoptionlist,
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
		tvb, 0, 0, ett_v2giso2_array, NULL, "PaymentOption");
	for (i = 0; i < paymentoptionlist->PaymentOption.arrayLen; i++) {
		char index[sizeof("[65536]")];

		snprintf(index, sizeof(index), "[%u]", i);
		paymentoption_i_tree = proto_tree_add_subtree(
			paymentoption_tree, tvb, 0, 0,
			ett_v2giso2_array_i, NULL, index);

		it = proto_tree_add_uint(paymentoption_i_tree,
			hf_v2giso2_struct_iso2_PaymentOptionLstType_PaymentOption,
			tvb, 0, 0,
			paymentoptionlist->PaymentOption.array[i]);
		proto_item_set_generated(it);
	}

	return;
}

static void
dissect_v2giso2_supportedenergytransfermode(
	const struct iso2_SupportedEnergyTransferModeType
		 *supportedenergytransfermode,
	tvbuff_t *tvb,
	packet_info *pinfo _U_,
	proto_tree *tree,
	gint idx,
	const char *subtree_name)
{
	unsigned int i;
	proto_tree *subtree;
	proto_tree *energytransfermode_tree;
	proto_tree *energytransfermode_i_tree;
	proto_item *it;

	subtree = proto_tree_add_subtree(tree, tvb, 0, 0,
		idx, NULL, subtree_name);

	energytransfermode_tree = proto_tree_add_subtree(subtree,
		tvb, 0, 0, ett_v2giso2_array, NULL, "EnergyTransferMode");
	for (i = 0; i < supportedenergytransfermode->EnergyTransferMode.arrayLen; i++) {
		energytransfermode_i_tree = proto_tree_add_subtree_format(
			energytransfermode_tree,
			tvb, 0, 0, ett_v2giso2_array_i, NULL, "[%u]", i);

		it = proto_tree_add_uint(energytransfermode_i_tree,
			hf_v2giso2_struct_iso2_SupportedEnergyTransferModeType_EnergyTransferMode,
			tvb, 0, 0,
			supportedenergytransfermode->EnergyTransferMode.array[i]);
		proto_item_set_generated(it);
	}

	return;
}

static void
dissect_v2giso2_chargeservice(
	const struct iso2_ChargeServiceType *chargeservice,
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
		hf_v2giso2_struct_iso2_ChargeServiceType_ServiceID,
		tvb, 0, 0, chargeservice->ServiceID);
	proto_item_set_generated(it);

	if (chargeservice->ServiceName_isUsed) {
		exi_add_characters(subtree,
			hf_v2giso2_struct_iso2_ChargeServiceType_ServiceName,
			tvb,
			chargeservice->ServiceName.characters,
			chargeservice->ServiceName.charactersLen,
			sizeof(chargeservice->ServiceName.characters));
	}

	it = proto_tree_add_uint(subtree,
		hf_v2giso2_struct_iso2_ChargeServiceType_ServiceCategory,
		tvb, 0, 0, chargeservice->ServiceCategory);
	proto_item_set_generated(it);

	if (chargeservice->ServiceScope_isUsed) {
		exi_add_characters(subtree,
			hf_v2giso2_struct_iso2_ChargeServiceType_ServiceScope,
			tvb,
			chargeservice->ServiceScope.characters,
			chargeservice->ServiceScope.charactersLen,
			sizeof(chargeservice->ServiceScope.characters));
	}

	it = proto_tree_add_int(subtree,
		hf_v2giso2_struct_iso2_ChargeServiceType_FreeService,
		tvb, 0, 0, chargeservice->FreeService);
	proto_item_set_generated(it);

	dissect_v2giso2_supportedenergytransfermode(
		&chargeservice->SupportedEnergyTransferMode,
		tvb, pinfo, subtree,
		ett_v2giso2_struct_iso2_SupportedEnergyTransferModeType,
		"SupportedEnergyTransferMode");

	return;
}

static void
dissect_v2giso2_service(
	const struct iso2_ServiceType *service,
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
		hf_v2giso2_struct_iso2_ServiceType_ServiceID,
		tvb, 0, 0, service->ServiceID);
	proto_item_set_generated(it);

	if (service->ServiceName_isUsed) {
		exi_add_characters(subtree,
			hf_v2giso2_struct_iso2_ServiceType_ServiceName,
			tvb,
			service->ServiceName.characters,
			service->ServiceName.charactersLen,
			sizeof(service->ServiceName.characters));
	}

	it = proto_tree_add_uint(subtree,
		hf_v2giso2_struct_iso2_ServiceType_ServiceCategory,
		tvb, 0, 0, service->ServiceCategory);
	proto_item_set_generated(it);

	if (service->ServiceScope_isUsed) {
		exi_add_characters(subtree,
			hf_v2giso2_struct_iso2_ServiceType_ServiceScope,
			tvb,
			service->ServiceScope.characters,
			service->ServiceScope.charactersLen,
			sizeof(service->ServiceScope.characters));
	}

	it = proto_tree_add_int(subtree,
		hf_v2giso2_struct_iso2_ServiceType_FreeService, tvb, 0, 0,
		service->FreeService);
	proto_item_set_generated(it);

	return;
}

static void
dissect_v2giso2_servicelist(
	const struct iso2_ServiceListType *servicelist,
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
		tvb, 0, 0, ett_v2giso2_array, NULL, "Service");
	for (i = 0; i < servicelist->Service.arrayLen; i++) {
		char index[sizeof("[65536]")];

		snprintf(index, sizeof(index), "[%u]", i);
		dissect_v2giso2_service(
			&servicelist->Service.array[i],
			tvb, pinfo, service_tree,
			ett_v2giso2_struct_iso2_ServiceType, index);
	}

	return;
}

static inline double
v2giso2_physicalvalue_to_double(
	const struct iso2_PhysicalValueType *physicalvalue)
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
dissect_v2giso2_physicalvalue(
	const struct iso2_PhysicalValueType *physicalvalue,
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
		hf_v2giso2_struct_iso2_PhysicalValueType_Multiplier,
		tvb, 0, 0, physicalvalue->Multiplier);
	proto_item_set_generated(it);

	it = proto_tree_add_uint(subtree,
		hf_v2giso2_struct_iso2_PhysicalValueType_Unit,
		tvb, 0, 0, physicalvalue->Unit);
	proto_item_set_generated(it);

	it = proto_tree_add_int(subtree,
		hf_v2giso2_struct_iso2_PhysicalValueType_Value,
		tvb, 0, 0, physicalvalue->Value);
	proto_item_set_generated(it);

	return;
}

static void
dissect_v2giso2_parameter(
	const struct iso2_ParameterType *parameter,
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
		hf_v2giso2_struct_iso2_ParameterType_Name,
		tvb,
		parameter->Name.characters,
		parameter->Name.charactersLen,
		sizeof(parameter->Name.characters));

	if (parameter->boolValue_isUsed) {
		it = proto_tree_add_int(subtree,
			hf_v2giso2_struct_iso2_ParameterType_boolValue,
			tvb, 0, 0, parameter->boolValue);
		proto_item_set_generated(it);
	}
	if (parameter->byteValue_isUsed) {
		it = proto_tree_add_int(subtree,
			hf_v2giso2_struct_iso2_ParameterType_byteValue,
			tvb, 0, 0, parameter->byteValue);
		proto_item_set_generated(it);
	}
	if (parameter->shortValue_isUsed) {
		it = proto_tree_add_int(subtree,
			hf_v2giso2_struct_iso2_ParameterType_shortValue,
			tvb, 0, 0, parameter->shortValue);
		proto_item_set_generated(it);
	}
	if (parameter->intValue_isUsed) {
		it = proto_tree_add_int(subtree,
			hf_v2giso2_struct_iso2_ParameterType_intValue,
			tvb, 0, 0, parameter->intValue);
		proto_item_set_generated(it);
	}
	if (parameter->physicalValue_isUsed) {
		dissect_v2giso2_physicalvalue(&parameter->physicalValue,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2_PhysicalValueType,
			"physicalValue");
	}
	if (parameter->stringValue_isUsed) {
		exi_add_characters(subtree,
			hf_v2giso2_struct_iso2_ParameterType_stringValue,
			tvb,
			parameter->stringValue.characters,
			parameter->stringValue.charactersLen,
			sizeof(parameter->stringValue.characters));
	}

	return;
}

static void
dissect_v2giso2_parameterset(
	const struct iso2_ParameterSetType *parameterset,
	tvbuff_t *tvb,
	packet_info *pinfo,
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
		hf_v2giso2_struct_iso2_ParameterSetType_ParameterSetID,
		tvb, 0, 0, parameterset->ParameterSetID);
	proto_item_set_generated(it);

	parameter_tree = proto_tree_add_subtree(subtree,
		tvb, 0, 0, ett_v2giso2_array, NULL, "Parameter");
	for (i = 0; i < parameterset->Parameter.arrayLen; i++) {
		char index[sizeof("[65536]")];

		snprintf(index, sizeof(index), "[%u]", i);
		dissect_v2giso2_parameter(
			&parameterset->Parameter.array[i],
			tvb, pinfo, parameter_tree,
			ett_v2giso2_struct_iso2_ParameterType, index);
	}

	return;
}

static void
dissect_v2giso2_serviceparameterlist(
	const struct iso2_ServiceParameterListType *serviceparameterlist,
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
		tvb, 0, 0, ett_v2giso2_array, NULL, "ParameterSet");
	for (i = 0; i < serviceparameterlist->ParameterSet.arrayLen; i++) {
		char index[sizeof("[65536]")];

		snprintf(index, sizeof(index), "[%u]", i);
		dissect_v2giso2_parameterset(
			&serviceparameterlist->ParameterSet.array[i],
			tvb, pinfo, parameterset_tree,
			ett_v2giso2_struct_iso2_ParameterSetType, index);
	}

	return;
}

static void
dissect_v2giso2_selectedservice(
	const struct iso2_SelectedServiceType *selectedservice,
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
		hf_v2giso2_struct_iso2_SelectedServiceType_ServiceID,
		tvb, 0, 0, selectedservice->ServiceID);
	proto_item_set_generated(it);

	if (selectedservice->ParameterSetID_isUsed) {
		it = proto_tree_add_int(subtree,
			hf_v2giso2_struct_iso2_SelectedServiceType_ParameterSetID,
			tvb, 0, 0, selectedservice->ParameterSetID);
		proto_item_set_generated(it);
	}

	return;
}

static void
dissect_v2giso2_selectedservicelist(
	const struct iso2_SelectedServiceListType *selectedservicelist,
	tvbuff_t *tvb,
	packet_info *pinfo,
	proto_tree *tree,
	gint idx,
	const char *subtree_name)
{
	unsigned int i;
	proto_tree *subtree;
	proto_tree *selectedservice_tree;

	subtree = proto_tree_add_subtree(tree, tvb, 0, 0,
		idx, NULL, subtree_name);

	selectedservice_tree = proto_tree_add_subtree(subtree,
		tvb, 0, 0, ett_v2giso2_array, NULL, "SelectedService");
	for (i = 0; i < selectedservicelist->SelectedService.arrayLen; i++) {
		char index[sizeof("[65536]")];

		snprintf(index, sizeof(index), "[%u]", i);
		dissect_v2giso2_selectedservice(
			&selectedservicelist->SelectedService.array[i],
			tvb, pinfo, selectedservice_tree,
			ett_v2giso2_struct_iso2_SelectedServiceType, index);
	}

	return;
}

static void
dissect_v2giso2_subcertificates(
	const struct iso2_SubCertificatesType *subcertificates,
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
		tvb, 0, 0, ett_v2giso2_array, NULL, "Certificate");
	for (i = 0; i < subcertificates->Certificate.arrayLen; i++) {
		certificate_i_tree = proto_tree_add_subtree_format(
			certificate_tree,
			tvb, 0, 0, ett_v2giso2_array_i, NULL, "[%u]", i);

		if (v2gber_handle == NULL) {
			exi_add_bytes(certificate_i_tree,
				hf_v2giso2_struct_iso2_SubCertificatesType_Certificate,
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
				ett_v2giso2_asn1, NULL, "Certificate ASN1");
			call_dissector(v2gber_handle, child, pinfo, asn1_tree);
		}
	}

	return;
}

static void
dissect_v2giso2_certificatechain(
	const struct iso2_CertificateChainType *certificatechain,
	tvbuff_t *tvb,
	packet_info *pinfo,
	proto_tree *tree,
	gint idx,
	const char *subtree_name)
{
	proto_tree *subtree;

	subtree = proto_tree_add_subtree(tree, tvb, 0, 0,
		idx, NULL, subtree_name);

	if (certificatechain->Id_isUsed) {
		exi_add_characters(subtree,
			hf_v2giso2_struct_iso2_CertificateChainType_Id,
			tvb,
			certificatechain->Id.characters,
			certificatechain->Id.charactersLen,
			sizeof(certificatechain->Id.characters));
	}

	if (v2gber_handle == NULL) {
		exi_add_bytes(subtree,
			hf_v2giso2_struct_iso2_CertificateChainType_Certificate,
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
			ett_v2giso2_asn1, NULL, "Certificate ASN1");
		call_dissector(v2gber_handle, child, pinfo, asn1_tree);
	}

	if (certificatechain->SubCertificates_isUsed) {
		dissect_v2giso2_subcertificates(
			&certificatechain->SubCertificates,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2_SubCertificatesType,
			"SubCertificates");
	}

	return;
}

static void
dissect_v2giso2_evchargeparameter(
	const struct iso2_EVChargeParameterType *evchargeparameter _U_,
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
dissect_v2giso2_ac_evchargeparameter(
	const struct iso2_AC_EVChargeParameterType *ac_evchargeparameter,
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
		hf_v2giso2_struct_iso2_AC_EVChargeParameterType_DepartureTime,
		tvb, 0, 0, ac_evchargeparameter->DepartureTime);
	proto_item_set_generated(it);

	dissect_v2giso2_physicalvalue(&ac_evchargeparameter->EAmount,
		tvb, pinfo, subtree,
		ett_v2giso2_struct_iso2_PhysicalValueType, "EAmount");

	dissect_v2giso2_physicalvalue(&ac_evchargeparameter->EVMaxVoltage,
		tvb, pinfo, subtree,
		ett_v2giso2_struct_iso2_PhysicalValueType, "EVMaxVoltage");

	dissect_v2giso2_physicalvalue(&ac_evchargeparameter->EVMaxCurrent,
		tvb, pinfo, subtree,
		ett_v2giso2_struct_iso2_PhysicalValueType, "EVMaxCurrent");

	dissect_v2giso2_physicalvalue(&ac_evchargeparameter->EVMinCurrent,
		tvb, pinfo, subtree,
		ett_v2giso2_struct_iso2_PhysicalValueType, "EVMinCurrent");

	return;
}

static void
dissect_v2giso2_dc_evstatus(
	const struct iso2_DC_EVStatusType *dc_evstatus,
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
		hf_v2giso2_struct_iso2_DC_EVStatusType_EVReady,
		tvb, 0, 0, dc_evstatus->EVReady);
	proto_item_set_generated(it);

	it = proto_tree_add_uint(subtree,
		hf_v2giso2_struct_iso2_DC_EVStatusType_EVErrorCode,
		tvb, 0, 0, dc_evstatus->EVErrorCode);
	proto_item_set_generated(it);

	it = proto_tree_add_int(subtree,
		hf_v2giso2_struct_iso2_DC_EVStatusType_EVRESSSOC,
		tvb, 0, 0, dc_evstatus->EVRESSSOC);
	proto_item_set_generated(it);

	return;
}

static void
dissect_v2giso2_dc_evchargeparameter(
	const struct iso2_DC_EVChargeParameterType *dc_evchargeparameter,
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

	if (dc_evchargeparameter->DepartureTime_isUsed) {
		it = proto_tree_add_uint(subtree,
			hf_v2giso2_struct_iso2_DC_EVChargeParameterType_DepartureTime,
			tvb, 0, 0, dc_evchargeparameter->DepartureTime);
		proto_item_set_generated(it);
	}

	dissect_v2giso2_dc_evstatus(&dc_evchargeparameter->DC_EVStatus,
		tvb, pinfo, subtree,
		ett_v2giso2_struct_iso2_DC_EVStatusType, "DC_EVStatus");

	dissect_v2giso2_physicalvalue(
		&dc_evchargeparameter->EVMaximumVoltageLimit,
		tvb, pinfo, subtree,
		ett_v2giso2_struct_iso2_PhysicalValueType,
		"EVMaximumVoltageLimit");
	value = v2giso2_physicalvalue_to_double(
		&dc_evchargeparameter->EVMaximumVoltageLimit);
	it = proto_tree_add_double(subtree,
		hf_v2giso2_ev_maximum_voltage_limit,
		tvb, 0, 0, value);
	proto_item_set_generated(it);

	dissect_v2giso2_physicalvalue(
		&dc_evchargeparameter->EVMaximumCurrentLimit,
		tvb, pinfo, subtree,
		ett_v2giso2_struct_iso2_PhysicalValueType,
		"EVMaximumCurrentLimit");
	value = v2giso2_physicalvalue_to_double(
		&dc_evchargeparameter->EVMaximumCurrentLimit);
	it = proto_tree_add_double(subtree,
		hf_v2giso2_ev_maximum_current_limit,
		tvb, 0, 0, value);
	proto_item_set_generated(it);

	if (dc_evchargeparameter->EVMaximumPowerLimit_isUsed) {
		dissect_v2giso2_physicalvalue(
			&dc_evchargeparameter->EVMaximumPowerLimit,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2_PhysicalValueType,
			"EVMaximumPowerLimit");
		value = v2giso2_physicalvalue_to_double(
			&dc_evchargeparameter->EVMaximumPowerLimit);
		it = proto_tree_add_double(subtree,
			hf_v2giso2_ev_maximum_power_limit,
			tvb, 0, 0, value);
		proto_item_set_generated(it);
	}

	if (dc_evchargeparameter->EVEnergyCapacity_isUsed) {
		dissect_v2giso2_physicalvalue(
			&dc_evchargeparameter->EVEnergyCapacity,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2_PhysicalValueType,
			"EVEnergyCapacity");
	}

	if (dc_evchargeparameter->EVEnergyRequest_isUsed) {
		dissect_v2giso2_physicalvalue(
			&dc_evchargeparameter->EVEnergyRequest,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2_PhysicalValueType,
			"EVEnergyRequest");
	}

	if (dc_evchargeparameter->FullSOC_isUsed) {
		it = proto_tree_add_int(subtree,
			hf_v2giso2_struct_iso2_DC_EVChargeParameterType_FullSOC,
			tvb, 0, 0, dc_evchargeparameter->FullSOC);
		proto_item_set_generated(it);
	}

	if (dc_evchargeparameter->BulkSOC_isUsed) {
		it = proto_tree_add_int(subtree,
			hf_v2giso2_struct_iso2_DC_EVChargeParameterType_BulkSOC,
			tvb, 0, 0, dc_evchargeparameter->BulkSOC);
		proto_item_set_generated(it);
	}

	return;
}

static void
dissect_v2giso2_evsestatus(
	const struct iso2_EVSEStatusType *evsestatus,
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
		hf_v2giso2_struct_iso2_EVSEStatusType_NotificationMaxDelay,
		tvb, 0, 0, evsestatus->NotificationMaxDelay);
	proto_item_set_generated(it);

	it = proto_tree_add_uint(subtree,
		hf_v2giso2_struct_iso2_EVSEStatusType_EVSENotification,
		tvb, 0, 0, evsestatus->EVSENotification);
	proto_item_set_generated(it);

	return;
}

static void
dissect_v2giso2_ac_evsestatus(
	const struct iso2_AC_EVSEStatusType *ac_evsestatus,
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
		hf_v2giso2_struct_iso2_AC_EVSEStatusType_NotificationMaxDelay,
		tvb, 0, 0, ac_evsestatus->NotificationMaxDelay);
	proto_item_set_generated(it);

	it = proto_tree_add_uint(subtree,
		hf_v2giso2_struct_iso2_AC_EVSEStatusType_EVSENotification,
		tvb, 0, 0, ac_evsestatus->EVSENotification);
	proto_item_set_generated(it);

	it = proto_tree_add_int(subtree,
		hf_v2giso2_struct_iso2_AC_EVSEStatusType_RCD,
		tvb, 0, 0, ac_evsestatus->RCD);
	proto_item_set_generated(it);

	return;
}

static void
dissect_v2giso2_dc_evsestatus(
	const struct iso2_DC_EVSEStatusType *dc_evsestatus,
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
		hf_v2giso2_struct_iso2_DC_EVSEStatusType_NotificationMaxDelay,
		tvb, 0, 0, dc_evsestatus->NotificationMaxDelay);
	proto_item_set_generated(it);

	it = proto_tree_add_uint(subtree,
		hf_v2giso2_struct_iso2_DC_EVSEStatusType_EVSENotification,
		tvb, 0, 0, dc_evsestatus->EVSENotification);
	proto_item_set_generated(it);

	if (dc_evsestatus->EVSEIsolationStatus_isUsed) {
		it = proto_tree_add_uint(subtree,
			hf_v2giso2_struct_iso2_DC_EVSEStatusType_EVSEIsolationStatus,
			tvb, 0, 0, dc_evsestatus->EVSEIsolationStatus);
		proto_item_set_generated(it);
	}

	it = proto_tree_add_uint(subtree,
		hf_v2giso2_struct_iso2_DC_EVSEStatusType_EVSEStatusCode,
		tvb, 0, 0, dc_evsestatus->EVSEStatusCode);
	proto_item_set_generated(it);

	return;
};

static void
dissect_v2giso2_evsechargeparameter(
	const struct iso2_EVSEChargeParameterType *evsechargeparameter _U_,
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
dissect_v2giso2_ac_evsechargeparameter(
	const struct iso2_AC_EVSEChargeParameterType *ac_evsechargeparameter,
	tvbuff_t *tvb,
	packet_info *pinfo,
	proto_tree *tree,
	gint idx,
	const char *subtree_name)
{
	proto_tree *subtree;

	subtree = proto_tree_add_subtree(tree, tvb, 0, 0,
		idx, NULL, subtree_name);

	dissect_v2giso2_ac_evsestatus(&ac_evsechargeparameter->AC_EVSEStatus,
		tvb, pinfo, subtree,
		ett_v2giso2_struct_iso2_AC_EVSEStatusType,
		"AC_EVSEStatus");

	dissect_v2giso2_physicalvalue(
		&ac_evsechargeparameter->EVSENominalVoltage,
		tvb, pinfo, subtree,
		ett_v2giso2_struct_iso2_PhysicalValueType,
		"EVSENominalVoltage");

	dissect_v2giso2_physicalvalue(&ac_evsechargeparameter->EVSEMaxCurrent,
		tvb, pinfo, subtree,
		ett_v2giso2_struct_iso2_PhysicalValueType,
		"EVSEMaxCurrent");

	return;
}

static void
dissect_v2giso2_dc_evsechargeparameter(
	const struct iso2_DC_EVSEChargeParameterType *dc_evsechargeparameter,
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

	dissect_v2giso2_dc_evsestatus(&dc_evsechargeparameter->DC_EVSEStatus,
		tvb, pinfo, subtree,
		ett_v2giso2_struct_iso2_DC_EVSEStatusType,
		"DC_EVSEStatus");

	dissect_v2giso2_physicalvalue(
		&dc_evsechargeparameter->EVSEMaximumVoltageLimit,
		tvb, pinfo, subtree,
		ett_v2giso2_struct_iso2_PhysicalValueType,
		"EVSEMaximumVoltageLimit");
	value = v2giso2_physicalvalue_to_double(
		&dc_evsechargeparameter->EVSEMaximumVoltageLimit);
	it = proto_tree_add_double(subtree,
		hf_v2giso2_evse_maximum_voltage_limit,
		tvb, 0, 0, value);
	proto_item_set_generated(it);

	dissect_v2giso2_physicalvalue(
		&dc_evsechargeparameter->EVSEMinimumVoltageLimit,
		tvb, pinfo, subtree,
		ett_v2giso2_struct_iso2_PhysicalValueType,
		"EVSEMinimumVoltageLimit");

	dissect_v2giso2_physicalvalue(
		&dc_evsechargeparameter->EVSEMaximumCurrentLimit,
		tvb, pinfo, subtree,
		ett_v2giso2_struct_iso2_PhysicalValueType,
		"EVSEMaximumCurrentLimit");
	value = v2giso2_physicalvalue_to_double(
		&dc_evsechargeparameter->EVSEMaximumCurrentLimit);
	it = proto_tree_add_double(subtree,
		hf_v2giso2_evse_maximum_current_limit,
		tvb, 0, 0, value);
	proto_item_set_generated(it);

	dissect_v2giso2_physicalvalue(
		&dc_evsechargeparameter->EVSEMinimumCurrentLimit,
		tvb, pinfo, subtree,
		ett_v2giso2_struct_iso2_PhysicalValueType,
		"EVSEMinimumCurrentLimit");

	dissect_v2giso2_physicalvalue(
		&dc_evsechargeparameter->EVSEMaximumPowerLimit,
		tvb, pinfo, subtree,
		ett_v2giso2_struct_iso2_PhysicalValueType,
		"EVSEMaximumPowerLimit");
	value = v2giso2_physicalvalue_to_double(
		&dc_evsechargeparameter->EVSEMaximumPowerLimit);
	it = proto_tree_add_double(subtree,
		hf_v2giso2_evse_maximum_power_limit,
		tvb, 0, 0, value);
	proto_item_set_generated(it);

	if (dc_evsechargeparameter->EVSECurrentRegulationTolerance_isUsed) {
		dissect_v2giso2_physicalvalue(
			&dc_evsechargeparameter->EVSECurrentRegulationTolerance,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2_PhysicalValueType,
			"EVSECurrentRegulationTolerance");
	}

	dissect_v2giso2_physicalvalue(
		&dc_evsechargeparameter->EVSEPeakCurrentRipple,
		tvb, pinfo, subtree,
		ett_v2giso2_struct_iso2_PhysicalValueType,
		"EVSEPeakCurrentRipple");

	if (dc_evsechargeparameter->EVSEEnergyToBeDelivered_isUsed) {
		dissect_v2giso2_physicalvalue(
			&dc_evsechargeparameter->EVSEEnergyToBeDelivered,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2_PhysicalValueType,
			"EVSEEnergyToBeDelivered");
	}

	return;
}

static void
dissect_v2giso2_interval(
	const struct iso2_IntervalType *interval _U_,
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
dissect_v2giso2_relativetimeinterval(
	const struct iso2_RelativeTimeIntervalType *relativetimeinterval,
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
		hf_v2giso2_struct_iso2_RelativeTimeIntervalType_start,
		tvb, 0, 0, relativetimeinterval->start);
	proto_item_set_generated(it);

	if (relativetimeinterval->duration_isUsed) {
		it = proto_tree_add_uint(subtree,
			hf_v2giso2_struct_iso2_RelativeTimeIntervalType_duration,
			tvb, 0, 0, relativetimeinterval->duration);
		proto_item_set_generated(it);
	}

	return;
}

static void
dissect_v2giso2_pmaxscheduleentry(
	const struct iso2_PMaxScheduleEntryType *pmaxscheduleentry,
	tvbuff_t *tvb,
	packet_info *pinfo,
	proto_tree *tree,
	gint idx,
	const char *subtree_name)
{
	proto_tree *subtree;

	subtree = proto_tree_add_subtree(tree, tvb, 0, 0,
		idx, NULL, subtree_name);

	if (pmaxscheduleentry->TimeInterval_isUsed) {
		dissect_v2giso2_interval(&pmaxscheduleentry->TimeInterval,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2_IntervalType,
			"TimeInterval");
	}

	if (pmaxscheduleentry->RelativeTimeInterval_isUsed) {
		dissect_v2giso2_relativetimeinterval(
			&pmaxscheduleentry->RelativeTimeInterval,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2_RelativeTimeIntervalType,
			"RelativeTimeInterval");
	}

	dissect_v2giso2_physicalvalue(&pmaxscheduleentry->PMax,
		tvb, pinfo, subtree,
		ett_v2giso2_struct_iso2_PhysicalValueType, "PMax");

	return;
}

static void
dissect_v2giso2_pmaxschedule(
	const struct iso2_PMaxScheduleType *pmaxschedule,
	tvbuff_t *tvb,
	packet_info *pinfo,
	proto_tree *tree,
	gint idx,
	const char *subtree_name)
{
	unsigned int i;
	proto_tree *subtree;
	proto_tree *pmaxscheduleentry_tree;

	subtree = proto_tree_add_subtree(tree, tvb, 0, 0,
		idx, NULL, subtree_name);

	pmaxscheduleentry_tree = proto_tree_add_subtree(subtree,
		tvb, 0, 0, ett_v2giso2_array, NULL, "PMaxScheduleEntry");
	for (i = 0; i < pmaxschedule->PMaxScheduleEntry.arrayLen; i++) {
		char index[sizeof("[65536]")];

		snprintf(index, sizeof(index), "[%u]", i);
		dissect_v2giso2_pmaxscheduleentry(
			&pmaxschedule->PMaxScheduleEntry.array[i],
			tvb, pinfo, pmaxscheduleentry_tree,
			ett_v2giso2_struct_iso2_PMaxScheduleEntryType, index);
	}

	return;
}

static void
dissect_v2giso2_cost(
	const struct iso2_CostType *cost,
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
		hf_v2giso2_struct_iso2_CostType_costKind,
		tvb, 0, 0, cost->costKind);
	proto_item_set_generated(it);

	it = proto_tree_add_uint(subtree,
		hf_v2giso2_struct_iso2_CostType_amount,
		tvb, 0, 0, cost->amount);
	proto_item_set_generated(it);

	if (cost->amountMultiplier_isUsed) {
		it = proto_tree_add_int(subtree,
			hf_v2giso2_struct_iso2_CostType_amountMultiplier,
			tvb, 0, 0, cost->amount);
		proto_item_set_generated(it);
	}

	return;
}

static void
dissect_v2giso2_consumptioncost(
	const struct iso2_ConsumptionCostType *consumptioncost,
	tvbuff_t *tvb,
	packet_info *pinfo,
	proto_tree *tree,
	gint idx,
	const char *subtree_name)
{
	unsigned int i;
	proto_tree *subtree;
	proto_tree *cost_tree;

	subtree = proto_tree_add_subtree(tree, tvb, 0, 0,
		idx, NULL, subtree_name);

	dissect_v2giso2_physicalvalue(
		&consumptioncost->startValue, tvb, pinfo, subtree,
		ett_v2giso2_struct_iso2_PhysicalValueType, "startValue");

	cost_tree = proto_tree_add_subtree(subtree,
		tvb, 0, 0, ett_v2giso2_array, NULL, "Cost");
	for (i = 0; i < consumptioncost->Cost.arrayLen; i++) {
		char index[sizeof("[65536]")];

		snprintf(index, sizeof(index), "[%u]", i);
		dissect_v2giso2_cost(
			&consumptioncost->Cost.array[i],
			tvb, pinfo, cost_tree,
			ett_v2giso2_struct_iso2_CostType, index);
	}

	return;
}

static void
dissect_v2giso2_salestariffentry(
	const struct iso2_SalesTariffEntryType *salestariffentry,
	tvbuff_t *tvb,
	packet_info *pinfo,
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
		dissect_v2giso2_interval(&salestariffentry->TimeInterval,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2_IntervalType,
			"TimeInterval");
	}

	if (salestariffentry->RelativeTimeInterval_isUsed) {
		dissect_v2giso2_relativetimeinterval(
			&salestariffentry->RelativeTimeInterval,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2_RelativeTimeIntervalType,
			"RelativeTimeInterval");
	}

	it = proto_tree_add_uint(subtree,
		hf_v2giso2_struct_iso2_SalesTariffEntryType_EPriceLevel,
		tvb, 0, 0, salestariffentry->EPriceLevel);
	proto_item_set_generated(it);

	consumptioncost_tree = proto_tree_add_subtree(subtree,
		tvb, 0, 0, ett_v2giso2_array, NULL, "ConsumptionCost");
	for (i = 0; i < salestariffentry->ConsumptionCost.arrayLen; i++) {
		char index[sizeof("[65536]")];

		snprintf(index, sizeof(index), "[%u]", i);
		dissect_v2giso2_consumptioncost(
			&salestariffentry->ConsumptionCost.array[i],
			tvb, pinfo, consumptioncost_tree,
			ett_v2giso2_struct_iso2_ConsumptionCostType, index);
	}

	return;
}

static void
dissect_v2giso2_salestariff(
	const struct iso2_SalesTariffType *salestariff,
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

	if (salestariff->Id_isUsed) {
		exi_add_characters(subtree,
			hf_v2giso2_struct_iso2_SalesTariffType_Id,
			tvb,
			salestariff->Id.characters,
			salestariff->Id.charactersLen,
			sizeof(salestariff->Id.characters));
	}

	if (salestariff->SalesTariffDescription_isUsed) {
		exi_add_characters(subtree,
			hf_v2giso2_struct_iso2_SalesTariffType_SalesTariffDescription,
			tvb,
			salestariff->SalesTariffDescription.characters,
			salestariff->SalesTariffDescription.charactersLen,
			sizeof(salestariff->SalesTariffDescription.characters));
	}

	if (salestariff->NumEPriceLevels_isUsed) {
		it = proto_tree_add_uint(subtree,
			hf_v2giso2_struct_iso2_SalesTariffType_NumEPriceLevels,
			tvb, 0, 0, salestariff->NumEPriceLevels);
		proto_item_set_generated(it);
	}

	salestariffentry_tree = proto_tree_add_subtree(subtree,
		tvb, 0, 0, ett_v2giso2_array, NULL, "SalesTariffEntry");
	for (i = 0; i < salestariff->SalesTariffEntry.arrayLen; i++) {
		char index[sizeof("[65536]")];

		snprintf(index, sizeof(index), "[%u]", i);
		dissect_v2giso2_salestariffentry(
			&salestariff->SalesTariffEntry.array[i],
			tvb, pinfo, salestariffentry_tree,
			ett_v2giso2_struct_iso2_SalesTariffEntryType, index);
	}

	return;
}

static void
dissect_v2giso2_saschedules(
	const struct iso2_SASchedulesType *saschedules _U_,
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
dissect_v2giso2_sascheduletuple(
	const struct iso2_SAScheduleTupleType *sascheduletuple,
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
		hf_v2giso2_struct_iso2_SAScheduleTupleType_SAScheduleTupleID,
		tvb, 0, 0, sascheduletuple->SAScheduleTupleID);
	proto_item_set_generated(it);

	dissect_v2giso2_pmaxschedule(&sascheduletuple->PMaxSchedule,
		tvb, pinfo, subtree,
		ett_v2giso2_struct_iso2_PMaxScheduleType,
		"PMaxSchedule");

	if (sascheduletuple->SalesTariff_isUsed) {
		dissect_v2giso2_salestariff(&sascheduletuple->SalesTariff,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2_SalesTariffType,
			"SalesTariff");
	}

	return;
}

static void
dissect_v2giso2_saschedulelist(
	const struct iso2_SAScheduleListType *saschedulelist,
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
		tvb, 0, 0, ett_v2giso2_array, NULL, "SAScheduleTuple");
	for (i = 0; i < saschedulelist->SAScheduleTuple.arrayLen; i++) {
		char index[sizeof("[65536]")];

		snprintf(index, sizeof(index), "[%u]", i);
		dissect_v2giso2_sascheduletuple(
			&saschedulelist->SAScheduleTuple.array[i],
			tvb, pinfo, sascheduletuple_tree,
			ett_v2giso2_struct_iso2_SAScheduleTupleType, index);
	}

	return;
}

static void
dissect_v2giso2_profileentry(
	const struct iso2_ProfileEntryType *profileentry,
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
		hf_v2giso2_struct_iso2_ProfileEntryType_ChargingProfileEntryStart,
		tvb, 0, 0, profileentry->ChargingProfileEntryStart);
	proto_item_set_generated(it);

	dissect_v2giso2_physicalvalue(
		&profileentry->ChargingProfileEntryMaxPower,
		tvb, pinfo, subtree,
		ett_v2giso2_struct_iso2_PhysicalValueType,
		"ChargingProfileEntryMaxPower");

	if (profileentry->ChargingProfileEntryMaxNumberOfPhasesInUse) {
		it = proto_tree_add_int(subtree,
			hf_v2giso2_struct_iso2_ProfileEntryType_ChargingProfileEntryMaxNumberOfPhasesInUse,
			tvb, 0, 0, profileentry->ChargingProfileEntryMaxNumberOfPhasesInUse);
		proto_item_set_generated(it);
	}

	return;
}

static void
dissect_v2giso2_chargingprofile(
	const struct iso2_ChargingProfileType *chargingprofile,
	tvbuff_t *tvb,
	packet_info *pinfo,
	proto_tree *tree,
	gint idx,
	const char *subtree_name)
{
	unsigned int i;
	proto_tree *subtree;
	proto_tree *profileentry_tree;

	subtree = proto_tree_add_subtree(tree, tvb, 0, 0,
		idx, NULL, subtree_name);

	profileentry_tree = proto_tree_add_subtree(subtree,
		tvb, 0, 0, ett_v2giso2_array, NULL, "ProfileEntry");
	for (i = 0; i < chargingprofile->ProfileEntry.arrayLen; i++) {
		char index[sizeof("[65536]")];

		snprintf(index, sizeof(index), "[%u]", i);
		dissect_v2giso2_profileentry(
			&chargingprofile->ProfileEntry.array[i],
			tvb, pinfo, profileentry_tree,
			ett_v2giso2_struct_iso2_ProfileEntryType, index);
	}

	return;
}

static void
dissect_v2giso2_evpowerdeliveryparameter(
	const struct iso2_EVPowerDeliveryParameterType
		*evpowerdeliveryparameter _U_,
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
dissect_v2giso2_dc_evpowerdeliveryparameter(
	const struct iso2_DC_EVPowerDeliveryParameterType
		*dc_evpowerdeliveryparameter,
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

	dissect_v2giso2_dc_evstatus(&dc_evpowerdeliveryparameter->DC_EVStatus,
		tvb, pinfo, subtree,
		ett_v2giso2_struct_iso2_DC_EVStatusType,
		"DC_EVStatus");

	if (dc_evpowerdeliveryparameter->BulkChargingComplete_isUsed) {
		it = proto_tree_add_int(subtree,
			hf_v2giso2_struct_iso2_DC_EVPowerDeliveryParameterType_BulkChargingComplete,
			tvb, 0, 0,
			dc_evpowerdeliveryparameter->BulkChargingComplete);
		proto_item_set_generated(it);
	}

	it = proto_tree_add_int(subtree,
		hf_v2giso2_struct_iso2_DC_EVPowerDeliveryParameterType_ChargingComplete,
		tvb, 0, 0,
		dc_evpowerdeliveryparameter->ChargingComplete);
		proto_item_set_generated(it);

	return;
}

static void
dissect_v2giso2_meterinfo(const struct iso2_MeterInfoType *meterinfo,
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
		hf_v2giso2_struct_iso2_MeterInfoType_MeterID,
		tvb,
		meterinfo->MeterID.characters,
		meterinfo->MeterID.charactersLen,
		sizeof(meterinfo->MeterID.characters));

	if (meterinfo->MeterReading_isUsed) {
		it = proto_tree_add_uint64(subtree,
			hf_v2giso2_struct_iso2_MeterInfoType_MeterReading,
			tvb, 0, 0, meterinfo->MeterReading);
		proto_item_set_generated(it);
	}

	if (meterinfo->SigMeterReading_isUsed) {
		exi_add_bytes(subtree,
			hf_v2giso2_struct_iso2_MeterInfoType_SigMeterReading,
			tvb,
			meterinfo->SigMeterReading.bytes,
			meterinfo->SigMeterReading.bytesLen,
			sizeof(meterinfo->SigMeterReading.bytes));
	}

	if (meterinfo->MeterStatus_isUsed) {
		it = proto_tree_add_int(subtree,
			hf_v2giso2_struct_iso2_MeterInfoType_MeterStatus,
			tvb, 0, 0, meterinfo->MeterStatus);
		proto_item_set_generated(it);
	}

	if (meterinfo->TMeter_isUsed) {
		it = proto_tree_add_int64(subtree,
			hf_v2giso2_struct_iso2_MeterInfoType_TMeter,
			tvb, 0, 0, meterinfo->TMeter);
		proto_item_set_generated(it);
	}

	return;
}

static void
dissect_v2giso2_listofrootcertificateids(
	const struct iso2_ListOfRootCertificateIDsType
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
		tvb, 0, 0, ett_v2giso2_array, NULL, "RootCertificateID");
	for (i = 0; i < listofrootcertificateids->RootCertificateID.arrayLen; i++) {
		char index[sizeof("[65536]")];

		snprintf(index, sizeof(index), "[%u]", i);
		dissect_v2giso2_x509issuerserial(
			&listofrootcertificateids->RootCertificateID.array[i],
			tvb, pinfo, rootcertificateid_tree,
			ett_v2giso2_struct_iso2_X509IssuerSerialType,
			"RootCertificateID");
	}

	return;
}

static void
dissect_v2giso2_contractsignatureencryptedprivatekey(
	const struct iso2_ContractSignatureEncryptedPrivateKeyType
		*contractsignatureencryptedprivatekey,
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
		hf_v2giso2_struct_iso2_ContractSignatureEncryptedPrivateKeyType_Id,
		tvb,
		contractsignatureencryptedprivatekey->Id.characters,
		contractsignatureencryptedprivatekey->Id.charactersLen,
		sizeof(contractsignatureencryptedprivatekey->Id.characters));

	exi_add_bytes(subtree,
		hf_v2giso2_struct_iso2_ContractSignatureEncryptedPrivateKeyType_CONTENT,
		tvb,
		contractsignatureencryptedprivatekey->CONTENT.bytes,
		contractsignatureencryptedprivatekey->CONTENT.bytesLen,
		sizeof(contractsignatureencryptedprivatekey->CONTENT.bytes));

	return;
}

static void
dissect_v2giso2_diffiehellmanpublickey(
	const struct iso2_DiffieHellmanPublickeyType *diffiehellmanpublickey,
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
		hf_v2giso2_struct_iso2_DiffieHellmanPublickeyType_Id,
		tvb,
		diffiehellmanpublickey->Id.characters,
		diffiehellmanpublickey->Id.charactersLen,
		sizeof(diffiehellmanpublickey->Id.characters));

	exi_add_bytes(subtree,
		hf_v2giso2_struct_iso2_DiffieHellmanPublickeyType_CONTENT,
		tvb,
		diffiehellmanpublickey->CONTENT.bytes,
		diffiehellmanpublickey->CONTENT.bytesLen,
		sizeof(diffiehellmanpublickey->CONTENT.bytes));

	return;
}

static void
dissect_v2giso2_emaid(
	const struct iso2_EMAIDType *emaid,
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
		hf_v2giso2_struct_iso2_EMAIDType_Id,
		tvb,
		emaid->Id.characters,
		emaid->Id.charactersLen,
		sizeof(emaid->Id.characters));

	exi_add_characters(subtree,
		hf_v2giso2_struct_iso2_EMAIDType_CONTENT,
		tvb,
		emaid->CONTENT.characters,
		emaid->CONTENT.charactersLen,
		sizeof(emaid->CONTENT.characters));

	return;
}


static void
dissect_v2giso2_sessionsetupreq(
	const struct iso2_SessionSetupReqType *sessionsetupreq,
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
		hf_v2giso2_struct_iso2_SessionSetupReqType_EVCCID,
		tvb,
		sessionsetupreq->EVCCID.bytes,
		sessionsetupreq->EVCCID.bytesLen,
		sizeof(sessionsetupreq->EVCCID.bytes));

	return;
}

static void
dissect_v2giso2_sessionsetupres(
	const struct iso2_SessionSetupResType *sessionsetupres,
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
		hf_v2giso2_struct_iso2_SessionSetupResType_ResponseCode,
		tvb, 0, 0, sessionsetupres->ResponseCode);
	proto_item_set_generated(it);

	exi_add_characters(subtree,
		hf_v2giso2_struct_iso2_SessionSetupResType_EVSEID,
		tvb,
		sessionsetupres->EVSEID.characters,
		sessionsetupres->EVSEID.charactersLen,
		sizeof(sessionsetupres->EVSEID.characters));

	if (sessionsetupres->EVSETimeStamp_isUsed) {
		it = proto_tree_add_int64(subtree,
			hf_v2giso2_struct_iso2_SessionSetupResType_EVSETimeStamp,
			tvb, 0, 0, sessionsetupres->EVSETimeStamp);
		proto_item_set_generated(it);
	}

	return;
}

static void
dissect_v2giso2_servicediscoveryreq(
	const struct iso2_ServiceDiscoveryReqType *servicediscoveryreq,
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
			hf_v2giso2_struct_iso2_ServiceDiscoveryReqType_ServiceScope,
			tvb,
			servicediscoveryreq->ServiceScope.characters,
			servicediscoveryreq->ServiceScope.charactersLen,
			sizeof(servicediscoveryreq->ServiceScope.characters));
	}

	if (servicediscoveryreq->ServiceCategory_isUsed) {
		it = proto_tree_add_uint(subtree,
			hf_v2giso2_struct_iso2_ServiceDiscoveryReqType_ServiceCategory,
			tvb, 0, 0, servicediscoveryreq->ServiceCategory);
		proto_item_set_generated(it);
	}

	return;
}

static void
dissect_v2giso2_servicediscoveryres(
	const struct iso2_ServiceDiscoveryResType *servicediscoveryres,
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
		hf_v2giso2_struct_iso2_ServiceDiscoveryResType_ResponseCode,
		tvb, 0, 0, servicediscoveryres->ResponseCode);
	proto_item_set_generated(it);

	dissect_v2giso2_paymentoptionlist(
		&servicediscoveryres->PaymentOptionList,
		tvb, pinfo, subtree,
		ett_v2giso2_struct_iso2_PaymentOptionListType,
		"PaymentOptionList");

	dissect_v2giso2_chargeservice(
		&servicediscoveryres->ChargeService,
		tvb, pinfo, subtree,
		ett_v2giso2_struct_iso2_ChargeServiceType,
		"ChargeService");

	if (servicediscoveryres->ServiceList_isUsed) {
		dissect_v2giso2_servicelist(
			&servicediscoveryres->ServiceList,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2_ServiceListType,
			"ServiceList");
	}

	return;
}

static void
dissect_v2giso2_servicedetailreq(
	const struct iso2_ServiceDetailReqType *servicedetailreq,
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
		hf_v2giso2_struct_iso2_ServiceDetailReqType_ServiceID,
		tvb, 0, 0, servicedetailreq->ServiceID);
	proto_item_set_generated(it);

	return;
}

static void
dissect_v2giso2_servicedetailres(
	const struct iso2_ServiceDetailResType *servicedetailres,
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
		hf_v2giso2_struct_iso2_ServiceDetailResType_ResponseCode,
		tvb, 0, 0, servicedetailres->ResponseCode);
	proto_item_set_generated(it);

	it = proto_tree_add_uint(subtree,
		hf_v2giso2_struct_iso2_ServiceDetailResType_ServiceID,
		tvb, 0, 0, servicedetailres->ServiceID);
	proto_item_set_generated(it);

	if (servicedetailres->ServiceParameterList_isUsed) {
		dissect_v2giso2_serviceparameterlist(
			&servicedetailres->ServiceParameterList,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2_ServiceParameterListType,
			"ServiceParameterList");
	}

	return;
}

static void
dissect_v2giso2_paymentserviceselectionreq(
	const struct iso2_PaymentServiceSelectionReqType
		*paymentserviceselectionreq,
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
		hf_v2giso2_struct_iso2_PaymentServiceSelectionReqType_SelectedPaymentOption,
		tvb, 0, 0, paymentserviceselectionreq->SelectedPaymentOption);
	proto_item_set_generated(it);

	dissect_v2giso2_selectedservicelist(
		&paymentserviceselectionreq->SelectedServiceList,
		tvb, pinfo, subtree,
		ett_v2giso2_struct_iso2_SelectedServiceListType,
		"SelectedServiceList");

	return;
}

static void
dissect_v2giso2_paymentserviceselectionres(
	const struct iso2_PaymentServiceSelectionResType
		*paymentserviceselectionres,
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
		hf_v2giso2_struct_iso2_PaymentServiceSelectionResType_ResponseCode,
		tvb, 0, 0,
		paymentserviceselectionres->ResponseCode);
	proto_item_set_generated(it);

	return;
}

static void
dissect_v2giso2_paymentdetailsreq(
	const struct iso2_PaymentDetailsReqType *paymentdetailsreq,
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
		hf_v2giso2_struct_iso2_PaymentDetailsReqType_eMAID,
		tvb,
		paymentdetailsreq->eMAID.characters,
		paymentdetailsreq->eMAID.charactersLen,
		sizeof(paymentdetailsreq->eMAID.characters));

	dissect_v2giso2_certificatechain(
		&paymentdetailsreq->ContractSignatureCertChain,
		tvb, pinfo, subtree,
		ett_v2giso2_struct_iso2_CertificateChainType,
		"ContractSignatureCertChain");

	return;
}

static void
dissect_v2giso2_paymentdetailsres(
	const struct iso2_PaymentDetailsResType *paymentdetailsres,
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
		hf_v2giso2_struct_iso2_PaymentDetailsResType_ResponseCode,
		tvb, 0, 0,
		paymentdetailsres->ResponseCode);
	proto_item_set_generated(it);

	exi_add_bytes(subtree,
		hf_v2giso2_struct_iso2_PaymentDetailsResType_GenChallenge,
		tvb,
		paymentdetailsres->GenChallenge.bytes,
		paymentdetailsres->GenChallenge.bytesLen,
		sizeof(paymentdetailsres->GenChallenge.bytes));

	it = proto_tree_add_int64(subtree,
		hf_v2giso2_struct_iso2_PaymentDetailsResType_EVSETimeStamp,
		tvb, 0, 0,
		paymentdetailsres->EVSETimeStamp);
	proto_item_set_generated(it);

	return;
}

static void
dissect_v2giso2_authorizationreq(
	const struct iso2_AuthorizationReqType *authorizationreq,
	tvbuff_t *tvb,
	packet_info *pinfo _U_,
	proto_tree *tree,
	gint idx,
	const char *subtree_name)
{
	proto_tree *subtree;

	subtree = proto_tree_add_subtree(tree,
		tvb, 0, 0, idx, NULL, subtree_name);

	if (authorizationreq->Id_isUsed) {
		exi_add_characters(subtree,
			hf_v2giso2_struct_iso2_AuthorizationReqType_Id,
			tvb,
			authorizationreq->Id.characters,
			authorizationreq->Id.charactersLen,
			sizeof(authorizationreq->Id.characters));
	}

	if (authorizationreq->GenChallenge_isUsed) {
		exi_add_bytes(subtree,
			hf_v2giso2_struct_iso2_AuthorizationReqType_GenChallenge,
			tvb,
			authorizationreq->GenChallenge.bytes,
			authorizationreq->GenChallenge.bytesLen,
			sizeof(authorizationreq->GenChallenge.bytes));
	}

	return;
}

static void
dissect_v2giso2_authorizationres(
	const struct iso2_AuthorizationResType *authorizationres,
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
		hf_v2giso2_struct_iso2_AuthorizationResType_ResponseCode,
		tvb, 0, 0,
		authorizationres->ResponseCode);
	proto_item_set_generated(it);

	it = proto_tree_add_uint(subtree,
		hf_v2giso2_struct_iso2_AuthorizationResType_EVSEProcessing,
		tvb, 0, 0,
		authorizationres->EVSEProcessing);
	proto_item_set_generated(it);

	return;
}

static void
dissect_v2giso2_chargeparameterdiscoveryreq(
	const struct iso2_ChargeParameterDiscoveryReqType
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

	if (chargeparameterdiscoveryreq->MaxEntriesSAScheduleTuple_isUsed) {
		it = proto_tree_add_uint(subtree,
			hf_v2giso2_struct_iso2_ChargeParameterDiscoveryReqType_MaxEntriesSAScheduleTuple,
			tvb, 0, 0,
			chargeparameterdiscoveryreq->MaxEntriesSAScheduleTuple);
	}

	it = proto_tree_add_uint(subtree,
		hf_v2giso2_struct_iso2_ChargeParameterDiscoveryReqType_RequestedEnergyTransferType,
		tvb, 0, 0,
		chargeparameterdiscoveryreq->RequestedEnergyTransferMode);
	proto_item_set_generated(it);

	if (chargeparameterdiscoveryreq->EVChargeParameter_isUsed) {
		dissect_v2giso2_evchargeparameter(
			&chargeparameterdiscoveryreq->EVChargeParameter,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2_EVChargeParameterType,
			"EVChargeParameter");
	}

	if (chargeparameterdiscoveryreq->AC_EVChargeParameter_isUsed) {
		dissect_v2giso2_ac_evchargeparameter(
			&chargeparameterdiscoveryreq->AC_EVChargeParameter,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2_AC_EVChargeParameterType,
			"AC_EVChargeParameter");
	}

	if (chargeparameterdiscoveryreq->DC_EVChargeParameter_isUsed) {
		dissect_v2giso2_dc_evchargeparameter(
			&chargeparameterdiscoveryreq->DC_EVChargeParameter,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2_DC_EVChargeParameterType,
			"DC_EVChargeParameter");
	}

	return;
}

static void
dissect_v2giso2_chargeparameterdiscoveryres(
	const struct iso2_ChargeParameterDiscoveryResType
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
		hf_v2giso2_struct_iso2_ChargeParameterDiscoveryResType_ResponseCode,
		tvb, 0, 0,
		chargeparameterdiscoveryres->ResponseCode);
	proto_item_set_generated(it);

	it = proto_tree_add_uint(subtree,
		hf_v2giso2_struct_iso2_ChargeParameterDiscoveryResType_EVSEProcessing,
		tvb, 0, 0,
		chargeparameterdiscoveryres->EVSEProcessing);
	proto_item_set_generated(it);

	if (chargeparameterdiscoveryres->SASchedules_isUsed) {
		dissect_v2giso2_saschedules(
			&chargeparameterdiscoveryres->SASchedules,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2_SASchedulesType,
			"SASchedules");
	}
	if (chargeparameterdiscoveryres->SAScheduleList_isUsed) {
		dissect_v2giso2_saschedulelist(
			&chargeparameterdiscoveryres->SAScheduleList,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2_SAScheduleListType,
			"SAScheduleList");
	}
	if (chargeparameterdiscoveryres->EVSEChargeParameter_isUsed) {
		dissect_v2giso2_evsechargeparameter(&chargeparameterdiscoveryres->EVSEChargeParameter,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2_EVSEChargeParameterType,
			"EVSEChargeParameter");
	}
	if (chargeparameterdiscoveryres->AC_EVSEChargeParameter_isUsed) {
		dissect_v2giso2_ac_evsechargeparameter(
			&chargeparameterdiscoveryres->AC_EVSEChargeParameter,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2_AC_EVSEChargeParameterType,
			"AC_EVSEChargeParameter");
	}
	if (chargeparameterdiscoveryres->DC_EVSEChargeParameter_isUsed) {
		dissect_v2giso2_dc_evsechargeparameter(
			&chargeparameterdiscoveryres->DC_EVSEChargeParameter,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2_DC_EVSEChargeParameterType,
			"DC_EVSEChargeParameter");
	}

	return;
}

static void
dissect_v2giso2_powerdeliveryreq(
	const struct iso2_PowerDeliveryReqType *powerdeliveryreq,
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
		hf_v2giso2_struct_iso2_PowerDeliveryReqType_ChargeProgress,
		tvb, 0, 0, powerdeliveryreq->ChargeProgress);
	proto_item_set_generated(it);

	it = proto_tree_add_uint(subtree,
		hf_v2giso2_struct_iso2_PowerDeliveryReqType_SAScheduleTupleID,
		tvb, 0, 0, powerdeliveryreq->SAScheduleTupleID);
	proto_item_set_generated(it);

	if (powerdeliveryreq->ChargingProfile_isUsed) {
		dissect_v2giso2_chargingprofile(
			&powerdeliveryreq->ChargingProfile,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2_ChargingProfileType,
			"ChargingProfile");
	}
	if (powerdeliveryreq->EVPowerDeliveryParameter_isUsed) {
		dissect_v2giso2_evpowerdeliveryparameter(
			&powerdeliveryreq->EVPowerDeliveryParameter,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2_EVPowerDeliveryParameterType,
			"EVPowerDeliveryParameter");
	}
	if (powerdeliveryreq->DC_EVPowerDeliveryParameter_isUsed) {
		dissect_v2giso2_dc_evpowerdeliveryparameter(
			&powerdeliveryreq->DC_EVPowerDeliveryParameter,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2_DC_EVPowerDeliveryParameterType,
			"DC_EVPowerDeliveryParameter");
	}

	return;
}

static void
dissect_v2giso2_powerdeliveryres(
	const struct iso2_PowerDeliveryResType *powerdeliveryres,
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
		hf_v2giso2_struct_iso2_PowerDeliveryResType_ResponseCode,
		tvb, 0, 0,
		powerdeliveryres->ResponseCode);
	proto_item_set_generated(it);

	if (powerdeliveryres->EVSEStatus_isUsed) {
		dissect_v2giso2_evsestatus(
			&powerdeliveryres->EVSEStatus,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2_EVSEStatusType,
			"EVSEStatus");
	}
	if (powerdeliveryres->AC_EVSEStatus_isUsed) {
		dissect_v2giso2_ac_evsestatus(
			&powerdeliveryres->AC_EVSEStatus,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2_AC_EVSEStatusType,
			"AC_EVSEStatus");
	}
	if (powerdeliveryres->DC_EVSEStatus_isUsed) {
		dissect_v2giso2_dc_evsestatus(
			&powerdeliveryres->DC_EVSEStatus,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2_DC_EVSEStatusType,
			"DC_EVSEStatus");
	}

	return;
}

static void
dissect_v2giso2_meteringreceiptreq(
	const struct iso2_MeteringReceiptReqType *meteringreceiptreq,
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
			hf_v2giso2_struct_iso2_MeteringReceiptReqType_Id,
			tvb,
			meteringreceiptreq->Id.characters,
			meteringreceiptreq->Id.charactersLen,
			sizeof(meteringreceiptreq->Id.characters));
	}

	exi_add_bytes(subtree,
		hf_v2giso2_struct_iso2_MeteringReceiptReqType_SessionID,
		tvb,
		meteringreceiptreq->SessionID.bytes,
		meteringreceiptreq->SessionID.bytesLen,
		sizeof(meteringreceiptreq->SessionID.bytes));

	if (meteringreceiptreq->SAScheduleTupleID_isUsed) {
		it = proto_tree_add_int(subtree,
			hf_v2giso2_struct_iso2_MeteringReceiptReqType_SAScheduleTupleID,
			tvb, 0, 0,
			meteringreceiptreq->SAScheduleTupleID);
		proto_item_set_generated(it);
	}

	dissect_v2giso2_meterinfo(
		&meteringreceiptreq->MeterInfo,
		tvb, pinfo, subtree,
		ett_v2giso2_struct_iso2_MeterInfoType,
		"MeterInfo");

	return;
}

static void
dissect_v2giso2_meteringreceiptres(
	const struct iso2_MeteringReceiptResType *meteringreceiptres,
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
		hf_v2giso2_struct_iso2_MeteringReceiptResType_ResponseCode,
		tvb, 0, 0,
		meteringreceiptres->ResponseCode);
	proto_item_set_generated(it);

	dissect_v2giso2_ac_evsestatus(
		&meteringreceiptres->AC_EVSEStatus,
		tvb, pinfo, subtree,
		ett_v2giso2_struct_iso2_AC_EVSEStatusType,
		"AC_EVSEStatus");

	return;
}

static void
dissect_v2giso2_sessionstopreq(
	const struct iso2_SessionStopReqType *sessionstopreq,
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
		hf_v2giso2_struct_iso2_SessionStopReqType_ChargingSession,
		tvb, 0, 0, sessionstopreq->ChargingSession);
	proto_item_set_generated(it);

	return;
}

static void
dissect_v2giso2_sessionstopres(
	const struct iso2_SessionStopResType *sessionstopres,
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
		hf_v2giso2_struct_iso2_SessionStopResType_ResponseCode,
		tvb, 0, 0, sessionstopres->ResponseCode);
	proto_item_set_generated(it);

	return;
}

static void
dissect_v2giso2_certificateupdatereq(
	const struct iso2_CertificateUpdateReqType *req,
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
		hf_v2giso2_struct_iso2_CertificateUpdateReqType_Id,
		tvb,
		req->Id.characters,
		req->Id.charactersLen,
		sizeof(req->Id.characters));

	dissect_v2giso2_certificatechain(
		&req->ContractSignatureCertChain,
		tvb, pinfo, subtree,
		ett_v2giso2_struct_iso2_CertificateChainType,
		"ContractSignatureCertChain");

	exi_add_characters(subtree,
		hf_v2giso2_struct_iso2_CertificateUpdateReqType_eMAID,
		tvb,
		req->eMAID.characters,
		req->eMAID.charactersLen,
		sizeof(req->eMAID.characters));

	dissect_v2giso2_listofrootcertificateids(
		&req->ListOfRootCertificateIDs,
		tvb, pinfo, subtree,
		ett_v2giso2_struct_iso2_ListOfRootCertificateIDsType,
		"ListOfRootCertificateIDs");

	return;
}

static void
dissect_v2giso2_certificateupdateres(
	const struct iso2_CertificateUpdateResType *res,
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
		hf_v2giso2_struct_iso2_CertificateUpdateResType_ResponseCode,
		tvb, 0, 0, res->ResponseCode);
	proto_item_set_generated(it);

	dissect_v2giso2_certificatechain(
		&res->SAProvisioningCertificateChain,
		tvb, pinfo, subtree,
		ett_v2giso2_struct_iso2_CertificateChainType,
		"SAProvisioningCertificateChain");

	dissect_v2giso2_certificatechain(
		&res->ContractSignatureCertChain,
		tvb, pinfo, subtree,
		ett_v2giso2_struct_iso2_CertificateChainType,
		"ContractSignatureCertChain");

	dissect_v2giso2_contractsignatureencryptedprivatekey(
		&res->ContractSignatureEncryptedPrivateKey,
		tvb, pinfo, subtree,
		ett_v2giso2_struct_iso2_ContractSignatureEncryptedPrivateKeyType,
		"ContractSignatureEncryptedPrivateKey");

	dissect_v2giso2_diffiehellmanpublickey(
		&res->DHpublickey,
		tvb, pinfo, subtree,
		ett_v2giso2_struct_iso2_DiffieHellmanPublickeyType,
		"DHpublickey");

	dissect_v2giso2_emaid(
		&res->eMAID,
		tvb, pinfo, subtree,
		ett_v2giso2_struct_iso2_EMAIDType,
		"eMAID");

	if (res->RetryCounter_isUsed) {
		it = proto_tree_add_uint(subtree,
			hf_v2giso2_struct_iso2_CertificateUpdateResType_RetryCounter,
			tvb, 0, 0, res->RetryCounter);
		proto_item_set_generated(it);
	}

	return;
}

static void
dissect_v2giso2_certificateinstallationreq(
	const struct iso2_CertificateInstallationReqType *req,
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
		hf_v2giso2_struct_iso2_CertificateInstallationReqType_Id,
		tvb,
		req->Id.characters,
		req->Id.charactersLen,
		sizeof(req->Id.characters));

	if (v2gber_handle == NULL) {
		exi_add_bytes(subtree,
			hf_v2giso2_struct_iso2_CertificateInstallationReqType_OEMProvisioningCert,
			tvb,
			req->OEMProvisioningCert.bytes,
			req->OEMProvisioningCert.bytesLen,
			sizeof(req->OEMProvisioningCert.bytes));
	} else {
		tvbuff_t *child;
		proto_tree *asn1_tree;

		child = tvb_new_child_real_data(tvb,
			req->OEMProvisioningCert.bytes,
			sizeof(req->OEMProvisioningCert.bytes),
			req->OEMProvisioningCert.bytesLen);

		asn1_tree = proto_tree_add_subtree(subtree,
			child, 0, tvb_reported_length(child),
			ett_v2giso2_asn1, NULL, "OEMProvisioningCert ASN1");
		call_dissector(v2gber_handle, child, pinfo, asn1_tree);
	}

	dissect_v2giso2_listofrootcertificateids(
		&req->ListOfRootCertificateIDs,
		tvb, pinfo, subtree,
		ett_v2giso2_struct_iso2_ListOfRootCertificateIDsType,
		"ListOfRootCertificateIDs");

	return;
}

static void
dissect_v2giso2_certificateinstallationres(
	const struct iso2_CertificateInstallationResType *res,
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
		hf_v2giso2_struct_iso2_CertificateInstallationResType_ResponseCode,
		tvb, 0, 0, res->ResponseCode);
	proto_item_set_generated(it);

	dissect_v2giso2_certificatechain(
		&res->SAProvisioningCertificateChain,
		tvb, pinfo, subtree,
		ett_v2giso2_struct_iso2_CertificateChainType,
		"SAProvisioningCertificateChain");

	dissect_v2giso2_certificatechain(
		&res->ContractSignatureCertChain,
		tvb, pinfo, subtree,
		ett_v2giso2_struct_iso2_CertificateChainType,
		"ContractSignatureCertChain");

	dissect_v2giso2_contractsignatureencryptedprivatekey(
		&res->ContractSignatureEncryptedPrivateKey,
		tvb, pinfo, subtree,
		ett_v2giso2_struct_iso2_ContractSignatureEncryptedPrivateKeyType,
		"ContractSignatureEncryptedPrivateKey");

	dissect_v2giso2_diffiehellmanpublickey(
		&res->DHpublickey,
		tvb, pinfo, subtree,
		ett_v2giso2_struct_iso2_DiffieHellmanPublickeyType,
		"DHpublickey");

	dissect_v2giso2_emaid(
		&res->eMAID,
		tvb, pinfo, subtree,
		ett_v2giso2_struct_iso2_EMAIDType,
		"eMAID");

	return;
}

static void
dissect_v2giso2_chargingstatusreq(
	const struct iso2_ChargingStatusReqType *chargingstatusreq _U_,
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
dissect_v2giso2_chargingstatusres(
	const struct iso2_ChargingStatusResType *chargingstatusres,
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
		hf_v2giso2_struct_iso2_ChargingStatusResType_ResponseCode,
		tvb, 0, 0,
		chargingstatusres->ResponseCode);
	proto_item_set_generated(it);

	exi_add_characters(subtree,
		hf_v2giso2_struct_iso2_ChargingStatusResType_EVSEID,
		tvb,
		chargingstatusres->EVSEID.characters,
		chargingstatusres->EVSEID.charactersLen,
		sizeof(chargingstatusres->EVSEID.characters));

	it = proto_tree_add_uint(subtree,
		hf_v2giso2_struct_iso2_ChargingStatusResType_SAScheduleTupleID,
		tvb, 0, 0,
		chargingstatusres->SAScheduleTupleID);
	proto_item_set_generated(it);

	if (chargingstatusres->EVSEMaxCurrent_isUsed) {
		dissect_v2giso2_physicalvalue(
			&chargingstatusres->EVSEMaxCurrent,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2_PhysicalValueType,
			"EVSEMaxCurrent");
	}

	if (chargingstatusres->MeterInfo_isUsed) {
		dissect_v2giso2_meterinfo(
			&chargingstatusres->MeterInfo,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2_MeterInfoType,
			"MeterInfo");
	}

	if (chargingstatusres->ReceiptRequired_isUsed) {
		it = proto_tree_add_int(subtree,
			hf_v2giso2_struct_iso2_ChargingStatusResType_ReceiptRequired,
			tvb, 0, 0,
			chargingstatusres->ReceiptRequired);
		proto_item_set_generated(it);
	}

	dissect_v2giso2_ac_evsestatus(
		&chargingstatusres->AC_EVSEStatus,
		tvb, pinfo, subtree,
		ett_v2giso2_struct_iso2_AC_EVSEStatusType,
		"AC_EVSEStatus");

	return;
}

static void
dissect_v2giso2_cablecheckreq(
	const struct iso2_CableCheckReqType *req,
	tvbuff_t *tvb,
	packet_info *pinfo,
	proto_tree *tree,
	gint idx,
	const char *subtree_name)
{
	proto_tree *subtree;

	subtree = proto_tree_add_subtree(tree,
		tvb, 0, 0, idx, NULL, subtree_name);

	dissect_v2giso2_dc_evstatus(
		&req->DC_EVStatus,
		tvb, pinfo, subtree,
		ett_v2giso2_struct_iso2_DC_EVStatusType,
		"DC_EVStatus");

	return;
}

static void
dissect_v2giso2_cablecheckres(
	const struct iso2_CableCheckResType *res,
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
		hf_v2giso2_struct_iso2_CableCheckResType_ResponseCode,
		tvb, 0, 0, res->ResponseCode);
	proto_item_set_generated(it);

	dissect_v2giso2_dc_evsestatus(
		&res->DC_EVSEStatus,
		tvb, pinfo, subtree,
		ett_v2giso2_struct_iso2_DC_EVSEStatusType,
		"DC_EVSEStatus");

	it = proto_tree_add_uint(subtree,
		hf_v2giso2_struct_iso2_CableCheckResType_EVSEProcessing,
		tvb, 0, 0, res->EVSEProcessing);
	proto_item_set_generated(it);

	return;
}

static void
dissect_v2giso2_prechargereq(
	const struct iso2_PreChargeReqType *req,
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

	dissect_v2giso2_dc_evstatus(
		&req->DC_EVStatus,
		tvb, pinfo, subtree,
		ett_v2giso2_struct_iso2_DC_EVStatusType,
		"DC_EVStatus");

	dissect_v2giso2_physicalvalue(
		&req->EVTargetVoltage,
		tvb, pinfo, subtree,
		ett_v2giso2_struct_iso2_PhysicalValueType,
		"EVTargetVoltage");
	value = v2giso2_physicalvalue_to_double(&req->EVTargetVoltage);
	it = proto_tree_add_double(subtree,
		hf_v2giso2_ev_target_voltage,
		tvb, 0, 0, value);
	proto_item_set_generated(it);

	dissect_v2giso2_physicalvalue(
		&req->EVTargetCurrent,
		tvb, pinfo, subtree,
		ett_v2giso2_struct_iso2_PhysicalValueType,
		"EVTargetCurrent");
	value = v2giso2_physicalvalue_to_double(&req->EVTargetCurrent);
	it = proto_tree_add_double(subtree,
		hf_v2giso2_ev_target_current,
		tvb, 0, 0, value);
	proto_item_set_generated(it);

	return;
}

static void
dissect_v2giso2_prechargeres(
	const struct iso2_PreChargeResType *res,
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
		hf_v2giso2_struct_iso2_PreChargeResType_ResponseCode,
		tvb, 0, 0, res->ResponseCode);
	proto_item_set_generated(it);

	dissect_v2giso2_dc_evsestatus(
		&res->DC_EVSEStatus,
		tvb, pinfo, subtree,
		ett_v2giso2_struct_iso2_DC_EVSEStatusType,
		"DC_EVSEStatus");

	dissect_v2giso2_physicalvalue(
		&res->EVSEPresentVoltage,
		tvb, pinfo, subtree,
		ett_v2giso2_struct_iso2_PhysicalValueType,
		"EVSEPresentVoltage");
	value = v2giso2_physicalvalue_to_double(&res->EVSEPresentVoltage);
	it = proto_tree_add_double(subtree,
		hf_v2giso2_evse_present_voltage,
		tvb, 0, 0, value);
	proto_item_set_generated(it);

	return;
}

static void
dissect_v2giso2_currentdemandreq(
	const struct iso2_CurrentDemandReqType *req,
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

	dissect_v2giso2_dc_evstatus(
		&req->DC_EVStatus,
		tvb, pinfo, subtree,
		ett_v2giso2_struct_iso2_DC_EVStatusType,
		"DC_EVStatus");

	dissect_v2giso2_physicalvalue(
		&req->EVTargetVoltage,
		tvb, pinfo, subtree,
		ett_v2giso2_struct_iso2_PhysicalValueType,
		"EVTargetVoltage");
	value = v2giso2_physicalvalue_to_double(&req->EVTargetVoltage);
	it = proto_tree_add_double(subtree,
		hf_v2giso2_ev_target_voltage,
		tvb, 0, 0, value);
	proto_item_set_generated(it);

	dissect_v2giso2_physicalvalue(
		&req->EVTargetCurrent,
		tvb, pinfo, subtree,
		ett_v2giso2_struct_iso2_PhysicalValueType,
		"EVTargetCurrent");
	value = v2giso2_physicalvalue_to_double(&req->EVTargetCurrent);
	it = proto_tree_add_double(subtree,
		hf_v2giso2_ev_target_current,
		tvb, 0, 0, value);
	proto_item_set_generated(it);

	it = proto_tree_add_int(subtree,
		hf_v2giso2_struct_iso2_CurrentDemandReqType_ChargingComplete,
		tvb, 0, 0, req->ChargingComplete);
	proto_item_set_generated(it);

	if (req->BulkChargingComplete_isUsed) {
		it = proto_tree_add_int(subtree,
			hf_v2giso2_struct_iso2_CurrentDemandReqType_BulkChargingComplete,
			tvb, 0, 0, req->BulkChargingComplete);
		proto_item_set_generated(it);
	}

	if (req->EVMaximumVoltageLimit_isUsed) {
		dissect_v2giso2_physicalvalue(
			&req->EVMaximumVoltageLimit,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2_PhysicalValueType,
			"EVMaximumVoltageLimit");
		value = v2giso2_physicalvalue_to_double(&req->EVMaximumVoltageLimit);
		it = proto_tree_add_double(subtree,
			hf_v2giso2_ev_maximum_voltage_limit,
			tvb, 0, 0, value);
		proto_item_set_generated(it);
	}

	if (req->EVMaximumCurrentLimit_isUsed) {
		dissect_v2giso2_physicalvalue(
			&req->EVMaximumCurrentLimit,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2_PhysicalValueType,
			"EVMaximumCurrentLimit");
		value = v2giso2_physicalvalue_to_double(&req->EVMaximumCurrentLimit);
		it = proto_tree_add_double(subtree,
			hf_v2giso2_ev_maximum_current_limit,
			tvb, 0, 0, value);
		proto_item_set_generated(it);
	}

	if (req->EVMaximumPowerLimit_isUsed) {
		dissect_v2giso2_physicalvalue(
			&req->EVMaximumPowerLimit,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2_PhysicalValueType,
			"EVMaximumPowerLimit");
		value = v2giso2_physicalvalue_to_double(&req->EVMaximumPowerLimit);
		it = proto_tree_add_double(subtree,
			hf_v2giso2_ev_maximum_power_limit,
			tvb, 0, 0, value);
		proto_item_set_generated(it);
	}

	if (req->RemainingTimeToFullSoC_isUsed) {
		dissect_v2giso2_physicalvalue(
			&req->RemainingTimeToFullSoC,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2_PhysicalValueType,
			"RemainingTimeToFullSoC");
		value = v2giso2_physicalvalue_to_double(&req->RemainingTimeToFullSoC);
		it = proto_tree_add_double(subtree,
			hf_v2giso2_remaining_time_to_full_soc,
			tvb, 0, 0, value);
		proto_item_set_generated(it);
	}

	if (req->RemainingTimeToBulkSoC_isUsed) {
		dissect_v2giso2_physicalvalue(
			&req->RemainingTimeToBulkSoC,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2_PhysicalValueType,
			"RemainingTimeToBulkSoC");
		value = v2giso2_physicalvalue_to_double(&req->RemainingTimeToBulkSoC);
		it = proto_tree_add_double(subtree,
			hf_v2giso2_remaining_time_to_bulk_soc,
			tvb, 0, 0, value);
		proto_item_set_generated(it);
	}

	return;
}

static void
dissect_v2giso2_currentdemandres(
	const struct iso2_CurrentDemandResType *res,
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
		hf_v2giso2_struct_iso2_CurrentDemandResType_ResponseCode,
		tvb, 0, 0, res->ResponseCode);
	proto_item_set_generated(it);

	dissect_v2giso2_dc_evsestatus(
		&res->DC_EVSEStatus,
		tvb, pinfo, subtree,
		ett_v2giso2_struct_iso2_DC_EVSEStatusType,
		"DC_EVSEStatus");

	dissect_v2giso2_physicalvalue(
		&res->EVSEPresentVoltage,
		tvb, pinfo, subtree,
		ett_v2giso2_struct_iso2_PhysicalValueType,
		"EVSEPresentVoltage");
	value = v2giso2_physicalvalue_to_double(&res->EVSEPresentVoltage);
	it = proto_tree_add_double(subtree,
		hf_v2giso2_evse_present_voltage,
		tvb, 0, 0, value);
	proto_item_set_generated(it);

	dissect_v2giso2_physicalvalue(
		&res->EVSEPresentCurrent,
		tvb, pinfo, subtree,
		ett_v2giso2_struct_iso2_PhysicalValueType,
		"EVSEPresentCurrent");
	value = v2giso2_physicalvalue_to_double(&res->EVSEPresentCurrent);
	it = proto_tree_add_double(subtree,
		hf_v2giso2_evse_present_current,
		tvb, 0, 0, value);
	proto_item_set_generated(it);

	it = proto_tree_add_int(subtree,
		hf_v2giso2_struct_iso2_CurrentDemandResType_EVSECurrentLimitAchieved,
		tvb, 0, 0, res->EVSECurrentLimitAchieved);
	proto_item_set_generated(it);

	it = proto_tree_add_int(subtree,
		hf_v2giso2_struct_iso2_CurrentDemandResType_EVSEVoltageLimitAchieved,
		tvb, 0, 0, res->EVSEVoltageLimitAchieved);
	proto_item_set_generated(it);

	it = proto_tree_add_int(subtree,
		hf_v2giso2_struct_iso2_CurrentDemandResType_EVSEPowerLimitAchieved,
		tvb, 0, 0, res->EVSEPowerLimitAchieved);
	proto_item_set_generated(it);

	if (res->EVSEMaximumVoltageLimit_isUsed) {
		dissect_v2giso2_physicalvalue(
			&res->EVSEMaximumVoltageLimit,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2_PhysicalValueType,
			"EVSEMaximumVoltageLimit");
		value = v2giso2_physicalvalue_to_double(&res->EVSEMaximumVoltageLimit);
		it = proto_tree_add_double(subtree,
			hf_v2giso2_evse_maximum_voltage_limit,
			tvb, 0, 0, value);
		proto_item_set_generated(it);
	}
	if (res->EVSEMaximumCurrentLimit_isUsed) {
		dissect_v2giso2_physicalvalue(
			&res->EVSEMaximumCurrentLimit,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2_PhysicalValueType,
			"EVSEMaximumCurrentLimit");
		value = v2giso2_physicalvalue_to_double(&res->EVSEMaximumCurrentLimit);
		it = proto_tree_add_double(subtree,
			hf_v2giso2_evse_maximum_current_limit,
			tvb, 0, 0, value);
		proto_item_set_generated(it);
	}
	if (res->EVSEMaximumPowerLimit_isUsed) {
		dissect_v2giso2_physicalvalue(
			&res->EVSEMaximumPowerLimit,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2_PhysicalValueType,
			"EVSEMaximumPowerLimit");
		value = v2giso2_physicalvalue_to_double(&res->EVSEMaximumPowerLimit);
		it = proto_tree_add_double(subtree,
			hf_v2giso2_evse_maximum_power_limit,
			tvb, 0, 0, value);
		proto_item_set_generated(it);
	}

	exi_add_characters(subtree,
		hf_v2giso2_struct_iso2_CurrentDemandResType_EVSEID,
		tvb,
		res->EVSEID.characters,
		res->EVSEID.charactersLen,
		sizeof(res->EVSEID.characters));

	it = proto_tree_add_uint(subtree,
		hf_v2giso2_struct_iso2_CurrentDemandResType_SAScheduleTupleID,
		tvb, 0, 0, res->SAScheduleTupleID);
	proto_item_set_generated(it);

	if (res->MeterInfo_isUsed) {
		dissect_v2giso2_meterinfo(
			&res->MeterInfo,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2_MeterInfoType,
			"MeterInfo");
	}

	if (res->ReceiptRequired_isUsed) {
		it = proto_tree_add_int(subtree,
			hf_v2giso2_struct_iso2_CurrentDemandResType_ReceiptRequired,
			tvb, 0, 0, res->ReceiptRequired);
		proto_item_set_generated(it);
	}

	return;
}

static void
dissect_v2giso2_weldingdetectionreq(
	const struct iso2_WeldingDetectionReqType *req,
	tvbuff_t *tvb,
	packet_info *pinfo,
	proto_tree *tree,
	gint idx,
	const char *subtree_name)
{
	proto_tree *subtree;

	subtree = proto_tree_add_subtree(tree,
		tvb, 0, 0, idx, NULL, subtree_name);

	dissect_v2giso2_dc_evstatus(
		&req->DC_EVStatus,
		tvb, pinfo, subtree,
		ett_v2giso2_struct_iso2_DC_EVStatusType, "DC_EVStatus");

	return;
}

static void
dissect_v2giso2_weldingdetectionres(
	const struct iso2_WeldingDetectionResType *res,
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
		hf_v2giso2_struct_iso2_WeldingDetectionResType_ResponseCode,
		tvb, 0, 0, res->ResponseCode);
	proto_item_set_generated(it);

	dissect_v2giso2_dc_evsestatus(
		&res->DC_EVSEStatus,
		tvb, pinfo, subtree,
		ett_v2giso2_struct_iso2_DC_EVSEStatusType, "DC_EVSEStatus");

	dissect_v2giso2_physicalvalue(
		&res->EVSEPresentVoltage,
		tvb, pinfo, subtree,
		ett_v2giso2_struct_iso2_PhysicalValueType,
		"EVSEPresentVoltage");
	value = v2giso2_physicalvalue_to_double(&res->EVSEPresentVoltage);
	it = proto_tree_add_double(subtree,
		hf_v2giso2_evse_present_voltage,
		tvb, 0, 0, value);
	proto_item_set_generated(it);

	return;
}


static void
dissect_v2giso2_body(const struct iso2_BodyType *body,
		     tvbuff_t *tvb,
		     packet_info *pinfo,
		     proto_tree *tree,
		     gint idx,
		     const char *subtree_name)
{
	proto_tree *subtree;

	subtree = proto_tree_add_subtree(tree,
		tvb, 0, 0, idx, NULL, subtree_name);

	if (body->SessionSetupReq_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO, "SessionSetupReq");
		dissect_v2giso2_sessionsetupreq(
			&body->SessionSetupReq, tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2_SessionSetupReqType,
			"SessionSetupReq");
	}
	if (body->SessionSetupRes_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO, "SessionSetupRes");
		dissect_v2giso2_sessionsetupres(
			&body->SessionSetupRes, tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2_SessionSetupResType,
			"SessionSetupRes");
	}

	if (body->ServiceDiscoveryReq_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO, "ServiceDiscoveryReq");
		dissect_v2giso2_servicediscoveryreq(
			&body->ServiceDiscoveryReq, tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2_ServiceDiscoveryReqType,
			"ServiceDiscoveryReq");
	}
	if (body->ServiceDiscoveryRes_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO, "ServiceDiscoveryRes");
		dissect_v2giso2_servicediscoveryres(
			&body->ServiceDiscoveryRes, tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2_ServiceDiscoveryResType,
			"ServiceDiscoveryRes");
	}

	if (body->ServiceDetailReq_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO, "ServiceDetailReq");
		dissect_v2giso2_servicedetailreq(
			&body->ServiceDetailReq, tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2_ServiceDetailReqType,
			"ServiceDetailReq");
	}
	if (body->ServiceDetailRes_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO, "ServiceDetailRes");
		dissect_v2giso2_servicedetailres(
			&body->ServiceDetailRes, tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2_ServiceDetailResType,
			"ServiceDetailRes");
	}

	if (body->PaymentServiceSelectionReq_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO,
			"PaymentServiceSelectionReq");
		dissect_v2giso2_paymentserviceselectionreq(
			&body->PaymentServiceSelectionReq, tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2_PaymentServiceSelectionReqType,
			"PaymentServiceSelectionReq");
	}
	if (body->PaymentServiceSelectionRes_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO,
			"PaymentServiceSelectionRes");
		dissect_v2giso2_paymentserviceselectionres(
			&body->PaymentServiceSelectionRes, tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2_PaymentServiceSelectionResType,
			"PaymentServiceSelectionRes");
	}

	if (body->PaymentDetailsReq_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO, "PaymentDetailsReq");
		dissect_v2giso2_paymentdetailsreq(
			&body->PaymentDetailsReq, tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2_PaymentDetailsReqType,
			"PaymentDetailsReq");
	}
	if (body->PaymentDetailsRes_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO, "PaymentDetailsRes");
		dissect_v2giso2_paymentdetailsres(
			&body->PaymentDetailsRes, tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2_PaymentDetailsResType,
			"PaymentDetailsRes");
	}

	if (body->AuthorizationReq_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO, "AuthorizationReq");
		dissect_v2giso2_authorizationreq(
			&body->AuthorizationReq, tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2_AuthorizationReqType,
			"AuthorizationReq");
	}
	if (body->AuthorizationRes_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO, "AuthorizationRes");
		dissect_v2giso2_authorizationres(
			&body->AuthorizationRes, tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2_AuthorizationResType,
			"AuthorizationRes");
	}

	if (body->ChargeParameterDiscoveryReq_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO,
			"ChargeParameterDiscoveryReq");
		dissect_v2giso2_chargeparameterdiscoveryreq(
			&body->ChargeParameterDiscoveryReq, tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2_ChargeParameterDiscoveryReqType,
			"ChargeParameterDiscoveryReq");
	}
	if (body->ChargeParameterDiscoveryRes_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO,
			"ChargeParameterDiscoveryRes");
		dissect_v2giso2_chargeparameterdiscoveryres(
			&body->ChargeParameterDiscoveryRes, tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2_ChargeParameterDiscoveryResType,
			"ChargeParameterDiscoveryRes");
	}

	if (body->PowerDeliveryReq_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO, "PowerDeliveryReq");
		dissect_v2giso2_powerdeliveryreq(
			&body->PowerDeliveryReq, tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2_PowerDeliveryReqType,
			"PowerDeliveryReq");
	}
	if (body->PowerDeliveryRes_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO, "PowerDeliveryRes");
		dissect_v2giso2_powerdeliveryres(
			&body->PowerDeliveryRes, tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2_PowerDeliveryResType,
			"PowerDeliveryRes");
	}

	if (body->MeteringReceiptReq_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO, "MeteringReceiptReq");
		dissect_v2giso2_meteringreceiptreq(
			&body->MeteringReceiptReq, tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2_MeteringReceiptReqType,
			"MeteringReceiptReq");
	}
	if (body->MeteringReceiptRes_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO, "MeteringReceiptRes");
		dissect_v2giso2_meteringreceiptres(
			&body->MeteringReceiptRes, tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2_MeteringReceiptResType,
			"MeteringReceiptRes");
	}

	if (body->SessionStopReq_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO, "SessionStopReq");
		dissect_v2giso2_sessionstopreq(
			&body->SessionStopReq, tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2_SessionStopReqType,
			"SessionStopReq");
	}
	if (body->SessionStopRes_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO, "SessionStopRes");
		dissect_v2giso2_sessionstopres(
			&body->SessionStopRes, tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2_SessionStopResType,
			"SessionStopRes");
	}

	if (body->CertificateUpdateReq_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO, "CertificateUpdateReq");
		dissect_v2giso2_certificateupdatereq(
			&body->CertificateUpdateReq, tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2_CertificateUpdateReqType,
			"CertificateUpdateReq");
	}
	if (body->CertificateUpdateRes_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO, "CertificateUpdateRes");
		dissect_v2giso2_certificateupdateres(
			&body->CertificateUpdateRes, tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2_CertificateUpdateResType,
			"CertificateUpdateRes");
	}

	if (body->CertificateInstallationReq_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO,
			"CertificateInstallationReq");
		dissect_v2giso2_certificateinstallationreq(
			&body->CertificateInstallationReq, tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2_CertificateInstallationReqType,
			"CertificateInstallationReq");
	}
	if (body->CertificateInstallationRes_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO,
			"CertificateInstallationRes");
		dissect_v2giso2_certificateinstallationres(
			&body->CertificateInstallationRes, tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2_CertificateInstallationResType,
			"CertificateInstallationRes");
	}

	if (body->ChargingStatusReq_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO, "ChargingStatusReq");
		dissect_v2giso2_chargingstatusreq(
			&body->ChargingStatusReq, tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2_ChargingStatusReqType,
			"ChargingStatusReq");
	}
	if (body->ChargingStatusRes_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO, "ChargingStatusRes");
		dissect_v2giso2_chargingstatusres(
			&body->ChargingStatusRes, tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2_ChargingStatusResType,
			"ChargingStatusRes");
	}

	if (body->CableCheckReq_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO, "CableCheckReq");
		dissect_v2giso2_cablecheckreq(
			&body->CableCheckReq, tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2_CableCheckReqType,
			"CableCheckReq");
	}
	if (body->CableCheckRes_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO, "CableCheckRes");
		dissect_v2giso2_cablecheckres(
			&body->CableCheckRes, tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2_CableCheckResType,
			"CableCheckRes");
	}

	if (body->PreChargeReq_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO, "PreChargeReq");
		dissect_v2giso2_prechargereq(
			&body->PreChargeReq, tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2_PreChargeReqType,
			"PreChargeReq");
	}
	if (body->PreChargeRes_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO, "PreChargeRes");
		dissect_v2giso2_prechargeres(
			&body->PreChargeRes, tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2_PreChargeResType,
			"PreChargeRes");
	}

	if (body->CurrentDemandReq_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO, "CurrentDemandReq");
		dissect_v2giso2_currentdemandreq(
			&body->CurrentDemandReq, tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2_CurrentDemandReqType,
			"CurrentDemandReq");
	}
	if (body->CurrentDemandRes_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO, "CurrentDemandRes");
		dissect_v2giso2_currentdemandres(
			&body->CurrentDemandRes, tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2_CurrentDemandResType,
			"CurrentDemandRes");
	}

	if (body->WeldingDetectionReq_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO, "WeldingDetectionReq");
		dissect_v2giso2_weldingdetectionreq(
			&body->WeldingDetectionReq, tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2_WeldingDetectionReqType,
			"WeldingDetectionReq");
	}
	if (body->WeldingDetectionRes_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO, "WeldingDetectionRes");
		dissect_v2giso2_weldingdetectionres(
			&body->WeldingDetectionRes, tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2_WeldingDetectionResType,
			"WeldingDetectionRes");
	}

	return;
}


static int
dissect_v2giso2(tvbuff_t *tvb,
		packet_info *pinfo, proto_tree *tree _U_, void *data _U_)
{
	proto_tree *v2giso2_tree;
	size_t size;
	exi_bitstream_t stream;
	int errn;
	struct iso2_exiDocument *exiiso2;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "ISO2");
	/* Clear the info column */
	col_clear(pinfo->cinfo, COL_INFO);

	size = tvb_reported_length(tvb);
	exi_bitstream_init(&stream,
			   tvb_memdup(wmem_packet_scope(), tvb, 0, size),
			   size, 0, NULL);

	exiiso2 = wmem_alloc(pinfo->pool, sizeof(*exiiso2));
	errn = decode_iso2_exiDocument(&stream, exiiso2);
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
	v2giso2_tree = proto_tree_add_subtree(tree,
		tvb, 0, 0, ett_v2giso2, NULL, "V2G ISO2 Message");

	dissect_v2giso2_header(&exiiso2->V2G_Message.Header,
		tvb, pinfo, v2giso2_tree,
		ett_v2giso2_header, "Header");
	dissect_v2giso2_body(& exiiso2->V2G_Message.Body,
		tvb, pinfo, v2giso2_tree, ett_v2giso2_body, "Body");

	wmem_free(pinfo->pool, exiiso2);
	return tvb_captured_length(tvb);
}


void
proto_register_v2giso2(void)
{

	static hf_register_info hf[] = {
		/* struct iso2_MessageHeaderType */
		{ &hf_v2giso2_struct_iso2_MessageHeaderType_SessionID,
		  { "SessionID", "v2giso2.struct.messageheader.sessionid",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso2_NotificationType */
		{ &hf_v2giso2_struct_iso2_NotificationType_FaultCode,
		  { "FaultCode", "v2giso2.struct.notification.faultcode",
		    FT_UINT16, BASE_DEC, VALS(v2giso2_fault_code_names),
		    0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2_NotificationType_FaultMsg,
		  { "FaultMsg", "v2giso2.struct.notification.faultmsg",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso2_SignatureType */
		{ &hf_v2giso2_struct_iso2_SignatureType_Id,
		  { "Id", "v2giso2.struct.signature.id",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso2_SignedInfoType */
		{ &hf_v2giso2_struct_iso2_SignedInfoType_Id,
		  { "Id", "v2giso2.struct.signedinfo.id",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso2_CanonicalizationMethodType */
		{ &hf_v2giso2_struct_iso2_CanonicalizationMethodType_Algorithm,
		  { "Algorithm",
		    "v2giso2.struct.canonicalizationmethod.algorithm",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2_CanonicalizationMethodType_ANY,
		  { "ANY",
		    "v2giso2.struct.canonicalizationmethod.any",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso2_SignatureMethodType */
		{ &hf_v2giso2_struct_iso2_SignatureMethodType_Algorithm,
		  { "Algorithm", "v2giso2.struct.signaturemethod.algorithm",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2_SignatureMethodType_HMACOutputLength,
		  { "HMACOutputLength",
		    "v2giso2.struct.signaturemethod.hmacoutputlength",
		    FT_INT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2_SignatureMethodType_ANY,
		  { "ANY", "v2giso2.struct.signaturemethod.any",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso2_ReferenceType */
		{ &hf_v2giso2_struct_iso2_ReferenceType_Id,
		  { "Id", "v2giso2.struct.reference.id",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2_ReferenceType_URI,
		  { "URI", "v2giso2.struct.reference.uri",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2_ReferenceType_Type,
		  { "Type", "v2giso2.struct.reference.type",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2_ReferenceType_DigestValue,
		  { "DigestValue", "v2giso2.struct.reference.digestvalue",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso2_SignatureValueType */
		{ &hf_v2giso2_struct_iso2_SignatureValueType_Id,
		  { "Id", "v2giso2.struct.signavturevalue.id",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2_SignatureValueType_CONTENT,
		  { "CONTENT", "v2giso2.struct.signaturevalue.content",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso2_ObjectType */
		{ &hf_v2giso2_struct_iso2_ObjectType_Id,
		  { "Id", "v2giso2.struct.object.id",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2_ObjectType_MimeType,
		  { "MimeType", "v2giso2.struct.object.mimetype",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2_ObjectType_Encoding,
		  { "Encoding", "v2giso2.struct.object.encoding",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2_ObjectType_ANY,
		  { "ANY", "v2giso2.struct.object.any",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso2_TransformType */
		{ &hf_v2giso2_struct_iso2_TransformType_Algorithm,
		  { "Algorithm", "v2giso2.struct.transform.algorithm",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2_TransformType_ANY,
		  { "ANY", "v2giso2.struct.transform.any",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2_TransformType_XPath,
		  { "XPath", "v2giso2.struct.transform.xpath",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso2_DigestMethodType */
		{ &hf_v2giso2_struct_iso2_DigestMethodType_Algorithm,
		  { "Algorithm", "v2giso2.struct.digestmethod.algorithm",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2_DigestMethodType_ANY,
		  { "ANY", "v2giso2.struct.digestmethod.any",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso2_KeyInfoType */
		{ &hf_v2giso2_struct_iso2_KeyInfoType_Id,
		  { "Id", "v2giso2.struct.keyinfo.id",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2_KeyInfoType_KeyName,
		  { "KeyName", "v2giso2.struct.keyinfo.keyname",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2_KeyInfoType_MgmtData,
		  { "MgmtData", "v2giso2.struct.keyinfo.mgmtdata",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2_KeyInfoType_ANY,
		  { "ANY", "v2giso2.struct.keyinfo.any",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso2_RetrievalMethodType */
		{ &hf_v2giso2_struct_iso2_RetrievalMethodType_URI,
		  { "URI", "v2giso2.struct.retrievalmethod.uri",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2_RetrievalMethodType_Type,
		  { "Type", "v2giso2.struct.retrievalmethod.type",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso2_KeyValueType */
		{ &hf_v2giso2_struct_iso2_KeyValueType_ANY,
		  { "ANY", "v2giso2.struct.keyvalue.any",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso2_DSAKeyValueType */
		{ &hf_v2giso2_struct_iso2_DSAKeyValueType_P,
		  { "P", "v2giso2.struct.dsakeyvalue.p",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2_DSAKeyValueType_Q,
		  { "Q", "v2giso2.struct.dsakeyvalue.q",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2_DSAKeyValueType_G,
		  { "G", "v2giso2.struct.dsakeyvalue.g",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2_DSAKeyValueType_Y,
		  { "Y", "v2giso2.struct.dsakeyvalue.y",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2_DSAKeyValueType_J,
		  { "J", "v2giso2.struct.dsakeyvalue.j",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2_DSAKeyValueType_Seed,
		  { "Seed", "v2giso2.struct.dsakeyvalue.seed",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2_DSAKeyValueType_PgenCounter,
		  { "PgenCounter", "v2giso2.struct.dsakeyvalue.pgencounter",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso2_RSAKeyValueType */
		{ &hf_v2giso2_struct_iso2_RSAKeyValueType_Modulus,
		  { "Modulus", "v2giso2.struct.rsakeyvalue.modulus",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2_RSAKeyValueType_Exponent,
		  { "Exponent", "v2giso2.struct.rsakeyvalue.exponent",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso2_X509DataType */
		{ &hf_v2giso2_struct_iso2_X509DataType_X509SKI,
		  { "X509SKI", "v2giso2.struct.x509data.x509ski",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2_X509DataType_X509SubjectName,
		  { "X509SubjectName",
		    "v2giso2.struct.x509data.x509subjectname",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2_X509DataType_X509Certificate,
		  { "X509Certificate",
		    "v2giso2.struct.x509data.x509certificate",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2_X509DataType_X509CRL,
		  { "X509CRL", "v2giso2.struct.x509data.x509crl",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2_X509DataType_ANY,
		  { "ANY", "v2giso2.struct.x509data.any",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso2_X509IssuerSerialType */
		{ &hf_v2giso2_struct_iso2_X509IssuerSerialType_X509IssuerName,
		  { "X509IssuerName",
		    "v2giso2.struct.x509issuerserial.x509issuername",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2_X509IssuerSerialType_X509SerialNumber,
		  { "X509SerialNumber",
		    "v2giso2.struct.x509issuerserial.x509serialnumber",
		    FT_INT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso2_PGPDataType */
		{ &hf_v2giso2_struct_iso2_PGPDataType_PGPKeyID,
		  { "PGPKeyID", "v2giso2.struct.pgpdata.pgpkeyid",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2_PGPDataType_PGPKeyPacket,
		  { "PGPKeyPacket", "v2giso2.struct.pgpdata.pgpkeypacket",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2_PGPDataType_ANY,
		  { "ANY", "v2giso2.struct.pgpdata.any",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso2_SPKIDataType */
		{ &hf_v2giso2_struct_iso2_SPKIDataType_SPKISexp,
		  { "SPKISexp", "v2giso2.struct.spkidata.spkisexp",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2_SPKIDataType_ANY,
		  { "ANY", "v2giso2.struct.spkidata.any",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso2_ChargeServiceType */
		{ &hf_v2giso2_struct_iso2_ChargeServiceType_ServiceID,
		  { "ServiceID", "v2giso2.struct.chargeservice.serviceid",
		    FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2_ChargeServiceType_ServiceName,
		  { "ServiceName", "v2giso2.struct.chargeservice.servicename",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2_ChargeServiceType_ServiceCategory,
		  { "ServiceCategory",
		    "v2giso2.struct.chargeservice.servicecategory",
		    FT_UINT32, BASE_DEC, VALS(v2giso2_service_category_names),
		    0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2_ChargeServiceType_ServiceScope,
		  { "ServiceScope",
		    "v2giso2.struct.chargeservice.servicescope",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2_ChargeServiceType_FreeService,
		  { "FreeService", "v2giso2.struct.chargeservice.freeservice",
		    FT_INT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso2_PaymentOptionListType */
		{ &hf_v2giso2_struct_iso2_PaymentOptionLstType_PaymentOption,
		  { "PaymentOption",
		    "v2giso2.struct.paymentoptionlist.paymentoption",
		    FT_UINT32, BASE_DEC, VALS(v2giso2_payment_option_names),
		    0x0, NULL, HFILL }
		},

		{ &hf_v2giso2_struct_iso2_SupportedEnergyTransferModeType_EnergyTransferMode,
		  { "EnergyTransferMode",
		    "v2giso2.struct.supportedenergytransfermode.energytransfermode",
		    FT_UINT32, BASE_DEC, VALS(v2giso2_energy_transfer_mode_names),
		    0x0, NULL, HFILL }
		},

		/* struct iso2_ServiceType */
		{ &hf_v2giso2_struct_iso2_ServiceType_ServiceID,
		  { "ServiceID", "v2giso2.struct.service.serviceid",
		    FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2_ServiceType_ServiceName,
		  { "ServiceName", "v2giso2.struct.service.servicename",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2_ServiceType_ServiceCategory,
		  { "ServiceCategory", "v2giso2.struct.service.servicecategory",
		    FT_UINT32, BASE_DEC, VALS(v2giso2_service_category_names),
		    0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2_ServiceType_ServiceScope,
		  { "ServiceScope", "v2giso2.struct.service.servicescope",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2_ServiceType_FreeService,
		  { "FreeService", "v2giso2.struct.service.freeservice",
		    FT_INT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso2_ParameterSetType */
		{ &hf_v2giso2_struct_iso2_ParameterSetType_ParameterSetID,
		  { "ParameterSetID",
		    "v2giso2.struct.parameterset.parametersetid",
		    FT_INT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso2_ParameterType */
		{ &hf_v2giso2_struct_iso2_ParameterType_Name,
		  { "Name", "v2giso2.struct.parameter.name",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2_ParameterType_boolValue,
		  { "boolValue", "v2giso2.struct.parameter.boolvalue",
		    FT_INT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2_ParameterType_byteValue,
		  { "byteValue", "v2giso2.struct.parameter.bytevalue",
		    FT_INT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2_ParameterType_shortValue,
		  { "shortValue", "v2giso2.struct.parameter.shortvalue",
		    FT_INT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2_ParameterType_intValue,
		  { "intValue", "v2giso2.struct.parameter.intvalue",
		    FT_INT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2_ParameterType_stringValue,
		  { "stringValue", "v2giso2.struct.parameter.stringvalue",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso2_PhysicalValueType */
		{ &hf_v2giso2_struct_iso2_PhysicalValueType_Multiplier,
		  { "Multiplier", "v2giso2.struct.physicalvalue.multiplier",
		    FT_INT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2_PhysicalValueType_Unit,
		  { "Unit", "v2giso2.struct.physicalvalue.unit",
		    FT_UINT32, BASE_DEC, VALS(v2giso2_unit_symbol_names),
		    0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2_PhysicalValueType_Value,
		  { "Value", "v2giso2.struct.physicalvalue.value",
		    FT_INT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso2_SelectedServiceType */
		{ &hf_v2giso2_struct_iso2_SelectedServiceType_ServiceID,
		  { "ServiceID", "v2giso2.struct.selectedservice.serviceid",
		    FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2_SelectedServiceType_ParameterSetID,
		  { "ParameterSetID",
		    "v2giso2.struct.selectedservice.parametersetid",
		    FT_INT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso2_CertificateChainType */
		{ &hf_v2giso2_struct_iso2_CertificateChainType_Id,
		  { "Id", "v2giso2.struct.certificatechain.id",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2_CertificateChainType_Certificate,
		  { "Certificate",
		    "v2giso2.struct.certificatechain.certificate",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso2_SubCertificatesType */
		{ &hf_v2giso2_struct_iso2_SubCertificatesType_Certificate,
		  { "Certificate",
		    "v2giso2.struct.subcertificates.certificate",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso2_AC_EVChargeParameterType */
		{ &hf_v2giso2_struct_iso2_AC_EVChargeParameterType_DepartureTime,
		  { "DepartureTime",
		    "v2giso2.struct.ac_evchargeparameter.departuretime",
		    FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso2_DC_EVChargeParameterType */
		{ &hf_v2giso2_struct_iso2_DC_EVChargeParameterType_DepartureTime,
		  { "DepartureTime",
		    "v2giso2.struct.dc_evchargeparameter.departuretime",
		    FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2_DC_EVChargeParameterType_FullSOC,
		  { "FullSOC", "v2giso2.struct.dc_evchargeparameter.fullsoc",
		    FT_INT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2_DC_EVChargeParameterType_BulkSOC,
		  { "BulkSOC", "v2giso2.struct.dc_evchargeparameter.bulksoc",
		    FT_INT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso2_DC_EVStatusType */
		{ &hf_v2giso2_struct_iso2_DC_EVStatusType_EVReady,
		  { "EVReady", "v2giso2.struct.dc_evstatus.evready",
		    FT_INT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2_DC_EVStatusType_EVErrorCode,
		  { "EVErrorCode", "v2giso2.struct.dc_evstatus.everrorcode",
		    FT_UINT32, BASE_DEC, VALS(v2giso2_dc_everrorcode_names),
		    0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2_DC_EVStatusType_EVRESSSOC,
		  { "EVRESSSOC", "v2giso2.struct.dc_evstatus.evressoc",
		    FT_INT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso2_EVSEStatusType */
		{ &hf_v2giso2_struct_iso2_EVSEStatusType_NotificationMaxDelay,
		  { "NotificationMaxDelay",
		    "v2giso2.struct.evsestatus.notificationmaxdelay",
		    FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2_EVSEStatusType_EVSENotification,
		  { "EVSENotification",
		    "v2giso2.struct.evsestatus.evsenotification",
		    FT_UINT32, BASE_DEC, VALS(v2giso2_evsenotification_names),
		    0x0, NULL, HFILL }
		},

		/* struct iso2_AC_EVSEStatusType */
		{ &hf_v2giso2_struct_iso2_AC_EVSEStatusType_NotificationMaxDelay,
		  { "NotificationMaxDelay",
		    "v2giso2.struct.ac_evsestatus.notificationmaxdelay",
		    FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2_AC_EVSEStatusType_EVSENotification,
		  { "EVSENotification",
		    "v2giso2.struct.ac_evsestatus.evsenotification",
		    FT_UINT32, BASE_DEC, VALS(v2giso2_evsenotification_names),
		    0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2_AC_EVSEStatusType_RCD,
		  { "RCD", "v2giso2.struct.ac_evsestatus.rcd",
		    FT_INT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso2_DC_EVSEStatusType */
		{ &hf_v2giso2_struct_iso2_DC_EVSEStatusType_NotificationMaxDelay,
		  { "NotificationMaxDelay",
		    "v2giso2.struct.dc_evsestatus.notificationmaxdelay",
		    FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2_DC_EVSEStatusType_EVSENotification,
		  { "EVSENotification",
		    "v2giso2.struct.dc_evsestatus.evsenotification",
		    FT_UINT32, BASE_DEC, VALS(v2giso2_evsenotification_names),
		    0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2_DC_EVSEStatusType_EVSEIsolationStatus,
		  { "EVSEIsolationStatus",
		    "v2giso2.struct.dc_evsestatus.evseisolationstatus",
		    FT_UINT32, BASE_DEC,
		    VALS(v2giso2_evseisolation_level_names), 0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2_DC_EVSEStatusType_EVSEStatusCode,
		  { "EVSEStatusCode",
		    "v2giso2.struct.dc_evsestatus.evsestatuscode",
		    FT_UINT32, BASE_DEC, VALS(v2giso2_dc_evsestatuscode_names),
		    0x0, NULL, HFILL }
		},

		/* struct iso2_SAScheduleTupleType */
		{ &hf_v2giso2_struct_iso2_SAScheduleTupleType_SAScheduleTupleID,
		  { "SAScheduleTupleID",
		    "v2giso2.struct.sascheduletuple.sascheduletupleid",
		    FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso2_SalesTariffType */
		{ &hf_v2giso2_struct_iso2_SalesTariffType_Id,
		  { "Id", "v2giso2.struct.salestariff.id",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2_SalesTariffType_SalesTariffDescription,
		  { "SalesTariffDescription",
		    "v2giso2.struct.salestariff.salestariffdescription",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2_SalesTariffType_NumEPriceLevels,
		  { "NumEPriceLevels",
		    "v2giso2.struct.salestariff.numepricelevels",
		    FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso2_SalesTariffEntryType */
		{ &hf_v2giso2_struct_iso2_SalesTariffEntryType_EPriceLevel,
		  { "EPriceLevel",
		    "v2giso2.struct.salestariffentry.epricelevel",
		    FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso2_RelativeTimeIntervalType */
		{ &hf_v2giso2_struct_iso2_RelativeTimeIntervalType_start,
		  { "start", "v2giso2.struct.relativetimeinterval.start",
		    FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2_RelativeTimeIntervalType_duration,
		  { "duration", "v2giso2.struct.relativetimeinterval.duration",
		    FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso2_CostType */
		{ &hf_v2giso2_struct_iso2_CostType_costKind,
		  { "costKind", "v2giso2.struct.cost.costkind",
		    FT_UINT32, BASE_DEC, VALS(v2giso2_cost_kind_names),
		    0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2_CostType_amount,
		  { "amount", "v2giso2.struct.cost.amount",
		    FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2_CostType_amountMultiplier,
		  { "amountMultiplier", "v2giso2.struct.cost.amountmultiplier",
		    FT_INT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso2_ProfileEntryType */
		{ &hf_v2giso2_struct_iso2_ProfileEntryType_ChargingProfileEntryStart,
		  { "ChargingProfileEntryStart",
		    "v2giso2.struct.profilentry.chargingprofileentrystart",
		    FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2_ProfileEntryType_ChargingProfileEntryMaxNumberOfPhasesInUse,
		  { "ChargingProfileEntryMaxNumberOfPhasesInUse",
		    "v2giso2.struct.profilentry.chargingprofileentrymaxnumberofphasesinuses",
		    FT_INT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso2_DC_EVPowerDeliveryParameterType */
		{ &hf_v2giso2_struct_iso2_DC_EVPowerDeliveryParameterType_BulkChargingComplete,
		  { "BulkChargingComplete",
		    "v2giso2.struct.dc_evpowerdeliveryparameter.bulkchargingcomplete",
		    FT_INT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2_DC_EVPowerDeliveryParameterType_ChargingComplete,
		  { "ChargingComplete",
		    "v2giso2.struct.dc_evpowerdeliveryparameter.chargingcomplete",
		    FT_INT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso2_MeterInfoType */
		{ &hf_v2giso2_struct_iso2_MeterInfoType_MeterID,
		  { "MeterID", "v2giso2.struct.meterinfo.meterid",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2_MeterInfoType_MeterReading,
		  { "MeterReading", "v2giso2.struct.meterinfo.meterreading",
		    FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2_MeterInfoType_SigMeterReading,
		  { "SigMeterReading",
		    "v2giso2.struct.meterinfo.sigmeterreading",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2_MeterInfoType_MeterStatus,
		  { "MeterStatus", "v2giso2.struct.meterinfo.meterstatus",
		    FT_INT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2_MeterInfoType_TMeter,
		  { "TMeter", "v2giso2.struct.meterinfo.tmeter",
		    FT_INT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso2_ContractSignatureEncryptedPrivateKeyType */
		{ &hf_v2giso2_struct_iso2_ContractSignatureEncryptedPrivateKeyType_Id,
		  { "Id",
		    "v2giso2.struct.contractsignatureencryptedprivatekey.id",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2_ContractSignatureEncryptedPrivateKeyType_CONTENT,
		  { "CONTENT",
		    "v2giso2.struct.contractsignatureencryptedprivatekey.content",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso2_DiffieHellmanPublickeyType */
		{ &hf_v2giso2_struct_iso2_DiffieHellmanPublickeyType_Id,
		  { "Id", "v2giso2.struct.diffiehellmanpublickey.id",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2_DiffieHellmanPublickeyType_CONTENT,
		  { "CONTENT", "v2giso2.struct.diffiehellmanpublickey.content",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso2_EMAIDType */
		{ &hf_v2giso2_struct_iso2_EMAIDType_Id,
		  { "Id", "v2giso2.struct.emaid.id",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2_EMAIDType_CONTENT,
		  { "CONTENT", "v2giso2.struct.emaid.content",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso2_SessionSetupReqType */
		{ &hf_v2giso2_struct_iso2_SessionSetupReqType_EVCCID,
		  { "EVCCID", "v2giso2.struct.sessionsetupreq.evccid",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		/* struct iso2_SessionSetupReqType */
		{ &hf_v2giso2_struct_iso2_SessionSetupResType_ResponseCode,
		  { "ResponseCode",
		    "v2giso2.struct.sessionsetupres.responsecode",
		    FT_UINT32, BASE_DEC, VALS(v2giso2_response_code_names),
		    0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2_SessionSetupResType_EVSEID,
		  { "EVSEID", "v2giso2.struct.sessionsetupres.evseid",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2_SessionSetupResType_EVSETimeStamp,
		  { "EVSETimeStamp",
		    "v2giso2.struct.sessionsetupres.evsetimestamp",
		    FT_INT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso2_ServiceDiscoveryReqType */
		{ &hf_v2giso2_struct_iso2_ServiceDiscoveryReqType_ServiceScope,
		  { "ServiceScope",
		    "v2giso2.struct.servicediscoveryreq.servicescope",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2_ServiceDiscoveryReqType_ServiceCategory,
		  { "ServiceCategory",
		    "v2giso2.struct.servicediscoveryreq.servicecategory",
		    FT_UINT32, BASE_DEC, VALS(v2giso2_service_category_names),
		    0x0, NULL, HFILL }
		},
		/* struct iso2_ServiceDiscoveryResType */
		{ &hf_v2giso2_struct_iso2_ServiceDiscoveryResType_ResponseCode,
		  { "ResponseCode",
		    "v2giso2.struct.servicediscoveryres.responsecode",
		    FT_UINT32, BASE_DEC, VALS(v2giso2_response_code_names),
		    0x0, NULL, HFILL }
		},

		/* struct iso2_ServiceDetailReqType */
		{ &hf_v2giso2_struct_iso2_ServiceDetailReqType_ServiceID,
		  { "ServiceID", "v2giso2.struct.servicedetailreq.serviceid",
		    FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }
		},
		/* struct iso2_ServiceDetailResType */
		{ &hf_v2giso2_struct_iso2_ServiceDetailResType_ResponseCode,
		  { "ResponseCode",
		    "v2giso2.struct.servicedetailres.responsecode",
		    FT_UINT32, BASE_DEC, VALS(v2giso2_response_code_names),
		    0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2_ServiceDetailResType_ServiceID,
		  { "ServiceID", "v2giso2.struct.servicedetailres.serviceid",
		    FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso2_PaymentServiceSelectionReqType */
		{ &hf_v2giso2_struct_iso2_PaymentServiceSelectionReqType_SelectedPaymentOption,
		  { "SelectedPaymentOption",
		    "v2giso2.struct.paymentserviceslectionreq.selectpaymentoption",
		    FT_UINT32, BASE_DEC, VALS(v2giso2_payment_option_names),
		    0x0, NULL, HFILL }
		},
		/* struct iso2_PaymentServiceSelectionResType */
		{ &hf_v2giso2_struct_iso2_PaymentServiceSelectionResType_ResponseCode,
		  { "ResponseCode",
		    "v2giso2.struct.paymentserviceslectionres.responsecode",
		    FT_UINT32, BASE_DEC, VALS(v2giso2_response_code_names),
		    0x0, NULL, HFILL }
		},

		/* struct iso2_PaymentDetailsReqType */
		{ &hf_v2giso2_struct_iso2_PaymentDetailsReqType_eMAID,
		  { "eMAID", "v2giso2.struct.paymentdetailsreq.emaid",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		/* struct iso2_PaymentDetailsResType */
		{ &hf_v2giso2_struct_iso2_PaymentDetailsResType_ResponseCode,
		  { "ResponseCode",
		    "v2giso2.struct.paymentdetailsres.responsecode",
		    FT_UINT32, BASE_DEC, VALS(v2giso2_response_code_names),
		    0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2_PaymentDetailsResType_GenChallenge,
		  { "GenChallenge",
		    "v2giso2.struct.paymentdetailsres.genchallenge",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2_PaymentDetailsResType_EVSETimeStamp,
		  { "EVSETimeStamp",
		    "v2giso2.struct.paymentdetailsres.evsetimestamp",
		    FT_INT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso2_AuthorizationReqType */
		{ &hf_v2giso2_struct_iso2_AuthorizationReqType_Id,
		  { "Id", "v2giso2.struct.authorizationreq.id",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2_AuthorizationReqType_GenChallenge,
		  { "GenChallenge",
		    "v2giso2.struct.authorizationreq.genchallenge",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		/* struct iso2_AuthorizationResType */
		{ &hf_v2giso2_struct_iso2_AuthorizationResType_ResponseCode,
		  { "ResponseCode",
		    "v2giso2.struct.authorizationres.responsecode",
		    FT_UINT32, BASE_DEC, VALS(v2giso2_response_code_names),
		    0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2_AuthorizationResType_EVSEProcessing,
		  { "EVSEProcessing",
		    "v2giso2.struct.authorizationres.evseprocessing",
		    FT_UINT32, BASE_DEC, VALS(v2giso2_evse_processing_names),
		    0x0, NULL, HFILL }
		},

		/* struct iso2_ChargeParameterDiscoveryReqType */
		{ &hf_v2giso2_struct_iso2_ChargeParameterDiscoveryReqType_MaxEntriesSAScheduleTuple,
		  { "MaxEntriesSAScheduleTuple",
		    "v2giso2.struct.chargeparameterdiscoveryreq.maxentriessascheduletuple",
		    FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2_ChargeParameterDiscoveryReqType_RequestedEnergyTransferType,
		  { "RequestedEnergyTransferMode",
		    "v2giso2.struct.chargeparameterdiscoveryreq.requestedenergytransfermode",
		    FT_UINT32, BASE_DEC,
		    VALS(v2giso2_energy_transfer_mode_names),
		    0x0, NULL, HFILL }
		},
		/* struct iso2_ChargeParameterDiscoveryResType */
		{ &hf_v2giso2_struct_iso2_ChargeParameterDiscoveryResType_ResponseCode,
		  { "ResponseCode",
		    "v2giso2.struct.chargeparameterdiscoveryres.responsecode",
		    FT_UINT32, BASE_DEC, VALS(v2giso2_response_code_names),
		    0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2_ChargeParameterDiscoveryResType_EVSEProcessing,
		  { "EVSEProcessing",
		    "v2giso2.struct.chargeparameterdiscoveryres.evseprocessing",
		    FT_UINT32, BASE_DEC, VALS(v2giso2_evse_processing_names),
		    0x0, NULL, HFILL }
		},

		/* struct iso2_PowerDeliveryReqType */
		{ &hf_v2giso2_struct_iso2_PowerDeliveryReqType_ChargeProgress,
		  { "ChargeProgress",
		    "v2giso2.struct.powerdeliveryreq.chargeprogress",
		    FT_UINT32, BASE_DEC, VALS(v2giso2_charge_progress_names),
		    0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2_PowerDeliveryReqType_SAScheduleTupleID,
		  { "SAScheduleTupleID",
		    "v2giso2.struct.powerdeliveryreq.sascheduletupleid",
		    FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		/* struct iso2_PowerDeliveryResType */
		{ &hf_v2giso2_struct_iso2_PowerDeliveryResType_ResponseCode,
		  { "ResponseCode",
		    "v2giso2.struct.powerdeliveryres.responsecode",
		    FT_UINT32, BASE_DEC, VALS(v2giso2_response_code_names),
		    0x0, NULL, HFILL }
		},

		/* struct iso2_MeteringReceiptReqType */
		{ &hf_v2giso2_struct_iso2_MeteringReceiptReqType_Id,
		  { "Id", "v2giso2.struct.meteringreceiptreq.id",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2_MeteringReceiptReqType_SessionID,
		  { "SessionID", "v2giso2.struct.meteringreceiptreq.sessionid",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2_MeteringReceiptReqType_SAScheduleTupleID,
		  { "SAScheduleTupleID",
		    "v2giso2.struct.meteringreceiptreq.sascheduletupleid",
		    FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		/* struct iso2_MeteringReceiptResType */
		{ &hf_v2giso2_struct_iso2_MeteringReceiptResType_ResponseCode,
		  { "ResponseCode",
		    "v2giso2.struct.meteringreceiptres.responsecode",
		    FT_UINT32, BASE_DEC, VALS(v2giso2_response_code_names),
		    0x0, NULL, HFILL }
		},

		/* struct iso2_SessionStopReqType */
		{ &hf_v2giso2_struct_iso2_SessionStopReqType_ChargingSession,
		  { "ChargingSession",
		    "v2giso2.struct.sessionstopreq.chargingsession",
		    FT_UINT32, BASE_DEC, VALS(v2giso2_charging_session_names),
		    0x0, NULL, HFILL }
		},
		/* struct iso2_SessionStopResType */
		{ &hf_v2giso2_struct_iso2_SessionStopResType_ResponseCode,
		  { "ResponseCode",
		    "v2giso2.struct.sessionstopres.responsecode",
		    FT_UINT32, BASE_DEC, VALS(v2giso2_response_code_names),
		    0x0, NULL, HFILL }
		},

		/* struct iso2_CertificateUpdateReqType */
		{ &hf_v2giso2_struct_iso2_CertificateUpdateReqType_Id,
		  { "Id", "v2giso2.struct.certificateupdatereq.id",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2_CertificateUpdateReqType_eMAID,
		  { "eMAID", "v2giso2.struct.certificateupdatereq.emaid",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		/* struct iso2_CertificateUpdateResType */
		{ &hf_v2giso2_struct_iso2_CertificateUpdateResType_ResponseCode,
		  { "ResponseCode",
		    "v2giso2.struct.certificateupdateres.responsecode",
		    FT_UINT32, BASE_DEC, VALS(v2giso2_response_code_names),
		    0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2_CertificateUpdateResType_RetryCounter,
		  { "RetryCounter",
		    "v2giso2.struct.certificateupdateres.retrycounter",
		    FT_INT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso2_CertificateInstallationReqType */
		{ &hf_v2giso2_struct_iso2_CertificateInstallationReqType_Id,
		  { "Id", "v2giso2.struct.certificateinstallationreq.id",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2_CertificateInstallationReqType_OEMProvisioningCert,
		  { "OEMProvisioningCert",
		    "v2giso2.struct.certificateinstallationreq.oemprovisioningcert",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		/* struct iso2_CertificateInstallationResType */
		{ &hf_v2giso2_struct_iso2_CertificateInstallationResType_ResponseCode,
		  { "ResponseCode",
		    "v2giso2.struct.certificateinstallationres.responsecode",
		    FT_UINT32, BASE_DEC, VALS(v2giso2_response_code_names),
		    0x0, NULL, HFILL }
		},

		/* struct iso2_ChargingStatusResType */
		{ &hf_v2giso2_struct_iso2_ChargingStatusResType_ResponseCode,
		  { "ResponseCode",
		    "v2giso2.struct.chargingstatusres.responsecode",
		    FT_UINT32, BASE_DEC, VALS(v2giso2_response_code_names),
		    0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2_ChargingStatusResType_EVSEID,
		  { "EVSEID", "v2giso2.struct.chargingstatusres.evseid",
		    FT_STRING, BASE_NONE, NULL,  0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2_ChargingStatusResType_SAScheduleTupleID,
		  { "SAScheduleTupleID",
		    "v2giso2.struct.chargingstatusres.sascheduletupleid",
		    FT_UINT8, BASE_DEC,  NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2_ChargingStatusResType_ReceiptRequired,
		  { "ReceiptRequired",
		    "v2giso2.struct.chargingstatusres.receiptrequired",
		    FT_INT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso2_CableCheckResType */
		{ &hf_v2giso2_struct_iso2_CableCheckResType_ResponseCode,
		  { "ResponseCode", "v2giso2.struct.cablecheckres.responsecode",
		    FT_UINT32, BASE_DEC, VALS(v2giso2_response_code_names),
		    0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2_CableCheckResType_EVSEProcessing,
		  { "EVSEProcessing",
		    "v2giso2.struct.cablecheckres.evseprocessing",
		    FT_UINT32, BASE_DEC, VALS(v2giso2_evse_processing_names),
		    0x0, NULL, HFILL }
		},

		/* struct iso2_PreChargeResType */
		{ &hf_v2giso2_struct_iso2_PreChargeResType_ResponseCode,
		  { "ResponseCode", "v2giso2.struct.prechargeres.responsecode",
		    FT_UINT32, BASE_DEC, VALS(v2giso2_response_code_names),
		    0x0, NULL, HFILL }
		},

		/* struct iso2_CurrentDemandReqType */
		{ &hf_v2giso2_struct_iso2_CurrentDemandReqType_BulkChargingComplete,
		  { "BulkChargingComplete",
		    "v2giso2.struct.currentdemandreq.bulkchargingcomplete",
		    FT_INT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2_CurrentDemandReqType_ChargingComplete,
		  { "ChargingComplete",
		    "v2giso2.struct.currentdemandreq.chargingcomplete",
		    FT_INT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		/* struct iso2_CurrentDemandResType */
		{ &hf_v2giso2_struct_iso2_CurrentDemandResType_ResponseCode,
		  { "ResponseCode",
		    "v2giso2.struct.currentdemandres.responsecode",
		    FT_UINT32, BASE_DEC, VALS(v2giso2_response_code_names),
		    0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2_CurrentDemandResType_EVSECurrentLimitAchieved,
		  { "EVSECurrentLimitAchieved",
		    "v2giso2.struct.currentdemandres.evsecurrentlimitachieved",
		    FT_INT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2_CurrentDemandResType_EVSEVoltageLimitAchieved,
		  { "EVSEVoltageLimitAchieved",
		    "v2giso2.struct.currentdemandres.evsevoltagelimitachieved",
		    FT_INT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2_CurrentDemandResType_EVSEPowerLimitAchieved,
		  { "EVSEPowerLimitAchieved",
		    "v2giso2.struct.currentdemandres.evsepowerlimitachieved",
		    FT_INT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2_CurrentDemandResType_EVSEID,
		  { "EVSEID", "v2giso2.struct.currentdemandres.evseid",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2_CurrentDemandResType_SAScheduleTupleID,
		  { "SAScheduleTupleID",
		    "v2giso2.struct.currentdemandres.sascheduletupleid",
		    FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2_CurrentDemandResType_ReceiptRequired,
		  { "ReceiptRequired",
		    "v2giso2.struct.currentdemandres.receiptrequired",
		    FT_INT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso2_WeldingDetectionResType */
		{ &hf_v2giso2_struct_iso2_WeldingDetectionResType_ResponseCode,
		  { "ResponseCode",
		    "v2giso2.struct.weldingdetectionres.responsecode",
		    FT_UINT32, BASE_DEC, VALS(v2giso2_response_code_names),
		    0x0, NULL, HFILL }
		},

		/* Derived values for graphing */
		{ &hf_v2giso2_ev_target_voltage,
		  { "EV Target Voltage (derived)", "v2giso2.ev.target.voltage",
		    FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_ev_target_current,
		  { "EV Target Current (derived)", "v2giso2.ev.target.current",
		    FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_ev_maximum_voltage_limit,
		  { "EV Maximum Voltage Limit (derived)",
		    "v2giso2.ev.maximum.voltage.limit",
		    FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_ev_maximum_current_limit,
		  { "EV Maximum Current Limit (derived)",
		    "v2giso2.ev.maximum.current.limit",
		    FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_ev_maximum_power_limit,
		  { "EV Maximum Power Limit (derived)",
		    "v2giso2.ev.maximum.power.limit",
		    FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_remaining_time_to_full_soc,
		  { "Remaining Time To Full SOC (derived)",
		    "v2giso2.remaining.time.to.full.soc",
		    FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_remaining_time_to_bulk_soc,
		  { "Remaining Time To Bulk SOC (derived)",
		    "v2giso2.remaining.time.to.bulk.soc",
		    FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_evse_present_voltage,
		  { "EVSE Present Voltage (derived)",
		    "v2giso2.evse.present.voltage",
		    FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_evse_present_current,
		  { "EVSE Present Current (derived)",
		    "v2giso2.evse.present.current",
		    FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_evse_maximum_voltage_limit,
		  { "EVSE Maximum Voltage Limit (derived)",
		    "v2giso2.evse.maximum.voltage.limit",
		    FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_evse_maximum_current_limit,
		  { "EVSE Maximum Current Limit (derived)",
		    "v2giso2.evse.maximum.current.limit",
		    FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_evse_maximum_power_limit,
		  { "EVSE Maximum Power Limit (derived)",
		    "v2giso2.evse.maximum.power.limit",
		    FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL }
		}
	};

	static gint *ett[] = {
		&ett_v2giso2,
		&ett_v2giso2_header,
		&ett_v2giso2_body,
		&ett_v2giso2_array,
		&ett_v2giso2_array_i,
		&ett_v2giso2_asn1,

		&ett_v2giso2_struct_iso2_NotificationType,
		&ett_v2giso2_struct_iso2_SignatureType,
		&ett_v2giso2_struct_iso2_SignedInfoType,
		&ett_v2giso2_struct_iso2_SignatureValueType,
		&ett_v2giso2_struct_iso2_ObjectType,
		&ett_v2giso2_struct_iso2_CanonicalizationMethodType,
		&ett_v2giso2_struct_iso2_SignatureMethodType,
		&ett_v2giso2_struct_iso2_DigestMethodType,
		&ett_v2giso2_struct_iso2_ReferenceType,
		&ett_v2giso2_struct_iso2_TransformsType,
		&ett_v2giso2_struct_iso2_TransformType,
		&ett_v2giso2_struct_iso2_KeyInfoType,
		&ett_v2giso2_struct_iso2_KeyValueType,
		&ett_v2giso2_struct_iso2_DSAKeyValueType,
		&ett_v2giso2_struct_iso2_RSAKeyValueType,
		&ett_v2giso2_struct_iso2_RetrievalMethodType,
		&ett_v2giso2_struct_iso2_X509DataType,
		&ett_v2giso2_struct_iso2_X509IssuerSerialType,
		&ett_v2giso2_struct_iso2_PGPDataType,
		&ett_v2giso2_struct_iso2_SPKIDataType,

		&ett_v2giso2_struct_iso2_ServiceType,
		&ett_v2giso2_struct_iso2_SupportedEnergyTransferModeType,
		&ett_v2giso2_struct_iso2_PaymentOptionListType,
		&ett_v2giso2_struct_iso2_ChargeServiceType,
		&ett_v2giso2_struct_iso2_ServiceListType,
		&ett_v2giso2_struct_iso2_ServiceParameterListType,
		&ett_v2giso2_struct_iso2_ParameterSetType,
		&ett_v2giso2_struct_iso2_ParameterType,
		&ett_v2giso2_struct_iso2_PhysicalValueType,
		&ett_v2giso2_struct_iso2_SelectedServiceListType,
		&ett_v2giso2_struct_iso2_SelectedServiceType,
		&ett_v2giso2_struct_iso2_CertificateChainType,
		&ett_v2giso2_struct_iso2_SubCertificatesType,
		&ett_v2giso2_struct_iso2_EVChargeParameterType,
		&ett_v2giso2_struct_iso2_AC_EVChargeParameterType,
		&ett_v2giso2_struct_iso2_DC_EVChargeParameterType,
		&ett_v2giso2_struct_iso2_DC_EVStatusType,
		&ett_v2giso2_struct_iso2_EVSEChargeParameterType,
		&ett_v2giso2_struct_iso2_AC_EVSEChargeParameterType,
		&ett_v2giso2_struct_iso2_DC_EVSEChargeParameterType,
		&ett_v2giso2_struct_iso2_EVSEStatusType,
		&ett_v2giso2_struct_iso2_AC_EVSEStatusType,
		&ett_v2giso2_struct_iso2_DC_EVSEStatusType,
		&ett_v2giso2_struct_iso2_SASchedulesType,
		&ett_v2giso2_struct_iso2_SAScheduleListType,
		&ett_v2giso2_struct_iso2_SAScheduleTupleType,
		&ett_v2giso2_struct_iso2_PMaxScheduleType,
		&ett_v2giso2_struct_iso2_PMaxScheduleEntryType,
		&ett_v2giso2_struct_iso2_SalesTariffType,
		&ett_v2giso2_struct_iso2_SalesTariffEntryType,
		&ett_v2giso2_struct_iso2_ConsumptionCostType,
		&ett_v2giso2_struct_iso2_CostType,
		&ett_v2giso2_struct_iso2_RelativeTimeIntervalType,
		&ett_v2giso2_struct_iso2_IntervalType,
		&ett_v2giso2_struct_iso2_ChargingProfileType,
		&ett_v2giso2_struct_iso2_ProfileEntryType,
		&ett_v2giso2_struct_iso2_EVPowerDeliveryParameterType,
		&ett_v2giso2_struct_iso2_DC_EVPowerDeliveryParameterType,
		&ett_v2giso2_struct_iso2_MeterInfoType,
		&ett_v2giso2_struct_iso2_ListOfRootCertificateIDsType,
		&ett_v2giso2_struct_iso2_ContractSignatureEncryptedPrivateKeyType,
		&ett_v2giso2_struct_iso2_DiffieHellmanPublickeyType,
		&ett_v2giso2_struct_iso2_EMAIDType,

		&ett_v2giso2_struct_iso2_SessionSetupReqType,
		&ett_v2giso2_struct_iso2_SessionSetupResType,
		&ett_v2giso2_struct_iso2_ServiceDiscoveryReqType,
		&ett_v2giso2_struct_iso2_ServiceDiscoveryResType,
		&ett_v2giso2_struct_iso2_ServiceDetailReqType,
		&ett_v2giso2_struct_iso2_ServiceDetailResType,
		&ett_v2giso2_struct_iso2_PaymentServiceSelectionReqType,
		&ett_v2giso2_struct_iso2_PaymentServiceSelectionResType,
		&ett_v2giso2_struct_iso2_PaymentDetailsReqType,
		&ett_v2giso2_struct_iso2_PaymentDetailsResType,
		&ett_v2giso2_struct_iso2_AuthorizationReqType,
		&ett_v2giso2_struct_iso2_AuthorizationResType,
		&ett_v2giso2_struct_iso2_ChargeParameterDiscoveryReqType,
		&ett_v2giso2_struct_iso2_ChargeParameterDiscoveryResType,
		&ett_v2giso2_struct_iso2_PowerDeliveryReqType,
		&ett_v2giso2_struct_iso2_PowerDeliveryResType,
		&ett_v2giso2_struct_iso2_MeteringReceiptReqType,
		&ett_v2giso2_struct_iso2_MeteringReceiptResType,
		&ett_v2giso2_struct_iso2_SessionStopReqType,
		&ett_v2giso2_struct_iso2_SessionStopResType,
		&ett_v2giso2_struct_iso2_CertificateUpdateReqType,
		&ett_v2giso2_struct_iso2_CertificateUpdateResType,
		&ett_v2giso2_struct_iso2_CertificateInstallationReqType,
		&ett_v2giso2_struct_iso2_CertificateInstallationResType,
		&ett_v2giso2_struct_iso2_ChargingStatusReqType,
		&ett_v2giso2_struct_iso2_ChargingStatusResType,
		&ett_v2giso2_struct_iso2_CableCheckReqType,
		&ett_v2giso2_struct_iso2_CableCheckResType,
		&ett_v2giso2_struct_iso2_PreChargeReqType,
		&ett_v2giso2_struct_iso2_PreChargeResType,
		&ett_v2giso2_struct_iso2_CurrentDemandReqType,
		&ett_v2giso2_struct_iso2_CurrentDemandResType,
		&ett_v2giso2_struct_iso2_WeldingDetectionReqType,
		&ett_v2giso2_struct_iso2_WeldingDetectionResType,
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
