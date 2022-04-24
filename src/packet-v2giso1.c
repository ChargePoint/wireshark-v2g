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
#include <iso1/iso1EXIDatatypes.h>
#include <iso1/iso1EXIDatatypesDecoder.h>

#include "v2gexi.h"


/* forward declare */
void proto_register_v2giso1(void);
void proto_reg_handoff_v2giso1(void);


static dissector_handle_t v2gexi_handle;

static int proto_v2giso1 = -1;

static int hf_v2giso1_struct_iso1MessageHeaderType_SessionID = -1;

static int hf_v2giso1_struct_iso1NotificationType_FaultCode = -1;
static int hf_v2giso1_struct_iso1NotificationType_FaultMsg = -1;
static int hf_v2giso1_struct_iso1SignatureType_Id = -1;
static int hf_v2giso1_struct_iso1SignedInfoType_Id = -1;
static int hf_v2giso1_struct_iso1CanonicalizationMethodType_Algorithm = -1;
static int hf_v2giso1_struct_iso1CanonicalizationMethodType_ANY = -1;
static int hf_v2giso1_struct_iso1SignatureMethodType_Algorithm = -1;
static int hf_v2giso1_struct_iso1SignatureMethodType_HMACOutputLength = -1;
static int hf_v2giso1_struct_iso1SignatureMethodType_ANY = -1;
static int hf_v2giso1_struct_iso1ReferenceType_Id = -1;
static int hf_v2giso1_struct_iso1ReferenceType_URI = -1;
static int hf_v2giso1_struct_iso1ReferenceType_Type = -1;
static int hf_v2giso1_struct_iso1ReferenceType_DigestValue = -1;
static int hf_v2giso1_struct_iso1SignatureValueType_Id = -1;
static int hf_v2giso1_struct_iso1SignatureValueType_CONTENT = -1;
static int hf_v2giso1_struct_iso1ObjectType_Id = -1;
static int hf_v2giso1_struct_iso1ObjectType_MimeType = -1;
static int hf_v2giso1_struct_iso1ObjectType_Encoding = -1;
static int hf_v2giso1_struct_iso1ObjectType_ANY = -1;
static int hf_v2giso1_struct_iso1TransformType_Algorithm = -1;
static int hf_v2giso1_struct_iso1TransformType_ANY = -1;
static int hf_v2giso1_struct_iso1TransformType_XPath = -1;
static int hf_v2giso1_struct_iso1DigestMethodType_Algorithm = -1;
static int hf_v2giso1_struct_iso1DigestMethodType_ANY = -1;
static int hf_v2giso1_struct_iso1KeyInfoType_Id = -1;
static int hf_v2giso1_struct_iso1KeyInfoType_KeyName = -1;
static int hf_v2giso1_struct_iso1KeyInfoType_MgmtData = -1;
static int hf_v2giso1_struct_iso1KeyInfoType_ANY = -1;
static int hf_v2giso1_struct_iso1RetrievalMethodType_URI = -1;
static int hf_v2giso1_struct_iso1RetrievalMethodType_Type = -1;
static int hf_v2giso1_struct_iso1KeyValueType_ANY = -1;
static int hf_v2giso1_struct_iso1DSAKeyValueType_P = -1;
static int hf_v2giso1_struct_iso1DSAKeyValueType_Q = -1;
static int hf_v2giso1_struct_iso1DSAKeyValueType_G = -1;
static int hf_v2giso1_struct_iso1DSAKeyValueType_Y = -1;
static int hf_v2giso1_struct_iso1DSAKeyValueType_J = -1;
static int hf_v2giso1_struct_iso1DSAKeyValueType_Seed = -1;
static int hf_v2giso1_struct_iso1DSAKeyValueType_PgenCounter = -1;
static int hf_v2giso1_struct_iso1RSAKeyValueType_Exponent = -1;
static int hf_v2giso1_struct_iso1RSAKeyValueType_Modulus = -1;
static int hf_v2giso1_struct_iso1X509DataType_X509SKI = -1;
static int hf_v2giso1_struct_iso1X509DataType_X509SubjectName = -1;
static int hf_v2giso1_struct_iso1X509DataType_X509Certificate = -1;
static int hf_v2giso1_struct_iso1X509DataType_X509CRL = -1;
static int hf_v2giso1_struct_iso1X509DataType_ANY = -1;
static int hf_v2giso1_struct_iso1X509IssuerSerialType_X509IssuerName = -1;
static int hf_v2giso1_struct_iso1X509IssuerSerialType_X509SerialNumber_negative = -1;
static int hf_v2giso1_struct_iso1X509IssuerSerialType_X509SerialNumber_data = -1;
static int hf_v2giso1_struct_iso1PGPDataType_PGPKeyID = -1;
static int hf_v2giso1_struct_iso1PGPDataType_PGPKeyPacket = -1;
static int hf_v2giso1_struct_iso1PGPDataType_ANY = -1;
static int hf_v2giso1_struct_iso1SPKIDataType_SPKISexp = -1;
static int hf_v2giso1_struct_iso1SPKIDataType_ANY = -1;

static int hf_v2giso1_struct_iso1ChargeServiceType_ServiceID = -1;
static int hf_v2giso1_struct_iso1ChargeServiceType_ServiceName = -1;
static int hf_v2giso1_struct_iso1ChargeServiceType_ServiceCategory = -1;
static int hf_v2giso1_struct_iso1ChargeServiceType_ServiceScope = -1;
static int hf_v2giso1_struct_iso1ChargeServiceType_FreeService = -1;

static int hf_v2giso1_struct_iso1PaymentOptionLstType_PaymentOption = -1;

static int hf_v2giso1_struct_iso1SupportedEnergyTransferModeType_EnergyTransferMode = -1;

static int hf_v2giso1_struct_iso1ServiceType_ServiceID = -1;
static int hf_v2giso1_struct_iso1ServiceType_ServiceName = -1;
static int hf_v2giso1_struct_iso1ServiceType_ServiceCategory = -1;
static int hf_v2giso1_struct_iso1ServiceType_ServiceScope = -1;
static int hf_v2giso1_struct_iso1ServiceType_FreeService = -1;

static int hf_v2giso1_struct_iso1ParameterSetType_ParameterSetID = -1;

static int hf_v2giso1_struct_iso1ParameterType_Name = -1;
static int hf_v2giso1_struct_iso1ParameterType_boolValue = -1;
static int hf_v2giso1_struct_iso1ParameterType_byteValue = -1;
static int hf_v2giso1_struct_iso1ParameterType_shortValue = -1;
static int hf_v2giso1_struct_iso1ParameterType_intValue = -1;
static int hf_v2giso1_struct_iso1ParameterType_stringValue = -1;

static int hf_v2giso1_struct_iso1PhysicalValueType_Multiplier = -1;
static int hf_v2giso1_struct_iso1PhysicalValueType_Unit = -1;
static int hf_v2giso1_struct_iso1PhysicalValueType_Value = -1;

static int hf_v2giso1_struct_iso1SelectedServiceType_ServiceID = -1;
static int hf_v2giso1_struct_iso1SelectedServiceType_ParameterSetID = -1;

static int hf_v2giso1_struct_iso1CertificateChainType_Id = -1;
static int hf_v2giso1_struct_iso1CertificateChainType_Certificate = -1;

static int hf_v2giso1_struct_iso1SubCertificatesType_Certificate = -1;

static int hf_v2giso1_struct_iso1AC_EVChargeParameterType_DepartureTime = -1;

static int hf_v2giso1_struct_iso1DC_EVChargeParameterType_DepartureTime = -1;
static int hf_v2giso1_struct_iso1DC_EVChargeParameterType_FullSOC = -1;
static int hf_v2giso1_struct_iso1DC_EVChargeParameterType_BulkSOC = -1;

static int hf_v2giso1_struct_iso1DC_EVStatusType_EVReady = -1;
static int hf_v2giso1_struct_iso1DC_EVStatusType_EVErrorCode = -1;
static int hf_v2giso1_struct_iso1DC_EVStatusType_EVRESSSOC = -1;

static int hf_v2giso1_struct_iso1EVSEStatusType_NotificationMaxDelay = -1;
static int hf_v2giso1_struct_iso1EVSEStatusType_EVSENotification = -1;

static int hf_v2giso1_struct_iso1AC_EVSEStatusType_NotificationMaxDelay = -1;
static int hf_v2giso1_struct_iso1AC_EVSEStatusType_EVSENotification = -1;
static int hf_v2giso1_struct_iso1AC_EVSEStatusType_RCD = -1;

static int hf_v2giso1_struct_iso1DC_EVSEStatusType_NotificationMaxDelay = -1;
static int hf_v2giso1_struct_iso1DC_EVSEStatusType_EVSENotification = -1;
static int hf_v2giso1_struct_iso1DC_EVSEStatusType_EVSEIsolationStatus = -1;
static int hf_v2giso1_struct_iso1DC_EVSEStatusType_EVSEStatusCode = -1;

static int hf_v2giso1_struct_iso1SAScheduleTupleType_SAScheduleTupleID = -1;

static int hf_v2giso1_struct_iso1SalesTariffType_Id = -1;
static int hf_v2giso1_struct_iso1SalesTariffType_SalesTariffDescription = -1;
static int hf_v2giso1_struct_iso1SalesTariffType_NumEPriceLevels = -1;
static int hf_v2giso1_struct_iso1SalesTariffEntryType_EPriceLevel = -1;

static int hf_v2giso1_struct_iso1RelativeTimeIntervalType_start = -1;
static int hf_v2giso1_struct_iso1RelativeTimeIntervalType_duration = -1;

static int hf_v2giso1_struct_iso1CostType_costKind = -1;
static int hf_v2giso1_struct_iso1CostType_amount = -1;
static int hf_v2giso1_struct_iso1CostType_amountMultiplier = -1;

static int hf_v2giso1_struct_iso1ProfileEntryType_ChargingProfileEntryStart = -1;
static int hf_v2giso1_struct_iso1ProfileEntryType_ChargingProfileEntryMaxNumberOfPhasesInUse = -1;

static int hf_v2giso1_struct_iso1DC_EVPowerDeliveryParameterType_BulkChargingComplete = -1;
static int hf_v2giso1_struct_iso1DC_EVPowerDeliveryParameterType_ChargingComplete = -1;

static int hf_v2giso1_struct_iso1MeterInfoType_MeterID = -1;
static int hf_v2giso1_struct_iso1MeterInfoType_MeterReading = -1;
static int hf_v2giso1_struct_iso1MeterInfoType_SigMeterReading = -1;
static int hf_v2giso1_struct_iso1MeterInfoType_MeterStatus = -1;
static int hf_v2giso1_struct_iso1MeterInfoType_TMeter = -1;

static int hf_v2giso1_struct_iso1ContractSignatureEncryptedPrivateKeyType_Id = -1;
static int hf_v2giso1_struct_iso1ContractSignatureEncryptedPrivateKeyType_CONTENT = -1;

static int hf_v2giso1_struct_iso1DiffieHellmanPublickeyType_Id = -1;
static int hf_v2giso1_struct_iso1DiffieHellmanPublickeyType_CONTENT = -1;

static int hf_v2giso1_struct_iso1EMAIDType_Id = -1;
static int hf_v2giso1_struct_iso1EMAIDType_CONTENT = -1;

static int hf_v2giso1_struct_iso1SessionSetupReqType_EVCCID = -1;
static int hf_v2giso1_struct_iso1SessionSetupResType_ResponseCode = -1;
static int hf_v2giso1_struct_iso1SessionSetupResType_EVSEID = -1;
static int hf_v2giso1_struct_iso1SessionSetupResType_EVSETimeStamp = -1;

static int hf_v2giso1_struct_iso1ServiceDiscoveryReqType_ServiceScope = -1;
static int hf_v2giso1_struct_iso1ServiceDiscoveryReqType_ServiceCategory = -1;
static int hf_v2giso1_struct_iso1ServiceDiscoveryResType_ResponseCode = -1;

static int hf_v2giso1_struct_iso1ServiceDetailReqType_ServiceID = -1;
static int hf_v2giso1_struct_iso1ServiceDetailResType_ResponseCode = -1;
static int hf_v2giso1_struct_iso1ServiceDetailResType_ServiceID = -1;

static int hf_v2giso1_struct_iso1PaymentServiceSelectionReqType_SelectedPaymentOption = -1;
static int hf_v2giso1_struct_iso1PaymentServiceSelectionResType_ResponseCode = -1;

static int hf_v2giso1_struct_iso1PaymentDetailsReqType_eMAID = -1;
static int hf_v2giso1_struct_iso1PaymentDetailsResType_ResponseCode = -1;
static int hf_v2giso1_struct_iso1PaymentDetailsResType_GenChallenge = -1;
static int hf_v2giso1_struct_iso1PaymentDetailsResType_EVSETimeStamp = -1;

static int hf_v2giso1_struct_iso1AuthorizationReqType_Id = -1;
static int hf_v2giso1_struct_iso1AuthorizationReqType_GenChallenge = -1;
static int hf_v2giso1_struct_iso1AuthorizationResType_ResponseCode = -1;
static int hf_v2giso1_struct_iso1AuthorizationResType_EVSEProcessing = -1;

static int hf_v2giso1_struct_iso1ChargeParameterDiscoveryReqType_MaxEntriesSAScheduleTuple = -1;
static int hf_v2giso1_struct_iso1ChargeParameterDiscoveryReqType_RequestedEnergyTransferType = -1;
static int hf_v2giso1_struct_iso1ChargeParameterDiscoveryResType_ResponseCode = -1;
static int hf_v2giso1_struct_iso1ChargeParameterDiscoveryResType_EVSEProcessing = -1;

static int hf_v2giso1_struct_iso1PowerDeliveryReqType_ChargeProgress = -1;
static int hf_v2giso1_struct_iso1PowerDeliveryReqType_SAScheduleTupleID = -1;
static int hf_v2giso1_struct_iso1PowerDeliveryResType_ResponseCode = -1;

static int hf_v2giso1_struct_iso1MeteringReceiptReqType_Id = -1;
static int hf_v2giso1_struct_iso1MeteringReceiptReqType_SessionID = -1;
static int hf_v2giso1_struct_iso1MeteringReceiptReqType_SAScheduleTupleID = -1;
static int hf_v2giso1_struct_iso1MeteringReceiptResType_ResponseCode = -1;

static int hf_v2giso1_struct_iso1SessionStopReqType_ChargingSession = -1;
static int hf_v2giso1_struct_iso1SessionStopResType_ResponseCode = -1;

static int hf_v2giso1_struct_iso1CertificateUpdateReqType_Id = -1;
static int hf_v2giso1_struct_iso1CertificateUpdateReqType_eMAID = -1;
static int hf_v2giso1_struct_iso1CertificateUpdateResType_ResponseCode = -1;
static int hf_v2giso1_struct_iso1CertificateUpdateResType_RetryCounter = -1;

static int hf_v2giso1_struct_iso1CertificateInstallationReqType_Id = -1;
static int hf_v2giso1_struct_iso1CertificateInstallationReqType_OEMProvisioningCert = -1;
static int hf_v2giso1_struct_iso1CertificateInstallationResType_ResponseCode = -1;

static int hf_v2giso1_struct_iso1ChargingStatusResType_ResponseCode = -1;
static int hf_v2giso1_struct_iso1ChargingStatusResType_EVSEID = -1;
static int hf_v2giso1_struct_iso1ChargingStatusResType_SAScheduleTupleID = -1;
static int hf_v2giso1_struct_iso1ChargingStatusResType_ReceiptRequired = -1;

static int hf_v2giso1_struct_iso1CableCheckResType_ResponseCode = -1;
static int hf_v2giso1_struct_iso1CableCheckResType_EVSEProcessing = -1;

static int hf_v2giso1_struct_iso1PreChargeResType_ResponseCode = -1;

static int hf_v2giso1_struct_iso1CurrentDemandReqType_BulkChargingComplete = -1;
static int hf_v2giso1_struct_iso1CurrentDemandReqType_ChargingComplete = -1;
static int hf_v2giso1_struct_iso1CurrentDemandResType_ResponseCode = -1;
static int hf_v2giso1_struct_iso1CurrentDemandResType_EVSECurrentLimitAchieved = -1;
static int hf_v2giso1_struct_iso1CurrentDemandResType_EVSEVoltageLimitAchieved = -1;
static int hf_v2giso1_struct_iso1CurrentDemandResType_EVSEPowerLimitAchieved = -1;
static int hf_v2giso1_struct_iso1CurrentDemandResType_EVSEID = -1;
static int hf_v2giso1_struct_iso1CurrentDemandResType_SAScheduleTupleID = -1;
static int hf_v2giso1_struct_iso1CurrentDemandResType_ReceiptRequired = -1;

static int hf_v2giso1_struct_iso1WeldingDetectionResType_ResponseCode = -1;

/* Initialize the subtree pointers */
static gint ett_v2giso1 = -1;
static gint ett_v2giso1_header = -1;
static gint ett_v2giso1_body = -1;
static gint ett_v2giso1_array = -1;
static gint ett_v2giso1_array_i = -1;

static gint ett_v2giso1_struct_iso1NotificationType = -1;
static gint ett_v2giso1_struct_iso1SignatureType = -1;
static gint ett_v2giso1_struct_iso1SignedInfoType = -1;
static gint ett_v2giso1_struct_iso1SignatureValueType = -1;
static gint ett_v2giso1_struct_iso1ObjectType = -1;
static gint ett_v2giso1_struct_iso1CanonicalizationMethodType = -1;
static gint ett_v2giso1_struct_iso1SignatureMethodType = -1;
static gint ett_v2giso1_struct_iso1DigestMethodType = -1;
static gint ett_v2giso1_struct_iso1ReferenceType = -1;
static gint ett_v2giso1_struct_iso1TransformsType = -1;
static gint ett_v2giso1_struct_iso1TransformType = -1;
static gint ett_v2giso1_struct_iso1KeyInfoType = -1;
static gint ett_v2giso1_struct_iso1KeyValueType = -1;
static gint ett_v2giso1_struct_iso1DSAKeyValueType = -1;
static gint ett_v2giso1_struct_iso1RSAKeyValueType = -1;
static gint ett_v2giso1_struct_iso1RetrievalMethodType = -1;
static gint ett_v2giso1_struct_iso1X509DataType = -1;
static gint ett_v2giso1_struct_iso1X509IssuerSerialType = -1;
static gint ett_v2giso1_struct_iso1PGPDataType = -1;
static gint ett_v2giso1_struct_iso1SPKIDataType = -1;

static gint ett_v2giso1_struct_iso1ServiceType = -1;
static gint ett_v2giso1_struct_iso1SupportedEnergyTransferModeType = -1;
static gint ett_v2giso1_struct_iso1PaymentOptionListType = -1;
static gint ett_v2giso1_struct_iso1ChargeServiceType = -1;
static gint ett_v2giso1_struct_iso1ServiceListType = -1;
static gint ett_v2giso1_struct_iso1ServiceParameterListType = -1;
static gint ett_v2giso1_struct_iso1ParameterSetType = -1;
static gint ett_v2giso1_struct_iso1ParameterType = -1;
static gint ett_v2giso1_struct_iso1PhysicalValueType = -1;
static gint ett_v2giso1_struct_iso1SelectedServiceListType = -1;
static gint ett_v2giso1_struct_iso1SelectedServiceType = -1;
static gint ett_v2giso1_struct_iso1CertificateChainType = -1;
static gint ett_v2giso1_struct_iso1SubCertificatesType = -1;
static gint ett_v2giso1_struct_iso1EVChargeParameterType = -1;
static gint ett_v2giso1_struct_iso1AC_EVChargeParameterType = -1;
static gint ett_v2giso1_struct_iso1DC_EVChargeParameterType = -1;
static gint ett_v2giso1_struct_iso1DC_EVStatusType = -1;
static gint ett_v2giso1_struct_iso1EVSEChargeParameterType = -1;
static gint ett_v2giso1_struct_iso1AC_EVSEChargeParameterType = -1;
static gint ett_v2giso1_struct_iso1DC_EVSEChargeParameterType = -1;
static gint ett_v2giso1_struct_iso1EVSEStatusType = -1;
static gint ett_v2giso1_struct_iso1AC_EVSEStatusType = -1;
static gint ett_v2giso1_struct_iso1DC_EVSEStatusType = -1;
static gint ett_v2giso1_struct_iso1SASchedulesType = -1;
static gint ett_v2giso1_struct_iso1SAScheduleListType = -1;
static gint ett_v2giso1_struct_iso1SAScheduleTupleType = -1;
static gint ett_v2giso1_struct_iso1PMaxScheduleType = -1;
static gint ett_v2giso1_struct_iso1PMaxScheduleEntryType = -1;
static gint ett_v2giso1_struct_iso1SalesTariffType = -1;
static gint ett_v2giso1_struct_iso1SalesTariffEntryType = -1;
static gint ett_v2giso1_struct_iso1ConsumptionCostType = -1;
static gint ett_v2giso1_struct_iso1CostType = -1;
static gint ett_v2giso1_struct_iso1RelativeTimeIntervalType = -1;
static gint ett_v2giso1_struct_iso1IntervalType = -1;
static gint ett_v2giso1_struct_iso1ChargingProfileType = -1;
static gint ett_v2giso1_struct_iso1ProfileEntryType = -1;
static gint ett_v2giso1_struct_iso1EVPowerDeliveryParameterType = -1;
static gint ett_v2giso1_struct_iso1DC_EVPowerDeliveryParameterType = -1;
static gint ett_v2giso1_struct_iso1MeterInfoType = -1;
static gint ett_v2giso1_struct_iso1ListOfRootCertificateIDsType = -1;
static gint ett_v2giso1_struct_iso1ContractSignatureEncryptedPrivateKeyType = -1;
static gint ett_v2giso1_struct_iso1DiffieHellmanPublickeyType = -1;
static gint ett_v2giso1_struct_iso1EMAIDType = -1;

static gint ett_v2giso1_struct_iso1SessionSetupReqType = -1;
static gint ett_v2giso1_struct_iso1SessionSetupResType = -1;
static gint ett_v2giso1_struct_iso1ServiceDiscoveryReqType = -1;
static gint ett_v2giso1_struct_iso1ServiceDiscoveryResType = -1;
static gint ett_v2giso1_struct_iso1ServiceDetailReqType = -1;
static gint ett_v2giso1_struct_iso1ServiceDetailResType = -1;
static gint ett_v2giso1_struct_iso1PaymentServiceSelectionReqType = -1;
static gint ett_v2giso1_struct_iso1PaymentServiceSelectionResType = -1;
static gint ett_v2giso1_struct_iso1PaymentDetailsReqType = -1;
static gint ett_v2giso1_struct_iso1PaymentDetailsResType = -1;
static gint ett_v2giso1_struct_iso1AuthorizationReqType = -1;
static gint ett_v2giso1_struct_iso1AuthorizationResType = -1;
static gint ett_v2giso1_struct_iso1ChargeParameterDiscoveryReqType = -1;
static gint ett_v2giso1_struct_iso1ChargeParameterDiscoveryResType = -1;
static gint ett_v2giso1_struct_iso1PowerDeliveryReqType = -1;
static gint ett_v2giso1_struct_iso1PowerDeliveryResType = -1;
static gint ett_v2giso1_struct_iso1MeteringReceiptReqType = -1;
static gint ett_v2giso1_struct_iso1MeteringReceiptResType = -1;
static gint ett_v2giso1_struct_iso1SessionStopReqType = -1;
static gint ett_v2giso1_struct_iso1SessionStopResType = -1;
static gint ett_v2giso1_struct_iso1CertificateUpdateReqType = -1;
static gint ett_v2giso1_struct_iso1CertificateUpdateResType = -1;
static gint ett_v2giso1_struct_iso1CertificateInstallationReqType = -1;
static gint ett_v2giso1_struct_iso1CertificateInstallationResType = -1;
static gint ett_v2giso1_struct_iso1ChargingStatusReqType = -1;
static gint ett_v2giso1_struct_iso1ChargingStatusResType = -1;
static gint ett_v2giso1_struct_iso1CableCheckReqType = -1;
static gint ett_v2giso1_struct_iso1CableCheckResType = -1;
static gint ett_v2giso1_struct_iso1PreChargeReqType = -1;
static gint ett_v2giso1_struct_iso1PreChargeResType = -1;
static gint ett_v2giso1_struct_iso1CurrentDemandReqType = -1;
static gint ett_v2giso1_struct_iso1CurrentDemandResType = -1;
static gint ett_v2giso1_struct_iso1WeldingDetectionReqType = -1;
static gint ett_v2giso1_struct_iso1WeldingDetectionResType = -1;

static const value_string v2giso1_fault_code_names[] = {
	{ iso1faultCodeType_ParsingError, "ParsingError" },
	{ iso1faultCodeType_NoTLSRootCertificatAvailable,
	  "NoTLSRootCertificatAvailable" },
	{ iso1faultCodeType_UnknownError, "UnknownError" }
};

static const value_string v2giso1_service_category_names[] = {
	{ iso1serviceCategoryType_EVCharging, "EVCharging" },
	{ iso1serviceCategoryType_Internet, "Internet" },
	{ iso1serviceCategoryType_ContractCertificate, "ContractCertificate" },
	{ iso1serviceCategoryType_OtherCustom, "OtherCustom" }
};

static const value_string v2giso1_payment_option_names[] = {
	{ iso1paymentOptionType_Contract, "Contract" },
	{ iso1paymentOptionType_ExternalPayment, "ExternalPayment" }
};

static const value_string v2giso1_energy_transfer_mode_names[] = {
	{ iso1EnergyTransferModeType_AC_single_phase_core,
	  "AC_single_phase_core" },
	{ iso1EnergyTransferModeType_AC_three_phase_core,
	  "AC_three_phase_core" },
	{ iso1EnergyTransferModeType_DC_core, "DC_core" },
	{ iso1EnergyTransferModeType_DC_extended, "DC_extended" },
	{ iso1EnergyTransferModeType_DC_combo_core, "DC_combo_core" },
	{ iso1EnergyTransferModeType_DC_unique, "DC_unique" },
};

static const value_string v2giso1_unit_symbol_names[] = {
	{ iso1unitSymbolType_h, "h" },
	{ iso1unitSymbolType_m, "m" },
	{ iso1unitSymbolType_s, "s" },
	{ iso1unitSymbolType_A, "A" },
	{ iso1unitSymbolType_V, "V" },
	{ iso1unitSymbolType_W, "W" },
	{ iso1unitSymbolType_Wh, "Wh" }
};

static const value_string v2giso1_dc_everrorcode_names[] = {
	{ iso1DC_EVErrorCodeType_NO_ERROR, "NO ERROR" },
	{ iso1DC_EVErrorCodeType_FAILED_RESSTemperatureInhibit,
	  "FAILED (RESSTemperatureInhibit)" },
	{ iso1DC_EVErrorCodeType_FAILED_EVShiftPosition,
	  "FAILED (EVShiftPosition)" },
	{ iso1DC_EVErrorCodeType_FAILED_ChargerConnectorLockFault,
	  "FAILED (ChargerConnectorLockFault)" },
	{ iso1DC_EVErrorCodeType_FAILED_EVRESSMalfunction,
	  "FAILED (EVRESSMalfunction)" },
	{ iso1DC_EVErrorCodeType_FAILED_ChargingCurrentdifferential,
	  "FAILED (ChargingCurrentdifferential)" },
	{ iso1DC_EVErrorCodeType_FAILED_ChargingVoltageOutOfRange,
	  "FAILED (ChargingVoltageOutOfRange)" },
	{ iso1DC_EVErrorCodeType_Reserved_A, "Reserved A" },
	{ iso1DC_EVErrorCodeType_Reserved_B, "Reserved B" },
	{ iso1DC_EVErrorCodeType_Reserved_C, "Reserved C" },
	{ iso1DC_EVErrorCodeType_FAILED_ChargingSystemIncompatibility,
	  "FAILED (ChargingSystemIncompatibility)" },
	{ iso1DC_EVErrorCodeType_NoData, "NoData" }
};

static const value_string v2giso1_evsenotification_names[] = {
	{ iso1EVSENotificationType_None, "None" },
	{ iso1EVSENotificationType_StopCharging, "StopCharging" },
	{ iso1EVSENotificationType_ReNegotiation, "ReNegotiation" }
};

static const value_string v2giso1_evseisolation_level_names[] = {
	{ iso1isolationLevelType_Invalid, "Invalid" },
	{ iso1isolationLevelType_Valid, "Valid" },
	{ iso1isolationLevelType_Warning, "Warning" },
	{ iso1isolationLevelType_Fault, "Fault" },
	{ iso1isolationLevelType_No_IMD, "No IMD" }
};

static const value_string v2giso1_dc_evsestatuscode_names[] = {
	{ iso1DC_EVSEStatusCodeType_EVSE_NotReady, "EVSE NotReady" },
	{ iso1DC_EVSEStatusCodeType_EVSE_Ready, "EVSE Ready" },
	{ iso1DC_EVSEStatusCodeType_EVSE_Shutdown, "EVSE Shutdown" },
	{ iso1DC_EVSEStatusCodeType_EVSE_UtilityInterruptEvent,
	  "EVSE UtilityInterruptEvent" },
	{ iso1DC_EVSEStatusCodeType_EVSE_IsolationMonitoringActive,
	  "EVSE IsolationMonitoringActive" },
	{ iso1DC_EVSEStatusCodeType_EVSE_EmergencyShutdown,
	  "EVSE EmergencyShutdown" },
	{ iso1DC_EVSEStatusCodeType_EVSE_Malfunction, "EVSE Malfunction" },
	{ iso1DC_EVSEStatusCodeType_Reserved_8, "Reserved_8" },
	{ iso1DC_EVSEStatusCodeType_Reserved_9, "Reserved_9" },
	{ iso1DC_EVSEStatusCodeType_Reserved_A, "Reserved_A" },
	{ iso1DC_EVSEStatusCodeType_Reserved_B, "Reserved_B" },
	{ iso1DC_EVSEStatusCodeType_Reserved_C, "Reserved_C" }
};

static const value_string v2giso1_cost_kind_names[] = {
	{ iso1costKindType_relativePricePercentage,
	  "relativePricePercentage" },
	{ iso1costKindType_RenewableGenerationPercentage,
	  "RenewableGenerationPercentage" },
	{ iso1costKindType_CarbonDioxideEmission,
	  "CarbonDioxideEmission" }
};

static const value_string v2giso1_response_code_names[] = {
	{ iso1responseCodeType_OK, "OK" },
	{ iso1responseCodeType_OK_NewSessionEstablished,
	  "OK (NewSessionEstablished" },
	{ iso1responseCodeType_OK_OldSessionJoined,
	  "OK (OldSessionJoined)" },
	{ iso1responseCodeType_OK_CertificateExpiresSoon,
	  "OK (CertificateExpiresSoon)" },
	{ iso1responseCodeType_FAILED, "FAILED" },
	{ iso1responseCodeType_FAILED_SequenceError,
	  "FAILED (SequenceError)" },
	{ iso1responseCodeType_FAILED_ServiceIDInvalid,
	  "FAILED (ServiceIDInvalid)" },
	{ iso1responseCodeType_FAILED_UnknownSession,
	  "FAILED (UnknownSession)" },
	{ iso1responseCodeType_FAILED_ServiceSelectionInvalid,
	  "FAILED (ServiceSelectionInvalid)" },
	{ iso1responseCodeType_FAILED_PaymentSelectionInvalid,
	  "FAILED (PaymentSelectionInvalid)" },
	{ iso1responseCodeType_FAILED_CertificateExpired,
	  "FAILED (CertificateExpired)" },
	{ iso1responseCodeType_FAILED_SignatureError,
	  "FAILED (SignatureError)" },
	{ iso1responseCodeType_FAILED_NoCertificateAvailable,
	  "FAILED (NoCertificateAvailable)" },
	{ iso1responseCodeType_FAILED_CertChainError,
	  "FAILED (CertChainError)" },
	{ iso1responseCodeType_FAILED_ChallengeInvalid,
	  "FAILED (ChallengeInvalid)" },
	{ iso1responseCodeType_FAILED_ContractCanceled,
	  "FAILED (ContractCanceled)" },
	{ iso1responseCodeType_FAILED_WrongChargeParameter,
	  "FAILED (WrongChargeParameter)" },
	{ iso1responseCodeType_FAILED_PowerDeliveryNotApplied,
	  "FAILED (PowerDeliveryNotApplied)" },
	{ iso1responseCodeType_FAILED_TariffSelectionInvalid,
	  "FAILED (TariffSelectionInvalid)" },
	{ iso1responseCodeType_FAILED_ChargingProfileInvalid,
	  "FAILED (ChargingProfileInvalid)" },
	{ iso1responseCodeType_FAILED_MeteringSignatureNotValid,
	  "FAILED (MeteringSignatureNotValid)" },
	{ iso1responseCodeType_FAILED_NoChargeServiceSelected,
	  "FAILED (NoChargeServiceSelected)" },
	{ iso1responseCodeType_FAILED_WrongEnergyTransferMode,
	  "FAILED (WrongEnergyTransferMode)" },
	{ iso1responseCodeType_FAILED_ContactorError,
	  "FAILED (ContactorError)" },
	{ iso1responseCodeType_FAILED_CertificateNotAllowedAtThisEVSE,
	  "FAILED (CertificateNotAllowedAtThisEVSE)" },
	{ iso1responseCodeType_FAILED_CertificateRevoked,
	  "FAILED (CertificateRevoked)" }
};

static const value_string v2giso1_evse_processing_names[] = {
	{ iso1EVSEProcessingType_Finished, "Finished" },
	{ iso1EVSEProcessingType_Ongoing, "Ongoing" },
	{ iso1EVSEProcessingType_Ongoing_WaitingForCustomerInteraction,
	  "Ongoing (WaitingForCustomerInteraction)" }
};

static const value_string v2giso1_charge_progress_names[] = {
	{ iso1chargeProgressType_Start, "Start" },
	{ iso1chargeProgressType_Stop, "Stop" },
	{ iso1chargeProgressType_Renegotiate, "Renegotiate" }
};

static const value_string v2giso1_charging_session_names[] = {
	{ iso1chargingSessionType_Terminate, "Terminate" },
	{ iso1chargingSessionType_Pause, "Pause" }
};


static void
dissect_v2giso1_notification(const struct iso1NotificationType *notification,
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
		hf_v2giso1_struct_iso1NotificationType_FaultCode,
		tvb, 0, 0, notification->FaultCode);
	proto_item_set_generated(it);

	if (notification->FaultMsg_isUsed) {
		exi_add_characters(subtree,
			hf_v2giso1_struct_iso1NotificationType_FaultMsg,
			tvb,
			notification->FaultMsg.characters,
			notification->FaultMsg.charactersLen,
			sizeof(notification->FaultMsg.characters));
	}

	return;
}

static void
dissect_v2giso1_object(const struct iso1ObjectType *object,
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
			hf_v2giso1_struct_iso1ObjectType_Id,
			tvb,
			object->Id.characters,
			object->Id.charactersLen,
			sizeof(object->Id.characters));
	}
	if (object->MimeType_isUsed) {
		exi_add_characters(subtree,
			hf_v2giso1_struct_iso1ObjectType_MimeType,
			tvb,
			object->MimeType.characters,
			object->MimeType.charactersLen,
			sizeof(object->MimeType.characters));
	}
	if (object->Encoding_isUsed) {
		exi_add_characters(subtree,
			hf_v2giso1_struct_iso1ObjectType_Encoding,
			tvb,
			object->Encoding.characters,
			object->Encoding.charactersLen,
			sizeof(object->Encoding.characters));
	}
	if (object->ANY_isUsed) {
		exi_add_characters(subtree,
			hf_v2giso1_struct_iso1ObjectType_ANY,
			tvb,
			object->ANY.characters,
			object->ANY.charactersLen,
			sizeof(object->ANY.characters));
	}

	return;
}

static void
dissect_v2giso1_transform(const struct iso1TransformType *transform,
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
		hf_v2giso1_struct_iso1TransformType_Algorithm,
		tvb,
		transform->Algorithm.characters,
		transform->Algorithm.charactersLen,
		sizeof(transform->Algorithm.characters));

	if (transform->ANY_isUsed) {
		exi_add_characters(subtree,
			hf_v2giso1_struct_iso1TransformType_ANY,
			tvb,
			transform->ANY.characters,
			transform->ANY.charactersLen,
			sizeof(transform->ANY.characters));
	}

	xpath_tree = proto_tree_add_subtree(subtree,
		tvb, 0, 0, ett_v2giso1_array, NULL, "XPath");
	for (i = 0; i < transform->XPath.arrayLen; i++) {
		xpath_i_tree = proto_tree_add_subtree_format(xpath_tree,
			tvb, 0, 0, ett_v2giso1_array_i, NULL, "[%u]", i);
		exi_add_characters(xpath_i_tree,
			hf_v2giso1_struct_iso1TransformType_XPath,
			tvb,
			transform->XPath.array[i].characters,
			transform->XPath.array[i].charactersLen,
			sizeof(transform->XPath.array[i].characters));
	}

	return;
}

static void
dissect_v2giso1_transforms(const struct iso1TransformsType *transforms,
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
		tvb, 0, 0, ett_v2giso1_array, NULL, "Transform");
	for (i = 0; i < transforms->Transform.arrayLen; i++) {
		char index[sizeof("[65536]")];

		snprintf(index, sizeof(index), "[%u]", i);
		dissect_v2giso1_transform(&transforms->Transform.array[i], tvb,
			transform_tree, ett_v2giso1_struct_iso1TransformType,
			index);
	}

	return;
}

static void
dissect_v2giso1_digestmethod(const struct iso1DigestMethodType *digestmethod,
			     tvbuff_t *tvb,
			     proto_tree *tree,
			     gint idx,
			     const char *subtree_name)
{
	proto_tree *subtree;

	subtree = proto_tree_add_subtree(tree,
		tvb, 0, 0, idx, NULL, subtree_name);

	exi_add_characters(subtree,
		hf_v2giso1_struct_iso1DigestMethodType_Algorithm,
		tvb,
		digestmethod->Algorithm.characters,
		digestmethod->Algorithm.charactersLen,
		sizeof(digestmethod->Algorithm.characters));

	if (digestmethod->ANY_isUsed) {
		exi_add_characters(subtree,
			hf_v2giso1_struct_iso1DigestMethodType_ANY,
			tvb,
			digestmethod->ANY.characters,
			digestmethod->ANY.charactersLen,
			sizeof(digestmethod->ANY.characters));
	}

	return;
}

static void
dissect_v2giso1_reference(const struct iso1ReferenceType *reference,
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
			hf_v2giso1_struct_iso1ReferenceType_Id,
			tvb,
			reference->Id.characters,
			reference->Id.charactersLen,
			sizeof(reference->Id.characters));
	}
	if (reference->URI_isUsed) {
		exi_add_characters(subtree,
			hf_v2giso1_struct_iso1ReferenceType_URI,
			tvb,
			reference->URI.characters,
			reference->URI.charactersLen,
			sizeof(reference->URI.characters));
	}
	if (reference->Type_isUsed) {
		exi_add_characters(subtree,
			hf_v2giso1_struct_iso1ReferenceType_Type,
			tvb,
			reference->Type.characters,
			reference->Type.charactersLen,
			sizeof(reference->Type.characters));
	}
	if (reference->Transforms_isUsed) {
		dissect_v2giso1_transforms(&reference->Transforms,
			tvb, subtree, ett_v2giso1_struct_iso1TransformsType,
			"Transforms");
	}

	dissect_v2giso1_digestmethod(&reference->DigestMethod,
			tvb, subtree, ett_v2giso1_struct_iso1DigestMethodType,
			"DigestMethod");

	exi_add_bytes(subtree,
		hf_v2giso1_struct_iso1ReferenceType_DigestValue,
		tvb,
		reference->DigestValue.bytes,
		reference->DigestValue.bytesLen,
		sizeof(reference->DigestValue.bytes));

	return;
}

static void
dissect_v2giso1_canonicalizationmethod(
	const struct iso1CanonicalizationMethodType *canonicalizationmethod,
	tvbuff_t *tvb,
	proto_tree *tree,
	gint idx,
	const char *subtree_name)
{
	proto_tree *subtree;

	subtree = proto_tree_add_subtree(tree,
		tvb, 0, 0, idx, NULL, subtree_name);

	exi_add_characters(subtree,
		hf_v2giso1_struct_iso1CanonicalizationMethodType_Algorithm,
		tvb,
		canonicalizationmethod->Algorithm.characters,
		canonicalizationmethod->Algorithm.charactersLen,
		sizeof(canonicalizationmethod->Algorithm.characters));

	if (canonicalizationmethod->ANY_isUsed) {
		exi_add_characters(subtree,
			hf_v2giso1_struct_iso1CanonicalizationMethodType_ANY,
			tvb,
			canonicalizationmethod->ANY.characters,
			canonicalizationmethod->ANY.charactersLen,
			sizeof(canonicalizationmethod->ANY.characters));
	}

	return;
}

static void
dissect_v2giso1_signaturemethod(
	const struct iso1SignatureMethodType *signaturemethod,
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
		hf_v2giso1_struct_iso1SignatureMethodType_Algorithm,
		tvb,
		signaturemethod->Algorithm.characters,
		signaturemethod->Algorithm.charactersLen,
		sizeof(signaturemethod->Algorithm.characters));

	if (signaturemethod->HMACOutputLength_isUsed) {
		it = proto_tree_add_int64(subtree,
			hf_v2giso1_struct_iso1SignatureMethodType_HMACOutputLength,
			tvb, 0, 0, signaturemethod->HMACOutputLength);
		proto_item_set_generated(it);
	}

	if (signaturemethod->ANY_isUsed) {
		exi_add_characters(subtree,
			hf_v2giso1_struct_iso1SignatureMethodType_ANY,
			tvb,
			signaturemethod->ANY.characters,
			signaturemethod->ANY.charactersLen,
			sizeof(signaturemethod->ANY.characters));
	}

	return;
}

static void
dissect_v2giso1_signaturevalue(
	const struct iso1SignatureValueType *signaturevalue,
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
			hf_v2giso1_struct_iso1SignatureValueType_Id,
			tvb,
			signaturevalue->Id.characters,
			signaturevalue->Id.charactersLen,
			sizeof(signaturevalue->Id.characters));
	}

	exi_add_bytes(subtree,
		hf_v2giso1_struct_iso1SignatureValueType_CONTENT,
		tvb,
		signaturevalue->CONTENT.bytes,
		signaturevalue->CONTENT.bytesLen,
		sizeof(signaturevalue->CONTENT.bytes));

	return;
}

static void
dissect_v2giso1_signedinfo(const struct iso1SignedInfoType *signedinfo,
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
			hf_v2giso1_struct_iso1SignedInfoType_Id,
			tvb,
			signedinfo->Id.characters,
			signedinfo->Id.charactersLen,
			sizeof(signedinfo->Id.characters));
	}

	dissect_v2giso1_canonicalizationmethod(
		&signedinfo->CanonicalizationMethod, tvb, subtree,
		ett_v2giso1_struct_iso1CanonicalizationMethodType,
		"CanonicalizationMethod");
	dissect_v2giso1_signaturemethod(
		&signedinfo->SignatureMethod, tvb, subtree,
		ett_v2giso1_struct_iso1SignatureMethodType,
		"SignatureMethod");

	reference_tree = proto_tree_add_subtree(subtree,
		tvb, 0, 0, ett_v2giso1_array, NULL, "Reference");
	for (i = 0; i < signedinfo->Reference.arrayLen; i++) {
		char index[sizeof("[65536]")];

		snprintf(index, sizeof(index), "[%u]", i);
		dissect_v2giso1_reference(&signedinfo->Reference.array[i], tvb,
			reference_tree, ett_v2giso1_struct_iso1ReferenceType,
			index);
	}

	return;
}

static void
dissect_v2giso1_dsakeyvalue(const struct iso1DSAKeyValueType *dsakeyvalue,
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
			hf_v2giso1_struct_iso1DSAKeyValueType_P,
			tvb,
			dsakeyvalue->P.bytes,
			dsakeyvalue->P.bytesLen,
			sizeof(dsakeyvalue->P.bytes));
	}
	if (dsakeyvalue->Q_isUsed) {
		exi_add_bytes(subtree,
			hf_v2giso1_struct_iso1DSAKeyValueType_Q,
			tvb,
			dsakeyvalue->Q.bytes,
			dsakeyvalue->Q.bytesLen,
			sizeof(dsakeyvalue->Q.bytes));
	}
	if (dsakeyvalue->G_isUsed) {
		exi_add_bytes(subtree,
			hf_v2giso1_struct_iso1DSAKeyValueType_G,
			tvb,
			dsakeyvalue->G.bytes,
			dsakeyvalue->G.bytesLen,
			sizeof(dsakeyvalue->G.bytes));
	}
	exi_add_bytes(subtree,
		hf_v2giso1_struct_iso1DSAKeyValueType_Y,
		tvb,
		dsakeyvalue->Y.bytes,
		dsakeyvalue->Y.bytesLen,
		sizeof(dsakeyvalue->Y.bytes));
	if (dsakeyvalue->J_isUsed) {
		exi_add_bytes(subtree,
			hf_v2giso1_struct_iso1DSAKeyValueType_J,
			tvb,
			dsakeyvalue->J.bytes,
			dsakeyvalue->J.bytesLen,
			sizeof(dsakeyvalue->J.bytes));
	}
	if (dsakeyvalue->Seed_isUsed) {
		exi_add_bytes(subtree,
			hf_v2giso1_struct_iso1DSAKeyValueType_Seed,
			tvb,
			dsakeyvalue->Seed.bytes,
			dsakeyvalue->Seed.bytesLen,
			sizeof(dsakeyvalue->Seed.bytes));
	}
	if (dsakeyvalue->PgenCounter_isUsed) {
		exi_add_bytes(subtree,
			hf_v2giso1_struct_iso1DSAKeyValueType_PgenCounter,
			tvb,
			dsakeyvalue->PgenCounter.bytes,
			dsakeyvalue->PgenCounter.bytesLen,
			sizeof(dsakeyvalue->PgenCounter.bytes));
	}

	return;
}

static void
dissect_v2giso1_rsakeyvalue(const struct iso1RSAKeyValueType *rsakeyvalue,
			    tvbuff_t *tvb,
			    proto_tree *tree,
			    gint idx,
			    const char *subtree_name)
{
	proto_tree *subtree;

	subtree = proto_tree_add_subtree(tree,
		tvb, 0, 0, idx, NULL, subtree_name);

	exi_add_bytes(subtree,
		hf_v2giso1_struct_iso1RSAKeyValueType_Modulus,
		tvb,
		rsakeyvalue->Modulus.bytes,
		rsakeyvalue->Modulus.bytesLen,
		sizeof(rsakeyvalue->Modulus.bytes));

	exi_add_bytes(subtree,
		hf_v2giso1_struct_iso1RSAKeyValueType_Exponent,
		tvb,
		rsakeyvalue->Exponent.bytes,
		rsakeyvalue->Exponent.bytesLen,
		sizeof(rsakeyvalue->Exponent.bytes));

	return;
}

static void
dissect_v2giso1_keyvalue(const struct iso1KeyValueType *keyvalue,
			 tvbuff_t *tvb,
			 proto_tree *tree,
			 gint idx,
			 const char *subtree_name)
{
	proto_tree *subtree;

	subtree = proto_tree_add_subtree(tree,
		tvb, 0, 0, idx, NULL, subtree_name);

	if (keyvalue->DSAKeyValue_isUsed) {
		dissect_v2giso1_dsakeyvalue(&keyvalue->DSAKeyValue,
			tvb, subtree, ett_v2giso1_struct_iso1DSAKeyValueType,
			"DSAKeyValue");
	}
	if (keyvalue->RSAKeyValue_isUsed) {
		dissect_v2giso1_rsakeyvalue(&keyvalue->RSAKeyValue,
			tvb, subtree, ett_v2giso1_struct_iso1RSAKeyValueType,
			"RSAKeyValue");
	}

	exi_add_characters(subtree,
		hf_v2giso1_struct_iso1KeyValueType_ANY,
		tvb,
		keyvalue->ANY.characters,
		keyvalue->ANY.charactersLen,
		sizeof(keyvalue->ANY.characters));

	return;
}

static void
dissect_v2giso1_retrievalmethod(
	const struct iso1RetrievalMethodType *retrievalmethod,
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
			hf_v2giso1_struct_iso1RetrievalMethodType_URI,
			tvb,
			retrievalmethod->URI.characters,
			retrievalmethod->URI.charactersLen,
			sizeof(retrievalmethod->URI.characters));
	}
	if (retrievalmethod->Type_isUsed) {
		exi_add_characters(subtree,
			hf_v2giso1_struct_iso1RetrievalMethodType_Type,
			tvb,
			retrievalmethod->Type.characters,
			retrievalmethod->Type.charactersLen,
			sizeof(retrievalmethod->Type.characters));
	}
	if (retrievalmethod->Transforms_isUsed) {
		dissect_v2giso1_transforms(&retrievalmethod->Transforms,
			tvb, subtree, ett_v2giso1_struct_iso1TransformsType,
			"Transforms");
	}

	return;
}

static void
dissect_v2giso1_x509issuerserial(
	const struct iso1X509IssuerSerialType *x509issuerserial,
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
		hf_v2giso1_struct_iso1X509IssuerSerialType_X509IssuerName,
		tvb,
		x509issuerserial->X509IssuerName.characters,
		x509issuerserial->X509IssuerName.charactersLen,
		sizeof(x509issuerserial->X509IssuerName.characters));

	it = proto_tree_add_int64(subtree,
		hf_v2giso1_struct_iso1X509IssuerSerialType_X509SerialNumber_negative,
		tvb, 0, 0, x509issuerserial->X509SerialNumber.negative);
	proto_item_set_generated(it);

	exi_add_bytes(subtree,
		hf_v2giso1_struct_iso1X509IssuerSerialType_X509SerialNumber_data,
		tvb,
		x509issuerserial->X509SerialNumber.data,
		x509issuerserial->X509SerialNumber.len,
		sizeof(x509issuerserial->X509SerialNumber.data));

	return;
}

static void
dissect_v2giso1_x509data(const struct iso1X509DataType *x509data,
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
		tvb, 0, 0, ett_v2giso1_array, NULL, "X509IssuerSerial");
	for (i = 0; i < x509data->X509IssuerSerial.arrayLen; i++) {
		char index[sizeof("[65536]")];

		snprintf(index, sizeof(index), "[%u]", i);
		dissect_v2giso1_x509issuerserial(
			&x509data->X509IssuerSerial.array[i],
			tvb, x509issuerserial_tree,
			ett_v2giso1_struct_iso1X509IssuerSerialType, index);
	}

	x509ski_tree = proto_tree_add_subtree(subtree,
		tvb, 0, 0, ett_v2giso1_array, NULL, "X509SKI");
	for (i = 0; i < x509data->X509SKI.arrayLen; i++) {
		x509ski_i_tree = proto_tree_add_subtree_format(x509ski_tree,
			tvb, 0, 0, ett_v2giso1_array_i, NULL, "[%u]", i);
		exi_add_bytes(x509ski_i_tree,
			hf_v2giso1_struct_iso1X509DataType_X509SKI,
			tvb,
			x509data->X509SKI.array[i].bytes,
			x509data->X509SKI.array[i].bytesLen,
			sizeof(x509data->X509SKI.array[i].bytes));
	}

	x509subjectname_tree = proto_tree_add_subtree(subtree,
		tvb, 0, 0, ett_v2giso1_array, NULL, "X509SKI");
	for (i = 0; i < x509data->X509SubjectName.arrayLen; i++) {
		x509subjectname_i_tree = proto_tree_add_subtree_format(
			x509subjectname_tree,
			tvb, 0, 0, ett_v2giso1_array_i, NULL, "[%u]", i);
		exi_add_characters(x509subjectname_i_tree,
			hf_v2giso1_struct_iso1X509DataType_X509SubjectName,
			tvb,
			x509data->X509SubjectName.array[i].characters,
			x509data->X509SubjectName.array[i].charactersLen,
			sizeof(x509data->X509SubjectName.array[i].characters));
	}

	x509certificate_tree = proto_tree_add_subtree(subtree,
		tvb, 0, 0, ett_v2giso1_array, NULL, "X509SKI");
	for (i = 0; i < x509data->X509Certificate.arrayLen; i++) {
		x509certificate_i_tree = proto_tree_add_subtree_format(
			x509certificate_tree,
			tvb, 0, 0, ett_v2giso1_array_i, NULL, "[%u]", i);
		exi_add_bytes(x509certificate_i_tree,
			hf_v2giso1_struct_iso1X509DataType_X509Certificate,
			tvb,
			x509data->X509Certificate.array[i].bytes,
			x509data->X509Certificate.array[i].bytesLen,
			sizeof(x509data->X509Certificate.array[i].bytes));
	}

	x509crl_tree = proto_tree_add_subtree(subtree,
		tvb, 0, 0, ett_v2giso1_array, NULL, "X509CRL");
	for (i = 0; i < x509data->X509CRL.arrayLen; i++) {
		x509crl_i_tree = proto_tree_add_subtree_format(x509crl_tree,
			tvb, 0, 0, ett_v2giso1_array_i, NULL, "[%u]", i);
		exi_add_bytes(x509crl_i_tree,
			hf_v2giso1_struct_iso1X509DataType_X509CRL,
			tvb,
			x509data->X509CRL.array[i].bytes,
			x509data->X509CRL.array[i].bytesLen,
			sizeof(x509data->X509CRL.array[i].bytes));
	}

	if (x509data->ANY_isUsed) {
		exi_add_characters(subtree,
			hf_v2giso1_struct_iso1X509DataType_ANY,
			tvb,
			x509data->ANY.characters,
			x509data->ANY.charactersLen,
			sizeof(x509data->ANY.characters));
	}

	return;
}

static void
dissect_v2giso1_pgpdata(const struct iso1PGPDataType *pgpdata,
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
			hf_v2giso1_struct_iso1PGPDataType_PGPKeyID,
			tvb,
			pgpdata->PGPKeyID.bytes,
			pgpdata->PGPKeyID.bytesLen,
			sizeof(pgpdata->PGPKeyID.bytes));
	}

	if (pgpdata->PGPKeyPacket_isUsed) {
		exi_add_bytes(subtree,
			hf_v2giso1_struct_iso1PGPDataType_PGPKeyPacket,
			tvb,
			pgpdata->PGPKeyPacket.bytes,
			pgpdata->PGPKeyPacket.bytesLen,
			sizeof(pgpdata->PGPKeyPacket.bytes));
	}

	if (pgpdata->ANY_isUsed) {
		exi_add_characters(subtree,
			hf_v2giso1_struct_iso1PGPDataType_ANY,
			tvb,
			pgpdata->ANY.characters,
			pgpdata->ANY.charactersLen,
			sizeof(pgpdata->ANY.characters));
	}

	return;
}

static void
dissect_v2giso1_spkidata(const struct iso1SPKIDataType *spkidata,
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
		tvb, 0, 0, ett_v2giso1_array, NULL, "SPKISexp");
	for (i = 0; i < spkidata->SPKISexp.arrayLen; i++) {
		spkisexp_i_tree = proto_tree_add_subtree_format(spkisexp_tree,
			tvb, 0, 0, ett_v2giso1_array_i, NULL, "[%u]", i);
		exi_add_bytes(spkisexp_i_tree,
			hf_v2giso1_struct_iso1SPKIDataType_SPKISexp,
			tvb,
			spkidata->SPKISexp.array[i].bytes,
			spkidata->SPKISexp.array[i].bytesLen,
			sizeof(spkidata->SPKISexp.array[i].bytes));
	}

	if (spkidata->ANY_isUsed) {
		exi_add_characters(subtree,
			hf_v2giso1_struct_iso1SPKIDataType_ANY,
			tvb,
			spkidata->ANY.characters,
			spkidata->ANY.charactersLen,
			sizeof(spkidata->ANY.characters));
	}

	return;
}

static void
dissect_v2giso1_keyinfo(const struct iso1KeyInfoType *keyinfo,
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
			hf_v2giso1_struct_iso1KeyInfoType_Id,
			tvb,
			keyinfo->Id.characters,
			keyinfo->Id.charactersLen,
			sizeof(keyinfo->Id.characters));
	}

	keyname_tree = proto_tree_add_subtree(subtree,
		tvb, 0, 0, ett_v2giso1_array, NULL, "KeyName");
	for (i = 0; i < keyinfo->KeyName.arrayLen; i++) {
		keyname_i_tree = proto_tree_add_subtree_format(keyname_tree,
			tvb, 0, 0, ett_v2giso1_array_i, NULL, "[%u]", i);
		exi_add_characters(keyname_i_tree,
			hf_v2giso1_struct_iso1KeyInfoType_KeyName,
			tvb,
			keyinfo->KeyName.array[i].characters,
			keyinfo->KeyName.array[i].charactersLen,
			sizeof(keyinfo->KeyName.array[i].characters));
	}

	keyvalue_tree = proto_tree_add_subtree(subtree,
		tvb, 0, 0, ett_v2giso1_array, NULL, "KeyValue");
	for (i = 0; i < keyinfo->KeyValue.arrayLen; i++) {
		char index[sizeof("[65536]")];

		snprintf(index, sizeof(index), "[%u]", i);
		dissect_v2giso1_keyvalue(&keyinfo->KeyValue.array[i],
					tvb, keyvalue_tree,
					ett_v2giso1_struct_iso1KeyValueType,
					index);
	}

	retrievalmethod_tree = proto_tree_add_subtree(subtree,
		tvb, 0, 0, ett_v2giso1_array, NULL, "RetrievalMethod");
	for (i = 0; i < keyinfo->RetrievalMethod.arrayLen; i++) {
		char index[sizeof("[65536]")];

		snprintf(index, sizeof(index), "[%u]", i);
		dissect_v2giso1_retrievalmethod(
			&keyinfo->RetrievalMethod.array[i],
			tvb, retrievalmethod_tree,
			ett_v2giso1_struct_iso1RetrievalMethodType,
			index);
	}

	x509data_tree = proto_tree_add_subtree(subtree,
		tvb, 0, 0, ett_v2giso1_array, NULL, "X509Data");
	for (i = 0; i < keyinfo->X509Data.arrayLen; i++) {
		char index[sizeof("[65536]")];

		snprintf(index, sizeof(index), "[%u]", i);
		dissect_v2giso1_x509data(&keyinfo->X509Data.array[i],
					tvb, x509data_tree,
					ett_v2giso1_struct_iso1X509DataType,
					index);
	}

	pgpdata_tree = proto_tree_add_subtree(subtree,
		tvb, 0, 0, ett_v2giso1_array, NULL, "PGPData");
	for (i = 0; i < keyinfo->PGPData.arrayLen; i++) {
		char index[sizeof("[65536]")];

		snprintf(index, sizeof(index), "[%u]", i);
		dissect_v2giso1_pgpdata(&keyinfo->PGPData.array[i],
				       tvb, pgpdata_tree,
				       ett_v2giso1_struct_iso1PGPDataType,
				       index);
	}

	spkidata_tree = proto_tree_add_subtree(subtree,
		tvb, 0, 0, ett_v2giso1_array, NULL, "SPKIData");
	for (i = 0; i < keyinfo->SPKIData.arrayLen; i++) {
		char index[sizeof("[65536]")];

		snprintf(index, sizeof(index), "[%u]", i);
		dissect_v2giso1_spkidata(&keyinfo->SPKIData.array[i],
					tvb, spkidata_tree,
					ett_v2giso1_struct_iso1SPKIDataType,
					index);
	}

	mgmtdata_tree = proto_tree_add_subtree(subtree,
		tvb, 0, 0, ett_v2giso1_array, NULL, "MgmtData");
	for (i = 0; i < keyinfo->MgmtData.arrayLen; i++) {
		mgmtdata_i_tree = proto_tree_add_subtree_format(mgmtdata_tree,
			tvb, 0, 0, ett_v2giso1_array_i, NULL, "[%u]", i);
		exi_add_characters(mgmtdata_i_tree,
			hf_v2giso1_struct_iso1KeyInfoType_MgmtData,
			tvb,
			keyinfo->MgmtData.array[i].characters,
			keyinfo->MgmtData.array[i].charactersLen,
			sizeof(keyinfo->MgmtData.array[i].characters));
	}

	if (keyinfo->ANY_isUsed) {
		exi_add_characters(subtree,
			hf_v2giso1_struct_iso1KeyInfoType_ANY,
			tvb,
			keyinfo->ANY.characters,
			keyinfo->ANY.charactersLen,
			sizeof(keyinfo->ANY.characters));
	}

	return;
}

static void
dissect_v2giso1_signature(const struct iso1SignatureType *signature,
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
			hf_v2giso1_struct_iso1SignatureType_Id,
			tvb,
			signature->Id.characters,
			signature->Id.charactersLen,
			sizeof(signature->Id.characters));
	}

	dissect_v2giso1_signedinfo(&signature->SignedInfo, tvb,
		subtree, ett_v2giso1_struct_iso1SignedInfoType, "SignedInfo");
	dissect_v2giso1_signaturevalue(&signature->SignatureValue, tvb,
		subtree, ett_v2giso1_struct_iso1SignatureValueType,
		"SignatureValue");

	if (signature->KeyInfo_isUsed) {
		dissect_v2giso1_keyinfo(&signature->KeyInfo, tvb,
			subtree, ett_v2giso1_struct_iso1KeyInfoType, "KeyInfo");
	}

	object_tree = proto_tree_add_subtree(subtree,
		tvb, 0, 0, ett_v2giso1_array, NULL, "Object");
	for (i = 0; i < signature->Object.arrayLen; i++) {
		char index[sizeof("[65536]")];

		snprintf(index, sizeof(index), "[%u]", i);
		dissect_v2giso1_object(&signature->Object.array[i], tvb,
			object_tree, ett_v2giso1_struct_iso1ObjectType, index);
	}

	return;
}


static void
dissect_v2giso1_header(const struct iso1MessageHeaderType *header,
		       tvbuff_t *tvb,
		       proto_tree *tree,
		       gint idx,
		       const char *subtree_name)
{
	proto_tree *subtree;

	subtree = proto_tree_add_subtree(tree,
		tvb, 0, 0, idx, NULL, subtree_name);

	exi_add_bytes(subtree,
		hf_v2giso1_struct_iso1MessageHeaderType_SessionID,
		tvb,
		header->SessionID.bytes,
		header->SessionID.bytesLen,
		sizeof(header->SessionID.bytes));

	if (header->Notification_isUsed) {
		dissect_v2giso1_notification(
			&header->Notification, tvb, subtree,
			ett_v2giso1_struct_iso1NotificationType,
			"Notification");
	}

	if (header->Signature_isUsed) {
		dissect_v2giso1_signature(
			&header->Signature, tvb, subtree,
			ett_v2giso1_struct_iso1SignatureType,
			"Signature");
	}

	return;
}

static void
dissect_v2giso1_paymentoptionlist(
	const struct iso1PaymentOptionListType *paymentoptionlist,
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
		tvb, 0, 0, ett_v2giso1_array, NULL, "PaymentOption");
	for (i = 0; i < paymentoptionlist->PaymentOption.arrayLen; i++) {
		char index[sizeof("[65536]")];

		snprintf(index, sizeof(index), "[%u]", i);
		paymentoption_i_tree = proto_tree_add_subtree(
			paymentoption_tree, tvb, 0, 0,
			ett_v2giso1_array_i, NULL, index);

		it = proto_tree_add_uint(paymentoption_i_tree,
			hf_v2giso1_struct_iso1PaymentOptionLstType_PaymentOption,
			tvb, 0, 0,
			paymentoptionlist->PaymentOption.array[i]);
		proto_item_set_generated(it);
	}

	return;
}

static void
dissect_v2giso1_supportedenergytransfermode(
	const struct iso1SupportedEnergyTransferModeType
		 *supportedenergytransfermode,
	tvbuff_t *tvb,
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
		tvb, 0, 0, ett_v2giso1_array, NULL, "EnergyTransferMode");
	for (i = 0; i < supportedenergytransfermode->EnergyTransferMode.arrayLen; i++) {
		energytransfermode_i_tree = proto_tree_add_subtree_format(
			energytransfermode_tree,
			tvb, 0, 0, ett_v2giso1_array_i, NULL, "[%u]", i);

		it = proto_tree_add_uint(energytransfermode_i_tree,
			hf_v2giso1_struct_iso1SupportedEnergyTransferModeType_EnergyTransferMode,
			tvb, 0, 0,
			supportedenergytransfermode->EnergyTransferMode.array[i]);
		proto_item_set_generated(it);
	}

	return;
}

static void
dissect_v2giso1_chargeservice(
	const struct iso1ChargeServiceType *chargeservice,
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
		hf_v2giso1_struct_iso1ChargeServiceType_ServiceID,
		tvb, 0, 0, chargeservice->ServiceID);
	proto_item_set_generated(it);

	if (chargeservice->ServiceName_isUsed) {
		exi_add_characters(subtree,
			hf_v2giso1_struct_iso1ChargeServiceType_ServiceName,
			tvb,
			chargeservice->ServiceName.characters,
			chargeservice->ServiceName.charactersLen,
			sizeof(chargeservice->ServiceName.characters));
	}

	it = proto_tree_add_uint(subtree,
		hf_v2giso1_struct_iso1ChargeServiceType_ServiceCategory,
		tvb, 0, 0, chargeservice->ServiceCategory);
	proto_item_set_generated(it);

	if (chargeservice->ServiceScope_isUsed) {
		exi_add_characters(subtree,
			hf_v2giso1_struct_iso1ChargeServiceType_ServiceScope,
			tvb,
			chargeservice->ServiceScope.characters,
			chargeservice->ServiceScope.charactersLen,
			sizeof(chargeservice->ServiceScope.characters));
	}

	it = proto_tree_add_int(subtree,
		hf_v2giso1_struct_iso1ChargeServiceType_FreeService,
		tvb, 0, 0, chargeservice->FreeService);
	proto_item_set_generated(it);

	dissect_v2giso1_supportedenergytransfermode(
		&chargeservice->SupportedEnergyTransferMode,
		tvb, subtree,
		ett_v2giso1_struct_iso1SupportedEnergyTransferModeType,
		"SupportedEnergyTransferMode");

	return;
}

static void
dissect_v2giso1_service(
	const struct iso1ServiceType *service,
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
		hf_v2giso1_struct_iso1ServiceType_ServiceID,
		tvb, 0, 0, service->ServiceID);
	proto_item_set_generated(it);

	if (service->ServiceName_isUsed) {
		exi_add_characters(subtree,
			hf_v2giso1_struct_iso1ServiceType_ServiceName,
			tvb,
			service->ServiceName.characters,
			service->ServiceName.charactersLen,
			sizeof(service->ServiceName.characters));
	}

	it = proto_tree_add_uint(subtree,
		hf_v2giso1_struct_iso1ServiceType_ServiceCategory,
		tvb, 0, 0, service->ServiceCategory);
	proto_item_set_generated(it);

	if (service->ServiceScope_isUsed) {
		exi_add_characters(subtree,
			hf_v2giso1_struct_iso1ServiceType_ServiceScope,
			tvb,
			service->ServiceScope.characters,
			service->ServiceScope.charactersLen,
			sizeof(service->ServiceScope.characters));
	}

	it = proto_tree_add_int(subtree,
		hf_v2giso1_struct_iso1ServiceType_FreeService, tvb, 0, 0,
		service->FreeService);
	proto_item_set_generated(it);

	return;
}

static void
dissect_v2giso1_servicelist(
	const struct iso1ServiceListType *servicelist,
	tvbuff_t *tvb,
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
		tvb, 0, 0, ett_v2giso1_array, NULL, "Service");
	for (i = 0; i < servicelist->Service.arrayLen; i++) {
		char index[sizeof("[65536]")];

		snprintf(index, sizeof(index), "[%u]", i);
		dissect_v2giso1_service(
			&servicelist->Service.array[i],
			tvb, service_tree,
			ett_v2giso1_struct_iso1ServiceType, index);
	}

	return;
}

static void
dissect_v2giso1_physicalvalue(
	const struct iso1PhysicalValueType *physicalvalue,
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
		hf_v2giso1_struct_iso1PhysicalValueType_Multiplier,
		tvb, 0, 0, physicalvalue->Multiplier);
	proto_item_set_generated(it);

	it = proto_tree_add_uint(subtree,
		hf_v2giso1_struct_iso1PhysicalValueType_Unit,
		tvb, 0, 0, physicalvalue->Unit);
	proto_item_set_generated(it);

	it = proto_tree_add_int(subtree,
		hf_v2giso1_struct_iso1PhysicalValueType_Value,
		tvb, 0, 0, physicalvalue->Value);
	proto_item_set_generated(it);

	return;
}

static void
dissect_v2giso1_parameter(
	const struct iso1ParameterType *parameter,
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
		hf_v2giso1_struct_iso1ParameterType_Name,
		tvb,
		parameter->Name.characters,
		parameter->Name.charactersLen,
		sizeof(parameter->Name.characters));

	if (parameter->boolValue_isUsed) {
		it = proto_tree_add_int(subtree,
			hf_v2giso1_struct_iso1ParameterType_boolValue,
			tvb, 0, 0, parameter->boolValue);
		proto_item_set_generated(it);
	}
	if (parameter->byteValue_isUsed) {
		it = proto_tree_add_int(subtree,
			hf_v2giso1_struct_iso1ParameterType_byteValue,
			tvb, 0, 0, parameter->byteValue);
		proto_item_set_generated(it);
	}
	if (parameter->shortValue_isUsed) {
		it = proto_tree_add_int(subtree,
			hf_v2giso1_struct_iso1ParameterType_shortValue,
			tvb, 0, 0, parameter->shortValue);
		proto_item_set_generated(it);
	}
	if (parameter->intValue_isUsed) {
		it = proto_tree_add_int(subtree,
			hf_v2giso1_struct_iso1ParameterType_intValue,
			tvb, 0, 0, parameter->intValue);
		proto_item_set_generated(it);
	}
	if (parameter->physicalValue_isUsed) {
		dissect_v2giso1_physicalvalue(&parameter->physicalValue,
			tvb, subtree, ett_v2giso1_struct_iso1PhysicalValueType,
			"physicalValue");
	}
	if (parameter->stringValue_isUsed) {
		exi_add_characters(subtree,
			hf_v2giso1_struct_iso1ParameterType_stringValue,
			tvb,
			parameter->stringValue.characters,
			parameter->stringValue.charactersLen,
			sizeof(parameter->stringValue.characters));
	}

	return;
}

static void
dissect_v2giso1_parameterset(
	const struct iso1ParameterSetType *parameterset,
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
		hf_v2giso1_struct_iso1ParameterSetType_ParameterSetID,
		tvb, 0, 0, parameterset->ParameterSetID);
	proto_item_set_generated(it);

	parameter_tree = proto_tree_add_subtree(subtree,
		tvb, 0, 0, ett_v2giso1_array, NULL, "Parameter");
	for (i = 0; i < parameterset->Parameter.arrayLen; i++) {
		char index[sizeof("[65536]")];

		dissect_v2giso1_parameter(
			&parameterset->Parameter.array[i],
			tvb, parameter_tree,
			ett_v2giso1_struct_iso1ParameterType, index);
	}

	return;
}

static void
dissect_v2giso1_serviceparameterlist(
	const struct iso1ServiceParameterListType *serviceparameterlist,
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
		tvb, 0, 0, ett_v2giso1_array, NULL, "ParameterSet");
	for (i = 0; i < serviceparameterlist->ParameterSet.arrayLen; i++) {
		char index[sizeof("[65536]")];

		dissect_v2giso1_parameterset(
			&serviceparameterlist->ParameterSet.array[i],
			tvb, parameterset_tree,
			ett_v2giso1_struct_iso1ParameterSetType, index);
	}

	return;
}

static void
dissect_v2giso1_selectedservice(
	const struct iso1SelectedServiceType *selectedservice,
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
		hf_v2giso1_struct_iso1SelectedServiceType_ServiceID,
		tvb, 0, 0, selectedservice->ServiceID);
	proto_item_set_generated(it);

	if (selectedservice->ParameterSetID_isUsed) {
		it = proto_tree_add_int(subtree,
			hf_v2giso1_struct_iso1SelectedServiceType_ParameterSetID,
			tvb, 0, 0, selectedservice->ParameterSetID);
		proto_item_set_generated(it);
	}

	return;
}

static void
dissect_v2giso1_selectedservicelist(
	const struct iso1SelectedServiceListType *selectedservicelist,
	tvbuff_t *tvb,
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
		tvb, 0, 0, ett_v2giso1_array, NULL, "SelectedService");
	for (i = 0; i < selectedservicelist->SelectedService.arrayLen; i++) {
		char index[sizeof("[65536]")];

		dissect_v2giso1_selectedservice(
			&selectedservicelist->SelectedService.array[i],
			tvb, selectedservice_tree,
			ett_v2giso1_struct_iso1SelectedServiceType, index);
	}

	return;
}

static void
dissect_v2giso1_subcertificates(
	const struct iso1SubCertificatesType *subcertificates,
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
		tvb, 0, 0, ett_v2giso1_array, NULL, "Certificate");
	for (i = 0; i < subcertificates->Certificate.arrayLen; i++) {
		certificate_i_tree = proto_tree_add_subtree_format(
			certificate_tree,
			tvb, 0, 0, ett_v2giso1_array_i, NULL, "[%u]", i);
		exi_add_bytes(certificate_i_tree,
			hf_v2giso1_struct_iso1SubCertificatesType_Certificate,
			tvb,
			subcertificates->Certificate.array[i].bytes,
			subcertificates->Certificate.array[i].bytesLen,
			sizeof(subcertificates->Certificate.array[i].bytes));
	}

	return;
}

static void
dissect_v2giso1_certificatechain(
	const struct iso1CertificateChainType *certificatechain,
	tvbuff_t *tvb,
	proto_tree *tree,
	gint idx,
	const char *subtree_name)
{
	proto_tree *subtree;

	subtree = proto_tree_add_subtree(tree, tvb, 0, 0,
		idx, NULL, subtree_name);

	if (certificatechain->Id_isUsed) {
		exi_add_characters(subtree,
			hf_v2giso1_struct_iso1CertificateChainType_Id,
			tvb,
			certificatechain->Id.characters,
			certificatechain->Id.charactersLen,
			sizeof(certificatechain->Id.characters));
	}

	exi_add_bytes(subtree,
		hf_v2giso1_struct_iso1CertificateChainType_Certificate,
		tvb,
		certificatechain->Certificate.bytes,
		certificatechain->Certificate.bytesLen,
		sizeof(certificatechain->Certificate.bytes));

	if (certificatechain->SubCertificates_isUsed) {
		dissect_v2giso1_subcertificates(
			&certificatechain->SubCertificates,
			tvb, subtree,
			ett_v2giso1_struct_iso1SubCertificatesType,
			"SubCertificates");
	}

	return;
}

static void
dissect_v2giso1_evchargeparameter(
	const struct iso1EVChargeParameterType *evchargeparameter,
	tvbuff_t *tvb,
	proto_tree *tree,
	gint idx,
	const char *subtree_name)
{
	/* no content */
	return;
}

static void
dissect_v2giso1_ac_evchargeparameter(
	const struct iso1AC_EVChargeParameterType *ac_evchargeparameter,
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
		hf_v2giso1_struct_iso1AC_EVChargeParameterType_DepartureTime,
		tvb, 0, 0, ac_evchargeparameter->DepartureTime);
	proto_item_set_generated(it);

	dissect_v2giso1_physicalvalue(&ac_evchargeparameter->EAmount,
		tvb, subtree, ett_v2giso1_struct_iso1PhysicalValueType,
		"EAmount");

	dissect_v2giso1_physicalvalue(&ac_evchargeparameter->EVMaxVoltage,
		tvb, subtree, ett_v2giso1_struct_iso1PhysicalValueType,
		"EVMaxVoltage");

	dissect_v2giso1_physicalvalue(&ac_evchargeparameter->EVMaxCurrent,
		tvb, subtree, ett_v2giso1_struct_iso1PhysicalValueType,
		"EVMaxCurrent");

	dissect_v2giso1_physicalvalue(&ac_evchargeparameter->EVMinCurrent,
		tvb, subtree, ett_v2giso1_struct_iso1PhysicalValueType,
		"EVMinCurrent");

	return;
}

static void
dissect_v2giso1_dc_evstatus(
	const struct iso1DC_EVStatusType *dc_evstatus,
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
		hf_v2giso1_struct_iso1DC_EVStatusType_EVReady,
		tvb, 0, 0, dc_evstatus->EVReady);
	proto_item_set_generated(it);

	it = proto_tree_add_uint(subtree,
		hf_v2giso1_struct_iso1DC_EVStatusType_EVErrorCode,
		tvb, 0, 0, dc_evstatus->EVErrorCode);
	proto_item_set_generated(it);

	it = proto_tree_add_int(subtree,
		hf_v2giso1_struct_iso1DC_EVStatusType_EVRESSSOC,
		tvb, 0, 0, dc_evstatus->EVRESSSOC);
	proto_item_set_generated(it);

	return;
}

static void
dissect_v2giso1_dc_evchargeparameter(
	const struct iso1DC_EVChargeParameterType *dc_evchargeparameter,
	tvbuff_t *tvb,
	proto_tree *tree,
	gint idx,
	const char *subtree_name)
{
	proto_tree *subtree;
	proto_item *it;

	subtree = proto_tree_add_subtree(tree, tvb, 0, 0,
		idx, NULL, subtree_name);

	if (dc_evchargeparameter->DepartureTime_isUsed) {
		it = proto_tree_add_uint(subtree,
			hf_v2giso1_struct_iso1DC_EVChargeParameterType_DepartureTime,
			tvb, 0, 0, dc_evchargeparameter->DepartureTime);
		proto_item_set_generated(it);
	}

	dissect_v2giso1_dc_evstatus(&dc_evchargeparameter->DC_EVStatus,
		tvb, subtree, ett_v2giso1_struct_iso1DC_EVStatusType,
		"DC_EVStatus");

	dissect_v2giso1_physicalvalue(
		&dc_evchargeparameter->EVMaximumVoltageLimit,
		tvb, subtree, ett_v2giso1_struct_iso1PhysicalValueType,
		"EVMaximumVoltageLimit");

	dissect_v2giso1_physicalvalue(
		&dc_evchargeparameter->EVMaximumCurrentLimit,
		tvb, subtree, ett_v2giso1_struct_iso1PhysicalValueType,
		"EVMaximumCurrentLimit");

	if (dc_evchargeparameter->EVMaximumPowerLimit_isUsed) {
		dissect_v2giso1_physicalvalue(
			&dc_evchargeparameter->EVMaximumPowerLimit,
			tvb, subtree, ett_v2giso1_struct_iso1PhysicalValueType,
			"EVMaximumPowertLimit");
	}

	if (dc_evchargeparameter->EVEnergyCapacity_isUsed) {
		dissect_v2giso1_physicalvalue(
			&dc_evchargeparameter->EVEnergyCapacity,
			tvb, subtree, ett_v2giso1_struct_iso1PhysicalValueType,
			"EVEnergyCapacity");
	}

	if (dc_evchargeparameter->EVEnergyRequest_isUsed) {
		dissect_v2giso1_physicalvalue(
			&dc_evchargeparameter->EVEnergyRequest,
			tvb, subtree, ett_v2giso1_struct_iso1PhysicalValueType,
			"EVEnergyRequest");
	}

	if (dc_evchargeparameter->FullSOC_isUsed) {
		it = proto_tree_add_int(subtree,
			hf_v2giso1_struct_iso1DC_EVChargeParameterType_FullSOC,
			tvb, 0, 0, dc_evchargeparameter->FullSOC);
		proto_item_set_generated(it);
	}

	if (dc_evchargeparameter->BulkSOC_isUsed) {
		it = proto_tree_add_int(subtree,
			hf_v2giso1_struct_iso1DC_EVChargeParameterType_BulkSOC,
			tvb, 0, 0, dc_evchargeparameter->BulkSOC);
		proto_item_set_generated(it);
	}

	return;
}

static void
dissect_v2giso1_evsestatus(
	const struct iso1EVSEStatusType *evsestatus,
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
		hf_v2giso1_struct_iso1EVSEStatusType_NotificationMaxDelay,
		tvb, 0, 0, evsestatus->NotificationMaxDelay);
	proto_item_set_generated(it);

	it = proto_tree_add_uint(subtree,
		hf_v2giso1_struct_iso1EVSEStatusType_EVSENotification,
		tvb, 0, 0, evsestatus->EVSENotification);
	proto_item_set_generated(it);

	return;
}

static void
dissect_v2giso1_ac_evsestatus(
	const struct iso1AC_EVSEStatusType *ac_evsestatus,
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
		hf_v2giso1_struct_iso1AC_EVSEStatusType_NotificationMaxDelay,
		tvb, 0, 0, ac_evsestatus->NotificationMaxDelay);
	proto_item_set_generated(it);

	it = proto_tree_add_uint(subtree,
		hf_v2giso1_struct_iso1AC_EVSEStatusType_EVSENotification,
		tvb, 0, 0, ac_evsestatus->EVSENotification);
	proto_item_set_generated(it);

	it = proto_tree_add_int(subtree,
		hf_v2giso1_struct_iso1AC_EVSEStatusType_RCD,
		tvb, 0, 0, ac_evsestatus->RCD);
	proto_item_set_generated(it);

	return;
}

static void
dissect_v2giso1_dc_evsestatus(
	const struct iso1DC_EVSEStatusType *dc_evsestatus,
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
		hf_v2giso1_struct_iso1DC_EVSEStatusType_NotificationMaxDelay,
		tvb, 0, 0, dc_evsestatus->NotificationMaxDelay);
	proto_item_set_generated(it);

	it = proto_tree_add_uint(subtree,
		hf_v2giso1_struct_iso1DC_EVSEStatusType_EVSENotification,
		tvb, 0, 0, dc_evsestatus->EVSENotification);
	proto_item_set_generated(it);

	if (dc_evsestatus->EVSEIsolationStatus_isUsed) {
		it = proto_tree_add_uint(subtree,
			hf_v2giso1_struct_iso1DC_EVSEStatusType_EVSEIsolationStatus,
			tvb, 0, 0, dc_evsestatus->EVSEIsolationStatus);
		proto_item_set_generated(it);
	}

	it = proto_tree_add_uint(subtree,
		hf_v2giso1_struct_iso1DC_EVSEStatusType_EVSEStatusCode,
		tvb, 0, 0, dc_evsestatus->EVSEStatusCode);
	proto_item_set_generated(it);

	return;
};

static void
dissect_v2giso1_evsechargeparameter(
	const struct iso1EVSEChargeParameterType *evsechargeparameter,
	tvbuff_t *tvb,
	proto_tree *tree,
	gint idx,
	const char *subtree_name)
{
	/* no content */
	return;
}

static void
dissect_v2giso1_ac_evsechargeparameter(
	const struct iso1AC_EVSEChargeParameterType *ac_evsechargeparameter,
	tvbuff_t *tvb,
	proto_tree *tree,
	gint idx,
	const char *subtree_name)
{
	proto_tree *subtree;

	subtree = proto_tree_add_subtree(tree, tvb, 0, 0,
		idx, NULL, subtree_name);

	dissect_v2giso1_ac_evsestatus(&ac_evsechargeparameter->AC_EVSEStatus,
		tvb, subtree, ett_v2giso1_struct_iso1AC_EVSEStatusType,
		"AC_EVSEStatus");

	dissect_v2giso1_physicalvalue(
		&ac_evsechargeparameter->EVSENominalVoltage,
		tvb, subtree, ett_v2giso1_struct_iso1PhysicalValueType,
		"EVSENominalVoltage");

	dissect_v2giso1_physicalvalue(&ac_evsechargeparameter->EVSEMaxCurrent,
		tvb, subtree, ett_v2giso1_struct_iso1PhysicalValueType,
		"EVSEMaxCurrent");

	return;
}

static void
dissect_v2giso1_dc_evsechargeparameter(
	const struct iso1DC_EVSEChargeParameterType *dc_evsechargeparameter,
	tvbuff_t *tvb,
	proto_tree *tree,
	gint idx,
	const char *subtree_name)
{
	proto_tree *subtree;

	subtree = proto_tree_add_subtree(tree, tvb, 0, 0,
		idx, NULL, subtree_name);

	dissect_v2giso1_dc_evsestatus(&dc_evsechargeparameter->DC_EVSEStatus,
		tvb, subtree, ett_v2giso1_struct_iso1DC_EVSEStatusType,
		"DC_EVSEStatus");

	dissect_v2giso1_physicalvalue(
		&dc_evsechargeparameter->EVSEMaximumVoltageLimit,
		tvb, subtree, ett_v2giso1_struct_iso1PhysicalValueType,
		"EVSEMaximumVoltageLimit");

	dissect_v2giso1_physicalvalue(
		&dc_evsechargeparameter->EVSEMinimumVoltageLimit,
		tvb, subtree, ett_v2giso1_struct_iso1PhysicalValueType,
		"EVSEMinimumVoltageLimit");

	dissect_v2giso1_physicalvalue(
		&dc_evsechargeparameter->EVSEMaximumCurrentLimit,
		tvb, subtree, ett_v2giso1_struct_iso1PhysicalValueType,
		"EVSEMaximumCurrentLimit");

	dissect_v2giso1_physicalvalue(
		&dc_evsechargeparameter->EVSEMinimumCurrentLimit,
		tvb, subtree, ett_v2giso1_struct_iso1PhysicalValueType,
		"EVSEMinimumCurrentLimit");

	dissect_v2giso1_physicalvalue(
		&dc_evsechargeparameter->EVSEMaximumPowerLimit,
		tvb, subtree, ett_v2giso1_struct_iso1PhysicalValueType,
		"EVSEMaximumPowerLimit");

	if (dc_evsechargeparameter->EVSECurrentRegulationTolerance_isUsed) {
		dissect_v2giso1_physicalvalue(
			&dc_evsechargeparameter->EVSECurrentRegulationTolerance,
			tvb, subtree, ett_v2giso1_struct_iso1PhysicalValueType,
			"EVSECurrentRegulationTolerance");
	}

	dissect_v2giso1_physicalvalue(
		&dc_evsechargeparameter->EVSEPeakCurrentRipple,
		tvb, subtree, ett_v2giso1_struct_iso1PhysicalValueType,
		"EVSEPeakCurrentRipple");

	if (dc_evsechargeparameter->EVSEEnergyToBeDelivered_isUsed) {
		dissect_v2giso1_physicalvalue(
			&dc_evsechargeparameter->EVSEEnergyToBeDelivered,
			tvb, subtree, ett_v2giso1_struct_iso1PhysicalValueType,
			"EVSEEnergyToBeDelivered");
	}

	return;
}

static void
dissect_v2giso1_interval(
	const struct iso1IntervalType *interval,
	tvbuff_t *tvb,
	proto_tree *tree,
	gint idx,
	const char *subtree_name)
{
	/* no content */
	return;
}

static void
dissect_v2giso1_relativetimeinterval(
	const struct iso1RelativeTimeIntervalType *relativetimeinterval,
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
		hf_v2giso1_struct_iso1RelativeTimeIntervalType_start,
		tvb, 0, 0, relativetimeinterval->start);
	proto_item_set_generated(it);

	if (relativetimeinterval->duration_isUsed) {
		it = proto_tree_add_uint(subtree,
			hf_v2giso1_struct_iso1RelativeTimeIntervalType_duration,
			tvb, 0, 0, relativetimeinterval->duration);
		proto_item_set_generated(it);
	}

	return;
}

static void
dissect_v2giso1_pmaxscheduleentry(
	const struct iso1PMaxScheduleEntryType *pmaxscheduleentry,
	tvbuff_t *tvb,
	proto_tree *tree,
	gint idx,
	const char *subtree_name)
{
	proto_tree *subtree;

	subtree = proto_tree_add_subtree(tree, tvb, 0, 0,
		idx, NULL, subtree_name);

	if (pmaxscheduleentry->TimeInterval_isUsed) {
		dissect_v2giso1_interval(&pmaxscheduleentry->TimeInterval,
			tvb, subtree, ett_v2giso1_struct_iso1IntervalType,
			"TimeInterval");
	}

	if (pmaxscheduleentry->RelativeTimeInterval_isUsed) {
		dissect_v2giso1_relativetimeinterval(
			&pmaxscheduleentry->RelativeTimeInterval,
			tvb, subtree,
			ett_v2giso1_struct_iso1RelativeTimeIntervalType,
			"RelativeTimeInterval");
	}

	dissect_v2giso1_physicalvalue(&pmaxscheduleentry->PMax,
		tvb, subtree,
		ett_v2giso1_struct_iso1PhysicalValueType, "PMax");

	return;
}

static void
dissect_v2giso1_pmaxschedule(
	const struct iso1PMaxScheduleType *pmaxschedule,
	tvbuff_t *tvb,
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
		tvb, 0, 0, ett_v2giso1_array, NULL, "PMaxScheduleEntry");
	for (i = 0; i < pmaxschedule->PMaxScheduleEntry.arrayLen; i++) {
		char index[sizeof("[65536]")];

		snprintf(index, sizeof(index), "[%u]", i);
		dissect_v2giso1_pmaxscheduleentry(
			&pmaxschedule->PMaxScheduleEntry.array[i],
			tvb, pmaxscheduleentry_tree,
			ett_v2giso1_struct_iso1PMaxScheduleEntryType, index);
	}

	return;
}

static void
dissect_v2giso1_cost(
	const struct iso1CostType *cost,
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
		hf_v2giso1_struct_iso1CostType_costKind,
		tvb, 0, 0, cost->costKind);
	proto_item_set_generated(it);

	it = proto_tree_add_uint(subtree,
		hf_v2giso1_struct_iso1CostType_amount,
		tvb, 0, 0, cost->amount);
	proto_item_set_generated(it);

	if (cost->amountMultiplier_isUsed) {
		it = proto_tree_add_int(subtree,
			hf_v2giso1_struct_iso1CostType_amountMultiplier,
			tvb, 0, 0, cost->amount);
		proto_item_set_generated(it);
	}

	return;
}

static void
dissect_v2giso1_consumptioncost(
	const struct iso1ConsumptionCostType *consumptioncost,
	tvbuff_t *tvb,
	proto_tree *tree,
	gint idx,
	const char *subtree_name)
{
	unsigned int i;
	proto_tree *subtree;
	proto_tree *cost_tree;

	subtree = proto_tree_add_subtree(tree, tvb, 0, 0,
		idx, NULL, subtree_name);

	dissect_v2giso1_physicalvalue(
		&consumptioncost->startValue, tvb, subtree,
		ett_v2giso1_struct_iso1PhysicalValueType, "startValue");

	cost_tree = proto_tree_add_subtree(subtree,
		tvb, 0, 0, ett_v2giso1_array, NULL, "Cost");
	for (i = 0; i < consumptioncost->Cost.arrayLen; i++) {
		char index[sizeof("[65536]")];

		snprintf(index, sizeof(index), "[%u]", i);
		dissect_v2giso1_cost(
			&consumptioncost->Cost.array[i], tvb, cost_tree,
			ett_v2giso1_struct_iso1CostType, index);
	}

	return;
}

static void
dissect_v2giso1_salestariffentry(
	const struct iso1SalesTariffEntryType *salestariffentry,
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
		dissect_v2giso1_interval(&salestariffentry->TimeInterval,
			tvb, subtree, ett_v2giso1_struct_iso1IntervalType,
			"TimeInterval");
	}

	if (salestariffentry->RelativeTimeInterval_isUsed) {
		dissect_v2giso1_relativetimeinterval(
			&salestariffentry->RelativeTimeInterval,
			tvb, subtree,
			ett_v2giso1_struct_iso1RelativeTimeIntervalType,
			"RelativeTimeInterval");
	}

	it = proto_tree_add_uint(subtree,
		hf_v2giso1_struct_iso1SalesTariffEntryType_EPriceLevel,
		tvb, 0, 0, salestariffentry->EPriceLevel);
	proto_item_set_generated(it);

	consumptioncost_tree = proto_tree_add_subtree(subtree,
		tvb, 0, 0, ett_v2giso1_array, NULL, "ConsumptionCost");
	for (i = 0; i < salestariffentry->ConsumptionCost.arrayLen; i++) {
		char index[sizeof("[65536]")];

		snprintf(index, sizeof(index), "[%u]", i);
		dissect_v2giso1_consumptioncost(
			&salestariffentry->ConsumptionCost.array[i], tvb,
			consumptioncost_tree,
			ett_v2giso1_struct_iso1ConsumptionCostType, index);
	}

	return;
}

static void
dissect_v2giso1_salestariff(
	const struct iso1SalesTariffType *salestariff,
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
		hf_v2giso1_struct_iso1SalesTariffType_Id,
		tvb,
		salestariff->Id.characters,
		salestariff->Id.charactersLen,
		sizeof(salestariff->Id.characters));

	if (salestariff->SalesTariffDescription_isUsed) {
		exi_add_characters(subtree,
			hf_v2giso1_struct_iso1SalesTariffType_SalesTariffDescription,
			tvb,
			salestariff->SalesTariffDescription.characters,
			salestariff->SalesTariffDescription.charactersLen,
			sizeof(salestariff->SalesTariffDescription.characters));
	}

	it = proto_tree_add_uint(subtree,
		hf_v2giso1_struct_iso1SalesTariffType_NumEPriceLevels,
		tvb, 0, 0, salestariff->NumEPriceLevels);
	proto_item_set_generated(it);

	salestariffentry_tree = proto_tree_add_subtree(subtree,
		tvb, 0, 0, ett_v2giso1_array, NULL, "SalesTariffEntry");
	for (i = 0; i < salestariff->SalesTariffEntry.arrayLen; i++) {
		char index[sizeof("[65536]")];

		snprintf(index, sizeof(index), "[%u]", i);
		dissect_v2giso1_salestariffentry(
			&salestariff->SalesTariffEntry.array[i], tvb,
			salestariffentry_tree,
			ett_v2giso1_struct_iso1SalesTariffEntryType, index);
	}

	return;
}

static void
dissect_v2giso1_saschedules(
	const struct iso1SASchedulesType *saschedules,
	tvbuff_t *tvb,
	proto_tree *tree,
	gint idx,
	const char *subtree_name)
{
	/* no content */
	return;
}

static void
dissect_v2giso1_sascheduletuple(
	const struct iso1SAScheduleTupleType *sascheduletuple,
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
		hf_v2giso1_struct_iso1SAScheduleTupleType_SAScheduleTupleID,
		tvb, 0, 0, sascheduletuple->SAScheduleTupleID);
	proto_item_set_generated(it);

	dissect_v2giso1_pmaxschedule(&sascheduletuple->PMaxSchedule,
		tvb, subtree, ett_v2giso1_struct_iso1PMaxScheduleType,
		"PMaxSchedule");

	if (sascheduletuple->SalesTariff_isUsed) {
		dissect_v2giso1_salestariff(&sascheduletuple->SalesTariff,
			tvb, subtree, ett_v2giso1_struct_iso1SalesTariffType,
			"SalesTariff");
	}

	return;
}

static void
dissect_v2giso1_saschedulelist(
	const struct iso1SAScheduleListType *saschedulelist,
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
		tvb, 0, 0, ett_v2giso1_array, NULL, "SAScheduleTuple");
	for (i = 0; i < saschedulelist->SAScheduleTuple.arrayLen; i++) {
		char index[sizeof("[65536]")];

		snprintf(index, sizeof(index), "[%u]", i);
		dissect_v2giso1_sascheduletuple(
			&saschedulelist->SAScheduleTuple.array[i], tvb,
			sascheduletuple_tree,
			ett_v2giso1_struct_iso1SAScheduleTupleType, index);
	}

	return;
}

static void
dissect_v2giso1_profileentry(
	const struct iso1ProfileEntryType *profileentry,
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
		hf_v2giso1_struct_iso1ProfileEntryType_ChargingProfileEntryStart,
		tvb, 0, 0, profileentry->ChargingProfileEntryStart);
	proto_item_set_generated(it);

	dissect_v2giso1_physicalvalue(
		&profileentry->ChargingProfileEntryMaxPower,
		tvb, subtree, ett_v2giso1_struct_iso1PhysicalValueType,
		"ChargingProfileEntryMaxPower");

	if (profileentry->ChargingProfileEntryMaxNumberOfPhasesInUse) {
		it = proto_tree_add_int(subtree,
			hf_v2giso1_struct_iso1ProfileEntryType_ChargingProfileEntryMaxNumberOfPhasesInUse,
			tvb, 0, 0, profileentry->ChargingProfileEntryMaxNumberOfPhasesInUse);
		proto_item_set_generated(it);
	}

	return;
}

static void
dissect_v2giso1_chargingprofile(
	const struct iso1ChargingProfileType *chargingprofile,
	tvbuff_t *tvb,
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
		tvb, 0, 0, ett_v2giso1_array, NULL, "ProfileEntry");
	for (i = 0; i < chargingprofile->ProfileEntry.arrayLen; i++) {
		char index[sizeof("[65536]")];

		snprintf(index, sizeof(index), "[%u]", i);
		dissect_v2giso1_profileentry(
			&chargingprofile->ProfileEntry.array[i], tvb,
			profileentry_tree,
			ett_v2giso1_struct_iso1ProfileEntryType, index);
	}

	return;
}

static void
dissect_v2giso1_evpowerdeliveryparameter(
	const struct iso1EVPowerDeliveryParameterType *evpowerdeliveryparameter,
	tvbuff_t *tvb,
	proto_tree *tree,
	gint idx,
	const char *subtree_name)
{
	/* no content */
	return;
}

static void
dissect_v2giso1_dc_evpowerdeliveryparameter(
	const struct iso1DC_EVPowerDeliveryParameterType *dc_evpowerdeliveryparameter,
	tvbuff_t *tvb,
	proto_tree *tree,
	gint idx,
	const char *subtree_name)
{
	proto_tree *subtree;
	proto_item *it;

	subtree = proto_tree_add_subtree(tree, tvb, 0, 0,
		idx, NULL, subtree_name);

	dissect_v2giso1_dc_evstatus(&dc_evpowerdeliveryparameter->DC_EVStatus,
		tvb, subtree, ett_v2giso1_struct_iso1DC_EVStatusType,
		"DC_EVStatus");

	if (dc_evpowerdeliveryparameter->BulkChargingComplete_isUsed) {
		it = proto_tree_add_int(subtree,
			hf_v2giso1_struct_iso1DC_EVPowerDeliveryParameterType_BulkChargingComplete,
			tvb, 0, 0,
			dc_evpowerdeliveryparameter->BulkChargingComplete);
		proto_item_set_generated(it);
	}

	it = proto_tree_add_int(subtree,
		hf_v2giso1_struct_iso1DC_EVPowerDeliveryParameterType_ChargingComplete,
		tvb, 0, 0,
		dc_evpowerdeliveryparameter->ChargingComplete);
		proto_item_set_generated(it);

	return;
}

static void
dissect_v2giso1_meterinfo(const struct iso1MeterInfoType *meterinfo,
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
		hf_v2giso1_struct_iso1MeterInfoType_MeterID,
		tvb,
		meterinfo->MeterID.characters,
		meterinfo->MeterID.charactersLen,
		sizeof(meterinfo->MeterID.characters));

	if (meterinfo->MeterReading_isUsed) {
		it = proto_tree_add_uint64(subtree,
			hf_v2giso1_struct_iso1MeterInfoType_MeterReading,
			tvb, 0, 0, meterinfo->MeterReading);
		proto_item_set_generated(it);
	}

	if (meterinfo->SigMeterReading_isUsed) {
		exi_add_bytes(subtree,
			hf_v2giso1_struct_iso1MeterInfoType_SigMeterReading,
			tvb,
			meterinfo->SigMeterReading.bytes,
			meterinfo->SigMeterReading.bytesLen,
			sizeof(meterinfo->SigMeterReading.bytes));
	}

	if (meterinfo->MeterStatus_isUsed) {
		it = proto_tree_add_int(subtree,
			hf_v2giso1_struct_iso1MeterInfoType_MeterStatus,
			tvb, 0, 0, meterinfo->MeterStatus);
		proto_item_set_generated(it);
	}

	if (meterinfo->TMeter_isUsed) {
		it = proto_tree_add_int64(subtree,
			hf_v2giso1_struct_iso1MeterInfoType_TMeter,
			tvb, 0, 0, meterinfo->TMeter);
		proto_item_set_generated(it);
	}

	return;
}

static void
dissect_v2giso1_listofrootcertificateids(
	const struct iso1ListOfRootCertificateIDsType
		*listofrootcertificateids,
	tvbuff_t *tvb,
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
		tvb, 0, 0, ett_v2giso1_array, NULL, "RootCertificateID");
	for (i = 0; i < listofrootcertificateids->RootCertificateID.arrayLen; i++) {
		char index[sizeof("[65536]")];

		snprintf(index, sizeof(index), "[%u]", i);
		dissect_v2giso1_x509issuerserial(
			&listofrootcertificateids->RootCertificateID.array[i],
			tvb, rootcertificateid_tree,
			ett_v2giso1_struct_iso1X509IssuerSerialType,
			"RootCertificateID");
	}

	return;
}

static void
dissect_v2giso1_contractsignatureencryptedprivatekey(
	const struct iso1ContractSignatureEncryptedPrivateKeyType
		*contractsignatureencryptedprivatekey,
	tvbuff_t *tvb,
	proto_tree *tree,
	gint idx,
	const char *subtree_name)
{
	proto_tree *subtree;

	subtree = proto_tree_add_subtree(tree,
		tvb, 0, 0, idx, NULL, subtree_name);

	exi_add_characters(subtree,
		hf_v2giso1_struct_iso1ContractSignatureEncryptedPrivateKeyType_Id,
		tvb,
		contractsignatureencryptedprivatekey->Id.characters,
		contractsignatureencryptedprivatekey->Id.charactersLen,
		sizeof(contractsignatureencryptedprivatekey->Id.characters));

	exi_add_bytes(subtree,
		hf_v2giso1_struct_iso1ContractSignatureEncryptedPrivateKeyType_CONTENT,
		tvb,
		contractsignatureencryptedprivatekey->CONTENT.bytes,
		contractsignatureencryptedprivatekey->CONTENT.bytesLen,
		sizeof(contractsignatureencryptedprivatekey->CONTENT.bytes));

	return;
}

static void
dissect_v2giso1_diffiehellmanpublickey(
	const struct iso1DiffieHellmanPublickeyType *diffiehellmanpublickey,
	tvbuff_t *tvb,
	proto_tree *tree,
	gint idx,
	const char *subtree_name)
{
	proto_tree *subtree;

	subtree = proto_tree_add_subtree(tree,
		tvb, 0, 0, idx, NULL, subtree_name);

	exi_add_characters(subtree,
		hf_v2giso1_struct_iso1DiffieHellmanPublickeyType_Id,
		tvb,
		diffiehellmanpublickey->Id.characters,
		diffiehellmanpublickey->Id.charactersLen,
		sizeof(diffiehellmanpublickey->Id.characters));

	exi_add_bytes(subtree,
		hf_v2giso1_struct_iso1DiffieHellmanPublickeyType_CONTENT,
		tvb,
		diffiehellmanpublickey->CONTENT.bytes,
		diffiehellmanpublickey->CONTENT.bytesLen,
		sizeof(diffiehellmanpublickey->CONTENT.bytes));

	return;
}

static void
dissect_v2giso1_emaid(
	const struct iso1EMAIDType *emaid,
	tvbuff_t *tvb,
	proto_tree *tree,
	gint idx,
	const char *subtree_name)
{
	proto_tree *subtree;

	subtree = proto_tree_add_subtree(tree,
		tvb, 0, 0, idx, NULL, subtree_name);

	exi_add_characters(subtree,
		hf_v2giso1_struct_iso1EMAIDType_Id,
		tvb,
		emaid->Id.characters,
		emaid->Id.charactersLen,
		sizeof(emaid->Id.characters));

	exi_add_characters(subtree,
		hf_v2giso1_struct_iso1EMAIDType_CONTENT,
		tvb,
		emaid->CONTENT.characters,
		emaid->CONTENT.charactersLen,
		sizeof(emaid->CONTENT.characters));

	return;
}


static void
dissect_v2giso1_sessionsetupreq(
	const struct iso1SessionSetupReqType *sessionsetupreq,
	tvbuff_t *tvb,
	proto_tree *tree,
	gint idx,
	const char *subtree_name)
{
	proto_tree *subtree;

	subtree = proto_tree_add_subtree(tree,
		tvb, 0, 0, idx, NULL, subtree_name);

	exi_add_bytes(subtree,
		hf_v2giso1_struct_iso1SessionSetupReqType_EVCCID,
		tvb,
		sessionsetupreq->EVCCID.bytes,
		sessionsetupreq->EVCCID.bytesLen,
		sizeof(sessionsetupreq->EVCCID.bytes));

	return;
}

static void
dissect_v2giso1_sessionsetupres(
	const struct iso1SessionSetupResType *sessionsetupres,
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
		hf_v2giso1_struct_iso1SessionSetupResType_ResponseCode,
		tvb, 0, 0, sessionsetupres->ResponseCode);
	proto_item_set_generated(it);

	exi_add_characters(subtree,
		hf_v2giso1_struct_iso1SessionSetupResType_EVSEID,
		tvb,
		sessionsetupres->EVSEID.characters,
		sessionsetupres->EVSEID.charactersLen,
		sizeof(sessionsetupres->EVSEID.characters));

	if (sessionsetupres->EVSETimeStamp_isUsed) {
		it = proto_tree_add_int64(subtree,
			hf_v2giso1_struct_iso1SessionSetupResType_EVSETimeStamp,
			tvb, 0, 0, sessionsetupres->EVSETimeStamp);
		proto_item_set_generated(it);
	}

	return;
}

static void
dissect_v2giso1_servicediscoveryreq(
	const struct iso1ServiceDiscoveryReqType *servicediscoveryreq,
	tvbuff_t *tvb,
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
			hf_v2giso1_struct_iso1ServiceDiscoveryReqType_ServiceScope,
			tvb,
			servicediscoveryreq->ServiceScope.characters,
			servicediscoveryreq->ServiceScope.charactersLen,
			sizeof(servicediscoveryreq->ServiceScope.characters));
	}

	if (servicediscoveryreq->ServiceCategory_isUsed) {
		it = proto_tree_add_uint(subtree,
			hf_v2giso1_struct_iso1ServiceDiscoveryReqType_ServiceCategory,
			tvb, 0, 0, servicediscoveryreq->ServiceCategory);
		proto_item_set_generated(it);
	}

	return;
}

static void
dissect_v2giso1_servicediscoveryres(
	const struct iso1ServiceDiscoveryResType *servicediscoveryres,
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
		hf_v2giso1_struct_iso1ServiceDiscoveryResType_ResponseCode,
		tvb, 0, 0, servicediscoveryres->ResponseCode);
	proto_item_set_generated(it);

	dissect_v2giso1_paymentoptionlist(
		&servicediscoveryres->PaymentOptionList,
		tvb, subtree,
		ett_v2giso1_struct_iso1PaymentOptionListType,
		"PaymentOptionList");

	dissect_v2giso1_chargeservice(
		&servicediscoveryres->ChargeService,
		tvb, subtree,
		ett_v2giso1_struct_iso1ChargeServiceType,
		"ChargeService");

	if (servicediscoveryres->ServiceList_isUsed) {
		dissect_v2giso1_servicelist(
			&servicediscoveryres->ServiceList,
			tvb, subtree,
			ett_v2giso1_struct_iso1ServiceListType,
			"ServiceList");
	}

	return;
}

static void
dissect_v2giso1_servicedetailreq(
	const struct iso1ServiceDetailReqType *servicedetailreq,
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
		hf_v2giso1_struct_iso1ServiceDetailReqType_ServiceID,
		tvb, 0, 0, servicedetailreq->ServiceID);
	proto_item_set_generated(it);

	return;
}

static void
dissect_v2giso1_servicedetailres(
	const struct iso1ServiceDetailResType *servicedetailres,
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
		hf_v2giso1_struct_iso1ServiceDetailResType_ResponseCode,
		tvb, 0, 0, servicedetailres->ResponseCode);
	proto_item_set_generated(it);

	it = proto_tree_add_uint(subtree,
		hf_v2giso1_struct_iso1ServiceDetailResType_ServiceID,
		tvb, 0, 0, servicedetailres->ServiceID);
	proto_item_set_generated(it);

	if (servicedetailres->ServiceParameterList_isUsed) {
		dissect_v2giso1_serviceparameterlist(
			&servicedetailres->ServiceParameterList,
			tvb, subtree,
			ett_v2giso1_struct_iso1ServiceParameterListType,
			"ServiceParameterList");
	}

	return;
}

static void
dissect_v2giso1_paymentserviceselectionreq(
	const struct iso1PaymentServiceSelectionReqType
		*paymentserviceselectionreq,
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
		hf_v2giso1_struct_iso1PaymentServiceSelectionReqType_SelectedPaymentOption,
		tvb, 0, 0, paymentserviceselectionreq->SelectedPaymentOption);
	proto_item_set_generated(it);

	dissect_v2giso1_selectedservicelist(
		&paymentserviceselectionreq->SelectedServiceList,
		tvb, subtree,
		ett_v2giso1_struct_iso1SelectedServiceListType,
		"SelectedServiceList");

	return;
}

static void
dissect_v2giso1_paymentserviceselectionres(
	const struct iso1PaymentServiceSelectionResType
		*paymentserviceselectionres,
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
		hf_v2giso1_struct_iso1PaymentServiceSelectionResType_ResponseCode,
		tvb, 0, 0,
		paymentserviceselectionres->ResponseCode);
	proto_item_set_generated(it);

	return;
}

static void
dissect_v2giso1_paymentdetailsreq(
	const struct iso1PaymentDetailsReqType *paymentdetailsreq,
	tvbuff_t *tvb,
	proto_tree *tree,
	gint idx,
	const char *subtree_name)
{
	proto_tree *subtree;

	subtree = proto_tree_add_subtree(tree,
		tvb, 0, 0, idx, NULL, subtree_name);

	exi_add_characters(subtree,
		hf_v2giso1_struct_iso1PaymentDetailsReqType_eMAID,
		tvb,
		paymentdetailsreq->eMAID.characters,
		paymentdetailsreq->eMAID.charactersLen,
		sizeof(paymentdetailsreq->eMAID.characters));

	dissect_v2giso1_certificatechain(
		&paymentdetailsreq->ContractSignatureCertChain,
		tvb, subtree,
		ett_v2giso1_struct_iso1CertificateChainType,
		"ContractSignatureCertChain");

	return;
}

static void
dissect_v2giso1_paymentdetailsres(
	const struct iso1PaymentDetailsResType *paymentdetailsres,
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
		hf_v2giso1_struct_iso1PaymentDetailsResType_ResponseCode,
		tvb, 0, 0,
		paymentdetailsres->ResponseCode);
	proto_item_set_generated(it);

	exi_add_bytes(subtree,
		hf_v2giso1_struct_iso1PaymentDetailsResType_GenChallenge,
		tvb,
		paymentdetailsres->GenChallenge.bytes,
		paymentdetailsres->GenChallenge.bytesLen,
		sizeof(paymentdetailsres->GenChallenge.bytes));

	it = proto_tree_add_int64(subtree,
		hf_v2giso1_struct_iso1PaymentDetailsResType_EVSETimeStamp,
		tvb, 0, 0,
		paymentdetailsres->EVSETimeStamp);
	proto_item_set_generated(it);

	return;
}

static void
dissect_v2giso1_authorizationreq(
	const struct iso1AuthorizationReqType *authorizationreq,
	tvbuff_t *tvb,
	proto_tree *tree,
	gint idx,
	const char *subtree_name)
{
	proto_tree *subtree;

	subtree = proto_tree_add_subtree(tree,
		tvb, 0, 0, idx, NULL, subtree_name);

	if (authorizationreq->Id_isUsed) {
		exi_add_characters(subtree,
			hf_v2giso1_struct_iso1AuthorizationReqType_Id,
			tvb,
			authorizationreq->Id.characters,
			authorizationreq->Id.charactersLen,
			sizeof(authorizationreq->Id.characters));
	}

	if (authorizationreq->GenChallenge_isUsed) {
		exi_add_bytes(subtree,
			hf_v2giso1_struct_iso1AuthorizationReqType_GenChallenge,
			tvb,
			authorizationreq->GenChallenge.bytes,
			authorizationreq->GenChallenge.bytesLen,
			sizeof(authorizationreq->GenChallenge.bytes));
	}

	return;
}

static void
dissect_v2giso1_authorizationres(
	const struct iso1AuthorizationResType *authorizationres,
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
		hf_v2giso1_struct_iso1AuthorizationResType_ResponseCode,
		tvb, 0, 0,
		authorizationres->ResponseCode);
	proto_item_set_generated(it);

	it = proto_tree_add_uint(subtree,
		hf_v2giso1_struct_iso1AuthorizationResType_EVSEProcessing,
		tvb, 0, 0,
		authorizationres->EVSEProcessing);
	proto_item_set_generated(it);

	return;
}

static void
dissect_v2giso1_chargeparameterdiscoveryreq(
	const struct iso1ChargeParameterDiscoveryReqType
		*chargeparameterdiscoveryreq,
	tvbuff_t *tvb,
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
			hf_v2giso1_struct_iso1ChargeParameterDiscoveryReqType_MaxEntriesSAScheduleTuple,
			tvb, 0, 0,
			chargeparameterdiscoveryreq->MaxEntriesSAScheduleTuple);
	}

	it = proto_tree_add_uint(subtree,
		hf_v2giso1_struct_iso1ChargeParameterDiscoveryReqType_RequestedEnergyTransferType,
		tvb, 0, 0,
		chargeparameterdiscoveryreq->RequestedEnergyTransferMode);
	proto_item_set_generated(it);

	if (chargeparameterdiscoveryreq->EVChargeParameter_isUsed) {
		dissect_v2giso1_evchargeparameter(
			&chargeparameterdiscoveryreq->EVChargeParameter,
			tvb, subtree,
			ett_v2giso1_struct_iso1EVChargeParameterType,
			"EVChargeParameter");
	}

	if (chargeparameterdiscoveryreq->AC_EVChargeParameter_isUsed) {
		dissect_v2giso1_ac_evchargeparameter(
			&chargeparameterdiscoveryreq->AC_EVChargeParameter,
			tvb, subtree,
			ett_v2giso1_struct_iso1AC_EVChargeParameterType,
			"AC_EVChargeParameter");
	}

	if (chargeparameterdiscoveryreq->DC_EVChargeParameter_isUsed) {
		dissect_v2giso1_dc_evchargeparameter(
			&chargeparameterdiscoveryreq->DC_EVChargeParameter,
			tvb, subtree,
			ett_v2giso1_struct_iso1DC_EVChargeParameterType,
			"DC_EVChargeParameter");
	}

	return;
}

static void
dissect_v2giso1_chargeparameterdiscoveryres(
	const struct iso1ChargeParameterDiscoveryResType
		*chargeparameterdiscoveryres,
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
		hf_v2giso1_struct_iso1ChargeParameterDiscoveryResType_ResponseCode,
		tvb, 0, 0,
		chargeparameterdiscoveryres->ResponseCode);
	proto_item_set_generated(it);

	it = proto_tree_add_uint(subtree,
		hf_v2giso1_struct_iso1ChargeParameterDiscoveryResType_EVSEProcessing,
		tvb, 0, 0,
		chargeparameterdiscoveryres->EVSEProcessing);
	proto_item_set_generated(it);

	if (chargeparameterdiscoveryres->SASchedules_isUsed) {
		dissect_v2giso1_saschedules(
			&chargeparameterdiscoveryres->SASchedules,
			tvb, subtree,
			ett_v2giso1_struct_iso1SASchedulesType,
			"SASchedules");
	}
	if (chargeparameterdiscoveryres->SAScheduleList_isUsed) {
		dissect_v2giso1_saschedulelist(
			&chargeparameterdiscoveryres->SAScheduleList,
			tvb, subtree,
			ett_v2giso1_struct_iso1SAScheduleListType,
			"SAScheduleList");
	}
	if (chargeparameterdiscoveryres->EVSEChargeParameter_isUsed) {
		dissect_v2giso1_evsechargeparameter(&chargeparameterdiscoveryres->EVSEChargeParameter,
			tvb, subtree,
			ett_v2giso1_struct_iso1EVSEChargeParameterType,
			"EVSEChargeParameter");
	}
	if (chargeparameterdiscoveryres->AC_EVSEChargeParameter_isUsed) {
		dissect_v2giso1_ac_evsechargeparameter(
			&chargeparameterdiscoveryres->AC_EVSEChargeParameter,
			tvb, subtree,
			ett_v2giso1_struct_iso1AC_EVSEChargeParameterType,
			"AC_EVSEChargeParameter");
	}
	if (chargeparameterdiscoveryres->DC_EVSEChargeParameter_isUsed) {
		dissect_v2giso1_dc_evsechargeparameter(
			&chargeparameterdiscoveryres->DC_EVSEChargeParameter,
			tvb, subtree,
			ett_v2giso1_struct_iso1DC_EVSEChargeParameterType,
			"DC_EVSEChargeParameter");
	}

	return;
}

static void
dissect_v2giso1_powerdeliveryreq(
	const struct iso1PowerDeliveryReqType *powerdeliveryreq,
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
		hf_v2giso1_struct_iso1PowerDeliveryReqType_ChargeProgress,
		tvb, 0, 0, powerdeliveryreq->ChargeProgress);
	proto_item_set_generated(it);

	it = proto_tree_add_uint(subtree,
		hf_v2giso1_struct_iso1PowerDeliveryReqType_SAScheduleTupleID,
		tvb, 0, 0, powerdeliveryreq->SAScheduleTupleID);
	proto_item_set_generated(it);

	if (powerdeliveryreq->ChargingProfile_isUsed) {
		dissect_v2giso1_chargingprofile(
			&powerdeliveryreq->ChargingProfile,
			tvb, subtree,
			ett_v2giso1_struct_iso1ChargingProfileType,
			"ChargingProfile");
	}
	if (powerdeliveryreq->EVPowerDeliveryParameter_isUsed) {
		dissect_v2giso1_evpowerdeliveryparameter(
			&powerdeliveryreq->EVPowerDeliveryParameter,
			tvb, subtree,
			ett_v2giso1_struct_iso1EVPowerDeliveryParameterType,
			"EVPowerDeliveryParameter");
	}
	if (powerdeliveryreq->DC_EVPowerDeliveryParameter_isUsed) {
		dissect_v2giso1_dc_evpowerdeliveryparameter(
			&powerdeliveryreq->DC_EVPowerDeliveryParameter,
			tvb, subtree,
			ett_v2giso1_struct_iso1DC_EVPowerDeliveryParameterType,
			"DC_EVPowerDeliveryParameter");
	}

	return;
}

static void
dissect_v2giso1_powerdeliveryres(
	const struct iso1PowerDeliveryResType *powerdeliveryres,
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
		hf_v2giso1_struct_iso1PowerDeliveryResType_ResponseCode,
		tvb, 0, 0,
		powerdeliveryres->ResponseCode);
	proto_item_set_generated(it);

	if (powerdeliveryres->EVSEStatus_isUsed) {
		dissect_v2giso1_evsestatus(
			&powerdeliveryres->EVSEStatus,
			tvb, subtree,
			ett_v2giso1_struct_iso1EVSEStatusType,
			"EVSEStatus");
	}
	if (powerdeliveryres->AC_EVSEStatus_isUsed) {
		dissect_v2giso1_ac_evsestatus(
			&powerdeliveryres->AC_EVSEStatus,
			tvb, subtree,
			ett_v2giso1_struct_iso1AC_EVSEStatusType,
			"AC_EVSEStatus");
	}
	if (powerdeliveryres->DC_EVSEStatus_isUsed) {
		dissect_v2giso1_dc_evsestatus(
			&powerdeliveryres->DC_EVSEStatus,
			tvb, subtree,
			ett_v2giso1_struct_iso1DC_EVSEStatusType,
			"DC_EVSEStatus");
	}

	return;
}

static void
dissect_v2giso1_meteringreceiptreq(
	const struct iso1MeteringReceiptReqType *meteringreceiptreq,
	tvbuff_t *tvb,
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
			hf_v2giso1_struct_iso1MeteringReceiptReqType_Id,
			tvb,
			meteringreceiptreq->Id.characters,
			meteringreceiptreq->Id.charactersLen,
			sizeof(meteringreceiptreq->Id.characters));
	}

	exi_add_bytes(subtree,
		hf_v2giso1_struct_iso1MeteringReceiptReqType_SessionID,
		tvb,
		meteringreceiptreq->SessionID.bytes,
		meteringreceiptreq->SessionID.bytesLen,
		sizeof(meteringreceiptreq->SessionID.bytes));

	if (meteringreceiptreq->SAScheduleTupleID_isUsed) {
		it = proto_tree_add_int(subtree,
			hf_v2giso1_struct_iso1MeteringReceiptReqType_SAScheduleTupleID,
			tvb, 0, 0,
			meteringreceiptreq->SAScheduleTupleID);
		proto_item_set_generated(it);
	}

	dissect_v2giso1_meterinfo(
		&meteringreceiptreq->MeterInfo,
		tvb, subtree,
		ett_v2giso1_struct_iso1MeterInfoType,
		"MeterInfo");

	return;
}

static void
dissect_v2giso1_meteringreceiptres(
	const struct iso1MeteringReceiptResType *meteringreceiptres,
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
		hf_v2giso1_struct_iso1MeteringReceiptResType_ResponseCode,
		tvb, 0, 0,
		meteringreceiptres->ResponseCode);
	proto_item_set_generated(it);

	dissect_v2giso1_ac_evsestatus(
		&meteringreceiptres->AC_EVSEStatus,
		tvb, subtree,
		ett_v2giso1_struct_iso1AC_EVSEStatusType,
		"AC_EVSEStatus");

	return;
}

static void
dissect_v2giso1_sessionstopreq(
	const struct iso1SessionStopReqType *sessionstopreq,
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
		hf_v2giso1_struct_iso1SessionStopReqType_ChargingSession,
		tvb, 0, 0, sessionstopreq->ChargingSession);
	proto_item_set_generated(it);

	return;
}

static void
dissect_v2giso1_sessionstopres(
	const struct iso1SessionStopResType *sessionstopres,
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
		hf_v2giso1_struct_iso1SessionStopResType_ResponseCode,
		tvb, 0, 0, sessionstopres->ResponseCode);
	proto_item_set_generated(it);

	return;
}

static void
dissect_v2giso1_certificateupdatereq(
	const struct iso1CertificateUpdateReqType *req,
	tvbuff_t *tvb,
	proto_tree *tree,
	gint idx,
	const char *subtree_name)
{
	proto_tree *subtree;

	subtree = proto_tree_add_subtree(tree,
		tvb, 0, 0, idx, NULL, subtree_name);

	exi_add_characters(subtree,
		hf_v2giso1_struct_iso1CertificateUpdateReqType_Id,
		tvb,
		req->Id.characters,
		req->Id.charactersLen,
		sizeof(req->Id.characters));

	dissect_v2giso1_certificatechain(
		&req->ContractSignatureCertChain,
		tvb, subtree,
		ett_v2giso1_struct_iso1CertificateChainType,
		"ContractSignatureCertChain");

	exi_add_characters(subtree,
		hf_v2giso1_struct_iso1CertificateUpdateReqType_eMAID,
		tvb,
		req->eMAID.characters,
		req->eMAID.charactersLen,
		sizeof(req->eMAID.characters));

	dissect_v2giso1_listofrootcertificateids(
		&req->ListOfRootCertificateIDs,
		tvb, subtree,
		ett_v2giso1_struct_iso1ListOfRootCertificateIDsType,
		"ListOfRootCertificateIDs");

	return;
}

static void
dissect_v2giso1_certificateupdateres(
	const struct iso1CertificateUpdateResType *res,
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
		hf_v2giso1_struct_iso1CertificateUpdateResType_ResponseCode,
		tvb, 0, 0, res->ResponseCode);
	proto_item_set_generated(it);

	dissect_v2giso1_certificatechain(
		&res->SAProvisioningCertificateChain,
		tvb, subtree,
		ett_v2giso1_struct_iso1CertificateChainType,
		"SAProvisioningCertificateChain");

	dissect_v2giso1_certificatechain(
		&res->ContractSignatureCertChain,
		tvb, subtree,
		ett_v2giso1_struct_iso1CertificateChainType,
		"ContractSignatureCertChain");

	dissect_v2giso1_contractsignatureencryptedprivatekey(
		&res->ContractSignatureEncryptedPrivateKey,
		tvb, subtree,
		ett_v2giso1_struct_iso1ContractSignatureEncryptedPrivateKeyType,
		"ContractSignatureEncryptedPrivateKey");

	dissect_v2giso1_diffiehellmanpublickey(
		&res->DHpublickey,
		tvb, subtree,
		ett_v2giso1_struct_iso1DiffieHellmanPublickeyType,
		"DHpublickey");

	dissect_v2giso1_emaid(
		&res->eMAID,
		tvb, subtree,
		ett_v2giso1_struct_iso1EMAIDType,
		"eMAID");

	if (res->RetryCounter_isUsed) {
		it = proto_tree_add_uint(subtree,
			hf_v2giso1_struct_iso1CertificateUpdateResType_RetryCounter,
			tvb, 0, 0, res->RetryCounter);
		proto_item_set_generated(it);
	}

	return;
}

static void
dissect_v2giso1_certificateinstallationreq(
	const struct iso1CertificateInstallationReqType *req,
	tvbuff_t *tvb,
	proto_tree *tree,
	gint idx,
	const char *subtree_name)
{
	proto_tree *subtree;

	subtree = proto_tree_add_subtree(tree,
		tvb, 0, 0, idx, NULL, subtree_name);

	exi_add_characters(subtree,
		hf_v2giso1_struct_iso1CertificateInstallationReqType_Id,
		tvb,
		req->Id.characters,
		req->Id.charactersLen,
		sizeof(req->Id.characters));

	exi_add_bytes(subtree,
		hf_v2giso1_struct_iso1CertificateInstallationReqType_OEMProvisioningCert,
		tvb,
		req->OEMProvisioningCert.bytes,
		req->OEMProvisioningCert.bytesLen,
		sizeof(req->OEMProvisioningCert.bytes));

	dissect_v2giso1_listofrootcertificateids(
		&req->ListOfRootCertificateIDs,
		tvb, subtree,
		ett_v2giso1_struct_iso1ListOfRootCertificateIDsType,
		"ListOfRootCertificateIDs");

	return;
}

static void
dissect_v2giso1_certificateinstallationres(
	const struct iso1CertificateInstallationResType *res,
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
		hf_v2giso1_struct_iso1CertificateInstallationResType_ResponseCode,
		tvb, 0, 0, res->ResponseCode);
	proto_item_set_generated(it);

	dissect_v2giso1_certificatechain(
		&res->SAProvisioningCertificateChain,
		tvb, subtree,
		ett_v2giso1_struct_iso1CertificateChainType,
		"SAProvisioningCertificateChain");

	dissect_v2giso1_certificatechain(
		&res->ContractSignatureCertChain,
		tvb, subtree,
		ett_v2giso1_struct_iso1CertificateChainType,
		"ContractSignatureCertChain");

	dissect_v2giso1_contractsignatureencryptedprivatekey(
		&res->ContractSignatureEncryptedPrivateKey,
		tvb, subtree,
		ett_v2giso1_struct_iso1ContractSignatureEncryptedPrivateKeyType,
		"ContractSignatureEncryptedPrivateKey");

	dissect_v2giso1_diffiehellmanpublickey(
		&res->DHpublickey,
		tvb, subtree,
		ett_v2giso1_struct_iso1DiffieHellmanPublickeyType,
		"DHpublickey");

	dissect_v2giso1_emaid(
		&res->eMAID,
		tvb, subtree,
		ett_v2giso1_struct_iso1EMAIDType,
		"eMAID");

	return;
}

static void
dissect_v2giso1_chargingstatusreq(
	const struct iso1ChargingStatusReqType *chargingstatusreq,
	tvbuff_t *tvb,
	proto_tree *tree,
	gint idx,
	const char *subtree_name)
{
	proto_tree_add_subtree(tree,
		tvb, 0, 0, idx, NULL, subtree_name);

	/* no content */
	return;
}

static void
dissect_v2giso1_chargingstatusres(
	const struct iso1ChargingStatusResType *chargingstatusres,
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
		hf_v2giso1_struct_iso1ChargingStatusResType_ResponseCode,
		tvb, 0, 0,
		chargingstatusres->ResponseCode);
	proto_item_set_generated(it);

	exi_add_characters(subtree,
		hf_v2giso1_struct_iso1ChargingStatusResType_EVSEID,
		tvb,
		chargingstatusres->EVSEID.characters,
		chargingstatusres->EVSEID.charactersLen,
		sizeof(chargingstatusres->EVSEID.characters));

	it = proto_tree_add_uint(subtree,
		hf_v2giso1_struct_iso1ChargingStatusResType_SAScheduleTupleID,
		tvb, 0, 0,
		chargingstatusres->SAScheduleTupleID);
	proto_item_set_generated(it);

	if (chargingstatusres->EVSEMaxCurrent_isUsed) {
		dissect_v2giso1_physicalvalue(
			&chargingstatusres->EVSEMaxCurrent,
			tvb, subtree,
			ett_v2giso1_struct_iso1PhysicalValueType,
			"EVSEMaxCurrent");
	}

	if (chargingstatusres->MeterInfo_isUsed) {
		dissect_v2giso1_meterinfo(
			&chargingstatusres->MeterInfo,
			tvb, subtree,
			ett_v2giso1_struct_iso1MeterInfoType,
			"MeterInfo");
	}

	if (chargingstatusres->ReceiptRequired_isUsed) {
		it = proto_tree_add_int(subtree,
			hf_v2giso1_struct_iso1ChargingStatusResType_ReceiptRequired,
			tvb, 0, 0,
			chargingstatusres->ReceiptRequired);
		proto_item_set_generated(it);
	}

	dissect_v2giso1_ac_evsestatus(
		&chargingstatusres->AC_EVSEStatus,
		tvb, subtree,
		ett_v2giso1_struct_iso1AC_EVSEStatusType,
		"AC_EVSEStatus");

	return;
}

static void
dissect_v2giso1_cablecheckreq(
	const struct iso1CableCheckReqType *req,
	tvbuff_t *tvb,
	proto_tree *tree,
	gint idx,
	const char *subtree_name)
{
	proto_tree *subtree;

	subtree = proto_tree_add_subtree(tree,
		tvb, 0, 0, idx, NULL, subtree_name);

	dissect_v2giso1_dc_evstatus(
		&req->DC_EVStatus,
		tvb, subtree,
		ett_v2giso1_struct_iso1DC_EVStatusType,
		"DC_EVStatus");

	return;
}

static void
dissect_v2giso1_cablecheckres(
	const struct iso1CableCheckResType *res,
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
		hf_v2giso1_struct_iso1CableCheckResType_ResponseCode,
		tvb, 0, 0, res->ResponseCode);
	proto_item_set_generated(it);

	dissect_v2giso1_dc_evsestatus(
		&res->DC_EVSEStatus,
		tvb, subtree,
		ett_v2giso1_struct_iso1DC_EVSEStatusType,
		"DC_EVSEStatus");

	it = proto_tree_add_uint(subtree,
		hf_v2giso1_struct_iso1CableCheckResType_EVSEProcessing,
		tvb, 0, 0, res->EVSEProcessing);
	proto_item_set_generated(it);

	return;
}

static void
dissect_v2giso1_prechargereq(
	const struct iso1PreChargeReqType *req,
	tvbuff_t *tvb,
	proto_tree *tree,
	gint idx,
	const char *subtree_name)
{
	proto_tree *subtree;

	subtree = proto_tree_add_subtree(tree,
		tvb, 0, 0, idx, NULL, subtree_name);

	dissect_v2giso1_dc_evstatus(
		&req->DC_EVStatus,
		tvb, subtree,
		ett_v2giso1_struct_iso1DC_EVStatusType,
		"DC_EVStatus");

	dissect_v2giso1_physicalvalue(
		&req->EVTargetVoltage,
		tvb, subtree,
		ett_v2giso1_struct_iso1PhysicalValueType,
		"EVTargetVoltage");

	dissect_v2giso1_physicalvalue(
		&req->EVTargetCurrent,
		tvb, subtree,
		ett_v2giso1_struct_iso1PhysicalValueType,
		"EVTargetCurrent");

	return;
}

static void
dissect_v2giso1_prechargeres(
	const struct iso1PreChargeResType *res,
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
		hf_v2giso1_struct_iso1PreChargeResType_ResponseCode,
		tvb, 0, 0, res->ResponseCode);
	proto_item_set_generated(it);

	dissect_v2giso1_dc_evsestatus(
		&res->DC_EVSEStatus,
		tvb, subtree,
		ett_v2giso1_struct_iso1DC_EVSEStatusType,
		"DC_EVSEStatus");

	dissect_v2giso1_physicalvalue(
		&res->EVSEPresentVoltage,
		tvb, subtree,
		ett_v2giso1_struct_iso1PhysicalValueType,
		"EVSEPresentVoltage");

	return;
}

static void
dissect_v2giso1_currentdemandreq(
	const struct iso1CurrentDemandReqType *req,
	tvbuff_t *tvb,
	proto_tree *tree,
	gint idx,
	const char *subtree_name)
{
	proto_tree *subtree;
	proto_item *it;

	subtree = proto_tree_add_subtree(tree,
		tvb, 0, 0, idx, NULL, subtree_name);

	dissect_v2giso1_dc_evstatus(
		&req->DC_EVStatus,
		tvb, subtree,
		ett_v2giso1_struct_iso1DC_EVStatusType,
		"DC_EVStatus");

	dissect_v2giso1_physicalvalue(
		&req->EVTargetVoltage,
		tvb, subtree,
		ett_v2giso1_struct_iso1PhysicalValueType,
		"EVTargetVoltage");

	dissect_v2giso1_physicalvalue(
		&req->EVTargetCurrent,
		tvb, subtree,
		ett_v2giso1_struct_iso1PhysicalValueType,
		"EVTargetCurrent");

	it = proto_tree_add_int(subtree,
		hf_v2giso1_struct_iso1CurrentDemandReqType_ChargingComplete,
		tvb, 0, 0, req->ChargingComplete);
	proto_item_set_generated(it);

	if (req->BulkChargingComplete_isUsed) {
		it = proto_tree_add_int(subtree,
			hf_v2giso1_struct_iso1CurrentDemandReqType_BulkChargingComplete,
			tvb, 0, 0, req->BulkChargingComplete);
		proto_item_set_generated(it);
	}

	if (req->EVMaximumVoltageLimit_isUsed) {
		dissect_v2giso1_physicalvalue(
			&req->EVMaximumVoltageLimit,
			tvb, subtree,
			ett_v2giso1_struct_iso1PhysicalValueType,
			"EVMaximumVoltageLimit");
	}

	if (req->EVMaximumCurrentLimit_isUsed) {
		dissect_v2giso1_physicalvalue(
			&req->EVMaximumCurrentLimit,
			tvb, subtree,
			ett_v2giso1_struct_iso1PhysicalValueType,
			"EVMaximumCurrentLimit");
	}

	if (req->EVMaximumPowerLimit_isUsed) {
		dissect_v2giso1_physicalvalue(
			&req->EVMaximumPowerLimit,
			tvb, subtree,
			ett_v2giso1_struct_iso1PhysicalValueType,
			"EVMaximumPowerLimit");
	}

	if (req->RemainingTimeToFullSoC_isUsed) {
		dissect_v2giso1_physicalvalue(
			&req->RemainingTimeToFullSoC,
			tvb, subtree,
			ett_v2giso1_struct_iso1PhysicalValueType,
			"RemainingTimeToFullSoC");
	}

	if (req->RemainingTimeToBulkSoC_isUsed) {
		dissect_v2giso1_physicalvalue(
			&req->RemainingTimeToBulkSoC,
			tvb, subtree,
			ett_v2giso1_struct_iso1PhysicalValueType,
			"RemainingTimeToBulkSoC");
	}

	return;
}

static void
dissect_v2giso1_currentdemandres(
	const struct iso1CurrentDemandResType *res,
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
		hf_v2giso1_struct_iso1CurrentDemandResType_ResponseCode,
		tvb, 0, 0, res->ResponseCode);
	proto_item_set_generated(it);

	dissect_v2giso1_dc_evsestatus(
		&res->DC_EVSEStatus,
		tvb, subtree,
		ett_v2giso1_struct_iso1DC_EVSEStatusType,
		"DC_EVSEStatus");

	dissect_v2giso1_physicalvalue(
		&res->EVSEPresentVoltage,
		tvb, subtree,
		ett_v2giso1_struct_iso1PhysicalValueType,
		"EVSEPresentVoltage");

	dissect_v2giso1_physicalvalue(
		&res->EVSEPresentCurrent,
		tvb, subtree,
		ett_v2giso1_struct_iso1PhysicalValueType,
		"EVSEPresentCurrent");

	it = proto_tree_add_int(subtree,
		hf_v2giso1_struct_iso1CurrentDemandResType_EVSECurrentLimitAchieved,
		tvb, 0, 0, res->EVSECurrentLimitAchieved);
	proto_item_set_generated(it);

	it = proto_tree_add_int(subtree,
		hf_v2giso1_struct_iso1CurrentDemandResType_EVSEVoltageLimitAchieved,
		tvb, 0, 0, res->EVSEVoltageLimitAchieved);
	proto_item_set_generated(it);

	it = proto_tree_add_int(subtree,
		hf_v2giso1_struct_iso1CurrentDemandResType_EVSEPowerLimitAchieved,
		tvb, 0, 0, res->EVSEPowerLimitAchieved);
	proto_item_set_generated(it);

	if (res->EVSEMaximumVoltageLimit_isUsed) {
		dissect_v2giso1_physicalvalue(
			&res->EVSEMaximumVoltageLimit,
			tvb, subtree,
			ett_v2giso1_struct_iso1PhysicalValueType,
			"EVSEMaximumVoltageLimit");
	}
	if (res->EVSEMaximumCurrentLimit_isUsed) {
		dissect_v2giso1_physicalvalue(
			&res->EVSEMaximumCurrentLimit,
			tvb, subtree,
			ett_v2giso1_struct_iso1PhysicalValueType,
			"EVSEMaximumCurrentLimit");
	}
	if (res->EVSEMaximumPowerLimit_isUsed) {
		dissect_v2giso1_physicalvalue(
			&res->EVSEMaximumPowerLimit,
			tvb, subtree,
			ett_v2giso1_struct_iso1PhysicalValueType,
			"EVSEMaximumPowerLimit");
	}

	exi_add_characters(subtree,
		hf_v2giso1_struct_iso1CurrentDemandResType_EVSEID,
		tvb,
		res->EVSEID.characters,
		res->EVSEID.charactersLen,
		sizeof(res->EVSEID.characters));

	it = proto_tree_add_uint(subtree,
		hf_v2giso1_struct_iso1CurrentDemandResType_SAScheduleTupleID,
		tvb, 0, 0, res->SAScheduleTupleID);
	proto_item_set_generated(it);

	if (res->MeterInfo_isUsed) {
		dissect_v2giso1_meterinfo(
			&res->MeterInfo,
			tvb, subtree,
			ett_v2giso1_struct_iso1MeterInfoType,
			"MeterInfo");
	}

	if (res->ReceiptRequired_isUsed) {
		it = proto_tree_add_int(subtree,
			hf_v2giso1_struct_iso1CurrentDemandResType_ReceiptRequired,
			tvb, 0, 0, res->ReceiptRequired);
		proto_item_set_generated(it);
	}

	return;
}

static void
dissect_v2giso1_weldingdetectionreq(
	const struct iso1WeldingDetectionReqType *req,
	tvbuff_t *tvb,
	proto_tree *tree,
	gint idx,
	const char *subtree_name)
{
	proto_tree *subtree;

	subtree = proto_tree_add_subtree(tree,
		tvb, 0, 0, idx, NULL, subtree_name);

	dissect_v2giso1_dc_evstatus(
		&req->DC_EVStatus,
		tvb, subtree, ett_v2giso1_struct_iso1DC_EVStatusType,
		"DC_EVStatus");

	return;
}

static void
dissect_v2giso1_weldingdetectionres(
	const struct iso1WeldingDetectionResType *res,
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
		hf_v2giso1_struct_iso1WeldingDetectionResType_ResponseCode,
		tvb, 0, 0, res->ResponseCode);
	proto_item_set_generated(it);

	dissect_v2giso1_dc_evsestatus(
		&res->DC_EVSEStatus,
		tvb, subtree, ett_v2giso1_struct_iso1DC_EVSEStatusType,
		"DC_EVSEStatus");

	dissect_v2giso1_physicalvalue(
		&res->EVSEPresentVoltage,
		tvb, subtree, ett_v2giso1_struct_iso1PhysicalValueType,
		"EVSEPresentVoltage");

	return;
}


static void
dissect_v2giso1_body(const struct iso1BodyType *body,
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
		dissect_v2giso1_sessionsetupreq(
			&body->SessionSetupReq, tvb, subtree,
			ett_v2giso1_struct_iso1SessionSetupReqType,
			"SessionSetupReq");
	}
	if (body->SessionSetupRes_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO, "SessionSetupRes");
		dissect_v2giso1_sessionsetupres(
			&body->SessionSetupRes, tvb, subtree,
			ett_v2giso1_struct_iso1SessionSetupResType,
			"SessionSetupRes");
	}

	if (body->ServiceDiscoveryReq_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO, "ServiceDiscoveryReq");
		dissect_v2giso1_servicediscoveryreq(
			&body->ServiceDiscoveryReq, tvb, subtree,
			ett_v2giso1_struct_iso1ServiceDiscoveryReqType,
			"ServiceDiscoveryReq");
	}
	if (body->ServiceDiscoveryRes_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO, "ServiceDiscoveryRes");
		dissect_v2giso1_servicediscoveryres(
			&body->ServiceDiscoveryRes, tvb, subtree,
			ett_v2giso1_struct_iso1ServiceDiscoveryResType,
			"ServiceDiscoveryRes");
	}

	if (body->ServiceDetailReq_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO, "ServiceDetailReq");
		dissect_v2giso1_servicedetailreq(
			&body->ServiceDetailReq, tvb, subtree,
			ett_v2giso1_struct_iso1ServiceDetailReqType,
			"ServiceDetailReq");
	}
	if (body->ServiceDetailRes_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO, "ServiceDetailRes");
		dissect_v2giso1_servicedetailres(
			&body->ServiceDetailRes, tvb, subtree,
			ett_v2giso1_struct_iso1ServiceDetailResType,
			"ServiceDetailRes");
	}

	if (body->PaymentServiceSelectionReq_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO,
			"PaymentServiceSelectionReq");
		dissect_v2giso1_paymentserviceselectionreq(
			&body->PaymentServiceSelectionReq, tvb, subtree,
			ett_v2giso1_struct_iso1PaymentServiceSelectionReqType,
			"PaymentServiceSelectionReq");
	}
	if (body->PaymentServiceSelectionRes_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO,
			"PaymentServiceSelectionRes");
		dissect_v2giso1_paymentserviceselectionres(
			&body->PaymentServiceSelectionRes, tvb, subtree,
			ett_v2giso1_struct_iso1PaymentServiceSelectionResType,
			"PaymentServiceSelectionRes");
	}

	if (body->PaymentDetailsReq_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO, "PaymentDetailsReq");
		dissect_v2giso1_paymentdetailsreq(
			&body->PaymentDetailsReq, tvb, subtree,
			ett_v2giso1_struct_iso1PaymentDetailsReqType,
			"PaymentDetailsReq");
	}
	if (body->PaymentDetailsRes_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO, "PaymentDetailsRes");
		dissect_v2giso1_paymentdetailsres(
			&body->PaymentDetailsRes, tvb, subtree,
			ett_v2giso1_struct_iso1PaymentDetailsResType,
			"PaymentDetailsRes");
	}

	if (body->AuthorizationReq_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO, "AuthorizationReq");
		dissect_v2giso1_authorizationreq(
			&body->AuthorizationReq, tvb, subtree,
			ett_v2giso1_struct_iso1AuthorizationReqType,
			"AuthorizationReq");
	}
	if (body->AuthorizationRes_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO, "AuthorizationRes");
		dissect_v2giso1_authorizationres(
			&body->AuthorizationRes, tvb, subtree,
			ett_v2giso1_struct_iso1AuthorizationResType,
			"AuthorizationRes");
	}

	if (body->ChargeParameterDiscoveryReq_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO,
			"ChargeParameterDiscoveryReq");
		dissect_v2giso1_chargeparameterdiscoveryreq(
			&body->ChargeParameterDiscoveryReq, tvb, subtree,
			ett_v2giso1_struct_iso1ChargeParameterDiscoveryReqType,
			"ChargeParameterDiscoveryReq");
	}
	if (body->ChargeParameterDiscoveryRes_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO,
			"ChargeParameterDiscoveryRes");
		dissect_v2giso1_chargeparameterdiscoveryres(
			&body->ChargeParameterDiscoveryRes, tvb, subtree,
			ett_v2giso1_struct_iso1ChargeParameterDiscoveryResType,
			"ChargeParameterDiscoveryRes");
	}

	if (body->PowerDeliveryReq_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO, "PowerDeliveryReq");
		dissect_v2giso1_powerdeliveryreq(
			&body->PowerDeliveryReq, tvb, subtree,
			ett_v2giso1_struct_iso1PowerDeliveryReqType,
			"PowerDeliveryReq");
	}
	if (body->PowerDeliveryRes_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO, "PowerDeliveryRes");
		dissect_v2giso1_powerdeliveryres(
			&body->PowerDeliveryRes, tvb, subtree,
			ett_v2giso1_struct_iso1PowerDeliveryResType,
			"PowerDeliveryRes");
	}

	if (body->MeteringReceiptReq_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO, "MeteringReceiptReq");
		dissect_v2giso1_meteringreceiptreq(
			&body->MeteringReceiptReq, tvb, subtree,
			ett_v2giso1_struct_iso1MeteringReceiptReqType,
			"MeteringReceiptReq");
	}
	if (body->MeteringReceiptRes_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO, "MeteringReceiptRes");
		dissect_v2giso1_meteringreceiptres(
			&body->MeteringReceiptRes, tvb, subtree,
			ett_v2giso1_struct_iso1MeteringReceiptResType,
			"MeteringReceiptRes");
	}

	if (body->SessionStopReq_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO, "SessionStopReq");
		dissect_v2giso1_sessionstopreq(
			&body->SessionStopReq, tvb, subtree,
			ett_v2giso1_struct_iso1SessionStopReqType,
			"SessionStopReq");
	}
	if (body->SessionStopRes_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO, "SessionStopRes");
		dissect_v2giso1_sessionstopres(
			&body->SessionStopRes, tvb, subtree,
			ett_v2giso1_struct_iso1SessionStopResType,
			"SessionStopRes");
	}

	if (body->CertificateUpdateReq_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO, "CertificateUpdateReq");
		dissect_v2giso1_certificateupdatereq(
			&body->CertificateUpdateReq, tvb, subtree,
			ett_v2giso1_struct_iso1CertificateUpdateReqType,
			"CertificateUpdateReq");
	}
	if (body->CertificateUpdateRes_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO, "CertificateUpdateRes");
		dissect_v2giso1_certificateupdateres(
			&body->CertificateUpdateRes, tvb, subtree,
			ett_v2giso1_struct_iso1CertificateUpdateResType,
			"CertificateUpdateRes");
	}

	if (body->CertificateInstallationReq_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO,
			"CertificateInstallationReq");
		dissect_v2giso1_certificateinstallationreq(
			&body->CertificateInstallationReq, tvb, subtree,
			ett_v2giso1_struct_iso1CertificateInstallationReqType,
			"CertificateInstallationReq");
	}
	if (body->CertificateInstallationRes_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO,
			"CertificateInstallationRes");
		dissect_v2giso1_certificateinstallationres(
			&body->CertificateInstallationRes, tvb, subtree,
			ett_v2giso1_struct_iso1CertificateInstallationResType,
			"CertificateInstallationRes");
	}

	if (body->ChargingStatusReq_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO, "ChargingStatusReq");
		dissect_v2giso1_chargingstatusreq(
			&body->ChargingStatusReq, tvb, subtree,
			ett_v2giso1_struct_iso1ChargingStatusReqType,
			"ChargingStatusReq");
	}
	if (body->ChargingStatusRes_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO, "ChargingStatusRes");
		dissect_v2giso1_chargingstatusres(
			&body->ChargingStatusRes, tvb, subtree,
			ett_v2giso1_struct_iso1ChargingStatusResType,
			"ChargingStatusRes");
	}

	if (body->CableCheckReq_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO, "CableCheckReq");
		dissect_v2giso1_cablecheckreq(
			&body->CableCheckReq, tvb, subtree,
			ett_v2giso1_struct_iso1CableCheckReqType,
			"CableCheckReq");
	}
	if (body->CableCheckRes_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO, "CableCheckRes");
		dissect_v2giso1_cablecheckres(
			&body->CableCheckRes, tvb, subtree,
			ett_v2giso1_struct_iso1CableCheckResType,
			"CableCheckRes");
	}

	if (body->PreChargeReq_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO, "PreChargeReq");
		dissect_v2giso1_prechargereq(
			&body->PreChargeReq, tvb, subtree,
			ett_v2giso1_struct_iso1PreChargeReqType,
			"PreChargeReq");
	}
	if (body->PreChargeRes_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO, "PreChargeRes");
		dissect_v2giso1_prechargeres(
			&body->PreChargeRes, tvb, subtree,
			ett_v2giso1_struct_iso1PreChargeResType,
			"PreChargeRes");
	}

	if (body->CurrentDemandReq_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO, "CurrentDemandReq");
		dissect_v2giso1_currentdemandreq(
			&body->CurrentDemandReq, tvb, subtree,
			ett_v2giso1_struct_iso1CurrentDemandReqType,
			"CurrentDemandReq");
	}
	if (body->CurrentDemandRes_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO, "CurrentDemandRes");
		dissect_v2giso1_currentdemandres(
			&body->CurrentDemandRes, tvb, subtree,
			ett_v2giso1_struct_iso1CurrentDemandResType,
			"CurrentDemandRes");
	}

	if (body->WeldingDetectionReq_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO, "WeldingDetectionReq");
		dissect_v2giso1_weldingdetectionreq(
			&body->WeldingDetectionReq, tvb, subtree,
			ett_v2giso1_struct_iso1WeldingDetectionReqType,
			"WeldingDetectionReq");
	}
	if (body->WeldingDetectionRes_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO, "WeldingDetectionRes");
		dissect_v2giso1_weldingdetectionres(
			&body->WeldingDetectionRes, tvb, subtree,
			ett_v2giso1_struct_iso1WeldingDetectionResType,
			"WeldingDetectionRes");
	}

	return;
}

static int
dissect_v2giso1(tvbuff_t *tvb,
		packet_info *pinfo, proto_tree *tree _U_, void *data _U_)
{
	size_t pos;
	bitstream_t stream;
	int errn;
	struct iso1EXIDocument exiiso1;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "ISO1");
	/* Clear the info column */
	col_clear(pinfo->cinfo, COL_INFO);

	pos = 0;
	stream.size = tvb_reported_length(tvb);
	stream.pos = &pos;
	stream.data = tvb_memdup(wmem_packet_scope(),
				 tvb, pos, stream.size);
	errn = decode_iso1ExiDocument(&stream, &exiiso1);
	if (errn != 0) {
		/* decode failed */
		return 0;
	}

	/*
	 * Everything in ISO1 should come in as a messagge
	 * - Header
	 * - Body
	 */
	if (exiiso1.V2G_Message_isUsed) {
		proto_tree *v2giso1_tree;

		v2giso1_tree = proto_tree_add_subtree(tree,
			tvb, 0, 0, ett_v2giso1, NULL, "V2G ISO1 Message");

		dissect_v2giso1_header(&exiiso1.V2G_Message.Header,
			tvb, v2giso1_tree, ett_v2giso1_header, "Header");
		dissect_v2giso1_body(& exiiso1.V2G_Message.Body,
			tvb, pinfo, v2giso1_tree, ett_v2giso1_body, "Body");
	}

	return tvb_captured_length(tvb);
}

void
proto_register_v2giso1(void)
{

	static hf_register_info hf[] = {
		/* struct iso1MessageHeaderType */
		{ &hf_v2giso1_struct_iso1MessageHeaderType_SessionID,
		  { "SessionID", "v2giso1.struct.messageheader.sessionid",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso1NotificationType */
		{ &hf_v2giso1_struct_iso1NotificationType_FaultCode,
		  { "FaultCode", "v2giso1.struct.notification.faultcode",
		    FT_UINT16, BASE_DEC, VALS(v2giso1_fault_code_names),
		    0x0, NULL, HFILL }
		},
		{ &hf_v2giso1_struct_iso1NotificationType_FaultMsg,
		  { "FaultMsg", "v2giso1.struct.notification.faultmsg",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso1SignatureType */
		{ &hf_v2giso1_struct_iso1SignatureType_Id,
		  { "Id", "v2giso1.struct.signature.id",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso1SignedInfoType */
		{ &hf_v2giso1_struct_iso1SignedInfoType_Id,
		  { "Id", "v2giso1.struct.signedinfo.id",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso1CanonicalizationMethodType */
		{ &hf_v2giso1_struct_iso1CanonicalizationMethodType_Algorithm,
		  { "Algorithm",
		    "v2giso1.struct.canonicalizationmethod.algorithm",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso1_struct_iso1CanonicalizationMethodType_ANY,
		  { "ANY",
		    "v2giso1.struct.canonicalizationmethod.any",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso1SignatureMethodType */
		{ &hf_v2giso1_struct_iso1SignatureMethodType_Algorithm,
		  { "Algorithm", "v2giso1.struct.signaturemethod.algorithm",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso1_struct_iso1SignatureMethodType_HMACOutputLength,
		  { "HMACOutputLength",
		    "v2giso1.struct.signaturemethod.hmacoutputlength",
		    FT_INT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso1_struct_iso1SignatureMethodType_ANY,
		  { "ANY", "v2giso1.struct.signaturemethod.any",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso1ReferenceType */
		{ &hf_v2giso1_struct_iso1ReferenceType_Id,
		  { "Id", "v2giso1.struct.reference.id",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso1_struct_iso1ReferenceType_URI,
		  { "URI", "v2giso1.struct.reference.uri",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso1_struct_iso1ReferenceType_Type,
		  { "Type", "v2giso1.struct.reference.type",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso1_struct_iso1ReferenceType_DigestValue,
		  { "DigestValue", "v2giso1.struct.reference.digestvalue",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso1SignatureValueType */
		{ &hf_v2giso1_struct_iso1SignatureValueType_Id,
		  { "Id", "v2giso1.struct.signavturevalue.id",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso1_struct_iso1SignatureValueType_CONTENT,
		  { "CONTENT", "v2giso1.struct.signaturevalue.content",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso1ObjectType */
		{ &hf_v2giso1_struct_iso1ObjectType_Id,
		  { "Id", "v2giso1.struct.object.id",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso1_struct_iso1ObjectType_MimeType,
		  { "MimeType", "v2giso1.struct.object.mimetype",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso1_struct_iso1ObjectType_Encoding,
		  { "Encoding", "v2giso1.struct.object.encoiso1g",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso1_struct_iso1ObjectType_ANY,
		  { "ANY", "v2giso1.struct.object.any",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso1TransformType */
		{ &hf_v2giso1_struct_iso1TransformType_Algorithm,
		  { "Algorithm", "v2giso1.struct.transform.algorithm",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso1_struct_iso1TransformType_ANY,
		  { "ANY", "v2giso1.struct.transform.any",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso1_struct_iso1TransformType_XPath,
		  { "XPath", "v2giso1.struct.transform.xpath",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso1DigestMethodType */
		{ &hf_v2giso1_struct_iso1DigestMethodType_Algorithm,
		  { "Algorithm", "v2giso1.struct.digestmethod.algorithm",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso1_struct_iso1DigestMethodType_ANY,
		  { "ANY", "v2giso1.struct.digestmethod.any",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso1KeyInfoType */
		{ &hf_v2giso1_struct_iso1KeyInfoType_Id,
		  { "Id", "v2giso1.struct.keyinfo.id",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso1_struct_iso1KeyInfoType_KeyName,
		  { "KeyName", "v2giso1.struct.keyinfo.keyname",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso1_struct_iso1KeyInfoType_MgmtData,
		  { "MgmtData", "v2giso1.struct.keyinfo.mgmtdata",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso1_struct_iso1KeyInfoType_ANY,
		  { "ANY", "v2giso1.struct.keyinfo.any",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso1RetrievalMethodType */
		{ &hf_v2giso1_struct_iso1RetrievalMethodType_URI,
		  { "URI", "v2giso1.struct.retrievalmethod.uri",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso1_struct_iso1RetrievalMethodType_Type,
		  { "Type", "v2giso1.struct.retrievalmethod.type",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso1KeyValueType */
		{ &hf_v2giso1_struct_iso1KeyValueType_ANY,
		  { "ANY", "v2giso1.struct.keyvalue.any",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso1DSAKeyValueType */
		{ &hf_v2giso1_struct_iso1DSAKeyValueType_P,
		  { "P", "v2giso1.struct.dsakeyvalue.p",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso1_struct_iso1DSAKeyValueType_Q,
		  { "Q", "v2giso1.struct.dsakeyvalue.q",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso1_struct_iso1DSAKeyValueType_G,
		  { "G", "v2giso1.struct.dsakeyvalue.g",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso1_struct_iso1DSAKeyValueType_Y,
		  { "Y", "v2giso1.struct.dsakeyvalue.y",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso1_struct_iso1DSAKeyValueType_J,
		  { "J", "v2giso1.struct.dsakeyvalue.j",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso1_struct_iso1DSAKeyValueType_Seed,
		  { "Seed", "v2giso1.struct.dsakeyvalue.seed",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso1_struct_iso1DSAKeyValueType_PgenCounter,
		  { "PgenCounter", "v2giso1.struct.dsakeyvalue.pgencounter",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso1RSAKeyValueType */
		{ &hf_v2giso1_struct_iso1RSAKeyValueType_Modulus,
		  { "Modulus", "v2giso1.struct.rsakeyvalue.modulus",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso1_struct_iso1RSAKeyValueType_Exponent,
		  { "Exponent", "v2giso1.struct.rsakeyvalue.exponent",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso1X509DataType */
		{ &hf_v2giso1_struct_iso1X509DataType_X509SKI,
		  { "X509SKI", "v2giso1.struct.x509data.x509ski",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso1_struct_iso1X509DataType_X509SubjectName,
		  { "X509SubjectName",
		    "v2giso1.struct.x509data.x509subjectname",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso1_struct_iso1X509DataType_X509Certificate,
		  { "X509Certificate",
		    "v2giso1.struct.x509data.x509certificate",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso1_struct_iso1X509DataType_X509CRL,
		  { "X509CRL", "v2giso1.struct.x509data.x509crl",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso1_struct_iso1X509DataType_ANY,
		  { "ANY", "v2giso1.struct.x509data.any",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso1X509IssuerSerialType */
		{ &hf_v2giso1_struct_iso1X509IssuerSerialType_X509IssuerName,
		  { "X509IssuerName",
		    "v2giso1.struct.x509issuerserial.x509issuername",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso1_struct_iso1X509IssuerSerialType_X509SerialNumber_negative,
		  { "X509SerialNumber (negative)",
		    "v2giso1.struct.x509issuerserial.x509serialnumber.negative",
		    FT_INT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso1_struct_iso1X509IssuerSerialType_X509SerialNumber_data,
		  { "X509SerialNumber (data)",
		    "v2giso1.struct.x509issuerserial.x509serialnumber.data",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso1PGPDataType */
		{ &hf_v2giso1_struct_iso1PGPDataType_PGPKeyID,
		  { "PGPKeyID", "v2giso1.struct.pgpdata.pgpkeyid",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso1_struct_iso1PGPDataType_PGPKeyPacket,
		  { "PGPKeyPacket", "v2giso1.struct.pgpdata.pgpkeypacket",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso1_struct_iso1PGPDataType_ANY,
		  { "ANY", "v2giso1.struct.pgpdata.any",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso1SPKIDataType */
		{ &hf_v2giso1_struct_iso1SPKIDataType_SPKISexp,
		  { "SPKISexp", "v2giso1.struct.spkidata.spkisexp",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso1_struct_iso1SPKIDataType_ANY,
		  { "ANY", "v2giso1.struct.spkidata.any",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso1ChargeServiceType */
		{ &hf_v2giso1_struct_iso1ChargeServiceType_ServiceID,
		  { "ServiceID", "v2giso1.struct.chargeservice.serviceid",
		    FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso1_struct_iso1ChargeServiceType_ServiceName,
		  { "ServiceName", "v2giso1.struct.chargeservice.servicename",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso1_struct_iso1ChargeServiceType_ServiceCategory,
		  { "ServiceCategory",
		    "v2giso1.struct.chargeservice.servicecategory",
		    FT_UINT32, BASE_DEC, VALS(v2giso1_service_category_names),
		    0x0, NULL, HFILL }
		},
		{ &hf_v2giso1_struct_iso1ChargeServiceType_ServiceScope,
		  { "ServiceScope",
		    "v2giso1.struct.chargeservice.servicescope",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso1_struct_iso1ChargeServiceType_FreeService,
		  { "FreeService", "v2giso1.struct.chargeservice.freeservice",
		    FT_INT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso1PaymentOptionListType */
		{ &hf_v2giso1_struct_iso1PaymentOptionLstType_PaymentOption,
		  { "PaymentOption",
		    "v2giso1.struct.paymentoptionlist.paymentoption",
		    FT_UINT32, BASE_DEC, VALS(v2giso1_payment_option_names),
		    0x0, NULL, HFILL }
		},

		{ &hf_v2giso1_struct_iso1SupportedEnergyTransferModeType_EnergyTransferMode,
		  { "EnergyTransferMode",
		    "v2giso1.struct.supportedenergytransfermode.energytransfermode",
		    FT_UINT32, BASE_DEC, VALS(v2giso1_energy_transfer_mode_names),
		    0x0, NULL, HFILL }
		},

		/* struct iso1ServiceType */
		{ &hf_v2giso1_struct_iso1ServiceType_ServiceID,
		  { "ServiceID", "v2giso1.struct.service.serviceid",
		    FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso1_struct_iso1ServiceType_ServiceName,
		  { "ServiceName", "v2giso1.struct.service.servicename",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso1_struct_iso1ServiceType_ServiceCategory,
		  { "ServiceCategory", "v2giso1.struct.service.servicecategory",
		    FT_UINT32, BASE_DEC, VALS(v2giso1_service_category_names),
		    0x0, NULL, HFILL }
		},
		{ &hf_v2giso1_struct_iso1ServiceType_ServiceScope,
		  { "ServiceScope", "v2giso1.struct.service.servicescope",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso1_struct_iso1ServiceType_FreeService,
		  { "FreeService", "v2giso1.struct.service.freeservice",
		    FT_INT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso1ParameterSetType */
		{ &hf_v2giso1_struct_iso1ParameterSetType_ParameterSetID,
		  { "ParameterSetID",
		    "v2giso1.struct.parameterset.parametersetid",
		    FT_INT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso1ParameterType */
		{ &hf_v2giso1_struct_iso1ParameterType_Name,
		  { "Name", "v2giso1.struct.parameter.name",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso1_struct_iso1ParameterType_boolValue,
		  { "boolValue", "v2giso1.struct.parameter.boolvalue",
		    FT_INT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso1_struct_iso1ParameterType_byteValue,
		  { "byteValue", "v2giso1.struct.parameter.bytevalue",
		    FT_INT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso1_struct_iso1ParameterType_shortValue,
		  { "shortValue", "v2giso1.struct.parameter.shortvalue",
		    FT_INT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso1_struct_iso1ParameterType_intValue,
		  { "intValue", "v2giso1.struct.parameter.intvalue",
		    FT_INT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso1_struct_iso1ParameterType_stringValue,
		  { "stringValue", "v2giso1.struct.parameter.stringvalue",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso1PhysicalValueType */
		{ &hf_v2giso1_struct_iso1PhysicalValueType_Multiplier,
		  { "Multiplier", "v2giso1.struct.physicalvalue.multiplier",
		    FT_INT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso1_struct_iso1PhysicalValueType_Unit,
		  { "Unit", "v2giso1.struct.physicalvalue.unit",
		    FT_UINT32, BASE_DEC, VALS(v2giso1_unit_symbol_names),
		    0x0, NULL, HFILL }
		},
		{ &hf_v2giso1_struct_iso1PhysicalValueType_Value,
		  { "Value", "v2giso1.struct.physicalvalue.value",
		    FT_INT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso1SelectedServiceType */
		{ &hf_v2giso1_struct_iso1SelectedServiceType_ServiceID,
		  { "ServiceID", "v2giso1.struct.selectedservice.serviceid",
		    FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso1_struct_iso1SelectedServiceType_ParameterSetID,
		  { "ParameterSetID",
		    "v2giso1.struct.selectedservice.parametersetid",
		    FT_INT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso1CertificateChainType */
		{ &hf_v2giso1_struct_iso1CertificateChainType_Id,
		  { "Id", "v2giso1.struct.certificatechain.id",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso1_struct_iso1CertificateChainType_Certificate,
		  { "Certificate",
		    "v2giso1.struct.certificatechain.certificate",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso1SubCertificatesType */
		{ &hf_v2giso1_struct_iso1SubCertificatesType_Certificate,
		  { "Certificate",
		    "v2giso1.struct.subcertificates.certificate",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso1AC_EVChargeParameterType */
		{ &hf_v2giso1_struct_iso1AC_EVChargeParameterType_DepartureTime,
		  { "DepartureTime",
		    "v2giso1.struct.ac_evchargeparameter.departuretime",
		    FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso1DC_EVChargeParameterType */
		{ &hf_v2giso1_struct_iso1DC_EVChargeParameterType_DepartureTime,
		  { "DepartureTime",
		    "v2giso1.struct.dc_evchargeparameter.departuretime",
		    FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso1_struct_iso1DC_EVChargeParameterType_FullSOC,
		  { "FullSOC", "v2giso1.struct.dc_evchargeparameter.fullsoc",
		    FT_INT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso1_struct_iso1DC_EVChargeParameterType_BulkSOC,
		  { "BulkSOC", "v2giso1.struct.dc_evchargeparameter.bulksoc",
		    FT_INT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso1DC_EVStatusType */
		{ &hf_v2giso1_struct_iso1DC_EVStatusType_EVReady,
		  { "EVReady", "v2giso1.struct.dc_evstatus.evready",
		    FT_INT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso1_struct_iso1DC_EVStatusType_EVErrorCode,
		  { "EVErrorCode", "v2giso1.struct.dc_evstatus.everrorcode",
		    FT_UINT32, BASE_DEC, VALS(v2giso1_dc_everrorcode_names),
		    0x0, NULL, HFILL }
		},
		{ &hf_v2giso1_struct_iso1DC_EVStatusType_EVRESSSOC,
		  { "EVRESSSOC", "v2giso1.struct.dc_evstatus.evressoc",
		    FT_INT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso1EVSEStatusType */
		{ &hf_v2giso1_struct_iso1EVSEStatusType_NotificationMaxDelay,
		  { "NotificationMaxDelay",
		    "v2giso1.struct.evsestatus.notificationmaxdelay",
		    FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso1_struct_iso1EVSEStatusType_EVSENotification,
		  { "EVSENotification",
		    "v2giso1.struct.evsestatus.evsenotification",
		    FT_UINT32, BASE_DEC, VALS(v2giso1_evsenotification_names),
		    0x0, NULL, HFILL }
		},

		/* struct iso1AC_EVSEStatusType */
		{ &hf_v2giso1_struct_iso1AC_EVSEStatusType_NotificationMaxDelay,
		  { "NotificationMaxDelay",
		    "v2giso1.struct.ac_evsestatus.notificationmaxdelay",
		    FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso1_struct_iso1AC_EVSEStatusType_EVSENotification,
		  { "EVSENotification",
		    "v2giso1.struct.ac_evsestatus.evsenotification",
		    FT_UINT32, BASE_DEC, VALS(v2giso1_evsenotification_names),
		    0x0, NULL, HFILL }
		},
		{ &hf_v2giso1_struct_iso1AC_EVSEStatusType_RCD,
		  { "RCD", "v2giso1.struct.ac_evsestatus.rcd",
		    FT_INT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso1DC_EVSEStatusType */
		{ &hf_v2giso1_struct_iso1DC_EVSEStatusType_NotificationMaxDelay,
		  { "NotificationMaxDelay",
		    "v2giso1.struct.dc_evsestatus.notificationmaxdelay",
		    FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso1_struct_iso1DC_EVSEStatusType_EVSENotification,
		  { "EVSENotification",
		    "v2giso1.struct.dc_evsestatus.evsenotification",
		    FT_UINT32, BASE_DEC, VALS(v2giso1_evsenotification_names),
		    0x0, NULL, HFILL }
		},
		{ &hf_v2giso1_struct_iso1DC_EVSEStatusType_EVSEIsolationStatus,
		  { "EVSEIsolationStatus",
		    "v2giso1.struct.dc_evsestatus.evseisolationstatus",
		    FT_UINT32, BASE_DEC,
		    VALS(v2giso1_evseisolation_level_names), 0x0, NULL, HFILL }
		},
		{ &hf_v2giso1_struct_iso1DC_EVSEStatusType_EVSEStatusCode,
		  { "EVSEStatusCode",
		    "v2giso1.struct.dc_evsestatus.evsestatuscode",
		    FT_UINT32, BASE_DEC, VALS(v2giso1_dc_evsestatuscode_names),
		    0x0, NULL, HFILL }
		},

		/* struct iso1SAScheduleTupleType */
		{ &hf_v2giso1_struct_iso1SAScheduleTupleType_SAScheduleTupleID,
		  { "SAScheduleTupleID",
		    "v2giso1.struct.sascheduletuple.sascheduletupleid",
		    FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso1SalesTariffType */
		{ &hf_v2giso1_struct_iso1SalesTariffType_Id,
		  { "Id", "v2giso1.struct.salestariff.id",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso1_struct_iso1SalesTariffType_SalesTariffDescription,
		  { "SalesTariffDescription",
		    "v2giso1.struct.salestariff.salestariffdescription",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso1_struct_iso1SalesTariffType_NumEPriceLevels,
		  { "NumEPriceLevels",
		    "v2giso1.struct.salestariff.numepricelevels",
		    FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso1SalesTariffEntryType */
		{ &hf_v2giso1_struct_iso1SalesTariffEntryType_EPriceLevel,
		  { "EPriceLevel",
		    "v2giso1.struct.salestariffentry.epricelevel",
		    FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso1RelativeTimeIntervalType */
		{ &hf_v2giso1_struct_iso1RelativeTimeIntervalType_start,
		  { "start", "v2giso1.struct.relativetimeinterval.start",
		    FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso1_struct_iso1RelativeTimeIntervalType_duration,
		  { "duration", "v2giso1.struct.relativetimeinterval.duration",
		    FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso1CostType */
		{ &hf_v2giso1_struct_iso1CostType_costKind,
		  { "costKind", "v2giso1.struct.cost.costkind",
		    FT_UINT32, BASE_DEC, VALS(v2giso1_cost_kind_names),
		    0x0, NULL, HFILL }
		},
		{ &hf_v2giso1_struct_iso1CostType_amount,
		  { "amount", "v2giso1.struct.cost.amount",
		    FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso1_struct_iso1CostType_amountMultiplier,
		  { "amountMultiplier", "v2giso1.struct.cost.amountmultiplier",
		    FT_INT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso1ProfileEntryType */
		{ &hf_v2giso1_struct_iso1ProfileEntryType_ChargingProfileEntryStart,
		  { "ChargingProfileEntryStart",
		    "v2giso1.struct.profilentry.chargingprofileentrystart",
		    FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso1_struct_iso1ProfileEntryType_ChargingProfileEntryMaxNumberOfPhasesInUse,
		  { "ChargingProfileEntryMaxNumberOfPhasesInUse",
		    "v2giso1.struct.profilentry.chargingprofileentrymaxnumberofphasesinuses",
		    FT_INT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso1DC_EVPowerDeliveryParameterType */
		{ &hf_v2giso1_struct_iso1DC_EVPowerDeliveryParameterType_BulkChargingComplete,
		  { "BulkChargingComplete",
		    "v2giso1.struct.dc_evpowerdeliveryparameter.bulkchargingcomplete",
		    FT_INT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso1_struct_iso1DC_EVPowerDeliveryParameterType_ChargingComplete,
		  { "ChargingComplete",
		    "v2giso1.struct.dc_evpowerdeliveryparameter.chargingcomplete",
		    FT_INT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso1MeterInfoType */
		{ &hf_v2giso1_struct_iso1MeterInfoType_MeterID,
		  { "MeterID", "v2giso1.struct.meterinfo.meterid",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso1_struct_iso1MeterInfoType_MeterReading,
		  { "MeterReading", "v2giso1.struct.meterinfo.meterreading",
		    FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso1_struct_iso1MeterInfoType_SigMeterReading,
		  { "SigMeterReading",
		    "v2giso1.struct.meterinfo.sigmeterreading",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso1_struct_iso1MeterInfoType_MeterStatus,
		  { "MeterStatus", "v2giso1.struct.meterinfo.meterstatus",
		    FT_INT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso1_struct_iso1MeterInfoType_TMeter,
		  { "TMeter", "v2giso1.struct.meterinfo.tmeter",
		    FT_INT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso1ContractSignatureEncryptedPrivateKeyType */
		{ &hf_v2giso1_struct_iso1ContractSignatureEncryptedPrivateKeyType_Id,
		  { "Id",
		    "v2giso1.struct.contractsignatureencryptedprivatekey.id",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso1_struct_iso1ContractSignatureEncryptedPrivateKeyType_CONTENT,
		  { "CONTENT",
		    "v2giso1.struct.contractsignatureencryptedprivatekey.content",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso1DiffieHellmanPublickeyType */
		{ &hf_v2giso1_struct_iso1DiffieHellmanPublickeyType_Id,
		  { "Id", "v2giso1.struct.diffiehellmanpublickey.id",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso1_struct_iso1DiffieHellmanPublickeyType_CONTENT,
		  { "CONTENT", "v2giso1.struct.diffiehellmanpublickey.content",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso1EMAIDType */
		{ &hf_v2giso1_struct_iso1EMAIDType_Id,
		  { "Id", "v2giso1.struct.emaid.id",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso1_struct_iso1EMAIDType_CONTENT,
		  { "CONTENT", "v2giso1.struct.emaid.content",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso1SessionSetupReqType */
		{ &hf_v2giso1_struct_iso1SessionSetupReqType_EVCCID,
		  { "EVCCID", "v2giso1.struct.sessionsetupreq.evccid",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		/* struct iso1SessionSetupReqType */
		{ &hf_v2giso1_struct_iso1SessionSetupResType_ResponseCode,
		  { "ResponseCode",
		    "v2giso1.struct.sessionsetupres.responsecode",
		    FT_UINT32, BASE_DEC, VALS(v2giso1_response_code_names),
		    0x0, NULL, HFILL }
		},
		{ &hf_v2giso1_struct_iso1SessionSetupResType_EVSEID,
		  { "EVSEID", "v2giso1.struct.sessionsetupres.evseid",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso1_struct_iso1SessionSetupResType_EVSETimeStamp,
		  { "EVSETimeStamp",
		    "v2giso1.struct.sessionsetupres.evsetimestamp",
		    FT_INT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso1ServiceDiscoveryReqType */
		{ &hf_v2giso1_struct_iso1ServiceDiscoveryReqType_ServiceScope,
		  { "ServiceScope",
		    "v2giso1.struct.servicediscoveryreq.servicescope",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso1_struct_iso1ServiceDiscoveryReqType_ServiceCategory,
		  { "ServiceCategory",
		    "v2giso1.struct.servicediscoveryreq.servicecategory",
		    FT_UINT32, BASE_DEC, VALS(v2giso1_service_category_names),
		    0x0, NULL, HFILL }
		},
		/* struct iso1ServiceDiscoveryResType */
		{ &hf_v2giso1_struct_iso1ServiceDiscoveryResType_ResponseCode,
		  { "ResponseCode",
		    "v2giso1.struct.servicediscoveryres.responsecode",
		    FT_UINT32, BASE_DEC, VALS(v2giso1_response_code_names),
		    0x0, NULL, HFILL }
		},

		/* struct iso1ServiceDetailReqType */
		{ &hf_v2giso1_struct_iso1ServiceDetailReqType_ServiceID,
		  { "ServiceID", "v2giso1.struct.servicedetailreq.serviceid",
		    FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }
		},
		/* struct iso1ServiceDetailResType */
		{ &hf_v2giso1_struct_iso1ServiceDetailResType_ResponseCode,
		  { "ResponseCode",
		    "v2giso1.struct.servicedetailres.responsecode",
		    FT_UINT32, BASE_DEC, VALS(v2giso1_response_code_names),
		    0x0, NULL, HFILL }
		},
		{ &hf_v2giso1_struct_iso1ServiceDetailResType_ServiceID,
		  { "ServiceID", "v2giso1.struct.servicedetailres.serviceid",
		    FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso1PaymentServiceSelectionReqType */
		{ &hf_v2giso1_struct_iso1PaymentServiceSelectionReqType_SelectedPaymentOption,
		  { "SelectedPaymentOption",
		    "v2giso1.struct.paymentserviceslectionreq.selectpaymentoption",
		    FT_UINT32, BASE_DEC, VALS(v2giso1_payment_option_names),
		    0x0, NULL, HFILL }
		},
		/* struct iso1PaymentServiceSelectionResType */
		{ &hf_v2giso1_struct_iso1PaymentServiceSelectionResType_ResponseCode,
		  { "ResponseCode",
		    "v2giso1.struct.paymentserviceslectionres.responsecode",
		    FT_UINT32, BASE_DEC, VALS(v2giso1_response_code_names),
		    0x0, NULL, HFILL }
		},

		/* struct iso1PaymentDetailsReqType */
		{ &hf_v2giso1_struct_iso1PaymentDetailsReqType_eMAID,
		  { "eMAID", "v2giso1.struct.paymentdetailsreq.emaid",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		/* struct iso1PaymentDetailsResType */
		{ &hf_v2giso1_struct_iso1PaymentDetailsResType_ResponseCode,
		  { "ResponseCode",
		    "v2giso1.struct.paymentdetailsres.responsecode",
		    FT_UINT32, BASE_DEC, VALS(v2giso1_response_code_names),
		    0x0, NULL, HFILL }
		},
		{ &hf_v2giso1_struct_iso1PaymentDetailsResType_GenChallenge,
		  { "GenChallenge",
		    "v2giso1.struct.paymentdetailsres.genchallenge",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso1_struct_iso1PaymentDetailsResType_EVSETimeStamp,
		  { "EVSETimeStamp",
		    "v2giso1.struct.paymentdetailsres.evsetimestamp",
		    FT_INT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso1AuthorizationReqType */
		{ &hf_v2giso1_struct_iso1AuthorizationReqType_Id,
		  { "Id", "v2giso1.struct.authorizationreq.id",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso1_struct_iso1AuthorizationReqType_GenChallenge,
		  { "GenChallenge",
		    "v2giso1.struct.authorizationreq.genchallenge",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		/* struct iso1AuthorizationResType */
		{ &hf_v2giso1_struct_iso1AuthorizationResType_ResponseCode,
		  { "ResponseCode",
		    "v2giso1.struct.authorizationres.responsecode",
		    FT_UINT32, BASE_DEC, VALS(v2giso1_response_code_names),
		    0x0, NULL, HFILL }
		},
		{ &hf_v2giso1_struct_iso1AuthorizationResType_EVSEProcessing,
		  { "EVSEProcessing",
		    "v2giso1.struct.authorizationres.evseprocessing",
		    FT_UINT32, BASE_DEC, VALS(v2giso1_evse_processing_names),
		    0x0, NULL, HFILL }
		},

		/* struct iso1ChargeParameterDiscoveryReqType */
		{ &hf_v2giso1_struct_iso1ChargeParameterDiscoveryReqType_MaxEntriesSAScheduleTuple,
		  { "MaxEntriesSAScheduleTuple",
		    "v2giso1.struct.chargeparameterdiscoveryreq.maxentriessascheduletuple",
		    FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso1_struct_iso1ChargeParameterDiscoveryReqType_RequestedEnergyTransferType,
		  { "RequestedEnergyTransferMode",
		    "v2giso1.struct.chargeparameterdiscoveryreq.requestedenergytransfermode",
		    FT_UINT32, BASE_DEC,
		    VALS(v2giso1_energy_transfer_mode_names),
		    0x0, NULL, HFILL }
		},
		/* struct iso1ChargeParameterDiscoveryResType */
		{ &hf_v2giso1_struct_iso1ChargeParameterDiscoveryResType_ResponseCode,
		  { "ResponseCode",
		    "v2giso1.struct.chargeparameterdiscoveryres.responsecode",
		    FT_UINT32, BASE_DEC, VALS(v2giso1_response_code_names),
		    0x0, NULL, HFILL }
		},
		{ &hf_v2giso1_struct_iso1ChargeParameterDiscoveryResType_EVSEProcessing,
		  { "EVSEProcessing",
		    "v2giso1.struct.chargeparameterdiscoveryres.evseprocessing",
		    FT_UINT32, BASE_DEC, VALS(v2giso1_evse_processing_names),
		    0x0, NULL, HFILL }
		},

		/* struct iso1PowerDeliveryReqType */
		{ &hf_v2giso1_struct_iso1PowerDeliveryReqType_ChargeProgress,
		  { "ChargeProgress",
		    "v2giso1.struct.powerdeliveryreq.chargeprogress",
		    FT_UINT32, BASE_DEC, VALS(v2giso1_charge_progress_names),
		    0x0, NULL, HFILL }
		},
		{ &hf_v2giso1_struct_iso1PowerDeliveryReqType_SAScheduleTupleID,
		  { "SAScheduleTupleID",
		    "v2giso1.struct.powerdeliveryreq.sascheduletupleid",
		    FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		/* struct iso1PowerDeliveryResType */
		{ &hf_v2giso1_struct_iso1PowerDeliveryResType_ResponseCode,
		  { "ResponseCode",
		    "v2giso1.struct.powerdeliveryres.responsecode",
		    FT_UINT32, BASE_DEC, VALS(v2giso1_response_code_names),
		    0x0, NULL, HFILL }
		},

		/* struct iso1MeteringReceiptReqType */
		{ &hf_v2giso1_struct_iso1MeteringReceiptReqType_Id,
		  { "Id", "v2giso1.struct.meteringreceiptreq.id",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso1_struct_iso1MeteringReceiptReqType_SessionID,
		  { "SessionID", "v2giso1.struct.meteringreceiptreq.sessionid",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso1_struct_iso1MeteringReceiptReqType_SAScheduleTupleID,
		  { "SAScheduleTupleID",
		    "v2giso1.struct.meteringreceiptreq.sascheduletupleid",
		    FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		/* struct iso1MeteringReceiptResType */
		{ &hf_v2giso1_struct_iso1MeteringReceiptResType_ResponseCode,
		  { "ResponseCode",
		    "v2giso1.struct.meteringreceiptres.responsecode",
		    FT_UINT32, BASE_DEC, VALS(v2giso1_response_code_names),
		    0x0, NULL, HFILL }
		},

		/* struct iso1SessionStopReqType */
		{ &hf_v2giso1_struct_iso1SessionStopReqType_ChargingSession,
		  { "ChargingSession",
		    "v2giso1.struct.sessionstopreq.chargingsession",
		    FT_UINT32, BASE_DEC, VALS(v2giso1_charging_session_names),
		    0x0, NULL, HFILL }
		},
		/* struct iso1SessionStopResType */
		{ &hf_v2giso1_struct_iso1SessionStopResType_ResponseCode,
		  { "ResponseCode",
		    "v2giso1.struct.sessionstopres.responsecode",
		    FT_UINT32, BASE_DEC, VALS(v2giso1_response_code_names),
		    0x0, NULL, HFILL }
		},

		/* struct iso1CertificateUpdateReqType */
		{ &hf_v2giso1_struct_iso1CertificateUpdateReqType_Id,
		  { "Id", "v2giso1.struct.certificateupdatereq.id",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso1_struct_iso1CertificateUpdateReqType_eMAID,
		  { "eMAID", "v2giso1.struct.certificateupdatereq.emaid",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		/* struct iso1CertificateUpdateResType */
		{ &hf_v2giso1_struct_iso1CertificateUpdateResType_ResponseCode,
		  { "ResponseCode",
		    "v2giso1.struct.certificateupdateres.responsecode",
		    FT_UINT32, BASE_DEC, VALS(v2giso1_response_code_names),
		    0x0, NULL, HFILL }
		},
		{ &hf_v2giso1_struct_iso1CertificateUpdateResType_RetryCounter,
		  { "RetryCounter",
		    "v2giso1.struct.certificateupdateres.retrycounter",
		    FT_INT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso1CertificateInstallationReqType */
		{ &hf_v2giso1_struct_iso1CertificateInstallationReqType_Id,
		  { "Id", "v2giso1.struct.certificateinstallationreq.id",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso1_struct_iso1CertificateInstallationReqType_OEMProvisioningCert,
		  { "OEMProvisioningCert",
		    "v2giso1.struct.certificateinstallationreq.oemprovisioningcert",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		/* struct iso1CertificateInstallationResType */
		{ &hf_v2giso1_struct_iso1CertificateInstallationResType_ResponseCode,
		  { "ResponseCode",
		    "v2giso1.struct.certificateinstallationres.responsecode",
		    FT_UINT32, BASE_DEC, VALS(v2giso1_response_code_names),
		    0x0, NULL, HFILL }
		},

		/* struct iso1ChargingStatusResType */
		{ &hf_v2giso1_struct_iso1ChargingStatusResType_ResponseCode,
		  { "ResponseCode",
		    "v2giso1.struct.chargingstatusres.responsecode",
		    FT_UINT32, BASE_DEC, VALS(v2giso1_response_code_names),
		    0x0, NULL, HFILL }
		},
		{ &hf_v2giso1_struct_iso1ChargingStatusResType_EVSEID,
		  { "EVSEID", "v2giso1.struct.chargingstatusres.evseid",
		    FT_STRING, BASE_NONE, NULL,  0x0, NULL, HFILL }
		},
		{ &hf_v2giso1_struct_iso1ChargingStatusResType_SAScheduleTupleID,
		  { "SAScheduleTupleID",
		    "v2giso1.struct.chargingstatusres.sascheduletupleid",
		    FT_UINT8, BASE_DEC,  NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso1_struct_iso1ChargingStatusResType_ReceiptRequired,
		  { "ReceiptRequired",
		    "v2giso1.struct.chargingstatusres.receiptrequired",
		    FT_INT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso1CableCheckResType */
		{ &hf_v2giso1_struct_iso1CableCheckResType_ResponseCode,
		  { "ResponseCode", "v2giso1.struct.cablecheckres.responsecode",
		    FT_UINT32, BASE_DEC, VALS(v2giso1_response_code_names),
		    0x0, NULL, HFILL }
		},
		{ &hf_v2giso1_struct_iso1CableCheckResType_EVSEProcessing,
		  { "EVSEProcessing",
		    "v2giso1.struct.cablecheckres.evseprocessing",
		    FT_UINT32, BASE_DEC, VALS(v2giso1_evse_processing_names),
		    0x0, NULL, HFILL }
		},

		/* struct iso1PreChargeResType */
		{ &hf_v2giso1_struct_iso1PreChargeResType_ResponseCode,
		  { "ResponseCode", "v2giso1.struct.prechargeres.responsecode",
		    FT_UINT32, BASE_DEC, VALS(v2giso1_response_code_names),
		    0x0, NULL, HFILL }
		},

		/* struct iso1CurrentDemandReqType */
		{ &hf_v2giso1_struct_iso1CurrentDemandReqType_BulkChargingComplete,
		  { "BulkChargingComplete",
		    "v2giso1.struct.currentdemandreq.bulkchargingcomplete",
		    FT_INT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso1_struct_iso1CurrentDemandReqType_ChargingComplete,
		  { "ChargingComplete",
		    "v2giso1.struct.currentdemandreq.chargingcomplete",
		    FT_INT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		/* struct iso1CurrentDemandResType */
		{ &hf_v2giso1_struct_iso1CurrentDemandResType_ResponseCode,
		  { "ResponseCode",
		    "v2giso1.struct.currentdemandres.responsecode",
		    FT_UINT32, BASE_DEC, VALS(v2giso1_response_code_names),
		    0x0, NULL, HFILL }
		},
		{ &hf_v2giso1_struct_iso1CurrentDemandResType_EVSECurrentLimitAchieved,
		  { "EVSECurrentLimitAchieved",
		    "v2giso1.struct.currentdemandres.evsecurrentlimitachieved",
		    FT_INT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso1_struct_iso1CurrentDemandResType_EVSEVoltageLimitAchieved,
		  { "EVSEVoltageLimitAchieved",
		    "v2giso1.struct.currentdemandres.evsevoltagelimitachieved",
		    FT_INT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso1_struct_iso1CurrentDemandResType_EVSEPowerLimitAchieved,
		  { "EVSEPowerLimitAchieved",
		    "v2giso1.struct.currentdemandres.evsepowerlimitachieved",
		    FT_INT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso1_struct_iso1CurrentDemandResType_EVSEID,
		  { "EVSEID", "v2giso1.struct.currentdemandres.evseid",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso1_struct_iso1CurrentDemandResType_SAScheduleTupleID,
		  { "SAScheduleTupleID",
		    "v2giso1.struct.currentdemandres.sascheduletupleid",
		    FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso1_struct_iso1CurrentDemandResType_ReceiptRequired,
		  { "ReceiptRequired",
		    "v2giso1.struct.currentdemandres.receiptrequired",
		    FT_INT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso1WeldingDetectionResType */
		{ &hf_v2giso1_struct_iso1WeldingDetectionResType_ResponseCode,
		  { "ResponseCode",
		    "v2giso1.struct.weldingdetectionres.responsecode",
		    FT_UINT32, BASE_DEC, VALS(v2giso1_response_code_names),
		    0x0, NULL, HFILL }
		}
	};

	static gint *ett[] = {
		&ett_v2giso1,
		&ett_v2giso1_header,
		&ett_v2giso1_body,
		&ett_v2giso1_array,
		&ett_v2giso1_array_i,

		&ett_v2giso1_struct_iso1NotificationType,
		&ett_v2giso1_struct_iso1SignatureType,
		&ett_v2giso1_struct_iso1SignedInfoType,
		&ett_v2giso1_struct_iso1SignatureValueType,
		&ett_v2giso1_struct_iso1ObjectType,
		&ett_v2giso1_struct_iso1CanonicalizationMethodType,
		&ett_v2giso1_struct_iso1SignatureMethodType,
		&ett_v2giso1_struct_iso1DigestMethodType,
		&ett_v2giso1_struct_iso1ReferenceType,
		&ett_v2giso1_struct_iso1TransformsType,
		&ett_v2giso1_struct_iso1TransformType,
		&ett_v2giso1_struct_iso1KeyInfoType,
		&ett_v2giso1_struct_iso1KeyValueType,
		&ett_v2giso1_struct_iso1DSAKeyValueType,
		&ett_v2giso1_struct_iso1RSAKeyValueType,
		&ett_v2giso1_struct_iso1RetrievalMethodType,
		&ett_v2giso1_struct_iso1X509DataType,
		&ett_v2giso1_struct_iso1X509IssuerSerialType,
		&ett_v2giso1_struct_iso1PGPDataType,
		&ett_v2giso1_struct_iso1SPKIDataType,

		&ett_v2giso1_struct_iso1ServiceType,
		&ett_v2giso1_struct_iso1SupportedEnergyTransferModeType,
		&ett_v2giso1_struct_iso1PaymentOptionListType,
		&ett_v2giso1_struct_iso1ChargeServiceType,
		&ett_v2giso1_struct_iso1ServiceListType,
		&ett_v2giso1_struct_iso1ServiceParameterListType,
		&ett_v2giso1_struct_iso1ParameterSetType,
		&ett_v2giso1_struct_iso1ParameterType,
		&ett_v2giso1_struct_iso1PhysicalValueType,
		&ett_v2giso1_struct_iso1SelectedServiceListType,
		&ett_v2giso1_struct_iso1SelectedServiceType,
		&ett_v2giso1_struct_iso1CertificateChainType,
		&ett_v2giso1_struct_iso1SubCertificatesType,
		&ett_v2giso1_struct_iso1EVChargeParameterType,
		&ett_v2giso1_struct_iso1AC_EVChargeParameterType,
		&ett_v2giso1_struct_iso1DC_EVChargeParameterType,
		&ett_v2giso1_struct_iso1DC_EVStatusType,
		&ett_v2giso1_struct_iso1EVSEChargeParameterType,
		&ett_v2giso1_struct_iso1AC_EVSEChargeParameterType,
		&ett_v2giso1_struct_iso1DC_EVSEChargeParameterType,
		&ett_v2giso1_struct_iso1EVSEStatusType,
		&ett_v2giso1_struct_iso1AC_EVSEStatusType,
		&ett_v2giso1_struct_iso1DC_EVSEStatusType,
		&ett_v2giso1_struct_iso1SASchedulesType,
		&ett_v2giso1_struct_iso1SAScheduleListType,
		&ett_v2giso1_struct_iso1SAScheduleTupleType,
		&ett_v2giso1_struct_iso1PMaxScheduleType,
		&ett_v2giso1_struct_iso1PMaxScheduleEntryType,
		&ett_v2giso1_struct_iso1SalesTariffType,
		&ett_v2giso1_struct_iso1SalesTariffEntryType,
		&ett_v2giso1_struct_iso1ConsumptionCostType,
		&ett_v2giso1_struct_iso1CostType,
		&ett_v2giso1_struct_iso1RelativeTimeIntervalType,
		&ett_v2giso1_struct_iso1IntervalType,
		&ett_v2giso1_struct_iso1ChargingProfileType,
		&ett_v2giso1_struct_iso1ProfileEntryType,
		&ett_v2giso1_struct_iso1EVPowerDeliveryParameterType,
		&ett_v2giso1_struct_iso1DC_EVPowerDeliveryParameterType,
		&ett_v2giso1_struct_iso1MeterInfoType,
		&ett_v2giso1_struct_iso1ListOfRootCertificateIDsType,
		&ett_v2giso1_struct_iso1ContractSignatureEncryptedPrivateKeyType,
		&ett_v2giso1_struct_iso1DiffieHellmanPublickeyType,
		&ett_v2giso1_struct_iso1EMAIDType,

		&ett_v2giso1_struct_iso1SessionSetupReqType,
		&ett_v2giso1_struct_iso1SessionSetupResType,
		&ett_v2giso1_struct_iso1ServiceDiscoveryReqType,
		&ett_v2giso1_struct_iso1ServiceDiscoveryResType,
		&ett_v2giso1_struct_iso1ServiceDetailReqType,
		&ett_v2giso1_struct_iso1ServiceDetailResType,
		&ett_v2giso1_struct_iso1PaymentServiceSelectionReqType,
		&ett_v2giso1_struct_iso1PaymentServiceSelectionResType,
		&ett_v2giso1_struct_iso1PaymentDetailsReqType,
		&ett_v2giso1_struct_iso1PaymentDetailsResType,
		&ett_v2giso1_struct_iso1AuthorizationReqType,
		&ett_v2giso1_struct_iso1AuthorizationResType,
		&ett_v2giso1_struct_iso1ChargeParameterDiscoveryReqType,
		&ett_v2giso1_struct_iso1ChargeParameterDiscoveryResType,
		&ett_v2giso1_struct_iso1PowerDeliveryReqType,
		&ett_v2giso1_struct_iso1PowerDeliveryResType,
		&ett_v2giso1_struct_iso1MeteringReceiptReqType,
		&ett_v2giso1_struct_iso1MeteringReceiptResType,
		&ett_v2giso1_struct_iso1SessionStopReqType,
		&ett_v2giso1_struct_iso1SessionStopResType,
		&ett_v2giso1_struct_iso1CertificateUpdateReqType,
		&ett_v2giso1_struct_iso1CertificateUpdateResType,
		&ett_v2giso1_struct_iso1CertificateInstallationReqType,
		&ett_v2giso1_struct_iso1CertificateInstallationResType,
		&ett_v2giso1_struct_iso1ChargingStatusReqType,
		&ett_v2giso1_struct_iso1ChargingStatusResType,
		&ett_v2giso1_struct_iso1CableCheckReqType,
		&ett_v2giso1_struct_iso1CableCheckResType,
		&ett_v2giso1_struct_iso1PreChargeReqType,
		&ett_v2giso1_struct_iso1PreChargeResType,
		&ett_v2giso1_struct_iso1CurrentDemandReqType,
		&ett_v2giso1_struct_iso1CurrentDemandResType,
		&ett_v2giso1_struct_iso1WeldingDetectionReqType,
		&ett_v2giso1_struct_iso1WeldingDetectionResType,
	};

	proto_v2giso1 = proto_register_protocol(
		"V2G Efficient XML Interchange (ISO1)",
		"V2GISO1",
		"v2giso1"
	);
	proto_register_field_array(proto_v2giso1, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	register_dissector("v2giso1", dissect_v2giso1, proto_v2giso1);
}

void
proto_reg_handoff_v2giso1(void)
{

	/* add a handle for the connection oriented V2G EXI */
	v2gexi_handle = find_dissector_add_dependency("v2gexi", proto_v2giso1);
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
