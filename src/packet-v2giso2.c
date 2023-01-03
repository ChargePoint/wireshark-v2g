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

static int hf_v2giso2_struct_iso2EVSEStatusType_NotificationMaxDelay = -1;
static int hf_v2giso2_struct_iso2EVSEStatusType_EVSENotification = -1;

static int hf_v2giso2_struct_iso2PhysicalValueType_Exponent = -1;
static int hf_v2giso2_struct_iso2PhysicalValueType_Value = -1;

static int hf_v2giso2_struct_iso2DisplayParametersType_CurrentRange = -1;
static int hf_v2giso2_struct_iso2DisplayParametersType_CurrentSOC = -1;
static int hf_v2giso2_struct_iso2DisplayParametersType_TargetSOC = -1;
static int hf_v2giso2_struct_iso2DisplayParametersType_BulkSOC = -1;
static int hf_v2giso2_struct_iso2DisplayParametersType_MinimumSOC = -1;
static int hf_v2giso2_struct_iso2DisplayParametersType_RemainingTimeToTargetSOC = -1;
static int hf_v2giso2_struct_iso2DisplayParametersType_RemainingTimeToBulkSOC = -1;
static int hf_v2giso2_struct_iso2DisplayParametersType_RemainingTimeToMinimumSOC = -1;
static int hf_v2giso2_struct_iso2DisplayParametersType_ChargingComplete = -1;
static int hf_v2giso2_struct_iso2DisplayParametersType_BulkChargingComplete = -1;
static int hf_v2giso2_struct_iso2DisplayParametersType_InletHot = -1;

static int hf_v2giso2_struct_iso2MeterInfoType_MeterID = -1;
static int hf_v2giso2_struct_iso2MeterInfoType_MeterReadingCharged = -1;
static int hf_v2giso2_struct_iso2MeterInfoType_MeterReadingDischarged = -1;
static int hf_v2giso2_struct_iso2MeterInfoType_SigMeterReading = -1;
static int hf_v2giso2_struct_iso2MeterInfoType_MeterStatus = -1;
static int hf_v2giso2_struct_iso2MeterInfoType_TMeter = -1;

static int hf_v2giso2_struct_iso2TargetPositionType_TargetOffsetX = -1;
static int hf_v2giso2_struct_iso2TargetPositionType_TargetOffsetY = -1;

static int hf_v2giso2_struct_iso2ParameterType_Name = -1;
static int hf_v2giso2_struct_iso2ParameterType_boolValue = -1;
static int hf_v2giso2_struct_iso2ParameterType_byteValue = -1;
static int hf_v2giso2_struct_iso2ParameterType_shortValue = -1;
static int hf_v2giso2_struct_iso2ParameterType_intValue = -1;
static int hf_v2giso2_struct_iso2ParameterType_stringValue = -1;

static int hf_v2giso2_struct_iso2ParameterSetType_ParameterSetID = -1;

static int hf_v2giso2_struct_iso2MeasurementDataListType_MeasurementData = -1;

static int hf_v2giso2_struct_iso2SensorMeasurementsType_SensorID = -1;
static int hf_v2giso2_struct_iso2SensorMeasurementsType_EffectiveRadiatedPower = -1;

static int hf_v2giso2_struct_iso2SensorPackageType_PackageIndex = -1;

static int hf_v2giso2_struct_iso2CartesianCoordinatesType_XCoordinate = -1;
static int hf_v2giso2_struct_iso2CartesianCoordinatesType_YCoordinate = -1;
static int hf_v2giso2_struct_iso2CartesianCoordinatesType_ZCoordinate = -1;

static int hf_v2giso2_struct_iso2SensorType_SensorID = -1;

static int hf_v2giso2_struct_iso2SensorOrderListType_SensorPosition = -1;

static int hf_v2giso2_struct_iso2MagneticVectorType_GAID = -1;
static int hf_v2giso2_struct_iso2MagneticVectorType_Distance = -1;
static int hf_v2giso2_struct_iso2MagneticVectorType_FODStatus = -1;

static int hf_v2giso2_struct_iso2MagneticVectorSetupType_GAID = -1;
static int hf_v2giso2_struct_iso2MagneticVectorSetupType_FrequencyChannel = -1;

static int hf_v2giso2_struct_iso2LFA_EVFinePositioningParametersType_NumberOfSignalPackages = -1;

static int hf_v2giso2_struct_iso2LFA_EVSEFinePositioningParametersType_NumberOfSignalPackages = -1;

static int hf_v2giso2_struct_iso2LFA_EVFinePositioningSetupParametersType_NumberOfSensors = -1;
static int hf_v2giso2_struct_iso2LFA_EVFinePositioningSetupParametersType_SignalPulseDuration = -1;
static int hf_v2giso2_struct_iso2LFA_EVFinePositioningSetupParametersType_SignalSeparationTime = -1;
static int hf_v2giso2_struct_iso2LFA_EVFinePositioningSetupParametersType_PackageSeparationTime = -1;
static int hf_v2giso2_struct_iso2LFA_EVFinePositioningSetupParametersType_AlignmentOffset = -1;

static int hf_v2giso2_struct_iso2LFA_EVSEFinePositioningSetupParametersType_NumberOfSensors = -1;
static int hf_v2giso2_struct_iso2LFA_EVSEFinePositioningSetupParametersType_SignalPulseDuration = -1;
static int hf_v2giso2_struct_iso2LFA_EVSEFinePositioningSetupParametersType_SignalSeparationTime = -1;
static int hf_v2giso2_struct_iso2LFA_EVSEFinePositioningSetupParametersType_PackageSeparationTime = -1;
static int hf_v2giso2_struct_iso2LFA_EVSEFinePositioningSetupParametersType_AlignmentOffset = -1;
static int hf_v2giso2_struct_iso2LFA_EVSEFinePositioningSetupParametersType_SignalFrequency = -1;

static int hf_v2giso2_struct_iso2MV_EVSEFinePositioningSetupParametersType_FrequencyChannel = -1;

static int hf_v2giso2_struct_iso2SubCertificatesType_Certificate = -1;

static int hf_v2giso2_struct_iso2CertificateChainType_Id = -1;
static int hf_v2giso2_struct_iso2CertificateChainType_Certificate = -1;

static int hf_v2giso2_struct_iso2ContractSignatureEncryptedPrivateKeyType_Id = -1;
static int hf_v2giso2_struct_iso2ContractSignatureEncryptedPrivateKeyType_CONTENT = -1;

static int hf_v2giso2_struct_iso2DiffieHellmanPublickeyType_Id = -1;
static int hf_v2giso2_struct_iso2DiffieHellmanPublickeyType_CONTENT = -1;

static int hf_v2giso2_struct_iso2EMAIDType_Id = -1;
static int hf_v2giso2_struct_iso2EMAIDType_CONTENT = -1;

static int hf_v2giso2_struct_iso2RelativeTimeIntervalType_start = -1;
static int hf_v2giso2_struct_iso2RelativeTimeIntervalType_duration = -1;

static int hf_v2giso2_struct_iso2DisconnectChargingDeviceReqType_EVElectricalChargingDeviceStatus = -1;
static int hf_v2giso2_struct_iso2DisconnectChargingDeviceReqType_EVMechanicalChargingDeviceStatus = -1;
static int hf_v2giso2_struct_iso2DisconnectChargingDeviceResType_ResponseCode = -1;
static int hf_v2giso2_struct_iso2DisconnectChargingDeviceResType_EVSEProcessing = -1;
static int hf_v2giso2_struct_iso2DisconnectChargingDeviceResType_EVSEElectricalChargingDeviceStatus = -1;
static int hf_v2giso2_struct_iso2DisconnectChargingDeviceResType_EVSEMechanicalChargingDeviceStatus = -1;

static int hf_v2giso2_struct_iso2ConnectChargingDeviceReqType_EVElectricalChargingDeviceStatus = -1;
static int hf_v2giso2_struct_iso2ConnectChargingDeviceReqType_EVMechanicalChargingDeviceStatus = -1;
static int hf_v2giso2_struct_iso2ConnectChargingDeviceResType_ResponseCode = -1;
static int hf_v2giso2_struct_iso2ConnectChargingDeviceResType_EVSEProcessing = -1;
static int hf_v2giso2_struct_iso2ConnectChargingDeviceResType_EVSEElectricalChargingDeviceStatus = -1;
static int hf_v2giso2_struct_iso2ConnectChargingDeviceResType_EVSEMechanicalChargingDeviceStatus = -1;

static int hf_v2giso2_struct_iso2SystemStatusReqType_OperationMode = -1;
static int hf_v2giso2_struct_iso2SystemStatusReqType_EVMechanicalChargingDeviceStatus = -1;
static int hf_v2giso2_struct_iso2SystemStatusResType_ResponseCode = -1;
static int hf_v2giso2_struct_iso2SystemStatusResType_OperationMode = -1;
static int hf_v2giso2_struct_iso2SystemStatusResType_EVSEMechanicalChargingDeviceStatus = -1;

static int hf_v2giso2_struct_iso2DC_BidirectionalControlResType_ResponseCode = -1;
static int hf_v2giso2_struct_iso2DC_BidirectionalControlResType_EVSEPowerLimitAchieved = -1;
static int hf_v2giso2_struct_iso2DC_BidirectionalControlResType_EVSECurrentLimitAchieved = -1;
static int hf_v2giso2_struct_iso2DC_BidirectionalControlResType_EVSEVoltageLimitAchieved = -1;
static int hf_v2giso2_struct_iso2DC_BidirectionalControlResType_EVSEID = -1;
static int hf_v2giso2_struct_iso2DC_BidirectionalControlResType_ReceiptRequired = -1;

static int hf_v2giso2_struct_iso2AC_BidirectionalControlReqType_EVOperation = -1;
static int hf_v2giso2_struct_iso2AC_BidirectionalControlResType_ResponseCode = -1;
static int hf_v2giso2_struct_iso2AC_BidirectionalControlResType_EVSEProcessing = -1;
static int hf_v2giso2_struct_iso2AC_BidirectionalControlResType_EVSEID = -1;
static int hf_v2giso2_struct_iso2AC_BidirectionalControlResType_SAScheduleTupleID = -1;
static int hf_v2giso2_struct_iso2AC_BidirectionalControlResType_ReceiptRequired = -1;

static int hf_v2giso2_struct_iso2VehicleCheckOutReqType_EVCheckOutStatus = -1;
static int hf_v2giso2_struct_iso2VehicleCheckOutReqType_CheckOutTime = -1;
static int hf_v2giso2_struct_iso2VehicleCheckOutResType_ResponseCode = -1;
static int hf_v2giso2_struct_iso2VehicleCheckOutResType_EVSECheckOutStatus = -1;

static int hf_v2giso2_struct_iso2VehicleCheckInReqType_EVCheckInStatus = -1;
static int hf_v2giso2_struct_iso2VehicleCheckInReqType_ParkingMethod = -1;
static int hf_v2giso2_struct_iso2VehicleCheckInResType_ResponseCode = -1;
static int hf_v2giso2_struct_iso2VehicleCheckInResType_VehicleSpace = -1;

static int hf_v2giso2_struct_iso2PowerDemandResType_ResponseCode = -1;
static int hf_v2giso2_struct_iso2PowerDemandResType_EVSEID = -1;
static int hf_v2giso2_struct_iso2PowerDemandResType_SAScheduleTupleID = -1;
static int hf_v2giso2_struct_iso2PowerDemandResType_ReceiptRequired = -1;

static int hf_v2giso2_struct_iso2PairingReqType_EVProcessing = -1;
static int hf_v2giso2_struct_iso2PairingResType_ResponseCode = -1;
static int hf_v2giso2_struct_iso2PairingResType_EVSEProcessing = -1;

static int hf_v2giso2_struct_iso2AlignmentCheckReqType_EVProcessing = -1;
static int hf_v2giso2_struct_iso2AlignmentCheckResType_ResponseCode = -1;
static int hf_v2giso2_struct_iso2AlignmentCheckResType_EVSEProcessing = -1;

static int hf_v2giso2_struct_iso2FinePositioningReqType_EVProcessing = -1;
static int hf_v2giso2_struct_iso2FinePositioningResType_ResponseCode = -1;
static int hf_v2giso2_struct_iso2FinePositioningResType_EVSEProcessing = -1;

static int hf_v2giso2_struct_iso2FinePositioningSetupResType_ResponseCode = -1;

static int hf_v2giso2_struct_iso2WeldingDetectionResType_ResponseCode = -1;

static int hf_v2giso2_struct_iso2CurrentDemandResType_ResponseCode = -1;
static int hf_v2giso2_struct_iso2CurrentDemandResType_EVSEPowerLimitAchieved = -1;
static int hf_v2giso2_struct_iso2CurrentDemandResType_EVSECurrentLimitAchieved = -1;
static int hf_v2giso2_struct_iso2CurrentDemandResType_EVSEID = -1;
static int hf_v2giso2_struct_iso2CurrentDemandResType_SAScheduleTupleID = -1;
static int hf_v2giso2_struct_iso2CurrentDemandResType_ReceiptRequired = -1;

static int hf_v2giso2_struct_iso2CableCheckResType_ResponseCode = -1;
static int hf_v2giso2_struct_iso2CableCheckResType_EVSEProcessing = -1;

static int hf_v2giso2_struct_iso2ChargingStatusResType_ResponseCode = -1;
static int hf_v2giso2_struct_iso2ChargingStatusResType_EVSEID = -1;
static int hf_v2giso2_struct_iso2ChargingStatusResType_SAScheduleTupleID = -1;
static int hf_v2giso2_struct_iso2ChargingStatusResType_ReceiptRequired = -1;

static int hf_v2giso2_struct_iso2CertificateInstallationReqType_Id = -1;
static int hf_v2giso2_struct_iso2CertificateInstallationReqType_OEMProvisioningCert = -1;
static int hf_v2giso2_struct_iso2CertificateInstallationResType_ResponseCode = -1;

static int hf_v2giso2_struct_iso2CertificateUpdateReqType_Id = -1;
static int hf_v2giso2_struct_iso2CertificateUpdateReqType_eMAID = -1;
static int hf_v2giso2_struct_iso2CertificateUpdateResType_ResponseCode = -1;
static int hf_v2giso2_struct_iso2CertificateUpdateResType_RetryCounter = -1;

static int hf_v2giso2_struct_iso2SessionStopReqType_ChargingSession = -1;
static int hf_v2giso2_struct_iso2SessionStopResType_ResponseCode = -1;

static int hf_v2giso2_struct_iso2MeteringReceiptReqType_Id = -1;
static int hf_v2giso2_struct_iso2MeteringReceiptReqType_SessionID = -1;
static int hf_v2giso2_struct_iso2MeteringReceiptReqType_SAScheduleTupleID = -1;
static int hf_v2giso2_struct_iso2MeteringReceiptResType_ResponseCode = -1;

static int hf_v2giso2_struct_iso2PowerDeliveryReqType_ChargeProgress = -1;
static int hf_v2giso2_struct_iso2PowerDeliveryReqType_EVOperation = -1;
static int hf_v2giso2_struct_iso2PowerDeliveryReqType_SAScheduleTupleID = -1;
static int hf_v2giso2_struct_iso2PowerDeliveryResType_ResponseCode = -1;
static int hf_v2giso2_struct_iso2PowerDeliveryResType_EVSEProcessing = -1;

static int hf_v2giso2_struct_iso2ChargeParameterDiscoveryReqType_MaxSupportingPoints = -1;
static int hf_v2giso2_struct_iso2ChargeParameterDiscoveryResType_ResponseCode = -1;
static int hf_v2giso2_struct_iso2ChargeParameterDiscoveryResType_EVSEProcessing = -1;

static int hf_v2giso2_struct_iso2AuthorizationReqType_Id = -1;
static int hf_v2giso2_struct_iso2AuthorizationReqType_GenChallenge = -1;
static int hf_v2giso2_struct_iso2AuthorizationResType_ResponseCode = -1;
static int hf_v2giso2_struct_iso2AuthorizationResType_EVSEProcessing = -1;

static int hf_v2giso2_struct_iso2PaymentDetailsReqType_eMAID = -1;
static int hf_v2giso2_struct_iso2PaymentDetailsResType_ResponseCode = -1;
static int hf_v2giso2_struct_iso2PaymentDetailsResType_GenChallenge = -1;
static int hf_v2giso2_struct_iso2PaymentDetailsResType_EVSETimeStamp = -1;

static int hf_v2giso2_struct_iso2PaymentServiceSelectionReqType_SelectedPaymentOption = -1;
static int hf_v2giso2_struct_iso2PaymentServiceSelectionResType_ResponseCode = -1;

static int hf_v2giso2_struct_iso2ServiceDetailReqType_ServiceID = -1;
static int hf_v2giso2_struct_iso2ServiceDetailResType_ResponseCode = -1;
static int hf_v2giso2_struct_iso2ServiceDetailResType_ServiceID = -1;

static int hf_v2giso2_struct_iso2ServiceDiscoveryResType_ResponseCode = -1;

static int hf_v2giso2_struct_iso2SessionSetupReqType_EVCCID = -1;
static int hf_v2giso2_struct_iso2SessionSetupResType_ResponseCode = -1;
static int hf_v2giso2_struct_iso2SessionSetupResType_EVSEID = -1;
static int hf_v2giso2_struct_iso2SessionSetupResType_EVSETimeStamp = -1;

/* Specifically track voltage and current for graphing */
static int hf_v2giso2_target_voltage = -1;
static int hf_v2giso2_target_current = -1;
static int hf_v2giso2_present_voltage = -1;
static int hf_v2giso2_present_current = -1;

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

static gint ett_v2giso2_struct_iso2EVSEStatusType = -1;
static gint ett_v2giso2_struct_iso2PhysicalValueType = -1;
static gint ett_v2giso2_struct_iso2DisplayParametersType = -1;
static gint ett_v2giso2_struct_iso2MeterInfoType = -1;
static gint ett_v2giso2_struct_iso2TargetPositionType = -1;
static gint ett_v2giso2_struct_iso2ParameterType = -1;
static gint ett_v2giso2_struct_iso2ParameterSetType = -1;
static gint ett_v2giso2_struct_iso2MeasurementDataListType = -1;
static gint ett_v2giso2_struct_iso2SensorMeasurementsType = -1;
static gint ett_v2giso2_struct_iso2SensorPackageType = -1;
static gint ett_v2giso2_struct_iso2SensorPackageListType = -1;
static gint ett_v2giso2_struct_iso2CartesianCoordinatesType = -1;
static gint ett_v2giso2_struct_iso2SensorType = -1;
static gint ett_v2giso2_struct_iso2SensorListType = -1;
static gint ett_v2giso2_struct_iso2SensorOrderListType = -1;
static gint ett_v2giso2_struct_iso2MagneticVectorType = -1;
static gint ett_v2giso2_struct_iso2MagneticVectorListType = -1;
static gint ett_v2giso2_struct_iso2MagneticVectorSetupType = -1;
static gint ett_v2giso2_struct_iso2MagneticVectorSetupListType = -1;
static gint ett_v2giso2_struct_iso2EVFinePositioningParametersType = -1;
static gint ett_v2giso2_struct_iso2Generic_EVFinePositioningParametersType = -1;
static gint ett_v2giso2_struct_iso2LFA_EVFinePositioningParametersType = -1;
static gint ett_v2giso2_struct_iso2EVSEFinePositioningParametersType = -1;
static gint ett_v2giso2_struct_iso2Generic_EVSEFinePositioningParametersType = -1;
static gint ett_v2giso2_struct_iso2LFA_EVSEFinePositioningParametersType = -1;
static gint ett_v2giso2_struct_iso2MV_EVSEFinePositioningParametersType = -1;
static gint ett_v2giso2_struct_iso2EVFinePositioningSetupParametersType = -1;
static gint ett_v2giso2_struct_iso2LFA_EVFinePositioningSetupParametersType = -1;
static gint ett_v2giso2_struct_iso2EVSEFinePositioningSetupParametersType = -1;
static gint ett_v2giso2_struct_iso2LFA_EVSEFinePositioningSetupParametersType = -1;
static gint ett_v2giso2_struct_iso2MV_EVSEFinePositioningSetupParametersType = -1;
static gint ett_v2giso2_struct_iso2ListOfRootCertificateIDsType = -1;
static gint ett_v2giso2_struct_iso2SubCertificatesType = -1;
static gint ett_v2giso2_struct_iso2CertificateChainType = -1;
static gint ett_v2giso2_struct_iso2ContractSignatureEncryptedPrivateKeyType = -1;
static gint ett_v2giso2_struct_iso2DiffieHellmanPublickeyType = -1;
static gint ett_v2giso2_struct_iso2EMAIDType = -1;
static gint ett_v2giso2_struct_iso2ChargingProfileType = -1;
static gint ett_v2giso2_struct_iso2RelativeTimeIntervalType = -1;
static gint ett_v2giso2_struct_iso2PMaxScheduleEntryType = -1;
static gint ett_v2giso2_struct_iso2EVEnergyTransferParameterType = -1;
static gint ett_v2giso2_struct_iso2AC_EVChargeParameterType = -1;
static gint ett_v2giso2_struct_iso2AC_EVBidirectionalParameterType = -1;
static gint ett_v2giso2_struct_iso2DC_EVChargeParameterType = -1;
static gint ett_v2giso2_struct_iso2DC_EVBidirectionalParameterType = -1;
static gint ett_v2giso2_struct_iso2WPT_EVChargeParameterType = -1;
static gint ett_v2giso2_struct_iso2MinimumPMaxRequestType = -1;
static gint ett_v2giso2_struct_iso2SAScheduleListType = -1;
static gint ett_v2giso2_struct_iso2EVSEEnergyTransferParameterType = -1;
static gint ett_v2giso2_struct_iso2AC_EVSEChargeParameterType = -1;
static gint ett_v2giso2_struct_iso2AC_EVSEBidirectionalParameterType = -1;
static gint ett_v2giso2_struct_iso2DC_EVSEChargeParameterType = -1;
static gint ett_v2giso2_struct_iso2DC_EVSEBidirectionalParameterType = -1;
static gint ett_v2giso2_struct_iso2WPT_EVSEChargeParameterType = -1;
static gint ett_v2giso2_struct_iso2SelectedServiceType = -1;
static gint ett_v2giso2_struct_iso2SelectedServiceListType = -1;
static gint ett_v2giso2_struct_iso2ServiceParameterListType = -1;
static gint ett_v2giso2_struct_iso2ServiceIDListType = -1;
static gint ett_v2giso2_struct_iso2ServiceListType = -1;
static gint ett_v2giso2_struct_iso2PaymentOptionListType = -1;

static gint ett_v2giso2_struct_iso2DisconnectChargingDeviceReqType = -1;
static gint ett_v2giso2_struct_iso2DisconnectChargingDeviceResType = -1;
static gint ett_v2giso2_struct_iso2ConnectChargingDeviceReqType = -1;
static gint ett_v2giso2_struct_iso2ConnectChargingDeviceResType = -1;
static gint ett_v2giso2_struct_iso2SystemStatusReqType = -1;
static gint ett_v2giso2_struct_iso2SystemStatusResType = -1;
static gint ett_v2giso2_struct_iso2DC_BidirectionalControlReqType = -1;
static gint ett_v2giso2_struct_iso2DC_BidirectionalControlResType = -1;
static gint ett_v2giso2_struct_iso2AC_BidirectionalControlReqType = -1;
static gint ett_v2giso2_struct_iso2AC_BidirectionalControlResType = -1;
static gint ett_v2giso2_struct_iso2VehicleCheckOutReqType = -1;
static gint ett_v2giso2_struct_iso2VehicleCheckOutResType = -1;
static gint ett_v2giso2_struct_iso2VehicleCheckInReqType = -1;
static gint ett_v2giso2_struct_iso2VehicleCheckInResType = -1;
static gint ett_v2giso2_struct_iso2PowerDemandReqType = -1;
static gint ett_v2giso2_struct_iso2PowerDemandResType = -1;
static gint ett_v2giso2_struct_iso2PairingReqType = -1;
static gint ett_v2giso2_struct_iso2PairingResType = -1;
static gint ett_v2giso2_struct_iso2AlignmentCheckReqType = -1;
static gint ett_v2giso2_struct_iso2AlignmentCheckResType = -1;
static gint ett_v2giso2_struct_iso2FinePositioningReqType = -1;
static gint ett_v2giso2_struct_iso2FinePositioningResType = -1;
static gint ett_v2giso2_struct_iso2FinePositioningSetupReqType = -1;
static gint ett_v2giso2_struct_iso2FinePositioningSetupResType = -1;
static gint ett_v2giso2_struct_iso2WeldingDetectionReqType = -1;
static gint ett_v2giso2_struct_iso2WeldingDetectionResType = -1;
static gint ett_v2giso2_struct_iso2CurrentDemandReqType = -1;
static gint ett_v2giso2_struct_iso2CurrentDemandResType = -1;
static gint ett_v2giso2_struct_iso2PreChargeReqType = -1;
static gint ett_v2giso2_struct_iso2PreChargeResType = -1;
static gint ett_v2giso2_struct_iso2CableCheckReqType = -1;
static gint ett_v2giso2_struct_iso2CableCheckResType = -1;
static gint ett_v2giso2_struct_iso2ChargingStatusReqType = -1;
static gint ett_v2giso2_struct_iso2ChargingStatusResType = -1;
static gint ett_v2giso2_struct_iso2CertificateInstallationReqType = -1;
static gint ett_v2giso2_struct_iso2CertificateInstallationResType = -1;
static gint ett_v2giso2_struct_iso2CertificateUpdateReqType = -1;
static gint ett_v2giso2_struct_iso2CertificateUpdateResType = -1;
static gint ett_v2giso2_struct_iso2SessionStopReqType = -1;
static gint ett_v2giso2_struct_iso2SessionStopResType = -1;
static gint ett_v2giso2_struct_iso2MeteringReceiptReqType = -1;
static gint ett_v2giso2_struct_iso2MeteringReceiptResType = -1;
static gint ett_v2giso2_struct_iso2PowerDeliveryReqType = -1;
static gint ett_v2giso2_struct_iso2PowerDeliveryResType = -1;
static gint ett_v2giso2_struct_iso2ChargeParameterDiscoveryReqType = -1;
static gint ett_v2giso2_struct_iso2ChargeParameterDiscoveryResType = -1;
static gint ett_v2giso2_struct_iso2AuthorizationReqType = -1;
static gint ett_v2giso2_struct_iso2AuthorizationResType = -1;
static gint ett_v2giso2_struct_iso2PaymentDetailsReqType = -1;
static gint ett_v2giso2_struct_iso2PaymentDetailsResType = -1;
static gint ett_v2giso2_struct_iso2PaymentServiceSelectionReqType = -1;
static gint ett_v2giso2_struct_iso2PaymentServiceSelectionResType = -1;
static gint ett_v2giso2_struct_iso2ServiceDetailReqType = -1;
static gint ett_v2giso2_struct_iso2ServiceDetailResType = -1;
static gint ett_v2giso2_struct_iso2ServiceDiscoveryReqType = -1;
static gint ett_v2giso2_struct_iso2ServiceDiscoveryResType = -1;
static gint ett_v2giso2_struct_iso2SessionSetupReqType = -1;
static gint ett_v2giso2_struct_iso2SessionSetupResType = -1;


static const value_string v2giso2_enum_iso2mechanicalChargingDeviceStatusType_names[] = {
	{ iso2mechanicalChargingDeviceStatusType_Home, "Home" },
	{ iso2mechanicalChargingDeviceStatusType_Moving, "Moving" },
	{ iso2mechanicalChargingDeviceStatusType_EndPosition, "EndPosition" }
};

static const value_string v2giso2_enum_iso2electricalChargingDeviceStatusType_names[] = {
	{ iso2electricalChargingDeviceStatusType_Connected, "Connected" },
	{ iso2electricalChargingDeviceStatusType_Disconnected, "Disconnected" }
};

static const value_string v2giso2_enum_iso2EVSENotificationType_names[] = {
	{ iso2EVSENotificationType_StopCharging, "StopCharging" },
	{ iso2EVSENotificationType_ReNegotiation, "ReNegotiation" }
};

static const value_string v2giso2_enum_iso2responseCodeType_names[] = {
	{ iso2responseCodeType_OK, "OK" },
	{ iso2responseCodeType_OK_NewSessionEstablished,
	  "OK (NewSessionEstablished)" },
	{ iso2responseCodeType_OK_OldSessionJoined, "OK (OldSessionJoined)" },
	{ iso2responseCodeType_OK_CertificateExpiresSoon,
	  "OK (CertificateExpiresSoon)" },
	{ iso2responseCodeType_OK_IsolationValid, "OK (IsolationValid)" },
	{ iso2responseCodeType_OK_IsolationWarning, "OK (IsolationWarning)" },
	{ iso2responseCodeType_WARNING_CertificateExpired,
	  "WARNING (CertificateExpired)" },
	{ iso2responseCodeType_WARNING_NoCertificateAvailable,
	  "WARNING (NoCertificateAvailable)" },
	{ iso2responseCodeType_WARNING_CertValidationError,
	  "WARNING (CertValidationError)" },
	{ iso2responseCodeType_WARNING_CertVerificationError,
	  "WARNGIN (CertVerificationError)" },
	{ iso2responseCodeType_WARNING_ContractCanceled,
	  "WARNING (ContractCanceled)" },
	{ iso2responseCodeType_FAILED, "FAILED" },
	{ iso2responseCodeType_FAILED_SequenceError,
	  "FAILED (SequenceError)" },
	{ iso2responseCodeType_FAILED_ServiceIDInvalid,
	  "FAILED (ServiceIDInvalid)" },
	{ iso2responseCodeType_FAILED_UnknownSession,
	  "FAILED (UnknownSession)" },
	{ iso2responseCodeType_FAILED_ServiceSelectionInvalid,
	  "FAILED (ServiceSelectionInvalid)" },
	{ iso2responseCodeType_FAILED_SignatureError,
	  "FAILED (SignatureError)" },
	{ iso2responseCodeType_FAILED_PaymentSelectionInvalid,
	  "FAILED (PaymentSelectionInvalid)" },
	{ iso2responseCodeType_FAILED_ChallengeInvalid,
	  "FAILED (ChallengeInvalid)" },
	{ iso2responseCodeType_FAILED_WrongChargeParameter,
	  "FAILED (WrongChargeParameter)" },
	{ iso2responseCodeType_FAILED_IsolationFault,
	  "FAILED (IsolationFault)" },
	{ iso2responseCodeType_FAILED_PowerDeliveryNotApplied,
	  "FAILED (PowerDeliveryNotApplied)" },
	{ iso2responseCodeType_FAILED_TariffSelectionInvalid,
	  "FAILED (TariffSelectionInvalid)" },
	{ iso2responseCodeType_FAILED_ChargingProfileInvalid,
	  "FAILED (ChargingProfileInvalid)" },
	{ iso2responseCodeType_FAILED_MeteringSignatureNotValid,
	  "FAILED (MeteringSignatureNotValid)" },
	{ iso2responseCodeType_FAILED_NoChargeServiceSelected,
	  "FAILED (NoChargeServiceSelected)" },
	{ iso2responseCodeType_FAILED_WrongEnergyTransferMode,
	  "FAILED (WrongEnergyTransferMode)" },
	{ iso2responseCodeType_FAILED_ContactorError,
	  "FAILED (ContactorError)" },
	{ iso2responseCodeType_FAILED_CertificateRevoked,
	  "FAILED (CertificateRevoked)" },
	{ iso2responseCodeType_FAILED_CertificateNotYetValid,
	  "FAILED (CertificateNotYetValid)" }
};

static const value_string v2giso2_enum_iso2EVSEProcessingType_names[] = {
	{ iso2EVSEProcessingType_Finished, "Finished" },
	{ iso2EVSEProcessingType_Ongoing, "Ongoing" },
	{ iso2EVSEProcessingType_Ongoing_WaitingForCustomerInteraction,
	  "Ongoing (WaitingForCustomerInteraction)" }
};

static const value_string v2giso2_enum_iso2operationModeType_names[] = {
	{ iso2operationModeType_Ready, "Ready" },
	{ iso2operationModeType_NotReady, "NotReady" }
};

static const value_string v2giso2_enum_iso2EVOperationType_names[] = {
	{ iso2EVOperationType_Charge, "Charge" },
	{ iso2EVOperationType_BPT, "BPT" }
};

static const value_string v2giso2_enum_iso2EVCheckOutStatusType_names[] = {
	{ iso2EVCheckOutStatusType_CheckOut, "CheckOut" },
	{ iso2EVCheckOutStatusType_Processing, "Processing" },
	{ iso2EVCheckOutStatusType_Completed, "Completed" }
};

static const value_string v2giso2_enum_iso2EVSECheckOutStatusType_names[] = {
	{ iso2EVSECheckOutStatusType_Scheduled, "Scheduled" },
	{ iso2EVSECheckOutStatusType_Completed, "Completed" }
};

static const value_string v2giso2_enum_iso2EVCheckInStatusType_names[] = {
	{ iso2EVCheckInStatusType_CheckIn, "CheckIn" },
	{ iso2EVCheckInStatusType_Processing, "Processing" },
	{ iso2EVCheckInStatusType_Completed, "Completed" }
};

static const value_string v2giso2_enum_iso2parkingMethodType_names[] = {
	{ iso2parkingMethodType_AutoParking, "AutoParking" },
	{ iso2parkingMethodType_MVGuideManual, "MVGuideManual" },
	{ iso2parkingMethodType_Manual, "Manual" }
};

static const value_string v2giso2_enum_iso2FODStatusType_names[] = {
	{ iso2FODStatusType_ObjectOnPad, "ObjectOnPad" },
	{ iso2FODStatusType_PadClear, "PadClear" },
	{ iso2FODStatusType_UnknownError, "UnknownError" }
};

static const value_string v2giso2_enum_iso2chargingSessionType_names[] = {
	{ iso2chargingSessionType_Terminate, "Terminate" },
	{ iso2chargingSessionType_Pause, "Pause" }
};

static const value_string v2giso2_enum_iso2chargeProgressType_names[] = {
	{ iso2chargeProgressType_Start, "Start" },
	{ iso2chargeProgressType_Stop, "Stop" },
	{ iso2chargeProgressType_Renegotiate, "Renegotiate" }
};

static const value_string v2giso2_enum_iso2paymentOptionType_names[] = {
	{ iso2paymentOptionType_Contract, "Contract" },
	{ iso2paymentOptionType_ExternalPayment, "ExternalPayment" }
};


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
dissect_v2giso2_evsestatus(
	const struct iso2EVSEStatusType *evsestatus,
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
		hf_v2giso2_struct_iso2EVSEStatusType_NotificationMaxDelay,
		tvb, 0, 0, evsestatus->NotificationMaxDelay);
	proto_item_set_generated(it);

	it = proto_tree_add_uint(subtree,
		hf_v2giso2_struct_iso2EVSEStatusType_EVSENotification,
		tvb, 0, 0, evsestatus->EVSENotification);
	proto_item_set_generated(it);

	return;
}

static inline double
v2giso2_physicalvalue_to_double(
	const struct iso2PhysicalValueType *physicalvalue)
{
	double value;
	int32_t exponent;

	value = (double)physicalvalue->Value;
	exponent = physicalvalue->Exponent;
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

static void
dissect_v2giso2_physicalvalue(
	const struct iso2PhysicalValueType *physicalvalue,
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
		hf_v2giso2_struct_iso2PhysicalValueType_Exponent,
		tvb, 0, 0, physicalvalue->Exponent);
	proto_item_set_generated(it);

	it = proto_tree_add_int(subtree,
		hf_v2giso2_struct_iso2PhysicalValueType_Value,
		tvb, 0, 0, physicalvalue->Value);
	proto_item_set_generated(it);

	return;
}

static void
dissect_v2giso2_displayparameters(
	const struct iso2DisplayParametersType *displayparameters,
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

	if (displayparameters->CurrentRange_isUsed) {
		it = proto_tree_add_uint(subtree,
			hf_v2giso2_struct_iso2DisplayParametersType_CurrentRange,
			tvb, 0, 0, displayparameters->CurrentRange);
		proto_item_set_generated(it);
	}

	if (displayparameters->CurrentSOC_isUsed) {
		it = proto_tree_add_int(subtree,
			hf_v2giso2_struct_iso2DisplayParametersType_CurrentSOC,
			tvb, 0, 0, displayparameters->CurrentSOC);
		proto_item_set_generated(it);
	}

	if (displayparameters->TargetSOC_isUsed) {
		it = proto_tree_add_int(subtree,
			hf_v2giso2_struct_iso2DisplayParametersType_TargetSOC,
			tvb, 0, 0, displayparameters->TargetSOC);
		proto_item_set_generated(it);
	}

	if (displayparameters->BulkSOC_isUsed) {
		it = proto_tree_add_int(subtree,
			hf_v2giso2_struct_iso2DisplayParametersType_BulkSOC,
			tvb, 0, 0, displayparameters->BulkSOC);
		proto_item_set_generated(it);
	}

	if (displayparameters->MinimumSOC_isUsed) {
		it = proto_tree_add_int(subtree,
			hf_v2giso2_struct_iso2DisplayParametersType_MinimumSOC,
			tvb, 0, 0, displayparameters->MinimumSOC);
		proto_item_set_generated(it);
	}

	if (displayparameters->ChargingPerformance_isUsed) {
		dissect_v2giso2_physicalvalue(
			&displayparameters->ChargingPerformance,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2PhysicalValueType,
			"ChargingPerformance");
	}

	if (displayparameters->RemainingTimeToTargetSOC_isUsed) {
		it = proto_tree_add_int(subtree,
			hf_v2giso2_struct_iso2DisplayParametersType_RemainingTimeToTargetSOC,
			tvb, 0, 0, displayparameters->RemainingTimeToTargetSOC);
		proto_item_set_generated(it);
	}

	if (displayparameters->RemainingTimeToBulkSOC_isUsed) {
		it = proto_tree_add_int(subtree,
			hf_v2giso2_struct_iso2DisplayParametersType_RemainingTimeToBulkSOC,
			tvb, 0, 0, displayparameters->RemainingTimeToBulkSOC);
		proto_item_set_generated(it);
	}

	if (displayparameters->RemainingTimeToMinimumSOC_isUsed) {
		it = proto_tree_add_int(subtree,
			hf_v2giso2_struct_iso2DisplayParametersType_RemainingTimeToMinimumSOC,
			tvb, 0, 0, displayparameters->RemainingTimeToMinimumSOC);
		proto_item_set_generated(it);
	}

	if (displayparameters->ChargingComplete_isUsed) {
		it = proto_tree_add_int(subtree,
			hf_v2giso2_struct_iso2DisplayParametersType_ChargingComplete,
			tvb, 0, 0, displayparameters->ChargingComplete);
		proto_item_set_generated(it);
	}

	if (displayparameters->BulkChargingComplete_isUsed) {
		it = proto_tree_add_int(subtree,
			hf_v2giso2_struct_iso2DisplayParametersType_BulkChargingComplete,
			tvb, 0, 0, displayparameters->BulkChargingComplete);
		proto_item_set_generated(it);
	}

	if (displayparameters->InletHot_isUsed) {
		it = proto_tree_add_int(subtree,
			hf_v2giso2_struct_iso2DisplayParametersType_InletHot,
			tvb, 0, 0, displayparameters->InletHot);
		proto_item_set_generated(it);
	}

	return;
}

static void
dissect_v2giso2_meterinfo(
	const struct iso2MeterInfoType *meterinfo,
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
		hf_v2giso2_struct_iso2MeterInfoType_MeterID,
		tvb,
		meterinfo->MeterID.characters,
		meterinfo->MeterID.charactersLen,
		sizeof(meterinfo->MeterID.characters));

	if (meterinfo->MeterReadingCharged_isUsed) {
		it = proto_tree_add_uint64(subtree,
			hf_v2giso2_struct_iso2MeterInfoType_MeterReadingCharged,
			tvb, 0, 0, meterinfo->MeterReadingCharged);
		proto_item_set_generated(it);
	}

	if (meterinfo->MeterReadingDischarged_isUsed) {
		it = proto_tree_add_uint64(subtree,
			hf_v2giso2_struct_iso2MeterInfoType_MeterReadingDischarged,
			tvb, 0, 0, meterinfo->MeterReadingDischarged);
		proto_item_set_generated(it);
	}

	if (meterinfo->SigMeterReading_isUsed) {
		exi_add_bytes(subtree,
			hf_v2giso2_struct_iso2MeterInfoType_SigMeterReading,
			tvb,
			meterinfo->SigMeterReading.bytes,
			meterinfo->SigMeterReading.bytesLen,
			sizeof(meterinfo->SigMeterReading.bytes));
	}

	if (meterinfo->MeterStatus_isUsed) {
		it = proto_tree_add_int(subtree,
			hf_v2giso2_struct_iso2MeterInfoType_MeterStatus,
			tvb, 0, 0, meterinfo->MeterStatus);
		proto_item_set_generated(it);
	}

	if (meterinfo->TMeter_isUsed) {
		it = proto_tree_add_int64(subtree,
			hf_v2giso2_struct_iso2MeterInfoType_TMeter,
			tvb, 0, 0, meterinfo->TMeter);
		proto_item_set_generated(it);
	}

	return;
}

static void
dissect_v2giso2_targetposition(
	const struct iso2TargetPositionType *targetposition,
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
		hf_v2giso2_struct_iso2TargetPositionType_TargetOffsetX,
		tvb, 0, 0, targetposition->TargetOffsetX);
	proto_item_set_generated(it);

	it = proto_tree_add_uint(subtree,
		hf_v2giso2_struct_iso2TargetPositionType_TargetOffsetY,
		tvb, 0, 0, targetposition->TargetOffsetY);
	proto_item_set_generated(it);

	return;
}

static void
dissect_v2giso2_parameter(
	const struct iso2ParameterType *parameter,
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
		hf_v2giso2_struct_iso2ParameterType_Name,
		tvb,
		parameter->Name.characters,
		parameter->Name.charactersLen,
		sizeof(parameter->Name.characters));

	if (parameter->boolValue_isUsed) {
		it = proto_tree_add_int(subtree,
			hf_v2giso2_struct_iso2ParameterType_boolValue,
			tvb, 0, 0, parameter->boolValue);
		proto_item_set_generated(it);
	}
	if (parameter->byteValue_isUsed) {
		it = proto_tree_add_int(subtree,
			hf_v2giso2_struct_iso2ParameterType_byteValue,
			tvb, 0, 0, parameter->byteValue);
		proto_item_set_generated(it);
	}
	if (parameter->shortValue_isUsed) {
		it = proto_tree_add_int(subtree,
			hf_v2giso2_struct_iso2ParameterType_shortValue,
			tvb, 0, 0, parameter->shortValue);
		proto_item_set_generated(it);
	}
	if (parameter->intValue_isUsed) {
		it = proto_tree_add_int(subtree,
			hf_v2giso2_struct_iso2ParameterType_intValue,
			tvb, 0, 0, parameter->intValue);
		proto_item_set_generated(it);
	}
	if (parameter->physicalValue_isUsed) {
		dissect_v2giso2_physicalvalue(&parameter->physicalValue,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2PhysicalValueType,
			"physicalValue");
	}
	if (parameter->stringValue_isUsed) {
		exi_add_characters(subtree,
			hf_v2giso2_struct_iso2ParameterType_stringValue,
			tvb,
			parameter->stringValue.characters,
			parameter->stringValue.charactersLen,
			sizeof(parameter->stringValue.characters));
	}

	return;
}

static void
dissect_v2giso2_parameterset(
	const struct iso2ParameterSetType *parameterset,
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
		hf_v2giso2_struct_iso2ParameterSetType_ParameterSetID,
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
			ett_v2giso2_struct_iso2ParameterType, index);
	}

	return;
}

static void
dissect_v2giso2_measurementdatalist(
	const struct iso2MeasurementDataListType *measurementdatalist,
	tvbuff_t *tvb,
	packet_info *pinfo _U_,
	proto_tree *tree,
	gint idx,
	const char *subtree_name)
{
	unsigned int i;
	proto_tree *subtree;
	proto_tree *measurementdata_tree;
	proto_tree *measurementdata_i_tree;
	proto_item *it;

	subtree = proto_tree_add_subtree(tree,
		tvb, 0, 0, idx, NULL, subtree_name);

	measurementdata_tree = proto_tree_add_subtree(subtree,
		tvb, 0, 0, ett_v2giso2_array, NULL, "MeasurementData");
	for (i = 0; i < measurementdatalist->MeasurementData.arrayLen; i++) {
		char index[sizeof("[65536]")];

		snprintf(index, sizeof(index), "[%u]", i);
		measurementdata_i_tree = proto_tree_add_subtree(
			measurementdata_tree, tvb, 0, 0,
			ett_v2giso2_array_i, NULL, index);

		it = proto_tree_add_uint(measurementdata_i_tree,
			hf_v2giso2_struct_iso2MeasurementDataListType_MeasurementData,
			tvb, 0, 0,
			measurementdatalist->MeasurementData.array[i]);
		proto_item_set_generated(it);
	}

	return;
}

static void
dissect_v2giso2_sensormeasurements(
	const struct iso2SensorMeasurementsType *sensormeasurements,
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
		hf_v2giso2_struct_iso2SensorMeasurementsType_SensorID,
		tvb, 0, 0, sensormeasurements->SensorID);
	proto_item_set_generated(it);

	it = proto_tree_add_int(subtree,
		hf_v2giso2_struct_iso2SensorMeasurementsType_EffectiveRadiatedPower,
		tvb, 0, 0, sensormeasurements->EffectiveRadiatedPower);
	proto_item_set_generated(it);

	dissect_v2giso2_measurementdatalist(
		&sensormeasurements->MeasurementDataList,
		tvb, pinfo, subtree,
		ett_v2giso2_struct_iso2MeasurementDataListType,
		"MeasurementDataList");

	return;
}

static void
dissect_v2giso2_sensorpackage(
	const struct iso2SensorPackageType *sensorpackage,
	tvbuff_t *tvb,
	packet_info *pinfo _U_,
	proto_tree *tree,
	gint idx,
	const char *subtree_name)
{
	unsigned int i;
	proto_tree *subtree;
	proto_tree *sensormeasurements_tree;
	proto_item *it;

	subtree = proto_tree_add_subtree(tree,
		tvb, 0, 0, idx, NULL, subtree_name);

	it = proto_tree_add_uint(subtree,
		hf_v2giso2_struct_iso2SensorPackageType_PackageIndex,
		tvb, 0, 0, sensorpackage->PackageIndex);
	proto_item_set_generated(it);

	sensormeasurements_tree = proto_tree_add_subtree(subtree,
		tvb, 0, 0, ett_v2giso2_array, NULL, "SensorPackage");
	for (i = 0; i < sensorpackage->SensorMeasurements.arrayLen; i++) {
		char index[sizeof("[65536]")];

		snprintf(index, sizeof(index), "[%u]", i);
		dissect_v2giso2_sensormeasurements(
			&sensorpackage->SensorMeasurements.array[i],
			tvb, pinfo, sensormeasurements_tree,
			ett_v2giso2_struct_iso2SensorMeasurementsType, index);
	}

	return;
}

static void
dissect_v2giso2_sensorpackagelist(
	const struct iso2SensorPackageListType *sensorpackagelist,
	tvbuff_t *tvb,
	packet_info *pinfo _U_,
	proto_tree *tree,
	gint idx,
	const char *subtree_name)
{
	unsigned int i;
	proto_tree *subtree;
	proto_tree *sensorpackage_tree;

	subtree = proto_tree_add_subtree(tree,
		tvb, 0, 0, idx, NULL, subtree_name);

	sensorpackage_tree = proto_tree_add_subtree(subtree,
		tvb, 0, 0, ett_v2giso2_array, NULL, "SensorPackage");
	for (i = 0; i < sensorpackagelist->SensorPackage.arrayLen; i++) {
		char index[sizeof("[65536]")];

		snprintf(index, sizeof(index), "[%u]", i);
		dissect_v2giso2_sensorpackage(
			&sensorpackagelist->SensorPackage.array[i],
			tvb, pinfo, sensorpackage_tree,
			ett_v2giso2_struct_iso2SensorPackageType, index);
	}

	return;
}

static void
dissect_v2giso2_cartesiancoordinates(
	const struct iso2CartesianCoordinatesType *cartesiancoordinates,
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

	it = proto_tree_add_int(subtree,
		hf_v2giso2_struct_iso2CartesianCoordinatesType_XCoordinate,
		tvb, 0, 0, cartesiancoordinates->XCoordinate);
	proto_item_set_generated(it);

	it = proto_tree_add_int(subtree,
		hf_v2giso2_struct_iso2CartesianCoordinatesType_YCoordinate,
		tvb, 0, 0, cartesiancoordinates->YCoordinate);
	proto_item_set_generated(it);

	it = proto_tree_add_int(subtree,
		hf_v2giso2_struct_iso2CartesianCoordinatesType_ZCoordinate,
		tvb, 0, 0, cartesiancoordinates->ZCoordinate);
	proto_item_set_generated(it);

	return;
}

static void
dissect_v2giso2_sensor(
	const struct iso2SensorType *sensor,
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
		hf_v2giso2_struct_iso2SensorType_SensorID,
		tvb, 0, 0, sensor->SensorID);
	proto_item_set_generated(it);

	dissect_v2giso2_cartesiancoordinates(
		&sensor->SensorPosition,
		tvb, pinfo, subtree,
		ett_v2giso2_struct_iso2CartesianCoordinatesType,
		"SensorPosition");

	dissect_v2giso2_cartesiancoordinates(
		&sensor->SensorOrientation,
		tvb, pinfo, subtree,
		ett_v2giso2_struct_iso2CartesianCoordinatesType,
		"SensorOrientation");

	return;
}

static void
dissect_v2giso2_sensorlist(
	const struct iso2SensorListType *sensorlist,
	tvbuff_t *tvb,
	packet_info *pinfo _U_,
	proto_tree *tree,
	gint idx,
	const char *subtree_name)
{
	unsigned int i;
	proto_tree *subtree;
	proto_tree *sensor_tree;

	subtree = proto_tree_add_subtree(tree,
		tvb, 0, 0, idx, NULL, subtree_name);

	sensor_tree = proto_tree_add_subtree(subtree,
		tvb, 0, 0, ett_v2giso2_array, NULL, "Sensor");
	for (i = 0; i < sensorlist->Sensor.arrayLen; i++) {
		char index[sizeof("[65536]")];

		snprintf(index, sizeof(index), "[%u]", i);
		dissect_v2giso2_sensor(
			&sensorlist->Sensor.array[i],
			tvb, pinfo, sensor_tree,
			ett_v2giso2_struct_iso2SensorType, index);
	}

	return;
}

static void
dissect_v2giso2_sensororderlist(
	const struct iso2SensorOrderListType *sensororderlist,
	tvbuff_t *tvb,
	packet_info *pinfo _U_,
	proto_tree *tree,
	gint idx,
	const char *subtree_name)
{
	unsigned int i;
	proto_tree *subtree;
	proto_tree *sensorposition_tree;
	proto_tree *sensorposition_i_tree;
	proto_item *it;

	subtree = proto_tree_add_subtree(tree,
		tvb, 0, 0, idx, NULL, subtree_name);

	sensorposition_tree = proto_tree_add_subtree(subtree,
		tvb, 0, 0, ett_v2giso2_array, NULL, "Sensor");
	for (i = 0; i < sensororderlist->SensorPosition.arrayLen; i++) {
		char index[sizeof("[65536]")];

		snprintf(index, sizeof(index), "[%u]", i);
		sensorposition_i_tree = proto_tree_add_subtree(
			sensorposition_tree, tvb, 0, 0,
			ett_v2giso2_array_i, NULL, index);

		it = proto_tree_add_uint(sensorposition_i_tree,
			hf_v2giso2_struct_iso2SensorOrderListType_SensorPosition,
			tvb, 0, 0,
			sensororderlist->SensorPosition.array[i]);
		proto_item_set_generated(it);
	}

	return;
}

static void
dissect_v2giso2_magneticvector(
	const struct iso2MagneticVectorType *magneticvector,
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
		hf_v2giso2_struct_iso2MagneticVectorType_GAID,
		tvb,
		magneticvector->GAID.characters,
		magneticvector->GAID.charactersLen,
		sizeof(magneticvector->GAID.characters));

	it = proto_tree_add_uint(subtree,
		hf_v2giso2_struct_iso2MagneticVectorType_Distance,
		tvb, 0, 0, magneticvector->Distance);
	proto_item_set_generated(it);

	dissect_v2giso2_physicalvalue(
		&magneticvector->AngleGAtoVA,
		tvb, pinfo, subtree,
		ett_v2giso2_struct_iso2PhysicalValueType,
		"AngleGAtoVA");

	dissect_v2giso2_physicalvalue(
		&magneticvector->RotationVAtoGA,
		tvb, pinfo, subtree,
		ett_v2giso2_struct_iso2PhysicalValueType,
		"RotationVAtoGA");

	it = proto_tree_add_uint(subtree,
		hf_v2giso2_struct_iso2MagneticVectorType_FODStatus,
		tvb, 0, 0, magneticvector->FODStatus);
	proto_item_set_generated(it);

	return;
}

static void
dissect_v2giso2_magneticvectorlist(
	const struct iso2MagneticVectorListType *magneticvectorlist,
	tvbuff_t *tvb,
	packet_info *pinfo _U_,
	proto_tree *tree,
	gint idx,
	const char *subtree_name)
{
	unsigned int i;
	proto_tree *subtree;
	proto_tree *magneticvector_tree;

	subtree = proto_tree_add_subtree(tree,
		tvb, 0, 0, idx, NULL, subtree_name);

	magneticvector_tree = proto_tree_add_subtree(subtree,
		tvb, 0, 0, ett_v2giso2_array, NULL, "MagneticVector");
	for (i = 0; i < magneticvectorlist->MagneticVector.arrayLen; i++) {
		char index[sizeof("[65536]")];

		snprintf(index, sizeof(index), "[%u]", i);
		dissect_v2giso2_magneticvector(
			&magneticvectorlist->MagneticVector.array[i],
			tvb, pinfo, magneticvector_tree,
			ett_v2giso2_struct_iso2MagneticVectorType, index);
	}

	return;
}

static void
dissect_v2giso2_magneticvectorsetup(
	const struct iso2MagneticVectorSetupType *magneticvectorsetup,
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
		hf_v2giso2_struct_iso2MagneticVectorSetupType_GAID,
		tvb,
		magneticvectorsetup->GAID.characters,
		magneticvectorsetup->GAID.charactersLen,
		sizeof(magneticvectorsetup->GAID.characters));

	it = proto_tree_add_uint(subtree,
		hf_v2giso2_struct_iso2MagneticVectorSetupType_FrequencyChannel,
		tvb, 0, 0, magneticvectorsetup->FrequencyChannel);
	proto_item_set_generated(it);

	return;
}

static void
dissect_v2giso2_magneticvectorsetuplist(
	const struct iso2MagneticVectorSetupListType *magneticvectorsetuplist,
	tvbuff_t *tvb,
	packet_info *pinfo _U_,
	proto_tree *tree,
	gint idx,
	const char *subtree_name)
{
	unsigned int i;
	proto_tree *subtree;
	proto_tree *magneticvectorsetup_tree;

	subtree = proto_tree_add_subtree(tree,
		tvb, 0, 0, idx, NULL, subtree_name);

	magneticvectorsetup_tree = proto_tree_add_subtree(subtree,
		tvb, 0, 0, ett_v2giso2_array, NULL, "MagneticVectorSetup");
	for (i = 0; i < magneticvectorsetuplist->MagneticVectorSetup.arrayLen; i++) {
		char index[sizeof("[65536]")];

		snprintf(index, sizeof(index), "[%u]", i);
		dissect_v2giso2_magneticvectorsetup(
			&magneticvectorsetuplist->MagneticVectorSetup.array[i],
			tvb, pinfo, magneticvectorsetup_tree,
			ett_v2giso2_struct_iso2MagneticVectorSetupType, index);
	}

	return;
}

static void
dissect_v2giso2_evfinepositioningparameters(
	const struct iso2EVFinePositioningParametersType
		*evfinepositioningparameters _U_,
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
dissect_v2giso2_generic_evfinepositioningparameters(
	const struct iso2Generic_EVFinePositioningParametersType
		*generic_evfinepositioningparameters,
	tvbuff_t *tvb,
	packet_info *pinfo _U_,
	proto_tree *tree,
	gint idx,
	const char *subtree_name)
{
	proto_tree *subtree;

	subtree = proto_tree_add_subtree(tree, tvb, 0, 0,
		idx, NULL, subtree_name);

	dissect_v2giso2_parameterset(
		&generic_evfinepositioningparameters->GenericParameters,
		tvb, pinfo, subtree,
		ett_v2giso2_struct_iso2ParameterSetType,
		"GenericParameters");

	return;
}

static void
dissect_v2giso2_lfa_evfinepositioningparameters(
	const struct iso2LFA_EVFinePositioningParametersType
		*lfa_evfinepositioningparameters,
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
		hf_v2giso2_struct_iso2LFA_EVFinePositioningParametersType_NumberOfSignalPackages,
		tvb, 0, 0, lfa_evfinepositioningparameters->NumberOfSignalPackages);
	proto_item_set_generated(it);

	dissect_v2giso2_sensorpackagelist(
		&lfa_evfinepositioningparameters->SensorPackageList,
		tvb, pinfo, subtree,
		ett_v2giso2_struct_iso2SensorPackageListType,
		"SensorPackageList");

	return;
}

static void
dissect_v2giso2_evsefinepositioningparameters(
	const struct iso2EVSEFinePositioningParametersType
		*evsefinepositioningparameters _U_,
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
dissect_v2giso2_generic_evsefinepositioningparameters(
	const struct iso2Generic_EVSEFinePositioningParametersType
		*generic_evsefinepositioningparameters,
	tvbuff_t *tvb,
	packet_info *pinfo _U_,
	proto_tree *tree,
	gint idx,
	const char *subtree_name)
{
	proto_tree *subtree;

	subtree = proto_tree_add_subtree(tree, tvb, 0, 0,
		idx, NULL, subtree_name);

	dissect_v2giso2_parameterset(
		&generic_evsefinepositioningparameters->GenericParameters,
		tvb, pinfo, subtree,
		ett_v2giso2_struct_iso2ParameterSetType,
		"GenericParameters");

	return;
}

static void
dissect_v2giso2_lfa_evsefinepositioningparameters(
	const struct iso2LFA_EVSEFinePositioningParametersType
		*lfa_evsefinepositioningparameters,
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
		hf_v2giso2_struct_iso2LFA_EVSEFinePositioningParametersType_NumberOfSignalPackages,
		tvb, 0, 0, lfa_evsefinepositioningparameters->NumberOfSignalPackages);
	proto_item_set_generated(it);

	dissect_v2giso2_sensorpackagelist(
		&lfa_evsefinepositioningparameters->SensorPackageList,
		tvb, pinfo, subtree,
		ett_v2giso2_struct_iso2SensorPackageListType,
		"SensorPackageList");

	return;
}

static void
dissect_v2giso2_mv_evsefinepositioningparameters(
	const struct iso2MV_EVSEFinePositioningParametersType
		*mv_evsefinepositioningparameters,
	tvbuff_t *tvb,
	packet_info *pinfo _U_,
	proto_tree *tree,
	gint idx,
	const char *subtree_name)
{
	proto_tree *subtree;

	subtree = proto_tree_add_subtree(tree,
		tvb, 0, 0, idx, NULL, subtree_name);

	dissect_v2giso2_magneticvectorlist(
		&mv_evsefinepositioningparameters->MagneticVectorList,
		tvb, pinfo, subtree,
		ett_v2giso2_struct_iso2MagneticVectorListType,
		"MagneticVectorList");

	return;
}

static void
dissect_v2giso2_evfinepositioningsetupparameters(
	const struct iso2EVFinePositioningSetupParametersType
		*evfinepositioningsetupparameters,
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
dissect_v2giso2_lfa_evfinepositioningsetupparameters(
	const struct iso2LFA_EVFinePositioningSetupParametersType
		*lfa_evfinepositioningsetupparameters,
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
		hf_v2giso2_struct_iso2LFA_EVFinePositioningSetupParametersType_NumberOfSensors,
		tvb, 0, 0, lfa_evfinepositioningsetupparameters->NumberOfSensors);
	proto_item_set_generated(it);

	dissect_v2giso2_sensorlist(
		&lfa_evfinepositioningsetupparameters->SensorList,
		tvb, pinfo, subtree,
		ett_v2giso2_struct_iso2SensorListType,
		"SensorList");

	dissect_v2giso2_sensororderlist(
		&lfa_evfinepositioningsetupparameters->SensorOrder,
		tvb, pinfo, subtree,
		ett_v2giso2_struct_iso2SensorOrderListType,
		"SensorList");

	it = proto_tree_add_uint(subtree,
		hf_v2giso2_struct_iso2LFA_EVFinePositioningSetupParametersType_SignalPulseDuration,
		tvb, 0, 0, lfa_evfinepositioningsetupparameters->SignalPulseDuration);
	proto_item_set_generated(it);

	it = proto_tree_add_uint(subtree,
		hf_v2giso2_struct_iso2LFA_EVFinePositioningSetupParametersType_SignalSeparationTime,
		tvb, 0, 0, lfa_evfinepositioningsetupparameters->SignalSeparationTime);
	proto_item_set_generated(it);

	it = proto_tree_add_uint(subtree,
		hf_v2giso2_struct_iso2LFA_EVFinePositioningSetupParametersType_PackageSeparationTime,
		tvb, 0, 0, lfa_evfinepositioningsetupparameters->PackageSeparationTime);
	proto_item_set_generated(it);

	it = proto_tree_add_uint(subtree,
		hf_v2giso2_struct_iso2LFA_EVFinePositioningSetupParametersType_AlignmentOffset,
		tvb, 0, 0, lfa_evfinepositioningsetupparameters->AlignmentOffset);
	proto_item_set_generated(it);

	return;
}

static void
dissect_v2giso2_evsefinepositioningsetupparameters(
	const struct iso2EVSEFinePositioningSetupParametersType
		*evsefinepositioningsetupparameters _U_,
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
dissect_v2giso2_lfa_evsefinepositioningsetupparameters(
	const struct iso2LFA_EVSEFinePositioningSetupParametersType
		*lfa_evsefinepositioningsetupparameters,
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
		hf_v2giso2_struct_iso2LFA_EVSEFinePositioningSetupParametersType_NumberOfSensors,
		tvb, 0, 0, lfa_evsefinepositioningsetupparameters->NumberOfSensors);
	proto_item_set_generated(it);

	dissect_v2giso2_sensorlist(
		&lfa_evsefinepositioningsetupparameters->SensorList,
		tvb, pinfo, subtree,
		ett_v2giso2_struct_iso2SensorListType,
		"SensorList");

	dissect_v2giso2_sensororderlist(
		&lfa_evsefinepositioningsetupparameters->SensorOrder,
		tvb, pinfo, subtree,
		ett_v2giso2_struct_iso2SensorOrderListType,
		"SensorList");

	it = proto_tree_add_uint(subtree,
		hf_v2giso2_struct_iso2LFA_EVSEFinePositioningSetupParametersType_SignalPulseDuration,
		tvb, 0, 0, lfa_evsefinepositioningsetupparameters->SignalPulseDuration);
	proto_item_set_generated(it);

	it = proto_tree_add_uint(subtree,
		hf_v2giso2_struct_iso2LFA_EVSEFinePositioningSetupParametersType_SignalSeparationTime,
		tvb, 0, 0, lfa_evsefinepositioningsetupparameters->SignalSeparationTime);
	proto_item_set_generated(it);

	it = proto_tree_add_uint(subtree,
		hf_v2giso2_struct_iso2LFA_EVSEFinePositioningSetupParametersType_PackageSeparationTime,
		tvb, 0, 0, lfa_evsefinepositioningsetupparameters->PackageSeparationTime);
	proto_item_set_generated(it);

	it = proto_tree_add_uint(subtree,
		hf_v2giso2_struct_iso2LFA_EVSEFinePositioningSetupParametersType_AlignmentOffset,
		tvb, 0, 0, lfa_evsefinepositioningsetupparameters->AlignmentOffset);
	proto_item_set_generated(it);

	it = proto_tree_add_uint(subtree,
		hf_v2giso2_struct_iso2LFA_EVSEFinePositioningSetupParametersType_SignalFrequency,
		tvb, 0, 0, lfa_evsefinepositioningsetupparameters->SignalFrequency);
	proto_item_set_generated(it);

	return;
}

static void
dissect_v2giso2_mv_evsefinepositioningsetupparameters(
	const struct iso2MV_EVSEFinePositioningSetupParametersType
		*mv_evsefinepositioningsetupparameters,
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

	if (mv_evsefinepositioningsetupparameters->FrequencyChannel_isUsed) {
		it = proto_tree_add_uint(subtree,
			hf_v2giso2_struct_iso2MV_EVSEFinePositioningSetupParametersType_FrequencyChannel,
			tvb, 0, 0, mv_evsefinepositioningsetupparameters->FrequencyChannel);
		proto_item_set_generated(it);
	}

	if (mv_evsefinepositioningsetupparameters->MagneticVectorSetupList_isUsed) {
		dissect_v2giso2_magneticvectorsetuplist(
			&mv_evsefinepositioningsetupparameters->MagneticVectorSetupList,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2MagneticVectorSetupListType,
			"MagneticVectorSetupList");
	}

	return;
}

static void
dissect_v2giso2_listofrootcertificateids(
	const struct iso2ListOfRootCertificateIDsType
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
			ett_v2giso2_struct_iso2X509IssuerSerialType,
			index);
	}

	return;
}

static void
dissect_v2giso2_subcertificates(
	const struct iso2SubCertificatesType *subcertificates,
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
				hf_v2giso2_struct_iso2SubCertificatesType_Certificate,
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
	const struct iso2CertificateChainType *certificatechain,
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
			hf_v2giso2_struct_iso2CertificateChainType_Id,
			tvb,
			certificatechain->Id.characters,
			certificatechain->Id.charactersLen,
			sizeof(certificatechain->Id.characters));
	}

	if (v2gber_handle == NULL) {
		exi_add_bytes(subtree,
			hf_v2giso2_struct_iso2CertificateChainType_Certificate,
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
			ett_v2giso2_struct_iso2SubCertificatesType,
			"SubCertificates");
	}

	return;
}

static void
dissect_v2giso2_contractsignatureencryptedprivatekey(
	const struct iso2ContractSignatureEncryptedPrivateKeyType
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
		hf_v2giso2_struct_iso2ContractSignatureEncryptedPrivateKeyType_Id,
		tvb,
		contractsignatureencryptedprivatekey->Id.characters,
		contractsignatureencryptedprivatekey->Id.charactersLen,
		sizeof(contractsignatureencryptedprivatekey->Id.characters));


	exi_add_bytes(subtree,
		hf_v2giso2_struct_iso2ContractSignatureEncryptedPrivateKeyType_CONTENT,
		tvb,
		contractsignatureencryptedprivatekey->CONTENT.bytes,
		contractsignatureencryptedprivatekey->CONTENT.bytesLen,
		sizeof(contractsignatureencryptedprivatekey->CONTENT.bytes));

	return;
}

static void
dissect_v2giso2_diffiehellmanpublickey(
	const struct iso2DiffieHellmanPublickeyType *diffiehellmanpublickey,
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
		hf_v2giso2_struct_iso2DiffieHellmanPublickeyType_Id,
		tvb,
		diffiehellmanpublickey->Id.characters,
		diffiehellmanpublickey->Id.charactersLen,
		sizeof(diffiehellmanpublickey->Id.characters));

	exi_add_bytes(subtree,
		hf_v2giso2_struct_iso2DiffieHellmanPublickeyType_CONTENT,
		tvb,
		diffiehellmanpublickey->CONTENT.bytes,
		diffiehellmanpublickey->CONTENT.bytesLen,
		sizeof(diffiehellmanpublickey->CONTENT.bytes));

	return;
}

static void
dissect_v2giso2_emaid(
	const struct iso2EMAIDType *emaid,
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
		hf_v2giso2_struct_iso2EMAIDType_Id,
		tvb,
		emaid->Id.characters,
		emaid->Id.charactersLen,
		sizeof(emaid->Id.characters));

	exi_add_characters(subtree,
		hf_v2giso2_struct_iso2EMAIDType_CONTENT,
		tvb,
		emaid->CONTENT.characters,
		emaid->CONTENT.charactersLen,
		sizeof(emaid->CONTENT.characters));

	return;
}

static void
dissect_v2giso2_relativetimeinterval(
	const struct iso2RelativeTimeIntervalType *relativetimeinterval,
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
		hf_v2giso2_struct_iso2RelativeTimeIntervalType_start,
		tvb, 0, 0, relativetimeinterval->start);
	proto_item_set_generated(it);

	if (relativetimeinterval->duration_isUsed) {
		it = proto_tree_add_uint(subtree,
			hf_v2giso2_struct_iso2RelativeTimeIntervalType_duration,
			tvb, 0, 0, relativetimeinterval->duration);
		proto_item_set_generated(it);
	}

	return;
}

static void
dissect_v2giso2_pmaxscheduleentry(
	const struct iso2PMaxScheduleEntryType *pmaxscheduleentry,
	tvbuff_t *tvb,
	packet_info *pinfo _U_,
	proto_tree *tree,
	gint idx,
	const char *subtree_name)
{
	unsigned int i;
	proto_tree *subtree;
	proto_tree *pmax_tree;

	subtree = proto_tree_add_subtree(tree, tvb, 0, 0,
		idx, NULL, subtree_name);

	dissect_v2giso2_relativetimeinterval(
		&pmaxscheduleentry->RelativeTimeInterval,
		tvb, pinfo, subtree,
		ett_v2giso2_struct_iso2RelativeTimeIntervalType,
		"RelativeTimeInterval");

	pmax_tree = proto_tree_add_subtree(subtree,
		tvb, 0, 0, ett_v2giso2_array, NULL, "PMax");
	for (i = 0; i < pmaxscheduleentry->PMax.arrayLen; i++) {
		char index[sizeof("[65536]")];

		snprintf(index, sizeof(index), "[%u]", i);
		dissect_v2giso2_physicalvalue(
			&pmaxscheduleentry->PMax.array[i],
			tvb, pinfo, pmax_tree,
			ett_v2giso2_struct_iso2PhysicalValueType,
			index);
	}

	return;
}

static void
dissect_v2giso2_chargingprofile(
	const struct iso2ChargingProfileType *chargingprofile,
	tvbuff_t *tvb,
	packet_info *pinfo _U_,
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
		dissect_v2giso2_pmaxscheduleentry(
			&chargingprofile->ProfileEntry.array[i],
			tvb, pinfo, profileentry_tree,
			ett_v2giso2_struct_iso2PMaxScheduleEntryType,
			index);
	}

	return;
}

static void
dissect_v2giso2_evenergytransferparameter(
	const struct iso2EVEnergyTransferParameterType
		*evenergytransferparameter,
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

static void
dissect_v2giso2_ac_evchargeparameter(
	const struct iso2AC_EVChargeParameterType *ac_evchargeparameter,
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

static void
dissect_v2giso2_ac_evbidirectionalparameter(
	const struct iso2AC_EVBidirectionalParameterType
		*ac_evbidirectionalparameter,
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

static void
dissect_v2giso2_dc_evchargeparameter(
	const struct iso2DC_EVChargeParameterType *dc_evchargeparameter,
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

static void
dissect_v2giso2_dc_evbidirectionalparameter(
	const struct iso2DC_EVBidirectionalParameterType
		*dc_evbidirectionalparameter,
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

static void
dissect_v2giso2_wpt_evchargeparameter(
	const struct iso2WPT_EVChargeParameterType *wpt_evchargeparameter,
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

static void
dissect_v2giso2_minimumpmaxrequest(
	const struct iso2MinimumPMaxRequestType *minimumpmaxrequest,
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

static void
dissect_v2giso2_saschedulelist(
	const struct iso2SAScheduleListType *saschedulelist, 
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

static void
dissect_v2giso2_evseenergytransferparameter(
	const struct iso2EVSEEnergyTransferParameterType
		*evseenergytransferparameter,
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

static void
dissect_v2giso2_ac_evsechargeparameter(
	const struct iso2AC_EVSEChargeParameterType *ac_evsechargeparameter,
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

static void
dissect_v2giso2_ac_evsebidirectionalparameter(
	const struct iso2AC_EVSEBidirectionalParameterType
		*ac_evsebidirectionalparameter,
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

static void
dissect_v2giso2_dc_evsechargeparameter(
	const struct iso2DC_EVSEChargeParameterType *dc_evsechargeparameter,
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

static void
dissect_v2giso2_dc_evsebidirectionalparameter(
	const struct iso2DC_EVSEBidirectionalParameterType
		*dc_evsebidirectionalparameter,
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

static void
dissect_v2giso2_wpt_evsechargeparameter(
	const struct iso2WPT_EVSEChargeParameterType *wpt_evsechargeparameter,
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

static void
dissect_v2giso2_selectedservice(
	const struct iso2SelectedServiceType *selectedservice,
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

static void
dissect_v2giso2_selectedservicelist(
	const struct iso2SelectedServiceListType *selectedservicelist,
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

static void
dissect_v2giso2_serviceparameterlist(
	const struct iso2ServiceParameterListType *serviceparameterlist,
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

static void
dissect_v2giso2_serviceidlist(
	const struct iso2ServiceIDListType *serviceidlist,
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

static void
dissect_v2giso2_servicelist(
	const struct iso2ServiceListType *servicelist,
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

static void
dissect_v2giso2_paymentoptionlist(
	const struct iso2PaymentOptionListType *paymentoptionlist,
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

static void
dissect_v2giso2_disconnectchargingdevicereq(
	const struct iso2DisconnectChargingDeviceReqType
		*disconnectchargingdevicereq,
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
		hf_v2giso2_struct_iso2DisconnectChargingDeviceReqType_EVElectricalChargingDeviceStatus,
		tvb, 0, 0, disconnectchargingdevicereq->EVElectricalChargingDeviceStatus);
	proto_item_set_generated(it);

	it = proto_tree_add_uint(subtree,
		hf_v2giso2_struct_iso2DisconnectChargingDeviceReqType_EVMechanicalChargingDeviceStatus,
		tvb, 0, 0, disconnectchargingdevicereq->EVMechanicalChargingDeviceStatus);
	proto_item_set_generated(it);

	return;
}

static void
dissect_v2giso2_disconnectchargingdeviceres(
	const struct iso2DisconnectChargingDeviceResType
		*disconnectchargingdeviceres,
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
		hf_v2giso2_struct_iso2DisconnectChargingDeviceResType_ResponseCode,
		tvb, 0, 0, disconnectchargingdeviceres->ResponseCode);
	proto_item_set_generated(it);

	if (disconnectchargingdeviceres->EVSEStatus_isUsed) {
		dissect_v2giso2_evsestatus(
			&disconnectchargingdeviceres->EVSEStatus,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2EVSEStatusType,
			"EVSEStatus");
	}

	it = proto_tree_add_uint(subtree,
		hf_v2giso2_struct_iso2DisconnectChargingDeviceResType_EVSEProcessing,
		tvb, 0, 0, disconnectchargingdeviceres->EVSEProcessing);
	proto_item_set_generated(it);

	it = proto_tree_add_uint(subtree,
		hf_v2giso2_struct_iso2DisconnectChargingDeviceResType_EVSEElectricalChargingDeviceStatus,
		tvb, 0, 0, disconnectchargingdeviceres->EVSEElectricalChargingDeviceStatus);
	proto_item_set_generated(it);

	it = proto_tree_add_uint(subtree,
		hf_v2giso2_struct_iso2DisconnectChargingDeviceResType_EVSEMechanicalChargingDeviceStatus,
		tvb, 0, 0, disconnectchargingdeviceres->EVSEMechanicalChargingDeviceStatus);
	proto_item_set_generated(it);

	return;
}

static void
dissect_v2giso2_connectchargingdevicereq(
	const struct iso2ConnectChargingDeviceReqType
		*connectchargingdevicereq,
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
		hf_v2giso2_struct_iso2ConnectChargingDeviceReqType_EVElectricalChargingDeviceStatus,
		tvb, 0, 0, connectchargingdevicereq->EVElectricalChargingDeviceStatus);
	proto_item_set_generated(it);

	it = proto_tree_add_uint(subtree,
		hf_v2giso2_struct_iso2ConnectChargingDeviceReqType_EVMechanicalChargingDeviceStatus,
		tvb, 0, 0, connectchargingdevicereq->EVMechanicalChargingDeviceStatus);
	proto_item_set_generated(it);

	return;
}

static void
dissect_v2giso2_connectchargingdeviceres(
	const struct iso2ConnectChargingDeviceResType
		*connectchargingdeviceres,
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
		hf_v2giso2_struct_iso2ConnectChargingDeviceResType_ResponseCode,
		tvb, 0, 0, connectchargingdeviceres->ResponseCode);
	proto_item_set_generated(it);

	if (connectchargingdeviceres->EVSEStatus_isUsed) {
		dissect_v2giso2_evsestatus(
			&connectchargingdeviceres->EVSEStatus,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2EVSEStatusType,
			"EVSEStatus");
	}

	it = proto_tree_add_uint(subtree,
		hf_v2giso2_struct_iso2ConnectChargingDeviceResType_EVSEProcessing,
		tvb, 0, 0, connectchargingdeviceres->EVSEProcessing);
	proto_item_set_generated(it);

	it = proto_tree_add_uint(subtree,
		hf_v2giso2_struct_iso2ConnectChargingDeviceResType_EVSEElectricalChargingDeviceStatus,
		tvb, 0, 0, connectchargingdeviceres->EVSEElectricalChargingDeviceStatus);
	proto_item_set_generated(it);

	it = proto_tree_add_uint(subtree,
		hf_v2giso2_struct_iso2ConnectChargingDeviceResType_EVSEMechanicalChargingDeviceStatus,
		tvb, 0, 0, connectchargingdeviceres->EVSEMechanicalChargingDeviceStatus);
	proto_item_set_generated(it);

	return;
}

static void
dissect_v2giso2_systemstatusreq(
	const struct iso2SystemStatusReqType *systemstatusreq,
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
		hf_v2giso2_struct_iso2SystemStatusReqType_OperationMode,
		tvb, 0, 0, systemstatusreq->OperationMode);
	proto_item_set_generated(it);

	it = proto_tree_add_uint(subtree,
		hf_v2giso2_struct_iso2SystemStatusReqType_EVMechanicalChargingDeviceStatus,
		tvb, 0, 0, systemstatusreq->EVMechanicalChargingDeviceStatus);
	proto_item_set_generated(it);

	return;
}

static void
dissect_v2giso2_systemstatusres(
	const struct iso2SystemStatusResType *systemstatusres,
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
		hf_v2giso2_struct_iso2SystemStatusResType_ResponseCode,
		tvb, 0, 0, systemstatusres->ResponseCode);
	proto_item_set_generated(it);

	if (systemstatusres->EVSEStatus_isUsed) {
		dissect_v2giso2_evsestatus(
			&systemstatusres->EVSEStatus,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2EVSEStatusType,
			"EVSEStatus");
	}

	it = proto_tree_add_uint(subtree,
		hf_v2giso2_struct_iso2SystemStatusResType_OperationMode,
		tvb, 0, 0, systemstatusres->OperationMode);
	proto_item_set_generated(it);

	it = proto_tree_add_uint(subtree,
		hf_v2giso2_struct_iso2SystemStatusResType_EVSEMechanicalChargingDeviceStatus,
		tvb, 0, 0, systemstatusres->EVSEMechanicalChargingDeviceStatus);
	proto_item_set_generated(it);

	return;
}

static void
dissect_v2giso2_dc_bidirectionalcontrolreq(
	const struct iso2DC_BidirectionalControlReqType
		*dc_bidirectionalcontrolreq,
	tvbuff_t *tvb,
	packet_info *pinfo _U_,
	proto_tree *tree,
	gint idx,
	const char *subtree_name)
{
	proto_tree *subtree;
	proto_item *it;
	double value;

	subtree = proto_tree_add_subtree(tree,
		tvb, 0, 0, idx, NULL, subtree_name);

	dissect_v2giso2_physicalvalue(
		&dc_bidirectionalcontrolreq->EVTargetEnergyRequest,
		tvb, pinfo, subtree,
		ett_v2giso2_struct_iso2PhysicalValueType,
		"EVTargetEnergyRequest");

	if (dc_bidirectionalcontrolreq->EVMaximumEnergyRequest_isUsed) {
		dissect_v2giso2_physicalvalue(
			&dc_bidirectionalcontrolreq->EVMaximumEnergyRequest,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2PhysicalValueType,
			"EVMaximumEnergyRequest");
	}

	if (dc_bidirectionalcontrolreq->EVMinimumEnergyRequest_isUsed) {
		dissect_v2giso2_physicalvalue(
			&dc_bidirectionalcontrolreq->EVMinimumEnergyRequest,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2PhysicalValueType,
			"EVMinimumEnergyRequest");
	}

	if (dc_bidirectionalcontrolreq->DisplayParameters_isUsed) {
		dissect_v2giso2_displayparameters(
			&dc_bidirectionalcontrolreq->DisplayParameters,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2DisplayParametersType,
			"DisplayParameters");
	}

	dissect_v2giso2_physicalvalue(
		&dc_bidirectionalcontrolreq->EVTargetCurrent,
		tvb, pinfo, subtree,
		ett_v2giso2_struct_iso2PhysicalValueType,
		"EVTargetCurrent");
	value = v2giso2_physicalvalue_to_double(
		&dc_bidirectionalcontrolreq->EVTargetCurrent);
	it = proto_tree_add_double(subtree,
		hf_v2giso2_target_current,
		tvb, 0, 0, value);
	proto_item_set_generated(it);

	dissect_v2giso2_physicalvalue(
		&dc_bidirectionalcontrolreq->EVTargetVoltage,
		tvb, pinfo, subtree,
		ett_v2giso2_struct_iso2PhysicalValueType,
		"EVTargetVoltage");
	value = v2giso2_physicalvalue_to_double(
		&dc_bidirectionalcontrolreq->EVTargetVoltage);
	it = proto_tree_add_double(subtree,
		hf_v2giso2_target_voltage,
		tvb, 0, 0, value);
	proto_item_set_generated(it);

	dissect_v2giso2_physicalvalue(
		&dc_bidirectionalcontrolreq->EVMaximumVoltage,
		tvb, pinfo, subtree,
		ett_v2giso2_struct_iso2PhysicalValueType,
		"EVMaximumVoltage");

	dissect_v2giso2_physicalvalue(
		&dc_bidirectionalcontrolreq->EVMinimumVoltage,
		tvb, pinfo, subtree,
		ett_v2giso2_struct_iso2PhysicalValueType,
		"EVMinimumVoltage");

	dissect_v2giso2_physicalvalue(
		&dc_bidirectionalcontrolreq->EVMaximumChargeCurrent,
		tvb, pinfo, subtree,
		ett_v2giso2_struct_iso2PhysicalValueType,
		"EVMaximumChargeCurrent");

	if (dc_bidirectionalcontrolreq->EVMaximumDischargeCurrent_isUsed) {
		dissect_v2giso2_physicalvalue(
			&dc_bidirectionalcontrolreq->EVMaximumDischargeCurrent,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2PhysicalValueType,
			"EVMaximumDischargeCurrent");
	}

	if (dc_bidirectionalcontrolreq->EVMaximumChargePower_isUsed) {
		dissect_v2giso2_physicalvalue(
			&dc_bidirectionalcontrolreq->EVMaximumChargePower,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2PhysicalValueType,
			"EVMaximumChargePower");
	}

	if (dc_bidirectionalcontrolreq->EVMaximumDischargePower_isUsed) {
		dissect_v2giso2_physicalvalue(
			&dc_bidirectionalcontrolreq->EVMaximumDischargePower,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2PhysicalValueType,
			"EVMaximumDischargePower");
	}

	return;
}

static void
dissect_v2giso2_dc_bidirectionalcontrolres(
	const struct iso2DC_BidirectionalControlResType
		*dc_bidirectionalcontrolres,
	tvbuff_t *tvb,
	packet_info *pinfo _U_,
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
		hf_v2giso2_struct_iso2DC_BidirectionalControlResType_ResponseCode,
		tvb, 0, 0, dc_bidirectionalcontrolres->ResponseCode);
	proto_item_set_generated(it);

	if (dc_bidirectionalcontrolres->EVSEStatus_isUsed) {
		dissect_v2giso2_evsestatus(
			&dc_bidirectionalcontrolres->EVSEStatus,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2EVSEStatusType,
			"EVSEStatus");
	}

	dissect_v2giso2_physicalvalue(
		&dc_bidirectionalcontrolres->EVSEPresentCurrent,
		tvb, pinfo, subtree,
		ett_v2giso2_struct_iso2PhysicalValueType,
		"EVSEPresentCurrent");
	value = v2giso2_physicalvalue_to_double(
		&dc_bidirectionalcontrolres->EVSEPresentCurrent);
	it = proto_tree_add_double(subtree,
		hf_v2giso2_present_current,
		tvb, 0, 0, value);
	proto_item_set_generated(it);

	dissect_v2giso2_physicalvalue(
		&dc_bidirectionalcontrolres->EVSEPresentVoltage,
		tvb, pinfo, subtree,
		ett_v2giso2_struct_iso2PhysicalValueType,
		"EVSEPresentVoltage");
	value = v2giso2_physicalvalue_to_double(
		&dc_bidirectionalcontrolres->EVSEPresentVoltage);
	it = proto_tree_add_double(subtree,
		hf_v2giso2_present_voltage,
		tvb, 0, 0, value);
	proto_item_set_generated(it);

	it = proto_tree_add_int(subtree,
		hf_v2giso2_struct_iso2DC_BidirectionalControlResType_EVSEPowerLimitAchieved,
		tvb, 0, 0, dc_bidirectionalcontrolres->EVSEPowerLimitAchieved);
	proto_item_set_generated(it);

	it = proto_tree_add_int(subtree,
		hf_v2giso2_struct_iso2DC_BidirectionalControlResType_EVSECurrentLimitAchieved,
		tvb, 0, 0, dc_bidirectionalcontrolres->EVSECurrentLimitAchieved);
	proto_item_set_generated(it);

	it = proto_tree_add_int(subtree,
		hf_v2giso2_struct_iso2DC_BidirectionalControlResType_EVSEVoltageLimitAchieved,
		tvb, 0, 0, dc_bidirectionalcontrolres->EVSEVoltageLimitAchieved);
	proto_item_set_generated(it);


	if (dc_bidirectionalcontrolres->EVSEMaximumChargePower_isUsed) {
		dissect_v2giso2_physicalvalue(
			&dc_bidirectionalcontrolres->EVSEMaximumChargePower,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2PhysicalValueType,
			"EVSEMaximumChargePower");
	}
	if (dc_bidirectionalcontrolres->EVSEMaximumDischargePower_isUsed) {
		dissect_v2giso2_physicalvalue(
			&dc_bidirectionalcontrolres->EVSEMaximumDischargePower,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2PhysicalValueType,
			"EVSEMaximumDischargePower");
	}
	if (dc_bidirectionalcontrolres->EVSEMaximumChargeCurrent_isUsed) {
		dissect_v2giso2_physicalvalue(
			&dc_bidirectionalcontrolres->EVSEMaximumChargeCurrent,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2PhysicalValueType,
			"EVSEMaximumChargeCurrent");
	}
	if (dc_bidirectionalcontrolres->EVSEMaximumDischargeCurrent_isUsed) {
		dissect_v2giso2_physicalvalue(
			&dc_bidirectionalcontrolres->EVSEMaximumDischargeCurrent,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2PhysicalValueType,
			"EVSEMaximumDischargeCurrent");
	}
	if (dc_bidirectionalcontrolres->EVSEMaximumVoltage_isUsed) {
		dissect_v2giso2_physicalvalue(
			&dc_bidirectionalcontrolres->EVSEMaximumVoltage,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2PhysicalValueType,
			"EVSEMaximumVoltage");
	}
	if (dc_bidirectionalcontrolres->EVSEMinimumVoltage_isUsed) {
		dissect_v2giso2_physicalvalue(
			&dc_bidirectionalcontrolres->EVSEMinimumVoltage,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2PhysicalValueType,
			"EVSEMinimumVoltage");
	}

	exi_add_characters(subtree,
		hf_v2giso2_struct_iso2DC_BidirectionalControlResType_EVSEID,
		tvb,
		dc_bidirectionalcontrolres->EVSEID.characters,
		dc_bidirectionalcontrolres->EVSEID.charactersLen,
		sizeof(dc_bidirectionalcontrolres->EVSEID.characters));

	if (dc_bidirectionalcontrolres->MeterInfo_isUsed) {
		dissect_v2giso2_meterinfo(
			&dc_bidirectionalcontrolres->MeterInfo,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2MeterInfoType,
			"MeterInfo");
	}

	if (dc_bidirectionalcontrolres->ReceiptRequired_isUsed) {
		it = proto_tree_add_int(subtree,
			hf_v2giso2_struct_iso2DC_BidirectionalControlResType_ReceiptRequired,
			tvb, 0, 0, dc_bidirectionalcontrolres->ReceiptRequired);
		proto_item_set_generated(it);
	}

	return;
}

static void
dissect_v2giso2_ac_bidirectionalcontrolreq(
	const struct iso2AC_BidirectionalControlReqType
		*ac_bidirectionalcontrolreq,
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

	dissect_v2giso2_physicalvalue(
		&ac_bidirectionalcontrolreq->EVTargetEnergyRequest,
		tvb, pinfo, subtree,
		ett_v2giso2_struct_iso2PhysicalValueType,
		"EVTargetEnergyRequest");

	if (ac_bidirectionalcontrolreq->EVMaximumEnergyRequest_isUsed) {
		dissect_v2giso2_physicalvalue(
			&ac_bidirectionalcontrolreq->EVMaximumEnergyRequest,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2PhysicalValueType,
			"EVMaximumEnergyRequest");
	}

	if (ac_bidirectionalcontrolreq->EVMinimumEnergyRequest_isUsed) {
		dissect_v2giso2_physicalvalue(
			&ac_bidirectionalcontrolreq->EVMinimumEnergyRequest,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2PhysicalValueType,
			"EVMinimumEnergyRequest");
	}

	if (ac_bidirectionalcontrolreq->DisplayParameters_isUsed) {
		dissect_v2giso2_displayparameters(
			&ac_bidirectionalcontrolreq->DisplayParameters,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2DisplayParametersType,
			"DisplayParameters");
	}

	if (ac_bidirectionalcontrolreq->EVOperation_isUsed) {
		it = proto_tree_add_uint(subtree,
			hf_v2giso2_struct_iso2AC_BidirectionalControlReqType_EVOperation,
			tvb, 0, 0, ac_bidirectionalcontrolreq->EVOperation);
		proto_item_set_generated(it);
	}

	dissect_v2giso2_physicalvalue(
		&ac_bidirectionalcontrolreq->EVMaximumChargePower,
		tvb, pinfo, subtree,
		ett_v2giso2_struct_iso2PhysicalValueType,
		"EVMaximumChargePower");

	if (ac_bidirectionalcontrolreq->EVMaximumDischargePower_isUsed) {
		dissect_v2giso2_physicalvalue(
			&ac_bidirectionalcontrolreq->EVMaximumDischargePower,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2PhysicalValueType,
			"EVMaximumDischargePower");
	}

	dissect_v2giso2_physicalvalue(
		&ac_bidirectionalcontrolreq->EVMaximumChargeCurrent,
		tvb, pinfo, subtree,
		ett_v2giso2_struct_iso2PhysicalValueType,
		"EVMaximumChargeCurrent");

	if (ac_bidirectionalcontrolreq->EVMaximumDischargeCurrent_isUsed) {
		dissect_v2giso2_physicalvalue(
			&ac_bidirectionalcontrolreq->EVMaximumDischargeCurrent,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2PhysicalValueType,
			"EVMaximumDischargeCurrent");
	}

	dissect_v2giso2_physicalvalue(
		&ac_bidirectionalcontrolreq->EVMinimumChargeCurrent,
		tvb, pinfo, subtree,
		ett_v2giso2_struct_iso2PhysicalValueType,
		"EVMinimumChargeCurrent");

	if (ac_bidirectionalcontrolreq->EVMinimumDischargeCurrent_isUsed) {
		dissect_v2giso2_physicalvalue(
			&ac_bidirectionalcontrolreq->EVMinimumDischargeCurrent,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2PhysicalValueType,
			"EVMinimumDischargeCurrent");
	}

	dissect_v2giso2_physicalvalue(
		&ac_bidirectionalcontrolreq->EVPresentActivePower,
		tvb, pinfo, subtree,
		ett_v2giso2_struct_iso2PhysicalValueType,
		"EVPresentActivePower");

	dissect_v2giso2_physicalvalue(
		&ac_bidirectionalcontrolreq->EVPresentReactivePower,
		tvb, pinfo, subtree,
		ett_v2giso2_struct_iso2PhysicalValueType,
		"EVPresentReactivePower");

	return;
}

static void
dissect_v2giso2_ac_bidirectionalcontrolres(
	const struct iso2AC_BidirectionalControlResType
		*ac_bidirectionalcontrolres,
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
		hf_v2giso2_struct_iso2AC_BidirectionalControlResType_ResponseCode,
		tvb, 0, 0, ac_bidirectionalcontrolres->ResponseCode);
	proto_item_set_generated(it);

	if (ac_bidirectionalcontrolres->EVSEStatus_isUsed) {
		dissect_v2giso2_evsestatus(
			&ac_bidirectionalcontrolres->EVSEStatus,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2EVSEStatusType,
			"EVSEStatus");
	}

	it = proto_tree_add_uint(subtree,
		hf_v2giso2_struct_iso2AC_BidirectionalControlResType_EVSEProcessing,
		tvb, 0, 0, ac_bidirectionalcontrolres->EVSEProcessing);
	proto_item_set_generated(it);

	dissect_v2giso2_physicalvalue(
		&ac_bidirectionalcontrolres->EVSETargetPower,
		tvb, pinfo, subtree,
		ett_v2giso2_struct_iso2PhysicalValueType,
		"EVSETargetPower");

	dissect_v2giso2_physicalvalue(
		&ac_bidirectionalcontrolres->EVSETargetReactivePower,
		tvb, pinfo, subtree,
		ett_v2giso2_struct_iso2PhysicalValueType,
		"EVSETargetReactivePower");

	exi_add_characters(subtree,
		hf_v2giso2_struct_iso2AC_BidirectionalControlResType_EVSEID,
		tvb,
		ac_bidirectionalcontrolres->EVSEID.characters,
		ac_bidirectionalcontrolres->EVSEID.charactersLen,
		sizeof(ac_bidirectionalcontrolres->EVSEID.characters));

	if (ac_bidirectionalcontrolres->SAScheduleTupleID_isUsed) {
		it = proto_tree_add_uint(subtree,
			hf_v2giso2_struct_iso2AC_BidirectionalControlResType_SAScheduleTupleID,
			tvb, 0, 0, ac_bidirectionalcontrolres->SAScheduleTupleID);
		proto_item_set_generated(it);
	}

	if (ac_bidirectionalcontrolres->MeterInfo_isUsed) {
		dissect_v2giso2_meterinfo(
			&ac_bidirectionalcontrolres->MeterInfo,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2MeterInfoType,
			"MeterInfo");
	}

	if (ac_bidirectionalcontrolres->ReceiptRequired_isUsed) {
		it = proto_tree_add_int(subtree,
			hf_v2giso2_struct_iso2AC_BidirectionalControlResType_ReceiptRequired,
			tvb, 0, 0, ac_bidirectionalcontrolres->ReceiptRequired);
		proto_item_set_generated(it);
	}

	return;
}

static void
dissect_v2giso2_vehiclecheckoutreq(
	const struct iso2VehicleCheckOutReqType *vehiclecheckoutreq,
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
		hf_v2giso2_struct_iso2VehicleCheckOutReqType_EVCheckOutStatus,
		tvb, 0, 0, vehiclecheckoutreq->EVCheckOutStatus);
	proto_item_set_generated(it);

	it = proto_tree_add_uint64(subtree,
		hf_v2giso2_struct_iso2VehicleCheckOutReqType_CheckOutTime,
		tvb, 0, 0, vehiclecheckoutreq->CheckOutTime);
	proto_item_set_generated(it);

	return;
}

static void
dissect_v2giso2_vehiclecheckoutres(
	const struct iso2VehicleCheckOutResType *vehiclecheckoutres,
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
		hf_v2giso2_struct_iso2VehicleCheckOutResType_ResponseCode,
		tvb, 0, 0, vehiclecheckoutres->ResponseCode);
	proto_item_set_generated(it);

	if (vehiclecheckoutres->EVSEStatus_isUsed) {
		dissect_v2giso2_evsestatus(
			&vehiclecheckoutres->EVSEStatus,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2EVSEStatusType,
			"EVSEStatus");
	}

	it = proto_tree_add_uint(subtree,
		hf_v2giso2_struct_iso2VehicleCheckOutResType_EVSECheckOutStatus,
		tvb, 0, 0, vehiclecheckoutres->EVSECheckOutStatus);
	proto_item_set_generated(it);

	return;
}

static void
dissect_v2giso2_vehiclecheckinreq(
	const struct iso2VehicleCheckInReqType *vehiclecheckinreq,
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
		hf_v2giso2_struct_iso2VehicleCheckInReqType_EVCheckInStatus,
		tvb, 0, 0, vehiclecheckinreq->EVCheckInStatus);
	proto_item_set_generated(it);

	if (vehiclecheckinreq->ParkingMethod_isUsed) {
		it = proto_tree_add_uint(subtree,
			hf_v2giso2_struct_iso2VehicleCheckInReqType_ParkingMethod,
			tvb, 0, 0, vehiclecheckinreq->ParkingMethod);
		proto_item_set_generated(it);
	}

	return;
}

static void
dissect_v2giso2_vehiclecheckinres(
	const struct iso2VehicleCheckInResType *vehiclecheckinres,
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
		hf_v2giso2_struct_iso2VehicleCheckInResType_ResponseCode,
		tvb, 0, 0, vehiclecheckinres->ResponseCode);
	proto_item_set_generated(it);

	if (vehiclecheckinres->EVSEStatus_isUsed) {
		dissect_v2giso2_evsestatus(
			&vehiclecheckinres->EVSEStatus,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2EVSEStatusType,
			"EVSEStatus");
	}

	it = proto_tree_add_uint(subtree,
		hf_v2giso2_struct_iso2VehicleCheckInResType_VehicleSpace,
		tvb, 0, 0, vehiclecheckinres->VehicleSpace);
	proto_item_set_generated(it);

	if (vehiclecheckinres->TargetOffset_isUsed) {
		dissect_v2giso2_targetposition(
			&vehiclecheckinres->TargetOffset,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2TargetPositionType,
			"TargetOffset");
	}

	return;
}

static void
dissect_v2giso2_powerdemandreq(
	const struct iso2PowerDemandReqType *powerdemandreq,
	tvbuff_t *tvb,
	packet_info *pinfo _U_,
	proto_tree *tree,
	gint idx,
	const char *subtree_name)
{
	proto_tree *subtree;

	subtree = proto_tree_add_subtree(tree,
		tvb, 0, 0, idx, NULL, subtree_name);

	dissect_v2giso2_physicalvalue(
		&powerdemandreq->EVTargetEnergyRequest,
		tvb, pinfo, subtree,
		ett_v2giso2_struct_iso2PhysicalValueType,
		"EVTargetEnergyRequest");

	if (powerdemandreq->EVMaximumEnergyRequest_isUsed) {
		dissect_v2giso2_physicalvalue(
			&powerdemandreq->EVMaximumEnergyRequest,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2PhysicalValueType,
			"EVMaximumEnergyRequest");
	}

	if (powerdemandreq->EVMinimumEnergyRequest_isUsed) {
		dissect_v2giso2_physicalvalue(
			&powerdemandreq->EVMinimumEnergyRequest,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2PhysicalValueType,
			"EVMinimumEnergyRequest");
	}

	if (powerdemandreq->DisplayParameters_isUsed) {
		dissect_v2giso2_displayparameters(
			&powerdemandreq->DisplayParameters,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2DisplayParametersType,
			"DisplayParameters");
	}

	dissect_v2giso2_physicalvalue(
		&powerdemandreq->EVTargetPower,
		tvb, pinfo, subtree,
		ett_v2giso2_struct_iso2PhysicalValueType,
		"EVTargetPower");

	dissect_v2giso2_physicalvalue(
		&powerdemandreq->EVInputPower,
		tvb, pinfo, subtree,
		ett_v2giso2_struct_iso2PhysicalValueType,
		"EVInputPower");

	if (powerdemandreq->PowerDemandParameters_isUsed) {
		dissect_v2giso2_parameterset(
			&powerdemandreq->PowerDemandParameters,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2ParameterSetType,
			"PowerDemandParameters");
	}

	return;
}

static void
dissect_v2giso2_powerdemandres(
	const struct iso2PowerDemandResType *powerdemandres,
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
		hf_v2giso2_struct_iso2PowerDemandResType_ResponseCode,
		tvb, 0, 0, powerdemandres->ResponseCode);
	proto_item_set_generated(it);

	if (powerdemandres->EVSEStatus_isUsed) {
		dissect_v2giso2_evsestatus(
			&powerdemandres->EVSEStatus,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2EVSEStatusType,
			"EVSEStatus");
	}

	dissect_v2giso2_physicalvalue(
		&powerdemandres->EVSEOutputPower,
		tvb, pinfo, subtree,
		ett_v2giso2_struct_iso2PhysicalValueType,
		"EVSEOutputPower");

	exi_add_characters(subtree,
		hf_v2giso2_struct_iso2PowerDemandResType_EVSEID,
		tvb,
		powerdemandres->EVSEID.characters,
		powerdemandres->EVSEID.charactersLen,
		sizeof(powerdemandres->EVSEID.characters));

	if (powerdemandres->SAScheduleTupleID_isUsed) {
		it = proto_tree_add_uint(subtree,
			hf_v2giso2_struct_iso2PowerDemandResType_SAScheduleTupleID,
			tvb, 0, 0, powerdemandres->SAScheduleTupleID);
		proto_item_set_generated(it);
	}

	if (powerdemandres->MeterInfo_isUsed) {
		dissect_v2giso2_meterinfo(
			&powerdemandres->MeterInfo,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2MeterInfoType,
			"MeterInfo");
	}

	if (powerdemandres->ReceiptRequired_isUsed) {
		it = proto_tree_add_int(subtree,
			hf_v2giso2_struct_iso2PowerDemandResType_ReceiptRequired,
			tvb, 0, 0, powerdemandres->ReceiptRequired);
		proto_item_set_generated(it);
	}

	if (powerdemandres->PowerDemandParameters_isUsed) {
		dissect_v2giso2_parameterset(
			&powerdemandres->PowerDemandParameters,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2ParameterSetType,
			"PowerDemandParameters");
	}

	return;
}

static void
dissect_v2giso2_pairingreq(
	const struct iso2PairingReqType *pairingreq,
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
		hf_v2giso2_struct_iso2PairingReqType_EVProcessing,
		tvb, 0, 0, pairingreq->EVProcessing);
	proto_item_set_generated(it);

	if (pairingreq->PairingParameters_isUsed) {
		dissect_v2giso2_parameterset(
			&pairingreq->PairingParameters,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2ParameterSetType,
			"PairingParameters");
	}

	return;
}

static void
dissect_v2giso2_pairingres(
	const struct iso2PairingResType *pairingres,
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
		hf_v2giso2_struct_iso2PairingResType_ResponseCode,
		tvb, 0, 0, pairingres->ResponseCode);
	proto_item_set_generated(it);

	if (pairingres->EVSEStatus_isUsed) {
		dissect_v2giso2_evsestatus(
			&pairingres->EVSEStatus,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2EVSEStatusType,
			"EVSEStatus");
	}

	it = proto_tree_add_uint(subtree,
		hf_v2giso2_struct_iso2PairingResType_EVSEProcessing,
		tvb, 0, 0, pairingres->EVSEProcessing);
	proto_item_set_generated(it);

	if (pairingres->PairingParameters_isUsed) {
		dissect_v2giso2_parameterset(
			&pairingres->PairingParameters,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2ParameterSetType,
			"PairingParameters");
	}

	return;
}

static void
dissect_v2giso2_alignmentcheckreq(
	const struct iso2AlignmentCheckReqType *alignmentcheckreq,
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
		hf_v2giso2_struct_iso2AlignmentCheckReqType_EVProcessing,
		tvb, 0, 0, alignmentcheckreq->EVProcessing);
	proto_item_set_generated(it);

	if (alignmentcheckreq->AlignmentCheckParameters_isUsed) {
		dissect_v2giso2_parameterset(
			&alignmentcheckreq->AlignmentCheckParameters,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2ParameterSetType,
			"AlignmentCheckParameters");
	}

	return;
}

static void
dissect_v2giso2_alignmentcheckres(
	const struct iso2AlignmentCheckResType *alignmentcheckres,
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
		hf_v2giso2_struct_iso2AlignmentCheckResType_ResponseCode,
		tvb, 0, 0, alignmentcheckres->ResponseCode);
	proto_item_set_generated(it);

	if (alignmentcheckres->EVSEStatus_isUsed) {
		dissect_v2giso2_evsestatus(
			&alignmentcheckres->EVSEStatus,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2EVSEStatusType,
			"EVSEStatus");
	}

	it = proto_tree_add_uint(subtree,
		hf_v2giso2_struct_iso2AlignmentCheckResType_EVSEProcessing,
		tvb, 0, 0, alignmentcheckres->EVSEProcessing);
	proto_item_set_generated(it);

	if (alignmentcheckres->AlignmentCheckParameters_isUsed) {
		dissect_v2giso2_parameterset(
			&alignmentcheckres->AlignmentCheckParameters,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2ParameterSetType,
			"AlignmentCheckParameters");
	}

	return;
}

static void
dissect_v2giso2_finepositioningreq(
	const struct iso2FinePositioningReqType *finepositioningreq,
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
		hf_v2giso2_struct_iso2FinePositioningReqType_EVProcessing,
		tvb, 0, 0, finepositioningreq->EVProcessing);
	proto_item_set_generated(it);

	if (finepositioningreq->EVFinePositioningParameters_isUsed) {
		dissect_v2giso2_evfinepositioningparameters(
			&finepositioningreq->EVFinePositioningParameters,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2EVFinePositioningParametersType,
			"EVFinePositioningParameters");
	}

	if (finepositioningreq->Generic_EVFinePositioningParameters_isUsed) {
		dissect_v2giso2_generic_evfinepositioningparameters(
			&finepositioningreq->Generic_EVFinePositioningParameters,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2Generic_EVFinePositioningParametersType,
			"Generic_EVFinePositioningParameters");
	}

	if (finepositioningreq->LFA_EVFinePositioningParameters_isUsed) {
		dissect_v2giso2_lfa_evfinepositioningparameters(
			&finepositioningreq->LFA_EVFinePositioningParameters,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2LFA_EVFinePositioningParametersType,
			"LFA_EVFinePositioningParameters");
	}

	return;
}

static void
dissect_v2giso2_finepositioningres(
	const struct iso2FinePositioningResType *finepositioningres,
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
		hf_v2giso2_struct_iso2FinePositioningResType_ResponseCode,
		tvb, 0, 0, finepositioningres->ResponseCode);
	proto_item_set_generated(it);

	if (finepositioningres->EVSEStatus_isUsed) {
		dissect_v2giso2_evsestatus(
			&finepositioningres->EVSEStatus,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2EVSEStatusType,
			"EVSEStatus");
	}

	it = proto_tree_add_uint(subtree,
		hf_v2giso2_struct_iso2FinePositioningResType_EVSEProcessing,
		tvb, 0, 0, finepositioningres->EVSEProcessing);
	proto_item_set_generated(it);

	if (finepositioningres->EVSEFinePositioningParameters_isUsed) {
		dissect_v2giso2_evsefinepositioningparameters(
			&finepositioningres->EVSEFinePositioningParameters,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2EVSEFinePositioningParametersType,
			"EVSEFinePositioningParameters");
	}

	if (finepositioningres->Generic_EVSEFinePositioningParameters_isUsed) {
		dissect_v2giso2_generic_evsefinepositioningparameters(
			&finepositioningres->Generic_EVSEFinePositioningParameters,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2Generic_EVSEFinePositioningParametersType,
			"Generic_EVSEFinePositioningParameters");
	}

	if (finepositioningres->LFA_EVSEFinePositioningParameters_isUsed) {
		dissect_v2giso2_lfa_evsefinepositioningparameters(
			&finepositioningres->LFA_EVSEFinePositioningParameters,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2LFA_EVSEFinePositioningParametersType,
			"LFA_EVSEFinePositioningParameters");
	}

	if (finepositioningres->MV_EVSEFinePositioningParameters_isUsed) {
		dissect_v2giso2_mv_evsefinepositioningparameters(
			&finepositioningres->MV_EVSEFinePositioningParameters,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2MV_EVSEFinePositioningParametersType,
			"MV_EVSEFinePositioningParameters");
	}

	return;
}

static void
dissect_v2giso2_finepositioningsetupreq(
	const struct iso2FinePositioningSetupReqType *finepositioningsetupreq,
	tvbuff_t *tvb,
	packet_info *pinfo _U_,
	proto_tree *tree,
	gint idx,
	const char *subtree_name)
{
	proto_tree *subtree;

	subtree = proto_tree_add_subtree(tree,
		tvb, 0, 0, idx, NULL, subtree_name);

	if (finepositioningsetupreq->EVFinePositioningSetupParameters_isUsed) {
		dissect_v2giso2_evfinepositioningsetupparameters(
			&finepositioningsetupreq->EVFinePositioningSetupParameters,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2EVFinePositioningSetupParametersType,
			"EVFinePositioningSetupParameters");
	}

	if (finepositioningsetupreq->LFA_EVFinePositioningSetupParameters_isUsed) {
		dissect_v2giso2_lfa_evfinepositioningsetupparameters(
			&finepositioningsetupreq->LFA_EVFinePositioningSetupParameters,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2LFA_EVFinePositioningSetupParametersType,
			"LFA_EVFinePositioningSetupParameters");
	}

	return;
}

static void
dissect_v2giso2_finepositioningsetupres(
	const struct iso2FinePositioningSetupResType *finepositioningsetupres,
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
		hf_v2giso2_struct_iso2FinePositioningSetupResType_ResponseCode,
		tvb, 0, 0, finepositioningsetupres->ResponseCode);
	proto_item_set_generated(it);

	if (finepositioningsetupres->EVSEStatus_isUsed) {
		dissect_v2giso2_evsestatus(
			&finepositioningsetupres->EVSEStatus,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2EVSEStatusType,
			"EVSEStatus");
	}

	if (finepositioningsetupres->EVSEFinePositioningSetupParameters_isUsed) {
		dissect_v2giso2_evsefinepositioningsetupparameters(
			&finepositioningsetupres->EVSEFinePositioningSetupParameters,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2EVSEFinePositioningSetupParametersType,
			"EVSEFinePositioningSetupParameters");
	}

	if (finepositioningsetupres->LFA_EVSEFinePositioningSetupParameters_isUsed) {
		dissect_v2giso2_lfa_evsefinepositioningsetupparameters(
			&finepositioningsetupres->LFA_EVSEFinePositioningSetupParameters,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2LFA_EVSEFinePositioningSetupParametersType,
			"LFA_EVSEFinePositioningSetupParameters");
	}

	if (finepositioningsetupres->MV_EVSEFinePositioningSetupParameters_isUsed) {
		dissect_v2giso2_mv_evsefinepositioningsetupparameters(
			&finepositioningsetupres->MV_EVSEFinePositioningSetupParameters,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2MV_EVSEFinePositioningSetupParametersType,
			"MV_EVSEFinePositioningSetupParameters");
	}

	return;
}

static void
dissect_v2giso2_weldingdetectionreq(
	const struct iso2WeldingDetectionReqType *weldingdetectionreq _U_,
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
dissect_v2giso2_weldingdetectionres(
	const struct iso2WeldingDetectionResType *weldingdetectionres,
	tvbuff_t *tvb,
	packet_info *pinfo _U_,
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
		hf_v2giso2_struct_iso2WeldingDetectionResType_ResponseCode,
		tvb, 0, 0, weldingdetectionres->ResponseCode);
	proto_item_set_generated(it);

	if (weldingdetectionres->EVSEStatus_isUsed) {
		dissect_v2giso2_evsestatus(
			&weldingdetectionres->EVSEStatus,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2EVSEStatusType,
			"EVSEStatus");
	}

	dissect_v2giso2_physicalvalue(
		&weldingdetectionres->EVSEPresentVoltage,
		tvb, pinfo, subtree,
		ett_v2giso2_struct_iso2PhysicalValueType,
		"EVSEPresentVoltage");
	value = v2giso2_physicalvalue_to_double(
		&weldingdetectionres->EVSEPresentVoltage);
	it = proto_tree_add_double(subtree,
		hf_v2giso2_present_voltage,
		tvb, 0, 0, value);
	proto_item_set_generated(it);

	return;
}

static void
dissect_v2giso2_currentdemandreq(
	const struct iso2CurrentDemandReqType *currentdemandreq,
	tvbuff_t *tvb,
	packet_info *pinfo _U_,
	proto_tree *tree,
	gint idx,
	const char *subtree_name)
{
	proto_tree *subtree;

	subtree = proto_tree_add_subtree(tree,
		tvb, 0, 0, idx, NULL, subtree_name);

	dissect_v2giso2_physicalvalue(
		&currentdemandreq->EVTargetEnergyRequest,
		tvb, pinfo, subtree,
		ett_v2giso2_struct_iso2PhysicalValueType,
		"EVTargetEnergyRequest");

	if (currentdemandreq->EVMaximumEnergyRequest_isUsed) {
		dissect_v2giso2_physicalvalue(
			&currentdemandreq->EVMaximumEnergyRequest,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2PhysicalValueType,
			"EVMaximumEnergyRequest");
	}

	if (currentdemandreq->EVMinimumEnergyRequest_isUsed) {
		dissect_v2giso2_physicalvalue(
			&currentdemandreq->EVMinimumEnergyRequest,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2PhysicalValueType,
			"EVMinimumEnergyRequest");
	}

	if (currentdemandreq->DisplayParameters_isUsed) {
		dissect_v2giso2_displayparameters(
			&currentdemandreq->DisplayParameters,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2DisplayParametersType,
			"DisplayParameters");
	}

	dissect_v2giso2_physicalvalue(
		&currentdemandreq->EVTargetCurrent,
		tvb, pinfo, subtree,
		ett_v2giso2_struct_iso2PhysicalValueType,
		"EVTargetCurrent");

	dissect_v2giso2_physicalvalue(
		&currentdemandreq->EVTargetVoltage,
		tvb, pinfo, subtree,
		ett_v2giso2_struct_iso2PhysicalValueType,
		"EVTargetVoltage");

	if (currentdemandreq->EVMaximumCurrent_isUsed) {
		dissect_v2giso2_physicalvalue(
			&currentdemandreq->EVMaximumCurrent,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2PhysicalValueType,
			"EVMaximumCurrent");
	}

	if (currentdemandreq->EVMaximumPower_isUsed) {
		dissect_v2giso2_physicalvalue(
			&currentdemandreq->EVMaximumPower,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2PhysicalValueType,
			"EVMaximumPower");
	}

	if (currentdemandreq->EVMaximumVoltage_isUsed) {
		dissect_v2giso2_physicalvalue(
			&currentdemandreq->EVMaximumVoltage,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2PhysicalValueType,
			"EVMaximumVoltage");
	}

	return;
}

static void
dissect_v2giso2_currentdemandres(
	const struct iso2CurrentDemandResType *currentdemandres,
	tvbuff_t *tvb,
	packet_info *pinfo _U_,
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
		hf_v2giso2_struct_iso2CurrentDemandResType_ResponseCode,
		tvb, 0, 0, currentdemandres->ResponseCode);
	proto_item_set_generated(it);

	if (currentdemandres->EVSEStatus_isUsed) {
		dissect_v2giso2_evsestatus(
			&currentdemandres->EVSEStatus,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2EVSEStatusType,
			"EVSEStatus");
	}

	dissect_v2giso2_physicalvalue(
		&currentdemandres->EVSEPresentCurrent,
		tvb, pinfo, subtree,
		ett_v2giso2_struct_iso2PhysicalValueType,
		"EVSEPresentCurrent");
	value = v2giso2_physicalvalue_to_double(
		&currentdemandres->EVSEPresentCurrent);
	it = proto_tree_add_double(subtree,
		hf_v2giso2_present_current,
		tvb, 0, 0, value);
	proto_item_set_generated(it);

	dissect_v2giso2_physicalvalue(
		&currentdemandres->EVSEPresentVoltage,
		tvb, pinfo, subtree,
		ett_v2giso2_struct_iso2PhysicalValueType,
		"EVSEPresentVoltage");
	value = v2giso2_physicalvalue_to_double(
		&currentdemandres->EVSEPresentVoltage);
	it = proto_tree_add_double(subtree,
		hf_v2giso2_present_current,
		tvb, 0, 0, value);
	proto_item_set_generated(it);

	it = proto_tree_add_int(subtree,
		hf_v2giso2_struct_iso2CurrentDemandResType_EVSEPowerLimitAchieved,
		tvb, 0, 0, currentdemandres->EVSEPowerLimitAchieved);
	proto_item_set_generated(it);

	it = proto_tree_add_int(subtree,
		hf_v2giso2_struct_iso2CurrentDemandResType_EVSECurrentLimitAchieved,
		tvb, 0, 0, currentdemandres->EVSECurrentLimitAchieved);
	proto_item_set_generated(it);

	it = proto_tree_add_int(subtree,
		hf_v2giso2_struct_iso2CurrentDemandResType_EVSECurrentLimitAchieved,
		tvb, 0, 0, currentdemandres->EVSEVoltageLimitAchieved);
	proto_item_set_generated(it);

	if (currentdemandres->EVSEMaximumPower_isUsed) {
		dissect_v2giso2_physicalvalue(
			&currentdemandres->EVSEMaximumPower,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2PhysicalValueType,
			"EVSEMaximumPower");
	}

	if (currentdemandres->EVSEMaximumCurrent_isUsed) {
		dissect_v2giso2_physicalvalue(
			&currentdemandres->EVSEMaximumCurrent,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2PhysicalValueType,
			"EVSEMaximumCurrent");
	}

	if (currentdemandres->EVSEMaximumVoltage_isUsed) {
		dissect_v2giso2_physicalvalue(
			&currentdemandres->EVSEMaximumVoltage,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2PhysicalValueType,
			"EVSEMaximumVoltage");
	}

	exi_add_characters(subtree,
		hf_v2giso2_struct_iso2CurrentDemandResType_EVSEID,
		tvb,
		currentdemandres->EVSEID.characters,
		currentdemandres->EVSEID.charactersLen,
		sizeof(currentdemandres->EVSEID.characters));

	if (currentdemandres->SAScheduleTupleID_isUsed) {
		it = proto_tree_add_uint(subtree,
			hf_v2giso2_struct_iso2CurrentDemandResType_SAScheduleTupleID,
			tvb, 0, 0, currentdemandres->SAScheduleTupleID);
		proto_item_set_generated(it);
	}

	if (currentdemandres->MeterInfo_isUsed) {
		dissect_v2giso2_meterinfo(
			&currentdemandres->MeterInfo,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2MeterInfoType,
			"MeterInfo");
	}

	if (currentdemandres->ReceiptRequired_isUsed) {
		it = proto_tree_add_int(subtree,
			hf_v2giso2_struct_iso2CurrentDemandResType_ReceiptRequired,
			tvb, 0, 0, currentdemandres->ReceiptRequired);
		proto_item_set_generated(it);
	}

	return;
}

static void
dissect_v2giso2_prechargereq(
	const struct iso2PreChargeReqType *prechargereq,
	tvbuff_t *tvb,
	packet_info *pinfo _U_,
	proto_tree *tree,
	gint idx,
	const char *subtree_name)
{
	proto_tree *subtree;

	subtree = proto_tree_add_subtree(tree,
		tvb, 0, 0, idx, NULL, subtree_name);

	dissect_v2giso2_physicalvalue(
		&prechargereq->EVTargetCurrent,
		tvb, pinfo, subtree,
		ett_v2giso2_struct_iso2PhysicalValueType,
		"EVTargetCurrent");

	dissect_v2giso2_physicalvalue(
		&prechargereq->EVTargetVoltage,
		tvb, pinfo, subtree,
		ett_v2giso2_struct_iso2PhysicalValueType,
		"EVTargetVoltage");

	return;
}

static void
dissect_v2giso2_prechargeres(
	const struct iso2PreChargeResType *prechargeres,
	tvbuff_t *tvb,
	packet_info *pinfo _U_,
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
		hf_v2giso2_struct_iso2CurrentDemandResType_ResponseCode,
		tvb, 0, 0, prechargeres->ResponseCode);
	proto_item_set_generated(it);

	if (prechargeres->EVSEStatus_isUsed) {
		dissect_v2giso2_evsestatus(
			&prechargeres->EVSEStatus,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2EVSEStatusType,
			"EVSEStatus");
	}

	dissect_v2giso2_physicalvalue(
		&prechargeres->EVSEPresentVoltage,
		tvb, pinfo, subtree,
		ett_v2giso2_struct_iso2PhysicalValueType,
		"EVSEPresentVoltage");
	value = v2giso2_physicalvalue_to_double(
		&prechargeres->EVSEPresentVoltage);
	it = proto_tree_add_double(subtree,
		hf_v2giso2_present_current,
		tvb, 0, 0, value);

	return;
}

static void
dissect_v2giso2_cablecheckreq(
	const struct iso2CableCheckReqType *cablecheckreq _U_,
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
dissect_v2giso2_cablecheckres(
	const struct iso2CableCheckResType *cablecheckres,
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
		hf_v2giso2_struct_iso2CableCheckResType_ResponseCode,
		tvb, 0, 0, cablecheckres->ResponseCode);
	proto_item_set_generated(it);

	if (cablecheckres->EVSEStatus_isUsed) {
		dissect_v2giso2_evsestatus(
			&cablecheckres->EVSEStatus,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2EVSEStatusType,
			"EVSEStatus");
	}

	it = proto_tree_add_uint(subtree,
		hf_v2giso2_struct_iso2CableCheckResType_EVSEProcessing,
		tvb, 0, 0, cablecheckres->EVSEProcessing);
	proto_item_set_generated(it);

	return;
}

static void
dissect_v2giso2_chargingstatusreq(
	const struct iso2ChargingStatusReqType *chargingstatusreq,
	tvbuff_t *tvb,
	packet_info *pinfo _U_,
	proto_tree *tree,
	gint idx,
	const char *subtree_name)
{
	proto_tree *subtree;

	subtree = proto_tree_add_subtree(tree,
		tvb, 0, 0, idx, NULL, subtree_name);

	dissect_v2giso2_physicalvalue(
		&chargingstatusreq->EVTargetEnergyRequest,
		tvb, pinfo, subtree,
		ett_v2giso2_struct_iso2PhysicalValueType,
		"EVTargetEnergyRequest");

	if (chargingstatusreq->EVMaximumEnergyRequest_isUsed) {
		dissect_v2giso2_physicalvalue(
			&chargingstatusreq->EVMaximumEnergyRequest,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2PhysicalValueType,
			"EVMaximumEnergyRequest");
	}

	if (chargingstatusreq->EVMinimumEnergyRequest_isUsed) {
		dissect_v2giso2_physicalvalue(
			&chargingstatusreq->EVMinimumEnergyRequest,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2PhysicalValueType,
			"EVMinimumEnergyRequest");
	}

	if (chargingstatusreq->DisplayParameters_isUsed) {
		dissect_v2giso2_displayparameters(
			&chargingstatusreq->DisplayParameters,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2DisplayParametersType,
			"DisplayParameters");
	}

	if (chargingstatusreq->EVMaximumChargePower_isUsed) {
		dissect_v2giso2_physicalvalue(
			&chargingstatusreq->EVMaximumChargePower,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2PhysicalValueType,
			"EVMaximumChargePower");
	}

	if (chargingstatusreq->EVMaximumChargeCurrent_isUsed) {
		dissect_v2giso2_physicalvalue(
			&chargingstatusreq->EVMaximumChargeCurrent,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2PhysicalValueType,
			"EVMaximumChargeCurrent");
	}

	if (chargingstatusreq->EVMinimumChargeCurrent_isUsed) {
		dissect_v2giso2_physicalvalue(
			&chargingstatusreq->EVMinimumChargeCurrent,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2PhysicalValueType,
			"EVMinimumChargeCurrent");
	}

	return;
}

static void
dissect_v2giso2_chargingstatusres(
	const struct iso2ChargingStatusResType *chargingstatusres,
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
		hf_v2giso2_struct_iso2ChargingStatusResType_ResponseCode,
		tvb, 0, 0, chargingstatusres->ResponseCode);
	proto_item_set_generated(it);

	if (chargingstatusres->EVSEStatus_isUsed) {
		dissect_v2giso2_evsestatus(
			&chargingstatusres->EVSEStatus,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2EVSEStatusType,
			"EVSEStatus");
	}

	exi_add_characters(subtree,
		hf_v2giso2_struct_iso2ChargingStatusResType_EVSEID,
		tvb,
		chargingstatusres->EVSEID.characters,
		chargingstatusres->EVSEID.charactersLen,
		sizeof(chargingstatusres->EVSEID.characters));

	if (chargingstatusres->SAScheduleTupleID_isUsed) {
		it = proto_tree_add_uint(subtree,
			hf_v2giso2_struct_iso2ChargingStatusResType_SAScheduleTupleID,
			tvb, 0, 0, chargingstatusres->SAScheduleTupleID);
		proto_item_set_generated(it);
	}

	if (chargingstatusres->MeterInfo_isUsed) {
		dissect_v2giso2_meterinfo(
			&chargingstatusres->MeterInfo,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2MeterInfoType,
			"MeterInfo");
	}

	if (chargingstatusres->ReceiptRequired_isUsed) {
		it = proto_tree_add_int(subtree,
			hf_v2giso2_struct_iso2ChargingStatusResType_ReceiptRequired,
			tvb, 0, 0, chargingstatusres->ReceiptRequired);
		proto_item_set_generated(it);
	}

	if (chargingstatusres->EVSETargetPower_isUsed) {
		dissect_v2giso2_physicalvalue(
			&chargingstatusres->EVSETargetPower,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2PhysicalValueType,
			"EVSETargetPower");
	}

	return;
}

static void
dissect_v2giso2_certificateinstallationreq(
	const struct iso2CertificateInstallationReqType
		*certificateinstallationreq,
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
		hf_v2giso2_struct_iso2CertificateInstallationReqType_Id,
		tvb,
		certificateinstallationreq->Id.characters,
		certificateinstallationreq->Id.charactersLen,
		sizeof(certificateinstallationreq->Id.characters));

	if (v2gber_handle == NULL) {
		exi_add_bytes(subtree,
			hf_v2giso2_struct_iso2CertificateInstallationReqType_OEMProvisioningCert,
			tvb,
			certificateinstallationreq->OEMProvisioningCert.bytes,
			certificateinstallationreq->OEMProvisioningCert.bytesLen,
			sizeof(certificateinstallationreq->OEMProvisioningCert.bytes));
	} else {
		tvbuff_t *child;
		proto_tree *asn1_tree;

		child = tvb_new_child_real_data(tvb,
			certificateinstallationreq->OEMProvisioningCert.bytes,
			sizeof(certificateinstallationreq->OEMProvisioningCert.bytes),
			certificateinstallationreq->OEMProvisioningCert.bytesLen);

		asn1_tree = proto_tree_add_subtree(subtree,
			child, 0, tvb_reported_length(child),
			ett_v2giso2_asn1, NULL, "OEMProvisioningCert ASN1");
		call_dissector(v2gber_handle, child, pinfo, asn1_tree);
	}

	dissect_v2giso2_listofrootcertificateids(
		&certificateinstallationreq->ListOfRootCertificateIDs,
		tvb, pinfo, subtree,
		ett_v2giso2_struct_iso2ListOfRootCertificateIDsType,
		"ListOfRootCertificateIDs");

	return;
}

static void
dissect_v2giso2_certificateinstallationres(
	const struct iso2CertificateInstallationResType
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

	it = proto_tree_add_uint(subtree,
		hf_v2giso2_struct_iso2CertificateInstallationResType_ResponseCode,
		tvb, 0, 0, certificateinstallationres->ResponseCode);
	proto_item_set_generated(it);

	if (certificateinstallationres->EVSEStatus_isUsed) {
		dissect_v2giso2_evsestatus(
			&certificateinstallationres->EVSEStatus,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2EVSEStatusType,
			"EVSEStatus");
	}

	dissect_v2giso2_certificatechain(
		&certificateinstallationres->SAProvisioningCertificateChain,
		tvb, pinfo, subtree,
		ett_v2giso2_struct_iso2CertificateChainType,
		"SAProvisioningCertificateChain");

	dissect_v2giso2_certificatechain(
		&certificateinstallationres->ContractSignatureCertChain,
		tvb, pinfo, subtree,
		ett_v2giso2_struct_iso2CertificateChainType,
		"ContractSignatureCertChain");

	dissect_v2giso2_contractsignatureencryptedprivatekey(
		&certificateinstallationres->ContractSignatureEncryptedPrivateKey,
		tvb, pinfo, subtree,
		ett_v2giso2_struct_iso2ContractSignatureEncryptedPrivateKeyType,
		"ContractSignatureEncryptedPrivateKey");

	dissect_v2giso2_diffiehellmanpublickey(
		&certificateinstallationres->DHpublickey,
		tvb, pinfo, subtree,
		ett_v2giso2_struct_iso2DiffieHellmanPublickeyType,
		"DHpublickey");

	dissect_v2giso2_emaid(
		&certificateinstallationres->eMAID,
		tvb, pinfo, subtree,
		ett_v2giso2_struct_iso2EMAIDType,
		"eMAID");

	return;
}

static void
dissect_v2giso2_certificateupdatereq(
	const struct iso2CertificateUpdateReqType *certificateupdatereq,
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
		hf_v2giso2_struct_iso2CertificateUpdateReqType_Id,
		tvb,
		certificateupdatereq->Id.characters,
		certificateupdatereq->Id.charactersLen,
		sizeof(certificateupdatereq->Id.characters));

	dissect_v2giso2_certificatechain(
		&certificateupdatereq->ContractSignatureCertChain,
		tvb, pinfo, subtree,
		ett_v2giso2_struct_iso2CertificateChainType,
		"ContractSignatureCertChain");

	exi_add_characters(subtree,
		hf_v2giso2_struct_iso2CertificateUpdateReqType_eMAID,
		tvb,
		certificateupdatereq->eMAID.characters,
		certificateupdatereq->eMAID.charactersLen,
		sizeof(certificateupdatereq->eMAID.characters));

	dissect_v2giso2_listofrootcertificateids(
		&certificateupdatereq->ListOfRootCertificateIDs,
		tvb, pinfo, subtree,
		ett_v2giso2_struct_iso2ListOfRootCertificateIDsType,
		"ListOfRootCertificateIDs");

	return;
}

static void
dissect_v2giso2_certificateupdateres(
	const struct iso2CertificateUpdateResType *certificateupdateres,
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
		hf_v2giso2_struct_iso2CertificateUpdateResType_ResponseCode,
		tvb, 0, 0, certificateupdateres->ResponseCode);
	proto_item_set_generated(it);

	if (certificateupdateres->EVSEStatus_isUsed) {
		dissect_v2giso2_evsestatus(
			&certificateupdateres->EVSEStatus,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2EVSEStatusType,
			"EVSEStatus");
	}

	dissect_v2giso2_certificatechain(
		&certificateupdateres->SAProvisioningCertificateChain,
		tvb, pinfo, subtree,
		ett_v2giso2_struct_iso2CertificateChainType,
		"SAProvisioningCertificateChain");

	dissect_v2giso2_certificatechain(
		&certificateupdateres->ContractSignatureCertChain,
		tvb, pinfo, subtree,
		ett_v2giso2_struct_iso2CertificateChainType,
		"ContractSignatureCertChain");

	dissect_v2giso2_contractsignatureencryptedprivatekey(
		&certificateupdateres->ContractSignatureEncryptedPrivateKey,
		tvb, pinfo, subtree,
		ett_v2giso2_struct_iso2ContractSignatureEncryptedPrivateKeyType,
		"ContractSignatureEncryptedPrivateKey");

	dissect_v2giso2_diffiehellmanpublickey(
		&certificateupdateres->DHpublickey,
		tvb, pinfo, subtree,
		ett_v2giso2_struct_iso2DiffieHellmanPublickeyType,
		"DHpublickey");

	dissect_v2giso2_emaid(
		&certificateupdateres->eMAID,
		tvb, pinfo, subtree,
		ett_v2giso2_struct_iso2EMAIDType,
		"eMAID");

	if (certificateupdateres->RetryCounter_isUsed) {
		it = proto_tree_add_int(subtree,
			hf_v2giso2_struct_iso2CertificateUpdateResType_RetryCounter,
			tvb, 0, 0, certificateupdateres->RetryCounter);
		proto_item_set_generated(it);
	}

	return;
}

static void
dissect_v2giso2_sessionstopreq(
	const struct iso2SessionStopReqType *sessionstopreq,
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
		hf_v2giso2_struct_iso2SessionStopReqType_ChargingSession,
		tvb, 0, 0, sessionstopreq->ChargingSession);
	proto_item_set_generated(it);

	return;
}

static void
dissect_v2giso2_sessionstopres(
	const struct iso2SessionStopResType *sessionstopres,
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
		hf_v2giso2_struct_iso2SessionStopResType_ResponseCode,
		tvb, 0, 0, sessionstopres->ResponseCode);
	proto_item_set_generated(it);

	if (sessionstopres->EVSEStatus_isUsed) {
		dissect_v2giso2_evsestatus(
			&sessionstopres->EVSEStatus,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2EVSEStatusType,
			"EVSEStatus");
	}

	return;
}

static void
dissect_v2giso2_meteringreceiptreq(
	const struct iso2MeteringReceiptReqType *meteringreceiptreq,
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
		hf_v2giso2_struct_iso2MeteringReceiptReqType_Id,
		tvb,
		meteringreceiptreq->Id.characters,
		meteringreceiptreq->Id.charactersLen,
		sizeof(meteringreceiptreq->Id.characters));

	exi_add_bytes(subtree,
		hf_v2giso2_struct_iso2MeteringReceiptReqType_SessionID,
		tvb,
		meteringreceiptreq->SessionID.bytes,
		meteringreceiptreq->SessionID.bytesLen,
		sizeof(meteringreceiptreq->SessionID.bytes));

	if (meteringreceiptreq->SAScheduleTupleID_isUsed) {
		it = proto_tree_add_uint(subtree,
			hf_v2giso2_struct_iso2MeteringReceiptReqType_SAScheduleTupleID,
			tvb, 0, 0, meteringreceiptreq->SAScheduleTupleID);
		proto_item_set_generated(it);
	}

	dissect_v2giso2_meterinfo(
		&meteringreceiptreq->MeterInfo,
		tvb, pinfo, subtree,
		ett_v2giso2_struct_iso2MeterInfoType,
		"MeterInfo");

	return;
}

static void
dissect_v2giso2_meteringreceiptres(
	const struct iso2MeteringReceiptResType *meteringreceiptres,
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
		hf_v2giso2_struct_iso2MeteringReceiptResType_ResponseCode,
		tvb, 0, 0, meteringreceiptres->ResponseCode);
	proto_item_set_generated(it);

	if (meteringreceiptres->EVSEStatus_isUsed) {
		dissect_v2giso2_evsestatus(
			&meteringreceiptres->EVSEStatus,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2EVSEStatusType,
			"EVSEStatus");
	}

	return;
}

static void
dissect_v2giso2_powerdeliveryreq(
	const struct iso2PowerDeliveryReqType *powerdeliveryreq,
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
		hf_v2giso2_struct_iso2PowerDeliveryReqType_ChargeProgress,
		tvb, 0, 0, powerdeliveryreq->ChargeProgress);
	proto_item_set_generated(it);

	if (powerdeliveryreq->EVOperation_isUsed) {
		it = proto_tree_add_uint(subtree,
			hf_v2giso2_struct_iso2PowerDeliveryReqType_EVOperation,
			tvb, 0, 0, powerdeliveryreq->EVOperation);
		proto_item_set_generated(it);
	}

	if (powerdeliveryreq->SAScheduleTupleID_isUsed) {
		it = proto_tree_add_uint(subtree,
			hf_v2giso2_struct_iso2PowerDeliveryReqType_SAScheduleTupleID,
			tvb, 0, 0, powerdeliveryreq->SAScheduleTupleID);
		proto_item_set_generated(it);
	}

	if (powerdeliveryreq->ChargingProfile_isUsed) {
		dissect_v2giso2_chargingprofile(
			&powerdeliveryreq->ChargingProfile,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2ChargingProfileType,
			"ChargingProfile");
	}

	return;
}

static void
dissect_v2giso2_powerdeliveryres(
	const struct iso2PowerDeliveryResType *powerdeliveryres,
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
		hf_v2giso2_struct_iso2PowerDeliveryResType_ResponseCode,
		tvb, 0, 0, powerdeliveryres->ResponseCode);
	proto_item_set_generated(it);

	if (powerdeliveryres->EVSEStatus_isUsed) {
		dissect_v2giso2_evsestatus(
			&powerdeliveryres->EVSEStatus,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2EVSEStatusType,
			"EVSEStatus");
	}

	it = proto_tree_add_uint(subtree,
		hf_v2giso2_struct_iso2PowerDeliveryResType_EVSEProcessing,
		tvb, 0, 0, powerdeliveryres->EVSEProcessing);
	proto_item_set_generated(it);

	return;
}

static void
dissect_v2giso2_chargeparameterdiscoveryreq(
	const struct iso2ChargeParameterDiscoveryReqType
		*chargeparameterdiscoveryreq,
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

	if (chargeparameterdiscoveryreq->MaxSupportingPoints_isUsed) {
		it = proto_tree_add_uint(subtree,
			hf_v2giso2_struct_iso2ChargeParameterDiscoveryReqType_MaxSupportingPoints,
			tvb, 0, 0, chargeparameterdiscoveryreq->MaxSupportingPoints);
		proto_item_set_generated(it);
	}

	if (chargeparameterdiscoveryreq->EVEnergyTransferParameter_isUsed) {
		dissect_v2giso2_evenergytransferparameter(
			&chargeparameterdiscoveryreq->EVEnergyTransferParameter,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2EVEnergyTransferParameterType,
			"EVEnergyTransferParameter");
	}

	if (chargeparameterdiscoveryreq->AC_EVChargeParameter_isUsed) {
		dissect_v2giso2_ac_evchargeparameter(
			&chargeparameterdiscoveryreq->AC_EVChargeParameter,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2AC_EVChargeParameterType,
			"AC_EVChargeParameter");
	}

	if (chargeparameterdiscoveryreq->AC_EVBidirectionalParameter_isUsed) {
		dissect_v2giso2_ac_evbidirectionalparameter(
			&chargeparameterdiscoveryreq->AC_EVBidirectionalParameter,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2AC_EVBidirectionalParameterType,
			"AC_EVBidirectionalParameter");
	}

	if (chargeparameterdiscoveryreq->DC_EVChargeParameter_isUsed) {
		dissect_v2giso2_dc_evchargeparameter(
			&chargeparameterdiscoveryreq->DC_EVChargeParameter,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2DC_EVChargeParameterType,
			"DC_EVChargeParameter");
	}

	if (chargeparameterdiscoveryreq->DC_EVBidirectionalParameter_isUsed) {
		dissect_v2giso2_dc_evbidirectionalparameter(
			&chargeparameterdiscoveryreq->DC_EVBidirectionalParameter,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2DC_EVBidirectionalParameterType,
			"DC_EVBidirectionalParameter");
	}

	if (chargeparameterdiscoveryreq->WPT_EVChargeParameter_isUsed) {
		dissect_v2giso2_wpt_evchargeparameter(
			&chargeparameterdiscoveryreq->WPT_EVChargeParameter,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2WPT_EVChargeParameterType,
			"WPT_EVChargeParameter");
	}

	if (chargeparameterdiscoveryreq->MinimumPMaxRequest_isUsed) {
		dissect_v2giso2_minimumpmaxrequest(
			&chargeparameterdiscoveryreq->MinimumPMaxRequest,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2MinimumPMaxRequestType,
			"MinimumPMaxRequest");
	}

	return;
}

static void
dissect_v2giso2_chargeparameterdiscoveryres(
	const struct iso2ChargeParameterDiscoveryResType *chargeparameterdiscoveryres,
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
		hf_v2giso2_struct_iso2ChargeParameterDiscoveryResType_ResponseCode,
		tvb, 0, 0, chargeparameterdiscoveryres->ResponseCode);
	proto_item_set_generated(it);

	if (chargeparameterdiscoveryres->EVSEStatus_isUsed) {
		dissect_v2giso2_evsestatus(
			&chargeparameterdiscoveryres->EVSEStatus,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2EVSEStatusType,
			"EVSEStatus");
	}

	it = proto_tree_add_uint(subtree,
		hf_v2giso2_struct_iso2ChargeParameterDiscoveryResType_EVSEProcessing,
		tvb, 0, 0, chargeparameterdiscoveryres->EVSEProcessing);
	proto_item_set_generated(it);

	if (chargeparameterdiscoveryres->SAScheduleList_isUsed) {
		dissect_v2giso2_saschedulelist(
			&chargeparameterdiscoveryres->SAScheduleList,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2SAScheduleListType,
			"SAScheduleList");
	}

	if (chargeparameterdiscoveryres->EVSEEnergyTransferParameter_isUsed) {
		dissect_v2giso2_evseenergytransferparameter(
			&chargeparameterdiscoveryres->EVSEEnergyTransferParameter,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2EVSEEnergyTransferParameterType,
			"EVSEEnergyTransferParameter");
	}

	if (chargeparameterdiscoveryres->AC_EVSEChargeParameter_isUsed) {
		dissect_v2giso2_ac_evsechargeparameter(
			&chargeparameterdiscoveryres->AC_EVSEChargeParameter,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2AC_EVSEChargeParameterType,
			"AC_EVSEChargeParameter");
	}

	if (chargeparameterdiscoveryres->AC_EVSEBidirectionalParameter_isUsed) {
		dissect_v2giso2_ac_evsebidirectionalparameter(
			&chargeparameterdiscoveryres->AC_EVSEBidirectionalParameter,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2AC_EVSEBidirectionalParameterType,
			"AC_EVSEBidirectionalParameter");
	}

	if (chargeparameterdiscoveryres->DC_EVSEChargeParameter_isUsed) {
		dissect_v2giso2_dc_evsechargeparameter(
			&chargeparameterdiscoveryres->DC_EVSEChargeParameter,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2DC_EVSEChargeParameterType,
			"DC_EVSEChargeParameter");
	}

	if (chargeparameterdiscoveryres->DC_EVSEBidirectionalParameter_isUsed) {
		dissect_v2giso2_dc_evsebidirectionalparameter(
			&chargeparameterdiscoveryres->DC_EVSEBidirectionalParameter,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2DC_EVSEBidirectionalParameterType,
			"DC_EVSEBidirectionalParameter");
	}

	if (chargeparameterdiscoveryres->WPT_EVSEChargeParameter_isUsed) {
		dissect_v2giso2_wpt_evsechargeparameter(
			&chargeparameterdiscoveryres->WPT_EVSEChargeParameter,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2WPT_EVSEChargeParameterType,
			"WPT_EVSEChargeParameter");
	}

	return;
}

static void
dissect_v2giso2_authorizationreq(
	const struct iso2AuthorizationReqType *authorizationreq,
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
			hf_v2giso2_struct_iso2AuthorizationReqType_Id,
			tvb,
			authorizationreq->Id.characters,
			authorizationreq->Id.charactersLen,
			sizeof(authorizationreq->Id.characters));
	}

	if (authorizationreq->GenChallenge_isUsed) {
		exi_add_bytes(subtree,
			hf_v2giso2_struct_iso2AuthorizationReqType_GenChallenge,
			tvb,
			authorizationreq->GenChallenge.bytes,
			authorizationreq->GenChallenge.bytesLen,
			sizeof(authorizationreq->GenChallenge.bytes));
	}

	return;
}

static void
dissect_v2giso2_authorizationres(
	const struct iso2AuthorizationResType *authorizationres,
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
		hf_v2giso2_struct_iso2AuthorizationResType_ResponseCode,
		tvb, 0, 0, authorizationres->ResponseCode);
	proto_item_set_generated(it);

	if (authorizationres->EVSEStatus_isUsed) {
		dissect_v2giso2_evsestatus(
			&authorizationres->EVSEStatus,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2EVSEStatusType,
			"EVSEStatus");
	}

	it = proto_tree_add_uint(subtree,
		hf_v2giso2_struct_iso2AuthorizationResType_EVSEProcessing,
		tvb, 0, 0, authorizationres->EVSEProcessing);
	proto_item_set_generated(it);

	return;
}

static void
dissect_v2giso2_paymentdetailsreq(
	const struct iso2PaymentDetailsReqType *paymentdetailsreq,
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
		hf_v2giso2_struct_iso2PaymentDetailsReqType_eMAID,
		tvb,
		paymentdetailsreq->eMAID.characters,
		paymentdetailsreq->eMAID.charactersLen,
		sizeof(paymentdetailsreq->eMAID.characters));

	dissect_v2giso2_certificatechain(
		&paymentdetailsreq->ContractSignatureCertChain,
		tvb, pinfo, subtree,
		ett_v2giso2_struct_iso2CertificateChainType,
		"ContractSignatureCertChain");

	return;
}

static void
dissect_v2giso2_paymentdetailsres(
	const struct iso2PaymentDetailsResType *paymentdetailsres,
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
		hf_v2giso2_struct_iso2PaymentDetailsResType_ResponseCode,
		tvb, 0, 0, paymentdetailsres->ResponseCode);
	proto_item_set_generated(it);

	if (paymentdetailsres->EVSEStatus_isUsed) {
		dissect_v2giso2_evsestatus(
			&paymentdetailsres->EVSEStatus,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2EVSEStatusType,
			"EVSEStatus");
	}

	exi_add_bytes(subtree,
		hf_v2giso2_struct_iso2PaymentDetailsResType_GenChallenge,
		tvb,
		paymentdetailsres->GenChallenge.bytes,
		paymentdetailsres->GenChallenge.bytesLen,
		sizeof(paymentdetailsres->GenChallenge.bytes));

	it = proto_tree_add_int64(subtree,
		hf_v2giso2_struct_iso2PaymentDetailsResType_EVSETimeStamp,
		tvb, 0, 0, paymentdetailsres->EVSETimeStamp);
	proto_item_set_generated(it);

	return;
}

static void
dissect_v2giso2_paymentserviceselectionreq(
	const struct iso2PaymentServiceSelectionReqType
		*paymentserviceselectionreq,
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
		hf_v2giso2_struct_iso2PaymentServiceSelectionReqType_SelectedPaymentOption,
		tvb, 0, 0, paymentserviceselectionreq->SelectedPaymentOption);
	proto_item_set_generated(it);

	dissect_v2giso2_selectedservice(
		&paymentserviceselectionreq->SelectedEnergyTransferService,
		tvb, pinfo, subtree,
		ett_v2giso2_struct_iso2SelectedServiceType,
		"SelectedEnergyTransferService");

	if (paymentserviceselectionreq->SelectedVASList_isUsed) {
		dissect_v2giso2_selectedservicelist(
			&paymentserviceselectionreq->SelectedVASList,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2SelectedServiceListType,
			"SelectedVASList");
	}

	return;
}

static void
dissect_v2giso2_paymentserviceselectionres(
	const struct iso2PaymentServiceSelectionResType
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
		hf_v2giso2_struct_iso2PaymentServiceSelectionResType_ResponseCode,
		tvb, 0, 0, paymentserviceselectionres->ResponseCode);
	proto_item_set_generated(it);

	if (paymentserviceselectionres->EVSEStatus_isUsed) {
		dissect_v2giso2_evsestatus(
			&paymentserviceselectionres->EVSEStatus,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2EVSEStatusType,
			"EVSEStatus");
	}

	return;
}

static void
dissect_v2giso2_servicedetailreq(
	const struct iso2ServiceDetailReqType *servicedetailreq,
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
		hf_v2giso2_struct_iso2ServiceDetailReqType_ServiceID,
		tvb, 0, 0, servicedetailreq->ServiceID);
	proto_item_set_generated(it);

	return;
}

static void
dissect_v2giso2_servicedetailres(
	const struct iso2ServiceDetailResType *servicedetailres,
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
		hf_v2giso2_struct_iso2ServiceDetailResType_ResponseCode,
		tvb, 0, 0, servicedetailres->ResponseCode);
	proto_item_set_generated(it);

	if (servicedetailres->EVSEStatus_isUsed) {
		dissect_v2giso2_evsestatus(
			&servicedetailres->EVSEStatus,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2EVSEStatusType,
			"EVSEStatus");
	}

	it = proto_tree_add_uint(subtree,
		hf_v2giso2_struct_iso2ServiceDetailResType_ServiceID,
		tvb, 0, 0, servicedetailres->ServiceID);
	proto_item_set_generated(it);

	if (servicedetailres->ServiceParameterList_isUsed) {
		dissect_v2giso2_serviceparameterlist(
			&servicedetailres->ServiceParameterList,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2ServiceParameterListType,
			"ServiceParameterList");
	}

	return;
}

static void
dissect_v2giso2_servicediscoveryreq(
	const struct iso2ServiceDiscoveryReqType *servicediscoveryreq,
	tvbuff_t *tvb,
	packet_info *pinfo _U_,
	proto_tree *tree,
	gint idx,
	const char *subtree_name)
{
	proto_tree *subtree;

	subtree = proto_tree_add_subtree(tree,
		tvb, 0, 0, idx, NULL, subtree_name);

	if (servicediscoveryreq->SupportedServiceIDs_isUsed) {
		dissect_v2giso2_serviceidlist(
			&servicediscoveryreq->SupportedServiceIDs,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2ServiceIDListType,
			"SupportedServiceIDs");
	}

	return;
}

static void
dissect_v2giso2_servicediscoveryres(
	const struct iso2ServiceDiscoveryResType *servicediscoveryres,
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
		hf_v2giso2_struct_iso2ServiceDiscoveryResType_ResponseCode,
		tvb, 0, 0, servicediscoveryres->ResponseCode);
	proto_item_set_generated(it);

	if (servicediscoveryres->EVSEStatus_isUsed) {
		dissect_v2giso2_evsestatus(
			&servicediscoveryres->EVSEStatus,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2EVSEStatusType,
			"EVSEStatus");
	}

	dissect_v2giso2_paymentoptionlist(
		&servicediscoveryres->PaymentOptionList,
		tvb, pinfo, subtree,
		ett_v2giso2_struct_iso2PaymentOptionListType,
		"PaymentOptionList");

	dissect_v2giso2_servicelist(
		&servicediscoveryres->EnergyTransferServiceList,
		tvb, pinfo, subtree,
		ett_v2giso2_struct_iso2ServiceListType,
		"EnergyTransferServiceList");

	if (servicediscoveryres->VASList_isUsed) {
		dissect_v2giso2_servicelist(
			&servicediscoveryres->VASList,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2ServiceListType,
			"VASList");
	}

	return;
}

static void
dissect_v2giso2_sessionsetupreq(
	const struct iso2SessionSetupReqType *sessionsetupreq,
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
		hf_v2giso2_struct_iso2SessionSetupReqType_EVCCID,
		tvb,
		sessionsetupreq->EVCCID.bytes,
		sessionsetupreq->EVCCID.bytesLen,
		sizeof(sessionsetupreq->EVCCID.bytes));

	return;
}

static void
dissect_v2giso2_sessionsetupres(
	const struct iso2SessionSetupResType *sessionsetupres,
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
		hf_v2giso2_struct_iso2SessionSetupResType_ResponseCode,
		tvb, 0, 0, sessionsetupres->ResponseCode);
	proto_item_set_generated(it);

	if (sessionsetupres->EVSEStatus_isUsed) {
		dissect_v2giso2_evsestatus(
			&sessionsetupres->EVSEStatus,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2EVSEStatusType,
			"EVSEStatus");
	}

	exi_add_characters(subtree,
		hf_v2giso2_struct_iso2SessionSetupResType_EVSEID,
		tvb,
		sessionsetupres->EVSEID.characters,
		sessionsetupres->EVSEID.charactersLen,
		sizeof(sessionsetupres->EVSEID.characters));

	if (sessionsetupres->EVSETimeStamp_isUsed) {
		it = proto_tree_add_int64(subtree,
			hf_v2giso2_struct_iso2SessionSetupResType_EVSETimeStamp,
			tvb, 0, 0, sessionsetupres->EVSETimeStamp);
		proto_item_set_generated(it);
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

	if (body->DisconnectChargingDeviceReq_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO,
			"DisconnectChargingDeviceReq");
		dissect_v2giso2_disconnectchargingdevicereq(
			&body->DisconnectChargingDeviceReq,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2DisconnectChargingDeviceReqType,
			"DisconnectChargingDeviceReq");
	}
	if (body->DisconnectChargingDeviceRes_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO,
			"DisconnectChargingDeviceRes");
		dissect_v2giso2_disconnectchargingdeviceres(
			&body->DisconnectChargingDeviceRes,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2DisconnectChargingDeviceResType,
			"DisconnectChargingDeviceRes");
	}

	if (body->ConnectChargingDeviceReq_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO,
			"ConnectChargingDeviceReq");
		dissect_v2giso2_connectchargingdevicereq(
			&body->ConnectChargingDeviceReq,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2ConnectChargingDeviceReqType,
			"ConnectChargingDeviceReq");
	}
	if (body->ConnectChargingDeviceRes_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO,
			"ConnectChargingDeviceReq");
		dissect_v2giso2_connectchargingdeviceres(
			&body->ConnectChargingDeviceRes,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2ConnectChargingDeviceResType,
			"ConnectChargingDeviceRes");
	}

	if (body->SystemStatusReq_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO,
			"SystemStatusReq");
		dissect_v2giso2_systemstatusreq(
			&body->SystemStatusReq,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2SystemStatusReqType,
			"SystemStatusReq");
	}
	if (body->SystemStatusRes_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO,
			"SystemStatusRes");
		dissect_v2giso2_systemstatusres(
			&body->SystemStatusRes,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2SystemStatusResType,
			"SystemStatusRes");
	}

	if (body->DC_BidirectionalControlReq_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO,
			"DC_BidirectionalControlReq");
		dissect_v2giso2_dc_bidirectionalcontrolreq(
			&body->DC_BidirectionalControlReq,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2DC_BidirectionalControlReqType,
			"DC_BidirectionalControlReq");
	}
	if (body->DC_BidirectionalControlRes_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO,
			"DC_BidirectionalControlRes");
		dissect_v2giso2_dc_bidirectionalcontrolres(
			&body->DC_BidirectionalControlRes,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2DC_BidirectionalControlResType,
			"DC_BidirectionalControlRes");
	}

	if (body->AC_BidirectionalControlReq_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO,
			"AC_BidirectionalControlReq");
		dissect_v2giso2_ac_bidirectionalcontrolreq(
			&body->AC_BidirectionalControlReq,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2AC_BidirectionalControlReqType,
			"AC_BidirectionalControlReq");
	}
	if (body->AC_BidirectionalControlRes_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO,
			"AC_BidirectionalControlRes");
		dissect_v2giso2_ac_bidirectionalcontrolres(
			&body->AC_BidirectionalControlRes,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2AC_BidirectionalControlResType,
			"AC_BidirectionalControlRes");
	}

	if (body->VehicleCheckOutReq_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO,
			"VehicleCheckOutReq");
		dissect_v2giso2_vehiclecheckoutreq(
			&body->VehicleCheckOutReq,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2VehicleCheckOutReqType,
			"VehicleCheckOutReq");
	}
	if (body->VehicleCheckOutRes_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO,
			"VehicleCheckOutRes");
		dissect_v2giso2_vehiclecheckoutres(
			&body->VehicleCheckOutRes,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2VehicleCheckOutResType,
			"VehicleCheckOutRes");
	}

	if (body->VehicleCheckInReq_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO,
			"VehicleCheckInReq");
		dissect_v2giso2_vehiclecheckinreq(
			&body->VehicleCheckInReq,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2VehicleCheckInReqType,
			"VehicleCheckInReq");
	}
	if (body->VehicleCheckInRes_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO,
			"VehicleCheckInRes");
		dissect_v2giso2_vehiclecheckinres(
			&body->VehicleCheckInRes,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2VehicleCheckInResType,
			"VehicleCheckInRes");
	}

	if (body->PowerDemandReq_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO,
			"PowerDemandReq");
		dissect_v2giso2_powerdemandreq(
			&body->PowerDemandReq,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2PowerDemandReqType,
			"PowerDemandReq");
	}
	if (body->PowerDemandRes_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO,
			"PowerDemandRes");
		dissect_v2giso2_powerdemandres(
			&body->PowerDemandRes,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2PowerDemandResType,
			"PowerDemandRes");
	}

	if (body->PairingReq_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO,
			"PairingReq");
		dissect_v2giso2_pairingreq(
			&body->PairingReq,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2PairingReqType,
			"PairingReq");
	}
	if (body->PairingRes_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO,
			"PairingRes");
		dissect_v2giso2_pairingres(
			&body->PairingRes,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2PairingResType,
			"PairingRes");
	}

	if (body->AlignmentCheckReq_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO,
			"AlignmentCheckReq");
		dissect_v2giso2_alignmentcheckreq(
			&body->AlignmentCheckReq,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2AlignmentCheckReqType,
			"AlignmentCheckReq");
	}
	if (body->AlignmentCheckRes_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO,
			"AlignmentCheckRes");
		dissect_v2giso2_alignmentcheckres(
			&body->AlignmentCheckRes,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2AlignmentCheckResType,
			"AlignmentCheckRes");
	}

	if (body->FinePositioningReq_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO,
			"FinePositioningReq");
		dissect_v2giso2_finepositioningreq(
			&body->FinePositioningReq,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2FinePositioningReqType,
			"FinePositioningReq");
	}
	if (body->FinePositioningRes_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO,
			"FinePositioningRes");
		dissect_v2giso2_finepositioningres(
			&body->FinePositioningRes,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2FinePositioningResType,
			"FinePositioningRes");
	}

	if (body->FinePositioningSetupReq_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO,
			"FinePositioningSetupReq");
		dissect_v2giso2_finepositioningsetupreq(
			&body->FinePositioningSetupReq,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2FinePositioningSetupReqType,
			"FinePositioningSetupReq");
	}
	if (body->FinePositioningSetupRes_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO,
			"FinePositioningSetupRes");
		dissect_v2giso2_finepositioningsetupres(
			&body->FinePositioningSetupRes,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2FinePositioningSetupResType,
			"FinePositioningSetupRes");
	}

	if (body->WeldingDetectionReq_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO,
			"WeldingDetectionReq");
		dissect_v2giso2_weldingdetectionreq(
			&body->WeldingDetectionReq,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2WeldingDetectionReqType,
			"WeldingDetectionReq");
	}
	if (body->WeldingDetectionRes_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO,
			"WeldingDetectionRes");
		dissect_v2giso2_weldingdetectionres(
			&body->WeldingDetectionRes,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2WeldingDetectionResType,
			"WeldingDetectionRes");
	}

	if (body->CurrentDemandReq_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO,
			"CurrentDemandReq");
		dissect_v2giso2_currentdemandreq(
			&body->CurrentDemandReq,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2CurrentDemandReqType,
			"CurrentDemandReq");
	}
	if (body->CurrentDemandRes_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO,
			"CurrentDemandRes");
		dissect_v2giso2_currentdemandres(
			&body->CurrentDemandRes,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2CurrentDemandResType,
			"CurrentDemandRes");
	}

	if (body->PreChargeReq_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO,
			"PreChargeReq");
		dissect_v2giso2_prechargereq(
			&body->PreChargeReq,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2PreChargeReqType,
			"PreChargeReq");
	}
	if (body->PreChargeRes_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO,
			"PreChargeRes");
		dissect_v2giso2_prechargeres(
			&body->PreChargeRes,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2PreChargeResType,
			"PreChargeRes");
	}

	if (body->CableCheckReq_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO,
			"CableCheckReq");
		dissect_v2giso2_cablecheckreq(
			&body->CableCheckReq,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2CableCheckReqType,
			"CableCheckReq");
	}
	if (body->CableCheckRes_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO,
			"CableCheckRes");
		dissect_v2giso2_cablecheckres(
			&body->CableCheckRes,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2CableCheckResType,
			"CableCheckRes");
	}

	if (body->ChargingStatusReq_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO,
			"ChargingStatusReq");
		dissect_v2giso2_chargingstatusreq(
			&body->ChargingStatusReq,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2ChargingStatusReqType,
			"ChargingStatusReq");
	}
	if (body->ChargingStatusRes_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO,
			"ChargingStatusRes");
		dissect_v2giso2_chargingstatusres(
			&body->ChargingStatusRes,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2ChargingStatusResType,
			"ChargingStatusRes");
	}

	if (body->CertificateInstallationReq_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO,
			"CertificateInstallationReq");
		dissect_v2giso2_certificateinstallationreq(
			&body->CertificateInstallationReq,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2CertificateInstallationReqType,
			"CertificateInstallationReq");
	}
	if (body->CertificateInstallationRes_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO,
			"CertificateInstallationRes");
		dissect_v2giso2_certificateinstallationres(
			&body->CertificateInstallationRes,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2CertificateInstallationResType,
			"CertificateInstallationRes");
	}

	if (body->CertificateUpdateReq_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO,
			"CertificateUpdateReq");
		dissect_v2giso2_certificateupdatereq(
			&body->CertificateUpdateReq,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2CertificateUpdateReqType,
			"CertificateUpdateReq");
	}
	if (body->CertificateUpdateRes_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO,
			"CertificateUpdateRes");
		dissect_v2giso2_certificateupdateres(
			&body->CertificateUpdateRes,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2CertificateUpdateResType,
			"CertificateUpdateRes");
	}

	if (body->SessionStopReq_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO,
			"SessionStopReq");
		dissect_v2giso2_sessionstopreq(
			&body->SessionStopReq,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2SessionStopReqType,
			"SessionStopReq");
	}
	if (body->SessionStopRes_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO,
			"SessionStopRes");
		dissect_v2giso2_sessionstopres(
			&body->SessionStopRes,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2SessionStopResType,
			"SessionStopRes");
	}

	if (body->MeteringReceiptReq_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO,
			"MeteringReceiptReq");
		dissect_v2giso2_meteringreceiptreq(
			&body->MeteringReceiptReq,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2MeteringReceiptReqType,
			"MeteringReceiptReq");
	}
	if (body->MeteringReceiptRes_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO,
			"MeteringReceiptRes");
		dissect_v2giso2_meteringreceiptres(
			&body->MeteringReceiptRes,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2MeteringReceiptResType,
			"MeteringReceiptRes");
	}

	if (body->PowerDeliveryReq_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO,
			"PowerDeliveryReq");
		dissect_v2giso2_powerdeliveryreq(
			&body->PowerDeliveryReq,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2PowerDeliveryReqType,
			"PowerDeliveryReq");
	}
	if (body->PowerDeliveryRes_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO,
			"PowerDeliveryRes");
		dissect_v2giso2_powerdeliveryres(
			&body->PowerDeliveryRes,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2PowerDeliveryResType,
			"PowerDeliveryRes");
	}

	if (body->ChargeParameterDiscoveryReq_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO,
			"ChargeParameterDiscoveryReq");
		dissect_v2giso2_chargeparameterdiscoveryreq(
			&body->ChargeParameterDiscoveryReq,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2ChargeParameterDiscoveryReqType,
			"ChargeParameterDiscoveryReq");
	}
	if (body->ChargeParameterDiscoveryRes_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO,
			"ChargeParameterDiscoveryRes");
		dissect_v2giso2_chargeparameterdiscoveryres(
			&body->ChargeParameterDiscoveryRes,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2ChargeParameterDiscoveryResType,
			"ChargeParameterDiscoveryRes");
	}

	if (body->AuthorizationReq_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO,
			"AuthorizationReq");
		dissect_v2giso2_authorizationreq(
			&body->AuthorizationReq,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2AuthorizationReqType,
			"AuthorizationReq");
	}
	if (body->AuthorizationRes_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO,
			"AuthorizationRes");
		dissect_v2giso2_authorizationres(
			&body->AuthorizationRes,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2AuthorizationResType,
			"AuthorizationRes");
	}

	if (body->PaymentDetailsReq_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO,
			"PaymentDetailsReq");
		dissect_v2giso2_paymentdetailsreq(
			&body->PaymentDetailsReq,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2PaymentDetailsReqType,
			"PaymentDetailsReq");
	}
	if (body->PaymentDetailsRes_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO,
			"PaymentDetailsRes");
		dissect_v2giso2_paymentdetailsres(
			&body->PaymentDetailsRes,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2PaymentDetailsResType,
			"PaymentDetailsRes");
	}

	if (body->PaymentServiceSelectionReq_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO,
			"PaymentServiceSelectionReq");
		dissect_v2giso2_paymentserviceselectionreq(
			&body->PaymentServiceSelectionReq,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2PaymentServiceSelectionReqType,
			"PaymentServiceSelectionReq");
	}
	if (body->PaymentServiceSelectionRes_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO,
			"PaymentServiceSelectionRes");
		dissect_v2giso2_paymentserviceselectionres(
			&body->PaymentServiceSelectionRes,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2PaymentServiceSelectionResType,
			"PaymentServiceSelectionRes");
	}

	if (body->ServiceDetailReq_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO,
			"ServiceDetailReq");
		dissect_v2giso2_servicedetailreq(
			&body->ServiceDetailReq,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2ServiceDetailReqType,
			"ServiceDetailReq");
	}
	if (body->ServiceDetailRes_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO,
			"ServiceDetailRes");
		dissect_v2giso2_servicedetailres(
			&body->ServiceDetailRes,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2ServiceDetailResType,
			"ServiceDetailRes");
	}

	if (body->ServiceDiscoveryReq_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO,
			"ServiceDiscoveryReq");
		dissect_v2giso2_servicediscoveryreq(
			&body->ServiceDiscoveryReq,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2ServiceDiscoveryReqType,
			"ServiceDiscoveryReq");
	}
	if (body->ServiceDiscoveryRes_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO,
			"ServiceDiscoveryRes");
		dissect_v2giso2_servicediscoveryres(
			&body->ServiceDiscoveryRes,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2ServiceDiscoveryResType,
			"ServiceDiscoveryRes");
	}

	if (body->SessionSetupReq_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO,
			"SessionSetupReq");
		dissect_v2giso2_sessionsetupreq(
			&body->SessionSetupReq,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2SessionSetupReqType,
			"SessionSetupReq");
	}
	if (body->SessionSetupRes_isUsed) {
		col_append_str(pinfo->cinfo, COL_INFO,
			"SessionSetupRes");
		dissect_v2giso2_sessionsetupres(
			&body->SessionSetupRes,
			tvb, pinfo, subtree,
			ett_v2giso2_struct_iso2SessionSetupResType,
			"SessionSetupRes");
	}

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
		},

		/* struct iso2EVSEStatusType */
		{ &hf_v2giso2_struct_iso2EVSEStatusType_NotificationMaxDelay,
		  { "NotificationMaxDelay",
		    "v2giso2.struct.evsestatus.notificationmaxdelay",
		    FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2EVSEStatusType_EVSENotification,
		  { "EVSENotification",
		    "v2giso2.struct.evsestatus.evsenotification",
		    FT_UINT16, BASE_DEC,
		    VALS(v2giso2_enum_iso2EVSENotificationType_names),
		    0x0, NULL, HFILL }
		},

		/* struct iso2PhysicalValueType */
		{ &hf_v2giso2_struct_iso2PhysicalValueType_Exponent,
		  { "Exponent", "v2giso2.struct.physicalvalue.exponent",
		    FT_INT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2PhysicalValueType_Value,
		  { "Value", "v2giso2.struct.physicalvalue.value",
		    FT_INT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso2DisplayParametersType */
		{ &hf_v2giso2_struct_iso2DisplayParametersType_CurrentRange,
		  { "CurrentRange",
		    "v2giso2.struct.displayparameters.currentrange",
		    FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2DisplayParametersType_CurrentSOC,
		  { "CurrentSOC",
		    "v2giso2.struct.displayparameters.currentsoc",
		    FT_INT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2DisplayParametersType_TargetSOC,
		  { "TargetSOC",
		    "v2giso2.struct.displayparameters.targetsoc",
		    FT_INT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2DisplayParametersType_BulkSOC,
		  { "BulkSOC",
		    "v2giso2.struct.displayparameters.bulksoc",
		    FT_INT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2DisplayParametersType_MinimumSOC,
		  { "MinimumSOC",
		    "v2giso2.struct.displayparameters.minimumsoc",
		    FT_INT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2DisplayParametersType_RemainingTimeToTargetSOC,
		  { "RemainingTimeToTargetSOC",
		    "v2giso2.struct.displayparameters.remainingtimetotargetsoc",
		    FT_INT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2DisplayParametersType_RemainingTimeToBulkSOC,
		  { "RemainingTimeToBulkSOC",
		    "v2giso2.struct.displayparameters.remainingtimetobulksoc",
		    FT_INT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2DisplayParametersType_RemainingTimeToMinimumSOC,
		  { "RemainingTimeToMinimumSOC",
		    "v2giso2.struct.displayparameters.remainingtimetominimumsoc",
		    FT_INT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2DisplayParametersType_ChargingComplete,
		  { "ChargingComplete",
		    "v2giso2.struct.displayparameters.chargingcomplete",
		    FT_INT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2DisplayParametersType_BulkChargingComplete,
		  { "BulkChargingComplete",
		    "v2giso2.struct.displayparameters.bulkchargingcomplete",
		    FT_INT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2DisplayParametersType_InletHot,
		  { "InletHot", "v2giso2.struct.displayparameters.inlethot",
		    FT_INT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso2MeterInfoType */
		{ &hf_v2giso2_struct_iso2MeterInfoType_MeterID,
		  { "MeterID", "v2giso2.struct.meterinfo.meterid",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2MeterInfoType_MeterReadingCharged,
		  { "MeterReading", "v2giso2.struct.meterinfo.meterreadingcharged",
		    FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2MeterInfoType_MeterReadingDischarged,
		  { "MeterReading", "v2giso2.struct.meterinfo.meterreadingdischarged",
		    FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2MeterInfoType_SigMeterReading,
		  { "SigMeterReading",
		    "v2giso2.struct.meterinfo.sigmeterreading",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2MeterInfoType_MeterStatus,
		  { "MeterStatus", "v2giso2.struct.meterinfo.meterstatus",
		    FT_INT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2MeterInfoType_TMeter,
		  { "TMeter", "v2giso2.struct.meterinfo.tmeter",
		    FT_INT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso2TargetPositionType */
		{ &hf_v2giso2_struct_iso2TargetPositionType_TargetOffsetX,
		  { "TargetOffsetX",
		    "v2giso2.struct.targetposition.targetoffsetx",
		    FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2TargetPositionType_TargetOffsetY,
		  { "TargetOffsetY",
		    "v2giso2.struct.targetposition.targetoffsety",
		    FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso2ParameterType */
		{ &hf_v2giso2_struct_iso2ParameterType_Name,
		  { "Name", "v2giso2.struct.parameter.name",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2ParameterType_boolValue,
		  { "boolValue", "v2giso2.struct.parameter.boolvalue",
		    FT_INT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2ParameterType_byteValue,
		  { "byteValue", "v2giso2.struct.parameter.bytevalue",
		    FT_INT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2ParameterType_shortValue,
		  { "shortValue", "v2giso2.struct.parameter.shortvalue",
		    FT_INT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2ParameterType_intValue,
		  { "intValue", "v2giso2.struct.parameter.intvalue",
		    FT_INT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2ParameterType_stringValue,
		  { "stringValue", "v2giso2.struct.parameter.stringvalue",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso2ParameterSetType */
		{ &hf_v2giso2_struct_iso2ParameterSetType_ParameterSetID,
		  { "ParameterSetID",
		    "v2giso2.struct.parameterset.parametersetid",
		    FT_INT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso2MeasurementDataListType */
		{ &hf_v2giso2_struct_iso2MeasurementDataListType_MeasurementData,
		  { "MeasurementData",
		    "v2giso2.struct.measurementdatalist.measurementdata",
		    FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso2SensorMeasurementsType */
		{ &hf_v2giso2_struct_iso2SensorMeasurementsType_SensorID,
		  { "SensorID",
		    "v2giso2.struct.sensormeasurements.sensorid",
		    FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2SensorMeasurementsType_EffectiveRadiatedPower,
		  { "EffectiveRadiatedPower",
		    "v2giso2.struct.sensormeasurements.effectiveradiatedpower",
		    FT_INT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso2SensorPackageType */
		{ &hf_v2giso2_struct_iso2SensorPackageType_PackageIndex,
		  { "PackageIndex",
		    "v2giso2.struct.sensorpackage.packageindex",
		    FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso2CartesianCoordinatesType */
		{ &hf_v2giso2_struct_iso2CartesianCoordinatesType_XCoordinate,
		  { "XCoordinate",
		    "v2giso2.struct.cartesiancoordinates.xcoordinate",
		    FT_INT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2CartesianCoordinatesType_YCoordinate,
		  { "XCoordinate",
		    "v2giso2.struct.cartesiancoordinates.ycoordinate",
		    FT_INT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2CartesianCoordinatesType_ZCoordinate,
		  { "XCoordinate",
		    "v2giso2.struct.cartesiancoordinates.zcoordinate",
		    FT_INT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso2SensorType */
		{ &hf_v2giso2_struct_iso2SensorType_SensorID,
		  { "SensorID",
		    "v2giso2.struct.sensor.sensorid",
		    FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso2SensorOrderListType */
		{ &hf_v2giso2_struct_iso2SensorOrderListType_SensorPosition,
		  { "SensorPosition",
		    "v2giso2.struct.sensororderlist.sensorposition",
		    FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso2MagneticVectorType */
		{ &hf_v2giso2_struct_iso2MagneticVectorType_GAID,
		  { "GAID",
		    "v2giso2.struct.magneticvector.gaid",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2MagneticVectorType_Distance,
		  { "Distance",
		    "v2giso2.struct.magneticvector.distance",
		    FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2MagneticVectorType_FODStatus,
		  { "FODStatus",
		    "v2giso2.struct.magneticvector.fodstatus",
		    FT_UINT16, BASE_DEC,
		    VALS(v2giso2_enum_iso2FODStatusType_names),
		    0x0, NULL, HFILL }
		},

		/* struct iso2MagneticVectorSetupType */
		{ &hf_v2giso2_struct_iso2MagneticVectorSetupType_GAID,
		  { "GAID",
		    "v2giso2.struct.magneticvectorsetup.gaid",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2MagneticVectorSetupType_FrequencyChannel,
		  { "FrequencyChannel",
		    "v2giso2.struct.magneticvectorsetup.frequencychannel",
		    FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso2LFA_EVFinePositioningParametersType */
		{ &hf_v2giso2_struct_iso2LFA_EVFinePositioningParametersType_NumberOfSignalPackages,
		  { "NumberOfSignalPackages",
		    "v2giso2.struct.lfa_evfinepositioningparameters.numberofsignalpackages",
		    FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso2LFA_EVSEFinePositioningParametersType */
		{ &hf_v2giso2_struct_iso2LFA_EVSEFinePositioningParametersType_NumberOfSignalPackages,
		  { "NumberOfSignalPackages",
		    "v2giso2.struct.lfa_evsefinepositioningparameters.numberofsignalpackages",
		    FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},

		/* struct EVFinePositioningSetupParametersType */
		{ &hf_v2giso2_struct_iso2LFA_EVFinePositioningSetupParametersType_NumberOfSensors,
		  { "NumberOfSensors",
		    "v2giso2.struct.lfa_evfinepositioningsetupparameters.numberofsensors",
		    FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2LFA_EVFinePositioningSetupParametersType_SignalPulseDuration,
		  { "SignalPulseDuration",
		    "v2giso2.struct.lfa_evfinepositioningsetupparameters.signalpulseduration",
		    FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2LFA_EVFinePositioningSetupParametersType_SignalSeparationTime,
		  { "SignalSeparationTime",
		    "v2giso2.struct.lfa_evfinepositioningsetupparameters.signalseparationtime",
		    FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2LFA_EVFinePositioningSetupParametersType_PackageSeparationTime,
		  { "PackageSeparationTime",
		    "v2giso2.struct.lfa_evfinepositioningsetupparameters.packageseparationtime",
		    FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2LFA_EVFinePositioningSetupParametersType_AlignmentOffset,
		  { "AlignmentOffset",
		    "v2giso2.struct.lfa_evfinepositioningsetupparameters.alignmentoffset",
		    FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso2LFA_EVSEFinePositioningSetupParametersType */
		{ &hf_v2giso2_struct_iso2LFA_EVSEFinePositioningSetupParametersType_NumberOfSensors,
		  { "NumberOfSensors",
		    "v2giso2.struct.lfa_evsefinepositioningsetupparameters.numberofsensors",
		    FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2LFA_EVSEFinePositioningSetupParametersType_SignalPulseDuration,
		  { "SignalPulseDuration",
		    "v2giso2.struct.lfa_evsefinepositioningsetupparameters.signalpulseduration",
		    FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2LFA_EVSEFinePositioningSetupParametersType_SignalSeparationTime,
		  { "SignalSeparationTime",
		    "v2giso2.struct.lfa_evsefinepositioningsetupparameters.signalseparationtime",
		    FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2LFA_EVSEFinePositioningSetupParametersType_PackageSeparationTime,
		  { "PackageSeparationTime",
		    "v2giso2.struct.lfa_evsefinepositioningsetupparameters.packageseparationtime",
		    FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2LFA_EVSEFinePositioningSetupParametersType_AlignmentOffset,
		  { "AlignmentOffset",
		    "v2giso2.struct.lfa_evsefinepositioningsetupparameters.alignmentoffset",
		    FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2LFA_EVSEFinePositioningSetupParametersType_SignalFrequency,
		  { "SignalFrequency",
		    "v2giso2.struct.lfa_evsefinepositioningsetupparameters.signalfrequency",
		    FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso2MV_EVSEFinePositioningSetupParametersType */
		{ &hf_v2giso2_struct_iso2MV_EVSEFinePositioningSetupParametersType_FrequencyChannel,
		  { "FrequencyChannel",
		    "v2giso2.struct.lfa_evsefinepositioningsetupparameters.frequencychannel",
		    FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso2SubCertificatesType */
		{ &hf_v2giso2_struct_iso2SubCertificatesType_Certificate,
		  { "Certificate",
		    "v2giso2.struct.subcertificates.certificate",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso2CertificateChainType */
		{ &hf_v2giso2_struct_iso2CertificateChainType_Id,
		  { "Id", "v2giso2.struct.certificatechain.id",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2CertificateChainType_Certificate,
		  { "Certificate",
		    "v2giso2.struct.certificatechain.certificate",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso2ContractSignatureEncryptedPrivateKeyType */
		{ &hf_v2giso2_struct_iso2ContractSignatureEncryptedPrivateKeyType_Id,
		  { "Id",
		    "v2giso2.struct.contractsignatureencryptedprivatekey.id",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2ContractSignatureEncryptedPrivateKeyType_CONTENT,
		  { "CONTENT",
		    "v2giso2.struct.contractsignatureencryptedprivatekey.content",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso2DiffieHellmanPublickeyType */
		{ &hf_v2giso2_struct_iso2DiffieHellmanPublickeyType_Id,
		  { "Id", "v2giso2.struct.diffiehellmanpublickey.id",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2DiffieHellmanPublickeyType_CONTENT,
		  { "CONTENT", "v2giso2.struct.diffiehellmanpublickey.content",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso2EMAIDType */
		{ &hf_v2giso2_struct_iso2EMAIDType_Id,
		  { "Id", "v2giso2.struct.emaid.id",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2EMAIDType_CONTENT,
		  { "CONTENT", "v2giso2.struct.emaid.content",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso2RelativeTimeIntervalType */
		{ &hf_v2giso2_struct_iso2RelativeTimeIntervalType_start,
		  { "start",
		    "v2giso2.struct.relativetimeinterval.start",
		    FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2RelativeTimeIntervalType_duration,
		  { "duration",
		    "v2giso2.struct.relativetimeinterval.start",
		    FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso2DisconnectChargingDeviceReqType */
		{ &hf_v2giso2_struct_iso2DisconnectChargingDeviceReqType_EVElectricalChargingDeviceStatus,
		  { "EVElectricalChargingDeviceStatus",
		    "v2giso2.struct.disconnectchargingdevicereq.evelectricalchargingdevicestatus",
		    FT_UINT16, BASE_DEC,
		    VALS(v2giso2_enum_iso2electricalChargingDeviceStatusType_names),
		    0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2DisconnectChargingDeviceReqType_EVMechanicalChargingDeviceStatus,
		  { "EVMechanicalChargingDeviceStatus",
		    "v2giso2.struct.disconnectchargingdevicereq.evmechanicalchargingdevicestatus",
		    FT_UINT16, BASE_DEC,
		    VALS(v2giso2_enum_iso2mechanicalChargingDeviceStatusType_names),
		    0x0, NULL, HFILL }
		},
		/* struct iso2DisconnectChargingDeviceResType */
		{ &hf_v2giso2_struct_iso2DisconnectChargingDeviceResType_ResponseCode,
		  { "ResponseCode",
		    "v2giso2.struct.disconnectchargingdeviceres.responsecode",
		    FT_UINT16, BASE_DEC,
		    VALS(v2giso2_enum_iso2responseCodeType_names),
		    0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2DisconnectChargingDeviceResType_EVSEProcessing,
		  { "EVSEProcessing",
		    "v2giso2.struct.disconnectchargingdeviceres.evseprocessing",
		    FT_UINT16, BASE_DEC,
		    VALS(v2giso2_enum_iso2EVSEProcessingType_names),
		    0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2DisconnectChargingDeviceResType_EVSEElectricalChargingDeviceStatus,
		  { "EVSEElectricalChargingDeviceStatus",
		    "v2giso2.struct.disconnectchargingdeviceres.evseelectricalchargingdevicestatus",
		    FT_UINT16, BASE_DEC,
		    VALS(v2giso2_enum_iso2electricalChargingDeviceStatusType_names),
		    0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2DisconnectChargingDeviceResType_EVSEMechanicalChargingDeviceStatus,
		  { "EVSEMechanicalChargingDeviceStatus",
		    "v2giso2.struct.disconnectchargingdeviceres.evsmechanicalchargingdevicestatus",
		    FT_UINT16, BASE_DEC,
		    VALS(v2giso2_enum_iso2mechanicalChargingDeviceStatusType_names),
		    0x0, NULL, HFILL }
		},

		/* struct iso2ConnectChargingDeviceReqType */
		{ &hf_v2giso2_struct_iso2ConnectChargingDeviceReqType_EVElectricalChargingDeviceStatus,
		  { "EVElectricalChargingDeviceStatus",
		    "v2giso2.struct.connectchargingdevicereq.evelectricalchargingdevicestatus",
		    FT_UINT16, BASE_DEC,
		    VALS(v2giso2_enum_iso2electricalChargingDeviceStatusType_names),
		    0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2ConnectChargingDeviceReqType_EVMechanicalChargingDeviceStatus,
		  { "EVMechanicalChargingDeviceStatus",
		    "v2giso2.struct.connectchargingdevicereq.evmechanicalchargingdevicestatus",
		    FT_UINT16, BASE_DEC,
		    VALS(v2giso2_enum_iso2mechanicalChargingDeviceStatusType_names),
		    0x0, NULL, HFILL }
		},
		/* struct iso2ConnectChargingDeviceResType */
		{ &hf_v2giso2_struct_iso2ConnectChargingDeviceResType_ResponseCode,
		  { "ResponseCode",
		    "v2giso2.struct.connectchargingdeviceres.responsecode",
		    FT_UINT16, BASE_DEC,
		    VALS(v2giso2_enum_iso2responseCodeType_names),
		    0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2ConnectChargingDeviceResType_EVSEProcessing,
		  { "EVSEProcessing",
		    "v2giso2.struct.connectchargingdeviceres.evseprocessing",
		    FT_UINT16, BASE_DEC,
		    VALS(v2giso2_enum_iso2EVSEProcessingType_names),
		    0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2ConnectChargingDeviceResType_EVSEElectricalChargingDeviceStatus,
		  { "EVSEElectricalChargingDeviceStatus",
		    "v2giso2.struct.connectchargingdeviceres.evseelectricalchargingdevicestatus",
		    FT_UINT16, BASE_DEC,
		    VALS(v2giso2_enum_iso2electricalChargingDeviceStatusType_names),
		    0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2ConnectChargingDeviceResType_EVSEMechanicalChargingDeviceStatus,
		  { "EVSEMechanicalChargingDeviceStatus",
		    "v2giso2.struct.connectchargingdeviceres.evsmechanicalchargingdevicestatus",
		    FT_UINT16, BASE_DEC,
		    VALS(v2giso2_enum_iso2mechanicalChargingDeviceStatusType_names),
		    0x0, NULL, HFILL }
		},

		/* struct iso2SystemStatusReqType */
		{ &hf_v2giso2_struct_iso2SystemStatusReqType_OperationMode,
		  { "OperationMode",
		    "v2giso2.struct.systemstatusreq.operationmode",
		    FT_UINT16, BASE_DEC,
		    VALS(v2giso2_enum_iso2operationModeType_names),
		    0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2SystemStatusReqType_EVMechanicalChargingDeviceStatus,
		  { "EVMechanicalChargingDeviceStatus",
		    "v2giso2.struct.systemstatusreq.evmechanicalchargingdevicestatus",
		    FT_UINT16, BASE_DEC,
		    VALS(v2giso2_enum_iso2mechanicalChargingDeviceStatusType_names),
		    0x0, NULL, HFILL }
		},
		/* struct iso2SystemStatusResType */
		{ &hf_v2giso2_struct_iso2SystemStatusResType_ResponseCode,
		  { "ResponseCode",
		    "v2giso2.struct.systemstatusres.responsecode",
		    FT_UINT16, BASE_DEC,
		    VALS(v2giso2_enum_iso2responseCodeType_names),
		    0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2SystemStatusResType_OperationMode,
		  { "OperationMode",
		    "v2giso2.struct.systemstatusres.operationmode",
		    FT_UINT16, BASE_DEC,
		    VALS(v2giso2_enum_iso2operationModeType_names),
		    0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2SystemStatusResType_EVSEMechanicalChargingDeviceStatus,
		  { "EVSEMechanicalChargingDeviceStatus",
		    "v2giso2.struct.systemstatusres.evsemechanicalchargingdevicestatus",
		    FT_UINT16, BASE_DEC,
		    VALS(v2giso2_enum_iso2mechanicalChargingDeviceStatusType_names),
		    0x0, NULL, HFILL }
		},

		/* struct iso2DC_BidirectionalControlReqType */
		/* struct iso2DC_BidirectionalControlResType */
		{ &hf_v2giso2_struct_iso2DC_BidirectionalControlResType_ResponseCode,
		  { "ResponseCode",
		    "v2giso2.struct.dc_bidirectionalcontrolres.responsecode",
		    FT_UINT16, BASE_DEC,
		    VALS(v2giso2_enum_iso2responseCodeType_names),
		    0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2DC_BidirectionalControlResType_EVSEPowerLimitAchieved,
		  { "EVSEPowerLimitAchieved",
		    "v2giso2.struct.dc_bidirectionalcontrolres.evsepowerlimitachieved",
		    FT_INT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2DC_BidirectionalControlResType_EVSECurrentLimitAchieved,
		  { "EVSECurrentLimitAchieved",
		    "v2giso2.struct.dc_bidirectionalcontrolres.evsecurrentlimitachieved",
		    FT_INT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2DC_BidirectionalControlResType_EVSEVoltageLimitAchieved,
		  { "EVSEVoltageLimitAchieved",
		    "v2giso2.struct.dc_bidirectionalcontrolres.evsevoltagelimitachieved",
		    FT_INT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2DC_BidirectionalControlResType_EVSEID,
		  { "EVSEID",
		    "v2giso2.struct.dc_bidirectionalcontrolres.evseid",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2DC_BidirectionalControlResType_ReceiptRequired,
		  { "ReceiptRequired",
		    "v2giso2.struct.dc_bidirectionalcontrolres.receiptrequired",
		    FT_INT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso2AC_BidirectionalControlReqType */
		{ &hf_v2giso2_struct_iso2AC_BidirectionalControlReqType_EVOperation,
		  { "EVOperation",
		    "v2giso2.struct.ac_bidirectionalcontrolreq.evoperation",
		    FT_UINT16, BASE_DEC,
		    VALS(v2giso2_enum_iso2EVOperationType_names),
		    0x0, NULL, HFILL }
		},
		/* struct iso2AC_BidirectionalControlResType */
		{ &hf_v2giso2_struct_iso2AC_BidirectionalControlResType_ResponseCode,
		  { "ResponseCode",
		    "v2giso2.struct.ac_bidirectionalcontrolres.responsecode",
		    FT_UINT16, BASE_DEC,
		    VALS(v2giso2_enum_iso2responseCodeType_names),
		    0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2AC_BidirectionalControlResType_EVSEProcessing,
		  { "EVSEProcessing",
		    "v2giso2.struct.ac_bidirectionalcontrolres.evseprocessing",
		    FT_UINT16, BASE_DEC,
		    VALS(v2giso2_enum_iso2EVSEProcessingType_names),
		    0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2AC_BidirectionalControlResType_EVSEID,
		  { "EVSEID",
		    "v2giso2.struct.ac_bidirectionalcontrolres.evseid",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2AC_BidirectionalControlResType_SAScheduleTupleID,
		  { "SAScheduleTupleID",
		    "v2giso2.struct.ac_bidirectionalcontrolres.sascheduletupleid",
		    FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2AC_BidirectionalControlResType_ReceiptRequired,
		  { "ReceiptRequired",
		    "v2giso2.struct.ac_bidirectionalcontrolres.receiptrequired",
		    FT_INT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso2VehicleCheckOutReqType */
		{ &hf_v2giso2_struct_iso2VehicleCheckOutReqType_EVCheckOutStatus,
		  { "EVCheckOutStatus",
		    "v2giso2.struct.vehichlecheckoutreq.evcheckoutstatus",
		    FT_UINT16, BASE_DEC,
		    VALS(v2giso2_enum_iso2EVCheckOutStatusType_names),
		    0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2VehicleCheckOutReqType_CheckOutTime,
		  { "CheckOutTime",
		    "v2giso2.struct.vehichlecheckoutreq.checkouttime",
		    FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		/* struct iso2VehicleCheckOutResType */
		{ &hf_v2giso2_struct_iso2VehicleCheckOutResType_ResponseCode,
		  { "ResponseCode",
		    "v2giso2.struct.vehichlecheckoutres.responsecode",
		    FT_UINT16, BASE_DEC,
		    VALS(v2giso2_enum_iso2responseCodeType_names),
		    0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2VehicleCheckOutResType_EVSECheckOutStatus,
		  { "EVSECheckOutStatus",
		    "v2giso2.struct.vehichlecheckoutres.evsecheckoutstatus",
		    FT_UINT16, BASE_DEC,
		    VALS(v2giso2_enum_iso2EVSECheckOutStatusType_names),
		    0x0, NULL, HFILL }
		},

		/* struct iso2VehicleCheckInReqType */
		{ &hf_v2giso2_struct_iso2VehicleCheckInReqType_EVCheckInStatus,
		  { "EVCheckInStatus",
		    "v2giso2.struct.vehichlecheckinreq.evcheckinstatus",
		    FT_UINT16, BASE_DEC,
		    VALS(v2giso2_enum_iso2EVCheckInStatusType_names),
		    0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2VehicleCheckInReqType_ParkingMethod,
		  { "ParkingMethod",
		    "v2giso2.struct.vehichlecheckinreq.parkingmethod",
		    FT_UINT16, BASE_DEC,
		    VALS(v2giso2_enum_iso2parkingMethodType_names),
		    0x0, NULL, HFILL }
		},
		/* struct iso2VehicleCheckInResType */
		{ &hf_v2giso2_struct_iso2VehicleCheckInResType_ResponseCode,
		  { "ResponseCode",
		    "v2giso2.struct.vehichlecheckinres.responsecode",
		    FT_UINT16, BASE_DEC,
		    VALS(v2giso2_enum_iso2responseCodeType_names),
		    0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2VehicleCheckInResType_VehicleSpace,
		  { "VehicleSpace",
		    "v2giso2.struct.vehichlecheckinres.vehiclespace",
		    FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso2PowerDemandReqType */
		/* struct iso2PowerDemandResType */
		{ &hf_v2giso2_struct_iso2PowerDemandResType_ResponseCode,
		  { "ResponseCode",
		    "v2giso2.struct.powerdemandres.responsecode",
		    FT_UINT16, BASE_DEC,
		    VALS(v2giso2_enum_iso2responseCodeType_names),
		    0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2PowerDemandResType_EVSEID,
		  { "EVSEID",
		    "v2giso2.struct.powerdemandres.evseid",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2PowerDemandResType_SAScheduleTupleID,
		  { "SAScheduleTupleID",
		    "v2giso2.struct.powerdemandres.sascheduletupleid",
		    FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2PowerDemandResType_ReceiptRequired,
		  { "ReceiptRequired",
		    "v2giso2.struct.powerdemandres.receiptrequired",
		    FT_INT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso2PairingReqType */
		{ &hf_v2giso2_struct_iso2PairingReqType_EVProcessing,
		  { "EVProcessing",
		    "v2giso2.struct.pairingreq.evprocessing",
		    FT_UINT16, BASE_DEC,
		    VALS(v2giso2_enum_iso2EVSEProcessingType_names),
		    0x0, NULL, HFILL }
		},
		/* struct iso2PairingResType */
		{ &hf_v2giso2_struct_iso2PairingResType_ResponseCode,
		  { "ResponseCode",
		    "v2giso2.struct.pairingres.responsecode",
		    FT_UINT16, BASE_DEC,
		    VALS(v2giso2_enum_iso2responseCodeType_names),
		    0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2PairingResType_EVSEProcessing,
		  { "EVSEProcessing",
		    "v2giso2.struct.pairingres.evseprocessing",
		    FT_UINT16, BASE_DEC,
		    VALS(v2giso2_enum_iso2EVSEProcessingType_names),
		    0x0, NULL, HFILL }
		},

		/* struct iso2AlignmentCheckReqType */
		{ &hf_v2giso2_struct_iso2AlignmentCheckReqType_EVProcessing,
		  { "EVProcessing",
		    "v2giso2.struct.alignmentcheckreq.evprocessing",
		    FT_UINT16, BASE_DEC,
		    VALS(v2giso2_enum_iso2EVSEProcessingType_names),
		    0x0, NULL, HFILL }
		},
		/* struct iso2AlignmentCheckResType */
		{ &hf_v2giso2_struct_iso2AlignmentCheckResType_ResponseCode,
		  { "ResponseCode",
		    "v2giso2.struct.alignmentcheckres.responsecode",
		    FT_UINT16, BASE_DEC,
		    VALS(v2giso2_enum_iso2responseCodeType_names),
		    0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2AlignmentCheckResType_EVSEProcessing,
		  { "EVSEProcessing",
		    "v2giso2.struct.alignmentcheckres.evseprocessing",
		    FT_UINT16, BASE_DEC,
		    VALS(v2giso2_enum_iso2EVSEProcessingType_names),
		    0x0, NULL, HFILL }
		},

		/* struct iso2FinePositioningReqType */
		{ &hf_v2giso2_struct_iso2FinePositioningReqType_EVProcessing,
		  { "EVProcessing",
		    "v2giso2.struct.finepositioningreq.evprocessing",
		    FT_UINT16, BASE_DEC,
		    VALS(v2giso2_enum_iso2EVSEProcessingType_names),
		    0x0, NULL, HFILL }
		},
		/* struct iso2FinePositioningResType */
		{ &hf_v2giso2_struct_iso2FinePositioningResType_ResponseCode,
		  { "ResponseCode",
		    "v2giso2.struct.finepositioningres.responsecode",
		    FT_UINT16, BASE_DEC,
		    VALS(v2giso2_enum_iso2responseCodeType_names),
		    0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2FinePositioningResType_EVSEProcessing,
		  { "EVSEProcessing",
		    "v2giso2.struct.finepositioningres.evseprocessing",
		    FT_UINT16, BASE_DEC,
		    VALS(v2giso2_enum_iso2EVSEProcessingType_names),
		    0x0, NULL, HFILL }
		},

		/* struct iso2FinePositioningSetupReqType */
		/* struct iso2FinePositioningSetupResType */
		{ &hf_v2giso2_struct_iso2FinePositioningSetupResType_ResponseCode,
		  { "ResponseCode",
		    "v2giso2.struct.finepositioningsetupres.responsecode",
		    FT_UINT16, BASE_DEC,
		    VALS(v2giso2_enum_iso2responseCodeType_names),
		    0x0, NULL, HFILL }
		},

		/* struct iso2WeldingDetectionReqType */
		/* struct iso2WeldingDetectionResType */
		{ &hf_v2giso2_struct_iso2WeldingDetectionResType_ResponseCode,
		  { "ResponseCode",
		    "v2giso2.struct.weldingdetectionres.responsecode",
		    FT_UINT16, BASE_DEC,
		    VALS(v2giso2_enum_iso2responseCodeType_names),
		    0x0, NULL, HFILL }
		},

		/* struct iso2CurrentDemandReqType */
		/* struct iso2CurrentDemandResType */
		{ &hf_v2giso2_struct_iso2CurrentDemandResType_ResponseCode,
		  { "ResponseCode",
		    "v2giso2.struct.currentdemandres.responsecode",
		    FT_UINT16, BASE_DEC,
		    VALS(v2giso2_enum_iso2responseCodeType_names),
		    0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2CurrentDemandResType_EVSEPowerLimitAchieved,
		  { "EVSEPowerLimitAchieved",
		    "v2giso2.struct.currentdemandres.evsepowerlimitachieved",
		    FT_INT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2CurrentDemandResType_EVSECurrentLimitAchieved,
		  { "EVSECurrentLimitAchieved",
		    "v2giso2.struct.currentdemandres.evsecurrentlimitachieved",
		    FT_INT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2CurrentDemandResType_EVSEID,
		  { "EVSEID",
		    "v2giso2.struct.currentdemandres.evseid",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2CurrentDemandResType_SAScheduleTupleID,
		  { "SAScheduleTupleID",
		    "v2giso2.struct.currentdemandres.sascheduletupleid",
		    FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2CurrentDemandResType_ReceiptRequired,
		  { "ReceiptRequired",
		    "v2giso2.struct.currentdemandres.receiptrequired",
		    FT_INT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso2PreChargeReqType */
		/* struct iso2PreChargeResType */

		/* struct iso2CableCheckReqType */
		/* struct iso2CableCheckResType */
		{ &hf_v2giso2_struct_iso2CableCheckResType_ResponseCode,
		  { "ResponseCode",
		    "v2giso2.struct.cablecheckres.responsecode",
		    FT_UINT16, BASE_DEC,
		    VALS(v2giso2_enum_iso2responseCodeType_names),
		    0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2CableCheckResType_EVSEProcessing,
		  { "EVSEProcessing",
		    "v2giso2.struct.cablecheckres.evseprocessing",
		    FT_UINT16, BASE_DEC,
		    VALS(v2giso2_enum_iso2EVSEProcessingType_names),
		    0x0, NULL, HFILL }
		},

		/* struct iso2ChargingStatusReqType */
		/* struct iso2ChargingStatusResType */
		{ &hf_v2giso2_struct_iso2ChargingStatusResType_ResponseCode,
		  { "ResponseCode",
		    "v2giso2.struct.chargingstatusres.responsecode",
		    FT_UINT16, BASE_DEC,
		    VALS(v2giso2_enum_iso2responseCodeType_names),
		    0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2ChargingStatusResType_EVSEID,
		  { "EVSEID",
		    "v2giso2.struct.chargingstatusres.evseid",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2ChargingStatusResType_SAScheduleTupleID,
		  { "SAScheduleTupleID",
		    "v2giso2.struct.chargingstatusres.sascheduletupleid",
		    FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2ChargingStatusResType_ReceiptRequired,
		  { "ReceiptRequired",
		    "v2giso2.struct.chargingstatusres.receiptrequired",
		    FT_INT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso2CertificateInstallationReqType */
		{ &hf_v2giso2_struct_iso2CertificateInstallationReqType_Id,
		  { "Id", "v2giso2.struct.certificateinstallationreq.id",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2CertificateInstallationReqType_OEMProvisioningCert,
		  { "OEMProvisioningCert",
		    "v2giso2.struct.certificateinstallationreq.oemprovisioningcert",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		/* struct iso2CertificateInstallationResType */
		{ &hf_v2giso2_struct_iso2CertificateInstallationResType_ResponseCode,
		  { "ResponseCode",
		    "v2giso2.struct.certificateinstallationres.responsecode",
		    FT_UINT16, BASE_DEC,
		    VALS(v2giso2_enum_iso2responseCodeType_names),
		    0x0, NULL, HFILL }
		},

		/* struct iso2CertificateUpdateReqType */
		{ &hf_v2giso2_struct_iso2CertificateUpdateReqType_Id,
		  { "Id", "v2giso2.struct.certificateupdatereq.id",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2CertificateUpdateReqType_eMAID,
		  { "eMAID", "v2giso2.struct.certificateupdatereq.emaid",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		/* struct iso2CertificateUpdateResType */
		{ &hf_v2giso2_struct_iso2CertificateUpdateResType_ResponseCode,
		  { "ResponseCode",
		    "v2giso2.struct.certificateupdateres.responsecode",
		    FT_UINT16, BASE_DEC,
		    VALS(v2giso2_enum_iso2responseCodeType_names),
		    0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2CertificateUpdateResType_RetryCounter,
		  { "RetryCounter",
		    "v2giso2.struct.certificateupdateres.retrycount",
		    FT_INT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso2SessionStopReqType */
		{ &hf_v2giso2_struct_iso2SessionStopReqType_ChargingSession,
		  { "ChargingSession",
		    "v2giso2.struct.sessionstopreq.chargingsession",
		    FT_UINT16, BASE_DEC,
		    VALS(v2giso2_enum_iso2chargingSessionType_names),
		    0x0, NULL, HFILL }
		},
		/* struct iso2SessionStopResType */
		{ &hf_v2giso2_struct_iso2SessionStopResType_ResponseCode,
		  { "ResponseCode",
		    "v2giso2.struct.sessionstopres.responsecode",
		    FT_UINT16, BASE_DEC,
		    VALS(v2giso2_enum_iso2responseCodeType_names),
		    0x0, NULL, HFILL }
		},

		/* struct iso2MeteringReceiptReqType */
		{ &hf_v2giso2_struct_iso2MeteringReceiptReqType_Id,
		  { "Id", "v2giso2.struct.meteringreceiptreq.id",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2MeteringReceiptReqType_SessionID,
		  { "SessionID", "v2giso2.struct.meteringreceiptreq.sessionid",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2MeteringReceiptReqType_SAScheduleTupleID,
		  { "SAScheduleTupleID",
		    "v2giso2.struct.meteringreceiptreq.sascheduletupleid",
		    FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		/* struct iso2MeteringReceiptResType */
		{ &hf_v2giso2_struct_iso2MeteringReceiptResType_ResponseCode,
		  { "ResponseCode",
		    "v2giso2.struct.meteringreceiptres.responsecode",
		    FT_UINT16, BASE_DEC,
		    VALS(v2giso2_enum_iso2responseCodeType_names),
		    0x0, NULL, HFILL }
		},

		/* struct iso2PowerDeliveryReqType */
		{ &hf_v2giso2_struct_iso2PowerDeliveryReqType_ChargeProgress,
		  { "ChargeProgress",
		    "v2giso2.struct.powerdeliveryreq.chargeprogress",
		    FT_UINT16, BASE_DEC,
		    VALS(v2giso2_enum_iso2chargeProgressType_names),
		    0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2PowerDeliveryReqType_EVOperation,
		  { "EVOperation",
		    "v2giso2.struct.powerdeliveryreq.evoperation",
		    FT_UINT16, BASE_DEC,
		    VALS(v2giso2_enum_iso2EVOperationType_names),
		    0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2PowerDeliveryReqType_SAScheduleTupleID,
		  { "SAScheduleTupleID",
		    "v2giso2.struct.powerdeliveryreq.sascheduletupleid",
		    FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		/* struct iso2PowerDeliveryResType */
		{ &hf_v2giso2_struct_iso2PowerDeliveryResType_ResponseCode,
		  { "ResponseCode",
		    "v2giso2.struct.powerdeliveryres.responsecode",
		    FT_UINT16, BASE_DEC,
		    VALS(v2giso2_enum_iso2responseCodeType_names),
		    0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2PowerDeliveryResType_EVSEProcessing,
		  { "EVSEProcessing",
		    "v2giso2.struct.powerdeliveryres.evseprocessing",
		    FT_UINT16, BASE_DEC,
		    VALS(v2giso2_enum_iso2EVSEProcessingType_names),
		    0x0, NULL, HFILL }
		},

		/* struct iso2ChargeParameterDiscoveryReqType */
		{ &hf_v2giso2_struct_iso2ChargeParameterDiscoveryReqType_MaxSupportingPoints,
		  { "MaxSupportingPoints",
		    "v2giso2.struct.chargeparameterdiscoveryreq.maxsupportingpoints",
		    FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		/* struct iso2ChargeParameterDiscoveryResType */
		{ &hf_v2giso2_struct_iso2ChargeParameterDiscoveryResType_ResponseCode,
		  { "ResponseCode",
		    "v2giso2.struct.chargeparameterdiscoveryres.responsecode",
		    FT_UINT16, BASE_DEC,
		    VALS(v2giso2_enum_iso2responseCodeType_names),
		    0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2ChargeParameterDiscoveryResType_EVSEProcessing,
		  { "EVSEProcessing",
		    "v2giso2.struct.chargeparameterdiscoveryres.evseprocessing",
		    FT_UINT16, BASE_DEC,
		    VALS(v2giso2_enum_iso2EVSEProcessingType_names),
		    0x0, NULL, HFILL }
		},

		/* struct iso2AuthorizationReqType */
		{ &hf_v2giso2_struct_iso2AuthorizationReqType_Id,
		  { "Id", "v2giso2.struct.authorizationreq.id",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2AuthorizationReqType_GenChallenge,
		  { "GenChallenge", "v2giso2.struct.authorizationreq.genchallenge",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		/* struct iso2AuthorizationResType */
		{ &hf_v2giso2_struct_iso2AuthorizationResType_ResponseCode,
		  { "ResponseCode",
		    "v2giso2.struct.authorizationres.responsecode",
		    FT_UINT16, BASE_DEC,
		    VALS(v2giso2_enum_iso2responseCodeType_names),
		    0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2AuthorizationResType_EVSEProcessing,
		  { "EVSEProcessing",
		    "v2giso2.struct.authorizationres.evseprocessing",
		    FT_UINT16, BASE_DEC,
		    VALS(v2giso2_enum_iso2EVSEProcessingType_names),
		    0x0, NULL, HFILL }
		},

		/* struct iso2PaymentDetailsReqType */
		{ &hf_v2giso2_struct_iso2PaymentDetailsReqType_eMAID,
		  { "eMAID",
		    "v2giso2.struct.paymentdetailsres.emaid",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		/* struct iso2PaymentDetailsResType */
		{ &hf_v2giso2_struct_iso2PaymentDetailsResType_ResponseCode,
		  { "ResponseCode",
		    "v2giso2.struct.paymentdetailsres.responsecode",
		    FT_UINT16, BASE_DEC,
		    VALS(v2giso2_enum_iso2responseCodeType_names),
		    0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2PaymentDetailsResType_GenChallenge,
		  { "GenChallenge",
		    "v2giso2.struct.paymentdetailsres.genchallenge",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2PaymentDetailsResType_EVSETimeStamp,
		  { "EVSETimeStamp",
		    "v2giso2.struct.paymentdetailsres.evsetimestamp",
		    FT_INT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso2PaymentServiceSelectionReqType */
		{ &hf_v2giso2_struct_iso2PaymentServiceSelectionReqType_SelectedPaymentOption,
		  { "SelectedPaymentOption",
		    "v2giso2.struct.paymentserviceselectionres.selectedpaymentoption",
		    FT_UINT16, BASE_DEC,
		    VALS(v2giso2_enum_iso2paymentOptionType_names),
		    0x0, NULL, HFILL }
		},
		/* struct iso2PaymentServiceSelectionResType */
		{ &hf_v2giso2_struct_iso2PaymentServiceSelectionResType_ResponseCode,
		  { "ResponseCode",
		    "v2giso2.struct.paymentserviceselectionres.responsecode",
		    FT_UINT16, BASE_DEC,
		    VALS(v2giso2_enum_iso2responseCodeType_names),
		    0x0, NULL, HFILL }
		},

		/* struct iso2ServiceDetailReqType */
		{ &hf_v2giso2_struct_iso2ServiceDetailReqType_ServiceID,
		  { "ServiceID",
		    "v2giso2.struct.servicedetailreq.serviceid",
		    FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		/* struct iso2ServiceDetailResType */
		{ &hf_v2giso2_struct_iso2ServiceDetailResType_ResponseCode,
		  { "ResponseCode",
		    "v2giso2.struct.servicedetailres.responsecode",
		    FT_UINT16, BASE_DEC,
		    VALS(v2giso2_enum_iso2responseCodeType_names),
		    0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2ServiceDetailResType_ServiceID,
		  { "ServiceID",
		    "v2giso2.struct.servicedetailres.serviceid",
		    FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},

		/* struct iso2ServiceDiscoveryReqType */
		/* struct iso2ServiceDiscoveryResType */
		{ &hf_v2giso2_struct_iso2ServiceDiscoveryResType_ResponseCode,
		  { "ResponseCode",
		    "v2giso2.struct.servicediscoveryres.responsecode",
		    FT_UINT16, BASE_DEC,
		    VALS(v2giso2_enum_iso2responseCodeType_names),
		    0x0, NULL, HFILL }
		},

		/* struct iso2SessionSetupReqType */
		{ &hf_v2giso2_struct_iso2SessionSetupReqType_EVCCID,
		  { "EVCCID",
		    "v2giso2.struct.paymentdetailsreq.evccid",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		/* struct iso2SessionSetupResType */
		{ &hf_v2giso2_struct_iso2SessionSetupResType_ResponseCode,
		  { "ResponseCode",
		    "v2giso2.struct.sessionsetupres.responsecode",
		    FT_UINT16, BASE_DEC,
		    VALS(v2giso2_enum_iso2responseCodeType_names),
		    0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2SessionSetupResType_EVSEID,
		  { "EVSEID",
		    "v2giso2.struct.paymentdetailsres.evseid",
		    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_struct_iso2SessionSetupResType_EVSETimeStamp,
		  { "EVSETimeStamp",
		    "v2giso2.struct.sessionsetupres.evsetimestamp",
		    FT_INT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},

		/* Derived values for graphing */
		{ &hf_v2giso2_target_voltage,
		  { "Voltage", "v2giso2.target.voltage",
		    FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_target_current,
		  { "Current", "v2giso2.target.current",
		    FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_present_voltage,
		  { "Voltage", "v2giso2.present.voltage",
		    FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_v2giso2_present_current,
		  { "Current", "v2giso2.present.current",
		    FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
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

		&ett_v2giso2_struct_iso2EVSEStatusType,
		&ett_v2giso2_struct_iso2PhysicalValueType,
		&ett_v2giso2_struct_iso2DisplayParametersType,
		&ett_v2giso2_struct_iso2MeterInfoType,
		&ett_v2giso2_struct_iso2TargetPositionType,
		&ett_v2giso2_struct_iso2ParameterType,
		&ett_v2giso2_struct_iso2ParameterSetType,
		&ett_v2giso2_struct_iso2MeasurementDataListType,
		&ett_v2giso2_struct_iso2SensorMeasurementsType,
		&ett_v2giso2_struct_iso2SensorPackageType,
		&ett_v2giso2_struct_iso2SensorPackageListType,
		&ett_v2giso2_struct_iso2CartesianCoordinatesType,
		&ett_v2giso2_struct_iso2SensorType,
		&ett_v2giso2_struct_iso2SensorListType,
		&ett_v2giso2_struct_iso2SensorOrderListType,
		&ett_v2giso2_struct_iso2MagneticVectorType,
		&ett_v2giso2_struct_iso2MagneticVectorListType,
		&ett_v2giso2_struct_iso2MagneticVectorSetupType,
		&ett_v2giso2_struct_iso2MagneticVectorSetupListType,
		&ett_v2giso2_struct_iso2EVFinePositioningParametersType,
		&ett_v2giso2_struct_iso2Generic_EVFinePositioningParametersType,
		&ett_v2giso2_struct_iso2LFA_EVFinePositioningParametersType,
		&ett_v2giso2_struct_iso2EVSEFinePositioningParametersType,
		&ett_v2giso2_struct_iso2Generic_EVSEFinePositioningParametersType,
		&ett_v2giso2_struct_iso2LFA_EVSEFinePositioningParametersType,
		&ett_v2giso2_struct_iso2MV_EVSEFinePositioningParametersType,
		&ett_v2giso2_struct_iso2EVFinePositioningSetupParametersType,
		&ett_v2giso2_struct_iso2LFA_EVFinePositioningSetupParametersType,
		&ett_v2giso2_struct_iso2EVSEFinePositioningSetupParametersType,
		&ett_v2giso2_struct_iso2LFA_EVSEFinePositioningSetupParametersType,
		&ett_v2giso2_struct_iso2MV_EVSEFinePositioningSetupParametersType,
		&ett_v2giso2_struct_iso2ListOfRootCertificateIDsType,
		&ett_v2giso2_struct_iso2SubCertificatesType,
		&ett_v2giso2_struct_iso2CertificateChainType,
		&ett_v2giso2_struct_iso2ContractSignatureEncryptedPrivateKeyType,
		&ett_v2giso2_struct_iso2DiffieHellmanPublickeyType,
		&ett_v2giso2_struct_iso2EMAIDType,
		&ett_v2giso2_struct_iso2ChargingProfileType,
		&ett_v2giso2_struct_iso2RelativeTimeIntervalType,
		&ett_v2giso2_struct_iso2PMaxScheduleEntryType,
		&ett_v2giso2_struct_iso2EVEnergyTransferParameterType,
		&ett_v2giso2_struct_iso2AC_EVChargeParameterType,
		&ett_v2giso2_struct_iso2AC_EVBidirectionalParameterType,
		&ett_v2giso2_struct_iso2DC_EVChargeParameterType,
		&ett_v2giso2_struct_iso2DC_EVBidirectionalParameterType,
		&ett_v2giso2_struct_iso2WPT_EVChargeParameterType,
		&ett_v2giso2_struct_iso2MinimumPMaxRequestType,
		&ett_v2giso2_struct_iso2SAScheduleListType,
		&ett_v2giso2_struct_iso2EVSEEnergyTransferParameterType,
		&ett_v2giso2_struct_iso2AC_EVSEChargeParameterType,
		&ett_v2giso2_struct_iso2AC_EVSEBidirectionalParameterType,
		&ett_v2giso2_struct_iso2DC_EVSEChargeParameterType,
		&ett_v2giso2_struct_iso2DC_EVSEBidirectionalParameterType,
		&ett_v2giso2_struct_iso2WPT_EVSEChargeParameterType,
		&ett_v2giso2_struct_iso2SelectedServiceType,
		&ett_v2giso2_struct_iso2SelectedServiceListType,
		&ett_v2giso2_struct_iso2ServiceParameterListType,
		&ett_v2giso2_struct_iso2ServiceIDListType,
		&ett_v2giso2_struct_iso2ServiceListType,
		&ett_v2giso2_struct_iso2PaymentOptionListType,

		&ett_v2giso2_struct_iso2DisconnectChargingDeviceReqType,
		&ett_v2giso2_struct_iso2DisconnectChargingDeviceResType,
		&ett_v2giso2_struct_iso2ConnectChargingDeviceReqType,
		&ett_v2giso2_struct_iso2ConnectChargingDeviceResType,
		&ett_v2giso2_struct_iso2SystemStatusReqType,
		&ett_v2giso2_struct_iso2SystemStatusResType,
		&ett_v2giso2_struct_iso2DC_BidirectionalControlReqType,
		&ett_v2giso2_struct_iso2DC_BidirectionalControlResType,
		&ett_v2giso2_struct_iso2AC_BidirectionalControlReqType,
		&ett_v2giso2_struct_iso2AC_BidirectionalControlResType,
		&ett_v2giso2_struct_iso2VehicleCheckOutReqType,
		&ett_v2giso2_struct_iso2VehicleCheckOutResType,
		&ett_v2giso2_struct_iso2VehicleCheckInReqType,
		&ett_v2giso2_struct_iso2VehicleCheckInResType,
		&ett_v2giso2_struct_iso2PowerDemandReqType,
		&ett_v2giso2_struct_iso2PowerDemandResType,
		&ett_v2giso2_struct_iso2PairingReqType,
		&ett_v2giso2_struct_iso2PairingResType,
		&ett_v2giso2_struct_iso2AlignmentCheckReqType,
		&ett_v2giso2_struct_iso2AlignmentCheckResType,
		&ett_v2giso2_struct_iso2FinePositioningReqType,
		&ett_v2giso2_struct_iso2FinePositioningResType,
		&ett_v2giso2_struct_iso2FinePositioningSetupReqType,
		&ett_v2giso2_struct_iso2FinePositioningSetupResType,
		&ett_v2giso2_struct_iso2WeldingDetectionReqType,
		&ett_v2giso2_struct_iso2WeldingDetectionResType,
		&ett_v2giso2_struct_iso2CurrentDemandReqType,
		&ett_v2giso2_struct_iso2CurrentDemandResType,
		&ett_v2giso2_struct_iso2PreChargeReqType,
		&ett_v2giso2_struct_iso2PreChargeResType,
		&ett_v2giso2_struct_iso2CableCheckReqType,
		&ett_v2giso2_struct_iso2CableCheckResType,
		&ett_v2giso2_struct_iso2ChargingStatusReqType,
		&ett_v2giso2_struct_iso2ChargingStatusResType,
		&ett_v2giso2_struct_iso2CertificateInstallationReqType,
		&ett_v2giso2_struct_iso2CertificateInstallationResType,
		&ett_v2giso2_struct_iso2CertificateUpdateReqType,
		&ett_v2giso2_struct_iso2CertificateUpdateResType,
		&ett_v2giso2_struct_iso2SessionStopReqType,
		&ett_v2giso2_struct_iso2SessionStopResType,
		&ett_v2giso2_struct_iso2MeteringReceiptReqType,
		&ett_v2giso2_struct_iso2MeteringReceiptResType,
		&ett_v2giso2_struct_iso2PowerDeliveryReqType,
		&ett_v2giso2_struct_iso2PowerDeliveryResType,
		&ett_v2giso2_struct_iso2ChargeParameterDiscoveryReqType,
		&ett_v2giso2_struct_iso2ChargeParameterDiscoveryResType,
		&ett_v2giso2_struct_iso2AuthorizationReqType,
		&ett_v2giso2_struct_iso2AuthorizationResType,
		&ett_v2giso2_struct_iso2PaymentDetailsReqType,
		&ett_v2giso2_struct_iso2PaymentDetailsResType,
		&ett_v2giso2_struct_iso2PaymentServiceSelectionReqType,
		&ett_v2giso2_struct_iso2PaymentServiceSelectionResType,
		&ett_v2giso2_struct_iso2ServiceDetailReqType,
		&ett_v2giso2_struct_iso2ServiceDetailResType,
		&ett_v2giso2_struct_iso2ServiceDiscoveryReqType,
		&ett_v2giso2_struct_iso2ServiceDiscoveryResType,
		&ett_v2giso2_struct_iso2SessionSetupReqType,
		&ett_v2giso2_struct_iso2SessionSetupResType,
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
