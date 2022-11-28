# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

function(awsSdkCppMain)
  generateAwsCrtCpp()
  generateAwsCppSdkCore()
  generateAwsCppSdkFirehose()
  generateAwsCppSdkKinesis()
  generateAwsCppSdkS3()
  generateAwsCppSdkSts()
  generateAwsCppSdkEc2()

  add_library(thirdparty_aws-sdk-cpp INTERFACE)
  target_link_libraries(thirdparty_aws-sdk-cpp INTERFACE
    thirdparty_aws-cpp-sdk-s3
    thirdparty_aws-cpp-sdk-firehose
    thirdparty_aws-cpp-sdk-kinesis
    thirdparty_aws-cpp-sdk-sts
    thirdparty_aws-cpp-sdk-ec2
  )
endfunction()

function(generateAwsCppSdkEc2)
  set(library_root "${CMAKE_CURRENT_SOURCE_DIR}/src/aws-sdk-cpp/aws-cpp-sdk-ec2")

  add_library(thirdparty_aws-cpp-sdk-ec2 EXCLUDE_FROM_ALL
    "${library_root}/source/EC2Client.cpp"
    "${library_root}/source/EC2Endpoint.cpp"
    "${library_root}/source/EC2ErrorMarshaller.cpp"
    "${library_root}/source/EC2Errors.cpp"
    "${library_root}/source/model/AcceptReservedInstancesExchangeQuoteRequest.cpp"
    "${library_root}/source/model/AcceptReservedInstancesExchangeQuoteResponse.cpp"
    "${library_root}/source/model/AcceptTransitGatewayMulticastDomainAssociationsRequest.cpp"
    "${library_root}/source/model/AcceptTransitGatewayMulticastDomainAssociationsResponse.cpp"
    "${library_root}/source/model/AcceptTransitGatewayPeeringAttachmentRequest.cpp"
    "${library_root}/source/model/AcceptTransitGatewayPeeringAttachmentResponse.cpp"
    "${library_root}/source/model/AcceptTransitGatewayVpcAttachmentRequest.cpp"
    "${library_root}/source/model/AcceptTransitGatewayVpcAttachmentResponse.cpp"
    "${library_root}/source/model/AcceptVpcEndpointConnectionsRequest.cpp"
    "${library_root}/source/model/AcceptVpcEndpointConnectionsResponse.cpp"
    "${library_root}/source/model/AcceptVpcPeeringConnectionRequest.cpp"
    "${library_root}/source/model/AcceptVpcPeeringConnectionResponse.cpp"
    "${library_root}/source/model/AccountAttribute.cpp"
    "${library_root}/source/model/AccountAttributeName.cpp"
    "${library_root}/source/model/AccountAttributeValue.cpp"
    "${library_root}/source/model/ActiveInstance.cpp"
    "${library_root}/source/model/ActivityStatus.cpp"
    "${library_root}/source/model/AddPrefixListEntry.cpp"
    "${library_root}/source/model/AddressAttribute.cpp"
    "${library_root}/source/model/AddressAttributeName.cpp"
    "${library_root}/source/model/Address.cpp"
    "${library_root}/source/model/AdvertiseByoipCidrRequest.cpp"
    "${library_root}/source/model/AdvertiseByoipCidrResponse.cpp"
    "${library_root}/source/model/Affinity.cpp"
    "${library_root}/source/model/AllocateAddressRequest.cpp"
    "${library_root}/source/model/AllocateAddressResponse.cpp"
    "${library_root}/source/model/AllocateHostsRequest.cpp"
    "${library_root}/source/model/AllocateHostsResponse.cpp"
    "${library_root}/source/model/AllocationState.cpp"
    "${library_root}/source/model/AllocationStrategy.cpp"
    "${library_root}/source/model/AllowedPrincipal.cpp"
    "${library_root}/source/model/AllowsMultipleInstanceTypes.cpp"
    "${library_root}/source/model/AlternatePathHint.cpp"
    "${library_root}/source/model/AnalysisAclRule.cpp"
    "${library_root}/source/model/AnalysisComponent.cpp"
    "${library_root}/source/model/AnalysisLoadBalancerListener.cpp"
    "${library_root}/source/model/AnalysisLoadBalancerTarget.cpp"
    "${library_root}/source/model/AnalysisPacketHeader.cpp"
    "${library_root}/source/model/AnalysisRouteTableRoute.cpp"
    "${library_root}/source/model/AnalysisSecurityGroupRule.cpp"
    "${library_root}/source/model/AnalysisStatus.cpp"
    "${library_root}/source/model/ApplianceModeSupportValue.cpp"
    "${library_root}/source/model/ApplySecurityGroupsToClientVpnTargetNetworkRequest.cpp"
    "${library_root}/source/model/ApplySecurityGroupsToClientVpnTargetNetworkResponse.cpp"
    "${library_root}/source/model/ArchitectureType.cpp"
    "${library_root}/source/model/ArchitectureValues.cpp"
    "${library_root}/source/model/AssignedPrivateIpAddress.cpp"
    "${library_root}/source/model/AssignIpv6AddressesRequest.cpp"
    "${library_root}/source/model/AssignIpv6AddressesResponse.cpp"
    "${library_root}/source/model/AssignPrivateIpAddressesRequest.cpp"
    "${library_root}/source/model/AssignPrivateIpAddressesResponse.cpp"
    "${library_root}/source/model/AssociateAddressRequest.cpp"
    "${library_root}/source/model/AssociateAddressResponse.cpp"
    "${library_root}/source/model/AssociateClientVpnTargetNetworkRequest.cpp"
    "${library_root}/source/model/AssociateClientVpnTargetNetworkResponse.cpp"
    "${library_root}/source/model/AssociateDhcpOptionsRequest.cpp"
    "${library_root}/source/model/AssociatedNetworkType.cpp"
    "${library_root}/source/model/AssociatedRole.cpp"
    "${library_root}/source/model/AssociatedTargetNetwork.cpp"
    "${library_root}/source/model/AssociateEnclaveCertificateIamRoleRequest.cpp"
    "${library_root}/source/model/AssociateEnclaveCertificateIamRoleResponse.cpp"
    "${library_root}/source/model/AssociateIamInstanceProfileRequest.cpp"
    "${library_root}/source/model/AssociateIamInstanceProfileResponse.cpp"
    "${library_root}/source/model/AssociateInstanceEventWindowRequest.cpp"
    "${library_root}/source/model/AssociateInstanceEventWindowResponse.cpp"
    "${library_root}/source/model/AssociateRouteTableRequest.cpp"
    "${library_root}/source/model/AssociateRouteTableResponse.cpp"
    "${library_root}/source/model/AssociateSubnetCidrBlockRequest.cpp"
    "${library_root}/source/model/AssociateSubnetCidrBlockResponse.cpp"
    "${library_root}/source/model/AssociateTransitGatewayMulticastDomainRequest.cpp"
    "${library_root}/source/model/AssociateTransitGatewayMulticastDomainResponse.cpp"
    "${library_root}/source/model/AssociateTransitGatewayRouteTableRequest.cpp"
    "${library_root}/source/model/AssociateTransitGatewayRouteTableResponse.cpp"
    "${library_root}/source/model/AssociateTrunkInterfaceRequest.cpp"
    "${library_root}/source/model/AssociateTrunkInterfaceResponse.cpp"
    "${library_root}/source/model/AssociateVpcCidrBlockRequest.cpp"
    "${library_root}/source/model/AssociateVpcCidrBlockResponse.cpp"
    "${library_root}/source/model/AssociationStatusCode.cpp"
    "${library_root}/source/model/AssociationStatus.cpp"
    "${library_root}/source/model/AthenaIntegration.cpp"
    "${library_root}/source/model/AttachClassicLinkVpcRequest.cpp"
    "${library_root}/source/model/AttachClassicLinkVpcResponse.cpp"
    "${library_root}/source/model/AttachInternetGatewayRequest.cpp"
    "${library_root}/source/model/AttachmentStatus.cpp"
    "${library_root}/source/model/AttachNetworkInterfaceRequest.cpp"
    "${library_root}/source/model/AttachNetworkInterfaceResponse.cpp"
    "${library_root}/source/model/AttachVolumeRequest.cpp"
    "${library_root}/source/model/AttachVolumeResponse.cpp"
    "${library_root}/source/model/AttachVpnGatewayRequest.cpp"
    "${library_root}/source/model/AttachVpnGatewayResponse.cpp"
    "${library_root}/source/model/AttributeBooleanValue.cpp"
    "${library_root}/source/model/AttributeValue.cpp"
    "${library_root}/source/model/AuthorizationRule.cpp"
    "${library_root}/source/model/AuthorizeClientVpnIngressRequest.cpp"
    "${library_root}/source/model/AuthorizeClientVpnIngressResponse.cpp"
    "${library_root}/source/model/AuthorizeSecurityGroupEgressRequest.cpp"
    "${library_root}/source/model/AuthorizeSecurityGroupEgressResponse.cpp"
    "${library_root}/source/model/AuthorizeSecurityGroupIngressRequest.cpp"
    "${library_root}/source/model/AuthorizeSecurityGroupIngressResponse.cpp"
    "${library_root}/source/model/AutoAcceptSharedAssociationsValue.cpp"
    "${library_root}/source/model/AutoAcceptSharedAttachmentsValue.cpp"
    "${library_root}/source/model/AutoPlacement.cpp"
    "${library_root}/source/model/AvailabilityZone.cpp"
    "${library_root}/source/model/AvailabilityZoneMessage.cpp"
    "${library_root}/source/model/AvailabilityZoneOptInStatus.cpp"
    "${library_root}/source/model/AvailabilityZoneState.cpp"
    "${library_root}/source/model/AvailableCapacity.cpp"
    "${library_root}/source/model/BatchState.cpp"
    "${library_root}/source/model/BgpStatus.cpp"
    "${library_root}/source/model/BlobAttributeValue.cpp"
    "${library_root}/source/model/BlockDeviceMapping.cpp"
    "${library_root}/source/model/BootModeType.cpp"
    "${library_root}/source/model/BootModeValues.cpp"
    "${library_root}/source/model/BundleInstanceRequest.cpp"
    "${library_root}/source/model/BundleInstanceResponse.cpp"
    "${library_root}/source/model/BundleTask.cpp"
    "${library_root}/source/model/BundleTaskError.cpp"
    "${library_root}/source/model/BundleTaskState.cpp"
    "${library_root}/source/model/ByoipCidr.cpp"
    "${library_root}/source/model/ByoipCidrState.cpp"
    "${library_root}/source/model/CancelBatchErrorCode.cpp"
    "${library_root}/source/model/CancelBundleTaskRequest.cpp"
    "${library_root}/source/model/CancelBundleTaskResponse.cpp"
    "${library_root}/source/model/CancelCapacityReservationFleetError.cpp"
    "${library_root}/source/model/CancelCapacityReservationFleetsRequest.cpp"
    "${library_root}/source/model/CancelCapacityReservationFleetsResponse.cpp"
    "${library_root}/source/model/CancelCapacityReservationRequest.cpp"
    "${library_root}/source/model/CancelCapacityReservationResponse.cpp"
    "${library_root}/source/model/CancelConversionTaskRequest.cpp"
    "${library_root}/source/model/CancelExportTaskRequest.cpp"
    "${library_root}/source/model/CancelImportTaskRequest.cpp"
    "${library_root}/source/model/CancelImportTaskResponse.cpp"
    "${library_root}/source/model/CancelledSpotInstanceRequest.cpp"
    "${library_root}/source/model/CancelReservedInstancesListingRequest.cpp"
    "${library_root}/source/model/CancelReservedInstancesListingResponse.cpp"
    "${library_root}/source/model/CancelSpotFleetRequestsError.cpp"
    "${library_root}/source/model/CancelSpotFleetRequestsErrorItem.cpp"
    "${library_root}/source/model/CancelSpotFleetRequestsRequest.cpp"
    "${library_root}/source/model/CancelSpotFleetRequestsResponse.cpp"
    "${library_root}/source/model/CancelSpotFleetRequestsSuccessItem.cpp"
    "${library_root}/source/model/CancelSpotInstanceRequestsRequest.cpp"
    "${library_root}/source/model/CancelSpotInstanceRequestsResponse.cpp"
    "${library_root}/source/model/CancelSpotInstanceRequestState.cpp"
    "${library_root}/source/model/CapacityReservation.cpp"
    "${library_root}/source/model/CapacityReservationFleetCancellationState.cpp"
    "${library_root}/source/model/CapacityReservationFleet.cpp"
    "${library_root}/source/model/CapacityReservationFleetState.cpp"
    "${library_root}/source/model/CapacityReservationGroup.cpp"
    "${library_root}/source/model/CapacityReservationInstancePlatform.cpp"
    "${library_root}/source/model/CapacityReservationOptions.cpp"
    "${library_root}/source/model/CapacityReservationOptionsRequest.cpp"
    "${library_root}/source/model/CapacityReservationPreference.cpp"
    "${library_root}/source/model/CapacityReservationSpecification.cpp"
    "${library_root}/source/model/CapacityReservationSpecificationResponse.cpp"
    "${library_root}/source/model/CapacityReservationState.cpp"
    "${library_root}/source/model/CapacityReservationTarget.cpp"
    "${library_root}/source/model/CapacityReservationTargetResponse.cpp"
    "${library_root}/source/model/CapacityReservationTenancy.cpp"
    "${library_root}/source/model/CarrierGateway.cpp"
    "${library_root}/source/model/CarrierGatewayState.cpp"
    "${library_root}/source/model/CertificateAuthentication.cpp"
    "${library_root}/source/model/CertificateAuthenticationRequest.cpp"
    "${library_root}/source/model/CidrAuthorizationContext.cpp"
    "${library_root}/source/model/CidrBlock.cpp"
    "${library_root}/source/model/ClassicLinkDnsSupport.cpp"
    "${library_root}/source/model/ClassicLinkInstance.cpp"
    "${library_root}/source/model/ClassicLoadBalancer.cpp"
    "${library_root}/source/model/ClassicLoadBalancersConfig.cpp"
    "${library_root}/source/model/ClientCertificateRevocationListStatusCode.cpp"
    "${library_root}/source/model/ClientCertificateRevocationListStatus.cpp"
    "${library_root}/source/model/ClientConnectOptions.cpp"
    "${library_root}/source/model/ClientConnectResponseOptions.cpp"
    "${library_root}/source/model/ClientData.cpp"
    "${library_root}/source/model/ClientVpnAuthentication.cpp"
    "${library_root}/source/model/ClientVpnAuthenticationRequest.cpp"
    "${library_root}/source/model/ClientVpnAuthenticationType.cpp"
    "${library_root}/source/model/ClientVpnAuthorizationRuleStatusCode.cpp"
    "${library_root}/source/model/ClientVpnAuthorizationRuleStatus.cpp"
    "${library_root}/source/model/ClientVpnConnection.cpp"
    "${library_root}/source/model/ClientVpnConnectionStatusCode.cpp"
    "${library_root}/source/model/ClientVpnConnectionStatus.cpp"
    "${library_root}/source/model/ClientVpnEndpointAttributeStatusCode.cpp"
    "${library_root}/source/model/ClientVpnEndpointAttributeStatus.cpp"
    "${library_root}/source/model/ClientVpnEndpoint.cpp"
    "${library_root}/source/model/ClientVpnEndpointStatusCode.cpp"
    "${library_root}/source/model/ClientVpnEndpointStatus.cpp"
    "${library_root}/source/model/ClientVpnRoute.cpp"
    "${library_root}/source/model/ClientVpnRouteStatusCode.cpp"
    "${library_root}/source/model/ClientVpnRouteStatus.cpp"
    "${library_root}/source/model/CoipAddressUsage.cpp"
    "${library_root}/source/model/CoipPool.cpp"
    "${library_root}/source/model/ConfirmProductInstanceRequest.cpp"
    "${library_root}/source/model/ConfirmProductInstanceResponse.cpp"
    "${library_root}/source/model/ConnectionLogOptions.cpp"
    "${library_root}/source/model/ConnectionLogResponseOptions.cpp"
    "${library_root}/source/model/ConnectionNotification.cpp"
    "${library_root}/source/model/ConnectionNotificationState.cpp"
    "${library_root}/source/model/ConnectionNotificationType.cpp"
    "${library_root}/source/model/ConnectivityType.cpp"
    "${library_root}/source/model/ContainerFormat.cpp"
    "${library_root}/source/model/ConversionTask.cpp"
    "${library_root}/source/model/ConversionTaskState.cpp"
    "${library_root}/source/model/CopyFpgaImageRequest.cpp"
    "${library_root}/source/model/CopyFpgaImageResponse.cpp"
    "${library_root}/source/model/CopyImageRequest.cpp"
    "${library_root}/source/model/CopyImageResponse.cpp"
    "${library_root}/source/model/CopySnapshotRequest.cpp"
    "${library_root}/source/model/CopySnapshotResponse.cpp"
    "${library_root}/source/model/CopyTagsFromSource.cpp"
    "${library_root}/source/model/CpuOptions.cpp"
    "${library_root}/source/model/CpuOptionsRequest.cpp"
    "${library_root}/source/model/CreateCapacityReservationFleetRequest.cpp"
    "${library_root}/source/model/CreateCapacityReservationFleetResponse.cpp"
    "${library_root}/source/model/CreateCapacityReservationRequest.cpp"
    "${library_root}/source/model/CreateCapacityReservationResponse.cpp"
    "${library_root}/source/model/CreateCarrierGatewayRequest.cpp"
    "${library_root}/source/model/CreateCarrierGatewayResponse.cpp"
    "${library_root}/source/model/CreateClientVpnEndpointRequest.cpp"
    "${library_root}/source/model/CreateClientVpnEndpointResponse.cpp"
    "${library_root}/source/model/CreateClientVpnRouteRequest.cpp"
    "${library_root}/source/model/CreateClientVpnRouteResponse.cpp"
    "${library_root}/source/model/CreateCustomerGatewayRequest.cpp"
    "${library_root}/source/model/CreateCustomerGatewayResponse.cpp"
    "${library_root}/source/model/CreateDefaultSubnetRequest.cpp"
    "${library_root}/source/model/CreateDefaultSubnetResponse.cpp"
    "${library_root}/source/model/CreateDefaultVpcRequest.cpp"
    "${library_root}/source/model/CreateDefaultVpcResponse.cpp"
    "${library_root}/source/model/CreateDhcpOptionsRequest.cpp"
    "${library_root}/source/model/CreateDhcpOptionsResponse.cpp"
    "${library_root}/source/model/CreateEgressOnlyInternetGatewayRequest.cpp"
    "${library_root}/source/model/CreateEgressOnlyInternetGatewayResponse.cpp"
    "${library_root}/source/model/CreateFleetError.cpp"
    "${library_root}/source/model/CreateFleetInstance.cpp"
    "${library_root}/source/model/CreateFleetRequest.cpp"
    "${library_root}/source/model/CreateFleetResponse.cpp"
    "${library_root}/source/model/CreateFlowLogsRequest.cpp"
    "${library_root}/source/model/CreateFlowLogsResponse.cpp"
    "${library_root}/source/model/CreateFpgaImageRequest.cpp"
    "${library_root}/source/model/CreateFpgaImageResponse.cpp"
    "${library_root}/source/model/CreateImageRequest.cpp"
    "${library_root}/source/model/CreateImageResponse.cpp"
    "${library_root}/source/model/CreateInstanceEventWindowRequest.cpp"
    "${library_root}/source/model/CreateInstanceEventWindowResponse.cpp"
    "${library_root}/source/model/CreateInstanceExportTaskRequest.cpp"
    "${library_root}/source/model/CreateInstanceExportTaskResponse.cpp"
    "${library_root}/source/model/CreateInternetGatewayRequest.cpp"
    "${library_root}/source/model/CreateInternetGatewayResponse.cpp"
    "${library_root}/source/model/CreateKeyPairRequest.cpp"
    "${library_root}/source/model/CreateKeyPairResponse.cpp"
    "${library_root}/source/model/CreateLaunchTemplateRequest.cpp"
    "${library_root}/source/model/CreateLaunchTemplateResponse.cpp"
    "${library_root}/source/model/CreateLaunchTemplateVersionRequest.cpp"
    "${library_root}/source/model/CreateLaunchTemplateVersionResponse.cpp"
    "${library_root}/source/model/CreateLocalGatewayRouteRequest.cpp"
    "${library_root}/source/model/CreateLocalGatewayRouteResponse.cpp"
    "${library_root}/source/model/CreateLocalGatewayRouteTableVpcAssociationRequest.cpp"
    "${library_root}/source/model/CreateLocalGatewayRouteTableVpcAssociationResponse.cpp"
    "${library_root}/source/model/CreateManagedPrefixListRequest.cpp"
    "${library_root}/source/model/CreateManagedPrefixListResponse.cpp"
    "${library_root}/source/model/CreateNatGatewayRequest.cpp"
    "${library_root}/source/model/CreateNatGatewayResponse.cpp"
    "${library_root}/source/model/CreateNetworkAclEntryRequest.cpp"
    "${library_root}/source/model/CreateNetworkAclRequest.cpp"
    "${library_root}/source/model/CreateNetworkAclResponse.cpp"
    "${library_root}/source/model/CreateNetworkInsightsPathRequest.cpp"
    "${library_root}/source/model/CreateNetworkInsightsPathResponse.cpp"
    "${library_root}/source/model/CreateNetworkInterfacePermissionRequest.cpp"
    "${library_root}/source/model/CreateNetworkInterfacePermissionResponse.cpp"
    "${library_root}/source/model/CreateNetworkInterfaceRequest.cpp"
    "${library_root}/source/model/CreateNetworkInterfaceResponse.cpp"
    "${library_root}/source/model/CreatePlacementGroupRequest.cpp"
    "${library_root}/source/model/CreatePlacementGroupResponse.cpp"
    "${library_root}/source/model/CreateReplaceRootVolumeTaskRequest.cpp"
    "${library_root}/source/model/CreateReplaceRootVolumeTaskResponse.cpp"
    "${library_root}/source/model/CreateReservedInstancesListingRequest.cpp"
    "${library_root}/source/model/CreateReservedInstancesListingResponse.cpp"
    "${library_root}/source/model/CreateRestoreImageTaskRequest.cpp"
    "${library_root}/source/model/CreateRestoreImageTaskResponse.cpp"
    "${library_root}/source/model/CreateRouteRequest.cpp"
    "${library_root}/source/model/CreateRouteResponse.cpp"
    "${library_root}/source/model/CreateRouteTableRequest.cpp"
    "${library_root}/source/model/CreateRouteTableResponse.cpp"
    "${library_root}/source/model/CreateSecurityGroupRequest.cpp"
    "${library_root}/source/model/CreateSecurityGroupResponse.cpp"
    "${library_root}/source/model/CreateSnapshotRequest.cpp"
    "${library_root}/source/model/CreateSnapshotResponse.cpp"
    "${library_root}/source/model/CreateSnapshotsRequest.cpp"
    "${library_root}/source/model/CreateSnapshotsResponse.cpp"
    "${library_root}/source/model/CreateSpotDatafeedSubscriptionRequest.cpp"
    "${library_root}/source/model/CreateSpotDatafeedSubscriptionResponse.cpp"
    "${library_root}/source/model/CreateStoreImageTaskRequest.cpp"
    "${library_root}/source/model/CreateStoreImageTaskResponse.cpp"
    "${library_root}/source/model/CreateSubnetCidrReservationRequest.cpp"
    "${library_root}/source/model/CreateSubnetCidrReservationResponse.cpp"
    "${library_root}/source/model/CreateSubnetRequest.cpp"
    "${library_root}/source/model/CreateSubnetResponse.cpp"
    "${library_root}/source/model/CreateTagsRequest.cpp"
    "${library_root}/source/model/CreateTrafficMirrorFilterRequest.cpp"
    "${library_root}/source/model/CreateTrafficMirrorFilterResponse.cpp"
    "${library_root}/source/model/CreateTrafficMirrorFilterRuleRequest.cpp"
    "${library_root}/source/model/CreateTrafficMirrorFilterRuleResponse.cpp"
    "${library_root}/source/model/CreateTrafficMirrorSessionRequest.cpp"
    "${library_root}/source/model/CreateTrafficMirrorSessionResponse.cpp"
    "${library_root}/source/model/CreateTrafficMirrorTargetRequest.cpp"
    "${library_root}/source/model/CreateTrafficMirrorTargetResponse.cpp"
    "${library_root}/source/model/CreateTransitGatewayConnectPeerRequest.cpp"
    "${library_root}/source/model/CreateTransitGatewayConnectPeerResponse.cpp"
    "${library_root}/source/model/CreateTransitGatewayConnectRequest.cpp"
    "${library_root}/source/model/CreateTransitGatewayConnectRequestOptions.cpp"
    "${library_root}/source/model/CreateTransitGatewayConnectResponse.cpp"
    "${library_root}/source/model/CreateTransitGatewayMulticastDomainRequest.cpp"
    "${library_root}/source/model/CreateTransitGatewayMulticastDomainRequestOptions.cpp"
    "${library_root}/source/model/CreateTransitGatewayMulticastDomainResponse.cpp"
    "${library_root}/source/model/CreateTransitGatewayPeeringAttachmentRequest.cpp"
    "${library_root}/source/model/CreateTransitGatewayPeeringAttachmentResponse.cpp"
    "${library_root}/source/model/CreateTransitGatewayPrefixListReferenceRequest.cpp"
    "${library_root}/source/model/CreateTransitGatewayPrefixListReferenceResponse.cpp"
    "${library_root}/source/model/CreateTransitGatewayRequest.cpp"
    "${library_root}/source/model/CreateTransitGatewayResponse.cpp"
    "${library_root}/source/model/CreateTransitGatewayRouteRequest.cpp"
    "${library_root}/source/model/CreateTransitGatewayRouteResponse.cpp"
    "${library_root}/source/model/CreateTransitGatewayRouteTableRequest.cpp"
    "${library_root}/source/model/CreateTransitGatewayRouteTableResponse.cpp"
    "${library_root}/source/model/CreateTransitGatewayVpcAttachmentRequest.cpp"
    "${library_root}/source/model/CreateTransitGatewayVpcAttachmentRequestOptions.cpp"
    "${library_root}/source/model/CreateTransitGatewayVpcAttachmentResponse.cpp"
    "${library_root}/source/model/CreateVolumePermission.cpp"
    "${library_root}/source/model/CreateVolumePermissionModifications.cpp"
    "${library_root}/source/model/CreateVolumeRequest.cpp"
    "${library_root}/source/model/CreateVolumeResponse.cpp"
    "${library_root}/source/model/CreateVpcEndpointConnectionNotificationRequest.cpp"
    "${library_root}/source/model/CreateVpcEndpointConnectionNotificationResponse.cpp"
    "${library_root}/source/model/CreateVpcEndpointRequest.cpp"
    "${library_root}/source/model/CreateVpcEndpointResponse.cpp"
    "${library_root}/source/model/CreateVpcEndpointServiceConfigurationRequest.cpp"
    "${library_root}/source/model/CreateVpcEndpointServiceConfigurationResponse.cpp"
    "${library_root}/source/model/CreateVpcPeeringConnectionRequest.cpp"
    "${library_root}/source/model/CreateVpcPeeringConnectionResponse.cpp"
    "${library_root}/source/model/CreateVpcRequest.cpp"
    "${library_root}/source/model/CreateVpcResponse.cpp"
    "${library_root}/source/model/CreateVpnConnectionRequest.cpp"
    "${library_root}/source/model/CreateVpnConnectionResponse.cpp"
    "${library_root}/source/model/CreateVpnConnectionRouteRequest.cpp"
    "${library_root}/source/model/CreateVpnGatewayRequest.cpp"
    "${library_root}/source/model/CreateVpnGatewayResponse.cpp"
    "${library_root}/source/model/CreditSpecification.cpp"
    "${library_root}/source/model/CreditSpecificationRequest.cpp"
    "${library_root}/source/model/CurrencyCodeValues.cpp"
    "${library_root}/source/model/CustomerGateway.cpp"
    "${library_root}/source/model/DatafeedSubscriptionState.cpp"
    "${library_root}/source/model/DefaultRouteTableAssociationValue.cpp"
    "${library_root}/source/model/DefaultRouteTablePropagationValue.cpp"
    "${library_root}/source/model/DefaultTargetCapacityType.cpp"
    "${library_root}/source/model/DeleteCarrierGatewayRequest.cpp"
    "${library_root}/source/model/DeleteCarrierGatewayResponse.cpp"
    "${library_root}/source/model/DeleteClientVpnEndpointRequest.cpp"
    "${library_root}/source/model/DeleteClientVpnEndpointResponse.cpp"
    "${library_root}/source/model/DeleteClientVpnRouteRequest.cpp"
    "${library_root}/source/model/DeleteClientVpnRouteResponse.cpp"
    "${library_root}/source/model/DeleteCustomerGatewayRequest.cpp"
    "${library_root}/source/model/DeleteDhcpOptionsRequest.cpp"
    "${library_root}/source/model/DeleteEgressOnlyInternetGatewayRequest.cpp"
    "${library_root}/source/model/DeleteEgressOnlyInternetGatewayResponse.cpp"
    "${library_root}/source/model/DeleteFleetErrorCode.cpp"
    "${library_root}/source/model/DeleteFleetError.cpp"
    "${library_root}/source/model/DeleteFleetErrorItem.cpp"
    "${library_root}/source/model/DeleteFleetsRequest.cpp"
    "${library_root}/source/model/DeleteFleetsResponse.cpp"
    "${library_root}/source/model/DeleteFleetSuccessItem.cpp"
    "${library_root}/source/model/DeleteFlowLogsRequest.cpp"
    "${library_root}/source/model/DeleteFlowLogsResponse.cpp"
    "${library_root}/source/model/DeleteFpgaImageRequest.cpp"
    "${library_root}/source/model/DeleteFpgaImageResponse.cpp"
    "${library_root}/source/model/DeleteInstanceEventWindowRequest.cpp"
    "${library_root}/source/model/DeleteInstanceEventWindowResponse.cpp"
    "${library_root}/source/model/DeleteInternetGatewayRequest.cpp"
    "${library_root}/source/model/DeleteKeyPairRequest.cpp"
    "${library_root}/source/model/DeleteLaunchTemplateRequest.cpp"
    "${library_root}/source/model/DeleteLaunchTemplateResponse.cpp"
    "${library_root}/source/model/DeleteLaunchTemplateVersionsRequest.cpp"
    "${library_root}/source/model/DeleteLaunchTemplateVersionsResponse.cpp"
    "${library_root}/source/model/DeleteLaunchTemplateVersionsResponseErrorItem.cpp"
    "${library_root}/source/model/DeleteLaunchTemplateVersionsResponseSuccessItem.cpp"
    "${library_root}/source/model/DeleteLocalGatewayRouteRequest.cpp"
    "${library_root}/source/model/DeleteLocalGatewayRouteResponse.cpp"
    "${library_root}/source/model/DeleteLocalGatewayRouteTableVpcAssociationRequest.cpp"
    "${library_root}/source/model/DeleteLocalGatewayRouteTableVpcAssociationResponse.cpp"
    "${library_root}/source/model/DeleteManagedPrefixListRequest.cpp"
    "${library_root}/source/model/DeleteManagedPrefixListResponse.cpp"
    "${library_root}/source/model/DeleteNatGatewayRequest.cpp"
    "${library_root}/source/model/DeleteNatGatewayResponse.cpp"
    "${library_root}/source/model/DeleteNetworkAclEntryRequest.cpp"
    "${library_root}/source/model/DeleteNetworkAclRequest.cpp"
    "${library_root}/source/model/DeleteNetworkInsightsAnalysisRequest.cpp"
    "${library_root}/source/model/DeleteNetworkInsightsAnalysisResponse.cpp"
    "${library_root}/source/model/DeleteNetworkInsightsPathRequest.cpp"
    "${library_root}/source/model/DeleteNetworkInsightsPathResponse.cpp"
    "${library_root}/source/model/DeleteNetworkInterfacePermissionRequest.cpp"
    "${library_root}/source/model/DeleteNetworkInterfacePermissionResponse.cpp"
    "${library_root}/source/model/DeleteNetworkInterfaceRequest.cpp"
    "${library_root}/source/model/DeletePlacementGroupRequest.cpp"
    "${library_root}/source/model/DeleteQueuedReservedInstancesErrorCode.cpp"
    "${library_root}/source/model/DeleteQueuedReservedInstancesError.cpp"
    "${library_root}/source/model/DeleteQueuedReservedInstancesRequest.cpp"
    "${library_root}/source/model/DeleteQueuedReservedInstancesResponse.cpp"
    "${library_root}/source/model/DeleteRouteRequest.cpp"
    "${library_root}/source/model/DeleteRouteTableRequest.cpp"
    "${library_root}/source/model/DeleteSecurityGroupRequest.cpp"
    "${library_root}/source/model/DeleteSnapshotRequest.cpp"
    "${library_root}/source/model/DeleteSpotDatafeedSubscriptionRequest.cpp"
    "${library_root}/source/model/DeleteSubnetCidrReservationRequest.cpp"
    "${library_root}/source/model/DeleteSubnetCidrReservationResponse.cpp"
    "${library_root}/source/model/DeleteSubnetRequest.cpp"
    "${library_root}/source/model/DeleteTagsRequest.cpp"
    "${library_root}/source/model/DeleteTrafficMirrorFilterRequest.cpp"
    "${library_root}/source/model/DeleteTrafficMirrorFilterResponse.cpp"
    "${library_root}/source/model/DeleteTrafficMirrorFilterRuleRequest.cpp"
    "${library_root}/source/model/DeleteTrafficMirrorFilterRuleResponse.cpp"
    "${library_root}/source/model/DeleteTrafficMirrorSessionRequest.cpp"
    "${library_root}/source/model/DeleteTrafficMirrorSessionResponse.cpp"
    "${library_root}/source/model/DeleteTrafficMirrorTargetRequest.cpp"
    "${library_root}/source/model/DeleteTrafficMirrorTargetResponse.cpp"
    "${library_root}/source/model/DeleteTransitGatewayConnectPeerRequest.cpp"
    "${library_root}/source/model/DeleteTransitGatewayConnectPeerResponse.cpp"
    "${library_root}/source/model/DeleteTransitGatewayConnectRequest.cpp"
    "${library_root}/source/model/DeleteTransitGatewayConnectResponse.cpp"
    "${library_root}/source/model/DeleteTransitGatewayMulticastDomainRequest.cpp"
    "${library_root}/source/model/DeleteTransitGatewayMulticastDomainResponse.cpp"
    "${library_root}/source/model/DeleteTransitGatewayPeeringAttachmentRequest.cpp"
    "${library_root}/source/model/DeleteTransitGatewayPeeringAttachmentResponse.cpp"
    "${library_root}/source/model/DeleteTransitGatewayPrefixListReferenceRequest.cpp"
    "${library_root}/source/model/DeleteTransitGatewayPrefixListReferenceResponse.cpp"
    "${library_root}/source/model/DeleteTransitGatewayRequest.cpp"
    "${library_root}/source/model/DeleteTransitGatewayResponse.cpp"
    "${library_root}/source/model/DeleteTransitGatewayRouteRequest.cpp"
    "${library_root}/source/model/DeleteTransitGatewayRouteResponse.cpp"
    "${library_root}/source/model/DeleteTransitGatewayRouteTableRequest.cpp"
    "${library_root}/source/model/DeleteTransitGatewayRouteTableResponse.cpp"
    "${library_root}/source/model/DeleteTransitGatewayVpcAttachmentRequest.cpp"
    "${library_root}/source/model/DeleteTransitGatewayVpcAttachmentResponse.cpp"
    "${library_root}/source/model/DeleteVolumeRequest.cpp"
    "${library_root}/source/model/DeleteVpcEndpointConnectionNotificationsRequest.cpp"
    "${library_root}/source/model/DeleteVpcEndpointConnectionNotificationsResponse.cpp"
    "${library_root}/source/model/DeleteVpcEndpointServiceConfigurationsRequest.cpp"
    "${library_root}/source/model/DeleteVpcEndpointServiceConfigurationsResponse.cpp"
    "${library_root}/source/model/DeleteVpcEndpointsRequest.cpp"
    "${library_root}/source/model/DeleteVpcEndpointsResponse.cpp"
    "${library_root}/source/model/DeleteVpcPeeringConnectionRequest.cpp"
    "${library_root}/source/model/DeleteVpcPeeringConnectionResponse.cpp"
    "${library_root}/source/model/DeleteVpcRequest.cpp"
    "${library_root}/source/model/DeleteVpnConnectionRequest.cpp"
    "${library_root}/source/model/DeleteVpnConnectionRouteRequest.cpp"
    "${library_root}/source/model/DeleteVpnGatewayRequest.cpp"
    "${library_root}/source/model/DeprovisionByoipCidrRequest.cpp"
    "${library_root}/source/model/DeprovisionByoipCidrResponse.cpp"
    "${library_root}/source/model/DeregisterImageRequest.cpp"
    "${library_root}/source/model/DeregisterInstanceEventNotificationAttributesRequest.cpp"
    "${library_root}/source/model/DeregisterInstanceEventNotificationAttributesResponse.cpp"
    "${library_root}/source/model/DeregisterInstanceTagAttributeRequest.cpp"
    "${library_root}/source/model/DeregisterTransitGatewayMulticastGroupMembersRequest.cpp"
    "${library_root}/source/model/DeregisterTransitGatewayMulticastGroupMembersResponse.cpp"
    "${library_root}/source/model/DeregisterTransitGatewayMulticastGroupSourcesRequest.cpp"
    "${library_root}/source/model/DeregisterTransitGatewayMulticastGroupSourcesResponse.cpp"
    "${library_root}/source/model/DescribeAccountAttributesRequest.cpp"
    "${library_root}/source/model/DescribeAccountAttributesResponse.cpp"
    "${library_root}/source/model/DescribeAddressesAttributeRequest.cpp"
    "${library_root}/source/model/DescribeAddressesAttributeResponse.cpp"
    "${library_root}/source/model/DescribeAddressesRequest.cpp"
    "${library_root}/source/model/DescribeAddressesResponse.cpp"
    "${library_root}/source/model/DescribeAggregateIdFormatRequest.cpp"
    "${library_root}/source/model/DescribeAggregateIdFormatResponse.cpp"
    "${library_root}/source/model/DescribeAvailabilityZonesRequest.cpp"
    "${library_root}/source/model/DescribeAvailabilityZonesResponse.cpp"
    "${library_root}/source/model/DescribeBundleTasksRequest.cpp"
    "${library_root}/source/model/DescribeBundleTasksResponse.cpp"
    "${library_root}/source/model/DescribeByoipCidrsRequest.cpp"
    "${library_root}/source/model/DescribeByoipCidrsResponse.cpp"
    "${library_root}/source/model/DescribeCapacityReservationFleetsRequest.cpp"
    "${library_root}/source/model/DescribeCapacityReservationFleetsResponse.cpp"
    "${library_root}/source/model/DescribeCapacityReservationsRequest.cpp"
    "${library_root}/source/model/DescribeCapacityReservationsResponse.cpp"
    "${library_root}/source/model/DescribeCarrierGatewaysRequest.cpp"
    "${library_root}/source/model/DescribeCarrierGatewaysResponse.cpp"
    "${library_root}/source/model/DescribeClassicLinkInstancesRequest.cpp"
    "${library_root}/source/model/DescribeClassicLinkInstancesResponse.cpp"
    "${library_root}/source/model/DescribeClientVpnAuthorizationRulesRequest.cpp"
    "${library_root}/source/model/DescribeClientVpnAuthorizationRulesResponse.cpp"
    "${library_root}/source/model/DescribeClientVpnConnectionsRequest.cpp"
    "${library_root}/source/model/DescribeClientVpnConnectionsResponse.cpp"
    "${library_root}/source/model/DescribeClientVpnEndpointsRequest.cpp"
    "${library_root}/source/model/DescribeClientVpnEndpointsResponse.cpp"
    "${library_root}/source/model/DescribeClientVpnRoutesRequest.cpp"
    "${library_root}/source/model/DescribeClientVpnRoutesResponse.cpp"
    "${library_root}/source/model/DescribeClientVpnTargetNetworksRequest.cpp"
    "${library_root}/source/model/DescribeClientVpnTargetNetworksResponse.cpp"
    "${library_root}/source/model/DescribeCoipPoolsRequest.cpp"
    "${library_root}/source/model/DescribeCoipPoolsResponse.cpp"
    "${library_root}/source/model/DescribeConversionTasksRequest.cpp"
    "${library_root}/source/model/DescribeConversionTasksResponse.cpp"
    "${library_root}/source/model/DescribeCustomerGatewaysRequest.cpp"
    "${library_root}/source/model/DescribeCustomerGatewaysResponse.cpp"
    "${library_root}/source/model/DescribeDhcpOptionsRequest.cpp"
    "${library_root}/source/model/DescribeDhcpOptionsResponse.cpp"
    "${library_root}/source/model/DescribeEgressOnlyInternetGatewaysRequest.cpp"
    "${library_root}/source/model/DescribeEgressOnlyInternetGatewaysResponse.cpp"
    "${library_root}/source/model/DescribeElasticGpusRequest.cpp"
    "${library_root}/source/model/DescribeElasticGpusResponse.cpp"
    "${library_root}/source/model/DescribeExportImageTasksRequest.cpp"
    "${library_root}/source/model/DescribeExportImageTasksResponse.cpp"
    "${library_root}/source/model/DescribeExportTasksRequest.cpp"
    "${library_root}/source/model/DescribeExportTasksResponse.cpp"
    "${library_root}/source/model/DescribeFastSnapshotRestoresRequest.cpp"
    "${library_root}/source/model/DescribeFastSnapshotRestoresResponse.cpp"
    "${library_root}/source/model/DescribeFastSnapshotRestoreSuccessItem.cpp"
    "${library_root}/source/model/DescribeFleetError.cpp"
    "${library_root}/source/model/DescribeFleetHistoryRequest.cpp"
    "${library_root}/source/model/DescribeFleetHistoryResponse.cpp"
    "${library_root}/source/model/DescribeFleetInstancesRequest.cpp"
    "${library_root}/source/model/DescribeFleetInstancesResponse.cpp"
    "${library_root}/source/model/DescribeFleetsInstances.cpp"
    "${library_root}/source/model/DescribeFleetsRequest.cpp"
    "${library_root}/source/model/DescribeFleetsResponse.cpp"
    "${library_root}/source/model/DescribeFlowLogsRequest.cpp"
    "${library_root}/source/model/DescribeFlowLogsResponse.cpp"
    "${library_root}/source/model/DescribeFpgaImageAttributeRequest.cpp"
    "${library_root}/source/model/DescribeFpgaImageAttributeResponse.cpp"
    "${library_root}/source/model/DescribeFpgaImagesRequest.cpp"
    "${library_root}/source/model/DescribeFpgaImagesResponse.cpp"
    "${library_root}/source/model/DescribeHostReservationOfferingsRequest.cpp"
    "${library_root}/source/model/DescribeHostReservationOfferingsResponse.cpp"
    "${library_root}/source/model/DescribeHostReservationsRequest.cpp"
    "${library_root}/source/model/DescribeHostReservationsResponse.cpp"
    "${library_root}/source/model/DescribeHostsRequest.cpp"
    "${library_root}/source/model/DescribeHostsResponse.cpp"
    "${library_root}/source/model/DescribeIamInstanceProfileAssociationsRequest.cpp"
    "${library_root}/source/model/DescribeIamInstanceProfileAssociationsResponse.cpp"
    "${library_root}/source/model/DescribeIdentityIdFormatRequest.cpp"
    "${library_root}/source/model/DescribeIdentityIdFormatResponse.cpp"
    "${library_root}/source/model/DescribeIdFormatRequest.cpp"
    "${library_root}/source/model/DescribeIdFormatResponse.cpp"
    "${library_root}/source/model/DescribeImageAttributeRequest.cpp"
    "${library_root}/source/model/DescribeImageAttributeResponse.cpp"
    "${library_root}/source/model/DescribeImagesRequest.cpp"
    "${library_root}/source/model/DescribeImagesResponse.cpp"
    "${library_root}/source/model/DescribeImportImageTasksRequest.cpp"
    "${library_root}/source/model/DescribeImportImageTasksResponse.cpp"
    "${library_root}/source/model/DescribeImportSnapshotTasksRequest.cpp"
    "${library_root}/source/model/DescribeImportSnapshotTasksResponse.cpp"
    "${library_root}/source/model/DescribeInstanceAttributeRequest.cpp"
    "${library_root}/source/model/DescribeInstanceAttributeResponse.cpp"
    "${library_root}/source/model/DescribeInstanceCreditSpecificationsRequest.cpp"
    "${library_root}/source/model/DescribeInstanceCreditSpecificationsResponse.cpp"
    "${library_root}/source/model/DescribeInstanceEventNotificationAttributesRequest.cpp"
    "${library_root}/source/model/DescribeInstanceEventNotificationAttributesResponse.cpp"
    "${library_root}/source/model/DescribeInstanceEventWindowsRequest.cpp"
    "${library_root}/source/model/DescribeInstanceEventWindowsResponse.cpp"
    "${library_root}/source/model/DescribeInstancesRequest.cpp"
    "${library_root}/source/model/DescribeInstancesResponse.cpp"
    "${library_root}/source/model/DescribeInstanceStatusRequest.cpp"
    "${library_root}/source/model/DescribeInstanceStatusResponse.cpp"
    "${library_root}/source/model/DescribeInstanceTypeOfferingsRequest.cpp"
    "${library_root}/source/model/DescribeInstanceTypeOfferingsResponse.cpp"
    "${library_root}/source/model/DescribeInstanceTypesRequest.cpp"
    "${library_root}/source/model/DescribeInstanceTypesResponse.cpp"
    "${library_root}/source/model/DescribeInternetGatewaysRequest.cpp"
    "${library_root}/source/model/DescribeInternetGatewaysResponse.cpp"
    "${library_root}/source/model/DescribeIpv6PoolsRequest.cpp"
    "${library_root}/source/model/DescribeIpv6PoolsResponse.cpp"
    "${library_root}/source/model/DescribeKeyPairsRequest.cpp"
    "${library_root}/source/model/DescribeKeyPairsResponse.cpp"
    "${library_root}/source/model/DescribeLaunchTemplatesRequest.cpp"
    "${library_root}/source/model/DescribeLaunchTemplatesResponse.cpp"
    "${library_root}/source/model/DescribeLaunchTemplateVersionsRequest.cpp"
    "${library_root}/source/model/DescribeLaunchTemplateVersionsResponse.cpp"
    "${library_root}/source/model/DescribeLocalGatewayRouteTablesRequest.cpp"
    "${library_root}/source/model/DescribeLocalGatewayRouteTablesResponse.cpp"
    "${library_root}/source/model/DescribeLocalGatewayRouteTableVirtualInterfaceGroupAssociationsRequest.cpp"
    "${library_root}/source/model/DescribeLocalGatewayRouteTableVirtualInterfaceGroupAssociationsResponse.cpp"
    "${library_root}/source/model/DescribeLocalGatewayRouteTableVpcAssociationsRequest.cpp"
    "${library_root}/source/model/DescribeLocalGatewayRouteTableVpcAssociationsResponse.cpp"
    "${library_root}/source/model/DescribeLocalGatewaysRequest.cpp"
    "${library_root}/source/model/DescribeLocalGatewaysResponse.cpp"
    "${library_root}/source/model/DescribeLocalGatewayVirtualInterfaceGroupsRequest.cpp"
    "${library_root}/source/model/DescribeLocalGatewayVirtualInterfaceGroupsResponse.cpp"
    "${library_root}/source/model/DescribeLocalGatewayVirtualInterfacesRequest.cpp"
    "${library_root}/source/model/DescribeLocalGatewayVirtualInterfacesResponse.cpp"
    "${library_root}/source/model/DescribeManagedPrefixListsRequest.cpp"
    "${library_root}/source/model/DescribeManagedPrefixListsResponse.cpp"
    "${library_root}/source/model/DescribeMovingAddressesRequest.cpp"
    "${library_root}/source/model/DescribeMovingAddressesResponse.cpp"
    "${library_root}/source/model/DescribeNatGatewaysRequest.cpp"
    "${library_root}/source/model/DescribeNatGatewaysResponse.cpp"
    "${library_root}/source/model/DescribeNetworkAclsRequest.cpp"
    "${library_root}/source/model/DescribeNetworkAclsResponse.cpp"
    "${library_root}/source/model/DescribeNetworkInsightsAnalysesRequest.cpp"
    "${library_root}/source/model/DescribeNetworkInsightsAnalysesResponse.cpp"
    "${library_root}/source/model/DescribeNetworkInsightsPathsRequest.cpp"
    "${library_root}/source/model/DescribeNetworkInsightsPathsResponse.cpp"
    "${library_root}/source/model/DescribeNetworkInterfaceAttributeRequest.cpp"
    "${library_root}/source/model/DescribeNetworkInterfaceAttributeResponse.cpp"
    "${library_root}/source/model/DescribeNetworkInterfacePermissionsRequest.cpp"
    "${library_root}/source/model/DescribeNetworkInterfacePermissionsResponse.cpp"
    "${library_root}/source/model/DescribeNetworkInterfacesRequest.cpp"
    "${library_root}/source/model/DescribeNetworkInterfacesResponse.cpp"
    "${library_root}/source/model/DescribePlacementGroupsRequest.cpp"
    "${library_root}/source/model/DescribePlacementGroupsResponse.cpp"
    "${library_root}/source/model/DescribePrefixListsRequest.cpp"
    "${library_root}/source/model/DescribePrefixListsResponse.cpp"
    "${library_root}/source/model/DescribePrincipalIdFormatRequest.cpp"
    "${library_root}/source/model/DescribePrincipalIdFormatResponse.cpp"
    "${library_root}/source/model/DescribePublicIpv4PoolsRequest.cpp"
    "${library_root}/source/model/DescribePublicIpv4PoolsResponse.cpp"
    "${library_root}/source/model/DescribeRegionsRequest.cpp"
    "${library_root}/source/model/DescribeRegionsResponse.cpp"
    "${library_root}/source/model/DescribeReplaceRootVolumeTasksRequest.cpp"
    "${library_root}/source/model/DescribeReplaceRootVolumeTasksResponse.cpp"
    "${library_root}/source/model/DescribeReservedInstancesListingsRequest.cpp"
    "${library_root}/source/model/DescribeReservedInstancesListingsResponse.cpp"
    "${library_root}/source/model/DescribeReservedInstancesModificationsRequest.cpp"
    "${library_root}/source/model/DescribeReservedInstancesModificationsResponse.cpp"
    "${library_root}/source/model/DescribeReservedInstancesOfferingsRequest.cpp"
    "${library_root}/source/model/DescribeReservedInstancesOfferingsResponse.cpp"
    "${library_root}/source/model/DescribeReservedInstancesRequest.cpp"
    "${library_root}/source/model/DescribeReservedInstancesResponse.cpp"
    "${library_root}/source/model/DescribeRouteTablesRequest.cpp"
    "${library_root}/source/model/DescribeRouteTablesResponse.cpp"
    "${library_root}/source/model/DescribeScheduledInstanceAvailabilityRequest.cpp"
    "${library_root}/source/model/DescribeScheduledInstanceAvailabilityResponse.cpp"
    "${library_root}/source/model/DescribeScheduledInstancesRequest.cpp"
    "${library_root}/source/model/DescribeScheduledInstancesResponse.cpp"
    "${library_root}/source/model/DescribeSecurityGroupReferencesRequest.cpp"
    "${library_root}/source/model/DescribeSecurityGroupReferencesResponse.cpp"
    "${library_root}/source/model/DescribeSecurityGroupRulesRequest.cpp"
    "${library_root}/source/model/DescribeSecurityGroupRulesResponse.cpp"
    "${library_root}/source/model/DescribeSecurityGroupsRequest.cpp"
    "${library_root}/source/model/DescribeSecurityGroupsResponse.cpp"
    "${library_root}/source/model/DescribeSnapshotAttributeRequest.cpp"
    "${library_root}/source/model/DescribeSnapshotAttributeResponse.cpp"
    "${library_root}/source/model/DescribeSnapshotsRequest.cpp"
    "${library_root}/source/model/DescribeSnapshotsResponse.cpp"
    "${library_root}/source/model/DescribeSpotDatafeedSubscriptionRequest.cpp"
    "${library_root}/source/model/DescribeSpotDatafeedSubscriptionResponse.cpp"
    "${library_root}/source/model/DescribeSpotFleetInstancesRequest.cpp"
    "${library_root}/source/model/DescribeSpotFleetInstancesResponse.cpp"
    "${library_root}/source/model/DescribeSpotFleetRequestHistoryRequest.cpp"
    "${library_root}/source/model/DescribeSpotFleetRequestHistoryResponse.cpp"
    "${library_root}/source/model/DescribeSpotFleetRequestsRequest.cpp"
    "${library_root}/source/model/DescribeSpotFleetRequestsResponse.cpp"
    "${library_root}/source/model/DescribeSpotInstanceRequestsRequest.cpp"
    "${library_root}/source/model/DescribeSpotInstanceRequestsResponse.cpp"
    "${library_root}/source/model/DescribeSpotPriceHistoryRequest.cpp"
    "${library_root}/source/model/DescribeSpotPriceHistoryResponse.cpp"
    "${library_root}/source/model/DescribeStaleSecurityGroupsRequest.cpp"
    "${library_root}/source/model/DescribeStaleSecurityGroupsResponse.cpp"
    "${library_root}/source/model/DescribeStoreImageTasksRequest.cpp"
    "${library_root}/source/model/DescribeStoreImageTasksResponse.cpp"
    "${library_root}/source/model/DescribeSubnetsRequest.cpp"
    "${library_root}/source/model/DescribeSubnetsResponse.cpp"
    "${library_root}/source/model/DescribeTagsRequest.cpp"
    "${library_root}/source/model/DescribeTagsResponse.cpp"
    "${library_root}/source/model/DescribeTrafficMirrorFiltersRequest.cpp"
    "${library_root}/source/model/DescribeTrafficMirrorFiltersResponse.cpp"
    "${library_root}/source/model/DescribeTrafficMirrorSessionsRequest.cpp"
    "${library_root}/source/model/DescribeTrafficMirrorSessionsResponse.cpp"
    "${library_root}/source/model/DescribeTrafficMirrorTargetsRequest.cpp"
    "${library_root}/source/model/DescribeTrafficMirrorTargetsResponse.cpp"
    "${library_root}/source/model/DescribeTransitGatewayAttachmentsRequest.cpp"
    "${library_root}/source/model/DescribeTransitGatewayAttachmentsResponse.cpp"
    "${library_root}/source/model/DescribeTransitGatewayConnectPeersRequest.cpp"
    "${library_root}/source/model/DescribeTransitGatewayConnectPeersResponse.cpp"
    "${library_root}/source/model/DescribeTransitGatewayConnectsRequest.cpp"
    "${library_root}/source/model/DescribeTransitGatewayConnectsResponse.cpp"
    "${library_root}/source/model/DescribeTransitGatewayMulticastDomainsRequest.cpp"
    "${library_root}/source/model/DescribeTransitGatewayMulticastDomainsResponse.cpp"
    "${library_root}/source/model/DescribeTransitGatewayPeeringAttachmentsRequest.cpp"
    "${library_root}/source/model/DescribeTransitGatewayPeeringAttachmentsResponse.cpp"
    "${library_root}/source/model/DescribeTransitGatewayRouteTablesRequest.cpp"
    "${library_root}/source/model/DescribeTransitGatewayRouteTablesResponse.cpp"
    "${library_root}/source/model/DescribeTransitGatewaysRequest.cpp"
    "${library_root}/source/model/DescribeTransitGatewaysResponse.cpp"
    "${library_root}/source/model/DescribeTransitGatewayVpcAttachmentsRequest.cpp"
    "${library_root}/source/model/DescribeTransitGatewayVpcAttachmentsResponse.cpp"
    "${library_root}/source/model/DescribeTrunkInterfaceAssociationsRequest.cpp"
    "${library_root}/source/model/DescribeTrunkInterfaceAssociationsResponse.cpp"
    "${library_root}/source/model/DescribeVolumeAttributeRequest.cpp"
    "${library_root}/source/model/DescribeVolumeAttributeResponse.cpp"
    "${library_root}/source/model/DescribeVolumesModificationsRequest.cpp"
    "${library_root}/source/model/DescribeVolumesModificationsResponse.cpp"
    "${library_root}/source/model/DescribeVolumesRequest.cpp"
    "${library_root}/source/model/DescribeVolumesResponse.cpp"
    "${library_root}/source/model/DescribeVolumeStatusRequest.cpp"
    "${library_root}/source/model/DescribeVolumeStatusResponse.cpp"
    "${library_root}/source/model/DescribeVpcAttributeRequest.cpp"
    "${library_root}/source/model/DescribeVpcAttributeResponse.cpp"
    "${library_root}/source/model/DescribeVpcClassicLinkDnsSupportRequest.cpp"
    "${library_root}/source/model/DescribeVpcClassicLinkDnsSupportResponse.cpp"
    "${library_root}/source/model/DescribeVpcClassicLinkRequest.cpp"
    "${library_root}/source/model/DescribeVpcClassicLinkResponse.cpp"
    "${library_root}/source/model/DescribeVpcEndpointConnectionNotificationsRequest.cpp"
    "${library_root}/source/model/DescribeVpcEndpointConnectionNotificationsResponse.cpp"
    "${library_root}/source/model/DescribeVpcEndpointConnectionsRequest.cpp"
    "${library_root}/source/model/DescribeVpcEndpointConnectionsResponse.cpp"
    "${library_root}/source/model/DescribeVpcEndpointServiceConfigurationsRequest.cpp"
    "${library_root}/source/model/DescribeVpcEndpointServiceConfigurationsResponse.cpp"
    "${library_root}/source/model/DescribeVpcEndpointServicePermissionsRequest.cpp"
    "${library_root}/source/model/DescribeVpcEndpointServicePermissionsResponse.cpp"
    "${library_root}/source/model/DescribeVpcEndpointServicesRequest.cpp"
    "${library_root}/source/model/DescribeVpcEndpointServicesResponse.cpp"
    "${library_root}/source/model/DescribeVpcEndpointsRequest.cpp"
    "${library_root}/source/model/DescribeVpcEndpointsResponse.cpp"
    "${library_root}/source/model/DescribeVpcPeeringConnectionsRequest.cpp"
    "${library_root}/source/model/DescribeVpcPeeringConnectionsResponse.cpp"
    "${library_root}/source/model/DescribeVpcsRequest.cpp"
    "${library_root}/source/model/DescribeVpcsResponse.cpp"
    "${library_root}/source/model/DescribeVpnConnectionsRequest.cpp"
    "${library_root}/source/model/DescribeVpnConnectionsResponse.cpp"
    "${library_root}/source/model/DescribeVpnGatewaysRequest.cpp"
    "${library_root}/source/model/DescribeVpnGatewaysResponse.cpp"
    "${library_root}/source/model/DetachClassicLinkVpcRequest.cpp"
    "${library_root}/source/model/DetachClassicLinkVpcResponse.cpp"
    "${library_root}/source/model/DetachInternetGatewayRequest.cpp"
    "${library_root}/source/model/DetachNetworkInterfaceRequest.cpp"
    "${library_root}/source/model/DetachVolumeRequest.cpp"
    "${library_root}/source/model/DetachVolumeResponse.cpp"
    "${library_root}/source/model/DetachVpnGatewayRequest.cpp"
    "${library_root}/source/model/DeviceType.cpp"
    "${library_root}/source/model/DhcpConfiguration.cpp"
    "${library_root}/source/model/DhcpOptions.cpp"
    "${library_root}/source/model/DirectoryServiceAuthentication.cpp"
    "${library_root}/source/model/DirectoryServiceAuthenticationRequest.cpp"
    "${library_root}/source/model/DisableEbsEncryptionByDefaultRequest.cpp"
    "${library_root}/source/model/DisableEbsEncryptionByDefaultResponse.cpp"
    "${library_root}/source/model/DisableFastSnapshotRestoreErrorItem.cpp"
    "${library_root}/source/model/DisableFastSnapshotRestoresRequest.cpp"
    "${library_root}/source/model/DisableFastSnapshotRestoresResponse.cpp"
    "${library_root}/source/model/DisableFastSnapshotRestoreStateError.cpp"
    "${library_root}/source/model/DisableFastSnapshotRestoreStateErrorItem.cpp"
    "${library_root}/source/model/DisableFastSnapshotRestoreSuccessItem.cpp"
    "${library_root}/source/model/DisableImageDeprecationRequest.cpp"
    "${library_root}/source/model/DisableImageDeprecationResponse.cpp"
    "${library_root}/source/model/DisableSerialConsoleAccessRequest.cpp"
    "${library_root}/source/model/DisableSerialConsoleAccessResponse.cpp"
    "${library_root}/source/model/DisableTransitGatewayRouteTablePropagationRequest.cpp"
    "${library_root}/source/model/DisableTransitGatewayRouteTablePropagationResponse.cpp"
    "${library_root}/source/model/DisableVgwRoutePropagationRequest.cpp"
    "${library_root}/source/model/DisableVpcClassicLinkDnsSupportRequest.cpp"
    "${library_root}/source/model/DisableVpcClassicLinkDnsSupportResponse.cpp"
    "${library_root}/source/model/DisableVpcClassicLinkRequest.cpp"
    "${library_root}/source/model/DisableVpcClassicLinkResponse.cpp"
    "${library_root}/source/model/DisassociateAddressRequest.cpp"
    "${library_root}/source/model/DisassociateClientVpnTargetNetworkRequest.cpp"
    "${library_root}/source/model/DisassociateClientVpnTargetNetworkResponse.cpp"
    "${library_root}/source/model/DisassociateEnclaveCertificateIamRoleRequest.cpp"
    "${library_root}/source/model/DisassociateEnclaveCertificateIamRoleResponse.cpp"
    "${library_root}/source/model/DisassociateIamInstanceProfileRequest.cpp"
    "${library_root}/source/model/DisassociateIamInstanceProfileResponse.cpp"
    "${library_root}/source/model/DisassociateInstanceEventWindowRequest.cpp"
    "${library_root}/source/model/DisassociateInstanceEventWindowResponse.cpp"
    "${library_root}/source/model/DisassociateRouteTableRequest.cpp"
    "${library_root}/source/model/DisassociateSubnetCidrBlockRequest.cpp"
    "${library_root}/source/model/DisassociateSubnetCidrBlockResponse.cpp"
    "${library_root}/source/model/DisassociateTransitGatewayMulticastDomainRequest.cpp"
    "${library_root}/source/model/DisassociateTransitGatewayMulticastDomainResponse.cpp"
    "${library_root}/source/model/DisassociateTransitGatewayRouteTableRequest.cpp"
    "${library_root}/source/model/DisassociateTransitGatewayRouteTableResponse.cpp"
    "${library_root}/source/model/DisassociateTrunkInterfaceRequest.cpp"
    "${library_root}/source/model/DisassociateTrunkInterfaceResponse.cpp"
    "${library_root}/source/model/DisassociateVpcCidrBlockRequest.cpp"
    "${library_root}/source/model/DisassociateVpcCidrBlockResponse.cpp"
    "${library_root}/source/model/DiskImage.cpp"
    "${library_root}/source/model/DiskImageDescription.cpp"
    "${library_root}/source/model/DiskImageDetail.cpp"
    "${library_root}/source/model/DiskImageFormat.cpp"
    "${library_root}/source/model/DiskImageVolumeDescription.cpp"
    "${library_root}/source/model/DiskInfo.cpp"
    "${library_root}/source/model/DiskType.cpp"
    "${library_root}/source/model/DnsEntry.cpp"
    "${library_root}/source/model/DnsNameState.cpp"
    "${library_root}/source/model/DnsServersOptionsModifyStructure.cpp"
    "${library_root}/source/model/DnsSupportValue.cpp"
    "${library_root}/source/model/DomainType.cpp"
    "${library_root}/source/model/EbsBlockDevice.cpp"
    "${library_root}/source/model/EbsEncryptionSupport.cpp"
    "${library_root}/source/model/EbsInfo.cpp"
    "${library_root}/source/model/EbsInstanceBlockDevice.cpp"
    "${library_root}/source/model/EbsInstanceBlockDeviceSpecification.cpp"
    "${library_root}/source/model/EbsNvmeSupport.cpp"
    "${library_root}/source/model/EbsOptimizedInfo.cpp"
    "${library_root}/source/model/EbsOptimizedSupport.cpp"
    "${library_root}/source/model/EfaInfo.cpp"
    "${library_root}/source/model/EgressOnlyInternetGateway.cpp"
    "${library_root}/source/model/ElasticGpuAssociation.cpp"
    "${library_root}/source/model/ElasticGpuHealth.cpp"
    "${library_root}/source/model/ElasticGpus.cpp"
    "${library_root}/source/model/ElasticGpuSpecification.cpp"
    "${library_root}/source/model/ElasticGpuSpecificationResponse.cpp"
    "${library_root}/source/model/ElasticGpuState.cpp"
    "${library_root}/source/model/ElasticGpuStatus.cpp"
    "${library_root}/source/model/ElasticInferenceAcceleratorAssociation.cpp"
    "${library_root}/source/model/ElasticInferenceAccelerator.cpp"
    "${library_root}/source/model/EnableEbsEncryptionByDefaultRequest.cpp"
    "${library_root}/source/model/EnableEbsEncryptionByDefaultResponse.cpp"
    "${library_root}/source/model/EnableFastSnapshotRestoreErrorItem.cpp"
    "${library_root}/source/model/EnableFastSnapshotRestoresRequest.cpp"
    "${library_root}/source/model/EnableFastSnapshotRestoresResponse.cpp"
    "${library_root}/source/model/EnableFastSnapshotRestoreStateError.cpp"
    "${library_root}/source/model/EnableFastSnapshotRestoreStateErrorItem.cpp"
    "${library_root}/source/model/EnableFastSnapshotRestoreSuccessItem.cpp"
    "${library_root}/source/model/EnableImageDeprecationRequest.cpp"
    "${library_root}/source/model/EnableImageDeprecationResponse.cpp"
    "${library_root}/source/model/EnableSerialConsoleAccessRequest.cpp"
    "${library_root}/source/model/EnableSerialConsoleAccessResponse.cpp"
    "${library_root}/source/model/EnableTransitGatewayRouteTablePropagationRequest.cpp"
    "${library_root}/source/model/EnableTransitGatewayRouteTablePropagationResponse.cpp"
    "${library_root}/source/model/EnableVgwRoutePropagationRequest.cpp"
    "${library_root}/source/model/EnableVolumeIORequest.cpp"
    "${library_root}/source/model/EnableVpcClassicLinkDnsSupportRequest.cpp"
    "${library_root}/source/model/EnableVpcClassicLinkDnsSupportResponse.cpp"
    "${library_root}/source/model/EnableVpcClassicLinkRequest.cpp"
    "${library_root}/source/model/EnableVpcClassicLinkResponse.cpp"
    "${library_root}/source/model/EnaSupport.cpp"
    "${library_root}/source/model/EnclaveOptions.cpp"
    "${library_root}/source/model/EnclaveOptionsRequest.cpp"
    "${library_root}/source/model/EndDateType.cpp"
    "${library_root}/source/model/EphemeralNvmeSupport.cpp"
    "${library_root}/source/model/EventCode.cpp"
    "${library_root}/source/model/EventInformation.cpp"
    "${library_root}/source/model/EventType.cpp"
    "${library_root}/source/model/ExcessCapacityTerminationPolicy.cpp"
    "${library_root}/source/model/Explanation.cpp"
    "${library_root}/source/model/ExportClientVpnClientCertificateRevocationListRequest.cpp"
    "${library_root}/source/model/ExportClientVpnClientCertificateRevocationListResponse.cpp"
    "${library_root}/source/model/ExportClientVpnClientConfigurationRequest.cpp"
    "${library_root}/source/model/ExportClientVpnClientConfigurationResponse.cpp"
    "${library_root}/source/model/ExportEnvironment.cpp"
    "${library_root}/source/model/ExportImageRequest.cpp"
    "${library_root}/source/model/ExportImageResponse.cpp"
    "${library_root}/source/model/ExportImageTask.cpp"
    "${library_root}/source/model/ExportTask.cpp"
    "${library_root}/source/model/ExportTaskS3Location.cpp"
    "${library_root}/source/model/ExportTaskS3LocationRequest.cpp"
    "${library_root}/source/model/ExportTaskState.cpp"
    "${library_root}/source/model/ExportToS3Task.cpp"
    "${library_root}/source/model/ExportToS3TaskSpecification.cpp"
    "${library_root}/source/model/ExportTransitGatewayRoutesRequest.cpp"
    "${library_root}/source/model/ExportTransitGatewayRoutesResponse.cpp"
    "${library_root}/source/model/FailedCapacityReservationFleetCancellationResponse.cpp"
    "${library_root}/source/model/FailedQueuedPurchaseDeletion.cpp"
    "${library_root}/source/model/FastSnapshotRestoreStateCode.cpp"
    "${library_root}/source/model/FederatedAuthentication.cpp"
    "${library_root}/source/model/FederatedAuthenticationRequest.cpp"
    "${library_root}/source/model/Filter.cpp"
    "${library_root}/source/model/FleetActivityStatus.cpp"
    "${library_root}/source/model/FleetCapacityReservation.cpp"
    "${library_root}/source/model/FleetCapacityReservationTenancy.cpp"
    "${library_root}/source/model/FleetCapacityReservationUsageStrategy.cpp"
    "${library_root}/source/model/FleetData.cpp"
    "${library_root}/source/model/FleetEventType.cpp"
    "${library_root}/source/model/FleetExcessCapacityTerminationPolicy.cpp"
    "${library_root}/source/model/FleetInstanceMatchCriteria.cpp"
    "${library_root}/source/model/FleetLaunchTemplateConfig.cpp"
    "${library_root}/source/model/FleetLaunchTemplateConfigRequest.cpp"
    "${library_root}/source/model/FleetLaunchTemplateOverrides.cpp"
    "${library_root}/source/model/FleetLaunchTemplateOverridesRequest.cpp"
    "${library_root}/source/model/FleetLaunchTemplateSpecification.cpp"
    "${library_root}/source/model/FleetLaunchTemplateSpecificationRequest.cpp"
    "${library_root}/source/model/FleetOnDemandAllocationStrategy.cpp"
    "${library_root}/source/model/FleetReplacementStrategy.cpp"
    "${library_root}/source/model/FleetSpotCapacityRebalance.cpp"
    "${library_root}/source/model/FleetSpotCapacityRebalanceRequest.cpp"
    "${library_root}/source/model/FleetSpotMaintenanceStrategies.cpp"
    "${library_root}/source/model/FleetSpotMaintenanceStrategiesRequest.cpp"
    "${library_root}/source/model/FleetStateCode.cpp"
    "${library_root}/source/model/FleetType.cpp"
    "${library_root}/source/model/FlowLog.cpp"
    "${library_root}/source/model/FlowLogsResourceType.cpp"
    "${library_root}/source/model/FpgaDeviceInfo.cpp"
    "${library_root}/source/model/FpgaDeviceMemoryInfo.cpp"
    "${library_root}/source/model/FpgaImageAttribute.cpp"
    "${library_root}/source/model/FpgaImageAttributeName.cpp"
    "${library_root}/source/model/FpgaImage.cpp"
    "${library_root}/source/model/FpgaImageStateCode.cpp"
    "${library_root}/source/model/FpgaImageState.cpp"
    "${library_root}/source/model/FpgaInfo.cpp"
    "${library_root}/source/model/GatewayType.cpp"
    "${library_root}/source/model/GetAssociatedEnclaveCertificateIamRolesRequest.cpp"
    "${library_root}/source/model/GetAssociatedEnclaveCertificateIamRolesResponse.cpp"
    "${library_root}/source/model/GetAssociatedIpv6PoolCidrsRequest.cpp"
    "${library_root}/source/model/GetAssociatedIpv6PoolCidrsResponse.cpp"
    "${library_root}/source/model/GetCapacityReservationUsageRequest.cpp"
    "${library_root}/source/model/GetCapacityReservationUsageResponse.cpp"
    "${library_root}/source/model/GetCoipPoolUsageRequest.cpp"
    "${library_root}/source/model/GetCoipPoolUsageResponse.cpp"
    "${library_root}/source/model/GetConsoleOutputRequest.cpp"
    "${library_root}/source/model/GetConsoleOutputResponse.cpp"
    "${library_root}/source/model/GetConsoleScreenshotRequest.cpp"
    "${library_root}/source/model/GetConsoleScreenshotResponse.cpp"
    "${library_root}/source/model/GetDefaultCreditSpecificationRequest.cpp"
    "${library_root}/source/model/GetDefaultCreditSpecificationResponse.cpp"
    "${library_root}/source/model/GetEbsDefaultKmsKeyIdRequest.cpp"
    "${library_root}/source/model/GetEbsDefaultKmsKeyIdResponse.cpp"
    "${library_root}/source/model/GetEbsEncryptionByDefaultRequest.cpp"
    "${library_root}/source/model/GetEbsEncryptionByDefaultResponse.cpp"
    "${library_root}/source/model/GetFlowLogsIntegrationTemplateRequest.cpp"
    "${library_root}/source/model/GetFlowLogsIntegrationTemplateResponse.cpp"
    "${library_root}/source/model/GetGroupsForCapacityReservationRequest.cpp"
    "${library_root}/source/model/GetGroupsForCapacityReservationResponse.cpp"
    "${library_root}/source/model/GetHostReservationPurchasePreviewRequest.cpp"
    "${library_root}/source/model/GetHostReservationPurchasePreviewResponse.cpp"
    "${library_root}/source/model/GetLaunchTemplateDataRequest.cpp"
    "${library_root}/source/model/GetLaunchTemplateDataResponse.cpp"
    "${library_root}/source/model/GetManagedPrefixListAssociationsRequest.cpp"
    "${library_root}/source/model/GetManagedPrefixListAssociationsResponse.cpp"
    "${library_root}/source/model/GetManagedPrefixListEntriesRequest.cpp"
    "${library_root}/source/model/GetManagedPrefixListEntriesResponse.cpp"
    "${library_root}/source/model/GetPasswordDataRequest.cpp"
    "${library_root}/source/model/GetPasswordDataResponse.cpp"
    "${library_root}/source/model/GetReservedInstancesExchangeQuoteRequest.cpp"
    "${library_root}/source/model/GetReservedInstancesExchangeQuoteResponse.cpp"
    "${library_root}/source/model/GetSerialConsoleAccessStatusRequest.cpp"
    "${library_root}/source/model/GetSerialConsoleAccessStatusResponse.cpp"
    "${library_root}/source/model/GetSubnetCidrReservationsRequest.cpp"
    "${library_root}/source/model/GetSubnetCidrReservationsResponse.cpp"
    "${library_root}/source/model/GetTransitGatewayAttachmentPropagationsRequest.cpp"
    "${library_root}/source/model/GetTransitGatewayAttachmentPropagationsResponse.cpp"
    "${library_root}/source/model/GetTransitGatewayMulticastDomainAssociationsRequest.cpp"
    "${library_root}/source/model/GetTransitGatewayMulticastDomainAssociationsResponse.cpp"
    "${library_root}/source/model/GetTransitGatewayPrefixListReferencesRequest.cpp"
    "${library_root}/source/model/GetTransitGatewayPrefixListReferencesResponse.cpp"
    "${library_root}/source/model/GetTransitGatewayRouteTableAssociationsRequest.cpp"
    "${library_root}/source/model/GetTransitGatewayRouteTableAssociationsResponse.cpp"
    "${library_root}/source/model/GetTransitGatewayRouteTablePropagationsRequest.cpp"
    "${library_root}/source/model/GetTransitGatewayRouteTablePropagationsResponse.cpp"
    "${library_root}/source/model/GetVpnConnectionDeviceSampleConfigurationRequest.cpp"
    "${library_root}/source/model/GetVpnConnectionDeviceSampleConfigurationResponse.cpp"
    "${library_root}/source/model/GetVpnConnectionDeviceTypesRequest.cpp"
    "${library_root}/source/model/GetVpnConnectionDeviceTypesResponse.cpp"
    "${library_root}/source/model/GpuDeviceInfo.cpp"
    "${library_root}/source/model/GpuDeviceMemoryInfo.cpp"
    "${library_root}/source/model/GpuInfo.cpp"
    "${library_root}/source/model/GroupIdentifier.cpp"
    "${library_root}/source/model/HibernationOptions.cpp"
    "${library_root}/source/model/HibernationOptionsRequest.cpp"
    "${library_root}/source/model/HistoryRecord.cpp"
    "${library_root}/source/model/HistoryRecordEntry.cpp"
    "${library_root}/source/model/Host.cpp"
    "${library_root}/source/model/HostInstance.cpp"
    "${library_root}/source/model/HostOffering.cpp"
    "${library_root}/source/model/HostProperties.cpp"
    "${library_root}/source/model/HostRecovery.cpp"
    "${library_root}/source/model/HostReservation.cpp"
    "${library_root}/source/model/HostTenancy.cpp"
    "${library_root}/source/model/HttpTokensState.cpp"
    "${library_root}/source/model/HypervisorType.cpp"
    "${library_root}/source/model/IamInstanceProfileAssociation.cpp"
    "${library_root}/source/model/IamInstanceProfileAssociationState.cpp"
    "${library_root}/source/model/IamInstanceProfile.cpp"
    "${library_root}/source/model/IamInstanceProfileSpecification.cpp"
    "${library_root}/source/model/IcmpTypeCode.cpp"
    "${library_root}/source/model/IdFormat.cpp"
    "${library_root}/source/model/Igmpv2SupportValue.cpp"
    "${library_root}/source/model/IKEVersionsListValue.cpp"
    "${library_root}/source/model/IKEVersionsRequestListValue.cpp"
    "${library_root}/source/model/ImageAttributeName.cpp"
    "${library_root}/source/model/Image.cpp"
    "${library_root}/source/model/ImageDiskContainer.cpp"
    "${library_root}/source/model/ImageState.cpp"
    "${library_root}/source/model/ImageTypeValues.cpp"
    "${library_root}/source/model/ImportClientVpnClientCertificateRevocationListRequest.cpp"
    "${library_root}/source/model/ImportClientVpnClientCertificateRevocationListResponse.cpp"
    "${library_root}/source/model/ImportImageLicenseConfigurationRequest.cpp"
    "${library_root}/source/model/ImportImageLicenseConfigurationResponse.cpp"
    "${library_root}/source/model/ImportImageRequest.cpp"
    "${library_root}/source/model/ImportImageResponse.cpp"
    "${library_root}/source/model/ImportImageTask.cpp"
    "${library_root}/source/model/ImportInstanceLaunchSpecification.cpp"
    "${library_root}/source/model/ImportInstanceRequest.cpp"
    "${library_root}/source/model/ImportInstanceResponse.cpp"
    "${library_root}/source/model/ImportInstanceTaskDetails.cpp"
    "${library_root}/source/model/ImportInstanceVolumeDetailItem.cpp"
    "${library_root}/source/model/ImportKeyPairRequest.cpp"
    "${library_root}/source/model/ImportKeyPairResponse.cpp"
    "${library_root}/source/model/ImportSnapshotRequest.cpp"
    "${library_root}/source/model/ImportSnapshotResponse.cpp"
    "${library_root}/source/model/ImportSnapshotTask.cpp"
    "${library_root}/source/model/ImportVolumeRequest.cpp"
    "${library_root}/source/model/ImportVolumeResponse.cpp"
    "${library_root}/source/model/ImportVolumeTaskDetails.cpp"
    "${library_root}/source/model/InferenceAcceleratorInfo.cpp"
    "${library_root}/source/model/InferenceDeviceInfo.cpp"
    "${library_root}/source/model/InstanceAttributeName.cpp"
    "${library_root}/source/model/InstanceBlockDeviceMapping.cpp"
    "${library_root}/source/model/InstanceBlockDeviceMappingSpecification.cpp"
    "${library_root}/source/model/InstanceCapacity.cpp"
    "${library_root}/source/model/InstanceCount.cpp"
    "${library_root}/source/model/Instance.cpp"
    "${library_root}/source/model/InstanceCreditSpecification.cpp"
    "${library_root}/source/model/InstanceCreditSpecificationRequest.cpp"
    "${library_root}/source/model/InstanceEventWindowAssociationRequest.cpp"
    "${library_root}/source/model/InstanceEventWindowAssociationTarget.cpp"
    "${library_root}/source/model/InstanceEventWindow.cpp"
    "${library_root}/source/model/InstanceEventWindowDisassociationRequest.cpp"
    "${library_root}/source/model/InstanceEventWindowStateChange.cpp"
    "${library_root}/source/model/InstanceEventWindowState.cpp"
    "${library_root}/source/model/InstanceEventWindowTimeRange.cpp"
    "${library_root}/source/model/InstanceEventWindowTimeRangeRequest.cpp"
    "${library_root}/source/model/InstanceExportDetails.cpp"
    "${library_root}/source/model/InstanceFamilyCreditSpecification.cpp"
    "${library_root}/source/model/InstanceHealthStatus.cpp"
    "${library_root}/source/model/InstanceInterruptionBehavior.cpp"
    "${library_root}/source/model/InstanceIpv4Prefix.cpp"
    "${library_root}/source/model/InstanceIpv6Address.cpp"
    "${library_root}/source/model/InstanceIpv6AddressRequest.cpp"
    "${library_root}/source/model/InstanceIpv6Prefix.cpp"
    "${library_root}/source/model/InstanceLifecycle.cpp"
    "${library_root}/source/model/InstanceLifecycleType.cpp"
    "${library_root}/source/model/InstanceMarketOptionsRequest.cpp"
    "${library_root}/source/model/InstanceMatchCriteria.cpp"
    "${library_root}/source/model/InstanceMetadataEndpointState.cpp"
    "${library_root}/source/model/InstanceMetadataOptionsRequest.cpp"
    "${library_root}/source/model/InstanceMetadataOptionsResponse.cpp"
    "${library_root}/source/model/InstanceMetadataOptionsState.cpp"
    "${library_root}/source/model/InstanceMetadataProtocolState.cpp"
    "${library_root}/source/model/InstanceMonitoring.cpp"
    "${library_root}/source/model/InstanceNetworkInterfaceAssociation.cpp"
    "${library_root}/source/model/InstanceNetworkInterfaceAttachment.cpp"
    "${library_root}/source/model/InstanceNetworkInterface.cpp"
    "${library_root}/source/model/InstanceNetworkInterfaceSpecification.cpp"
    "${library_root}/source/model/InstancePrivateIpAddress.cpp"
    "${library_root}/source/model/InstanceSpecification.cpp"
    "${library_root}/source/model/InstanceStateChange.cpp"
    "${library_root}/source/model/InstanceState.cpp"
    "${library_root}/source/model/InstanceStateName.cpp"
    "${library_root}/source/model/InstanceStatus.cpp"
    "${library_root}/source/model/InstanceStatusDetails.cpp"
    "${library_root}/source/model/InstanceStatusEvent.cpp"
    "${library_root}/source/model/InstanceStatusSummary.cpp"
    "${library_root}/source/model/InstanceStorageInfo.cpp"
    "${library_root}/source/model/InstanceTagNotificationAttribute.cpp"
    "${library_root}/source/model/InstanceType.cpp"
    "${library_root}/source/model/InstanceTypeHypervisor.cpp"
    "${library_root}/source/model/InstanceTypeInfo.cpp"
    "${library_root}/source/model/InstanceTypeOffering.cpp"
    "${library_root}/source/model/InstanceUsage.cpp"
    "${library_root}/source/model/IntegrateServices.cpp"
    "${library_root}/source/model/InterfacePermissionType.cpp"
    "${library_root}/source/model/InterfaceProtocolType.cpp"
    "${library_root}/source/model/InternetGatewayAttachment.cpp"
    "${library_root}/source/model/InternetGateway.cpp"
    "${library_root}/source/model/IpPermission.cpp"
    "${library_root}/source/model/IpRange.cpp"
    "${library_root}/source/model/Ipv4PrefixSpecification.cpp"
    "${library_root}/source/model/Ipv4PrefixSpecificationRequest.cpp"
    "${library_root}/source/model/Ipv4PrefixSpecificationResponse.cpp"
    "${library_root}/source/model/Ipv6CidrAssociation.cpp"
    "${library_root}/source/model/Ipv6CidrBlock.cpp"
    "${library_root}/source/model/Ipv6Pool.cpp"
    "${library_root}/source/model/Ipv6PrefixSpecification.cpp"
    "${library_root}/source/model/Ipv6PrefixSpecificationRequest.cpp"
    "${library_root}/source/model/Ipv6PrefixSpecificationResponse.cpp"
    "${library_root}/source/model/Ipv6Range.cpp"
    "${library_root}/source/model/Ipv6SupportValue.cpp"
    "${library_root}/source/model/KeyPairInfo.cpp"
    "${library_root}/source/model/KeyType.cpp"
    "${library_root}/source/model/LastError.cpp"
    "${library_root}/source/model/LaunchPermission.cpp"
    "${library_root}/source/model/LaunchPermissionModifications.cpp"
    "${library_root}/source/model/LaunchSpecification.cpp"
    "${library_root}/source/model/LaunchTemplateAndOverridesResponse.cpp"
    "${library_root}/source/model/LaunchTemplateBlockDeviceMapping.cpp"
    "${library_root}/source/model/LaunchTemplateBlockDeviceMappingRequest.cpp"
    "${library_root}/source/model/LaunchTemplateCapacityReservationSpecificationRequest.cpp"
    "${library_root}/source/model/LaunchTemplateCapacityReservationSpecificationResponse.cpp"
    "${library_root}/source/model/LaunchTemplateConfig.cpp"
    "${library_root}/source/model/LaunchTemplate.cpp"
    "${library_root}/source/model/LaunchTemplateCpuOptions.cpp"
    "${library_root}/source/model/LaunchTemplateCpuOptionsRequest.cpp"
    "${library_root}/source/model/LaunchTemplateEbsBlockDevice.cpp"
    "${library_root}/source/model/LaunchTemplateEbsBlockDeviceRequest.cpp"
    "${library_root}/source/model/LaunchTemplateElasticInferenceAccelerator.cpp"
    "${library_root}/source/model/LaunchTemplateElasticInferenceAcceleratorResponse.cpp"
    "${library_root}/source/model/LaunchTemplateEnclaveOptions.cpp"
    "${library_root}/source/model/LaunchTemplateEnclaveOptionsRequest.cpp"
    "${library_root}/source/model/LaunchTemplateErrorCode.cpp"
    "${library_root}/source/model/LaunchTemplateHibernationOptions.cpp"
    "${library_root}/source/model/LaunchTemplateHibernationOptionsRequest.cpp"
    "${library_root}/source/model/LaunchTemplateHttpTokensState.cpp"
    "${library_root}/source/model/LaunchTemplateIamInstanceProfileSpecification.cpp"
    "${library_root}/source/model/LaunchTemplateIamInstanceProfileSpecificationRequest.cpp"
    "${library_root}/source/model/LaunchTemplateInstanceMarketOptions.cpp"
    "${library_root}/source/model/LaunchTemplateInstanceMarketOptionsRequest.cpp"
    "${library_root}/source/model/LaunchTemplateInstanceMetadataEndpointState.cpp"
    "${library_root}/source/model/LaunchTemplateInstanceMetadataOptions.cpp"
    "${library_root}/source/model/LaunchTemplateInstanceMetadataOptionsRequest.cpp"
    "${library_root}/source/model/LaunchTemplateInstanceMetadataOptionsState.cpp"
    "${library_root}/source/model/LaunchTemplateInstanceMetadataProtocolIpv6.cpp"
    "${library_root}/source/model/LaunchTemplateInstanceNetworkInterfaceSpecification.cpp"
    "${library_root}/source/model/LaunchTemplateInstanceNetworkInterfaceSpecificationRequest.cpp"
    "${library_root}/source/model/LaunchTemplateLicenseConfiguration.cpp"
    "${library_root}/source/model/LaunchTemplateLicenseConfigurationRequest.cpp"
    "${library_root}/source/model/LaunchTemplateOverrides.cpp"
    "${library_root}/source/model/LaunchTemplatePlacement.cpp"
    "${library_root}/source/model/LaunchTemplatePlacementRequest.cpp"
    "${library_root}/source/model/LaunchTemplatesMonitoring.cpp"
    "${library_root}/source/model/LaunchTemplatesMonitoringRequest.cpp"
    "${library_root}/source/model/LaunchTemplateSpecification.cpp"
    "${library_root}/source/model/LaunchTemplateSpotMarketOptions.cpp"
    "${library_root}/source/model/LaunchTemplateSpotMarketOptionsRequest.cpp"
    "${library_root}/source/model/LaunchTemplateTagSpecification.cpp"
    "${library_root}/source/model/LaunchTemplateTagSpecificationRequest.cpp"
    "${library_root}/source/model/LaunchTemplateVersion.cpp"
    "${library_root}/source/model/LicenseConfiguration.cpp"
    "${library_root}/source/model/LicenseConfigurationRequest.cpp"
    "${library_root}/source/model/ListingState.cpp"
    "${library_root}/source/model/ListingStatus.cpp"
    "${library_root}/source/model/LoadBalancersConfig.cpp"
    "${library_root}/source/model/LoadPermission.cpp"
    "${library_root}/source/model/LoadPermissionModifications.cpp"
    "${library_root}/source/model/LoadPermissionRequest.cpp"
    "${library_root}/source/model/LocalGateway.cpp"
    "${library_root}/source/model/LocalGatewayRoute.cpp"
    "${library_root}/source/model/LocalGatewayRouteState.cpp"
    "${library_root}/source/model/LocalGatewayRouteTable.cpp"
    "${library_root}/source/model/LocalGatewayRouteTableVirtualInterfaceGroupAssociation.cpp"
    "${library_root}/source/model/LocalGatewayRouteTableVpcAssociation.cpp"
    "${library_root}/source/model/LocalGatewayRouteType.cpp"
    "${library_root}/source/model/LocalGatewayVirtualInterface.cpp"
    "${library_root}/source/model/LocalGatewayVirtualInterfaceGroup.cpp"
    "${library_root}/source/model/LocationType.cpp"
    "${library_root}/source/model/LogDestinationType.cpp"
    "${library_root}/source/model/ManagedPrefixList.cpp"
    "${library_root}/source/model/MarketType.cpp"
    "${library_root}/source/model/MembershipType.cpp"
    "${library_root}/source/model/MemoryInfo.cpp"
    "${library_root}/source/model/ModifyAddressAttributeRequest.cpp"
    "${library_root}/source/model/ModifyAddressAttributeResponse.cpp"
    "${library_root}/source/model/ModifyAvailabilityZoneGroupRequest.cpp"
    "${library_root}/source/model/ModifyAvailabilityZoneGroupResponse.cpp"
    "${library_root}/source/model/ModifyAvailabilityZoneOptInStatus.cpp"
    "${library_root}/source/model/ModifyCapacityReservationFleetRequest.cpp"
    "${library_root}/source/model/ModifyCapacityReservationFleetResponse.cpp"
    "${library_root}/source/model/ModifyCapacityReservationRequest.cpp"
    "${library_root}/source/model/ModifyCapacityReservationResponse.cpp"
    "${library_root}/source/model/ModifyClientVpnEndpointRequest.cpp"
    "${library_root}/source/model/ModifyClientVpnEndpointResponse.cpp"
    "${library_root}/source/model/ModifyDefaultCreditSpecificationRequest.cpp"
    "${library_root}/source/model/ModifyDefaultCreditSpecificationResponse.cpp"
    "${library_root}/source/model/ModifyEbsDefaultKmsKeyIdRequest.cpp"
    "${library_root}/source/model/ModifyEbsDefaultKmsKeyIdResponse.cpp"
    "${library_root}/source/model/ModifyFleetRequest.cpp"
    "${library_root}/source/model/ModifyFleetResponse.cpp"
    "${library_root}/source/model/ModifyFpgaImageAttributeRequest.cpp"
    "${library_root}/source/model/ModifyFpgaImageAttributeResponse.cpp"
    "${library_root}/source/model/ModifyHostsRequest.cpp"
    "${library_root}/source/model/ModifyHostsResponse.cpp"
    "${library_root}/source/model/ModifyIdentityIdFormatRequest.cpp"
    "${library_root}/source/model/ModifyIdFormatRequest.cpp"
    "${library_root}/source/model/ModifyImageAttributeRequest.cpp"
    "${library_root}/source/model/ModifyInstanceAttributeRequest.cpp"
    "${library_root}/source/model/ModifyInstanceCapacityReservationAttributesRequest.cpp"
    "${library_root}/source/model/ModifyInstanceCapacityReservationAttributesResponse.cpp"
    "${library_root}/source/model/ModifyInstanceCreditSpecificationRequest.cpp"
    "${library_root}/source/model/ModifyInstanceCreditSpecificationResponse.cpp"
    "${library_root}/source/model/ModifyInstanceEventStartTimeRequest.cpp"
    "${library_root}/source/model/ModifyInstanceEventStartTimeResponse.cpp"
    "${library_root}/source/model/ModifyInstanceEventWindowRequest.cpp"
    "${library_root}/source/model/ModifyInstanceEventWindowResponse.cpp"
    "${library_root}/source/model/ModifyInstanceMetadataOptionsRequest.cpp"
    "${library_root}/source/model/ModifyInstanceMetadataOptionsResponse.cpp"
    "${library_root}/source/model/ModifyInstancePlacementRequest.cpp"
    "${library_root}/source/model/ModifyInstancePlacementResponse.cpp"
    "${library_root}/source/model/ModifyLaunchTemplateRequest.cpp"
    "${library_root}/source/model/ModifyLaunchTemplateResponse.cpp"
    "${library_root}/source/model/ModifyManagedPrefixListRequest.cpp"
    "${library_root}/source/model/ModifyManagedPrefixListResponse.cpp"
    "${library_root}/source/model/ModifyNetworkInterfaceAttributeRequest.cpp"
    "${library_root}/source/model/ModifyReservedInstancesRequest.cpp"
    "${library_root}/source/model/ModifyReservedInstancesResponse.cpp"
    "${library_root}/source/model/ModifySecurityGroupRulesRequest.cpp"
    "${library_root}/source/model/ModifySecurityGroupRulesResponse.cpp"
    "${library_root}/source/model/ModifySnapshotAttributeRequest.cpp"
    "${library_root}/source/model/ModifySpotFleetRequestRequest.cpp"
    "${library_root}/source/model/ModifySpotFleetRequestResponse.cpp"
    "${library_root}/source/model/ModifySubnetAttributeRequest.cpp"
    "${library_root}/source/model/ModifyTrafficMirrorFilterNetworkServicesRequest.cpp"
    "${library_root}/source/model/ModifyTrafficMirrorFilterNetworkServicesResponse.cpp"
    "${library_root}/source/model/ModifyTrafficMirrorFilterRuleRequest.cpp"
    "${library_root}/source/model/ModifyTrafficMirrorFilterRuleResponse.cpp"
    "${library_root}/source/model/ModifyTrafficMirrorSessionRequest.cpp"
    "${library_root}/source/model/ModifyTrafficMirrorSessionResponse.cpp"
    "${library_root}/source/model/ModifyTransitGatewayOptions.cpp"
    "${library_root}/source/model/ModifyTransitGatewayPrefixListReferenceRequest.cpp"
    "${library_root}/source/model/ModifyTransitGatewayPrefixListReferenceResponse.cpp"
    "${library_root}/source/model/ModifyTransitGatewayRequest.cpp"
    "${library_root}/source/model/ModifyTransitGatewayResponse.cpp"
    "${library_root}/source/model/ModifyTransitGatewayVpcAttachmentRequest.cpp"
    "${library_root}/source/model/ModifyTransitGatewayVpcAttachmentRequestOptions.cpp"
    "${library_root}/source/model/ModifyTransitGatewayVpcAttachmentResponse.cpp"
    "${library_root}/source/model/ModifyVolumeAttributeRequest.cpp"
    "${library_root}/source/model/ModifyVolumeRequest.cpp"
    "${library_root}/source/model/ModifyVolumeResponse.cpp"
    "${library_root}/source/model/ModifyVpcAttributeRequest.cpp"
    "${library_root}/source/model/ModifyVpcEndpointConnectionNotificationRequest.cpp"
    "${library_root}/source/model/ModifyVpcEndpointConnectionNotificationResponse.cpp"
    "${library_root}/source/model/ModifyVpcEndpointRequest.cpp"
    "${library_root}/source/model/ModifyVpcEndpointResponse.cpp"
    "${library_root}/source/model/ModifyVpcEndpointServiceConfigurationRequest.cpp"
    "${library_root}/source/model/ModifyVpcEndpointServiceConfigurationResponse.cpp"
    "${library_root}/source/model/ModifyVpcEndpointServicePermissionsRequest.cpp"
    "${library_root}/source/model/ModifyVpcEndpointServicePermissionsResponse.cpp"
    "${library_root}/source/model/ModifyVpcPeeringConnectionOptionsRequest.cpp"
    "${library_root}/source/model/ModifyVpcPeeringConnectionOptionsResponse.cpp"
    "${library_root}/source/model/ModifyVpcTenancyRequest.cpp"
    "${library_root}/source/model/ModifyVpcTenancyResponse.cpp"
    "${library_root}/source/model/ModifyVpnConnectionOptionsRequest.cpp"
    "${library_root}/source/model/ModifyVpnConnectionOptionsResponse.cpp"
    "${library_root}/source/model/ModifyVpnConnectionRequest.cpp"
    "${library_root}/source/model/ModifyVpnConnectionResponse.cpp"
    "${library_root}/source/model/ModifyVpnTunnelCertificateRequest.cpp"
    "${library_root}/source/model/ModifyVpnTunnelCertificateResponse.cpp"
    "${library_root}/source/model/ModifyVpnTunnelOptionsRequest.cpp"
    "${library_root}/source/model/ModifyVpnTunnelOptionsResponse.cpp"
    "${library_root}/source/model/ModifyVpnTunnelOptionsSpecification.cpp"
    "${library_root}/source/model/Monitoring.cpp"
    "${library_root}/source/model/MonitoringState.cpp"
    "${library_root}/source/model/MonitorInstancesRequest.cpp"
    "${library_root}/source/model/MonitorInstancesResponse.cpp"
    "${library_root}/source/model/MoveAddressToVpcRequest.cpp"
    "${library_root}/source/model/MoveAddressToVpcResponse.cpp"
    "${library_root}/source/model/MoveStatus.cpp"
    "${library_root}/source/model/MovingAddressStatus.cpp"
    "${library_root}/source/model/MulticastSupportValue.cpp"
    "${library_root}/source/model/NatGatewayAddress.cpp"
    "${library_root}/source/model/NatGateway.cpp"
    "${library_root}/source/model/NatGatewayState.cpp"
    "${library_root}/source/model/NetworkAclAssociation.cpp"
    "${library_root}/source/model/NetworkAcl.cpp"
    "${library_root}/source/model/NetworkAclEntry.cpp"
    "${library_root}/source/model/NetworkCardInfo.cpp"
    "${library_root}/source/model/NetworkInfo.cpp"
    "${library_root}/source/model/NetworkInsightsAnalysis.cpp"
    "${library_root}/source/model/NetworkInsightsPath.cpp"
    "${library_root}/source/model/NetworkInterfaceAssociation.cpp"
    "${library_root}/source/model/NetworkInterfaceAttachmentChanges.cpp"
    "${library_root}/source/model/NetworkInterfaceAttachment.cpp"
    "${library_root}/source/model/NetworkInterfaceAttribute.cpp"
    "${library_root}/source/model/NetworkInterface.cpp"
    "${library_root}/source/model/NetworkInterfaceCreationType.cpp"
    "${library_root}/source/model/NetworkInterfaceIpv6Address.cpp"
    "${library_root}/source/model/NetworkInterfacePermission.cpp"
    "${library_root}/source/model/NetworkInterfacePermissionStateCode.cpp"
    "${library_root}/source/model/NetworkInterfacePermissionState.cpp"
    "${library_root}/source/model/NetworkInterfacePrivateIpAddress.cpp"
    "${library_root}/source/model/NetworkInterfaceStatus.cpp"
    "${library_root}/source/model/NetworkInterfaceType.cpp"
    "${library_root}/source/model/NewDhcpConfiguration.cpp"
    "${library_root}/source/model/OfferingClassType.cpp"
    "${library_root}/source/model/OfferingTypeValues.cpp"
    "${library_root}/source/model/OnDemandAllocationStrategy.cpp"
    "${library_root}/source/model/OnDemandOptions.cpp"
    "${library_root}/source/model/OnDemandOptionsRequest.cpp"
    "${library_root}/source/model/OperationType.cpp"
    "${library_root}/source/model/PartitionLoadFrequency.cpp"
    "${library_root}/source/model/PathComponent.cpp"
    "${library_root}/source/model/PaymentOption.cpp"
    "${library_root}/source/model/PciId.cpp"
    "${library_root}/source/model/PeeringAttachmentStatus.cpp"
    "${library_root}/source/model/PeeringConnectionOptions.cpp"
    "${library_root}/source/model/PeeringConnectionOptionsRequest.cpp"
    "${library_root}/source/model/PeeringTgwInfo.cpp"
    "${library_root}/source/model/PermissionGroup.cpp"
    "${library_root}/source/model/Phase1DHGroupNumbersListValue.cpp"
    "${library_root}/source/model/Phase1DHGroupNumbersRequestListValue.cpp"
    "${library_root}/source/model/Phase1EncryptionAlgorithmsListValue.cpp"
    "${library_root}/source/model/Phase1EncryptionAlgorithmsRequestListValue.cpp"
    "${library_root}/source/model/Phase1IntegrityAlgorithmsListValue.cpp"
    "${library_root}/source/model/Phase1IntegrityAlgorithmsRequestListValue.cpp"
    "${library_root}/source/model/Phase2DHGroupNumbersListValue.cpp"
    "${library_root}/source/model/Phase2DHGroupNumbersRequestListValue.cpp"
    "${library_root}/source/model/Phase2EncryptionAlgorithmsListValue.cpp"
    "${library_root}/source/model/Phase2EncryptionAlgorithmsRequestListValue.cpp"
    "${library_root}/source/model/Phase2IntegrityAlgorithmsListValue.cpp"
    "${library_root}/source/model/Phase2IntegrityAlgorithmsRequestListValue.cpp"
    "${library_root}/source/model/Placement.cpp"
    "${library_root}/source/model/PlacementGroup.cpp"
    "${library_root}/source/model/PlacementGroupInfo.cpp"
    "${library_root}/source/model/PlacementGroupState.cpp"
    "${library_root}/source/model/PlacementGroupStrategy.cpp"
    "${library_root}/source/model/PlacementResponse.cpp"
    "${library_root}/source/model/PlacementStrategy.cpp"
    "${library_root}/source/model/PlatformValues.cpp"
    "${library_root}/source/model/PoolCidrBlock.cpp"
    "${library_root}/source/model/PortRange.cpp"
    "${library_root}/source/model/PrefixListAssociation.cpp"
    "${library_root}/source/model/PrefixList.cpp"
    "${library_root}/source/model/PrefixListEntry.cpp"
    "${library_root}/source/model/PrefixListId.cpp"
    "${library_root}/source/model/PrefixListState.cpp"
    "${library_root}/source/model/PriceSchedule.cpp"
    "${library_root}/source/model/PriceScheduleSpecification.cpp"
    "${library_root}/source/model/PricingDetail.cpp"
    "${library_root}/source/model/PrincipalIdFormat.cpp"
    "${library_root}/source/model/PrincipalType.cpp"
    "${library_root}/source/model/PrivateDnsDetails.cpp"
    "${library_root}/source/model/PrivateDnsNameConfiguration.cpp"
    "${library_root}/source/model/PrivateIpAddressSpecification.cpp"
    "${library_root}/source/model/ProcessorInfo.cpp"
    "${library_root}/source/model/ProductCode.cpp"
    "${library_root}/source/model/ProductCodeValues.cpp"
    "${library_root}/source/model/PropagatingVgw.cpp"
    "${library_root}/source/model/Protocol.cpp"
    "${library_root}/source/model/ProtocolValue.cpp"
    "${library_root}/source/model/ProvisionByoipCidrRequest.cpp"
    "${library_root}/source/model/ProvisionByoipCidrResponse.cpp"
    "${library_root}/source/model/ProvisionedBandwidth.cpp"
    "${library_root}/source/model/PtrUpdateStatus.cpp"
    "${library_root}/source/model/PublicIpv4Pool.cpp"
    "${library_root}/source/model/PublicIpv4PoolRange.cpp"
    "${library_root}/source/model/Purchase.cpp"
    "${library_root}/source/model/PurchaseHostReservationRequest.cpp"
    "${library_root}/source/model/PurchaseHostReservationResponse.cpp"
    "${library_root}/source/model/PurchaseRequest.cpp"
    "${library_root}/source/model/PurchaseReservedInstancesOfferingRequest.cpp"
    "${library_root}/source/model/PurchaseReservedInstancesOfferingResponse.cpp"
    "${library_root}/source/model/PurchaseScheduledInstancesRequest.cpp"
    "${library_root}/source/model/PurchaseScheduledInstancesResponse.cpp"
    "${library_root}/source/model/RebootInstancesRequest.cpp"
    "${library_root}/source/model/RecurringCharge.cpp"
    "${library_root}/source/model/RecurringChargeFrequency.cpp"
    "${library_root}/source/model/ReferencedSecurityGroup.cpp"
    "${library_root}/source/model/Region.cpp"
    "${library_root}/source/model/RegisterImageRequest.cpp"
    "${library_root}/source/model/RegisterImageResponse.cpp"
    "${library_root}/source/model/RegisterInstanceEventNotificationAttributesRequest.cpp"
    "${library_root}/source/model/RegisterInstanceEventNotificationAttributesResponse.cpp"
    "${library_root}/source/model/RegisterInstanceTagAttributeRequest.cpp"
    "${library_root}/source/model/RegisterTransitGatewayMulticastGroupMembersRequest.cpp"
    "${library_root}/source/model/RegisterTransitGatewayMulticastGroupMembersResponse.cpp"
    "${library_root}/source/model/RegisterTransitGatewayMulticastGroupSourcesRequest.cpp"
    "${library_root}/source/model/RegisterTransitGatewayMulticastGroupSourcesResponse.cpp"
    "${library_root}/source/model/RejectTransitGatewayMulticastDomainAssociationsRequest.cpp"
    "${library_root}/source/model/RejectTransitGatewayMulticastDomainAssociationsResponse.cpp"
    "${library_root}/source/model/RejectTransitGatewayPeeringAttachmentRequest.cpp"
    "${library_root}/source/model/RejectTransitGatewayPeeringAttachmentResponse.cpp"
    "${library_root}/source/model/RejectTransitGatewayVpcAttachmentRequest.cpp"
    "${library_root}/source/model/RejectTransitGatewayVpcAttachmentResponse.cpp"
    "${library_root}/source/model/RejectVpcEndpointConnectionsRequest.cpp"
    "${library_root}/source/model/RejectVpcEndpointConnectionsResponse.cpp"
    "${library_root}/source/model/RejectVpcPeeringConnectionRequest.cpp"
    "${library_root}/source/model/RejectVpcPeeringConnectionResponse.cpp"
    "${library_root}/source/model/ReleaseAddressRequest.cpp"
    "${library_root}/source/model/ReleaseHostsRequest.cpp"
    "${library_root}/source/model/ReleaseHostsResponse.cpp"
    "${library_root}/source/model/RemovePrefixListEntry.cpp"
    "${library_root}/source/model/ReplaceIamInstanceProfileAssociationRequest.cpp"
    "${library_root}/source/model/ReplaceIamInstanceProfileAssociationResponse.cpp"
    "${library_root}/source/model/ReplacementStrategy.cpp"
    "${library_root}/source/model/ReplaceNetworkAclAssociationRequest.cpp"
    "${library_root}/source/model/ReplaceNetworkAclAssociationResponse.cpp"
    "${library_root}/source/model/ReplaceNetworkAclEntryRequest.cpp"
    "${library_root}/source/model/ReplaceRootVolumeTask.cpp"
    "${library_root}/source/model/ReplaceRootVolumeTaskState.cpp"
    "${library_root}/source/model/ReplaceRouteRequest.cpp"
    "${library_root}/source/model/ReplaceRouteTableAssociationRequest.cpp"
    "${library_root}/source/model/ReplaceRouteTableAssociationResponse.cpp"
    "${library_root}/source/model/ReplaceTransitGatewayRouteRequest.cpp"
    "${library_root}/source/model/ReplaceTransitGatewayRouteResponse.cpp"
    "${library_root}/source/model/ReportInstanceReasonCodes.cpp"
    "${library_root}/source/model/ReportInstanceStatusRequest.cpp"
    "${library_root}/source/model/ReportStatusType.cpp"
    "${library_root}/source/model/RequestLaunchTemplateData.cpp"
    "${library_root}/source/model/RequestSpotFleetRequest.cpp"
    "${library_root}/source/model/RequestSpotFleetResponse.cpp"
    "${library_root}/source/model/RequestSpotInstancesRequest.cpp"
    "${library_root}/source/model/RequestSpotInstancesResponse.cpp"
    "${library_root}/source/model/RequestSpotLaunchSpecification.cpp"
    "${library_root}/source/model/Reservation.cpp"
    "${library_root}/source/model/ReservationFleetInstanceSpecification.cpp"
    "${library_root}/source/model/ReservationState.cpp"
    "${library_root}/source/model/ReservationValue.cpp"
    "${library_root}/source/model/ReservedInstanceLimitPrice.cpp"
    "${library_root}/source/model/ReservedInstanceReservationValue.cpp"
    "${library_root}/source/model/ReservedInstancesConfiguration.cpp"
    "${library_root}/source/model/ReservedInstances.cpp"
    "${library_root}/source/model/ReservedInstancesId.cpp"
    "${library_root}/source/model/ReservedInstancesListing.cpp"
    "${library_root}/source/model/ReservedInstancesModification.cpp"
    "${library_root}/source/model/ReservedInstancesModificationResponse.cpp"
    "${library_root}/source/model/ReservedInstancesOffering.cpp"
    "${library_root}/source/model/ReservedInstanceState.cpp"
    "${library_root}/source/model/ResetAddressAttributeRequest.cpp"
    "${library_root}/source/model/ResetAddressAttributeResponse.cpp"
    "${library_root}/source/model/ResetEbsDefaultKmsKeyIdRequest.cpp"
    "${library_root}/source/model/ResetEbsDefaultKmsKeyIdResponse.cpp"
    "${library_root}/source/model/ResetFpgaImageAttributeName.cpp"
    "${library_root}/source/model/ResetFpgaImageAttributeRequest.cpp"
    "${library_root}/source/model/ResetFpgaImageAttributeResponse.cpp"
    "${library_root}/source/model/ResetImageAttributeName.cpp"
    "${library_root}/source/model/ResetImageAttributeRequest.cpp"
    "${library_root}/source/model/ResetInstanceAttributeRequest.cpp"
    "${library_root}/source/model/ResetNetworkInterfaceAttributeRequest.cpp"
    "${library_root}/source/model/ResetSnapshotAttributeRequest.cpp"
    "${library_root}/source/model/ResourceType.cpp"
    "${library_root}/source/model/ResponseError.cpp"
    "${library_root}/source/model/ResponseLaunchTemplateData.cpp"
    "${library_root}/source/model/ResponseMetadata.cpp"
    "${library_root}/source/model/RestoreAddressToClassicRequest.cpp"
    "${library_root}/source/model/RestoreAddressToClassicResponse.cpp"
    "${library_root}/source/model/RestoreManagedPrefixListVersionRequest.cpp"
    "${library_root}/source/model/RestoreManagedPrefixListVersionResponse.cpp"
    "${library_root}/source/model/RevokeClientVpnIngressRequest.cpp"
    "${library_root}/source/model/RevokeClientVpnIngressResponse.cpp"
    "${library_root}/source/model/RevokeSecurityGroupEgressRequest.cpp"
    "${library_root}/source/model/RevokeSecurityGroupEgressResponse.cpp"
    "${library_root}/source/model/RevokeSecurityGroupIngressRequest.cpp"
    "${library_root}/source/model/RevokeSecurityGroupIngressResponse.cpp"
    "${library_root}/source/model/RIProductDescription.cpp"
    "${library_root}/source/model/RootDeviceType.cpp"
    "${library_root}/source/model/Route.cpp"
    "${library_root}/source/model/RouteOrigin.cpp"
    "${library_root}/source/model/RouteState.cpp"
    "${library_root}/source/model/RouteTableAssociation.cpp"
    "${library_root}/source/model/RouteTableAssociationStateCode.cpp"
    "${library_root}/source/model/RouteTableAssociationState.cpp"
    "${library_root}/source/model/RouteTable.cpp"
    "${library_root}/source/model/RuleAction.cpp"
    "${library_root}/source/model/RunInstancesMonitoringEnabled.cpp"
    "${library_root}/source/model/RunInstancesRequest.cpp"
    "${library_root}/source/model/RunInstancesResponse.cpp"
    "${library_root}/source/model/RunScheduledInstancesRequest.cpp"
    "${library_root}/source/model/RunScheduledInstancesResponse.cpp"
    "${library_root}/source/model/S3ObjectTag.cpp"
    "${library_root}/source/model/S3Storage.cpp"
    "${library_root}/source/model/ScheduledInstanceAvailability.cpp"
    "${library_root}/source/model/ScheduledInstance.cpp"
    "${library_root}/source/model/ScheduledInstanceRecurrence.cpp"
    "${library_root}/source/model/ScheduledInstanceRecurrenceRequest.cpp"
    "${library_root}/source/model/ScheduledInstancesBlockDeviceMapping.cpp"
    "${library_root}/source/model/ScheduledInstancesEbs.cpp"
    "${library_root}/source/model/ScheduledInstancesIamInstanceProfile.cpp"
    "${library_root}/source/model/ScheduledInstancesIpv6Address.cpp"
    "${library_root}/source/model/ScheduledInstancesLaunchSpecification.cpp"
    "${library_root}/source/model/ScheduledInstancesMonitoring.cpp"
    "${library_root}/source/model/ScheduledInstancesNetworkInterface.cpp"
    "${library_root}/source/model/ScheduledInstancesPlacement.cpp"
    "${library_root}/source/model/ScheduledInstancesPrivateIpAddressConfig.cpp"
    "${library_root}/source/model/Scope.cpp"
    "${library_root}/source/model/SearchLocalGatewayRoutesRequest.cpp"
    "${library_root}/source/model/SearchLocalGatewayRoutesResponse.cpp"
    "${library_root}/source/model/SearchTransitGatewayMulticastGroupsRequest.cpp"
    "${library_root}/source/model/SearchTransitGatewayMulticastGroupsResponse.cpp"
    "${library_root}/source/model/SearchTransitGatewayRoutesRequest.cpp"
    "${library_root}/source/model/SearchTransitGatewayRoutesResponse.cpp"
    "${library_root}/source/model/SecurityGroup.cpp"
    "${library_root}/source/model/SecurityGroupIdentifier.cpp"
    "${library_root}/source/model/SecurityGroupReference.cpp"
    "${library_root}/source/model/SecurityGroupRule.cpp"
    "${library_root}/source/model/SecurityGroupRuleDescription.cpp"
    "${library_root}/source/model/SecurityGroupRuleRequest.cpp"
    "${library_root}/source/model/SecurityGroupRuleUpdate.cpp"
    "${library_root}/source/model/SelfServicePortal.cpp"
    "${library_root}/source/model/SendDiagnosticInterruptRequest.cpp"
    "${library_root}/source/model/ServiceConfiguration.cpp"
    "${library_root}/source/model/ServiceDetail.cpp"
    "${library_root}/source/model/ServiceState.cpp"
    "${library_root}/source/model/ServiceType.cpp"
    "${library_root}/source/model/ServiceTypeDetail.cpp"
    "${library_root}/source/model/ShutdownBehavior.cpp"
    "${library_root}/source/model/SlotDateTimeRangeRequest.cpp"
    "${library_root}/source/model/SlotStartTimeRangeRequest.cpp"
    "${library_root}/source/model/SnapshotAttributeName.cpp"
    "${library_root}/source/model/Snapshot.cpp"
    "${library_root}/source/model/SnapshotDetail.cpp"
    "${library_root}/source/model/SnapshotDiskContainer.cpp"
    "${library_root}/source/model/SnapshotInfo.cpp"
    "${library_root}/source/model/SnapshotState.cpp"
    "${library_root}/source/model/SnapshotTaskDetail.cpp"
    "${library_root}/source/model/SpotAllocationStrategy.cpp"
    "${library_root}/source/model/SpotCapacityRebalance.cpp"
    "${library_root}/source/model/SpotDatafeedSubscription.cpp"
    "${library_root}/source/model/SpotFleetLaunchSpecification.cpp"
    "${library_root}/source/model/SpotFleetMonitoring.cpp"
    "${library_root}/source/model/SpotFleetRequestConfig.cpp"
    "${library_root}/source/model/SpotFleetRequestConfigData.cpp"
    "${library_root}/source/model/SpotFleetTagSpecification.cpp"
    "${library_root}/source/model/SpotInstanceInterruptionBehavior.cpp"
    "${library_root}/source/model/SpotInstanceRequest.cpp"
    "${library_root}/source/model/SpotInstanceState.cpp"
    "${library_root}/source/model/SpotInstanceStateFault.cpp"
    "${library_root}/source/model/SpotInstanceStatus.cpp"
    "${library_root}/source/model/SpotInstanceType.cpp"
    "${library_root}/source/model/SpotMaintenanceStrategies.cpp"
    "${library_root}/source/model/SpotMarketOptions.cpp"
    "${library_root}/source/model/SpotOptions.cpp"
    "${library_root}/source/model/SpotOptionsRequest.cpp"
    "${library_root}/source/model/SpotPlacement.cpp"
    "${library_root}/source/model/SpotPrice.cpp"
    "${library_root}/source/model/StaleIpPermission.cpp"
    "${library_root}/source/model/StaleSecurityGroup.cpp"
    "${library_root}/source/model/StartInstancesRequest.cpp"
    "${library_root}/source/model/StartInstancesResponse.cpp"
    "${library_root}/source/model/StartNetworkInsightsAnalysisRequest.cpp"
    "${library_root}/source/model/StartNetworkInsightsAnalysisResponse.cpp"
    "${library_root}/source/model/StartVpcEndpointServicePrivateDnsVerificationRequest.cpp"
    "${library_root}/source/model/StartVpcEndpointServicePrivateDnsVerificationResponse.cpp"
    "${library_root}/source/model/State.cpp"
    "${library_root}/source/model/StateReason.cpp"
    "${library_root}/source/model/StaticSourcesSupportValue.cpp"
    "${library_root}/source/model/Status.cpp"
    "${library_root}/source/model/StatusName.cpp"
    "${library_root}/source/model/StatusType.cpp"
    "${library_root}/source/model/StopInstancesRequest.cpp"
    "${library_root}/source/model/StopInstancesResponse.cpp"
    "${library_root}/source/model/Storage.cpp"
    "${library_root}/source/model/StorageLocation.cpp"
    "${library_root}/source/model/StoreImageTaskResponse.cpp"
    "${library_root}/source/model/SubnetAssociation.cpp"
    "${library_root}/source/model/SubnetCidrBlockStateCode.cpp"
    "${library_root}/source/model/SubnetCidrBlockState.cpp"
    "${library_root}/source/model/SubnetCidrReservation.cpp"
    "${library_root}/source/model/SubnetCidrReservationType.cpp"
    "${library_root}/source/model/Subnet.cpp"
    "${library_root}/source/model/SubnetIpv6CidrBlockAssociation.cpp"
    "${library_root}/source/model/SubnetState.cpp"
    "${library_root}/source/model/SuccessfulInstanceCreditSpecificationItem.cpp"
    "${library_root}/source/model/SuccessfulQueuedPurchaseDeletion.cpp"
    "${library_root}/source/model/SummaryStatus.cpp"
    "${library_root}/source/model/Tag.cpp"
    "${library_root}/source/model/TagDescription.cpp"
    "${library_root}/source/model/TagSpecification.cpp"
    "${library_root}/source/model/TargetCapacitySpecification.cpp"
    "${library_root}/source/model/TargetCapacitySpecificationRequest.cpp"
    "${library_root}/source/model/TargetConfiguration.cpp"
    "${library_root}/source/model/TargetConfigurationRequest.cpp"
    "${library_root}/source/model/TargetGroup.cpp"
    "${library_root}/source/model/TargetGroupsConfig.cpp"
    "${library_root}/source/model/TargetNetwork.cpp"
    "${library_root}/source/model/TargetReservationValue.cpp"
    "${library_root}/source/model/TelemetryStatus.cpp"
    "${library_root}/source/model/Tenancy.cpp"
    "${library_root}/source/model/TerminateClientVpnConnectionsRequest.cpp"
    "${library_root}/source/model/TerminateClientVpnConnectionsResponse.cpp"
    "${library_root}/source/model/TerminateConnectionStatus.cpp"
    "${library_root}/source/model/TerminateInstancesRequest.cpp"
    "${library_root}/source/model/TerminateInstancesResponse.cpp"
    "${library_root}/source/model/TrafficDirection.cpp"
    "${library_root}/source/model/TrafficMirrorFilter.cpp"
    "${library_root}/source/model/TrafficMirrorFilterRule.cpp"
    "${library_root}/source/model/TrafficMirrorFilterRuleField.cpp"
    "${library_root}/source/model/TrafficMirrorNetworkService.cpp"
    "${library_root}/source/model/TrafficMirrorPortRange.cpp"
    "${library_root}/source/model/TrafficMirrorPortRangeRequest.cpp"
    "${library_root}/source/model/TrafficMirrorRuleAction.cpp"
    "${library_root}/source/model/TrafficMirrorSession.cpp"
    "${library_root}/source/model/TrafficMirrorSessionField.cpp"
    "${library_root}/source/model/TrafficMirrorTarget.cpp"
    "${library_root}/source/model/TrafficMirrorTargetType.cpp"
    "${library_root}/source/model/TrafficType.cpp"
    "${library_root}/source/model/TransitGatewayAssociation.cpp"
    "${library_root}/source/model/TransitGatewayAssociationState.cpp"
    "${library_root}/source/model/TransitGatewayAttachmentAssociation.cpp"
    "${library_root}/source/model/TransitGatewayAttachmentBgpConfiguration.cpp"
    "${library_root}/source/model/TransitGatewayAttachment.cpp"
    "${library_root}/source/model/TransitGatewayAttachmentPropagation.cpp"
    "${library_root}/source/model/TransitGatewayAttachmentResourceType.cpp"
    "${library_root}/source/model/TransitGatewayAttachmentState.cpp"
    "${library_root}/source/model/TransitGatewayConnect.cpp"
    "${library_root}/source/model/TransitGatewayConnectOptions.cpp"
    "${library_root}/source/model/TransitGatewayConnectPeerConfiguration.cpp"
    "${library_root}/source/model/TransitGatewayConnectPeer.cpp"
    "${library_root}/source/model/TransitGatewayConnectPeerState.cpp"
    "${library_root}/source/model/TransitGatewayConnectRequestBgpOptions.cpp"
    "${library_root}/source/model/TransitGateway.cpp"
    "${library_root}/source/model/TransitGatewayMulitcastDomainAssociationState.cpp"
    "${library_root}/source/model/TransitGatewayMulticastDeregisteredGroupMembers.cpp"
    "${library_root}/source/model/TransitGatewayMulticastDeregisteredGroupSources.cpp"
    "${library_root}/source/model/TransitGatewayMulticastDomainAssociation.cpp"
    "${library_root}/source/model/TransitGatewayMulticastDomainAssociations.cpp"
    "${library_root}/source/model/TransitGatewayMulticastDomain.cpp"
    "${library_root}/source/model/TransitGatewayMulticastDomainOptions.cpp"
    "${library_root}/source/model/TransitGatewayMulticastDomainState.cpp"
    "${library_root}/source/model/TransitGatewayMulticastGroup.cpp"
    "${library_root}/source/model/TransitGatewayMulticastRegisteredGroupMembers.cpp"
    "${library_root}/source/model/TransitGatewayMulticastRegisteredGroupSources.cpp"
    "${library_root}/source/model/TransitGatewayOptions.cpp"
    "${library_root}/source/model/TransitGatewayPeeringAttachment.cpp"
    "${library_root}/source/model/TransitGatewayPrefixListAttachment.cpp"
    "${library_root}/source/model/TransitGatewayPrefixListReference.cpp"
    "${library_root}/source/model/TransitGatewayPrefixListReferenceState.cpp"
    "${library_root}/source/model/TransitGatewayPropagation.cpp"
    "${library_root}/source/model/TransitGatewayPropagationState.cpp"
    "${library_root}/source/model/TransitGatewayRequestOptions.cpp"
    "${library_root}/source/model/TransitGatewayRouteAttachment.cpp"
    "${library_root}/source/model/TransitGatewayRoute.cpp"
    "${library_root}/source/model/TransitGatewayRouteState.cpp"
    "${library_root}/source/model/TransitGatewayRouteTableAssociation.cpp"
    "${library_root}/source/model/TransitGatewayRouteTable.cpp"
    "${library_root}/source/model/TransitGatewayRouteTablePropagation.cpp"
    "${library_root}/source/model/TransitGatewayRouteTableState.cpp"
    "${library_root}/source/model/TransitGatewayRouteType.cpp"
    "${library_root}/source/model/TransitGatewayState.cpp"
    "${library_root}/source/model/TransitGatewayVpcAttachment.cpp"
    "${library_root}/source/model/TransitGatewayVpcAttachmentOptions.cpp"
    "${library_root}/source/model/TransportProtocol.cpp"
    "${library_root}/source/model/TrunkInterfaceAssociation.cpp"
    "${library_root}/source/model/TunnelInsideIpVersion.cpp"
    "${library_root}/source/model/TunnelOption.cpp"
    "${library_root}/source/model/UnassignIpv6AddressesRequest.cpp"
    "${library_root}/source/model/UnassignIpv6AddressesResponse.cpp"
    "${library_root}/source/model/UnassignPrivateIpAddressesRequest.cpp"
    "${library_root}/source/model/UnlimitedSupportedInstanceFamily.cpp"
    "${library_root}/source/model/UnmonitorInstancesRequest.cpp"
    "${library_root}/source/model/UnmonitorInstancesResponse.cpp"
    "${library_root}/source/model/UnsuccessfulInstanceCreditSpecificationErrorCode.cpp"
    "${library_root}/source/model/UnsuccessfulInstanceCreditSpecificationItem.cpp"
    "${library_root}/source/model/UnsuccessfulInstanceCreditSpecificationItemError.cpp"
    "${library_root}/source/model/UnsuccessfulItem.cpp"
    "${library_root}/source/model/UnsuccessfulItemError.cpp"
    "${library_root}/source/model/UpdateSecurityGroupRuleDescriptionsEgressRequest.cpp"
    "${library_root}/source/model/UpdateSecurityGroupRuleDescriptionsEgressResponse.cpp"
    "${library_root}/source/model/UpdateSecurityGroupRuleDescriptionsIngressRequest.cpp"
    "${library_root}/source/model/UpdateSecurityGroupRuleDescriptionsIngressResponse.cpp"
    "${library_root}/source/model/UsageClassType.cpp"
    "${library_root}/source/model/UserBucket.cpp"
    "${library_root}/source/model/UserBucketDetails.cpp"
    "${library_root}/source/model/UserData.cpp"
    "${library_root}/source/model/UserIdGroupPair.cpp"
    "${library_root}/source/model/ValidationError.cpp"
    "${library_root}/source/model/ValidationWarning.cpp"
    "${library_root}/source/model/VCpuInfo.cpp"
    "${library_root}/source/model/VgwTelemetry.cpp"
    "${library_root}/source/model/VirtualizationType.cpp"
    "${library_root}/source/model/VolumeAttachment.cpp"
    "${library_root}/source/model/VolumeAttachmentState.cpp"
    "${library_root}/source/model/VolumeAttributeName.cpp"
    "${library_root}/source/model/Volume.cpp"
    "${library_root}/source/model/VolumeDetail.cpp"
    "${library_root}/source/model/VolumeModification.cpp"
    "${library_root}/source/model/VolumeModificationState.cpp"
    "${library_root}/source/model/VolumeState.cpp"
    "${library_root}/source/model/VolumeStatusAction.cpp"
    "${library_root}/source/model/VolumeStatusAttachmentStatus.cpp"
    "${library_root}/source/model/VolumeStatusDetails.cpp"
    "${library_root}/source/model/VolumeStatusEvent.cpp"
    "${library_root}/source/model/VolumeStatusInfo.cpp"
    "${library_root}/source/model/VolumeStatusInfoStatus.cpp"
    "${library_root}/source/model/VolumeStatusItem.cpp"
    "${library_root}/source/model/VolumeStatusName.cpp"
    "${library_root}/source/model/VolumeType.cpp"
    "${library_root}/source/model/VpcAttachment.cpp"
    "${library_root}/source/model/VpcAttributeName.cpp"
    "${library_root}/source/model/VpcCidrBlockAssociation.cpp"
    "${library_root}/source/model/VpcCidrBlockStateCode.cpp"
    "${library_root}/source/model/VpcCidrBlockState.cpp"
    "${library_root}/source/model/VpcClassicLink.cpp"
    "${library_root}/source/model/Vpc.cpp"
    "${library_root}/source/model/VpcEndpointConnection.cpp"
    "${library_root}/source/model/VpcEndpoint.cpp"
    "${library_root}/source/model/VpcEndpointType.cpp"
    "${library_root}/source/model/VpcIpv6CidrBlockAssociation.cpp"
    "${library_root}/source/model/VpcPeeringConnection.cpp"
    "${library_root}/source/model/VpcPeeringConnectionOptionsDescription.cpp"
    "${library_root}/source/model/VpcPeeringConnectionStateReasonCode.cpp"
    "${library_root}/source/model/VpcPeeringConnectionStateReason.cpp"
    "${library_root}/source/model/VpcPeeringConnectionVpcInfo.cpp"
    "${library_root}/source/model/VpcState.cpp"
    "${library_root}/source/model/VpcTenancy.cpp"
    "${library_root}/source/model/VpnConnection.cpp"
    "${library_root}/source/model/VpnConnectionDeviceType.cpp"
    "${library_root}/source/model/VpnConnectionOptions.cpp"
    "${library_root}/source/model/VpnConnectionOptionsSpecification.cpp"
    "${library_root}/source/model/VpnEcmpSupportValue.cpp"
    "${library_root}/source/model/VpnGateway.cpp"
    "${library_root}/source/model/VpnProtocol.cpp"
    "${library_root}/source/model/VpnState.cpp"
    "${library_root}/source/model/VpnStaticRoute.cpp"
    "${library_root}/source/model/VpnStaticRouteSource.cpp"
    "${library_root}/source/model/VpnTunnelOptionsSpecification.cpp"
    "${library_root}/source/model/WeekDay.cpp"
    "${library_root}/source/model/WithdrawByoipCidrRequest.cpp"
    "${library_root}/source/model/WithdrawByoipCidrResponse.cpp"
  )

  target_include_directories(thirdparty_aws-cpp-sdk-ec2 PRIVATE
    "${library_root}/include"
  )

  target_include_directories(thirdparty_aws-cpp-sdk-ec2 SYSTEM INTERFACE
    "${library_root}/include"
  )

  target_link_libraries(thirdparty_aws-cpp-sdk-ec2
    PRIVATE
      thirdparty_cxx_settings

    PUBLIC
      thirdparty_aws-cpp-sdk-core
  )

  if(PLATFORM_POSIX)
    find_package(Threads REQUIRED)
    target_link_libraries(thirdparty_aws-cpp-sdk-ec2 PUBLIC
      Threads::Threads
    )

    target_compile_definitions(thirdparty_aws-cpp-sdk-ec2 PRIVATE
      HAS_PATHCONF
      HAS_UMASK
    )
  endif()

  if(PLATFORM_LINUX)
    target_compile_definitions(thirdparty_aws-cpp-sdk-ec2 PRIVATE
      PLATFORM_LINUX
      ENABLE_OPENSSL_ENCRYPTION
    )

  elseif(PLATFORM_MACOS)
    target_compile_definitions(thirdparty_aws-cpp-sdk-ec2 PRIVATE
      PLATFORM_APPLE
      ENABLE_COMMONCRYPTO_ENCRYPTION
    )

  elseif(PLATFORM_WINDOWS)
    target_compile_definitions(thirdparty_aws-cpp-sdk-ec2 PRIVATE
      PLATFORM_WINDOWS
      ENABLE_BCRYPT_ENCRYPTION
    )

    target_link_libraries(thirdparty_aws-cpp-sdk-ec2 PUBLIC
      Userenv
      version
      ws2_32
    )
  endif()
endfunction()

function(generateAwsCppSdkSts)
  set(library_root "${CMAKE_CURRENT_SOURCE_DIR}/src/aws-sdk-cpp/aws-cpp-sdk-sts")

  add_library(thirdparty_aws-cpp-sdk-sts EXCLUDE_FROM_ALL
    "${library_root}/source/model/AssumedRoleUser.cpp"
    "${library_root}/source/model/AssumeRoleRequest.cpp"
    "${library_root}/source/model/AssumeRoleResult.cpp"
    "${library_root}/source/model/AssumeRoleWithSAMLRequest.cpp"
    "${library_root}/source/model/AssumeRoleWithSAMLResult.cpp"
    "${library_root}/source/model/AssumeRoleWithWebIdentityRequest.cpp"
    "${library_root}/source/model/AssumeRoleWithWebIdentityResult.cpp"
    "${library_root}/source/model/Credentials.cpp"
    "${library_root}/source/model/DecodeAuthorizationMessageRequest.cpp"
    "${library_root}/source/model/DecodeAuthorizationMessageResult.cpp"
    "${library_root}/source/model/FederatedUser.cpp"
    "${library_root}/source/model/GetAccessKeyInfoRequest.cpp"
    "${library_root}/source/model/GetAccessKeyInfoResult.cpp"
    "${library_root}/source/model/GetCallerIdentityRequest.cpp"
    "${library_root}/source/model/GetCallerIdentityResult.cpp"
    "${library_root}/source/model/GetFederationTokenRequest.cpp"
    "${library_root}/source/model/GetFederationTokenResult.cpp"
    "${library_root}/source/model/GetSessionTokenRequest.cpp"
    "${library_root}/source/model/GetSessionTokenResult.cpp"
    "${library_root}/source/model/PolicyDescriptorType.cpp"
    "${library_root}/source/model/ResponseMetadata.cpp"
    "${library_root}/source/model/Tag.cpp"
    "${library_root}/source/STSClient.cpp"
    "${library_root}/source/STSEndpoint.cpp"
    "${library_root}/source/STSErrorMarshaller.cpp"
    "${library_root}/source/STSErrors.cpp"
  )

  target_include_directories(thirdparty_aws-cpp-sdk-sts PRIVATE
    "${library_root}/include"
  )

  target_include_directories(thirdparty_aws-cpp-sdk-sts SYSTEM INTERFACE
    "${library_root}/include"
  )

  target_link_libraries(thirdparty_aws-cpp-sdk-sts
    PRIVATE
      thirdparty_cxx_settings

    PUBLIC
      thirdparty_aws-cpp-sdk-core
  )

  if(PLATFORM_POSIX)
    find_package(Threads REQUIRED)
    target_link_libraries(thirdparty_aws-cpp-sdk-sts PUBLIC
      Threads::Threads
    )

    target_compile_definitions(thirdparty_aws-cpp-sdk-sts PRIVATE
      HAS_PATHCONF
      HAS_UMASK
    )
  endif()

  if(PLATFORM_LINUX)
    target_compile_definitions(thirdparty_aws-cpp-sdk-sts PRIVATE
      PLATFORM_LINUX
      ENABLE_OPENSSL_ENCRYPTION
    )

  elseif(PLATFORM_MACOS)
    target_compile_definitions(thirdparty_aws-cpp-sdk-sts PRIVATE
      PLATFORM_APPLE
      ENABLE_COMMONCRYPTO_ENCRYPTION
    )

  elseif(PLATFORM_WINDOWS)
    target_compile_definitions(thirdparty_aws-cpp-sdk-sts PRIVATE
      PLATFORM_WINDOWS
      ENABLE_BCRYPT_ENCRYPTION
    )

    target_link_libraries(thirdparty_aws-cpp-sdk-sts PUBLIC
      Userenv
      version
      ws2_32
    )
  endif()
endfunction()

function(generateAwsCppSdkS3)
  set(library_root "${CMAKE_CURRENT_SOURCE_DIR}/src/aws-sdk-cpp/aws-cpp-sdk-s3")

  add_library(thirdparty_aws-cpp-sdk-s3 EXCLUDE_FROM_ALL
    "${library_root}/source/model/AbortIncompleteMultipartUpload.cpp"
    "${library_root}/source/model/AbortMultipartUploadRequest.cpp"
    "${library_root}/source/model/AbortMultipartUploadResult.cpp"
    "${library_root}/source/model/AccelerateConfiguration.cpp"
    "${library_root}/source/model/AccessControlPolicy.cpp"
    "${library_root}/source/model/AccessControlTranslation.cpp"
    "${library_root}/source/model/AnalyticsAndOperator.cpp"
    "${library_root}/source/model/AnalyticsConfiguration.cpp"
    "${library_root}/source/model/AnalyticsExportDestination.cpp"
    "${library_root}/source/model/AnalyticsFilter.cpp"
    "${library_root}/source/model/AnalyticsS3BucketDestination.cpp"
    "${library_root}/source/model/AnalyticsS3ExportFileFormat.cpp"
    "${library_root}/source/model/ArchiveStatus.cpp"
    "${library_root}/source/model/BucketAccelerateStatus.cpp"
    "${library_root}/source/model/BucketCannedACL.cpp"
    "${library_root}/source/model/Bucket.cpp"
    "${library_root}/source/model/BucketLifecycleConfiguration.cpp"
    "${library_root}/source/model/BucketLocationConstraint.cpp"
    "${library_root}/source/model/BucketLoggingStatus.cpp"
    "${library_root}/source/model/BucketLogsPermission.cpp"
    "${library_root}/source/model/BucketVersioningStatus.cpp"
    "${library_root}/source/model/CloudFunctionConfiguration.cpp"
    "${library_root}/source/model/CommonPrefix.cpp"
    "${library_root}/source/model/CompletedMultipartUpload.cpp"
    "${library_root}/source/model/CompletedPart.cpp"
    "${library_root}/source/model/CompleteMultipartUploadRequest.cpp"
    "${library_root}/source/model/CompleteMultipartUploadResult.cpp"
    "${library_root}/source/model/CompressionType.cpp"
    "${library_root}/source/model/Condition.cpp"
    "${library_root}/source/model/CopyObjectRequest.cpp"
    "${library_root}/source/model/CopyObjectResult.cpp"
    "${library_root}/source/model/CopyObjectResultDetails.cpp"
    "${library_root}/source/model/CopyPartResult.cpp"
    "${library_root}/source/model/CORSConfiguration.cpp"
    "${library_root}/source/model/CORSRule.cpp"
    "${library_root}/source/model/CreateBucketConfiguration.cpp"
    "${library_root}/source/model/CreateBucketRequest.cpp"
    "${library_root}/source/model/CreateBucketResult.cpp"
    "${library_root}/source/model/CreateMultipartUploadRequest.cpp"
    "${library_root}/source/model/CreateMultipartUploadResult.cpp"
    "${library_root}/source/model/CSVInput.cpp"
    "${library_root}/source/model/CSVOutput.cpp"
    "${library_root}/source/model/DefaultRetention.cpp"
    "${library_root}/source/model/DeleteBucketAnalyticsConfigurationRequest.cpp"
    "${library_root}/source/model/DeleteBucketCorsRequest.cpp"
    "${library_root}/source/model/DeleteBucketEncryptionRequest.cpp"
    "${library_root}/source/model/DeleteBucketIntelligentTieringConfigurationRequest.cpp"
    "${library_root}/source/model/DeleteBucketInventoryConfigurationRequest.cpp"
    "${library_root}/source/model/DeleteBucketLifecycleRequest.cpp"
    "${library_root}/source/model/DeleteBucketMetricsConfigurationRequest.cpp"
    "${library_root}/source/model/DeleteBucketOwnershipControlsRequest.cpp"
    "${library_root}/source/model/DeleteBucketPolicyRequest.cpp"
    "${library_root}/source/model/DeleteBucketReplicationRequest.cpp"
    "${library_root}/source/model/DeleteBucketRequest.cpp"
    "${library_root}/source/model/DeleteBucketTaggingRequest.cpp"
    "${library_root}/source/model/DeleteBucketWebsiteRequest.cpp"
    "${library_root}/source/model/Delete.cpp"
    "${library_root}/source/model/DeletedObject.cpp"
    "${library_root}/source/model/DeleteMarkerEntry.cpp"
    "${library_root}/source/model/DeleteMarkerReplication.cpp"
    "${library_root}/source/model/DeleteMarkerReplicationStatus.cpp"
    "${library_root}/source/model/DeleteObjectRequest.cpp"
    "${library_root}/source/model/DeleteObjectResult.cpp"
    "${library_root}/source/model/DeleteObjectsRequest.cpp"
    "${library_root}/source/model/DeleteObjectsResult.cpp"
    "${library_root}/source/model/DeleteObjectTaggingRequest.cpp"
    "${library_root}/source/model/DeleteObjectTaggingResult.cpp"
    "${library_root}/source/model/DeletePublicAccessBlockRequest.cpp"
    "${library_root}/source/model/Destination.cpp"
    "${library_root}/source/model/EncodingType.cpp"
    "${library_root}/source/model/EncryptionConfiguration.cpp"
    "${library_root}/source/model/Encryption.cpp"
    "${library_root}/source/model/Error.cpp"
    "${library_root}/source/model/ErrorDocument.cpp"
    "${library_root}/source/model/Event.cpp"
    "${library_root}/source/model/ExistingObjectReplication.cpp"
    "${library_root}/source/model/ExistingObjectReplicationStatus.cpp"
    "${library_root}/source/model/ExpirationStatus.cpp"
    "${library_root}/source/model/ExpressionType.cpp"
    "${library_root}/source/model/FileHeaderInfo.cpp"
    "${library_root}/source/model/FilterRule.cpp"
    "${library_root}/source/model/FilterRuleName.cpp"
    "${library_root}/source/model/GetBucketAccelerateConfigurationRequest.cpp"
    "${library_root}/source/model/GetBucketAccelerateConfigurationResult.cpp"
    "${library_root}/source/model/GetBucketAclRequest.cpp"
    "${library_root}/source/model/GetBucketAclResult.cpp"
    "${library_root}/source/model/GetBucketAnalyticsConfigurationRequest.cpp"
    "${library_root}/source/model/GetBucketAnalyticsConfigurationResult.cpp"
    "${library_root}/source/model/GetBucketCorsRequest.cpp"
    "${library_root}/source/model/GetBucketCorsResult.cpp"
    "${library_root}/source/model/GetBucketEncryptionRequest.cpp"
    "${library_root}/source/model/GetBucketEncryptionResult.cpp"
    "${library_root}/source/model/GetBucketIntelligentTieringConfigurationRequest.cpp"
    "${library_root}/source/model/GetBucketIntelligentTieringConfigurationResult.cpp"
    "${library_root}/source/model/GetBucketInventoryConfigurationRequest.cpp"
    "${library_root}/source/model/GetBucketInventoryConfigurationResult.cpp"
    "${library_root}/source/model/GetBucketLifecycleConfigurationRequest.cpp"
    "${library_root}/source/model/GetBucketLifecycleConfigurationResult.cpp"
    "${library_root}/source/model/GetBucketLocationRequest.cpp"
    "${library_root}/source/model/GetBucketLocationResult.cpp"
    "${library_root}/source/model/GetBucketLoggingRequest.cpp"
    "${library_root}/source/model/GetBucketLoggingResult.cpp"
    "${library_root}/source/model/GetBucketMetricsConfigurationRequest.cpp"
    "${library_root}/source/model/GetBucketMetricsConfigurationResult.cpp"
    "${library_root}/source/model/GetBucketNotificationConfigurationRequest.cpp"
    "${library_root}/source/model/GetBucketNotificationConfigurationResult.cpp"
    "${library_root}/source/model/GetBucketOwnershipControlsRequest.cpp"
    "${library_root}/source/model/GetBucketOwnershipControlsResult.cpp"
    "${library_root}/source/model/GetBucketPolicyRequest.cpp"
    "${library_root}/source/model/GetBucketPolicyResult.cpp"
    "${library_root}/source/model/GetBucketPolicyStatusRequest.cpp"
    "${library_root}/source/model/GetBucketPolicyStatusResult.cpp"
    "${library_root}/source/model/GetBucketReplicationRequest.cpp"
    "${library_root}/source/model/GetBucketReplicationResult.cpp"
    "${library_root}/source/model/GetBucketRequestPaymentRequest.cpp"
    "${library_root}/source/model/GetBucketRequestPaymentResult.cpp"
    "${library_root}/source/model/GetBucketTaggingRequest.cpp"
    "${library_root}/source/model/GetBucketTaggingResult.cpp"
    "${library_root}/source/model/GetBucketVersioningRequest.cpp"
    "${library_root}/source/model/GetBucketVersioningResult.cpp"
    "${library_root}/source/model/GetBucketWebsiteRequest.cpp"
    "${library_root}/source/model/GetBucketWebsiteResult.cpp"
    "${library_root}/source/model/GetObjectAclRequest.cpp"
    "${library_root}/source/model/GetObjectAclResult.cpp"
    "${library_root}/source/model/GetObjectLegalHoldRequest.cpp"
    "${library_root}/source/model/GetObjectLegalHoldResult.cpp"
    "${library_root}/source/model/GetObjectLockConfigurationRequest.cpp"
    "${library_root}/source/model/GetObjectLockConfigurationResult.cpp"
    "${library_root}/source/model/GetObjectRequest.cpp"
    "${library_root}/source/model/GetObjectResult.cpp"
    "${library_root}/source/model/GetObjectRetentionRequest.cpp"
    "${library_root}/source/model/GetObjectRetentionResult.cpp"
    "${library_root}/source/model/GetObjectTaggingRequest.cpp"
    "${library_root}/source/model/GetObjectTaggingResult.cpp"
    "${library_root}/source/model/GetObjectTorrentRequest.cpp"
    "${library_root}/source/model/GetObjectTorrentResult.cpp"
    "${library_root}/source/model/GetPublicAccessBlockRequest.cpp"
    "${library_root}/source/model/GetPublicAccessBlockResult.cpp"
    "${library_root}/source/model/GlacierJobParameters.cpp"
    "${library_root}/source/model/Grant.cpp"
    "${library_root}/source/model/Grantee.cpp"
    "${library_root}/source/model/HeadBucketRequest.cpp"
    "${library_root}/source/model/HeadObjectRequest.cpp"
    "${library_root}/source/model/HeadObjectResult.cpp"
    "${library_root}/source/model/IndexDocument.cpp"
    "${library_root}/source/model/Initiator.cpp"
    "${library_root}/source/model/InputSerialization.cpp"
    "${library_root}/source/model/IntelligentTieringAccessTier.cpp"
    "${library_root}/source/model/IntelligentTieringAndOperator.cpp"
    "${library_root}/source/model/IntelligentTieringConfiguration.cpp"
    "${library_root}/source/model/IntelligentTieringFilter.cpp"
    "${library_root}/source/model/IntelligentTieringStatus.cpp"
    "${library_root}/source/model/InvalidObjectState.cpp"
    "${library_root}/source/model/InventoryConfiguration.cpp"
    "${library_root}/source/model/InventoryDestination.cpp"
    "${library_root}/source/model/InventoryEncryption.cpp"
    "${library_root}/source/model/InventoryFilter.cpp"
    "${library_root}/source/model/InventoryFormat.cpp"
    "${library_root}/source/model/InventoryFrequency.cpp"
    "${library_root}/source/model/InventoryIncludedObjectVersions.cpp"
    "${library_root}/source/model/InventoryOptionalField.cpp"
    "${library_root}/source/model/InventoryS3BucketDestination.cpp"
    "${library_root}/source/model/InventorySchedule.cpp"
    "${library_root}/source/model/JSONInput.cpp"
    "${library_root}/source/model/JSONOutput.cpp"
    "${library_root}/source/model/JSONType.cpp"
    "${library_root}/source/model/LambdaFunctionConfiguration.cpp"
    "${library_root}/source/model/LifecycleConfiguration.cpp"
    "${library_root}/source/model/LifecycleExpiration.cpp"
    "${library_root}/source/model/LifecycleRuleAndOperator.cpp"
    "${library_root}/source/model/LifecycleRule.cpp"
    "${library_root}/source/model/LifecycleRuleFilter.cpp"
    "${library_root}/source/model/ListBucketAnalyticsConfigurationsRequest.cpp"
    "${library_root}/source/model/ListBucketAnalyticsConfigurationsResult.cpp"
    "${library_root}/source/model/ListBucketIntelligentTieringConfigurationsRequest.cpp"
    "${library_root}/source/model/ListBucketIntelligentTieringConfigurationsResult.cpp"
    "${library_root}/source/model/ListBucketInventoryConfigurationsRequest.cpp"
    "${library_root}/source/model/ListBucketInventoryConfigurationsResult.cpp"
    "${library_root}/source/model/ListBucketMetricsConfigurationsRequest.cpp"
    "${library_root}/source/model/ListBucketMetricsConfigurationsResult.cpp"
    "${library_root}/source/model/ListBucketsResult.cpp"
    "${library_root}/source/model/ListMultipartUploadsRequest.cpp"
    "${library_root}/source/model/ListMultipartUploadsResult.cpp"
    "${library_root}/source/model/ListObjectsRequest.cpp"
    "${library_root}/source/model/ListObjectsResult.cpp"
    "${library_root}/source/model/ListObjectsV2Request.cpp"
    "${library_root}/source/model/ListObjectsV2Result.cpp"
    "${library_root}/source/model/ListObjectVersionsRequest.cpp"
    "${library_root}/source/model/ListObjectVersionsResult.cpp"
    "${library_root}/source/model/ListPartsRequest.cpp"
    "${library_root}/source/model/ListPartsResult.cpp"
    "${library_root}/source/model/LoggingEnabled.cpp"
    "${library_root}/source/model/MetadataDirective.cpp"
    "${library_root}/source/model/MetadataEntry.cpp"
    "${library_root}/source/model/MetricsAndOperator.cpp"
    "${library_root}/source/model/MetricsConfiguration.cpp"
    "${library_root}/source/model/Metrics.cpp"
    "${library_root}/source/model/MetricsFilter.cpp"
    "${library_root}/source/model/MetricsStatus.cpp"
    "${library_root}/source/model/MFADelete.cpp"
    "${library_root}/source/model/MFADeleteStatus.cpp"
    "${library_root}/source/model/MultipartUpload.cpp"
    "${library_root}/source/model/NoncurrentVersionExpiration.cpp"
    "${library_root}/source/model/NoncurrentVersionTransition.cpp"
    "${library_root}/source/model/NotificationConfiguration.cpp"
    "${library_root}/source/model/NotificationConfigurationDeprecated.cpp"
    "${library_root}/source/model/NotificationConfigurationFilter.cpp"
    "${library_root}/source/model/ObjectCannedACL.cpp"
    "${library_root}/source/model/Object.cpp"
    "${library_root}/source/model/ObjectIdentifier.cpp"
    "${library_root}/source/model/ObjectLockConfiguration.cpp"
    "${library_root}/source/model/ObjectLockEnabled.cpp"
    "${library_root}/source/model/ObjectLockLegalHold.cpp"
    "${library_root}/source/model/ObjectLockLegalHoldStatus.cpp"
    "${library_root}/source/model/ObjectLockMode.cpp"
    "${library_root}/source/model/ObjectLockRetention.cpp"
    "${library_root}/source/model/ObjectLockRetentionMode.cpp"
    "${library_root}/source/model/ObjectLockRule.cpp"
    "${library_root}/source/model/ObjectOwnership.cpp"
    "${library_root}/source/model/ObjectStorageClass.cpp"
    "${library_root}/source/model/ObjectVersion.cpp"
    "${library_root}/source/model/ObjectVersionStorageClass.cpp"
    "${library_root}/source/model/OutputLocation.cpp"
    "${library_root}/source/model/OutputSerialization.cpp"
    "${library_root}/source/model/Owner.cpp"
    "${library_root}/source/model/OwnerOverride.cpp"
    "${library_root}/source/model/OwnershipControls.cpp"
    "${library_root}/source/model/OwnershipControlsRule.cpp"
    "${library_root}/source/model/ParquetInput.cpp"
    "${library_root}/source/model/Part.cpp"
    "${library_root}/source/model/Payer.cpp"
    "${library_root}/source/model/Permission.cpp"
    "${library_root}/source/model/PolicyStatus.cpp"
    "${library_root}/source/model/Progress.cpp"
    "${library_root}/source/model/ProgressEvent.cpp"
    "${library_root}/source/model/Protocol.cpp"
    "${library_root}/source/model/PublicAccessBlockConfiguration.cpp"
    "${library_root}/source/model/PutBucketAccelerateConfigurationRequest.cpp"
    "${library_root}/source/model/PutBucketAclRequest.cpp"
    "${library_root}/source/model/PutBucketAnalyticsConfigurationRequest.cpp"
    "${library_root}/source/model/PutBucketCorsRequest.cpp"
    "${library_root}/source/model/PutBucketEncryptionRequest.cpp"
    "${library_root}/source/model/PutBucketIntelligentTieringConfigurationRequest.cpp"
    "${library_root}/source/model/PutBucketInventoryConfigurationRequest.cpp"
    "${library_root}/source/model/PutBucketLifecycleConfigurationRequest.cpp"
    "${library_root}/source/model/PutBucketLoggingRequest.cpp"
    "${library_root}/source/model/PutBucketMetricsConfigurationRequest.cpp"
    "${library_root}/source/model/PutBucketNotificationConfigurationRequest.cpp"
    "${library_root}/source/model/PutBucketOwnershipControlsRequest.cpp"
    "${library_root}/source/model/PutBucketPolicyRequest.cpp"
    "${library_root}/source/model/PutBucketReplicationRequest.cpp"
    "${library_root}/source/model/PutBucketRequestPaymentRequest.cpp"
    "${library_root}/source/model/PutBucketTaggingRequest.cpp"
    "${library_root}/source/model/PutBucketVersioningRequest.cpp"
    "${library_root}/source/model/PutBucketWebsiteRequest.cpp"
    "${library_root}/source/model/PutObjectAclRequest.cpp"
    "${library_root}/source/model/PutObjectAclResult.cpp"
    "${library_root}/source/model/PutObjectLegalHoldRequest.cpp"
    "${library_root}/source/model/PutObjectLegalHoldResult.cpp"
    "${library_root}/source/model/PutObjectLockConfigurationRequest.cpp"
    "${library_root}/source/model/PutObjectLockConfigurationResult.cpp"
    "${library_root}/source/model/PutObjectRequest.cpp"
    "${library_root}/source/model/PutObjectResult.cpp"
    "${library_root}/source/model/PutObjectRetentionRequest.cpp"
    "${library_root}/source/model/PutObjectRetentionResult.cpp"
    "${library_root}/source/model/PutObjectTaggingRequest.cpp"
    "${library_root}/source/model/PutObjectTaggingResult.cpp"
    "${library_root}/source/model/PutPublicAccessBlockRequest.cpp"
    "${library_root}/source/model/QueueConfiguration.cpp"
    "${library_root}/source/model/QueueConfigurationDeprecated.cpp"
    "${library_root}/source/model/QuoteFields.cpp"
    "${library_root}/source/model/RedirectAllRequestsTo.cpp"
    "${library_root}/source/model/Redirect.cpp"
    "${library_root}/source/model/ReplicaModifications.cpp"
    "${library_root}/source/model/ReplicaModificationsStatus.cpp"
    "${library_root}/source/model/ReplicationConfiguration.cpp"
    "${library_root}/source/model/ReplicationRuleAndOperator.cpp"
    "${library_root}/source/model/ReplicationRule.cpp"
    "${library_root}/source/model/ReplicationRuleFilter.cpp"
    "${library_root}/source/model/ReplicationRuleStatus.cpp"
    "${library_root}/source/model/ReplicationStatus.cpp"
    "${library_root}/source/model/ReplicationTime.cpp"
    "${library_root}/source/model/ReplicationTimeStatus.cpp"
    "${library_root}/source/model/ReplicationTimeValue.cpp"
    "${library_root}/source/model/RequestCharged.cpp"
    "${library_root}/source/model/RequestPayer.cpp"
    "${library_root}/source/model/RequestPaymentConfiguration.cpp"
    "${library_root}/source/model/RequestProgress.cpp"
    "${library_root}/source/model/RestoreObjectRequest.cpp"
    "${library_root}/source/model/RestoreObjectResult.cpp"
    "${library_root}/source/model/RestoreRequest.cpp"
    "${library_root}/source/model/RestoreRequestType.cpp"
    "${library_root}/source/model/RoutingRule.cpp"
    "${library_root}/source/model/Rule.cpp"
    "${library_root}/source/model/S3KeyFilter.cpp"
    "${library_root}/source/model/S3Location.cpp"
    "${library_root}/source/model/ScanRange.cpp"
    "${library_root}/source/model/SelectObjectContentHandler.cpp"
    "${library_root}/source/model/SelectObjectContentRequest.cpp"
    "${library_root}/source/model/SelectParameters.cpp"
    "${library_root}/source/model/ServerSideEncryptionByDefault.cpp"
    "${library_root}/source/model/ServerSideEncryptionConfiguration.cpp"
    "${library_root}/source/model/ServerSideEncryption.cpp"
    "${library_root}/source/model/ServerSideEncryptionRule.cpp"
    "${library_root}/source/model/SourceSelectionCriteria.cpp"
    "${library_root}/source/model/SSEKMS.cpp"
    "${library_root}/source/model/SseKmsEncryptedObjects.cpp"
    "${library_root}/source/model/SseKmsEncryptedObjectsStatus.cpp"
    "${library_root}/source/model/SSES3.cpp"
    "${library_root}/source/model/Stats.cpp"
    "${library_root}/source/model/StatsEvent.cpp"
    "${library_root}/source/model/StorageClassAnalysis.cpp"
    "${library_root}/source/model/StorageClassAnalysisDataExport.cpp"
    "${library_root}/source/model/StorageClassAnalysisSchemaVersion.cpp"
    "${library_root}/source/model/StorageClass.cpp"
    "${library_root}/source/model/Tag.cpp"
    "${library_root}/source/model/Tagging.cpp"
    "${library_root}/source/model/TaggingDirective.cpp"
    "${library_root}/source/model/TargetGrant.cpp"
    "${library_root}/source/model/Tier.cpp"
    "${library_root}/source/model/Tiering.cpp"
    "${library_root}/source/model/TopicConfiguration.cpp"
    "${library_root}/source/model/TopicConfigurationDeprecated.cpp"
    "${library_root}/source/model/Transition.cpp"
    "${library_root}/source/model/TransitionStorageClass.cpp"
    "${library_root}/source/model/Type.cpp"
    "${library_root}/source/model/UploadPartCopyRequest.cpp"
    "${library_root}/source/model/UploadPartCopyResult.cpp"
    "${library_root}/source/model/UploadPartRequest.cpp"
    "${library_root}/source/model/UploadPartResult.cpp"
    "${library_root}/source/model/VersioningConfiguration.cpp"
    "${library_root}/source/model/WebsiteConfiguration.cpp"
    "${library_root}/source/model/WriteGetObjectResponseRequest.cpp"
    "${library_root}/source/S3ARN.cpp"
    "${library_root}/source/S3Client.cpp"
    "${library_root}/source/S3Endpoint.cpp"
    "${library_root}/source/S3ErrorMarshaller.cpp"
    "${library_root}/source/S3Errors.cpp"
  )

  target_include_directories(thirdparty_aws-cpp-sdk-s3 PRIVATE
    "${library_root}/include"
  )

  target_include_directories(thirdparty_aws-cpp-sdk-s3 SYSTEM INTERFACE
    "${library_root}/include"
  )

  target_link_libraries(thirdparty_aws-cpp-sdk-s3
    PRIVATE
      thirdparty_cxx_settings

    PUBLIC
      thirdparty_aws-cpp-sdk-core
  )

  if(PLATFORM_POSIX)
    find_package(Threads REQUIRED)
    target_link_libraries(thirdparty_aws-cpp-sdk-s3 PUBLIC
      Threads::Threads
    )

    target_compile_definitions(thirdparty_aws-cpp-sdk-s3 PRIVATE
      HAS_PATHCONF
      HAS_UMASK
    )
  endif()

  if(PLATFORM_LINUX)
    target_compile_definitions(thirdparty_aws-cpp-sdk-s3 PRIVATE
      PLATFORM_LINUX
      ENABLE_OPENSSL_ENCRYPTION
    )

  elseif(PLATFORM_MACOS)
    target_compile_definitions(thirdparty_aws-cpp-sdk-s3 PRIVATE
      PLATFORM_APPLE
      ENABLE_COMMONCRYPTO_ENCRYPTION
    )

  elseif(PLATFORM_WINDOWS)
    target_compile_definitions(thirdparty_aws-cpp-sdk-s3 PRIVATE
      PLATFORM_WINDOWS
      ENABLE_BCRYPT_ENCRYPTION
    )

    target_link_libraries(thirdparty_aws-cpp-sdk-s3 PUBLIC
      Userenv
      version
      ws2_32
    )
  endif()
endfunction()

function(generateAwsCppSdkKinesis)
  set(library_root "${CMAKE_CURRENT_SOURCE_DIR}/src/aws-sdk-cpp/aws-cpp-sdk-kinesis")

  add_library(thirdparty_aws-cpp-sdk-kinesis EXCLUDE_FROM_ALL
    "${library_root}/source/KinesisClient.cpp"
    "${library_root}/source/KinesisEndpoint.cpp"
    "${library_root}/source/KinesisErrorMarshaller.cpp"
    "${library_root}/source/KinesisErrors.cpp"
    "${library_root}/source/model/AddTagsToStreamRequest.cpp"
    "${library_root}/source/model/ChildShard.cpp"
    "${library_root}/source/model/Consumer.cpp"
    "${library_root}/source/model/ConsumerDescription.cpp"
    "${library_root}/source/model/ConsumerStatus.cpp"
    "${library_root}/source/model/CreateStreamRequest.cpp"
    "${library_root}/source/model/DecreaseStreamRetentionPeriodRequest.cpp"
    "${library_root}/source/model/DeleteStreamRequest.cpp"
    "${library_root}/source/model/DeregisterStreamConsumerRequest.cpp"
    "${library_root}/source/model/DescribeLimitsRequest.cpp"
    "${library_root}/source/model/DescribeLimitsResult.cpp"
    "${library_root}/source/model/DescribeStreamConsumerRequest.cpp"
    "${library_root}/source/model/DescribeStreamConsumerResult.cpp"
    "${library_root}/source/model/DescribeStreamRequest.cpp"
    "${library_root}/source/model/DescribeStreamResult.cpp"
    "${library_root}/source/model/DescribeStreamSummaryRequest.cpp"
    "${library_root}/source/model/DescribeStreamSummaryResult.cpp"
    "${library_root}/source/model/DisableEnhancedMonitoringRequest.cpp"
    "${library_root}/source/model/DisableEnhancedMonitoringResult.cpp"
    "${library_root}/source/model/EnableEnhancedMonitoringRequest.cpp"
    "${library_root}/source/model/EnableEnhancedMonitoringResult.cpp"
    "${library_root}/source/model/EncryptionType.cpp"
    "${library_root}/source/model/EnhancedMetrics.cpp"
    "${library_root}/source/model/GetRecordsRequest.cpp"
    "${library_root}/source/model/GetRecordsResult.cpp"
    "${library_root}/source/model/GetShardIteratorRequest.cpp"
    "${library_root}/source/model/GetShardIteratorResult.cpp"
    "${library_root}/source/model/HashKeyRange.cpp"
    "${library_root}/source/model/IncreaseStreamRetentionPeriodRequest.cpp"
    "${library_root}/source/model/ListShardsRequest.cpp"
    "${library_root}/source/model/ListShardsResult.cpp"
    "${library_root}/source/model/ListStreamConsumersRequest.cpp"
    "${library_root}/source/model/ListStreamConsumersResult.cpp"
    "${library_root}/source/model/ListStreamsRequest.cpp"
    "${library_root}/source/model/ListStreamsResult.cpp"
    "${library_root}/source/model/ListTagsForStreamRequest.cpp"
    "${library_root}/source/model/ListTagsForStreamResult.cpp"
    "${library_root}/source/model/MergeShardsRequest.cpp"
    "${library_root}/source/model/MetricsName.cpp"
    "${library_root}/source/model/PutRecordRequest.cpp"
    "${library_root}/source/model/PutRecordResult.cpp"
    "${library_root}/source/model/PutRecordsRequest.cpp"
    "${library_root}/source/model/PutRecordsRequestEntry.cpp"
    "${library_root}/source/model/PutRecordsResult.cpp"
    "${library_root}/source/model/PutRecordsResultEntry.cpp"
    "${library_root}/source/model/Record.cpp"
    "${library_root}/source/model/RegisterStreamConsumerRequest.cpp"
    "${library_root}/source/model/RegisterStreamConsumerResult.cpp"
    "${library_root}/source/model/RemoveTagsFromStreamRequest.cpp"
    "${library_root}/source/model/ScalingType.cpp"
    "${library_root}/source/model/SequenceNumberRange.cpp"
    "${library_root}/source/model/Shard.cpp"
    "${library_root}/source/model/ShardFilter.cpp"
    "${library_root}/source/model/ShardFilterType.cpp"
    "${library_root}/source/model/ShardIteratorType.cpp"
    "${library_root}/source/model/SplitShardRequest.cpp"
    "${library_root}/source/model/StartingPosition.cpp"
    "${library_root}/source/model/StartStreamEncryptionRequest.cpp"
    "${library_root}/source/model/StopStreamEncryptionRequest.cpp"
    "${library_root}/source/model/StreamDescription.cpp"
    "${library_root}/source/model/StreamDescriptionSummary.cpp"
    "${library_root}/source/model/StreamStatus.cpp"
    "${library_root}/source/model/SubscribeToShardEvent.cpp"
    "${library_root}/source/model/SubscribeToShardHandler.cpp"
    "${library_root}/source/model/SubscribeToShardRequest.cpp"
    "${library_root}/source/model/Tag.cpp"
    "${library_root}/source/model/UpdateShardCountRequest.cpp"
    "${library_root}/source/model/UpdateShardCountResult.cpp"
  )

  target_include_directories(thirdparty_aws-cpp-sdk-kinesis PRIVATE
    "${library_root}/include"
  )

  target_include_directories(thirdparty_aws-cpp-sdk-kinesis SYSTEM INTERFACE
    "${library_root}/include"
  )

  target_link_libraries(thirdparty_aws-cpp-sdk-kinesis
    PRIVATE
      thirdparty_cxx_settings

    PUBLIC
      thirdparty_aws-cpp-sdk-core
  )

  if(PLATFORM_POSIX)
    find_package(Threads REQUIRED)
    target_link_libraries(thirdparty_aws-cpp-sdk-kinesis PUBLIC
      Threads::Threads
    )

    target_compile_definitions(thirdparty_aws-cpp-sdk-kinesis PRIVATE
      HAS_PATHCONF
      HAS_UMASK
    )
  endif()

  if(PLATFORM_LINUX)
    target_compile_definitions(thirdparty_aws-cpp-sdk-kinesis PRIVATE
      PLATFORM_LINUX
      ENABLE_OPENSSL_ENCRYPTION
    )

  elseif(PLATFORM_MACOS)
    target_compile_definitions(thirdparty_aws-cpp-sdk-kinesis PRIVATE
      PLATFORM_APPLE
      ENABLE_COMMONCRYPTO_ENCRYPTION
    )

  elseif(PLATFORM_WINDOWS)
    target_compile_definitions(thirdparty_aws-cpp-sdk-kinesis PRIVATE
      PLATFORM_WINDOWS
      ENABLE_BCRYPT_ENCRYPTION
    )

    target_link_libraries(thirdparty_aws-cpp-sdk-kinesis PUBLIC
      Userenv
      version
      ws2_32
    )
  endif()
endfunction()

function(generateAwsCppSdkFirehose)
  set(library_root "${CMAKE_CURRENT_SOURCE_DIR}/src/aws-sdk-cpp/aws-cpp-sdk-firehose")

  add_library(thirdparty_aws-cpp-sdk-firehose EXCLUDE_FROM_ALL
    "${library_root}/source/FirehoseClient.cpp"
    "${library_root}/source/FirehoseEndpoint.cpp"
    "${library_root}/source/FirehoseErrorMarshaller.cpp"
    "${library_root}/source/FirehoseErrors.cpp"
    "${library_root}/source/model/BufferingHints.cpp"
    "${library_root}/source/model/CloudWatchLoggingOptions.cpp"
    "${library_root}/source/model/CompressionFormat.cpp"
    "${library_root}/source/model/ContentEncoding.cpp"
    "${library_root}/source/model/CopyCommand.cpp"
    "${library_root}/source/model/CreateDeliveryStreamRequest.cpp"
    "${library_root}/source/model/CreateDeliveryStreamResult.cpp"
    "${library_root}/source/model/DataFormatConversionConfiguration.cpp"
    "${library_root}/source/model/DeleteDeliveryStreamRequest.cpp"
    "${library_root}/source/model/DeleteDeliveryStreamResult.cpp"
    "${library_root}/source/model/DeliveryStreamDescription.cpp"
    "${library_root}/source/model/DeliveryStreamEncryptionConfiguration.cpp"
    "${library_root}/source/model/DeliveryStreamEncryptionConfigurationInput.cpp"
    "${library_root}/source/model/DeliveryStreamEncryptionStatus.cpp"
    "${library_root}/source/model/DeliveryStreamFailureType.cpp"
    "${library_root}/source/model/DeliveryStreamStatus.cpp"
    "${library_root}/source/model/DeliveryStreamType.cpp"
    "${library_root}/source/model/DescribeDeliveryStreamRequest.cpp"
    "${library_root}/source/model/DescribeDeliveryStreamResult.cpp"
    "${library_root}/source/model/Deserializer.cpp"
    "${library_root}/source/model/DestinationDescription.cpp"
    "${library_root}/source/model/DynamicPartitioningConfiguration.cpp"
    "${library_root}/source/model/ElasticsearchBufferingHints.cpp"
    "${library_root}/source/model/ElasticsearchDestinationConfiguration.cpp"
    "${library_root}/source/model/ElasticsearchDestinationDescription.cpp"
    "${library_root}/source/model/ElasticsearchDestinationUpdate.cpp"
    "${library_root}/source/model/ElasticsearchIndexRotationPeriod.cpp"
    "${library_root}/source/model/ElasticsearchRetryOptions.cpp"
    "${library_root}/source/model/ElasticsearchS3BackupMode.cpp"
    "${library_root}/source/model/EncryptionConfiguration.cpp"
    "${library_root}/source/model/ExtendedS3DestinationConfiguration.cpp"
    "${library_root}/source/model/ExtendedS3DestinationDescription.cpp"
    "${library_root}/source/model/ExtendedS3DestinationUpdate.cpp"
    "${library_root}/source/model/FailureDescription.cpp"
    "${library_root}/source/model/HECEndpointType.cpp"
    "${library_root}/source/model/HiveJsonSerDe.cpp"
    "${library_root}/source/model/HttpEndpointBufferingHints.cpp"
    "${library_root}/source/model/HttpEndpointCommonAttribute.cpp"
    "${library_root}/source/model/HttpEndpointConfiguration.cpp"
    "${library_root}/source/model/HttpEndpointDescription.cpp"
    "${library_root}/source/model/HttpEndpointDestinationConfiguration.cpp"
    "${library_root}/source/model/HttpEndpointDestinationDescription.cpp"
    "${library_root}/source/model/HttpEndpointDestinationUpdate.cpp"
    "${library_root}/source/model/HttpEndpointRequestConfiguration.cpp"
    "${library_root}/source/model/HttpEndpointRetryOptions.cpp"
    "${library_root}/source/model/HttpEndpointS3BackupMode.cpp"
    "${library_root}/source/model/InputFormatConfiguration.cpp"
    "${library_root}/source/model/InvalidKMSResourceException.cpp"
    "${library_root}/source/model/KMSEncryptionConfig.cpp"
    "${library_root}/source/model/KeyType.cpp"
    "${library_root}/source/model/KinesisStreamSourceConfiguration.cpp"
    "${library_root}/source/model/KinesisStreamSourceDescription.cpp"
    "${library_root}/source/model/ListDeliveryStreamsRequest.cpp"
    "${library_root}/source/model/ListDeliveryStreamsResult.cpp"
    "${library_root}/source/model/ListTagsForDeliveryStreamRequest.cpp"
    "${library_root}/source/model/ListTagsForDeliveryStreamResult.cpp"
    "${library_root}/source/model/NoEncryptionConfig.cpp"
    "${library_root}/source/model/OpenXJsonSerDe.cpp"
    "${library_root}/source/model/OrcCompression.cpp"
    "${library_root}/source/model/OrcFormatVersion.cpp"
    "${library_root}/source/model/OrcSerDe.cpp"
    "${library_root}/source/model/OutputFormatConfiguration.cpp"
    "${library_root}/source/model/ParquetCompression.cpp"
    "${library_root}/source/model/ParquetSerDe.cpp"
    "${library_root}/source/model/ParquetWriterVersion.cpp"
    "${library_root}/source/model/ProcessingConfiguration.cpp"
    "${library_root}/source/model/Processor.cpp"
    "${library_root}/source/model/ProcessorParameter.cpp"
    "${library_root}/source/model/ProcessorParameterName.cpp"
    "${library_root}/source/model/ProcessorType.cpp"
    "${library_root}/source/model/PutRecordBatchRequest.cpp"
    "${library_root}/source/model/PutRecordBatchResponseEntry.cpp"
    "${library_root}/source/model/PutRecordBatchResult.cpp"
    "${library_root}/source/model/PutRecordRequest.cpp"
    "${library_root}/source/model/PutRecordResult.cpp"
    "${library_root}/source/model/Record.cpp"
    "${library_root}/source/model/RedshiftDestinationConfiguration.cpp"
    "${library_root}/source/model/RedshiftDestinationDescription.cpp"
    "${library_root}/source/model/RedshiftDestinationUpdate.cpp"
    "${library_root}/source/model/RedshiftRetryOptions.cpp"
    "${library_root}/source/model/RedshiftS3BackupMode.cpp"
    "${library_root}/source/model/RetryOptions.cpp"
    "${library_root}/source/model/S3BackupMode.cpp"
    "${library_root}/source/model/S3DestinationConfiguration.cpp"
    "${library_root}/source/model/S3DestinationDescription.cpp"
    "${library_root}/source/model/S3DestinationUpdate.cpp"
    "${library_root}/source/model/SchemaConfiguration.cpp"
    "${library_root}/source/model/Serializer.cpp"
    "${library_root}/source/model/SourceDescription.cpp"
    "${library_root}/source/model/SplunkDestinationConfiguration.cpp"
    "${library_root}/source/model/SplunkDestinationDescription.cpp"
    "${library_root}/source/model/SplunkDestinationUpdate.cpp"
    "${library_root}/source/model/SplunkRetryOptions.cpp"
    "${library_root}/source/model/SplunkS3BackupMode.cpp"
    "${library_root}/source/model/StartDeliveryStreamEncryptionRequest.cpp"
    "${library_root}/source/model/StartDeliveryStreamEncryptionResult.cpp"
    "${library_root}/source/model/StopDeliveryStreamEncryptionRequest.cpp"
    "${library_root}/source/model/StopDeliveryStreamEncryptionResult.cpp"
    "${library_root}/source/model/Tag.cpp"
    "${library_root}/source/model/TagDeliveryStreamRequest.cpp"
    "${library_root}/source/model/TagDeliveryStreamResult.cpp"
    "${library_root}/source/model/UntagDeliveryStreamRequest.cpp"
    "${library_root}/source/model/UntagDeliveryStreamResult.cpp"
    "${library_root}/source/model/UpdateDestinationRequest.cpp"
    "${library_root}/source/model/UpdateDestinationResult.cpp"
    "${library_root}/source/model/VpcConfiguration.cpp"
    "${library_root}/source/model/VpcConfigurationDescription.cpp"
  )

  target_include_directories(thirdparty_aws-cpp-sdk-firehose PRIVATE
    "${library_root}/include"
  )

  target_include_directories(thirdparty_aws-cpp-sdk-firehose SYSTEM INTERFACE
    "${library_root}/include"
  )

  target_link_libraries(thirdparty_aws-cpp-sdk-firehose
    PRIVATE
      thirdparty_cxx_settings

    PUBLIC
      thirdparty_aws-cpp-sdk-core
  )

  if(PLATFORM_POSIX)
    find_package(Threads REQUIRED)
    target_link_libraries(thirdparty_aws-cpp-sdk-firehose PUBLIC
      Threads::Threads
    )

    target_compile_definitions(thirdparty_aws-cpp-sdk-firehose PRIVATE
      HAS_PATHCONF
      HAS_UMASK
    )
  endif()

  if(PLATFORM_LINUX)
    target_compile_definitions(thirdparty_aws-cpp-sdk-firehose PRIVATE
      PLATFORM_LINUX
      ENABLE_OPENSSL_ENCRYPTION
    )
  
  elseif(PLATFORM_MACOS)
    target_compile_definitions(thirdparty_aws-cpp-sdk-firehose PRIVATE
      PLATFORM_APPLE
      ENABLE_COMMONCRYPTO_ENCRYPTION
    )

  elseif(PLATFORM_WINDOWS)
    target_compile_definitions(thirdparty_aws-cpp-sdk-firehose PUBLIC
      PLATFORM_WINDOWS
      ENABLE_BCRYPT_ENCRYPTION
    )

    target_link_libraries(thirdparty_aws-cpp-sdk-firehose PUBLIC
      Userenv
      version
      ws2_32
    )
  endif()
endfunction()

function(generateAwsCppSdkCore)
  set(library_root "${CMAKE_CURRENT_SOURCE_DIR}/src/aws-sdk-cpp/aws-cpp-sdk-core")

  if(PLATFORM_LINUX)
    set(config_path "${CMAKE_CURRENT_SOURCE_DIR}/config/aws-cpp-sdk-core/linux/${TARGET_PROCESSOR}")

  elseif(PLATFORM_MACOS)
    set(config_path "${CMAKE_CURRENT_SOURCE_DIR}/config/aws-cpp-sdk-core/macos/${TARGET_PROCESSOR}")

  elseif(PLATFORM_WINDOWS)
    set(config_path "${CMAKE_CURRENT_SOURCE_DIR}/config/aws-cpp-sdk-core/windows/${TARGET_PROCESSOR}")
  endif()

  add_library(thirdparty_aws-cpp-sdk-core EXCLUDE_FROM_ALL
    "${library_root}/source/AmazonSerializableWebServiceRequest.cpp"
    "${library_root}/source/AmazonStreamingWebServiceRequest.cpp"
    "${library_root}/source/AmazonWebServiceRequest.cpp"
    "${library_root}/source/Aws.cpp"
    "${library_root}/source/Globals.cpp"
    "${library_root}/source/Region.cpp"
    "${library_root}/source/Version.cpp"
    "${library_root}/source/auth/AWSAuthSigner.cpp"
    "${library_root}/source/auth/AWSAuthSignerProvider.cpp"
    "${library_root}/source/auth/AWSCredentialsProvider.cpp"
    "${library_root}/source/auth/AWSCredentialsProviderChain.cpp"
    "${library_root}/source/auth/SSOCredentialsProvider.cpp"
    "${library_root}/source/auth/STSCredentialsProvider.cpp"
    "${library_root}/source/client/AWSClient.cpp"
    "${library_root}/source/client/AWSErrorMarshaller.cpp"
    "${library_root}/source/client/AsyncCallerContext.cpp"
    "${library_root}/source/client/ClientConfiguration.cpp"
    "${library_root}/source/client/CoreErrors.cpp"
    "${library_root}/source/client/DefaultRetryStrategy.cpp"
    "${library_root}/source/client/RetryStrategy.cpp"
    "${library_root}/source/client/SpecifiedRetryableErrorsRetryStrategy.cpp"
    "${library_root}/source/config/AWSProfileConfigLoader.cpp"
    "${library_root}/source/external/cjson/cJSON.cpp"
    "${library_root}/source/external/tinyxml2/tinyxml2.cpp"
    "${library_root}/source/http/HttpClient.cpp"
    "${library_root}/source/http/HttpClientFactory.cpp"
    "${library_root}/source/http/HttpRequest.cpp"
    "${library_root}/source/http/HttpTypes.cpp"
    "${library_root}/source/http/Scheme.cpp"
    "${library_root}/source/http/URI.cpp"
    "${library_root}/source/http/standard/StandardHttpRequest.cpp"
    "${library_root}/source/http/standard/StandardHttpResponse.cpp"
    "${library_root}/source/internal/AWSHttpResourceClient.cpp"
    "${library_root}/source/monitoring/DefaultMonitoring.cpp"
    "${library_root}/source/monitoring/HttpClientMetrics.cpp"
    "${library_root}/source/monitoring/MonitoringManager.cpp"
    "${library_root}/source/utils/ARN.cpp"
    "${library_root}/source/utils/Array.cpp"
    "${library_root}/source/utils/DNS.cpp"
    "${library_root}/source/utils/DateTimeCommon.cpp"
    "${library_root}/source/utils/Directory.cpp"
    "${library_root}/source/utils/Document.cpp"
    "${library_root}/source/utils/EnumParseOverflowContainer.cpp"
    "${library_root}/source/utils/FileSystemUtils.cpp"
    "${library_root}/source/utils/GetTheLights.cpp"
    "${library_root}/source/utils/HashingUtils.cpp"
    "${library_root}/source/utils/StringUtils.cpp"
    "${library_root}/source/utils/TempFile.cpp"
    "${library_root}/source/utils/UUID.cpp"
    "${library_root}/source/utils/base64/Base64.cpp"
    "${library_root}/source/utils/crypto/Cipher.cpp"
    "${library_root}/source/utils/crypto/ContentCryptoMaterial.cpp"
    "${library_root}/source/utils/crypto/ContentCryptoScheme.cpp"
    "${library_root}/source/utils/crypto/CryptoBuf.cpp"
    "${library_root}/source/utils/crypto/CryptoStream.cpp"
    "${library_root}/source/utils/crypto/EncryptionMaterials.cpp"
    "${library_root}/source/utils/crypto/KeyWrapAlgorithm.cpp"
    "${library_root}/source/utils/crypto/MD5.cpp"
    "${library_root}/source/utils/crypto/Sha1.cpp"
    "${library_root}/source/utils/crypto/Sha256.cpp"
    "${library_root}/source/utils/crypto/Sha256HMAC.cpp"
    "${library_root}/source/utils/crypto/factory/Factories.cpp"
    "${library_root}/source/utils/event/EventDecoderStream.cpp"
    "${library_root}/source/utils/event/EventEncoderStream.cpp"
    "${library_root}/source/utils/event/EventHeader.cpp"
    "${library_root}/source/utils/event/EventMessage.cpp"
    "${library_root}/source/utils/event/EventStreamBuf.cpp"
    "${library_root}/source/utils/event/EventStreamDecoder.cpp"
    "${library_root}/source/utils/event/EventStreamEncoder.cpp"
    "${library_root}/source/utils/event/EventStreamErrors.cpp"
    "${library_root}/source/utils/json/JsonSerializer.cpp"
    "${library_root}/source/utils/logging/AWSLogging.cpp"
    "${library_root}/source/utils/logging/CRTLogSystem.cpp"
    "${library_root}/source/utils/logging/CRTLogging.cpp"
    "${library_root}/source/utils/logging/ConsoleLogSystem.cpp"
    "${library_root}/source/utils/logging/DefaultLogSystem.cpp"
    "${library_root}/source/utils/logging/FormattedLogSystem.cpp"
    "${library_root}/source/utils/logging/LogLevel.cpp"
    "${library_root}/source/utils/memory/AWSMemory.cpp"
    "${library_root}/source/utils/memory/stl/SimpleStringStream.cpp"
    "${library_root}/source/utils/stream/ConcurrentStreamBuf.cpp"
    "${library_root}/source/utils/stream/PreallocatedStreamBuf.cpp"
    "${library_root}/source/utils/stream/ResponseStream.cpp"
    "${library_root}/source/utils/stream/SimpleStreamBuf.cpp"
    "${library_root}/source/utils/threading/Executor.cpp"
    "${library_root}/source/utils/threading/ReaderWriterLock.cpp"
    "${library_root}/source/utils/threading/Semaphore.cpp"
    "${library_root}/source/utils/threading/ThreadTask.cpp"
    "${library_root}/source/utils/xml/XmlSerializer.cpp"
  )

  if(PLATFORM_POSIX)
    target_sources(thirdparty_aws-cpp-sdk-core PRIVATE
      "${library_root}/source/net/linux-shared/Net.cpp"
      "${library_root}/source/net/linux-shared/SimpleUDP.cpp"
      "${library_root}/source/platform/linux-shared/Environment.cpp"
      "${library_root}/source/platform/linux-shared/FileSystem.cpp"
      "${library_root}/source/platform/linux-shared/OSVersionInfo.cpp"
      "${library_root}/source/platform/linux-shared/Security.cpp"
      "${library_root}/source/platform/linux-shared/Time.cpp"
    )
  endif()

  if(PLATFORM_LINUX)
    target_sources(thirdparty_aws-cpp-sdk-core PRIVATE
      "${library_root}/source/utils/crypto/openssl/CryptoImpl.cpp"
    )

  elseif(PLATFORM_MACOS)
    target_sources(thirdparty_aws-cpp-sdk-core PRIVATE
      "${library_root}/source/utils/crypto/commoncrypto/CryptoImpl.cpp"
    )

  elseif(PLATFORM_WINDOWS)
    target_sources(thirdparty_aws-cpp-sdk-core PRIVATE
      "${library_root}/source/net/windows/Net.cpp"
      "${library_root}/source/net/windows/SimpleUDP.cpp"
      "${library_root}/source/platform/windows/Environment.cpp"
      "${library_root}/source/platform/windows/FileSystem.cpp"
      "${library_root}/source/platform/windows/OSVersionInfo.cpp"
      "${library_root}/source/platform/windows/Security.cpp"
      "${library_root}/source/platform/windows/Time.cpp"
      "${library_root}/source/utils/crypto/bcrypt/CryptoImpl.cpp"
    )
  endif()

  target_include_directories(thirdparty_aws-cpp-sdk-core PRIVATE
    "${library_root}/include/aws/core/platform/refs"
    "${library_root}/include"
    "${config_path}"
  )

  target_include_directories(thirdparty_aws-cpp-sdk-core SYSTEM INTERFACE
    "${library_root}/include"
    "${config_path}"
  )

  target_link_libraries(thirdparty_aws-cpp-sdk-core
    PRIVATE
      thirdparty_cxx_settings

    PUBLIC
      thirdparty_aws-crt-cpp
  )

  if(PLATFORM_POSIX)
    find_package(Threads REQUIRED)
    target_link_libraries(thirdparty_aws-cpp-sdk-core PUBLIC
      Threads::Threads
    )
  endif()

  if(PLATFORM_LINUX)
    target_link_libraries(thirdparty_aws-cpp-sdk-core PUBLIC
      thirdparty_zlib
      thirdparty_aws-crt-cpp
    )

  elseif(PLATFORM_WINDOWS)
    target_link_libraries(thirdparty_aws-cpp-sdk-core PUBLIC
      Userenv
      version
      ws2_32
      Wininet
      winhttp
      Bcrypt
    )
  endif()

  target_compile_definitions(thirdparty_aws-cpp-sdk-core
    PRIVATE
      ENABLE_CURL_LOGGING

    PUBLIC
      AWS_SDK_VERSION_MAJOR=1
      AWS_SDK_VERSION_MINOR=9
      AWS_SDK_VERSION_PATCH=116
  )

  if(PLATFORM_POSIX)
    target_compile_definitions(thirdparty_aws-cpp-sdk-core PRIVATE
      HAS_PATHCONF
      HAS_UMASK
    )
  endif()

  if(PLATFORM_LINUX)
    target_compile_definitions(thirdparty_aws-cpp-sdk-core PRIVATE
      PLATFORM_LINUX
      ENABLE_OPENSSL_ENCRYPTION
    )

  elseif(PLATFORM_MACOS)
    target_compile_definitions(thirdparty_aws-cpp-sdk-core PRIVATE
      PLATFORM_APPLE
      ENABLE_COMMONCRYPTO_ENCRYPTION
    )

  elseif(PLATFORM_WINDOWS)
    target_compile_definitions(thirdparty_aws-cpp-sdk-core PRIVATE
      USE_WINDOWS_DLL_SEMANTICS
      PLATFORM_WINDOWS
      ENABLE_BCRYPT_ENCRYPTION
    )
  endif()
endfunction()

function(generateAwsCrtCpp)
  generateAwsCCommon()
  generateAwsCCompression()
  generateAwsCCal()
  generateAwsCCIo()
  generateAwsChecksums()
  generateAwsCAuth()
  generateAwsCHttp()
  generateAwsCMqtt()
  generateAwsCEventStream()
  generateAwsCS3()

  if(PLATFORM_LINUX)
    generateS2n()
  endif()

  set(library_root "${CMAKE_CURRENT_SOURCE_DIR}/src/aws-crt-cpp")

  if(PLATFORM_LINUX)
    set(config_path "${CMAKE_CURRENT_SOURCE_DIR}/config/aws-crt-cpp/linux/${TARGET_PROCESSOR}")

  elseif(PLATFORM_MACOS)
    set(config_path "${CMAKE_CURRENT_SOURCE_DIR}/config/aws-crt-cpp/macos/${TARGET_PROCESSOR}")

  elseif(PLATFORM_WINDOWS)
    set(config_path "${CMAKE_CURRENT_SOURCE_DIR}/config/aws-crt-cpp/windows/${TARGET_PROCESSOR}")
  endif()

  add_library(thirdparty_aws-crt-cpp EXCLUDE_FROM_ALL
    "${library_root}/source/Api.cpp"
    "${library_root}/source/auth/Credentials.cpp"
    "${library_root}/source/auth/Sigv4Signing.cpp"
    "${library_root}/source/crypto/Hash.cpp"
    "${library_root}/source/crypto/HMAC.cpp"
    "${library_root}/source/DateTime.cpp"
    "${library_root}/source/external/cJSON.cpp"
    "${library_root}/source/http/HttpConnection.cpp"
    "${library_root}/source/http/HttpConnectionManager.cpp"
    "${library_root}/source/http/HttpProxyStrategy.cpp"
    "${library_root}/source/http/HttpRequestResponse.cpp"
    "${library_root}/source/ImdsClient.cpp"
    "${library_root}/source/io/Bootstrap.cpp"
    "${library_root}/source/io/ChannelHandler.cpp"
    "${library_root}/source/io/EventLoopGroup.cpp"
    "${library_root}/source/io/HostResolver.cpp"
    "${library_root}/source/io/SocketOptions.cpp"
    "${library_root}/source/io/Stream.cpp"
    "${library_root}/source/io/TlsOptions.cpp"
    "${library_root}/source/iot/MqttClient.cpp"
    "${library_root}/source/io/Uri.cpp"
    "${library_root}/source/JsonObject.cpp"
    "${library_root}/source/mqtt/MqttClient.cpp"
    "${library_root}/source/StringUtils.cpp"
    "${library_root}/source/Types.cpp"
    "${library_root}/source/UUID.cpp"
  )

  target_include_directories(thirdparty_aws-crt-cpp PRIVATE
    "${library_root}/include"
    "${config_path}"
  )

  target_include_directories(thirdparty_aws-crt-cpp SYSTEM INTERFACE
    "${library_root}/include"
  )

  target_link_libraries(thirdparty_aws-crt-cpp
    PRIVATE
      thirdparty_cxx_settings

    PUBLIC
      thirdparty_aws-c-http
      thirdparty_aws-c-mqtt
      thirdparty_aws-c-cal
      thirdparty_aws-c-auth
      thirdparty_aws-c-common
      thirdparty_aws-c-io
      thirdparty_aws-checksums
      thirdparty_aws-c-event-stream
      thirdparty_aws-c-s3
  )

  target_compile_definitions(thirdparty_aws-crt-cpp PRIVATE
    CJSON_HIDE_SYMBOLS
  )

  if(PLATFORM_LINUX)
    target_compile_definitions(thirdparty_aws-crt-cpp PRIVATE
      PLATFORM_LINUX
      ENABLE_OPENSSL_ENCRYPTION
    )

    if(TARGET_PROCESSOR STREQUAL "x86_64")
      target_compile_definitions(thirdparty_aws-crt-cpp PRIVATE
        HAVE_SYSCONF
      )
    endif()

  elseif(PLATFORM_MACOS)
    target_compile_definitions(thirdparty_aws-crt-cpp PRIVATE
      PLATFORM_APPLE
      ENABLE_COMMONCRYPTO_ENCRYPTION
    )

  elseif(PLATFORM_WINDOWS)
    target_compile_definitions(thirdparty_aws-crt-cpp PRIVATE
      PLATFORM_WINDOWS
      ENABLE_BCRYPT_ENCRYPTION
    )
  endif()
endfunction()

function(generateAwsCS3)
  set(library_root "${CMAKE_CURRENT_SOURCE_DIR}/src/aws-c-s3")

  add_library(thirdparty_aws-c-s3 EXCLUDE_FROM_ALL
    "${library_root}/source/s3_auto_ranged_get.c"
    "${library_root}/source/s3_auto_ranged_put.c"
    "${library_root}/source/s3.c"
    "${library_root}/source/s3_client.c"
    "${library_root}/source/s3_default_meta_request.c"
    "${library_root}/source/s3_meta_request.c"
    "${library_root}/source/s3_request.c"
    "${library_root}/source/s3_request_messages.c"
    "${library_root}/source/s3_util.c"
  )

  target_include_directories(thirdparty_aws-c-s3 PRIVATE
    "${library_root}/include"
  )

  target_include_directories(thirdparty_aws-c-s3 SYSTEM INTERFACE
    "${library_root}/include"
  )

  target_link_libraries(thirdparty_aws-c-s3
    PRIVATE
      thirdparty_c_settings

    PUBLIC
      thirdparty_aws-c-auth
  )

  target_compile_definitions(thirdparty_aws-c-s3 PRIVATE
    CJSON_HIDE_SYMBOLS
  )

  if(PLATFORM_POSIX)
    target_compile_definitions(thirdparty_aws-c-s3 PRIVATE
      HAVE_SYSCONF
    )
  endif()

  if(PLATFORM_LINUX)
    target_compile_definitions(thirdparty_aws-c-s3 PRIVATE
      PLATFORM_LINUX
      ENABLE_OPENSSL_ENCRYPTION
    )

  elseif(PLATFORM_MACOS)
    target_compile_definitions(thirdparty_aws-c-s3 PRIVATE
      PLATFORM_APPLE
      ENABLE_COMMONCRYPTO_ENCRYPTION
    )

  elseif(PLATFORM_WINDOWS)
    target_compile_definitions(thirdparty_aws-c-s3 PRIVATE
      PLATFORM_WINDOWS
      ENABLE_BCRYPT_ENCRYPTION
    )
  endif()
endfunction()

function(generateAwsCEventStream)
  set(library_root "${CMAKE_CURRENT_SOURCE_DIR}/src/aws-c-event-stream")

  add_library(thirdparty_aws-c-event-stream EXCLUDE_FROM_ALL
    "${library_root}/source/event_stream.c"
    "${library_root}/source/event_stream_channel_handler.c"
    "${library_root}/source/event_stream_rpc.c"
    "${library_root}/source/event_stream_rpc_client.c"
    "${library_root}/source/event_stream_rpc_server.c"
  )

  target_include_directories(thirdparty_aws-c-event-stream PRIVATE
    "${library_root}/include"
  )

  target_include_directories(thirdparty_aws-c-event-stream SYSTEM INTERFACE
    "${library_root}/include"
  )

  target_link_libraries(thirdparty_aws-c-event-stream
    PRIVATE
      thirdparty_c_settings

    PUBLIC
      thirdparty_aws-c-io
      thirdparty_aws-c-common
      thirdparty_aws-checksums
  )

  if(PLATFORM_POSIX)
    target_compile_definitions(thirdparty_aws-c-event-stream PRIVATE
      HAVE_SYSCONF
    )
  endif()

  if(PLATFORM_LINUX)
    target_compile_definitions(thirdparty_aws-c-event-stream PRIVATE
      PLATFORM_LINUX
      ENABLE_OPENSSL_ENCRYPTION
    )

  elseif(PLATFORM_MACOS)
    target_compile_definitions(thirdparty_aws-c-event-stream PRIVATE
      PLATFORM_APPLE
      ENABLE_COMMONCRYPTO_ENCRYPTION
    )

  elseif(PLATFORM_WINDOWS)
    target_compile_definitions(thirdparty_aws-c-event-stream PRIVATE
      PLATFORM_WINDOWS
      ENABLE_BCRYPT_ENCRYPTION
    )
  endif()
endfunction()

function(generateAwsCMqtt)
  set(library_root "${CMAKE_CURRENT_SOURCE_DIR}/src/aws-c-mqtt")

  add_library(thirdparty_aws-c-mqtt EXCLUDE_FROM_ALL
    "${library_root}/source/client.c"
    "${library_root}/source/client_channel_handler.c"
    "${library_root}/source/fixed_header.c"
    "${library_root}/source/mqtt.c"
    "${library_root}/source/packets.c"
    "${library_root}/source/topic_tree.c"
  )

  target_include_directories(thirdparty_aws-c-mqtt PRIVATE
    "${library_root}/include"
  )

  target_include_directories(thirdparty_aws-c-mqtt SYSTEM INTERFACE
    "${library_root}/include"
  )

  target_link_libraries(thirdparty_aws-c-mqtt
    PRIVATE
      thirdparty_c_settings

    PUBLIC
      thirdparty_aws-c-io
      thirdparty_aws-c-http
  )

  target_compile_definitions(thirdparty_aws-c-mqtt PUBLIC
    AWS_MQTT_WITH_WEBSOCKETS
  )

  if(PLATFORM_POSIX)
    target_compile_definitions(thirdparty_aws-c-mqtt PRIVATE
      HAVE_SYSCONF
    )
  endif()

  if(PLATFORM_LINUX)
    target_compile_definitions(thirdparty_aws-c-mqtt PRIVATE
      PLATFORM_LINUX
      ENABLE_OPENSSL_ENCRYPTION
    )

  elseif(PLATFORM_MACOS)
    target_compile_definitions(thirdparty_aws-c-mqtt PRIVATE
      PLATFORM_APPLE
      ENABLE_COMMONCRYPTO_ENCRYPTION
    )

  elseif(PLATFORM_WINDOWS)
    target_compile_definitions(thirdparty_aws-c-mqtt PRIVATE
      PLATFORM_WINDOWS
      ENABLE_BCRYPT_ENCRYPTION
    )
  endif()
endfunction()

function(generateAwsCHttp)
  set(library_root "${CMAKE_CURRENT_SOURCE_DIR}/src/aws-c-http")

  add_library(thirdparty_aws-c-http EXCLUDE_FROM_ALL
    "${library_root}/source/connection.c"
    "${library_root}/source/connection_manager.c"
    "${library_root}/source/connection_monitor.c"
    "${library_root}/source/h1_connection.c"
    "${library_root}/source/h1_decoder.c"
    "${library_root}/source/h1_encoder.c"
    "${library_root}/source/h1_stream.c"
    "${library_root}/source/h2_connection.c"
    "${library_root}/source/h2_decoder.c"
    "${library_root}/source/h2_frames.c"
    "${library_root}/source/h2_stream.c"
    "${library_root}/source/hpack.c"
    "${library_root}/source/hpack_huffman_static.c"
    "${library_root}/source/http.c"
    "${library_root}/source/proxy_connection.c"
    "${library_root}/source/proxy_strategy.c"
    "${library_root}/source/request_response.c"
    "${library_root}/source/statistics.c"
    "${library_root}/source/strutil.c"
    "${library_root}/source/websocket_bootstrap.c"
    "${library_root}/source/websocket.c"
    "${library_root}/source/websocket_decoder.c"
    "${library_root}/source/websocket_encoder.c"
  )

  target_include_directories(thirdparty_aws-c-http PRIVATE
    "${library_root}/include"
  )

  target_include_directories(thirdparty_aws-c-http SYSTEM INTERFACE
    "${library_root}/include"
  )

  target_link_libraries(thirdparty_aws-c-http
    PRIVATE
      thirdparty_c_settings

    PUBLIC
      thirdparty_aws-c-io
      thirdparty_aws-c-compression
  )

  if(PLATFORM_POSIX)
    target_compile_definitions(thirdparty_aws-c-http PRIVATE
      HAVE_SYSCONF
    )
  endif()

  if(PLATFORM_LINUX)
    target_compile_definitions(thirdparty_aws-c-http PRIVATE
      PLATFORM_LINUX
      ENABLE_OPENSSL_ENCRYPTION
    )

  elseif(PLATFORM_MACOS)
    target_compile_definitions(thirdparty_aws-c-http PRIVATE
      PLATFORM_APPLE
      ENABLE_COMMONCRYPTO_ENCRYPTION
    )

  elseif(PLATFORM_WINDOWS)
    target_compile_definitions(thirdparty_aws-c-http PRIVATE
      PLATFORM_WINDOWS
      ENABLE_BCRYPT_ENCRYPTION
    )
  endif()
endfunction()

function(generateAwsCAuth)
  set(library_root "${CMAKE_CURRENT_SOURCE_DIR}/src/aws-c-auth")

  add_library(thirdparty_aws-c-auth EXCLUDE_FROM_ALL
    "${library_root}/source/auth.c"
    "${library_root}/source/aws_imds_client.c"
    "${library_root}/source/aws_profile.c"
    "${library_root}/source/aws_signing.c"
    "${library_root}/source/credentials.c"
    "${library_root}/source/credentials_provider_cached.c"
    "${library_root}/source/credentials_provider_chain.c"
    "${library_root}/source/credentials_provider_default_chain.c"
    "${library_root}/source/credentials_provider_delegate.c"
    "${library_root}/source/credentials_provider_ecs.c"
    "${library_root}/source/credentials_provider_environment.c"
    "${library_root}/source/credentials_provider_imds.c"
    "${library_root}/source/credentials_provider_process.c"
    "${library_root}/source/credentials_provider_profile.c"
    "${library_root}/source/credentials_provider_static.c"
    "${library_root}/source/credentials_provider_sts.c"
    "${library_root}/source/credentials_provider_sts_web_identity.c"
    "${library_root}/source/credentials_provider_x509.c"
    "${library_root}/source/credentials_utils.c"
    "${library_root}/source/external/cJSON.c"
    "${library_root}/source/key_derivation.c"
    "${library_root}/source/signable.c"
    "${library_root}/source/signing.c"
    "${library_root}/source/signing_config.c"
    "${library_root}/source/signing_result.c"
    "${library_root}/source/sigv4_http_request.c"
  )

  target_include_directories(thirdparty_aws-c-auth PRIVATE
    "${library_root}/include"
  )

  target_include_directories(thirdparty_aws-c-auth SYSTEM INTERFACE
    "${library_root}/include"
  )

  target_link_libraries(thirdparty_aws-c-auth
    PRIVATE
      thirdparty_c_settings

    PUBLIC
      thirdparty_aws-c-cal
      thirdparty_aws-c-http
  )

  target_compile_definitions(thirdparty_aws-c-auth PRIVATE
    CJSON_HIDE_SYMBOLS
  )

  if(PLATFORM_POSIX)
    target_compile_definitions(thirdparty_aws-c-auth PRIVATE
      HAVE_SYSCONF
    )
  endif()

  if(PLATFORM_LINUX)
    target_compile_definitions(thirdparty_aws-c-auth PRIVATE
      PLATFORM_LINUX
      ENABLE_OPENSSL_ENCRYPTION
    )

  elseif(PLATFORM_MACOS)
    target_compile_definitions(thirdparty_aws-c-auth PRIVATE
      PLATFORM_APPLE
      ENABLE_COMMONCRYPTO_ENCRYPTION
    )

  elseif(PLATFORM_WINDOWS)
    target_compile_definitions(thirdparty_aws-c-auth PRIVATE
      PLATFORM_WINDOWS
      ENABLE_BCRYPT_ENCRYPTION
    )
  endif()
endfunction()

function(generateAwsChecksums)
  set(library_root "${CMAKE_CURRENT_SOURCE_DIR}/src/aws-checksums")

  add_library(thirdparty_aws-checksums EXCLUDE_FROM_ALL
    "${library_root}/source/crc.c"
    "${library_root}/source/crc_sw.c"
  )

  if(TARGET_PROCESSOR STREQUAL "x86_64")
    if(PLATFORM_WINDOWS)
      target_sources(thirdparty_aws-checksums PRIVATE
        "${library_root}/source/intel/visualc/visualc_crc32c_sse42.c"
      )

    elseif(PLATFORM_POSIX)
      target_sources(thirdparty_aws-checksums PRIVATE
        "${library_root}/source/intel/asm/crc32c_sse42_asm.c"
      )
    endif()

  elseif(TARGET_PROCESSOR STREQUAL "aarch64")
    set(crc_impl_file "${library_root}/source/arm/crc32c_arm.c")

    target_sources(thirdparty_aws-checksums PRIVATE
      "${crc_impl_file}"
    )

    set_source_files_properties("${crc_impl_file}" PROPERTIES
      COMPILE_FLAGS
        "-march=armv8-a+crc"
    )
  endif()

  target_include_directories(thirdparty_aws-checksums PRIVATE
    "${library_root}/include"
  )

  target_include_directories(thirdparty_aws-checksums SYSTEM INTERFACE
    "${library_root}/include"
  )

  target_link_libraries(thirdparty_aws-checksums
    PRIVATE
      thirdparty_c_settings

    PUBLIC
      thirdparty_aws-c-common
  )

  if(PLATFORM_POSIX)
    target_compile_definitions(thirdparty_aws-checksums PRIVATE
      HAVE_SYSCONF
    )
  endif()

  if(PLATFORM_LINUX)
    target_compile_definitions(thirdparty_aws-checksums PRIVATE
      PLATFORM_LINUX
      ENABLE_OPENSSL_ENCRYPTION
    )

  elseif(PLATFORM_MACOS)
    target_compile_definitions(thirdparty_aws-checksums PRIVATE
      PLATFORM_APPLE
      ENABLE_COMMONCRYPTO_ENCRYPTION
    )

  elseif(PLATFORM_WINDOWS)
    target_compile_definitions(thirdparty_aws-checksums PRIVATE
      PLATFORM_WINDOWS
      ENABLE_BCRYPT_ENCRYPTION
    )
  endif()
endfunction()

function(generateS2n)
  if(PLATFORM_MACOS)
    message(FATAL_ERROR "Unsuppoted platform")
  endif()

  set(library_root "${CMAKE_CURRENT_SOURCE_DIR}/src/s2n")

  add_library(thirdparty_s2n EXCLUDE_FROM_ALL
    "${library_root}/crypto/s2n_aead_cipher_aes_gcm.c"
    "${library_root}/crypto/s2n_aead_cipher_chacha20_poly1305.c"
    "${library_root}/crypto/s2n_cbc_cipher_3des.c"
    "${library_root}/crypto/s2n_cbc_cipher_aes.c"
    "${library_root}/crypto/s2n_certificate.c"
    "${library_root}/crypto/s2n_cipher.c"
    "${library_root}/crypto/s2n_composite_cipher_aes_sha.c"
    "${library_root}/crypto/s2n_crypto.c"
    "${library_root}/crypto/s2n_dhe.c"
    "${library_root}/crypto/s2n_drbg.c"
    "${library_root}/crypto/s2n_ecc_evp.c"
    "${library_root}/crypto/s2n_ecdsa.c"
    "${library_root}/crypto/s2n_evp.c"
    "${library_root}/crypto/s2n_fips.c"
    "${library_root}/crypto/s2n_hash.c"
    "${library_root}/crypto/s2n_hkdf.c"
    "${library_root}/crypto/s2n_hmac.c"
    "${library_root}/crypto/s2n_openssl_x509.c"
    "${library_root}/crypto/s2n_pkey.c"
    "${library_root}/crypto/s2n_rsa.c"
    "${library_root}/crypto/s2n_rsa_pss.c"
    "${library_root}/crypto/s2n_rsa_signing.c"
    "${library_root}/crypto/s2n_sequence.c"
    "${library_root}/crypto/s2n_stream_cipher_null.c"
    "${library_root}/crypto/s2n_stream_cipher_rc4.c"
    "${library_root}/crypto/s2n_tls13_keys.c"
    "${library_root}/error/s2n_errno.c"
    "${library_root}/pq-crypto/bike_r1/aes_ctr_prf.c"
    "${library_root}/pq-crypto/bike_r1/bike_r1_kem.c"
    "${library_root}/pq-crypto/bike_r1/converts_portable.c"
    "${library_root}/pq-crypto/bike_r1/decode.c"
    "${library_root}/pq-crypto/bike_r1/error.c"
    "${library_root}/pq-crypto/bike_r1/gf2x_mul.c"
    "${library_root}/pq-crypto/bike_r1/gf2x_portable.c"
    "${library_root}/pq-crypto/bike_r1/openssl_utils.c"
    "${library_root}/pq-crypto/bike_r1/parallel_hash.c"
    "${library_root}/pq-crypto/bike_r1/sampling.c"
    "${library_root}/pq-crypto/bike_r1/sampling_portable.c"
    "${library_root}/pq-crypto/bike_r1/secure_decode_portable.c"
    "${library_root}/pq-crypto/bike_r1/utilities.c"
    "${library_root}/pq-crypto/bike_r2/aes_ctr_prf.c"
    "${library_root}/pq-crypto/bike_r2/bike_r2_kem.c"
    "${library_root}/pq-crypto/bike_r2/decode.c"
    "${library_root}/pq-crypto/bike_r2/error.c"
    "${library_root}/pq-crypto/bike_r2/gf2x_mul.c"
    "${library_root}/pq-crypto/bike_r2/gf2x_portable.c"
    "${library_root}/pq-crypto/bike_r2/openssl_utils.c"
    "${library_root}/pq-crypto/bike_r2/sampling.c"
    "${library_root}/pq-crypto/bike_r2/sampling_portable.c"
    "${library_root}/pq-crypto/bike_r2/secure_decode_portable.c"
    "${library_root}/pq-crypto/bike_r2/utilities.c"
    "${library_root}/pq-crypto/bike_r3/aes_ctr_prf.c"
    "${library_root}/pq-crypto/bike_r3/bike_r3_kem.c"
    "${library_root}/pq-crypto/bike_r3/decode_avx2.c"
    "${library_root}/pq-crypto/bike_r3/decode_avx512.c"
    "${library_root}/pq-crypto/bike_r3/decode.c"
    "${library_root}/pq-crypto/bike_r3/decode_portable.c"
    "${library_root}/pq-crypto/bike_r3/error.c"
    "${library_root}/pq-crypto/bike_r3/gf2x_inv.c"
    "${library_root}/pq-crypto/bike_r3/gf2x_ksqr_avx2.c"
    "${library_root}/pq-crypto/bike_r3/gf2x_ksqr_avx512.c"
    "${library_root}/pq-crypto/bike_r3/gf2x_ksqr_portable.c"
    "${library_root}/pq-crypto/bike_r3/gf2x_mul_avx2.c"
    "${library_root}/pq-crypto/bike_r3/gf2x_mul_avx512.c"
    "${library_root}/pq-crypto/bike_r3/gf2x_mul_base_pclmul.c"
    "${library_root}/pq-crypto/bike_r3/gf2x_mul_base_portable.c"
    "${library_root}/pq-crypto/bike_r3/gf2x_mul_base_vpclmul.c"
    "${library_root}/pq-crypto/bike_r3/gf2x_mul.c"
    "${library_root}/pq-crypto/bike_r3/gf2x_mul_portable.c"
    "${library_root}/pq-crypto/bike_r3/sampling_avx2.c"
    "${library_root}/pq-crypto/bike_r3/sampling_avx512.c"
    "${library_root}/pq-crypto/bike_r3/sampling.c"
    "${library_root}/pq-crypto/bike_r3/sampling_portable.c"
    "${library_root}/pq-crypto/bike_r3/utilities.c"
    "${library_root}/pq-crypto/kyber_90s_r2/aes256ctr.c"
    "${library_root}/pq-crypto/kyber_90s_r2/aes_c.c"
    "${library_root}/pq-crypto/kyber_90s_r2/cbd.c"
    "${library_root}/pq-crypto/kyber_90s_r2/indcpa.c"
    "${library_root}/pq-crypto/kyber_90s_r2/kyber_90s_r2_kem.c"
    "${library_root}/pq-crypto/kyber_90s_r2/ntt.c"
    "${library_root}/pq-crypto/kyber_90s_r2/poly.c"
    "${library_root}/pq-crypto/kyber_90s_r2/polyvec.c"
    "${library_root}/pq-crypto/kyber_90s_r2/reduce.c"
    "${library_root}/pq-crypto/kyber_90s_r2/sha2_c.c"
    "${library_root}/pq-crypto/kyber_90s_r2/verify.c"
    "${library_root}/pq-crypto/kyber_r2/cbd.c"
    "${library_root}/pq-crypto/kyber_r2/fips202_kyber_r2.c"
    "${library_root}/pq-crypto/kyber_r2/indcpa.c"
    "${library_root}/pq-crypto/kyber_r2/kyber_r2_kem.c"
    "${library_root}/pq-crypto/kyber_r2/ntt.c"
    "${library_root}/pq-crypto/kyber_r2/poly.c"
    "${library_root}/pq-crypto/kyber_r2/polyvec.c"
    "${library_root}/pq-crypto/kyber_r2/reduce.c"
    "${library_root}/pq-crypto/kyber_r2/symmetric-fips202.c"
    "${library_root}/pq-crypto/kyber_r2/verify.c"
    "${library_root}/pq-crypto/kyber_r3/kyber512r3_cbd.c"
    "${library_root}/pq-crypto/kyber_r3/kyber512r3_fips202.c"
    "${library_root}/pq-crypto/kyber_r3/kyber512r3_indcpa.c"
    "${library_root}/pq-crypto/kyber_r3/kyber512r3_kem.c"
    "${library_root}/pq-crypto/kyber_r3/kyber512r3_ntt.c"
    "${library_root}/pq-crypto/kyber_r3/kyber512r3_poly.c"
    "${library_root}/pq-crypto/kyber_r3/kyber512r3_polyvec.c"
    "${library_root}/pq-crypto/kyber_r3/kyber512r3_reduce.c"
    "${library_root}/pq-crypto/kyber_r3/kyber512r3_symmetric-shake.c"
    "${library_root}/pq-crypto/s2n_pq.c"
    "${library_root}/pq-crypto/s2n_pq_random.c"
    "${library_root}/pq-crypto/sike_r1/fips202_r1.c"
    "${library_root}/pq-crypto/sike_r1/fp_generic_r1.c"
    "${library_root}/pq-crypto/sike_r1/P503_r1.c"
    "${library_root}/pq-crypto/sike_r1/sike_r1_kem.c"
    "${library_root}/pq-crypto/sike_r3/sikep434r3.c"
    "${library_root}/pq-crypto/sike_r3/sikep434r3_ec_isogeny.c"
    "${library_root}/pq-crypto/sike_r3/sikep434r3_fips202.c"
    "${library_root}/pq-crypto/sike_r3/sikep434r3_fp.c"
    "${library_root}/pq-crypto/sike_r3/sikep434r3_fpx.c"
    "${library_root}/pq-crypto/sike_r3/sikep434r3_kem.c"
    "${library_root}/pq-crypto/sike_r3/sikep434r3_sidh.c"
    "${library_root}/stuffer/s2n_stuffer_base64.c"
    "${library_root}/stuffer/s2n_stuffer.c"
    "${library_root}/stuffer/s2n_stuffer_file.c"
    "${library_root}/stuffer/s2n_stuffer_network_order.c"
    "${library_root}/stuffer/s2n_stuffer_pem.c"
    "${library_root}/stuffer/s2n_stuffer_text.c"
    "${library_root}/tls/extensions/s2n_client_alpn.c"
    "${library_root}/tls/extensions/s2n_client_early_data_indication.c"
    "${library_root}/tls/extensions/s2n_client_key_share.c"
    "${library_root}/tls/extensions/s2n_client_max_frag_len.c"
    "${library_root}/tls/extensions/s2n_client_pq_kem.c"
    "${library_root}/tls/extensions/s2n_client_psk.c"
    "${library_root}/tls/extensions/s2n_client_renegotiation_info.c"
    "${library_root}/tls/extensions/s2n_client_sct_list.c"
    "${library_root}/tls/extensions/s2n_client_server_name.c"
    "${library_root}/tls/extensions/s2n_client_session_ticket.c"
    "${library_root}/tls/extensions/s2n_client_signature_algorithms.c"
    "${library_root}/tls/extensions/s2n_client_status_request.c"
    "${library_root}/tls/extensions/s2n_client_supported_groups.c"
    "${library_root}/tls/extensions/s2n_client_supported_versions.c"
    "${library_root}/tls/extensions/s2n_cookie.c"
    "${library_root}/tls/extensions/s2n_ec_point_format.c"
    "${library_root}/tls/extensions/s2n_extension_list.c"
    "${library_root}/tls/extensions/s2n_extension_type.c"
    "${library_root}/tls/extensions/s2n_extension_type_lists.c"
    "${library_root}/tls/extensions/s2n_key_share.c"
    "${library_root}/tls/extensions/s2n_nst_early_data_indication.c"
    "${library_root}/tls/extensions/s2n_psk_key_exchange_modes.c"
    "${library_root}/tls/extensions/s2n_quic_transport_params.c"
    "${library_root}/tls/extensions/s2n_server_alpn.c"
    "${library_root}/tls/extensions/s2n_server_certificate_status.c"
    "${library_root}/tls/extensions/s2n_server_early_data_indication.c"
    "${library_root}/tls/extensions/s2n_server_key_share.c"
    "${library_root}/tls/extensions/s2n_server_max_fragment_length.c"
    "${library_root}/tls/extensions/s2n_server_psk.c"
    "${library_root}/tls/extensions/s2n_server_renegotiation_info.c"
    "${library_root}/tls/extensions/s2n_server_sct_list.c"
    "${library_root}/tls/extensions/s2n_server_server_name.c"
    "${library_root}/tls/extensions/s2n_server_session_ticket.c"
    "${library_root}/tls/extensions/s2n_server_signature_algorithms.c"
    "${library_root}/tls/extensions/s2n_server_status_request.c"
    "${library_root}/tls/extensions/s2n_server_supported_versions.c"
    "${library_root}/tls/extensions/s2n_supported_versions.c"
    "${library_root}/tls/s2n_aead.c"
    "${library_root}/tls/s2n_alerts.c"
    "${library_root}/tls/s2n_async_pkey.c"
    "${library_root}/tls/s2n_auth_selection.c"
    "${library_root}/tls/s2n_cbc.c"
    "${library_root}/tls/s2n_change_cipher_spec.c"
    "${library_root}/tls/s2n_cipher_preferences.c"
    "${library_root}/tls/s2n_cipher_suites.c"
    "${library_root}/tls/s2n_client_cert.c"
    "${library_root}/tls/s2n_client_cert_verify.c"
    "${library_root}/tls/s2n_client_finished.c"
    "${library_root}/tls/s2n_client_hello.c"
    "${library_root}/tls/s2n_client_key_exchange.c"
    "${library_root}/tls/s2n_config.c"
    "${library_root}/tls/s2n_connection.c"
    "${library_root}/tls/s2n_connection_evp_digests.c"
    "${library_root}/tls/s2n_early_data.c"
    "${library_root}/tls/s2n_early_data_io.c"
    "${library_root}/tls/s2n_ecc_preferences.c"
    "${library_root}/tls/s2n_encrypted_extensions.c"
    "${library_root}/tls/s2n_establish_session.c"
    "${library_root}/tls/s2n_handshake.c"
    "${library_root}/tls/s2n_handshake_io.c"
    "${library_root}/tls/s2n_handshake_transcript.c"
    "${library_root}/tls/s2n_handshake_type.c"
    "${library_root}/tls/s2n_kem.c"
    "${library_root}/tls/s2n_kem_preferences.c"
    "${library_root}/tls/s2n_kex.c"
    "${library_root}/tls/s2n_key_log.c"
    "${library_root}/tls/s2n_key_update.c"
    "${library_root}/tls/s2n_ocsp_stapling.c"
    "${library_root}/tls/s2n_post_handshake.c"
    "${library_root}/tls/s2n_prf.c"
    "${library_root}/tls/s2n_protocol_preferences.c"
    "${library_root}/tls/s2n_psk.c"
    "${library_root}/tls/s2n_quic_support.c"
    "${library_root}/tls/s2n_record_read_aead.c"
    "${library_root}/tls/s2n_record_read.c"
    "${library_root}/tls/s2n_record_read_cbc.c"
    "${library_root}/tls/s2n_record_read_composite.c"
    "${library_root}/tls/s2n_record_read_stream.c"
    "${library_root}/tls/s2n_record_write.c"
    "${library_root}/tls/s2n_recv.c"
    "${library_root}/tls/s2n_resume.c"
    "${library_root}/tls/s2n_security_policies.c"
    "${library_root}/tls/s2n_send.c"
    "${library_root}/tls/s2n_server_cert.c"
    "${library_root}/tls/s2n_server_cert_request.c"
    "${library_root}/tls/s2n_server_done.c"
    "${library_root}/tls/s2n_server_extensions.c"
    "${library_root}/tls/s2n_server_finished.c"
    "${library_root}/tls/s2n_server_hello.c"
    "${library_root}/tls/s2n_server_hello_retry.c"
    "${library_root}/tls/s2n_server_key_exchange.c"
    "${library_root}/tls/s2n_server_new_session_ticket.c"
    "${library_root}/tls/s2n_shutdown.c"
    "${library_root}/tls/s2n_signature_algorithms.c"
    "${library_root}/tls/s2n_signature_scheme.c"
    "${library_root}/tls/s2n_tls13.c"
    "${library_root}/tls/s2n_tls13_certificate_verify.c"
    "${library_root}/tls/s2n_tls13_handshake.c"
    "${library_root}/tls/s2n_tls.c"
    "${library_root}/tls/s2n_x509_validator.c"
    "${library_root}/utils/s2n_array.c"
    "${library_root}/utils/s2n_asn1_time.c"
    "${library_root}/utils/s2n_blob.c"
    "${library_root}/utils/s2n_ensure.c"
    "${library_root}/utils/s2n_init.c"
    "${library_root}/utils/s2n_map.c"
    "${library_root}/utils/s2n_mem.c"
    "${library_root}/utils/s2n_random.c"
    "${library_root}/utils/s2n_result.c"
    "${library_root}/utils/s2n_rfc5952.c"
    "${library_root}/utils/s2n_safety.c"
    "${library_root}/utils/s2n_set.c"
    "${library_root}/utils/s2n_socket.c"
    "${library_root}/utils/s2n_str.c"
    "${library_root}/utils/s2n_timer.c"
  )

  if(TARGET_PROCESSOR STREQUAL "x86_64")
    target_sources(thirdparty_s2n PRIVATE
      "${library_root}/pq-crypto/sike_r3/sikep434r3_fp_x64_asm.S"
    )
  endif()

  target_include_directories(thirdparty_s2n PRIVATE
    "${library_root}"
    "${library_root}/api"
  )

  target_include_directories(thirdparty_s2n SYSTEM INTERFACE
    "${library_root}/api"
  )

  find_package(Threads REQUIRED)

  target_link_libraries(thirdparty_s2n
    PRIVATE
      thirdparty_c_settings
  
    PUBLIC
      ${CMAKE_DL_LIBS}
      Threads::Threads
      thirdparty_openssl
      rt
      m
  )

  target_compile_definitions(thirdparty_s2n PRIVATE
    _POSIX_C_SOURCE=200809L
    _FORTIFY_SOURCE=2
    PLATFORM_LINUX
    ENABLE_OPENSSL_ENCRYPTION
  )
endfunction()

function(generateAwsCCIo)
  set(library_root "${CMAKE_CURRENT_SOURCE_DIR}/src/aws-c-io")

  add_library(thirdparty_aws-c-io EXCLUDE_FROM_ALL
    "${library_root}/source/alpn_handler.c"
    "${library_root}/source/channel_bootstrap.c"
    "${library_root}/source/channel.c"
    "${library_root}/source/event_loop.c"
    "${library_root}/source/exponential_backoff_retry_strategy.c"
    "${library_root}/source/file_utils_shared.c"
    "${library_root}/source/host_resolver.c"
    "${library_root}/source/io.c"
    "${library_root}/source/message_pool.c"
    "${library_root}/source/pem_utils.c"
    "${library_root}/source/pki_utils.c"
    "${library_root}/source/retry_strategy.c"
    "${library_root}/source/socket_channel_handler.c"
    "${library_root}/source/standard_retry_strategy.c"
    "${library_root}/source/statistics.c"
    "${library_root}/source/stream.c"
    "${library_root}/source/tls_channel_handler.c"
    "${library_root}/source/tls_channel_handler_shared.c"
    "${library_root}/source/uri.c"
  )

  if(PLATFORM_POSIX)
    target_sources(thirdparty_aws-c-io PRIVATE
      "${library_root}/source/posix/file_utils.c"
      "${library_root}/source/posix/host_resolver.c"
      "${library_root}/source/posix/pipe.c"
      "${library_root}/source/posix/shared_library.c"
      "${library_root}/source/posix/socket.c"
    )

  elseif(PLATFORM_WINDOWS)
    target_sources(thirdparty_aws-c-io PRIVATE
      "${library_root}/source/windows/file_utils.c"
      "${library_root}/source/windows/host_resolver.c"
      "${library_root}/source/windows/iocp/iocp_event_loop.c"
      "${library_root}/source/windows/iocp/pipe.c"
      "${library_root}/source/windows/iocp/socket.c"
      "${library_root}/source/windows/secure_channel_tls_handler.c"
      "${library_root}/source/windows/shared_library.c"
      "${library_root}/source/windows/windows_pki_utils.c"
      "${library_root}/source/windows/winsock_init.c"
    )
  endif()

  if(PLATFORM_LINUX)
    target_sources(thirdparty_aws-c-io PRIVATE
      "${library_root}/source/linux/epoll_event_loop.c"
      "${library_root}/source/s2n/s2n_tls_channel_handler.c"
    )

  elseif(PLATFORM_MACOS)
    target_sources(thirdparty_aws-c-io PRIVATE
      "${library_root}/source/bsd/kqueue_event_loop.c"
      "${library_root}/source/darwin/darwin_pki_utils.c"
      "${library_root}/source/darwin/secure_transport_tls_channel_handler.c"
    )
  endif()

  target_include_directories(thirdparty_aws-c-io PRIVATE
    "${library_root}/include"
  )

  target_include_directories(thirdparty_aws-c-io SYSTEM INTERFACE
    "${library_root}/include"
  )

  target_link_libraries(thirdparty_aws-c-io
    PRIVATE
      thirdparty_c_settings

    PUBLIC
      thirdparty_aws-c-common
      thirdparty_aws-c-cal
  )

  if(PLATFORM_LINUX)
    target_link_libraries(thirdparty_aws-c-io PUBLIC
      thirdparty_s2n
    )

  elseif(PLATFORM_MACOS)
    target_link_libraries(thirdparty_aws-c-io PUBLIC
      "-framework Security"
    )

  elseif(PLATFORM_WINDOWS)
    target_link_libraries(thirdparty_aws-c-io PUBLIC
      Secur32
      Crypt32
      Shlwapi
    )
  endif()

  if(PLATFORM_POSIX)
    target_compile_definitions(thirdparty_aws-c-io PRIVATE
      HAVE_SYSCONF
    )
  endif()

  if(PLATFORM_LINUX)
    target_compile_definitions(thirdparty_aws-c-io
      PRIVATE
        PLATFORM_LINUX
        ENABLE_OPENSSL_ENCRYPTION

      PUBLIC
        AWS_USE_EPOLL
    )

  elseif(PLATFORM_MACOS)
    target_compile_definitions(thirdparty_aws-c-io
      PRIVATE
        PLATFORM_APPLE
        ENABLE_COMMONCRYPTO_ENCRYPTION

      PUBLIC
        AWS_USE_KQUEUE
    )

  elseif(PLATFORM_WINDOWS)
    target_compile_definitions(thirdparty_aws-c-io
      PRIVATE
        PLATFORM_WINDOWS
        ENABLE_BCRYPT_ENCRYPTION

      PUBLIC
        AWS_USE_IO_COMPLETION_PORTS
    )
  endif()
endfunction()

function(generateAwsCCal)
  set(library_root "${CMAKE_CURRENT_SOURCE_DIR}/src/aws-c-cal")

  add_library(thirdparty_aws-c-cal EXCLUDE_FROM_ALL
    "${library_root}/source/cal.c"
    "${library_root}/source/der.c"
    "${library_root}/source/ecc.c"
    "${library_root}/source/hash.c"
    "${library_root}/source/hmac.c"
  )

  if(PLATFORM_LINUX)
    target_sources(thirdparty_aws-c-cal PRIVATE
      "${library_root}/source/unix/opensslcrypto_ecc.c"
      "${library_root}/source/unix/opensslcrypto_hash.c"
      "${library_root}/source/unix/opensslcrypto_hmac.c"
      "${library_root}/source/unix/openssl_platform_init.c"
    )

  elseif(PLATFORM_MACOS)
    target_sources(thirdparty_aws-c-cal PRIVATE
      "${library_root}/source/darwin/commoncrypto_hmac.c"
      "${library_root}/source/darwin/commoncrypto_md5.c"
      "${library_root}/source/darwin/commoncrypto_platform_init.c"
      "${library_root}/source/darwin/commoncrypto_sha1.c"
      "${library_root}/source/darwin/commoncrypto_sha256.c"
      "${library_root}/source/darwin/securityframework_ecc.c"
    )

  elseif(PLATFORM_WINDOWS)
    target_sources(thirdparty_aws-c-cal PRIVATE
      "${library_root}/source/windows/bcrypt_ecc.c"
      "${library_root}/source/windows/bcrypt_hash.c"
      "${library_root}/source/windows/bcrypt_hmac.c"
      "${library_root}/source/windows/bcrypt_platform_init.c"
    )
  endif()

  target_include_directories(thirdparty_aws-c-cal PRIVATE
    "${library_root}/include"
  )

  target_include_directories(thirdparty_aws-c-cal SYSTEM INTERFACE
    "${library_root}/include"
  )

  target_link_libraries(thirdparty_aws-c-cal
    PRIVATE
      thirdparty_c_settings

    PUBLIC
      thirdparty_aws-c-common
  )

  if(PLATFORM_LINUX)
    target_link_libraries(thirdparty_aws-c-cal PUBLIC
      thirdparty_openssl
      ${CMAKE_DL_LIBS}
    )
  
  elseif(PLATFORM_MACOS)
    target_link_libraries(thirdparty_aws-c-cal PUBLIC
      "-framework Security"
    )

  elseif(PLATFORM_WINDOWS)
    target_link_libraries(thirdparty_aws-c-cal PUBLIC
      NCrypt
    )
  endif()

  if(PLATFORM_POSIX)
    target_compile_definitions(thirdparty_aws-c-cal PRIVATE
      HAVE_SYSCONF
    )
  endif()

  if(PLATFORM_LINUX)
    target_compile_definitions(thirdparty_aws-c-cal PRIVATE
      PLATFORM_LINUX
      ENABLE_OPENSSL_ENCRYPTION
    )

  elseif(PLATFORM_MACOS)
    target_compile_definitions(thirdparty_aws-c-cal PRIVATE
      PLATFORM_APPLE
      ENABLE_COMMONCRYPTO_ENCRYPTION
    )

  elseif(PLATFORM_WINDOWS)
    target_compile_definitions(thirdparty_aws-c-cal PRIVATE
      PLATFORM_WINDOWS
      ENABLE_BCRYPT_ENCRYPTION
    )
  endif()
endfunction()

function(generateAwsCCompression)
  set(library_root "${CMAKE_CURRENT_SOURCE_DIR}/src/aws-c-compression")

  add_library(thirdparty_aws-c-compression EXCLUDE_FROM_ALL
    "${library_root}/source/compression.c"
    "${library_root}/source/huffman.c"
    "${library_root}/source/huffman_testing.c"
  )

  target_include_directories(thirdparty_aws-c-compression PRIVATE
    "${library_root}/include"
  )

  target_include_directories(thirdparty_aws-c-compression SYSTEM INTERFACE
    "${library_root}/include"
  )

  target_link_libraries(thirdparty_aws-c-compression
    PRIVATE
      thirdparty_c_settings

    PUBLIC
      thirdparty_aws-c-common
  )

  if(PLATFORM_POSIX)
    target_compile_definitions(thirdparty_aws-c-compression PRIVATE
      HAVE_SYSCONF
    )
  endif()

  if(PLATFORM_LINUX)
    target_compile_definitions(thirdparty_aws-c-compression PRIVATE
      PLATFORM_LINUX
      ENABLE_OPENSSL_ENCRYPTION
    )

  elseif(PLATFORM_MACOS)
    target_compile_definitions(thirdparty_aws-c-compression PRIVATE
      PLATFORM_APPLE
      ENABLE_COMMONCRYPTO_ENCRYPTION
    )

  elseif(PLATFORM_WINDOWS)
    target_compile_definitions(thirdparty_aws-c-compression PRIVATE
      PLATFORM_WINDOWS
      ENABLE_BCRYPT_ENCRYPTION
    )
  endif()
endfunction()

function(generateAwsCCommon)
  set(library_root "${CMAKE_CURRENT_SOURCE_DIR}/src/aws-c-common")

  if(PLATFORM_LINUX)
    set(config_path "${CMAKE_CURRENT_SOURCE_DIR}/config/aws-c-common/linux/${TARGET_PROCESSOR}/include")

  elseif(PLATFORM_MACOS)
    set(config_path "${CMAKE_CURRENT_SOURCE_DIR}/config/aws-c-common/macos/${TARGET_PROCESSOR}/include")

  elseif(PLATFORM_WINDOWS)
    set(config_path "${CMAKE_CURRENT_SOURCE_DIR}/config/aws-c-common/windows/${TARGET_PROCESSOR}/include")
  endif()

  add_library(thirdparty_aws-c-common EXCLUDE_FROM_ALL
    "${library_root}/source/allocator.c"
    "${library_root}/source/allocator_sba.c"
    "${library_root}/source/array_list.c"
    "${library_root}/source/assert.c"
    "${library_root}/source/byte_buf.c"
    "${library_root}/source/cache.c"
    "${library_root}/source/codegen.c"
    "${library_root}/source/command_line_parser.c"
    "${library_root}/source/common.c"
    "${library_root}/source/condition_variable.c"
    "${library_root}/source/date_time.c"
    "${library_root}/source/device_random.c"
    "${library_root}/source/encoding.c"
    "${library_root}/source/error.c"
    "${library_root}/source/fifo_cache.c"
    "${library_root}/source/hash_table.c"
    "${library_root}/source/lifo_cache.c"
    "${library_root}/source/linked_hash_table.c"
    "${library_root}/source/log_channel.c"
    "${library_root}/source/log_formatter.c"
    "${library_root}/source/logging.c"
    "${library_root}/source/log_writer.c"
    "${library_root}/source/lru_cache.c"
    "${library_root}/source/math.c"
    "${library_root}/source/memtrace.c"
    "${library_root}/source/priority_queue.c"
    "${library_root}/source/process_common.c"
    "${library_root}/source/promise.c"
    "${library_root}/source/ref_count.c"
    "${library_root}/source/resource_name.c"
    "${library_root}/source/ring_buffer.c"
    "${library_root}/source/statistics.c"
    "${library_root}/source/string.c"
    "${library_root}/source/task_scheduler.c"
    "${library_root}/source/thread_scheduler.c"
    "${library_root}/source/thread_shared.c"
    "${library_root}/source/uuid.c"
    "${library_root}/source/xml_parser.c"
  )

  if(PLATFORM_POSIX)
    target_sources(thirdparty_aws-c-common PRIVATE
      "${library_root}/source/posix/clock.c"
      "${library_root}/source/posix/condition_variable.c"
      "${library_root}/source/posix/device_random.c"
      "${library_root}/source/posix/environment.c"
      "${library_root}/source/posix/file.c"
      "${library_root}/source/posix/mutex.c"
      "${library_root}/source/posix/process.c"
      "${library_root}/source/posix/rw_lock.c"
      "${library_root}/source/posix/system_info.c"
      "${library_root}/source/posix/thread.c"
      "${library_root}/source/posix/time.c"
    )

    if(TARGET_PROCESSOR STREQUAL "aarch64")
      target_sources(thirdparty_aws-c-common PRIVATE
        "${library_root}/source/arch/arm/asm/cpuid.c"
      )
    endif()

  elseif(PLATFORM_WINDOWS)
    target_sources(thirdparty_aws-c-common PRIVATE
      "${library_root}/source/windows/clock.c"
      "${library_root}/source/windows/condition_variable.c"
      "${library_root}/source/windows/device_random.c"
      "${library_root}/source/windows/environment.c"
      "${library_root}/source/windows/file.c"
      "${library_root}/source/windows/mutex.c"
      "${library_root}/source/windows/process.c"
      "${library_root}/source/windows/rw_lock.c"
      "${library_root}/source/windows/system_info.c"
      "${library_root}/source/windows/thread.c"
      "${library_root}/source/windows/time.c"
    )
  endif()

  target_include_directories(thirdparty_aws-c-common PRIVATE
    "${config_path}"
    "${library_root}/include"
  )

  target_include_directories(thirdparty_aws-c-common SYSTEM INTERFACE
    "${config_path}"
    "${library_root}/include"
  )

  target_link_libraries(thirdparty_aws-c-common PRIVATE
    thirdparty_c_settings
  )

  if(PLATFORM_POSIX)
    find_package(Threads REQUIRED)
    target_link_libraries(thirdparty_aws-c-common PUBLIC
      ${CMAKE_DL_LIBS}
      Threads::Threads
    )
  endif()

  if(PLATFORM_LINUX)
    target_link_libraries(thirdparty_aws-c-common PUBLIC
      m
      rt
    )

  elseif(PLATFORM_MACOS)
    target_link_libraries(thirdparty_aws-c-common PUBLIC
      "-framework CoreFoundation"
    )

  elseif(PLATFORM_WINDOWS)
    target_link_libraries(thirdparty_aws-c-common PUBLIC
      BCrypt
      Kernel32
      Ws2_32
    )
  endif()

  if(TARGET_PROCESSOR STREQUAL "x86_64")
    set(avx_impl_file "${library_root}/source/arch/intel/encoding_avx2.c")

    target_sources(thirdparty_aws-c-common PRIVATE
      "${avx_impl_file}"
      "${library_root}/source/arch/intel/cpuid.c"
    )

    if(PLATFORM_POSIX)
      target_sources(thirdparty_aws-c-common PRIVATE
        "${library_root}/source/arch/intel/asm/cpuid.c"
      )

      set_source_files_properties(
        "${avx_impl_file}"
  
        COMPILE_FLAGS
          "-mavx -mavx2"
      )

    elseif(PLATFORM_WINDOWS)
      target_sources(thirdparty_aws-c-common PRIVATE
        "${library_root}/source/arch/intel/msvc/cpuid.c"
      )

      set_source_files_properties(
        "${avx_impl_file}"
  
        COMPILE_FLAGS
          "/arch:AVX2"
      )
    endif()

    target_compile_definitions(thirdparty_aws-c-common PRIVATE
      HAVE_AVX2_INTRINSICS
      USE_SIMD_ENCODING
    )

  elseif(TARGET_PROCESSOR STREQUAL "aarch64")
    target_sources(thirdparty_aws-c-common PRIVATE
      "${library_root}/source/arch/generic/cpuid.c"
    )
  endif()

  if(PLATFORM_POSIX)
    target_compile_definitions(thirdparty_aws-c-common PRIVATE
      HAVE_SYSCONF
    )
  endif()

  if(PLATFORM_LINUX)
    target_compile_definitions(thirdparty_aws-c-common PRIVATE
      _POSIX_C_SOURCE=200809L
      _XOPEN_SOURCE=500
      AWS_AFFINITY_METHOD=AWS_AFFINITY_METHOD_PTHREAD_ATTR
      PLATFORM_LINUX
      ENABLE_OPENSSL_ENCRYPTION
    )

  elseif(PLATFORM_MACOS)
    target_compile_definitions(thirdparty_aws-c-common PRIVATE
      AWS_AFFINITY_METHOD=AWS_AFFINITY_METHOD_NONE
      PLATFORM_APPLE
      ENABLE_COMMONCRYPTO_ENCRYPTION
    )

  elseif(PLATFORM_WINDOWS)
    target_compile_definitions(thirdparty_aws-c-common PRIVATE
      AWS_AFFINITY_METHOD=AWS_AFFINITY_METHOD_NONE
      WINDOWS_KERNEL_LIB=Kernel32
      PLATFORM_WINDOWS
      ENABLE_BCRYPT_ENCRYPTION
    )
  endif()
endfunction()

awsSdkCppMain()
