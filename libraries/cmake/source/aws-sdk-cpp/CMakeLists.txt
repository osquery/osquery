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
  generateAwsCppSdkSts()

  add_library(thirdparty_aws-sdk-cpp INTERFACE)
  target_link_libraries(thirdparty_aws-sdk-cpp INTERFACE
    thirdparty_aws-cpp-sdk-firehose
    thirdparty_aws-cpp-sdk-kinesis
    thirdparty_aws-cpp-sdk-sts
  )
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

  target_precompile_headers(thirdparty_aws-cpp-sdk-sts REUSE_FROM
    thirdparty_aws-cpp-sdk-core
  )

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

  target_precompile_headers(thirdparty_aws-cpp-sdk-kinesis REUSE_FROM
    thirdparty_aws-cpp-sdk-core
  )

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

  target_precompile_headers(thirdparty_aws-cpp-sdk-firehose REUSE_FROM
    thirdparty_aws-cpp-sdk-core
  )

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

  target_precompile_headers(thirdparty_aws-cpp-sdk-core PRIVATE
    "${CMAKE_SOURCE_DIR}/cmake/osquery_aws_pch.h"
  )
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
