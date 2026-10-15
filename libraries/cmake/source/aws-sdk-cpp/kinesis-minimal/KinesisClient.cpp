#include "aws/kinesis/KinesisClient.h"

#include <aws/core/auth/AWSAuthSigner.h>
#include <aws/core/http/Scheme.h>
#include <aws/kinesis/KinesisEndpoint.h>
#include <aws/kinesis/KinesisErrorMarshaller.h>

namespace Aws {
namespace Kinesis {

KinesisClient::KinesisClient(
    const std::shared_ptr<Aws::Auth::AWSCredentialsProvider>&
        credentialsProvider,
    const Aws::Client::ClientConfiguration& config)
    : AWSJsonClient(config,
                    Aws::MakeShared<Aws::Client::AWSAuthV4Signer>(
                        "KinesisClient",
                        credentialsProvider,
                        "kinesis",
                        Aws::Region::ComputeSignerRegion(config.region)),
                    Aws::MakeShared<Aws::Client::KinesisErrorMarshaller>(
                        "KinesisClient")) {
  SetServiceClientName("Kinesis");
  const Aws::String scheme = Aws::Http::SchemeMapper::ToString(config.scheme);
  if (config.endpointOverride.empty()) {
    m_uri = scheme + "://" +
            KinesisEndpoint::ForRegion(config.region, config.useDualStack);
  } else if (config.endpointOverride.compare(0, 7, "http://") == 0 ||
             config.endpointOverride.compare(0, 8, "https://") == 0) {
    m_uri = config.endpointOverride;
  } else {
    m_uri = scheme + "://" + config.endpointOverride;
  }
}

Model::PutRecordsOutcome KinesisClient::PutRecords(
    const Model::PutRecordsRequest& request) const {
  Aws::Http::URI uri = m_uri;
  return Model::PutRecordsOutcome(MakeRequest(
      uri, request, Aws::Http::HttpMethod::HTTP_POST, Aws::Auth::SIGV4_SIGNER));
}

} // namespace Kinesis
} // namespace Aws