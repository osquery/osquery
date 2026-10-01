#include "aws/firehose/FirehoseClient.h"

#include <aws/core/auth/AWSAuthSigner.h>
#include <aws/core/http/Scheme.h>
#include <aws/firehose/FirehoseEndpoint.h>
#include <aws/firehose/FirehoseErrorMarshaller.h>

namespace Aws {
namespace Firehose {

FirehoseClient::FirehoseClient(
    const std::shared_ptr<Aws::Auth::AWSCredentialsProvider>&
        credentialsProvider,
    const Aws::Client::ClientConfiguration& config)
    : AWSJsonClient(config,
                    Aws::MakeShared<Aws::Client::AWSAuthV4Signer>(
                        "FirehoseClient",
                        credentialsProvider,
                        "firehose",
                        Aws::Region::ComputeSignerRegion(config.region)),
                    Aws::MakeShared<Aws::Client::FirehoseErrorMarshaller>(
                        "FirehoseClient")) {
  SetServiceClientName("Firehose");
  const Aws::String scheme = Aws::Http::SchemeMapper::ToString(config.scheme);
  if (config.endpointOverride.empty()) {
    m_uri = scheme + "://" +
            FirehoseEndpoint::ForRegion(config.region, config.useDualStack);
  } else if (config.endpointOverride.compare(0, 7, "http://") == 0 ||
             config.endpointOverride.compare(0, 8, "https://") == 0) {
    m_uri = config.endpointOverride;
  } else {
    m_uri = scheme + "://" + config.endpointOverride;
  }
}

Model::PutRecordBatchOutcome FirehoseClient::PutRecordBatch(
    const Model::PutRecordBatchRequest& request) const {
  Aws::Http::URI uri = m_uri;
  return Model::PutRecordBatchOutcome(MakeRequest(
      uri, request, Aws::Http::HttpMethod::HTTP_POST, Aws::Auth::SIGV4_SIGNER));
}

} // namespace Firehose
} // namespace Aws