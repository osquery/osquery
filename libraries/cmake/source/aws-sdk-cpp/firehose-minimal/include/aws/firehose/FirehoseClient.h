#pragma once

#include <aws/core/client/AWSClient.h>
#include <aws/core/client/ClientConfiguration.h>
#include <aws/firehose/FirehoseErrors.h>
#include <aws/firehose/Firehose_EXPORTS.h>
#include <aws/firehose/model/PutRecordBatchRequest.h>
#include <aws/firehose/model/PutRecordBatchResult.h>

namespace Aws {
namespace Firehose {
namespace Model {
using PutRecordBatchOutcome =
    Aws::Utils::Outcome<PutRecordBatchResult, FirehoseError>;
}

class AWS_FIREHOSE_API FirehoseClient : public Aws::Client::AWSJsonClient {
 public:
  FirehoseClient(const std::shared_ptr<Aws::Auth::AWSCredentialsProvider>&
                     credentialsProvider,
                 const Aws::Client::ClientConfiguration& config);

  Model::PutRecordBatchOutcome PutRecordBatch(
      const Model::PutRecordBatchRequest& request) const;

 private:
  Aws::String m_uri;
};
} // namespace Firehose
} // namespace Aws