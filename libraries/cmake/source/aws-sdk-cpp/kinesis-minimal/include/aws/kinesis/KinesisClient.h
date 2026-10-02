#pragma once

#include <aws/core/client/AWSClient.h>
#include <aws/core/client/ClientConfiguration.h>
#include <aws/kinesis/KinesisErrors.h>
#include <aws/kinesis/Kinesis_EXPORTS.h>
#include <aws/kinesis/model/PutRecordsRequest.h>
#include <aws/kinesis/model/PutRecordsResult.h>

namespace Aws {
namespace Kinesis {
namespace Model {
using PutRecordsOutcome = Aws::Utils::Outcome<PutRecordsResult, KinesisError>;
}

class AWS_KINESIS_API KinesisClient : public Aws::Client::AWSJsonClient {
 public:
  KinesisClient(const std::shared_ptr<Aws::Auth::AWSCredentialsProvider>&
                    credentialsProvider,
                const Aws::Client::ClientConfiguration& config);

  Model::PutRecordsOutcome PutRecords(
      const Model::PutRecordsRequest& request) const;

 private:
  Aws::String m_uri;
};
} // namespace Kinesis
} // namespace Aws