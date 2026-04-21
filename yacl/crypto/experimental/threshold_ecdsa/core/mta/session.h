// Copyright 2026 Ant Group Co., Ltd.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#pragma once

#include <cstddef>
#include <optional>
#include <string>
#include <memory>
#include <unordered_map>
#include <unordered_set>

#include "yacl/crypto/experimental/threshold_ecdsa/core/mta/messages.h"
#include "yacl/crypto/experimental/threshold_ecdsa/core/suite/suite.h"
#include "yacl/crypto/experimental/threshold_ecdsa/core/suite/group_context.h"
#include "yacl/crypto/experimental/threshold_ecdsa/crypto/ec_point.h"
#include "yacl/crypto/experimental/threshold_ecdsa/crypto/paillier.h"
#include "yacl/crypto/experimental/threshold_ecdsa/crypto/scalar.h"

namespace tecdsa::core::mta {

Bytes RandomMtaInstanceId();
std::string BytesToKey(const Bytes& bytes);
std::string MakeResponderRequestKey(PartyIndex initiator, MtaType type);
size_t ExpectedPairwiseProductMessageCount(size_t peer_count);

struct PairwiseProductInitiatorInstance {
  PartyIndex responder = 0;
  MtaType type = MtaType::kMta;
  Bytes instance_id;
  BigInt c1 = BigInt(0);
};

class PairwiseProductSession {
 public:
  struct Config {
    Bytes session_id;
    PartyIndex self_id = 0;
    std::optional<ThresholdSuite> suite;
    std::shared_ptr<const GroupContext> group;
  };

  struct CreateRequestArgs {
    PartyIndex responder_id = 0;
    MtaType type = MtaType::kMta;
    const PaillierProvider* initiator_paillier = nullptr;
    const AuxRsaParams* responder_aux = nullptr;
    Scalar initiator_secret;
  };

  struct ConsumeRequestArgs {
    BigInt initiator_modulus_n = BigInt(0);
    const AuxRsaParams* responder_aux = nullptr;
    const AuxRsaParams* initiator_aux = nullptr;
    Scalar responder_secret;
    std::optional<ECPoint> public_witness_point;
  };

  struct ConsumeRequestResult {
    PairwiseProductResponse response;
    Scalar responder_share;
  };

  struct ConsumeResponseArgs {
    const PaillierProvider* initiator_paillier = nullptr;
    const AuxRsaParams* initiator_aux = nullptr;
    std::optional<ECPoint> public_witness_point;
  };

  struct ConsumeResponseResult {
    Scalar initiator_share;
  };

  explicit PairwiseProductSession(Config cfg);

  const Config& config() const;

  Bytes AllocateInstanceId();
  void RegisterInitiatorInstance(PairwiseProductInitiatorInstance instance);
  size_t initiator_instance_count() const;
  const PairwiseProductInitiatorInstance& GetInitiatorInstance(
      const Bytes& instance_id) const;

  PairwiseProductRequest CreateRequest(const CreateRequestArgs& args);
  ConsumeRequestResult ConsumeRequest(const PairwiseProductRequest& request,
                                      const ConsumeRequestArgs& args);
  ConsumeResponseResult ConsumeResponse(
      const PairwiseProductResponse& response,
      const ConsumeResponseArgs& args);

  size_t pending_outbound_count() const;

 private:
  Bytes ReserveFreshInstanceId();

  Config cfg_;
  std::unordered_map<std::string, PairwiseProductInitiatorInstance>
      pending_initiator_instances_;
  std::unordered_set<std::string> generated_instance_keys_;
  std::unordered_set<std::string> consumed_request_keys_;
};

const PairwiseProductInitiatorInstance& GetInitiatorInstance(
    const PairwiseProductSession& session, const Bytes& instance_id);

}  // namespace tecdsa::core::mta
