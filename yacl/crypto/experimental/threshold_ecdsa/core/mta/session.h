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
#include <functional>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "yacl/crypto/experimental/threshold_ecdsa/common/errors.h"
#include "yacl/crypto/experimental/threshold_ecdsa/core/mta/messages.h"
#include "yacl/crypto/experimental/threshold_ecdsa/core/paillier/paillier.h"
#include "yacl/crypto/experimental/threshold_ecdsa/core/suite/group_context.h"
#include "yacl/crypto/experimental/threshold_ecdsa/core/suite/suite.h"

namespace tecdsa::core::mta {

using PaillierProvider = core::paillier::PaillierProvider;
using PaillierCiphertextWithRandomBigInt =
    core::paillier::PaillierCiphertextWithRandomBigInt;

Bytes RandomMtaInstanceId();
std::string BytesToKey(const Bytes& bytes);
std::string MakeResponderRequestKey(PartyIndex initiator, MtaType type);
size_t ExpectedPairwiseProductMessageCount(size_t peer_count);

inline bool IsPeer(std::span<const PartyIndex> peers, PartyIndex party) {
  for (PartyIndex peer : peers) {
    if (peer == party) {
      return true;
    }
  }
  return false;
}

template <typename Request, typename ToCoreRequest>
void RequireExactlyOneRequestPerPeerAndType(
    const std::vector<Request>& requests, std::span<const PartyIndex> peers,
    PartyIndex self_id, std::span<const MtaType> expected_types,
    ToCoreRequest to_core_request, const std::string& message_name) {
  if (requests.size() != peers.size() * expected_types.size()) {
    TECDSA_THROW_ARGUMENT(message_name +
                          " must contain exactly one request per peer/type");
  }

  std::unordered_set<std::string> expected_type_keys;
  expected_type_keys.reserve(expected_types.size());
  for (MtaType type : expected_types) {
    expected_type_keys.insert(std::to_string(static_cast<int>(type)));
  }

  std::unordered_set<std::string> seen_request_keys;
  std::unordered_set<std::string> seen_instance_keys;
  seen_request_keys.reserve(requests.size());
  seen_instance_keys.reserve(requests.size());
  for (const auto& request : requests) {
    const PairwiseProductRequest core_request = to_core_request(request);
    if (!IsPeer(peers, core_request.from)) {
      TECDSA_THROW_ARGUMENT(message_name + " sender is not a peer");
    }
    if (core_request.to != self_id) {
      TECDSA_THROW_ARGUMENT(message_name + " must target self");
    }
    if (!expected_type_keys.contains(
            std::to_string(static_cast<int>(core_request.type)))) {
      TECDSA_THROW_ARGUMENT(message_name + " has unexpected type");
    }
    if (core_request.instance_id.size() != kMtaInstanceIdLen) {
      TECDSA_THROW_ARGUMENT(message_name + " instance id has invalid length");
    }

    const std::string request_key =
        MakeResponderRequestKey(core_request.from, core_request.type);
    if (!seen_request_keys.insert(request_key).second) {
      TECDSA_THROW_ARGUMENT("duplicate " + message_name + " for sender/type");
    }
    const std::string instance_key = BytesToKey(core_request.instance_id);
    if (!seen_instance_keys.insert(instance_key).second) {
      TECDSA_THROW_ARGUMENT("duplicate " + message_name + " instance id");
    }
  }
}

template <typename Request, typename ToCoreRequest>
void RequireExactlyOneRequestPerPeer(
    const std::vector<Request>& requests, std::span<const PartyIndex> peers,
    PartyIndex self_id, MtaType expected_type, ToCoreRequest to_core_request,
    const std::string& message_name) {
  const MtaType expected_types[] = {expected_type};
  RequireExactlyOneRequestPerPeerAndType(
      requests, peers, self_id, std::span<const MtaType>(expected_types),
      to_core_request, message_name);
}

// ProofBackend binds scheme-specific exact proof implementations onto the
// generic PairwiseProductSession transport interface.
struct ProofBackend {
  std::function<A1RangeProof(const MtaProofContext&, const BigInt&,
                             const AuxRsaParams&, const BigInt&,
                             const BigInt&, const BigInt&)>
      prove_a1_range;
  std::function<bool(const MtaProofContext&, const BigInt&,
                     const AuxRsaParams&, const BigInt&, const A1RangeProof&)>
      verify_a1_range;
  std::function<A2MtAwcProof(const MtaProofContext&, const BigInt&,
                             const AuxRsaParams&, const BigInt&, const BigInt&,
                             const ECPoint&, const BigInt&, const BigInt&,
                             const BigInt&)>
      prove_a2_mtawc;
  std::function<bool(const MtaProofContext&, const BigInt&,
                     const AuxRsaParams&, const BigInt&, const BigInt&,
                     const ECPoint&, const A2MtAwcProof&)>
      verify_a2_mtawc;
  std::function<A3MtAProof(const MtaProofContext&, const BigInt&,
                           const AuxRsaParams&, const BigInt&, const BigInt&,
                           const BigInt&, const BigInt&, const BigInt&)>
      prove_a3_mta;
  std::function<bool(const MtaProofContext&, const BigInt&,
                     const AuxRsaParams&, const BigInt&, const BigInt&,
                     const A3MtAProof&)>
      verify_a3_mta;
};

std::shared_ptr<const ProofBackend> BuildDefaultProofBackend();

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
    std::shared_ptr<const ProofBackend> proof_backend;
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

template <typename Response, typename ToCoreResponse>
void RequireExactlyOneResponsePerInitiatorInstance(
    const std::vector<Response>& responses, std::span<const PartyIndex> peers,
    PartyIndex self_id, const PairwiseProductSession& session,
    ToCoreResponse to_core_response, const std::string& message_name) {
  if (responses.size() != session.initiator_instance_count()) {
    TECDSA_THROW_ARGUMENT(message_name +
                          " must contain exactly one response per request");
  }

  std::unordered_set<std::string> seen_request_keys;
  std::unordered_set<std::string> seen_instance_keys;
  seen_request_keys.reserve(responses.size());
  seen_instance_keys.reserve(responses.size());
  for (const auto& response : responses) {
    const PairwiseProductResponse core_response = to_core_response(response);
    if (!IsPeer(peers, core_response.from)) {
      TECDSA_THROW_ARGUMENT(message_name + " sender is not a peer");
    }
    if (core_response.to != self_id) {
      TECDSA_THROW_ARGUMENT(message_name + " must target self");
    }
    if (core_response.instance_id.size() != kMtaInstanceIdLen) {
      TECDSA_THROW_ARGUMENT(message_name + " instance id has invalid length");
    }

    const std::string instance_key = BytesToKey(core_response.instance_id);
    if (!seen_instance_keys.insert(instance_key).second) {
      TECDSA_THROW_ARGUMENT("duplicate " + message_name + " instance id");
    }

    const auto& instance =
        session.GetInitiatorInstance(core_response.instance_id);
    if (instance.responder != core_response.from) {
      TECDSA_THROW_ARGUMENT(message_name + " sender mismatch");
    }
    if (instance.type != core_response.type) {
      TECDSA_THROW_ARGUMENT(message_name + " type mismatch");
    }
    const std::string request_key =
        MakeResponderRequestKey(core_response.from, core_response.type);
    if (!seen_request_keys.insert(request_key).second) {
      TECDSA_THROW_ARGUMENT("duplicate " + message_name + " for sender/type");
    }
  }
}

}  // namespace tecdsa::core::mta
