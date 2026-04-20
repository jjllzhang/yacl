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

#include "yacl/crypto/experimental/threshold_ecdsa/core/mta/session.h"

#include <exception>
#include <utility>

#include "yacl/crypto/experimental/threshold_ecdsa/common/errors.h"
#include "yacl/crypto/experimental/threshold_ecdsa/crypto/bigint_utils.h"
#include "yacl/crypto/experimental/threshold_ecdsa/crypto/random.h"

namespace tecdsa::core::mta {
namespace {

void ValidateMtAwcSecretPointOrThrow(
    const Scalar& responder_secret,
    const std::optional<ECPoint>& public_witness_point) {
  if (!public_witness_point.has_value()) {
    TECDSA_THROW_ARGUMENT("MtAwc requires a public witness point");
  }
  try {
    if (ECPoint::GeneratorMultiply(responder_secret) != *public_witness_point) {
      TECDSA_THROW_ARGUMENT(
          "MtAwc public witness point does not match responder secret");
    }
  } catch (const std::exception& ex) {
    TECDSA_THROW_ARGUMENT(std::string("failed to validate MtAwc point: ") +
                          ex.what());
  }
}

void ValidatePublicWitnessPointPresenceOrThrow(
    MtaType type, const std::optional<ECPoint>& public_witness_point,
    const char* context_name) {
  if (RequiresPublicPoint(type)) {
    if (!public_witness_point.has_value()) {
      TECDSA_THROW_ARGUMENT(std::string(context_name) +
                            " requires a public witness point");
    }
    return;
  }
  if (public_witness_point.has_value()) {
    TECDSA_THROW_ARGUMENT(std::string(context_name) +
                          " does not use a public witness point");
  }
}

}  // namespace

Bytes RandomMtaInstanceId() { return Csprng::RandomBytes(kMtaInstanceIdLen); }

std::string BytesToKey(const Bytes& bytes) {
  return std::string(reinterpret_cast<const char*>(bytes.data()), bytes.size());
}

std::string MakeResponderRequestKey(PartyIndex initiator, MtaType type) {
  std::string out;
  out.reserve(8);
  out.push_back(static_cast<char>((initiator >> 24) & 0xFF));
  out.push_back(static_cast<char>((initiator >> 16) & 0xFF));
  out.push_back(static_cast<char>((initiator >> 8) & 0xFF));
  out.push_back(static_cast<char>(initiator & 0xFF));
  out.push_back(static_cast<char>(type));
  return out;
}

size_t ExpectedPairwiseProductMessageCount(size_t peer_count) {
  return peer_count * 2;
}

PairwiseProductSession::PairwiseProductSession(Config cfg)
    : cfg_(std::move(cfg)) {}

const PairwiseProductSession::Config& PairwiseProductSession::config() const {
  return cfg_;
}

Bytes PairwiseProductSession::AllocateInstanceId() { return ReserveFreshInstanceId(); }

void PairwiseProductSession::RegisterInitiatorInstance(
    PairwiseProductInitiatorInstance instance) {
  if (instance.instance_id.size() != kMtaInstanceIdLen) {
    TECDSA_THROW_ARGUMENT("initiator instance id has invalid length");
  }

  const std::string instance_key = BytesToKey(instance.instance_id);
  if (consumed_request_keys_.contains(instance_key)) {
    TECDSA_THROW_ARGUMENT("initiator instance id conflicts with a consumed request");
  }
  generated_instance_keys_.insert(instance_key);
  if (!pending_initiator_instances_
           .emplace(instance_key, std::move(instance))
           .second) {
    TECDSA_THROW_ARGUMENT("duplicate initiator instance id");
  }
}

size_t PairwiseProductSession::initiator_instance_count() const {
  return pending_initiator_instances_.size();
}

const PairwiseProductInitiatorInstance&
PairwiseProductSession::GetInitiatorInstance(const Bytes& instance_id) const {
  const std::string instance_key = BytesToKey(instance_id);
  const auto it = pending_initiator_instances_.find(instance_key);
  if (it == pending_initiator_instances_.end()) {
    TECDSA_THROW_ARGUMENT("unknown initiator instance id");
  }
  return it->second;
}

PairwiseProductRequest PairwiseProductSession::CreateRequest(
    const CreateRequestArgs& args) {
  if (args.initiator_paillier == nullptr) {
    TECDSA_THROW_ARGUMENT("initiator Paillier provider must be present");
  }
  if (args.responder_aux == nullptr) {
    TECDSA_THROW_ARGUMENT("responder auxiliary parameters must be present");
  }
  if (args.responder_id == cfg_.self_id) {
    TECDSA_THROW_ARGUMENT("responder id must be a peer");
  }

  const Bytes instance_id = ReserveFreshInstanceId();
  const BigInt n = args.initiator_paillier->modulus_n_bigint();
  const PaillierCiphertextWithRandomBigInt encrypted =
      args.initiator_paillier->EncryptWithRandomBigInt(
          args.initiator_secret.mp_value());

  const A1RangeProof a1_proof =
      ProveA1Range(BuildProofContext(cfg_.session_id, cfg_.self_id,
                                     args.responder_id, instance_id),
                   n, *args.responder_aux, encrypted.ciphertext,
                   args.initiator_secret.mp_value(), encrypted.randomness);

  RegisterInitiatorInstance(PairwiseProductInitiatorInstance{
      .responder = args.responder_id,
      .type = args.type,
      .instance_id = instance_id,
      .c1 = encrypted.ciphertext,
  });
  return PairwiseProductRequest{
      .from = cfg_.self_id,
      .to = args.responder_id,
      .type = args.type,
      .instance_id = instance_id,
      .c1 = encrypted.ciphertext,
      .a1_proof = a1_proof,
  };
}

PairwiseProductSession::ConsumeRequestResult
PairwiseProductSession::ConsumeRequest(const PairwiseProductRequest& request,
                                       const ConsumeRequestArgs& args) {
  if (args.responder_aux == nullptr) {
    TECDSA_THROW_ARGUMENT("responder auxiliary parameters must be present");
  }
  if (args.initiator_aux == nullptr) {
    TECDSA_THROW_ARGUMENT("initiator auxiliary parameters must be present");
  }
  if (request.to != cfg_.self_id) {
    TECDSA_THROW_ARGUMENT("pairwise product request must target self");
  }
  if (request.from == cfg_.self_id) {
    TECDSA_THROW_ARGUMENT("pairwise product request sender must be a peer");
  }
  if (request.instance_id.size() != kMtaInstanceIdLen) {
    TECDSA_THROW_ARGUMENT("pairwise product request instance id has invalid length");
  }

  const std::string instance_key = BytesToKey(request.instance_id);
  if (generated_instance_keys_.contains(instance_key) ||
      consumed_request_keys_.contains(instance_key)) {
    TECDSA_THROW_ARGUMENT("duplicate pairwise product request instance id");
  }

  const BigInt n = args.initiator_modulus_n;
  const BigInt n2 = n * n;
  if (request.c1 < 0 || request.c1 >= n2) {
    TECDSA_THROW_ARGUMENT("pairwise product request ciphertext c1 is out of range");
  }

  if (!VerifyA1Range(BuildProofContext(cfg_.session_id, request.from,
                                       cfg_.self_id, request.instance_id),
                     n, *args.responder_aux, request.c1, request.a1_proof)) {
    TECDSA_THROW_ARGUMENT("pairwise product A1 proof verification failed");
  }

  ValidatePublicWitnessPointPresenceOrThrow(request.type,
                                            args.public_witness_point,
                                            "pairwise product responder input");
  if (request.type == MtaType::kMtAwc) {
    ValidateMtAwcSecretPointOrThrow(args.responder_secret,
                                    args.public_witness_point);
  }

  const BigInt y = RandomBelow(QPow5());
  const BigInt r_b = SampleZnStar(n);
  const BigInt gamma = n + BigInt(1);
  const BigInt c1_pow_x =
      PowMod(request.c1, args.responder_secret.mp_value(), n2);
  const BigInt gamma_pow_y = PowMod(gamma, y, n2);
  const BigInt r_pow_n = PowMod(r_b, n, n2);
  const BigInt c2 =
      MulMod(MulMod(c1_pow_x, gamma_pow_y, n2), r_pow_n, n2);

  PairwiseProductResponse response{
      .from = cfg_.self_id,
      .to = request.from,
      .type = request.type,
      .instance_id = request.instance_id,
      .c2 = c2,
      .a2_proof = std::nullopt,
      .a3_proof = std::nullopt,
  };

  if (request.type == MtaType::kMta) {
    response.a3_proof = ProveA3MtA(
        BuildProofContext(cfg_.session_id, request.from, cfg_.self_id,
                          request.instance_id),
        n, *args.initiator_aux, request.c1, c2,
        args.responder_secret.mp_value(), y, r_b);
  } else {
    response.a2_proof = ProveA2MtAwc(
        BuildProofContext(cfg_.session_id, request.from, cfg_.self_id,
                          request.instance_id),
        n, *args.initiator_aux, request.c1, c2, *args.public_witness_point,
        args.responder_secret.mp_value(), y, r_b);
  }

  consumed_request_keys_.insert(instance_key);
  return ConsumeRequestResult{
      .response = std::move(response),
      .responder_share = Scalar(-y),
  };
}

PairwiseProductSession::ConsumeResponseResult
PairwiseProductSession::ConsumeResponse(const PairwiseProductResponse& response,
                                        const ConsumeResponseArgs& args) {
  if (args.initiator_paillier == nullptr) {
    TECDSA_THROW_ARGUMENT("initiator Paillier provider must be present");
  }
  if (args.initiator_aux == nullptr) {
    TECDSA_THROW_ARGUMENT("initiator auxiliary parameters must be present");
  }
  if (response.to != cfg_.self_id) {
    TECDSA_THROW_ARGUMENT("pairwise product response must target self");
  }
  if (response.from == cfg_.self_id) {
    TECDSA_THROW_ARGUMENT("pairwise product response sender must be a peer");
  }
  if (response.instance_id.size() != kMtaInstanceIdLen) {
    TECDSA_THROW_ARGUMENT("pairwise product response instance id has invalid length");
  }

  const std::string instance_key = BytesToKey(response.instance_id);
  const auto instance_it = pending_initiator_instances_.find(instance_key);
  if (instance_it == pending_initiator_instances_.end()) {
    TECDSA_THROW_ARGUMENT("unknown pairwise product response instance id");
  }
  const PairwiseProductInitiatorInstance& instance = instance_it->second;
  if (instance.responder != response.from) {
    TECDSA_THROW_ARGUMENT("pairwise product response sender mismatch");
  }
  if (instance.type != response.type) {
    TECDSA_THROW_ARGUMENT("pairwise product response type mismatch");
  }

  const BigInt n = args.initiator_paillier->modulus_n_bigint();
  const BigInt n2 = n * n;
  if (response.c2 < 0 || response.c2 >= n2) {
    TECDSA_THROW_ARGUMENT("pairwise product response ciphertext c2 is out of range");
  }

  ValidatePublicWitnessPointPresenceOrThrow(response.type,
                                            args.public_witness_point,
                                            "pairwise product response input");

  if (response.type == MtaType::kMta) {
    if (!response.a3_proof.has_value() || response.a2_proof.has_value()) {
      TECDSA_THROW_ARGUMENT("MtA response must carry only an A3 proof");
    }
    if (!VerifyA3MtA(BuildProofContext(cfg_.session_id, cfg_.self_id,
                                       response.from, response.instance_id),
                     n, *args.initiator_aux, instance.c1, response.c2,
                     *response.a3_proof)) {
      TECDSA_THROW_ARGUMENT("pairwise product A3 proof verification failed");
    }
  } else {
    if (!response.a2_proof.has_value() || response.a3_proof.has_value()) {
      TECDSA_THROW_ARGUMENT("MtAwc response must carry only an A2 proof");
    }
    if (!VerifyA2MtAwc(BuildProofContext(cfg_.session_id, cfg_.self_id,
                                         response.from, response.instance_id),
                       n, *args.initiator_aux, instance.c1, response.c2,
                       *args.public_witness_point, *response.a2_proof)) {
      TECDSA_THROW_ARGUMENT("pairwise product A2 proof verification failed");
    }
  }

  const Scalar initiator_share(
      args.initiator_paillier->DecryptBigInt(response.c2));
  pending_initiator_instances_.erase(instance_it);
  return ConsumeResponseResult{.initiator_share = initiator_share};
}

size_t PairwiseProductSession::pending_outbound_count() const {
  return pending_initiator_instances_.size();
}

Bytes PairwiseProductSession::ReserveFreshInstanceId() {
  while (true) {
    Bytes instance_id = RandomMtaInstanceId();
    const std::string instance_key = BytesToKey(instance_id);
    if (generated_instance_keys_.contains(instance_key) ||
        consumed_request_keys_.contains(instance_key)) {
      continue;
    }
    generated_instance_keys_.insert(instance_key);
    return instance_id;
  }
}

const PairwiseProductInitiatorInstance& GetInitiatorInstance(
    const PairwiseProductSession& session, const Bytes& instance_id) {
  return session.GetInitiatorInstance(instance_id);
}

}  // namespace tecdsa::core::mta
