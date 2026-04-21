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

#include <memory>
#include <optional>
#include <unordered_map>
#include <vector>

#include "yacl/crypto/experimental/threshold_ecdsa/common/ids.h"
#include "yacl/crypto/experimental/threshold_ecdsa/core/mta/messages.h"
#include "yacl/crypto/experimental/threshold_ecdsa/core/mta/session.h"
#include "yacl/crypto/experimental/threshold_ecdsa/core/proof/types.h"
#include "yacl/crypto/experimental/threshold_ecdsa/crypto/ec_point.h"
#include "yacl/crypto/experimental/threshold_ecdsa/crypto/paillier.h"
#include "yacl/crypto/experimental/threshold_ecdsa/crypto/scalar.h"
#include "yacl/crypto/experimental/threshold_ecdsa/crypto/strict_proofs.h"
#include "yacl/crypto/experimental/threshold_ecdsa/sm2/zid/zid.h"

namespace tecdsa::sm2::keygen {

template <typename T>
using PeerMap = std::unordered_map<PartyIndex, T>;

struct KeygenConfig {
  Bytes session_id;
  PartyIndex self_id = 0;
  std::vector<PartyIndex> participants;
  uint32_t threshold = 1;
  uint32_t paillier_modulus_bits = 2048;
  uint32_t aux_rsa_modulus_bits = 2048;
  Bytes signer_id;
};

struct KeygenRound1Msg {
  Bytes commitment;
  PaillierPublicKey paillier_public;
  AuxRsaParams aux_rsa_params;
  AuxRsaParamProof aux_param_proof;
};

struct KeygenRound2Broadcast {
  ECPoint Z_i;
  Bytes randomness;
  std::vector<ECPoint> commitments;
};

struct KeygenRound2Out {
  KeygenRound2Broadcast broadcast;
  PeerMap<Scalar> shares_for_peers;
};

using KeygenRound3Request = tecdsa::core::mta::PairwiseProductRequest;
using KeygenRound3Response = tecdsa::core::mta::PairwiseProductResponse;

struct KeygenRound4Msg {
  Scalar sigma_i;
  ECPoint Gamma_i;
  tecdsa::core::proof::SchnorrProof gamma_proof;
  SquareFreeProof square_free_proof;
};

struct LocalKeyShare {
  Scalar z_i;
  std::shared_ptr<PaillierProvider> paillier;
  zid::IdentityBinding binding;
};

struct PublicKeygenData {
  ECPoint public_key;
  Scalar sigma_inverse;
  PeerMap<ECPoint> all_plus_one_public_shares;
  PeerMap<PaillierPublicKey> all_paillier_public;
  PeerMap<AuxRsaParams> all_aux_rsa_params;
  PeerMap<SquareFreeProof> all_square_free_proofs;
  PeerMap<AuxRsaParamProof> all_aux_param_proofs;
};

struct KeygenOutput {
  LocalKeyShare local_key_share;
  PublicKeygenData public_keygen_data;
};

class KeygenParty {
 public:
  explicit KeygenParty(KeygenConfig cfg);

  const KeygenConfig& config() const;

  KeygenRound1Msg MakeRound1();
  KeygenRound2Out MakeRound2(const PeerMap<KeygenRound1Msg>& peer_round1);
  std::vector<KeygenRound3Request> MakeRound3Requests(
      const PeerMap<KeygenRound2Broadcast>& peer_round2,
      const PeerMap<Scalar>& shares_for_self);
  std::vector<KeygenRound3Response> MakeRound3Responses(
      const std::vector<KeygenRound3Request>& requests_for_self);
  KeygenRound4Msg MakeRound4(
      const std::vector<KeygenRound3Response>& responses_for_self);
  KeygenOutput Finalize(const PeerMap<KeygenRound4Msg>& peer_round4);

 private:
  void EnsureLocalPolynomialPrepared();
  void EnsureLocalPaillierPrepared();
  void EnsureLocalProofsPrepared();
  bool VerifyDealerShareForSelf(PartyIndex dealer,
                                const KeygenRound2Broadcast& round2,
                                const Scalar& share) const;

  KeygenConfig cfg_;
  std::vector<PartyIndex> peers_;

  std::vector<Scalar> local_poly_coefficients_;
  PeerMap<Scalar> local_shares_;
  std::shared_ptr<PaillierProvider> local_paillier_;
  PaillierPublicKey local_paillier_public_;
  AuxRsaParams local_aux_rsa_params_;
  SquareFreeProof local_square_free_proof_;
  AuxRsaParamProof local_aux_param_proof_;

  ECPoint local_Z_i_;
  Bytes local_commitment_;
  Bytes local_open_randomness_;
  std::vector<ECPoint> local_vss_commitments_;

  PeerMap<Bytes> all_phase1_commitments_;
  PeerMap<PaillierPublicKey> all_paillier_public_;
  PeerMap<AuxRsaParams> all_aux_rsa_params_;
  PeerMap<AuxRsaParamProof> all_aux_param_proofs_;

  Scalar local_z_i_;
  Scalar local_gamma_i_;
  ECPoint local_Gamma_i_;
  tecdsa::core::mta::PairwiseProductSession sigma_session_;
  std::vector<KeygenRound3Request> round3_requests_;
  std::optional<std::vector<KeygenRound3Response>> round3_responses_;
  Scalar sigma_initiator_sum_;
  Scalar sigma_responder_sum_;
  Scalar local_sigma_i_;

  std::optional<KeygenRound1Msg> round1_;
  std::optional<KeygenRound2Out> round2_;
  std::optional<KeygenRound4Msg> round4_;
  std::optional<KeygenOutput> output_;
};

}  // namespace tecdsa::sm2::keygen
