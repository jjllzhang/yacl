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
#include <unordered_map>
#include <vector>

#include "yacl/crypto/experimental/threshold_signatures/common/ids.h"
#include "yacl/crypto/experimental/threshold_signatures/core/paillier/aux_proofs.h"
#include "yacl/crypto/experimental/threshold_signatures/core/paillier/paper_aux_proofs.h"
#include "yacl/crypto/experimental/threshold_signatures/common/types.h"
#include "yacl/crypto/experimental/threshold_signatures/ecdsa/proofs/types.h"

namespace tecdsa::ecdsa::keygen {

template <typename T>
using PeerMap = std::unordered_map<PartyIndex, T>;

using AuxCorrectFormProof = core::paillier::AuxCorrectFormProof;
using AuxRsaParams = core::paillier::AuxRsaParams;
using SquareFreeProof = core::paillier::SquareFreeProof;

struct KeygenRound1Msg {
  Bytes commitment;
  PaillierPublicKey paillier_public;
  AuxRsaParams aux_rsa_params;
  AuxCorrectFormProof aux_param_proof;
};

struct KeygenRound2Broadcast {
  ECPoint y_i;
  Bytes randomness;
  std::vector<ECPoint> commitments;
};

struct KeygenRound2Out {
  KeygenRound2Broadcast broadcast;
  PeerMap<Scalar> shares_for_peers;
};

struct KeygenRound3Msg {
  ECPoint X_i;
  tecdsa::ecdsa::proofs::SchnorrProof proof;
  SquareFreeProof square_free_proof;
};

struct LocalKeyShare {
  Scalar x_i;
  ECPoint X_i;
  std::shared_ptr<PaillierProvider> paillier;
};

struct PublicKeygenData {
  ECPoint y;
  uint32_t threshold = 0;
  PeerMap<ECPoint> all_X_i;
  PeerMap<PaillierPublicKey> all_paillier_public;
  PeerMap<AuxRsaParams> all_aux_rsa_params;
  PeerMap<SquareFreeProof> all_square_free_proofs;
  PeerMap<AuxCorrectFormProof> all_aux_param_proofs;
};

struct KeygenOutput {
  LocalKeyShare local_key_share;
  PublicKeygenData public_keygen_data;
};

}  // namespace tecdsa::ecdsa::keygen
