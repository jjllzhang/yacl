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

#include "yacl/crypto/experimental/threshold_ecdsa/common/bytes.h"
#include "yacl/crypto/experimental/threshold_ecdsa/common/ids.h"
#include "yacl/crypto/experimental/threshold_ecdsa/core/proof/types.h"
#include "yacl/crypto/experimental/threshold_ecdsa/crypto/ec_point.h"
#include "yacl/crypto/experimental/threshold_ecdsa/crypto/paillier.h"
#include "yacl/crypto/experimental/threshold_ecdsa/crypto/scalar.h"
#include "yacl/crypto/experimental/threshold_ecdsa/crypto/strict_proofs.h"

namespace tecdsa::ecdsa::keygen {

template <typename T>
using PeerMap = std::unordered_map<PartyIndex, T>;

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
  core::proof::SchnorrProof proof;
  SquareFreeProof square_free_proof;
};

struct LocalKeyShare {
  Scalar x_i;
  ECPoint X_i;
  std::shared_ptr<PaillierProvider> paillier;
};

struct PublicKeygenData {
  ECPoint y;
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
