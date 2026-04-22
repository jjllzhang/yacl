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

#include <cstdint>
#include <optional>
#include <unordered_map>

#include "yacl/crypto/experimental/threshold_ecdsa/common/bytes.h"
#include "yacl/crypto/experimental/threshold_ecdsa/common/ids.h"
#include "yacl/crypto/experimental/threshold_ecdsa/core/proof/types.h"
#include "yacl/crypto/experimental/threshold_ecdsa/crypto/ec_point.h"
#include "yacl/crypto/experimental/threshold_ecdsa/crypto/paillier.h"
#include "yacl/crypto/experimental/threshold_ecdsa/crypto/scalar.h"
#include "yacl/crypto/experimental/threshold_ecdsa/ecdsa/proofs/gg19_affine.h"
#include "yacl/crypto/experimental/threshold_ecdsa/ecdsa/proofs/gg19_range.h"
#include "yacl/crypto/experimental/threshold_ecdsa/ecdsa/sign/relation_proofs.h"

namespace tecdsa::ecdsa::sign {

template <typename T>
using PeerMap = std::unordered_map<PartyIndex, T>;

enum class MtaType : uint8_t {
  kTimesGamma = 1,
  kTimesW = 2,
};

struct SignRound1Msg {
  Bytes commitment;
};

struct SignRound2Request {
  PartyIndex from = 0;
  PartyIndex to = 0;
  MtaType type = MtaType::kTimesGamma;
  Bytes instance_id;
  BigInt c1 = BigInt(0);
  proofs::A1RangeProof a1_proof;
};

struct SignRound2Response {
  PartyIndex from = 0;
  PartyIndex to = 0;
  MtaType type = MtaType::kTimesGamma;
  Bytes instance_id;
  BigInt c2 = BigInt(0);
  std::optional<proofs::A2MtAwcProof> a2_proof;
  std::optional<proofs::A3MtAProof> a3_proof;
};

struct SignRound3Msg {
  Scalar delta_i;
};

struct SignRound4Msg {
  ECPoint gamma_i;
  Bytes randomness;
  core::proof::SchnorrProof gamma_proof;
};

struct SignRound5AMsg {
  Bytes commitment;
};

struct SignRound5BMsg {
  ECPoint V_i;
  ECPoint A_i;
  Bytes randomness;
  core::proof::SchnorrProof a_schnorr_proof;
  VRelationProof v_relation_proof;
};

struct SignRound5CMsg {
  Bytes commitment;
};

struct SignRound5DMsg {
  ECPoint U_i;
  ECPoint T_i;
  Bytes randomness;
};

struct Signature {
  Scalar r;
  Scalar s;
  ECPoint R;
};

}  // namespace tecdsa::ecdsa::sign
