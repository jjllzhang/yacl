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

#include "yacl/crypto/experimental/threshold_ecdsa/common/bytes.h"
#include "yacl/crypto/experimental/threshold_ecdsa/crypto/ec_point.h"
#include "yacl/crypto/experimental/threshold_ecdsa/crypto/scalar.h"
#include "yacl/crypto/experimental/threshold_ecdsa/protocol/types.h"

namespace tecdsa::ecdsa::sign {

struct VRelationProof {
  ECPoint alpha;
  Scalar t;
  Scalar u;
};

Bytes SerializePointPair(const ECPoint& first, const ECPoint& second);

Scalar BuildVRelationChallenge(const Bytes& session_id, PartyIndex party_id,
                               const ECPoint& r_statement,
                               const ECPoint& v_statement,
                               const ECPoint& alpha);

ECPoint BuildRGeneratorLinearCombination(const ECPoint& r_base,
                                         const Scalar& r_multiplier,
                                         const Scalar& g_multiplier);

VRelationProof BuildVRelationProof(const Bytes& session_id, PartyIndex prover_id,
                                   const ECPoint& r_statement,
                                   const ECPoint& v_statement,
                                   const Scalar& s_witness,
                                   const Scalar& l_witness);

bool VerifyVRelationProof(const Bytes& session_id, PartyIndex prover_id,
                          const ECPoint& r_statement,
                          const ECPoint& v_statement,
                          const VRelationProof& proof);

}  // namespace tecdsa::ecdsa::sign
