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

#include "yacl/crypto/experimental/threshold_ecdsa/sm2/proofs/pi_group.h"

#include "yacl/crypto/experimental/threshold_ecdsa/core/proof/schnorr.h"
#include "yacl/crypto/experimental/threshold_ecdsa/core/suite/suite.h"

namespace tecdsa::sm2::proofs {

PiGroupProof BuildPiGroupProof(const Bytes& session_id, PartyIndex prover_id,
                               const ECPoint& statement,
                               const Scalar& witness) {
  return core::proof::BuildSchnorrProof(core::DefaultSm2Suite(), session_id,
                                        prover_id, statement, witness);
}

bool VerifyPiGroupProof(const Bytes& session_id, PartyIndex prover_id,
                        const ECPoint& statement, const PiGroupProof& proof) {
  return core::proof::VerifySchnorrProof(core::DefaultSm2Suite(), session_id,
                                         prover_id, statement, proof);
}

}  // namespace tecdsa::sm2::proofs
