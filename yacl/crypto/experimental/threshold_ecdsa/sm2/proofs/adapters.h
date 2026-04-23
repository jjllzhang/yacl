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

#include "yacl/crypto/experimental/threshold_ecdsa/core/mta/proofs.h"
#include "yacl/crypto/experimental/threshold_ecdsa/core/proof/types.h"
#include "yacl/crypto/experimental/threshold_ecdsa/sm2/proofs/types.h"

namespace tecdsa::sm2::proofs {

inline PiRangeProof FromCorePiRangeProof(const core::mta::A1RangeProof& proof) {
  return proof;
}
inline core::mta::A1RangeProof ToCorePiRangeProof(const PiRangeProof& proof) {
  return proof;
}

inline PiLinearGroupProof FromCorePiLinearGroupProof(
    const core::mta::A2MtAwcProof& proof) {
  return proof;
}
inline core::mta::A2MtAwcProof ToCorePiLinearGroupProof(
    const PiLinearGroupProof& proof) {
  return proof;
}

inline PiLinearProof FromCorePiLinearProof(const core::mta::A3MtAProof& proof) {
  return proof;
}
inline core::mta::A3MtAProof ToCorePiLinearProof(const PiLinearProof& proof) {
  return proof;
}

PiGroupProof FromCorePiGroupProof(const core::proof::SchnorrProof& proof);
core::proof::SchnorrProof ToCorePiGroupProof(const PiGroupProof& proof);

}  // namespace tecdsa::sm2::proofs
