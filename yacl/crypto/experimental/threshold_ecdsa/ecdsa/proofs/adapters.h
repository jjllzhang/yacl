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
#include "yacl/crypto/experimental/threshold_ecdsa/ecdsa/proofs/types.h"

namespace tecdsa::ecdsa::proofs {

inline A1RangeProof FromCoreA1RangeProof(const core::mta::A1RangeProof& proof) {
  return proof;
}
inline core::mta::A1RangeProof ToCoreA1RangeProof(const A1RangeProof& proof) {
  return proof;
}

inline A2MtAwcProof FromCoreA2MtAwcProof(
    const core::mta::A2MtAwcProof& proof) {
  return proof;
}
inline core::mta::A2MtAwcProof ToCoreA2MtAwcProof(
    const A2MtAwcProof& proof) {
  return proof;
}

inline A3MtAProof FromCoreA3MtAProof(const core::mta::A3MtAProof& proof) {
  return proof;
}
inline core::mta::A3MtAProof ToCoreA3MtAProof(const A3MtAProof& proof) {
  return proof;
}

SchnorrProof FromCoreSchnorrProof(const core::proof::SchnorrProof& proof);
core::proof::SchnorrProof ToCoreSchnorrProof(const SchnorrProof& proof);

}  // namespace tecdsa::ecdsa::proofs
