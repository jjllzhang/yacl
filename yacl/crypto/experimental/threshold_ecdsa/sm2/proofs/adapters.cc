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

#include "yacl/crypto/experimental/threshold_ecdsa/sm2/proofs/adapters.h"

namespace tecdsa::sm2::proofs {

PiGroupProof FromCorePiGroupProof(const core::proof::SchnorrProof& proof) {
  return PiGroupProof{
      .a = proof.a,
      .z = proof.z,
  };
}

core::proof::SchnorrProof ToCorePiGroupProof(const PiGroupProof& proof) {
  return core::proof::SchnorrProof{
      .a = proof.a,
      .z = proof.z,
  };
}

}  // namespace tecdsa::sm2::proofs
