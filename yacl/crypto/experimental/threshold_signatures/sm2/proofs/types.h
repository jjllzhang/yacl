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

#include "yacl/crypto/experimental/threshold_signatures/common/types.h"
#include "yacl/crypto/experimental/threshold_signatures/core/mta/proofs.h"
#include "yacl/crypto/experimental/threshold_signatures/core/paillier/aux_proofs.h"
#include "yacl/crypto/experimental/threshold_signatures/core/proof/types.h"

namespace tecdsa::sm2::proofs {

using BigInt = core::paillier::BigInt;
using PiRangeProof = core::mta::A1RangeProof;
using PiLinearGroupProof = core::mta::A2MtAwcProof;
using PiLinearProof = core::mta::A3MtAProof;
using PiGroupProof = core::proof::SchnorrProof;
using PiSqrProof = core::paillier::SquareFreeProof;

struct PiGroupRelationProof {
  ECPoint a_g;
  ECPoint a_h;
  Scalar z;
};

}  // namespace tecdsa::sm2::proofs
