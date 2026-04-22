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
#include "yacl/crypto/experimental/threshold_ecdsa/core/paillier/paillier.h"
#include "yacl/crypto/experimental/threshold_ecdsa/crypto/scalar.h"

namespace tecdsa::sm2::proofs {

using BigInt = Scalar::BigInt;

struct PiSqrProof {
  Bytes blob;
};

PiSqrProof BuildPiSqrProof(
    const BigInt& modulus_n, const BigInt& lambda_n,
    const core::paillier::StrictProofVerifierContext& context);
bool VerifyPiSqrProof(
    const BigInt& modulus_n, const PiSqrProof& proof,
    const core::paillier::StrictProofVerifierContext& context);

}  // namespace tecdsa::sm2::proofs
