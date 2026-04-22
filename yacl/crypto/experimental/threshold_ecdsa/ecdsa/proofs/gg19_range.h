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

namespace tecdsa::ecdsa::proofs {

using BigInt = core::paillier::BigInt;
using MtaProofContext = core::mta::MtaProofContext;
using A1RangeProof = core::mta::A1RangeProof;
using AuxRsaParams = core::paillier::AuxRsaParams;

A1RangeProof ProveA1Range(const MtaProofContext& ctx, const BigInt& n,
                          const AuxRsaParams& verifier_aux, const BigInt& c,
                          const BigInt& witness_m, const BigInt& witness_r);
bool VerifyA1Range(const MtaProofContext& ctx, const BigInt& n,
                   const AuxRsaParams& verifier_aux, const BigInt& c,
                   const A1RangeProof& proof);

}  // namespace tecdsa::ecdsa::proofs
