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

#include "yacl/crypto/experimental/threshold_ecdsa/core/mta/session.h"
#include "yacl/crypto/experimental/threshold_ecdsa/sm2/proofs/types.h"

namespace tecdsa::sm2::proofs {

using BigInt = core::paillier::BigInt;
using MtaProofContext = core::mta::MtaProofContext;
using AuxRsaParams = core::paillier::AuxRsaParams;

PiLinearGroupProof ProvePiLinearGroup(const MtaProofContext& ctx,
                                      const BigInt& n,
                                      const AuxRsaParams& verifier_aux,
                                      const BigInt& c1, const BigInt& c2,
                                      const ECPoint& statement_x,
                                      const BigInt& witness_x,
                                      const BigInt& witness_y,
                                      const BigInt& witness_r);
bool VerifyPiLinearGroup(const MtaProofContext& ctx, const BigInt& n,
                         const AuxRsaParams& verifier_aux, const BigInt& c1,
                         const BigInt& c2, const ECPoint& statement_x,
                         const PiLinearGroupProof& proof);

PiLinearProof ProvePiLinear(const MtaProofContext& ctx, const BigInt& n,
                            const AuxRsaParams& verifier_aux,
                            const BigInt& c1, const BigInt& c2,
                            const BigInt& witness_x, const BigInt& witness_y,
                            const BigInt& witness_r);
bool VerifyPiLinear(const MtaProofContext& ctx, const BigInt& n,
                    const AuxRsaParams& verifier_aux, const BigInt& c1,
                    const BigInt& c2, const PiLinearProof& proof);

std::shared_ptr<const core::mta::ProofBackend> BuildSm2ProofBackend();

}  // namespace tecdsa::sm2::proofs
