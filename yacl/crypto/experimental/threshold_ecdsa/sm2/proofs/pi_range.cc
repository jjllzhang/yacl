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

#include "yacl/crypto/experimental/threshold_ecdsa/sm2/proofs/pi_range.h"

namespace tecdsa::sm2::proofs {
namespace {

core::mta::MtaProofNames Sm2ProofNames() {
  return core::mta::MtaProofNames{
      .a1_range = "PiRange",
      .a2_mtawc = "PiLinearGroup",
      .a3_mta = "PiLinear",
  };
}

core::mta::MtaProofContext WithSm2ProofNames(const MtaProofContext& ctx) {
  auto named_ctx = ctx;
  named_ctx.proof_names = Sm2ProofNames();
  return named_ctx;
}

}  // namespace

PiRangeProof ProvePiRange(const MtaProofContext& ctx, const BigInt& n,
                          const AuxRsaParams& verifier_aux, const BigInt& c,
                          const BigInt& witness_m, const BigInt& witness_r) {
  return core::mta::ProveA1Range(WithSm2ProofNames(ctx), n, verifier_aux, c,
                                 witness_m, witness_r);
}

bool VerifyPiRange(const MtaProofContext& ctx, const BigInt& n,
                   const AuxRsaParams& verifier_aux, const BigInt& c,
                   const PiRangeProof& proof) {
  return core::mta::VerifyA1Range(WithSm2ProofNames(ctx), n, verifier_aux, c,
                                  proof);
}

}  // namespace tecdsa::sm2::proofs
