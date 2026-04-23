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

#include "yacl/crypto/experimental/threshold_ecdsa/sm2/proofs/pi_linear.h"

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

PiLinearGroupProof ProvePiLinearGroup(const MtaProofContext& ctx,
                                      const BigInt& n,
                                      const AuxRsaParams& verifier_aux,
                                      const BigInt& c1, const BigInt& c2,
                                      const ECPoint& statement_x,
                                      const BigInt& witness_x,
                                      const BigInt& witness_y,
                                      const BigInt& witness_r) {
  return core::mta::ProveA2MtAwc(WithSm2ProofNames(ctx), n, verifier_aux, c1,
                                 c2, statement_x, witness_x, witness_y,
                                 witness_r);
}

bool VerifyPiLinearGroup(const MtaProofContext& ctx, const BigInt& n,
                         const AuxRsaParams& verifier_aux, const BigInt& c1,
                         const BigInt& c2, const ECPoint& statement_x,
                         const PiLinearGroupProof& proof) {
  return core::mta::VerifyA2MtAwc(WithSm2ProofNames(ctx), n, verifier_aux, c1,
                                  c2, statement_x, proof);
}

PiLinearProof ProvePiLinear(const MtaProofContext& ctx, const BigInt& n,
                            const AuxRsaParams& verifier_aux,
                            const BigInt& c1, const BigInt& c2,
                            const BigInt& witness_x, const BigInt& witness_y,
                            const BigInt& witness_r) {
  return core::mta::ProveA3MtA(WithSm2ProofNames(ctx), n, verifier_aux, c1, c2,
                               witness_x, witness_y, witness_r);
}

bool VerifyPiLinear(const MtaProofContext& ctx, const BigInt& n,
                    const AuxRsaParams& verifier_aux, const BigInt& c1,
                    const BigInt& c2, const PiLinearProof& proof) {
  return core::mta::VerifyA3MtA(WithSm2ProofNames(ctx), n, verifier_aux, c1,
                                c2, proof);
}

std::shared_ptr<const core::mta::ProofBackend> BuildSm2ProofBackend() {
  auto backend = std::make_shared<core::mta::ProofBackend>();
  backend->prove_a1_range = [](const MtaProofContext& ctx, const BigInt& n,
                               const AuxRsaParams& verifier_aux,
                               const BigInt& c, const BigInt& witness_m,
                               const BigInt& witness_r) {
    return core::mta::ProveA1Range(WithSm2ProofNames(ctx), n, verifier_aux, c,
                                   witness_m, witness_r);
  };
  backend->verify_a1_range = [](const MtaProofContext& ctx, const BigInt& n,
                                const AuxRsaParams& verifier_aux,
                                const BigInt& c, const PiRangeProof& proof) {
    return core::mta::VerifyA1Range(WithSm2ProofNames(ctx), n, verifier_aux, c,
                                    proof);
  };
  backend->prove_a2_mtawc =
      [](const MtaProofContext& ctx, const BigInt& n,
         const AuxRsaParams& verifier_aux, const BigInt& c1, const BigInt& c2,
         const ECPoint& statement_x, const BigInt& witness_x,
         const BigInt& witness_y, const BigInt& witness_r) {
        return core::mta::ProveA2MtAwc(WithSm2ProofNames(ctx), n, verifier_aux,
                                       c1, c2, statement_x, witness_x,
                                       witness_y, witness_r);
      };
  backend->verify_a2_mtawc = [](const MtaProofContext& ctx, const BigInt& n,
                                const AuxRsaParams& verifier_aux,
                                const BigInt& c1, const BigInt& c2,
                                const ECPoint& statement_x,
                                const PiLinearGroupProof& proof) {
    return core::mta::VerifyA2MtAwc(WithSm2ProofNames(ctx), n, verifier_aux,
                                    c1, c2, statement_x, proof);
  };
  backend->prove_a3_mta =
      [](const MtaProofContext& ctx, const BigInt& n,
         const AuxRsaParams& verifier_aux, const BigInt& c1, const BigInt& c2,
         const BigInt& witness_x, const BigInt& witness_y,
         const BigInt& witness_r) {
        return core::mta::ProveA3MtA(WithSm2ProofNames(ctx), n, verifier_aux,
                                     c1, c2, witness_x, witness_y, witness_r);
      };
  backend->verify_a3_mta = [](const MtaProofContext& ctx, const BigInt& n,
                              const AuxRsaParams& verifier_aux,
                              const BigInt& c1, const BigInt& c2,
                              const PiLinearProof& proof) {
    return core::mta::VerifyA3MtA(WithSm2ProofNames(ctx), n, verifier_aux, c1,
                                  c2, proof);
  };
  return backend;
}

}  // namespace tecdsa::sm2::proofs
