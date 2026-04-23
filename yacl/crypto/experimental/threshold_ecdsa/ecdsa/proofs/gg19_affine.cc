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

#include "yacl/crypto/experimental/threshold_ecdsa/ecdsa/proofs/gg19_affine.h"

namespace tecdsa::ecdsa::proofs {

A2MtAwcProof ProveA2MtAwc(const MtaProofContext& ctx, const BigInt& n,
                          const AuxRsaParams& verifier_aux, const BigInt& c1,
                          const BigInt& c2, const ECPoint& statement_x,
                          const BigInt& witness_x, const BigInt& witness_y,
                          const BigInt& witness_r) {
  return core::mta::ProveA2MtAwc(ctx, n, verifier_aux, c1, c2, statement_x,
                                 witness_x, witness_y, witness_r);
}

bool VerifyA2MtAwc(const MtaProofContext& ctx, const BigInt& n,
                   const AuxRsaParams& verifier_aux, const BigInt& c1,
                   const BigInt& c2, const ECPoint& statement_x,
                   const A2MtAwcProof& proof) {
  return core::mta::VerifyA2MtAwc(ctx, n, verifier_aux, c1, c2, statement_x,
                                  proof);
}

A3MtAProof ProveA3MtA(const MtaProofContext& ctx, const BigInt& n,
                      const AuxRsaParams& verifier_aux, const BigInt& c1,
                      const BigInt& c2, const BigInt& witness_x,
                      const BigInt& witness_y, const BigInt& witness_r) {
  return core::mta::ProveA3MtA(ctx, n, verifier_aux, c1, c2, witness_x,
                               witness_y, witness_r);
}

bool VerifyA3MtA(const MtaProofContext& ctx, const BigInt& n,
                 const AuxRsaParams& verifier_aux, const BigInt& c1,
                 const BigInt& c2, const A3MtAProof& proof) {
  return core::mta::VerifyA3MtA(ctx, n, verifier_aux, c1, c2, proof);
}

std::shared_ptr<const core::mta::ProofBackend> BuildGg19ProofBackend() {
  return core::mta::BuildDefaultProofBackend();
}

}  // namespace tecdsa::ecdsa::proofs
