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

#include "yacl/crypto/experimental/threshold_signatures/sm2/proofs/pi_group.h"

#include "yacl/crypto/experimental/threshold_signatures/core/encoding/encoding.h"
#include "yacl/crypto/experimental/threshold_signatures/core/proof/schnorr.h"
#include "yacl/crypto/experimental/threshold_signatures/core/suite/suite.h"
#include "yacl/crypto/experimental/threshold_signatures/core/transcript/transcript.h"
#include "yacl/crypto/experimental/threshold_signatures/sm2/common.h"

namespace tecdsa::sm2::proofs {
namespace {

constexpr char kPiGroupRelationProofId[] = "SM2/PiGroupRelation/v1";

Scalar BuildPiGroupRelationChallenge(const Bytes& session_id,
                                     PartyIndex prover_id, const ECPoint& base_h,
                                     const ECPoint& statement_g,
                                     const ECPoint& statement_h,
                                     const PiGroupRelationProof& proof) {
  core::transcript::Transcript transcript(core::DefaultSm2Suite().transcript_hash);
  transcript.append_proof_id(kPiGroupRelationProofId);
  transcript.append_session_id(session_id);
  transcript.append_u32_be("prover", prover_id);
  const Bytes base_h_bytes = core::encoding::EncodePoint(base_h);
  const Bytes statement_g_bytes = core::encoding::EncodePoint(statement_g);
  const Bytes statement_h_bytes = core::encoding::EncodePoint(statement_h);
  const Bytes a_g_bytes = core::encoding::EncodePoint(proof.a_g);
  const Bytes a_h_bytes = core::encoding::EncodePoint(proof.a_h);
  transcript.append_fields({
      core::transcript::TranscriptFieldRef{
          .label = "base_h", .data = base_h_bytes},
      core::transcript::TranscriptFieldRef{
          .label = "statement_g", .data = statement_g_bytes},
      core::transcript::TranscriptFieldRef{
          .label = "statement_h", .data = statement_h_bytes},
      core::transcript::TranscriptFieldRef{.label = "a_g", .data = a_g_bytes},
      core::transcript::TranscriptFieldRef{.label = "a_h", .data = a_h_bytes},
  });
  return transcript.challenge_scalar(tecdsa::sm2::internal::Sm2Group());
}

}  // namespace

PiGroupProof BuildPiGroupProof(const Bytes& session_id, PartyIndex prover_id,
                               const ECPoint& statement,
                               const Scalar& witness) {
  return core::proof::BuildSchnorrProof(core::DefaultSm2Suite(), session_id,
                                        prover_id, statement, witness);
}

bool VerifyPiGroupProof(const Bytes& session_id, PartyIndex prover_id,
                        const ECPoint& statement, const PiGroupProof& proof) {
  return core::proof::VerifySchnorrProof(core::DefaultSm2Suite(), session_id,
                                         prover_id, statement, proof);
}

PiGroupRelationProof BuildPiGroupRelationProof(const Bytes& session_id,
                                               PartyIndex prover_id,
                                               const ECPoint& base_h,
                                               const ECPoint& statement_g,
                                               const ECPoint& statement_h,
                                               const Scalar& witness) {
  const Scalar alpha = tecdsa::sm2::internal::RandomNonZeroSm2Scalar();
  PiGroupRelationProof proof{
      .a_g = ECPoint::GeneratorMultiply(alpha),
      .a_h = base_h.Mul(alpha),
      .z = alpha,
  };
  const Scalar challenge = BuildPiGroupRelationChallenge(
      session_id, prover_id, base_h, statement_g, statement_h, proof);
  proof.z = alpha + (challenge * witness);
  return proof;
}

bool VerifyPiGroupRelationProof(const Bytes& session_id, PartyIndex prover_id,
                                const ECPoint& base_h,
                                const ECPoint& statement_g,
                                const ECPoint& statement_h,
                                const PiGroupRelationProof& proof) {
  try {
    const Scalar challenge = BuildPiGroupRelationChallenge(
        session_id, prover_id, base_h, statement_g, statement_h, proof);
    const ECPoint lhs_g = ECPoint::GeneratorMultiply(proof.z);
    const ECPoint rhs_g = proof.a_g.Add(statement_g.Mul(challenge));
    if (lhs_g != rhs_g) {
      return false;
    }
    const ECPoint lhs_h = base_h.Mul(proof.z);
    const ECPoint rhs_h = proof.a_h.Add(statement_h.Mul(challenge));
    return lhs_h == rhs_h;
  } catch (const std::exception&) {
    return false;
  }
}

}  // namespace tecdsa::sm2::proofs
