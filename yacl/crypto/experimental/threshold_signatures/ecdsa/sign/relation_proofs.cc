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

#include "yacl/crypto/experimental/threshold_signatures/ecdsa/sign/relation_proofs.h"

#include <exception>
#include <optional>
#include <string>

#include "yacl/crypto/experimental/threshold_signatures/common/errors.h"
#include "yacl/crypto/experimental/threshold_signatures/core/encoding/encoding.h"
#include "yacl/crypto/experimental/threshold_signatures/core/transcript/transcript.h"
#include "yacl/crypto/experimental/threshold_signatures/core/random/csprng.h"

namespace tecdsa::ecdsa::sign {
namespace {

constexpr char kVRelationProofId[] = "GG2019/VRel/v1";

}  // namespace

Bytes SerializePointPair(const ECPoint& first, const ECPoint& second) {
  Bytes out;
  const Bytes first_bytes = first.ToCompressedBytes();
  const Bytes second_bytes = second.ToCompressedBytes();
  out.reserve(first_bytes.size() + second_bytes.size());
  out.insert(out.end(), first_bytes.begin(), first_bytes.end());
  out.insert(out.end(), second_bytes.begin(), second_bytes.end());
  return out;
}

Scalar BuildVRelationChallenge(const Bytes& session_id, PartyIndex party_id,
                               const ECPoint& r_statement,
                               const ECPoint& v_statement,
                               const ECPoint& alpha) {
  core::transcript::Transcript transcript(core::DefaultEcdsaSuite().transcript_hash);
  const Bytes r_bytes = core::encoding::EncodePoint(r_statement);
  const Bytes v_bytes = core::encoding::EncodePoint(v_statement);
  const Bytes alpha_bytes = core::encoding::EncodePoint(alpha);
  transcript.append_proof_id(kVRelationProofId);
  transcript.append_session_id(session_id);
  transcript.append_u32_be("party_id", party_id);
  transcript.append_fields({
      core::transcript::TranscriptFieldRef{.label = "R", .data = r_bytes},
      core::transcript::TranscriptFieldRef{.label = "V", .data = v_bytes},
      core::transcript::TranscriptFieldRef{.label = "alpha",
                                           .data = alpha_bytes},
  });
  return transcript.challenge_scalar(r_statement.group());
}

ECPoint BuildRGeneratorLinearCombination(const ECPoint& r_base,
                                         const Scalar& r_multiplier,
                                         const Scalar& g_multiplier) {
  std::optional<ECPoint> out;
  if (r_multiplier.value() != 0) {
    out = r_base.Mul(r_multiplier);
  }
  if (g_multiplier.value() != 0) {
    const ECPoint g_term = ECPoint::GeneratorMultiply(g_multiplier);
    out = out.has_value() ? out->Add(g_term) : g_term;
  }
  if (!out.has_value()) {
    TECDSA_THROW_ARGUMENT("linear combination is point at infinity");
  }
  return *out;
}

VRelationProof BuildVRelationProof(const Bytes& session_id, PartyIndex prover_id,
                                   const ECPoint& r_statement,
                                   const ECPoint& v_statement,
                                   const Scalar& s_witness,
                                   const Scalar& l_witness) {
  try {
    if (BuildRGeneratorLinearCombination(r_statement, s_witness, l_witness) !=
        v_statement) {
      TECDSA_THROW_ARGUMENT("v relation witness does not match statement");
    }
  } catch (const std::exception& ex) {
    TECDSA_THROW_ARGUMENT(std::string("invalid v relation witness: ") +
                          ex.what());
  }

  while (true) {
    const Scalar a = Csprng::RandomScalar();
    const Scalar b = Csprng::RandomScalar();
    if (a.value() == 0 && b.value() == 0) {
      continue;
    }

    ECPoint alpha;
    try {
      alpha = BuildRGeneratorLinearCombination(r_statement, a, b);
    } catch (const std::exception&) {
      continue;
    }

    const Scalar c = BuildVRelationChallenge(session_id, prover_id, r_statement,
                                             v_statement, alpha);
    const Scalar t = a + (c * s_witness);
    const Scalar u = b + (c * l_witness);
    if (t.value() == 0 && u.value() == 0) {
      continue;
    }

    return VRelationProof{
        .alpha = alpha,
        .t = t,
        .u = u,
    };
  }
}

bool VerifyVRelationProof(const Bytes& session_id, PartyIndex prover_id,
                          const ECPoint& r_statement,
                          const ECPoint& v_statement,
                          const VRelationProof& proof) {
  if (proof.t.value() == 0 && proof.u.value() == 0) {
    return false;
  }

  try {
    const Scalar c = BuildVRelationChallenge(session_id, prover_id, r_statement,
                                             v_statement, proof.alpha);
    const ECPoint lhs =
        BuildRGeneratorLinearCombination(r_statement, proof.t, proof.u);

    ECPoint rhs = proof.alpha;
    if (c.value() != 0) {
      rhs = rhs.Add(v_statement.Mul(c));
    }
    return lhs == rhs;
  } catch (const std::exception&) {
    return false;
  }
}

}  // namespace tecdsa::ecdsa::sign
