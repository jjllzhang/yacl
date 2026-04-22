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

#include <cstddef>
#include <optional>
#include <string>

#include "yacl/crypto/experimental/threshold_ecdsa/common/errors.h"
#include "yacl/crypto/experimental/threshold_ecdsa/core/encoding/encoding.h"
#include "yacl/crypto/experimental/threshold_ecdsa/core/transcript/transcript.h"
#include "yacl/crypto/experimental/threshold_ecdsa/crypto/bigint_utils.h"

namespace tecdsa::sm2::proofs {
namespace {

constexpr char kPiRangeProofName[] = "PiRange";

BigInt NormalizeMod(const BigInt& value, const BigInt& modulus) {
  return bigint::NormalizeMod(value, modulus);
}

bool IsZnStarElement(const BigInt& value, const BigInt& modulus) {
  if (value <= 0 || value >= modulus) {
    return false;
  }
  return BigInt::Gcd(value, modulus) == 1;
}

bool IsInRange(const BigInt& value, const BigInt& modulus) {
  return value >= 0 && value < modulus;
}

BigInt RandomBelow(const BigInt& upper_exclusive) {
  if (upper_exclusive <= 0) {
    TECDSA_THROW_ARGUMENT("random upper bound must be positive");
  }
  return bigint::RandomBelow(upper_exclusive);
}

BigInt SampleZnStar(const BigInt& modulus_n) {
  if (modulus_n <= 2) {
    TECDSA_THROW_ARGUMENT("Paillier modulus must be > 2");
  }
  return bigint::RandomZnStar(modulus_n);
}

BigInt MulMod(const BigInt& lhs, const BigInt& rhs, const BigInt& modulus) {
  return NormalizeMod(lhs * rhs, modulus);
}

BigInt PowMod(const BigInt& base, const BigInt& exp, const BigInt& modulus) {
  if (exp < 0) {
    TECDSA_THROW_ARGUMENT("modular exponent must be non-negative");
  }
  return bigint::PowMod(base, exp, modulus);
}

BigInt QPow(const BigInt& q, size_t exponent) {
  BigInt out(1);
  for (size_t i = 0; i < exponent; ++i) {
    out *= q;
  }
  return out;
}

BigInt QPow3(const MtaProofContext& ctx) { return QPow(ctx.group->order(), 3); }

std::string BuildProofId(const MtaProofContext& ctx, const char* proof_name) {
  return ctx.proof_domain_prefix + "/" + proof_name + "/v1";
}

Bytes CurveNameBytes(const MtaProofContext& ctx) {
  const auto curve_name = ctx.group->curve_name();
  return Bytes(reinterpret_cast<const uint8_t*>(curve_name.data()),
               reinterpret_cast<const uint8_t*>(curve_name.data()) +
                   curve_name.size());
}

Bytes ModulusQBytes(const MtaProofContext& ctx) {
  return bigint::ToFixedWidth(ctx.group->order(), ctx.group->scalar_size_bytes());
}

void AppendCommonMtaTranscriptFields(core::transcript::Transcript* transcript,
                                     const char* proof_name,
                                     const MtaProofContext& ctx) {
  const std::string proof_id = BuildProofId(ctx, proof_name);
  transcript->append_proof_id(proof_id);
  transcript->append_session_id(ctx.session_id);
  transcript->append_u32_be("initiator", ctx.initiator_id);
  transcript->append_u32_be("responder", ctx.responder_id);
  transcript->append_fields({
      core::transcript::TranscriptFieldRef{
          .label = "mta_id", .data = ctx.instance_id},
      core::transcript::TranscriptFieldRef{
          .label = "curve", .data = CurveNameBytes(ctx)},
      core::transcript::TranscriptFieldRef{
          .label = "q", .data = ModulusQBytes(ctx)},
  });
}

Scalar BuildPiRangeChallenge(const MtaProofContext& ctx, const BigInt& n,
                             const BigInt& gamma, const AuxRsaParams& aux,
                             const BigInt& c, const BigInt& z, const BigInt& u,
                             const BigInt& w) {
  core::transcript::Transcript transcript(ctx.transcript_hash);
  AppendCommonMtaTranscriptFields(&transcript, kPiRangeProofName, ctx);
  const Bytes n_bytes = core::encoding::EncodeMpInt(n);
  const Bytes gamma_bytes = core::encoding::EncodeMpInt(gamma);
  const Bytes n_tilde_bytes = core::encoding::EncodeMpInt(aux.n_tilde);
  const Bytes h1_bytes = core::encoding::EncodeMpInt(aux.h1);
  const Bytes h2_bytes = core::encoding::EncodeMpInt(aux.h2);
  const Bytes c_bytes = core::encoding::EncodeMpInt(c);
  const Bytes z_bytes = core::encoding::EncodeMpInt(z);
  const Bytes u_bytes = core::encoding::EncodeMpInt(u);
  const Bytes w_bytes = core::encoding::EncodeMpInt(w);
  transcript.append_fields({
      core::transcript::TranscriptFieldRef{.label = "N", .data = n_bytes},
      core::transcript::TranscriptFieldRef{
          .label = "Gamma", .data = gamma_bytes},
      core::transcript::TranscriptFieldRef{
          .label = "Ntilde", .data = n_tilde_bytes},
      core::transcript::TranscriptFieldRef{.label = "h1", .data = h1_bytes},
      core::transcript::TranscriptFieldRef{.label = "h2", .data = h2_bytes},
      core::transcript::TranscriptFieldRef{.label = "c", .data = c_bytes},
      core::transcript::TranscriptFieldRef{.label = "z", .data = z_bytes},
      core::transcript::TranscriptFieldRef{.label = "u", .data = u_bytes},
      core::transcript::TranscriptFieldRef{.label = "w", .data = w_bytes},
  });
  return transcript.challenge_scalar(ctx.group);
}

}  // namespace

PiRangeProof ProvePiRange(const MtaProofContext& ctx, const BigInt& n,
                          const AuxRsaParams& verifier_aux, const BigInt& c,
                          const BigInt& witness_m, const BigInt& witness_r) {
  const BigInt n2 = n * n;
  const BigInt gamma = n + BigInt(1);
  const BigInt n_tilde = verifier_aux.n_tilde;
  const BigInt h1 = verifier_aux.h1;
  const BigInt h2 = verifier_aux.h2;
  const BigInt q_mul_n_tilde = ctx.group->order() * n_tilde;
  const BigInt q3_mul_n_tilde = QPow3(ctx) * n_tilde;

  while (true) {
    const BigInt alpha = RandomBelow(QPow3(ctx));
    const BigInt beta = SampleZnStar(n);
    const BigInt gamma_rand = RandomBelow(q3_mul_n_tilde);
    const BigInt rho = RandomBelow(q_mul_n_tilde);

    const BigInt z = MulMod(PowMod(h1, witness_m, n_tilde),
                            PowMod(h2, rho, n_tilde), n_tilde);
    const BigInt u = MulMod(PowMod(gamma, alpha, n2), PowMod(beta, n, n2), n2);
    const BigInt w = MulMod(PowMod(h1, alpha, n_tilde),
                            PowMod(h2, gamma_rand, n_tilde), n_tilde);

    const Scalar e_scalar =
        BuildPiRangeChallenge(ctx, n, gamma, verifier_aux, c, z, u, w);
    const BigInt e = e_scalar.mp_value();
    const BigInt s = MulMod(PowMod(witness_r, e, n), beta, n);
    const BigInt s1 = (e * witness_m) + alpha;
    const BigInt s2 = (e * rho) + gamma_rand;
    if (s1 > QPow3(ctx)) {
      continue;
    }

    return PiRangeProof{
        .z = z,
        .u = u,
        .w = w,
        .s = s,
        .s1 = s1,
        .s2 = s2,
    };
  }
}

bool VerifyPiRange(const MtaProofContext& ctx, const BigInt& n,
                   const AuxRsaParams& verifier_aux, const BigInt& c,
                   const PiRangeProof& proof) {
  const BigInt n2 = n * n;
  const BigInt gamma = n + BigInt(1);
  const BigInt n_tilde = verifier_aux.n_tilde;
  const BigInt h1 = verifier_aux.h1;
  const BigInt h2 = verifier_aux.h2;

  if (!IsInRange(c, n2) || !IsInRange(proof.u, n2) ||
      !IsInRange(proof.z, n_tilde) || !IsInRange(proof.w, n_tilde) ||
      !IsZnStarElement(proof.s, n)) {
    return false;
  }
  if (proof.s1 < 0 || proof.s1 > QPow3(ctx) || proof.s2 < 0) {
    return false;
  }

  const Scalar e_scalar = BuildPiRangeChallenge(ctx, n, gamma, verifier_aux, c,
                                                proof.z, proof.u, proof.w);
  const BigInt e = e_scalar.mp_value();

  const BigInt c_pow_e = PowMod(c, e, n2);
  const std::optional<BigInt> c_pow_e_inv = bigint::TryInvertMod(c_pow_e, n2);
  if (!c_pow_e_inv.has_value()) {
    return false;
  }

  BigInt rhs_u =
      MulMod(PowMod(gamma, proof.s1, n2), PowMod(proof.s, n, n2), n2);
  rhs_u = MulMod(rhs_u, *c_pow_e_inv, n2);
  if (NormalizeMod(proof.u, n2) != rhs_u) {
    return false;
  }

  const BigInt lhs_nt = MulMod(PowMod(h1, proof.s1, n_tilde),
                               PowMod(h2, proof.s2, n_tilde), n_tilde);
  const BigInt rhs_nt = MulMod(proof.w, PowMod(proof.z, e, n_tilde), n_tilde);
  return lhs_nt == rhs_nt;
}

}  // namespace tecdsa::sm2::proofs
