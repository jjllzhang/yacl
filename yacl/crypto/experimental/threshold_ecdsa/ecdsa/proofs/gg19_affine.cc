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

#include <cstddef>
#include <exception>
#include <optional>
#include <string>

#include "yacl/crypto/experimental/threshold_ecdsa/common/errors.h"
#include "yacl/crypto/experimental/threshold_ecdsa/core/encoding/encoding.h"
#include "yacl/crypto/experimental/threshold_ecdsa/core/transcript/transcript.h"
#include "yacl/crypto/experimental/threshold_ecdsa/crypto/bigint_utils.h"
#include "yacl/crypto/experimental/threshold_ecdsa/ecdsa/proofs/adapters.h"
#include "yacl/crypto/experimental/threshold_ecdsa/ecdsa/proofs/gg19_range.h"

namespace tecdsa::ecdsa::proofs {
namespace {

constexpr char kA2MtAwcProofName[] = "A2MtAwc";
constexpr char kA3MtAProofName[] = "A3MtA";

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

BigInt QPow7(const MtaProofContext& ctx) { return QPow(ctx.group->order(), 7); }

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

Scalar BuildA2MtAwcChallenge(const MtaProofContext& ctx, const BigInt& n,
                             const BigInt& gamma, const AuxRsaParams& aux,
                             const BigInt& c1, const BigInt& c2,
                             const ECPoint& statement_x,
                             const A2MtAwcProof& proof) {
  core::transcript::Transcript transcript(ctx.transcript_hash);
  AppendCommonMtaTranscriptFields(&transcript, kA2MtAwcProofName, ctx);
  const Bytes n_bytes = core::encoding::EncodeMpInt(n);
  const Bytes gamma_bytes = core::encoding::EncodeMpInt(gamma);
  const Bytes n_tilde_bytes = core::encoding::EncodeMpInt(aux.n_tilde);
  const Bytes h1_bytes = core::encoding::EncodeMpInt(aux.h1);
  const Bytes h2_bytes = core::encoding::EncodeMpInt(aux.h2);
  const Bytes c1_bytes = core::encoding::EncodeMpInt(c1);
  const Bytes c2_bytes = core::encoding::EncodeMpInt(c2);
  const Bytes x_bytes = core::encoding::EncodePoint(statement_x);
  const Bytes u_bytes = core::encoding::EncodePoint(proof.u);
  const Bytes z_bytes = core::encoding::EncodeMpInt(proof.z);
  const Bytes z2_bytes = core::encoding::EncodeMpInt(proof.z2);
  const Bytes t_bytes = core::encoding::EncodeMpInt(proof.t);
  const Bytes v_bytes = core::encoding::EncodeMpInt(proof.v);
  const Bytes w_bytes = core::encoding::EncodeMpInt(proof.w);
  transcript.append_fields({
      core::transcript::TranscriptFieldRef{.label = "N", .data = n_bytes},
      core::transcript::TranscriptFieldRef{
          .label = "Gamma", .data = gamma_bytes},
      core::transcript::TranscriptFieldRef{
          .label = "Ntilde", .data = n_tilde_bytes},
      core::transcript::TranscriptFieldRef{.label = "h1", .data = h1_bytes},
      core::transcript::TranscriptFieldRef{.label = "h2", .data = h2_bytes},
      core::transcript::TranscriptFieldRef{.label = "c1", .data = c1_bytes},
      core::transcript::TranscriptFieldRef{.label = "c2", .data = c2_bytes},
      core::transcript::TranscriptFieldRef{.label = "X", .data = x_bytes},
      core::transcript::TranscriptFieldRef{.label = "u", .data = u_bytes},
      core::transcript::TranscriptFieldRef{.label = "z", .data = z_bytes},
      core::transcript::TranscriptFieldRef{.label = "z2", .data = z2_bytes},
      core::transcript::TranscriptFieldRef{.label = "t", .data = t_bytes},
      core::transcript::TranscriptFieldRef{.label = "v", .data = v_bytes},
      core::transcript::TranscriptFieldRef{.label = "w", .data = w_bytes},
  });
  return transcript.challenge_scalar(ctx.group);
}

Scalar BuildA3MtAChallenge(const MtaProofContext& ctx, const BigInt& n,
                           const BigInt& gamma, const AuxRsaParams& aux,
                           const BigInt& c1, const BigInt& c2,
                           const A3MtAProof& proof) {
  core::transcript::Transcript transcript(ctx.transcript_hash);
  AppendCommonMtaTranscriptFields(&transcript, kA3MtAProofName, ctx);
  const Bytes n_bytes = core::encoding::EncodeMpInt(n);
  const Bytes gamma_bytes = core::encoding::EncodeMpInt(gamma);
  const Bytes n_tilde_bytes = core::encoding::EncodeMpInt(aux.n_tilde);
  const Bytes h1_bytes = core::encoding::EncodeMpInt(aux.h1);
  const Bytes h2_bytes = core::encoding::EncodeMpInt(aux.h2);
  const Bytes c1_bytes = core::encoding::EncodeMpInt(c1);
  const Bytes c2_bytes = core::encoding::EncodeMpInt(c2);
  const Bytes z_bytes = core::encoding::EncodeMpInt(proof.z);
  const Bytes z2_bytes = core::encoding::EncodeMpInt(proof.z2);
  const Bytes t_bytes = core::encoding::EncodeMpInt(proof.t);
  const Bytes v_bytes = core::encoding::EncodeMpInt(proof.v);
  const Bytes w_bytes = core::encoding::EncodeMpInt(proof.w);
  transcript.append_fields({
      core::transcript::TranscriptFieldRef{.label = "N", .data = n_bytes},
      core::transcript::TranscriptFieldRef{
          .label = "Gamma", .data = gamma_bytes},
      core::transcript::TranscriptFieldRef{
          .label = "Ntilde", .data = n_tilde_bytes},
      core::transcript::TranscriptFieldRef{.label = "h1", .data = h1_bytes},
      core::transcript::TranscriptFieldRef{.label = "h2", .data = h2_bytes},
      core::transcript::TranscriptFieldRef{.label = "c1", .data = c1_bytes},
      core::transcript::TranscriptFieldRef{.label = "c2", .data = c2_bytes},
      core::transcript::TranscriptFieldRef{.label = "z", .data = z_bytes},
      core::transcript::TranscriptFieldRef{.label = "z2", .data = z2_bytes},
      core::transcript::TranscriptFieldRef{.label = "t", .data = t_bytes},
      core::transcript::TranscriptFieldRef{.label = "v", .data = v_bytes},
      core::transcript::TranscriptFieldRef{.label = "w", .data = w_bytes},
  });
  return transcript.challenge_scalar(ctx.group);
}

}  // namespace

A2MtAwcProof ProveA2MtAwc(const MtaProofContext& ctx, const BigInt& n,
                          const AuxRsaParams& verifier_aux, const BigInt& c1,
                          const BigInt& c2, const ECPoint& statement_x,
                          const BigInt& witness_x, const BigInt& witness_y,
                          const BigInt& witness_r) {
  const BigInt n2 = n * n;
  const BigInt gamma = n + BigInt(1);
  const BigInt n_tilde = verifier_aux.n_tilde;
  const BigInt h1 = verifier_aux.h1;
  const BigInt h2 = verifier_aux.h2;
  const BigInt q_mul_n_tilde = ctx.group->order() * n_tilde;
  const BigInt q3_mul_n_tilde = QPow3(ctx) * n_tilde;

  while (true) {
    const BigInt alpha = RandomBelow(QPow3(ctx));
    const Scalar alpha_scalar(alpha, ctx.group);
    if (alpha_scalar.value() == 0) {
      continue;
    }

    const BigInt rho = RandomBelow(q_mul_n_tilde);
    const BigInt rho2 = RandomBelow(q3_mul_n_tilde);
    const BigInt sigma = RandomBelow(q_mul_n_tilde);
    const BigInt beta = SampleZnStar(n);
    const BigInt gamma_rand = RandomBelow(QPow7(ctx));
    const BigInt tau = RandomBelow(q3_mul_n_tilde);

    const ECPoint u = ECPoint::GeneratorMultiply(alpha_scalar);
    const BigInt z = MulMod(PowMod(h1, witness_x, n_tilde),
                            PowMod(h2, rho, n_tilde), n_tilde);
    const BigInt z2 =
        MulMod(PowMod(h1, alpha, n_tilde), PowMod(h2, rho2, n_tilde), n_tilde);
    const BigInt t = MulMod(PowMod(h1, witness_y, n_tilde),
                            PowMod(h2, sigma, n_tilde), n_tilde);

    BigInt v = MulMod(PowMod(c1, alpha, n2), PowMod(gamma, gamma_rand, n2), n2);
    v = MulMod(v, PowMod(beta, n, n2), n2);
    const BigInt w = MulMod(PowMod(h1, gamma_rand, n_tilde),
                            PowMod(h2, tau, n_tilde), n_tilde);

    A2MtAwcProof proof{
        .u = u,
        .z = z,
        .z2 = z2,
        .t = t,
        .v = v,
        .w = w,
    };
    const Scalar e_scalar = BuildA2MtAwcChallenge(ctx, n, gamma, verifier_aux,
                                                  c1, c2, statement_x, proof);
    const BigInt e = e_scalar.mp_value();

    const BigInt s = MulMod(PowMod(witness_r, e, n), beta, n);
    const BigInt s1 = (e * witness_x) + alpha;
    const BigInt s2 = (e * rho) + rho2;
    const BigInt t1 = (e * witness_y) + gamma_rand;
    const BigInt t2 = (e * sigma) + tau;
    if (s1 > QPow3(ctx) || t1 > QPow7(ctx)) {
      continue;
    }
    proof.s = s;
    proof.s1 = s1;
    proof.s2 = s2;
    proof.t1 = t1;
    proof.t2 = t2;
    return proof;
  }
}

bool VerifyA2MtAwc(const MtaProofContext& ctx, const BigInt& n,
                   const AuxRsaParams& verifier_aux, const BigInt& c1,
                   const BigInt& c2, const ECPoint& statement_x,
                   const A2MtAwcProof& proof) {
  const BigInt n2 = n * n;
  const BigInt gamma = n + BigInt(1);
  const BigInt n_tilde = verifier_aux.n_tilde;
  const BigInt h1 = verifier_aux.h1;
  const BigInt h2 = verifier_aux.h2;

  if (!IsInRange(c1, n2) || !IsInRange(c2, n2) || !IsInRange(proof.v, n2) ||
      !IsInRange(proof.z, n_tilde) || !IsInRange(proof.z2, n_tilde) ||
      !IsInRange(proof.t, n_tilde) || !IsInRange(proof.w, n_tilde) ||
      !IsZnStarElement(proof.s, n)) {
    return false;
  }
  if (proof.s1 < 0 || proof.s1 > QPow3(ctx) || proof.t1 < 0 ||
      proof.t1 > QPow7(ctx) || proof.s2 < 0 || proof.t2 < 0) {
    return false;
  }

  const Scalar e_scalar = BuildA2MtAwcChallenge(ctx, n, gamma, verifier_aux, c1,
                                                c2, statement_x, proof);

  try {
    const Scalar s1_mod_q(proof.s1, ctx.group);
    if (s1_mod_q.value() == 0) {
      return false;
    }
    const ECPoint lhs_curve = ECPoint::GeneratorMultiply(s1_mod_q);
    ECPoint rhs_curve = proof.u;
    if (e_scalar.value() != 0) {
      rhs_curve = rhs_curve.Add(statement_x.Mul(e_scalar));
    }
    if (lhs_curve != rhs_curve) {
      return false;
    }
  } catch (const std::exception&) {
    return false;
  }

  const BigInt e = e_scalar.mp_value();
  const BigInt lhs_nt_1 = MulMod(PowMod(h1, proof.s1, n_tilde),
                                 PowMod(h2, proof.s2, n_tilde), n_tilde);
  const BigInt rhs_nt_1 =
      MulMod(PowMod(proof.z, e, n_tilde), proof.z2, n_tilde);
  if (lhs_nt_1 != rhs_nt_1) {
    return false;
  }

  const BigInt lhs_nt_2 = MulMod(PowMod(h1, proof.t1, n_tilde),
                                 PowMod(h2, proof.t2, n_tilde), n_tilde);
  const BigInt rhs_nt_2 = MulMod(PowMod(proof.t, e, n_tilde), proof.w, n_tilde);
  if (lhs_nt_2 != rhs_nt_2) {
    return false;
  }

  BigInt lhs_paillier =
      MulMod(PowMod(c1, proof.s1, n2), PowMod(proof.s, n, n2), n2);
  lhs_paillier = MulMod(lhs_paillier, PowMod(gamma, proof.t1, n2), n2);
  const BigInt rhs_paillier = MulMod(PowMod(c2, e, n2), proof.v, n2);
  return lhs_paillier == rhs_paillier;
}

A3MtAProof ProveA3MtA(const MtaProofContext& ctx, const BigInt& n,
                      const AuxRsaParams& verifier_aux, const BigInt& c1,
                      const BigInt& c2, const BigInt& witness_x,
                      const BigInt& witness_y, const BigInt& witness_r) {
  const BigInt n2 = n * n;
  const BigInt gamma = n + BigInt(1);
  const BigInt n_tilde = verifier_aux.n_tilde;
  const BigInt h1 = verifier_aux.h1;
  const BigInt h2 = verifier_aux.h2;
  const BigInt q_mul_n_tilde = ctx.group->order() * n_tilde;
  const BigInt q3_mul_n_tilde = QPow3(ctx) * n_tilde;

  while (true) {
    const BigInt alpha = RandomBelow(QPow3(ctx));
    const BigInt rho = RandomBelow(q_mul_n_tilde);
    const BigInt rho2 = RandomBelow(q3_mul_n_tilde);
    const BigInt sigma = RandomBelow(q_mul_n_tilde);
    const BigInt beta = SampleZnStar(n);
    const BigInt gamma_rand = RandomBelow(QPow7(ctx));
    const BigInt tau = RandomBelow(q3_mul_n_tilde);

    const BigInt z = MulMod(PowMod(h1, witness_x, n_tilde),
                            PowMod(h2, rho, n_tilde), n_tilde);
    const BigInt z2 =
        MulMod(PowMod(h1, alpha, n_tilde), PowMod(h2, rho2, n_tilde), n_tilde);
    const BigInt t = MulMod(PowMod(h1, witness_y, n_tilde),
                            PowMod(h2, sigma, n_tilde), n_tilde);
    BigInt v = MulMod(PowMod(c1, alpha, n2), PowMod(gamma, gamma_rand, n2), n2);
    v = MulMod(v, PowMod(beta, n, n2), n2);
    const BigInt w = MulMod(PowMod(h1, gamma_rand, n_tilde),
                            PowMod(h2, tau, n_tilde), n_tilde);

    A3MtAProof proof{
        .z = z,
        .z2 = z2,
        .t = t,
        .v = v,
        .w = w,
    };
    const Scalar e_scalar =
        BuildA3MtAChallenge(ctx, n, gamma, verifier_aux, c1, c2, proof);
    const BigInt e = e_scalar.mp_value();

    const BigInt s = MulMod(PowMod(witness_r, e, n), beta, n);
    const BigInt s1 = (e * witness_x) + alpha;
    const BigInt s2 = (e * rho) + rho2;
    const BigInt t1 = (e * witness_y) + gamma_rand;
    const BigInt t2 = (e * sigma) + tau;
    if (s1 > QPow3(ctx) || t1 > QPow7(ctx)) {
      continue;
    }
    proof.s = s;
    proof.s1 = s1;
    proof.s2 = s2;
    proof.t1 = t1;
    proof.t2 = t2;
    return proof;
  }
}

bool VerifyA3MtA(const MtaProofContext& ctx, const BigInt& n,
                 const AuxRsaParams& verifier_aux, const BigInt& c1,
                 const BigInt& c2, const A3MtAProof& proof) {
  const BigInt n2 = n * n;
  const BigInt gamma = n + BigInt(1);
  const BigInt n_tilde = verifier_aux.n_tilde;
  const BigInt h1 = verifier_aux.h1;
  const BigInt h2 = verifier_aux.h2;

  if (!IsInRange(c1, n2) || !IsInRange(c2, n2) || !IsInRange(proof.v, n2) ||
      !IsInRange(proof.z, n_tilde) || !IsInRange(proof.z2, n_tilde) ||
      !IsInRange(proof.t, n_tilde) || !IsInRange(proof.w, n_tilde) ||
      !IsZnStarElement(proof.s, n)) {
    return false;
  }
  if (proof.s1 < 0 || proof.s1 > QPow3(ctx) || proof.t1 < 0 ||
      proof.t1 > QPow7(ctx) || proof.s2 < 0 || proof.t2 < 0) {
    return false;
  }

  const Scalar e_scalar =
      BuildA3MtAChallenge(ctx, n, gamma, verifier_aux, c1, c2, proof);
  const BigInt e = e_scalar.mp_value();

  const BigInt lhs_nt_1 = MulMod(PowMod(h1, proof.s1, n_tilde),
                                 PowMod(h2, proof.s2, n_tilde), n_tilde);
  const BigInt rhs_nt_1 =
      MulMod(PowMod(proof.z, e, n_tilde), proof.z2, n_tilde);
  if (lhs_nt_1 != rhs_nt_1) {
    return false;
  }

  const BigInt lhs_nt_2 = MulMod(PowMod(h1, proof.t1, n_tilde),
                                 PowMod(h2, proof.t2, n_tilde), n_tilde);
  const BigInt rhs_nt_2 = MulMod(PowMod(proof.t, e, n_tilde), proof.w, n_tilde);
  if (lhs_nt_2 != rhs_nt_2) {
    return false;
  }

  BigInt lhs_paillier =
      MulMod(PowMod(c1, proof.s1, n2), PowMod(proof.s, n, n2), n2);
  lhs_paillier = MulMod(lhs_paillier, PowMod(gamma, proof.t1, n2), n2);
  const BigInt rhs_paillier = MulMod(PowMod(c2, e, n2), proof.v, n2);
  return lhs_paillier == rhs_paillier;
}

std::shared_ptr<const core::mta::ProofBackend> BuildGg19ProofBackend() {
  auto backend = std::make_shared<core::mta::ProofBackend>();
  backend->prove_a1_range =
      [](const MtaProofContext& ctx, const BigInt& n,
         const AuxRsaParams& verifier_aux, const BigInt& c,
         const BigInt& witness_m, const BigInt& witness_r) {
        return tecdsa::ecdsa::proofs::ToCoreA1RangeProof(
            tecdsa::ecdsa::proofs::ProveA1Range(ctx, n, verifier_aux, c,
                                                witness_m, witness_r));
      };
  backend->verify_a1_range =
      [](const MtaProofContext& ctx, const BigInt& n,
         const AuxRsaParams& verifier_aux, const BigInt& c,
         const core::mta::A1RangeProof& proof) {
        return tecdsa::ecdsa::proofs::VerifyA1Range(ctx, n, verifier_aux, c,
                                                    FromCoreA1RangeProof(proof));
      };
  backend->prove_a2_mtawc =
      [](const MtaProofContext& ctx, const BigInt& n,
         const AuxRsaParams& verifier_aux, const BigInt& c1, const BigInt& c2,
         const ECPoint& statement_x, const BigInt& witness_x,
         const BigInt& witness_y, const BigInt& witness_r) {
        return tecdsa::ecdsa::proofs::ToCoreA2MtAwcProof(
            tecdsa::ecdsa::proofs::ProveA2MtAwc(
                ctx, n, verifier_aux, c1, c2, statement_x, witness_x,
                witness_y, witness_r));
      };
  backend->verify_a2_mtawc =
      [](const MtaProofContext& ctx, const BigInt& n,
         const AuxRsaParams& verifier_aux, const BigInt& c1, const BigInt& c2,
         const ECPoint& statement_x, const core::mta::A2MtAwcProof& proof) {
        return tecdsa::ecdsa::proofs::VerifyA2MtAwc(
            ctx, n, verifier_aux, c1, c2, statement_x,
            FromCoreA2MtAwcProof(proof));
      };
  backend->prove_a3_mta =
      [](const MtaProofContext& ctx, const BigInt& n,
         const AuxRsaParams& verifier_aux, const BigInt& c1, const BigInt& c2,
         const BigInt& witness_x, const BigInt& witness_y,
         const BigInt& witness_r) {
        return tecdsa::ecdsa::proofs::ToCoreA3MtAProof(
            tecdsa::ecdsa::proofs::ProveA3MtA(ctx, n, verifier_aux, c1, c2,
                                              witness_x, witness_y,
                                              witness_r));
      };
  backend->verify_a3_mta =
      [](const MtaProofContext& ctx, const BigInt& n,
         const AuxRsaParams& verifier_aux, const BigInt& c1, const BigInt& c2,
         const core::mta::A3MtAProof& proof) {
        return tecdsa::ecdsa::proofs::VerifyA3MtA(
            ctx, n, verifier_aux, c1, c2, FromCoreA3MtAProof(proof));
      };
  return backend;
}

}  // namespace tecdsa::ecdsa::proofs
