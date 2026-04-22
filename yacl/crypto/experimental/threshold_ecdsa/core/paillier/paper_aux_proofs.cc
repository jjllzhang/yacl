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

#include "yacl/crypto/experimental/threshold_ecdsa/core/paillier/paper_aux_proofs.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <optional>
#include <span>
#include <string>
#include <vector>

#include "yacl/crypto/experimental/threshold_ecdsa/common/errors.h"
#include "yacl/crypto/experimental/threshold_ecdsa/core/encoding/byte_io.h"
#include "yacl/crypto/experimental/threshold_ecdsa/core/encoding/encoding.h"
#include "yacl/crypto/experimental/threshold_ecdsa/core/paillier/aux_proofs_internal.h"
#include "yacl/crypto/experimental/threshold_ecdsa/core/paillier/paper_aux_setup.h"
#include "yacl/crypto/experimental/threshold_ecdsa/core/transcript/transcript.h"
#include "yacl/crypto/experimental/threshold_ecdsa/crypto/bigint_utils.h"
#include "yacl/crypto/experimental/threshold_ecdsa/crypto/hash.h"

namespace tecdsa::core::paillier {
namespace {

constexpr char kPiModProofName[] = "PiMod";
constexpr char kPiPrmProofName[] = "PiPrm";
constexpr uint32_t kPiModRounds = 128;
constexpr uint32_t kPiPrmRounds = 128;

struct PiModRoundPayload {
  BigInt x;
  uint8_t a = 0;
  uint8_t b = 0;
  BigInt z;
};

struct PiModPayload {
  BigInt w;
  std::vector<PiModRoundPayload> rounds;
};

struct PiPrmPayload {
  std::vector<BigInt> commitments;
  std::vector<BigInt> responses;
};

void AppendVerifierContext(transcript::Transcript* transcript,
                           const StrictProofVerifierContext& context) {
  if (!context.session_id.empty()) {
    transcript->append_session_id(context.session_id);
  }
  if (context.prover_id.has_value()) {
    transcript->append_u32_be("prover_id", *context.prover_id);
  }
  if (context.verifier_id.has_value()) {
    transcript->append_u32_be("verifier_id", *context.verifier_id);
  }
}

std::string BuildProofId(const StrictProofVerifierContext& context,
                         const char* proof_name) {
  return context.proof_domain_prefix + "/" + proof_name + "/v1";
}

void AppendMpIntField(const BigInt& value, Bytes* out) {
  const Bytes encoded = encoding::EncodeMpInt(value);
  encoding::AppendSizedField(encoded, out);
}

BigInt ReadMpIntField(std::span<const uint8_t> input, size_t* offset,
                      const char* field_name) {
  const Bytes encoded =
      encoding::ReadSizedField(input, offset,
                               paillier_internal::kMaxStrictFieldLen,
                               field_name);
  return encoding::DecodeMpInt(encoded,
                               paillier_internal::kMaxStrictFieldLen);
}

Bytes ExpandHashStream(HashId hash_id, std::span<const uint8_t> seed,
                       size_t out_len) {
  if (out_len == 0) {
    return {};
  }

  Bytes out;
  out.reserve(out_len);
  uint32_t block = 0;
  while (out.size() < out_len) {
    Bytes block_input(seed.begin(), seed.end());
    encoding::AppendU32Be(block, &block_input);
    const Bytes digest = Hash(hash_id, block_input);
    const size_t remaining = out_len - out.size();
    const size_t take = std::min(remaining, digest.size());
    out.insert(out.end(), digest.begin(),
               digest.begin() + static_cast<std::ptrdiff_t>(take));
    ++block;
  }
  return out;
}

BigInt NormalizeMod(const BigInt& value, const BigInt& modulus) {
  return paillier_internal::NormalizeMod(value, modulus);
}

BigInt PowMod(const BigInt& base, const BigInt& exp, const BigInt& modulus) {
  return paillier_internal::PowMod(base, exp, modulus);
}

BigInt MulMod(const BigInt& lhs, const BigInt& rhs, const BigInt& modulus) {
  return paillier_internal::MulMod(lhs, rhs, modulus);
}

std::optional<BigInt> TryInvertMod(const BigInt& value, const BigInt& modulus) {
  return paillier_internal::InvertMod(value, modulus);
}

bool IsQuadraticResidueModPrime(const BigInt& value, const BigInt& prime,
                                const BigInt& prime_subgroup_order) {
  const BigInt reduced = NormalizeMod(value, prime);
  if (reduced == 0) {
    return false;
  }
  return PowMod(reduced, prime_subgroup_order, prime) == 1;
}

BigInt CombineCrt(const BigInt& mod_p_value, const BigInt& mod_q_value,
                  const BigInt& prime_p, const BigInt& prime_q) {
  const auto p_inv_mod_q = TryInvertMod(prime_p, prime_q);
  if (!p_inv_mod_q.has_value()) {
    TECDSA_THROW("CRT combination requires coprime moduli");
  }
  const BigInt delta =
      NormalizeMod((mod_q_value - mod_p_value) * *p_inv_mod_q, prime_q);
  return NormalizeMod(mod_p_value + (prime_p * delta), prime_p * prime_q);
}

BigInt MakeJacobiMinusOneWitnessElement(const PaperAuxSetupWitness& witness) {
  return CombineCrt(witness.P_tilde - 1, BigInt(1), witness.P_tilde,
                    witness.Q_tilde);
}

int JacobiSymbol(BigInt value, BigInt modulus) {
  if (modulus <= 0 || modulus.IsEven()) {
    TECDSA_THROW_ARGUMENT("Jacobi symbol requires a positive odd modulus");
  }

  value = NormalizeMod(value, modulus);
  int sign = 1;
  while (value != 0) {
    while (value.IsEven()) {
      value /= 2;
      const auto modulus_mod_8 = modulus % 8;
      if (modulus_mod_8 == 3 || modulus_mod_8 == 5) {
        sign = -sign;
      }
    }
    std::swap(value, modulus);
    if ((value % 4) == 3 && (modulus % 4) == 3) {
      sign = -sign;
    }
    value = NormalizeMod(value, modulus);
  }
  return modulus == 1 ? sign : 0;
}

bool HasJacobiSymbolMinusOne(const BigInt& value, const BigInt& modulus) {
  return IsZnStarElement(value, modulus) && JacobiSymbol(value, modulus) == -1;
}

std::vector<BigInt> DerivePiModChallenges(
    const AuxRsaParams& params, const StrictProofVerifierContext& context,
    const BigInt& w) {
  transcript::Transcript base(context.transcript_hash);
  base.append_proof_id(BuildProofId(context, kPiModProofName));
  AppendVerifierContext(&base, context);
  const Bytes n_bytes = encoding::EncodeMpInt(params.n_tilde);
  const Bytes w_bytes = encoding::EncodeMpInt(w);
  base.append_fields({
      transcript::TranscriptFieldRef{.label = "Ntilde", .data = n_bytes},
      transcript::TranscriptFieldRef{.label = "w", .data = w_bytes},
  });
  base.append_u32_be("rounds", kPiModRounds);

  const size_t byte_len =
      std::max<size_t>(1, (params.n_tilde.BitCount() + 7) / 8);
  std::vector<BigInt> challenges;
  challenges.reserve(kPiModRounds);
  for (uint32_t round = 0; round < kPiModRounds; ++round) {
    for (uint32_t attempt = 0;
         attempt < paillier_internal::kMaxSquareFreeGmr98ChallengeAttempts;
         ++attempt) {
      transcript::Transcript round_transcript(context.transcript_hash);
      round_transcript.append_fields({
          transcript::TranscriptFieldRef{
              .label = "base",
              .data = base.bytes(),
          },
      });
      round_transcript.append_u32_be("round", round);
      round_transcript.append_u32_be("attempt", attempt);
      const Bytes seed = Hash(context.transcript_hash, round_transcript.bytes());
      const Bytes expanded = ExpandHashStream(context.transcript_hash, seed,
                                             byte_len);
      BigInt candidate = bigint::FromBigEndian(expanded);
      candidate = NormalizeMod(candidate, params.n_tilde);
      if (IsZnStarElement(candidate, params.n_tilde)) {
        challenges.push_back(candidate);
        break;
      }
    }
    if (challenges.size() != round + 1) {
      TECDSA_THROW("failed to derive PiMod challenge in Z*_N");
    }
  }
  return challenges;
}

std::vector<uint8_t> DerivePiPrmChallengeBits(
    const AuxRsaParams& params, const StrictProofVerifierContext& context,
    const std::vector<BigInt>& commitments) {
  transcript::Transcript transcript(context.transcript_hash);
  transcript.append_proof_id(BuildProofId(context, kPiPrmProofName));
  AppendVerifierContext(&transcript, context);
  const Bytes n_bytes = encoding::EncodeMpInt(params.n_tilde);
  const Bytes h1_bytes = encoding::EncodeMpInt(params.h1);
  const Bytes h2_bytes = encoding::EncodeMpInt(params.h2);
  transcript.append_fields({
      transcript::TranscriptFieldRef{.label = "Ntilde", .data = n_bytes},
      transcript::TranscriptFieldRef{.label = "h1", .data = h1_bytes},
      transcript::TranscriptFieldRef{.label = "h2", .data = h2_bytes},
  });
  for (size_t i = 0; i < commitments.size(); ++i) {
    transcript.append("A" + std::to_string(i), encoding::EncodeMpInt(commitments[i]));
  }

  const Bytes seed = Hash(context.transcript_hash, transcript.bytes());
  const Bytes expanded = ExpandHashStream(context.transcript_hash, seed,
                                          (kPiPrmRounds + 7) / 8);
  std::vector<uint8_t> bits;
  bits.reserve(kPiPrmRounds);
  for (uint32_t i = 0; i < kPiPrmRounds; ++i) {
    const uint8_t byte = expanded[i / 8];
    bits.push_back(static_cast<uint8_t>((byte >> (i % 8)) & 0x01));
  }
  return bits;
}

std::optional<std::pair<uint8_t, uint8_t>> SelectPiModMasks(
    const BigInt& y_i, const BigInt& w, const PaperAuxSetupWitness& witness,
    BigInt* adjusted) {
  for (uint8_t a = 0; a <= 1; ++a) {
    for (uint8_t b = 0; b <= 1; ++b) {
      BigInt candidate = y_i;
      if (b == 1) {
        candidate = MulMod(candidate, w, witness.P_tilde * witness.Q_tilde);
      }
      if (a == 1) {
        candidate = NormalizeMod(BigInt(0) - candidate,
                                 witness.P_tilde * witness.Q_tilde);
      }
      if (IsQuadraticResidueModPrime(candidate, witness.P_tilde,
                                     witness.p_tilde) &&
          IsQuadraticResidueModPrime(candidate, witness.Q_tilde,
                                     witness.q_tilde)) {
        *adjusted = candidate;
        return std::make_pair(a, b);
      }
    }
  }
  return std::nullopt;
}

PiModRoundPayload BuildPiModRound(const BigInt& y_i, const BigInt& w,
                                  const PaperAuxSetupWitness& witness) {
  BigInt adjusted;
  const auto masks = SelectPiModMasks(y_i, w, witness, &adjusted);
  if (!masks.has_value()) {
    TECDSA_THROW("failed to select PiMod adjustment bits");
  }

  const auto inv4_p = TryInvertMod(BigInt(4), witness.p_tilde);
  const auto inv4_q = TryInvertMod(BigInt(4), witness.q_tilde);
  if (!inv4_p.has_value() || !inv4_q.has_value()) {
    TECDSA_THROW("failed to invert 4 modulo Blum safe-prime sub-orders");
  }

  const BigInt x_p =
      PowMod(NormalizeMod(adjusted, witness.P_tilde), *inv4_p, witness.P_tilde);
  const BigInt x_q =
      PowMod(NormalizeMod(adjusted, witness.Q_tilde), *inv4_q, witness.Q_tilde);
  const BigInt x = CombineCrt(x_p, x_q, witness.P_tilde, witness.Q_tilde);

  const BigInt phi_n =
      (witness.P_tilde - 1) * (witness.Q_tilde - 1);
  const auto n_inv = TryInvertMod(witness.P_tilde * witness.Q_tilde, phi_n);
  if (!n_inv.has_value()) {
    TECDSA_THROW("PiMod requires gcd(N, phi(N)) = 1");
  }
  const BigInt z = PowMod(y_i, *n_inv, witness.P_tilde * witness.Q_tilde);

  if (PowMod(x, BigInt(4), witness.P_tilde * witness.Q_tilde) != adjusted) {
    TECDSA_THROW("PiMod prover failed to build a valid quartic root");
  }
  if (PowMod(z, witness.P_tilde * witness.Q_tilde,
             witness.P_tilde * witness.Q_tilde) != y_i) {
    TECDSA_THROW("PiMod prover failed to build a valid N-th root");
  }

  return PiModRoundPayload{
      .x = x,
      .a = masks->first,
      .b = masks->second,
      .z = z,
  };
}

Bytes EncodePiModPayload(const PiModPayload& payload) {
  Bytes out;
  AppendMpIntField(payload.w, &out);
  encoding::AppendU32Be(payload.rounds.size(), &out);
  for (const auto& round : payload.rounds) {
    AppendMpIntField(round.x, &out);
    out.push_back(round.a);
    out.push_back(round.b);
    AppendMpIntField(round.z, &out);
  }
  return out;
}

PiModPayload DecodePiModPayload(std::span<const uint8_t> blob) {
  size_t offset = 0;
  PiModPayload payload;
  payload.w = ReadMpIntField(blob, &offset, "PiMod w");
  const uint32_t rounds = encoding::ReadU32Be(blob, &offset);
  payload.rounds.reserve(rounds);
  for (uint32_t i = 0; i < rounds; ++i) {
    PiModRoundPayload round;
    round.x = ReadMpIntField(blob, &offset, "PiMod x");
    if (offset + 2 > blob.size()) {
      TECDSA_THROW_ARGUMENT("PiMod payload truncated on bit flags");
    }
    round.a = blob[offset++];
    round.b = blob[offset++];
    round.z = ReadMpIntField(blob, &offset, "PiMod z");
    payload.rounds.push_back(std::move(round));
  }
  if (offset != blob.size()) {
    TECDSA_THROW_ARGUMENT("PiMod payload has trailing bytes");
  }
  return payload;
}

Bytes EncodePiPrmPayload(const PiPrmPayload& payload) {
  Bytes out;
  encoding::AppendU32Be(payload.commitments.size(), &out);
  for (const BigInt& commitment : payload.commitments) {
    AppendMpIntField(commitment, &out);
  }
  encoding::AppendU32Be(payload.responses.size(), &out);
  for (const BigInt& response : payload.responses) {
    AppendMpIntField(response, &out);
  }
  return out;
}

PiPrmPayload DecodePiPrmPayload(std::span<const uint8_t> blob) {
  size_t offset = 0;
  PiPrmPayload payload;
  const uint32_t commitments_count = encoding::ReadU32Be(blob, &offset);
  payload.commitments.reserve(commitments_count);
  for (uint32_t i = 0; i < commitments_count; ++i) {
    payload.commitments.push_back(
        ReadMpIntField(blob, &offset, "PiPrm commitment"));
  }
  const uint32_t responses_count = encoding::ReadU32Be(blob, &offset);
  payload.responses.reserve(responses_count);
  for (uint32_t i = 0; i < responses_count; ++i) {
    payload.responses.push_back(ReadMpIntField(blob, &offset, "PiPrm response"));
  }
  if (offset != blob.size()) {
    TECDSA_THROW_ARGUMENT("PiPrm payload has trailing bytes");
  }
  return payload;
}

PiPrmPayload BuildPiPrmPayload(const AuxRsaParams& params,
                               const PaperAuxSetupWitness& witness,
                               const StrictProofVerifierContext& context) {
  const BigInt phi_n =
      (witness.P_tilde - 1) * (witness.Q_tilde - 1);
  PiPrmPayload payload;
  payload.commitments.reserve(kPiPrmRounds);
  payload.responses.reserve(kPiPrmRounds);

  std::vector<BigInt> randomness;
  randomness.reserve(kPiPrmRounds);
  for (uint32_t i = 0; i < kPiPrmRounds; ++i) {
    const BigInt a_i = BigInt::RandomLtN(phi_n);
    randomness.push_back(a_i);
    payload.commitments.push_back(PowMod(params.h2, a_i, params.n_tilde));
  }

  const std::vector<uint8_t> challenge_bits =
      DerivePiPrmChallengeBits(params, context, payload.commitments);
  for (uint32_t i = 0; i < kPiPrmRounds; ++i) {
    const BigInt response = NormalizeMod(
        randomness[i] + (challenge_bits[i] == 0 ? BigInt(0) : witness.lambda),
        phi_n);
    payload.responses.push_back(response);
  }
  return payload;
}

}  // namespace

AuxCorrectFormProof BuildAuxCorrectFormProof(
    const AuxRsaParams& params, const PaperAuxSetupWitness& witness,
    const StrictProofVerifierContext& context) {
  if (!ValidatePaperAuxSetup(params, witness)) {
    TECDSA_THROW_ARGUMENT(
        "cannot build paper aux proof from invalid parameters or witness");
  }

  const BigInt w = MakeJacobiMinusOneWitnessElement(witness);
  PiModPayload pi_mod;
  pi_mod.w = w;
  const std::vector<BigInt> y_values = DerivePiModChallenges(params, context, w);
  pi_mod.rounds.reserve(y_values.size());
  for (const BigInt& y_i : y_values) {
    pi_mod.rounds.push_back(BuildPiModRound(y_i, w, witness));
  }

  const PiPrmPayload pi_prm = BuildPiPrmPayload(params, witness, context);
  return AuxCorrectFormProof{
      .pi_mod =
          PiModProof{
              .blob = EncodePiModPayload(pi_mod),
          },
      .pi_prm =
          PiPrmProof{
              .blob = EncodePiPrmPayload(pi_prm),
          },
  };
}

bool VerifyAuxCorrectFormProof(const AuxRsaParams& params,
                               const AuxCorrectFormProof& proof,
                               const StrictProofVerifierContext& context) {
  if (!ValidateAuxRsaParams(params) || proof.pi_mod.blob.empty() ||
      proof.pi_prm.blob.empty()) {
    return false;
  }

  PiModPayload pi_mod;
  PiPrmPayload pi_prm;
  try {
    pi_mod = DecodePiModPayload(proof.pi_mod.blob);
    pi_prm = DecodePiPrmPayload(proof.pi_prm.blob);
  } catch (const std::exception&) {
    return false;
  }

  if (params.n_tilde <= 2 || params.n_tilde.IsEven() || params.n_tilde.IsPrime()) {
    return false;
  }
  if (!HasJacobiSymbolMinusOne(pi_mod.w, params.n_tilde) ||
      pi_mod.rounds.size() != kPiModRounds ||
      pi_prm.commitments.size() != kPiPrmRounds ||
      pi_prm.responses.size() != kPiPrmRounds) {
    return false;
  }

  const std::vector<BigInt> y_values =
      DerivePiModChallenges(params, context, pi_mod.w);
  for (size_t i = 0; i < pi_mod.rounds.size(); ++i) {
    const auto& round = pi_mod.rounds[i];
    if (round.a > 1 || round.b > 1 || !IsZnStarElement(round.x, params.n_tilde) ||
        !IsZnStarElement(round.z, params.n_tilde)) {
      return false;
    }
    BigInt expected = y_values[i];
    if (round.b == 1) {
      expected = MulMod(expected, pi_mod.w, params.n_tilde);
    }
    if (round.a == 1) {
      expected = NormalizeMod(BigInt(0) - expected, params.n_tilde);
    }
    if (PowMod(round.z, params.n_tilde, params.n_tilde) != y_values[i]) {
      return false;
    }
    if (PowMod(round.x, BigInt(4), params.n_tilde) != expected) {
      return false;
    }
  }

  if (!IsZnStarElement(params.h2, params.n_tilde)) {
    return false;
  }
  const std::vector<uint8_t> challenge_bits =
      DerivePiPrmChallengeBits(params, context, pi_prm.commitments);
  for (size_t i = 0; i < pi_prm.commitments.size(); ++i) {
    if (!IsZnStarElement(pi_prm.commitments[i], params.n_tilde) ||
        pi_prm.responses[i] < 0) {
      return false;
    }
    BigInt rhs = pi_prm.commitments[i];
    if (challenge_bits[i] != 0) {
      rhs = MulMod(rhs, params.h1, params.n_tilde);
    }
    if (PowMod(params.h2, pi_prm.responses[i], params.n_tilde) != rhs) {
      return false;
    }
  }
  return true;
}

}  // namespace tecdsa::core::paillier
