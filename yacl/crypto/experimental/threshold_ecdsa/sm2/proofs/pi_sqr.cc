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

#include "yacl/crypto/experimental/threshold_ecdsa/sm2/proofs/pi_sqr.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <span>
#include <string>

#include "yacl/crypto/experimental/threshold_ecdsa/common/errors.h"
#include "yacl/crypto/experimental/threshold_ecdsa/core/encoding/byte_io.h"
#include "yacl/crypto/experimental/threshold_ecdsa/core/encoding/encoding.h"
#include "yacl/crypto/experimental/threshold_ecdsa/core/paillier/aux_proofs_internal.h"
#include "yacl/crypto/experimental/threshold_ecdsa/core/transcript/transcript.h"
#include "yacl/crypto/experimental/threshold_ecdsa/crypto/bigint_utils.h"
#include "yacl/crypto/experimental/threshold_ecdsa/crypto/random.h"

namespace tecdsa::sm2::proofs {
namespace {

namespace spi = tecdsa::core::paillier_internal;

constexpr char kPiSqrProofName[] = "PiSqr";

void AppendVerifierContext(core::transcript::Transcript* transcript,
                           const core::paillier::StrictProofVerifierContext& context) {
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

std::string BuildProofId(
    const core::paillier::StrictProofVerifierContext& context,
    const char* proof_name) {
  return context.proof_domain_prefix + "/" + proof_name + "/v1";
}

Bytes ExpandHashStream(core::HashId hash_id, std::span<const uint8_t> seed,
                       size_t out_len) {
  if (out_len == 0) {
    return {};
  }

  Bytes out;
  out.reserve(out_len);
  uint32_t block = 0;
  while (out.size() < out_len) {
    Bytes block_input(seed.begin(), seed.end());
    core::encoding::AppendU32Be(block, &block_input);
    const Bytes digest = tecdsa::core::Hash(hash_id, block_input);
    const size_t remaining = out_len - out.size();
    const size_t take = std::min(remaining, digest.size());
    out.insert(out.end(), digest.begin(),
               digest.begin() + static_cast<std::ptrdiff_t>(take));
    ++block;
  }
  return out;
}

BigInt DerivePiSqrChallenge(
    const BigInt& modulus_n,
    const core::paillier::StrictProofVerifierContext& context,
    std::span<const uint8_t> nonce, uint32_t round_idx) {
  if (modulus_n <= 3) {
    TECDSA_THROW_ARGUMENT("pi_sqr challenge requires modulus N > 3");
  }

  const Bytes n_bytes = core::encoding::EncodeMpInt(modulus_n);
  const size_t byte_len = std::max<size_t>(1, (modulus_n.BitCount() + 7) / 8);

  for (uint32_t attempt = 0; attempt < spi::kMaxSquareFreeGmr98ChallengeAttempts;
       ++attempt) {
    core::transcript::Transcript transcript(context.transcript_hash);
    transcript.append_proof_id(BuildProofId(context, kPiSqrProofName));
    AppendVerifierContext(&transcript, context);
    transcript.append_fields({
        core::transcript::TranscriptFieldRef{.label = "N", .data = n_bytes},
        core::transcript::TranscriptFieldRef{.label = "nonce", .data = nonce},
    });
    transcript.append_u32_be("round", round_idx);
    transcript.append_u32_be("attempt", attempt);

    const Bytes seed =
        tecdsa::core::Hash(context.transcript_hash, transcript.bytes());
    const Bytes expanded = ExpandHashStream(context.transcript_hash, seed,
                                           byte_len);
    BigInt candidate = bigint::FromBigEndian(expanded);
    candidate = spi::NormalizeMod(candidate, modulus_n);
    if (spi::IsZnStarResidue(candidate, modulus_n)) {
      return candidate;
    }
  }

  TECDSA_THROW("failed to derive pi_sqr challenge in Z*_N");
}

}  // namespace

PiSqrProof BuildPiSqrProof(
    const BigInt& modulus_n, const BigInt& lambda_n,
    const core::paillier::StrictProofVerifierContext& context) {
  if (modulus_n <= 3) {
    TECDSA_THROW_ARGUMENT("pi_sqr proof requires modulus N > 3");
  }
  if (lambda_n <= 1) {
    TECDSA_THROW_ARGUMENT("pi_sqr proof requires lambda(N) > 1");
  }
  if (!core::paillier::IsLikelySquareFreeModulus(modulus_n)) {
    TECDSA_THROW_ARGUMENT("pi_sqr proof requires likely square-free modulus");
  }

  const auto d_opt = spi::InvertMod(spi::NormalizeMod(modulus_n, lambda_n),
                                    lambda_n);
  if (!d_opt.has_value()) {
    TECDSA_THROW_ARGUMENT("pi_sqr proof requires gcd(N, lambda(N)) = 1");
  }
  const BigInt d = *d_opt;
  const Bytes nonce = Csprng::RandomBytes(spi::kStrictNonceLen);

  spi::SquareFreeGmr98Payload payload;
  payload.nonce = nonce;
  payload.rounds = static_cast<uint32_t>(spi::kSquareFreeGmr98Rounds);
  payload.roots.reserve(payload.rounds);

  for (uint32_t round = 0; round < payload.rounds; ++round) {
    const BigInt challenge =
        DerivePiSqrChallenge(modulus_n, context, nonce, round);
    const BigInt root = spi::PowMod(challenge, d, modulus_n);
    if (!spi::IsZnStarResidue(root, modulus_n)) {
      TECDSA_THROW("pi_sqr proof generated invalid root");
    }
    if (spi::PowMod(root, modulus_n, modulus_n) != challenge) {
      TECDSA_THROW("pi_sqr proof generated inconsistent root equation");
    }
    payload.roots.push_back(root);
  }

  return PiSqrProof{.blob = spi::EncodeSquareFreeGmr98Payload(payload)};
}

bool VerifyPiSqrProof(
    const BigInt& modulus_n, const PiSqrProof& proof,
    const core::paillier::StrictProofVerifierContext& context) {
  if (!core::paillier::IsLikelySquareFreeModulus(modulus_n) ||
      proof.blob.empty()) {
    return false;
  }

  spi::SquareFreeGmr98Payload payload;
  try {
    payload = spi::DecodeSquareFreeGmr98Payload(proof.blob);
  } catch (const std::exception&) {
    return false;
  }
  if (payload.nonce.size() != spi::kStrictNonceLen ||
      payload.rounds != spi::kSquareFreeGmr98Rounds ||
      payload.roots.size() != payload.rounds) {
    return false;
  }

  for (uint32_t round = 0; round < payload.rounds; ++round) {
    const BigInt& root = payload.roots[round];
    if (!spi::IsZnStarResidue(root, modulus_n)) {
      return false;
    }
    const BigInt challenge =
        DerivePiSqrChallenge(modulus_n, context, payload.nonce, round);
    if (spi::PowMod(root, modulus_n, modulus_n) != challenge) {
      return false;
    }
  }
  return true;
}

}  // namespace tecdsa::sm2::proofs
