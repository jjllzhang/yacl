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

#include "yacl/crypto/experimental/threshold_ecdsa/core/transcript/transcript.h"

#include <array>

#include "yacl/crypto/experimental/threshold_ecdsa/common/errors.h"
#include "yacl/crypto/experimental/threshold_ecdsa/core/encoding/byte_io.h"
#include "yacl/crypto/experimental/threshold_ecdsa/core/suite/suite.h"
#include "yacl/crypto/experimental/threshold_ecdsa/crypto/bigint_utils.h"

namespace tecdsa::core::transcript {
namespace {

std::span<const uint8_t> AsByteSpan(std::string_view value) {
  return std::span<const uint8_t>(
      reinterpret_cast<const uint8_t*>(value.data()), value.size());
}

}  // namespace

Transcript::Transcript(HashId challenge_hash) : challenge_hash_(challenge_hash) {}

void Transcript::append(std::string_view label, std::span<const uint8_t> data) {
  if (label.size() > UINT32_MAX || data.size() > UINT32_MAX) {
    TECDSA_THROW_ARGUMENT("Transcript field exceeds uint32 length");
  }

  encoding::AppendU32Be(static_cast<uint32_t>(label.size()), &transcript_);
  transcript_.insert(transcript_.end(), label.begin(), label.end());

  encoding::AppendU32Be(static_cast<uint32_t>(data.size()), &transcript_);
  transcript_.insert(transcript_.end(), data.begin(), data.end());
}

void Transcript::append_ascii(std::string_view label, std::string_view ascii) {
  append(label, AsByteSpan(ascii));
}

void Transcript::append_proof_id(std::string_view proof_id) {
  append_ascii("proof_id", proof_id);
}

void Transcript::append_session_id(std::span<const uint8_t> session_id) {
  append("session_id", session_id);
}

void Transcript::append_u32_be(std::string_view label, uint32_t value) {
  std::array<uint8_t, 4> encoded = {
      static_cast<uint8_t>((value >> 24) & 0xFF),
      static_cast<uint8_t>((value >> 16) & 0xFF),
      static_cast<uint8_t>((value >> 8) & 0xFF),
      static_cast<uint8_t>(value & 0xFF),
  };
  append(label, encoded);
}

void Transcript::append_fields(
    std::initializer_list<TranscriptFieldRef> fields) {
  for (const TranscriptFieldRef& field : fields) {
    append(field.label, field.data);
  }
}

Transcript::BigInt Transcript::challenge_bigint_mod(
    const BigInt& modulus) const {
  if (modulus <= BigInt(0)) {
    TECDSA_THROW_ARGUMENT("Transcript challenge modulus must be positive");
  }
  return bigint::NormalizeMod(bigint::FromBigEndian(Hash(challenge_hash_, transcript_)),
                              modulus);
}

Scalar Transcript::challenge_scalar(
    const std::shared_ptr<const GroupContext>& group) const {
  return Scalar::FromBigEndianModQ(Hash(challenge_hash_, transcript_), group);
}

const Bytes& Transcript::bytes() const { return transcript_; }

}  // namespace tecdsa::core::transcript
