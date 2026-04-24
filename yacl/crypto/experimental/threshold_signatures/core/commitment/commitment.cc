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

#include "yacl/crypto/experimental/threshold_signatures/core/commitment/commitment.h"

#include <algorithm>

#include "yacl/crypto/experimental/threshold_signatures/core/encoding/encoding.h"
#include "yacl/crypto/experimental/threshold_signatures/core/suite/suite.h"
#include "yacl/crypto/experimental/threshold_signatures/core/random/csprng.h"

namespace tecdsa::core::commitment {
namespace {

constexpr char kCommitPrefix[] = "GG2019/commit/v1";

void AppendField(std::span<const uint8_t> field, Bytes* out) {
  encoding::AppendSizedField(field, out,
                             "Commitment field exceeds uint32 length");
}

Bytes BuildCommitPreimage(const std::string& domain,
                          std::span<const uint8_t> message,
                          std::span<const uint8_t> randomness) {
  Bytes preimage;
  preimage.reserve(sizeof(kCommitPrefix) - 1 + domain.size() + message.size() +
                   randomness.size() + 12);

  const std::span<const uint8_t> prefix_bytes(
      reinterpret_cast<const uint8_t*>(kCommitPrefix),
      sizeof(kCommitPrefix) - 1);
  const std::span<const uint8_t> domain_bytes(
      reinterpret_cast<const uint8_t*>(domain.data()), domain.size());

  AppendField(prefix_bytes, &preimage);
  AppendField(domain_bytes, &preimage);
  AppendField(message, &preimage);
  AppendField(randomness, &preimage);
  return preimage;
}

}  // namespace

CommitmentResult CommitMessage(HashId hash_id, const std::string& domain,
                               std::span<const uint8_t> message,
                               size_t randomness_len) {
  CommitmentResult out;
  out.randomness = Csprng::RandomBytes(randomness_len);
  out.commitment =
      ComputeCommitment(hash_id, domain, message, out.randomness);
  return out;
}

CommitmentResult CommitMessage(const ThresholdSuite& suite,
                               const std::string& domain,
                               std::span<const uint8_t> message,
                               size_t randomness_len) {
  return CommitMessage(suite.commitment_hash, domain, message, randomness_len);
}

Bytes ComputeCommitment(HashId hash_id, const std::string& domain,
                        std::span<const uint8_t> message,
                        std::span<const uint8_t> randomness) {
  const Bytes preimage = BuildCommitPreimage(domain, message, randomness);
  return Hash(hash_id, preimage);
}

Bytes ComputeCommitment(const ThresholdSuite& suite, const std::string& domain,
                        std::span<const uint8_t> message,
                        std::span<const uint8_t> randomness) {
  return ComputeCommitment(suite.commitment_hash, domain, message, randomness);
}

bool VerifyCommitment(HashId hash_id, const std::string& domain,
                      std::span<const uint8_t> message,
                      std::span<const uint8_t> randomness,
                      std::span<const uint8_t> commitment) {
  const Bytes expected = ComputeCommitment(hash_id, domain, message, randomness);
  return std::equal(expected.begin(), expected.end(), commitment.begin(),
                    commitment.end());
}

bool VerifyCommitment(const ThresholdSuite& suite, const std::string& domain,
                      std::span<const uint8_t> message,
                      std::span<const uint8_t> randomness,
                      std::span<const uint8_t> commitment) {
  return VerifyCommitment(suite.commitment_hash, domain, message, randomness,
                          commitment);
}

}  // namespace tecdsa::core::commitment
