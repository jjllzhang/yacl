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

#pragma once

#include "yacl/crypto/experimental/threshold_ecdsa/core/commitment/commitment.h"

namespace tecdsa {

using CommitmentResult = core::commitment::CommitmentResult;
using core::commitment::CommitMessage;
using core::commitment::ComputeCommitment;
using core::commitment::VerifyCommitment;

inline CommitmentResult CommitMessage(const std::string& domain,
                                      std::span<const uint8_t> message,
                                      size_t randomness_len = 32) {
  return core::commitment::CommitMessage(core::DefaultEcdsaSuite(), domain,
                                         message, randomness_len);
}

inline Bytes ComputeCommitment(const std::string& domain,
                               std::span<const uint8_t> message,
                               std::span<const uint8_t> randomness) {
  return core::commitment::ComputeCommitment(core::DefaultEcdsaSuite(), domain,
                                             message, randomness);
}

inline bool VerifyCommitment(const std::string& domain,
                             std::span<const uint8_t> message,
                             std::span<const uint8_t> randomness,
                             std::span<const uint8_t> commitment) {
  return core::commitment::VerifyCommitment(core::DefaultEcdsaSuite(), domain,
                                            message, randomness, commitment);
}

}  // namespace tecdsa
