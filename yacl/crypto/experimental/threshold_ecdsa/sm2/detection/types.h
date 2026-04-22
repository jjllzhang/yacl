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

#include <optional>
#include <string>

#include "yacl/crypto/experimental/threshold_ecdsa/common/bytes.h"
#include "yacl/crypto/experimental/threshold_ecdsa/common/ids.h"

namespace tecdsa::sm2::detection {

enum class AbortStage {
  kKeygen = 1,
  kOffline = 2,
  kOnline = 3,
};

enum class AbortKind {
  kIdentifiable = 1,
  kUnattributed = 2,
};

enum class EvidenceKind {
  kMtaProof = 1,
  kNonceProof = 2,
  kPartialSignature = 3,
  kGammaProof = 4,
  kSquareFreeProof = 5,
  kCommitment = 6,
};

struct AbortEvidence {
  Bytes session_id;
  AbortStage stage = AbortStage::kKeygen;
  EvidenceKind evidence_kind = EvidenceKind::kMtaProof;
  AbortKind kind = AbortKind::kUnattributed;
  PartyIndex reporter = 0;
  std::optional<PartyIndex> culprit;
  std::optional<Bytes> instance_id;
  std::string reason;
};

template <typename T>
struct DetectionResult {
  std::optional<T> value;
  std::optional<AbortEvidence> abort;

  bool ok() const { return value.has_value(); }
};

}  // namespace tecdsa::sm2::detection
