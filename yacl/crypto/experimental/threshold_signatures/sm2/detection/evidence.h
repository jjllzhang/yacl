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

#include "yacl/crypto/experimental/threshold_signatures/sm2/detection/types.h"

namespace tecdsa::sm2::detection {

inline AbortEvidence MakeAbort(
    AbortStage stage, EvidenceKind evidence_kind, const Bytes& session_id,
    PartyIndex reporter, std::string reason,
    std::optional<PartyIndex> culprit = std::nullopt,
    std::optional<Bytes> instance_id = std::nullopt) {
  return AbortEvidence{
      .session_id = session_id,
      .stage = stage,
      .evidence_kind = evidence_kind,
      .reporter = reporter,
      .culprit = culprit,
      .instance_id = std::move(instance_id),
      .reason = std::move(reason),
  };
}

}  // namespace tecdsa::sm2::detection
