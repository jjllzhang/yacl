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

#include <cstdint>
#include <optional>

#include "yacl/crypto/experimental/threshold_signatures/core/mta/proofs.h"

namespace tecdsa::core::mta {

enum class MtaType : uint8_t {
  kMta = 1,
  kMtAwc = 2,
};

inline bool RequiresPublicPoint(MtaType type) {
  return type == MtaType::kMtAwc;
}

// Internal transport object used by PairwiseProductSession. Scheme-owned public
// message types live outside core and adapt to this structure at the boundary.
struct PairwiseProductRequest {
  PartyIndex from = 0;
  PartyIndex to = 0;
  MtaType type = MtaType::kMta;
  Bytes instance_id;
  BigInt c1 = BigInt(0);
  A1RangeProof a1_proof;
};

// Internal transport object used by PairwiseProductSession. Scheme-owned public
// message types live outside core and adapt to this structure at the boundary.
struct PairwiseProductResponse {
  PartyIndex from = 0;
  PartyIndex to = 0;
  MtaType type = MtaType::kMta;
  Bytes instance_id;
  BigInt c2 = BigInt(0);
  std::optional<A2MtAwcProof> a2_proof;
  std::optional<A3MtAProof> a3_proof;
};

}  // namespace tecdsa::core::mta
