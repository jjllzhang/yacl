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

#include <unordered_map>
#include <vector>

#include "yacl/crypto/experimental/threshold_ecdsa/common/ids.h"
#include "yacl/crypto/experimental/threshold_ecdsa/core/algebra/point.h"
#include "yacl/crypto/experimental/threshold_ecdsa/core/algebra/scalar.h"
#include "yacl/crypto/experimental/threshold_ecdsa/core/suite/group_context.h"

namespace tecdsa::core::vss {

std::unordered_map<PartyIndex, Scalar> ComputeLagrangeAtZero(
    const std::vector<PartyIndex>& participants,
    const std::shared_ptr<const GroupContext>& group);

ECPoint SumPointsOrThrow(const std::vector<ECPoint>& points);

}  // namespace tecdsa::core::vss
