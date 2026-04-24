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

#include <cstddef>
#include <memory>
#include <vector>

#include "yacl/crypto/experimental/threshold_signatures/common/ids.h"
#include "yacl/crypto/experimental/threshold_signatures/core/algebra/point.h"
#include "yacl/crypto/experimental/threshold_signatures/core/algebra/scalar.h"
#include "yacl/crypto/experimental/threshold_signatures/core/suite/group_context.h"

namespace tecdsa::core::vss {

Scalar RandomNonZeroScalar(const std::shared_ptr<const GroupContext>& group);

Scalar EvaluatePolynomialAt(const std::vector<Scalar>& coefficients,
                            PartyIndex party_id);

std::vector<ECPoint> BuildCommitments(
    const std::vector<Scalar>& coefficients);

bool VerifyShareForReceiver(PartyIndex receiver_id, size_t threshold,
                            const std::vector<ECPoint>& commitments,
                            const Scalar& share);

}  // namespace tecdsa::core::vss
