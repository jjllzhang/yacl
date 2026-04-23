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

#include "yacl/crypto/experimental/threshold_ecdsa/core/mta/messages.h"
#include "yacl/crypto/experimental/threshold_ecdsa/sm2/messages/mta_messages.h"

namespace tecdsa::sm2::messages::internal {

PairwiseProductRequest FromCoreRequest(
    const core::mta::PairwiseProductRequest& request);
core::mta::PairwiseProductRequest ToCoreRequest(
    const PairwiseProductRequest& request);

PairwiseProductResponse FromCoreResponse(
    const core::mta::PairwiseProductResponse& response);
core::mta::PairwiseProductResponse ToCoreResponse(
    const PairwiseProductResponse& response);

}  // namespace tecdsa::sm2::messages::internal
