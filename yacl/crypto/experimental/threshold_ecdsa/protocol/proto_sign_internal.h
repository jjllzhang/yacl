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

#include "yacl/crypto/experimental/threshold_ecdsa/core/mta/proofs.h"
#include "yacl/crypto/experimental/threshold_ecdsa/core/mta/session.h"
#include "yacl/crypto/experimental/threshold_ecdsa/crypto/scalar.h"

namespace tecdsa::sign_internal {

using MtaProofContext = tecdsa::core::mta::MtaProofContext;
using PairwiseProductInitiatorInstance =
    tecdsa::core::mta::PairwiseProductInitiatorInstance;
using PairwiseProductSession = tecdsa::core::mta::PairwiseProductSession;
using tecdsa::core::mta::BuildProofContext;
using tecdsa::core::mta::BytesToKey;
using tecdsa::core::mta::ExpectedPairwiseProductMessageCount;
using tecdsa::core::mta::kMtaInstanceIdLen;
using tecdsa::core::mta::MakeResponderRequestKey;
using tecdsa::core::mta::MulMod;
using tecdsa::core::mta::PowMod;
using tecdsa::core::mta::ProveA1Range;
using tecdsa::core::mta::ProveA2MtAwc;
using tecdsa::core::mta::ProveA3MtA;
using tecdsa::core::mta::QPow5;
using tecdsa::core::mta::RandomBelow;
using tecdsa::core::mta::RandomMtaInstanceId;
using tecdsa::core::mta::SampleZnStar;
using tecdsa::core::mta::VerifyA1Range;
using tecdsa::core::mta::VerifyA2MtAwc;
using tecdsa::core::mta::VerifyA3MtA;

std::optional<Scalar> InvertScalar(const Scalar& scalar);

}  // namespace tecdsa::sign_internal
