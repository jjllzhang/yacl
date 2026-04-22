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

#include "yacl/crypto/experimental/threshold_ecdsa/sm2/messages/mta_messages.h"

#include "yacl/crypto/experimental/threshold_ecdsa/sm2/proofs/adapters.h"

namespace tecdsa::sm2::messages {

PairwiseProductRequest FromCoreRequest(
    const core::mta::PairwiseProductRequest& request) {
  return PairwiseProductRequest{
      .from = request.from,
      .to = request.to,
      .type = request.type,
      .instance_id = request.instance_id,
      .c1 = request.c1,
      .a1_proof = proofs::FromCorePiRangeProof(request.a1_proof),
  };
}

core::mta::PairwiseProductRequest ToCoreRequest(
    const PairwiseProductRequest& request) {
  return core::mta::PairwiseProductRequest{
      .from = request.from,
      .to = request.to,
      .type = request.type,
      .instance_id = request.instance_id,
      .c1 = request.c1,
      .a1_proof = proofs::ToCorePiRangeProof(request.a1_proof),
  };
}

PairwiseProductResponse FromCoreResponse(
    const core::mta::PairwiseProductResponse& response) {
  return PairwiseProductResponse{
      .from = response.from,
      .to = response.to,
      .type = response.type,
      .instance_id = response.instance_id,
      .c2 = response.c2,
      .a2_proof = response.a2_proof
                      ? std::make_optional(
                            proofs::FromCorePiLinearGroupProof(*response.a2_proof))
                      : std::nullopt,
      .a3_proof = response.a3_proof
                      ? std::make_optional(
                            proofs::FromCorePiLinearProof(*response.a3_proof))
                      : std::nullopt,
  };
}

core::mta::PairwiseProductResponse ToCoreResponse(
    const PairwiseProductResponse& response) {
  return core::mta::PairwiseProductResponse{
      .from = response.from,
      .to = response.to,
      .type = response.type,
      .instance_id = response.instance_id,
      .c2 = response.c2,
      .a2_proof = response.a2_proof
                      ? std::make_optional(
                            proofs::ToCorePiLinearGroupProof(*response.a2_proof))
                      : std::nullopt,
      .a3_proof = response.a3_proof
                      ? std::make_optional(
                            proofs::ToCorePiLinearProof(*response.a3_proof))
                      : std::nullopt,
  };
}

}  // namespace tecdsa::sm2::messages
