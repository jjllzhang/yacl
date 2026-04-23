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

#include <concepts>
#include <type_traits>

#include "yacl/crypto/experimental/threshold_ecdsa/core/algebra/point.h"
#include "yacl/crypto/experimental/threshold_ecdsa/core/algebra/scalar.h"

namespace tecdsa::core::proof {

template <typename T>
concept SchnorrProofLike =
    requires(const T& proof, const ECPoint& point, const Scalar& scalar) {
      { proof.a } -> std::convertible_to<ECPoint>;
      { proof.z } -> std::convertible_to<Scalar>;
      T{point, scalar};
    };

// Generic substrate proof shared by multiple schemes. Canonical public proof
// owners should live in the scheme layer, not in core::proof.
struct SchnorrProof {
  ECPoint a;
  Scalar z;

  template <typename T>
    requires(!std::same_as<std::remove_cvref_t<T>, SchnorrProof> &&
             requires(const ECPoint& point, const Scalar& scalar) {
               T{point, scalar};
             })
  operator T() const {
    return T{a, z};
  }
};

}  // namespace tecdsa::core::proof
