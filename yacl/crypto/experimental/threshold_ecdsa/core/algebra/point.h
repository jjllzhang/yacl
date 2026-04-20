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

#include <array>
#include <cstdint>
#include <memory>
#include <span>

#include "yacl/crypto/experimental/threshold_ecdsa/common/bytes.h"
#include "yacl/crypto/experimental/threshold_ecdsa/core/algebra/scalar.h"

namespace tecdsa::core {

class Point {
 public:
  Point();

  static Point FromCompressed(
      std::span<const uint8_t> compressed_bytes,
      std::shared_ptr<const GroupContext> group = DefaultGroupContext());
  static Point GeneratorMultiply(const Scalar& scalar);

  Point Add(const Point& other) const;
  Point Mul(const Scalar& scalar) const;

  Bytes ToCompressedBytes() const;
  const std::shared_ptr<const GroupContext>& group() const;

  bool operator==(const Point& other) const;
  bool operator!=(const Point& other) const;

 private:
  Point(std::shared_ptr<const GroupContext> group,
        const std::array<uint8_t, 33>& compressed);

  std::shared_ptr<const GroupContext> group_;
  std::array<uint8_t, 33> compressed_{};
};

}  // namespace tecdsa::core
