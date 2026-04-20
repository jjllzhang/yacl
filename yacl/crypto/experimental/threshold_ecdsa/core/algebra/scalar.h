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

#include "yacl/crypto/experimental/threshold_ecdsa/core/suite/group_context.h"

namespace tecdsa::core {

class Scalar {
 public:
  using BigInt = yacl::math::MPInt;

  Scalar();
  explicit Scalar(const BigInt& value,
                  std::shared_ptr<const GroupContext> group =
                      DefaultGroupContext());

  static Scalar FromUint64(uint64_t value,
                           std::shared_ptr<const GroupContext> group =
                               DefaultGroupContext());
  static Scalar FromBigEndianModQ(
      std::span<const uint8_t> bytes,
      std::shared_ptr<const GroupContext> group = DefaultGroupContext());
  static Scalar FromCanonicalBytes(
      std::span<const uint8_t> bytes,
      std::shared_ptr<const GroupContext> group = DefaultGroupContext());

  std::array<uint8_t, 32> ToCanonicalBytes() const;

  const BigInt& mp_value() const;
  const BigInt& value() const;
  const std::shared_ptr<const GroupContext>& group() const;

  Scalar operator+(const Scalar& other) const;
  Scalar operator-(const Scalar& other) const;
  Scalar operator*(const Scalar& other) const;
  Scalar InverseModQ() const;

  bool operator==(const Scalar& other) const;
  bool operator!=(const Scalar& other) const;

  static const BigInt& ModulusQMpInt();
  static const BigInt& ModulusQ();

 private:
  std::shared_ptr<const GroupContext> group_;
  BigInt value_;
};

}  // namespace tecdsa::core
