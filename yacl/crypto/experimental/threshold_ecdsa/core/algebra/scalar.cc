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

#include "yacl/crypto/experimental/threshold_ecdsa/core/algebra/scalar.h"

#include <algorithm>
#include <utility>

#include "yacl/crypto/experimental/threshold_ecdsa/common/errors.h"
#include "yacl/crypto/experimental/threshold_ecdsa/core/bigint/bigint_utils.h"

namespace tecdsa::core {
namespace {

using BigInt = Scalar::BigInt;

std::shared_ptr<const GroupContext> RequireGroup(
    std::shared_ptr<const GroupContext> group) {
  return group == nullptr ? DefaultGroupContext() : std::move(group);
}

const GroupContext& RequireSameGroup(
    const std::shared_ptr<const GroupContext>& lhs,
    const std::shared_ptr<const GroupContext>& rhs) {
  if (lhs == nullptr || rhs == nullptr) {
    TECDSA_THROW_ARGUMENT("Scalar group context must not be null");
  }
  if (lhs->curve_id() != rhs->curve_id()) {
    TECDSA_THROW_ARGUMENT("Scalar operands must use the same group context");
  }
  return *lhs;
}

BigInt NormalizeToGroupOrder(const GroupContext& group, const BigInt& input) {
  return bigint::NormalizeMod(input, group.order());
}

BigInt ImportBigEndian(std::span<const uint8_t> bytes) {
  if (bytes.empty()) {
    TECDSA_THROW_ARGUMENT("Big-endian input must not be empty");
  }
  return bigint::FromBigEndian(bytes);
}

}  // namespace

Scalar::Scalar() : Scalar(BigInt(0), DefaultGroupContext()) {}

Scalar::Scalar(const BigInt& value, std::shared_ptr<const GroupContext> group)
    : group_(RequireGroup(std::move(group))),
      value_(NormalizeToGroupOrder(*group_, value)) {}

Scalar Scalar::FromUint64(uint64_t value,
                          std::shared_ptr<const GroupContext> group) {
  return Scalar(BigInt(value), std::move(group));
}

Scalar Scalar::FromBigEndianModQ(std::span<const uint8_t> bytes,
                                 std::shared_ptr<const GroupContext> group) {
  return Scalar(ImportBigEndian(bytes), std::move(group));
}

Scalar Scalar::FromCanonicalBytes(std::span<const uint8_t> bytes,
                                  std::shared_ptr<const GroupContext> group) {
  auto resolved_group = RequireGroup(std::move(group));
  if (bytes.size() != resolved_group->scalar_size_bytes()) {
    TECDSA_THROW_ARGUMENT("Canonical scalar must be exactly 32 bytes");
  }

  BigInt imported = ImportBigEndian(bytes);
  if (imported >= resolved_group->order()) {
    TECDSA_THROW_ARGUMENT("Canonical scalar is out of range");
  }
  return Scalar(imported, std::move(resolved_group));
}

std::array<uint8_t, 32> Scalar::ToCanonicalBytes() const {
  if (group_->scalar_size_bytes() != 32) {
    TECDSA_THROW("Stage-1 scalar encoding only supports 32-byte groups");
  }

  std::array<uint8_t, 32> out{};
  const Bytes fixed = bigint::ToFixedWidth(value_, out.size());
  std::copy(fixed.begin(), fixed.end(), out.begin());
  return out;
}

const Scalar::BigInt& Scalar::mp_value() const { return value_; }

const Scalar::BigInt& Scalar::value() const { return value_; }

const std::shared_ptr<const GroupContext>& Scalar::group() const {
  return group_;
}

Scalar Scalar::operator+(const Scalar& other) const {
  const GroupContext& group = RequireSameGroup(group_, other.group_);
  return Scalar(value_ + other.value_, GroupContext::Create(group.curve_id()));
}

Scalar Scalar::operator-(const Scalar& other) const {
  const GroupContext& group = RequireSameGroup(group_, other.group_);
  return Scalar(value_ - other.value_, GroupContext::Create(group.curve_id()));
}

Scalar Scalar::operator*(const Scalar& other) const {
  const GroupContext& group = RequireSameGroup(group_, other.group_);
  return Scalar(value_ * other.value_, GroupContext::Create(group.curve_id()));
}

Scalar Scalar::InverseModQ() const {
  if (value_ == 0) {
    TECDSA_THROW_ARGUMENT("zero has no inverse modulo q");
  }

  const auto inv = bigint::TryInvertMod(value_, group_->order());
  if (!inv.has_value()) {
    TECDSA_THROW_ARGUMENT("failed to invert scalar modulo q");
  }
  return Scalar(*inv, group_);
}

bool Scalar::operator==(const Scalar& other) const {
  if (group_ == nullptr || other.group_ == nullptr) {
    return group_ == other.group_ && value_ == other.value_;
  }
  return group_->curve_id() == other.group_->curve_id() &&
         value_ == other.value_;
}

bool Scalar::operator!=(const Scalar& other) const { return !(*this == other); }

const Scalar::BigInt& Scalar::ModulusQMpInt() {
  return DefaultGroupContext()->order();
}

const Scalar::BigInt& Scalar::ModulusQ() { return DefaultGroupContext()->order(); }

}  // namespace tecdsa::core
