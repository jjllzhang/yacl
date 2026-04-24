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

#include "yacl/crypto/experimental/threshold_signatures/core/algebra/point.h"

#include <algorithm>
#include <cstring>
#include <exception>
#include <utility>

#include "yacl/crypto/experimental/threshold_signatures/common/errors.h"

namespace tecdsa::core {
namespace {

using yacl::crypto::EcPoint;
using yacl::crypto::PointOctetFormat;

std::shared_ptr<const GroupContext> RequireGroup(
    std::shared_ptr<const GroupContext> group) {
  return group == nullptr ? DefaultGroupContext() : std::move(group);
}

const GroupContext& RequireSameGroup(
    const std::shared_ptr<const GroupContext>& lhs,
    const std::shared_ptr<const GroupContext>& rhs) {
  if (lhs == nullptr || rhs == nullptr) {
    TECDSA_THROW_ARGUMENT("Point group context must not be null");
  }
  if (lhs->curve_id() != rhs->curve_id()) {
    TECDSA_THROW_ARGUMENT("Point operands must use the same group context");
  }
  return *lhs;
}

std::string InvalidPointMessage(const GroupContext& group) {
  return "Compressed point is not a valid " + std::string(group.curve_name()) +
         " point";
}

EcPoint DeserializeCompressed(const GroupContext& group,
                              const std::array<uint8_t, 33>& compressed) {
  try {
    EcPoint point = group.ec_group().DeserializePoint(
        compressed, PointOctetFormat::X962Compressed);
    if (!group.ec_group().IsInCurveGroup(point) ||
        group.ec_group().IsInfinity(point)) {
      TECDSA_THROW_ARGUMENT(InvalidPointMessage(group));
    }
    return point;
  } catch (const std::exception&) {
    TECDSA_THROW_ARGUMENT(InvalidPointMessage(group));
  }
}

std::array<uint8_t, 33> SerializeCompressed(const GroupContext& group,
                                            const EcPoint& point) {
  const auto encoded =
      group.ec_group().SerializePoint(point, PointOctetFormat::X962Compressed);

  std::array<uint8_t, 33> out{};
  if (encoded.size() != static_cast<int64_t>(out.size())) {
    TECDSA_THROW("Failed to serialize compressed curve point");
  }
  std::memcpy(out.data(), encoded.data<uint8_t>(), out.size());
  if (out[0] != 0x02 && out[0] != 0x03) {
    TECDSA_THROW("Failed to serialize compressed curve point");
  }
  return out;
}

}  // namespace

Point::Point() : group_(DefaultGroupContext()) {
  compressed_.fill(0);
  compressed_[0] = 0x02;
}

Point::Point(std::shared_ptr<const GroupContext> group,
             const std::array<uint8_t, 33>& compressed)
    : group_(RequireGroup(std::move(group))), compressed_(compressed) {}

Point Point::FromCompressed(std::span<const uint8_t> compressed_bytes,
                            std::shared_ptr<const GroupContext> group) {
  auto resolved_group = RequireGroup(std::move(group));
  if (compressed_bytes.size() != resolved_group->compressed_point_size_bytes()) {
    TECDSA_THROW_ARGUMENT("Compressed point must be 33 bytes");
  }
  if (compressed_bytes[0] != 0x02 && compressed_bytes[0] != 0x03) {
    TECDSA_THROW_ARGUMENT(InvalidPointMessage(*resolved_group));
  }

  std::array<uint8_t, 33> compressed{};
  std::copy(compressed_bytes.begin(), compressed_bytes.end(),
            compressed.begin());
  (void)DeserializeCompressed(*resolved_group, compressed);
  return Point(std::move(resolved_group), compressed);
}

Point Point::GeneratorMultiply(const Scalar& scalar) {
  if (scalar.mp_value() == 0) {
    TECDSA_THROW_ARGUMENT(
        "Generator multiplication failed: scalar must be in [1, q-1]");
  }

  const GroupContext& group = *scalar.group();
  const EcPoint point = group.ec_group().MulBase(scalar.mp_value());
  if (group.ec_group().IsInfinity(point)) {
    TECDSA_THROW_ARGUMENT(
        "Generator multiplication failed: scalar must be in [1, q-1]");
  }
  return Point(scalar.group(), SerializeCompressed(group, point));
}

Point Point::Add(const Point& other) const {
  const GroupContext& group = RequireSameGroup(group_, other.group_);
  const EcPoint lhs = DeserializeCompressed(group, compressed_);
  const EcPoint rhs = DeserializeCompressed(group, other.compressed_);
  const EcPoint combined = group.ec_group().Add(lhs, rhs);
  if (group.ec_group().IsInfinity(combined)) {
    TECDSA_THROW_ARGUMENT("Point addition failed (sum is point at infinity?)");
  }

  return Point(group_, SerializeCompressed(group, combined));
}

Point Point::Mul(const Scalar& scalar) const {
  const GroupContext& group = RequireSameGroup(group_, scalar.group());
  if (scalar.mp_value() == 0) {
    TECDSA_THROW_ARGUMENT("Point scalar multiplication failed");
  }

  const EcPoint point = DeserializeCompressed(group, compressed_);
  const EcPoint multiplied = group.ec_group().Mul(point, scalar.mp_value());
  if (group.ec_group().IsInfinity(multiplied)) {
    TECDSA_THROW_ARGUMENT("Point scalar multiplication failed");
  }

  return Point(group_, SerializeCompressed(group, multiplied));
}

Bytes Point::ToCompressedBytes() const {
  return Bytes(compressed_.begin(), compressed_.end());
}

const std::shared_ptr<const GroupContext>& Point::group() const {
  return group_;
}

bool Point::operator==(const Point& other) const {
  if (group_ == nullptr || other.group_ == nullptr) {
    return group_ == other.group_ && compressed_ == other.compressed_;
  }
  return group_->curve_id() == other.group_->curve_id() &&
         compressed_ == other.compressed_;
}

bool Point::operator!=(const Point& other) const { return !(*this == other); }

}  // namespace tecdsa::core
