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

#include <memory>
#include <string>
#include <string_view>

#include "yacl/crypto/ecc/ecc_spi.h"
#include "yacl/crypto/experimental/threshold_ecdsa/core/suite/suite.h"
#include "yacl/math/mpint/mp_int.h"

namespace tecdsa::core {

class Scalar;
class Point;

class GroupContext {
 public:
  using BigInt = yacl::math::MPInt;

  static std::shared_ptr<const GroupContext> Create(CurveId curve_id);

  GroupContext(CurveId curve_id, std::string curve_name, BigInt order,
               size_t scalar_size_bytes, size_t compressed_point_size_bytes,
               std::unique_ptr<yacl::crypto::EcGroup> ec_group);

  CurveId curve_id() const;
  std::string_view curve_name() const;
  const BigInt& order() const;
  size_t scalar_size_bytes() const;
  size_t compressed_point_size_bytes() const;
  yacl::crypto::EcGroup& ec_group() const;

 private:
  CurveId curve_id_;
  std::string curve_name_;
  BigInt order_;
  size_t scalar_size_bytes_;
  size_t compressed_point_size_bytes_;
  std::unique_ptr<yacl::crypto::EcGroup> ec_group_;

  friend class Scalar;
  friend class Point;
};

const std::shared_ptr<const GroupContext>& DefaultGroupContext();

}  // namespace tecdsa::core
