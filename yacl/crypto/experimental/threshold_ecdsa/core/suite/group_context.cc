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

#include "yacl/crypto/experimental/threshold_ecdsa/core/suite/group_context.h"

#include <memory>
#include <utility>

#include "yacl/crypto/experimental/threshold_ecdsa/common/errors.h"

namespace tecdsa::core {
namespace {

using yacl::crypto::EcGroupFactory;

std::shared_ptr<const GroupContext> CreateSecp256k1Context() {
  auto group =
      EcGroupFactory::Instance().Create("secp256k1", yacl::ArgLib = "openssl");
  if (group == nullptr) {
    TECDSA_THROW("Failed to create secp256k1 curve via yacl openssl backend");
  }

  return std::shared_ptr<const GroupContext>(new GroupContext(
      CurveId::kSecp256k1, "secp256k1",
      GroupContext::BigInt(
          "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"),
      32, 33, std::move(group)));
}

}  // namespace

GroupContext::GroupContext(CurveId curve_id, std::string curve_name,
                           BigInt order, size_t scalar_size_bytes,
                           size_t compressed_point_size_bytes,
                           std::unique_ptr<yacl::crypto::EcGroup> ec_group)
    : curve_id_(curve_id),
      curve_name_(std::move(curve_name)),
      order_(std::move(order)),
      scalar_size_bytes_(scalar_size_bytes),
      compressed_point_size_bytes_(compressed_point_size_bytes),
      ec_group_(std::move(ec_group)) {}

std::shared_ptr<const GroupContext> GroupContext::Create(CurveId curve_id) {
  switch (curve_id) {
    case CurveId::kSecp256k1: {
      static const std::shared_ptr<const GroupContext> kSecp256k1 =
          CreateSecp256k1Context();
      return kSecp256k1;
    }
    case CurveId::kSm2P256V1:
      TECDSA_THROW_ARGUMENT(
          "SM2 group context is not wired into threshold_ecdsa stage-1 yet");
  }

  TECDSA_THROW_ARGUMENT("Unsupported curve id");
}

CurveId GroupContext::curve_id() const { return curve_id_; }

std::string_view GroupContext::curve_name() const { return curve_name_; }

const GroupContext::BigInt& GroupContext::order() const { return order_; }

size_t GroupContext::scalar_size_bytes() const { return scalar_size_bytes_; }

size_t GroupContext::compressed_point_size_bytes() const {
  return compressed_point_size_bytes_;
}

yacl::crypto::EcGroup& GroupContext::ec_group() const { return *ec_group_; }

const std::shared_ptr<const GroupContext>& DefaultGroupContext() {
  static const std::shared_ptr<const GroupContext> kDefault =
      GroupContext::Create(DefaultEcdsaSuite().curve);
  return kDefault;
}

}  // namespace tecdsa::core
