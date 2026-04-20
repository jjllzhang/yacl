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

#include "yacl/crypto/experimental/threshold_ecdsa/sm2/zid/zid.h"

#include <array>

#include "yacl/crypto/experimental/threshold_ecdsa/common/errors.h"
#include "yacl/crypto/experimental/threshold_ecdsa/crypto/hash.h"
#include "yacl/crypto/experimental/threshold_ecdsa/sm2/common.h"

namespace tecdsa::sm2::zid {
namespace {

constexpr std::array<uint8_t, 32> kSm2A = {
    0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00,
    0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFC,
};

constexpr std::array<uint8_t, 32> kSm2B = {
    0x28, 0xE9, 0xFA, 0x9E, 0x9D, 0x9F, 0x5E, 0x34, 0x4D, 0x5A, 0x9E,
    0x4B, 0xCF, 0x65, 0x09, 0xA7, 0xF3, 0x97, 0x89, 0xF5, 0x15, 0xAB,
    0x8F, 0x92, 0xDD, 0xBC, 0xBD, 0x41, 0x4D, 0x94, 0x0E, 0x93,
};

constexpr std::array<uint8_t, 32> kSm2Gx = {
    0x32, 0xC4, 0xAE, 0x2C, 0x1F, 0x19, 0x81, 0x19, 0x5F, 0x99, 0x04,
    0x46, 0x6A, 0x39, 0xC9, 0x94, 0x8F, 0xE3, 0x0B, 0xBF, 0xF2, 0x66,
    0x0B, 0xE1, 0x71, 0x5A, 0x45, 0x89, 0x33, 0x4C, 0x74, 0xC7,
};

constexpr std::array<uint8_t, 32> kSm2Gy = {
    0xBC, 0x37, 0x36, 0xA2, 0xF4, 0xF6, 0x77, 0x9C, 0x59, 0xBD, 0xCE,
    0xE3, 0x6B, 0x69, 0x21, 0x53, 0xD0, 0xA9, 0x87, 0x7C, 0xC6, 0x2A,
    0x47, 0x40, 0x02, 0xDF, 0x32, 0xE5, 0x21, 0x39, 0xF0, 0xA0,
};

void AppendU16Be(uint16_t value, Bytes* out) {
  out->push_back(static_cast<uint8_t>((value >> 8) & 0xFF));
  out->push_back(static_cast<uint8_t>(value & 0xFF));
}

}  // namespace

Bytes ComputeZid(std::span<const uint8_t> signer_id, const ECPoint& public_key) {
  if (signer_id.size() > (UINT16_MAX / 8)) {
    TECDSA_THROW_ARGUMENT("SM2 signer id is too long");
  }

  const Bytes public_key_uncompressed = internal::SerializeUncompressed(public_key);
  if (public_key_uncompressed.size() != 65 || public_key_uncompressed[0] != 0x04) {
    TECDSA_THROW_ARGUMENT("SM2 public key must serialize to uncompressed form");
  }

  Bytes preimage;
  preimage.reserve(2 + signer_id.size() + 32 * 6);
  AppendU16Be(static_cast<uint16_t>(signer_id.size() * 8), &preimage);
  preimage.insert(preimage.end(), signer_id.begin(), signer_id.end());
  preimage.insert(preimage.end(), kSm2A.begin(), kSm2A.end());
  preimage.insert(preimage.end(), kSm2B.begin(), kSm2B.end());
  preimage.insert(preimage.end(), kSm2Gx.begin(), kSm2Gx.end());
  preimage.insert(preimage.end(), kSm2Gy.begin(), kSm2Gy.end());
  preimage.insert(preimage.end(), public_key_uncompressed.begin() + 1,
                  public_key_uncompressed.begin() + 33);
  preimage.insert(preimage.end(), public_key_uncompressed.begin() + 33,
                  public_key_uncompressed.end());
  return Sm3(preimage);
}

IdentityBinding BindIdentity(std::span<const uint8_t> signer_id,
                             const ECPoint& public_key) {
  IdentityBinding binding;
  binding.signer_id.assign(signer_id.begin(), signer_id.end());
  binding.zid = ComputeZid(signer_id, public_key);
  return binding;
}

Bytes PreprocessMessageDigest(const IdentityBinding& binding,
                              std::span<const uint8_t> message) {
  Bytes preimage = binding.zid;
  preimage.insert(preimage.end(), message.begin(), message.end());
  return Sm3(preimage);
}

}  // namespace tecdsa::sm2::zid
