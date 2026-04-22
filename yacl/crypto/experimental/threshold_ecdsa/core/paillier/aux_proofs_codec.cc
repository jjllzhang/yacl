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

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>

#include "yacl/crypto/experimental/threshold_ecdsa/common/errors.h"
#include "yacl/crypto/experimental/threshold_ecdsa/core/encoding/byte_io.h"
#include "yacl/crypto/experimental/threshold_ecdsa/core/encoding/encoding.h"
#include "yacl/crypto/experimental/threshold_ecdsa/core/paillier/aux_proofs_internal.h"

namespace tecdsa::core::paillier_internal {
namespace {

void AppendMpIntField(const BigInt& value, Bytes* out) {
  const Bytes encoded = encoding::EncodeMpInt(value);
  encoding::AppendSizedField(encoded, out);
}

BigInt ReadMpIntField(std::span<const uint8_t> input, size_t* offset,
                      const char* field_name) {
  const Bytes encoded =
      encoding::ReadSizedField(input, offset, kMaxStrictFieldLen, field_name);
  return encoding::DecodeMpInt(encoded, kMaxStrictFieldLen);
}

}  // namespace

Bytes EncodeSquareFreeGmr98Payload(const SquareFreeGmr98Payload& payload) {
  if (payload.rounds == 0 || payload.rounds > kMaxSquareFreeGmr98Rounds) {
    TECDSA_THROW_ARGUMENT("square-free GMR98 rounds out of range");
  }
  if (payload.roots.size() != payload.rounds) {
    TECDSA_THROW_ARGUMENT("square-free GMR98 roots count mismatch");
  }

  Bytes out;
  encoding::AppendSizedField(payload.nonce, &out);
  encoding::AppendU32Be(payload.rounds, &out);
  for (const BigInt& root : payload.roots) {
    AppendMpIntField(root, &out);
  }
  return out;
}

SquareFreeGmr98Payload DecodeSquareFreeGmr98Payload(
    std::span<const uint8_t> blob) {
  size_t offset = 0;
  SquareFreeGmr98Payload payload;
  payload.nonce = encoding::ReadSizedField(blob, &offset, kMaxStrictNonceLen,
                                           "square-free GMR98 nonce");
  payload.rounds = encoding::ReadU32Be(blob, &offset);
  if (payload.rounds == 0 || payload.rounds > kMaxSquareFreeGmr98Rounds) {
    TECDSA_THROW_ARGUMENT("square-free GMR98 rounds out of range");
  }
  payload.roots.reserve(payload.rounds);
  for (uint32_t i = 0; i < payload.rounds; ++i) {
    payload.roots.push_back(
        ReadMpIntField(blob, &offset, "square-free GMR98 root"));
  }
  if (offset != blob.size()) {
    TECDSA_THROW_ARGUMENT("square-free GMR98 payload has trailing bytes");
  }
  return payload;
}

}  // namespace tecdsa::core::paillier_internal
