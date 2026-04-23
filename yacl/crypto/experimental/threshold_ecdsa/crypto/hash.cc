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

#include "yacl/crypto/experimental/threshold_ecdsa/crypto/hash.h"

#include "yacl/crypto/experimental/threshold_ecdsa/core/suite/suite.h"

namespace tecdsa {

Bytes Hash(HashId hash_id, std::span<const uint8_t> data) {
  return core::Hash(hash_id, data);
}

Bytes Sha256(std::span<const uint8_t> data) {
  return core::Hash(HashId::kSha256, data);
}

Bytes Sha512(std::span<const uint8_t> data) {
  return core::Hash(HashId::kSha512, data);
}

Bytes Sm3(std::span<const uint8_t> data) {
  return core::Hash(HashId::kSm3, data);
}

}  // namespace tecdsa
