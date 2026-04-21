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

#include <span>
#include <string>

#include "yacl/crypto/experimental/threshold_ecdsa/common/bytes.h"

namespace tecdsa::core {

enum class SchemeId {
  kEcdsa,
  kSm2,
};

enum class CurveId {
  kSecp256k1,
  kSm2P256V1,
};

enum class HashId {
  kSha256,
  kSha512,
  kSm3,
};

struct ThresholdSuite {
  SchemeId scheme = SchemeId::kEcdsa;
  CurveId curve = CurveId::kSecp256k1;
  HashId transcript_hash = HashId::kSha256;
  HashId commitment_hash = HashId::kSha256;
  HashId message_hash = HashId::kSha256;
  std::string proof_domain_prefix = "GG2019";
  bool normalize_low_s = true;
};

const ThresholdSuite& DefaultEcdsaSuite();
const ThresholdSuite& DefaultSm2Suite();

Bytes Hash(HashId hash_id, std::span<const uint8_t> data);

}  // namespace tecdsa::core
