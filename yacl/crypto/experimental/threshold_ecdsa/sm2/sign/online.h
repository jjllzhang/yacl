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

#include <optional>
#include <span>
#include <unordered_map>
#include <vector>

#include "yacl/crypto/experimental/threshold_ecdsa/common/ids.h"
#include "yacl/crypto/experimental/threshold_ecdsa/sm2/keygen/keygen.h"
#include "yacl/crypto/experimental/threshold_ecdsa/sm2/presign/offline.h"
#include "yacl/crypto/experimental/threshold_ecdsa/sm2/verify/verify.h"

namespace tecdsa::sm2::sign {

template <typename T>
using PeerMap = std::unordered_map<PartyIndex, T>;

struct OnlineConfig {
  Bytes session_id;
  PartyIndex self_id = 0;
  std::vector<PartyIndex> participants;
  keygen::LocalKeyShare local_key_share;
  keygen::PublicKeygenData public_keygen_data;
  presign::OfflineState offline;
  Bytes message;
};

class OnlineParty {
 public:
  explicit OnlineParty(OnlineConfig cfg);

  const OnlineConfig& config() const;

  Scalar MakePartialSignature();
  verify::Signature Finalize(const PeerMap<Scalar>& peer_partials);

 private:
  OnlineConfig cfg_;
  std::vector<PartyIndex> peers_;
  Scalar message_hash_;
  Scalar r_;
  std::optional<Scalar> partial_s_prime_;
  std::optional<verify::Signature> signature_;
};

}  // namespace tecdsa::sm2::sign
