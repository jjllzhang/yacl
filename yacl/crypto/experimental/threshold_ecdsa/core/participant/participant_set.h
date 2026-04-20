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

#include <string>
#include <vector>

#include "yacl/crypto/experimental/threshold_ecdsa/common/errors.h"
#include "yacl/crypto/experimental/threshold_ecdsa/protocol/types.h"

namespace tecdsa::core::participant {

struct ParticipantSet {
  std::vector<PartyIndex> participants;
  std::vector<PartyIndex> peers;
  PartyIndex self_id = 0;
};

void ValidateParticipantsOrThrow(const std::vector<PartyIndex>& participants,
                                 PartyIndex self_id,
                                 const char* context_name);

std::vector<PartyIndex> BuildPeers(const std::vector<PartyIndex>& participants,
                                   PartyIndex self_id);

ParticipantSet BuildParticipantSet(const std::vector<PartyIndex>& participants,
                                   PartyIndex self_id,
                                   const char* context_name);

template <typename MapType>
void RequireExactlyPeers(const MapType& messages,
                         const std::vector<PartyIndex>& participants,
                         PartyIndex self_id, const char* field_name) {
  size_t expected = 0;
  for (PartyIndex party : participants) {
    if (party != self_id) {
      ++expected;
    }
  }
  if (messages.size() != expected) {
    TECDSA_THROW_ARGUMENT(std::string(field_name) +
                          " must contain exactly one entry per peer");
  }
  for (PartyIndex party : participants) {
    if (party == self_id) {
      continue;
    }
    if (!messages.contains(party)) {
      TECDSA_THROW_ARGUMENT(std::string(field_name) +
                            " is missing a peer message");
    }
  }
}

}  // namespace tecdsa::core::participant
