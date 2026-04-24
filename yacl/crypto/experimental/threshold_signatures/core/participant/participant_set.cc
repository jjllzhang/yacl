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

#include "yacl/crypto/experimental/threshold_signatures/core/participant/participant_set.h"

#include <string>
#include <unordered_set>

namespace tecdsa::core::participant {

void ValidateParticipantsOrThrow(const std::vector<PartyIndex>& participants,
                                 PartyIndex self_id,
                                 const char* context_name) {
  if (participants.size() < 2) {
    TECDSA_THROW_ARGUMENT(std::string(context_name) +
                          " requires at least 2 participants");
  }

  std::unordered_set<PartyIndex> dedup;
  bool self_present = false;
  for (PartyIndex id : participants) {
    if (id == 0) {
      TECDSA_THROW_ARGUMENT("participants must not contain 0");
    }
    if (!dedup.insert(id).second) {
      TECDSA_THROW_ARGUMENT("participants must be unique");
    }
    if (id == self_id) {
      self_present = true;
    }
  }
  if (!self_present) {
    TECDSA_THROW_ARGUMENT("self_id must be in participants");
  }
}

std::vector<PartyIndex> BuildPeers(const std::vector<PartyIndex>& participants,
                                   PartyIndex self_id) {
  std::vector<PartyIndex> peers;
  peers.reserve(participants.size());
  for (PartyIndex party : participants) {
    if (party != self_id) {
      peers.push_back(party);
    }
  }
  return peers;
}

ParticipantSet BuildParticipantSet(const std::vector<PartyIndex>& participants,
                                   PartyIndex self_id,
                                   const char* context_name) {
  ValidateParticipantsOrThrow(participants, self_id, context_name);
  return ParticipantSet{
      .participants = participants,
      .peers = BuildPeers(participants, self_id),
      .self_id = self_id,
  };
}

}  // namespace tecdsa::core::participant
