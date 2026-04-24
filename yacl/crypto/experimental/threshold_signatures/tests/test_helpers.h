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

#include <functional>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <vector>

#include "yacl/crypto/experimental/threshold_signatures/common/ids.h"

namespace tecdsa::test_helpers {

inline void Expect(bool condition, const std::string& message) {
  if (!condition) {
    throw std::runtime_error("Test failed: " + message);
  }
}

inline void ExpectThrow(const std::function<void()>& fn,
                        const std::string& message) {
  bool threw = false;
  try {
    fn();
  } catch (const std::exception&) {
    threw = true;
  }
  if (!threw) {
    throw std::runtime_error("Test failed: " + message);
  }
}

template <typename T>
std::unordered_map<PartyIndex, T> BuildPeerMapFor(
    const std::vector<PartyIndex>& parties, PartyIndex self_id,
    const std::unordered_map<PartyIndex, T>& all_msgs) {
  std::unordered_map<PartyIndex, T> out;
  for (PartyIndex peer : parties) {
    if (peer != self_id) {
      out.emplace(peer, all_msgs.at(peer));
    }
  }
  return out;
}

}  // namespace tecdsa::test_helpers
