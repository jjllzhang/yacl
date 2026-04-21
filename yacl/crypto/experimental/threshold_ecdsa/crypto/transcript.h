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

#include "yacl/crypto/experimental/threshold_ecdsa/core/suite/group_context.h"
#include "yacl/crypto/experimental/threshold_ecdsa/core/transcript/transcript.h"

namespace tecdsa {

using TranscriptFieldRef = core::transcript::TranscriptFieldRef;

class Transcript : public core::transcript::Transcript {
 public:
  using BigInt = core::transcript::Transcript::BigInt;
  using core::transcript::Transcript::Transcript;

  Transcript()
      : core::transcript::Transcript(core::DefaultEcdsaSuite().transcript_hash) {}

  core::Scalar challenge_scalar_mod_q() const {
    return challenge_scalar(core::DefaultGroupContext());
  }
};

}  // namespace tecdsa
