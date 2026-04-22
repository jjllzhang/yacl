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

#include "yacl/crypto/experimental/threshold_ecdsa/core/paillier/aux_proofs.h"

namespace tecdsa::core::paillier {

struct PaperAuxSetupWitness {
  BigInt p_tilde = BigInt(0);
  BigInt q_tilde = BigInt(0);
  BigInt P_tilde = BigInt(0);
  BigInt Q_tilde = BigInt(0);
  BigInt tau = BigInt(0);
  BigInt lambda = BigInt(0);
};

struct PaperAuxSetupBundle {
  AuxRsaParams params;
  PaperAuxSetupWitness witness;
};

}  // namespace tecdsa::core::paillier
