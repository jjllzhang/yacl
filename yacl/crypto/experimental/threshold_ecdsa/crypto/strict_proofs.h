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

#include <cstdint>

#include "yacl/crypto/experimental/threshold_ecdsa/core/paillier/aux_proofs.h"
#include "yacl/crypto/experimental/threshold_ecdsa/core/paillier/paper_aux_proofs.h"
#include "yacl/crypto/experimental/threshold_ecdsa/core/paillier/paper_aux_setup.h"

namespace tecdsa {

using BigInt = core::paillier::BigInt;
using StrictProofVerifierContext = core::paillier::StrictProofVerifierContext;
using AuxRsaParams = core::paillier::AuxRsaParams;
using SquareFreeProof = core::paillier::SquareFreeProof;
using AuxRsaParamProof = core::paillier::AuxRsaParamProof;
using AuxCorrectFormProof = core::paillier::AuxCorrectFormProof;
using PiModProof = core::paillier::PiModProof;
using PiPrmProof = core::paillier::PiPrmProof;
using PaperAuxSetupBundle = core::paillier::PaperAuxSetupBundle;
using PaperAuxSetupWitness = core::paillier::PaperAuxSetupWitness;
using core::paillier::BuildAuxCorrectFormProof;
using core::paillier::BuildSquareFreeProofGmr98;
using core::paillier::DecodeAuxRsaParamProof;
using core::paillier::DecodeSquareFreeProof;
using core::paillier::EncodeAuxRsaParamProof;
using core::paillier::EncodeSquareFreeProof;
using core::paillier::GenerateAuxRsaParams;
using core::paillier::GeneratePaperAuxSetup;
using core::paillier::IsLikelySquareFreeModulus;
using core::paillier::IsZnStarElement;
using core::paillier::ValidateAuxRsaParams;
using core::paillier::ValidatePaperAuxSetup;
using core::paillier::VerifyAuxCorrectFormProof;
using core::paillier::VerifySquareFreeProofGmr98;

inline StrictProofVerifierContext BuildProofContext(
    const Bytes& session_id, PartyIndex prover_id,
    std::optional<PartyIndex> verifier_id = std::nullopt) {
  return core::paillier::BuildProofContext(
      session_id, prover_id, core::DefaultEcdsaSuite(),
      core::DefaultGroupContext(), verifier_id);
}

}  // namespace tecdsa
