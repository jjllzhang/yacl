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

#include <cstddef>
#include <memory>
#include <string>

#include "yacl/crypto/experimental/threshold_ecdsa/common/bytes.h"
#include "yacl/crypto/experimental/threshold_ecdsa/common/ids.h"
#include "yacl/crypto/experimental/threshold_ecdsa/core/paillier/aux_proofs.h"
#include "yacl/crypto/experimental/threshold_ecdsa/core/suite/suite.h"
#include "yacl/crypto/experimental/threshold_ecdsa/crypto/ec_point.h"
#include "yacl/crypto/experimental/threshold_ecdsa/crypto/scalar.h"

namespace tecdsa::core::mta {

using BigInt = core::paillier::BigInt;
using AuxRsaParams = core::paillier::AuxRsaParams;

inline constexpr size_t kMtaInstanceIdLen = 16;

struct MtaProofContext {
  Bytes session_id;
  PartyIndex initiator_id = 0;
  PartyIndex responder_id = 0;
  Bytes instance_id;
  HashId transcript_hash = HashId::kSha256;
  std::shared_ptr<const GroupContext> group;
  std::string proof_domain_prefix = "GG2019";
};

MtaProofContext BuildProofContext(const Bytes& session_id,
                                  PartyIndex initiator_id,
                                  PartyIndex responder_id,
                                  const Bytes& instance_id,
                                  const ThresholdSuite& suite,
                                  std::shared_ptr<const GroupContext> group);

struct A1RangeProof {
  BigInt z = BigInt(0);
  BigInt u = BigInt(0);
  BigInt w = BigInt(0);
  BigInt s = BigInt(0);
  BigInt s1 = BigInt(0);
  BigInt s2 = BigInt(0);
};

struct A2MtAwcProof {
  ECPoint u;
  BigInt z = BigInt(0);
  BigInt z2 = BigInt(0);
  BigInt t = BigInt(0);
  BigInt v = BigInt(0);
  BigInt w = BigInt(0);
  BigInt s = BigInt(0);
  BigInt s1 = BigInt(0);
  BigInt s2 = BigInt(0);
  BigInt t1 = BigInt(0);
  BigInt t2 = BigInt(0);
};

struct A3MtAProof {
  BigInt z = BigInt(0);
  BigInt z2 = BigInt(0);
  BigInt t = BigInt(0);
  BigInt v = BigInt(0);
  BigInt w = BigInt(0);
  BigInt s = BigInt(0);
  BigInt s1 = BigInt(0);
  BigInt s2 = BigInt(0);
  BigInt t1 = BigInt(0);
  BigInt t2 = BigInt(0);
};

BigInt RandomBelow(const BigInt& upper_exclusive);
BigInt SampleZnStar(const BigInt& modulus_n);
BigInt QPow5(const std::shared_ptr<const GroupContext>& group);
BigInt MulMod(const BigInt& lhs, const BigInt& rhs, const BigInt& modulus);
BigInt PowMod(const BigInt& base, const BigInt& exp, const BigInt& modulus);

A1RangeProof ProveA1Range(const MtaProofContext& ctx, const BigInt& n,
                          const AuxRsaParams& verifier_aux, const BigInt& c,
                          const BigInt& witness_m, const BigInt& witness_r);
bool VerifyA1Range(const MtaProofContext& ctx, const BigInt& n,
                   const AuxRsaParams& verifier_aux, const BigInt& c,
                   const A1RangeProof& proof);

A2MtAwcProof ProveA2MtAwc(const MtaProofContext& ctx, const BigInt& n,
                          const AuxRsaParams& verifier_aux, const BigInt& c1,
                          const BigInt& c2, const ECPoint& statement_x,
                          const BigInt& witness_x, const BigInt& witness_y,
                          const BigInt& witness_r);
bool VerifyA2MtAwc(const MtaProofContext& ctx, const BigInt& n,
                   const AuxRsaParams& verifier_aux, const BigInt& c1,
                   const BigInt& c2, const ECPoint& statement_x,
                   const A2MtAwcProof& proof);

A3MtAProof ProveA3MtA(const MtaProofContext& ctx, const BigInt& n,
                      const AuxRsaParams& verifier_aux, const BigInt& c1,
                      const BigInt& c2, const BigInt& witness_x,
                      const BigInt& witness_y, const BigInt& witness_r);
bool VerifyA3MtA(const MtaProofContext& ctx, const BigInt& n,
                 const AuxRsaParams& verifier_aux, const BigInt& c1,
                 const BigInt& c2, const A3MtAProof& proof);

}  // namespace tecdsa::core::mta
