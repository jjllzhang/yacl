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
#include <optional>
#include <string>

#include "yacl/crypto/experimental/threshold_signatures/common/ids.h"
#include "yacl/crypto/experimental/threshold_signatures/core/suite/group_context.h"
#include "yacl/crypto/experimental/threshold_signatures/core/suite/suite.h"
#include "yacl/math/mpint/mp_int.h"

namespace tecdsa::core::paillier {

using BigInt = yacl::math::MPInt;

struct PaillierCiphertextWithRandom {
  BigInt ciphertext;
  BigInt randomness;
};

using PaillierCiphertextWithRandomBigInt = PaillierCiphertextWithRandom;

struct PaillierPublicKey {
  BigInt n = BigInt(0);
};

struct StrictProofVerifierContext {
  Bytes session_id;
  std::optional<PartyIndex> prover_id;
  std::optional<PartyIndex> verifier_id;
  HashId transcript_hash = HashId::kSha256;
  std::shared_ptr<const GroupContext> challenge_group;
  std::string proof_domain_prefix = "GG2019";
};

StrictProofVerifierContext BuildProofContext(
    const Bytes& session_id, PartyIndex prover_id,
    const ThresholdSuite& suite,
    std::shared_ptr<const GroupContext> challenge_group,
    std::optional<PartyIndex> verifier_id = std::nullopt);
BigInt MinPaillierModulusQ8(
    const std::shared_ptr<const GroupContext>& challenge_group);
void ValidatePaillierPublicKeyOrThrow(
    const PaillierPublicKey& pub,
    const std::shared_ptr<const GroupContext>& challenge_group);

class PaillierProvider {
 public:
  explicit PaillierProvider(unsigned long modulus_bits);
  ~PaillierProvider() = default;

  PaillierProvider(const PaillierProvider&) = delete;
  PaillierProvider& operator=(const PaillierProvider&) = delete;

  PaillierProvider(PaillierProvider&& other) noexcept = default;
  PaillierProvider& operator=(PaillierProvider&& other) noexcept = default;

  PaillierCiphertextWithRandomBigInt EncryptWithRandomBigInt(
      const BigInt& plaintext) const;
  BigInt EncryptWithProvidedRandomBigInt(const BigInt& plaintext,
                                         const BigInt& randomness) const;
  BigInt DecryptBigInt(const BigInt& ciphertext) const;

  BigInt modulus_n_bigint() const;
  BigInt private_lambda_bigint() const;

  bool VerifyKeyPair() const;

 private:
  void GenerateKeyPair(unsigned long modulus_bits);
  static BigInt NormalizeMod(const BigInt& value, const BigInt& modulus);
  static bool IsProbablePrime(const BigInt& candidate);
  static BigInt RandomBelow(const BigInt& upper_exclusive);
  static BigInt RandomOddWithBitSize(size_t bits);

  BigInt SampleZnStar() const;
  bool IsInZnStar(const BigInt& value) const;
  BigInt LFunction(const BigInt& value) const;

  BigInt p_;
  BigInt q_;
  BigInt n_;
  BigInt n2_;
  BigInt g_;
  BigInt lambda_;
  BigInt mu_;
  bool initialized_ = false;
};

}  // namespace tecdsa::core::paillier
