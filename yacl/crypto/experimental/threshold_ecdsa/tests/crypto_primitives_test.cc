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

#include <functional>
#include <iostream>
#include <span>
#include <stdexcept>
#include <unordered_map>
#include <vector>

#include "yacl/crypto/experimental/threshold_ecdsa/common/bytes.h"
#include "yacl/crypto/experimental/threshold_ecdsa/core/algebra/point.h"
#include "yacl/crypto/experimental/threshold_ecdsa/core/algebra/scalar.h"
#include "yacl/crypto/experimental/threshold_ecdsa/core/participant/participant_set.h"
#include "yacl/crypto/experimental/threshold_ecdsa/core/proof/schnorr.h"
#include "yacl/crypto/experimental/threshold_ecdsa/core/suite/group_context.h"
#include "yacl/crypto/experimental/threshold_ecdsa/core/suite/suite.h"
#include "yacl/crypto/experimental/threshold_ecdsa/core/vss/dealerless_dkg.h"
#include "yacl/crypto/experimental/threshold_ecdsa/core/vss/feldman.h"
#include "yacl/crypto/experimental/threshold_ecdsa/crypto/bigint_utils.h"
#include "yacl/crypto/experimental/threshold_ecdsa/crypto/commitment.h"
#include "yacl/crypto/experimental/threshold_ecdsa/crypto/ec_point.h"
#include "yacl/crypto/experimental/threshold_ecdsa/crypto/ecdsa_verify.h"
#include "yacl/crypto/experimental/threshold_ecdsa/crypto/encoding.h"
#include "yacl/crypto/experimental/threshold_ecdsa/crypto/hash.h"
#include "yacl/crypto/experimental/threshold_ecdsa/crypto/paillier.h"
#include "yacl/crypto/experimental/threshold_ecdsa/crypto/random.h"
#include "yacl/crypto/experimental/threshold_ecdsa/crypto/scalar.h"
#include "yacl/crypto/experimental/threshold_ecdsa/crypto/transcript.h"
namespace {

using tecdsa::BigInt;
using tecdsa::Bytes;
using tecdsa::CommitMessage;
using tecdsa::ComputeCommitment;
using tecdsa::core::CurveId;
using tecdsa::core::DefaultEcdsaSuite;
using tecdsa::core::DefaultGroupContext;
using tecdsa::DecodeMpInt;
using tecdsa::ECPoint;
using tecdsa::EncodeMpInt;
using tecdsa::PaillierProvider;
using tecdsa::PartyIndex;
using tecdsa::Scalar;
using tecdsa::Sha256;
using tecdsa::Transcript;
using tecdsa::VerifyCommitment;
using tecdsa::VerifyEcdsaSignatureMath;

void Expect(bool condition, const std::string& message) {
  if (!condition) {
    throw std::runtime_error("Test failed: " + message);
  }
}

void ExpectThrow(const std::function<void()>& fn, const std::string& message) {
  try {
    fn();
  } catch (const std::exception&) {
    return;
  }
  throw std::runtime_error("Expected exception: " + message);
}

Scalar XCoordinateModQ(const ECPoint& point) {
  const Bytes compressed = point.ToCompressedBytes();
  if (compressed.size() != 33) {
    throw std::runtime_error("invalid compressed point length");
  }
  return Scalar::FromBigEndianModQ(
      std::span<const uint8_t>(compressed.data() + 1, 32));
}

void TestStage1SuiteMetadata() {
  const auto& suite = DefaultEcdsaSuite();
  Expect(suite.curve == CurveId::kSecp256k1,
         "Default suite must stay on secp256k1 in stage 1");
  Expect(suite.transcript_hash == tecdsa::HashId::kSha256,
         "Default suite transcript hash must stay SHA256");
  Expect(suite.commitment_hash == tecdsa::HashId::kSha256,
         "Default suite commitment hash must stay SHA256");
  Expect(DefaultGroupContext()->curve_id() == CurveId::kSecp256k1,
         "Default group context must stay on secp256k1 in stage 1");
}

void TestCoreAlgebraCompatibility() {
  const tecdsa::core::Scalar core_two = tecdsa::core::Scalar::FromUint64(2);
  const tecdsa::core::Scalar core_three = tecdsa::core::Scalar::FromUint64(3);
  const tecdsa::core::Point core_g2 =
      tecdsa::core::Point::GeneratorMultiply(core_two);
  const tecdsa::core::Point core_g3 =
      tecdsa::core::Point::GeneratorMultiply(core_three);

  const Scalar compat_two = Scalar::FromUint64(2);
  const ECPoint compat_g2 = ECPoint::GeneratorMultiply(compat_two);
  const ECPoint compat_g3 = ECPoint::GeneratorMultiply(Scalar::FromUint64(3));

  Expect(core_two.group()->curve_id() == CurveId::kSecp256k1,
         "core::Scalar must inherit the default secp256k1 group");
  Expect(core_g2.ToCompressedBytes() == compat_g2.ToCompressedBytes(),
         "compat ECPoint alias must match core::Point encoding");
  Expect(core_g3.ToCompressedBytes() == compat_g3.ToCompressedBytes(),
         "core::Point arithmetic must match legacy ECPoint behavior");
}

void TestStage2ParticipantAndVssHelpers() {
  const std::vector<PartyIndex> participants = {1, 2, 3};
  tecdsa::core::participant::ValidateParticipantsOrThrow(
      participants, /*self_id=*/2, "stage2 test");
  const auto participant_set = tecdsa::core::participant::BuildParticipantSet(
      participants, /*self_id=*/2, "stage2 test");
  Expect(participant_set.peers == std::vector<PartyIndex>({1, 3}),
         "participant_set must derive peers without self");

  std::unordered_map<PartyIndex, uint32_t> ok_messages = {
      {1, 10},
      {3, 30},
  };
  tecdsa::core::participant::RequireExactlyPeers(ok_messages, participants,
                                                 /*self_id=*/2, "ok_messages");
  ExpectThrow(
      [&]() {
        tecdsa::core::participant::RequireExactlyPeers(
            std::unordered_map<PartyIndex, uint32_t>{{1, 10}}, participants,
            /*self_id=*/2, "bad_messages");
      },
      "RequireExactlyPeers must reject missing peers");

  const std::vector<Scalar> polynomial = {
      Scalar::FromUint64(5),
      Scalar::FromUint64(7),
  };
  const Scalar share_for_two =
      tecdsa::core::vss::EvaluatePolynomialAt(polynomial, /*party_id=*/2);
  Expect(share_for_two == Scalar::FromUint64(19),
         "EvaluatePolynomialAt must evaluate the linear polynomial at x=2");

  const auto commitments = tecdsa::core::vss::BuildCommitments(polynomial);
  Expect(tecdsa::core::vss::VerifyShareForReceiver(
             /*receiver_id=*/2, /*threshold=*/1, commitments, share_for_two),
         "VerifyShareForReceiver must accept a valid Feldman share");
  Expect(!tecdsa::core::vss::VerifyShareForReceiver(
             /*receiver_id=*/2, /*threshold=*/1, commitments,
             share_for_two + Scalar::FromUint64(1)),
         "VerifyShareForReceiver must reject a tampered share");

  const auto lagrange =
      tecdsa::core::vss::ComputeLagrangeAtZero(participants);
  Expect(lagrange.size() == participants.size(),
         "ComputeLagrangeAtZero must return all coefficients");
  Expect(lagrange.at(1) + lagrange.at(2) + lagrange.at(3) ==
             Scalar::FromUint64(1),
         "Lagrange coefficients at zero must sum to one");

  const ECPoint sum = tecdsa::core::vss::SumPointsOrThrow(
      {ECPoint::GeneratorMultiply(Scalar::FromUint64(2)),
       ECPoint::GeneratorMultiply(Scalar::FromUint64(3))});
  Expect(sum == ECPoint::GeneratorMultiply(Scalar::FromUint64(5)),
         "SumPointsOrThrow must aggregate points in the same group");
}

void TestStage2SchnorrHelpers() {
  const Bytes session_id = {0x53, 0x32};
  const Scalar witness = Scalar::FromUint64(9);
  const ECPoint statement = ECPoint::GeneratorMultiply(witness);

  const auto proof =
      tecdsa::core::proof::BuildSchnorrProof(session_id, /*prover_id=*/7,
                                             statement, witness);
  Expect(tecdsa::core::proof::VerifySchnorrProof(session_id, /*prover_id=*/7,
                                                 statement, proof),
         "BuildSchnorrProof output must verify");

  auto tampered = proof;
  tampered.z = tampered.z + Scalar::FromUint64(1);
  Expect(!tecdsa::core::proof::VerifySchnorrProof(
             session_id, /*prover_id=*/7, statement, tampered),
         "VerifySchnorrProof must reject a tampered response");
}

void TestMpIntRoundTrip() {
  BigInt huge(1);
  for (size_t i = 0; i < 1023; ++i) {
    huge *= 2;
  }

  const std::vector<BigInt> values = {
      BigInt(0),
      BigInt(1),
      BigInt(255),
      BigInt(256),
      BigInt("123456789012345678901234567890", 10),
      huge};

  for (const auto& value : values) {
    const Bytes encoded = EncodeMpInt(value);
    const BigInt decoded = DecodeMpInt(encoded);
    Expect(decoded == value, "mpint round-trip must preserve value");
  }

  Bytes bad = EncodeMpInt(BigInt(42));
  bad.pop_back();
  ExpectThrow([&]() { (void)DecodeMpInt(bad); },
              "DecodeMpInt rejects malformed length");
}

void TestScalarEncodingAndReduction() {
  Scalar five(BigInt(5));
  const auto five_bytes = five.ToCanonicalBytes();
  Expect(five_bytes[31] == 5, "Scalar canonical encoding should match value");

  Scalar reduced(Scalar::ModulusQMpInt() + BigInt(7));
  Expect(reduced == Scalar(BigInt(7)), "Scalar constructor must reduce mod q");

  const Bytes q_bytes =
      tecdsa::bigint::ToFixedWidth(Scalar::ModulusQMpInt(), 32);
  ExpectThrow([&]() { (void)Scalar::FromCanonicalBytes(q_bytes); },
              "Canonical scalar decoding rejects >= q");

  Scalar zero = Scalar::FromBigEndianModQ(q_bytes);
  Expect(zero == Scalar(BigInt(0)),
         "Non-canonical decoder should reduce mod q");
}

void TestPointEncoding() {
  const ECPoint g = ECPoint::GeneratorMultiply(Scalar::FromUint64(1));
  const Bytes compressed = g.ToCompressedBytes();
  const ECPoint parsed = ECPoint::FromCompressed(compressed);
  Expect(parsed == g, "ECPoint round-trip must preserve valid points");

  Bytes invalid_prefix = compressed;
  invalid_prefix[0] = 0x04;
  ExpectThrow([&]() { (void)ECPoint::FromCompressed(invalid_prefix); },
              "ECPoint rejects non-compressed prefix");

  Bytes invalid_len(32, 0x02);
  ExpectThrow([&]() { (void)ECPoint::FromCompressed(invalid_len); },
              "ECPoint rejects invalid length");

  Bytes invalid_curve(33, 0x00);
  invalid_curve[0] = 0x02;
  ExpectThrow([&]() { (void)ECPoint::FromCompressed(invalid_curve); },
              "ECPoint rejects bytes not on secp256k1 curve");
}

void TestPointArithmetic() {
  const Scalar one = Scalar::FromUint64(1);
  const Scalar two = Scalar::FromUint64(2);
  const Scalar three = Scalar::FromUint64(3);
  const Scalar six = Scalar::FromUint64(6);

  const ECPoint g = ECPoint::GeneratorMultiply(one);
  const ECPoint g2 = ECPoint::GeneratorMultiply(two);
  const ECPoint g3 = ECPoint::GeneratorMultiply(three);

  const ECPoint g_plus_g2 = g.Add(g2);
  Expect(g_plus_g2 == g3, "ECPoint::Add should match scalar multiplication");

  const ECPoint g3_mul_two = g3.Mul(two);
  const ECPoint g6 = ECPoint::GeneratorMultiply(six);
  Expect(g3_mul_two == g6,
         "ECPoint::Mul should match generator multiplication");

  ExpectThrow(
      [&]() { (void)ECPoint::GeneratorMultiply(Scalar::FromUint64(0)); },
      "GeneratorMultiply rejects zero scalar");
}

void TestEcdsaVerifyRegression() {
  const Bytes msg32 = {
      0x4d, 0x34, 0x2d, 0x73, 0x69, 0x67, 0x6e, 0x2d, 0x74, 0x65, 0x73,
      0x74, 0x2d, 0x30, 0x30, 0x31, 0xaa, 0xbb, 0xcc, 0xdd, 0x10, 0x20,
      0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xa0, 0xb0, 0xc0,
  };

  const Scalar private_key = Scalar::FromUint64(7);
  const Scalar nonce = Scalar::FromUint64(3);
  const ECPoint public_key = ECPoint::GeneratorMultiply(private_key);
  const ECPoint nonce_point = ECPoint::GeneratorMultiply(nonce);
  const Scalar r = XCoordinateModQ(nonce_point);
  const Scalar z = Scalar::FromBigEndianModQ(msg32);
  const Scalar s = nonce.InverseModQ() * (z + r * private_key);

  Expect(VerifyEcdsaSignatureMath(public_key, msg32, r, s),
         "ECDSA verify should accept a valid signature");

  Scalar wrong_r = r + Scalar::FromUint64(1);
  if (wrong_r == Scalar()) {
    wrong_r = wrong_r + Scalar::FromUint64(1);
  }
  Expect(!VerifyEcdsaSignatureMath(public_key, msg32, wrong_r, s),
         "ECDSA verify should reject wrong r");

  Scalar wrong_s = s + Scalar::FromUint64(1);
  if (wrong_s == Scalar()) {
    wrong_s = wrong_s + Scalar::FromUint64(1);
  }
  Expect(!VerifyEcdsaSignatureMath(public_key, msg32, r, wrong_s),
         "ECDSA verify should reject wrong s");

  const ECPoint wrong_public_key =
      ECPoint::GeneratorMultiply(private_key + Scalar::FromUint64(1));
  Expect(!VerifyEcdsaSignatureMath(wrong_public_key, msg32, r, s),
         "ECDSA verify should reject wrong public key");

  Bytes wrong_msg32 = msg32;
  wrong_msg32[0] ^= 0x01;
  Expect(!VerifyEcdsaSignatureMath(public_key, wrong_msg32, r, s),
         "ECDSA verify should reject wrong msg32");
}

void TestHashAndCommitment() {
  const Bytes msg = {'a', 'b', 'c'};
  const Bytes digest_via_suite = tecdsa::Hash(tecdsa::HashId::kSha256, msg);
  const Bytes digest = Sha256(msg);
  const Bytes expected = {0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
                          0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
                          0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
                          0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad};
  Expect(digest == expected, "SHA256 must match known test vector for 'abc'");
  Expect(digest_via_suite == expected,
         "suite-driven hash helper must match SHA256 test vector");

  const std::string domain = "keygen/phase1";
  const Bytes randomness = {1, 2, 3, 4, 5};
  const Bytes commitment = ComputeCommitment(domain, msg, randomness);
  Expect(VerifyCommitment(domain, msg, randomness, commitment),
         "Commitment verifies for valid open");

  Bytes tampered_msg = msg;
  tampered_msg[0] ^= 0x01;
  Expect(!VerifyCommitment(domain, tampered_msg, randomness, commitment),
         "Commitment verify fails for tampered message");

  Bytes tampered_r = randomness;
  tampered_r.back() ^= 0x01;
  Expect(!VerifyCommitment(domain, msg, tampered_r, commitment),
         "Commitment verify fails for tampered randomness");

  const auto generated = CommitMessage(domain, msg);
  Expect(generated.randomness.size() == 32,
         "CommitMessage default randomness length is 32");
  Expect(
      VerifyCommitment(domain, msg, generated.randomness, generated.commitment),
      "CommitMessage output should verify");
}

void TestCsprng() {
  const Bytes random16 = tecdsa::Csprng::RandomBytes(16);
  Expect(random16.size() == 16,
         "Csprng::RandomBytes should return requested length");

  const Scalar s = tecdsa::Csprng::RandomScalar();
  Expect(s.mp_value() < Scalar::ModulusQMpInt(),
         "Csprng::RandomScalar should return value in Z_q");
}

void TestTranscriptChallengeDeterminismAndOrder() {
  const Bytes first = {1, 2, 3};
  const Bytes second = {9, 8};

  Transcript t1;
  t1.append("field1", first);
  t1.append("field2", second);

  Transcript t2;
  t2.append("field1", first);
  t2.append("field2", second);

  Transcript t3;
  t3.append("field2", second);
  t3.append("field1", first);

  const Scalar c1 = t1.challenge_scalar_mod_q();
  const Scalar c2 = t2.challenge_scalar_mod_q();
  const Scalar c3 = t3.challenge_scalar_mod_q();

  Transcript t4(tecdsa::HashId::kSha512);
  t4.append("field1", first);
  t4.append("field2", second);
  const Scalar c4 = t4.challenge_scalar_mod_q();

  Expect(c1 == c2, "Transcript challenge must be deterministic");
  Expect(c1 != c3, "Transcript challenge should depend on append order");
  Expect(c1 != c4,
         "Transcript challenge should honor the configured suite hash");
}

void TestPaillierNative() {
  PaillierProvider paillier(/*modulus_bits=*/512);
  Expect(paillier.VerifyKeyPair(), "Native Paillier key pair should verify");

  const BigInt a(50);
  const BigInt b(76);

  const BigInt c_a = paillier.EncryptBigInt(a);
  const BigInt c_b = paillier.EncryptBigInt(b);

  const BigInt c_sum = paillier.AddCiphertextsBigInt(c_a, c_b);
  const BigInt plain_sum = paillier.DecryptBigInt(c_sum);
  Expect(plain_sum == a + b,
         "Paillier encrypted addition should decrypt to a+b");

  const BigInt c_mul = paillier.MulPlaintextBigInt(c_a, b);
  const BigInt plain_mul = paillier.DecryptBigInt(c_mul);
  Expect(plain_mul == a * b,
         "Paillier encrypted/plain multiplication should decrypt to a*b");

  const auto enc_with_r = paillier.EncryptWithRandomBigInt(a);
  const BigInt c_same =
      paillier.EncryptWithProvidedRandomBigInt(a, enc_with_r.randomness);
  Expect(enc_with_r.ciphertext == c_same,
         "EncryptWithRandom should be reproducible with the same randomness");

  ExpectThrow(
      [&]() { (void)paillier.EncryptWithProvidedRandomBigInt(a, BigInt(0)); },
      "EncryptWithProvidedRandom rejects zero randomness");
  ExpectThrow(
      [&]() {
        (void)paillier.EncryptWithProvidedRandomBigInt(
            a, paillier.modulus_n_bigint());
      },
      "EncryptWithProvidedRandom rejects randomness not in Z*_N");

  const BigInt c_neg_one = paillier.EncryptBigInt(BigInt(0) - BigInt(1));
  Expect(paillier.DecryptBigInt(c_neg_one) ==
             paillier.modulus_n_bigint() - BigInt(1),
         "Paillier encryption should normalize negative plaintext to mod N");

  const BigInt c_wrap =
      paillier.EncryptBigInt(paillier.modulus_n_bigint() + BigInt(7));
  Expect(paillier.DecryptBigInt(c_wrap) == BigInt(7),
         "Paillier encryption should normalize plaintext larger than N");
}

}  // namespace

int main() {
  try {
    TestStage1SuiteMetadata();
    TestCoreAlgebraCompatibility();
    TestStage2ParticipantAndVssHelpers();
    TestStage2SchnorrHelpers();
    TestMpIntRoundTrip();
    TestScalarEncodingAndReduction();
    TestPointEncoding();
    TestPointArithmetic();
    TestEcdsaVerifyRegression();
    TestHashAndCommitment();
    TestCsprng();
    TestTranscriptChallengeDeterminismAndOrder();
    TestPaillierNative();
  } catch (const std::exception& ex) {
    std::cerr << ex.what() << '\n';
    return 1;
  }

  std::cout << "crypto_primitives_tests passed" << '\n';
  return 0;
}
