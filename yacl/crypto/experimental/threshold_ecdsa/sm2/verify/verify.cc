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

#include "yacl/crypto/experimental/threshold_ecdsa/sm2/verify/verify.h"

#include <exception>

#include "yacl/crypto/experimental/threshold_ecdsa/sm2/common.h"

namespace tecdsa::sm2::verify {

bool VerifySm2SignatureMath(const ECPoint& public_key,
                            const zid::IdentityBinding& binding,
                            std::span<const uint8_t> message,
                            const Signature& signature) {
  if (signature.r.value() == 0 || signature.s.value() == 0) {
    return false;
  }

  try {
    const Bytes digest = zid::PreprocessMessageDigest(binding, message);
    const Scalar e = Scalar::FromBigEndianModQ(digest, internal::Sm2Group());
    const Scalar t = signature.r + signature.s;
    if (t.value() == 0) {
      return false;
    }

    ECPoint reconstructed = ECPoint::GeneratorMultiply(signature.s);
    reconstructed = reconstructed.Add(public_key.Mul(t));
    const Scalar expected_r = e + internal::XCoordinateModN(reconstructed);
    return expected_r == signature.r;
  } catch (const std::exception&) {
    return false;
  }
}

}  // namespace tecdsa::sm2::verify
