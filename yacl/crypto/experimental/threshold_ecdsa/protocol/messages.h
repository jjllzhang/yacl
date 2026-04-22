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

#include <unordered_map>

#include "yacl/crypto/experimental/threshold_ecdsa/common/ids.h"
#include "yacl/crypto/experimental/threshold_ecdsa/core/mta/messages.h"
#include "yacl/crypto/experimental/threshold_ecdsa/core/mta/proofs.h"
#include "yacl/crypto/experimental/threshold_ecdsa/core/proof/types.h"
#include "yacl/crypto/experimental/threshold_ecdsa/ecdsa/keygen/messages.h"
#include "yacl/crypto/experimental/threshold_ecdsa/ecdsa/proofs/types.h"
#include "yacl/crypto/experimental/threshold_ecdsa/ecdsa/sign/messages.h"

namespace tecdsa::proto {

template <typename T>
using PeerMap = std::unordered_map<PartyIndex, T>;

using SchnorrProof = tecdsa::core::proof::SchnorrProof;
using VRelationProof = tecdsa::ecdsa::sign::VRelationProof;

// Compatibility wrapper that remains convertible to both the scheme-owned
// ECDSA proof type and the legacy core transport proof type.
struct A1RangeProof {
  tecdsa::ecdsa::proofs::BigInt z = tecdsa::ecdsa::proofs::BigInt(0);
  tecdsa::ecdsa::proofs::BigInt u = tecdsa::ecdsa::proofs::BigInt(0);
  tecdsa::ecdsa::proofs::BigInt w = tecdsa::ecdsa::proofs::BigInt(0);
  tecdsa::ecdsa::proofs::BigInt s = tecdsa::ecdsa::proofs::BigInt(0);
  tecdsa::ecdsa::proofs::BigInt s1 = tecdsa::ecdsa::proofs::BigInt(0);
  tecdsa::ecdsa::proofs::BigInt s2 = tecdsa::ecdsa::proofs::BigInt(0);

  operator tecdsa::ecdsa::proofs::A1RangeProof() const {
    return tecdsa::ecdsa::proofs::A1RangeProof{
        .z = z,
        .u = u,
        .w = w,
        .s = s,
        .s1 = s1,
        .s2 = s2,
    };
  }

  operator tecdsa::core::mta::A1RangeProof() const {
    return tecdsa::core::mta::A1RangeProof{
        .z = z,
        .u = u,
        .w = w,
        .s = s,
        .s1 = s1,
        .s2 = s2,
    };
  }
};

// Compatibility wrapper that remains convertible to both the scheme-owned
// ECDSA proof type and the legacy core transport proof type.
struct A2MtAwcProof {
  ECPoint u;
  tecdsa::ecdsa::proofs::BigInt z = tecdsa::ecdsa::proofs::BigInt(0);
  tecdsa::ecdsa::proofs::BigInt z2 = tecdsa::ecdsa::proofs::BigInt(0);
  tecdsa::ecdsa::proofs::BigInt t = tecdsa::ecdsa::proofs::BigInt(0);
  tecdsa::ecdsa::proofs::BigInt v = tecdsa::ecdsa::proofs::BigInt(0);
  tecdsa::ecdsa::proofs::BigInt w = tecdsa::ecdsa::proofs::BigInt(0);
  tecdsa::ecdsa::proofs::BigInt s = tecdsa::ecdsa::proofs::BigInt(0);
  tecdsa::ecdsa::proofs::BigInt s1 = tecdsa::ecdsa::proofs::BigInt(0);
  tecdsa::ecdsa::proofs::BigInt s2 = tecdsa::ecdsa::proofs::BigInt(0);
  tecdsa::ecdsa::proofs::BigInt t1 = tecdsa::ecdsa::proofs::BigInt(0);
  tecdsa::ecdsa::proofs::BigInt t2 = tecdsa::ecdsa::proofs::BigInt(0);

  operator tecdsa::ecdsa::proofs::A2MtAwcProof() const {
    return tecdsa::ecdsa::proofs::A2MtAwcProof{
        .u = u,
        .z = z,
        .z2 = z2,
        .t = t,
        .v = v,
        .w = w,
        .s = s,
        .s1 = s1,
        .s2 = s2,
        .t1 = t1,
        .t2 = t2,
    };
  }

  operator tecdsa::core::mta::A2MtAwcProof() const {
    return tecdsa::core::mta::A2MtAwcProof{
        .u = u,
        .z = z,
        .z2 = z2,
        .t = t,
        .v = v,
        .w = w,
        .s = s,
        .s1 = s1,
        .s2 = s2,
        .t1 = t1,
        .t2 = t2,
    };
  }
};

// Compatibility wrapper that remains convertible to both the scheme-owned
// ECDSA proof type and the legacy core transport proof type.
struct A3MtAProof {
  tecdsa::ecdsa::proofs::BigInt z = tecdsa::ecdsa::proofs::BigInt(0);
  tecdsa::ecdsa::proofs::BigInt z2 = tecdsa::ecdsa::proofs::BigInt(0);
  tecdsa::ecdsa::proofs::BigInt t = tecdsa::ecdsa::proofs::BigInt(0);
  tecdsa::ecdsa::proofs::BigInt v = tecdsa::ecdsa::proofs::BigInt(0);
  tecdsa::ecdsa::proofs::BigInt w = tecdsa::ecdsa::proofs::BigInt(0);
  tecdsa::ecdsa::proofs::BigInt s = tecdsa::ecdsa::proofs::BigInt(0);
  tecdsa::ecdsa::proofs::BigInt s1 = tecdsa::ecdsa::proofs::BigInt(0);
  tecdsa::ecdsa::proofs::BigInt s2 = tecdsa::ecdsa::proofs::BigInt(0);
  tecdsa::ecdsa::proofs::BigInt t1 = tecdsa::ecdsa::proofs::BigInt(0);
  tecdsa::ecdsa::proofs::BigInt t2 = tecdsa::ecdsa::proofs::BigInt(0);

  operator tecdsa::ecdsa::proofs::A3MtAProof() const {
    return tecdsa::ecdsa::proofs::A3MtAProof{
        .z = z,
        .z2 = z2,
        .t = t,
        .v = v,
        .w = w,
        .s = s,
        .s1 = s1,
        .s2 = s2,
        .t1 = t1,
        .t2 = t2,
    };
  }

  operator tecdsa::core::mta::A3MtAProof() const {
    return tecdsa::core::mta::A3MtAProof{
        .z = z,
        .z2 = z2,
        .t = t,
        .v = v,
        .w = w,
        .s = s,
        .s1 = s1,
        .s2 = s2,
        .t1 = t1,
        .t2 = t2,
    };
  }
};

using KeygenRound1Msg = tecdsa::ecdsa::keygen::KeygenRound1Msg;
using KeygenRound2Broadcast = tecdsa::ecdsa::keygen::KeygenRound2Broadcast;
using KeygenRound2Out = tecdsa::ecdsa::keygen::KeygenRound2Out;
using KeygenRound3Msg = tecdsa::ecdsa::keygen::KeygenRound3Msg;
using LocalKeyShare = tecdsa::ecdsa::keygen::LocalKeyShare;
using PublicKeygenData = tecdsa::ecdsa::keygen::PublicKeygenData;
using KeygenOutput = tecdsa::ecdsa::keygen::KeygenOutput;
using MtaType = tecdsa::ecdsa::sign::MtaType;
using SignRound1Msg = tecdsa::ecdsa::sign::SignRound1Msg;
using SignRound2Request = tecdsa::ecdsa::sign::SignRound2Request;
using SignRound2Response = tecdsa::ecdsa::sign::SignRound2Response;
using SignRound3Msg = tecdsa::ecdsa::sign::SignRound3Msg;
using SignRound4Msg = tecdsa::ecdsa::sign::SignRound4Msg;
using SignRound5AMsg = tecdsa::ecdsa::sign::SignRound5AMsg;
using SignRound5BMsg = tecdsa::ecdsa::sign::SignRound5BMsg;
using SignRound5CMsg = tecdsa::ecdsa::sign::SignRound5CMsg;
using SignRound5DMsg = tecdsa::ecdsa::sign::SignRound5DMsg;
using Signature = tecdsa::ecdsa::sign::Signature;

}  // namespace tecdsa::proto
