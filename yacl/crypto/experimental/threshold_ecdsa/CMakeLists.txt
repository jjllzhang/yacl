# Copyright 2026 Ant Group Co., Ltd.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

cmake_minimum_required(VERSION 3.22)
project(threshold_ecdsa LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(OpenSSL QUIET)
find_path(ABSL_INCLUDE_DIR absl/debugging/stacktrace.h)
find_path(LIBTOMMATH_INCLUDE_DIR libtommath/tommath.h)

set(BUILD_SHARED_LIBS OFF CACHE BOOL "" FORCE)

if(NOT ABSL_INCLUDE_DIR)
  message(FATAL_ERROR
    "threshold_ecdsa CMake build requires Abseil headers "
    "(missing absl/debugging/stacktrace.h). "
    "Use Bazel inside the YACL repo, or provide Abseil via CMAKE_PREFIX_PATH/CPATH.")
endif()

if(NOT LIBTOMMATH_INCLUDE_DIR)
  message(FATAL_ERROR
    "threshold_ecdsa CMake build requires libtommath headers "
    "(missing libtommath/tommath.h). "
    "Use Bazel inside the YACL repo, or provide libtommath via CMAKE_PREFIX_PATH/CPATH.")
endif()

set(TSIG_CORE_SRCS
  core/suite/group_context.cc
  core/algebra/scalar.cc
  core/algebra/point.cc
  core/encoding/encoding.cc
  core/mta/proofs.cc
  core/mta/session.cc
  core/commitment/commitment.cc
  core/transcript/transcript.cc
  core/participant/participant_set.cc
  core/proof/schnorr.cc
  core/paillier/paillier.cc
  core/paillier/aux_proofs.cc
  core/paillier/aux_proofs_codec.cc
  core/paillier/aux_proofs_math.cc
  core/vss/feldman.cc
  core/vss/dealerless_dkg.cc
  crypto/scalar.cc
  crypto/ec_point.cc
  crypto/hash.cc
  crypto/random.cc
  crypto/commitment.cc
  crypto/encoding.cc
  crypto/paillier.cc
  crypto/strict_proofs_codec.cc
  crypto/strict_proofs_math.cc
  crypto/strict_proofs.cc
  crypto/transcript.cc
)

set(TSIG_ECDSA_SRCS
  crypto/ecdsa_verify.cc
  ecdsa/keygen/keygen.cc
  ecdsa/sign/sign.cc
  ecdsa/verify/verify.cc
  ecdsa/sign/relation_proofs.cc
  protocol/proto_common.cc
  protocol/proto_sign_internal.cc
  protocol/keygen.cc
  protocol/sign.cc
)

set(TSIG_SM2_SRCS
  sm2/zid/zid.cc
  sm2/keygen/keygen.cc
  sm2/presign/offline.cc
  sm2/sign/online.cc
  sm2/verify/verify.cc
)

add_library(tsig_core ${TSIG_CORE_SRCS})

target_include_directories(tsig_core PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/../../../../
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${ABSL_INCLUDE_DIR}
  ${LIBTOMMATH_INCLUDE_DIR}
)

if(OpenSSL_FOUND)
  target_link_libraries(tsig_core PUBLIC OpenSSL::Crypto)
else()
  target_link_libraries(tsig_core PUBLIC crypto)
endif()

add_library(tsig_ecdsa ${TSIG_ECDSA_SRCS})
target_include_directories(tsig_ecdsa PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/../../../../
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${ABSL_INCLUDE_DIR}
  ${LIBTOMMATH_INCLUDE_DIR}
)
target_link_libraries(tsig_ecdsa PUBLIC tsig_core)

add_library(tsig_sm2 ${TSIG_SM2_SRCS})
target_include_directories(tsig_sm2 PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/../../../../
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${ABSL_INCLUDE_DIR}
  ${LIBTOMMATH_INCLUDE_DIR}
)
target_link_libraries(tsig_sm2 PUBLIC tsig_core)

# Preserve legacy consumer names while switching the canonical target graph.
add_library(tecdsa_core ALIAS tsig_ecdsa)
add_library(tecdsa_m0 ALIAS tsig_ecdsa)

add_executable(crypto_primitives_tests tests/crypto_primitives_test.cc)
target_link_libraries(crypto_primitives_tests PRIVATE tsig_ecdsa)

add_executable(keygen_flow_tests
  tests/keygen_flow_test.cc
  tests/sign_flow_test_support.cc
)
target_link_libraries(keygen_flow_tests PRIVATE tsig_ecdsa)

add_executable(sign_flow_tests
  tests/sign_flow_test.cc
  tests/sign_flow_test_cases.cc
  tests/sign_flow_test_support.cc
)
target_link_libraries(sign_flow_tests PRIVATE tsig_ecdsa)

add_executable(sm2_keygen_flow_tests
  tests/sm2/keygen_flow_test.cc
  tests/sm2/test_support.cc
)
target_link_libraries(sm2_keygen_flow_tests PRIVATE tsig_sm2)

add_executable(sm2_sign_flow_tests
  tests/sm2/sign_flow_test.cc
  tests/sm2/offline_presign_test.cc
  tests/sm2/online_sign_test.cc
  tests/sm2/tamper_cases_test.cc
  tests/sm2/test_support.cc
)
target_link_libraries(sm2_sign_flow_tests PRIVATE tsig_sm2)

enable_testing()
add_test(NAME crypto_primitives_tests COMMAND crypto_primitives_tests)
add_test(NAME keygen_flow_tests COMMAND keygen_flow_tests)
add_test(NAME sign_flow_tests COMMAND sign_flow_tests)
add_test(NAME sm2_keygen_flow_tests COMMAND sm2_keygen_flow_tests)
add_test(NAME sm2_sign_flow_tests COMMAND sm2_sign_flow_tests)
