#include <string>
#include <iostream>
#include "cryptopp/integer.h"
#include "cryptopp/modarith.h"
#include "proofs.hpp"

int main() {
  std::string proof("11.22222.5555555555555555.");
  bool ok;

  //  proof = ni_proof_create(1.0, 1.0, 1.0,
  //                          2.0, 2.0, 2.0, 8.0);
  ok = ni_proof_verify(proof);

  return 0;
}
