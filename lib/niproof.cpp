/* Platin.io 2018
 * written by Vadym Fedyukovych
 * proofs library
 */

#include <string>
#include <iostream>
#include "cryptopp/integer.h"
#include "cryptopp/modarith.h"
#include "proofs.hpp"

std::string ni_proof_create(const double xn, const double yn, const double zn, const double xl, const double yl, const double zl, const double d) {
  std::string proof("Hello proof");
  return proof;
}

bool ni_proof_verify(const std::string proof) {
  return true;
}
