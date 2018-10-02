#include <string>
#include <iostream>
#include "proofs.hpp"

int main() {
  std::string proof;
  bool ok;
  double xl = 44.0, yl = 21.0, zl = 2.0, d = 38000.0;

  // Geo coordinates, in decimal degrees for latitude-longitude
  proof = ni_proof_create(44.1, 21.3, 3.9,
                          xl, yl, zl, d);
  std::cout << "proof: " << proof << std::endl;
  ok = ni_proof_verify(proof, xl, yl, zl, d);
  if(ok) {
    std::cout << "True" << std::endl;
  } else {
    std::cout << "False" << std::endl;
  }
  return 0;
}
