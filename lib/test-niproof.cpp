#include <string>
#include <iostream>
#include "proofs.hpp"

int main() {
  std::string proof;
  bool ok;

  // Geo coordinates, in decimal degrees for latitude-longitude
  proof = ni_proof_create(44.1, 21.3, 3.9,
                          44.0, 21.0, 2.0, 38000.0);
  std::cout << "proof: " << proof << std::endl;
  ok = ni_proof_verify(proof);
  if(ok) {
    std::cout << "True" << std::endl;
  } else {
    std::cout << "False" << std::endl;
  }
  return 0;
}
