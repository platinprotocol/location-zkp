#include <string>
#include <iostream>
#include "cryptopp/integer.h"
#include "cryptopp/modarith.h"
#include "proofs.hpp"

// make cli_ni && ./cli_ni_proof 1 1 1 1 1
// make cli_ni && ./cli_ni_proof 44.0 21.0 38000.0 44.1 21.3
int main(int argc, char **argv) {
  std::string proof;

  double xl = std::stod(argv[1]),
        yl = std::stod(argv[2]),
        zl = 2.0,
        d = std::stod(argv[3]),
        xn = std::stod(argv[4]),
        yn = std::stod(argv[5]),
        zn = 3.9;

  if(argc != 6) {
       std::cerr << "Wrong argument to cli_ni_proof. Expected args: xl yl d xn yn (coordinates are in decimal degrees)" << std::endl;
       return 1;
  }

  proof = ni_proof_create(xn, yn, zn, xl, yl, zl, d);

  std::cout << "generated_proof_value: " << proof << std::endl;

  return 0;
}