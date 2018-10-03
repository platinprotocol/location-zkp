#include <string>
#include <iostream>
#include "cryptopp/integer.h"
#include "cryptopp/modarith.h"
#include "proofs.hpp"

// make cli_ni && ./cli_ni_proof 1 1 10000 1 1
// make cli_ni && ./cli_ni_proof 44.0 21.0 38000.0 44.1 21.3
// make cli_ni && ./cli_ni_proof 50.428938 30.559123 1000 50.428938 30.559123
// make cli_ni && ./cli_ni_proof 50.428938 30.559123 1000 50.4299018 30.5595315
int main(int argc, char **argv) {
  std::string proof;

  if(argc != 6) {
       std::cerr << "Wrong argument to cli_ni_proof. Expected args: xl yl d xn yn (coordinates are in decimal degrees)" << std::endl;
       return 1;
  }

  double xl = std::stod(argv[1]),
        yl = std::stod(argv[2]),
        zl = 0.0,
        d = std::stod(argv[3]),
        xn = std::stod(argv[4]),
        yn = std::stod(argv[5]),
        zn = 0.0;

  std::cout.precision(10);

  std::cout << "xl: " << xl << std::endl;
  std::cout << "yl: " << yl << std::endl;
  std::cout << "d: " << d << std::endl;
  std::cout << "xn: " << xn << std::endl;
  std::cout << "yn: " << yn << std::endl;

  proof = ni_proof_create(xn, yn, zn, xl, yl, zl, d);

  std::cout << "generated_proof_value: " << proof << std::endl;

  bool ok = ni_proof_verify(proof, xl, yl, zl, d);

  std::cout << "self_check_result_int: " << ok << std::endl;
  std::cout << "self_check_result_bool: " << (ok == 1 ?  "true" : "false")<< std::endl << std::flush;

  return 0;
}