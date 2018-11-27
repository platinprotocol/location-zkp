/* Platin.io 2018
 * written by Vadym Fedyukovych
 * proofs library
 */

#include <iostream>
#include "proofs.hpp"
#include "primes_lst.hpp"

void prime4table() {
  long k, a1, a2, a3, a4;

  for(k=0; k<PSZ; k++) {
    pa4decomposition(primesl[k], a1, a2, a3, a4);
    std::cout << "  {" << primesl[k] << ", {" << a1 << ", " <<  a2 << ", " <<  a3 << ", " <<  a4 << "}}," << std::endl;
  }
}

int main() {
  prime4table();
  return 0;
}
