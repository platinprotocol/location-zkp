/* Platin.io 2018
 * written by Vadym Fedyukovych
 * gcd() for Gaussian Integers
 */

#include <iostream>
#include "proofs.hpp"

// https://math.stackexchange.com/questions/1969019/how-can-i-find-gcd167i-10-5i-by-using-the-euclidean-algorithm
void ggcd(const GInt &ga, const GInt &gb, GInt &gc) {
  bool done = false;
  CryptoPP::Integer denom;
  GInt qt, rr, a = ga, b = gb, last_rr(0, 0);
  do {
    // mult by conj, div by norm^2
    denom = b.r * b.r + b.i * b.i;
    qt.r = ground(a.r * b.r + a.i * b.i, denom);
    qt.i = ground(a.i * b.r - a.r * b.i, denom);
    std::cout << "qtnt(" << qt.r << ", " << qt.i << ")" << std::endl;
    rr.r = a.r - (b.r * qt.r - b.i * qt.i);
    rr.i = a.i - (b.r * qt.i + b.i * qt.r);
    std::cout << "rmdr(" << rr.r << ", " << rr.i << ")" << std::endl;
    if(rr.r == 0 && rr.i == 0) {
      done = true;
      gc = last_rr;
      std::cout << "gdc(" << gc.r << ", " << gc.i << ")" << std::endl;
    } else {
      a = b;
      b = rr;
      last_rr = rr;
    }
  } while(!done);
}
