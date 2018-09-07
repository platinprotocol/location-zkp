/* Platin.io 2018
 * written by Vadym Fedyukovych
 * gcd() for Gaussian Integers and 2-squares for (4k+1) primes
 */

#include <iostream>
#include "cryptopp/integer.h"
#include "cryptopp/modarith.h"

class GInt {
public:
  GInt(CryptoPP::Integer mr, CryptoPP::Integer mi) {r = mr; i = mi;};
  GInt(const long mr, const long mi) {r = mr; i = mi;};
  GInt() {r = 0; i = 0;};

  CryptoPP::Integer r, i;
};

CryptoPP::Integer ground(const CryptoPP::Integer &numr, const CryptoPP::Integer &denomn) {
  CryptoPP::Integer remn, qtnt;

  remn = numr.Modulo(denomn);
  qtnt = numr / denomn;
  if(2*remn > denomn)
    qtnt++;
  return qtnt;
}

// https://math.stackexchange.com/questions/1969019/how-can-i-find-gcd167i-10-5i-by-using-the-euclidean-algorithm
void ggcd(const GInt &pa, const GInt &pb, GInt &c) {
  bool done = false;
  CryptoPP::Integer denom;
  GInt qt, rr, a = pa, b = pb, last_rr(0, 0);
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
      c = last_rr;
      std::cout << "gdc(" << c.r << ", " << c.i << ")" << std::endl;
    } else {
      a = b;
      b = rr;
      last_rr = rr;
    }
  } while(!done);
}

int main() {
/* test for rounding
  std::cout << ground(9, 5) << std::endl   // 2
	    << ground(6, 5) << std::endl   // 1
	    << ground(-6, 5) << std::endl  // -1
	    << ground(-8, 5) << std::endl; // -2
*/
  GInt x1num(16, 7), x1denm(10, -5), x1;
  ggcd(x1num, x1denm, x1); // should be (1,1), (1,2)

// 13 = 4*3 + 1, is a prime
// 13 = 3^2 + 2^2
// 2^6 = -1  ->  2^3 = sqrt(-1) = 8
  GInt a(13, 0), b(8, 1), c;
  // gcd(p, t+i)  for prime p and square-root t
  ggcd(a, b, c);

  return 0;
}
