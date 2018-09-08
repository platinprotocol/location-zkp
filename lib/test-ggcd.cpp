/* Platin.io 2018
 * written by Vadym Fedyukovych
 * test gcd() for Gaussian Integers
 */

#include <iostream>
#include "proofs.hpp"

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
