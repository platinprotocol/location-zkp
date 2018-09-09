/* Platin.io 2018
 * written by Vadym Fedyukovych
 * test qgcrd() for quaternions
 */

#include <iostream>
#include "proofs.hpp"

int main() {
// n = 1^2 + 1^2 + 0 + 0 = 5
// (2n)^5 = 100000
// p = 4k+1, p = 5s-1  (s odd)  (k even)  449?
// 3^224 = -1   3^112 = 67
  GInt a(419, 0), b(67, 1), c;
  // gcd(p, t+i)  for prime p and square-root t
  ggcd(a, b, c);
  // A = 1, B = 0

// p = A^2 + B^2
// qgcrd(n, A + Bi + j)
//  QInt qa(419, 0, 0, 0), qb(67, 1, 0, 0), qc;
  QInt qa(5, 0, 0, 0), qb(1, 0, 1, 0), qc;
  qgcrd(qa, qb, qc);

  return 0;
}
// 38966 = 197*197 + 12*12 + 3*3 + 2*2
// expected qgcrd output: (197 + 12i + 3j + 2k)
