/* Platin.io 2018
 * written by Vadym Fedyukovych
 * gcd() for quaternions
 */

#include <iostream>
#include "proofs.hpp"

// a = b r + s
// (b^* a)/|b| = r + s/|b|

// (p_0 + p_1 i + p_2 j + p_3 k)(q_0 + q_1 i + q_2 j + q_3 k) =
// p_0 q_0 − (p_1 q_1 + p_2 q_2 + p_3 q_3) + p_0 (q_1 i + q_2 j + q_3 k) + q_0 (p_1 i + p_2 j + p_3 k) +
// (p_2 q_3 − p_3 q_2) i + (p_3 q_1 − p_1 q_3) j + (p_1 q_2 − p_2 q_1) k

void qgcrd(const QInt &qa, const QInt &qb, QInt &qc) {
  bool done = false;
  CryptoPP::Integer denom;
  QInt qt, rr, a = qa, b = qb, last_rr(0, 0, 0, 0);
  do {
    denom = b.r * b.r + b.i * b.i + b.j * b.j + b.k * b.k;
    // b^* a
    qt.r = ground(b.r * a.r + b.i * a.i + b.j * a.j + b.k * a.k, denom);
    qt.i = ground(-b.r * a.i - b.i * a.r - (b.j * a.k - b.k * a.j), denom);
    qt.j = ground(-b.r * a.j - b.j * a.r - (b.k * a.i - b.i * a.k), denom);
    qt.k = ground(-b.r * a.k - b.k * a.r - (b.i * a.j - b.j * a.i), denom);
    std::cout << "quotient(" << qt.r << ", " << qt.i << ", " << qt.k << ", " << qt.k << ")" << std::endl;
    // a - b r
    rr.r = a.r - (b.r * qt.r - b.i * qt.i - b.j * qt.j - b.k * qt.k);
    rr.i = a.i - (b.r * qt.i + b.i * qt.r + (b.j * qt.k - b.k * qt.j));
    rr.j = a.j - (b.r * qt.j + b.j * qt.r + (b.k * qt.i - b.i * qt.k));
    rr.k = a.k - (b.r * qt.k + b.k * qt.r + (b.i * qt.j - b.j * qt.i));
    std::cout << "reminder(" << rr.r << ", " << rr.i << ", " << rr.j << ", " << rr.k << ")" << std::endl;
    if(rr.r == 0 && rr.i == 0 && rr.j == 0 && rr.k == 0) {
      done = true;
      qc = last_rr;
      std::cout << "gdrc(" << qc.r << ", " << qc.i << ", " << qc.j << ", " << qc.k << ")" << std::endl;
    } else {
      a = b;
      b = rr;
      last_rr = rr;
    }
  } while(!done);
}
