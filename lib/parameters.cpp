/* Platin.io 2018
 * written by Vadym Fedyukovych
 * proofs library
 */

#include <iostream>
#include "proofs.hpp"

void init_parameters(Parameters &pp) {
// (19 * 10 + 1)*(103 = 17 * 6 + 1) = 191*103 = 19673;  order 17*19 = 323, co-order 30
  pp.n = 19673;
  pp.group.SetModulus(pp.n);

// 4323 = 4^30%19673
// 4323^323%19673 = 1
  pp.g = 4323;

  pp.gx = 18652;
  pp.gy = 12642;
  pp.gz = 19445;
  pp.gr = 17679;
  pp.h[0] = 16385;
  pp.h[1] = 9555;
  pp.h[2] = 12638;
  pp.h[3] = 2153;
}

