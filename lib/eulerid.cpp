/* Platin.io 2018
 * written by Vadym Fedyukovych
 * proofs library
 *
 Euler's four-square identity
  (a_1^2 + a_2^2 + a_3^2 + a_4^2) (b_1^2 + b_2^2 + b_3^2 + b_4^2) =
    (a_1 b_1 - a_2 b_2 - a_3 b_3 - a_4 b_4)^2 +
    (a_1 b_2 + a_2 b_1 + a_3 b_4 - a_4 b_3)^2 +
    (a_1 b_3 - a_2 b_4 + a_3 b_1 + a_4 b_2)^2+
    (a_1 b_4 + a_2 b_3 - a_3 b_2 + a_4 b_1)^2
 */

#include "proofs.hpp"

void euclidid(long a[4], long b[4], long *c[4]) {
  *c[0] = a[0] * b[0] - a[1] * b[1] - a[2] * b[2] - a[3] * b[3];
  *c[1] = a[0] * b[1] + a[1] * b[0] + a[2] * b[2] - a[3] * b[2];
  *c[2] = a[0] * b[2] - a[1] * b[3] + a[2] * b[0] + a[3] * b[1];
  *c[3] = a[0] * b[3] + a[1] * b[2] - a[2] * b[1] + a[3] * b[0];
}

void upd_decomposition(long *a1, long *a2, long *a3, long *a4, long aprime) {
  long a[4], b[4], *c[4];
  euclidid(a, b, c);
}

void pa4decomposition(long inp, long *a1, long *a2, long *a3, long *a4) {
  long k1, k2, k3, k4, df1, df2, df3, df4;
  bool found = false;

  for(k1 = 0; (df1 = inp - k1*k1) >= 0 && !found; k1++)
    for(k2 = 0;  (df2 = df1 - k2*k2) >= 0 && !found; k2++)
      for(k3 = 0;  (df3 = df2 - k3*k3) >= 0 && !found; k3++)
	for(k4 = 0;  (df4 = df3 - k4*k4) >= 0 && !found; k4++) {
	  if(df4 == 0) {
	    *a1 = k1;
	    *a2 = k2;
	    *a3 = k3;
	    *a4 = k4;
	    found = true;
	  }
	}
}
