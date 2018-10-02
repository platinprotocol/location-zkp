/* Platin.io 2018
 * written by Vadym Fedyukovych
 * approximate solution for Lagrange 4-squares representation
 */

#include <string>
#include <iostream>
#include "proofs.hpp"

//#define DBG_APPROXA4

long get_airdrop_radius(PublicInfo &pubi, PrivateInfo &privi) {
  long dist_sq, diff_dist, approx;
  CryptoPP::Integer d2 =
    (privi.x - pubi.x_l) * (privi.x - pubi.x_l) +
    (privi.y - pubi.y_l) * (privi.y - pubi.y_l) +
    (privi.z - pubi.z_l) * (privi.z - pubi.z_l);
  dist_sq = d2.ConvertToLong();
  diff_dist = pubi.radius * pubi.radius - dist_sq;

  if(diff_dist < 0) {
    std::cout << "Distance is larger threshold: "
	      << dist_sq << " - " << pubi.radius * pubi.radius << std::endl;
    return -1;
  }

  for(int j=0; j<4; j++) {  // calculate_A1_A2_A3_A4()
    approx = sqrt(diff_dist); // approximation by rounding while assigning to integer
    privi.a[j] = approx;
    diff_dist -= approx * approx;
#ifdef DBG_APPROXA4
    std::cout << approx << std::endl;
#endif
  }

  for(int j=0; j<4; j++) {
    d2 += privi.a[j] * privi.a[j];
  };
#ifdef DBG_APPROXA4
  std::cout << "Recalculated d2 " << d2 << std::endl;
  std::cout << "Original d2 " << (pubi.radius * pubi.radius) << std::endl;
#endif
  pubi.d2 = d2;
  return d2.ConvertToLong();
}
