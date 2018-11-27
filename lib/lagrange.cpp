/* Platin.io 2018
 * written by Vadym Fedyukovych
 * approximate solution for Lagrange 4-squares representation
 */

#include <string>
#include <iostream>
#include "proofs.hpp"

//#define DBG_APPROXA4
#define DBG_ENUMERATE4

#ifdef DBG_ENUMERATE4
#include "primes_lst.hpp"

p4sq primes_decomposed[] = { 
#include "primes_decomposition.inc"
};
#endif

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

#ifdef DBG_ENUMERATE4
  std::cout << "Before decomposition distance " << diff_dist << std::endl;

  int k, remndr, pcnt=0;
  long ka[4], full_a[4]={1,0,0,0};
  long diff_reduced = diff_dist;

  for(k = 0; k < PSZ && primesl[k]*primesl[k] <= diff_reduced; k++) {
    do {
      remndr = diff_reduced % primesl[k];
      if(remndr == 0) {
	pa4decomposition(primesl[k], ka[0], ka[1], ka[2], ka[3]);
	diff_reduced /= primesl[k];
        pcnt++;
	std::cout << "Reduced " << primesl[k]
		  << " " << ka[0]
		  << " " << ka[1]
		  << " " << ka[2]
		  << " " << ka[3]
		  << std::endl;
	eulerid(full_a, ka);
      }
    } while(remndr == 0);
  }
  std::cout << "Cnt " << pcnt << " left " << diff_reduced << std::endl;

  //  std::cout << "Before search distance " << diff_reduced << std::endl;

  pa4decomposition(diff_reduced, ka[0], ka[1], ka[2], ka[3]);
  eulerid(full_a, ka);
  std::cout << "Reduced-last " << diff_reduced
	    << " " << ka[0]
	    << " " << ka[1]
	    << " " << ka[2]
	    << " " << ka[3]
	    << std::endl;
  std::cout << "Full " << diff_dist
	    << " " << full_a[0]
	    << " " << full_a[1]
	    << " " << full_a[2]
	    << " " << full_a[3]
	    << std::endl;

  privi.a[0] = full_a[0]; privi.a[1] = full_a[1]; privi.a[2] = full_a[2]; privi.a[3] = full_a[3];
#else
  for(int j=0; j<4; j++) {  // calculate_A1_A2_A3_A4()
    approx = sqrt(diff_dist); // approximation by rounding while assigning to integer
    privi.a[j] = approx;
    diff_dist -= approx * approx;
#ifdef DBG_APPROXA4
    std::cout << approx << std::endl;
#endif
  }
#endif // DBG_ENUMERATE4

  for(int j=0; j<4; j++) {
    d2 += privi.a[j] * privi.a[j];
  };
  //#ifdef DBG_APPROXA4
  std::cout << "Recalculated d2 " << d2 << std::endl;
  std::cout << "Original d2 " << (pubi.radius * pubi.radius) << std::endl;
  //#endif
  pubi.d2 = d2;
  return d2.ConvertToLong();
}
