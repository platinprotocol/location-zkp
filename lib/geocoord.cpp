/* Platin.io 2018
 * written by Vadym Fedyukovych
 * conversion from latitude-longitude degrees into meters
 */

//#include <math>
#include <iostream>
#include "proofs.hpp"

//#define DBG_GEOCOORD
//#define DBG_ABSXY

// Earth radius, meters
#define R_earch 6371000.
#define GradToRad 0.0175

// (node - airdrop); X direction is to south pole
long geo_x(double dlx) {
  long intx = R_earch * GradToRad * dlx + 0.5;
#ifdef DBG_GEOCOORD
  std::cout << "int_x: " << intx << std::endl;
#endif
#ifdef DBG_ABSXY
  if(intx < 0)
     return -intx;
#endif
  return intx;
}
// return R() * gradToRad() * (c_latitude - org_latitude); };

// Y is to Greenwich
long geo_y(double dly, double org_latitude) {
  long inty = R_earch * GradToRad * dly * cos(GradToRad * org_latitude) + 0.5;
#ifdef DBG_GEOCOORD
  std::cout << "int_y: " << inty << std::endl;
#endif
#ifdef DBG_ABSXY
  if(inty < 0)
     return -inty;
#endif
  return inty;
}
// return R() * gradToRad() * (org_longitude - c_longitude) * cos(gradToRad() * org_latitude); };

// Z is up
long geo_z(double dlz) {
  long intz = dlz + 0.5;
#ifdef DBG_GEOCOORD
  std::cout << "int_z: " << intz << std::endl;
#endif
  return intz;
}
// return (c_elevation - org_elevation);} ;
