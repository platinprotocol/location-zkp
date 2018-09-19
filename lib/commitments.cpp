/* Platin.io 2018
 * written by Vadym Fedyukovych
 * proofs library
 */

#include <iostream>
#include "proofs.hpp"

CryptoPP::Integer CreateCommitment(const Parameters &pp, const CryptoPP::Integer x, const CryptoPP::Integer y, const CryptoPP::Integer z, const CryptoPP::Integer r) {
  CryptoPP::Integer s;

#ifdef DBG_NEGEXP
  s = pp.group.Multiply(
          neg_a_exp_b_mod_c(pp.gx, x, pp.group),
          pp.group.Multiply(
             neg_a_exp_b_mod_c(pp.gy, y, pp.group),
             pp.group.Multiply(
                neg_a_exp_b_mod_c(pp.gz, z, pp.gz),
                neg_a_exp_b_mod_c(pp.gr, r, pp.group))));
#else
  s = pp.group.Multiply(
	  pp.group.Exponentiate(pp.gx, x),
	  pp.group.Multiply(
	     pp.group.Exponentiate(pp.gy, y),
             pp.group.Multiply(
		pp.group.Exponentiate(pp.gz, z),
                pp.group.Exponentiate(pp.gr, r))));
#endif

#ifdef DBG_LOCCOMM
  std::cout << "x " << x << " y " << y << " z " << z << " r " << r << std::endl;
  std::cout << "location comm " << s << std::endl;
#endif
  return s;
}

CryptoPP::Integer CreateACommitment(const Parameters &pp, const CryptoPP::Integer crnd, const CryptoPP::Integer a[]) {
  CryptoPP::Integer s = pp.group.Exponentiate(pp.g, crnd), t;

  for(int j=0; j<4; j++) {
    //    std::cout << s <<  " _ ";
    t = pp.group.Multiply(s, pp.group.Exponentiate(pp.h[j], a[j]));
    s = t;
#ifdef DBG_ACOMM
    std::cout << a[j] << " " << t <<  " | ";
#endif
  }
#ifdef DBG_ACOMM
  std::cout << std::endl << "a4 commitment " << s << std::endl;
#endif
  return s;
}

CryptoPP::Integer CreateNCommitment(const Parameters &pp, const CryptoPP::Integer f, const CryptoPP::Integer rho) {
  CryptoPP::Integer s, t;
#ifdef DBG_NEGEXP
  t = neg_a_exp_b_mod_c(pp.g, f, pp.group);
#else
  if(f < 0) {
    s = pp.group.Exponentiate(pp.g, -f);
    t = pp.group.MultiplicativeInverse(s);
  } else {
    t = pp.group.Exponentiate(pp.g, f);
  }
#endif
  s = pp.group.Multiply(t,
#ifdef DBG_NEGEXP
        neg_a_exp_b_mod_c(pp.gr, rho, pp.group));
#else
        pp.group.Exponentiate(pp.gr, rho));
#endif

#ifdef DBG_NCOMM
  std::cout << "f " << f << std::endl;
  std::cout << "rho " << rho << std::endl;
  std::cout << "exp(f) " << t << std::endl;
  std::cout << "comm   " << s << std::endl;
#endif
  return s;
}

void rnd_commitment(const Parameters &parm, CryptoPP::Integer &s) {
  ;
}
