/* Platin.io 2018
 * written by Vadym Fedyukovych
 * proofs library
 */

#include <iostream>
#include "proofs.hpp"

#define NEED_NEGEXP
#define DBG_NEGEXP
//#define DBG_LOCCOMM
//#define DBG_ACOMM
//#define DBG_NCOMM

#ifdef NEED_NEGEXP
CryptoPP::Integer neg_a_exp_b_mod_c(const CryptoPP::Integer& a, const CryptoPP::Integer& b, const CryptoPP::ModularArithmetic& c) {
  CryptoPP::Integer interm, result;

  if(b < 0) {
    interm = c.Exponentiate(a, -b);
    result = c.MultiplicativeInverse(interm);
  } else {
    result = c.Exponentiate(a, b);
    interm = c.MultiplicativeInverse(result);
  }
  return result;
}
#endif

CryptoPP::Integer CreateCommitment(const Parameters &pp, const CryptoPP::Integer x, const CryptoPP::Integer y, const CryptoPP::Integer z, const CryptoPP::Integer r) {
  CryptoPP::Integer s;

#ifdef NEED_NEGEXP
  s = pp.group.Multiply(
          neg_a_exp_b_mod_c(pp.gx, x, pp.group),
          pp.group.Multiply(
             neg_a_exp_b_mod_c(pp.gy, y, pp.group),
             pp.group.Multiply(
                neg_a_exp_b_mod_c(pp.gz, z, pp.gz),
                neg_a_exp_b_mod_c(pp.gr, r, pp.group))));
#else // need negative
#ifdef DBG_NEGEXP
  if(x < 0 || y < 0 || z < 0 || r < 0) {
    std::cout << "Negative exp at CreateCommitment()" << std::endl
	      << "x: " << x
	      << "  y: " << y
	      << "  z: " << z
	      << "  r: " << r
	      << std::endl;
    return CryptoPP::Integer::Zero();
  }
#endif // debug negative
#endif // need negative
  s = pp.group.Multiply(
	  pp.group.Exponentiate(pp.gx, x),
	  pp.group.Multiply(
	     pp.group.Exponentiate(pp.gy, y),
             pp.group.Multiply(
		pp.group.Exponentiate(pp.gz, z),
                pp.group.Exponentiate(pp.gr, r))));

#ifdef DBG_LOCCOMM
  std::cout << "x " << x << " y " << y << " z " << z << " r " << r << std::endl;
  std::cout << "location comm " << s << std::endl;
#endif
  return s;
}

CryptoPP::Integer CreateACommitment(const Parameters &pp, const CryptoPP::Integer crnd, const CryptoPP::Integer a[]) {
#ifdef DBG_NEGEXP
  if(crnd < 0) {
    std::cout << "Negative exp at CreateACommitment()" << std::endl
	      << "a0: " << a[0]
	      << "  a1: " << a[1]
	      << "  a2: " << a[2]
	      << "  a3: " << a[3]
	      << "  r: " << crnd
	      << std::endl;
    return CryptoPP::Integer::Zero();
  }
#endif
  CryptoPP::Integer s = pp.group.Exponentiate(pp.g, crnd), t;

  for(int j=0; j<4; j++) {
#ifdef DBG_NEGEXP
  if(a[j] < 0) {
    std::cout << "Negative exp at CreateACommitment() " << j << std::endl;
    return CryptoPP::Integer::Zero();
  }
#endif
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
  if(f < 0 || rho < 0) {
    std::cout << "Negative exp at CreateNCommitment()" << std::endl
	      << "f: " << f
	      << "  r: " << rho
	      << std::endl;
    return CryptoPP::Integer::Zero();
  }
#endif

  t = pp.group.Exponentiate(pp.g, f);
  s = pp.group.Multiply(t,
        pp.group.Exponentiate(pp.gr, rho));

#ifdef DBG_NCOMM
  std::cout << "f " << f << std::endl;
  std::cout << "rho " << rho << std::endl;
  std::cout << "exp(f) " << t << std::endl;
  std::cout << "comm   " << s << std::endl;
#endif
  return s;
}

void rnd_commitment(const Parameters &parm, CryptoPP::Integer &s) {
  s = CryptoPP::Integer::One() << 256+30;
}
