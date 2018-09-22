/* Platin.io 2018
 * written by Vadym Fedyukovych
 * proofs library
 */

#include <string>
#include <string.h>
#include <sstream>
#include <iostream>
#include "proofs.hpp"

// #define DBG_NICHALLENGE
// #define DBG_SERIALIZE

void ni_proof_initial(InitialCommitments &ic, PrivateInfo &privi, ProofPrivate &privpf, const PublicInfo &pubi, const Parameters &pp) {
  // ic = {b_0, b_1, s_a, t_a, t_n};

  rnd_commitment(pp, privpf.beta_x);
  rnd_commitment(pp, privpf.beta_y);
  rnd_commitment(pp, privpf.beta_z);
  rnd_commitment(pp, privpf.beta_r);
  ic.t_n = CreateCommitment(pp, privpf.beta_x, privpf.beta_y, privpf.beta_z, privpf.beta_r);

  rnd_commitment(pp, privi.gamma);
  ic.s_a = CreateACommitment(pp, privi.gamma, privi.a);

  rnd_commitment(pp, privpf.eta);
  for(int j=0; j<4; j++)
     rnd_commitment(pp, privpf.alpha[j]);
  ic.t_a = CreateACommitment(pp, privpf.eta, privpf.alpha);

  privpf.f_0 = (privpf.beta_x * privpf.beta_x + privpf.beta_y * privpf.beta_y + privpf.beta_z * privpf.beta_z);
  privpf.f_1 = (privi.x - pubi.x_l)*privpf.beta_x + (privi.y - pubi.y_l)*privpf.beta_y + (privi.z - pubi.z_l)*privpf.beta_z;
  for(int j=0; j<4; j++) {
    privpf.f_0 += privpf.alpha[j] * privpf.alpha[j];
    privpf.f_1 +=  privi.a[j] * privpf.alpha[j];
  }
  privpf.f_1 *= 2;

  rnd_commitment(pp, privpf.rho_0);
  rnd_commitment(pp, privpf.rho_1);
  ic.b_0 = CreateNCommitment(pp, privpf.f_0, privpf.rho_0);
  ic.b_1 = CreateNCommitment(pp, privpf.f_1, privpf.rho_1);
}

CryptoPP::Integer ni_proof_challenge(const InitialCommitments &ic, const CryptoPP::Integer &s_U) {
  CryptoPP::byte h_img[CryptoPP::SHA256::DIGESTSIZE]; //20 bytes of result hash, or 30 for sha256 - result of this function
  CryptoPP::SHA256 hashf;

  std::stringstream cpreimg;
  cpreimg << ic.t_n << ic.s_a << ic.t_a << ic.b_1 << ic.b_0 << s_U; //concatenate numbers into single string so that we can push that into hash function.
  CryptoPP::byte *pimg = (CryptoPP::byte *) cpreimg.str().c_str();
  int sz = strlen(cpreimg.str().c_str());
  hashf.CalculateDigest(h_img, pimg, sz); //calculating hash, result printed into h_img

  // explicit conversion into a bignumber, byte by byte
  CryptoPP::Integer c=0;
  for(int j=0; j<CryptoPP::SHA256::DIGESTSIZE; j++) {
    std::cout << (unsigned int) h_img[j] << std::endl;
    c = c*256 + (unsigned int)h_img[j]; 
  }
#ifdef DBG_NICHALLENGE
  std::cout << pimg << std::endl
	    << sz << std::endl;
  std::cout << c << std::endl;
#endif
  return c;
}

void ni_proof_responses(Responses &resp, const CryptoPP::Integer &c, const PrivateInfo &privi, const ProofPrivate &privpf) {
  resp.X_n = -c * privi.x + privpf.beta_x;
  resp.Y_n = -c * privi.y + privpf.beta_y;
  resp.Z_n = -c * privi.z + privpf.beta_z;
  resp.R = -c * privi.r + privpf.beta_r;

  for(int j=0; j<4; j++)
    resp.A[j] = -c * privi.a[j] + privpf.alpha[j];

  resp.R_a = -c * privi.gamma + privpf.eta;
  resp.R_d = -c * privpf.rho_1 + privpf.rho_0;
}

void ni_proof_serialize(std::string &proof, const InitialCommitments &ic, const CryptoPP::Integer &c, const Responses &resp) {
  std::stringstream package;
  package << c << resp.X_n << resp.Y_n << resp.Z_n << resp.R << resp.A[0] << resp.A[1] << resp.A[2] << resp.A[3] << resp.R_a << resp.R_d << ic.s_a << ic.b_1;
  proof = package.str();
}

std::string ni_proof_create(const double xn, const double yn, const double zn, const double xl, const double yl, const double zl, const double d) {
  std::string proof;
  PublicInfo pubi;
  PrivateInfo privi;
  ProofPrivate privpf;
  Parameters parm;
  InitialCommitments ic;
  Responses resp;
  CryptoPP::Integer c;

  init_parameters(parm);

  // set coordinates in privi, produce commitment s_U, 
  pubi.x_l = 0;
  pubi.y_l = 0;
  pubi.z_l = 0;

  // x, y, z, r, a[4], gamma
  privi.x = geo_x(xn - xl);
  privi.y = geo_y(yn - yl, yl);
  privi.z = geo_z(zn - zl);
  rnd_commitment(parm, privi.r);
  pubi.s_U = CreateCommitment(parm, privi.x, privi.y, privi.z, privi.r);

  pubi.radius = d;
  //  pubi.d2 = d*d; // approx
  get_airdrop_radius(pubi, privi);

  // alpha[4], eta, rho_0, rho_1, beta_x, beta_y, beta_z, f_0, f_1
  ni_proof_initial(ic, privi, privpf, pubi, parm);
  c = ni_proof_challenge(ic, pubi.s_U);
  ni_proof_responses(resp, c, privi, privpf);
  ni_proof_serialize(proof, ic, c, resp);
  return proof;
}

void ni_reproduce_initial(InitialCommitments &ic, const Responses &resp, const Parameters &parm) {
  CryptoPP::Integer c, X_n, Y_n, Z_n, R,
    A[4], R_a,
    F_d, R_d,
    s_U;
  PublicInfo pubi;

  // copy from NIproof
  ic.s_a = 0;
  ic.b_1 = 0;

  ic.t_n = parm.group.Multiply(
	     CreateCommitment(parm, X_n, Y_n, Z_n, R), // g_x^{X_n} g_y^{Y_n} g_z^{Z_n} g^R
	     parm.group.Exponentiate(s_U, c)); // s_U^c
  ic.t_a = parm.group.Multiply(
	     CreateACommitment(parm, R_a, A), // \prod_j h_j^{A_j} g^{R_a}
	     parm.group.Exponentiate(ic.s_a, c)); // s_a^c

  F_d = (X_n + c * pubi.x_l)*(X_n + c * pubi.x_l) +
        (Y_n + c * pubi.y_l)*(Y_n + c * pubi.y_l) +
        (Z_n + c * pubi.z_l)*(Z_n + c * pubi.z_l)
        - c * c * pubi.d2;
  for(int j=0; j<4; j++)
    F_d += A[j] * A[j];

  ic.b_0 = parm.group.Multiply(
	     CreateNCommitment(parm, F_d, R_d), // g^{F_d} g_r^{R_d}
	     parm.group.Exponentiate(ic.b_1, c)); // b_1^c
}

void ni_proof_deserialize(const std::string &proof, const InitialCommitments &ic, const CryptoPP::Integer &c, const Responses &resp) {
#define SZ 1024
  char bf[SZ];
  const char *nxt,
#ifdef DBG_SERIALIZE
                  *p = "12.345671111111111111111111111222222222222222222222222888888888888888888.-890222222222222222222222222777777777777777777333333333333333333.";
#else
                  *p = proof.c_str();
#endif
  int cnt;

  // std::cout << c << resp.X_n << resp.Y_n << resp.Z_n << resp.R << resp.A[0] << resp.A[1] << resp.A[2] << resp.A[3] << resp.R_a << resp.R_d << ic.s_a << ic.b_1;
  // 1+(3+1)+(4+1)+1+2 = 13
  CryptoPP::Integer args[13];
  cnt = 0;
  while((nxt = strchr(p, '.')) != NULL) {
    strncpy(bf, p, (int)(nxt-p));
    *(bf + (nxt-p)) = 0;
    p = nxt+1;
    CryptoPP::Integer aa(bf);
    args[cnt] = aa;
#ifdef DBG_SERIALIZE
    printf("   %s\n", bf);
    std::cout << cnt << ": " << args[cnt] << std::endl;
#endif
    cnt++;
  }
  if(cnt != 3) { // 13
    std::cout << "Invalid encoding" << std::endl;
  }
}

bool ni_proof_verify(const std::string proof) {
  Parameters parm;
  CryptoPP::Integer s_U, c, repr_c;
  InitialCommitments re_ic;
  Responses resp;

  ni_proof_deserialize(proof, re_ic, c, resp);

  ni_reproduce_initial(re_ic, resp, parm);
  repr_c = ni_proof_challenge(re_ic, s_U);
  return repr_c == c;

  //  return true;
}
