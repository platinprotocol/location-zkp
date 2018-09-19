/* Platin.io 2018
 * written by Vadym Fedyukovych
 * proofs library
 */

#include <string>
#include <sstream>
#include <iostream>
#include "proofs.hpp"

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
/*
  std::cout << pimg << std::endl
	    << sz << std::endl;
*/
  hashf.CalculateDigest(h_img, pimg, sz); //calculating hash, result printed into h_img

  // explicit conversion into a bignumber, byte by byte
  CryptoPP::Integer c=0;
  for(int j=0; j<CryptoPP::SHA256::DIGESTSIZE; j++) {
    std::cout << (unsigned int) h_img[j] << std::endl;
    c = c*256 + (unsigned int)h_img[j]; 
  }
  //  std::cout << c << std::endl;
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

long geo_x(double dlx) {
  return 0;
}

long geo_y(double dly) {
  return 0;
}

long geo_z(double dlz) {
  return 0;
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
  privi.y = geo_y(yn - yl);
  privi.z = geo_z(zn - zl);
  rnd_commitment(parm, privi.r);
  pubi.s_U = CreateCommitment(parm, privi.x, privi.y, privi.z, privi.r);

  pubi.d2 = d*d; // approx

  // alpha[4], eta, rho_0, rho_1, beta_x, beta_y, beta_z, f_0, f_1
  ni_proof_initial(ic, privi, privpf, pubi, parm);
  c = ni_proof_challenge(ic, pubi.s_U);
  ni_proof_responses(resp, c, privi, privpf);
  ni_proof_serialize(proof, ic, c, resp);
  return proof;
}

void ni_reproduce_initial(InitialCommitments &ic) {
  ;
}

bool ni_proof_verify(const std::string proof) {
  CryptoPP::Integer s_U, repr_c;
  InitialCommitments ic;

  ni_reproduce_initial(ic);
  repr_c = ni_proof_challenge(ic, s_U);
  //  return repr_c == proof.c;
  return true;
}
