/* Platin.io 2018
 * written by Vadym Fedyukovych
 * proofs library
 */

#include <string>
#include <string.h>
#include <sstream>
#include <iostream>
#include "proofs.hpp"

//#define DBG_NICHALLENGE
//#define DBG_SERIALIZE
std::string integer_to_string(CryptoPP::Integer integer) {
    std::string retVal;
    retVal.resize(integer.MinEncodedSize());
    
    integer.Encode((CryptoPP::byte *)retVal.data(), retVal.size());
    
    return retVal;
}

void ni_proof_initial(InitialCommitments &ic, PrivateInfo &privi, ProofPrivate &privpf, const PublicInfo &pubi, const Parameters &pp) {
  // ic = {b_0, b_1, s_a, t_a, t_n};

  rnd_commitment(pp, privpf.beta_x);
  rnd_commitment(pp, privpf.beta_y);
  rnd_commitment(pp, privpf.beta_z);
  rnd_commitment(pp, privpf.beta_r);
  ic.t_n = CreateCommitment(pp, privpf.beta_x, privpf.beta_y, privpf.beta_z, privpf.beta_r);

  // NZERO rnd_commitment(pp, privi.gamma);
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
  // NZERO rnd_commitment(pp, privpf.rho_1);
  ic.b_0 = CreateNCommitment(pp, privpf.f_0, privpf.rho_0);
  ic.b_1 = CreateNCommitment(pp, privpf.f_1, privpf.rho_1);
}

CryptoPP::Integer ni_proof_challenge(const InitialCommitments &ic, const CryptoPP::Integer &s_U) {
  CryptoPP::byte h_img[CryptoPP::SHA256::DIGESTSIZE]; //20 bytes of result hash, or 30 for sha256 - result of this function
  CryptoPP::SHA256 hashf;
  
  std::string var = integer_to_string(ic.t_n) + "." +
      integer_to_string(ic.s_a) + "." +
      integer_to_string(ic.t_a) + "." +
      integer_to_string(ic.b_1) + "." +
      integer_to_string(ic.b_0) + "." +
      integer_to_string(s_U) + ".";

  CryptoPP::byte *pimg = (CryptoPP::byte *) var.c_str();

  unsigned long sz =  var.length();
    
  hashf.CalculateDigest(h_img, pimg, sz); //calculating hash, result printed into h_img
  
  // explicit conversion into a bignumber, byte by byte
  CryptoPP::Integer c=0;
    
  for(int j=0; j<CryptoPP::SHA256::DIGESTSIZE; j++) {
    c = c*256 + (unsigned int)h_img[j];
  }
  
#ifdef DBG_NICHALLENGE
  std::cout << "FS challenge: "
        << sz << "  "
        << var.c_str()
        << "  int: " << c << std::endl;
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

void ni_proof_serialize(std::string &proof, const InitialCommitments &ic, const CryptoPP::Integer &c, const Responses &resp, const CryptoPP::Integer &s_U, const CryptoPP::Integer &d2) {
  std::stringstream package;
  package << c << resp.X_n << resp.Y_n << resp.Z_n << resp.R << resp.A[0] << resp.A[1] << resp.A[2] << resp.A[3] << resp.R_a << resp.R_d << ic.s_a << ic.b_1 << s_U << d2;
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

  // set coordinates in privi
  pubi.x_l = 0;
  pubi.y_l = 0;
  pubi.z_l = 0;

  // x, y, z, r, a[4], gamma
  privi.x = geo_x(xn - xl);
  privi.y = geo_y(yn - yl, yl);
  privi.z = geo_z(zn - zl);
  // NZERO rnd_commitment(parm, privi.r);

  // produce commitment s_U
  pubi.s_U = CreateCommitment(parm, privi.x, privi.y, privi.z, privi.r);

  pubi.radius = d;
  get_airdrop_radius(pubi, privi);    //  pubi.d2 = d*d;  approx

  // alpha[4], eta, rho_0, rho_1, beta_x, beta_y, beta_z, f_0, f_1
  ni_proof_initial(ic, privi, privpf, pubi, parm);
  c = ni_proof_challenge(ic, pubi.s_U);
  ni_proof_responses(resp, c, privi, privpf);
  ni_proof_serialize(proof, ic, c, resp, pubi.s_U, pubi.d2);
  return proof;
}

void ni_reproduce_initial(const CryptoPP::Integer c, const CryptoPP::Integer s_U, const CryptoPP::Integer d2, InitialCommitments &ic, const Responses &resp, const Parameters &parm) {
  CryptoPP::Integer F_d;
  PublicInfo pubi;  // xl = yl = zl = 0

  ic.t_n = parm.group.Multiply(
	     CreateCommitment(parm, resp.X_n, resp.Y_n, resp.Z_n, resp.R), // g_x^{X_n} g_y^{Y_n} g_z^{Z_n} g^R
	     parm.group.Exponentiate(s_U, c)); // s_U^c
  ic.t_a = parm.group.Multiply(
	     CreateACommitment(parm, resp.R_a, resp.A), // \prod_j h_j^{A_j} g^{R_a}
	     parm.group.Exponentiate(ic.s_a, c)); // s_a^c

  F_d = (resp.X_n + c * pubi.x_l)*(resp.X_n + c * pubi.x_l) +
        (resp.Y_n + c * pubi.y_l)*(resp.Y_n + c * pubi.y_l) +
        (resp.Z_n + c * pubi.z_l)*(resp.Z_n + c * pubi.z_l)
        - c * c * d2;
  for(int j=0; j<4; j++)
    F_d += resp.A[j] * resp.A[j];

  ic.b_0 = parm.group.Multiply(
	     CreateNCommitment(parm, F_d, resp.R_d), // g^{F_d} g_r^{R_d}
	     parm.group.Exponentiate(ic.b_1, c)); // b_1^c
}

void ni_proof_deserialize(const std::string &proof, InitialCommitments &ic, CryptoPP::Integer &c, Responses &resp, CryptoPP::Integer &s_U, CryptoPP::Integer &d2) {
#define SZ 1024
  char bf[SZ];
  const char *nxt, *p = proof.c_str();
  int cnt;

  // std::cout << c << resp.X_n << resp.Y_n << resp.Z_n << resp.R << resp.A[0] << resp.A[1] << resp.A[2] << resp.A[3] << resp.R_a << resp.R_d << ic.s_a << ic.b_1 << s_U << d2;
  // 1+(3+1)+(4+1)+1+2+1+1 = 15
  CryptoPP::Integer args[NIPROOF_COMPONENTS];
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
  if(cnt != NIPROOF_COMPONENTS) {
    std::cout << "Invalid encoding" << std::endl;
  }
  c = args[0];
  resp.X_n = args[1];
  resp.Y_n = args[2];
  resp.Z_n = args[3];
  resp.R = args[4];
  resp.A[0] = args[5];
  resp.A[1] = args[6];
  resp.A[2] = args[7];
  resp.A[3] = args[8];
  resp.R_a = args[9];
  resp.R_d = args[10];
  ic.s_a = args[11];
  ic.b_1 = args[12];
  s_U = args[13];
  d2 = args[14];
}

bool ni_proof_verify(const std::string proof) {
  Parameters parm;
  CryptoPP::Integer c, repr_c, s_U, d2;
  InitialCommitments re_ic;
  Responses resp;

  init_parameters(parm);

  ni_proof_deserialize(proof, re_ic, c, resp, s_U, d2);
  ni_reproduce_initial(c, s_U, d2, re_ic, resp, parm);
  repr_c = ni_proof_challenge(re_ic, s_U);

  return repr_c == c;
}
