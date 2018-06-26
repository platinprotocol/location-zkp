/* Platin.io 2018
 * written by Vadym Fedyukovych
 *
 * "Location is close enough" interactive proof implementation
 * described at "Private location verification"
 */
#include <iostream>
#include "cryptopp/integer.h"

class Parameters {
public:
//private:
  CryptoPP::Integer n,
    g, gx, gy, gz, gr, h[4];
};

class PublicInfo {
public:
  void set_center(int x, int y, int z);
  int get_radius_sq();  // temporary, to be replaced with Rabin-Shallit
//private:
  CryptoPP::Integer xl, yl, zl,
    d,  // threshold for distance
    su; // commitment to node_location
};

class PrivateInfo {
public:
//private:
  CryptoPP::Integer x, y, z, r,
    a[4],  // witness to non-negative (Lagrange theorem)
    alpha[4], eta,
    rho_0, rho_1;
};

class ProofPrivate {
public:
//private:
  CryptoPP::Integer
    beta_x, beta_y, beta_z, beta_r,   
    gamma,
    f_0, f_1;
};

class InitialCommitments {
public:
//private:
  CryptoPP::Integer b_0, b_1, sa, t_a, t_n;
};

class Responses {
public:
//private:
  CryptoPP::Integer A[4], Xn, Yn, Zn, R, R_a, R_d;
};

class Prover {
public:
//  void SetParameters(const Parameters &p);
  void step_start();
  void produce_responses();
//private:
  PublicInfo pubi;
  PrivateInfo privi;

  // from first step of protocol
  ProofPrivate privpf;
  InitialCommitments ic;

  CryptoPP::Integer c;  // challenge
  Responses rsp;
  Parameters pp;
};

class Verifier {
public:
//  void SetParameters(const Parameters &p);
  void choose_challenge(void);
  bool verify();

//private:
  PublicInfo pubi;
  
  InitialCommitments ic;
  CryptoPP::Integer c;  // challenge
  Responses rsp;
  Parameters pp;
};

bool Verifier::verify() {
  // location commitment -check
  if(a_times_b_mod_c(
       a_times_b_mod_c(
         a_times_b_mod_c(
           a_times_b_mod_c(a_exp_b_mod_c(pp.gx, rsp.Xn, pp.n),
                           a_exp_b_mod_c(pp.gy, rsp.Yn, pp.n), pp.n),
           a_exp_b_mod_c(pp.gz, rsp.Zn, pp.n), pp.n),
         a_exp_b_mod_c(pp.g, rsp.R, pp.n), pp.n),
       a_exp_b_mod_c(pubi.su, -c, pp.n), pp.n)
     != ic.t_n)
    return false;

  CryptoPP::Integer acc = a_exp_b_mod_c(pp.g, rsp.R_a, pp.n);
  for(int j=0; j<4; j++)
    acc = a_times_b_mod_c(acc,
			  a_exp_b_mod_c(pp.h[j], rsp.A[j], pp.n),
			  pp.n);

  if(a_times_b_mod_c(acc, a_exp_b_mod_c(ic.sa, -c, pp.n), pp.n)
     != ic.t_a)
    return false;

  CryptoPP::Integer pwr = c * c * pubi.d * pubi.d - (
    (rsp.Xn - c * pubi.xl)*(rsp.Xn - c * pubi.xl) +
    (rsp.Yn - c * pubi.yl)*(rsp.Yn - c * pubi.yl) +
    (rsp.Zn - c * pubi.zl)*(rsp.Zn - c * pubi.zl));
  for(int j=0; j<4; j++)
    pwr -= rsp.A[j] * rsp.A[j];

  if(a_times_b_mod_c(
       a_exp_b_mod_c(pp.g, pwr, pp.n),
       a_exp_b_mod_c(pp.gr, rsp.R_d, pp.n), pp.n)
     !=
     a_times_b_mod_c(
       a_exp_b_mod_c(ic.b_1, c, pp.n),
       ic.b_0, pp.n))
    return false;

  return true;
}

void Verifier::choose_challenge() {
}

void Prover::step_start() {
  ic.t_n = a_times_b_mod_c(
	     a_times_b_mod_c(
               a_times_b_mod_c(		     
	         a_exp_b_mod_c(pp.gx, privpf.beta_x, pp.n),
                 a_exp_b_mod_c(pp.gy, privpf.beta_y, pp.n), pp.n),
               a_exp_b_mod_c(pp.gz, privpf.beta_z, pp.n), pp.n),
	     a_exp_b_mod_c(pp.gr, privpf.beta_r, pp.n), pp.n);

  ic.sa = a_exp_b_mod_c(pp.g, privpf.gamma, pp.n);
  for(int j=0; j<4; j++)
    ic.sa = a_times_b_mod_c(ic.sa,
                            a_exp_b_mod_c(pp.h[j], privi.a[j], pp.n),
                            pp.n);

  ic.t_a =  a_exp_b_mod_c(pp.g, privi.eta, pp.n);
  for(int j=0; j<4; j++)
    ic.t_a = a_times_b_mod_c(ic.t_a,
                             a_exp_b_mod_c(pp.h[j], privi.alpha[j], pp.n),
                             pp.n);
}   

void Prover::produce_responses() {
  rsp.Xn = c*privi.x + privpf.beta_x;
  rsp.Yn = c*privi.y + privpf.beta_y;
  rsp.Zn = c*privi.z + privpf.beta_z;
  rsp.R = c*privi.r + privpf.beta_r;

  for(int j=0; j<4; j++)
    rsp.A[j] = c*privi.a[j] + privi.alpha[j];

  rsp.R_a = c*privpf.gamma + privi.eta;
  rsp.R_d = c*privi.rho_1 + privi.rho_0;
}

void set_node_location(Prover p, int xn, int yn, int zn) {
}

void set_airdrop_location(Prover p, Verifier v, int xl, int yl, int zl) {
}

int get_airdrop_radius(Prover p, Verifier v) {
  return 0;
}

int main() {
  Parameters Prm;
  Prover P;
  Verifier V;
  bool isok;

  // Prm. =  load from file
  P.pp = Prm;
  V.pp = Prm;

  int xn=19864, yn=77542, zn=4;  // node location
  set_node_location(P, xn, yn, zn);

  int xl=22148, yl=81237, zl=16;  // center
  set_airdrop_location(P, V, xl, yl, zl);

  int d2;  // radius squared
  d2 = get_airdrop_radius(P, V);  // will be set_radius()

  P.step_start();
  V.ic = P.ic;  // P -> V
  //  std::cout << P.ic << std::endl;

  V.choose_challenge();
  P.c = V.c; // V -> P
  //  std::cout << V.c << std::endl;

  P.produce_responses();
  V.rsp = P.rsp;  // P -> V
  //  std::cout << P.rsp << std::endl;

  isok = V.verify();
  if(isok)
    std::cout << "Proof verified OK" << std::endl;
  else
    std::cout << "Proof verified WRONG" << std::endl;

  return 0;
}
