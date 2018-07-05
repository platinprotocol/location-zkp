/* Platin.io 2018
 * written by Vadym Fedyukovych
 *
 * "Location is close enough" interactive proof implementation
 * described at "Private location verification"
 */
#include <iostream>
//#include "cryptopp/integer.h"
#include "cryptopp/modarith.h"
#include "cryptopp/rsa.h"
#include "cryptopp/randpool.h"

class Parameters {
public:
//private:
  CryptoPP::Integer n,
    g, gx, gy, gz, gr, h[4];
  CryptoPP::ModularArithmetic group;
  int rnd_bitsize_modulus,
      rnd_bitsize_commitment,
      rnd_bitsize_chall, rnd_offset_chall;
};

class PublicInfo {
public:
  void set_center(int x, int y, int z);
  int get_radius_sq();  // temporary, to be replaced with Rabin-Shallit
//private:
  CryptoPP::Integer xl, yl, zl,
    d;  // threshold for distance
  CryptoPP::Integer su; // commitment to node_location
};

class PrivateInfo {
public:
//private:
  CryptoPP::Integer x, y, z,
    r,
    a[4],  // witness to non-negative (Lagrange theorem)
    gamma;
};

class ProofPrivate {
public:
//private:
  CryptoPP::Integer
    alpha[4], eta,
    rho_0, rho_1,
    beta_x, beta_y, beta_z, beta_r,   
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
  void step_start(CryptoPP::RandomNumberGenerator &rng);
  void step_responses();
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
  void step_challenge(CryptoPP::RandomNumberGenerator &rng);
  bool step_verify();

//private:
  PublicInfo pubi;
  
  InitialCommitments ic;
  CryptoPP::Integer c;  // challenge
  Responses rsp;
  Parameters pp;
};

CryptoPP::Integer rnd_commitment(const Parameters &pp, CryptoPP::RandomNumberGenerator &rng) {
  return CryptoPP::Integer(rng, pp.rnd_bitsize_commitment);
}

CryptoPP::Integer CreateCommitment(const Parameters &pp, const CryptoPP::Integer x, const CryptoPP::Integer y, const CryptoPP::Integer z, const CryptoPP::Integer r) {
  CryptoPP::Integer s;

  s = pp.group.Multiply(
	  pp.group.Exponentiate(pp.gx, x),
	  pp.group.Multiply(
	     pp.group.Exponentiate(pp.gy, y),
             pp.group.Multiply(
		pp.group.Exponentiate(pp.gz, z),
                pp.group.Exponentiate(pp.gr, r))));
  // should be like  group.Add(a, group.Add(b, group.Add(c,d))
  return s;
}

CryptoPP::Integer CreateACommitment(const Parameters &pp, const CryptoPP::Integer crnd, const CryptoPP::Integer a[]) {
  CryptoPP::Integer s = pp.group.Exponentiate(pp.g, crnd), t;

  for(int j=0; j<4; j++) {
    //    std::cout << s <<  " _ ";
    t = pp.group.Multiply(s, pp.group.Exponentiate(pp.h[j], a[j]));
    s = t;
    //    std::cout << a[j] << " " << t <<  " | ";
  }
  //  std::cout << std::endl;

  return s;
}

CryptoPP::Integer CreateNCommitment(const Parameters &pp, const CryptoPP::Integer f, const CryptoPP::Integer rho) {
  CryptoPP::Integer s, t;

  if(f < 0) {
    s = pp.group.Exponentiate(pp.g, -f);
    t = pp.group.MultiplicativeInverse(s);
/*
  std::cout << "-f " << -f << std::endl;
  std::cout << "exp(-f) " << pp.group.Exponentiate(pp.g, -f) << std::endl;
  std::cout << "t=minv " << t << std::endl;
*/
  } else {
   t = pp.group.Exponentiate(pp.g, f);
  }
  //  return t;

  s = pp.group.Multiply(t,
        pp.group.Exponentiate(pp.gr, rho)); 

  return s;
}

void PrintCommitment(const std::string title, const CryptoPP::Integer comm) {
  std::cout << title << " " 
	    << comm << std::endl;
}

bool Verifier::step_verify() {
  if(pp.group.Multiply(
       CreateCommitment(pp, rsp.Xn, rsp.Yn, rsp.Zn, rsp.R),
       pp.group.MultiplicativeInverse(
         pp.group.Exponentiate(pubi.su, c)))
     !=
     ic.t_n)
    return false;

  if(pp.group.Multiply(
       CreateACommitment(pp, rsp.R_a, rsp.A),
       pp.group.MultiplicativeInverse(
         pp.group.Exponentiate(ic.sa, c)))
     !=
     ic.t_a)
    return false;

  CryptoPP::Integer pwr = c * c * pubi.d * pubi.d - (
    (rsp.Xn - c * pubi.xl)*(rsp.Xn - c * pubi.xl) +
    (rsp.Yn - c * pubi.yl)*(rsp.Yn - c * pubi.yl) +
    (rsp.Zn - c * pubi.zl)*(rsp.Zn - c * pubi.zl));
  for(int j=0; j<4; j++)
    pwr -= rsp.A[j] * rsp.A[j];

  if(CreateNCommitment(pp, pwr, rsp.R_d)
     !=
     pp.group.Multiply(
       pp.group.Exponentiate(ic.b_1, c),
       ic.b_0)) {
    std::cout << "Trap" << std::endl;
    return false;
  }

  return true;
}

void Verifier::step_challenge(CryptoPP::RandomNumberGenerator &rng) {
  c = CryptoPP::Integer(rng, pp.rnd_bitsize_chall);
}

void Prover::step_start(CryptoPP::RandomNumberGenerator &rng) {
  privi.gamma = rnd_commitment(pp, rng);
  ic.sa = CreateACommitment(pp, privi.gamma, privi.a);
  //  std::cout << "Gamma " << privi.gamma << std::endl;

  privpf.eta = rnd_commitment(pp, rng);
  for(int j=0; j<4; j++)
    privpf.alpha[j] = rnd_commitment(pp, rng);
  ic.t_a = CreateACommitment(pp, privpf.eta, privpf.alpha);

  // CryptoPP::Integer rnd_commitment(const Parameters &pp, CryptoPP::RandomNumberGenerator &rng)
  privpf.beta_x = rnd_commitment(pp, rng);
  privpf.beta_y = rnd_commitment(pp, rng);
  privpf.beta_z = rnd_commitment(pp, rng);
  privpf.beta_r = rnd_commitment(pp, rng);
  ic.t_n = CreateCommitment(pp, privpf.beta_x, privpf.beta_y, privpf.beta_z, privpf.beta_r);

  privpf.f_0 = -(privpf.beta_x * privpf.beta_x + privpf.beta_y * privpf.beta_y + privpf.beta_z * privpf.beta_z);
  privpf.f_1 = (privi.x - pubi.xl)*privpf.beta_x + (privi.y - pubi.yl)*privpf.beta_y + (privi.z - pubi.zl)*privpf.beta_z;

  for(int j=0; j<4; j++) {
    privpf.f_0 -= privpf.alpha[j] * privpf.alpha[j];
    privpf.f_1 +=  privi.a[j] * privpf.alpha[j];
  }
  privpf.f_1 *= -2;
  privpf.rho_0 = rnd_commitment(pp, rng);
  privpf.rho_1 = rnd_commitment(pp, rng);

  ic.b_0 = CreateNCommitment(pp, privpf.f_0, privpf.rho_0);
  ic.b_1 = CreateNCommitment(pp, privpf.f_1, privpf.rho_1);
}

void Prover::step_responses() {
  rsp.Xn = c*privi.x + privpf.beta_x;
  rsp.Yn = c*privi.y + privpf.beta_y;
  rsp.Zn = c*privi.z + privpf.beta_z;
  rsp.R = c*privi.r + privpf.beta_r;

  for(int j=0; j<4; j++)
    rsp.A[j] = c*privi.a[j] + privpf.alpha[j];

  rsp.R_a = c*privi.gamma + privpf.eta;
  rsp.R_d = c*privpf.rho_1 + privpf.rho_0;
}

void SetParameters(Parameters &pp, CryptoPP::RandomNumberGenerator &rng) {
  pp.rnd_bitsize_modulus = 2048;
  pp.rnd_bitsize_commitment = 20; // 200;
  pp.rnd_bitsize_chall = 100;
  pp.rnd_offset_chall = 100;

  CryptoPP::InvertibleRSAFunction pv;
  pv.Initialize(rng, pp.rnd_bitsize_modulus, 3);
  pp.n = pv.GetPrime1() * pv.GetPrime2();
  pp.n = 37; // 11; // 89*73; // 11;

  pp.group.SetModulus(pp.n);
  pp.g = 4;
  pp.gx = 3;
  pp.gy = 9;
  pp.gz = 5;
  pp.gr = 4;
  pp.h[0] = 3;
  pp.h[1] = 9;
  pp.h[2] = 5;
  pp.h[3] = 4;
};

void PrintParameters(const Parameters &pp) {
  std::cout << "Parameters" << std::endl
            << "Modulus " << pp.n << std::endl
            << "g " << pp.g << std::endl
            << "g_x " << pp.gx << std::endl
            << "g_y " << pp.gy << std::endl
            << "g_z " << pp.gz << std::endl
            << "g_r " << pp.gr << std::endl
            << "h[0] (a_1 generator) " << pp.h[0] << std::endl
            << "h[1] (a_2 generator) " << pp.h[1] << std::endl
            << "h[2] (a_3 generator) " << pp.h[2] << std::endl
            << "h[3] (a_4 generator) " << pp.h[3] << std::endl;
}

void Print_start(const Verifier &v) {
  PrintCommitment("Commitment b_0", v.ic.b_0);
  PrintCommitment("Commitment b_1", v.ic.b_1);
  PrintCommitment("Commitment s_a", v.ic.sa);
  PrintCommitment("Commitment t_a", v.ic.t_a);
  PrintCommitment("Commitment t_n", v.ic.t_n);
}

void Print_responses(const Verifier &v) {
  std::cout << "Responses" << std::endl
            << "X_n " << v.rsp.Xn << std::endl
            << "Y_n " << v.rsp.Yn << std::endl
            << "Z_n " << v.rsp.Zn << std::endl
            << "R  " << v.rsp.R << std::endl;
  for(int j=0; j<4; j++)
    std::cout << "A_" << j+1 << " " << v.rsp.A[j]  << std::endl;

  std::cout << "R_a " << v.rsp.R_a << std::endl
	    << "R_d " << v.rsp.R_d << std::endl;
}

void set_node_location(Prover &p, Verifier &v, const int xn, const int yn, const int zn) {
  p.privi.x = xn;
  p.privi.y = yn;
  p.privi.z = zn;
  p.privi.r = 1;

  CryptoPP::Integer scomm;
  scomm = CreateCommitment(p.pp, p.privi.x, p.privi.y, p.privi.z, p.privi.r);
  p.pubi.su = scomm;
  v.pubi.su = scomm;
}

void set_airdrop_location(Prover &p, Verifier &v, int xl, int yl, int zl) {
  p.pubi.xl = xl;
  v.pubi.xl = xl;
  p.pubi.yl = yl;
  v.pubi.yl = yl;
  p.pubi.zl = zl;
  v.pubi.zl = zl;
}

long get_airdrop_radius(Prover &p, Verifier &v) {
  p.privi.a[0] = 0;
  p.privi.a[1] = 3;
  p.privi.a[2] = 1;
  p.privi.a[3] = 4;

  CryptoPP::Integer d2;
  d2 =
    (p.privi.x - p.pubi.xl) * (p.privi.x - p.pubi.xl) +
    (p.privi.y - p.pubi.yl) * (p.privi.y - p.pubi.yl) +
    (p.privi.z - p.pubi.zl) * (p.privi.z - p.pubi.zl);

  for(int j=0; j<4; j++) {
    d2 += p.privi.a[j] * p.privi.a[j];
  };

  p.pubi.d = d2;
  v.pubi.d = d2;
  return d2.ConvertToLong();
}

int main() {
  Parameters Prm;
  Prover P;
  Verifier V;
  bool isok;

  CryptoPP::RandomPool randPool;

  std::cout << "Establishing zero knowledge common reference string" << std::endl;
  SetParameters(Prm, randPool);

  PrintParameters(Prm);
  P.pp = Prm;
  V.pp = Prm;

  int xl=3, yl=4, zl=5;  // center
  set_airdrop_location(P, V, xl, yl, zl);
  std::cout << "Airdrop location " << xl << ", " << yl << ", " << zl << std::endl;
  std::cout << "Pause";
  std::cin.get();

  int xn=2, yn=1, zn=3;  // node location
//  std::cout << "Enter Xn: ";
//  std::cin >> xn;
//  std::cout << " Now Xn = " << xn << std::endl;
  set_node_location(P, V, xn, yn, zn);
  std::cout << "Pocket location " << xn << ", " << yn << ", " << zn << std::endl;
  std::cout << "Pause";
  std::cin.get();

  PrintCommitment("Pocket location commitment s_U", V.pubi.su);

  int d2;  // radius squared
  d2 = get_airdrop_radius(P, V);  // will be set_radius()
  std::cout << "Radius-squared " << d2 << std::endl;

  P.step_start(randPool);
  V.ic = P.ic;  // P -> V
  Print_start(V);

  V.step_challenge(randPool);
  P.c = V.c; // V -> P
  std::cout << "Challenge " // << std::endl
            << V.c << std::endl;

  P.step_responses();
  V.rsp = P.rsp;  // P -> V
  Print_responses(V);

  isok = V.step_verify();
  if(isok)
    std::cout << "Proof verified OK" << std::endl;
  else
    std::cout << "Proof verified WRONG" << std::endl;

  return 0;
}
