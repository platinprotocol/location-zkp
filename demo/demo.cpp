/* Platin.io 2018
 * written by Vadym Fedyukovych
 *
 * "Location is close enough" interactive proof implementation
 * described at "Private location verification"
 */
#include <iostream>
#include <math.h>
#include <unistd.h>
#include <term.h>
#include "cryptopp/integer.h"
#include "cryptopp/modarith.h"
#include "cryptopp/rsa.h"
#include "cryptopp/randpool.h"

#define ENABLE_PAUSE

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
    d2;  // threshold for distance, squared
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
/*
  std::cout << "f " << f << std::endl;
  std::cout << "rho " << rho << std::endl;
  std::cout << "exp(f) " << t << std::endl;
  std::cout << "comm   " << s << std::endl;
*/
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

  CryptoPP::Integer pwr = c * c * pubi.d2 - (
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

  privpf.eta = rnd_commitment(pp, rng);
  for(int j=0; j<4; j++)
    privpf.alpha[j] = rnd_commitment(pp, rng);
  ic.t_a = CreateACommitment(pp, privpf.eta, privpf.alpha);

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

// (19 * 10 + 1)*(103 = 17 * 6 + 1) = 191*103 = 19673;  order 17*19 = 323, co-order 30
  pp.n = 19673;
  pp.group.SetModulus(pp.n);

// 4323 = 4^30%19673
// 4323^323%19673 = 1
  pp.g = 4323;

  pp.gx = 18652;
  pp.gy = 12642;
  pp.gz = 19445;
  pp.gr = 17679;
  pp.h[0] = 16385;
  pp.h[1] = 9555;
  pp.h[2] = 12638;
  pp.h[3] = 2153;
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
  p.privi.r = 1; // rnd_commitment(pp, rng);

  CryptoPP::Integer scomm;
  scomm = CreateCommitment(p.pp, p.privi.x, p.privi.y, p.privi.z, p.privi.r);
  p.pubi.su = scomm;
  v.pubi.su = scomm;
}

void set_airdrop_location(Prover &p, Verifier &v, int xl, int yl, int zl, int RR) {
  p.pubi.xl = xl;
  v.pubi.xl = xl;
  p.pubi.yl = yl;
  v.pubi.yl = yl;
  p.pubi.zl = zl;
  v.pubi.zl = zl;
  p.pubi.d2 = RR;
  v.pubi.d2 = RR;
}

long distance_meters(double latoriginrad, double longoriginrad, double latdestrad, double longdestrad){
  double HalfPi = 1.5707963;
  double R = 3956000; /* the radius gives you the measurement unit*/

  double a = HalfPi - latoriginrad;
  double b = HalfPi - latdestrad;
  double u = a * a + b * b;
  double v = - 2 * a * b * cos(longdestrad - longoriginrad);
  double c = sqrt(abs(u + v));
  return (long) (R * c);
}

long get_airdrop_radius(Prover &p, Verifier &v) {
  //std::cout << "d2"

  p.privi.a[0] = 0;
  p.privi.a[1] = 3;
  p.privi.a[2] = 1;
  p.privi.a[3] = 4;

  CryptoPP::Integer d2;
  d2 =
    (p.privi.x - p.pubi.xl) * (p.privi.x - p.pubi.xl) +
    (p.privi.y - p.pubi.yl) * (p.privi.y - p.pubi.yl) +
    (p.privi.z - p.pubi.zl) * (p.privi.z - p.pubi.zl);

  CryptoPP::Integer d3;
  d3=d2.SquareRoot();

  for(int j=0; j<4; j++) {
    d2 += p.privi.a[j] * p.privi.a[j];
  };

  p.pubi.d2 = d2;
  v.pubi.d2 = d2;
  std::cout << "d2" << d2 << std::endl << std::endl;
  //std::cout << "d3" << d3 << std::endl << std::endl;
  //std::cin.get();
  return d2.ConvertToLong();
}

void ClearScreen(){
  if (!cur_term)
    {
    int result;
    setupterm( NULL, STDOUT_FILENO, &result );
    if (result <= 0) return;
    }

  putp( tigetstr( "clear" ) );
  }

void pauseLines(int linesOfEndl){
  std::cout << "Pause" ;
  #ifdef ENABLE_PAUSE
    for(int i=0;i<0;i++){
      std::cout << std::endl;
    }
    std::cin.get();
    ClearScreen();
    std::cout << std::endl << std::endl;
  #endif
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

  pauseLines(18);
  //ZUG
  int xl=471666, yl=85166, zl=425, RR=10000;

  //int xl=3, yl=4, zl=5, RR;  // center
  std::cout << "** Platin Airdrop Request **"  << std::endl <<
               "Format: Lat/Long coordinates (x,y,z), radius (R), currency (BTC,ETH), Amount."  << std::endl <<
               //"Example: 3,4,5, 70, BTC,1.0" <<
               std::endl;
  /*
  std::cout << "Enter XL: ";
  std::cin >> xl;
  std::cout << "Enter YL: ";
  std::cin >> yl;
  std::cout << "Enter ZL: ";
  std::cin >> zl;
  std::cout << "Enter R: ";
  std::cin >> RR;
  */
  //std::cout << " Now XL = " << xl << " YL = " << yl << " ZL = " << zl << std::endl;
  set_airdrop_location(P, V, xl, yl, zl, RR);
  std::cout << "Airdrop location " << xl << ", " << yl << ", " << zl << " Amount: 1.2 ETH" << std::endl;

  pauseLines(6);
  //int xn=2, yn=1, =3;  // node location
  int xn=473542, yn=86321, zn=460;
  std::cout << "** Platin Test Pocket **" << std::endl <<
               "Format: Lat/Long coordinates (x,y,z), pocket_address\n Example: 2,1,3,UUID" << std::endl;
  /*
  std::cout << "Enter XN: ";
  std::cin >> xn;
  std::cout << "Enter YN: ";
  std::cin >> yn;
  std::cout << "Enter ZN: ";
  std::cin >> zn;
  */
  //std::cout << " Pocket XN = " << xn << " YN = " << yn << " ZN = " << zn << std::endl;
  set_node_location(P, V, xn, yn, zn);
  std::cout << "Pocket location " << xn << ", " << yn << ", " << zn << std::endl;

  pauseLines(6);
  std::cout << "** Platin Pocket Begin Location Claim **"  << std::endl <<
               "Producing zero knowledge commitment "  << std::endl <<
               "Sharing with Plexus" << std::endl;
  //  PrintCommitment("Pocket location commitment s_U", V.pubi.su);

  int d2;  // radius squared
  d2 = get_airdrop_radius(P, V);  // will be set_radius()
  std::cout << "Radius-squared " << d2 << std::endl;

  P.step_start(randPool);
  V.ic = P.ic;  // P -> V
  Print_start(V);

  pauseLines(6);
  std::cout << "** Plexus Policy: Zero Knowledge Location Commitment Received **"  << std::endl <<
               "Generating Random Challenge"  << std::endl <<
               "Sharing with Plexus" << std::endl;
  V.step_challenge(randPool);
  P.c = V.c; // V -> P
  std::cout << "Challenge " // << std::endl
            << V.c << std::endl;

  pauseLines(6);

  std::cout << std::endl;
  std::cout << "** Platin Pocket: Challenge Received **"  << std::endl <<
               "Generating Challenge Response"  << std::endl <<
               "Sharing with Plexus" << std::endl;
  P.step_responses();
  V.rsp = P.rsp;  // P -> V
  Print_responses(V);

  pauseLines(6);
  std::cout << std::endl;
  std::cout << "** Plexus Policy: Challenge Response Received *"  << std::endl <<
               "Calculating zero knowledge protocol - location blinded..."  << std::endl <<
               "Returning SUCCEED or FAILED";

  pauseLines(6);
  isok = V.step_verify();
  if(isok)
    std::cout << "**Proof verification SUCCEED**" << std::endl << std::endl << std::endl;
  else
    std::cout << "**Proof verification FAILED**" << std::endl << std::endl << std::endl;

  return 0;
}
