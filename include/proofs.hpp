/* Platin.io 2018
 * written by Vadym Fedyukovych
 * proofs library
 */

#include <iostream>
#if defined(__ANDROID__)
    #include <integer.h>
    #include <sha.h>
    #include <modarith.h>
#elif defined(__APPLE__)
    #include "TargetConditionals.h"
    #if TARGET_IPHONE_SIMULATOR || TARGET_OS_IPHONE
        #include <integer.h>
        #include <sha.h>
        #include <modarith.h>
    #else
        #include "cryptopp/integer.h"
        #include "cryptopp/modarith.h"
        #include "cryptopp/sha.h"
    #endif
#else
    #include "cryptopp/integer.h"
    #include "cryptopp/modarith.h"
    #include "cryptopp/sha.h"
#endif

/* Create and verify a non-interactive proof instance, according to section 14 at the documentation.
 * Input is coordinates of the node, center and radius of the airdrop.
 * Proof is encoded as a string.
 */
std::string ni_proof_create(const double xn, const double yn, const double zn, const double xl, const double yl, const double zl, const double d);
bool ni_proof_verify(const std::string proof, const double xl, const double yl, const double zl, const double d);

class GInt {
public:
  GInt(CryptoPP::Integer mr, CryptoPP::Integer mi) {r = mr; i = mi;};
  GInt(const long mr, const long mi) {r = mr; i = mi;};
  GInt() {r = 0; i = 0;};

  CryptoPP::Integer r, i;
};

class QInt {
public:
  QInt(CryptoPP::Integer mr, CryptoPP::Integer mi, CryptoPP::Integer mj, CryptoPP::Integer mk) {r = mr; i = mi; j = mj; k = mk;};
  QInt(const long mr, const long mi, const long mj, const long mk) {r = mr; i = mi; j = mj; k = mk;};
  QInt() {r = 0; i = 0; j = 0; k = 0;};

  CryptoPP::Integer r, i, j, k;
};

/* Round to nearest integer
 */
CryptoPP::Integer ground(const CryptoPP::Integer &numr, const CryptoPP::Integer &denomn);

/* GCD() for Gaussian Integers
 */
void ggcd(const GInt &ga, const GInt &gb, GInt &gc);

/* GCRD() for Quaternions
 */
void qgcrd(const QInt &qa, const QInt &qb, QInt &qc);

class Parameters {
public:
  CryptoPP::Integer n,
    g, gx, gy, gz, gr, h[4];
  CryptoPP::ModularArithmetic group;
  int rnd_bitsize_modulus,
      rnd_bitsize_commitment,
      rnd_bitsize_chall, rnd_offset_chall;
};

class PublicInfo {
public:
  long radius; // requested radius
  CryptoPP::Integer x_l, y_l, z_l,  // airdrop center
    d2;  // threshold for distance (radius), squared, actual, approximate at the moment
  CryptoPP::Integer s_U; // commitment to node_location
};

class PrivateInfo {
public:
  CryptoPP::Integer x, y, z,
    r,
    a[4],  // witness to non-negative (Lagrange theorem)
    gamma;
};

class ProofPrivate {
public:
  CryptoPP::Integer
    alpha[4], eta,
    rho_0, rho_1,
    beta_x, beta_y, beta_z, beta_r,
    f_0, f_1;
};

class InitialCommitments {
public:
  CryptoPP::Integer b_0, b_1, s_a, t_a, t_n;
};

class Responses {
public:
  CryptoPP::Integer A[4], X_n, Y_n, Z_n, R, R_a, R_d;
};

typedef long sq4[4];

typedef struct p4sq_ {
  long prime;
  sq4 sq;
} p4sq;


void init_parameters(Parameters &parm);
void ni_proof_initial(InitialCommitments &ic, PrivateInfo &privi, ProofPrivate &privpf, const PublicInfo &pubi, const Parameters &pp);
CryptoPP::Integer ni_proof_challenge(const InitialCommitments &ic, const CryptoPP::Integer &s_U, const std::string aux);
void ni_proof_responses(Responses &resp, const CryptoPP::Integer &c, const PrivateInfo &privi, const ProofPrivate &privpf);

void ni_reproduce_initial(const CryptoPP::Integer c, const CryptoPP::Integer s_U, const CryptoPP::Integer d2, InitialCommitments &ic, const Responses &resp, const Parameters &parm);

CryptoPP::Integer CreateCommitment(const Parameters &pp, const CryptoPP::Integer x, const CryptoPP::Integer y, const CryptoPP::Integer z, const CryptoPP::Integer r);
CryptoPP::Integer CreateACommitment(const Parameters &pp, const CryptoPP::Integer crnd, const CryptoPP::Integer a[]);
CryptoPP::Integer CreateNCommitment(const Parameters &pp, const CryptoPP::Integer f, const CryptoPP::Integer rho);

void rnd_commitment(const Parameters &parm, CryptoPP::Integer &s);

long get_airdrop_radius(PublicInfo &pubi, PrivateInfo &privi);

long geo_x(double dlx);
long geo_y(double dly, double org_latitude);
long geo_z(double dlz);

#define NIPROOF_COMPONENTS 15
void ni_proof_serialize(std::string &proof, const InitialCommitments &ic, const CryptoPP::Integer &c, const Responses &resp, const CryptoPP::Integer &s_U, const CryptoPP::Integer &d2);
void ni_proof_deserialize(const std::string &proof, InitialCommitments &ic, CryptoPP::Integer &c, Responses &resp, CryptoPP::Integer &s_U, CryptoPP::Integer &d2);

std::string pubcoords(const double xl, const double yl, const double zl, const double d);

void pa4decomposition(long inp, long &a1, long &a2, long &a3, long &a4);
