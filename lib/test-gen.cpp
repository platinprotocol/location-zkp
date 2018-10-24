//#include "cryptlib.h"
//#include "pubkey.h"
#include <iostream>
#include "cryptopp/integer.h"
#include "cryptopp/modarith.h"
#include "cryptopp/algparam.h"
#include "cryptopp/nbtheory.h"
#include "cryptopp/osrng.h"

class Parameters
{
 protected:
  CryptoPP::Integer m_n, m_gen[9];
};

class Parameters_pvt : public Parameters
{
 public:
  bool generate(int bitsize, int ordsize);
  /*
  save();
  load();
  */
 protected:
  CryptoPP::Integer m_ordp, m_ordq, m_p, m_q;
};

int main() {
  Parameters_pvt privk;
  privk.generate(2000, 120);
  Parameters pp(privk);
  return 0;
}

bool Parameters_pvt::generate(int bitsize, int ordsize) {
  CryptoPP::AutoSeededRandomPool rng;

  std::cout << "Bitsize and order size: " << bitsize << ",  " << 2*ordsize << std::endl;

  CryptoPP::AlgorithmParameters ordPrm =
    CryptoPP::MakeParametersForTwoPrimesOfEqualSize(ordsize);
  m_ordp.GenerateRandom(rng, ordPrm);
  m_ordq.GenerateRandom(rng, ordPrm);
  std::cout << "Group order: "  << std::endl
	    << m_ordp << std::endl
	    << m_ordq << std::endl;

  CryptoPP::AlgorithmParameters ordprimePrm =
    CryptoPP::MakeParametersForTwoPrimesOfEqualSize(bitsize)
    ("EquivalentTo", 1);

  m_p.GenerateRandom(rng, ordprimePrm("Mod", 2*m_ordp));
  m_q.GenerateRandom(rng, ordprimePrm("Mod", 2*m_ordq));
  m_n = m_q * m_p;

  CryptoPP::ModularArithmetic group;
  group.SetModulus(m_n);

  std::cout << "Primes: " << std::endl
	    << m_p << std::endl
	    << m_q << std::endl
	    << "Mult group  modulus: " << std::endl
	    << m_n << std::endl;

  CryptoPP::Integer ord = (m_p - 1) * (m_q - 1),
                    pwr_pq = ord/(m_ordp * m_ordq), r;
  bool ok;
  do {
    r.GenerateRandom(rng,
		     CryptoPP::MakeParameters("BitLength", bitsize));
    m_gen[0] = group.Exponentiate(r, pwr_pq);
    ok = group.Exponentiate(m_gen[0], m_ordp) != 1 &&
         group.Exponentiate(m_gen[0], m_ordq) != 1;
  } while (!ok);

  for(int j=1; j<9; j++) {
    r.GenerateRandom(rng,
      CryptoPP::MakeParameters("BitLength", 2*ordsize));
    m_gen[j] = group.Exponentiate(m_gen[0], r);
  }
  
  std::cout << "Generators (g, gx, gy, gz, gr, h[4]): " << std::endl;
  for(int j=0; j<9; j++) {
    std::cout << m_gen[j] << std::endl;
  }
  
  return true;
}
