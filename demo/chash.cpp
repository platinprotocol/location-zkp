/* A minimal code supporting challenge calculation as a Fiat-Shamir hash of group elements
 * Vadym Fedyukovych 2018
 * Input: 6 group elements (big integers), output: hash as big integer
 */

#include <sstream>
#include <iostream>
#include "cryptopp/integer.h"
#include "cryptopp/sha.h"
#include <string.h>

int main() {
  CryptoPP::byte h_img[CryptoPP::SHA256::DIGESTSIZE];
  CryptoPP::SHA256 hashf;

  std::stringstream cpreimg;
  CryptoPP::Integer t_n=3, s_a=4, t_a=9, b_1=2, b_0=8, s_U=1;
  cpreimg << t_n << s_a << t_a << b_1 << b_0 << s_U;
  CryptoPP::byte *pimg = (CryptoPP::byte *) cpreimg.str().c_str();
  int sz = strlen(cpreimg.str().c_str());

  std::cout << pimg << std::endl
	    << sz << std::endl;

  hashf.CalculateDigest(h_img, pimg, sz);

  // explicit conversion into a bignumber
  CryptoPP::Integer c=0;
  for(int j=0; j<CryptoPP::SHA256::DIGESTSIZE; j++) {
    std::cout << (unsigned int) h_img[j] << std::endl;
    c = c*256 + (unsigned int)h_img[j];
  }

  std::cout << c << std::endl;
  return 0;
}
