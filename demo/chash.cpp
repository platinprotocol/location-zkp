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
  CryptoPP::byte h_img[CryptoPP::SHA256::DIGESTSIZE]; //20 bytes of result hash, or 30 for sha256 - result of this function
  CryptoPP::SHA256 hashf;

  std::stringstream cpreimg;
  CryptoPP::Integer t_n=3, s_a=4, t_a=9, b_1=2, b_0=8, s_U=1; //sample numbers for proover formula calculation
  cpreimg << t_n << s_a << t_a << b_1 << b_0 << s_U; //concatenate numbers into single string so that we can push that into hash function.
  CryptoPP::byte *pimg = (CryptoPP::byte *) cpreimg.str().c_str(); //input data for hash function
  int sz = strlen(cpreimg.str().c_str()); //length of input data

  std::cout << pimg << std::endl
	    << sz << std::endl;

  hashf.CalculateDigest(h_img, pimg, sz); //calculating hash, result printed into h_img

  // explicit conversion into a bignumber, byte by byte
  CryptoPP::Integer c=0;
  for(int j=0; j<CryptoPP::SHA256::DIGESTSIZE; j++) {
    std::cout << (unsigned int) h_img[j] << std::endl;
    c = c*256 + (unsigned int)h_img[j]; 
  }
  //here we have to compare result of hash function in a form of bignumber to result of hash from proover
  std::cout << c << std::endl;
  return 0;
}
