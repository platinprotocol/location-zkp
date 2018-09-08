#include "proofs.hpp"

CryptoPP::Integer ground(const CryptoPP::Integer &numr, const CryptoPP::Integer &denomn) {
  CryptoPP::Integer remn, qtnt;

  remn = numr.Modulo(denomn);
  qtnt = numr / denomn;
  if(2*remn > denomn)
    qtnt++;
  return qtnt;
}
