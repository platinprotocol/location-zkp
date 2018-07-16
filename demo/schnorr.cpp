#include <iostream>
#include "cryptopp/modarith.h"

int main() {
  CryptoPP::Integer q=5, p=11,
                    // evidence: bc, 3^5%11 gives 1
                    g=3;
  CryptoPP::ModularArithmetic group(p);
  CryptoPP::ModularArithmetic field(q);

  std::cout << "Parameters" << std::endl
            << "Modulus " << p
            << ";  group order " << q
            << ";  generator " << g
            << std::endl;

  // secret x, public gx, initial witness w, public gw, challenge c, response X.
  CryptoPP::Integer x=2, gx, w, gw, c, X, gxc;
  // evidence: bc 3^2%11 -> 9
  gx = group.Exponentiate(g, x);
  std::cout << "Secret " << x
            << ";  public " << gx
            << std::endl;

  w = 2L;
  gw = group.Exponentiate(g, w);
  std::cout << "Initial witness " << w
            << ";  public " << gw
            << std::endl;

  c = 3;
  X = field.ConvertIn(c*x + w); // +1 for not Ok
  std::cout << "Response " << X
            << std::endl;

  if(group.Multiply(group.Exponentiate(g, X),
		    group.MultiplicativeInverse(group.Exponentiate(gx, c)))
     ==
     gw
     )
    std::cout << "Verify Ok" << std::endl;

  return 0;
}
