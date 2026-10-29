#include<gmpxx.h>
#include<random>
class DiffiHofman 
{
	protected:
		mpz_class p,g,x;
	public:
		// DiffiHoman::DiffiHoman{random_n(), random_n(128)};
		DiffiHofman(const mpz_class p, const mpz_class g);
		static mpz_class random_n(unsigned long num_bits=8192);
		mpz_class getPublicKey(unsigned long secret_bits=256);
		mpz_class getSharedKey(mpz_class B); // an another public key
					
};
