#include"alberthofman.h"
DiffiHofman::DiffiHofman(const mpz_class p, const mpz_class g) : p(p), g(g)
{
	int result = mpz_probab_prime_p(p.get_mpz_t(), 25);
	//int result1 = mpz_probab_prime_p(g.get_mpz_t(), 25);
	if (result == 0)
		throw std::runtime_error("p is not prime");
}

mpz_class DiffiHofman::random_n(unsigned long num_bits)
{
	//recursion is stack overflow... and ponti ebanije
	while(true)
	{
	std::random_device rd;
	gmp_randclass rand_gen(gmp_randinit_mt); 
	unsigned long seed = (static_cast<unsigned long>(rd()) << 32) | rd();
	rand_gen.seed(seed); // random seed for generator
			     //
	mpz_class start_num = rand_gen.get_z_bits(num_bits);
	mpz_setbit(start_num.get_mpz_t(), num_bits - 1);
	mpz_setbit(start_num.get_mpz_t(), 0);

	mpz_class prime_p;
	mpz_nextprime(prime_p.get_mpz_t(), start_num.get_mpz_t());
	if ( mpz_probab_prime_p(prime_p.get_mpz_t(), 25) == 2 )
	{
		return prime_p;
	}
	}
        //while(true)	
	//{
	//	mpz_class private_key = rand_gen.get_z_bits(num_bits);
	//	if ( mpz_probab_prime_p(private_key.get_mpz_t(), 25) == 2 )
	//		return private_key;
//
//	}
}

/*mpz_class DiffiHofman::getPublicKey(unsigned long secret_bits)
{
	mpz_class A;
	x = random_n(secret_bits);
	mpz_powm(A.get_mpz_t(), g.get_mpz_t(), x.get_mpz_t(), p.get_mpz_t());
	return A;
}*/
mpz_class DiffiHofman::getPublicKey(unsigned long secret_bits)
{
    mpz_class A;

    std::random_device rd;
    gmp_randclass rand_gen(gmp_randinit_mt);
    unsigned long seed = (static_cast<unsigned long>(rd()) << 32) | rd();
    rand_gen.seed(seed);

    x = rand_gen.get_z_bits(secret_bits);

    mpz_powm(A.get_mpz_t(), g.get_mpz_t(), x.get_mpz_t(), p.get_mpz_t());
    return A;
}

mpz_class DiffiHofman::getSharedKey(mpz_class B)
{
	mpz_class shared_key;
	mpz_powm(shared_key.get_mpz_t(), B.get_mpz_t(), x.get_mpz_t(), p.get_mpz_t());
	return shared_key;
}


