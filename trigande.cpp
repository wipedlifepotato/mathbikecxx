/*
 * Triagenmetric things
 * sometimes teachers in schools even not know that sin(90) is not thing from table of answers but circle from 0 to 1...
 * */
//
#include"trigande.h"
namespace Triangle {
	mpf_class calc_rads(mpf_class deg)
	{
		//deg = deg % 360.0;
		mpf_class rads = (deg*M_PI/180.0);
		return rads;
	}
	mpf_class taylor_calc(mpf_class rads, long int acc, std::function<std::vector<long int>(long int)> fun, bool ish) 
	{
   	        mpf_class sum = 0.0;
		int step=0;
		for( auto n : fun(acc) )
		{
			mpz_class factorial{};
			mpz_fac_ui(factorial.get_mpz_t(), n);

			mpf_class pow{};
			mpf_pow_ui(pow.get_mpf_t(), rads.get_mpf_t(), n);
			if(step % 2 == 0 || ish)
			 sum += (pow/factorial);
			else 
			 sum -= (pow/factorial);
			step++;
		}
		return sum;
	}
	mpf_class cos_rads(mpf_class rads, long int acc)
	{

		return taylor_calc(rads, acc, [](long int c) {
			std::vector<long int> ret;
			for(long int i = 0; i < c; i+=2)
			{
				ret.push_back(i);	
			}
			return ret;
		});
	}
	mpf_class cos_deg(double deg, long int acc)
	{
		return cos_rads ( calc_rads(deg), acc);
	}
	mpf_class cos_deg(mpf_class deg, long int acc)
	{
		return cos_rads(deg, acc);
	}
	mpf_class sin_rads(mpf_class rads, long int acc)
	{
		auto odds = [](long int c)
		{
			std::vector<long int> ret;
			for(long int i = 1; i < c; i+=2)
			{
				ret.push_back(i);	
			}
			return ret;
		};
		return taylor_calc(rads, acc, odds);
	
	}
	mpf_class sin_rads(double rads, long int acc)
	{
		return sin_rads(mpf_class{rads}, acc);
	}
	mpf_class sin_deg(double deg, long int acc)
	{
		mpf_class rads = calc_rads(deg); //= (deg * M_PI/180.0); // rad-x need. so for calculate we need radians from degree
//		std::cout << "rads:" << rads << std::endl;
		return sin_rads(rads, acc);
	}
};
