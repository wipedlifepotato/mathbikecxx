/*
 * Triagenmetric things
 * sometimes teachers in schools even not know that sin(90) is not thing from table of answers but circle from 0 to 1...
 * */
#pragma once
#ifndef TRIGANDE_H
#define TRIGANDE_H
#include<gmpxx.h>
#define _USE_MATH_DEFINES
#include<math.h>

#include<vector>
#include<functional>
namespace Triangle {
	/*
	 *	give  a rads/deg and get sinus. acc is for formula
	 *	x - x^3/3! + x^5/5! ... acc is count of numbers that x%2 != 0 (Teylor)
	 * */
	mpf_class calc_rads(mpf_class deg);
	mpf_class sin_rads(mpf_class rads, long int acc=4);
	mpf_class sin_rads(double rads, long int acc=4);
	mpf_class sin_deg(double deg, long int acc=4);
	mpf_class taylor_calc(mpf_class rads, long int acc, std::function<std::vector<long int>(long int)> fun, bool ish = false);
	mpf_class cos_rads(mpf_class rads, long int acc=4);
	mpf_class cos_deg(double deg, long int acc=4);
	mpf_class cos_deg(mpf_class deg, long int acc=4);
};
#endif
