#include<iostream>
#include<functional>
#include<vector>
#include<map>
#include<string>
#include"i2psam/i2psam.h"
class Client
{

};
using CommandsT = std::map< std::string, std::function<bool(Client & client, std::vector<std::string> params)> >;

int main(const int c, 
		const char** v, 
		const char** a)
{
	
}
