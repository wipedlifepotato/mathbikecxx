#include<iostream>
#include"trigande.h"
#include<sstream>
#include"alberthofman.h"
#include"i2psam/i2psam.h"
#include<thread>
void clientThread(std::string dest) 
{
	    SAM::StreamSession session("TestClientSession",  "127.0.0.1", 7656  );
	    if(session.isSick())
	    {
		std::cerr << "Can't create session" << std::endl;
		exit(1);
	    }
	    auto lookupResult = session.namingLookup(dest);
	    auto result = session.connect(lookupResult.value, false);
	    // auto conn = result.value.get() ... conn-> write
	    if (!result.isOk || !result.value) {        std::cerr << "Can't connect to server\n";        exit(1);    }
	    auto& stream = *result.value;
	    while(true)
	    {
	     stream.write("EXIT");
	     std::cout << "CLIENT: " << stream.read() << std::endl;
	     sleep(5);
	    }

}
int main(int argc, char** argv, char **env)
{
	// SAM 
	{
	std::thread AcceptThread([](){
	SAM::StreamSession session(
			"TestSession",
			"127.0.0.1",
			7656
			//,"privkey"
	);
	if (session.isSick())
	{
		std::cerr << "Can't init session" << std::endl;
		return 1;
	}
	std::cout << "SERVER DESTINATION: " << session.getMyDestination().pub << std::endl;
	std::cout << "SERVER PRIVKEY: " << session.getMyDestination().priv << std::endl;
	std::thread ClientThread(clientThread, session.getMyDestination().pub);
	while(true)
	{
		auto result = session.accept(false);
		if( !result.isOk || !result.value )
		{
			std::cerr << "Can't accept" << std::endl;
			continue;
		}
		auto & stream = *result.value;

		const std::string message = stream.read();
		std::cout << "SERVER: " << message << std::endl;
		stream.write("Pong: " + message);
		if (message == "EXIT" || !message.length() )
		{
			break;
		}
	}
	return 0;
	});
	AcceptThread.join();
	return 0;
	}
	
	// sinus
	{
	 std::ostringstream sin_deg_stream;
	 sin_deg_stream << Triangle::sin_deg(35);
	 std::ostringstream sin_rads_stream;
	 sin_rads_stream << Triangle::sin_rads(0.6100);
	 std::string sin_deg_str = sin_deg_stream.str();
	 std::string sin_rads_str { sin_rads_stream.str() };
	 if ( sin_deg_str.substr(0,4) != sin_rads_str.substr(0,4) || sin_rads_str.substr(0,4) != "0.57" ) 
	 {
		std::cout << sin_deg_str << std::endl;
		std::cout << sin_rads_str << std::endl;
		throw std::runtime_error("Sinus of degree not equal sinus of rads or not equal 0.57");
	 }
	}
        // cosinus
        {
         std::ostringstream cos_deg_stream;
         cos_deg_stream << Triangle::cos_deg(35, 15);
         std::ostringstream cos_rads_stream;
         cos_rads_stream << Triangle::cos_rads(0.6100, 15);
         std::string cos_deg_str = cos_deg_stream.str();
         std::string cos_rads_str { cos_rads_stream.str() };
         if ( cos_deg_str.substr(0,4) != cos_rads_str.substr(0,4) || cos_rads_str.substr(0,4) != "0.81" )  
         {
               std::cout << cos_deg_str << std::endl;
               std::cout << cos_rads_str << std::endl;
               throw std::runtime_error("Cosinus of degree not equal cosinus of rads or not equal 0.81");
         }
	}
	// sinh / cosh
        {
            std::ostringstream h_cos, h_sin;
            h_cos << Triangle::cos_deg(35, 15, true);
            h_sin << Triangle::sin_deg(35, 15, true);

            if (h_cos.str().substr(0, 4) != "1.19" || h_sin.str().substr(0, 4) != "0.64")
                throw std::runtime_error("Hyperbolic math is broken");
        }

	{
		auto p = DiffiHofman::random_n();
		auto g = DiffiHofman::random_n(128);
		auto alice = DiffiHofman{p,g};
		auto bob = DiffiHofman{p,g};
		//
		auto alicePubKey = alice.getPublicKey();
		auto bobPubKey = bob.getPublicKey();
		//
		auto sharedKeyAlice = alice.getSharedKey(bobPubKey);
		auto sharedKeyBob = bob.getSharedKey(alicePubKey);

		std::cout << "shared key of Alice: " << sharedKeyAlice << std::endl;
		std::cout << "~~~~~~~~~~~~~~~~~~~~~~" << std::endl;
		std::cout << "shared key of Bob: " << sharedKeyBob << std::endl;

	}

}
