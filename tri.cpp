#include<iostream>
#include<functional>
#include<vector>
#include<map>
#include<string>
#include"i2psam/i2psam.h"
#define eLog(level, msg) \
    std::cout << "[" << level << "] [" << __FILE__ << ":" << __LINE__ << "] " << msg << std::endl

class Client final
{
	protected:
		uint16_t m_port;
		std::string m_host;
		std::unique_ptr<SAM::StreamSession> m_session;

		std::string m_sessionName;
	public:
		void WriteMessage(const std::string text) noexcept
		{
			std::cout << text << std::endl;
		}
		Client(const std::string host = "127.0.0.1", uint16_t port = 7656, std::string privKey = "", std::string sessionName = "TriMessage")
			:
			m_host(host), m_port(port), m_sessionName(sessionName)
		{
			// i2psam/i2psam.h:475:3: note: candidate: ‘SAM::StreamSession::StreamSession(const std::string&, const std::string&, uint16_t, const std::string&, const std::string&, const std::string&)’
			m_session = !privKey.length() ? std::make_unique<SAM::StreamSession>(m_sessionName, m_host, m_port) : std::make_unique<SAM::StreamSession>(m_sessionName, m_host, m_port, privKey);
			if (m_session->isSick())
			{
				throw std::runtime_error("Can't init SAM session");
			}
			//mPub = m_session.getMyDestination().pub;
			//mPriv = m_session.getMyDesination().priv;
		}
		void reInitSession(void)
		{
			std::string oldPrivKey = m_session->getMyDestination().priv;
			m_session = std::make_unique<SAM::StreamSession>(m_sessionName, m_host, m_port, oldPrivKey);
			if (m_session->isSick()) {
				throw std::runtime_error("Can't re-init SAM session");
			}

		}
		void AcceptThread(void)
		{
			uint8_t errors = 0;
			while(true)
			{
			       auto result = m_session->accept(false);
 		               if( !result.isOk || !result.value )
                	       {
                        	 eLog("WARNING","Can't accept");
				 errors++;
				 if(errors > 10)
				 {
					reInitSession();
					errors = 0;
				 }
                       		 continue;
                	       }
                	       auto & stream = *result.value;

                               //const std::string message = stream.read();
                               //std::cout << "SERVER: " << message << std::endl;
                               //stream.write(" " + message);
			       /*	Протокол приветствия
				*	Сервер должен получить информация о пользователе его никнейм, хэш клиента основанный на хэше публичного ключа. простой XOR всех байтов со сдвигом. Но лучше более менее нормальное
				*	Часть приватного ключа объеденяет этот хэш, при этом нужна будет проверка по элиптической кривой, тот ли человек или нет.
				*	Дальше сервер<->клиент либо отклоняет (пока-что всегда принимает)
				*	Дальше после приема создается отдельный клиент с std::vector пользователей. Между ними переключаться через команду /chat ID. Буфер для каждого пользователя в отдельный объект
				*	подгружается каждый раз и очищается предыдущий текст
				*	Сначала идет обмен DH ключами 8129 бит обязательно обоих.
				*	Дальше каждые 5-15 минут обмен снова DH но размер уже меньше намного 1024 достаточно и меняются ключи.
				*	За основу шифрования взят ChaCha20. nonce кажды йраз меняется
				*	Sin/Cos/SinH/CosH должен использоваться с обоих сторон каждый раз для padding. Каждый раз разные числа и специально брать такие числа, что бы значение
				*	было всегда псевдослучайное этот padding перед сообщением вообще не должен относиться к шифрованию. То есть даже дешифровываться не должен.
				*	Каждый раз он должен быть разной длины в целом. Понять что идет сообщение смогут лишь пользовали по тому как дешифрованное сообщение выглядит.
				*	Это должна быть структура, которая подгружается при каждом разе. В структуре должна быть информация об отправителе и получателе, ключи и остальном. Её соответственно будут видеть 
				*	участники. То есть в предыдущем блоке информации должно содержаться размер padding.
				*	дальше команда /msg для отправки сообщения нужному участнику. Для первых тестов размер ключа бит можно взять не 8129, так как тестов будет много. Для того что бы это менять
				*	в начале клиента сделай статичную переменную глобальную с ключами по умолчанию аля constexpr
				* */
			}// while
		}
};
using ParamsT = std::vector<std::string>;
using CommandsT = std::map< std::string, std::function<bool(Client & client, ParamsT params)> >;


#define COMMANDINIT [](Client & c, ParamsT params) -> bool

CommandsT commands
{
	{
		"help", COMMANDINIT {
					      c.WriteMessage("/help - usage of program"); 
					      return true;
		}
	}
};

int main(const int c, 
		const char** v, 
		const char** a)
{
	
}
