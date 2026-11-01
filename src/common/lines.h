/*
 * Buffered line reader shared by the client and the relay.
 *
 * The same reader must survive the handshake: SAM can deliver the AUTH/HELLO
 * reply and the first chat or roster lines in one TCP chunk.  If the buffer is
 * thrown away when the handshake ends, those lines are lost.  takeBuffer()
 * hands the unread bytes to the reader used by the peer thread.
 */
#pragma once

#include <cstddef>
#include <string>
#include <utility>

#include "i2psam/i2psam.h"

namespace TriMessage
{

class LineReader
{
public:
    explicit LineReader(SAM::I2pSocket& sock, std::string pending = {})
        : m_sock(sock), m_buffer(std::move(pending))
    {
    }

    bool readLine(std::string& line)
    {
        while (true)
        {
            const std::size_t pos = m_buffer.find('\n');
            if (pos != std::string::npos)
            {
                line = m_buffer.substr(0, pos);
                m_buffer.erase(0, pos + 1);
                if (!line.empty() && line.back() == '\r')
                    line.pop_back();
                return true;
            }
            if (!m_sock.isOk())
                return false;
            const std::string chunk = m_sock.read();
            if (chunk.empty())
                return false;
            m_buffer += chunk;
            if (m_buffer.size() > (1u << 20))
                return false;
        }
    }

    std::string takeBuffer() { return std::move(m_buffer); }

private:
    SAM::I2pSocket& m_sock;
    std::string m_buffer;
};

} // namespace TriMessage
