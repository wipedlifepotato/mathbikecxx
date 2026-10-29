#ifndef PORTABLE_ENDIAN_H
#define PORTABLE_ENDIAN_H

#if defined(__linux__)
#include <endian.h>
#ifndef htole32
#define htole32(x) le32toh(x)
#endif
#ifndef le32toh
#include <byteswap.h>
#if __BYTE_ORDER == __LITTLE_ENDIAN
#define htole32(x) (x)
#define le32toh(x) (x)
#define htobe32(x) __bswap_32(x)
#define be32toh(x) __bswap_32(x)
#else
#define htole32(x) __bswap_32(x)
#define le32toh(x) __bswap_32(x)
#define htobe32(x) (x)
#define be32toh(x) (x)
#endif
#endif
#define my_htole32 htole32
#define my_le32toh le32toh
#define my_htobe32 htobe32
#define my_be32toh be32toh
#elif defined(__APPLE__)
#include <libkern/OSByteOrder.h>
#define htobe32(x) OSSwapHostToBigInt32(x)
#define htole32(x) OSSwapHostToLittleInt32(x)
#define be32toh(x) OSSwapBigToHostInt32(x)
#define le32toh(x) OSSwapLittleToHostInt32(x)
#define my_htole32 htole32
#define my_le32toh le32toh
#define my_htobe32 htobe32
#define my_be32toh be32toh
#else
#include <arpa/inet.h>
#include <byteswap.h>
#if __BYTE_ORDER == __LITTLE_ENDIAN || BYTE_ORDER == LITTLE_ENDIAN
#define htole32(x) (x)
#define le32toh(x) (x)
#define htobe32(x) htonl(x)
#define be32toh(x) ntohl(x)
#else
#define htole32(x) __bswap_32(x)
#define le32toh(x) __bswap_32(x)
#define htobe32(x) (x)
#define be32toh(x) (x)
#endif
#define my_htole32 htole32
#define my_le32toh le32toh
#define my_htobe32 htobe32
#define my_be32toh be32toh
#endif

#endif
