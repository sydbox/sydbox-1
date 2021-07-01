/*
 * sydbox/pink.h
 *
 * pinktrace wrapper functions
 *
 * Copyright (c) 2014, 2021 Ali Polatel <alip@exherbo.org>
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef PINK_H
#define PINK_H

#ifndef HAVE_CONFIG_H
# include "config.h"
#endif

#include <syd/compiler.h>
#include "dump.h"

#include <string.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/un.h>
#include <linux/netlink.h>

#include <seccomp.h>

#if ENABLE_PSYSCALL
# include "psyscall_syd.h"
#endif

#if defined(__aarch64__)
# define ABIS_SUPPORTED 2
static const uint32_t abi[ABIS_SUPPORTED] = { SCMP_ARCH_AARCH64, SCMP_ARCH_ARM };
#elif defined(__ILP32__)
# define ABIS_SUPPORTED 2
static const uint32_t abi[ABIS_SUPPORTED] = { SCMP_ARCH_X32, SCMP_ARCH_X86 };
#elif defined(__x86_64__)
# define ABIS_SUPPORTED 3
static const uint32_t abi[ABIS_SUPPORTED] = { SCMP_ARCH_X86_64, SCMP_ARCH_X32,
	SCMP_ARCH_X86 };
#elif defined(__powerpc64__)
# define ABIS_SUPPORTED 2
static const uint32_t abi[ABIS_SUPPORTED] = { SCMP_ARCH_PPC64, SCMP_ARCH_PPC32 };
# endif

#ifndef ABIS_SUPPORTED
# define ABIS_SUPPORTED 1
# static const uint32_t abi[ABIS_SUPPORTED] = { SCMP_ARCH_NATIVE };
#endif

/** Structure which represents a socket address. */
struct pink_sockaddr {
	/** Family of the socket address **/
	int family;

	/** Length of the socket address */
	socklen_t length;

	/**
	 * This union contains type-safe pointers to the real socket address.
	 * Check the family before attempting to obtain the real object.
	 **/
	union {
		/** Padding, mostly for internal use */
		char pad[128];

		/** Socket address, mostly for internal use */
		struct sockaddr sa;

		/** Unix socket address, only valid if family is AF_UNIX */
		struct sockaddr_un sa_un;

		/** Inet socket address, only valid if family is AF_INET */
		struct sockaddr_in sa_in;

		/** Inet6 socket address, only valid if family is AF_INET6. */
		struct sockaddr_in6 sa6;

		/** Netlink socket address, only valid if family is AF_NETLINK. */
		struct sockaddr_nl nl;
	} u;
};

/** Decoded socket subcalls */
enum pink_socket_subcall {
	/** socket() subcall **/
	PINK_SOCKET_SUBCALL_SOCKET = 1,
	/** bind() subcall **/
	PINK_SOCKET_SUBCALL_BIND,
	/** connect() subcall **/
	PINK_SOCKET_SUBCALL_CONNECT,
	/** listen() subcall **/
	PINK_SOCKET_SUBCALL_LISTEN,
	/** accept() subcall **/
	PINK_SOCKET_SUBCALL_ACCEPT,
	/** getsockname() subcall **/
	PINK_SOCKET_SUBCALL_GETSOCKNAME,
	/** getpeername() subcall **/
	PINK_SOCKET_SUBCALL_GETPEERNAME,
	/** socketpair() subcall **/
	PINK_SOCKET_SUBCALL_SOCKETPAIR,
	/** send() subcall **/
	PINK_SOCKET_SUBCALL_SEND,
	/** recv() subcall **/
	PINK_SOCKET_SUBCALL_RECV,
	/** sendto() subcall **/
	PINK_SOCKET_SUBCALL_SENDTO,
	/** recvfrom() subcall **/
	PINK_SOCKET_SUBCALL_RECVFROM,
	/** shutdown() subcall **/
	PINK_SOCKET_SUBCALL_SHUTDOWN,
	/** setsockopt() subcall **/
	PINK_SOCKET_SUBCALL_SETSOCKOPT,
	/** getsockopt() subcall **/
	PINK_SOCKET_SUBCALL_GETSOCKOPT,
	/** sendmsg() subcall **/
	PINK_SOCKET_SUBCALL_SENDMSG,
	/** recvmsg() subcall **/
	PINK_SOCKET_SUBCALL_RECVMSG,
	/** accept4() subcall **/
	PINK_SOCKET_SUBCALL_ACCEPT4,
};

struct xlat {
	const char *str;
	int val;
};

SYD_GCC_ATTR((pure))
static inline const char *xname(const struct xlat *xlat, int val)
{
	for (; xlat->str != NULL; xlat++)
		if (xlat->val == val)
			return xlat->str;
	return NULL;
}

SYD_GCC_ATTR((pure,unused))
static inline int xlookup(const struct xlat *xlat, const char *str)
{
	if (!str || *str == '\0')
		return -1;

	for (; xlat->str != NULL; xlat++)
		if (!strcmp(str, xlat->str))
			return xlat->val;
	return -1;
}

static const struct xlat socket_subcalls[] = {
	{"bind",		PINK_SOCKET_SUBCALL_BIND},
	{"connect",		PINK_SOCKET_SUBCALL_CONNECT},
	{"listen",		PINK_SOCKET_SUBCALL_LISTEN},
	{"accept",		PINK_SOCKET_SUBCALL_ACCEPT},
	{"getsockname",		PINK_SOCKET_SUBCALL_GETSOCKNAME},
	{"getpeername",		PINK_SOCKET_SUBCALL_GETPEERNAME},
	{"socketpair",		PINK_SOCKET_SUBCALL_SOCKETPAIR},
	{"send",		PINK_SOCKET_SUBCALL_SEND},
	{"recv",		PINK_SOCKET_SUBCALL_RECV},
	{"sendto",		PINK_SOCKET_SUBCALL_SENDTO},
	{"recvfrom",		PINK_SOCKET_SUBCALL_RECVFROM},
	{"shutdown",		PINK_SOCKET_SUBCALL_SHUTDOWN},
	{"setsockopt",		PINK_SOCKET_SUBCALL_SETSOCKOPT},
	{"getsockopt",		PINK_SOCKET_SUBCALL_GETSOCKOPT},
	{"sendmsg",		PINK_SOCKET_SUBCALL_SENDMSG},
	{"recvmsg",		PINK_SOCKET_SUBCALL_RECVMSG},
	{"accept4",		PINK_SOCKET_SUBCALL_ACCEPT4},
	{NULL,			0},
};
#define name_socket_subcall(subcall) (xname((socket_subcalls), (subcall)))

#endif
