#include <stdbool.h>
#include <limits.h>
#include <syd/syd.h>

/*
 * Same as SHA1DCFinal, but convert collision attack case into a verbose die().
 */
bool syd_SHA1DCFinal(unsigned char hash[20], SHA1_CTX *ctx)
{
	if (!SHA1DCFinal(hash, ctx))
		return true;
	syd_say("SHA-1 appears to be part of a collision attack: %s",
		hash_to_hex(hash));
	return false;
}

/*
 * Same as SHA1DCUpdate, but adjust types to match git's usual interface.
 */
void syd_SHA1DCUpdate(SHA1_CTX *ctx, const void *vdata, unsigned long len)
{
	const char *data = vdata;
	/* We expect an unsigned long, but sha1dc only takes an int */
	while (len > INT_MAX) {
		SHA1DCUpdate(ctx, data, INT_MAX);
		data += INT_MAX;
		len -= INT_MAX;
	}
	SHA1DCUpdate(ctx, data, len);
}
