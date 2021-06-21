/*
 * libsyd/state.c
 *
 * Simple interface to C11 atomic_bool
 *
 * Copyright (c) 2021 Ali Polatel <alip@exherbo.org>
 * Released under the terms of the GNU General Public License v3 (or later)
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include "syd.h"
#include <stdatomic.h>
#include <stdbool.h>

inline bool syd_get_state(const volatile atomic_bool *state)
{
	return atomic_load(state);
}

inline bool syd_set_state(volatile atomic_bool *state, bool value)
{
	bool expected = !value;
	return atomic_compare_exchange_strong(state, &expected, value);
}
