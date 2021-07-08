/*
 * sydbox/wildmatch.h
 */

#ifndef WILDMATCH_H
#define WILDMATCH_H 1

#include "syd-conf.h"

int wildmatch(const char *pattern, const char *text);
int iwildmatch(const char *pattern, const char *text);
int wildmatch_array(const char *pattern, const char*const *texts, int where);
int litmatch_array(const char *string, const char*const *texts, int where);

#endif /* !WILDMATCH_H */
