/*
 * sydbox/serializer.h
 *
 * Escape JSON Strings
 *
 * Imported from pg-to-json-serializer:
 * https://github.com/alexclear/pg-to-json-serializer
 *
 * SPDX-License-Identifier: GPL-3.0-only
 */

#ifndef SERIALIZER_H
#define SERIALIZER_H 1

char *json_escape_str(char** presult, const char *str);

#endif
