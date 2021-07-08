/*
 * sydbox/serializer.c
 *
 * Escape JSON Strings
 *
 * Imported from pg-to-json-serializer:
 * https://github.com/alexclear/pg-to-json-serializer
 *
 * SPDX-License-Identifier: GPL-3.0-only
 */

#include "syd-conf.h"
#include "xfunc.h"
#include <string.h>

const char *json_hex_chars = "0123456789abcdef";

int printbuf_memappend(char* res, int* pos, const char *buf, int size)
{
	memcpy(res + *pos, buf, size);
	*pos += size;
	res[*pos]= '\0';
	return size;
}

char *json_escape_str(char** presult, const char *str)
{
	int result_pos = 0;
	int pos = 0, start_offset = 0;
	unsigned char c;

	(*presult) = xmalloc(strlen(str) * 6);
	(*presult)[0] = 0;
	do {
		c = str[pos];
		switch(c) {
		case '\0':
			break;
		case '\b':
		case '\n':
		case '\r':
		case '\t':
		case '"':
		case '\\':
//		case '/':
			if(pos - start_offset > 0)
			{
				printbuf_memappend(*presult, &result_pos, str + start_offset, pos - start_offset);
			}
			if(c == '\b')
			{
				printbuf_memappend(*presult, &result_pos, "\\b", 2);
			}
			else if(c == '\n')
			{
				printbuf_memappend(*presult, &result_pos, "\\n", 2);
			}
			else if(c == '\r')
			{
				printbuf_memappend(*presult, &result_pos, "\\r", 2);
			}
			else if(c == '\t') printbuf_memappend(*presult, &result_pos, "\\t", 2);
			else if(c == '"') printbuf_memappend(*presult, &result_pos, "\\\"", 2);
			else if(c == '\\') printbuf_memappend(*presult, &result_pos, "\\\\", 2);
//			else if(c == '/') printbuf_memappend(*presult, &result_pos, "\\/", 2);
			start_offset = ++pos;
			break;
		default:
			if(c < ' ') {
				if(pos - start_offset > 0)
					printbuf_memappend(*presult, &result_pos, str + start_offset, pos - start_offset);
				sprintf((*presult)+result_pos, "\\u00%c%c",
					json_hex_chars[c >> 4],
					json_hex_chars[c & 0xf]);
				result_pos += 6;
				(*presult)[result_pos] = '\0';
				start_offset = ++pos;
			} else pos++;
		}
	} while(c);
	if(pos - start_offset > 0)
		printbuf_memappend(*presult, &result_pos, str + start_offset, pos - start_offset);
	return *presult;
}
