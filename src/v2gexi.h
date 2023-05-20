/*
 * Copyright (c) 2022 ChargePoint, Inc.
 * All rights reserved.
 *
 * See LICENSE file
 */

#pragma once

#include <string.h>
#include <ctype.h>


/*
 * Compare the decode wide strings to an C string
 */
static inline int
exi_strncasecmp(const exi_string_character_t *s1, const char *s2, size_t n)
{
	size_t pos;

	if (n == 0)
		return 0;

	for (pos = 0; pos < n; pos++) {
		unsigned char c1;
		unsigned char c2;

		c1 = s1[pos];
		c2 = s2[pos];
		if (tolower(c1) != tolower(c2)) {
			return c1 - (c2 - 1);
		}
		if (c1 == '\0')
			break;
	}
	return 0;
}


/*
 * Decode the exi string character (int) into a c string
 */
static inline void
exi_add_characters(proto_tree *tree,
		   int hfindex,
		   tvbuff_t *tvb,
		   const exi_string_character_t *characters,
		   unsigned int characterslen,
		   size_t charactersmaxsize)
{
	unsigned int i, j;
	char *str;
	proto_item *it;
	int width;

	if (characterslen > charactersmaxsize) {
		proto_tree_add_debug_text(tree,
					  "characterslen %u > maxsize %zu",
					  characterslen, charactersmaxsize);
		return;
	}

	/* worst-case string length, assume every character is "\u{1fffff}" */
	str = g_malloc(characterslen * 10 + 1);
	if (str == NULL) {
		return;
	}

	for (i = 0, j = 0; i < characterslen; i++) {
		unsigned long int c = characters[i];

		if (isascii(c) && isprint(c)) {
			str[j++] = (char)c;
		} else {
			switch (c) {
			case 0:    strcpy(str + j, "\\0"); break;
			case '\a': strcpy(str + j, "\\a"); break;
			case '\b': strcpy(str + j, "\\b"); break;
			case '\f': strcpy(str + j, "\\f"); break;
			case '\n': strcpy(str + j, "\\n"); break;
			case '\r': strcpy(str + j, "\\r"); break;
			case '\t': strcpy(str + j, "\\t"); break;
			case '\v': strcpy(str + j, "\\v"); break;
			case '\'': strcpy(str + j, "\\'"); break;
			case '\\': strcpy(str + j, "\\\\"); break;
			default:
				if (c <= UINT8_MAX)
					width = 2;
				else if (c <= UINT16_MAX)
					width = 4;
				else
					width = 6;
				sprintf(str + j, "\\u{%0*lx}", width, c);
				break;
			}
			j += (unsigned int)strlen(str + j);
		}
	}
	str[j] = '\0';

	/*
	 * internally the proto string is a g_strdup - so, it's ok
	 * to use the malloc'd buffer from above
	 */
	it = proto_tree_add_string(tree, hfindex, tvb, 0, 0, str);
	proto_item_set_generated(it);

	g_free(str);

	return;
}


/*
 * Decode the exi bytes into a c string
 */
static inline void
exi_add_bytes(proto_tree *tree,
	      int hfindex,
	      tvbuff_t *tvb,
	      const uint8_t *bytes,
	      unsigned int byteslen,
	      size_t bytesmaxsize)
{
	unsigned int i;
	char *str;
	size_t strsz;
	proto_item *it;

	if (byteslen > bytesmaxsize) {
		proto_tree_add_debug_text(tree, "byteslen %u > maxsize %zu",
					  byteslen, bytesmaxsize);
		return;
	}

	strsz = (2*byteslen) + 1;
	str = alloca(strsz);
	if (str == NULL) {
		return;
	}

	for (i = 0; i < byteslen; i++) {
		snprintf(&str[2*i], strsz - 2*i, "%02X", bytes[i]);
	}
	str[2*i] = '\0';

	/*
	 * internally the proto string is a g_strdup - so, it's ok
	 * to use the alloca stack reference from above
	 */
	it = proto_tree_add_string(tree, hfindex, tvb, 0, 0, str);
	proto_item_set_generated(it);

	return;
}
