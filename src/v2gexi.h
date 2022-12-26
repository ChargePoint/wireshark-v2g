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
	unsigned int i;
	char *str;
	proto_item *it;

	if (characterslen > charactersmaxsize) {
		proto_tree_add_debug_text(tree,
					  "characterslen %u > maxsize %zu",
					  characterslen, charactersmaxsize);
		return;
	}

	str = alloca(characterslen + 1);
	if (str == NULL) {
		return;
	}

	for (i = 0; i < characterslen; i++) {
		str[i] = characters[i];
	}
	str[i] = '\0';

	/*
	 * internally the proto string is a g_strdup - so, it's ok
	 * to use the alloca stack reference from above
	 */
	it = proto_tree_add_string(tree, hfindex, tvb, 0, 0, str);
	proto_item_set_generated(it);

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
