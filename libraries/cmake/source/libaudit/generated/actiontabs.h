/* This is a generated file, see Makefile.am for its inputs. */
static const char action_strings[] = "always\0never\0possible";
static const unsigned action_s2i_s[] = {
	0,7,13,
};
static const int action_s2i_i[] = {
	2,0,1,
};
static int action_s2i(const char *s, int *value) {
	size_t len, i;
	len = strlen(s);
	{ char copy[len + 1];
	for (i = 0; i < len; i++) {
		char c = s[i];
		copy[i] = GT_ISUPPER(c) ? c - 'A' + 'a' : c;
	}
	copy[i] = 0;
	return s2i__(action_strings, action_s2i_s, action_s2i_i, 3, copy, value);
	}
}
static const unsigned action_i2s_direct[] = {
	7,13,0,
};
static const char *action_i2s(int v) {
	return i2s_direct__(action_strings, action_i2s_direct, 0, 2, v);
}
