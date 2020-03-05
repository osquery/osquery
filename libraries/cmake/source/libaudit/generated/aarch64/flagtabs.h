/* This is a generated file, see Makefile.am for its inputs. */
static const char flag_strings[] = "entry\0exclude\0exit\0task\0user";
static const unsigned flag_s2i_s[] = {
	0,6,14,19,24,
};
static const int flag_s2i_i[] = {
	2,5,4,1,0,
};
static int flag_s2i(const char *s, int *value) {
	size_t len, i;
	len = strlen(s);
	{ char copy[len + 1];
	for (i = 0; i < len; i++) {
		char c = s[i];
		copy[i] = GT_ISUPPER(c) ? c - 'A' + 'a' : c;
	}
	copy[i] = 0;
	return s2i__(flag_strings, flag_s2i_s, flag_s2i_i, 5, copy, value);
	}
}
static const unsigned flag_i2s_direct[] = {
	24,19,0,-1u,14,6,
};
static const char *flag_i2s(int v) {
	return i2s_direct__(flag_strings, flag_i2s_direct, 0, 5, v);
}
