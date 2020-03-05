/* This is a generated file, see Makefile.am for its inputs. */
static const char ftype_strings[] = "block\0character\0dir\0fifo\0file\0link\0socket";
static const unsigned ftype_s2i_s[] = {
	0,6,16,20,25,30,35,
};
static const int ftype_s2i_i[] = {
	24576,8192,16384,4096,32768,40960,49152,
};
static int ftype_s2i(const char *s, int *value) {
	size_t len, i;
	len = strlen(s);
	{ char copy[len + 1];
	for (i = 0; i < len; i++) {
		char c = s[i];
		copy[i] = GT_ISUPPER(c) ? c - 'A' + 'a' : c;
	}
	copy[i] = 0;
	return s2i__(ftype_strings, ftype_s2i_s, ftype_s2i_i, 7, copy, value);
	}
}
static const int ftype_i2s_i[] = {
	4096,8192,16384,24576,32768,40960,49152,
};
static const unsigned ftype_i2s_s[] = {
	20,6,16,0,25,30,35,
};
static const char *ftype_i2s(int v) {
	return i2s_bsearch__(ftype_strings, ftype_i2s_i, ftype_i2s_s, 7, v);
}
