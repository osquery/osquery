/* This is a generated file, see Makefile.am for its inputs. */
static const char field_strings[] = "a0\0a1\0a2\0a3\0arch\0auid\0devmajor\0devminor\0dir\0egid\0"
	"euid\0exit\0field_compare\0filetype\0fsgid\0fsuid\0gid\0inode\0key\0loginuid\0"
	"msgtype\0obj_gid\0obj_lev_high\0obj_lev_low\0obj_role\0obj_type\0obj_uid\0obj_user\0path\0perm\0"
	"pers\0pid\0ppid\0sgid\0subj_clr\0subj_role\0subj_sen\0subj_type\0subj_user\0success\0"
	"suid\0uid";
static const unsigned field_s2i_s[] = {
	0,3,6,9,12,17,22,31,40,44,
	49,54,59,73,82,88,94,98,104,108,
	117,125,133,146,158,167,176,184,193,198,
	203,208,212,217,222,231,241,250,260,270,
	278,283,
};
static const int field_s2i_i[] = {
	200,201,202,203,11,9,100,101,107,6,
	2,103,111,108,8,4,5,102,210,9,
	12,110,23,22,20,21,109,19,105,106,
	10,0,18,7,17,14,16,15,13,104,
	3,1,
};
static int field_s2i(const char *s, int *value) {
	size_t len, i;
	len = strlen(s);
	{ char copy[len + 1];
	for (i = 0; i < len; i++) {
		char c = s[i];
		copy[i] = GT_ISUPPER(c) ? c - 'A' + 'a' : c;
	}
	copy[i] = 0;
	return s2i__(field_strings, field_s2i_s, field_s2i_i, 42, copy, value);
	}
}
static const int field_i2s_i[] = {
	0,1,2,3,4,5,6,7,8,9,
	10,11,12,13,14,15,16,17,18,19,
	20,21,22,23,100,101,102,103,104,105,
	106,107,108,109,110,111,200,201,202,203,
	210,
};
static const unsigned field_i2s_s[] = {
	208,283,49,278,88,94,44,217,82,17,
	203,12,117,260,231,250,241,222,212,184,
	158,167,146,133,22,31,98,54,270,193,
	198,40,73,176,125,59,0,3,6,9,
	104,
};
static const char *field_i2s(int v) {
	return i2s_bsearch__(field_strings, field_i2s_i, field_i2s_s, 41, v);
}
