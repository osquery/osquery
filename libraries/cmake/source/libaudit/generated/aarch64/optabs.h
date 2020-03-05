/* This is a generated file, see Makefile.am for its inputs. */
static const char op_strings[] = "!=\0&\0&=\0<\0<=\0=\0>\0>=";
static const int op_i2s_i[] = {
	134217728,268435456,536870912,805306368,1073741824,1207959552,1342177280,1610612736,
};
static const unsigned op_i2s_s[] = {
	3,8,15,0,13,5,10,17,
};
static const char *op_i2s(int v) {
	return i2s_bsearch__(op_strings, op_i2s_i, op_i2s_s, 8, v);
}
