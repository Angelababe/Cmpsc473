#define STRLEN   16

struct A {
	char string_a[STRLEN]; // Any string
	struct B *ptr_b; // 
	char string_c[STRLEN]; // Any string
	char string_d[STRLEN]; // Any string
	struct C *ptr_e; // 
	int num_f; // >0 or set to 0
	int (*op0)(struct A *objA);
	unsigned char *(*op1)(struct A *objA);
};
struct B {
	int num_a; // <0 or set to 0
	int num_b; // >0 or set to 0
	char string_c[STRLEN]; // Must have vowel or add to end
	char string_d[STRLEN]; // Capitalize Strings
	int num_e; // <0 or set to 0
};
struct C {
	int num_a; // >0 or set to 0
	char string_b[STRLEN]; // Capitalize Strings
	int num_c; // <0 or set to 0
	char string_d[STRLEN]; // Any string
	int num_e; // >0 or set to 0
	char string_f[STRLEN]; // Must have vowel or add to end
};
