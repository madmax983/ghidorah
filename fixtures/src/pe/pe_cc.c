/* PE fixture pe_cc.exe: functions with 1 to 8 parameters, mixed integer and floating
 * parameters and functions with 4 or more parameters (design Section 4.15).
 * Each function uses every parameter, so the MS x64 recovery can see each one. */
#include "pe_rt.h"

int _fltused = 0;
volatile int sink;
volatile double dsink;

NOINLINE int p1(int a) { return a * 3 + sink; }
NOINLINE int p2(int a, int b) { return a * b + sink; }
NOINLINE int p3(int a, int b, int c) { return a * b - c + sink; }
NOINLINE int p4(int a, int b, int c, int d) { return (a + b) * (c - d) + sink; }
NOINLINE int p5(int a, int b, int c, int d, int e) { return a * b + c * d - e + sink; }
NOINLINE int p6(int a, int b, int c, int d, int e, int f) { return a + b * c + d * e - f; }
NOINLINE int p7(int a, int b, int c, int d, int e, int f, int g) {
    return a * g + b * f + c * e + d + sink;
}
NOINLINE int p8(int a, int b, int c, int d, int e, int f, int g, int h) {
    return (a ^ h) + (b ^ g) + (c ^ f) + (d ^ e) + sink;
}
NOINLINE long long q4(long long a, long long b, long long c, long long d) {
    return a * d - b * c;
}
NOINLINE int ptr2(const int *p, int n) { return p[n] + sink; }
NOINLINE double f1(double x) { return x * 2.5 + dsink; }
NOINLINE double f2(double x, double y) { return x * y + dsink; }
NOINLINE double m3(int a, double b, int c) { return (double)a * b + (double)c; }
NOINLINE double m4(double a, int b, double c, int d) { return a * (double)b + c * (double)d; }
NOINLINE double m5(int a, double b, int c, double d, int e) {
    return (double)a * b + (double)c * d + (double)e;
}
NOINLINE double m6(double a, double b, double c, double d, double e, int f) {
    return a * b + c * d + e * (double)f;
}
NOINLINE float g2(float x, int n) { return x * (float)n + (float)sink; }

int table[4] = {1, 2, 3, 4};

void cc_start(void) {
    int r = p1(1) + p2(1, 2) + p3(1, 2, 3) + p4(1, 2, 3, 4) + p5(1, 2, 3, 4, 5);
    r += p6(1, 2, 3, 4, 5, 6) + p7(1, 2, 3, 4, 5, 6, 7) + p8(1, 2, 3, 4, 5, 6, 7, 8);
    r += (int)q4(1, 2, 3, 4) + ptr2(table, 2);
    double d = f1(1.0) + f2(1.0, 2.0) + m3(1, 2.0, 3) + m4(1.0, 2, 3.0, 4);
    d += m5(1, 2.0, 3, 4.0, 5) + m6(1.0, 2.0, 3.0, 4.0, 5.0, 6) + (double)g2(1.5f, 2);
    sink = r;
    dsink = d;
}
