#include <cmath>
#include <sys/time.h>
#include "utils.h"

using namespace std;

void print_message(const uint64_t* msg, const char* name, int count) {
    fprintf(stderr, "%s = [", name);
    for (int i = 0; i < count; i++) {
        fprintf(stderr, "%lu, ", msg[i]);
    }
    fprintf(stderr, "...]\n");
}

void print_double_message(const double* msg, const char* name, int count) {
    fprintf(stderr, "%s = [", name);
    for (int i = 0; i < count; i++) {
        fprintf(stderr, "%f, ", msg[i]);
    }
    fprintf(stderr, "...]\n");
}

void output_message(const uint64_t* msg, const char* name, int count, FILE* fp) {
    for (int i = 0; i < count; i++) {
        fprintf(fp, "%lu\n", msg[i]);
    }
}

bool compare_double_vectors(const vector<double>& a, const vector<double>& b, int length, double tolerance) {
    bool different = false;
    for (int i = 0; i < length; i++) {
        if (fabs(b[i] - a[i]) > tolerance) {
            fprintf(stderr, "Comparison failed: index=%d, left=%.8f, right=%.8f, diff=%.4e\n", i, a[i], b[i],
                    b[i] - a[i]);
            different = true;
        }
    }
    return different;
}

bool compare_double_vectors_w_offset(const vector<double>& a,
                                     const vector<double>& b,
                                     int length,
                                     double tolerance,
                                     int offset,
                                     int n_slot) {
    bool different = false;
    for (int i = 0; i < length; i++) {
        int index = (i + offset + n_slot) % n_slot;
        if (fabs(b[index] - a[index]) > tolerance) {
            fprintf(stderr, "Comparison failed: index=%d, left=%.8f, right=%.8f, diff=%.4e\n", index, a[index],
                    b[index], b[index] - a[index]);
            different = true;
        }
    }
    return different;
}