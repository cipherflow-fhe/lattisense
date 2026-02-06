#include <inttypes.h>
#include <cstdio>
#include <vector>

void print_message(const uint64_t* msg, const char* name, int count);

void print_double_message(const double* msg, const char* name, int count);

void output_message(const uint64_t* msg, const char* name, int count, FILE* fp);

bool compare_double_vectors(const std::vector<double>& a, const std::vector<double>& b, int length, double tolerance);

bool compare_double_vectors_w_offset(const std::vector<double>& a,
                                     const std::vector<double>& b,
                                     int length,
                                     double tolerance,
                                     int offset = 0,
                                     int n_slot = 4096);