#include "crypto/w11.h"
#include "crypto/rw13.h"
#include "crypto/susm9.h"
#include "crypto/lusm9.h"
#include "crypto/sm9.h"
#include "crypto/shi19.h"
#include "crypto/ji21.h"
#include <chrono>
#include <iostream>
#include <curve/params.h>

using namespace crypto;

FILE *out = NULL; const bool out_file = true, visiable = false;
int turns = 0, turns_setup = 1, turns_keygen = 1, turns_enc = 1, turns_dec = 1, n = -1, rev_G1G2;
std::chrono::_V2::system_clock::time_point ts, te;
// std::vector<std::string> attrs = {"A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L"}; std::string policy = "(A and B and C) and (D or E or F) and (G and H and (I or J or K or L))";
std::vector<std::string> attrs = {"A", "B", "C", "D", "E", "F", "G", "H", "I"}; std::string policy = "A and B or C and D and E and F or G and H and I";
// std::vector<std::string> attrs = {"A", "B", "C", "D"}; std::string policy = "(A or B) and (C or D)";
CurveParams curve;

void w11_test(std::string &param) {
    fprintf(out, "w11:\n");
    double total_duration = 0;
    for (int _ = 0; _ < turns_setup; _++) {
        ts = std::chrono::high_resolution_clock::now(); crypto::w11 test(param, attrs); te = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(te - ts).count(); total_duration += duration;
    }
    fprintf(out, " setup time: %lf ms.\n", total_duration / turns_setup); total_duration = 0;
    crypto::w11 scheme(param, attrs); crypto::w11::attribute_set A; A.attrs = attrs; crypto::w11::secretkey sk;
    for (int _ = 0; _ < turns_keygen; _++) {
        ts = std::chrono::high_resolution_clock::now(); scheme.Keygen(&A, &sk); te = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(te - ts).count(); total_duration += duration;
    }
    fprintf(out, "keygen time: %lf ms.\n", total_duration / turns_keygen); total_duration = 0;
    crypto::w11::plaintext ptx; scheme.RandomEncaps(&ptx); crypto::w11::ciphertext ctx;
    for (int _ = 0; _ < turns_enc; _++) {
        ts = std::chrono::high_resolution_clock::now(); scheme.Encrypt(ptx, policy, &ctx); te = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(te - ts).count(); total_duration += duration;
    }
    fprintf(out, "   enc: %lf ms.\n", total_duration / turns_enc); total_duration = 0;
    crypto::w11::plaintext res;
    for (int _ = 0; _ < turns_dec; _++) {
        ts = std::chrono::high_resolution_clock::now(); scheme.Decrypt(&ctx, &A, &sk, &res); te = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(te - ts).count(); total_duration += duration;
    }
    fprintf(out, "   dec time: %lf ms.\n", total_duration / turns_dec);
}

void susm9_test(std::string &param) {
    fprintf(out, "susm9:\n");
    double total_duration = 0;
    for (int _ = 0; _ < turns_setup; _++) {
        ts = std::chrono::high_resolution_clock::now(); crypto::susm9 test(param, attrs); te = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(te - ts).count(); total_duration += duration;
    }
    fprintf(out, " setup time: %lf ms.\n", total_duration / turns_setup); total_duration = 0;
    crypto::susm9 scheme(param, attrs); crypto::susm9::attribute_set A; A.attrs = attrs; crypto::susm9::secretkey sk;
    for (int _ = 0; _ < turns_keygen; _++) {
        ts = std::chrono::high_resolution_clock::now(); scheme.Keygen(&A, &sk); te = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(te - ts).count(); total_duration += duration;
    }
    fprintf(out, "keygen time: %lf ms.\n", total_duration / turns_keygen); total_duration = 0;
    crypto::susm9::plaintext ptx; scheme.RandomEncaps(&ptx); crypto::susm9::ciphertext ctx;
    for (int _ = 0; _ < turns_enc; _++) {
        ts = std::chrono::high_resolution_clock::now(); scheme.Encrypt(ptx, policy, &ctx); te = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(te - ts).count(); total_duration += duration;
    }
    fprintf(out, "   enc: %lf ms.\n", total_duration / turns_enc); total_duration = 0;
    crypto::susm9::plaintext res;
    for (int _ = 0; _ < turns_dec; _++) {
        ts = std::chrono::high_resolution_clock::now(); scheme.Decrypt(&ctx, &A, &sk, &res); te = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(te - ts).count(); total_duration += duration;
    }
    fprintf(out, "   dec time: %lf ms.\n", total_duration / turns_dec);
}

void shi19_test(std::string &param) {
    fprintf(out, "shi19:\n");
    // std::vector<std::vector<std::string>> access_structure = {
    //     {"A", "B", "C"}
    // };
    double total_duration = 0;
    for (int _ = 0; _ < turns_setup; _++) {
        ts = std::chrono::high_resolution_clock::now(); crypto::shi19 test(param, attrs); te = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(te - ts).count(); total_duration += duration;
    }
    fprintf(out, " setup time: %lf ms.\n", total_duration / turns_setup); total_duration = 0;
    crypto::shi19 scheme(param, attrs); crypto::shi19::secretkey sk;
    for (int _ = 0; _ < turns_keygen; _++) {
        ts = std::chrono::high_resolution_clock::now(); scheme.shi19Keygen(attrs, &sk); te = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(te - ts).count(); total_duration += duration;
    }
    fprintf(out, "keygen time: %lf ms.\n", total_duration / turns_keygen); total_duration = 0;
    crypto::shi19::plaintext ptx; scheme.RandomEncaps(&ptx); crypto::shi19::abe_ciphertext ctx;
    for (int _ = 0; _ < turns_enc; _++) {
        ts = std::chrono::high_resolution_clock::now(); scheme.shi19Encrypt(ptx, policy, &ctx); te = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(te - ts).count(); total_duration += duration;
    }
    fprintf(out, "   enc: %lf ms.\n", total_duration / turns_enc); total_duration = 0;
    crypto::shi19::plaintext res;
    for (int _ = 0; _ < turns_dec; _++) {
        ts = std::chrono::high_resolution_clock::now(); scheme.shi19Decrypt(&ctx, attrs, &sk, &res); te = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(te - ts).count(); total_duration += duration;
    }
    fprintf(out, "   dec time: %lf ms.\n", total_duration / turns_dec);
}

void rw13_test(std::string &param) {
    fprintf(out, "rw13:\n");
    double total_duration = 0;
    for (int _ = 0; _ < turns_setup; _++) {
        ts = std::chrono::high_resolution_clock::now(); crypto::rw13 test(param); te = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(te - ts).count(); total_duration += duration;
    }
    fprintf(out, " setup time: %lf ms.\n", total_duration / turns_setup); total_duration = 0;
    crypto::rw13 scheme(param); crypto::rw13::attribute_set A; A.attrs = attrs; crypto::rw13::secretkey sk;
    for (int _ = 0; _ < turns_keygen; _++) {
        ts = std::chrono::high_resolution_clock::now(); scheme.Keygen(&A, &sk); te = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(te - ts).count(); total_duration += duration;
    }
    fprintf(out, "keygen time: %lf ms.\n", total_duration / turns_keygen); total_duration = 0;
    crypto::rw13::plaintext ptx; scheme.RandomEncaps(&ptx); crypto::rw13::ciphertext ctx;
    for (int _ = 0; _ < turns_enc; _++) {
        ts = std::chrono::high_resolution_clock::now(); scheme.Encrypt(ptx, policy, &ctx); te = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(te - ts).count(); total_duration += duration;
    }
    fprintf(out, "   enc: %lf ms.\n", total_duration / turns_enc); total_duration = 0;
    crypto::rw13::plaintext res;
    for (int _ = 0; _ < turns_dec; _++) {
        ts = std::chrono::high_resolution_clock::now(); scheme.Decrypt(&ctx, &A, &sk, &res); te = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(te - ts).count(); total_duration += duration;
    }
    fprintf(out, "   dec time: %lf ms.\n", total_duration / turns_dec);
}

void lusm9_test(std::string &param) {
    fprintf(out, "lusm9:\n");
    double total_duration = 0;
    for (int _ = 0; _ < turns_setup; _++) {
        ts = std::chrono::high_resolution_clock::now(); crypto::lusm9 test(param); te = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(te - ts).count(); total_duration += duration;
    }
    fprintf(out, " setup time: %lf ms.\n", total_duration / turns_setup); total_duration = 0;
    crypto::lusm9 scheme(param); crypto::lusm9::attribute_set A; A.attrs = attrs; crypto::lusm9::secretkey sk;
    for (int _ = 0; _ < turns_keygen; _++) {
        ts = std::chrono::high_resolution_clock::now(); scheme.Keygen(&A, &sk); te = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(te - ts).count(); total_duration += duration;
    }
    fprintf(out, "keygen time: %lf ms.\n", total_duration / turns_keygen); total_duration = 0;
    crypto::lusm9::plaintext ptx; scheme.RandomEncaps(&ptx); crypto::lusm9::ciphertext ctx;
    for (int _ = 0; _ < turns_enc; _++) {
        ts = std::chrono::high_resolution_clock::now(); scheme.Encrypt(ptx, policy, &ctx); te = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(te - ts).count(); total_duration += duration;
    }
    fprintf(out, "   enc: %lf ms.\n", total_duration / turns_enc); total_duration = 0;
    crypto::lusm9::plaintext res;
    for (int _ = 0; _ < turns_dec; _++) {
        ts = std::chrono::high_resolution_clock::now(); scheme.Decrypt(&ctx, &A, &sk, &res); te = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(te - ts).count(); total_duration += duration;
    }
    fprintf(out, "   dec time: %lf ms.\n", total_duration / turns_dec);
}

void ji21_test(std::string &param) {
    fprintf(out, "ji21:\n");
    double total_duration = 0;
    for (int _ = 0; _ < turns_setup; _++) {
        ts = std::chrono::high_resolution_clock::now(); crypto::ji21 test(param); te = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(te - ts).count(); total_duration += duration;
    }
    fprintf(out, " setup time: %lf ms.\n", total_duration / turns_setup); total_duration = 0;
    crypto::ji21 scheme(param);
    for (int _ = 0; _ < turns_keygen; _++) {
        ts = std::chrono::high_resolution_clock::now(); ji21::ji21Prv* prv = scheme.ji21_keygen(attrs); te = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(te - ts).count(); total_duration += duration;
    }
    ji21::ji21Prv* prv = scheme.ji21_keygen(attrs);
    fprintf(out, "keygen time: %lf ms.\n", total_duration / turns_keygen); total_duration = 0;
    crypto::ji21::plaintext ptx; scheme.RandomEncaps(&ptx);
    for (int _ = 0; _ < turns_enc; _++) {
        ts = std::chrono::high_resolution_clock::now(); ji21::ji21Cph* cph = scheme.ji21_enc(policy, &ptx); te = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(te - ts).count(); total_duration += duration;
    }
    ji21::ji21Cph* cph = scheme.ji21_enc(policy, &ptx);
    fprintf(out, "   enc: %lf ms.\n", total_duration / turns_enc); total_duration = 0;
    for (int _ = 0; _ < turns_dec; _++) {
        ts = std::chrono::high_resolution_clock::now(); ji21::ji21ElementBoolean* result = scheme.ji21_dec(prv, cph); te = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(te - ts).count(); total_duration += duration;
    }
    fprintf(out, "   dec time: %lf ms.\n", total_duration / turns_dec);
}

void test(std::string &param) {
    w11_test(param);
    susm9_test(param);
    rw13_test(param);
    lusm9_test(param);
    ji21_test(param);
    // shi19_test(param);
}

void test_hash(std::string &m, element_t &res) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    const char *bytes = m.data();
    SHA256_Update(&sha256, bytes, m.size());
    SHA256_Final(hash, &sha256);
    element_from_hash(res, hash, SHA256_DIGEST_LENGTH);
}
void hash_test() {
    pbc_param_t par;
    pbc_param_init_set_str(par, curve.a_param.c_str());
    pairing_t pairing;
    pairing_init_pbc_param(pairing, par);
    std::string m = "test";
    element_t eg;
    element_init_G2(eg, pairing);
    element_t er;
    element_init_Zr(er, pairing);
    
    double total_duration = 0;
    for (int _ = 0; _ < 10; _++) {
        ts = std::chrono::high_resolution_clock::now();
        test_hash(m, eg);
        te = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::nanoseconds>(te - ts).count(); total_duration += duration;
    }
    fprintf(out, "hash to group time: %lf ns.\n", total_duration / 10);

    total_duration = 0;
    for (int _ = 0; _ < 10; _++) {
        ts = std::chrono::high_resolution_clock::now();
        test_hash(m, er);
        te = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::nanoseconds>(te - ts).count(); total_duration += duration;
    }
    fprintf(out, "hahs to Zr time: %lf ns.\n", total_duration / 10);
}

int main(int argc, char *argv[]) { // curve, turn, function, if_swap
    if(argc < 4) {
        printf("usage: %s [a|sm9] {total_turns} [setup|keygen|enc|dec|all] [0|1]\n", argv[0]);
        return 0;
    }

    turns = atoi(argv[2]); rev_G1G2 = atoi(argv[4]);

    if (strcmp(argv[3], "setup") == 0) turns_setup = turns;
    else if (strcmp(argv[3], "keygen") == 0) turns_keygen = turns;
    else if (strcmp(argv[3], "enc") == 0) turns_enc = turns;
    else if (strcmp(argv[3], "dec") == 0) turns_dec = turns;
    else if (strcmp(argv[3], "all") == 0) {
        turns_setup = turns; turns_keygen = turns; turns_enc = turns; turns_dec = turns;
    } else return 0;

    out = fopen("tmp.txt", "w"); fflush(out);

    // hash_test();

    if(strcmp(argv[1], "a") == 0) test(curve.a_param);
    else if(strcmp(argv[1], "sm9") == 0) test(curve.sm9_param);

    fclose(out);
    return 0;
}