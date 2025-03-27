#include "crypto/w11.h"
#include "crypto/rw13.h"
#include "crypto/susm9.h"
#include "crypto/lusm9.h"
#include "crypto/sm9.h"
#include "crypto/shi19.h"
#include "crypto/ji21.h"
#include <gtest/gtest.h>
#include <vector>
#include <iostream>

#include <curve/params.h>

using namespace crypto;

int turns = 0, turns_setup = 1, turns_keygen = 1, turns_enc = 1, turns_dec = 1, n = -1, rev_G1G2;

int main(int argc, char *argv[]) { // curve, turn, function, if_swap
    if(argc < 4) {
        printf("usage: %s [a|sm9] {total_turns} [setup|keygen|enc|dec|all] [0|1]\n", argv[0]);
        return 0;
    }

    turns = atoi(argv[2]);
    rev_G1G2 = atoi(argv[4]);

    if (strcmp(argv[3], "setup") == 0) turns_setup = turns;
    else if (strcmp(argv[3], "keygen") == 0) turns_keygen = turns;
    else if (strcmp(argv[3], "enc") == 0) turns_enc = turns;
    else if (strcmp(argv[3], "dec") == 0) turns_dec = turns;
    else if (strcmp(argv[3], "all") == 0) {
        turns_setup = turns;
        turns_keygen = turns;
        turns_enc = turns;
        turns_dec = turns;
    } else return 0;

    
}