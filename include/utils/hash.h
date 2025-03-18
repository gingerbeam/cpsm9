#ifndef UTILS_HASH_H
#define UTILS_HASH_H

#include <iostream>
#include <stack>
#include <vector>
#include <unordered_map>
#include <sstream>
#include <regex>
#include <algorithm>
#include <cmath>
#include <random>

#include <pbc/pbc.h>

/* Usage
void IB_CH_S1::base_hash(element_t *H, element_t *R, element_t *ID, element_t *m) {
    if(this->rev_G1G2) element_pairing(*H, this->P, *R);
    else element_pairing(*H, *R, this->P);
    this->H1(*m, this->tmp_Zn);
    this->H0(*ID, this->tmp_G1);
    element_mul_zn(this->tmp_G1, this->tmp_G1, this->tmp_Zn);
    if(this->rev_G1G2) element_pairing(this->tmp_GT, this->P_pub, this->tmp_G1);
    else element_pairing(this->tmp_GT, this->tmp_G1, this->P_pub);
    element_mul(*H, *H, this->tmp_GT);
}

void IB_CH_S1::Hash(element_t *H, element_t *R, element_t *ID, element_t *m) {
    element_random(*R);
    this->base_hash(H, R, ID, m);
}
*/

namespace utils {
    void Hm(element_t &m, element_t &res);

    void Hgsm(element_t &gs, element_t &m, element_t &res);
    
    int CountSize(element_t &t);

}

#endif