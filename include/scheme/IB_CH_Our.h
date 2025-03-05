#ifndef IMPORT_ELEMENTLIST
#define IMPORT_ELEMENTLIST
#include "base/ElementList.h"
#endif //IMPORT_ELEMENTLIST

#ifndef IMPORT_UTIL_FUNC
#define IMPORT_UTIL_FUNC
#include "utils/func.h"
#endif //IMPORT_UTIL_FUNC

#ifndef IB_CH_OURS_H
#define IB_CH_OURS_H

class Our_IB_CH {
    protected:
    element_t *G1, *G2, *Zn, *GT, tmp_G1, tmp_G2, tmp_Zn, tmp_Zn_2, tmp_GT, tmp_GT_2, _g_1, _g_2, g_1, g_2, egg, eg2g, msk_1, msk_2;
    int rev_G1G2;

    void base_hash(element_t *h, element_t *m, element_t *ID, element_t *r_1, element_t *r_2);

    public:
    Our_IB_CH(element_t *_G1, element_t *_G2, element_t *_Zn, element_t *_GT, int _rev_G1G2);

    int public_key_size() {
        if(this->rev_G1G2 < 0) return CountSize(this->_g_1) + CountSize(this->g_1) + CountSize(this->g_2) + CountSize(this->egg) + CountSize(this->eg2g);
        return CountSize(this->_g_1) + CountSize(this->_g_2) + CountSize(this->g_1) + CountSize(this->g_2) + CountSize(this->egg) + CountSize(this->eg2g);
    }

    void Setup();

    void Keygen(element_t *ID, element_t *td_1, element_t *td_2);

    void Hash(element_t *h, element_t *m, element_t *ID, element_t *r_1, element_t *r_2);

    void Collision(element_t *td_1, element_t *td_2, element_t *m, element_t *m_p, element_t *r_1, element_t *r_2, element_t *r_1_p, element_t *r_2_p);

    bool Verify(element_t *h, element_t *m, element_t *ID, element_t *r_1, element_t *r_2);

    ~Our_IB_CH();
};

class Our_IB_CH_KEF: public Our_IB_CH {
    protected:
    element_t h_2, u_2, td_1b, td_2b, td_3b, tmp_G2_2, tmp_G1_2;
    int rev_G1G2;

    void base_hash(element_t *h, element_t *m, element_t *ID, element_t *L, element_t *r_1, element_t *r_2, element_t *r_3);

    void get_ab_ID(element_t *ID, element_t *res, element_t *a, element_t *b);

    public:
    Our_IB_CH_KEF(element_t *_G1, element_t *_G2, element_t *_Zn, element_t *_GT, int _rev_G1G2);

    int public_key_size() {
        return Our_IB_CH::public_key_size() + CountSize(this->h_2) + CountSize(this->u_2);
    }

    void Setup();

    void Hash(element_t *h, element_t *m, element_t *ID, element_t *L, element_t *r_1, element_t *r_2, element_t *r_3);

    void Collision(element_t *ID, element_t *td_1, element_t *td_2, element_t *L, element_t *m, element_t *m_p, element_t *r_1, element_t *r_2, element_t *r_3, element_t *r_1_p, element_t *r_2_p, element_t *r_3_p);

    bool Verify(element_t *h, element_t *m, element_t *ID, element_t *L, element_t *r_1, element_t *r_2, element_t *r_3);

    ~Our_IB_CH_KEF();
};

#endif //IB_CH_OURS_H