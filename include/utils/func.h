#ifndef IMPORT_PBC
#define IMPORT_PBC
#include <pbc/pbc.h>
#endif //IMPORT_PBC

#ifndef IMPORT_STRING
#define IMPORT_STRING
#include <string>
#endif //IMPORT_STRING

#ifndef UTIL_FUNC_H
#define UTIL_FUNC_H
void Hm(element_t &m, element_t &res, element_t &tmp_Zp, element_t &g);

void Hgsm(element_t &gs, element_t &m, element_t &res, element_t &tmp_Zp, element_t &g);

int CountSize(element_t &t);
#endif //UTIL_FUNC_H