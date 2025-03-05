#ifndef IMPORT_PBC
#define IMPORT_PBC
#include <pbc/pbc.h>
#endif //IMPORT_PBC

#ifndef IMPORT_VECTOR
#define IMPORT_VECTOR
#include <vector>
#endif //IMPORT_VECTOR

#ifndef IMPORT_STRING
#define IMPORT_STRING
#include <string>
#endif //IMPORT_STRING

#ifndef IMPORT_UTIL_FUNC
#define IMPORT_UTIL_FUNC
#include "utils/func.h"
#endif //IMPORT_UTIL_FUNC

#ifndef ELEMENT_LIST_H
#define ELEMENT_LIST_H

class ElementList {
    private:
    std::vector<element_t *> data;
    int offset = 0;

    public:
    ElementList();

    explicit ElementList(int n, int offset, element_t &type, bool randomit, bool random01);

    explicit ElementList(ElementList *target, int offset);

    explicit ElementList(ElementList *target, int totlen, int offset, bool randomit);

    void resize(int n);

    void SetOffset(int offset);

    void random();

    int GetOffset();

    int len();

    int ByteSize();

    void add(element_t &x);

    void remove_front();

    bool operator!=(const ElementList &b);

    element_t * operator[](int i);

    element_t *At(int i);

    std::string hash();
    
    std::string toString(std::string lenname, std::string name);

    ~ElementList();
};

#endif //ELEMENT_LIST_H