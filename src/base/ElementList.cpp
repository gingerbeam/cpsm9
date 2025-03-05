#include "base/ElementList.h"

ElementList::ElementList() {
    this->resize(0);
}

ElementList::ElementList(int n, int offset, element_t &type, bool randomit, bool random01) {
    this->SetOffset(offset);
    this->resize(n);
    mpz_t mpz_tmp, mpz_2;
    mpz_init(mpz_tmp);
    mpz_init(mpz_2);
    mpz_set_str(mpz_2, "2", 10);
    for(int i = this->offset + 1;i <= n;i++) {
        element_init_same_as(*this->At(i), type);
        if(randomit) {
            element_random(*this->At(i));
            if(random01) {
                element_to_mpz(mpz_tmp, *this->At(i));
                mpz_mod(mpz_tmp, mpz_tmp, mpz_2);
                if(mpz_is0(mpz_tmp)) element_set0(*this->At(i));
                else element_set1(*this->At(i));
            }
        } else element_set0(*this->At(i));
    }
    mpz_clear(mpz_tmp);
    mpz_clear(mpz_2);
}

ElementList::ElementList(ElementList *target, int offset) {
    this->SetOffset(offset);
    this->resize(target->len());
    for(int i = this->offset + 1;i <= target->len();i++) {
        element_init_same_as(*this->At(i), *target->At(i));
        element_set(*this->At(i), *target->At(i));
    }
}

ElementList::ElementList(ElementList *target, int totlen, int offset, bool randomit) {
    this->SetOffset(offset);
    this->resize(totlen);
    for(int i = this->offset + 1;i <= totlen;i++) {
        if(i < target->data.size()) {
            element_init_same_as(*this->At(i), *target->At(i));
            element_set(*this->At(i), *target->At(i));
        } else {
            element_init_same_as(*this->At(i), *this->At(i - 1));
            if(randomit) element_random(*this->At(i));
            else element_set0(*this->At(i));
        }
    }
}

void ElementList::resize(int n) {
    int old_len = this->data.size();
    this->data.resize(n - this->offset);
    for(int i = old_len;i < this->data.size();i++) {
        this->data[i] = (element_t *)(new element_t);
        if(old_len > 0) element_init_same_as(*this->data[i], *this->data[i - 1]);
    }
}

void ElementList::SetOffset(int offset) {
    this->offset = offset;
};

void ElementList::random() {
    for(int i = this->offset + 1;i <= this->len();i++) element_random(*this->At(i));
}

int ElementList::GetOffset() {
    return this->offset;
};

int ElementList::len() {
    return this->offset + this->data.size();
};

int ElementList::ByteSize() {
    int tmp = 0;
    for(int i = 0;i < this->data.size();i++) tmp += CountSize(*this->data[i]);
    return tmp;
}

void ElementList::add(element_t &x) {
    this->resize(this->len() + 1);
    element_init_same_as(*this->data[this->data.size() - 1], x);
    element_set(*this->data[this->data.size() - 1], x);
}

void ElementList::remove_front() {
    this->data.erase(this->data.begin());
}

bool ElementList::operator!=(const ElementList &b) {
    if(this->data.size() != b.data.size() || this->data.size() * b.data.size() == 0) return true;
    for(int i = 0;i < this->data.size();i++) if(element_cmp(*this->data[i], *b.data[i])) return true;
    return false;
}

element_t *ElementList::At(int i) {
    return this->data[i - 1 - this->offset];
}

element_t *ElementList::operator[](int i) {
    return this->At(i - 1 - this->offset);
}
    
std::string ElementList::hash() {
    int buflen = 1024;
    char buf[buflen];
    std::string res = "", tmp;
    for(int i = 0;i < this->data.size();i++) {
        element_snprint(buf, buflen, *this->data[i]);
        tmp = buf;
        res += tmp;
    }
    return res;
};

std::string ElementList::toString(std::string lenname = "列表长度", std::string name = "ElementList") {
    int buflen = 1024;
    char buf[buflen];
    std::string res = name + " (len = " + lenname + " = " + std::to_string(this->data.size()) + ")\n", tmp;
    for(int i = 0;i < this->data.size();i++) {
        res += std::to_string(i + 1 + this->offset) + ": ";
        element_snprint(buf, buflen, *this->data[i]);
        tmp = buf;
        res += tmp + "\n";
    }
    return res;
}

ElementList::~ElementList() {
    for(int i = 0;i < this->data.size();i++) element_clear(*this->data[i]);
};