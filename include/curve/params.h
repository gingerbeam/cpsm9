#ifndef IMPORT_STRING
#define IMPORT_STRING
#include <string>
#endif //IMPORT_STRING

#ifndef WILDCARDED_SM9_INCLUDE_CURVE_PARAMS_H_
#define WILDCARDED_SM9_INCLUDE_CURVE_PARAMS_H_

class CurveParams
{
    public:
    std::string a_param; // AC
    std::string a1_param; // AC
    std::string e_param; // AC
    std::string i_param; // AC
    std::string a_param_80; // ERR in res
    std::string a_param_112; // ERR in res
    std::string a_param_128; // ERR in res
    std::string a_param_160; // ERR in res
    // 对称

    std::string sm9_param;
    std::string d159_param;
    std::string d201_param;
    std::string d224_param;
    std::string d105171_196_185_param;
    std::string d277699_175_167_param;
    std::string d278027_190_181_param;
    std::string f_param;
    std::string g149_param;
    //非对称
    
    CurveParams();
};

#endif //WILDCARDED_SM9_INCLUDE_CURVE_PARAMS_H_
