#ifndef STRINGTRANS_H_
#define STRINGTRANS_H_

#include "BigInt.h"
#include <vector>
using namespace std;

class StringTrans : public vector<BigInt> {
    private:
        /**
         * �Դ����str���зֶΣ�ÿ��BitLen��
         *
         */
        void split(const string&);
        int BitLen;

    public:
        /**
         * ���캯��
         *
         * @param a ��Ϣԭ��
         * @param b ÿ�εĳ���
         */
        StringTrans(const string& a, int b);
        StringTrans() {};
        /**
         * �������еķ�Ƭ������ϳ�һ��string
         * 
         * @return ������ϵ�string
         */
        string toString();
        string toHexString();

        /**
         * ���ֺϲ�����
         */
        void push_back(const string&);
        void push_back(const BigInt&);
        StringTrans& operator+= (const string&);
        StringTrans& operator+= (const BigInt&);
        StringTrans& operator+= (const StringTrans&);
};

#endif
