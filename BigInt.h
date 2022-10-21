#ifndef BIGINT_H_
#define BIGINT_H_
#include <iostream>
#include <string>
#include <stdlib.h>
#include "globalData.h"

using namespace std;

class BigInt {
public:
    /**
     * �޲ι��캯����Ĭ��Ϊ0
     */
    BigInt();

    /**
     * ��int���Ͳ�����ʼ������
     *
     * @param [in]  input �����int��������
     */
    BigInt(const int&);

    /**
     * �������캯��
     *
     * @param [in] input ��һ������
     */
    BigInt(const BigInt&); 

    /**
     * ���캯������16�����ַ�������
     *
     * @param [in] str
     * @param [in] base ����(2, 10, 16)
     */
    BigInt(string, int);
    /**
     * ��16�����ַ�����������
     *
     * @param str 16�����ַ���
     */
    void GenFromHexString(string str);

    /**
     * ��2�����ַ�����������
     *
     * @param buf  2�����ַ���
     */
    void GenFromBinString(string buf);

    /**
     * ���ֽڴ���������
     *
     * @param buf  �ֽڴ�
     */
    void GenFromByteString(const string& buf);

    /**
     * �Ѵ���ת����10�����ַ���
     *
     * @return ����10�����ַ���
     */
    string ToString() const;

    /**
     * �Ѵ���ת����16�����ַ���
     *
     * @return ����16�����ַ���
     */
    string ToHexString() const;

    /**
     * ��ֵ������������
     * 
     * @param input ��һ������
     */
    BigInt& operator= (const BigInt&);

    /**
     * ��ֵ���������int����������ֵ
     *
     * @param a ����
     */
    BigInt& operator= (int& a) { Clear(); data[0]=a; return *this;}

    /**
     * λ���������
     *
     * @param a ����λ��
     */
    BigInt& operator>> (const int&);

    /**
     * λ���������
     *
     * @param a ����λ��
     */
    BigInt& operator<< (const int&);

    /**
     * ���ش����Ķ����Ƴ���
     *
     * @return �����Ƴ���
     */
    int GetBitLength() const;

    /**
     * ���ش����ĳ��ȣ���ռ�õ��ڲ��������鳤�ȣ�
     *
     * @return �����ĳ���
     */
    int GetLength() const;

    /**
     * �жϴ���������
     *
     * @return true������false����
     */
    bool TestSign() const {return sign;}

    /**
     * ����
     */
    void Clear();

    /**
     * �����������
     *
     * @param digNum �����Ƴ���
     */
    void Random(int digNum);

    /**
     * ����С���������������ΪdigNum��1/4��
     *
     * @param digNum �����Ƴ���
     */
    void Randomsmall(int digNum);
    
    /**
     * �жϴ�������ż��
     *
     * return true��������false��ż��
     */
    bool IsOdd() const {return (data[0]&1);}

    /* ��������� */
    BigInt operator+ (const BigInt&) const;         /* �ӷ� */
    BigInt operator- (const BigInt&) const;         /* ���� */
    BigInt operator- (const int&) const;
    BigInt operator* (const BigInt&) const;         /* �˷� */
    BigInt operator* (const unsigned int&) const;
    BigInt operator% (const BigInt&) const;         /* ȡ�� */
    int operator% (const int&) const;

    /* λ����� */
    BigInt operator/ (const BigInt&) const;         /* ���� */
    BigInt operator& (const BigInt&) const;         /* λ�� */
    BigInt operator^ (const BigInt&) const;         /* ��� */
    BigInt operator| (const BigInt&) const;         /* λ�� */
    
    /* �߼������ */
    bool operator< (const BigInt&) const;           /* С�� */
    bool operator> (const BigInt&) const;           /* ���� */
    bool operator<= (const int&) const;             /* С�ڵ��� */
    bool operator== (const BigInt&) const;          /* ���� */
    bool operator== (const int&) const;

    /**
     * �Ѵ����������
     *
     */
    friend ostream& operator<< (ostream&, const BigInt&);
    
    /**
     * ģ������ n ^ p mod m
     *
     * @param [in] n
     * @param [in] p
     * @param [in] m
     * @return n ^ p mod m ���
     */
    static BigInt PowerMode (const BigInt& n, const BigInt& p, const BigInt& m);

    /**
     * �����������Լ��
     *
     * @param [in] m
     * @param [in] n
     * @return m��n�����Լ��
     */
    static BigInt Gcd(const BigInt& m,const BigInt& n);

    /**
     * ŷ������㷨
     *
     * @param [in] E
     * @param [in] A
     * @return gcd(E, A)
     */
    static BigInt Euc(BigInt& E,BigInt& A);

    /**
     * ��չŷ������㷨����˷�ģ��
     *
     * @param [in] a
     * @param [in] b
     * @param [out] x a mod b�ĳ˷���Ԫ
     * @param [out] y b mod a�ĳ˷���Ԫ
     * @return gcd(a, b)
     */
    static BigInt ExtendedGcd(const BigInt& a, const BigInt& b, BigInt& x, BigInt& y);
private:
    static const size_t _capacity = 128 + 1;
    unsigned int data[_capacity];
    bool sign;
    /**
     * ����������������
     *
     * @param out �����
     */
    void _output(ostream& out) const;

    int _hexCharToInt(char c);
    char _intToHexChar(int c);
};

enum _STRING_TYPE {
    BIN_STRING = 2,
    HEX_STRING = 16,
    BYTE_STRING = 10
};

#endif
