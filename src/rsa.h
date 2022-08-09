#pragma once

#include <string>

class BigInt;

class RSA
{
public:
	RSA();
	~RSA();

	//����ָ��e
	void set_public_exp(const std::string& hex);

	//����ģ��n
	void set_modulus(const std::string& hex);

	//����˽Կd
	void set_private_exp(const std::string& hex);

	//���� ��Ҫ e ��n ���ܽ��� ����c���� ����m����
	std::string decode(const std::string& c_hex);

	//���� ��Ҫd �� n ���ܼ��� ����m���� ���� c����
	std::string encode(const std::string& m_hex);


	//����ָ������ ����ǩ��
	std::string get_sign(const std::string& context);

	//�������� ��ǩ�� �Ƚ��Ƿ�һ��
	bool check_sign(const std::string& context, const std::string& sign);


private:
	//public exponent
	BigInt* m_e;

	//modulus 
	BigInt* m_n;

	//private exponent
	BigInt* m_d;

};