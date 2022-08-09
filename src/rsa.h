#pragma once

#include <string>

class BigInt;

class RSA
{
public:
	RSA();
	~RSA();

	//设置指数e
	void set_public_exp(const std::string& hex);

	//设置模数n
	void set_modulus(const std::string& hex);

	//设置私钥d
	void set_private_exp(const std::string& hex);

	//解密 需要 e 跟n 才能解密 输入c密文 返回m明文
	std::string decode(const std::string& c_hex);

	//加密 需要d 跟 n 才能加密 输入m明文 返回 c密文
	std::string encode(const std::string& m_hex);


	//输入指定内容 生成签名
	std::string get_sign(const std::string& context);

	//输入内容 跟签名 比较是否一致
	bool check_sign(const std::string& context, const std::string& sign);


private:
	//public exponent
	BigInt* m_e;

	//modulus 
	BigInt* m_n;

	//private exponent
	BigInt* m_d;

};