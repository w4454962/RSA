#include <iostream>
#include "rsa.h"
#include "hex.h"

int main() {
	RSA rsa;

	//1024字节的rsa公私钥 可以加密 128字节

	//设置公钥指数 e
	rsa.set_public_exp("10001");

	//设置公钥模数 n
	rsa.set_modulus("a87441ebe810751e23ec1341315b0f3a87cb58f8e96b1ccaf03f5a6b7258c4dad563f2f533e04759a7e954c9a7e8ecd8f161a2830f5dc4e9dc66253aff85ac744940d368587307b64ba00c7b02d4df6583057126d1960591078be9a1c212bf54571f1e9a30525010ca5e93329010545966c569d6b58b38502d55d4096bf8e26d");

	//设置私钥指数 d 这个私钥只能放在安全环境里使用
	rsa.set_private_exp("53e8dd316a7e50287c524ae10d79c3632f633e6576b7f136b1678d5dba2eb7981df5547f89a0ad49de971eb1f85ed123db50fc0776af09b8481de56bb6fe5a011fdd8ef2becca9fc1d480cb3ab5249c67ac87b2bac81b668ee837dc099d6ab1a1fe32cd8cbff192fca05e18b2e4291379bb1c167ef905b43548655be732ceec1");

	//源文  
	std::string source = "hello worlds!";

	//转16进制
	std::string source_hex = BinToHex(source);
	
	//加密
	std::string password_hex = rsa.encode(source_hex);
	
	//解密 再解码16进制
	std::string decode = HexToBin(rsa.decode(password_hex));
	
	printf("源文[%s]\n", source.c_str());
	
	printf("密文[%s]\n", password_hex.c_str());
	
	printf("解密文[%s]\n", decode.c_str());


	//根据源文 生成签名
	std::string sign = rsa.get_sign(source);
	
	//验证签名 是否跟 源文一致
	if (rsa.check_sign(source, sign)) {
		printf("签名验证成功\n");
	} else {
		printf("签名验证失败\n");
	}

	system("pause");

	return 0;
}