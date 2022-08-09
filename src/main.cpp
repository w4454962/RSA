#include <iostream>
#include "rsa.h"
#include "hex.h"

int main() {
	RSA rsa;

	//1024�ֽڵ�rsa��˽Կ ���Լ��� 128�ֽ�

	//���ù�Կָ�� e
	rsa.set_public_exp("10001");

	//���ù�Կģ�� n
	rsa.set_modulus("a87441ebe810751e23ec1341315b0f3a87cb58f8e96b1ccaf03f5a6b7258c4dad563f2f533e04759a7e954c9a7e8ecd8f161a2830f5dc4e9dc66253aff85ac744940d368587307b64ba00c7b02d4df6583057126d1960591078be9a1c212bf54571f1e9a30525010ca5e93329010545966c569d6b58b38502d55d4096bf8e26d");

	//����˽Կָ�� d ���˽Կֻ�ܷ��ڰ�ȫ������ʹ��
	rsa.set_private_exp("53e8dd316a7e50287c524ae10d79c3632f633e6576b7f136b1678d5dba2eb7981df5547f89a0ad49de971eb1f85ed123db50fc0776af09b8481de56bb6fe5a011fdd8ef2becca9fc1d480cb3ab5249c67ac87b2bac81b668ee837dc099d6ab1a1fe32cd8cbff192fca05e18b2e4291379bb1c167ef905b43548655be732ceec1");

	//Դ��  
	std::string source = "hello worlds!";

	//ת16����
	std::string source_hex = BinToHex(source);
	
	//����
	std::string password_hex = rsa.encode(source_hex);
	
	//���� �ٽ���16����
	std::string decode = HexToBin(rsa.decode(password_hex));
	
	printf("Դ��[%s]\n", source.c_str());
	
	printf("����[%s]\n", password_hex.c_str());
	
	printf("������[%s]\n", decode.c_str());


	//����Դ�� ����ǩ��
	std::string sign = rsa.get_sign(source);
	
	//��֤ǩ�� �Ƿ�� Դ��һ��
	if (rsa.check_sign(source, sign)) {
		printf("ǩ����֤�ɹ�\n");
	} else {
		printf("ǩ����֤ʧ��\n");
	}

	system("pause");

	return 0;
}