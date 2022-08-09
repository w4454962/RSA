#include "rsa.h"
#include "bigint.h"
#include "hex.h"

#define RELEASE(ptr) if (ptr) { delete ptr; ptr = nullptr;}
RSA::RSA()
	: m_e(nullptr),
	m_n(nullptr),
	m_d(nullptr)
{ }

RSA::~RSA()
{
	RELEASE(m_e);
	RELEASE(m_n);
	RELEASE(m_d);

}

void RSA::set_public_exp(const std::string& hex)
{
	if (!m_e) 
		m_e = new BigInt(hex, 16);
	else
		m_e->fromHex(hex);
}

void RSA::set_modulus(const std::string& hex)
{
	if (!m_n)
		m_n = new BigInt(hex, 16);
	else
		m_n->fromHex(hex);
}

void RSA::set_private_exp(const std::string& hex)
{
	if (!m_d)
		m_d = new BigInt(hex, 16);
	else
		m_d->fromHex(hex);
;
}


std::string RSA::decode(const std::string& c_hex)
{
	if (!m_e || !m_n)
		return std::string();

	BigInt c(c_hex, 16);

	BigInt m = c.powm(*m_e, *m_n);

	return m.getString(16);
}


std::string RSA::encode(const std::string& m_hex)
{
	if (!m_e || !m_d)
		return std::string();

	BigInt m(m_hex, 16);

	BigInt c = m.powm(*m_d, *m_n);

	return c.getString(16);
}


std::string RSA::get_sign(const std::string& context)
{
	return encode(Sha1(context));
}


bool RSA::check_sign(const std::string& context, const std::string& sign)
{
	return BigInt(Sha1(context), 16) == BigInt(decode(sign), 16);
}