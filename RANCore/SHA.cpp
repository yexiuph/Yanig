#include "pch.h"
#include "SHA.h"

#include <exception>
#include <fstream>
//#include <strstream>

#ifdef _DEBUG
#define new DEBUG_NEW
#endif

using namespace std;

const unsigned int CSHA::sm_K256[64] =
{
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

const unsigned int CSHA::sm_H256[8] =
{
	0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
	0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
};

//CONSTRUCTOR
CSHA::CSHA()
	: m_auiBits{ 0, 0 }
{
	for (int i = 0; i < SHA256LENGTH; i++)
		m_auiBuf[i] = sm_H256[i];
}

void CSHA::AddData(const char* pcData, int iDataLength)
{
	if (iDataLength < 1)
		throw runtime_error("FileCrypt ERROR: in CSHA::AddData(), Data Length should be > 0!");

	unsigned int uiT;
	unsigned int uiBits = m_auiBits[0] + (static_cast<unsigned int>(iDataLength) << 3);

	if (uiBits < m_auiBits[0])
		m_auiBits[1]++; // Carry from low to high
	m_auiBits[1] += (iDataLength >> 29);
	uiT = BLOCKSIZE - (m_auiBits[0] >> 3); // Bytes already

	if (iDataLength >= uiT)
	{
		memcpy(m_aucIn + uiT, pcData, uiT);
		Transform();
		pcData += uiT;
		iDataLength -= uiT;

		while (iDataLength >= BLOCKSIZE)
		{
			memcpy(m_aucIn, pcData, BLOCKSIZE);
			Transform();
			pcData += BLOCKSIZE;
			iDataLength -= BLOCKSIZE;
		}
	}

	memcpy(m_aucIn, pcData, iDataLength);
	m_bAddData = true;
}

void CSHA::FinalDigest(char* pcDigest)
{
	if (false == m_bAddData)
		throw runtime_error("FileCrypt ERROR: in CSHA::FinalDigest(), No data Added before call!");

	unsigned int uiCount = (m_auiBits[0] >> 3) & 0x3F;
	unsigned char* puc = m_aucIn + uiCount;
	*puc++ = 0x80;

	uiCount = BLOCKSIZE - uiCount - 1;

	if (uiCount < 8)
	{
		memset(puc, 0, uiCount);
		Transform();
		memset(m_aucIn, 0, BLOCKSIZE - 8);
	}
	else
	{
		memset(puc, 0, uiCount - 8);
	}

	Word2Bytes(m_auiBits[1], m_aucIn + BLOCKSIZE - 8);
	Word2Bytes(m_auiBits[0], m_aucIn + BLOCKSIZE - 4);
	Transform();

	memcpy(pcDigest, m_auiBuf, SHA256LENGTH * sizeof(unsigned int));

	Reset();
}


//Reset current operation in order to prepare a new one
void CSHA::Reset()
{
	for (int i = 0; i < SHA256LENGTH; i++)
		m_auiBuf[i] = sm_H256[i];
	m_auiBits[0] = 0;
	m_auiBits[1] = 0;
	//Reset the flag
	m_bAddData = false;
}

void CSHA::Transform()
{
	unsigned int a, b, c, d, e, f, g, h, t;
	unsigned int auiW[64];

	for (int i = 0; i < 16; i++)
		Bytes2Word(m_aucIn + (i * 4), auiW[i]);

	for (int i = 16; i < 64; i++)
		auiW[i] = sig1(auiW[i - 2]) + auiW[i - 7] + sig0(auiW[i - 15]) + auiW[i - 16];

	a = m_auiBuf[0];
	b = m_auiBuf[1];
	c = m_auiBuf[2];
	d = m_auiBuf[3];
	e = m_auiBuf[4];
	f = m_auiBuf[5];
	g = m_auiBuf[6];
	h = m_auiBuf[7];

	for (int i = 0; i < 64; i++)
	{
		t = h + SIG1(e) + CH(e, f, g) + sm_K256[i] + auiW[i];
		h = t + SIG0(a) + MAJ(a, b, c);
		d += t;

		std::swap(a, h);
		std::swap(b, g);
		std::swap(c, f);
		std::swap(d, e);

		e += t;
	}

	m_auiBuf[0] += a;
	m_auiBuf[1] += b;
	m_auiBuf[2] += c;
	m_auiBuf[3] += d;
	m_auiBuf[4] += e;
	m_auiBuf[5] += f;
	m_auiBuf[6] += g;
	m_auiBuf[7] += h;
}


