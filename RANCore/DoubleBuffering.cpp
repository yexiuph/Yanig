#include "pch.h"
#include "DoubleBuffering.h"
#include <cassert>
#include <exception>

#ifdef _DEBUG
#define new DEBUG_NEW
#endif

using namespace std;

CDoubleBuffering::CDoubleBuffering(ifstream& in, char* pcBuff, int iSize, int iDataLen)
	: m_rin(in),
	m_iDataLen(iDataLen),
	m_bEOF(false),
	m_iSize(iSize),
	m_iSize2(iSize >> 1),
	m_pcBuff(pcBuff),
	m_iEnd(0),
	m_iCurPos(0),
	m_iBuf(0)
{
	// m_iSize should be even
	if (m_iSize % 2 != 0)
		throw runtime_error("CDoubleBuffering: m_iSize should be Even Number!");

	// Check file
	if (!in.is_open() || in.bad())
		throw runtime_error("CDoubleBuffering: Referenced File not Opened or in Bad State!");

	// Check construction data
	if (m_iDataLen < 1 || m_iSize2 < m_iDataLen)
		throw runtime_error("CDoubleBuffering: Illegal Construction Data!");

	m_rin.read(m_pcBuff, m_iSize2);
	m_iEnd = static_cast<int>(m_rin.gcount());
}


int CDoubleBuffering::GetData(char* pszDataBuf, int iDataLen)
{
    if (-1 == iDataLen)
        iDataLen = m_iDataLen;

    if (iDataLen < 1 || m_iSize2 < iDataLen)
        throw runtime_error("CDoubleBuffering::GetData(): Illegal iDataLen!");

    if (m_bEOF)
        return 0;

    int iCurPos = m_iCurPos + iDataLen;

    if (m_iBuf == 0) // First Buffer
    {
        if (iCurPos >= m_iEnd)
        {
            if (m_rin.eof())
            {
                m_bEOF = true;
                int iRead = m_iEnd - m_iCurPos;
                memcpy(pszDataBuf, m_pcBuff + m_iCurPos, iRead);
                return iRead;
            }
            else
            {
                m_rin.read(m_pcBuff + m_iEnd, m_iSize2);
                m_iEnd += static_cast<int>(m_rin.gcount());

                if (iCurPos > m_iEnd)
                {
                    assert(m_rin.eof());
                    m_bEOF = true;
                    int iRead = m_iEnd - m_iCurPos;
                    memcpy(pszDataBuf, m_pcBuff + m_iCurPos, iRead);
                    return iRead;
                }
                else
                {
                    memcpy(pszDataBuf, m_pcBuff + m_iCurPos, iDataLen);
                    m_iCurPos = iCurPos;
                    m_iBuf = 1;
                    return iDataLen;
                }
            }
        }
        else
        {
            memcpy(pszDataBuf, m_pcBuff + m_iCurPos, iDataLen);
            m_iCurPos = iCurPos;
            return iDataLen;
        }
    }
    else // Second Buffer
    {
        if (iCurPos >= m_iEnd)
        {
            if (m_rin.eof())
            {
                m_bEOF = true;
                int iRead = m_iEnd - m_iCurPos;
                memcpy(pszDataBuf, m_pcBuff + m_iCurPos, iRead);
                return iRead;
            }
            else
            {
                m_rin.read(m_pcBuff, m_iSize2);
                m_iEnd = static_cast<int>(m_rin.gcount());
                iCurPos %= m_iSize;

                if (iCurPos > m_iEnd)
                {
                    assert(m_rin.eof());
                    m_bEOF = true;
                    int iRead = m_iSize - m_iCurPos;
                    memcpy(pszDataBuf, m_pcBuff + m_iCurPos, iRead);
                    memcpy(pszDataBuf + iRead, m_pcBuff, m_iEnd);
                    return iRead + m_iEnd;
                }
                else
                {
                    int iRead = m_iSize - m_iCurPos;
                    memcpy(pszDataBuf, m_pcBuff + m_iCurPos, iRead);
                    memcpy(pszDataBuf + iRead, m_pcBuff, iDataLen - iRead);
                    m_iCurPos = iCurPos;
                    m_iBuf = 0;
                    return iDataLen;
                }
            }
        }
        else
        {
            memcpy(pszDataBuf, m_pcBuff + m_iCurPos, iDataLen);
            m_iCurPos = iCurPos;
            return iDataLen;
        }
    }
}


