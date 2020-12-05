#ifndef __SERIAL_H__
#define __SERIAL_H__

#include <Windows.h>
#include <string>
#include <stdio.h>

class Serial
{
private:
	HANDLE m_hPort = INVALID_HANDLE_VALUE;
	std::string m_sPort;

public:
	Serial(std::string port);
	virtual ~Serial();

	std::string port() { return m_sPort; }

	bool read(void *data, DWORD datasize);

	bool write(const void *data, DWORD datasize);
};

#endif