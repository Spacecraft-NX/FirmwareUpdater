#include "Serial.h"

Serial::Serial(std::string port) :
	m_sPort(port)
{
	m_hPort = CreateFile(("\\\\.\\" + port).c_str(), GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
	if (m_hPort == INVALID_HANDLE_VALUE)
	{
		printf("Failed to open! %i\n", GetLastError());
		return;
	}

	DCB dcb;
	if (!GetCommState(m_hPort, &dcb))
	{
		printf("Failed to get state! %i\n", GetLastError());
		return;
	}

	dcb.BaudRate = CBR_115200;
	dcb.ByteSize = 8;
	dcb.Parity = NOPARITY;
	dcb.StopBits = ONESTOPBIT;

	if (!SetCommState(m_hPort, &dcb))
	{
		printf("Failed to set state! %i\n", GetLastError());
		return;
	}

	COMMTIMEOUTS timeouts =
	{
		10 * 1000, //interval timeout. 0 = not used
		1 * 1000, // read multiplier
		10 * 1000, // read constant (milliseconds)
		1 * 1000, // Write multiplier
		10 * 1000  // Write Constant
	};

	if (!SetCommTimeouts(m_hPort, &timeouts))
	{
		printf("Failed to set timeout! %i\n", GetLastError());
		return;
	}

}

Serial::~Serial()
{
	if (m_hPort != INVALID_HANDLE_VALUE)
	{
		CloseHandle(m_hPort);
		m_hPort = INVALID_HANDLE_VALUE;
	}
}

bool Serial::read(void *data, DWORD datasize)
{
	DWORD done = 0;

	SetLastError(ERROR_SUCCESS);

	while (GetLastError() == ERROR_SUCCESS)
	{
		DWORD bytesReaded = 0;
		if (ReadFile(m_hPort, &((char *) data)[done], datasize - done, &bytesReaded, NULL) != TRUE)
		{
			printf("Failed to read! %i\n", GetLastError());
			return false;
		}
			
		done += bytesReaded;

		if (done == datasize)
			break;
	}

	return true;
}

bool Serial::write(const void *data, DWORD datasize)
{
	DWORD bytesWritten = 0;
	if (WriteFile(m_hPort, data, datasize, &bytesWritten, NULL) != TRUE || bytesWritten != datasize)
	{
		printf("Failed to write! %i\n", GetLastError());
		return false;
	}

	return true;
}