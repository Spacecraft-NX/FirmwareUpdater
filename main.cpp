#include <Windows.h>
#include <stdio.h>
#include <string>
#include <tchar.h>
#include <string.h>
#include <Setupapi.h>
#include "DFU.h"

void GetComPort(TCHAR* pszComePort, uint16_t vid, uint16_t pid)
{
    HDEVINFO DeviceInfoSet;
    SP_DEVINFO_DATA DeviceInfoData;
    const char *DevEnum = "USB";
    TCHAR ExpectedDeviceId[80] = { 0 }; //Store hardware id
    BYTE szBuffer[1024] = { 0 };
    DEVPROPTYPE ulPropertyType;
    DWORD dwSize = 0;
    DWORD Error = 0;
    //create device hardware id
    snprintf(ExpectedDeviceId, sizeof(ExpectedDeviceId), "\\??\\USB#VID_%04X&PID_%04X", vid, pid);
    //SetupDiGetClassDevs returns a handle to a device information set
    DeviceInfoSet = SetupDiGetClassDevs(NULL, DevEnum, NULL, DIGCF_ALLCLASSES | DIGCF_PRESENT);
    if (DeviceInfoSet == INVALID_HANDLE_VALUE)
        return;

    ZeroMemory(&DeviceInfoData, sizeof(SP_DEVINFO_DATA));
    DeviceInfoData.cbSize = sizeof(SP_DEVINFO_DATA);

    for (DWORD DeviceIndex = 0; SetupDiEnumDeviceInfo(DeviceInfoSet, DeviceIndex, &DeviceInfoData); DeviceIndex++)
    {
        if (SetupDiGetDeviceRegistryProperty(DeviceInfoSet, &DeviceInfoData, SPDRP_HARDWAREID, &ulPropertyType, (BYTE*)szBuffer, sizeof(szBuffer), &dwSize))
        {
            HKEY hDeviceRegistryKey = SetupDiOpenDevRegKey(DeviceInfoSet, &DeviceInfoData, DICS_FLAG_GLOBAL, 0, DIREG_DEV, KEY_READ);
            if (hDeviceRegistryKey == INVALID_HANDLE_VALUE)
            {
                Error = GetLastError();
                break; //Not able to open registry
            }

            char pszSymbolicName[2048];
            DWORD dwSize2 = sizeof(pszSymbolicName);
            DWORD dwType2 = 0;
            if ((RegQueryValueEx(hDeviceRegistryKey, "SymbolicName", NULL, &dwType2, (LPBYTE)pszSymbolicName, &dwSize2) == ERROR_SUCCESS) && (dwType2 == REG_SZ))
            {
                if (_tcsnicmp(pszSymbolicName, ExpectedDeviceId, strlen(ExpectedDeviceId)) == 0)
                {
                    char pszPortName[2048];
                    DWORD dwSize3 = sizeof(pszPortName);
                    DWORD dwType3 = 0;
                    if ((RegQueryValueEx(hDeviceRegistryKey, "PortName", NULL, &dwType3, (LPBYTE)pszPortName, &dwSize3) == ERROR_SUCCESS) && (dwType3 == REG_SZ))
                    {
                        // Check if it really is a com port
                        if (_tcsnicmp(pszPortName, _T("COM"), 3) == 0)
                        {
                            int nPortNr = _ttoi(pszPortName + 3);
                            if (nPortNr != 0)
                            {
                                _tcscpy_s(pszComePort, sizeof(pszPortName), pszPortName);
                            }
                        }
                    }
                }
            }

            RegCloseKey(hDeviceRegistryKey);
        }
    }
    if (DeviceInfoSet)
    {
        SetupDiDestroyDeviceInfoList(DeviceInfoSet);
    }
}

int main(int argc, char** argv)
{
    if (argc != 2)
    {
        printf("Usage: %s <firmware.bin>", argv[0]);
        return -1;
    }

    TCHAR sc[2048] = { 0 };
    GetComPort(sc, 0x600D, 0xC0DE);

    if (strlen(sc) == 0)
    {
        printf("Spacecraft-NX DFU not found!\n");
        return -1;
    }

    DFU dfu(sc);

    if (!dfu.ping())
    {
        printf("Failed to flash the update!\n");
        return -1;
    }

    printf("Flashing update.");

    if (!dfu.set_offset(0x3000))
    {
        printf("Failed to flash the update!\n");
        return -1;
    }

    FILE* f = fopen(argv[1], "rb");
    if (!f)
    {
        printf("Failed to open %s!\n", argv[1]);
        return -1;
    }

    uint8_t buffer[64];
    while (fread(buffer, 1, 64, f) > 0)
    {
        printf(".");
        if (!dfu.send_data(buffer))
        {
            printf("Failed to flash the update!\n");
            return -1;
        }
    }
    printf("\n");

    fclose(f);

    return 0;
}
