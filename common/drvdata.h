#ifndef DRV_DATA_H
#define DRV_DATA_H

//#include <Windows.h>
//#include <winioctl.h>

#define DEVICENAME L"MyDevice"
#define DEVICE_NAME L"\\Device\\" DEVICENAME
#define SYMBOLIC_LINK_NAME L"\\DosDevices\\" DEVICENAME
#define USERLINK_DEVICE_NAME L"\\\\.\\" DEVICENAME

#define IOCTL_REGISTER_ROOT CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_SETSHELLCODE_32 CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_SETSHELLCODE_64 CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)


typedef struct _Inject_Code_Data
{
	LONG64 code_data;
	ULONG code_data_len;
	ULONG entrypoint_offset;
	ULONG data_offset;
}Inject_Code_Data, *PInject_Code_Data;



#endif // !DRV_DATA_H

