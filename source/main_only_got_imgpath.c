#include <ntddk.h>
#include <WinDef.h> //PBYTE
#include <tchar.h>

/* Function Prototypes */
VOID MyDriver_Unload(PDRIVER_OBJECT DriverObject);
NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegistryPath);
NTSTATUS MyDriver_IRP_MJ_CREATE(PDEVICE_OBJECT DeviceObject, PIRP Irp);
NTSTATUS MyDriver_IRP_MJ_CLOSE(PDEVICE_OBJECT DeviceObject, PIRP Irp);
NTSTATUS MyDriver_IRP_MJ_DEVICE_CONTROL(PDEVICE_OBJECT DeviceObject, PIRP Irp);

/* Global declaration */
const WCHAR DeviceName[] = L"\\Device\\SSDT_getImagePath";
//const WCHAR SymLink[] = L"\\DosDevices\\HelloWorld";
const WCHAR SymLink[] = L"\\??\\SSDT_getImagePath";

/* IOCTL declaration */
#define SIOCTL_TYPE 40000
#define IOCTL_GETADDRESS CTL_CODE(SIOCTL_TYPE, 0X800, METHOD_BUFFERED, FILE_READ_DATA|FILE_WRITE_DATA)
#define MAX_SYSTEM_SERVICE_NUMBER 1024
/* Compile directives */
#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(PAGE, MyDriver_Unload)
#pragma alloc_text(PAGE, MyDriver_IRP_MJ_CREATE)
#pragma alloc_text(PAGE, MyDriver_IRP_MJ_CLOSE)
#pragma alloc_text(PAGE, MyDriver_IRP_MJ_DEVICE_CONTROL)

/* The structure of the System Service Table */
typedef struct SystemServiceTable{
	UINT32*	ServiceTable;
	UINT32* CounterTable;
	UINT32* ServiceLimit;
	UINT32* ArgumentTable;
}SST;

/* The structure of the RTL_USER_PROCESS_PARAMETERS*/
typedef struct _RTL_USER_PROCESS_PARAMETERS
{
UCHAR		Reserved1[16];
PVOID		Reserved2[10];
UNICODE_STRING	ImagePathName;
UNICODE_STRING	CommandLine;
} RTL_USER_PROCESS_PARAMETERS, *PRTL_USER_PROCESS_PARAMETERS;

/* Declaration of KeServiceDescriptorTable, which is exported by ntoskrnl.exe*/
__declspec(dllimport) SST KeServiceDescriptorTable;

/*NTSYSAPI NTSTATUS NTAPI ZwCreateUserProcess(
PHANDLE ProcessHandle,
PHANDLE ThreadHandle,
PVOID Parameter2,
PVOID Parameter3,
PVOID ProcessSecurityDescriptor,
PVOID ThreadSecurityDescriptor,
PVOID Parameter6,
PVOID Parameter7,
PRTL_USER_PROCESS_PARAMETERS ProcessParameters,
PVOID Parameter9,
PVOID pProcessUnKnow
);*/

/* Define ZwcreateUserProcessPrototype function pointer*/
typedef NTSTATUS (__stdcall *ZwCreateUserProcessPrototype)(
PHANDLE ProcessHandle,
PHANDLE ThreadHandle,
PVOID Parameter2,
PVOID Parameter3,
PVOID ProcessSecurityDescriptor,
PVOID ThreadSecurityDescriptor,
PVOID Parameter6,
PVOID Parameter7,
PRTL_USER_PROCESS_PARAMETERS ProcessParameters,
PVOID Parameter9,
PVOID pProcessUnKnow
);

/* global variable is used as a placeholder for saving the old address from SSDT */
ZwCreateUserProcessPrototype oldZwCreateUserProcess = NULL;
//ZwCreateUserProcessPrototype mZwCreateUserProcess=NULL;

ULONG ORIGINAL_SSDT_ENTRY[MAX_SYSTEM_SERVICE_NUMBER];

/* Disable the WriteProtect bit in CR0 register */
void DisableWP(){
	__asm{
		push edx;
		mov edx, cr0;
		and edx, 0xFFFEFFFF;
		mov cr0, edx;
		pop edx;
	}
}

/* Enable the WriteProtect bit in CR0 register */
void EnableWP(){
	__asm{
		push edx;
		mov edx, cr0;
		or edx, 0x00010000;
		mov cr0, edx;
		pop edx;
	}
}

VOID StoreOriginalSSDT(){
	
	PLONG ssdt;
	int i;

	DbgPrint("-----Store Original SSDT-----\n");

	ssdt = KeServiceDescriptorTable.ServiceTable;
	for (i = 0; i < KeServiceDescriptorTable.ServiceLimit; i++){
		ORIGINAL_SSDT_ENTRY[i] = ssdt[i];
	}
	return;
}

VOID RestoreSSDT(){
	PLONG ssdt;
	int i;

	DbgPrint("-----Restore Original SSDT-----\n");

	ssdt = KeServiceDescriptorTable.ServiceTable;
	for (i = 0; i < KeServiceDescriptorTable.ServiceLimit; i++){
		ssdt[i] = ORIGINAL_SSDT_ENTRY[i];
	}
	return;
}

PULONG HookSSDT(PUCHAR syscall, PUCHAR hookaddr){
	UINT32 index;
	PLONG ssdt;
	PLONG target;
	//PULONG ret;
	PULONG oldaddress;
	DbgPrint("-----Hook!!-----\n");
	DisableWP();
	ssdt = KeServiceDescriptorTable.ServiceTable;
	DbgPrint("The syscall address is %x\n", syscall);
	DbgPrint("The hook function address is %x\n", hookaddr);
	
	/* identify syscall index into the SSDT table*/
	// *() means to dereference to get the content at that addr
	index = *((PUCHAR)syscall+0x1);

	/* get the address of the service routine in SSDT*/
	target = (PLONG)&ssdt[index];
	DbgPrint("Before hooking: ssdt[%d] at %x is %x\n", index, target, ssdt[index]);
	oldaddress = (PVOID)InterlockedExchange(&ssdt[index], hookaddr);
	DbgPrint("After hooking: ssdt[%d] at %x is %x\n", index, target, ssdt[index]);

	return oldaddress;
}

/* hook function Hook_ZwCreateUserProcess*/
NTSTATUS MyFunction(PHANDLE ProcessHandle, PHANDLE ThreadHandle,
	PVOID Parameter2, PVOID Parameter3, PVOID ProcessSecurityDescriptor,
	PVOID ThreadSecurityDescriptor, PVOID Parameter6, PVOID Parameter7,
	PRTL_USER_PROCESS_PARAMETERS ProcessParameters, PVOID Parameter9, PVOID pProcessUnKnow)
{

	NTSTATUS ntstatus;
	PBYTE buffer;
	UNICODE_STRING usProcessName;
	PBYTE pProcessName;
	USHORT length;
	/* calling new instructions */
	DbgPrint("-----MyFunction-----\n");
	//GetProcessName(ProcessParameters->ImagePathName.Buffer, usProcessName);
	RtlInitUnicodeString(&usProcessName, ProcessParameters->ImagePathName.Buffer);
	
	length = ProcessParameters->ImagePathName.Length;
	pProcessName = &usProcessName;

	//DbgPrint(" Imagepath is %S \n", usProcessName);
	DbgPrint(" Imagepath is %wZ \n", *(pProcessName));
	DbgPrint(" length is %u \n", length);
	DbgPrint(" Imagepath is %wZ \n", usProcessName);

	/* calling old function */
	ntstatus = oldZwCreateUserProcess(ProcessHandle, ThreadHandle,
		Parameter2, Parameter3, ProcessSecurityDescriptor,
		ThreadSecurityDescriptor, Parameter6, Parameter7,
		ProcessParameters, Parameter9, pProcessUnKnow);
	
	// if(!NT_SUCCESS(status))
	/*if (ntstatus == STATUS_INFO_LENGTH_MISMATCH) {


		DbgPrint("Error:length mismatch! Allocate new buffer! ");
		PBYTE buffer = ExAllocatePoolWithTag(PagedPool, ReturnLength, 'Tag1');
		if (buffer == NULL){
		DbgPrint(" Allocate Error\n");
		status = STATUS_INSUFFICIENT_RESOURCES;
		return status;
		}
		status = oldZwQuerySystemInformation(SystemInformationClass, (PVOID)buffer, ReturnLength, NULL);
		if (status == STATUS_SUCCESS)
		{
		DbgPrint("--call origin api again and success! \n");
		}
	}*/
	if (NT_SUCCESS(ntstatus)){
		DbgPrint("call origin api success! \n");
	}
	return ntstatus;
}

VOID DriverUnload(PDRIVER_OBJECT DriverObject)
{
	UNICODE_STRING usDosDeviceName;
	DbgPrint("-----Driver unload-----\n");
	/* restore the hook */
	// let syscall addr in SSDT point to original syscall addr
	if (oldZwCreateUserProcess != NULL){
		RestoreSSDT();
		DbgPrint(" The original SSDT function restored\n");
	}

	
	RtlInitUnicodeString(&usDosDeviceName, SymLink);
	IoDeleteSymbolicLink(&usDosDeviceName);
	IoDeleteDevice(DriverObject->DeviceObject);
}

NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegistryPath){

	NTSTATUS ntStatus = STATUS_SUCCESS;
	unsigned int uiIndex = 0;
	PDEVICE_OBJECT pDeviceObject = NULL;
	UNICODE_STRING usDriverName, usDosDeviceName;

	DbgPrint("-----DriverEntry-----\n");

	// initialize driver name and device name
	RtlInitUnicodeString(&usDriverName, DeviceName);
	RtlInitUnicodeString(&usDosDeviceName, SymLink);

	// create a new device object(type is FILE_DEVICE_UNKNOWN, can only be used by a application)
	ntStatus = IoCreateDevice(pDriverObject, 0, &usDriverName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &pDeviceObject);

	// create the symbolic link
	ntStatus = IoCreateSymbolicLink(&usDosDeviceName, &usDriverName);
	if (ntStatus < 0){
		DbgPrint("Create Symbolic link error: %x\n", ntStatus);
	}
	pDriverObject->DriverUnload = DriverUnload;
	pDeviceObject->Flags |= DO_BUFFERED_IO;
	pDeviceObject->Flags &= (~DO_DEVICE_INITIALIZING);
	/* MajorFunction: is a list of function pointers for entry points into the driver */
	pDriverObject->MajorFunction[IRP_MJ_CREATE] = MyDriver_IRP_MJ_CREATE;
	pDriverObject->MajorFunction[IRP_MJ_CLOSE] = MyDriver_IRP_MJ_CLOSE;
	pDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = MyDriver_IRP_MJ_DEVICE_CONTROL;

	/*for (uiIndex = 0; uiIndex < IRP_MJ_MAXIMUM_FUNCTION; uiIndex++){

	}*/
	
	
	return STATUS_SUCCESS;
}

NTSTATUS MyDriver_IRP_MJ_CREATE(PDEVICE_OBJECT DeviceObject, PIRP Irp){
	NTSTATUS NtStatus = STATUS_SUCCESS;
	DbgPrint("-----MyDriver_IRP_MJ_CREATE-----\n");
	return NtStatus;
}

NTSTATUS MyDriver_IRP_MJ_CLOSE(PDEVICE_OBJECT DeviceObject, PIRP Irp){
	NTSTATUS NtStatus = STATUS_SUCCESS;
	DbgPrint("-----MyDriver_IRP_MJ_CLOSE-----\n");
	return NtStatus;
}

NTSTATUS MyDriver_IRP_MJ_DEVICE_CONTROL(PDEVICE_OBJECT DeviceObject, PIRP Irp){
	
	NTSTATUS NtStatus = STATUS_SUCCESS;
	PIO_STACK_LOCATION pIOStackLocation;
	PCHAR strToUser = "Good job!";
	PULONG pBuf = Irp->AssociatedIrp.SystemBuffer;
	PULONG ret_HookSSDT;
	DbgPrint("-----MyDriver_IRP_MJ_CONTROL-----\n");
	pIOStackLocation = IoGetCurrentIrpStackLocation(Irp);
	switch (pIOStackLocation->Parameters.DeviceIoControl.IoControlCode)
	{
	case IOCTL_GETADDRESS:
		DbgPrint("Irp->AssociatedIrp.SystemBuffer: %x at (%x)\n", Irp->AssociatedIrp.SystemBuffer, &Irp->AssociatedIrp.SystemBuffer);
		DbgPrint("pBuf: %x at (%x) %x \n", pBuf, &pBuf, *pBuf);
		oldZwCreateUserProcess = (ZwCreateUserProcessPrototype)*pBuf;
		DbgPrint("api: %x at (%x)\n", oldZwCreateUserProcess, &oldZwCreateUserProcess);
		RtlZeroMemory(pBuf, pIOStackLocation->Parameters.DeviceIoControl.InputBufferLength);
		RtlCopyMemory(pBuf, strToUser, strlen(strToUser));
		break;
	}

	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = strlen(strToUser);
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	
	StoreOriginalSSDT();
	oldZwCreateUserProcess = (ZwCreateUserProcessPrototype)HookSSDT((PULONG)oldZwCreateUserProcess, (PULONG)MyFunction);
	if (oldZwCreateUserProcess)
		DbgPrint("SSDT hook success!!!\n");

	return NtStatus;
}