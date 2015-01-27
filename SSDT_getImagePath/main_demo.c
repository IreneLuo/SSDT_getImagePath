#include <Ntifs.h>
#include <ntddk.h>
#include <WinDef.h> //PBYTE
#include <tchar.h>
#include <string.h>
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
#define IOCTL_IMAGEPATH CTL_CODE(SIOCTL_TYPE, 0X800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define PIPEBUFSIZE 512
#define MAX_SYSTEM_SERVICE_NUMBER 1024
#define MILLISECOND 10000 //100ns = 100 * 10^-6 = 10000 ms
#define RELATIVE_MILLISECOND (-MILLISECOND)

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
ULONG ORIGINAL_SSDT_ENTRY[MAX_SYSTEM_SERVICE_NUMBER];

typedef struct _WAIT_PIPE_PARAM
{
	__int64 liTimeOutvalue;
	ULONG   ulPipeNameLen;
	USHORT  bUsTimeoutValue;
}WAIT_PIPE_PARAM, *PWAIT_PIPE_PARAM;

void getStatusMessage(NTSTATUS ntstatus){
	switch (ntstatus)
	{
	case STATUS_INVALID_HANDLE:
		DbgPrint("invalid handle: %x\n", ntstatus);
		break;
	case STATUS_INSTANCE_NOT_AVAILABLE:
		DbgPrint("instance not available: %x\n", ntstatus);
		break;
	case STATUS_PIPE_NOT_AVAILABLE:
		DbgPrint("pipe not available: %x\n", ntstatus);
		break;
	case STATUS_INVALID_PIPE_STATE:
		DbgPrint("invalid pipe state: %x\n", ntstatus);
		break;
	case STATUS_PIPE_BUSY:
		DbgPrint("pipe busy: %x\n", ntstatus);
		break;
	case STATUS_ILLEGAL_FUNCTION:
		DbgPrint("illegal function: %x\n", ntstatus);
		break;
	case STATUS_PIPE_DISCONNECTED:
		DbgPrint("pipe disconnected: %x\n", ntstatus);
		break;
	case STATUS_PIPE_CLOSING:
		DbgPrint("pipe closing: %x\n", ntstatus);
		break;
	case STATUS_PIPE_LISTENING:
		DbgPrint("pipe listening: %x\n", ntstatus);
		break;
	case STATUS_INVALID_READ_MODE:
		DbgPrint("invalid read mode: %x\n", ntstatus);
		break;
	case STATUS_PIPE_EMPTY:
		DbgPrint("pipe empty: %x\n", ntstatus);
		break;
	case STATUS_CANNOT_IMPERSONATE:
		DbgPrint("cannot impersonate: %x\n", ntstatus);
		break;
	case STATUS_PIPE_BROKEN:
		DbgPrint("pipe broken: %x\n", ntstatus);
		break;
	case STATUS_OBJECTID_NOT_FOUND:
		DbgPrint("object not found: %x\n", ntstatus);
		break;
	default:
		DbgPrint("other error %x\n", ntstatus);
		break;

	}
	return;
}

NTSTATUS __stdcall ZwSetNamedPipeState(HANDLE hPipe, DWORD32 dwMode)
{
	NTSTATUS NtStatus = STATUS_UNSUCCESSFUL;
	ULONG    aBuf[2] = { 0 };
	IO_STATUS_BLOCK IoStatus = { 0 };
	FILE_PIPE_INFORMATION  pipeinfo;

	pipeinfo.ReadMode = dwMode; //Data is read from the pipe as a stream of messages
	pipeinfo.CompletionMode = FILE_PIPE_COMPLETE_OPERATION;//Non-blocking mode

	NtStatus = ZwSetInformationFile(hPipe, &IoStatus, &pipeinfo, sizeof(FILE_PIPE_INFORMATION), FilePipeInformation);
	return NtStatus;
}

NTSTATUS __stdcall ZwWaitNamedPipe(LARGE_INTEGER liTimeOut)
{
	NTSTATUS NtStatus = STATUS_UNSUCCESSFUL;
	IO_STATUS_BLOCK IoStatus = { 0 };
	HANDLE hParent = NULL;
	OBJECT_ATTRIBUTES Oa = { 0 };
	WCHAR  aTmpBuf[512] = { 0 };
	PWAIT_PIPE_PARAM pWaitPipeParam = (PWAIT_PIPE_PARAM)aTmpBuf;
	INT   iShortNameOffset = wcslen(L"\\\\.\\pipe\\")*sizeof(WCHAR);
	UNICODE_STRING uniPipeParentName = { 0 };
	UNICODE_STRING us_Pipename ;

	RtlInitUnicodeString(&us_Pipename, L"\\??\\pipe\\mynamedpipe");

	do
	{
		if (us_Pipename.Length < iShortNameOffset)
		{
			NtStatus = STATUS_OBJECT_NAME_NOT_FOUND;

			break;
		}
		RtlInitUnicodeString(&uniPipeParentName, L"\\DosDevices\\pipe\\");
		InitializeObjectAttributes(&Oa, &uniPipeParentName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
		NtStatus = ZwOpenFile(&hParent, 0x100080, &Oa, &IoStatus, FILE_SHARE_WRITE | FILE_SHARE_READ, 32);
		if (!NT_SUCCESS(NtStatus))
		{
			break;
		}

		pWaitPipeParam->liTimeOutvalue = liTimeOut.QuadPart;
		pWaitPipeParam->bUsTimeoutValue = TRUE;
		*((USHORT*)(&pWaitPipeParam->ulPipeNameLen)) = us_Pipename.Length - iShortNameOffset;
		//RtlCopyMemory((PVOID)((ULONG_PTR)pWaitPipeParam + sizeof(WAIT_PIPE_PARAM)), &puniPipeName->Buffer[iShortNameOffset / sizeof(WCHAR)], pWaitPipeParam->ulPipeNameLen);
		RtlCopyMemory((PVOID)((ULONG_PTR)pWaitPipeParam + sizeof(WAIT_PIPE_PARAM)), &us_Pipename.Buffer[iShortNameOffset / sizeof(WCHAR)], pWaitPipeParam->ulPipeNameLen);
		NtStatus = ZwFsControlFile(hParent, NULL, NULL, NULL, &IoStatus, FSCTL_PIPE_WAIT, &pWaitPipeParam, 14 + pWaitPipeParam->ulPipeNameLen, NULL, 0);

	} while (FALSE);

	if (hParent)
	{
		ZwClose(hParent);
	}
	return NtStatus;
}

int PipeConnection(HANDLE *hPipe){

	UNICODE_STRING us_Pipename;
	IO_STATUS_BLOCK ioStatusBlock = { 0 };
	OBJECT_ATTRIBUTES objAttr;
	NTSTATUS ntstatus;
	int result = 1;
	LARGE_INTEGER waitNamedPipeTime = {3000};	

	//DbgPrint("---Pipe connection \n", &hPipe, hPipe);
	// Try to open a named pipe; wait for it, if necessary.
	//init objectAttributes  
	RtlInitUnicodeString(&us_Pipename, L"\\??\\pipe\\mynamedpipe");
	InitializeObjectAttributes(&objAttr, &us_Pipename, OBJ_CASE_INSENSITIVE, NULL, NULL);
	//DbgPrint("hPipe %x (%x)\n", &hPipe, hPipe);
	while (1){

		ntstatus = ZwCreateFile(hPipe, SYNCHRONIZE | FILE_WRITE_DATA|FILE_READ_DATA, &objAttr, &ioStatusBlock, NULL, 0, 0,
			FILE_OPEN, FILE_NON_DIRECTORY_FILE, NULL, 0);

		//DbgPrint("ZwCreateFile hPipe %x (%x) %x\n", &hPipe, hPipe,*hPipe);

		if (!NT_SUCCESS(ntstatus)){
			//ntstatus = ioStatusBlock.Status;
			//DbgPrint("ZwCreateFile fail: %x\n", ntstatus);
			//getStatusMessage(ntstatus);
			result = 0;
		}

		if (ntstatus != STATUS_INVALID_HANDLE && NT_SUCCESS(ntstatus))
			break;
		/*
		if (!ZwWaitNamedPipe(&us_Pipename, waitNamedPipeTime)){
			DbgPrint("could not open pipe \n");
			result = 0;
		}*/
	}
	return result;
}
NTSTATUS SendImagePathFromPipe(UNICODE_STRING usImagePath, HANDLE hPipe){
	
	TCHAR  chBuf[PIPEBUFSIZE];
	DWORD32  cbRead, cbToWrite, cbWritten, dwMode;
	NTSTATUS ntstatus;
	IO_STATUS_BLOCK ioStatusBlock = { 0 };
	OBJECT_ATTRIBUTES objAttr;
	UNICODE_STRING us_Pipename;
	BOOL fSuccess;
	INT i = 1;
	DbgPrint("----SetImagePathFromPipe----\n");
	/*
	dwMode = FILE_PIPE_MESSAGE_MODE;
	ntstatus = ZwSetNamedPipeState(hPipe, dwMode);
	if (!NT_SUCCESS(ntstatus)){
		DbgPrint("SetNamedPipeState Error: %x\n", ntstatus);
		return ntstatus;
	}*/

	/*
	RtlInitUnicodeString(&us_Pipename, L"\\??\\pipe\\mynamedpipe");
	InitializeObjectAttributes(&objAttr, &us_Pipename, OBJ_CASE_INSENSITIVE, NULL, NULL);*/
	//set message length
	cbToWrite = usImagePath.Length + 1;
	DbgPrint("Send %d byte message: %ws \n", cbToWrite, usImagePath.Buffer);
	while (i)
	{
		//send message to the pipe server
		ntstatus = ZwWriteFile(hPipe, NULL, NULL, NULL, &ioStatusBlock, usImagePath.Buffer, cbToWrite, NULL, NULL);
		if (NT_SUCCESS(ntstatus))
			i = 0;
		else
		{
			DbgPrint("ZwWriteFile Error: %x --", ntstatus);
			getStatusMessage(ntstatus);
		}		
	}
	
	return ntstatus;
}
INT ReceiveOrderFromPipe(HANDLE hPipe, UNICODE_STRING usImagePath){
	NTSTATUS ntstatus = 0x0;
	NTSTATUS prev = 0x1;
	INT result = 0;
	TCHAR pBuffer[PIPEBUFSIZE] ;
	IO_STATUS_BLOCK ioStatusBlock = { 0 };
	int i = 1;
	DbgPrint("-----ReceiveOrderFromPipe----\n");
	while (i)
	{
		ntstatus = ZwReadFile(hPipe, NULL, NULL, NULL, &ioStatusBlock, &result, sizeof(INT), NULL, NULL);
		//ntstatus = ZwReadFile(hPipe, NULL, NULL, NULL, &ioStatusBlock, pBuffer, PIPEBUFSIZE * sizeof(TCHAR), NULL, NULL);
		if (NT_SUCCESS(ntstatus))
			i = 0;
	
		else {
			//DbgPrint("ZwReadFile Error: %x\n", ntstatus);
			//DbgPrint("iostatusblock: %x\n", ioStatusBlock.Status);
			if (ntstatus != prev)
			{
				getStatusMessage(ntstatus);
				if (ntstatus == STATUS_PIPE_DISCONNECTED)
				{
					result = ntstatus;
					i = 0;
				}
			}//end of if (ntstatus != prev)				
		}//end of else		
		prev = ntstatus;
	}
	return result;
}
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
NTSTATUS MyFunction(PHANDLE ProcessHandle, PHANDLE ThreadHandle, PVOID Parameter2, PVOID Parameter3, PVOID ProcessSecurityDescriptor,
	PVOID ThreadSecurityDescriptor, PVOID Parameter6, PVOID Parameter7, PRTL_USER_PROCESS_PARAMETERS ProcessParameters, PVOID Parameter9, PVOID pProcessUnKnow)
{

	NTSTATUS ntstatus;
	//PBYTE buffer;
	UNICODE_STRING usProcessName = {0};
	ANSI_STRING asProcessName = {0};
	USHORT length;
	HANDLE hPipe = NULL;
	UINT buffersize = 100;
	UINT result = 0;
	TCHAR *receiveBuf;
	DWORD dwMode;
	LARGE_INTEGER startSystemTime, startLocalTime;
	LARGE_INTEGER endSystemTime, endLocalTime;
	TIME_FIELDS startTimeInfo, endTimeInfo;

	LARGE_INTEGER waitNamedpipeTime;
	INT msecsToWait = 5000;
	waitNamedpipeTime.HighPart = 0;
	waitNamedpipeTime.LowPart = RELATIVE_MILLISECOND;
	waitNamedpipeTime.LowPart *= msecsToWait;

	CHAR test[] = "C:\\Windows\\System32\\notepad.exe";
	CHAR test2[] = "C:\\Users\\WDKRemoteUser.ACC-PC\\Desktop\\teraterm-4.82.exe";
	CHAR test3[] = "C:\\Users\\WDKRemoteUser.ACC-PC\\Desktop\\eicar.com";	
	CHAR test4[] = "C:\\Windows\\system32\\SearchProtocolHost.exe";
	CHAR test5[] = "C:\\Users\\WDKRemoteUser.ACC-PC\\Desktop\\test";
	/* calling new instructions */
	//DbgPrint("-----MyFunction-----\n");

	/* allocate memory to usProcessName, and copy Irp ImagePathName buffer into it */
	usProcessName.Buffer = (PWSTR)ExAllocatePool(PagedPool, &(ProcessParameters->ImagePathName.Length));
	usProcessName.MaximumLength = &(ProcessParameters->ImagePathName.MaximumLength);
	RtlCopyUnicodeString(&usProcessName, &(ProcessParameters->ImagePathName));	 
	//DbgPrint(" length: %d ,usProcessName(ws): %ws  \n",usProcessName.Length, usProcessName.Buffer);
	
	//convert usProcessName to asProcessName (Unicode string to Ansi string)
	asProcessName.Buffer = (PCHAR)ExAllocatePool(PagedPool, buffersize);
	asProcessName.MaximumLength = buffersize;
	ntstatus = RtlUnicodeStringToAnsiString(&asProcessName, &usProcessName, TRUE);

	if (NT_SUCCESS(ntstatus)){
		//DbgPrint("length:%d asProcessName(s): %s\n", asProcessName.Length, asProcessName.Buffer);
	}
	else{
		DbgPrint("convert unsuccessfully\n");
	}

	 /*test */
	if ( strncmp(asProcessName.Buffer, test5, strlen(test5)) != 0 )
	{		
		//if (strcmp(asProcessName.Buffer, test3) != 0)
			goto run;
	}
	
	
	KeQuerySystemTime(&startSystemTime);
	ExSystemTimeToLocalTime(&startSystemTime, &startLocalTime);
	RtlTimeToTimeFields(&startLocalTime, &startTimeInfo);

	do //status >=0 , then break
	{
		//connect to ImageHandler and get a handle
		result = PipeConnection(&hPipe);
	
		if (!result){
			DbgPrint("pipe connection failed\n");
		}

		//ntstatus = ZwWaitNamedPipe();

		//set namedpipe state
		dwMode = FILE_PIPE_MESSAGE_MODE;
		ntstatus = ZwSetNamedPipeState(hPipe, dwMode);
		if (!NT_SUCCESS(ntstatus)){
			DbgPrint("SetNamedPipeState Error: %x\n", ntstatus);	
		}
	
		// Using namedpipe to send ImagePath to ImageHandler
		ntstatus = SendImagePathFromPipe(usProcessName, hPipe);

		if (!NT_SUCCESS(ntstatus)){
			DbgPrint("SendImagePathFromPipe Error: %x! \n",ntstatus);
		}
		//DbgPrint("Handle of pipe %x : %x\n", &hPipe, hPipe);

		//Using namedpipe to receive order from ImageHandler
		result = ReceiveOrderFromPipe(hPipe, usProcessName);
		if (result != STATUS_PIPE_DISCONNECTED)//filter output record
			DbgPrint("ReceiveOrderFrom Pipe: %d\n", result);

		if (result == STATUS_PIPE_DISCONNECTED)
		{
			ZwClose(hPipe);
			KeDelayExecutionThread(KernelMode, 0, &waitNamedpipeTime);
		}
	} while (result == STATUS_PIPE_DISCONNECTED);
	

	KeQuerySystemTime(&endSystemTime);
	ExSystemTimeToLocalTime(&endSystemTime, &endLocalTime);
	RtlTimeToTimeFields(&endLocalTime, &endTimeInfo);
	//DbgPrint("Time: %d (s)",(((endTimeInfo.Minute - startTimeInfo.Minute) * 60 )+(endTimeInfo.Second - startTimeInfo.Second)));
	/*
	DbgPrint("Time: %d", (endTimeInfo.Hour - startTimeInfo.Hour) * 60 * 1000 * 1000 +
		(endTimeInfo.Minute - startTimeInfo.Minute) * 60 * 1000 +
		(endTimeInfo.Second - startTimeInfo.Second) * 1000 +
		(endTimeInfo.Milliseconds - startTimeInfo.Milliseconds));
	*/
	//receiveBuf = ReceiveOrderFromPipe(hPipe);
	//DbgPrint("ReceiveOrderFrom Pipe: %ws\n", receiveBuf);
	if (result != 1)
	{
		ntstatus = STATUS_DOWNGRADE_DETECTED; //STATUS_DOWNGRADE_DETECTED STATUS_ACCESS_DENIED
		goto refuse_run;
	}
	

run:
	/* calling old function */
	ntstatus = oldZwCreateUserProcess(ProcessHandle, ThreadHandle,
		Parameter2, Parameter3, ProcessSecurityDescriptor,
		ThreadSecurityDescriptor, Parameter6, Parameter7,
		ProcessParameters, Parameter9, pProcessUnKnow);

	if (NT_SUCCESS(ntstatus)){ 
		//if (strcmp(asProcessName.Buffer, test2) == 0 || strcmp(asProcessName.Buffer, test3) == 0)
			DbgPrint("Safe!! ( %s ) \n", asProcessName.Buffer);
	}
	goto end;
	
refuse_run:
	DbgPrint("Access Denied!! ( %s )\n", asProcessName.Buffer);
end:
	ZwClose(hPipe);
	ExFreePool(asProcessName.Buffer);
	ExFreePool(usProcessName.Buffer);
	return ntstatus;

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

	//pDriverObject->DriverUnload = DriverUnload;
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
	CHAR *OutputBuffer = NULL;
	DbgPrint("-----MyDriver_IRP_MJ_CONTROL-----\n");
	pIOStackLocation = IoGetCurrentIrpStackLocation(Irp);
	switch (pIOStackLocation->Parameters.DeviceIoControl.IoControlCode)
	{
	case IOCTL_GETADDRESS:
		DbgPrint("Irp->AssociatedIrp.SystemBuffer: %x at (%x)\n", Irp->AssociatedIrp.SystemBuffer, &Irp->AssociatedIrp.SystemBuffer);
		DbgPrint("pBuf: %x at (%x) %x \n", pBuf, &pBuf, *pBuf);

		oldZwCreateUserProcess = (ZwCreateUserProcessPrototype)*pBuf;
		DbgPrint("api: %x at (%x)\n", oldZwCreateUserProcess, &oldZwCreateUserProcess);

		StoreOriginalSSDT();
		oldZwCreateUserProcess = (ZwCreateUserProcessPrototype)HookSSDT((PULONG)oldZwCreateUserProcess, (PULONG)MyFunction);
		if (oldZwCreateUserProcess)
			DbgPrint("SSDT hook success!!!\n");
		
		
		RtlZeroMemory(pBuf, pIOStackLocation->Parameters.DeviceIoControl.InputBufferLength);
		RtlCopyMemory(pBuf, strToUser, strlen(strToUser));

		break;
	
	case IOCTL_IMAGEPATH:
		/*OutputBuffer = (CHAR*)Irp->AssociatedIrp.SystemBuffer;
		if (check_ssdt){
			//memset(OutputBuffer, &PROCESSNAME, sizeof(PROCESSNAME));
			memset(OutputBuffer, '\0', pIOStackLocation->Parameters.DeviceIoControl.InputBufferLength);
			if (sizeof(pIMAGENAME)){
				//RtlCopyMemory(OutputBuffer, pImagepath, sizeof(pImagepath));
			}
			else{
				DbgPrint("outputbuffer error\n");
			}
		}
		else{
			CHAR* str = "ssdt not ready";
			RtlCopyMemory(OutputBuffer, str, sizeof(str));
		}*/
		
		
		break;
	}
	

	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = strlen(strToUser);
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	
	return NtStatus;
}