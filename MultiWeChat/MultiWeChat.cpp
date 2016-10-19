#include "stdafx.h"
#include <Windows.h>
#include <Imagehlp.h>
#include <Tlhelp32.h>

#include <string>
#include <algorithm>
#include <map>

#include <Shlwapi.h>
#include <comdef.h>
#include <wbemidl.h>
#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "Shlwapi.lib")
#pragma comment(lib , "ImageHlp.lib")

typedef LONG NTSTATUS;
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)
#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)

typedef enum _SYSTEM_INFORMATION_CLASS {
	SystemBasicInformation,              // 0        Y        N
	SystemProcessorInformation,          // 1        Y        N
	SystemPerformanceInformation,        // 2        Y        N
	SystemTimeOfDayInformation,          // 3        Y        N
	SystemNotImplemented1,               // 4        Y        N
	SystemProcessesAndThreadsInformation, // 5       Y        N
	SystemCallCounts,                    // 6        Y        N
	SystemConfigurationInformation,      // 7        Y        N
	SystemProcessorTimes,                // 8        Y        N
	SystemGlobalFlag,                    // 9        Y        Y
	SystemNotImplemented2,               // 10       Y        N
	SystemModuleInformation,             // 11       Y        N
	SystemLockInformation,               // 12       Y        N
	SystemNotImplemented3,               // 13       Y        N
	SystemNotImplemented4,               // 14       Y        N
	SystemNotImplemented5,               // 15       Y        N
	SystemHandleInformation,             // 16       Y        N
	SystemObjectInformation,             // 17       Y        N
	SystemPagefileInformation,           // 18       Y        N
	SystemInstructionEmulationCounts,    // 19       Y        N
	SystemInvalidInfoClass1,             // 20
	SystemCacheInformation,              // 21       Y        Y
	SystemPoolTagInformation,            // 22       Y        N
	SystemProcessorStatistics,           // 23       Y        N
	SystemDpcInformation,                // 24       Y        Y
	SystemNotImplemented6,               // 25       Y        N
	SystemLoadImage,                     // 26       N        Y
	SystemUnloadImage,                   // 27       N        Y
	SystemTimeAdjustment,                // 28       Y        Y
	SystemNotImplemented7,               // 29       Y        N
	SystemNotImplemented8,               // 30       Y        N
	SystemNotImplemented9,               // 31       Y        N
	SystemCrashDumpInformation,          // 32       Y        N
	SystemExceptionInformation,          // 33       Y        N
	SystemCrashDumpStateInformation,     // 34       Y        Y/N
	SystemKernelDebuggerInformation,     // 35       Y        N
	SystemContextSwitchInformation,      // 36       Y        N
	SystemRegistryQuotaInformation,      // 37       Y        Y
	SystemLoadAndCallImage,              // 38       N        Y
	SystemPrioritySeparation,            // 39       N        Y
	SystemNotImplemented10,              // 40       Y        N
	SystemNotImplemented11,              // 41       Y        N
	SystemInvalidInfoClass2,             // 42
	SystemInvalidInfoClass3,             // 43
	SystemTimeZoneInformation,           // 44       Y        N
	SystemLookasideInformation,          // 45       Y        N
	SystemSetTimeSlipEvent,              // 46       N        Y
	SystemCreateSession,                 // 47       N        Y
	SystemDeleteSession,                 // 48       N        Y
	SystemInvalidInfoClass4,             // 49
	SystemRangeStartInformation,         // 50       Y        N
	SystemVerifierInformation,           // 51       Y        Y
	SystemAddVerifier,                   // 52       N        Y
	SystemSessionProcessesInformation    // 53       Y        N
} SYSTEM_INFORMATION_CLASS;

typedef struct _CLIENT_ID
{
	HANDLE UniqueProcess;
	HANDLE UniqueThread;
}CLIENT_ID,*PCLIENT_ID;

typedef struct
{
	USHORT Length;
	USHORT MaxLen;
	USHORT *Buffer;
}UNICODE_STRING, *PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES 
{
	ULONG Length;
	HANDLE RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG Attributes;
	PVOID SecurityDescriptor;
	PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES; 

typedef struct _IO_COUNTERSEX {
	LARGE_INTEGER ReadOperationCount;
	LARGE_INTEGER WriteOperationCount;
	LARGE_INTEGER OtherOperationCount;
	LARGE_INTEGER ReadTransferCount;
	LARGE_INTEGER WriteTransferCount;
	LARGE_INTEGER OtherTransferCount;
} IO_COUNTERSEX, *PIO_COUNTERSEX;

typedef enum {
	StateInitialized,
	StateReady,
	StateRunning,
	StateStandby,
	StateTerminated,
	StateWait,
	StateTransition,
	StateUnknown
} THREAD_STATE;

typedef struct _VM_COUNTERS {
	SIZE_T PeakVirtualSize;
	SIZE_T VirtualSize;
	ULONG PageFaultCount;
	SIZE_T PeakWorkingSetSize;
	SIZE_T WorkingSetSize;
	SIZE_T QuotaPeakPagedPoolUsage;
	SIZE_T QuotaPagedPoolUsage;
	SIZE_T QuotaPeakNonPagedPoolUsage;
	SIZE_T QuotaNonPagedPoolUsage;
	SIZE_T PagefileUsage;
	SIZE_T PeakPagefileUsage;
} VM_COUNTERS;
typedef VM_COUNTERS *PVM_COUNTERS;

typedef struct _SYSTEM_THREADS {
	LARGE_INTEGER KernelTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER CreateTime;
	ULONG WaitTime;
	PVOID StartAddress;
	CLIENT_ID ClientId;
	ULONG Priority;
	ULONG BasePriority;
	ULONG ContextSwitchCount;
	THREAD_STATE State;
	ULONG WaitReason;
} SYSTEM_THREADS, *PSYSTEM_THREADS;

typedef struct _SYSTEM_PROCESSES { // Information Class 5
	ULONG NextEntryDelta;
	ULONG ThreadCount;
	ULONG Reserved1[6];
	LARGE_INTEGER CreateTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER KernelTime;
	UNICODE_STRING ProcessName;
	ULONG BasePriority;
	ULONG ProcessId;
	ULONG InheritedFromProcessId;
	ULONG HandleCount;
	ULONG Reserved2[2];
	VM_COUNTERS VmCounters;
	IO_COUNTERSEX IoCounters;  // Windows 2000 only
	SYSTEM_THREADS Threads[1];
} SYSTEM_PROCESSES, *PSYSTEM_PROCESSES;

typedef struct _SYSTEM_HANDLE_INFORMATION
{
	ULONG            ProcessId;
	UCHAR            ObjectTypeNumber;
	UCHAR            Flags;
	USHORT            Handle;
	PVOID            Object;
	ACCESS_MASK        GrantedAccess;
} SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;

typedef enum _OBJECT_INFORMATION_CLASS {
	ObjectBasicInformation,
	ObjectNameInformation,
	ObjectTypeInformation,
	ObjectAllInformation,
	ObjectDataInformation
} OBJECT_INFORMATION_CLASS;

typedef struct _OBJECT_NAME_INFORMATION {
	UNICODE_STRING Name;
} OBJECT_NAME_INFORMATION, *POBJECT_NAME_INFORMATION;

typedef NTSTATUS (NTAPI *NTQUERYOBJECT)(
										_In_opt_   HANDLE Handle,
										_In_       OBJECT_INFORMATION_CLASS ObjectInformationClass,
										_Out_opt_  PVOID ObjectInformation,
										_In_       ULONG ObjectInformationLength,
										_Out_opt_  PULONG ReturnLength
										);


typedef NTSTATUS
(NTAPI *ZWQUERYSYSTEMINFORMATION)(
								  IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
								  OUT PVOID SystemInformation,
								  IN ULONG SystemInformationLength,
								  OUT PULONG ReturnLength OPTIONAL
								  );
ZWQUERYSYSTEMINFORMATION ZwQuerySystemInformation = (ZWQUERYSYSTEMINFORMATION)GetProcAddress(GetModuleHandle(L"ntdll.dll"),"ZwQuerySystemInformation");
NTQUERYOBJECT    NtQueryObject = (NTQUERYOBJECT)GetProcAddress(GetModuleHandle(L"ntdll.dll"),"NtQueryObject");

void enable(int privilege)
{
	bool bEnable(false);
	HANDLE hToken(INVALID_HANDLE_VALUE);
	do 
	{
		if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
			break;

		TOKEN_PRIVILEGES tkp = { 0 };
		tkp.Privileges[0].Luid.LowPart = privilege;
		tkp.PrivilegeCount = 1;
		tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
		if (!AdjustTokenPrivileges(hToken, FALSE, &tkp, sizeof(TOKEN_PRIVILEGES), NULL, NULL))
			break;

		DWORD dwError = GetLastError();
		bEnable = ERROR_SUCCESS == dwError;
	} while (false);

	if (INVALID_HANDLE_VALUE != hToken)
	{
		CloseHandle(hToken);
	}
}

bool enablePriv()
{
	bool bEnable(true);
	//SeAssignPrimaryTokenPrivilege
	//enable(3);
	//SE_SHUTDOWN_PRIVILEGE
	//enable(19);
	//SeDebugPrivilege
	enable(20);
	//SeRestorePrivilege
	//enable(18);
	//SeBackupPrivilege
	//enable(17);
	//SeTakeOwnershipPrivilege
	//enable(9);

	return bEnable;
}

std::map<int, bool> g_wechatProc;
void close(wchar_t* type_, wchar_t* incluedValue)
{
	enablePriv();
	DWORD dwSize = 0;
	PSYSTEM_HANDLE_INFORMATION pmodule = NULL;
	POBJECT_NAME_INFORMATION pNameInfo;
	POBJECT_NAME_INFORMATION pNameType;
	PVOID pbuffer = NULL;
	NTSTATUS Status;
	int nIndex = 0;
	DWORD dwFlags = 0;
	wchar_t szType[128] = {0};
	wchar_t szName[512] = {0};

	do 
	{
		if(!ZwQuerySystemInformation)
		{
			break;
		}

		pbuffer = VirtualAlloc(NULL, 0x1000, MEM_COMMIT, PAGE_READWRITE);

		if(!pbuffer)
		{
			break;
		}

		Status = ZwQuerySystemInformation(SystemHandleInformation, pbuffer, 0x1000, &dwSize);

		if(!NT_SUCCESS(Status))
		{
			if (STATUS_INFO_LENGTH_MISMATCH != Status)
			{
				break;
			}
			else
			{
				// 这里大家可以保证程序的正确性使用循环分配稍好
				if (NULL != pbuffer)
				{
					VirtualFree(pbuffer, 0, MEM_RELEASE);
				}

				if (dwSize*2 > 0x4000000)  // MAXSIZE
				{
					break;
				}

				pbuffer = VirtualAlloc(NULL, dwSize*2, MEM_COMMIT, PAGE_READWRITE);

				if(!pbuffer)
				{
					break;
				}

				Status = ZwQuerySystemInformation(SystemHandleInformation, pbuffer, dwSize*2, NULL);

				if(!NT_SUCCESS(Status))
				{
					break;   
				}
			}
		}

		pmodule = (PSYSTEM_HANDLE_INFORMATION)((PULONG)pbuffer+1);
		dwSize = *((PULONG)pbuffer);

		for(nIndex = 0; nIndex < dwSize; nIndex++)
		{
			if (g_wechatProc.end() == g_wechatProc.find(pmodule[nIndex].ProcessId))
			{
				continue;
			}

			HANDLE hSource = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pmodule[nIndex].ProcessId);
			HANDLE hDst = GetCurrentProcess();
			HANDLE hDupHandle(NULL);
			do 
			{
				if (NULL == hSource
					|| NULL == hDst)
					break;

				
				if (!DuplicateHandle(hSource, (HANDLE)pmodule[nIndex].Handle, hDst, &hDupHandle, 0, FALSE, DUPLICATE_SAME_ACCESS))
					break;

				Status = NtQueryObject((HANDLE)hDupHandle, ObjectNameInformation, szName, 512, &dwFlags);
				if (!NT_SUCCESS(Status))
				{
					break;
				}

				Status = NtQueryObject((HANDLE)hDupHandle, ObjectTypeInformation, szType, 128, &dwFlags);
				if (!NT_SUCCESS(Status))
				{
					break;
				}

				pNameInfo = (POBJECT_NAME_INFORMATION)szName;
				pNameType = (POBJECT_NAME_INFORMATION)szType;
				//L"Mutant"
				if (0 == wcscmp((wchar_t *)pNameType->Name.Buffer, type_))
				{

					if (pNameInfo->Name.Buffer
						&& wcsstr((wchar_t *)pNameInfo->Name.Buffer, incluedValue))
					{
						if (hDupHandle)
							CloseHandle(hDupHandle);

						if (!DuplicateHandle(hSource, (HANDLE)pmodule[nIndex].Handle, hDst, &hDupHandle, 0, FALSE, DUPLICATE_CLOSE_SOURCE))
						{
							DWORD err = GetLastError();
							printf("%d", err);
						}
						wprintf((wchar_t *)pNameInfo->Name.Buffer);
						printf("\r\n");
					}
				}
			} while (false);
			
			if (hSource)
				CloseHandle(hSource);
			if (hDst)
				CloseHandle(hDst);

			if (hDupHandle)
				CloseHandle(hDupHandle);
		}

	} while (false);

	if (NULL != pbuffer)
	{
		VirtualFree(pbuffer, 0, MEM_RELEASE);
	}
}

void closeAlreadyRunningWechat()
{
	HANDLE hProcessSnap(NULL);
	do 
	{
		PROCESSENTRY32 pe32;
		hProcessSnap = CreateToolhelp32Snapshot( TH32CS_SNAPPROCESS, 0 );
		if( hProcessSnap == INVALID_HANDLE_VALUE )
			break;

		pe32.dwSize = sizeof( PROCESSENTRY32 );
		if( !Process32First( hProcessSnap, &pe32 ) )
			break;
		do 
		{
			std::wstring szTemp(pe32.szExeFile);
			std::transform(szTemp.begin(), szTemp.end(), szTemp.begin(), ::tolower);
			if (std::wstring::npos != szTemp.find(_T("wechat.exe")))
			{
				DWORD dwProcID = pe32.th32ProcessID;
				g_wechatProc[dwProcID] = true;
			}
		} while(Process32Next(hProcessSnap, &pe32));

	} while (FALSE);

	if (NULL != hProcessSnap)
	{
		CloseHandle(hProcessSnap);
		hProcessSnap = NULL;
	}

	if (!g_wechatProc.empty())
	{
		close(L"Mutant", L"_WeChat_App_Instance_Identity_Mutex_Name");
		g_wechatProc.clear();
	}
}

DWORD WINAPI MonitorThreadFunction( LPVOID lpParam )
{
	HRESULT hRet = S_OK;
	hRet = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
	if (FAILED(hRet))
	{
		return hRet;
	}

	IWbemLocator *pIWbemLocator = NULL;

	hRet = CoCreateInstance(CLSID_WbemLocator, NULL, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (LPVOID*)&pIWbemLocator);
	if (FAILED(hRet))
	{
		CoUninitialize();
		return hRet;
	}

	IWbemServices *pIWbemServices = NULL;

	bstr_t strNetwoekResource("ROOT\\CIMV2");

	hRet = pIWbemLocator->ConnectServer(strNetwoekResource, NULL, NULL, NULL, 0, NULL, NULL, &pIWbemServices);
	if (FAILED(hRet))
	{
		pIWbemLocator->Release();
		CoUninitialize();
		return hRet;
	}

	hRet = CoSetProxyBlanket(pIWbemServices, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL, RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE);
	if (FAILED(hRet))
	{
		pIWbemServices->Release();
		pIWbemLocator->Release();
		CoUninitialize();
		return hRet;
	}

	bstr_t strQueryLanguage("WQL");
	bstr_t strQuery("SELECT * FROM __InstanceCreationEvent WITHIN 1 WHERE TargetInstance ISA 'Win32_Process'");

	IEnumWbemClassObject *pIEnumWbemClassObject = NULL;

	hRet = pIWbemServices->ExecNotificationQuery(strQueryLanguage, strQuery, WBEM_FLAG_FORWARD_ONLY|WBEM_FLAG_RETURN_IMMEDIATELY, NULL, &pIEnumWbemClassObject);

	if (SUCCEEDED(hRet))
	{
		do 
		{
			ULONG uReturned = 0;
			IWbemClassObject *pIWbemClassObject = NULL;

			hRet = pIEnumWbemClassObject->Next(WBEM_INFINITE, 1, &pIWbemClassObject, &uReturned);

			if (SUCCEEDED(hRet) && pIWbemClassObject)
			{
				VARIANT vtInstanceObject;
				hRet = pIWbemClassObject->Get(_T("TargetInstance"), 0, &vtInstanceObject, NULL, NULL);

				if (SUCCEEDED(hRet) && vtInstanceObject.vt == VT_UNKNOWN && vtInstanceObject.punkVal != NULL)
				{
					IWbemClassObject *pTargetInstance = (IWbemClassObject*)vtInstanceObject.punkVal;

					VARIANT vtProcessID, vtExecutablePath;
					hRet = pTargetInstance->Get(_T("ProcessID"), 0, &vtProcessID, NULL, NULL);
					if (SUCCEEDED(hRet))
					{
						hRet = pTargetInstance->Get(_T("Name"), 0, &vtExecutablePath, NULL, NULL);
						if (SUCCEEDED(hRet))
						{
							wchar_t pName[MAX_PATH] = {0};
							wsprintf(pName, L"%s", vtExecutablePath.bstrVal);
							_wcsupr_s(pName, MAX_PATH);
							std::wstring strTmp(pName);
							std::transform(strTmp.begin(), strTmp.end(), strTmp.begin(), ::tolower);
							if (std::wstring::npos != strTmp.find(L"wechat.exe"))
							{
								Sleep(2000);
								g_wechatProc[vtProcessID.ulVal] = true;
								close(L"Mutant", L"_WeChat_App_Instance_Identity_Mutex_Name");
								g_wechatProc.clear();
							}
						}
					}

					vtInstanceObject.punkVal->Release();
				}
			}

		} while (TRUE);
	}
	pIWbemServices->Release();
	pIWbemLocator->Release();
	CoUninitialize();

	return 0;
}

int _tmain(int argc, _TCHAR* argv[])
{
	closeAlreadyRunningWechat();

	HANDLE hMonitor = CreateThread( 
		NULL,                   // default security attributes
		0,                      // use default stack size  
		MonitorThreadFunction,       // thread function name
		NULL,          // argument to thread function 
		0,                      // use default creation flags 
		NULL);   // returns the thread identifier 

	system("pause");
	TerminateThread(hMonitor, 0);
	return 0;
}