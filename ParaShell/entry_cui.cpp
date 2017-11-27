#include <iostream>
#include <Windows.h>
#include "pediy.h"
#include "error.h"

int wmain(int argc, TCHAR* argv[])
{
	if (argc <= 1)
	{
		return -1;
	}

#ifdef _DEBUG
	TCHAR path[MAX_PATH];
	TCHAR path_bak[MAX_PATH];
	lstrcpy(path, argv[1]);
	lstrcpy(path_bak, argv[1]);
	lstrcat(path_bak, TEXT(".bak"));
	DeleteFile(path);
	MoveFile(path_bak, path);
#endif 

	if (ERR_SUCCESS == IsPEFile(argv[1]))
	{		
		ProtTheFile(argv[1]);
	}
	else
	{
		return -1;
	}

#ifdef _DEBUG
	WinExec("C:\\Users\\win10_rmtdbg\\Desktop\\rmtdbg\\test_exe.exe", SW_NORMAL);
#endif 

	return 0;
}