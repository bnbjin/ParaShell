#include <windows.h>
#include "utilities.h"
#include "resource.h"
#include "globalvalue.h"


/*
	Description: 打开对话框函数 
*/
BOOL  OpenFileDlg(TCHAR *szFilePath, HWND hwnd)
{
	OPENFILENAME ofn;
	memset(szFilePath, 0, MAX_PATH * sizeof(TCHAR));
	memset(&ofn, 0, sizeof(ofn));

	ofn.lStructSize = sizeof(ofn);
	ofn.hwndOwner = hwnd;
	ofn.hInstance = g_hInst;
	ofn.nMaxFile = MAX_PATH;
	ofn.lpstrInitialDir = NULL;
	ofn.lpstrFile = szFilePath;
	ofn.lpstrTitle = TEXT("Open ...");
	ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_LONGNAMES | OFN_EXPLORER | OFN_HIDEREADONLY;
	ofn.lpstrFilter = TEXT("PE Files (*.exe;*.dll)\0*.EXE;*.DLL\0")\
		TEXT("All Files (*.*)\0*.*\0\0");
	if (!GetOpenFileName(&ofn))
		return FALSE;

	return TRUE;
}


/*
	Description:	在消息框中增加一行消息输出
*/
void AddLine(HWND hDlg, TCHAR *szMsg)
{
	if (GetDlgItemText(hDlg, IDC_MESSAGEBOX_EDIT, g_pMessageBuffer, MAX_PATH) != 0) {
		lstrcat(g_pMessageBuffer, TEXT("\r\n"));
	}
	lstrcat(g_pMessageBuffer, szMsg);

	SendDlgItemMessage(hDlg, IDC_MESSAGEBOX_EDIT, WM_SETTEXT, 0, (LPARAM)g_pMessageBuffer);
	SendDlgItemMessage(hDlg, IDC_MESSAGEBOX_EDIT, EM_LINESCROLL, 0, SendDlgItemMessage(hDlg, IDC_MESSAGEBOX_EDIT, EM_GETLINECOUNT, 0, 0));
}

