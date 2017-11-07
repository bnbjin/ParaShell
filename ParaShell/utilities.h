#ifndef __UTILITIES_H__
#define __UTILITIES_H__

#include <windows.h>

/*
	Description: 打开对话框函数
*/
BOOL  OpenFileDlg(TCHAR *szFilePath, HWND hwnd);

/*
	Description:	在消息框中增加一行消息输出
*/
void AddLine(HWND hDlg, TCHAR *szMsg);

#endif // __UTILITIES_H__
