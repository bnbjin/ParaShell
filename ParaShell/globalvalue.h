#ifndef __GLOBALVALUE_H__
#define __GLOBALVALUE_H__

#include <windows.h>

// 进程实例句柄
extern HINSTANCE g_hInst;

// 显示窗口缓冲区
extern TCHAR* g_pMessageBuffer;

// 进度条句柄
extern HWND g_hProgress;

#endif // __GLOBALVALUE_H__