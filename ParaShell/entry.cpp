/*******************************************************
/*《加密与解密》第三版配套实例
/*第16章 外壳编写基础
/*Microsoft Visual C++ 6.0
/*Code by Hying 2001.1
/*Modified by kanxue  2005.3
/*Thanks ljtt
/*Hying原来的外壳主程序是asm，kanxue用VC改写，改写过程，参考了ljtt的外壳源码
/*(c)  看雪软件安全网站 www.pediy.com 2000-2008
********************************************************/
/********************************************************************************/
/*  VC 6.0工程直接融合了MASM32汇编编译的方法							        */
/* 1、将shell.asm填加到VC工程的Source files中；					                */
/* 2、将Source files中的shell.obj删除；							                */
/* 3、在Source files中的shell.asm上：右键->Setting->选中Custom Build页	        */
/*   在Commands中输入：													        */
/*    如果是DEBUG模式，则输入：											        */
/*    c:\masm32\bin\ml /c /coff /Zi /Fo$(IntDir)\$(InputName).obj $(InputPath)  */
/*																		        */
/*    如果是RELEASE模式，则输入： 							                    */
/*    c:\masm32\bin\ml /c /coff  /Fo$(IntDir)\$(InputName).obj $(InputPath)     */
/*																		        */
/*    在Outputs中输入：													      	*/
/* $(IntDir)\$(InputName).obj                                                   */
/*    如果没有把masm安装在c盘，则要作相应的修改。                               */
/********************************************************************************/


#include <windows.h>
#include <commctrl.h>
#include <process.h>
#include "entry.h"
#include "resource.h"
#include "config.h"
#include "utilities.h"
#include "error.h"
#include "pediy.h"
#include "globalvalue.h"

#pragma comment(lib, "comctl32.lib")


/*
	Description:	控制子窗口回调函数
*/
INT_PTR CALLBACK SubCTLDlgProc(
	_In_ HWND hDlg,
	_In_ UINT uMsg,
	_In_ WPARAM wParam,
	_In_ LPARAM lParam)
{
	HANDLE					hThread;
	DWORD					ProtFileThreadID;
	static TCHAR			szFilePath[MAX_PATH];

	switch (uMsg)
	{
	case WM_INITDIALOG:
		// 创建消息框缓冲
		g_pMessageBuffer = new TCHAR[0x10000];
		ZeroMemory(g_pMessageBuffer, 0x10000);

		// 获取进度条句柄
		g_hProgress = GetDlgItem(hDlg, IDC_PROGRESS);
		
		// 使能够文件拖动
		//DragAcceptFiles(hDlg, TRUE);
		
		// 禁用加壳处理按键
		EnableWindow(GetDlgItem(hDlg, IDC_PROT_BUTTON), FALSE);

#ifdef __PARADOX_DEBUG__
		DeleteFile(TEXT("C:\\Users\\Administrator\\Desktop\\test.exe"));
		MoveFile(TEXT("C:\\Users\\Administrator\\Desktop\\test.exe.bak"), TEXT("C:\\Users\\Administrator\\Desktop\\test.exe"));
		lstrcpy(szFilePath, TEXT("C:\\Users\\Administrator\\Desktop\\test.exe"));
		hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)ProtTheFile, (LPVOID)szFilePath, NORMAL_PRIORITY_CLASS, &ProtFileThreadID);
		WaitForSingleObject(hThread, INFINITE);
		CloseHandle(hThread);
		WinExec("C:\\Users\\Administrator\\Desktop\\test.exe", SW_NORMAL);
		SendMessage(GetParent(GetParent(hDlg)), WM_CLOSE, 0, 0);
#endif 

		break;
	/*
	case WM_DROPFILES://支持文件拖放

		if (FALSE == ISWORKING) {

			ZeroMemory(g_pMessageBuffer, 0x10000); //将消息缓冲区数据清零
			ZeroMemory(szFilePath, MAX_PATH);//清空文件名缓冲
			DragQueryFile((HDROP)wParam, 0, szFilePath, sizeof(szFilePath));
			DragFinish((HDROP)wParam);

			SendDlgItemMessage(hDlg, IDC_MESSAGEBOX_EDIT, WM_SETTEXT, 0, 0);//清空消息框中的提示
			SendDlgItemMessage(hDlg, IDC_FILEPATH_EDIT, WM_SETTEXT, MAX_PATH, (LPARAM)szFilePath);
			AddLine(hDlg, szFilePath);
			if (!IsPEFile(szFilePath, hDlg))
				EnableWindow(GetDlgItem(hDlg, IDC_PROT_BUTTON), FALSE);
			else
				EnableWindow(GetDlgItem(hDlg, IDC_PROT_BUTTON), TRUE);
			SendMessage(g_hProgress, PBM_SETPOS, 0, 0);
		}
		break;
	*/
	case WM_COMMAND:
		switch (LOWORD(wParam))
		{
		//保护			
		case IDC_PROT_BUTTON:
			EnableWindow(GetDlgItem(hDlg, IDC_PROT_BUTTON), FALSE);
			EnableWindow(GetDlgItem(hDlg, IDC_OPEN_BUTTON), FALSE);

			// 创建一个线程来处理数据
			hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)ProtTheFile, (LPVOID)szFilePath, NORMAL_PRIORITY_CLASS, &ProtFileThreadID);
			if (0 != hThread)
			{
				CloseHandle(hThread);
			}

			break;

		//打开预处理
		case IDC_OPEN_BUTTON:
			if (!OpenFileDlg(szFilePath, hDlg))
			{
				break;
			}
			
			SendDlgItemMessage(hDlg, IDC_MESSAGEBOX_EDIT, WM_SETTEXT, 0, 0);//清空消息框中的提示

			SendDlgItemMessage(hDlg, IDC_FILEPATH_EDIT, WM_SETTEXT, MAX_PATH, (LPARAM)szFilePath);
			AddLine(hDlg, szFilePath);
			
			if (ERR_SUCCESS == IsPEFile(szFilePath))
			{
				EnableWindow(GetDlgItem(hDlg, IDC_PROT_BUTTON), TRUE);
			}
			else
			{
				EnableWindow(GetDlgItem(hDlg, IDC_PROT_BUTTON), FALSE);
			}
			
			SendMessage(g_hProgress, PBM_SETPOS, 0, 0);
			
			break;

		default:
			
			// MessageBox(hDlg, TEXT("控制子窗口未处理WM_COMMAND"), 0, 0);
			
			return FALSE;

			break;
		}

		return TRUE;
		
		break;
	}
	return FALSE;
}

/*
	Description:	属性开关子窗口过程
*/
INT_PTR CALLBACK SubSWTDlgProc(
	_In_ HWND hDlg,
	_In_ UINT uMsg,
	_In_ WPARAM wParam,
	_In_ LPARAM lParam)
{

	switch (uMsg)
	{
	case WM_INITDIALOG:
		//配置对话框初始化
		//properinitDlgProc(hDlg);
		break;
	}
	return FALSE;
}

/*
	Description:	关于程序窗口
*/
INT_PTR CALLBACK AboutPGMDlgProc(
	_In_ HWND hDlg,
	_In_ UINT uMsg,
	_In_ WPARAM wParam,
	_In_ LPARAM lParam)
{
	switch (uMsg)
	{
	case  WM_LBUTTONDOWN:
		PostMessage(hDlg, WM_NCLBUTTONDOWN, HTCAPTION, 0);
		return TRUE;
		break;

	case WM_CLOSE:
		EndDialog(hDlg, 0);
		break;
	}
	return FALSE;
}

/*
	Description:	关于作者窗口
*/
INT_PTR CALLBACK AboutAuthorDlgProc(
	_In_ HWND hDlg,
	_In_ UINT uMsg,
	_In_ WPARAM wParam,
	_In_ LPARAM lParam)
{
	switch (uMsg)
	{
	case  WM_LBUTTONDOWN:
		PostMessage(hDlg, WM_NCLBUTTONDOWN, HTCAPTION, 0);
		return TRUE;

	case WM_CLOSE:
		EndDialog(hDlg, 0);
		break;
	}

	return FALSE;
}


/*
Description:	主对话框消息回调函数
*/
INT_PTR CALLBACK MainDlgProc(
	_In_ HWND hDlg,
	_In_ UINT uMsg,
	_In_ WPARAM wParam,
	_In_ LPARAM lParam)
{
	static int     i;
	static HWND    hwndTab;           //TAB控件句柄
	static HWND    SubCTLWnd;        //3个子对话框句柄
	static HWND    SubSWTWnd;
	static HWND    Child3hWnd;
	TC_ITEM ItemStruct;


	switch (uMsg)
	{
	case WM_CLOSE:
		// 释放在控制子窗口申请的内存
		delete g_pMessageBuffer;
		DestroyWindow(hDlg);

		break;

	case WM_COMMAND:
		switch (LOWORD(wParam))
		{
		case IDM_ABOUT_PGM:
			DialogBox(g_hInst, MAKEINTRESOURCE(IDD_ABOUT_PGM), hDlg, AboutPGMDlgProc);
			break;

		case IDM_ABOUT_AUTHOR:
			DialogBox(g_hInst, MAKEINTRESOURCE(IDD_ABOUT_AUTHOR), hDlg, AboutAuthorDlgProc);
			break;

		case IDM_FILE_OPEN:
			SendMessage(SubCTLWnd, WM_COMMAND, (WPARAM)IDC_OPEN_BUTTON, 0);
			break;

		case IDM_FILE_EXIT:
			SendMessage(hDlg, WM_CLOSE, 0, 0);
			break;

		default:
			MessageBox(hDlg, TEXT("主窗口未处理WM_COMMAND"), 0, 0);
			break;
		}

		break;

	case WM_INITDIALOG:

		// 设置主窗口图标
		SendMessage(hDlg, WM_SETICON, ICON_BIG, LPARAM(LoadIcon(g_hInst, MAKEINTRESOURCE(IDI_ICON1))));

		InitCommonControls();

		hwndTab = GetDlgItem(hDlg, IDC_TAB1);
		ItemStruct.mask = TCIF_TEXT;
		ItemStruct.iImage = 0;
		ItemStruct.lParam = 0;
		ItemStruct.pszText = TEXT("处理");
		ItemStruct.cchTextMax = 4;
		SendMessage(hwndTab, TCM_INSERTITEM, 0, (LPARAM)&ItemStruct);

		ItemStruct.pszText = TEXT("选项");
		ItemStruct.cchTextMax = 4;
		SendMessage(hwndTab, TCM_INSERTITEM, 1, (LPARAM)&ItemStruct);

		SubCTLWnd = CreateDialogParam(g_hInst, MAKEINTRESOURCE(IDD_SUB_CONTROL), hwndTab, SubCTLDlgProc, 0);
		SubSWTWnd = CreateDialogParam(g_hInst, MAKEINTRESOURCE(IDD_SUB_SWITCH), hwndTab, SubSWTDlgProc, 0);

		ShowWindow(SubCTLWnd, SW_SHOWDEFAULT);

		break;

	case WM_NOTIFY:
		//2个子对话框间的切换
		if (*(LPDWORD)((LPBYTE)lParam + 8) == TCN_SELCHANGE)
		{
			//先隐藏所有子对话框
			ShowWindow(SubCTLWnd, SW_HIDE);
			ShowWindow(SubSWTWnd, SW_HIDE);

			i = SendMessage(hwndTab, TCM_GETCURSEL, 0, 0);
			if (i == 0)
			{
				//GetOption(SubSWTWnd);//取得设置并保存到配置文件
				ShowWindow(SubCTLWnd, SW_SHOWDEFAULT);
			}
			else if (i == 1)
			{
				ShowWindow(SubSWTWnd, SW_SHOWDEFAULT);
			}

		}
		break;

	default:
		break;
	}

	return 0;
}


/*
	Description:	程序入口点
					1.启动主对话框
*/
int WINAPI WinMain(
	_In_ HINSTANCE hInstance, 
	_In_opt_ HINSTANCE hPrevInstance,
	_In_ LPSTR lpCmdLine, 
	_In_ int nCmdShow)
{
	// 保存实例句柄以供其他地方使用
	g_hInst = hInstance;

	DialogBoxParam(hInstance, MAKEINTRESOURCE(IDD_MAINDLG), NULL, MainDlgProc, NULL);

	return 0;
}