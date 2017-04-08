/*
 * Copyright (C) 2010-2015 Nektra S.A., Buenos Aires, Argentina.
 * All rights reserved. Contact: http://www.nektra.com
 *
 *
 * This file is part of Deviare In-Proc
 *
 *
 * Commercial License Usage
 * ------------------------
 * Licensees holding valid commercial Deviare In-Proc licenses may use this
 * file in accordance with the commercial license agreement provided with the
 * Software or, alternatively, in accordance with the terms contained in
 * a written agreement between you and Nektra.  For licensing terms and
 * conditions see http://www.nektra.com/licensing/.  For further information
 * use the contact form at http://www.nektra.com/contact/.
 *
 *
 * GNU General Public License Usage
 * --------------------------------
 * Alternatively, this file may be used under the terms of the GNU
 * General Public License version 3.0 as published by the Free Software
 * Foundation and appearing in the file LICENSE.GPL included in the
 * packaging of this file.  Please review the following information to
 * ensure the GNU General Public License version 3.0 requirements will be
 * met: http://www.gnu.org/copyleft/gpl.html.
 *
 **/

#include "TestDll.h"
#include "..\..\..\Include\NktHookLib.h"
#include <stdio.h>

HRESULT (STDMETHODCALLTYPE *RealInvokeFn)(
	      DISPID     dispIdMember,
	      REFIID     riid,
	      LCID       lcid,
	      WORD       wFlags,
	      DISPPARAMS *pDispParams,
	      VARIANT    *pVarResult,
	      EXCEPINFO  *pExcepInfo,
	      UINT       *puArgErr
);

HRESULT STDMETHODCALLTYPE HookedInvokeFunction(
	DISPID     dispIdMember,
	REFIID     riid,
	LCID       lcid,
	WORD       wFlags,
	DISPPARAMS *pDispParams,
	VARIANT    *pVarResult,
	EXCEPINFO  *pExcepInfo,
	UINT       *puArgErr
)
{
	printf("Hooked invoke %d\n", dispIdMember);
	return RealInvokeFn(dispIdMember, riid, lcid, wFlags, pDispParams, pVarResult, pExcepInfo, puArgErr);
}

static CNktHookLib cHookMgr;

static void
hookIDispatch(void)
{
	::MessageBoxW(NULL, L"About to newly hook IDispatch", L"TestDll", MB_OK);
	// FIXME: does this work nicely so early in the startup ?
	printf("about to coinitialize\n");
	CoInitialize(NULL);
	printf("done coinitialize\n");

	CLSID clsid;
	LPCOLESTR progID = L"Excel.Application";

	HRESULT hr = CLSIDFromProgID(progID, &clsid);
	if (FAILED(hr))
	{
		printf("Can't find prog-id\n");
		return;
	}
	IDispatch *pApp = NULL;
	hr = CoCreateInstance(clsid, NULL, CLSCTX_LOCAL_SERVER /* out of proc*/, IID_PPV_ARGS(&pApp));
	if (FAILED(hr))
	{
		printf("Failed to create instance\n");
	}
	if (pApp == NULL)
	{
		printf("No IDispatch interface\n");
	}
	printf("got IDispatch\n");

	SIZE_T ignoreHookId;
	cHookMgr.Hook(&ignoreHookId, (LPVOID *)&RealInvokeFn, (LPVOID)42 /*pApp->Invoke*/, (LPVOID)HookedInvokeFunction,
		          NKTHOOKLIB_DisallowReentrancy);

	// Leak the COM object - why not.
	::MessageBoxW(NULL, L"Done hooking IDispatch", L"TestDll", MB_OK);
}

extern "C" BOOL APIENTRY DllMain(__in HMODULE hModule, __in DWORD ulReasonForCall, __in LPVOID lpReserved)
{
  switch (ulReasonForCall)
  {
    case DLL_PROCESS_ATTACH:
		hookIDispatch();
      break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
      break;
  }
  return TRUE;
}

extern "C" DWORD __stdcall InitializeDll()
{
  if (::MessageBoxW(NULL, L"In InitializeDll. Press 'OK' to continue or 'Cancel' to return an error.", L"TestDll",
                    MB_OKCANCEL) != IDOK)
  {
    return ERROR_CANCELLED;
  }
  return ERROR_SUCCESS;
}
