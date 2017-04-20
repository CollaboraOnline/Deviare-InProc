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

#define ARRAYLEN(a) (sizeof(a)/sizeof(*a))

static CNktHookLib cHookMgr;

struct HookedInvoke
{
  IDispatch *pdisp;
  ITypeInfo *ptinfo;
  HookedInvoke *next;
};

static HookedInvoke *pHookedInvokes = NULL;

static HookedInvoke *
FindHookedInvoke(IDispatch *pdisp)
{
  HookedInvoke *p = pHookedInvokes;
  while (p != NULL && p->pdisp != pdisp)
    p = p->next;
  return p;
}

static HookedInvoke *
AddNewHookedInvoke(IDispatch *pdisp, ITypeInfo *pTInfo)
{
  HookedInvoke *p = new HookedInvoke;
  p->pdisp = pdisp;
  p->ptinfo = pTInfo;
  p->next = pHookedInvokes;
  pHookedInvokes = p;
  return pHookedInvokes;
}

static HookedInvoke *
MaybeAddHookedInvoke(IDispatch *pdisp)
{
  HookedInvoke *p = FindHookedInvoke(pdisp);
  if (p != NULL)
    return p;

  ITypeInfo *pTInfo;
  HRESULT hr = pdisp->GetTypeInfo(0, MAKELCID(MAKELANGID(LANG_ENGLISH, SUBLANG_ENGLISH_US), SORT_DEFAULT), &pTInfo);
  if (FAILED(hr))
    return NULL;

  return AddNewHookedInvoke(pdisp, pTInfo);
}

static HANDLE GetOutputHandle()
{
  static bool beenHere = false;
  static HANDLE result;

  if (beenHere)
    return result;

  char filename[100];
  if (::GetEnvironmentVariableA("DEVIARE_LOGFILE", filename, ARRAYLEN(filename)))
  {
    result = ::CreateFileA(filename, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
  }
  else
  {
    result = GetStdHandle(STD_OUTPUT_HANDLE);
  }
  beenHere = true;
  return result;
}

static void Print(char *format, ...)
{
  HANDLE output = GetOutputHandle();
  if (output != NULL && output != INVALID_HANDLE_VALUE)
  {
    char buffer[1000];
    va_list argptr;
    va_start(argptr, format);
    NktHookLibHelpers::vsnprintf(buffer, ARRAYLEN(buffer), format, argptr);
    va_end(argptr);
    DWORD written;
    ::WriteFile(output, buffer, ::lstrlenA(buffer), &written, NULL);
  }
}

static void Print(wchar_t *format, ...)
{
  HANDLE output = GetOutputHandle();
  if (output != NULL && output != INVALID_HANDLE_VALUE)
  {
    wchar_t wbuffer[1000];
    va_list argptr;
    va_start(argptr, format);
    NktHookLibHelpers::vsnwprintf(wbuffer, ARRAYLEN(wbuffer), format, argptr);
    va_end(argptr);
    int buflen = 4 * ::lstrlenW(wbuffer);
    char *buffer = new char[buflen];
    buflen = ::WideCharToMultiByte(CP_UTF8, 0, wbuffer, ::lstrlenW(wbuffer), buffer, buflen, NULL, NULL);
    DWORD written;
    ::WriteFile(output, buffer, buflen, &written, NULL);
    delete[] buffer;
  }
}

static void PrintVariant(VARIANT *pVariant)
{
  switch (pVariant->vt)
    {
    case VT_BOOL:
      Print(pVariant->boolVal ? "TRUE" : "FALSE");
      break;
    case VT_BSTR:
      Print(L"\"%s\"", pVariant->bstrVal);
      break;
    case VT_DISPATCH:
      Print("IDispatch:%x", pVariant->pdispVal);
      if (MaybeAddHookedInvoke(pVariant->pdispVal) == NULL)
	Print("(?)");
      break;
    case VT_I2:
      Print("%d",pVariant->iVal);
      break;
    case VT_I4:
      Print("%ld",pVariant->lVal);
      break;
    case VT_NULL:
      Print("NULL");
      break;
    case VT_R4:
      Print("%g", pVariant->fltVal);
      break;
    case VT_R8:
      Print("%g", pVariant->dblVal);
      break;
    case VT_UNKNOWN:
      Print("IUnknown:%x", pVariant->punkVal);
      break;
    case VT_VARIANT|VT_BYREF:
      Print("{");
      PrintVariant(pVariant->pvarVal);
      Print("}");
      break;
    default:
      Print("unhandled variant %d", pVariant->vt);
      break;
    }
}

typedef HRESULT (WINAPI *lpfnCoCreateInstance)(_In_  REFCLSID  rclsid,
					       _In_  LPUNKNOWN pUnkOuter,
					       _In_  DWORD     dwClsContext,
					       _In_  REFIID    riid,
					       _Out_ LPVOID    *ppv);

static HRESULT WINAPI Hooked_CoCreateInstance(_In_  REFCLSID  rclsid,
					      _In_  LPUNKNOWN pUnkOuter,
					      _In_  DWORD     dwClsContext,
					      _In_  REFIID    riid,
					      _Out_ LPVOID    *ppv);

static struct {
  SIZE_T nHookId;
  lpfnCoCreateInstance fnCoCreateInstance;
} sCoCreateInstance_Hook = { 0, NULL };

typedef HRESULT (WINAPI *lpfnCoCreateInstanceEx)(_In_    REFCLSID     rclsid,
						 _In_    IUnknown     *punkOuter,
						 _In_    DWORD        dwClsCtx,
						 _In_    COSERVERINFO *pServerInfo,
						 _In_    DWORD        dwCount,
						 _Inout_ MULTI_QI     *pResults);

static HRESULT WINAPI Hooked_CoCreateInstanceEx(_In_    REFCLSID     rclsid,
						_In_    IUnknown     *punkOuter,
						_In_    DWORD        dwClsCtx,
						_In_    COSERVERINFO *pServerInfo,
						_In_    DWORD        dwCount,
						_Inout_ MULTI_QI     *pResults);

static struct {
  SIZE_T nHookId;
  lpfnCoCreateInstanceEx fnCoCreateInstanceEx;
} sCoCreateInstanceEx_Hook = { 0, NULL };

typedef HRESULT (WINAPI *lpfnCoGetClassObject)(_In_     REFCLSID     rclsid,
					       _In_     DWORD        dwClsContext,
					       _In_opt_ COSERVERINFO *pServerInfo,
					       _In_     REFIID       riid,
					       _Out_    LPVOID       *ppv);

static HRESULT WINAPI Hooked_CoGetClassObject(_In_     REFCLSID     rclsid,
					      _In_     DWORD        dwClsContext,
					      _In_opt_ COSERVERINFO *pServerInfo,
					      _In_     REFIID       riid,
					      _Out_    LPVOID       *ppv);

static struct {
  SIZE_T nHookId;
  lpfnCoGetClassObject fnCoGetClassObject;
} sCoGetClassObject_Hook = { 0, NULL };

constexpr int INDENT_STEP = 2;
static __declspec(thread) int recursionIndent = 0;

static void
DumpCoCreateStyleCall(wchar_t *api, REFCLSID rclsid)
{
  LPOLESTR szRclsIDAsString;
  HRESULT hr;

  hr = ::StringFromCLSID(rclsid, &szRclsIDAsString);
  if (!FAILED(hr))
  {
    LPOLESTR szRclsIDAsProgID;
    hr = ::ProgIDFromCLSID(rclsid, &szRclsIDAsProgID);
    Print(L"#%*.s %s(%s) (%s)\n",
	  recursionIndent, L"",
	  api,
	  szRclsIDAsString,
	  (!FAILED(hr) ? szRclsIDAsProgID : L"unknown"));
    CoTaskMemFree(szRclsIDAsString);
    if (!FAILED(hr))
      CoTaskMemFree(szRclsIDAsProgID);
  }
  else
  {
    Print(L"# %s on bogus CLSID?\n", api);
  }
}

// From <oaidl.h>: The C style interface for IDispatch:

typedef struct
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(
	__RPC__in IDispatch * This,
	/* [in] */ __RPC__in REFIID riid,
	/* [annotation][iid_is][out] */
	_COM_Outptr_  void **ppvObject);

    ULONG ( STDMETHODCALLTYPE *AddRef )(
	__RPC__in IDispatch * This);

    ULONG ( STDMETHODCALLTYPE *Release )(
	__RPC__in IDispatch * This);

    HRESULT ( STDMETHODCALLTYPE *GetTypeInfoCount )(
	__RPC__in IDispatch * This,
	/* [out] */ __RPC__out UINT *pctinfo);

    HRESULT ( STDMETHODCALLTYPE *GetTypeInfo )(
	__RPC__in IDispatch * This,
	/* [in] */ UINT iTInfo,
	/* [in] */ LCID lcid,
	/* [out] */ __RPC__deref_out_opt ITypeInfo **ppTInfo);

    HRESULT ( STDMETHODCALLTYPE *GetIDsOfNames )(
	__RPC__in IDispatch * This,
	/* [in] */ __RPC__in REFIID riid,
	/* [size_is][in] */ __RPC__in_ecount_full(cNames) LPOLESTR *rgszNames,
	/* [range][in] */ __RPC__in_range(0,16384) UINT cNames,
	/* [in] */ LCID lcid,
	/* [size_is][out] */ __RPC__out_ecount_full(cNames) DISPID *rgDispId);

    /* [local] */ HRESULT ( STDMETHODCALLTYPE *Invoke )(
	IDispatch * This,
	/* [annotation][in] */
	_In_  DISPID dispIdMember,
	/* [annotation][in] */
	_In_  REFIID riid,
	/* [annotation][in] */
	_In_  LCID lcid,
	/* [annotation][in] */
	_In_  WORD wFlags,
	/* [annotation][out][in] */
	_In_  DISPPARAMS *pDispParams,
	/* [annotation][out] */
	_Out_opt_  VARIANT *pVarResult,
	/* [annotation][out] */
	_Out_opt_  EXCEPINFO *pExcepInfo,
	/* [annotation][out] */
	_Out_opt_  UINT *puArgErr);

    END_INTERFACE
} IDispatchVtbl;

static HookedInvoke *DumpPreInvoke(IDispatch *This,
				   DISPID dispIdMember,
				   REFIID riid,
				   LCID lcid,
				   WORD wFlags,
				   DISPPARAMS *pDispParams,
				   VARIANT *pVarResult,
				   EXCEPINFO *pExcepInfo,
				   UINT *puArgErr,
				   bool &hasByRefParameters)
{
  if (recursionIndent > 0)
    Print("\n");

  Print("%*.s%x:", recursionIndent, "", This);

  hasByRefParameters = false;

  HookedInvoke *p = MaybeAddHookedInvoke(This);
  if (p == NULL)
    Print("?");
  else
  {
    // Dump function name
    BSTR name = SysAllocString(L"                                                       ");
    UINT numNames;
    if (!SUCCEEDED(p->ptinfo->GetNames(dispIdMember, &name, 1, &numNames)))
    {
      SysFreeString(name);
      name = SysAllocString(L"?");
    }

    if (wFlags == DISPATCH_PROPERTYGET)
      Print("get");
    else if (wFlags == DISPATCH_PROPERTYPUT)
      Print("put");
    else if (wFlags == DISPATCH_PROPERTYPUTREF)
      Print("putref");

    Print(name);
    SysFreeString(name);
    Print("(");

    // Dump each parameter before call
    for (UINT i = 0; i < pDispParams->cArgs; i++)
    {
      if (pDispParams->rgvarg[i].vt & VT_BYREF)
	hasByRefParameters = true;

      PrintVariant(&pDispParams->rgvarg[i]);

      if (i+1 < pDispParams->cArgs)
	Print(",");
    }

    // TODO: Named parameters

    Print(")");
  }
  return p;
}

static void DumpPostInvoke(HookedInvoke *p,
			   IDispatch *This,
			   DISPID dispIdMember,
			   REFIID riid,
			   LCID lcid,
			   WORD wFlags,
			   DISPPARAMS *pDispParams,
			   VARIANT *pVarResult,
			   EXCEPINFO *pExcepInfo,
			   UINT *puArgErr,
			   bool hasByRefParameters)
{
  if (p != NULL)
  {
    // Dump potentially changed reference parameters and return value after call

    if (hasByRefParameters)
    {
      Print(" : (");
      for (UINT i = 0; i < pDispParams->cArgs; i++)
      {
	if (pDispParams->rgvarg[i].vt & VT_BYREF)
	  hasByRefParameters = true;

	PrintVariant(&pDispParams->rgvarg[i]);

	if (i+1 < pDispParams->cArgs)
	  Print(",");
      }
      Print(")");
    }

    if (pVarResult != NULL && pVarResult->vt != VT_EMPTY)
    {
      Print(" -> ");
      PrintVariant(pVarResult);
    }
  }
  Print("\n");

  if (recursionIndent > 0)
    Print("%*.s",
	  recursionIndent, "");
}

typedef HRESULT (WINAPI *lpfnInvoke)(IDispatch *This,
				     _In_  DISPID dispIdMember,
				     _In_  REFIID riid,
				     _In_  LCID lcid,
				     _In_  WORD wFlags,
				     _In_  DISPPARAMS *pDispParams,
				     _Out_opt_  VARIANT *pVarResult,
				     _Out_opt_  EXCEPINFO *pExcepInfo,
				     _Out_opt_  UINT *puArgErr);

#define HOOK_COUNT 8
static struct {
  SIZE_T nHookId[HOOK_COUNT]; // id of the hook.
  lpfnInvoke fnHooks[HOOK_COUNT]; // hook / proxy functions
  lpfnInvoke fnInvokes[HOOK_COUNT];
  LPVOID fnOrigInvokes[HOOK_COUNT]; // original functions
} sInvoke_Hook;

static void InitGlobals()
{
  for (int i = 0; i < HOOK_COUNT; ++i)
  {
    sInvoke_Hook.nHookId[i] = 0;
    sInvoke_Hook.fnHooks[i] = NULL;
    sInvoke_Hook.fnInvokes[i] = NULL;
    sInvoke_Hook.fnOrigInvokes[i] = NULL;
  }
}

/// We need to generate lots of these in order to hook more
/// than one impl. of IDispatch - would be nice if Deviare could be
/// tweaked to helped with this - it has trampoline generation code ...
#define GENERATE_INVOKE(i) \
static HRESULT WINAPI Hooked_Invoke_##i(IDispatch *This, \
				       _In_  DISPID dispIdMember, \
				       _In_  REFIID riid, \
				       _In_  LCID lcid, \
				       _In_  WORD wFlags, \
				       _In_  DISPPARAMS *pDispParams, \
				       _Out_opt_  VARIANT *pVarResult, \
				       _Out_opt_  EXCEPINFO *pExcepInfo, \
				       _Out_opt_  UINT *puArgErr) \
{ \
  bool hasByRefParameters; \
  HookedInvoke *p = DumpPreInvoke(This, dispIdMember, riid, lcid, wFlags, pDispParams, pVarResult, pExcepInfo, puArgErr, hasByRefParameters); \
  recursionIndent += INDENT_STEP; \
  \
  HRESULT result = sInvoke_Hook.fnInvokes[(i)](This, dispIdMember, riid, lcid, wFlags, pDispParams, pVarResult, pExcepInfo, puArgErr); \
  \
  recursionIndent -= INDENT_STEP; \
  \
  DumpPostInvoke(p, This, dispIdMember, riid, lcid, wFlags, pDispParams, pVarResult, pExcepInfo, puArgErr, hasByRefParameters); \
  \
  return result; \
}

GENERATE_INVOKE(0)
GENERATE_INVOKE(1)
GENERATE_INVOKE(2)
GENERATE_INVOKE(3)
GENERATE_INVOKE(4)
GENERATE_INVOKE(5)
GENERATE_INVOKE(6)
GENERATE_INVOKE(7)

#undef GENERATE_INVOKE

static void SetupInvokes()
{
#define ASSIGN(i) \
  sInvoke_Hook.fnHooks[i] = Hooked_Invoke_##i

  ASSIGN(0);
  ASSIGN(1);
  ASSIGN(2);
  ASSIGN(3);
  ASSIGN(4);
  ASSIGN(5);
  ASSIGN(6);
  ASSIGN(7);

#undef ASSIGN
}
 
static void
DoIDispatchMagic(IDispatch *pdisp)
{
  ITypeInfo *pTInfo;

  HRESULT hr = pdisp->GetTypeInfo(0, MAKELCID(MAKELANGID(LANG_ENGLISH, SUBLANG_ENGLISH_US), SORT_DEFAULT), &pTInfo);
  if (FAILED(hr))
  {
    Print("GetTypeInfo failed\n");
    return;
  }

#if 0
  // Test: Dump out function members
  UINT index = 0;
  FUNCDESC *pFuncDesc;
  while (SUCCEEDED(pTInfo->GetFuncDesc(index++, &pFuncDesc)))
  {
    BSTR name = SysAllocString(L"                                                       ");
    UINT numNames;
    if (!SUCCEEDED(pTInfo->GetNames(pFuncDesc->memid, &name, 1, &numNames)))
      Print("  GetNames failed\n");

    Print(L"  Member %lx: %s kind: %d invoke: %d\n",
	  pFuncDesc->memid,
	  name,
	  pFuncDesc->funckind,
	  pFuncDesc->invkind);
    SysFreeString(name);
    pTInfo->ReleaseFuncDesc(pFuncDesc);
  }
#endif

  LPVOID fnOrigInvoke = (*(IDispatchVtbl**)pdisp)->Invoke;

  // Are we already hooked ?
  int i;
  for (i = 0; i < HOOK_COUNT; ++i)
  {
     if (sInvoke_Hook.fnOrigInvokes[i] == fnOrigInvoke)
       return; // already hooked.
     if (sInvoke_Hook.fnInvokes[i] == NULL)
       break;
  }
  if (i >= HOOK_COUNT)
  {
     Print("All hooks exhausted !\n");
     return;
  }

  sInvoke_Hook.fnOrigInvokes[i] = fnOrigInvoke;

  DWORD dwOsErr = cHookMgr.Hook(&(sInvoke_Hook.nHookId[i]),
				(LPVOID *) &(sInvoke_Hook.fnInvokes[i]),
				fnOrigInvoke,
				sInvoke_Hook.fnHooks[i],
				0); // FIXME: Or NKTHOOKLIB_DisallowReentrancy?

  Print("# %s Invoke %d of %x (old: %x) (orig: %x)\n",
	(dwOsErr == ERROR_SUCCESS ? "Hooked" : "Failed to hook"),
	i,
	pdisp,
	sInvoke_Hook.fnInvokes[i],
	fnOrigInvoke);

  AddNewHookedInvoke(pdisp, pTInfo);
}

static void
hookCoCreateInstance(void)
{
	HINSTANCE hOle32Dll;
	DWORD dwOsErr;

	InitGlobals();
	SetupInvokes();

	hOle32Dll = NktHookLibHelpers::GetModuleBaseAddress(L"ole32.dll");
	if (hOle32Dll == NULL)
	{
		Print("Cannot get handle of ole32.dll\n");
		return;
	}

	LPVOID fnOrigCoCreateInstance = ::GetProcAddress(hOle32Dll, "CoCreateInstance");
	if (fnOrigCoCreateInstance == NULL)
	{
		Print("Cannot get address of CoCreateInstance\n");
		return;
	}

	// FIXME: No idea whether that NKTHOOKLIB_DisallowReentrancy
	// is useful or not here. Will leaving it out have any effect?
	// And what about the other possible flags?
	dwOsErr = cHookMgr.Hook(&(sCoCreateInstance_Hook.nHookId),
				(LPVOID *)&(sCoCreateInstance_Hook.fnCoCreateInstance),
				fnOrigCoCreateInstance,
				Hooked_CoCreateInstance,
				NKTHOOKLIB_DisallowReentrancy);

	LPVOID fnOrigCoCreateInstanceEx = ::GetProcAddress(hOle32Dll, "CoCreateInstanceEx");
	if (fnOrigCoCreateInstanceEx == NULL)
	{
		Print("Cannot get address of CoCreateInstanceEx\n");
		return;
	}

	dwOsErr = cHookMgr.Hook(&(sCoCreateInstanceEx_Hook.nHookId),
				(LPVOID *)&(sCoCreateInstanceEx_Hook.fnCoCreateInstanceEx),
				fnOrigCoCreateInstanceEx,
				Hooked_CoCreateInstanceEx,
				NKTHOOKLIB_DisallowReentrancy);

	LPVOID fnOrigCoGetClassObject = ::GetProcAddress(hOle32Dll, "CoGetClassObject");
	if (fnOrigCoGetClassObject == NULL)
	{
		Print("Cannot get address of CoGetClassObject\n");
		return;
	}

	dwOsErr = cHookMgr.Hook(&(sCoGetClassObject_Hook.nHookId),
				(LPVOID *)&(sCoGetClassObject_Hook.fnCoGetClassObject),
				fnOrigCoGetClassObject,
				Hooked_CoGetClassObject,
				NKTHOOKLIB_DisallowReentrancy);
}

static void
hookClassFactory(LPVOID pv)
{
  IClassFactory *pfactory = (IClassFactory *) pv;

  IDispatch *pdisp;
  HRESULT hr = pfactory->CreateInstance(NULL, IID_IDispatch, (LPVOID *) &pdisp);

  if (SUCCEEDED(hr))
  {
    DoIDispatchMagic(pdisp);
  }
}

static HRESULT WINAPI Hooked_CoCreateInstance(_In_  REFCLSID  rclsid,
					      _In_  LPUNKNOWN pUnkOuter,
					      _In_  DWORD     dwClsContext,
					      _In_  REFIID    riid,
					      _Out_ LPVOID    *ppv)
{
  DumpCoCreateStyleCall(L"CoCreateInstance", rclsid);

  LPOLESTR szRiidAsString;
  HRESULT hr = ::StringFromIID(riid, &szRiidAsString);
  if (SUCCEEDED(hr))
  {
    Print(L"#%*.s   riid=%s\n",
	  recursionIndent, L"",
	  szRiidAsString);
    CoTaskMemFree(szRiidAsString);
  }
  else
  {
    Print("#%*.s   on bogus REFIID?\n",
	  recursionIndent, "");
  }

  recursionIndent += INDENT_STEP;

  HRESULT result = sCoCreateInstance_Hook.fnCoCreateInstance(rclsid, pUnkOuter, dwClsContext, riid, ppv);

  recursionIndent -= INDENT_STEP;

  if (SUCCEEDED(result))
  {
    Print("#%*.s   result:%x\n",
	  recursionIndent, "",
	  *ppv);
  }
  else
  {
    Print("#%*.s   failed\n",
	  recursionIndent, "");
    return result;
  }
#if 0 // Not sure about the necessity of this
  if (IsEqualGUID(riid, IID_IClassFactory))
    hookClassFactory(*ppv);
#endif
  return result;
}

static HRESULT WINAPI Hooked_CoCreateInstanceEx(_In_     REFCLSID     rclsid,
						_In_     IUnknown     *pUnkOuter,
						_In_     DWORD        dwClsContext,
						_In_     COSERVERINFO *pServerInfo,
						_In_     DWORD        dwCount,
						_Inout_  MULTI_QI     *pResults)
{
  DumpCoCreateStyleCall(L"CoCreateInstanceEx", rclsid);

  recursionIndent += INDENT_STEP;

  HRESULT result = sCoCreateInstanceEx_Hook.fnCoCreateInstanceEx(rclsid, pUnkOuter, dwClsContext, pServerInfo, dwCount, pResults);

  recursionIndent -= INDENT_STEP;

  if (SUCCEEDED(result))
  {
    Print("#%*.s  results:\n",
	  recursionIndent, "");
    for (DWORD i = 0; i < dwCount; i++)
    {
      LPOLESTR szIidAsString;
      HRESULT hr = ::StringFromIID(*pResults[i].pIID, &szIidAsString);
      Print(L"#    %s: %x%s\n", 
	    szIidAsString,
	    pResults[i].pItf,
	    (FAILED(pResults[i].hr) ? L" (failed)" : L""));
    }
  }
  else
    Print("#  failed\n");

  return result;
}

static HRESULT WINAPI Hooked_CoGetClassObject(_In_     REFCLSID     rclsid,
					      _In_     DWORD        dwClsContext,
					      _In_opt_ COSERVERINFO *pServerInfo,
					      _In_     REFIID       riid,
					      _Out_    LPVOID       *ppv)
{
  DumpCoCreateStyleCall(L"CoGetClassObject", rclsid);

  LPOLESTR szRiidAsString;
  HRESULT hr = ::StringFromIID(riid, &szRiidAsString);
  if (SUCCEEDED(hr))
  {
    Print(L"#%*.s   riid=%s\n",
	  recursionIndent, L"",
	  szRiidAsString);
    CoTaskMemFree(szRiidAsString);
  }
  else
  {
    Print("#%*.s   on bogus REFIID?\n",
	  recursionIndent, "");
  }

  recursionIndent += INDENT_STEP;

  HRESULT result = sCoGetClassObject_Hook.fnCoGetClassObject(rclsid, dwClsContext, pServerInfo, riid, ppv);

  recursionIndent -= INDENT_STEP;

  if (SUCCEEDED(result))
  {
    Print("#%*.s   result:%x\n",
	  recursionIndent, "",
	  *ppv);
  }
  else
  {
    Print("#%*.s   failed\n",
	  recursionIndent, "");
    return result;
  }

  if (IsEqualGUID(riid, IID_IClassFactory))
    hookClassFactory(*ppv);

  return result;
}

extern "C" BOOL APIENTRY DllMain(__in HMODULE hModule, __in DWORD ulReasonForCall, __in LPVOID lpReserved)
{
  switch (ulReasonForCall)
  {
    case DLL_PROCESS_ATTACH:
      hookCoCreateInstance();
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
