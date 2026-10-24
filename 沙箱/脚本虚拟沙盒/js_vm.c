/* ============================================================================
 *  js_vm.c —— 受控 JScript 虚拟执行宿主（"脚本虚拟沙盒"内核）
 * ----------------------------------------------------------------------------
 *  要解决的问题
 *  ------------
 *  火绒"脚本行为沙盒"那份资料点破的关键：变形脚本把真实功能藏在
 *  "自定义解密器 + eval"里，连 eval / fromCharCode 这些词本身都是 \uXXXX
 *  转义的 —— 纯静态特征必然全瞎。要拿到真实行为，只能**把解密器跑起来**。
 *
 *  但"跑起来"必须有个前提：样本碰不到真实系统。本程序就解决这个前提。
 *
 *  三层保证（第 3 条是运行后校验，不是嘴上说说）
 *  ----------------------------------------------
 *  [1] 不提供任何"真"宿主对象：站点 GetItemInfo 对一切名字都返回"不存在"，
 *      所以 WScript / FileSystemObject / XMLHTTP 这些名字在脚本里是空的。
 *  [2] 引擎内置的 ActiveXObject / GetObject 是**绕开宿主站点的 COM 后门**
 *      （实测：不处理时真能创建 FSO 并写文件）。所以用前置护栏脚本把它们
 *      覆盖掉，优先锁定为只读不可删；失败则退化为普通赋值（此时真实
 *      ActiveXObject 也已被同一个属性槽覆盖，样本同样拿不回真身）。
 *  [3] 护栏函数上带唯一令牌 __svmToken，跑完回读一次；对不上就**拒绝采信
 *      结果**（退出码 6），宁可不出结论也不给假结论。
 *
 *  虚拟宿主（JS 层实现，不碰 COM）
 *  ------------------------------
 *  样本最常用的那几十个成员全部有"假实现"：任何调用只记一行日志、返回一个
 *  能继续链式访问的假对象，绝不真的执行。于是
 *      WScript.Shell.Run("cmd /c ...")   -> 记一行"★执行请求"，返回 0
 *      new ActiveXObject("MSXML2.XMLHTTP")-> 记一行"COM请求"，给假对象
 *      fso.SaveToFile("...")             -> 记一行落地路径
 *  这份日志就是"脚本行为"的证据本身（火绒把脚本行为转成 PE 行为来判定，
 *  我们是把它转成**可读的行为证据 + 交给静态规则复检**）。
 *
 *  用法
 *  ----
 *    js_vm.exe --file <js> --out <txt>          # 跑，导出 __OUT__（解密结果）
 *    js_vm.exe --file <js> --once               # 只打印 __OUT__
 *    js_vm.exe --file <js> --calls-out <txt>    # 导出虚拟宿主行为日志
 *    js_vm.exe --selftest                       # 自检（含护栏穿透测试）
 *
 *  编译（mingw-w64）
 *  ----------------
 *    gcc js_vm.c -o js_vm.exe -static -lole32 -loleaut32 -luuid -O2
 * ==========================================================================*/

#define COBJMACROS
#define INITGUID          /* 就地定义 activscp.h 里的 GUID（mingw 没有含脚本接口 GUID 的 uuid.lib） */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <activscp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <wchar.h>

/* 注册表实测：HKLM\SOFTWARE\Classes\CLSID\{F414C260-...}\InprocServer32 = jscript.dll */
static const CLSID CLSID_JScript_ =
    { 0xF414C260, 0x6AC0, 0x11CF, { 0xB6, 0xD1, 0x00, 0xAA, 0x00, 0xBB, 0xBB, 0x58 } };
static const GUID g_iidNone = { 0, 0, 0, { 0, 0, 0, 0, 0, 0, 0, 0 } };

#define SVM_VERSION   L"SVM-JSVM-1.1"
#define SVM_TOKEN     L"SVM-JSVM-V1"

/* ======================================================== 宿主侧日志缓冲 ==== */

static wchar_t *g_sitelog = NULL;
static size_t   g_sitelogLen = 0, g_sitelogCap = 0;
static int      g_siteProbes = 0;

static void sitelog_init(void) { g_sitelogCap = 32768; g_sitelog = (wchar_t *)calloc(g_sitelogCap, sizeof(wchar_t)); }
static void sitelog_fini(void) { if (g_sitelog) free(g_sitelog); g_sitelog = NULL; }
static void sitelog_add(const wchar_t *line)
{
    if (!g_sitelog) return;
    size_t n = wcslen(line);
    if (g_sitelogLen + n + 2 < g_sitelogCap) {
        memcpy(g_sitelog + g_sitelogLen, line, n * sizeof(wchar_t));
        g_sitelogLen += n;
        g_sitelog[g_sitelogLen++] = L'\n';
        g_sitelog[g_sitelogLen] = 0;
    }
}
static void sitelog_addf(const wchar_t *fmt, ...)
{
    wchar_t buf[512];
    va_list ap;
    va_start(ap, fmt);
    _vsnwprintf(buf, 511, fmt, ap);
    va_end(ap);
    buf[511] = 0;
    sitelog_add(buf);
}

/* ------------------------------------------------------------- 站点实现 ---- */

typedef struct {
    IActiveScriptSiteVtbl *lpVtbl;
    LONG ref;
    char errbuf[8192];
    int  errcount;
    BOOL interrupted;
} HostSite;

static HRESULT STDMETHODCALLTYPE Site_QueryInterface(IActiveScriptSite *iface, REFIID riid, void **ppv)
{
    if (!ppv) return E_POINTER;
    *ppv = NULL;
    if (IsEqualIID(riid, &IID_IUnknown) || IsEqualIID(riid, &IID_IActiveScriptSite)) { *ppv = iface; return S_OK; }
    return E_NOINTERFACE;   /* 故意不给 IActiveScriptSiteWindow：宿主没有窗口 */
}
static ULONG STDMETHODCALLTYPE Site_AddRef(IActiveScriptSite *iface)  { return (ULONG)InterlockedIncrement(&((HostSite *)iface)->ref); }
static ULONG STDMETHODCALLTYPE Site_Release(IActiveScriptSite *iface) { return (ULONG)InterlockedDecrement(&((HostSite *)iface)->ref); }
static HRESULT STDMETHODCALLTYPE Site_GetLCID(IActiveScriptSite *i, LCID *p) { (void)i; if (p) *p = 0x0804; return S_OK; }

/* 一切具名对象都不提供 —— 这是"样本碰不到系统"的第一层保证。
 * 顺便把样本引用过的不存在的全局名记下来（这本身就是环境探测线索）。 */
static HRESULT STDMETHODCALLTYPE Site_GetItemInfo(IActiveScriptSite *iface, LPCOLESTR name,
                                                 DWORD returnMask, IUnknown **ppunk, ITypeInfo **ppti)
{
    (void)iface; (void)returnMask;
    if (ppunk) *ppunk = NULL;
    if (ppti)  *ppti = NULL;
    if (name && name[0] && g_siteProbes < 200) {
        char mb[200] = "";
        WideCharToMultiByte(CP_UTF8, 0, name, -1, mb, sizeof(mb) - 1, NULL, NULL);
        sitelog_addf(L"[环境探测] 脚本引用了不存在的全局名: %s", mb);
        g_siteProbes++;
    }
    return TYPE_E_ELEMENTNOTFOUND;
}
static HRESULT STDMETHODCALLTYPE Site_GetDocVersionString(IActiveScriptSite *i, BSTR *p)
{ (void)i; if (p) *p = SysAllocString(SVM_VERSION); return S_OK; }
static HRESULT STDMETHODCALLTYPE Site_OnScriptTerminate(IActiveScriptSite *i, const VARIANT *r, const EXCEPINFO *e)
{ (void)i;(void)r;(void)e; return S_OK; }
static HRESULT STDMETHODCALLTYPE Site_OnStateChange(IActiveScriptSite *i, SCRIPTSTATE s) { (void)i;(void)s; return S_OK; }

/* 保留样本报出的错误文本 —— 样本"探测沙箱"或"用了我方未覆盖的成员"时都会走到这里 */
static HRESULT STDMETHODCALLTYPE Site_OnScriptError(IActiveScriptSite *iface, IActiveScriptError *pse)
{
    HostSite *s = (HostSite *)iface;
    EXCEPINFO ei;
    memset(&ei, 0, sizeof(ei));
    if (pse && SUCCEEDED(IActiveScriptError_GetExceptionInfo(pse, &ei))) {
        WCHAR wmsg[1000] = L"";
        if (ei.bstrDescription) wcsncpy(wmsg, ei.bstrDescription, 999);
        if (ei.bstrSource && wcslen(wmsg) < 900) { wcsncat(wmsg, L" @", 999 - wcslen(wmsg)); wcsncat(wmsg, ei.bstrSource, 999 - wcslen(wmsg)); }
        char msg[2400] = "";
        WideCharToMultiByte(CP_UTF8, 0, wmsg, -1, msg, sizeof(msg), NULL, NULL);
        DWORD ctx = 0; ULONG line = 0; LONG col = 0;
        IActiveScriptError_GetSourcePosition(pse, &ctx, &line, &col);
        char *dst = s->errbuf + strlen(s->errbuf);
        size_t left = sizeof(s->errbuf) - strlen(s->errbuf) - 1;
        snprintf(dst, left, "%s[脚本错误] 行%lu 列%ld: %s", s->errcount ? "; " : "",
                 (unsigned long)line + 1, (long)col + 1, msg);
        s->errcount++;
        SysFreeString(ei.bstrDescription);
        SysFreeString(ei.bstrSource);
        SysFreeString(ei.bstrHelpFile);
    }
    return S_OK;
}
static HRESULT STDMETHODCALLTYPE Site_OnEnterScript(IActiveScriptSite *i) { (void)i; return S_OK; }
static HRESULT STDMETHODCALLTYPE Site_OnLeaveScript(IActiveScriptSite *i) { (void)i; return S_OK; }

static IActiveScriptSiteVtbl g_siteVtbl = {
    Site_QueryInterface, Site_AddRef, Site_Release, Site_GetLCID, Site_GetItemInfo,
    Site_GetDocVersionString, Site_OnScriptTerminate, Site_OnStateChange,
    Site_OnScriptError, Site_OnEnterScript, Site_OnLeaveScript
};

/* --------------------------------------------------- 解析执行的统一包装 ------ */
static HRESULT vm_parse(IActiveScriptParse *parse, const wchar_t *code, VARIANT *pvarResult)
{
    VARIANT v;
    VariantInit(&v);
    HRESULT hr = parse->lpVtbl->ParseScriptText(parse, code, NULL, NULL, NULL, 0, 0,
                                                SCRIPTTEXT_ISVISIBLE, &v, NULL);
    if (pvarResult) *pvarResult = v;
    return hr;
}

/* ================= 前置护栏 + JS 层虚拟宿主（样本最常用的成员全覆盖） ======== */

static const wchar_t *PRELUDE =
L"var __SVM_GUARD__ = 0;\n"
L"var __SVM_MODE__ = 'none';\n"
L"var __SVM_LOG__ = '';\n"
L"var __SVM_N = 0;\n"
L"function __svm_rec(s){ if (__SVM_LOG__.length < 400000) { __SVM_N++; __SVM_LOG__ += s + '\\n'; } }\n"
L"function __svm_args(a){\n"
L"  var s = '';\n"
L"  for (var i = 0; i < a.length; i++) {\n"
L"    var v; try { v = '' + a[i]; } catch (e) { v = '<取不到>'; }\n"
L"    s += (i ? ', ' : '') + '\"' + v.substring(0, 300) + '\"';\n"
L"  }\n"
L"  return s;\n"
L"}\n"
L"function __svm_fake(pid){\n"
L"  var o = {};\n"
L"  var chain = ['Item','Items','Namespace','NameSpace','Self','Properties','Methods','Select','Drive','File','Folder',\n"
L"    'SubFolders','Files','Drives','GetFile','GetFolder','GetSpecialFolder','SpecialFolders','Environment','BuildPath',\n"
L"    'GetExtensionName','GetBaseName','GetParentFolderName','GetAbsolutePathName','GetTempName','GetDrive','GetDriveName',\n"
L"    'Add','Remove','RemoveAll','Exists','Keys','ConnectServer','Get','InstancesOf','ExecQuery','ExecNotificationQuery',\n"
L"    'CreateShortcut','ExpandEnvironmentStrings','AppActivate','SendKeys','Popup','BrowseForFolder','MinimizeAll','UndoMinimizeALL',\n"
L"    'TrayProperties','Window','Document','OpenTextFile','CreateTextFile','CreateFolder','DeleteFolder','MoveFolder',\n"
L"    'CopyFile','DeleteFile','MoveFile','CreateDirectory','SaveToFile','LoadFromFile','Open','Close','Read','ReadAll',\n"
L"    'ReadLine','ReadText','SkipLine','WriteLine','WriteText','Write','Copy','CopyFolder','GetType','Sub','GetFileName'];\n"
L"  for (var i = 0; i < chain.length; i++) {\n"
L"    (function(nm){ o[nm] = function(){ __svm_rec('[虚拟托管] ' + pid + '.' + nm + '(' + __svm_args(arguments) + ')'); return __svm_fake(pid + '.' + nm); }; })(chain[i]);\n"
L"  }\n"
L"  o.Run      = function(){ __svm_rec('[★执行请求] ' + pid + '.Run(' + __svm_args(arguments) + ') —— 被虚拟宿主拦下，未真的执行'); return 0; };\n"
L"  o.Exec     = function(){ __svm_rec('[★执行请求] ' + pid + '.Exec(' + __svm_args(arguments) + ') —— 被虚拟宿主拦下，未真的执行'); return __svm_fake(pid + '.Exec'); };\n"
L"  o.ShellExecute = function(){ __svm_rec('[★执行请求] ' + pid + '.ShellExecute(' + __svm_args(arguments) + ') —— 被虚拟宿主拦下'); };\n"
L"  o.CreateObject = function(n){ __svm_rec('[★COM请求] ' + pid + '.CreateObject(\"' + n + '\") —— 已被虚拟宿主接管'); return __svm_fake('' + n); };\n"
L"  o.GetObject    = function(n){ __svm_rec('[★COM请求] ' + pid + '.GetObject(\"' + n + '\") —— 已被虚拟宿主接管'); return __svm_fake('' + n); };\n"
L"  o.CopyHere = function(){ __svm_rec('[虚拟托管] ' + pid + '.CopyHere(' + __svm_args(arguments) + ')'); };\n"
L"  o.Sleep    = function(){ return; };\n"
L"  o.RegWrite = function(){ __svm_rec('[★写注册表] ' + pid + '.RegWrite(' + __svm_args(arguments) + ')'); };\n"
L"  o.RegDelete= function(){ __svm_rec('[★删注册表] ' + pid + '.RegDelete(' + __svm_args(arguments) + ')'); };\n"
L"  o.open     = function(){ __svm_rec('[★网络请求] ' + pid + '.open(' + __svm_args(arguments) + ')'); };\n"
L"  o.send     = function(){ __svm_rec('[★网络请求] ' + pid + '.send(' + __svm_args(arguments) + ')'); };\n"
L"  o.setRequestHeader = function(){ __svm_rec('[网络请求] ' + pid + '.setRequestHeader(' + __svm_args(arguments) + ')'); };\n"
L"  o.Write    = function(){ __svm_rec('[★写文件] ' + pid + '.Write(' + __svm_args(arguments) + ')'); };\n"
L"  o.WriteText= function(){ __svm_rec('[★写文件] ' + pid + '.WriteText(' + __svm_args(arguments) + ')'); };\n"
L"  o.WriteLine= function(){ __svm_rec('[★写文件] ' + pid + '.WriteLine(' + __svm_args(arguments) + ')'); };\n"
L"  o.DeleteFile = function(){ __svm_rec('[★删文件] ' + pid + '.DeleteFile(' + __svm_args(arguments) + ')'); };\n"
L"  o.SaveToFile = function(){ __svm_rec('[★落地文件] ' + pid + '.SaveToFile(' + __svm_args(arguments) + ')'); };\n"
L"  var vals = { Count:0, Length:0, Size:0, Position:0, status:0, Status:0, readyState:4, Type:1,\n"
L"    FileExists:false, FolderExists:false, DriveExists:false, AtEndOfStream:true, AtEndOfLine:true,\n"
L"    responseText:'', statusText:'', message:'', Text:'', Name:'', Path:'', Charset:'unicode',\n"
L"    ContentType:'', RegRead:'', ExpandEnvironmentStrings:'', BuildPath:'', MachineName:'', Version:'', Line:1, Column:1,\n"
L"    FullName:'', Interactive:true, SpecialFolders:null };\n"
L"  for (var k in vals) o[k] = vals[k];\n"
L"  return o;\n"
L"}\n"
L"/* WSH 的 Enumerator 在裸引擎里不存在；给一个\"空枚举器\"，让样本能顺利走完分支 */\n"
L"if (typeof Enumerator == 'undefined') {\n"
L"  __svm_enum = function(x){ this.__atEnd = true; this.atEnd = function(){ return true; }; this.moveNext = function(){}; this.item = function(){ return __svm_fake('Enumerator.item'); }; };\n"
L"  Enumerator = __svm_enum;\n"
L"}\n"
L"__svm_rec('[虚拟宿主] 前置护栏开始安装');\n"
L"var __svm_g = (function(){ return this; })();\n"
L"var __svm_ax = function(n){ __svm_rec('[★COM请求] ActiveXObject(\"' + n + '\") —— 已被虚拟宿主接管，不会真的创建'); return __svm_fake('' + n); };\n"
L"var __svm_go = function(n){ __svm_rec('[★COM请求] GetObject(\"' + n + '\") —— 已被虚拟宿主接管'); return __svm_fake('' + n); };\n"
L"try {\n"
L"  Object.defineProperty(__svm_g, 'ActiveXObject', { value: __svm_ax, writable: false, configurable: false });\n"
L"  Object.defineProperty(__svm_g, 'GetObject',     { value: __svm_go, writable: false, configurable: false });\n"
L"  __SVM_MODE__ = 'defineProperty 只读锁定';\n"
L"} catch (e1) {\n"
L"  try { ActiveXObject = __svm_ax; GetObject = __svm_go; __SVM_MODE__ = '普通赋值(defineProperty不可用: ' + e1.message + ')'; }\n"
L"  catch (e2) { __SVM_MODE__ = '安装失败: ' + e2.message; }\n"
L"}\n"
L"try { ActiveXObject.__svmToken = 'SVM-JSVM-V1'; } catch (e3) {}\n"
L"WScript = __svm_fake('WScript');\n"
L"__SVM_GUARD__ = 1;\n"
L"__svm_rec('[虚拟宿主] 护栏安装完成，模式=' + __SVM_MODE__);\n";

/* ------------------------------------------------------------- 超时看门狗 --- */

static IActiveScript *g_engine = NULL;
static volatile LONG  g_finished = 0;
static DWORD g_timeoutMs = 5000;
static DWORD g_startTick = 0;
static HostSite *g_site = NULL;

static DWORD WINAPI watchdog(LPVOID param)
{
    (void)param;
    while (!g_finished) {
        Sleep(30);
        if (GetTickCount() - g_startTick > g_timeoutMs) {
            if (g_engine) {
                g_engine->lpVtbl->InterruptScriptThread(g_engine, (SCRIPTTHREADID)0xFFFFFFFF, NULL,
                                                        SCRIPTINTERRUPT_RAISEEXCEPTION);
                if (g_site) g_site->interrupted = TRUE;
            }
            return 0;
        }
    }
    return 0;
}

/* ---------------------------------------------------------------- 读取全局 --- */

static IDispatch *g_scriptDisp = NULL;

static BOOL get_disp_id(const wchar_t *name, DISPID *id)
{
    LPOLESTR nm = (LPOLESTR)name;
    if (!g_scriptDisp) return FALSE;
    return SUCCEEDED(IDispatch_GetIDsOfNames(g_scriptDisp, &g_iidNone, &nm, 1, 0, id));
}
static BOOL read_global_str(const wchar_t *name, wchar_t *out, int cap)
{
    DISPID id;
    out[0] = 0;
    if (!get_disp_id(name, &id)) return FALSE;
    DISPPARAMS dp;
    memset(&dp, 0, sizeof(dp));
    VARIANT v;
    VariantInit(&v);
    if (!SUCCEEDED(IDispatch_Invoke(g_scriptDisp, id, &g_iidNone, 0, DISPATCH_PROPERTYGET, &dp, &v, NULL, NULL)))
        return FALSE;
    BOOL ok = TRUE;
    if (v.vt == VT_BSTR && v.bstrVal) { wcsncpy(out, v.bstrVal, cap - 1); out[cap - 1] = 0; }
    else if (v.vt == VT_EMPTY || v.vt == VT_NULL) out[0] = 0;
    else ok = FALSE;
    VariantClear(&v);
    return ok;
}
static BOOL read_global_num(const wchar_t *name, long *out)
{
    DISPID id;
    if (!get_disp_id(name, &id)) return FALSE;
    DISPPARAMS dp;
    memset(&dp, 0, sizeof(dp));
    VARIANT v;
    VariantInit(&v);
    if (!SUCCEEDED(IDispatch_Invoke(g_scriptDisp, id, &g_iidNone, 0, DISPATCH_PROPERTYGET, &dp, &v, NULL, NULL)))
        return FALSE;
    BOOL ok = (v.vt == VT_I4 || v.vt == VT_I2 || v.vt == VT_UI4 || v.vt == VT_R8 || v.vt == VT_BOOL);
    if (ok) *out = (v.vt == VT_R8) ? (long)v.dblVal : v.lVal;
    VariantClear(&v);
    return ok;
}
/* 读某个全局对象的成员（护栏令牌校验用）：ActiveXObject.__svmToken */
static BOOL read_nested_str(const wchar_t *objName, const wchar_t *member, wchar_t *out, int cap)
{
    DISPID oid;
    out[0] = 0;
    if (!get_disp_id(objName, &oid)) return FALSE;
    DISPPARAMS dp;
    memset(&dp, 0, sizeof(dp));
    VARIANT ov;
    VariantInit(&ov);
    if (!SUCCEEDED(IDispatch_Invoke(g_scriptDisp, oid, &g_iidNone, 0, DISPATCH_PROPERTYGET, &dp, &ov, NULL, NULL)))
        return FALSE;
    BOOL ok = FALSE;
    if (ov.vt == VT_DISPATCH && ov.pdispVal) {
        LPOLESTR nm = (LPOLESTR)member;
        DISPID mid;
        if (SUCCEEDED(IDispatch_GetIDsOfNames(ov.pdispVal, &g_iidNone, &nm, 1, 0, &mid))) {
            DISPPARAMS dp2;
            memset(&dp2, 0, sizeof(dp2));
            VARIANT mv;
            VariantInit(&mv);
            if (SUCCEEDED(IDispatch_Invoke(ov.pdispVal, mid, &g_iidNone, 0, DISPATCH_PROPERTYGET, &dp2, &mv, NULL, NULL))) {
                if (mv.vt == VT_BSTR && mv.bstrVal) { wcsncpy(out, mv.bstrVal, cap - 1); out[cap - 1] = 0; ok = TRUE; }
                VariantClear(&mv);
            }
        }
    }
    VariantClear(&ov);
    return ok;
}

/* ------------------------------------------------------------- 文件工具 ----- */

static char *read_all_utf8(const char *path, long *outLen)
{
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (n <= 0 || n > (64L << 20)) { fclose(f); return NULL; }
    char *b = (char *)malloc((size_t)n + 1);
    if (!b) { fclose(f); return NULL; }
    if (fread(b, 1, (size_t)n, f) != (size_t)n) { free(b); fclose(f); return NULL; }
    b[n] = 0;
    fclose(f);
    if (outLen) *outLen = n;
    return b;
}
static void write_utf8(const char *path, const wchar_t *wtext)
{
    if (!wtext) return;
    int n = WideCharToMultiByte(CP_UTF8, 0, wtext, -1, NULL, 0, NULL, NULL);
    char *b = (char *)malloc((size_t)n + 1);
    if (!b) return;
    WideCharToMultiByte(CP_UTF8, 0, wtext, -1, b, n, NULL, NULL);
    FILE *f = fopen(path, "wb");
    if (f) { fwrite(b, 1, strlen(b), f); fclose(f); }
    free(b);
}

/* ============================== 一次完整的受控执行 ========================== */

typedef struct {
    wchar_t *out;         /* __OUT__：解密器算出来的真实代码 */
    wchar_t *hostlog;     /* __SVM_LOG__：虚拟宿主记下来的行为 */
    int      ok;
    int      reason;      /* 0=正常 4=没有__OUT__ 6=护栏校验失败 */
    DWORD    usedMs;
    int      timedOut;
    wchar_t  guardMode[128];
    int      guardTokOk;
    int      hostCalls;
    char    *errs;
} RunResult;

static int run_script(const char *file, RunResult *rr)
{
    memset(rr, 0, sizeof(*rr));
    g_sitelogLen = 0; g_siteProbes = 0;
    if (g_sitelog) g_sitelog[0] = 0;

    long len = 0;
    char *src = read_all_utf8(file, &len);
    if (!src) { printf("[错误] 读不到文件: %s\n", file); return 2; }

    int wlen = MultiByteToWideChar(CP_UTF8, 0, src, (int)len, NULL, 0);
    wchar_t *wcode = (wchar_t *)malloc((size_t)(wlen + 1) * sizeof(wchar_t));
    if (!wcode) { free(src); return 2; }
    MultiByteToWideChar(CP_UTF8, 0, src, (int)len, wcode, wlen);
    wcode[wlen] = 0;
    free(src);

    CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);

    IActiveScript *eng = NULL;
    HRESULT hr = CoCreateInstance(&CLSID_JScript_, NULL, CLSCTX_INPROC_SERVER, &IID_IActiveScript, (void **)&eng);
    if (FAILED(hr)) { printf("[错误] 无法创建 JScript 引擎 0x%08lX\n", (unsigned long)hr); free(wcode); return 3; }
    g_engine = eng;

    HostSite *site = (HostSite *)calloc(1, sizeof(HostSite));
    site->lpVtbl = &g_siteVtbl;
    site->ref = 1;
    g_site = site;
    eng->lpVtbl->SetScriptSite(eng, (IActiveScriptSite *)site);

    IActiveScriptParse *parse = NULL;
    eng->lpVtbl->QueryInterface(eng, &IID_IActiveScriptParse, (void **)&parse);
    if (!parse) { printf("[错误] 取 IActiveScriptParse 失败\n"); eng->lpVtbl->Release(eng); free(wcode); return 3; }
    parse->lpVtbl->InitNew(parse);

    /* 1) 先装护栏 —— 必须在样本代码之前 */
    vm_parse(parse, PRELUDE, NULL);

    /* 2) 跑样本（这一层通常只是"解密器"：纯字符串算术，没有系统调用） */
    g_startTick = GetTickCount();
    HANDLE wt = CreateThread(NULL, 0, watchdog, NULL, 0, NULL);
    VARIANT vres;
    VariantInit(&vres);
    vm_parse(parse, wcode, &vres);
    eng->lpVtbl->SetScriptState(eng, SCRIPTSTATE_CONNECTED);
    g_finished = 1;
    if (wt) { WaitForSingleObject(wt, 1500); CloseHandle(wt); }
    rr->usedMs = GetTickCount() - g_startTick;
    rr->timedOut = site->interrupted;
    free(wcode);

    /* 3) 取结果 + 校验护栏 */
    eng->lpVtbl->GetScriptDispatch(eng, NULL, &g_scriptDisp);

    long guard = -1;
    read_global_num(L"__SVM_GUARD__", &guard);
    read_global_str(L"__SVM_MODE__", rr->guardMode, 128);
    long nlog = 0;
    read_global_num(L"__SVM_N", &nlog);
    rr->hostCalls = (int)nlog;

    wchar_t tok[128] = L"";
    read_nested_str(L"ActiveXObject", L"__svmToken", tok, 128);
    rr->guardTokOk = (wcscmp(tok, SVM_TOKEN) == 0);

    wchar_t *out = (wchar_t *)calloc(1 << 22, sizeof(wchar_t));      /* 4M 字符 */
    if (out && !read_global_str(L"__OUT__", out, (1 << 22) - 1)) { free(out); out = NULL; rr->reason = 4; }
    else if (out && !out[0]) { rr->reason = 4; }
    rr->out = out;

    wchar_t *hlog = (wchar_t *)calloc(1 << 21, sizeof(wchar_t));     /* 2M 字符 */
    if (hlog) read_global_str(L"__SVM_LOG__", hlog, (1 << 21) - 1);
    rr->hostlog = hlog;

    rr->errs = site->errbuf[0] ? _strdup(site->errbuf) : NULL;

    if (!(guard == 1 && rr->guardTokOk)) { rr->reason = 6; rr->ok = 0; }
    else if (rr->reason == 0) { rr->ok = 1; }

    if (g_scriptDisp) { IDispatch_Release(g_scriptDisp); g_scriptDisp = NULL; }
    parse->lpVtbl->Release(parse);
    eng->lpVtbl->SetScriptState(eng, SCRIPTSTATE_DISCONNECTED);
    eng->lpVtbl->Release(eng);
    g_engine = NULL; g_site = NULL;
    free(site);
    CoUninitialize();
    return rr->ok ? 0 : rr->reason;
}

static void print_run(const RunResult *rr, const char *outPath, const char *callsPath, int once)
{
    char mb[256] = "";
    if (rr->guardMode[0]) WideCharToMultiByte(CP_UTF8, 0, rr->guardMode, -1, mb, sizeof(mb), NULL, NULL);

    printf("[js_vm] 用时 %lu ms%s\n", (unsigned long)rr->usedMs,
           rr->timedOut ? "（触及超时上限，已掐断）" : "");
    printf("[js_vm] 护栏: %s ；令牌校验: %s\n", mb[0] ? mb : "(未安装)",
           rr->guardTokOk ? "吻合" : "★不吻合");
    printf("[js_vm] 虚拟宿主记录: %d 条\n", rr->hostCalls);
    if (rr->errs) printf("[js_vm] %s\n", rr->errs);

    if (rr->reason == 6)      printf("[js_vm] ★ 拒绝采信：护栏校验未通过，本次结果一律丢弃\n");
    else if (rr->reason == 4) printf("[js_vm] [注意] 脚本没有设置 __OUT__（不是解密器层？或提前退出/报错）\n");

    if (rr->out && rr->out[0]) {
        int n = WideCharToMultiByte(CP_UTF8, 0, rr->out, -1, NULL, 0, NULL, NULL);
        char *ob = (char *)malloc((size_t)n + 1);
        if (ob) {
            WideCharToMultiByte(CP_UTF8, 0, rr->out, -1, ob, n, NULL, NULL);
            long olen = (long)strlen(ob);
            if (outPath && !once) {
                FILE *f = fopen(outPath, "wb");
                if (f) { fwrite(ob, 1, (size_t)olen, f); fclose(f); printf("[js_vm] 已写出解密结果 %s (%ld 字节)\n", outPath, olen); }
                else printf("[错误] 写不出 %s\n", outPath);
            } else {
                printf("---- __OUT__ 内容（前 1500 字符）----\n%.1500s\n", ob);
            }
            printf("[js_vm] __OUT__ 长度 %ld 字符\n", olen);
            free(ob);
        }
    } else if (rr->reason == 0) {
        printf("[js_vm] [注意] __OUT__ 为空\n");
    }

    if (callsPath) {
        if (rr->hostlog && rr->hostlog[0]) {
            write_utf8(callsPath, rr->hostlog);
            printf("[js_vm] 已写出行为日志 %s\n", callsPath);
        } else printf("[js_vm] (虚拟宿主没有被调用，也没有环境探测)\n");
    }
    if (g_sitelog && g_sitelog[0] && !callsPath) {
        char *lb = NULL;
        int n = WideCharToMultiByte(CP_UTF8, 0, g_sitelog, -1, NULL, 0, NULL, NULL);
        lb = (char *)malloc((size_t)n + 1);
        if (lb) {
            WideCharToMultiByte(CP_UTF8, 0, g_sitelog, -1, lb, n, NULL, NULL);
            printf("---- 宿主侧环境探测记录（前 600 字符）----\n%.600s\n", lb);
            free(lb);
        }
    }
}

/* ================================== 自检 ==================================== */

static void selftest(void)
{
    SetConsoleOutputCP(CP_UTF8);
    printf("=== js_vm 自检 ===\n");
    printf("  引擎: jscript.dll → CLSID {F414C260-6AC0-11CF-B6D1-00AA00BBBB58}\n");

    const char *probe  = "C:\\Users\\17265\\AppData\\Local\\Temp\\opencode\\_jsvm_selftest.js";
    const char *marker = "C:\\Users\\17265\\AppData\\Local\\Temp\\opencode\\_jsvm_selftest_marker.txt";

    const char *js =
        "var s=''; for(var i=0;i<6;i++){ s += String.fromCharCode(65+i); }\n"
        "var r1='(未测)';\n"
        "try { var fso=new ActiveXObject('Scripting.FileSystemObject');\n"
        "      var ts=fso.CreateTextFile('C:\\\\Users\\\\17265\\\\AppData\\\\Local\\\\Temp\\\\opencode\\\\_jsvm_selftest_marker.txt', true);\n"
        "      ts.WriteLine('pwned'); ts.Close(); r1='虚拟宿主接管成功（未抛异常；是否真写盘看下面硬盘判据）'; }\n"
        "catch(e){ r1='已堵住: ' + e.message; }\n"
        "var r2='(未测)';\n"
        "try { var x=new ActiveXObject('WScript.Shell'); x.Run('calc.exe'); r2='虚拟对象可用（Run 已记录，没真跑）'; }\n"
        "catch(e){ r2='异常: ' + e.message; }\n"
        "__OUT__ = '解密结果=' + s + ' | COM探测=' + r1 + ' | 虚拟对象=' + r2;\n";

    FILE *f = fopen(probe, "wb");
    if (!f) { printf("  无法写自检脚本\n"); return; }
    fwrite(js, 1, strlen(js), f);
    fclose(f);
    DeleteFileA(marker);

    RunResult rr;
    int rc = run_script(probe, &rr);
    printf("\n---- 自检结果 ----\n");
    print_run(&rr, NULL, NULL, 1);

    printf("\n---- 安全判据（看硬盘）----\n");
    if (GetFileAttributesA(marker) != INVALID_FILE_ATTRIBUTES)
        printf("  ★★ 危险：marker 文件存在，COM 后门没堵住\n");
    else
        printf("  安全：marker 文件不存在，真实 COM 未被创建\n");
    printf("  退出码=%d（0=正常，6=护栏校验失败被拒）\n", rc);
    if (rr.out) free(rr.out);
    if (rr.hostlog) free(rr.hostlog);
    if (rr.errs) free(rr.errs);
    DeleteFileA(probe);

    /* 附加探针：样本若 delete ActiveXObject，能不能把真实 COM 换回来？
       该探针只读 typeof，绝不调用，所以即使被删也无副作用。 */
    {
        const char *probe2 = "C:\\Users\\17265\\AppData\\Local\\Temp\\opencode\\_jsvm_selftest2.js";
        const char *js2 =
            "var r='';\n"
            "try { delete ActiveXObject; r += 'delete后 typeof(ActiveXObject)=' + typeof ActiveXObject + '; '; }\n"
            "catch(e){ r += 'delete报错:' + e.message + '; '; }\n"
            "try { var y = (typeof GetObject); r += 'typeof(GetObject)=' + y; } catch(e2){ r += 'GetObject 取不到: ' + e2.message; }\n"
            "__OUT__ = r;\n";
        FILE *f2 = fopen(probe2, "wb");
        if (f2) {
            fwrite(js2, 1, strlen(js2), f2);
            fclose(f2);
            printf("\n---- 附加探针：删除 ActiveXObject 之后 ----\n");
            RunResult r2;
            run_script(probe2, &r2);
            print_run(&r2, NULL, NULL, 1);
            printf("  判据：typeof 变成 undefined/未知 即为安全（真身回不来）；\n");
            printf("        若还是可用的函数，需要人工复核。\n");
            if (r2.out) free(r2.out);
            if (r2.hostlog) free(r2.hostlog);
            if (r2.errs) free(r2.errs);
            DeleteFileA(probe2);
        }
    }
}

/* =================================== main =================================== */

int main(int argc, char **argv)
{
    const char *file = NULL, *outPath = NULL, *callsPath = NULL;
    int timeout = 5000, once = 0;

    sitelog_init();

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--selftest")) { selftest(); sitelog_fini(); return 0; }
        else if (!strcmp(argv[i], "--file") && i + 1 < argc) file = argv[++i];
        else if (!strcmp(argv[i], "--out") && i + 1 < argc) outPath = argv[++i];
        else if (!strcmp(argv[i], "--calls-out") && i + 1 < argc) callsPath = argv[++i];
        else if (!strcmp(argv[i], "--timeout-ms") && i + 1 < argc) timeout = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--once")) once = 1;
        else if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) {
            printf("用法: js_vm.exe --file <js> [--out <txt>] [--calls-out <txt>] [--timeout-ms N] [--once]\n");
            printf("      js_vm.exe --selftest\n\n");
            printf("说明: 在受控 JScript 环境里执行【脚本解密器层】，取回它算出的真实代码（__OUT__）。\n");
            printf("      不提供任何真实宿主对象；引擎内置的 ActiveXObject/GetObject 被前置护栏覆盖；\n");
            printf("      运行后校验护栏令牌，不吻合则拒绝采信（退出码 6）。\n");
            sitelog_fini();
            return 0;
        }
    }
    if (!file) { printf("用法: js_vm.exe --file <js> [--out <txt>] [--calls-out <txt>]\n     js_vm.exe --selftest\n"); sitelog_fini(); return 2; }

    SetConsoleOutputCP(CP_UTF8);
    g_timeoutMs = (DWORD)timeout;

    RunResult rr;
    int rc = run_script(file, &rr);
    print_run(&rr, outPath, callsPath, once);

    if (rr.out) free(rr.out);
    if (rr.hostlog) free(rr.hostlog);
    if (rr.errs) free(rr.errs);
    sitelog_fini();
    return rc;
}
