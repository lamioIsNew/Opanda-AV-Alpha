/* trust_check.c -- 数字签名信任检查
 *
 * 思路源于火绒 HipsDaemon 的 isTrustDigitalSigned / check_signed：
 * 有效数字签名 + 已知大厂 -> 视为可信，压误报。
 * 实现两级：
 *   1) WinVerifyTrust(WTD_CHOICE_FILE)     —— 嵌入式 Authenticode 签名；
 *   2) WinVerifyTrust(WTD_CHOICE_CATALOG)  —— 目录(catalog)签名，
 *      Windows 系统文件大多是这种，需 CryptCATAdmin 系列 API 先找 .cat。
 * 签名者名称用 CryptQueryObject + CertGetNameStringW 提取，
 * 再与内置厂商白名单做忽略大小写的子串匹配。
 * 注意：本检查只用于文件模式（有真实路径）；管道模式无路径不可用。
 */
#include "trust_check.h"
#include <windows.h>
#include <wintrust.h>
#include <softpub.h>
#include <wincrypt.h>
#include <mscat.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>

/* DRIVER_ACTION_VERIFY {f750e6c3-38ee-11d1-85e5-00c04fc295ee} */
static const GUID g_driver_action_verify = {
    0xf750e6c3, 0x38ee, 0x11d1,
    { 0x85, 0xe5, 0x00, 0xc0, 0x4f, 0xc2, 0x95, 0xee }
};

/* 厂商白名单：签名者名称的子串（全部小写） */
static const char *trusted_vendors[] = {
    "microsoft", "google", "mozilla", "apple", "adobe", "oracle",
    "intel", "nvidia", "advanced micro devices", "realtek",
    "tencent", "alibaba", "baidu", "duyou", "sogou", "netease",
    "bytedance", "douyin", "huorong", "kingsoft", "qihoo", "360",
    "vmware", "lenovo", "huawei", "xiaomi",
    "valve", "epic games", "jetbrains",
    "kaspersky", "eset", "avast", "avira", "bitdefender",
    "sophos", "symantec", "mcafee", "trend micro", "f-secure",
    /* 中文签名名：同时收录 UTF-8 与 GBK 两种字节形态 */
    "\xE7\x81\xAB\xE7\xBB\x92",       /* 火绒 (UTF-8) */
    "\xBB\xF0\xC8\xDE",               /* 火绒 (GBK) */
    NULL
};

/* ---- 嵌入式签名 ---- */
static int verify_embedded(const wchar_t *wpath) {
    WINTRUST_FILE_INFO fi;
    WINTRUST_DATA wd;
    GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    LONG r;

    memset(&fi, 0, sizeof(fi));
    fi.cbStruct = sizeof(fi);
    fi.pcwszFilePath = wpath;

    memset(&wd, 0, sizeof(wd));
    wd.cbStruct = sizeof(wd);
    wd.dwUIChoice = WTD_UI_NONE;
    wd.fdwRevocationChecks = WTD_REVOKE_NONE;   /* 离线可验证，不查吊销 */
    wd.dwUnionChoice = WTD_CHOICE_FILE;
    wd.pFile = &fi;
    wd.dwStateAction = WTD_STATEACTION_VERIFY;

    r = WinVerifyTrust(NULL, &action, &wd);

    wd.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(NULL, &action, &wd);

    return (r == ERROR_SUCCESS) ? 1 : 0;
}

/* ---- 目录(catalog)签名验证：找 .cat 并验证成员 ----
 * 关键点：WINTRUST_CATALOG_INFO 必须带 pbCalculatedFileHash /
 * cbCalculatedFileHash（预先算好的文件哈希），否则 WinVerifyTrust
 * 会返回 TRUST_E_SUBJECT_FORM_UNKNOWN (0x80096010)。
 */
static int verify_catalog(const wchar_t *wpath, wchar_t *catout, int catoutlen) {
    HANDLE hFile = INVALID_HANDLE_VALUE;
    HCATADMIN hCatAdmin = NULL;
    HCATINFO hCatInfo = NULL;
    HCATINFO hEnum = NULL;
    BYTE hash[64];
    DWORD hashLen = sizeof(hash);
    CATALOG_INFO ci;
    WINTRUST_CATALOG_INFO wci;
    WINTRUST_DATA wd;
    GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    LONG r;
    int ok = 0;

    if (catout && catoutlen > 0) catout[0] = 0;
    hFile = CreateFileW(wpath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return 0;
    if (!CryptCATAdminAcquireContext(&hCatAdmin, &g_driver_action_verify, 0))
        goto done;
    if (!CryptCATAdminCalcHashFromFileHandle(hFile, &hashLen, hash, 0))
        goto done;
    hCatInfo = CryptCATAdminEnumCatalogFromHash(hCatAdmin, hash, hashLen, 0, &hEnum);
    if (!hCatInfo)
        goto done;
    memset(&ci, 0, sizeof(ci));
    ci.cbStruct = sizeof(ci);
    if (!CryptCATCatalogInfoFromContext(hCatInfo, &ci, 0))
        goto done;

    memset(&wci, 0, sizeof(wci));
    wci.cbStruct = sizeof(wci);
    wci.pcwszCatalogFilePath = ci.wszCatalogFile;
    wci.pcwszMemberFilePath = wpath;
    wci.hMemberFile = hFile;
    wci.pbCalculatedFileHash = hash;
    wci.cbCalculatedFileHash = hashLen;

    memset(&wd, 0, sizeof(wd));
    wd.cbStruct = sizeof(wd);
    wd.dwUIChoice = WTD_UI_NONE;
    wd.fdwRevocationChecks = WTD_REVOKE_NONE;
    wd.dwUnionChoice = WTD_CHOICE_CATALOG;
    wd.pCatalog = &wci;
    wd.dwStateAction = WTD_STATEACTION_VERIFY;

    r = WinVerifyTrust(NULL, &action, &wd);

    wd.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(NULL, &action, &wd);

    if (r == ERROR_SUCCESS) {
        if (catout && catoutlen > 0) {
            wcsncpy(catout, ci.wszCatalogFile, (size_t)(catoutlen - 1));
            catout[catoutlen - 1] = 0;
        }
        ok = 1;
    }

done:
    if (hCatInfo && hCatAdmin)
        CryptCATAdminReleaseCatalogContext(hCatAdmin, hCatInfo, 0);
    if (hCatAdmin)
        CryptCATAdminReleaseContext(hCatAdmin, 0);
    if (hFile != INVALID_HANDLE_VALUE)
        CloseHandle(hFile);
    return ok;
}

/* ---- 从 PE 或 .cat 提取签名者显示名 ---- */
static int get_signer_w(const wchar_t *wpath, wchar_t *out, int outlen) {
    HCERTSTORE hStore = NULL;
    HCRYPTMSG hMsg = NULL;
    DWORD encType = 0, contentType = 0, formatType = 0;
    PCMSG_SIGNER_INFO pSigner = NULL;
    DWORD cb = 0;
    CERT_INFO certInfo;
    PCCERT_CONTEXT pCert = NULL;

    if (outlen > 0) out[0] = 0;

    if (!CryptQueryObject(CERT_QUERY_OBJECT_FILE, wpath,
                          CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED |
                          CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
                          CERT_QUERY_FORMAT_FLAG_BINARY, 0,
                          &encType, &contentType, &formatType,
                          &hStore, &hMsg, NULL))
        return 0;

    if (!CryptMsgGetParam(hMsg, CMSG_SIGNER_INFO_PARAM, 0, NULL, &cb))
        goto done;
    pSigner = (PCMSG_SIGNER_INFO)malloc(cb);
    if (!pSigner)
        goto done;
    if (!CryptMsgGetParam(hMsg, CMSG_SIGNER_INFO_PARAM, 0, pSigner, &cb))
        goto done;

    memset(&certInfo, 0, sizeof(certInfo));
    certInfo.Issuer = pSigner->Issuer;
    certInfo.SerialNumber = pSigner->SerialNumber;

    pCert = CertFindCertificateInStore(hStore,
                                       X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                                       0, CERT_FIND_SUBJECT_CERT, &certInfo, NULL);
    if (!pCert)
        goto done;

    CertGetNameStringW(pCert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, out, outlen);

done:
    if (pSigner) free(pSigner);
    if (pCert) CertFreeCertificateContext(pCert);
    if (hStore) CertCloseStore(hStore, 0);
    if (hMsg) CryptMsgClose(hMsg);
    return (outlen > 0 && out[0] != 0) ? 1 : 0;
}

int trust_check_file(const char *filepath, char *signer, int signer_len) {
    wchar_t wpath[MAX_PATH * 2];
    wchar_t signerW[512];
    wchar_t catpath[MAX_PATH];
    char signerA[512];
    char low[512];
    int verified = 0;
    int i, j;

    if (signer && signer_len > 0) signer[0] = '\0';

    if (!MultiByteToWideChar(CP_ACP, 0, filepath, -1,
                             wpath, (int)(sizeof(wpath) / sizeof(wpath[0]))))
        return 0;

    signerA[0] = '\0';
    signerW[0] = 0;

    /* 1) 嵌入式签名 */
    if (verify_embedded(wpath)) {
        verified = 1;
        if (get_signer_w(wpath, signerW, 512) && signerW[0])
            WideCharToMultiByte(CP_UTF8, 0, signerW, -1,
                                signerA, (int)sizeof(signerA), NULL, NULL);
    } else {
        /* 2) 目录签名（系统文件多为 catalog 签名） */
        catpath[0] = 0;
        if (verify_catalog(wpath, catpath, MAX_PATH)) {
            verified = 1;
            if (get_signer_w(catpath, signerW, 512) && signerW[0])
                WideCharToMultiByte(CP_UTF8, 0, signerW, -1,
                                    signerA, (int)sizeof(signerA), NULL, NULL);
        }
    }

    if (!verified)
        return 0;

    if (signer && signer_len > 0)
        snprintf(signer, (size_t)signer_len, "%s", signerA);

    /* 白名单：忽略大小写子串匹配 */
    for (j = 0; signerA[j] && j < (int)sizeof(low) - 1; j++)
        low[j] = (char)tolower((unsigned char)signerA[j]);
    low[j] = '\0';

    for (i = 0; trusted_vendors[i]; i++) {
        if (strstr(low, trusted_vendors[i]))
            return 2;
    }
    return 1;
}
