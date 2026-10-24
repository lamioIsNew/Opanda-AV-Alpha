# -*- coding: utf-8 -*-
r"""
unbox_js.py —— 变形脚本还原器（对应火绒"脚本行为沙盒"里"把脚本问题转成行为问题"那一步）

四步流水线，每步都只做我们能验证的事：

  第一步（纯静态，永不执行）：剥 "\uXXXX 转义 + 字符串拼接" 的 eval 塔
      - 只对**字符串字面量内部**做 JS 转义解码（关键：整篇解码会把字面量拆断）
      - 反复做"相邻字面量拼接折叠"到不动点
      - 逐层剥离 (0,this)["eval"]("<字面量>") 这种外壳

  第二步（受控执行）：剩下的通常是一个"自定义解密器"（纯字符串算术）
      - 把结尾那句  xxx[yyy](zzz);  （原意是 eval(解密结果)）
        改写成          __OUT__ = zzz;
      - 交给 js_vm.exe 跑：不给任何真实宿主对象，ActiveXObject/GetObject 被前置护栏覆盖
      - 取回 zzz，也就是被藏起来的真实代码

  第三步（虚拟执行）：把还原出来的真实代码**再放进 js_vm 跑一遍**
      - 它这次会去调 WScript.Shell.Run / XMLHTTP / ADODB.Stream / FSO …
      - 全部落到虚拟宿主上：只记一行行为日志，什么都不真做
      - 这就是"脚本行为证据"的来源

  第四步（解码取证）：把还原代码里剩下的 \uXXXX 字面量解开，抽 IOC
      - 下载 URL、落地文件名、命令行、ProgID、环境变量
      - 输出一份中文报告

用法:
  python unbox_js.py "<样本路径>" "<工作目录>" [--run-seconds N]
"""
import re
import sys
import os
import subprocess

sys.stdout.reconfigure(encoding='utf-8')

# 优先用与本脚本同目录的 js_vm.exe（交付后自包含），找不到再回退到开发目录
_HERE = os.path.dirname(os.path.abspath(__file__))
JS_VM = os.path.join(_HERE, 'js_vm.exe')
if not os.path.exists(JS_VM):
    JS_VM = r'F:\SVM项目\behavior\hvm\js_vm.exe'

LIT = re.compile(r'"((?:[^"\\]|\\.)*)"')
CONCAT = re.compile(r'"((?:[^"\\]|\\.)*)"\s*\+\s*"((?:[^"\\]|\\.)*)"')
SIMPLE = {'b': '\b', 'f': '\f', 'n': '\n', 'r': '\r', 't': '\t', 'v': '\v', '0': '\0',
          '\\': '\\', '/': '/', '"': '"', "'": "'"}


def js_unescape(raw):
    """按 JS 字符串字面量转义规则解码（输入是字面量内部原始文本，不含两端引号）"""
    out = []
    i, n = 0, len(raw)
    while i < n:
        c = raw[i]
        if c == '\\' and i + 1 < n:
            k = raw[i + 1]
            if k == 'u':
                try:
                    out.append(chr(int(raw[i + 2:i + 6], 16)))
                    i += 6
                    continue
                except ValueError:
                    pass
            if k == 'x':
                try:
                    out.append(chr(int(raw[i + 2:i + 4], 16)))
                    i += 4
                    continue
                except ValueError:
                    pass
            if k in SIMPLE:
                out.append(SIMPLE[k])
                i += 2
                continue
            out.append(k)
            i += 2
            continue
        out.append(c)
        i += 1
    return ''.join(out)


def js_escape(v):
    return (v.replace('\\', '\\\\').replace('"', '\\"')
             .replace('\n', '\\n').replace('\r', '\\r').replace('\t', '\\t'))


def fold_concat(s, cap=500000):
    for _ in range(cap):
        s2 = CONCAT.sub(lambda m: '"' + m.group(1) + m.group(2) + '"', s)
        if s2 == s:
            return s
        s = s2
    return s


def decode_literals(src):
    """把代码里所有字符串字面量的 \\uXXXX 解开（重新转义，保持可读且仍是合法 JS）"""
    return LIT.sub(lambda m: '"' + js_escape(js_unescape(m.group(1))) + '"', src)


def peel_eval_tower(raw, maxlayers=40):
    cur = raw
    log = [len(raw)]
    for _ in range(maxlayers):
        folded = fold_concat(cur)
        i0 = folded.find('("')
        j0 = folded.rfind('")')
        if i0 < 0 or j0 <= i0 + 2 or j0 < len(folded) - 4:
            break
        inner = js_unescape(folded[i0 + 2:j0])
        if len(inner) < 20 or inner == cur:
            break
        cur = inner
        log.append(len(cur))
    return cur, log


TAIL_CALL = re.compile(r'([A-Za-z_$][\w$]*)\s*\[([A-Za-z_$][\w$]*)\]\s*\(\s*([A-Za-z_$][\w$]*)\s*\)\s*;\s*$')
TAIL_CALL2 = re.compile(r'([A-Za-z_$][\w$]*)\s*\(\s*([A-Za-z_$][\w$]*)\s*\)\s*;\s*$')


def rewrite_tail(src):
    m = TAIL_CALL.search(src)
    if m:
        return src[:m.start()] + '__OUT__ = %s;' % m.group(3), 'xxx[yyy](zzz)'
    m = TAIL_CALL2.search(src)
    if m:
        return src[:m.start()] + '__OUT__ = %s;' % m.group(2), 'yyy(zzz)'
    return None, None


def run_js_vm(jsfile, outfile, callsfile, run_seconds=15):
    if not os.path.exists(JS_VM):
        return None, '找不到 js_vm.exe: ' + JS_VM
    cmd = [JS_VM, '--file', jsfile, '--out', outfile, '--calls-out', callsfile,
           '--timeout-ms', str(int(run_seconds * 1000))]
    try:
        p = subprocess.run(cmd, capture_output=True, timeout=run_seconds + 90)
    except subprocess.TimeoutExpired:
        return None, 'js_vm 超时（进程级）'
    out = (p.stdout or b'').decode('utf-8', 'replace')
    err = (p.stderr or b'').decode('utf-8', 'replace')
    return out + err, None


# ------------------------------------------------------------------ 第四步 ----

IOC_URL = re.compile(r'(?:https?|ftp)://[^\s"\'\\<>\)\]}{,;]+', re.I)
IOC_FILE = re.compile(r'[A-Za-z0-9_\-\$\{\}\u4e00-\u9fff]+\.[A-Za-z0-9]{1,5}\b')
CALL_RUN = re.compile(r'\.(?:Run|Exec)\(\s*([^)]{0,220})\)')
CALL_SHELLEXEC = re.compile(r'ShellExecute(?:A|W)?\(\s*([^)]{0,220})\)')
STR_CMD = re.compile(r'"([^"]*(?:msiexec|rundll32|regsvr32|powershell|cmd\.exe|wscript|cscript|schtasks'
                     r'|bitsadmin|certutil|/qn|/c\s)[^"]*)"', re.I)
IOC_PROGID = re.compile(r'\b(?:WScript\.Shell|Scripting\.FileSystemObject|Scripting\.Dictionary|Shell\.Application'
                        r'|ADODB\.Stream|ADODB\.Connection|WinHttp\.WinHttpRequest(?:\.\d+(?:\.\d+)?)?'
                        r'|MSXML2?\.(?:ServerXMLHTTP|XMLHTTP)(?:\.\d+(?:\.\d+)?)?|Microsoft\.XMLHTTP'
                        r'|WbemScripting\.SWbemLocator|WbemScripting\.SWbemServices|Schedule\.Service|Outlook\.Application'
                        r'|Excel\.Application|Word\.Application|Scripting\.Signer|WScript\.Network)\b', re.I)
IOC_ENV = re.compile(r'%[A-Za-z_][A-Za-z0-9_]*%')
IOC_SPECIAL = re.compile(r'GetSpecialFolder"?\]?\(\s*(\d)\s*\)')

EXT_INTEREST = {'.exe', '.dll', '.msi', '.zip', '.bin', '.ps1', '.vbs', '.vbe', '.js', '.jse', '.hta', '.bat',
                '.cmd', '.scr', '.cpl', '.lnk', '.rar', '.7z', '.dat', '.tmp', '.txt', '.url', '.wsf'}


def uniq(seq):
    return list(dict.fromkeys(seq))


JUNK_FILES = {'hit.exe', 'hit.msi', 'best.exe', 'best.msi'}
LINE_KEYS = ('"Run"', '"Exec"', 'ShellExecute', 'msiexec', 'CopyHere', 'SaveToFile', 'CreateFolder"',
             'DeleteFile"', 'DeleteFolder"', '"open"', '"send"', 'GetSpecialFolder', 'SubFolders',
             'Files"', 'CurrentDirectory', 'GetParentFolderName')


def behavior_lines(text, limit=20):
    out, seen = [], set()
    for line in text.splitlines():
        s = line.strip()
        if any(k in s for k in LINE_KEYS):
            if s not in seen and len(out) < limit:
                out.append(s[:220])
                seen.add(s)
    return out


def ioc_report(text):
    urls = uniq(IOC_URL.findall(text))
    files = [f for f in uniq(IOC_FILE.findall(text))
             if os.path.splitext(f)[1].lower() in EXT_INTEREST and f.lower() not in JUNK_FILES]
    cmds = uniq([c.strip() for c in CALL_SHELLEXEC.findall(text)] +
                [c.strip() for c in STR_CMD.findall(text)])
    progids = uniq(IOC_PROGID.findall(text))
    envs = uniq(IOC_ENV.findall(text))
    special = uniq(IOC_SPECIAL.findall(text))
    return urls, files, cmds, progids, envs, special


def process(sample, workdir, run_seconds=15):
    os.makedirs(workdir, exist_ok=True)
    name = os.path.basename(sample)
    rep = []
    P = lambda s='': (print(s), rep.append(s))

    P('#' * 78)
    P('# 样本: %s' % name)
    P('#' * 78)

    with open(sample, 'rb') as f:
        raw = f.read().decode('latin1')
    P('原始大小: %d 字符   扩展名: %s' % (len(raw), os.path.splitext(name)[1]))

    # ---- 第一步：静态剥壳 ----
    layer, sizes = peel_eval_tower(raw)
    P('第一步 静态剥壳: %s   → 最内层 %d 字符' % (sizes, len(layer)))
    lp = os.path.join(workdir, 'layer_final.js')
    open(lp, 'w', encoding='utf-8', newline='').write(layer)

    # ---- 第二步：受控跑解密器 ----
    rewritten, how = rewrite_tail(layer)
    if not rewritten:
        P('第二步 [!] 结尾不是可识别的调用，跳过受控执行')
        return
    P('第二步 改写结尾调用（形态 %s）→ __OUT__ = <结果>' % how)
    rp = os.path.join(workdir, 'layer_rewritten.js')
    open(rp, 'w', encoding='utf-8', newline='').write(rewritten)

    outfile = os.path.join(workdir, 'recovered.txt')
    callsfile = os.path.join(workdir, 'calls_decryptor.txt')
    log, err = run_js_vm(rp, outfile, callsfile, run_seconds)
    if err:
        P('  [!] %s' % err)
        return
    for line in log.strip().splitlines():
        if line.strip():
            P('  ' + line.strip())

    if not os.path.exists(outfile):
        P('  [!] 没拿到解密结果')
        return
    rec = open(outfile, 'rb').read().decode('utf-8', 'replace')
    recf = os.path.join(workdir, 'recovered_full.txt')
    open(recf, 'w', encoding='utf-8', newline='').write(rec)
    P('  还原出真实代码 %d 字符 → %s' % (len(rec), recf))

    # ---- 第三步：把真实代码再放进虚拟执行，记行为 ----
    rp2 = os.path.join(workdir, 'recovered_run.js')
    open(rp2, 'w', encoding='utf-8', newline='').write(rec)
    behfile = os.path.join(workdir, 'behavior.txt')
    behlog, err2 = run_js_vm(rp2, os.path.join(workdir, '_recovered_out.txt'), behfile, run_seconds)
    P('第三步 虚拟执行（%d 秒上限）:' % run_seconds)
    if err2:
        P('  [!] %s' % err2)
    else:
        for line in behlog.strip().splitlines():
            if line.strip():
                P('  ' + line.strip())
        if os.path.exists(behfile):
            beh = open(behfile, 'rb').read().decode('utf-8', 'replace')
            key = [l for l in beh.splitlines() if '★' in l]
            P('  --- 提取到的高价值行为（%d 条）---' % len(key))
            seen = set()
            for l in key:
                if l not in seen:
                    P('      ' + l)
                    seen.add(l)

    # ---- 第四步：解码取证 ----
    dec = decode_literals(rec)
    decf = os.path.join(workdir, 'recovered_decoded.js')
    open(decf, 'w', encoding='utf-8', newline='').write(dec)
    urls, files, cmds, progids, envs, special = ioc_report(dec)
    P('第四步 解码取证（%s）' % decf)
    if urls:
        P('  【下载地址】')
        for u in urls:
            P('      ' + u)
    if envs:
        P('  【用到的事件变量】%s' % ', '.join(envs))
    if special:
        P('  【GetSpecialFolder 取值】%s （2=临时目录, 0=Windows, 1=System32, 5=桌面, 7=启动）' % ', '.join(special))
    if files:
        P('  【落地/涉及文件名】%s' % ', '.join(files[:25]))
    if progids:
        P('  【COM 组件】%s' % ', '.join(progids))
    bl = behavior_lines(dec)
    if bl:
        P('  【行为相关代码行（原样摘录，来自还原后的代码）】')
        for l in bl:
            P('      ' + l)
    anti = []
    for k, label in [('wscript', '检测是否在 wscript.exe 下运行（反自动化）'),
                     ('Interactive', '关闭脚本交互（反弹窗/反提示）'),
                     ('new Date().getTime()', '基于时间差的等待/超时循环（反沙箱、拉长分析时间）'),
                     ('Sleep', 'ActiveXObject 休眠（反沙箱）'),
                     ('FullName', '读取宿主完整路径做环境判定')]:
        if k.lower() in dec.lower():
            anti.append(label)
    if anti:
        P('  【反沙箱/反分析手法】')
        for a in uniq(anti):
            P('      ' + a)

    repf = os.path.join(workdir, 'report.txt')
    open(repf, 'w', encoding='utf-8', newline='').write('\n'.join(rep) + '\n')
    print('\n报告已存: %s' % repf)


if __name__ == '__main__':
    args = [a for a in sys.argv[1:] if not a.startswith('--')]
    run_sec = 15
    for i, a in enumerate(sys.argv):
        if a == '--run-seconds' and i + 1 < len(sys.argv):
            run_sec = int(sys.argv[i + 1])
    if len(args) < 2:
        print('用法: python unbox_js.py "<样本路径>" "<工作目录>" [--run-seconds N]')
        sys.exit(2)
    process(args[0], args[1], run_sec)
