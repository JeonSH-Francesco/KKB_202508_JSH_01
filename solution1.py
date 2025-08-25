import os, re, time, json, shutil, threading, subprocess
from datetime import datetime, UTC

import psutil, wmi
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import win32con, win32api

# pywin32 일부 빌드에서 누락되는 레지스트리 상수 Fallback 처리
REG_NOTIFY_CHANGE_NAME       = getattr(win32con, "REG_NOTIFY_CHANGE_NAME",  0x00000001)
REG_NOTIFY_CHANGE_LAST_SET   = getattr(win32con, "REG_NOTIFY_CHANGE_LAST_SET",0x00000004)
KEY_WOW64_64KEY              = getattr(win32con, "KEY_WOW64_64KEY", 0x00000100)

# oletools (선택 설치). 없으면 매크로 스캔 건너뜀
try:
    from oletools.olevba import VBA_Parser
    OLETOOLS_OK = True
except Exception:
    OLETOOLS_OK = False

# 환경/정책 
WINDIR = os.path.expandvars(r"%WINDIR%")
WIN32  = os.path.join(WINDIR, "System32").lower()
WOW64  = os.path.join(WINDIR, "SysWOW64").lower()
USER   = os.path.expandvars(r"%USERPROFILE%").lower()
LAPP   = os.path.expandvars(r"%LOCALAPPDATA%").lower()
RAPP   = os.path.expandvars(r"%APPDATA%").lower()
TEMP   = os.path.expandvars(r"%TEMP%").lower()

CFG = {
    "allowed_upfc_paths": [
        os.path.join(WIN32, "upfc.exe"),
        os.path.join(WOW64, "upfc.exe"),
    ],
    "blocked_children_from_word": [
        r"(?i)\bcmd\.exe\b", r"(?i)\bpowershell(\.exe)?\b", r"(?i)\bmshta\.exe\b",
        r"(?i)\bwscript\.exe\b", r"(?i)\bcscript\.exe\b", r"(?i)\bregsvr32\.exe\b",
        r"(?i)\brundll32\.exe\b", r"(?i)\bbitsadmin\.exe\b", r"(?i)\bcertutil\.exe\b",
        r"(?i)\bupfc\.exe\b", r"(?i)\bsystemfailurereporter\.exe\b",
    ],
    "suspicious_ancestor_names": [
        "winword.exe","excel.exe","powerpnt.exe",
        "cmd.exe","powershell.exe","wscript.exe","cscript.exe",
        "mshta.exe","regsvr32.exe","rundll32.exe","systemfailurereporter.exe"
    ],
    "kill_temp_svchost": True,
    "monitor_paths": [
        os.path.join(USER, "desktop"),
        os.path.join(USER, "documents"),
        os.path.join(USER, "downloads"),
    ],
    "office_exts": [".doc", ".docm", ".dotm", ".xlsm", ".pptm"],
    "macro_quarantine": True,
    "waas_services_dir": os.path.join(WINDIR, "WaaS", "Services"),
    "waas_registry_root": r"SYSTEM\WaaS",
    "response": {"kill_process": True, "quarantine_exe": True, "firewall_block_exe": True},
    "quarantine_dir": r"C:\ProgramData\OakakGuard\quarantine",
    "log_file": r"C:\ProgramData\OakakGuard\guard.log",
    "user_writable_roots": [USER, LAPP, RAPP, TEMP],
}

CRITICAL_SYSTEM_BINARIES = {
    "svchost.exe","lsass.exe","services.exe","smss.exe","wininit.exe",
    "csrss.exe","taskhostw.exe","taskhost.exe","rundll32.exe",
    "regsvr32.exe","wuauclt.exe","dllhost.exe"
}

#공통 유틸/로그
def now() -> str:
    return datetime.now(UTC).isoformat()

class Log:
    def __init__(self, p): self.p=p; os.makedirs(os.path.dirname(p), exist_ok=True)
    def write(self, level, msg, **kv):
        rec={"ts":now(),"level":level,"msg":msg,**kv}
        line=json.dumps(rec,ensure_ascii=False); print(line,flush=True)
        try: open(self.p,"a",encoding="utf-8").write(line+"\n")
        except: pass
LOG=Log(CFG["log_file"])

def path_lower(x): return (x or "").strip().lower()
def is_system_dir(path): pl=path_lower(path); return pl.startswith(WIN32) or pl.startswith(WOW64)
def is_user_writable(path): pl=path_lower(path); return any(pl.startswith(r) for r in CFG["user_writable_roots"]) or pl.startswith(USER)
def safe_to_quarantine(path): return (not is_system_dir(path)) and os.path.exists(path)

def quarantine(path):
    try:
        os.makedirs(CFG["quarantine_dir"],exist_ok=True)
        dst=os.path.join(CFG["quarantine_dir"],f"{int(time.time())}_{os.path.basename(path)}")
        shutil.copy2(path,dst); return dst
    except: return None

def block_outbound(exe):
    try:
        subprocess.run(["netsh","advfirewall","firewall","add","rule",
                        f"name=OakakBlock_{os.path.basename(exe)}","dir=out","action=block",f"program={exe}"],
                       capture_output=True,text=True)
    except: pass

# 프로세스 메타
class Intel:
    def __init__(self): self.info={}; self.lock=threading.Lock()
    def upsert(self,pid,name,cmd,exe,ppid):
        with self.lock: self.info[pid]={"pid":pid,"name":(name or "").lower(),"cmd":cmd or "","exe":exe or "","ppid":ppid}
    def get(self,pid): 
        with self.lock: return self.info.get(pid)
INTEL=Intel()

def kill_quarantine_block(pid,reason):
    info=INTEL.get(pid); exe=info.get("exe") if info else ""
    try:
        p=psutil.Process(pid)
        if p.is_running() and CFG["response"]["kill_process"]:
            p.kill(); LOG.write("ALERT","process_killed",pid=pid,name=info["name"],reason=reason)
    except Exception as e: LOG.write("ERROR","kill_failed",pid=pid,err=str(e))
    if CFG["response"]["quarantine_exe"] and safe_to_quarantine(exe):
        dst=quarantine(exe); 
        if dst: LOG.write("WARN","quarantined",src=exe,dst=dst)
    if CFG["response"]["firewall_block_exe"] and exe: block_outbound(exe)

#파일 감시: 매크로
def has_vba(path: str) -> bool:
    if os.path.basename(path).startswith("~$"):  # Office 잠금파일 제외
        return False
    if not OLETOOLS_OK:
        LOG.write("WARN","oletools_not_installed",note="macro scan skipped",file=path)
        return False
    try:
        vp = VBA_Parser(path)
        ok = vp.detect_vba_macros()
        vp.close()
        return ok
    except Exception as e:
        LOG.write("ERROR","olevba_error",file=path,err=str(e))
        return False

class FSHandler(FileSystemEventHandler):
    def __init__(self):
        super().__init__(); self.office_exts=set(CFG["office_exts"])
    def _handle(self,path):
        ext=os.path.splitext(path.lower())[1]
        if ext in self.office_exts:
            time.sleep(0.2)
            if has_vba(path):
                LOG.write("ALERT","office_macro_found",file=path)
                if CFG["macro_quarantine"]:
                    dst=quarantine(path)
                    if dst: LOG.write("WARN","office_quarantined",src=path,dst=dst)
    def on_created(self,e): 
        if not e.is_directory: self._handle(e.src_path)
    def on_modified(self,e): 
        if not e.is_directory: self._handle(e.src_path)

# 조상 프로세스
def get_ancestors_names(ppid,max_depth=6):
    names=[]
    try:
        cur=ppid
        for _ in range(max_depth):
            if cur<=0: break
            p=psutil.Process(cur); names.append(p.name().lower()); cur=p.ppid()
    except: pass
    return names

#프로세스 감시 
def watch_process():
    import pythoncom; pythoncom.CoInitialize()
    try:
        c=wmi.WMI(); watcher=c.Win32_Process.watch_for("creation")
        rx_children=[re.compile(p) for p in CFG["blocked_children_from_word"]]
        bad_ancestors=set(CFG["suspicious_ancestor_names"])
        allowed_upfc=set(p.lower() for p in CFG["allowed_upfc_paths"])
        win_dir_l=WINDIR.lower()
        while True:
            try:
                proc=watcher(); pid=int(proc.ProcessId)
                name=(proc.Caption or "").strip().lower()
                cmd=(proc.CommandLine or "").strip()
                exe=(proc.ExecutablePath or "").strip()
                ppid=int(proc.ParentProcessId or 0)
                INTEL.upsert(pid,name,cmd,exe,ppid)

                parent_name=""; 
                try: parent_name=psutil.Process(ppid).name().lower()
                except: pass
                ancestors=set(get_ancestors_names(ppid))

                #중요 시스템 바이너리 이름이 System32/SysWOW64 외 경로(특히 Temp) → Kill
                if name in CRITICAL_SYSTEM_BINARIES and exe:
                    exe_l=exe.lower()
                    if (not is_system_dir(exe_l)) and is_user_writable(exe_l):
                        LOG.write("ALERT","system_binary_out_of_place",pid=pid,name=name,exe=exe,parent=parent_name)
                        kill_quarantine_block(pid,"system_binary_out_of_place"); continue

                # 사용자 writable 경로 EXE + 나쁜 조상
                if exe and exe.lower().endswith(".exe") and is_user_writable(exe) and (ancestors & bad_ancestors):
                    LOG.write("ALERT","userpath_exec_blocked",pid=pid,exe=exe,parent=parent_name,ancestors=list(ancestors))
                    kill_quarantine_block(pid,"userpath_exec_with_bad_ancestor"); continue

                # Word 스폰 블랙리스트 자식
                if parent_name=="winword.exe":
                    if any(rx.search(name) or rx.search(cmd) for rx in rx_children):
                        LOG.write("ALERT","word_spawn_blocked",parent=parent_name,pid=pid,name=name,cmd=cmd)
                        kill_quarantine_block(pid,"word_spawn_block"); continue

                # upfc.exe 악용
                if name=="upfc.exe":
                    exe_l=exe.lower() if exe else ""
                    in_windows=exe_l.startswith(win_dir_l); allowed=exe_l in allowed_upfc
                    if (ancestors & bad_ancestors) or (not in_windows) or (not allowed):
                        LOG.write("ALERT","suspicious_upfc_exec",pid=pid,exe=exe,parent=parent_name,ancestors=list(ancestors))
                        kill_quarantine_block(pid,"suspicious_upfc")
                    else:
                        LOG.write("INFO","upfc_normal_exec",pid=pid,parent=parent_name,exe=exe)

                # Temp 경로 svchost.exe 특화
                if CFG["kill_temp_svchost"] and name=="svchost.exe":
                    if exe and re.search(r"\\appdata\\local\\temp\\", exe.lower()):
                        LOG.write("ALERT","temp_svchost_blocked",pid=pid,exe=exe,parent=parent_name)
                        kill_quarantine_block(pid,"temp_svchost"); continue

                #SystemFailureReporter.exe (사용자 경로)
                if name=="systemfailurereporter.exe" and exe and is_user_writable(exe):
                    LOG.write("ALERT","sfr_blocked",pid=pid,exe=exe,parent=parent_name)
                    kill_quarantine_block(pid,"systemfailurereporter"); continue

            except Exception as e: LOG.write("ERROR","wmi_error",err=str(e)); time.sleep(1)
    finally: pythoncom.CoUninitialize()

#WaaS Services/Registry 
class WaasWatcher(FileSystemEventHandler):
    def on_created(self,e):
        if not e.is_directory and e.src_path.lower().endswith(".exe"):
            LOG.write("ALERT","waas_exe_created",path=e.src_path)
            dst=quarantine(e.src_path)
            if dst: LOG.write("WARN","waas_quarantined",src=e.src_path,dst=dst)
    def on_modified(self,e):
        if not e.is_directory and e.src_path.lower().endswith(".exe"):
            LOG.write("ALERT","waas_exe_modified",path=e.src_path)

def watch_registry_waas():
    try:
        try:
            h=win32api.RegOpenKeyEx(win32con.HKEY_LOCAL_MACHINE,CFG["waas_registry_root"],0,win32con.KEY_READ|KEY_WOW64_64KEY)
        except: 
            h=win32api.RegOpenKeyEx(win32con.HKEY_LOCAL_MACHINE,CFG["waas_registry_root"],0,win32con.KEY_READ)
    except Exception as e:
        LOG.write("WARN","waas_registry_open_failed",root=CFG["waas_registry_root"],err=str(e)); return
    while True:
        try:
            win32api.RegNotifyChangeKeyValue(h,True,REG_NOTIFY_CHANGE_NAME|REG_NOTIFY_CHANGE_LAST_SET,None,False)
            LOG.write("INFO","waas_registry_changed",root=CFG["waas_registry_root"])
            try:
                i=0
                while True:
                    val=win32api.RegEnumValue(h,i)
                    data=str(val[1]).lower()
                    if data.endswith(".exe"):
                        LOG.write("ALERT","waas_registry_exe_ref",value=val[0],data=data)
                    i+=1
            except OSError: pass
        except Exception as e:
            LOG.write("ERROR","waas_registry_notify_error",err=str(e)); time.sleep(1)


def main():
    obs=Observer()
    for p in CFG["monitor_paths"]:
        if os.path.isdir(p):
            obs.schedule(FSHandler(),p,recursive=True); LOG.write("INFO","watch_fs",path=p)
    if os.path.isdir(CFG["waas_services_dir"]):
        obs.schedule(WaasWatcher(),CFG["waas_services_dir"],recursive=True)
        LOG.write("INFO","watch_waas_services",path=CFG["waas_services_dir"])
    else: LOG.write("WARN","waas_services_dir_missing",path=CFG["waas_services_dir"])
    obs.start()

    threading.Thread(target=watch_registry_waas,daemon=True).start()
    threading.Thread(target=watch_process,daemon=True).start()

    LOG.write("INFO","OakakGuard integrated started",oletools=OLETOOLS_OK)
    try:
        while True: time.sleep(1)
    except KeyboardInterrupt:
        try: obs.stop(); obs.join()
        except: pass

if __name__=="__main__":
    main()

'''
실행 결과
->
{"ts": "2025-08-25T12:54:30.954406+00:00", "level": "INFO", "msg": "watch_fs", 
"path": "c:\\users\\alpha\\desktop"}
{"ts": "2025-08-25T12:54:31.017886+00:00", "level": "INFO", "msg": "watch_fs", 
"path": "c:\\users\\alpha\\documents"}
{"ts": "2025-08-25T12:54:31.330851+00:00", "level": "INFO", "msg": "watch_fs", 
"path": "c:\\users\\alpha\\downloads"}
{"ts": "2025-08-25T12:54:31.560305+00:00", "level": "INFO", "msg": 
"watch_waas_services", "path": "C:\\Windows\\WaaS\\Services"}
{"ts": "2025-08-25T12:54:32.730897+00:00", "level": "INFO", "msg": 
"OakakGuard integrated started", "oletools": true}

{"ts": "2025-08-25T12:56:20.146314+00:00", "level": "ALERT", "msg": 
"word_spawn_blocked", 
"parent": "winword.exe", "pid": 908, "name": "cmd.exe", 
"cmd": "cmd.exe /c %localappdata%\\SystemFailureReporter\\SystemFailureReporter.exe"}
{"ts": "2025-08-25T12:56:20.551087+00:00", "level": "ALERT", "msg": 
"process_killed", "pid": 908, "name": "cmd.exe", "reason": "word_spawn_block"}

{"ts": "2025-08-25T12:56:52.053821+00:00", "level": "ALERT", "msg": 
"system_binary_out_of_place", "pid": 4760, "name": "svchost.exe", 
"exe": "C:\\Users\\Alpha\\Desktop\\Oakak_ransomware\\svchost.exe", 
"parent": "explorer.exe"}

{"ts": "2025-08-25T12:56:52.422142+00:00", "level": "ALERT", "msg": 
"process_killed", "pid": 4760, "name": "svchost.exe", 
"reason": "system_binary_out_of_place"}    

{"ts": "2025-08-25T12:56:53.218057+00:00", "level": "WARN", "msg": 
"quarantined", "src": "C:\\Users\\Alpha\\Desktop\\Oakak_ransomware\\svchost.exe", 
"dst": "C:\\ProgramData\\OakakGuard\\quarantine\\1756126612_svchost.exe"}

'''
