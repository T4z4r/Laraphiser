#!/usr/bin/env python3
"""
LaraPhiser v2.0 – Laravel OWASP Scanner
Now with 15+ Laravel‑specific security tests
+ Per‑category intensity: Normal / Medium / Hard
"""

import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import threading
import time
import stat
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path

# Auto-install deps
def try_install(pkg):
    try:
        __import__(pkg.replace("-", "_"))
    except ImportError:
        subprocess.check_call([sys.executable, "-m", "pip", "install", pkg], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

for pkg in ("bandit", "colorama", "tqdm", "tkinterdnd2"):
    try_install(pkg)

from colorama import init as colorama_init
colorama_init()

from tkinter import (
    Tk, Text, Scrollbar, Button, Frame, Label, filedialog,
    messagebox, StringVar, BooleanVar, BOTH, LEFT, RIGHT, X, Y, END, NORMAL, DISABLED,
    Checkbutton, Toplevel, Radiobutton
)
from tkinter.ttk import Progressbar, Treeview

# -------------------------------
# Banner
# -------------------------------
BANNER = r"""
   __                  ____  __    _    __ 
  / /   ____ _____  __/ __ \/ /_  (_)  / /_
 / /   / __ `/ __ \/ __\ \/ __ \/ /  / __/
 / /___/ /_/ / /_/ / /___/ / /_/ / /  / /_  
 \____/\__,_/ .___/\__/_/ /_.___/_/   \__/  
           /_/        Laravel Security Scanner v2.0
"""

# -------------------------------
# OWASP + Intensity
# -------------------------------
OWASP_CATEGORIES = {
    "A01": "Broken Access Control",
    "A02": "Cryptographic Failures",
    "A03": "Injection",
    "A05": "Security Misconfiguration",
    "A07": "Identification and Authentication Failures",
    "A08": "Software and Data Integrity Failures",
    "A09": "Security Logging and Monitoring Failures",
    "A10": "Server-Side Request Forgery (SSRF)",
}

INTENSITY_LEVELS = ["Normal", "Medium", "Hard"]

# -------------------------------
# 15+ Laravel‑Specific Rules
# -------------------------------
REGEX_RULES = {
    # A01 – Broken Access Control
    "MASS_ASSIGN_ALL":    {"desc": "Mass assignment with $request->all()", "pattern": re.compile(r"\b(create|update)\s*\(\s*\$[^;]*->all\(\)", re.I)},
    "MODEL_NO_GUARD":     {"desc": "Model missing $fillable or $guarded", "pattern": re.compile(r"class\s+\w+\s+extends\s+Model(?![^}]*\$(fillable|guarded))", re.I)},
    "ROUTE_RESOURCE":     {"desc": "Full Route::resource() exposed", "pattern": re.compile(r"Route::resource\([^)]*\)", re.I)},
    "STORAGE_NO_VALIDATE":{"desc": "Storage::put without validation", "pattern": re.compile(r"Storage::put\([^)]*->file\([^)]*\)", re.I)},
    "FILE_UPLOAD":        {"desc": "move_uploaded_file()", "pattern": re.compile(r"\bmove_uploaded_file\s*\(", re.I)},

    # A02 – Cryptographic Failures
    "ENV_SECRET":         {"desc": "Hardcoded secret in .env", "pattern": re.compile(r"(APP_KEY|DB_PASSWORD|AWS_SECRET_ACCESS_KEY)\s*[:=]\s*['\"]?[A-Za-z0-9\-_+=/]{8,}['\"]?", re.I)},
    "LONG_BASE64":        {"desc": "Long base64 token", "pattern": re.compile(r"[A-Za-z0-9+\/=]{40,}")},
    "PHP_CRED":           {"desc": "Hardcoded password", "pattern": re.compile(r"password\s*=>\s*['\"][^'\"]{6,}", re.I)},
    "TOKEN_IN_VIEW":      {"desc": "Bearer token in Blade", "pattern": re.compile(r"Bearer\s+[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+", re.I)},

    # A03 – Injection
    "SQL_CONCAT":         {"desc": "SQL string concat", "pattern": re.compile(r"\b(query|exec)\b.*\.\s*\$[_A-Za-z]", re.I)},
    "DB_RAW":             {"desc": "DB::raw() with user input", "pattern": re.compile(r"DB::raw\([^)]*\$[_A-Za-z]", re.I)},
    "PHP_EVAL":           {"desc": "eval()/assert()", "pattern": re.compile(r"\b(eval|assert)\s*\(", re.I)},
    "SYSTEM_CALL":        {"desc": "system()/exec()", "pattern": re.compile(r"\b(system|exec|shell_exec|passthru)\s*\(", re.I)},

    # A05 – Security Misconfiguration
    "CSRF_MISSING":       {"desc": "Form missing @csrf", "pattern": re.compile(r"<form[^>]*>(?!.*@csrf)", re.I)},
    "DEBUG_ON":           {"desc": "APP_DEBUG=true", "pattern": re.compile(r"APP_DEBUG\s*=\s*true", re.I)},
    "PHPINFO":            {"desc": "phpinfo() call", "pattern": re.compile(r"phpinfo\s*\(\s*\)", re.I)},
    "TELESCOPE_ROUTE":    {"desc": "Telescope enabled", "pattern": re.compile(r"TelescopeServiceProvider", re.I)},
    "CACHE_FILE_PROD":    {"desc": "File cache in prod", "pattern": re.compile(r"CACHE_DRIVER\s*=\s*file", re.I)},
    "ARTISAN_EXPOSED":    {"desc": "artisan script executable", "pattern": re.compile(r"", re.I)},  # runtime
    "WORLD_WRITABLE":     {"desc": "World-writable dir", "pattern": re.compile(r"", re.I)},  # runtime

    # A07 – Auth
    "PASSWORD_NO_HASH":   {"desc": "Password without Hash::make", "pattern": re.compile(r"\$user->password\s*=\s*(?!Hash::make|bcrypt)", re.I)},

    # A10 – SSRF
    "POTENTIAL_SSRF":     {"desc": "Remote URL in file_get_contents/curl", "pattern": re.compile(r"\b(file_get_contents|curl_exec)\s*\(.*(http|https):", re.I)},
    "HEADER_INJECTION":   {"desc": "Header injection", "pattern": re.compile(r"\bheader\([^;]*http", re.I)},
    "OPEN_REDIRECT":      {"desc": "Open redirect via input", "pattern": re.compile(r"redirect\([^)]*->input\([^)]*['\"]next['\"]", re.I)},
}

# Map rule → OWASP
RULE_TO_OWASP = {
    "MASS_ASSIGN_ALL": "A01", "MODEL_NO_GUARD": "A01", "ROUTE_RESOURCE": "A01", "STORAGE_NO_VALIDATE": "A01", "FILE_UPLOAD": "A01",
    "ENV_SECRET": "A02", "LONG_BASE64": "A02", "PHP_CRED": "A02", "TOKEN_IN_VIEW": "A02",
    "SQL_CONCAT": "A03", "DB_RAW": "A03", "PHP_EVAL": "A03", "SYSTEM_CALL": "A03",
    "CSRF_MISSING": "A05", "DEBUG_ON": "A05", "PHPINFO": "A05", "TELESCOPE_ROUTE": "A05", "CACHE_FILE_PROD": "A05",
    "PASSWORD_NO_HASH": "A07",
    "POTENTIAL_SSRF": "A10", "HEADER_INJECTION": "A10", "OPEN_REDIRECT": "A10",
}

# Intensity rule sets
RULE_SETS = {
    "A01": {
        "Normal": ["FILE_UPLOAD"],
        "Medium": ["FILE_UPLOAD", "MASS_ASSIGN_ALL", "STORAGE_NO_VALIDATE"],
        "Hard":   ["FILE_UPLOAD", "MASS_ASSIGN_ALL", "STORAGE_NO_VALIDATE", "MODEL_NO_GUARD", "ROUTE_RESOURCE"]
    },
    "A02": {
        "Normal": ["ENV_SECRET"],
        "Medium": ["ENV_SECRET", "LONG_BASE64"],
        "Hard":   ["ENV_SECRET", "LONG_BASE64", "PHP_CRED", "TOKEN_IN_VIEW"]
    },
    "A03": {
        "Normal": ["SQL_CONCAT"],
        "Medium": ["SQL_CONCAT", "PHP_EVAL"],
        "Hard":   ["SQL_CONCAT", "PHP_EVAL", "SYSTEM_CALL", "DB_RAW"]
    },
    "A05": {
        "Normal": [],
        "Medium": ["CSRF_MISSING"],
        "Hard":   ["CSRF_MISSING", "DEBUG_ON", "PHPINFO", "TELESCOPE_ROUTE", "CACHE_FILE_PROD"]
    },
    "A07": {
        "Normal": [],
        "Medium": [],
        "Hard":   ["PASSWORD_NO_HASH"]
    },
    "A10": {
        "Normal": ["POTENTIAL_SSRF"],
        "Medium": ["POTENTIAL_SSRF", "HEADER_INJECTION"],
        "Hard":   ["POTENTIAL_SSRF", "HEADER_INJECTION", "OPEN_REDIRECT"]
    },
}

BANDIT_TO_OWASP = {
    "B101":"A01","B301":"A01","B307":"A01","B310":"A01","B314":"A01",
    "B602":"A01","B603":"A01","B605":"A01","B607":"A01",
    "B303":"A02","B304":"A02","B305":"A02","B324":"A02",
    "B608":"A03","B610":"A03","B611":"A03",
    "B105":"A05","B106":"A05","B107":"A05","B108":"A05",
    "B323":"A07",
    "B311":"A08","B312":"A08","B313":"A08",
    "B112":"A09","B113":"A09",
    "B501":"A10",
}

# -------------------------------
# Main App
# -------------------------------
class LaraPhiser:
    def __init__(self, root):
        self.root = root
        self.root.title("LaraPhiser v2.0 – Ultimate Laravel Scanner")
        self.root.configure(bg="#000000")
        self.root.geometry("1350x820")
        self.root.minsize(1150, 680)

        self.font = ("Consolas", 11)
        self.bold = ("Consolas", 11, "bold")
        self.title = ("Consolas", 24, "bold")

        self.target_path = None
        self.scan_thread = None
        self.stop_event = threading.Event()
        self.all_issues = []
        self.max_workers = min(16, (os.cpu_count() or 2) * 2)

        self.selected_owasp = {k: BooleanVar(value=False) for k in OWASP_CATEGORIES}
        self.intensity_var = {k: StringVar(value="Normal") for k in OWASP_CATEGORIES}

        self.setup_ui()
        threading.Thread(target=self.animate_banner, daemon=True).start()

    def setup_ui(self):
        Label(self.root, text="LaraPhiser v2.0", font=self.title, fg="#00ff00", bg="#000000").pack(pady=10)

        self.banner = Text(self.root, height=8, bg="#000000", fg="#00ff00", font=self.font, relief="flat")
        self.banner.pack(pady=5)
        self.banner.config(state=DISABLED)

        ctrl = Frame(self.root, bg="#000000")
        ctrl.pack(pady=10, fill=X, padx=20)

        btn_style = {
            "font": self.bold, "bg": "#0a0a0a", "fg": "lime",
            "activebackground": "#004400", "relief": "raised", "padx": 12, "pady": 6
        }

        Button(ctrl, text="Select Folder", command=self.select_folder, **btn_style).pack(side=LEFT, padx=5)
        Button(ctrl, text="OWASP & Intensity", command=self.open_selector, **btn_style).pack(side=LEFT, padx=5)
        Button(ctrl, text="Start Scan", command=self.start_scan, **btn_style).pack(side=LEFT, padx=5)
        Button(ctrl, text="Stop Scan", command=self.cancel_scan, **btn_style).pack(side=LEFT, padx=5)
        Button(ctrl, text="Export HTML", command=self.export_html, **btn_style).pack(side=LEFT, padx=5)
        Button(ctrl, text="Clear", command=self.clear_log, **btn_style).pack(side=LEFT, padx=5)

        self.path_var = StringVar(value="No folder selected")
        Label(ctrl, textvariable=self.path_var, font=self.font, fg="#00ff66", bg="#000000", anchor="w").pack(side=LEFT, fill=X, expand=True, padx=10)

        self.progress = Progressbar(self.root, mode="determinate", length=950)
        self.progress.pack(pady=10)

        log_frame = Frame(self.root, bg="#000000")
        log_frame.pack(fill=BOTH, expand=True, padx=20, pady=10)

        self.log = Text(log_frame, bg="#000000", fg="#00ff00", font=self.font, wrap="word", relief="sunken")
        vbar = Scrollbar(log_frame, command=self.log.yview)
        self.log.config(yscrollcommand=vbar.set)
        self.log.pack(side=LEFT, fill=BOTH, expand=True)
        vbar.pack(side=RIGHT, fill=Y)
        self.log.config(state=DISABLED)

        self.results_frame = Frame(self.root, bg="#000000")
        self.tree = Treeview(self.results_frame, columns=("file","line","cat","intensity","desc","rule"), show="headings")
        for c, w in zip(("file","line","cat","intensity","desc","rule"), (420,70,110,100,420,130)):
            self.tree.heading(c, text=c.title())
            self.tree.column(c, width=w, anchor="w" if c != "line" else "center")
        self.tree.bind("<Double-1>", self.on_double_click)

        try:
            from tkinterdnd2 import DND_FILES, TkinterDnD
            self.root.drop_target_register(DND_FILES)
            self.root.dnd_bind('<<Drop>>', self.on_drop)
        except:
            pass

    def log_msg(self, text, color="#00ff00"):
        ts = datetime.now().strftime("%H:%M:%S")
        self.log.config(state=NORMAL)
        tag = color.replace("#", "")
        self.log.insert(END, f"[{ts}] {text}\n", tag)
        self.log.tag_config(tag, foreground=color)
        self.log.see(END)
        self.log.config(state=DISABLED)
        self.root.update_idletasks()

    def animate_banner(self):
        self.banner.config(state=NORMAL)
        self.banner.delete(1.0, END)
        for line in BANNER.strip().splitlines():
            self.banner.insert(END, line + "\n")
            self.banner.update()
            time.sleep(0.05)
        self.banner.insert(END, "\n15+ Laravel‑Specific Tests | Intensity Control | Full OWASP\n")
        self.banner.config(state=DISABLED)

    def open_selector(self):
        dialog = Toplevel(self.root)
        dialog.title("Select OWASP & Intensity")
        dialog.geometry("560x500")
        dialog.configure(bg="#000000")
        dialog.transient(self.root)
        dialog.grab_set()

        Label(dialog, text="Select categories and scan depth:", font=self.bold, fg="#00ff00", bg="#000000").pack(pady=12)

        frame = Frame(dialog, bg="#000000")
        frame.pack(fill=BOTH, expand=True, padx=25)

        for code, name in OWASP_CATEGORIES.items():
            row = Frame(frame, bg="#000000")
            row.pack(fill=X, pady=3)

            cb = Checkbutton(row, variable=self.selected_owasp[code], bg="#000000", fg="#00ff66", selectcolor="#003300")
            cb.pack(side=LEFT)

            Label(row, text=f"{code} – {name}", font=self.font, fg="#00ff66", bg="#000000").pack(side=LEFT, padx=(0,15))

            intensity_frame = Frame(row, bg="#000000")
            intensity_frame.pack(side=RIGHT)

            for level in INTENSITY_LEVELS:
                Radiobutton(
                    intensity_frame, text=level, variable=self.intensity_var[code],
                    value=level, bg="#000000", fg="#00ffaa", selectcolor="#003300",
                    font=("Consolas", 10)
                ).pack(side=LEFT)

        Button(dialog, text="Done", command=dialog.destroy, font=self.bold, bg="#0a0a0a", fg="lime").pack(pady=15)

    def get_scan_config(self):
        config = {}
        for code in OWASP_CATEGORIES:
            if self.selected_owasp[code].get():
                intensity = self.intensity_var[code].get()
                config[code] = {"intensity": intensity, "rules": RULE_SETS.get(code, {}).get(intensity, [])}
        return config

    def select_folder(self):
        folder = filedialog.askdirectory()
        if folder:
            self.target_path = Path(folder)
            self.path_var.set(str(self.target_path))
            self.log_msg(f"Loaded: {self.target_path}", "#00ff66")

    def on_drop(self, event):
        path = event.data.strip("{}")
        if os.path.isdir(path):
            self.target_path = Path(path)
            self.path_var.set(str(self.target_path))
            self.log_msg(f"Dropped: {self.target_path}", "#00ff66")

    def clear_log(self):
        self.log.config(state=NORMAL)
        self.log.delete(1.0, END)
        self.log.config(state=DISABLED)

    def cancel_scan(self):
        if self.scan_thread and self.scan_thread.is_alive():
            self.stop_event.set()
            self.log_msg("Cancelling scan...", "#ff8800")

    def start_scan(self):
        if not self.target_path:
            messagebox.showwarning("Error", "Select a folder first!")
            return
        config = self.get_scan_config()
        if not config:
            messagebox.showwarning("No Selection", "Select at least one OWASP category!")
            return
        if self.scan_thread and self.scan_thread.is_alive():
            return

        self.all_issues = []
        self.stop_event.clear()
        for i in self.tree.get_children():
            self.tree.delete(i)
        if self.results_frame.winfo_ismapped():
            self.results_frame.pack_forget()

        self.scan_thread = threading.Thread(target=self.run_scan, args=(config,), daemon=True)
        self.scan_thread.start()

    def run_scan(self, config):
        start = time.time()
        self.progress["value"] = 0
        self.log_msg(f"Scanning with: { {k:v['intensity'] for k,v in config.items()} }", "#00ffff")

        exts = {".php",".blade.php",".env",".js",".json",".yml",".yaml",".sql",".html"}
        files = [p for p in self.target_path.rglob("*") if p.suffix.lower() in exts or p.name in (".env", "artisan")]
        files = [p for p in files if p.stat().st_size <= 5*1024*1024]
        files = [p for p in files if not any(x in p.parts for x in ("vendor","node_modules","storage","bootstrap",".git"))]

        total = len(files)
        if total == 0:
            self.log_msg("No files found.", "#00ff66")
            return

        self.progress["maximum"] = total
        self.log_msg(f"Scanning {total} files...", "#00ffff")

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {executor.submit(self.scan_file, f, config): f for f in files}
            for future in as_completed(futures):
                if self.stop_event.is_set():
                    break
                try:
                    issues = future.result()
                    self.all_issues.extend(issues)
                except:
                    pass
                self.progress["value"] += 1
                self.root.update_idletasks()

        if not self.stop_event.is_set():
            self.run_bandit(config)
            self.run_php_static(config)

        if not self.stop_event.is_set():
            self.display_results()
            elapsed = time.time() - start
            self.log_msg(f"Scan complete: {len(self.all_issues)} issues in {elapsed:.1f}s", "#00ff66")
        else:
            self.log_msg("Scan cancelled.", "#ff8800")

    def scan_file(self, path: Path, config):
        issues = []
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except:
            return issues

        # Regex rules
        for code, cfg in config.items():
            for rule_id in cfg["rules"]:
                rule = REGEX_RULES.get(rule_id)
                if not rule: continue
                for m in rule["pattern"].finditer(text):
                    line_no = text.count("\n", 0, m.start()) + 1
                    line_text = text.splitlines()[line_no-1] if line_no <= len(text.splitlines()) else ""
                    issues.append({
                        "file": str(path), "line": line_no, "owasp": code,
                        "intensity": cfg["intensity"],
                        "severity": "HIGH" if any(x in rule_id for x in ("SECRET","EVAL","RAW","HASH")) else "MEDIUM",
                        "desc": rule["desc"], "rule": rule_id, "snippet": line_text.strip()
                    })

        # Runtime checks (Hard only)
        if any(cfg["intensity"] == "Hard" for cfg in config.values()):
            # World-writable dirs
            if path.is_dir() and path.name in ("storage", "bootstrap"):
                mode = path.stat().st_mode
                if mode & stat.S_IWOTH:
                    issues.append({
                        "file": str(path), "line": 0, "owasp": "A05", "intensity": "Hard",
                        "severity": "HIGH", "desc": f"World-writable: {path.name}", "rule": "WORLD_WRITABLE", "snippet": ""
                    })

            # artisan executable
            if path.name == "artisan" and path.stat().st_mode & 0o111:
                issues.append({
                    "file": str(path), "line": 0, "owasp": "A05", "intensity": "Hard",
                    "severity": "MEDIUM", "desc": "artisan is executable", "rule": "ARTISAN_EXPOSED", "snippet": ""
                })

        # .env secrets
        if path.name == ".env" and "A02" in config:
            for i, line in enumerate(text.splitlines(), 1):
                if re.search(r"(DB_PASSWORD|APP_KEY|AWS_SECRET)", line):
                    issues.append({
                        "file": str(path), "line": i, "owasp": "A02", "intensity": config["A02"]["intensity"],
                        "severity": "HIGH", "desc": "Secret in .env", "rule": "ENV_LEAK", "snippet": line.strip()
                    })

        return issues

    def run_bandit(self, config):
        if not shutil.which("bandit"): return
        cmd = ["bandit", "-r", str(self.target_path), "-f", "json", "--quiet"]
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
            if r.stdout:
                data = json.loads(r.stdout)
                for i in data.get("results", []):
                    owasp = BANDIT_TO_OWASP.get(i["test_id"], "A01")
                    if owasp in config:
                        self.all_issues.append({
                            "file": i["filename"], "line": i["line_number"], "owasp": owasp,
                            "intensity": "Hard", "severity": i["issue_severity"].upper(),
                            "desc": i["issue_text"][:200], "rule": i["test_id"], "snippet": i.get("code", "")[:200]
                        })
        except: pass

    def run_php_static(self, config):
        if "A08" not in config: return
        if shutil.which("psalm"):
            try:
                r = subprocess.run(["psalm", "--output-format=json"], cwd=str(self.target_path), capture_output=True, text=True, timeout=180)
                if r.stdout:
                    data = json.loads(r.stdout)
                    for m in data.get("issues", []):
                        self.all_issues.append({
                            "file": m.get("file_name",""), "line": m.get("line_from",1), "owasp": "A08",
                            "intensity": "Hard", "severity": "MEDIUM", "desc": m.get("message",""), "rule": "PSALM", "snippet": ""
                        })
            except: pass
        if shutil.which("phpstan"):
            try:
                r = subprocess.run(["phpstan", "analyse", "--error-format=json"], cwd=str(self.target_path), capture_output=True, text=True, timeout=180)
                if r.stdout:
                    data = json.loads(r.stdout)
                    for f, d in data.get("files", {}).items():
                        for m in d.get("messages", []):
                            self.all_issues.append({
                                "file": f, "line": m.get("line",1), "owasp": "A08",
                                "intensity": "Hard", "severity": "LOW", "desc": m.get("message",""), "rule": "PHPSTAN", "snippet": ""
                            })
            except: pass

    def display_results(self):
        for i in self.tree.get_children():
            self.tree.delete(i)

        grouped = {}
        for issue in self.all_issues:
            cat = issue["owasp"]
            grouped.setdefault(cat, []).append(issue)

        total = len(self.all_issues)
        for cat in sorted(grouped):
            issues = grouped[cat]
            parent = self.tree.insert("", "end", text=f"{cat} - {OWASP_CATEGORIES[cat]} ({len(issues)})", values=("", "", "", "", "", ""))
            for issue in sorted(issues, key=lambda x: (-{"HIGH":3,"MEDIUM":2,"LOW":1}.get(x["severity"],0), x["intensity"])):
                rel = str(Path(issue["file"]).relative_to(self.target_path))
                self.tree.insert(parent, "end", values=(
                    rel, issue["line"], cat, issue["intensity"],
                    issue["desc"], issue["rule"]
                ))

        if total > 0:
            tree_scroll = Scrollbar(self.results_frame)
            self.tree.pack(side=LEFT, fill=BOTH, expand=True)
            tree_scroll.pack(side=RIGHT, fill=Y)
            self.tree.config(yscrollcommand=tree_scroll.set)
            tree_scroll.config(command=self.tree.yview)
            self.results_frame.pack(fill=BOTH, expand=True, padx=20, pady=10)
            self.log_msg(f"{total} issues found!", "#ff0066")

    def on_double_click(self, event):
        item = self.tree.selection()
        if not item: return
        values = self.tree.item(item, "values")
        if not values or not values[0]: return
        path = self.target_path / values[0]
        if path.exists():
            if sys.platform == "win32":
                os.startfile(str(path))
            elif sys.platform == "darwin":
                subprocess.call(["open", str(path)])
            else:
                subprocess.call(["xdg-open", str(path)])

    def export_html(self):
        if not self.all_issues:
            messagebox.showinfo("No Data", "Run a scan first.")
            return

        file = filedialog.asksaveasfilename(defaultextension=".html", filetypes=[("HTML", "*.html")])
        if not file: return

        config = self.get_scan_config()
        html = f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>LaraPhiser v2.0 Report</title>
<style>
body {{font-family: Consolas; background:#000; color:#0f0; padding:30px;}}
h1, h2 {{color:#0ff;}}
.issue {{background:#111; padding:12px; margin:10px 0; border-left:5px solid #0f0;}}
.file {{color:#0ff; font-weight:bold;}}
.tag {{background:#022; padding:2px 6px; border-radius:3px; margin:0 3px;}}
</style></head><body>
<h1>LaraPhiser v2.0 Report</h1>
<p><strong>Target:</strong> {self.target_path}</p>
<p><strong>Generated:</strong> {datetime.now():%Y-%m-%d %H:%M:%S}</p>
<p><strong>Intensity:</strong> { {k:v['intensity'] for k,v in config.items()} }</p>
<p><strong>Total Issues:</strong> {len(self.all_issues)}</p><hr>"""

        for i, issue in enumerate(sorted(self.all_issues, key=lambda x: (x["owasp"], -{"HIGH":3,"MEDIUM":2,"LOW":1}.get(x["severity"],0))), 1):
            rel = str(Path(issue["file"]).relative_to(self.target_path))
            html += f'<div class="issue"><div class="file">#{i} {rel}:{issue["line"]} ' \
                    f'<span class="tag">{issue["owasp"]}</span><span class="tag">{issue["intensity"]}</span><span class="tag">{issue["severity"]}</span></div>' \
                    f'<div><strong>{issue["desc"]}</strong></div>' \
                    f'<div><small>Rule: {issue["rule"]}</small></div>'
            if issue["snippet"]:
                html += f'<pre style="background:#000;color:#afa;padding:8px;margin-top:6px;">{html.escape(issue["snippet"])}</pre>'
            html += '</div>'

        html += "</body></html>"
        Path(file).write_text(html, encoding="utf-8")
        self.log_msg(f"Report saved: {file}", "#00ff66")

# -------------------------------
# Run
# -------------------------------
if __name__ == "__main__":
    try:
        from tkinterdnd2 import TkinterDnD
        root = TkinterDnD.Tk()
    except:
        root = Tk()
    app = LaraPhiser(root)
    root.mainloop()