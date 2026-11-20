"""The desktop window. Tkinter only (ships with Python) - no browser, no web server.

Screen: one big button, then two result cards (DNS, MTU), each with a one-line
verdict, and a single "apply" button. Details are hidden until asked for.
"""
from __future__ import annotations

import os
import subprocess
import sys
import threading
import tkinter as tk
from tkinter import messagebox, ttk

from ..core import settings
from . import viewmodel

COL = {"change": "#16a34a", "ok": "#2563eb", "unsure": "#d97706", "none": "#6b7280"}
ICON = {"change": "✔ ", "ok": "✔ ", "unsure": "⚠ ", "none": ""}
BG, CARD, FG = "#f3f4f6", "#ffffff", "#111827"
FONT = "Segoe UI"


class Window:
    def __init__(self, app, root=None):
        self.app = app
        self.root = root or tk.Tk()
        self.root.title(f"Network Optimizer {settings.APP_VERSION}")
        self.root.geometry("760x640")
        self.root.minsize(640, 560)
        self.root.configure(bg=BG)
        self.job = None
        self.busy = False
        self.vm = None
        self._build()
        self.render()
        self.root.protocol("WM_DELETE_WINDOW", self.close)

    # ------------------------------------------------------------ layout
    def _build(self):
        r = self.root
        tk.Label(r, text="محسّن الشبكة — أفضل DNS وأفضل MTU", bg=BG, fg=FG,
                 font=(FONT, 16, "bold")).pack(pady=(14, 2))
        self.net_lbl = tk.Label(r, text="", bg=BG, fg="#4b5563", font=(FONT, 10))
        self.net_lbl.pack()

        top = tk.Frame(r, bg=BG)
        top.pack(fill="x", padx=18, pady=10)
        self.start_btn = tk.Button(top, text="▶  ابدأ الفحص", font=(FONT, 13, "bold"), bg="#2563eb",
                                   fg="white", activebackground="#1d4ed8", relief="flat", padx=18, pady=8,
                                   command=self.start)
        self.start_btn.pack(side="right")
        self.cancel_btn = tk.Button(top, text="إيقاف", font=(FONT, 10), command=self.cancel, state="disabled")
        self.cancel_btn.pack(side="right", padx=8)
        self.bar = ttk.Progressbar(top, mode="determinate", maximum=100)
        self.bar.pack(side="left", fill="x", expand=True, padx=(0, 12))
        self.status = tk.Label(r, text="اضغط «ابدأ الفحص» (بياخد دقيقة تقريبًا).", bg=BG, fg="#4b5563",
                               font=(FONT, 10), anchor="e", justify="right")
        self.status.pack(fill="x", padx=20)

        self.cards = {}
        for key, title in (("dns", "DNS"), ("mtu", "MTU")):
            f = tk.Frame(r, bg=CARD, highlightbackground="#e5e7eb", highlightthickness=1)
            f.pack(fill="x", padx=18, pady=7)
            tk.Label(f, text=title, bg=CARD, fg="#6b7280", font=(FONT, 10, "bold"), anchor="e").pack(
                fill="x", padx=14, pady=(10, 0))
            head = tk.Label(f, text="", bg=CARD, font=(FONT, 15, "bold"), anchor="e", justify="right")
            head.pack(fill="x", padx=14)
            det = tk.Label(f, text="", bg=CARD, fg="#374151", font=(FONT, 10), anchor="e", justify="right",
                           wraplength=680)
            det.pack(fill="x", padx=14, pady=(2, 10))
            self.cards[key] = (head, det)

        row = tk.Frame(r, bg=BG)
        row.pack(fill="x", padx=18, pady=8)
        self.apply_btn = tk.Button(row, text="طبّق التوصية", font=(FONT, 12, "bold"), bg="#16a34a", fg="white",
                                   activebackground="#15803d", relief="flat", padx=16, pady=7,
                                   state="disabled", command=self.apply)
        self.apply_btn.pack(side="right")
        self.restore_btn = tk.Button(row, text="رجّع الإعدادات الأصلية", font=(FONT, 10), command=self.restore)
        self.restore_btn.pack(side="right", padx=8)
        tk.Button(row, text="فتح مجلد النتائج (CSV)", font=(FONT, 10), command=self.open_logs).pack(side="left")
        self.det_btn = tk.Button(row, text="التفاصيل ▾", font=(FONT, 10), command=self.toggle_details)
        self.det_btn.pack(side="left", padx=8)

        self.details = tk.Text(r, height=9, font=("Consolas", 9), bg=CARD, relief="flat", wrap="word")
        self.details_shown = False

    # ------------------------------------------------------------ rendering
    def render(self):
        state = self.app.state()
        self.vm = viewmodel.summarize(state, self.app.results)
        self.net_lbl.config(text=self.vm["network"])
        for key in ("dns", "mtu"):
            v = self.vm[key]
            head, det = self.cards[key]
            head.config(text=ICON[v["level"]] + v["title"], fg=COL[v["level"]])
            det.config(text=v["detail"])
        self.apply_btn.config(state="normal" if self.vm["plan"] and not self.busy else "disabled")
        self._fill_details()

    def _fill_details(self):
        t = self.details
        t.config(state="normal")
        t.delete("1.0", "end")
        vm = self.vm
        if vm["dns"]["rows"]:
            t.insert("end", "ترتيب سيرفرات DNS (الأفضل أولًا)\n")
            for r in vm["dns"]["rows"]:
                med = "—" if r["median"] is None else f"{r['median']:.1f} ms"
                succ = "—" if r["success"] is None else f"{r['success']:.0%}"
                t.insert("end", f"{'★' if r['is_best'] else ' '} {str(r['name'])[:24]:<24} {str(r['primary']):<16} "
                                f"score {r['score']!s:<5} median {med:<10} success {succ}\n")
            t.insert("end", "\n")
        for title, key in (("لماذا هذه توصية DNS", "dns"), ("لماذا هذه توصية MTU", "mtu")):
            if vm[key]["reasons"]:
                t.insert("end", title + "\n")
                for x in vm[key]["reasons"]:
                    t.insert("end", "  • " + x + "\n")
                t.insert("end", "\n")
        t.config(state="disabled")

    def toggle_details(self):
        if self.details_shown:
            self.details.pack_forget()
            self.det_btn.config(text="التفاصيل ▾")
        else:
            self.details.pack(fill="both", expand=True, padx=18, pady=(0, 12))
            self.det_btn.config(text="إخفاء التفاصيل ▴")
        self.details_shown = not self.details_shown

    # ------------------------------------------------------------ actions
    def start(self):
        if self.busy:
            return
        try:
            self.app.refresh()
            self.job = self.app.start_workflow(["ipv4"])
        except Exception as e:
            messagebox.showerror("خطأ", str(e))
            return
        self.set_busy(True)
        self.root.after(300, self.poll)

    def cancel(self):
        if self.job:
            self.app.jobs.cancel(self.job.id)

    def set_busy(self, b: bool):
        self.busy = b
        self.start_btn.config(state="disabled" if b else "normal")
        self.cancel_btn.config(state="normal" if b else "disabled")
        self.restore_btn.config(state="disabled" if b else "normal")
        if b:
            self.apply_btn.config(state="disabled")

    def poll(self):
        j = self.job
        self.bar["value"] = j.progress * 100
        self.status.config(text=j.message or "جارٍ الفحص…")
        if j.state == "running":
            self.root.after(300, self.poll)
            return
        self.set_busy(False)
        self.bar["value"] = 100 if j.state == "done" else 0
        if j.state == "done":
            self.status.config(text="تم الفحص. النتيجة تم حفظها في ملفات CSV.")
        elif j.state == "cancelled":
            self.status.config(text="تم إيقاف الفحص.")
        else:
            self.status.config(text="فشل الفحص: " + j.error)
            messagebox.showerror("فشل الفحص", j.error)
        self.render()

    def _run_bg(self, fn, done):
        """Run a slow call (UAC prompt, netsh) off the UI thread."""
        self.set_busy(True)
        self.status.config(text="جارٍ التنفيذ… وافق على نافذة الصلاحيات (UAC) لو ظهرت.")
        out = {}

        def work():
            try:
                out["r"] = fn()
            except Exception as e:
                out["e"] = e

        th = threading.Thread(target=work, daemon=True)
        th.start()

        def wait():
            if th.is_alive():
                self.root.after(200, wait)
                return
            self.set_busy(False)
            done(out.get("r"), out.get("e"))
            self.render()
        self.root.after(200, wait)

    def apply(self):
        plan = dict(self.vm["plan"])
        lines = []
        if "dns4" in plan:
            lines.append("DNS ← " + " , ".join(plan["dns4"]))
        if "mtu4" in plan:
            lines.append(f"MTU ← {plan['mtu4']}")
        if not messagebox.askyesno("تأكيد", "هيتم تطبيق:\n\n" + "\n".join(lines) +
                                   "\n\nهيتم عمل نسخة احتياطية قبل التغيير، وتقدر ترجع للأصل بزر «رجّع الإعدادات الأصلية»."):
            return

        def done(res, err):
            if err:
                self.status.config(text="لم يتم التطبيق")
                messagebox.showerror("لم يتم التطبيق", str(err))
                return
            bad = [c for c in res["checks"] if not c["ok"]]
            if bad:
                self.status.config(text="تم التطبيق لكن بعض الفحوصات فشلت")
                messagebox.showwarning("تنبيه", "بعض الإعدادات لم تتأكد:\n" +
                                       "\n".join(f"{c['check']}: {c['detail']}" for c in bad))
            else:
                self.status.config(text="تم التطبيق والتأكد من الإعدادات ✔")
                messagebox.showinfo("تم", "تم تطبيق الإعدادات والتأكد منها.")
        self._run_bg(lambda: self.app.apply(plan), done)

    def restore(self):
        p = self.app.primary
        bk = self.app.backups.original_for(p) if p else None
        if not bk:
            messagebox.showinfo("لا توجد نسخة", "مفيش نسخة أصلية محفوظة لهذه الشبكة (لم يتم تطبيق أي تغيير بعد).")
            return
        if not messagebox.askyesno("تأكيد", "هيتم إرجاع DNS و MTU لقيمهم الأصلية قبل أول تعديل. متابعة؟"):
            return

        def done(res, err):
            if err:
                messagebox.showerror("لم يتم الاسترجاع", str(err))
            else:
                self.status.config(text="تم إرجاع الإعدادات الأصلية ✔")
                messagebox.showinfo("تم", "تم إرجاع الإعدادات الأصلية.")
        self._run_bg(lambda: self.app.restore({"backup": bk["file"], "parts": ["dns", "mtu"]}), done)

    def open_logs(self):
        folder = os.path.dirname(settings.path("logs", "x"))
        try:
            if sys.platform == "win32":
                os.startfile(folder)  # type: ignore[attr-defined]
            elif sys.platform == "darwin":
                subprocess.Popen(["open", folder])
            else:
                subprocess.Popen(["xdg-open", folder])
        except Exception as e:
            messagebox.showinfo("المسار", f"{folder}\n({e})")

    def close(self):
        if self.busy and not messagebox.askyesno("خروج", "فيه عملية شغالة. تخرج؟"):
            return
        self.cancel()
        try:
            self.app.monitor.stop()
        except Exception:
            pass
        self.root.destroy()

    def run(self):
        self.root.mainloop()
