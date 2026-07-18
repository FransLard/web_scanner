

import asyncio
import json
import threading
import tkinter as tk
from tkinter import ttk ,scrolledtext ,filedialog ,messagebox
from urllib .parse import urlparse
from datetime import datetime

from utils .network import resolve_target
from utils .reporter import save_report
from scanners import port_scanner ,tech_detector ,vuln_scanner

def parse_ports (s :str ):
    if not s .strip ():
        return None
    ports =[]
    for part in s .split (","):
        part =part .strip ()
        if not part :
            continue
        if "-"in part :
            a ,b =part .split ("-",1 )
            ports .extend (range (int (a .strip ()),int (b .strip ())+1 ))
        else :
            ports .append (int (part ))
    return ports

class ScannerGUI (tk .Tk ):
    def __init__ (self ):
        super ().__init__ ()
        self .title ("Web Security Scanner")
        self .geometry ("860x640")
        self .minsize (760 ,560 )
        self .last_result =None

        frm =ttk .Frame (self ,padding =10 )
        frm .pack (fill ="x")

        ttk .Label (frm ,text ="Target:").grid (row =0 ,column =0 ,sticky ="w")
        self .target_var =tk .StringVar (value ="scanme.nmap.org")
        ttk .Entry (frm ,textvariable =self .target_var ,width =40 ).grid (row =0 ,column =1 ,sticky ="ew",padx =5 )

        ttk .Label (frm ,text ="Ports:").grid (row =1 ,column =0 ,sticky ="w")
        self .ports_var =tk .StringVar (value ="80,443,22,8080")
        ttk .Entry (frm ,textvariable =self .ports_var ,width =40 ).grid (row =1 ,column =1 ,sticky ="ew",padx =5 )
        ttk .Label (frm ,text ="cth: 80,443,8080-8090 (kosong = default)").grid (row =1 ,column =2 ,sticky ="w",padx =5 )

        ttk .Label (frm ,text ="Timeout:").grid (row =2 ,column =0 ,sticky ="w")
        self .timeout_var =tk .IntVar (value =8 )
        ttk .Spinbox (frm ,from_ =3 ,to =30 ,textvariable =self .timeout_var ,width =8 ).grid (row =2 ,column =1 ,sticky ="w",padx =5 )

        self .all_var =tk .BooleanVar (value =False )
        ttk .Checkbutton (frm ,text ="Scan all ports (1-1024 + common)",variable =self .all_var ).grid (row =2 ,column =2 ,sticky ="w")

        frm .columnconfigure (1 ,weight =1 )

        btn =ttk .Frame (self ,padding =(10 ,0 ))
        btn .pack (fill ="x")
        for label ,mode in [("Port Scan","scan"),("Tech Detect","tech"),
        ("Vuln Scan","vuln"),("Full Scan","full")]:
            ttk .Button (btn ,text =label ,command =lambda m =mode :self .start_scan (m )).pack (side ="left",padx =4 )
        ttk .Button (btn ,text ="Save Report",command =self .save_report ).pack (side ="right",padx =4 )
        ttk .Button (btn ,text ="Clear",command =self .clear_log ).pack (side ="right",padx =4 )

        self .status_var =tk .StringVar (value ="Idle")
        ttk .Label (self ,textvariable =self .status_var ,padding =(10 ,4 )).pack (fill ="x")

        self .progress =ttk .Progressbar (self ,mode ="indeterminate")
        self .progress .pack (fill ="x",padx =10 )

        self .log =scrolledtext .ScrolledText (self ,wrap ="word",height =24 ,font =("Consolas",10 ))
        self .log .pack (fill ="both",expand =True ,padx =10 ,pady =(0 ,10 ))
        self .log_insert ("Web Security Scanner GUI siap.\nTarget legal: scanme.nmap.org, example.com, http://testphp.vulnweb.com\n")

    def log_insert (self ,msg ):
        self .log .insert ("end",msg )
        self .log .see ("end")

    def clear_log (self ):
        self .log .delete ("1.0","end")

    def set_busy (self ,busy ,msg ="Idle"):
        self .status_var .set (msg )
        if busy :
            self .progress .start (12 )
        else :
            self .progress .stop ()

    def start_scan (self ,mode ):
        target =self .target_var .get ().strip ()
        if not target :
            messagebox .showwarning ("Input","Isi target dulu.")
            return
        threading .Thread (target =self ._run ,args =(mode ,target ),daemon =True ).start ()

    def _run (self ,mode ,target ):
        self .after (0 ,self .set_busy ,True ,f"Running {mode } on {target }...")
        try :
            if mode =="scan":
                result =self .do_port_scan (target )
            elif mode =="tech":
                result =self .do_tech (target )
            elif mode =="vuln":
                result =self .do_vuln (target )
            else :
                result =self .do_full (target )
            self .last_result =result
            self .after (0 ,self .set_busy ,False ,f"Done {mode } on {target } @ {datetime .now ():%H:%M:%S}")
        except Exception as e :
            self .after (0 ,self .log_insert ,f"[ERROR] {e }\n")
            self .after (0 ,self .set_busy ,False ,"Error")

    def do_port_scan (self ,target ):
        host =urlparse (target ).hostname or target
        try :
            ip =resolve_target (host )
        except Exception as e :
            self .after (0 ,self .log_insert ,f"[ERROR] {e }\n")
            return {}
        self .after (0 ,self .log_insert ,f"[+] Target: {target } ({ip })\n")
        ports =parse_ports (self .ports_var .get ())
        result =asyncio .run (port_scanner .run (host ,ports =ports ,all_ports =self .all_var .get ()))
        lines =[f"[*] Port Scan: {result ['open_count']} open / {result ['total_scanned']} scanned\n"]
        for r in sorted (result ["ports"],key =lambda x :x ["port"]):
            lines .append (f"  {r ['port']:<6} open  {r .get ('service','unknown'):<18} {(r .get ('banner')or '')[:80 ]}\n")
        if not result ["ports"]:
            lines .append ("  No open ports found.\n")
        self .after (0 ,self .log_insert ,"".join (lines )+"\n")
        return result

    def do_tech (self ,target ):
        result =tech_detector .run (target ,timeout =self .timeout_var .get ())
        if "error"in result :
            self .after (0 ,self .log_insert ,f"[ERROR] {result ['error']}\n")
            return result
        lines =[f"[*] Technology Detection: {len (result .get ('technologies',[]))} found\n"]
        for t in result .get ("technologies",[]):
            lines .append (f"  {t .get ('type','?'):<16} {t .get ('name','')}\n")
        if result .get ("headers"):
            lines .append ("  Headers:\n")
            for k ,v in result ["headers"].items ():
                if v :
                    lines .append (f"    {k }: {v }\n")
        self .after (0 ,self .log_insert ,"".join (lines )+"\n")
        return result

    def do_vuln (self ,target ):
        result =vuln_scanner .run (target ,timeout =self .timeout_var .get ())
        lines =[f"[*] Vulnerabilities: {result ['total']} found "
        f"({result ['high']} high, {result ['medium']} medium, {result ['low']} low)\n"]
        for v in result .get ("vulnerabilities",[]):
            lines .append (f"  [{v ['severity'].upper ()}] {v ['type']} - {v ['description']}\n")
            lines .append (f"      URL: {v .get ('url','')}\n")
        if not result .get ("vulnerabilities"):
            lines .append ("  No vulnerabilities detected.\n")
        self .after (0 ,self .log_insert ,"".join (lines )+"\n")
        return result

    def do_full (self ,target ):
        full ={"target":target }
        full .update (self .do_port_scan (target ))
        full .update ({k :v for k ,v in self .do_tech (target ).items ()if k in ("technologies","headers","status_code","final_url")})
        full .update ({k :v for k ,v in self .do_vuln (target ).items ()if k in ("vulnerabilities","total","high","medium","low")})
        return full

    def save_report (self ):
        if not self .last_result :
            messagebox .showinfo ("Report","Belum ada hasil scan.")
            return
        path =filedialog .asksaveasfilename (defaultextension =".json",
        filetypes =[("JSON","*.json"),("Text","*.txt")])
        if not path :
            return
        try :
            save_report (self .last_result ,path )
            self .log_insert (f"[+] Report saved to: {path }\n")
        except Exception as e :
            messagebox .showerror ("Report",str (e ))

if __name__ =="__main__":
    ScannerGUI ().mainloop ()
