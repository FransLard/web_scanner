import json
from datetime import datetime
from colorama import Fore ,Style

def color_status (open_count :int ,total :int )->str :
    if open_count ==0 :
        return f"{Fore .GREEN }All closed{Style .RESET_ALL }"
    return f"{Fore .RED }{open_count } open{Style .RESET_ALL } / {total } scanned"

def print_banner ():
    banner =f"""\n{Fore .CYAN }  __        ___     _____\n  \\ \\      / / |__ / ___/ ___   __ _ _ __ ___   ___\n   \\ \\ /\\ / /| '_ \\\\___ \\/ __| / _' | '_ \\` _ \\ / __|\n    \\ V  V / | |_) |___) \\__ \\| (_| | | | | | | (__\n     \\_/\\_/  |_.__/|____/|___(_)__,_|_| |_| |_|\\___|\n{Style .RESET_ALL }\n    {Fore .YELLOW }Web Security Scanner - Portfolio Project{Style .RESET_ALL }\n    {Fore .CYAN }{'='*44 }{Style .RESET_ALL }\n"""
    print (banner )

def print_target_info (target :str ,ip :str ):
    print (f"{Fore .BLUE }[+] Target:{Style .RESET_ALL } {target } {Fore .YELLOW }({ip }){Style .RESET_ALL }")
    print (f"{Fore .BLUE }[+] Started:{Style .RESET_ALL } {datetime .now ().strftime ('%Y-%m-%d %H:%M:%S')}")
    print ()

def print_port_scan_results (results :list [dict ],target :str ):
    if not results :
        print (f"  {Fore .YELLOW }No open ports found.{Style .RESET_ALL }")
        print ()
        return

    print (f"  {'PORT':<8} {'STATE':<8} {'SERVICE':<18} {'BANNER'}")
    print (f"  {'-'*6 :<8} {'-'*6 :<8} {'-'*16 :<18} {'-'*30 }")
    for r in sorted (results ,key =lambda x :x ["port"]):
        port_str =f"{r ['port']}"
        service =r .get ("service","unknown")
        banner =(r .get ("banner")or "")[:60 ]
        print (f"  {port_str :<8} {Fore .GREEN }{'open':<8}{Style .RESET_ALL } {service :<18} {banner }")
    print ()

def print_tech_results (results :list [dict ]):
    if not results :
        print (f"  {Fore .YELLOW }No technologies detected.{Style .RESET_ALL }")
        return

    for item in results :
        print (f"  {Fore .CYAN }{item ['type']:<16}{Style .RESET_ALL } {item ['name']}")
    print ()

def print_vuln_results (results :list [dict ]):
    if not results :
        print (f"  {Fore .GREEN }No vulnerabilities detected.{Style .RESET_ALL }")
        return

    for r in results :
        if r ["severity"]=="high":
            sev =f"{Fore .RED }HIGH{Style .RESET_ALL }"
        elif r ["severity"]=="medium":
            sev =f"{Fore .YELLOW }MEDIUM{Style .RESET_ALL }"
        else :
            sev =f"{Fore .CYAN }LOW{Style .RESET_ALL }"
        print (f"  [{sev }] {r ['type']:>8} - {r ['description']}")
        if r .get ("url"):
            print (f"          URL: {Fore .YELLOW }{r ['url']}{Style .RESET_ALL }")
        if r .get ("detail"):
            print (f"          Detail: {r ['detail']}")
    print ()

def save_report (results :dict ,filepath :str ):
    data ={
    "scan_time":datetime .now ().isoformat (),
    "target":results .get ("target"),
    "ip":results .get ("ip"),
    **results ,
    }
    if filepath .endswith (".json"):
        with open (filepath ,"w")as f :
            json .dump (data ,f ,indent =2 ,default =str )
    else :
        with open (filepath ,"w")as f :
            f .write (f"Web Scanner Report\n")
            f .write (f"{'='*50 }\n")
            f .write (f"Target: {results .get ('target','N/A')}\n")
            f .write (f"Date: {datetime .now ().strftime ('%Y-%m-%d %H:%M:%S')}\n\n")
            if results .get ("ports"):
                f .write ("PORT SCAN RESULTS:\n")
                f .write ("-"*40 +"\n")
                for p in results ["ports"]:
                    f .write (f"  {p ['port']}/tcp  open  {p ['service']}\n")
                f .write ("\n")
            if results .get ("technologies"):
                f .write ("TECHNOLOGY DETECTION:\n")
                f .write ("-"*40 +"\n")
                for t in results ["technologies"]:
                    f .write (f"  {t ['type']}: {t ['name']}\n")
                f .write ("\n")
            if results .get ("vulnerabilities"):
                f .write ("VULNERABILITIES:\n")
                f .write ("-"*40 +"\n")
                for v in results ["vulnerabilities"]:
                    f .write (f"  [{v ['severity'].upper ()}] {v ['type']}: {v ['description']}\n")
                f .write ("\n")
    print (f"{Fore .GREEN }[+] Report saved to: {filepath }{Style .RESET_ALL }")
