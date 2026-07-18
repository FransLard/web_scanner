
import argparse
import asyncio
import sys
from urllib .parse import urlparse
from colorama import Fore ,Style ,init as colorama_init

from utils .reporter import (
print_banner ,
print_target_info ,
print_port_scan_results ,
print_tech_results ,
print_vuln_results ,
save_report ,
color_status ,
)
from utils .network import resolve_target
from scanners import port_scanner ,tech_detector ,vuln_scanner

def cmd_scan (args ):
    print_banner ()
    ip =resolve_target (args .target )
    print_target_info (args .target ,ip )

    ports =None
    if args .ports :
        ports =[]
        for part in args .ports .split (","):
            part =part .strip ()
            if "-"in part :
                start ,end =part .split ("-")
                ports .extend (range (int (start .strip ()),int (end .strip ())+1 ))
            else :
                ports .append (int (part ))

    result =asyncio .run (port_scanner .run (args .target ,ports =ports ,all_ports =args .all ))

    open_count =result ["open_count"]
    total =result ["total_scanned"]
    print (f"{Fore .BLUE }[*] Port Scan Results:{Style .RESET_ALL } {color_status (open_count ,total )}")
    print_port_scan_results (result ["ports"],args .target )

    if args .output :
        save_report (result ,args .output )

def _get_host (target :str )->str :
    parsed =urlparse (target )
    return parsed .hostname or target

def cmd_tech (args ):
    print_banner ()
    host =_get_host (args .target )
    ip =resolve_target (host )
    print_target_info (args .target ,ip )

    result =tech_detector .run (args .target ,timeout =args .timeout )

    if "error"in result :
        print (f"{Fore .RED }[!] Error: {result ['error']}{Style .RESET_ALL }")
        sys .exit (1 )

    tech =result .get ("technologies",[])
    print (f"{Fore .BLUE }[*] Technology Detection:{Style .RESET_ALL } {len (tech )} technologies found")
    print_tech_results (tech )

    if result .get ("headers"):
        print (f"  {Fore .CYAN }Headers:{Style .RESET_ALL }")
        for key ,val in result ["headers"].items ():
            if val :
                print (f"    {key .replace ('_','-').title ():<20} {val }")
        print ()

    if args .output :
        save_report (result ,args .output )

def cmd_vuln (args ):
    print_banner ()
    host =_get_host (args .target )
    ip =resolve_target (host )
    print_target_info (args .target ,ip )

    result =vuln_scanner .run (args .target ,timeout =args .timeout )
    vulns =result .get ("vulnerabilities",[])

    print (f"{Fore .BLUE }[*] Vulnerability Scan Results:{Style .RESET_ALL } "
    f"{Fore .RED if result ['high']>0 else Fore .GREEN }{result ['total']} found "
    f"({result ['high']} high, {result ['medium']} medium, {result ['low']} low){Style .RESET_ALL }")
    print ()
    print_vuln_results (vulns )

    if args .output :
        save_report (result ,args .output )

def cmd_full (args ):
    print_banner ()
    host =_get_host (args .target )
    ip =resolve_target (host )
    print_target_info (args .target ,ip )

    full_result ={
    "target":args .target ,
    "ip":ip ,
    }

    result =asyncio .run (port_scanner .run (args .target ))
    full_result .update (result )
    open_count =result ["open_count"]
    total =result ["total_scanned"]
    print (f"{Fore .BLUE }[*] Port Scan Results:{Style .RESET_ALL } {color_status (open_count ,total )}")
    print_port_scan_results (result ["ports"],args .target )

    tech_result =tech_detector .run (args .target ,timeout =args .timeout )
    if "error"not in tech_result :
        all_tech =tech_result .get ("technologies",[])
        full_result ["technologies"]=all_tech
        print (f"{Fore .BLUE }[*] Technology Detection:{Style .RESET_ALL } {len (all_tech )} technologies found")
        print_tech_results (all_tech )

    vuln_result =vuln_scanner .run (args .target ,timeout =args .timeout )
    vulns =vuln_result .get ("vulnerabilities",[])
    full_result ["vulnerabilities"]=vulns
    print (f"{Fore .BLUE }[*] Vulnerability Scan Results:{Style .RESET_ALL } "
    f"{Fore .RED if vuln_result ['high']>0 else Fore .GREEN }{vuln_result ['total']} found "
    f"({vuln_result ['high']} high, {vuln_result ['medium']} medium, {vuln_result ['low']} low){Style .RESET_ALL }")
    print ()
    print_vuln_results (vulns )

    if args .output :
        save_report (full_result ,args .output )

def main ():
    colorama_init (autoreset =True )
    parser =argparse .ArgumentParser (
    description ="Web Security Scanner - Cybersecurity Portfolio Tool",
    formatter_class =argparse .RawDescriptionHelpFormatter ,
    epilog =f"""
{Fore .YELLOW }Examples:{Style .RESET_ALL }
  python main.py scan example.com
  python main.py scan example.com --ports 80,443,8080-8090
  python main.py scan example.com --all -o report.json
  python main.py tech example.com
  python main.py vuln http://testphp.vulnweb.com
  python main.py full example.com -o report.txt
        """,
    )

    subparsers =parser .add_subparsers (dest ="mode",help ="Scan mode")

    scan_parser =subparsers .add_parser ("scan",help ="Port scanning")
    scan_parser .add_argument ("target",help ="Target domain or IP address")
    scan_parser .add_argument ("--ports",help ="Port range (e.g. 80,443 or 1-1000)")
    scan_parser .add_argument ("--all",action ="store_true",help ="Scan all common ports (1-1024 + common high ports)")
    scan_parser .add_argument ("-o","--output",help ="Save report to file (.txt or .json)")

    tech_parser =subparsers .add_parser ("tech",help ="Technology detection")
    tech_parser .add_argument ("target",help ="Target domain or IP address")
    tech_parser .add_argument ("--timeout",type =int ,default =10 ,help ="Request timeout in seconds")
    tech_parser .add_argument ("-o","--output",help ="Save report to file (.txt or .json)")

    vuln_parser =subparsers .add_parser ("vuln",help ="Vulnerability scanner (SQLi, XSS)")
    vuln_parser .add_argument ("target",help ="Target URL or domain")
    vuln_parser .add_argument ("--timeout",type =int ,default =8 ,help ="Request timeout in seconds")
    vuln_parser .add_argument ("-o","--output",help ="Save report to file (.txt or .json)")

    full_parser =subparsers .add_parser ("full",help ="Run all scans")
    full_parser .add_argument ("target",help ="Target domain or IP address")
    full_parser .add_argument ("--timeout",type =int ,default =8 ,help ="Request timeout in seconds")
    full_parser .add_argument ("-o","--output",help ="Save report to file (.txt or .json)")

    args =parser .parse_args ()

    if not args .mode :
        parser .print_help ()
        sys .exit (1 )

    {"scan":cmd_scan ,"tech":cmd_tech ,"vuln":cmd_vuln ,"full":cmd_full }[args .mode ](args )

if __name__ =="__main__":
    main ()
