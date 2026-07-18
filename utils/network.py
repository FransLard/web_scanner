import socket
import ssl
import asyncio

COMMON_PORTS ={
21 :"FTP",
22 :"SSH",
23 :"Telnet",
25 :"SMTP",
53 :"DNS",
80 :"HTTP",
110 :"POP3",
143 :"IMAP",
443 :"HTTPS",
445 :"SMB",
465 :"SMTPS",
587 :"SMTP (Submission)",
993 :"IMAPS",
995 :"POP3S",
1433 :"MSSQL",
1521 :"Oracle DB",
2049 :"NFS",
3306 :"MySQL",
3389 :"RDP",
5432 :"PostgreSQL",
5900 :"VNC",
6379 :"Redis",
8080 :"HTTP Proxy",
8443 :"HTTPS Alt",
27017 :"MongoDB",
}

def resolve_target (target :str )->str :
    try :
        return socket .gethostbyname (target )
    except socket .gaierror :
        raise ValueError (f"Cannot resolve target: {target }")

async def scan_port (target :str ,port :int ,timeout :float =1.5 )->dict |None :
    sock =socket .socket (socket .AF_INET ,socket .SOCK_STREAM )
    sock .settimeout (timeout )
    sock .setsockopt (socket .SOL_SOCKET ,socket .SO_LINGER ,b'\x01\x00\x00\x00\x00\x00\x00\x00')
    try :
        result =sock .connect_ex ((target ,port ))
        if result ==0 :
            banner =None
            try :
                if port in (80 ,443 ,8080 ,8443 ):
                    sock .sendall (b"GET / HTTP/1.0\r\n\r\n")
                elif port ==21 :
                    sock .sendall (b"\r\n")
                elif port ==25 :
                    sock .sendall (b"EHLO scan\r\n")
                banner =sock .recv (256 ).decode ("utf-8",errors ="ignore").strip ()[:200 ]
            except Exception :
                pass
            return {
            "port":port ,
            "state":"open",
            "service":COMMON_PORTS .get (port ,"unknown"),
            "banner":banner or None ,
            }
        return None
    except socket .gaierror :
        return None
    except Exception :
        return None
    finally :
        sock .close ()

async def scan_ports (target :str ,ports :list [int ])->list [dict ]:
    semaphore =asyncio .Semaphore (128 )

    async def bounded_scan (port ):
        async with semaphore :
            return await scan_port (target ,port )

    tasks =[bounded_scan (port )for port in ports ]
    results =await asyncio .gather (*tasks )
    return [r for r in results if r is not None ]

def get_service_banner (target :str ,port :int ,timeout :float =2.0 )->str |None :
    try :
        sock =socket .socket (socket .AF_INET ,socket .SOCK_STREAM )
        sock .settimeout (timeout )
        sock .connect ((target ,port ))
        if port ==443 :
            context =ssl .create_default_context ()
            context .check_hostname =False
            context .verify_mode =ssl .CERT_NONE
            with context .wrap_socket (sock ,server_hostname =target )as ssock :
                ssock .sendall (b"GET / HTTP/1.0\r\n\r\n")
                return ssock .recv (512 ).decode ("utf-8",errors ="ignore").strip ()[:300 ]
        sock .sendall (b"GET / HTTP/1.0\r\n\r\n")
        data =sock .recv (512 ).decode ("utf-8",errors ="ignore").strip ()
        return data [:300 ]
    except Exception :
        return None
    finally :
        try :
            sock .close ()
        except Exception :
            pass
