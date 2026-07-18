import asyncio
from utils .network import resolve_target ,COMMON_PORTS ,scan_ports

async def run (target :str ,ports :list [int ]|None =None ,all_ports :bool =False )->dict :
    ip =resolve_target (target )

    if all_ports :
        port_list =list (range (1 ,1025 ))+list (COMMON_PORTS .keys ())
    elif ports :
        port_list =ports
    else :
        port_list =list (COMMON_PORTS .keys ())

    port_list =sorted (set (port_list ))
    results =await scan_ports (target ,port_list )

    return {
    "target":target ,
    "ip":ip ,
    "ports":results ,
    "total_scanned":len (port_list ),
    "open_count":len (results ),
    }
