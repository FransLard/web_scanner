import requests
from urllib .parse import urlparse

def _normalize_url (target :str )->str :
    if not target .startswith (("http://","https://")):
        target =f"https://{target }"
    return target

def _detect_technologies (headers :dict ,body :str )->list [dict ]:
    results =[]

    tech_map ={
    "Server":("Web Server",None ),
    "X-Powered-By":("Framework",None ),
    "X-Generator":("CMS/Generator",None ),
    "X-AspNet-Version":("ASP.NET Version",None ),
    "X-AspNetMvc-Version":("ASP.NET MVC",None ),
    "CF-RAY":("Cloudflare","CDN"),
    "X-Cloud-Trace-Context":("Google Cloud","Cloud"),
    "X-Varnish":("Varnish","Cache"),
    "Via":("Proxy",None ),
    }

    for header ,(tech_name ,category )in tech_map .items ():
        value =headers .get (header )
        if value :
            results .append ({"type":tech_name ,"name":value ,"category":category })

    cf =headers .get ("Server","")or ""
    if "cloudflare"in cf .lower ():
        results .append ({"type":"CDN","name":"Cloudflare","detail":cf })

    body_lower =body .lower ()
    meta_patterns =[
    ("WordPress","wp-content"in body_lower or "wp-includes"in body_lower ),
    ("Joomla","joomla"in body_lower ),
    ("Drupal","drupal"in body_lower ),
    ("Laravel","laravel"in body_lower ),
    ("React",'react'in body_lower or 'reactjs'in body_lower ),
    ("Vue.js",'vue'in body_lower ),
    ("Angular",'angular'in body_lower ),
    ]

    for name ,detected in meta_patterns :
        if detected and not any (r ["type"]=="CMS/Generator"and r .get ("name")==name for r in results ):
            results .append ({"type":"CMS/Framework","name":name })

    return results

def run (target :str ,timeout :int =10 )->dict :
    url =_normalize_url (target )
    parsed =urlparse (url )
    hostname =parsed .hostname or target

    results ={"target":target ,"url":url ,"technologies":[]}

    try :
        resp =requests .get (url ,timeout =timeout ,headers ={
        "User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        },allow_redirects =True ,verify =False )
        requests .packages .urllib3 .disable_warnings ()

        results ["status_code"]=resp .status_code
        results ["final_url"]=resp .url

        headers ={k :v for k ,v in resp .headers .items ()}
        results ["headers"]={
        "server":headers .get ("Server"),
        "content_type":headers .get ("Content-Type"),
        "x_powered_by":headers .get ("X-Powered-By"),
        }

        techs =_detect_technologies (headers ,resp .text )
        results ["technologies"]=techs

    except (requests .exceptions .SSLError ,requests .ConnectionError ,requests .exceptions .Timeout ):
        try :
            url_http =url .replace ("https://","http://")
            resp =requests .get (url_http ,timeout =timeout ,headers ={
            "User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
            },allow_redirects =True )
            results ["status_code"]=resp .status_code
            results ["final_url"]=resp .url
            headers ={k :v for k ,v in resp .headers .items ()}
            results ["headers"]={
            "server":headers .get ("Server"),
            "content_type":headers .get ("Content-Type"),
            "x_powered_by":headers .get ("X-Powered-By"),
            }
            techs =_detect_technologies (headers ,resp .text )
            results ["technologies"]=techs
        except Exception as e :
            results ["error"]=str (e )

    except Exception as e :
        results ["error"]=str (e )

    results ["tech_count"]=len (results .get ("technologies",[]))
    return results
