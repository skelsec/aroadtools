import json

try:
    from pyodide.http import pyfetch
    async def requestproxy(url, method, headers, data=None, restype='json', reqtype=None, no_fetch=False):
        try:
            if reqtype == 'json':
                data = json.dumps(data)
                headers['Content-Type'] = 'application/json'
            
            if no_fetch is False:
                response = await pyfetch(
                    url,
                    method = method,
                    headers = headers,
                    data = data
                )
                resdata = None
                if restype == 'json':
                    resdata = await response.json()
                elif restype == 'text':
                    resdata = await response.text()
                elif restype == 'content':
                    resdata = await response.bytes()
            else:
                from asysocks.unicomm.protocol.client.http.client import ClientSession
                from asysocks.unicomm.common.proxy import UniProxyTarget
                proxy = UniProxyTarget()
                async with ClientSession(url, proxies=[proxy]) as session:
                    if method == 'GET':
                        response = await session.get(url, headers=headers)
                    elif method == 'POST':
                        response = await session.post(url, headers=headers, data=data)
                    else:
                        raise Exception('Method not supported')
                    resdata = None
                    if response.status != 200:
                        resdata = await response.text()
                    else:
                        resdata = None
                        if restype == 'json':
                            resdata = await response.json()
                        elif restype == 'text':
                            resdata = await response.text()
                        elif restype == 'content':
                            resdata = await response.read()
                    return response, resdata, None



            return response, resdata, None
        except Exception as exc:
            return None, None, exc
        
except ImportError:
    import aiohttp
    async def requestproxy(url, method, headers, data=None, restype='json', reqtype=None, **kwargs):
        try:
            method = method.upper()
            async with aiohttp.ClientSession() as session:
                if method == 'GET':
                    presponse = session.get(url, headers=headers, data=data)
                elif method == 'POST':
                    if reqtype == 'json':
                        presponse = session.post(url, headers=headers, json=data)
                    else:
                        presponse = session.post(url, headers=headers, data=data)
                else:
                    raise Exception('Method not supported')
                async with presponse as response:
                    if response.status != 200:
                        resdata = await response.text()
                    else:
                        resdata = None
                        if restype == 'json':
                            resdata = await response.json()
                        elif restype == 'text':
                            resdata = await response.text()
                        elif restype == 'content':
                            resdata = await response.read()
                    return response, resdata, None
        except Exception as exc:
            return None, None, exc
