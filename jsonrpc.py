#jsonrpc.py from https://github.com/JoinMarket-Org/joinmarket/blob/master/joinmarket/jsonrpc.py
#copyright # Copyright (C) 2013,2015 by Daniel Kraft <d@domob.eu> and phelix / blockchained.com

import base64
import http.client
import json

class JsonRpcError(Exception):
    def __init__(self, obj):
        self.code = obj["code"]
        self.message = obj["message"]

class JsonRpcConnectionError(JsonRpcError): pass

class JsonRpc(object):
    def __init__(self, host, port, user, password, wallet_filename=""):
        self.host = host
        self.port = port
        self.authstr = "%s:%s" % (user, password)
        if len(wallet_filename) > 0:
            self.url = "/wallet/" + wallet_filename
        else:
            self.url = ""
        self.queryId = 1

    def queryHTTP(self, obj):
        headers = {"User-Agent": "electrum-personal-server",
                   "Content-Type": "application/json",
                   "Accept": "application/json"}
        headers["Authorization"] = "Basic %s" % base64.b64encode(
                                    self.authstr.encode()).decode()
        body = json.dumps(obj)
        try:
            conn = http.client.HTTPConnection(self.host, self.port)
            conn.request("POST", self.url, body, headers)
            response = conn.getresponse()
            if response.status == 401:
                conn.close()
                raise JsonRpcConnectionError(
                        "authentication for JSON-RPC failed")
            # All of the codes below are 'fine' from a JSON-RPC point of view.
            if response.status not in [200, 404, 500]:
                conn.close()
                raise JsonRpcConnectionError("unknown error in JSON-RPC")
            data = response.read()
            conn.close()
            return json.loads(data.decode())
        except JsonRpcConnectionError as exc:
            raise exc
        except Exception as exc:
            raise JsonRpcConnectionError("JSON-RPC connection failed. Err:" +
                                         repr(exc))

    def call(self, method, params):
        currentId = self.queryId
        self.queryId += 1
        request = {"method": method, "params": params, "id": currentId}
        response = self.queryHTTP(request)
        if response["id"] != currentId:
            raise JsonRpcConnectionError("invalid id returned by query")
        if response["error"] is not None:
            raise JsonRpcError(response["error"])
        return response["result"]
