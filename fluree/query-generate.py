#!/usr/bin/python3
import json
from ellipticcurve.utils.flureedb import DbSigner

def free_test(signer):
    data = {"foo": 42, "bar": "appelvlaai"}
    body, headers = signer.sign_query(data)
    rval = dict()
    rval["body"] = body
    rval["headers"] = headers
    rval = json.dumps(rval, indent=4, sort_keys=True)
    print(rval)

privkey = "bf8a7281f43918a18a3feab41d17e84f93b064c441106cf248307d87f8a60453"
address = "1AxKSFQ387AiQUX6CuF3JiBPGwYK5XzA1A"
signer = DbSigner(privkey, address, "something/test")
free_test(signer)

