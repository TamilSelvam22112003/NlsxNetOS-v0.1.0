from nlsxnetos.nls.config import endpoint
def test_endpoint_parser():
 assert endpoint("127.0.0.1:4789")==("127.0.0.1",4789)
 assert endpoint("[::1]:4789")==("::1",4789)
