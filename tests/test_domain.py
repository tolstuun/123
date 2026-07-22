from app.domain import compare_vtis, normalize_ioc, normalize_verdict

def test_ioc_normalization():
    assert normalize_ioc("domain","Example.COM.")=="example.com"
    assert normalize_ioc("ipv6","2001:0db8::1")=="2001:db8::1"
    assert normalize_ioc("url","HTTPS://Example.COM:443")=="https://example.com/"

def test_vti_score_change_is_not_addition():
    result=compare_vtis([{"id":"x","score":3}],[{"id":"x","score":5}])
    assert not result["added"] and len(result["score_increased"])==1

def test_verdict(): assert normalize_verdict("clean")=="benign"
