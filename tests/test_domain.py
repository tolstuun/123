from app.domain import compare_vtis, normalize_verdict

def test_vti_score_change_is_not_addition():
    result=compare_vtis([{"id":"x","score":3}],[{"id":"x","score":5}])
    assert not result["added"] and len(result["score_increased"])==1

def test_verdict(): assert normalize_verdict("clean")=="benign"
