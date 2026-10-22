import httpx
import pytest

from accounts.engine import EngineTokenClient, EngineUnavailable


def client_with(handler, sleeps=None, **kw):
    sleeps = sleeps if sleeps is not None else []
    http = httpx.Client(transport=httpx.MockTransport(handler))
    return EngineTokenClient("https://ave.test/", "cle-b2b", http, sleep=sleeps.append, **kw), sleeps


def test_mint_request_shape_and_result():
    seen = {}

    def handler(request):
        seen["method"], seen["url"], seen["auth"], seen["body"] = request.method, str(request.url), request.headers["authorization"], request.read()
        return httpx.Response(200, json={"token": "t1.abc", "expires_in": 600, "tenant": "ave-grand-public"})

    c, _ = client_with(handler)
    assert c.mint(600, sub="s" * 32, languages=["fra"]) == ("t1.abc", 600)
    assert seen["method"] == "POST" and seen["url"] == "https://ave.test/v1/token" and seen["auth"] == "Bearer cle-b2b"
    assert b'"sub"' in seen["body"] and b'"languages"' in seen["body"]


def test_mint_omits_sub_for_guests():
    bodies = []

    def handler(request):
        bodies.append(request.read())
        return httpx.Response(200, json={"token": "t", "expires_in": 1})

    c, _ = client_with(handler)
    c.mint(600, sub=None)
    assert b"sub" not in bodies[0]


def test_429_is_retried_once_after_the_requested_short_wait():
    answers = iter([httpx.Response(429, json={"error": "rate_limited", "retry_after_s": 2}, headers={"Retry-After": "2"}),
                    httpx.Response(200, json={"token": "t", "expires_in": 600})])
    c, sleeps = client_with(lambda r: next(answers))
    assert c.mint(600) == ("t", 600)
    assert sleeps == [2]


def test_persistent_429_stops_after_the_retry_budget_and_reports_the_wait():
    calls = []

    def handler(request):
        calls.append(1)
        return httpx.Response(429, json={"error": "rate_limited", "retry_after_s": 1})

    c, sleeps = client_with(handler)
    with pytest.raises(EngineUnavailable) as e:
        c.mint(600)
    assert len(calls) == 3 and sleeps == [1, 1] and e.value.retry_after_s == 1  # 1 essai + 2 nouveaux essais, jamais de boucle


def test_long_429_is_not_waited_for():
    calls = []

    def handler(request):
        calls.append(1)
        return httpx.Response(429, json={"error": "rate_limited", "retry_after_s": 60}, headers={"Retry-After": "60"})

    c, sleeps = client_with(handler)
    with pytest.raises(EngineUnavailable) as e:
        c.mint(600)
    assert len(calls) == 1 and sleeps == [] and e.value.retry_after_s == 60  # une requête ne dort pas une minute


def test_bad_key_and_network_errors_never_leak_details():
    c, _ = client_with(lambda r: httpx.Response(401, json={"error": "unauthorized"}))
    with pytest.raises(EngineUnavailable) as e:
        c.mint(600)
    assert "cle-b2b" not in str(e.value)

    def boom(request):
        raise httpx.ConnectError("refusé")

    c2, _ = client_with(boom)
    with pytest.raises(EngineUnavailable):
        c2.mint(600)


def test_erase_subject_learning_route_and_count():
    seen = {}

    def handler(request):
        seen["method"], seen["url"], seen["auth"] = request.method, str(request.url), request.headers["authorization"]
        return httpx.Response(200, json={"deleted": 3, "tenant": "ave-grand-public"})

    c, _ = client_with(handler)
    assert c.erase_subject_learning("ab" * 16) == 3
    assert seen == {"method": "DELETE", "url": f"https://ave.test/v1/subjects/{'ab' * 16}/learning", "auth": "Bearer cle-b2b"}


def test_erase_when_collection_is_not_configured_means_nothing_was_collected():
    c, _ = client_with(lambda r: httpx.Response(503, json={"error": "learning_disabled"}))
    assert c.erase_subject_learning("s" * 32) == 0


@pytest.mark.parametrize("response", [httpx.Response(401, json={"error": "unauthorized"}), httpx.Response(500),
                                      httpx.Response(503, json={"error": "autre"}), httpx.Response(503, text="pas du json")])
def test_erase_failures_are_errors_not_silent_successes(response):
    c, _ = client_with(lambda r: response)
    with pytest.raises(EngineUnavailable):
        c.erase_subject_learning("s" * 32)
