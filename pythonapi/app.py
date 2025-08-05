import os
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone, timedelta

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from opensearchpy import OpenSearch, exceptions as os_exc
from dotenv import load_dotenv

load_dotenv()

# ─── OpenSearch 연결 ───────────────────────────────────────────
OPENSEARCH_HOST = os.getenv("OPENSEARCH_HOST", "localhost")
OPENSEARCH_PORT = int(os.getenv("OPENSEARCH_PORT", 9200))
TRACE_INDEX    = os.getenv("TRACE_INDEX_PATTERN", "jaeger-span-*")

client = OpenSearch(
    hosts=[{"host": OPENSEARCH_HOST, "port": OPENSEARCH_PORT}],
    http_compress=True,
    timeout=30,
    retry_on_timeout=True,
    max_retries=5,
)

# ─── KST 타임존 객체 ───────────────────────────────────────────
KST = timezone(timedelta(hours=9))

# ─── 시각 변환 유틸 ────────────────────────────────────────────
FMT = "%Y-%m-%d %H:%M:%S"          # 포맷

def to_millis(dt_str: str) -> int:  # 입력 → epoch millis
    try:
        dt = datetime.strptime(dt_str, FMT).replace(tzinfo=KST)
    except ValueError:
        raise HTTPException(400, f"time format must be '{FMT}'")
    return int(dt.timestamp() * 1000)

def millis_to_str(ms: int) -> str:  # epoch millis → KST 문자열
    dt = datetime.fromtimestamp(ms / 1000, KST)
    return dt.strftime(FMT)

def _os_query(index: str, body: Dict[str, Any], size: int = 10_000):
    try:
        return client.search(index=index, body=body, size=size)
    except os_exc.OpenSearchException as e:
        raise HTTPException(500, f"OpenSearch error: {e}")

# ─── FastAPI 설정 ──────────────────────────────────────────────
app = FastAPI(title="Trace Query API", version="1.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], allow_methods=["*"], allow_headers=["*"]
)

# ─── 1) Trace 목록 ─────────────────────────────────────────────
@app.get("/traces", summary="Trace 목록 조회")
def list_traces(
    start: Optional[str] = Query(None, description=f"시작 시각({FMT})"),
    end:   Optional[str] = Query(None, description=f"종료 시각({FMT})"),
    limit: int           = Query(100, ge=1, le=10_000),
    order: str           = Query("desc", enum=["asc", "desc"])
):
    must: List[Dict[str, Any]] = []
    if start or end:
        range_q = {"range": {"startTimeMillis": {}}}
        if start: range_q["range"]["startTimeMillis"]["gte"] = to_millis(start)
        if end:   range_q["range"]["startTimeMillis"]["lte"] = to_millis(end)
        must.append(range_q)

    body = {
        "size": 0,
        "query": {"bool": {"must": must}} if must else {"match_all": {}},
        "aggs": {
            "traces": {
                "terms": {
                    "field": "traceID",
                    "size": limit,
                    "order": {"max_start": order}
                },
                "aggs": {
                    "max_start": {"max": {"field": "startTimeMillis"}},
                    "first_span": {
                        "top_hits": {
                            "size": 1,
                            "_source": ["startTimeMillis", "sigma.alert"]
                        }
                    }
                }
            }
        },
    }
    res = _os_query(TRACE_INDEX, body, size=0)
    traces = []
    for b in res["aggregations"]["traces"]["buckets"]:
        doc = b["first_span"]["hits"]["hits"][0]["_source"]
        traces.append({
            "trace_id":  b["key"],
            "span_count": b["doc_count"],
            "start_time": millis_to_str(doc["startTimeMillis"]),  # 포맷 변환
            "alert":      doc.get("sigma.alert")
        })
    return traces

# ─── 2) Trace 상세 ─────────────────────────────────────────────
@app.get("/traces/{trace_id}", summary="Trace 상세(스팬 전체)")
def get_trace(trace_id: str):
    body = {"query": {"term": {"traceID": trace_id}}}
    res = _os_query(TRACE_INDEX, body)
    spans = [h["_source"] for h in res["hits"]["hits"]]
    if not spans:
        raise HTTPException(404, "Trace not found")

    for s in spans:                      
        s["startTime"] = millis_to_str(s["startTimeMillis"])

    return {"trace_id": trace_id, "span_count": len(spans), "spans": spans}

# ─── 3) Timeline ───────────────────────────────────
@app.get("/stats/timeline", summary="기간별 Trace 수")
def timeline(
    start: str = Query(..., description=FMT),
    end:   str = Query(..., description=FMT),
    interval: str = Query("1h", description="예: 1h, 30m, 1d")
):
    body = {
        "size": 0,
        "query": {
            "range": {
                "startTimeMillis": {
                    "gte": to_millis(start),
                    "lte": to_millis(end)
                }
            }
        },
        "aggs": {
            "events_over_time": {
                "date_histogram": {
                    "field": "startTimeMillis",
                    "fixed_interval": interval
                }
            }
        }
    }
    res = _os_query(TRACE_INDEX, body, size=0)
    return [
        {"time": millis_to_str(b["key"]), "count": b["doc_count"]}
        for b in res["aggregations"]["events_over_time"]["buckets"]
    ]

# ─── 4) OpenSearch DSL ────────────────────────────────────
@app.post("/search", summary="OpenSearch DSL")
def dsl_search(body: Dict[str, Any]):
    res = _os_query(TRACE_INDEX, body)
    return res["hits"]

# ─── 헬스체크 ──────────────────────────────────────────────────
@app.get("/healthz")
def health():
    try:
        client.cluster.health()
        return {"status": "ok"}
    except os_exc.ConnectionError:
        raise HTTPException(503, "OpenSearch unavailable")