// trace_router_buffered.go
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	sigma "github.com/markuskont/go-sigma-rule-engine"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	_ "google.golang.org/grpc/encoding/gzip"
	"google.golang.org/protobuf/proto"

	collectortracepb "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	resourcepb "go.opentelemetry.io/proto/otlp/resource/v1"
	tracepb "go.opentelemetry.io/proto/otlp/trace/v1"
)

/* ─── CLI 옵션 ─────────────────────────────────────────── */
var (
	listen   = flag.String("listen", ":55680", "Collector→Router 수신 포트")
	forward  = flag.String("forward", "localhost:4320", "Router→Collector 전송 포트")
	rulesDir = flag.String("rules", "rules/rules/windows", "Sigma 룰 디렉터리")
	verbose  = flag.Bool("v", false, "디버그 로그")

	// 버퍼/보호 옵션
	traceTTL         = flag.Duration("trace_ttl", 10*time.Minute, "루트 종료 누락 시 Trace TTL(강제 flush)")
	maxSpansPerTrace = flag.Int("max_spans", 20000, "Trace당 최대 스팬 수(초과시 강제 flush)")
)

/* ─── Sigma Event 래퍼 ─────────────────────────────────── */
type MapEvent map[string]interface{}

func (m MapEvent) Keywords() ([]string, bool)          { return nil, false }
func (m MapEvent) Select(k string) (interface{}, bool) { v, ok := m[k]; return v, ok }

/* ─── 내부 구조체 ─────────────────────────────────────── */
type procInfo struct {
	traceID []byte
	spanID  []byte // 루트 spanID (process:<pid>)
	root    bool   // 부모 미상으로 시작한 경우 루트 간주
	ppid    int
}

type scopeKey struct {
	Name    string
	Version string
}

type resKey string

// Trace 버퍼(TraceID 단위로 누적)
type traceBuffer struct {
	// Resource별 → Scope별 → Spans
	byResScope map[resKey]map[scopeKey][]*tracepb.Span
	// 각 키의 원본 Resource/Scope 보존(플러시 조립용)
	resMeta   map[resKey]*resourcepb.Resource
	scopeMeta map[scopeKey]*commonpb.InstrumentationScope

	firstSeen time.Time
	lastSeen  time.Time
	spanCount int

	// 트레이스 내 PID 상태
	activePIDs     map[int]struct{} // 아직 종료 스팬(EID=5)을 못 본 PID
	terminatedPIDs map[int]struct{} // 종료 스팬을 본 PID
	rootPID        int              // 선택: 최초 루트 PID 추적(정보성)
}

// 메인 라우터
type traceRouter struct {
	collectortracepb.UnimplementedTraceServiceServer
	mu        sync.RWMutex
	procs     map[int]procInfo // PID → info
	rs        *sigma.Ruleset
	client    collectortracepb.TraceServiceClient
	buffers   map[string]*traceBuffer // hex(traceID) → buffer
	ttlStopCh chan struct{}
}

/* ─── main ────────────────────────────────────────────── */
func main() {
	flag.Parse()

	rs, err := sigma.NewRuleset(sigma.Config{Directory: []string{*rulesDir}})
	if err != nil {
		log.Fatalf("Sigma 룰 로드 실패: %v", err)
	}
	log.Printf("✅ Sigma 룰 %d개 로드", len(rs.Rules))

	conn, err := grpc.Dial(*forward, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatalf("Collector 연결 실패: %v", err)
	}

	router := &traceRouter{
		procs:     make(map[int]procInfo),
		rs:        rs,
		client:    collectortracepb.NewTraceServiceClient(conn),
		buffers:   make(map[string]*traceBuffer),
		ttlStopCh: make(chan struct{}),
	}
	go router.ttlGC()

	lis, err := net.Listen("tcp", *listen)
	if err != nil {
		log.Fatalf("Listen 실패: %v", err)
	}
	s := grpc.NewServer()
	collectortracepb.RegisterTraceServiceServer(s, router)

	log.Printf("🚏 Router 수신 %s ➜ 전송 %s (모든 PID 종료 시 flush)", *listen, *forward)
	if err := s.Serve(lis); err != nil {
		log.Fatalf("Serve 오류: %v", err)
	}
}

/* ─── Export 핸들러 ───────────────────────────────────── */
func (rt *traceRouter) Export(ctx context.Context, req *collectortracepb.ExportTraceServiceRequest) (*collectortracepb.ExportTraceServiceResponse, error) {
	var toFlushTraceIDs [][]byte

	// 모든 스팬 재작성 + 매칭 + 버퍼링
	for _, r := range req.ResourceSpans {
		rk := makeResKey(r.Resource)
		for _, s := range r.ScopeSpans {
			sk := scopeKey{Name: s.Scope.GetName(), Version: s.Scope.GetVersion()}
			for _, sp := range s.Spans {
				rt.rewriteSpan(sp) // Trace/Parent 보정
				rt.applySigma(sp)  // sigma.alert 부여(있다면)

				if len(sp.TraceId) == 0 {
					continue
				}
				pid := extractPID(sp)
				term := isTerminateEvent(sp)

				flushNow := rt.bufferSpanAndUpdatePID(sp.TraceId, rk, r.Resource, sk, s.Scope, sp, pid, term)
				if flushNow {
					toFlushTraceIDs = append(toFlushTraceIDs, sp.TraceId)
				}
			}
		}
	}

	// flush 대상 트레이스들 전송
	for _, tid := range toFlushTraceIDs {
		rt.flushTrace(tid)
	}
	// 실시간 전송 없음(버퍼링/조건부 플러시)
	return &collectortracepb.ExportTraceServiceResponse{}, nil
}

/* ─── 버퍼링 + PID 상태 갱신 ─────────────────────────── */
func (rt *traceRouter) bufferSpanAndUpdatePID(
	traceID []byte,
	rk resKey, res *resourcepb.Resource,
	sk scopeKey, scope *commonpb.InstrumentationScope,
	sp *tracepb.Span,
	pid int, isTerm bool,
) (shouldFlush bool) {
	rt.mu.Lock()
	defer rt.mu.Unlock()

	key := hex(traceID)
	tb := rt.buffers[key]
	if tb == nil {
		tb = &traceBuffer{
			byResScope:     make(map[resKey]map[scopeKey][]*tracepb.Span),
			resMeta:        make(map[resKey]*resourcepb.Resource),
			scopeMeta:      make(map[scopeKey]*commonpb.InstrumentationScope),
			firstSeen:      time.Now(),
			activePIDs:     make(map[int]struct{}),
			terminatedPIDs: make(map[int]struct{}),
		}
		rt.buffers[key] = tb
	}
	tb.lastSeen = time.Now()

	// 메타 보존
	if _, ok := tb.resMeta[rk]; !ok && res != nil {
		tb.resMeta[rk] = proto.Clone(res).(*resourcepb.Resource)
	}
	if _, ok := tb.scopeMeta[sk]; !ok && scope != nil {
		tb.scopeMeta[sk] = proto.Clone(scope).(*commonpb.InstrumentationScope)
	}

	// 스팬 복사 후 누적
	cloned := proto.Clone(sp).(*tracepb.Span)
	if tb.byResScope[rk] == nil {
		tb.byResScope[rk] = make(map[scopeKey][]*tracepb.Span)
	}
	tb.byResScope[rk][sk] = append(tb.byResScope[rk][sk], cloned)
	tb.spanCount++

	// PID 상태 갱신
	if pid != 0 {
		if isTerm {
			delete(tb.activePIDs, pid)
			tb.terminatedPIDs[pid] = struct{}{}
		} else {
			if _, done := tb.terminatedPIDs[pid]; !done {
				tb.activePIDs[pid] = struct{}{}
			}
		}
	}

	// 보호: 스팬 과다 시 즉시 flush
	if tb.spanCount > *maxSpansPerTrace {
		return true
	}
	// 핵심: 활성 PID가 하나도 없으면(= 모든 PID 종료) flush
	if len(tb.activePIDs) == 0 && len(tb.terminatedPIDs) > 0 {
		return true
	}
	return false
}

/* ─── 플러시(조립 → Export) ──────────────────────────── */
func (rt *traceRouter) flushTrace(traceID []byte) {
	rt.mu.Lock()
	key := hex(traceID)
	tb := rt.buffers[key]
	if tb == nil {
		rt.mu.Unlock()
		return
	}
	delete(rt.buffers, key) // 먼저 제거(중복 flush 방지)
	rt.mu.Unlock()

	// 조립
	var out []*tracepb.ResourceSpans
	// resKey 정렬로 결정적 순서
	resKeys := make([]resKey, 0, len(tb.byResScope))
	for rk := range tb.byResScope {
		resKeys = append(resKeys, rk)
	}
	sort.Slice(resKeys, func(i, j int) bool { return resKeys[i] < resKeys[j] })

	for _, rk := range resKeys {
		scopeMap := tb.byResScope[rk]
		scopeKeys := make([]scopeKey, 0, len(scopeMap))
		for sk := range scopeMap {
			scopeKeys = append(scopeKeys, sk)
		}
		sort.Slice(scopeKeys, func(i, j int) bool {
			if scopeKeys[i].Name == scopeKeys[j].Name {
				return scopeKeys[i].Version < scopeKeys[j].Version
			}
			return scopeKeys[i].Name < scopeKeys[j].Name
		})

		rsp := &tracepb.ResourceSpans{}
		if meta := tb.resMeta[rk]; meta != nil {
			rsp.Resource = proto.Clone(meta).(*resourcepb.Resource)
		}
		for _, sk := range scopeKeys {
			spans := scopeMap[sk]
			rsp.ScopeSpans = append(rsp.ScopeSpans, &tracepb.ScopeSpans{
				Scope: tb.scopeMeta[sk],
				Spans: spans,
			})
		}
		out = append(out, rsp)
	}

	req := &collectortracepb.ExportTraceServiceRequest{ResourceSpans: out}
	_, err := rt.client.Export(context.Background(), req)
	if err != nil {
		log.Printf("❌ flush 실패 trace=%s: %v", key, err)
	} else if *verbose {
		log.Printf("✅ flush 완료 trace=%s spans=%d", key, tb.spanCount)
	}

	// 이 트레이스에 속한 PID 정리(선택)
	rt.cleanupPIDsForTrace(traceID)
}

func (rt *traceRouter) cleanupPIDsForTrace(traceID []byte) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	for pid, info := range rt.procs {
		if bytes.Equal(info.traceID, traceID) {
			delete(rt.procs, pid)
		}
	}
}

/* ─── TTL GC: 종료 누락 대비 ─────────────────────────── */
func (rt *traceRouter) ttlGC() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			now := time.Now()
			rt.mu.RLock()
			var expired [][]byte
			for key, tb := range rt.buffers {
				if now.Sub(tb.lastSeen) > *traceTTL {
					expired = append(expired, unhex(key))
				}
			}
			rt.mu.RUnlock()
			for _, tid := range expired {
				if *verbose {
					log.Printf("⏰ TTL flush trace=%x", tid)
				}
				rt.flushTrace(tid)
			}
		case <-rt.ttlStopCh:
			return
		}
	}
}

/* ─── 계층 재작성 ─────────────────────────────────────── */
func (rt *traceRouter) rewriteSpan(sp *tracepb.Span) {
	pid, ppid := extractPID(sp), extractPPID(sp)
	if pid == 0 {
		return
	}
	isRootName := strings.HasPrefix(sp.Name, "process:")

	rt.mu.Lock()
	defer rt.mu.Unlock()

	info, ok := rt.procs[pid]
	if !ok {
		// traceID 상속 or 신규 생성
		if pInfo, ok := rt.procs[ppid]; ok {
			info.traceID = pInfo.traceID
			info.root = false
		} else {
			info.traceID = newTraceID()
			info.root = true // 부모 미상 → 루트로 간주
		}
		if len(sp.SpanId) == 0 {
			sp.SpanId = newSpanID()
		}
		info.spanID = sp.SpanId
		info.ppid = ppid
		rt.procs[pid] = info

		// 버퍼에도 rootPID 초기화(정보성)
		tb := rt.buffers[hex(info.traceID)]
		if tb == nil {
			tb = &traceBuffer{
				byResScope:     make(map[resKey]map[scopeKey][]*tracepb.Span),
				resMeta:        make(map[resKey]*resourcepb.Resource),
				scopeMeta:      make(map[scopeKey]*commonpb.InstrumentationScope),
				firstSeen:      time.Now(),
				activePIDs:     make(map[int]struct{}),
				terminatedPIDs: make(map[int]struct{}),
			}
			rt.buffers[hex(info.traceID)] = tb
		}
		if info.root && tb.rootPID == 0 {
			tb.rootPID = pid
		}
	}

	// 루트 스팬 중복 방지
	if isRootName {
		if len(info.spanID) != 0 && !bytes.Equal(info.spanID, sp.SpanId) {
			return
		}
		info.spanID = sp.SpanId
		rt.procs[pid] = info
	}

	// 부모 연결
	if pInfo, ok := rt.procs[ppid]; ok && ppid != 0 && pid != ppid {
		sp.ParentSpanId = pInfo.spanID
	}
	sp.TraceId = info.traceID

	if *verbose {
		fmt.Printf("rewrite pid=%d ppid=%d trace=%x\n", pid, ppid, sp.TraceId)
	}
}

/* ─── Sigma 매칭 + 표시 ──────────────────────────────── */
func (rt *traceRouter) applySigma(sp *tracepb.Span) {
	ev := spanToEvent(sp)

	if matches, ok := rt.rs.EvalAll(ev); ok && len(matches) > 0 {
		rule := matches[0] // 첫 번째 일치 규칙
		title := rule.Title
		rid := rule.ID

		sp.Attributes = append(sp.Attributes,
			&commonpb.KeyValue{Key: "sigma.alert", Value: strVal(rid)},
			&commonpb.KeyValue{Key: "sigma.rule_title", Value: strVal(title)},
		)
		sp.Status = &tracepb.Status{
			Code:    tracepb.Status_STATUS_CODE_ERROR,
			Message: "Sigma rule matched",
		}
		log.Printf("⚠️ Sigma 매칭! trace=%x span=%x rule=%s title=%s",
			sp.TraceId, sp.SpanId, rid, title)
	}
}

func strVal(s string) *commonpb.AnyValue {
	return &commonpb.AnyValue{
		Value: &commonpb.AnyValue_StringValue{StringValue: s},
	}
}

/* ─── 종료 이벤트 감지 ───────────────────────────────── */
func isTerminateEvent(sp *tracepb.Span) bool {
	// Sysmon ProcessTerminate == EventID 5
	eid := extractIntAttr(sp, "ID", "EventID", "event.id")
	return eid == 5
}

/* ─── Span → Sigma Event ─────────────────────────────── */
func spanToEvent(sp *tracepb.Span) sigma.Event {
	out := make(MapEvent, len(sp.Attributes))
	for _, kv := range sp.Attributes {
		switch v := kv.Value.Value.(type) {
		case *commonpb.AnyValue_StringValue:
			out[kv.Key] = v.StringValue
		case *commonpb.AnyValue_IntValue:
			out[kv.Key] = v.IntValue
		case *commonpb.AnyValue_BoolValue:
			out[kv.Key] = v.BoolValue
		}
	}
	return out
}

/* ─── 난수 ID 생성 ───────────────────────────────────── */
func newTraceID() []byte {
	id := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, id); err != nil {
		binary.LittleEndian.PutUint64(id, uint64(time.Now().UnixNano()))
	}
	return id
}
func newSpanID() []byte {
	id := make([]byte, 8)
	if _, err := io.ReadFull(rand.Reader, id); err != nil {
		binary.LittleEndian.PutUint32(id, uint32(time.Now().UnixNano()))
	}
	return id
}

/* ─── Attribute 파싱 ────────────────────────────────── */
func extractPID(sp *tracepb.Span) int {
	if strings.HasPrefix(sp.Name, "process:") {
		if p, err := strconv.Atoi(strings.TrimPrefix(sp.Name, "process:")); err == nil {
			return p
		}
	}
	return extractIntAttr(sp, "sysmon.pid", "pid", "ProcessId")
}
func extractPPID(sp *tracepb.Span) int {
	return extractIntAttr(sp, "ParentProcessId", "sysmon.ppid")
}

func extractIntAttr(sp *tracepb.Span, keys ...string) int {
	for _, kv := range sp.Attributes {
		for _, k := range keys {
			if kv.Key == k {
				switch v := kv.Value.Value.(type) {
				case *commonpb.AnyValue_StringValue:
					if p, err := strconv.Atoi(v.StringValue); err == nil {
						return p
					}
				case *commonpb.AnyValue_IntValue:
					return int(v.IntValue)
				}
			}
		}
	}
	return 0
}

/* ─── 키 유틸 ───────────────────────────────────────── */
func makeResKey(res *resourcepb.Resource) resKey {
	if res == nil || len(res.Attributes) == 0 {
		return resKey("")
	}
	parts := make([]string, 0, len(res.Attributes))
	for _, kv := range res.Attributes {
		parts = append(parts, kv.Key+"="+anyToStr(kv.Value))
	}
	sort.Strings(parts)
	return resKey(strings.Join(parts, "|"))
}

func anyToStr(v *commonpb.AnyValue) string {
	switch x := v.Value.(type) {
	case *commonpb.AnyValue_StringValue:
		return x.StringValue
	case *commonpb.AnyValue_IntValue:
		return strconv.FormatInt(x.IntValue, 10)
	case *commonpb.AnyValue_BoolValue:
		if x.BoolValue {
			return "true"
		}
		return "false"
	default:
		return ""
	}
}

func hex(b []byte) string {
	const hexdigits = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, v := range b {
		out[i*2] = hexdigits[v>>4]
		out[i*2+1] = hexdigits[v&0x0f]
	}
	return string(out)
}

func unhex(s string) []byte {
	n := len(s) / 2
	out := make([]byte, n)
	for i := 0; i < n; i++ {
		fmt.Sscanf(s[2*i:2*i+2], "%02x", &out[i])
	}
	return out
}
