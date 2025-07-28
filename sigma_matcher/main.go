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
	"strconv"
	"strings"
	"sync"
	"time"

	sigma "github.com/markuskont/go-sigma-rule-engine"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	_ "google.golang.org/grpc/encoding/gzip"

	collectortracepb "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	tracepb "go.opentelemetry.io/proto/otlp/trace/v1"
)

/* ─── CLI 옵션 ─────────────────────────────────────────── */
var (
	listen   = flag.String("listen", ":55680", "Collector→Router 수신 포트")
	forward  = flag.String("forward", "localhost:4320", "Router→Collector 전송 포트")
	rulesDir = flag.String("rules", "rules/rules/windows", "Sigma 룰 디렉터리")
	verbose  = flag.Bool("v", false, "디버그 로그")
)

/* ─── Sigma Event 래퍼 ─────────────────────────────────── */
type MapEvent map[string]interface{}

func (m MapEvent) Keywords() ([]string, bool)          { return nil, false }
func (m MapEvent) Select(k string) (interface{}, bool) { v, ok := m[k]; return v, ok }

/* ─── 내부 구조체 ─────────────────────────────────────── */
type procInfo struct{ traceID, spanID []byte }

type traceRouter struct {
	collectortracepb.UnimplementedTraceServiceServer
	mu     sync.RWMutex
	procs  map[int]procInfo
	rs     *sigma.Ruleset
	client collectortracepb.TraceServiceClient
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
		procs:  make(map[int]procInfo),
		rs:     rs,
		client: collectortracepb.NewTraceServiceClient(conn),
	}

	lis, err := net.Listen("tcp", *listen)
	if err != nil {
		log.Fatalf("Listen 실패: %v", err)
	}
	s := grpc.NewServer()
	collectortracepb.RegisterTraceServiceServer(s, router)

	log.Printf("🚏 Router 수신 %s ➜ 전송 %s", *listen, *forward)
	if err := s.Serve(lis); err != nil {
		log.Fatalf("Serve 오류: %v", err)
	}
}

/* ─── Export 핸들러 ───────────────────────────────────── */
func (rt *traceRouter) Export(ctx context.Context, req *collectortracepb.ExportTraceServiceRequest) (*collectortracepb.ExportTraceServiceResponse, error) {
	for _, r := range req.ResourceSpans {
		for _, s := range r.ScopeSpans {
			for _, sp := range s.Spans {
				rt.rewriteSpan(sp)
				rt.applySigma(sp)
			}
		}
	}
	_, err := rt.client.Export(ctx, req)
	return &collectortracepb.ExportTraceServiceResponse{}, err
}

/* ─── 계층 재작성 ─────────────────────────────────────── */
func (rt *traceRouter) rewriteSpan(sp *tracepb.Span) {
	pid, ppid := extractPID(sp), extractPPID(sp)
	if pid == 0 {
		return
	}
	isRoot := strings.HasPrefix(sp.Name, "process:")

	rt.mu.Lock()
	defer rt.mu.Unlock()

	info, ok := rt.procs[pid]
	if !ok {
		if pInfo, ok := rt.procs[ppid]; ok {
			info.traceID = pInfo.traceID
		} else {
			info.traceID = newTraceID()
		}
		if len(sp.SpanId) == 0 {
			sp.SpanId = newSpanID()
		}
		info.spanID = sp.SpanId
		rt.procs[pid] = info
	}
	if isRoot {
		// 이미 이 PID 에 대한 루트(spanID)가 map에 존재한다면 → 중복 루트
		if len(info.spanID) != 0 && !bytes.Equal(info.spanID, sp.SpanId) {
			return
		}

		// 아직 루트가 없을 때만 저장
		info.spanID = sp.SpanId
		rt.procs[pid] = info
	}
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
		title := matches[0].Title
		sp.Attributes = append(sp.Attributes, &commonpb.KeyValue{
			Key: "sigma.alert",
			Value: &commonpb.AnyValue{
				Value: &commonpb.AnyValue_StringValue{StringValue: title},
			},
		})
		sp.Status = &tracepb.Status{
			Code:    tracepb.Status_STATUS_CODE_ERROR,
			Message: "Sigma rule matched",
		}
		log.Printf("⚠️ Sigma 매칭! trace=%x span=%x rule=%q", sp.TraceId, sp.SpanId, title)
	}
}

/* ─── Helper: Span → MapEvent ────────────────────────── */
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
func extractPPID(sp *tracepb.Span) int { return extractIntAttr(sp, "ParentProcessId", "sysmon.ppid") }

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
