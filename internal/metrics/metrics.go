// Package metrics provides a small dependency-free metrics registry that
// renders the Prometheus text exposition format. It supports labeled
// counters, a single-value gauge, and labeled histograms; series are created
// on first use. Label values are escaped on output, and cardinality is the
// caller's responsibility — use route patterns, not raw paths.
package metrics

import (
	"fmt"
	"io"
	"net/http"
	"runtime"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// kind enumerates the metric types the registry can render.
type kind int

const (
	kindCounter kind = iota
	kindGauge
	kindHistogram
)

func (k kind) typeName() string {
	switch k {
	case kindCounter:
		return "counter"
	case kindGauge:
		return "gauge"
	default:
		return "histogram"
	}
}

// series holds the value(s) of one label combination: a single float for
// counters and gauges, or bucket counts plus sum/count for histograms.
type series struct {
	labels  []string
	value   float64  // counters and gauges
	count   uint64   // histograms
	sum     float64  // histograms
	buckets []uint64 // histograms, one slot per upper bound
}

// family is one registered metric: its metadata plus every observed series.
type family struct {
	name       string
	help       string
	kind       kind
	labelNames []string
	bounds     []float64 // histograms only, ascending

	mu     sync.Mutex
	series map[string]*series
}

// labelCount panics when values does not match the family's label names.
func (f *family) labelCount(values []string) {
	if len(values) != len(f.labelNames) {
		panic(fmt.Sprintf("metrics: %s expects %d label values, got %d", f.name, len(f.labelNames), len(values)))
	}
}

// seriesFor returns the series for values, creating it on first use. The
// caller must hold f.mu.
func (f *family) seriesFor(values []string) *series {
	key := strings.Join(values, "\xff")
	s, ok := f.series[key]
	if !ok {
		s = &series{labels: slices.Clone(values)}
		if f.kind == kindHistogram {
			s.buckets = make([]uint64, len(f.bounds))
		}
		f.series[key] = s
	}
	return s
}

// add increments a counter or gauge series by delta.
func (f *family) add(delta float64, values []string) {
	f.labelCount(values)
	f.mu.Lock()
	defer f.mu.Unlock()
	s := f.seriesFor(values)
	s.value += delta
}

// set replaces a gauge series value.
func (f *family) set(v float64, values []string) {
	f.labelCount(values)
	f.mu.Lock()
	defer f.mu.Unlock()
	s := f.seriesFor(values)
	s.value = v
}

// observe records one histogram observation.
func (f *family) observe(v float64, values []string) {
	f.labelCount(values)
	f.mu.Lock()
	defer f.mu.Unlock()
	s := f.seriesFor(values)
	s.count++
	s.sum += v
	if i := searchFloat64s(f.bounds, v); i < len(s.buckets) {
		s.buckets[i]++
	}
}

// searchFloat64s returns the index of the first bound >= v.
func searchFloat64s(bounds []float64, v float64) int {
	return sort.Search(len(bounds), func(i int) bool { return bounds[i] >= v })
}

// CounterVec is a monotonically increasing counter with labels.
type CounterVec struct{ f *family }

// Inc adds 1 to the series identified by values.
func (c *CounterVec) Inc(values ...string) { c.f.add(1, values) }

// Add adds delta to the series identified by values. Delta must be
// non-negative for a well-formed counter; the registry does not enforce it.
func (c *CounterVec) Add(delta float64, values ...string) { c.f.add(delta, values) }

// Gauge is a single-value metric that can go up and down.
type Gauge struct{ f *family }

// Inc adds 1 to the gauge.
func (g *Gauge) Inc() { g.f.add(1, nil) }

// Dec subtracts 1 from the gauge.
func (g *Gauge) Dec() { g.f.add(-1, nil) }

// Set replaces the gauge value.
func (g *Gauge) Set(v float64) { g.f.set(v, nil) }

// HistogramVec counts observations into buckets with labels. Buckets are
// rendered cumulative, as Prometheus expects.
type HistogramVec struct{ f *family }

// Observe records v in the series identified by values.
func (h *HistogramVec) Observe(v float64, values ...string) { h.f.observe(v, values) }

// Registry holds registered metric families and renders them in the
// Prometheus text exposition format.
type Registry struct {
	mu       sync.Mutex
	families []*family
	byName   map[string]struct{}
}

// NewRegistry returns an empty Registry.
func NewRegistry() *Registry {
	return &Registry{byName: map[string]struct{}{}}
}

// register adds f to the registry, panicking on a duplicate name.
func (r *Registry) register(f *family) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, dup := r.byName[f.name]; dup {
		panic("metrics: duplicate metric name " + f.name)
	}
	r.byName[f.name] = struct{}{}
	r.families = append(r.families, f)
}

// CounterVec registers and returns a labeled counter.
func (r *Registry) CounterVec(name, help string, labels ...string) *CounterVec {
	f := &family{name: name, help: help, kind: kindCounter, labelNames: labels, series: map[string]*series{}}
	r.register(f)
	return &CounterVec{f: f}
}

// Gauge registers and returns a single-value gauge.
func (r *Registry) Gauge(name, help string) *Gauge {
	f := &family{name: name, help: help, kind: kindGauge, series: map[string]*series{}}
	r.register(f)
	return &Gauge{f: f}
}

// HistogramVec registers and returns a labeled histogram. Buckets are copied
// and sorted ascending; at least one bucket is required.
func (r *Registry) HistogramVec(name, help string, buckets []float64, labels ...string) *HistogramVec {
	if len(buckets) == 0 {
		panic("metrics: histogram " + name + " needs at least one bucket")
	}
	bounds := slices.Clone(buckets)
	slices.Sort(bounds)
	f := &family{name: name, help: help, kind: kindHistogram, labelNames: labels, bounds: bounds, series: map[string]*series{}}
	r.register(f)
	return &HistogramVec{f: f}
}

// Handler serves the registry over HTTP in the Prometheus text exposition
// format, ready to be scraped.
func (r *Registry) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		r.Render(w)
	})
}

// labelEscaper escapes label values per the exposition format.
var labelEscaper = strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`)

// helpEscaper escapes HELP doc strings (backslash and newline only).
var helpEscaper = strings.NewReplacer(`\`, `\\`, "\n", `\n`)

// writeSeriesLine writes one exposition line: name, optional label set,
// optional le label, and the formatted value.
func writeSeriesLine(b *strings.Builder, name string, names, values []string, le, v string) {
	b.WriteString(name)
	if len(names) > 0 || le != "" {
		b.WriteByte('{')
		for i, n := range names {
			if i > 0 {
				b.WriteByte(',')
			}
			b.WriteString(n)
			b.WriteString(`="`)
			_, _ = labelEscaper.WriteString(b, values[i])
			b.WriteByte('"')
		}
		if le != "" {
			if len(names) > 0 {
				b.WriteByte(',')
			}
			b.WriteString(`le="`)
			b.WriteString(le)
			b.WriteByte('"')
		}
		b.WriteByte('}')
	}
	b.WriteByte(' ')
	b.WriteString(v)
	b.WriteByte('\n')
}

// formatFloat renders a metric value without trailing zeros.
func formatFloat(v float64) string {
	return strconv.FormatFloat(v, 'g', -1, 64)
}

// render appends one family's HELP, TYPE, and series lines.
func (f *family) render(b *strings.Builder) {
	f.mu.Lock()
	defer f.mu.Unlock()

	b.WriteString("# HELP ")
	b.WriteString(f.name)
	b.WriteByte(' ')
	_, _ = helpEscaper.WriteString(b, f.help)
	b.WriteByte('\n')
	b.WriteString("# TYPE ")
	b.WriteString(f.name)
	b.WriteByte(' ')
	b.WriteString(f.kind.typeName())
	b.WriteByte('\n')

	keys := make([]string, 0, len(f.series))
	for k := range f.series {
		keys = append(keys, k)
	}
	slices.Sort(keys)

	for _, k := range keys {
		s := f.series[k]
		if f.kind != kindHistogram {
			writeSeriesLine(b, f.name, f.labelNames, s.labels, "", formatFloat(s.value))
			continue
		}
		var cumulative uint64
		for i, bound := range f.bounds {
			cumulative += s.buckets[i]
			writeSeriesLine(b, f.name+"_bucket", f.labelNames, s.labels, formatFloat(bound), strconv.FormatUint(cumulative, 10))
		}
		writeSeriesLine(b, f.name+"_bucket", f.labelNames, s.labels, "+Inf", strconv.FormatUint(s.count, 10))
		writeSeriesLine(b, f.name+"_sum", f.labelNames, s.labels, "", formatFloat(s.sum))
		writeSeriesLine(b, f.name+"_count", f.labelNames, s.labels, "", strconv.FormatUint(s.count, 10))
	}
}

// writeRuntime appends a few Go runtime gauges collected at scrape time.
func writeRuntime(b *strings.Builder) {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	_, _ = fmt.Fprintf(b, "# HELP go_goroutines Number of live goroutines.\n# TYPE go_goroutines gauge\ngo_goroutines %d\n", runtime.NumGoroutine())
	_, _ = fmt.Fprintf(b, "# HELP go_memstats_alloc_bytes Bytes of allocated heap objects not yet freed.\n# TYPE go_memstats_alloc_bytes gauge\ngo_memstats_alloc_bytes %d\n", m.Alloc)
}

// Render writes every registered family plus Go runtime metrics to w in the
// Prometheus text exposition format. Series within a family are sorted by
// label key so output is deterministic.
func (r *Registry) Render(w io.Writer) {
	r.mu.Lock()
	families := slices.Clone(r.families)
	r.mu.Unlock()

	var b strings.Builder
	for _, f := range families {
		f.render(&b)
	}
	writeRuntime(&b)
	_, _ = io.WriteString(w, b.String())
}
