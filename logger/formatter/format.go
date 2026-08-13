// Copyright 2026 PointerByte Contributors
// SPDX-License-Identifier: Apache-2.0

package formatter

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"text/template"
)

type Formatter interface {
	Format(log LogFormat) ([]byte, error)
}

func New(template string) *CustomFormatter {
	return &CustomFormatter{Template: template}
}

type CustomFormatter struct {
	Template string
}

const defaultJSONTemplate = `{"timestamp":{{json .Timestamp}},"traceID":{{json .TraceID}},"level":{{json .Level}},"message":{{json .Message}},"details":{{json (buildDetails .Details)}},"process":{{json (buildServices .Process)}}{{if .Attributes}},"attributes":{{json .Attributes}}{{end}},"method":{{json .Method}},"line":{{json .Line}},"latency":{{json .Latency}}}`

func (f *CustomFormatter) Format(log LogFormat) ([]byte, error) {
	log = log.Normalize()
	switch strings.ToLower(strings.TrimSpace(f.Template)) {
	case "json":
		return f.FormatJSON(log)
	case "text", "txt", "":
		return f.FormatText(log)
	default:
		return f.FormatTemplate(log)
	}
}

func (f *CustomFormatter) FormatJSON(log LogFormat) ([]byte, error) {
	return f.executeTemplate(defaultJSONTemplate, log)
}

func (f *CustomFormatter) FormatText(log LogFormat) ([]byte, error) {
	var b strings.Builder
	fmt.Fprintf(
		&b,
		"[%s] [%v] [%s] %s:%d - %s",
		log.Timestamp,
		log.Level,
		log.TraceID,
		log.Method,
		log.Line,
		log.Message,
	)

	if log.Latency > 0 {
		fmt.Fprintf(&b, " latency=%dms", log.Latency)
	}

	// Details
	if log.Details.System != "" ||
		log.Details.Client != "" ||
		log.Details.Protocol != "" ||
		log.Details.Method != "" ||
		log.Details.Path != "" ||
		len(log.Details.Headers) > 0 ||
		log.Details.Request != nil ||
		log.Details.Response != nil ||
		log.Details.RequestCapture != nil ||
		log.Details.ResponseCapture != nil {

		b.WriteString(" | details={")

		first := true
		writeField := func(name string, value any) {
			if !first {
				b.WriteString(", ")
			}
			first = false
			fmt.Fprintf(&b, "%s=%v", name, value)
		}

		if log.Details.System != "" {
			writeField("system", log.Details.System)
		}
		if log.Details.Client != "" {
			writeField("client", log.Details.Client)
		}
		if log.Details.Protocol != "" {
			writeField("protocol", log.Details.Protocol)
		}
		if log.Details.Method != "" {
			writeField("method", log.Details.Method)
		}
		if log.Details.Path != "" {
			writeField("path", log.Details.Path)
		}
		if len(log.Details.Headers) > 0 {
			writeField("headers", toJSON(log.Details.Headers))
		}
		if log.Details.Request != nil {
			writeField("request", toJSON(log.Details.Request))
		}
		if log.Details.Response != nil {
			writeField("response", toJSON(log.Details.Response))
		}
		if log.Details.RequestCapture != nil {
			writeField("requestCapture", toJSON(log.Details.RequestCapture))
		}
		if log.Details.ResponseCapture != nil {
			writeField("responseCapture", toJSON(log.Details.ResponseCapture))
		}

		b.WriteString("}")
	}

	if len(log.Attributes) > 0 {
		fmt.Fprintf(&b, " | attributes=%s", toJSON(log.Attributes))
	}

	// Services
	if len(log.Process) > 0 {
		b.WriteString(" | services=[")
		for i, s := range log.Process {
			if i > 0 {
				b.WriteString(", ")
			}

			b.WriteString("{")
			first := true

			writeServiceField := func(name string, value any) {
				if !first {
					b.WriteString(", ")
				}
				first = false
				fmt.Fprintf(&b, "%s=%v", name, value)
			}

			if s.TraceID != "" {
				writeServiceField("traceID", s.TraceID)
			}
			if s.SpanID != "" {
				writeServiceField("spanID", s.SpanID)
			}
			if s.System != "" {
				writeServiceField("system", s.System)
			}
			if s.Process != "" {
				writeServiceField("process", s.Process)
			}
			if s.Server != "" {
				writeServiceField("server", s.Server)
			}
			if s.Headers != nil {
				writeServiceField("headers", toJSON(*s.Headers))
			}
			if s.Protocol != "" {
				writeServiceField("protocol", s.Protocol)
			}
			if s.Method != "" {
				writeServiceField("method", s.Method)
			}
			if s.Path != "" {
				writeServiceField("path", s.Path)
			}
			if s.Code != 0 {
				writeServiceField("code", s.Code)
			}
			if s.Request != nil {
				writeServiceField("request", toJSON(s.Request))
			}
			if s.Response != nil {
				writeServiceField("response", toJSON(s.Response))
			}
			if s.ResponseCapture != nil {
				writeServiceField("responseCapture", toJSON(s.ResponseCapture))
			}
			if s.Status != "" {
				writeServiceField("status", s.Status)
			}
			if s.Latency != 0 {
				writeServiceField("latency", fmt.Sprintf("%dms", s.Latency))
			}

			b.WriteString("}")
		}
		b.WriteString("]")
	}
	return []byte(b.String()), nil
}

func toJSON(v any) string {
	if v == nil {
		return ""
	}
	b, err := json.Marshal(v)
	if err != nil {
		return fmt.Sprintf("%v", v)
	}
	return string(b)
}

func (f *CustomFormatter) FormatTemplate(log LogFormat) ([]byte, error) {
	return f.executeTemplate(f.Template, log)
}

func (f *CustomFormatter) executeTemplate(tpl string, log LogFormat) ([]byte, error) {
	log = log.Normalize()
	funcMap := template.FuncMap{
		"json": func(v any) (string, error) {
			b, err := json.Marshal(v)
			return string(b), err
		},
		"buildDetails":  buildDetails,
		"buildServices": buildServices,
	}

	tmpl, err := template.New("log").Funcs(funcMap).Parse(tpl)
	if err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, log); err != nil {
		return nil, err
	}
	logf := bytes.TrimSpace(buf.Bytes())

	var logFormat LogFormat
	if err := json.Unmarshal(logf, &logFormat); err != nil {
		return logf, nil
	}
	return json.Marshal(logFormat)
}

func buildDetails(d Details) map[string]any {
	out := map[string]any{
		"system": d.System,
	}
	if d.Client != "" {
		out["client"] = d.Client
	}
	if d.Protocol != "" {
		out["protocol"] = d.Protocol
	}
	if d.Method != "" {
		out["method"] = d.Method
	}
	if d.Path != "" {
		out["path"] = d.Path
	}
	if len(d.Headers) > 0 {
		out["headers"] = d.Headers
	}
	if d.Request != nil {
		out["request"] = d.Request
	}
	if d.Response != nil {
		out["response"] = d.Response
	}
	if d.RequestCapture != nil {
		out["requestCapture"] = d.RequestCapture
	}
	if d.ResponseCapture != nil {
		out["responseCapture"] = d.ResponseCapture
	}
	return out
}

func buildServices(items []Process) []map[string]any {
	out := make([]map[string]any, 0, len(items))
	for _, s := range items {
		row := map[string]any{}
		if s.TraceID != "" {
			row["traceID"] = s.TraceID
		}
		if s.SpanID != "" {
			row["spanID"] = s.SpanID
		}
		if s.System != "" {
			row["system"] = s.System
		}
		if s.Process != "" {
			row["process"] = s.Process
		}
		if s.Server != "" {
			row["server"] = s.Server
		}
		if s.Headers != nil {
			row["headers"] = *s.Headers
		}
		if s.Protocol != "" {
			row["protocol"] = s.Protocol
		}
		if s.Method != "" {
			row["method"] = s.Method
		}
		if s.Path != "" {
			row["path"] = s.Path
		}
		if s.Code != 0 {
			row["code"] = s.Code
		}
		if s.Request != nil {
			row["request"] = s.Request
		}
		if s.Response != nil {
			row["response"] = s.Response
		}
		if s.ResponseCapture != nil {
			row["responseCapture"] = s.ResponseCapture
		}
		if s.Status != "" {
			row["status"] = s.Status
		}
		if s.Latency != 0 {
			row["latency"] = s.Latency
		}
		out = append(out, row)
	}
	return out
}
