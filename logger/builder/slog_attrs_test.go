// Copyright 2026 PointerByte Contributors
// SPDX-License-Identifier: Apache-2.0

package builder

import (
	"errors"
	"log/slog"
	"reflect"
	"testing"

	"github.com/PointerByte/forge-go/logger/sanitizer"
)

// --- attribute flattening ---

func TestAddSlogAttrScalarsAndGroups(t *testing.T) {
	tests := []struct {
		name string
		attr slog.Attr
		want map[string]any
	}{
		{
			name: "empty attribute is dropped",
			attr: slog.Attr{},
			want: map[string]any{},
		},
		{
			name: "scalar is stored under its key",
			attr: slog.String("user", "ada"),
			want: map[string]any{"user": "ada"},
		},
		{
			name: "keyed group nests its children",
			attr: slog.Group("db", slog.String("host", "local"), slog.Int("port", 5432)),
			want: map[string]any{"db": map[string]any{"host": "local", "port": int64(5432)}},
		},
		{
			name: "inline group hoists its children",
			attr: slog.Attr{Value: slog.GroupValue(slog.String("host", "local"))},
			want: map[string]any{"host": "local"},
		},
		{
			name: "empty keyed group leaves no key behind",
			attr: slog.Group("empty"),
			want: map[string]any{},
		},
		{
			name: "nested group keeps its shape",
			attr: slog.Group("outer", slog.Group("inner", slog.String("k", "v"))),
			want: map[string]any{"outer": map[string]any{"inner": map[string]any{"k": "v"}}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			target := map[string]any{}
			addSlogAttr(target, tt.attr)
			if !reflect.DeepEqual(target, tt.want) {
				t.Fatalf("addSlogAttr() = %#v, want %#v", target, tt.want)
			}
		})
	}
}

func TestAddSlogAttrStringifiesErrors(t *testing.T) {
	target := map[string]any{}
	addSlogAttr(target, slog.Any("cause", errors.New("boom")))
	if target["cause"] != "boom" {
		t.Fatalf("target[cause] = %#v, want \"boom\"", target["cause"])
	}
}

func TestAddSlogAttrReusesExistingGroupMap(t *testing.T) {
	target := map[string]any{"db": map[string]any{"host": "local"}}
	addSlogAttr(target, slog.Group("db", slog.Int("port", 5432)))

	group, ok := target["db"].(map[string]any)
	if !ok {
		t.Fatalf("target[db] = %T, want map[string]any", target["db"])
	}
	if group["host"] != "local" || group["port"] != int64(5432) {
		t.Fatalf("target[db] = %#v, want both host and port merged", group)
	}
}

func TestEnsureAttributeGroupReplacesNonGroupValues(t *testing.T) {
	target := map[string]any{"db": "not-a-group"}
	group := ensureAttributeGroup(target, "db")
	group["host"] = "local"

	if got, ok := target["db"].(map[string]any); !ok || got["host"] != "local" {
		t.Fatalf("target[db] = %#v, want a fresh group map", target["db"])
	}
}

func TestHasSlogAttrs(t *testing.T) {
	tests := []struct {
		name  string
		attrs []slog.Attr
		want  bool
	}{
		{name: "no attributes"},
		{name: "only empty attributes", attrs: []slog.Attr{{}, {}}},
		{name: "empty group", attrs: []slog.Attr{slog.Group("g")}},
		{
			name:  "group whose children are all empty",
			attrs: []slog.Attr{{Value: slog.GroupValue(slog.Attr{}, slog.Attr{})}},
		},
		{name: "scalar attribute", attrs: []slog.Attr{slog.String("k", "v")}, want: true},
		{name: "populated group", attrs: []slog.Attr{slog.Group("g", slog.String("k", "v"))}, want: true},
		{
			name:  "deeply nested populated group",
			attrs: []slog.Attr{slog.Group("a", slog.Group("b", slog.String("k", "v")))},
			want:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := hasSlogAttrs(tt.attrs); got != tt.want {
				t.Fatalf("hasSlogAttrs(%#v) = %t, want %t", tt.attrs, got, tt.want)
			}
		})
	}
}

func TestAddSlogAttrsSkipsEmptyGroupsBeforeCreatingNesting(t *testing.T) {
	target := map[string]any{}
	addSlogAttrs(target, []string{"outer"}, []slog.Attr{slog.Group("inner")})
	if len(target) != 0 {
		t.Fatalf("addSlogAttrs() = %#v, want no group scaffolding for empty attributes", target)
	}

	addSlogAttrs(target, []string{"outer"}, []slog.Attr{slog.String("k", "v")})
	want := map[string]any{"outer": map[string]any{"k": "v"}}
	if !reflect.DeepEqual(target, want) {
		t.Fatalf("addSlogAttrs() = %#v, want %#v", target, want)
	}
}

// --- attribute sanitization ---

func TestSanitizeSlogAttrDisabledSanitizerIsIdentity(t *testing.T) {
	disabled := sanitizer.New(nil)
	if disabled.Enabled() {
		t.Fatal("sanitizer.New(nil).Enabled() = true, want false")
	}

	attr := slog.String("password", "hunter2")
	if got := sanitizeSlogAttr(attr, disabled); !got.Equal(attr) {
		t.Fatalf("sanitizeSlogAttr() = %#v, want the attribute unchanged", got)
	}
}

func TestSanitizeSlogAttrRedactsConfiguredKeys(t *testing.T) {
	active := sanitizer.New([]string{"password"})

	redacted := sanitizeSlogAttr(slog.String("password", "hunter2"), active)
	if got := redacted.Value.Any(); got != sanitizer.RedactedValue {
		t.Fatalf("sanitized password = %#v, want %q", got, sanitizer.RedactedValue)
	}

	kept := sanitizeSlogAttr(slog.String("user", "ada"), active)
	if got := kept.Value.Any(); got != "ada" {
		t.Fatalf("sanitized user = %#v, want \"ada\"", got)
	}
}

func TestSanitizeSlogAttrRedactsInsideGroups(t *testing.T) {
	active := sanitizer.New([]string{"password"})

	sanitized := sanitizeSlogAttr(
		slog.Group("credentials", slog.String("password", "hunter2"), slog.String("user", "ada")),
		active,
	)

	flattened := map[string]any{}
	addSlogAttr(flattened, sanitized)
	group, ok := flattened["credentials"].(map[string]any)
	if !ok {
		t.Fatalf("flattened[credentials] = %T, want map[string]any", flattened["credentials"])
	}
	if group["password"] != sanitizer.RedactedValue {
		t.Fatalf("group[password] = %#v, want %q", group["password"], sanitizer.RedactedValue)
	}
	if group["user"] != "ada" {
		t.Fatalf("group[user] = %#v, want \"ada\"", group["user"])
	}
}

func TestSanitizeSlogAttrHandlesInlineGroupsAndEmptyAttrs(t *testing.T) {
	active := sanitizer.New([]string{"password"})

	if got := sanitizeSlogAttr(slog.Attr{}, active); !got.Equal(slog.Attr{}) {
		t.Fatalf("sanitizeSlogAttr(empty) = %#v, want the empty attribute", got)
	}

	inline := sanitizeSlogAttr(
		slog.Attr{Value: slog.GroupValue(slog.String("password", "hunter2"), slog.String("user", "ada"))},
		active,
	)
	if inline.Key != "" || inline.Value.Kind() != slog.KindGroup {
		t.Fatalf("sanitizeSlogAttr(inline group) = %#v, want an inline group", inline)
	}

	flattened := map[string]any{}
	addSlogAttr(flattened, inline)
	if flattened["password"] != sanitizer.RedactedValue || flattened["user"] != "ada" {
		t.Fatalf("flattened inline group = %#v, want only the password redacted", flattened)
	}
}

func TestSlogAttrValueFlattensGroupsForSanitization(t *testing.T) {
	group := slogAttrValue(slog.Group("db", slog.String("host", "local")))
	want := map[string]any{"host": "local"}
	if !reflect.DeepEqual(group, want) {
		t.Fatalf("slogAttrValue(group) = %#v, want %#v", group, want)
	}

	if got := slogAttrValue(slog.String("k", "v")); got != "v" {
		t.Fatalf("slogAttrValue(scalar) = %#v, want \"v\"", got)
	}
	if got := slogAttrValue(slog.Any("cause", errors.New("boom"))); got != "boom" {
		t.Fatalf("slogAttrValue(error) = %#v, want \"boom\"", got)
	}
}
