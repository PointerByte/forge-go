// Copyright 2026 PointerByte Contributors
// SPDX-License-Identifier: Apache-2.0

package http

import (
	"net/http"
	"net/url"
)

// RequestGeneric: Generic request for requests using generic REST methods
type RequestGeneric struct {
	HttpRequest      *http.Request
	System           string
	Process          string
	Header           http.Header
	Url              string
	Host             string
	Path             string
	Params           url.Values
	DisableTraceBody bool
	Request          any
	Response         any
}
