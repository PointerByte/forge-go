// Copyright 2026 PointerByte Contributors
// SPDX-License-Identifier: Apache-2.0

package http

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"reflect"

	viperdata "github.com/PointerByte/forge-go/logger/viperData"
)

func decodeResponse(resp *http.Response, object any) (err error) {
	body := resp.Body
	defer func() {
		if _, copyErr := io.Copy(io.Discard, body); copyErr != nil && err == nil {
			err = fmt.Errorf("problem draining response body: %w", copyErr)
		}
		if closeErr := body.Close(); closeErr != nil && err == nil {
			err = fmt.Errorf("problem closing response body: %w", closeErr)
		}
		resp.Body = http.NoBody
	}()

	if decodeErr := json.NewDecoder(body).Decode(object); decodeErr != nil && !errors.Is(decodeErr, io.EOF) {
		return fmt.Errorf("problem decoding the response: %w", decodeErr)
	}
	return nil
}

func drainAndCloseResponseBody(resp *http.Response) error {
	if resp == nil || resp.Body == nil {
		return nil
	}

	body := resp.Body
	_, drainErr := io.Copy(io.Discard, body)
	closeErr := body.Close()
	resp.Body = http.NoBody

	var err error
	if drainErr != nil {
		err = fmt.Errorf("problem draining response body: %w", drainErr)
	}
	if closeErr != nil {
		err = errors.Join(err, fmt.Errorf("problem closing response body: %w", closeErr))
	}
	return err
}

func readAndCloseResponseBodyLimited(resp *http.Response) ([]byte, bool, error) {
	if resp == nil || resp.Body == nil {
		return nil, false, nil
	}

	limit := viperdata.BodyCaptureMaxBytes()
	body := resp.Body
	responseBody, readErr := io.ReadAll(io.LimitReader(body, int64(limit)+1))
	_, drainErr := io.Copy(io.Discard, body)
	closeErr := body.Close()
	resp.Body = http.NoBody

	truncated := len(responseBody) > limit
	if truncated {
		responseBody = responseBody[:limit]
	}

	var err error
	if readErr != nil {
		err = fmt.Errorf("problem reading response body: %w", readErr)
	}
	if drainErr != nil {
		err = errors.Join(err, fmt.Errorf("problem draining response body: %w", drainErr))
	}
	if closeErr != nil {
		err = errors.Join(err, fmt.Errorf("problem closing response body: %w", closeErr))
	}
	return responseBody, truncated, err
}

func isNilOutput(object any) bool {
	if object == nil {
		return true
	}
	value := reflect.ValueOf(object)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}

func isSuccessfulHTTPStatus(statusCode int) bool {
	return statusCode >= http.StatusOK && statusCode < http.StatusMultipleChoices
}
