// Copyright 2026 PointerByte Contributors
// SPDX-License-Identifier: Apache-2.0

package viperdata

import (
	"strings"
	"sync"

	"github.com/spf13/viper"
)

var (
	viperData map[string]any
	once      sync.Once
	mux       sync.Mutex
)

const layout = "2006-01-02T15:04:05.000"

// DefaultBodyCaptureMaxBytes is the per-side request or response capture limit
// used when logger.bodyCaptureMaxBytes is absent or non-positive.
const DefaultBodyCaptureMaxBytes = 64 * 1024

func ResetViperDataSingleton() {
	mux.Lock()
	defer mux.Unlock()
	viperData = nil
	once = sync.Once{}
}

// GetViperData retrieves the value associated with the given key from the viperData map.
// It initializes the viperData map on the first call using sync.Once to ensure thread safety.
// The function also sets a default value for LoggerFormatDateAtribute if it is not already set in Viper.
func GetViperData(key string) any {
	mux.Lock()
	defer mux.Unlock()

	once.Do(func() {
		if viper.GetString(string(LoggerFormatDateAtribute)) == "" {
			viper.Set(string(LoggerFormatDateAtribute), layout)
		}
		bodyCaptureMaxBytes := viper.GetInt(string(LoggerBodyCaptureMaxBytesAtribute))
		if bodyCaptureMaxBytes <= 0 {
			bodyCaptureMaxBytes = DefaultBodyCaptureMaxBytes
		}
		viperData = map[string]any{
			string(AppVersionAtribute):                         viper.GetString(string(AppVersionAtribute)),
			string(AppAtribute):                                viper.GetString(string(AppAtribute)),
			string(GinLoggerWithConfigEnabledAtribute):         viper.GetBool(string(GinLoggerWithConfigEnabledAtribute)),
			string(GinLoggerWithConfigSkipPathsAtribute):       viper.GetStringSlice(string(GinLoggerWithConfigSkipPathsAtribute)),
			string(GinLoggerWithConfigSkipQueryStringAtribute): viper.GetBool(string(GinLoggerWithConfigSkipQueryStringAtribute)),
			string(LoggerModeTestAtribute):                     viper.GetBool(string(LoggerModeTestAtribute)),
			string(LoggerLevelAtribute):                        viper.GetString(string(LoggerLevelAtribute)),
			string(LoggerIgnoredHeadersAtribute):               viper.GetStringSlice(string(LoggerIgnoredHeadersAtribute)),
			string(LoggerFormatterAtribute):                    viper.GetString(string(LoggerFormatterAtribute)),
			string(LoggerFormatDateAtribute):                   viper.GetString(string(LoggerFormatDateAtribute)),
			string(LoggerSensibleKeysAtribute):                 viper.GetStringSlice(string(LoggerSensibleKeysAtribute)),
			string(LoggerBodyCaptureMaxBytesAtribute):          bodyCaptureMaxBytes,
			string(LoggerRotateEnableAtribute):                 viper.GetBool(string(LoggerRotateEnableAtribute)),
			string(LoggerRotateMaxSizeAtribute):                viper.GetInt(string(LoggerRotateMaxSizeAtribute)),
			string(LoggerRotateMaxBackupsAtribute):             viper.GetInt(string(LoggerRotateMaxBackupsAtribute)),
			string(LoggerRotateMaxAgeAtribute):                 viper.GetInt(string(LoggerRotateMaxAgeAtribute)),
			string(LoggerCompressMaxAgeAtribute):               viper.GetBool(string(LoggerCompressMaxAgeAtribute)),
			string(GRPCLoggerWithConfigEnabledAtribute):        viper.GetBool(string(GRPCLoggerWithConfigEnabledAtribute)),
			string(GRPCLoggerWithConfigSkipFunctionAtribute):   viper.GetStringSlice(string(GRPCLoggerWithConfigSkipFunctionAtribute)),
		}
	})

	if viperData[string(AppVersionAtribute)] == "" {
		// Keep the current map alive long enough to return the requested value.
		// Only invalidate sync.Once so the next call refreshes the snapshot.
		once = sync.Once{}
	}
	return viperData[key]
}

// BodyCaptureMaxBytes returns the normalized per-side body capture limit.
func BodyCaptureMaxBytes() int {
	value, ok := GetViperData(string(LoggerBodyCaptureMaxBytesAtribute)).(int)
	if !ok || value <= 0 {
		return DefaultBodyCaptureMaxBytes
	}
	return value
}

func IsIgnoredHeader(header string) bool {
	ignoredHeaders := GetViperData(string(LoggerIgnoredHeadersAtribute)).([]string)
	for _, ignoredHeader := range ignoredHeaders {
		if strings.EqualFold(ignoredHeader, header) {
			return true
		}
	}
	return false
}
