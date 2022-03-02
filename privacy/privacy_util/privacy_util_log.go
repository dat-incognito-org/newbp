//nolint:revive // skip linter for this package name
package privacy_util

import github.com/dat-incognito-org/newbp/common"

type PrivacyUtilLogger struct {
	Log common.Logger
}

func (logger *PrivacyUtilLogger) Init(inst common.Logger) {
	logger.Log = inst
}

// Logger is the exported Logger instance for this package
var Logger = PrivacyUtilLogger{}
