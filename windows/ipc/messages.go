package ipc

import (
	"fmt"
	"os"
	"time"
)

func milliseconds(ms int64) time.Duration { return time.Duration(ms) * time.Millisecond }

// formatRequestID builds a unique, sortable request id: <pid>.<counter>.
func formatRequestID(n uint64) string { return fmt.Sprintf("%d.%d", os.Getpid(), n) }
