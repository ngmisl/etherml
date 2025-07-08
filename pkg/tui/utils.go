package tui

import (
	"fmt"
	"time"

	"golang.design/x/clipboard"
)

// Initialize clipboard
func initClipboard() error {
	err := clipboard.Init()
	if err != nil {
		return fmt.Errorf("failed to initialize clipboard: %w", err)
	}
	return nil
}

// Copy to clipboard with timeout
func copyToClipboard(text string, timeout time.Duration) error {
	clipboard.Write(clipboard.FmtText, []byte(text))

	// Clear clipboard after timeout for sensitive data
	if timeout > 0 {
		go func() {
			time.Sleep(timeout)
			clipboard.Write(clipboard.FmtText, []byte(""))
		}()
	}

	return nil
}