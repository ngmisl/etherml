package tui

import (
	"encoding/hex"
	"fmt"
	"time"

	"github.com/charmbracelet/bubbles/list"
)

type item struct {
	wallet Wallet
}

func (i item) FilterValue() string {
	addr := hex.EncodeToString(i.wallet.Address[:])
	return i.wallet.Label + " 0x" + addr
}

func (i item) Title() string {
	addr := hex.EncodeToString(i.wallet.Address[:])
	addressStr := formatAddress(addr)

	if i.wallet.Label != "" {
		// Don't apply inline styling - let the delegate handle selection styling
		return fmt.Sprintf("🔐 %s (%s)", i.wallet.Label, addressStr)
	}
	return fmt.Sprintf("🔐 %s", addressStr)
}

func (i item) Description() string {
	timeAgo := humanizeTime(i.wallet.CreatedAt)
	return fmt.Sprintf("📅 Created %s", timeAgo)
}

// Format address for display
func formatAddress(addr string) string {
	if len(addr) >= 16 {
		return "0x" + addr[:6] + "..." + addr[len(addr)-4:]
	}
	return "0x" + addr
}

// Humanize time display
func humanizeTime(t time.Time) string {
	diff := time.Since(t)
	switch {
	case diff < time.Minute:
		return "just now"
	case diff < time.Hour:
		return fmt.Sprintf("%d min ago", int(diff.Minutes()))
	case diff < 24*time.Hour:
		return fmt.Sprintf("%d hours ago", int(diff.Hours()))
	case diff < 7*24*time.Hour:
		return fmt.Sprintf("%d days ago", int(diff.Hours()/24))
	default:
		return t.Format("Jan 2, 2006")
	}
}

// Helper to create list items from wallets
func createListItems(wallets []Wallet) []list.Item {
	items := make([]list.Item, len(wallets))
	for i, w := range wallets {
		items[i] = item{wallet: w}
	}
	return items
}