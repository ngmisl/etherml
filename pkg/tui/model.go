package tui

import (
	"strings"
	"encoding/hex"

	"github.com/charmbracelet/bubbles/help"
	"github.com/charmbracelet/bubbles/list"
	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/lipgloss"
)

type model struct {
	list              list.Model
	walletMgr         WalletManagerInterface
	wallets           []Wallet
	filteredWallets   []Wallet
	err               error
	quitting          bool
	input             textinput.Model
	passwordInput     textinput.Model
	inputMode         string
	searchQuery       string
	help              help.Model
	keys              keyMap
	status            string
	statusColor       lipgloss.Color
	showingPrivateKey bool
	selectedWallet    *Wallet
	confirmingDelete  bool
	walletToDelete    *Wallet
	width             int
	height            int
	spinner           spinner.Model
	loading           bool
	loadingMsg        string
	selectedIndex     int // Track selection for grid layout
	editingWallet     *Wallet // Wallet currently being edited
	masterPassword    []byte  // Store master password for re-authentication
}

// Loading complete message
type loadingCompleteMsg struct{}

// Helper function to refresh wallet list
func (m *model) refreshWalletList() {
	wallets, err := m.walletMgr.ListWallets()
	if err != nil {
		m.status = ErrorStyle.Render("❌ Failed to load wallets: " + err.Error())
		return
	}

	m.wallets = wallets
	m.filteredWallets = filterWallets(wallets, m.searchQuery)

	// Create new items and completely reset the list
	items := createListItems(m.filteredWallets)
	
	// Set items and reset selection to top
	m.list.SetItems(items)
	m.selectedIndex = 0 // Reset to top for grid layout
	if len(items) > 0 && m.selectedIndex >= len(items) {
		m.selectedIndex = len(items) - 1
	}
}

// Filter wallets based on search query
func filterWallets(wallets []Wallet, query string) []Wallet {
	if query == "" {
		return wallets
	}

	query = strings.ToLower(query)
	var filtered []Wallet

	for _, wallet := range wallets {
		addr := strings.ToLower(hex.EncodeToString(wallet.Address[:]))
		label := strings.ToLower(wallet.Label)

		if strings.Contains(addr, query) || strings.Contains(label, query) {
			filtered = append(filtered, wallet)
		}
	}

	return filtered
}