package tui

import (
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
)

// Render wallets in a multi-column grid layout
func (m model) renderWalletGrid() string {
	if len(m.filteredWallets) == 0 {
		emptyMessage := lipgloss.NewStyle().
			Foreground(lipgloss.Color(subtext1Color)).
			Italic(true).
			Padding(2, 0).
			Render("No wallets found. Press 'n' to create your first wallet.")
		return lipgloss.Place(m.width, m.height-2, lipgloss.Center, lipgloss.Center, emptyMessage)
	}

	// Calculate optimal column layout based on terminal width
	walletWidth := 45 // Minimum width per wallet entry
	maxCols := m.width / walletWidth
	if maxCols < 1 {
		maxCols = 1
	}
	if maxCols > 4 { // Cap at 4 columns for readability
		maxCols = 4
	}

	actualWalletWidth := m.width / maxCols
	selectedIndex := m.selectedIndex
	
	var rows []string
	
	for i := 0; i < len(m.filteredWallets); i += maxCols {
		var columns []string
		
		for col := 0; col < maxCols && i+col < len(m.filteredWallets); col++ {
			walletIndex := i + col
			wallet := m.filteredWallets[walletIndex]
			isSelected := walletIndex == selectedIndex
			
			// Format wallet entry
			addr := hex.EncodeToString(wallet.Address[:])
			addressStr := formatAddress(addr)
			timeAgo := humanizeTime(wallet.CreatedAt)
			
			label := wallet.Label
			if label == "" {
				label = "Unlabeled Wallet"
			}
			
			var walletContent string
			if isSelected {
				walletContent = SelectedCardStyle.Copy().
					Width(actualWalletWidth - 2).
					Render(fmt.Sprintf("🔐 %s\n📍 %s\n📅 %s", label, addressStr, timeAgo))
			} else {
				walletContent = CardStyle.Copy().
					Width(actualWalletWidth - 2).
					Render(fmt.Sprintf("🔐 %s\n📍 %s\n📅 %s", label, addressStr, timeAgo))
			}
			
			columns = append(columns, walletContent)
		}
		
		// Pad remaining columns if needed
		for len(columns) < maxCols {
			columns = append(columns, lipgloss.NewStyle().Width(actualWalletWidth-2).Render(""))
		}
		
		row := lipgloss.JoinHorizontal(lipgloss.Top, columns...)
		rows = append(rows, row)
	}
	
	return lipgloss.JoinVertical(lipgloss.Left, rows...)
}

func (m model) View() string {
	if m.quitting {
		farewell := lipgloss.NewStyle().
			Foreground(lipgloss.Color(successColor)).
			Bold(true).
			Padding(1, 2).
			Border(lipgloss.DoubleBorder()).
			BorderForeground(lipgloss.Color(primaryColor)).
			Render("👋 Stay secure with quantum-resistant encryption!")

		return lipgloss.Place(m.width, m.height, lipgloss.Center, lipgloss.Center, farewell)
	}

	// Handle loading state
	if m.loading {
		loadingView := lipgloss.JoinVertical(
			lipgloss.Center,
			TitleStyle.Render("🔐 Quantum Wallet Manager"),
			"",
			m.spinner.View()+" "+m.loadingMsg,
		)
		return lipgloss.Place(m.width, m.height, lipgloss.Center, lipgloss.Center,
			ModalStyle.Render(loadingView))
	}

	// Handle input modes with enhanced overlay
	if m.inputMode != "" {
		var title, inputView, helpText string
		var icon string

		switch m.inputMode {
		case "new":
			icon = "✨"
			title = "Create New Quantum-Resistant Wallet"
			inputView = m.input.View()
			helpText = "Enter • Create | Esc • Cancel"
		case "search":
			icon = "🔍"
			title = "Search Wallets"
			inputView = m.input.View()
			helpText = "Enter • Search | Esc • Cancel"
		case "password":
			icon = "🔐"
			title = "Authentication Required"
			inputView = m.passwordInput.View()
			helpText = "Enter • Authenticate | Esc • Cancel"
		case "edit":
			icon = "✏️"
			title = "Edit Wallet Label"
			inputView = m.input.View()
			helpText = "Enter • Save | Esc • Cancel"
		}

		content := lipgloss.JoinVertical(
			lipgloss.Center,
			IconStyle.Render(icon),
			TitleStyle.Render(title),
			"",
			inputView,
			"",
			MutedStyle.Render(helpText),
		)

		modal := ModalStyle.Width(60).Render(content)
		return lipgloss.Place(m.width, m.height, lipgloss.Center, lipgloss.Center, modal)
	}

	// Show private key if authenticated
	if m.showingPrivateKey && m.selectedWallet != nil {
		privateKeyHex := "0x" + hex.EncodeToString(m.selectedWallet.PrivateKey[:])
		addressHex := "0x" + hex.EncodeToString(m.selectedWallet.Address[:])

		labelText := "Unlabeled Wallet"
		if m.selectedWallet.Label != "" {
			labelText = m.selectedWallet.Label
		}

		// Auto-copy private key to clipboard with 30-second timeout
		copyToClipboard(privateKeyHex, 30*time.Second)

		content := lipgloss.JoinVertical(
			lipgloss.Left,
			TitleStyle.Render("🔓 Private Key Export"),
			"",
			lipgloss.NewStyle().
				Foreground(lipgloss.Color(textColor)).
				Background(lipgloss.Color(errorColor)).
				Bold(true).
				Padding(0, 1).
				Render("⚠️  EXTREMELY SENSITIVE DATA"),
			"",
			BoxStyle.Render(lipgloss.JoinVertical(
				lipgloss.Left,
				LabelStyle.Render("Label: ")+BaseStyle.Render(labelText),
				AddressStyle.Render("Address: ")+BaseStyle.Render(addressHex),
				"",
				WarningStyle.Render("Private Key:"),
				ErrorStyle.Copy().Underline(true).Render(privateKeyHex),
			)),
			"",
			SuccessStyle.Render("✅ Copied to clipboard (auto-clears in 30s)"),
			"",
			MutedStyle.Copy().Italic(true).Render("Press 'c' to copy again • Any other key to clear from memory"),
		)

		modal := ModalStyle.Width(80).Render(content)
		return lipgloss.Place(m.width, m.height, lipgloss.Center, lipgloss.Center, modal)
	}

	// Show delete confirmation if active
	if m.confirmingDelete && m.walletToDelete != nil {
		addressHex := hex.EncodeToString(m.walletToDelete.Address[:])
		label := m.walletToDelete.Label
		if label == "" {
			label = "Unlabeled Wallet"
		}

		content := lipgloss.JoinVertical(
			lipgloss.Center,
			TitleStyle.Render("🗑️ Confirm Deletion"),
			"",
			lipgloss.NewStyle().
				Foreground(lipgloss.Color(textColor)).
				Background(lipgloss.Color(errorColor)).
				Bold(true).
				Padding(0, 1).
				Render("⚠️  THIS ACTION CANNOT BE UNDONE"),
			"",
			BoxStyle.Render(lipgloss.JoinVertical(
				lipgloss.Left,
				LabelStyle.Render("Wallet: ")+BaseStyle.Render(label),
				AddressStyle.Render("Address: ")+BaseStyle.Render(formatAddress(addressHex)),
			)),
			"",
			MutedStyle.Render("Press 'y' to confirm • 'n' or Esc to cancel"),
		)

		modal := ModalStyle.Width(60).Render(content)
		return lipgloss.Place(m.width, m.height, lipgloss.Center, lipgloss.Center, modal)
	}

	// Compact sheet-style layout focused on wallets
	var sections []string

	// Compact single-line header with status and essential info
	walletCount := fmt.Sprintf("%d", len(m.wallets))
	if m.searchQuery != "" {
		walletCount = fmt.Sprintf("🔍 %d/%d", len(m.filteredWallets), len(m.wallets))
	}
	
	headerContent := lipgloss.JoinHorizontal(
		lipgloss.Left,
		lipgloss.NewStyle().Foreground(lipgloss.Color(primaryColor)).Bold(true).Render("🔐 Quantum Wallets"),
		lipgloss.NewStyle().Foreground(lipgloss.Color(subtext1Color)).Render(" • "),
		lipgloss.NewStyle().Foreground(lipgloss.Color(textColor)).Render(walletCount),
		lipgloss.NewStyle().Foreground(lipgloss.Color(subtext1Color)).Render(" • "),
		lipgloss.NewStyle().Foreground(lipgloss.Color(mutedColor)).Render("n•new ⏎•edit c•copy e•export d•delete /•search q•quit"),
	)
	
	// Add status message to header if present and not just ready message
	if m.status != "" && !strings.Contains(m.status, "Ready") {
		headerContent = lipgloss.JoinHorizontal(
			lipgloss.Left,
			headerContent,
			lipgloss.NewStyle().Render(" • "),
			m.status,
		)
	}
	
	compactHeader := lipgloss.NewStyle().
		Background(lipgloss.Color(mantleColor)).
		Foreground(lipgloss.Color(textColor)).
		Padding(0, 1).
		Width(m.width).
		Render(headerContent)
	sections = append(sections, compactHeader)

	// Multi-column wallet grid using full terminal width
	listView := m.renderWalletGrid()
	sections = append(sections, listView)

	// Join sections without extra spacing
	return lipgloss.JoinVertical(lipgloss.Left, sections...)
}