package tui

import (
	"encoding/hex"
	"fmt"
	"time"

	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"wallet/pkg/quantum"
)

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmds []tea.Cmd

	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		// With compact header, almost entire screen available for wallets
		availableHeight := msg.Height - 2 // Only subtract header space
		if availableHeight < 10 {
			availableHeight = 10
		}
		m.list.SetSize(msg.Width, availableHeight) // Full width for sheet appearance
		return m, nil

	case loadingCompleteMsg:
		m.loading = false
		m.refreshWalletList()
		return m, nil

	case spinner.TickMsg:
		if m.loading {
			m.spinner, _ = m.spinner.Update(msg)
			cmds = append(cmds, m.spinner.Tick)
		}
		return m, tea.Batch(cmds...)

	case tea.KeyMsg:
		// Handle private key display interactions
		if m.showingPrivateKey {
			switch msg.String() {
			case "c", "C":
				// Copy private key again
				if m.selectedWallet != nil {
					privateKeyHex := "0x" + hex.EncodeToString(m.selectedWallet.PrivateKey[:])
					copyToClipboard(privateKeyHex, 30*time.Second)
					m.status = SuccessStyle.Render("📋 Private key copied again (auto-clears in 30s)")
				}
				return m, nil
			default:
				// Clear private key display on any other key
				m.showingPrivateKey = false
				if m.selectedWallet != nil {
					quantum.SecureZero(m.selectedWallet.PrivateKey[:])
					m.selectedWallet = nil
				}
				m.status = InfoStyle.Render("🔒 Private key cleared from memory")
				return m, nil
			}
		}

		// Handle delete confirmation
		if m.confirmingDelete {
			switch msg.String() {
			case "y", "Y":
				if m.walletToDelete != nil {
					addr := hex.EncodeToString(m.walletToDelete.Address[:])
					if err := m.walletMgr.DeleteWallet(addr); err == nil {
						m.refreshWalletList()
						m.status = SuccessStyle.Render(fmt.Sprintf("✅ Wallet deleted: %s", formatAddress(addr)))
					} else {
						m.status = ErrorStyle.Render("❌ Failed to delete wallet: " + err.Error())
					}
				}
				m.confirmingDelete = false
				m.walletToDelete = nil
				return m, nil
			case "n", "N", "esc":
				m.confirmingDelete = false
				m.walletToDelete = nil
				m.status = InfoStyle.Render("❌ Delete cancelled")
				return m, nil
			}
			return m, nil
		}

		// Handle input modes
		if m.inputMode != "" {
			switch msg.String() {
			case "enter":
				switch m.inputMode {
				case "new":
					// Capture the label value before clearing input
					walletLabel := m.input.Value()
					m.loading = true
					m.loadingMsg = "Creating quantum-resistant wallet..."

					// Create wallet in background
					go func() {
						// Simulate some work for better UX
						time.Sleep(500 * time.Millisecond)

						// Create new wallet with label
						result := GenerateWallet()
						if wallet, err := result.Unwrap(); err == nil {
							wallet.Label = walletLabel

							if err := m.walletMgr.AddWallet(wallet); err == nil {
								addr := hex.EncodeToString(wallet.Address[:])
								m.status = SuccessStyle.Render(fmt.Sprintf("✅ Wallet created! %s", formatAddress(addr)))
								// Zero the private key in memory
								quantum.SecureZero(wallet.PrivateKey[:])
							} else {
								m.status = ErrorStyle.Render("❌ Failed to save wallet: " + err.Error())
							}
						} else {
							m.status = ErrorStyle.Render("❌ Failed to generate wallet: " + err.Error())
						}
					}()

					// Set a timer to complete loading
					cmds = append(cmds, tea.Tick(time.Second, func(t time.Time) tea.Msg {
						return loadingCompleteMsg{}
					}))

				case "search":
					m.searchQuery = m.input.Value()
					m.refreshWalletList()
					if m.searchQuery == "" {
						m.status = InfoStyle.Render("🔍 Search cleared - showing all wallets")
					} else {
						m.status = InfoStyle.Render(fmt.Sprintf("🔍 Found %d wallet(s) matching '%s'", len(m.filteredWallets), m.searchQuery))
					}
				case "password":
					// Verify password and show private key
					if m.selectedWallet != nil {
						password := m.passwordInput.Value()
						if quantum.SecureCompare([]byte(password), m.masterPassword) {
							m.showingPrivateKey = true
							m.status = WarningStyle.Render("🔓 Private key displayed - Press any key to clear")
						} else {
							m.status = ErrorStyle.Render("❌ Invalid password")
						}
					}
				case "edit":
					// Update wallet label
					if m.editingWallet != nil {
						newLabel := m.input.Value()
						addr := hex.EncodeToString(m.editingWallet.Address[:])
						if err := m.walletMgr.UpdateWalletLabel(addr, newLabel); err != nil {
							m.status = ErrorStyle.Render("❌ Failed to update label: " + err.Error())
						} else {
							m.status = SuccessStyle.Render(fmt.Sprintf("✅ Label updated: %s", newLabel))
							m.refreshWalletList()
						}
						m.editingWallet = nil
					}
				}
				m.inputMode = ""
				m.input.SetValue("")
				m.passwordInput.SetValue("")
				return m, tea.Batch(cmds...)
			case "esc":
				m.inputMode = ""
				m.input.SetValue("")
				m.passwordInput.SetValue("")
				m.showingPrivateKey = false
				m.selectedWallet = nil
				m.editingWallet = nil
				m.status = InfoStyle.Render("❌ Cancelled")
				return m, nil
			}

			// Update the appropriate input
			var cmd tea.Cmd
			if m.inputMode == "password" {
				m.passwordInput, cmd = m.passwordInput.Update(msg)
			} else {
				m.input, cmd = m.input.Update(msg)
			}
			cmds = append(cmds, cmd)
			return m, tea.Batch(cmds...)
		}

		// Handle grid navigation
		switch {
		case key.Matches(msg, m.keys.Up):
			if len(m.filteredWallets) > 0 {
				// Calculate grid dimensions for navigation
				walletWidth := 45
				maxCols := m.width / walletWidth
				if maxCols < 1 {
					maxCols = 1
				}
				if maxCols > 4 {
					maxCols = 4
				}
				
				newIndex := m.selectedIndex - maxCols
				if newIndex < 0 {
					newIndex = 0
				}
				m.selectedIndex = newIndex
			}
			return m, nil

		case key.Matches(msg, m.keys.Down):
			if len(m.filteredWallets) > 0 {
				// Calculate grid dimensions for navigation
				walletWidth := 45
				maxCols := m.width / walletWidth
				if maxCols < 1 {
					maxCols = 1
				}
				if maxCols > 4 {
					maxCols = 4
				}
				
				newIndex := m.selectedIndex + maxCols
				if newIndex >= len(m.filteredWallets) {
					newIndex = len(m.filteredWallets) - 1
				}
				m.selectedIndex = newIndex
			}
			return m, nil

		case msg.String() == "left", msg.String() == "h":
			if len(m.filteredWallets) > 0 && m.selectedIndex > 0 {
				m.selectedIndex--
			}
			return m, nil

		case msg.String() == "right", msg.String() == "l":
			if len(m.filteredWallets) > 0 && m.selectedIndex < len(m.filteredWallets)-1 {
				m.selectedIndex++
			}
			return m, nil
		}

		// Handle main key bindings
		switch {
		case key.Matches(msg, m.keys.Quit):
			m.quitting = true
			return m, tea.Quit

		case key.Matches(msg, m.keys.New):
			m.inputMode = "new"
			m.input.Placeholder = "Enter wallet label (optional)..."
			m.input.Focus()
			m.status = InfoStyle.Render("✨ Creating new quantum-resistant wallet...")
			return m, textinput.Blink

		case key.Matches(msg, m.keys.Search):
			m.inputMode = "search"
			m.input.Placeholder = "Search by label or address..."
			m.input.SetValue(m.searchQuery)
			m.input.Focus()
			m.status = InfoStyle.Render("🔍 Search mode - type to filter wallets")
			return m, textinput.Blink

		case key.Matches(msg, m.keys.Copy):
			if len(m.filteredWallets) > 0 && m.selectedIndex >= 0 && m.selectedIndex < len(m.filteredWallets) {
				wallet := m.filteredWallets[m.selectedIndex]
				addr := "0x" + hex.EncodeToString(wallet.Address[:])
				if err := copyToClipboard(addr, 0); err == nil {
					m.status = SuccessStyle.Render(fmt.Sprintf("📋 Address copied: %s", formatAddress(hex.EncodeToString(wallet.Address[:]))))
				} else {
					m.status = ErrorStyle.Render("❌ Failed to copy address")
				}
			} else {
				m.status = WarningStyle.Render("⚠️ No wallets to copy")
			}
			return m, nil

		case key.Matches(msg, m.keys.Export):
			if len(m.filteredWallets) > 0 && m.selectedIndex >= 0 && m.selectedIndex < len(m.filteredWallets) {
				wallet := m.filteredWallets[m.selectedIndex]
				m.selectedWallet = &wallet
				m.inputMode = "password"
				m.passwordInput.Focus()
				m.status = WarningStyle.Render("🔐 Enter master password to view private key")
				return m, textinput.Blink
			} else {
				m.status = WarningStyle.Render("⚠️ No wallets to export")
			}
			return m, nil

		case key.Matches(msg, m.keys.Delete):
			if len(m.filteredWallets) > 0 && m.selectedIndex >= 0 && m.selectedIndex < len(m.filteredWallets) {
				wallet := m.filteredWallets[m.selectedIndex]
				m.walletToDelete = &wallet
				m.confirmingDelete = true
				addr := hex.EncodeToString(wallet.Address[:])
				m.status = WarningStyle.Render(fmt.Sprintf("⚠️ Delete wallet %s? (y/N)", formatAddress(addr)))
			} else {
				m.status = WarningStyle.Render("⚠️ No wallets to delete")
			}
			return m, nil

		case key.Matches(msg, m.keys.Enter):
			if len(m.filteredWallets) > 0 && m.selectedIndex >= 0 && m.selectedIndex < len(m.filteredWallets) {
				wallet := m.filteredWallets[m.selectedIndex]
				m.editingWallet = &wallet
				m.inputMode = "edit"
				m.input.Placeholder = "Enter new label..."
				m.input.SetValue(wallet.Label)
				m.input.Focus()
				m.status = InfoStyle.Render("✏️ Editing wallet label - Enter to save, Esc to cancel")
				return m, textinput.Blink
			} else {
				m.status = WarningStyle.Render("⚠️ No wallets to edit")
			}
			return m, nil

		// Add a refresh key binding to reset list state if it gets stuck
		case key.Matches(msg, key.NewBinding(key.WithKeys("r"))):
			if m.inputMode == "" {
				m.refreshWalletList()
				m.status = InfoStyle.Render("🔄 List refreshed")
				return m, nil
			}
		}
	}

	// Update list if not in input mode
	if m.inputMode == "" && !m.loading {
		var cmd tea.Cmd
		m.list, cmd = m.list.Update(msg)
		cmds = append(cmds, cmd)
	}

	return m, tea.Batch(cmds...)
}