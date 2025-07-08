package tui

import (
	"fmt"

	"github.com/charmbracelet/bubbles/help"
	"github.com/charmbracelet/bubbles/list"
	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// Run initializes and starts the TUI with the provided wallet manager
func Run(walletMgr WalletManagerInterface, masterPassword []byte) error {
	// Initialize clipboard
	if err := initClipboard(); err != nil {
		// Non-fatal error, just log it
		fmt.Printf("Warning: Clipboard not available: %v\n", err)
	}

	// Create and run the TUI program
	p := tea.NewProgram(
		initialModel(walletMgr, masterPassword),
		tea.WithAltScreen(),
		tea.WithMouseCellMotion(),
	)

	_, err := p.Run()
	return err
}

func initialModel(walletMgr WalletManagerInterface, masterPassword []byte) model {
	wallets, err := walletMgr.ListWallets()
	if err != nil {
		wallets = []Wallet{} // Empty list on error
	}

	items := createListItems(wallets)

	const defaultWidth = 100
	const listHeight = 25 // Sheet-style with more visible wallets

	// Create enhanced delegate
	delegate := list.NewDefaultDelegate()
	delegate.Styles.SelectedTitle = SelectedCardStyle
	delegate.Styles.SelectedDesc = SelectedCardStyle.Copy().Foreground(lipgloss.Color(crustColor))
	delegate.Styles.NormalTitle = CardStyle
	delegate.Styles.NormalDesc = MutedStyle
	delegate.SetHeight(3) // Restore stable height for proper list calculations
	delegate.SetSpacing(1) // Add spacing back for list component stability

	l := list.New(items, delegate, defaultWidth, listHeight)
	l.Title = ""
	l.SetShowStatusBar(false)
	l.SetFilteringEnabled(false)
	l.SetShowPagination(true)
	l.SetShowHelp(false)
	l.Styles.Title = TitleStyle
	l.Styles.PaginationStyle = lipgloss.NewStyle().
		Foreground(lipgloss.Color(overlay2Color)).
		Align(lipgloss.Right)

	// Input for wallet labels
	ti := textinput.New()
	ti.Placeholder = "Enter wallet label..."
	ti.CharLimit = 50
	ti.Width = 50
	ti.PromptStyle = LabelStyle
	ti.TextStyle = BaseStyle

	// Password input for sensitive operations
	pi := textinput.New()
	pi.Placeholder = "Enter master password..."
	pi.EchoMode = textinput.EchoPassword
	pi.EchoCharacter = '•'
	pi.CharLimit = 100
	pi.Width = 50
	pi.PromptStyle = WarningStyle
	pi.TextStyle = BaseStyle

	// Spinner for loading states
	s := spinner.New()
	s.Spinner = spinner.Dot
	s.Style = lipgloss.NewStyle().Foreground(lipgloss.Color(primaryColor))

	// Store master password for re-authentication
	masterPasswordCopy := make([]byte, len(masterPassword))
	copy(masterPasswordCopy, masterPassword)

	return model{
		list:            l,
		walletMgr:       walletMgr,
		wallets:         wallets,
		filteredWallets: wallets,
		input:           ti,
		passwordInput:   pi,
		help:            help.New(),
		keys:            Keys,
		status:          InfoStyle.Render(fmt.Sprintf("✨ Ready - %d wallet(s) loaded", len(wallets))),
		statusColor:     lipgloss.Color(primaryColor),
		spinner:         s,
		selectedIndex:   0, // Initialize grid selection
		masterPassword:  masterPasswordCopy,
	}
}

func (m model) Init() tea.Cmd {
	return tea.Batch(
		m.spinner.Tick,
		textinput.Blink,
	)
}

// GenerateWallet is a placeholder that needs to be implemented or imported
// This function should be provided by the main package or wallet manager
var GenerateWallet func() Result[*Wallet]

// SetGenerateWalletFunc allows setting the wallet generation function from main
func SetGenerateWalletFunc(fn func() Result[*Wallet]) {
	GenerateWallet = fn
}