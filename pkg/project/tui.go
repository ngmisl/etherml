package project

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/help"
	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// WalletManagerInterface defines what we need from the main wallet manager
type WalletManagerInterface interface {
	ListWallets() ([]WalletInfo, error)
	AddWalletWithLabel(label string) (string, error) // Returns address
}

// WalletInfo represents wallet info from main wallet manager
type WalletInfo struct {
	Address   [20]byte
	Label     string
	CreatedAt string
}

// ProjectTUIModel represents the project management TUI
type ProjectTUIModel struct {
	manager        ProjectManager
	walletManager  WalletManagerInterface
	projects       []ProjectInfo
	currentProject Project
	walletRefs     []WalletRef

	// UI state
	state         ProjectTUIState
	selectedIndex int
	width         int
	height        int

	// Input handling
	input     textinput.Model
	inputMode string

	// Status and errors
	status string
	err    error

	// Key bindings
	keys ProjectKeyMap
	help help.Model
}

// ProjectKeyMap defines key bindings for project TUI
type ProjectKeyMap struct {
	Up     key.Binding
	Down   key.Binding
	Enter  key.Binding
	Back   key.Binding
	New    key.Binding
	Delete key.Binding
	Edit   key.Binding
	Copy   key.Binding
	Toggle key.Binding
	Help   key.Binding
	Quit   key.Binding
}

// DefaultProjectKeys returns the default key bindings
func DefaultProjectKeys() ProjectKeyMap {
	return ProjectKeyMap{
		Up: key.NewBinding(
			key.WithKeys("up", "k"),
			key.WithHelp("↑/k", "up"),
		),
		Down: key.NewBinding(
			key.WithKeys("down", "j"),
			key.WithHelp("↓/j", "down"),
		),
		Enter: key.NewBinding(
			key.WithKeys("enter"),
			key.WithHelp("⏎", "select/confirm"),
		),
		Back: key.NewBinding(
			key.WithKeys("esc", "b"),
			key.WithHelp("esc/b", "back"),
		),
		New: key.NewBinding(
			key.WithKeys("n"),
			key.WithHelp("n", "new"),
		),
		Delete: key.NewBinding(
			key.WithKeys("d"),
			key.WithHelp("d", "delete"),
		),
		Edit: key.NewBinding(
			key.WithKeys("e"),
			key.WithHelp("e", "edit"),
		),
		Copy: key.NewBinding(
			key.WithKeys("c"),
			key.WithHelp("c", "copy"),
		),
		Toggle: key.NewBinding(
			key.WithKeys(" "),
			key.WithHelp("space", "toggle network"),
		),
		Help: key.NewBinding(
			key.WithKeys("?"),
			key.WithHelp("?", "help"),
		),
		Quit: key.NewBinding(
			key.WithKeys("q", "ctrl+c"),
			key.WithHelp("q", "quit"),
		),
	}
}

// NewProjectTUIModel creates a new project TUI model
func NewProjectTUIModel(manager ProjectManager, walletManager WalletManagerInterface) *ProjectTUIModel {
	// Create text input
	input := textinput.New()
	input.Placeholder = "Enter project name..."
	input.CharLimit = 50
	input.Width = 50

	return &ProjectTUIModel{
		manager:       manager,
		walletManager: walletManager,
		state:         ProjectListState,
		selectedIndex: 0,
		input:         input,
		keys:          DefaultProjectKeys(),
		help:          help.New(),
	}
}

// Init initializes the model
func (m *ProjectTUIModel) Init() tea.Cmd {
	m.loadProjects()
	return textinput.Blink
}

// loadProjects loads the project list synchronously
func (m *ProjectTUIModel) loadProjects() {
	projects, err := m.manager.ListProjects()
	if err != nil {
		m.err = err
		m.status = fmt.Sprintf("Error loading projects: %s", err.Error())
		m.projects = []ProjectInfo{}
	} else {
		m.projects = projects
		m.err = nil
		if len(projects) == 0 {
			m.status = "No projects found. Press 'n' to create your first project."
		} else {
			m.status = fmt.Sprintf("Loaded %d project(s)", len(projects))
		}
	}

	// Reset selection if out of bounds
	if len(m.projects) > 0 && m.selectedIndex >= len(m.projects) {
		m.selectedIndex = len(m.projects) - 1
	}
}

// Update handles messages and updates the model
func (m *ProjectTUIModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmds []tea.Cmd

	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		return m, nil

	case tea.KeyMsg:
		return m.handleKeyPress(msg)
	}

	// Always update the text input to ensure proper handling
	if m.inputMode != "" && m.inputMode != "confirm_delete" && m.inputMode != "confirm_delete_wallet" {
		var cmd tea.Cmd
		m.input, cmd = m.input.Update(msg)
		cmds = append(cmds, cmd)
	}

	return m, tea.Batch(cmds...)
}

// handleKeyPress handles keyboard input based on current state
func (m *ProjectTUIModel) handleKeyPress(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	// Handle input modes
	if m.inputMode != "" {
		return m.handleInputMode(msg)
	}

	// Handle different states
	switch m.state {
	case ProjectListState:
		return m.handleProjectListKeys(msg)
	case ProjectWalletState:
		return m.handleWalletListKeys(msg)
	}

	return m, nil
}

// handleInputMode handles input when in input mode
func (m *ProjectTUIModel) handleInputMode(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	// Handle confirmation dialogs
	if m.inputMode == "confirm_delete" || m.inputMode == "confirm_delete_wallet" {
		switch msg.String() {
		case "y", "Y":
			return m.processInput()
		case "n", "N", "esc":
			m.inputMode = ""
			m.status = "Cancelled"
			return m, nil
		}
		return m, nil
	}

	// Handle text input modes
	switch msg.String() {
	case "enter":
		return m.processInput()
	case "esc":
		m.inputMode = ""
		m.input.SetValue("")
		m.input.Blur()
		m.status = "Cancelled"
		return m, nil
	}

	// For text input modes, we let the main Update method handle input updates
	// to avoid double-processing
	return m, nil
}

// handleProjectListKeys handles keys in project list state
func (m *ProjectTUIModel) handleProjectListKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch {
	case key.Matches(msg, m.keys.Up):
		if len(m.projects) > 0 && m.selectedIndex > 0 {
			m.selectedIndex--
		}
		return m, nil

	case key.Matches(msg, m.keys.Down):
		if len(m.projects) > 0 && m.selectedIndex < len(m.projects)-1 {
			m.selectedIndex++
		}
		return m, nil

	case key.Matches(msg, m.keys.Enter):
		if len(m.projects) > 0 {
			m.openProject()
		}
		return m, nil

	case key.Matches(msg, m.keys.New):
		m.inputMode = "new_project"
		m.input.Placeholder = "Enter new project name..."
		m.input.SetValue("")
		m.input.Focus()
		m.status = "Creating new project..."
		return m, textinput.Blink

	case key.Matches(msg, m.keys.Delete):
		if len(m.projects) > 0 {
			m.inputMode = "confirm_delete"
			m.status = fmt.Sprintf("Delete project '%s'? (y/N)", m.projects[m.selectedIndex].Name)
		}
		return m, nil

	case key.Matches(msg, m.keys.Quit):
		return m, tea.Quit
	}

	return m, nil
}

// handleWalletListKeys handles keys in wallet list state
func (m *ProjectTUIModel) handleWalletListKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch {
	case key.Matches(msg, m.keys.Up):
		if len(m.walletRefs) > 0 && m.selectedIndex > 0 {
			m.selectedIndex--
		}
		return m, nil

	case key.Matches(msg, m.keys.Down):
		if len(m.walletRefs) > 0 && m.selectedIndex < len(m.walletRefs)-1 {
			m.selectedIndex++
		}
		return m, nil

	case key.Matches(msg, m.keys.Back):
		m.state = ProjectListState
		m.selectedIndex = 0
		if m.currentProject != nil {
			m.currentProject = nil
		}
		m.loadProjects()
		return m, nil

	case key.Matches(msg, m.keys.New):
		m.inputMode = "new_wallet"
		m.input.Placeholder = "Enter wallet label..."
		m.input.SetValue("")
		m.input.Focus()
		m.status = "Creating new wallet..."
		return m, textinput.Blink

	case key.Matches(msg, m.keys.Edit):
		if len(m.walletRefs) > 0 {
			m.inputMode = "edit_wallet"
			m.input.Placeholder = "Enter new label..."
			m.input.SetValue(m.walletRefs[m.selectedIndex].Label)
			m.input.Focus()
			m.status = "Editing wallet label..."
		}
		return m, textinput.Blink

	case key.Matches(msg, m.keys.Toggle):
		if len(m.walletRefs) > 0 {
			m.toggleWalletNetwork()
		}
		return m, nil

	case key.Matches(msg, m.keys.Delete):
		if len(m.walletRefs) > 0 {
			m.inputMode = "confirm_delete_wallet"
			m.status = fmt.Sprintf("Remove wallet '%s' from project? (y/N)", m.walletRefs[m.selectedIndex].Label)
		}
		return m, nil

	case key.Matches(msg, m.keys.Quit):
		return m, tea.Quit
	}

	return m, nil
}

// processInput processes input based on current input mode
func (m *ProjectTUIModel) processInput() (tea.Model, tea.Cmd) {
	switch m.inputMode {
	case "new_project":
		m.createProject()
	case "new_wallet":
		m.createWallet()
	case "edit_wallet":
		m.editWallet()
	case "confirm_delete":
		m.confirmDelete()
	case "confirm_delete_wallet":
		m.confirmDeleteWallet()
	}

	m.inputMode = ""
	return m, nil
}

// createProject creates a new project (synchronously like main.go)
func (m *ProjectTUIModel) createProject() {
	name := strings.TrimSpace(m.input.Value())
	if name == "" {
		m.status = "Project name cannot be empty"
		m.inputMode = ""
		return
	}

	// Validate project name
	if len(name) < 3 {
		m.status = "Project name must be at least 3 characters"
		return
	}

	if len(name) > 50 {
		m.status = "Project name must be 50 characters or less"
		return
	}

	// Check for invalid characters
	for _, char := range name {
		if !((char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') || (char >= '0' && char <= '9') || char == '-' || char == '_' || char == ' ') {
			m.status = "Project name can only contain letters, numbers, spaces, hyphens, and underscores"
			return
		}
	}

	// Create the project synchronously
	proj, err := m.manager.CreateProject(name)
	if err != nil {
		m.status = fmt.Sprintf("Failed to create project: %s", err.Error())
		return
	}

	// Open the newly created project
	m.currentProject = proj
	m.walletRefs, _ = proj.GetWalletRefs()
	m.state = ProjectWalletState
	m.selectedIndex = 0
	m.status = fmt.Sprintf("Created and opened project '%s'", name)

	m.input.SetValue("")
	m.input.Blur()
}

// openProject opens the selected project (synchronously)
func (m *ProjectTUIModel) openProject() {
	if len(m.projects) == 0 || m.selectedIndex >= len(m.projects) {
		m.status = "No project selected"
		return
	}

	projectName := m.projects[m.selectedIndex].Name

	// Try to open the project
	proj, err := m.manager.OpenProject(projectName)
	if err != nil {
		m.status = fmt.Sprintf("Failed to open project: %s", err.Error())
		return
	}

	// Load wallet references from project
	walletRefs, err := proj.GetWalletRefs()
	if err != nil {
		m.status = fmt.Sprintf("Failed to load wallet references: %s", err.Error())
		return
	}

	// Switch to wallet view
	m.currentProject = proj
	m.walletRefs = walletRefs
	m.state = ProjectWalletState
	m.selectedIndex = 0
	m.status = fmt.Sprintf("Opened project '%s' with %d wallet(s)", projectName, len(walletRefs))
}

// createWallet creates a new wallet using the main wallet manager, then adds reference to project
func (m *ProjectTUIModel) createWallet() {
	if m.currentProject == nil {
		m.status = "No project selected"
		m.input.Blur()
		return
	}

	label := strings.TrimSpace(m.input.Value())
	if label == "" {
		label = fmt.Sprintf("Wallet %d", len(m.walletRefs)+1)
	} else {
		// Validate wallet label
		if len(label) > 100 {
			m.status = "Wallet label must be 100 characters or less"
			return
		}

		// Check for duplicate labels in project
		for _, ref := range m.walletRefs {
			if ref.Label == label {
				m.status = "Wallet label must be unique in project"
				return
			}
		}
	}

	// Create wallet using main wallet manager
	address, err := m.walletManager.AddWalletWithLabel(label)
	if err != nil {
		m.status = fmt.Sprintf("Failed to create wallet: %s", err.Error())
		return
	}

	// Add reference to project (default to testnet)
	if err := m.currentProject.AddWalletRef(address, label, Testnet); err != nil {
		m.status = fmt.Sprintf("Failed to add wallet to project: %s", err.Error())
		return
	}

	// Save the project
	if err := m.currentProject.Save(); err != nil {
		m.status = fmt.Sprintf("Failed to save project: %s", err.Error())
		return
	}

	// Reload wallet references
	m.walletRefs, _ = m.currentProject.GetWalletRefs()
	m.status = fmt.Sprintf("Created wallet '%s'", label)

	m.input.SetValue("")
	m.input.Blur()
}

// editWallet edits wallet label in project
func (m *ProjectTUIModel) editWallet() {
	if m.currentProject == nil || len(m.walletRefs) == 0 || m.selectedIndex >= len(m.walletRefs) {
		m.status = "No wallet selected"
		m.input.Blur()
		return
	}

	newLabel := strings.TrimSpace(m.input.Value())
	if newLabel == "" {
		m.status = "Label cannot be empty"
		m.input.Blur()
		return
	}

	// Validate wallet label
	if len(newLabel) > 100 {
		m.status = "Wallet label must be 100 characters or less"
		return
	}

	// Check for duplicate labels (excluding current wallet)
	for i, ref := range m.walletRefs {
		if i != m.selectedIndex && ref.Label == newLabel {
			m.status = "Wallet label must be unique in project"
			return
		}
	}

	walletRef := m.walletRefs[m.selectedIndex]

	// Update wallet reference
	if err := m.currentProject.EditWalletRef(walletRef.Address, newLabel, walletRef.Network); err != nil {
		m.status = fmt.Sprintf("Failed to edit wallet: %s", err.Error())
		return
	}

	// Save project
	if err := m.currentProject.Save(); err != nil {
		m.status = fmt.Sprintf("Failed to save project: %s", err.Error())
		return
	}

	// Reload wallet references
	m.walletRefs, _ = m.currentProject.GetWalletRefs()
	m.status = fmt.Sprintf("Updated wallet label to '%s'", newLabel)

	m.input.SetValue("")
	m.input.Blur()
}

// toggleWalletNetwork toggles between mainnet and testnet
func (m *ProjectTUIModel) toggleWalletNetwork() {
	if m.currentProject == nil || len(m.walletRefs) == 0 || m.selectedIndex >= len(m.walletRefs) {
		m.status = "No wallet selected"
		return
	}

	walletRef := m.walletRefs[m.selectedIndex]

	// Toggle network
	newNetwork := Testnet
	if walletRef.Network == Testnet {
		newNetwork = Mainnet
	}

	// Update wallet network
	if err := m.currentProject.EditWalletRef(walletRef.Address, walletRef.Label, newNetwork); err != nil {
		m.status = fmt.Sprintf("Failed to toggle network: %s", err.Error())
		return
	}

	// Save project
	if err := m.currentProject.Save(); err != nil {
		m.status = fmt.Sprintf("Failed to save project: %s", err.Error())
		return
	}

	// Reload wallet references
	m.walletRefs, _ = m.currentProject.GetWalletRefs()
	m.status = fmt.Sprintf("Toggled '%s' to %s", walletRef.Label, newNetwork)
}

// confirmDelete deletes the selected project
func (m *ProjectTUIModel) confirmDelete() {
	if len(m.projects) == 0 || m.selectedIndex >= len(m.projects) {
		m.status = "No project selected"
		return
	}

	projectName := m.projects[m.selectedIndex].Name

	// Delete the project
	if err := m.manager.DeleteProject(projectName); err != nil {
		m.status = fmt.Sprintf("Failed to delete project: %s", err.Error())
		return
	}

	// Reload project list
	m.loadProjects()
	m.status = fmt.Sprintf("Deleted project '%s'", projectName)
}

// confirmDeleteWallet removes wallet reference from project
func (m *ProjectTUIModel) confirmDeleteWallet() {
	if m.currentProject == nil || len(m.walletRefs) == 0 || m.selectedIndex >= len(m.walletRefs) {
		m.status = "No wallet selected"
		return
	}

	walletRef := m.walletRefs[m.selectedIndex]

	// Remove the wallet reference
	if err := m.currentProject.DeleteWalletRef(walletRef.Address); err != nil {
		m.status = fmt.Sprintf("Failed to remove wallet: %s", err.Error())
		return
	}

	// Save project
	if err := m.currentProject.Save(); err != nil {
		m.status = fmt.Sprintf("Failed to save project: %s", err.Error())
		return
	}

	// Reload wallet references
	m.walletRefs, _ = m.currentProject.GetWalletRefs()
	if m.selectedIndex >= len(m.walletRefs) && len(m.walletRefs) > 0 {
		m.selectedIndex = len(m.walletRefs) - 1
	}

	m.status = fmt.Sprintf("Removed wallet '%s' from project", walletRef.Label)
}

// View renders the TUI
func (m *ProjectTUIModel) View() string {
	switch m.state {
	case ProjectListState:
		return m.renderProjectList()
	case ProjectWalletState:
		return m.renderWalletList()
	}

	return "Unknown state"
}

// renderProjectList renders the project list view using grid layout like main.go
func (m *ProjectTUIModel) renderProjectList() string {
	var content strings.Builder

	// Header
	header := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#89b4fa")).
		Bold(true).
		Render("📁 Projects")

	content.WriteString(header + "\n\n")

	// Project grid
	if len(m.projects) == 0 {
		emptyMessage := lipgloss.NewStyle().
			Foreground(lipgloss.Color("#6c7086")).
			Italic(true).
			Padding(2, 0).
			Render("No projects found. Press 'n' to create your first project.")
		content.WriteString(emptyMessage)
	} else {
		grid := m.renderProjectGrid()
		content.WriteString(grid)
	}

	// Status
	if m.status != "" {
		content.WriteString("\n" + m.status)
	}

	// Show input fields if in input mode
	switch m.inputMode {
	case "new_project":
		content.WriteString("\n\n" + m.input.View())
		content.WriteString("\n" + lipgloss.NewStyle().
			Foreground(lipgloss.Color("#6c7086")).
			Render("⏎•confirm  esc•cancel"))
	case "confirm_delete":
		content.WriteString("\n" + lipgloss.NewStyle().
			Foreground(lipgloss.Color("#6c7086")).
			Render("y•yes  n/esc•no"))
	case "":
		help := "\nn•new  ⏎•open  d•delete  q•quit"
		content.WriteString(lipgloss.NewStyle().
			Foreground(lipgloss.Color("#6c7086")).
			Render(help))
	}

	return content.String()
}

// renderWalletList renders the wallet list view
func (m *ProjectTUIModel) renderWalletList() string {
	var content strings.Builder

	// Header with project info
	if m.currentProject != nil {
		info := m.currentProject.GetInfo()
		header := fmt.Sprintf("📁 %s • %d wallet refs", info.Name, info.WalletCount)
		content.WriteString(lipgloss.NewStyle().
			Foreground(lipgloss.Color("#89b4fa")).
			Bold(true).
			Render(header) + "\n\n")
	}

	if len(m.walletRefs) == 0 {
		content.WriteString("No wallets in this project. Press 'n' to create one.\n")
	} else {
		// Wallet list grouped by network
		mainnetRefs := []WalletRef{}
		testnetRefs := []WalletRef{}

		for _, ref := range m.walletRefs {
			if ref.Network == Mainnet {
				mainnetRefs = append(mainnetRefs, ref)
			} else {
				testnetRefs = append(testnetRefs, ref)
			}
		}

		// Render mainnet wallets
		if len(mainnetRefs) > 0 {
			content.WriteString("🟢 Mainnet:\n")
			for _, ref := range mainnetRefs {
				// Find global index for selection
				globalIndex := -1
				for gi, gref := range m.walletRefs {
					if strings.EqualFold(gref.Address, ref.Address) {
						globalIndex = gi
						break
					}
				}

				style := lipgloss.NewStyle()
				if globalIndex == m.selectedIndex {
					style = style.Background(lipgloss.Color("#313244")).
						Foreground(lipgloss.Color("#cdd6f4")).
						Bold(true)
				}

				// Format address for display
				addr := ref.Address
				if len(addr) >= 8 {
					addr = "0x" + addr[:6] + "..." + addr[len(addr)-4:]
				} else {
					addr = "0x" + addr
				}

				line := fmt.Sprintf("  %s (%s)", ref.Label, addr)
				content.WriteString(style.Render(line) + "\n")
			}
			content.WriteString("\n")
		}

		// Render testnet wallets
		if len(testnetRefs) > 0 {
			content.WriteString("🟡 Testnet:\n")
			for _, ref := range testnetRefs {
				// Find global index for selection
				globalIndex := -1
				for gi, gref := range m.walletRefs {
					if strings.EqualFold(gref.Address, ref.Address) {
						globalIndex = gi
						break
					}
				}

				style := lipgloss.NewStyle()
				if globalIndex == m.selectedIndex {
					style = style.Background(lipgloss.Color("#313244")).
						Foreground(lipgloss.Color("#cdd6f4")).
						Bold(true)
				}

				// Format address for display
				addr := ref.Address
				if len(addr) >= 8 {
					addr = "0x" + addr[:6] + "..." + addr[len(addr)-4:]
				} else {
					addr = "0x" + addr
				}

				line := fmt.Sprintf("  %s (%s)", ref.Label, addr)
				content.WriteString(style.Render(line) + "\n")
			}
		}
	}

	// Status
	if m.status != "" {
		content.WriteString("\n" + m.status)
	}

	// Show input fields if in input mode
	switch m.inputMode {
	case "new_wallet":
		content.WriteString("\n\n" + m.input.View())
		content.WriteString("\n" + lipgloss.NewStyle().
			Foreground(lipgloss.Color("#6c7086")).
			Render("⏎•confirm  esc•cancel"))
	case "edit_wallet":
		content.WriteString("\n\n" + m.input.View())
		content.WriteString("\n" + lipgloss.NewStyle().
			Foreground(lipgloss.Color("#6c7086")).
			Render("⏎•confirm  esc•cancel"))
	case "confirm_delete_wallet":
		content.WriteString("\n" + lipgloss.NewStyle().
			Foreground(lipgloss.Color("#6c7086")).
			Render("y•yes  n/esc•no"))
	case "":
		help := "\nn•new  e•edit  space•toggle  d•remove  b•back  q•quit"
		content.WriteString("\n" + lipgloss.NewStyle().
			Foreground(lipgloss.Color("#6c7086")).
			Render(help))
	}

	return content.String()
}

// renderProjectGrid renders projects in a multi-column grid layout like main.go
func (m *ProjectTUIModel) renderProjectGrid() string {
	// Define styles matching main.go's cardStyle and selectedCardStyle
	cardStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#cdd6f4")).
		Background(lipgloss.Color("#313244")).
		Padding(0, 1).
		Border(lipgloss.NormalBorder(), false, false, false, true).
		BorderForeground(lipgloss.Color("#45475a"))

	selectedCardStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#11111b")).
		Background(lipgloss.Color("#89b4fa")).
		Bold(true).
		Padding(0, 1).
		Border(lipgloss.NormalBorder(), false, false, false, true).
		BorderForeground(lipgloss.Color("#89b4fa"))

	// Calculate optimal column layout based on terminal width
	projectWidth := 50 // Minimum width per project entry
	maxCols := m.width / projectWidth
	if maxCols < 1 {
		maxCols = 1
	}
	if maxCols > 3 { // Cap at 3 columns for readability
		maxCols = 3
	}

	actualProjectWidth := m.width / maxCols
	selectedIndex := m.selectedIndex

	var rows []string

	for i := 0; i < len(m.projects); i += maxCols {
		var columns []string

		for col := 0; col < maxCols && i+col < len(m.projects); col++ {
			projectIndex := i + col
			project := m.projects[projectIndex]
			isSelected := projectIndex == selectedIndex

			// Format project entry
			name := project.Name
			if len(name) > 20 {
				name = name[:17] + "..."
			}

			// Format counts
			walletInfo := fmt.Sprintf("%d wallets", project.WalletCount)
			if project.MainnetCount > 0 || project.TestnetCount > 0 {
				walletInfo = fmt.Sprintf("%d 🟢 %d 🟡", project.MainnetCount, project.TestnetCount)
			}

			// Format time
			timeAgo := humanizeTime(project.UpdatedAt)

			var projectContent string
			if isSelected {
				projectContent = selectedCardStyle.Copy().
					Width(actualProjectWidth - 2).
					Render(fmt.Sprintf("📁 %s\n📊 %s\n📅 %s", name, walletInfo, timeAgo))
			} else {
				projectContent = cardStyle.Copy().
					Width(actualProjectWidth - 2).
					Render(fmt.Sprintf("📁 %s\n📊 %s\n📅 %s", name, walletInfo, timeAgo))
			}

			columns = append(columns, projectContent)
		}

		// Pad remaining columns if needed
		for len(columns) < maxCols {
			columns = append(columns, lipgloss.NewStyle().Width(actualProjectWidth-2).Render(""))
		}

		row := lipgloss.JoinHorizontal(lipgloss.Top, columns...)
		rows = append(rows, row)
	}

	return lipgloss.JoinVertical(lipgloss.Left, rows...)
}

// humanizeTime formats time in a human-readable way
func humanizeTime(t time.Time) string {
	now := time.Now()
	diff := now.Sub(t)

	if diff < time.Minute {
		return "just now"
	} else if diff < time.Hour {
		mins := int(diff.Minutes())
		if mins == 1 {
			return "1 min ago"
		}
		return fmt.Sprintf("%d mins ago", mins)
	} else if diff < 24*time.Hour {
		hours := int(diff.Hours())
		if hours == 1 {
			return "1 hour ago"
		}
		return fmt.Sprintf("%d hours ago", hours)
	} else if diff < 30*24*time.Hour {
		days := int(diff.Hours() / 24)
		if days == 1 {
			return "1 day ago"
		}
		return fmt.Sprintf("%d days ago", days)
	} else {
		return t.Format("Jan 2, 2006")
	}
}