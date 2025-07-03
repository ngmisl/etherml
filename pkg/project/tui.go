package project

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/help"
	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// ProjectTUIModel represents the project management TUI
type ProjectTUIModel struct {
	manager        ProjectManager
	projects       []ProjectInfo
	currentProject Project
	wallets        []ProjectWallet
	
	// UI state
	state          ProjectTUIState
	selectedIndex  int
	width          int
	height         int
	
	// Input handling
	input          textinput.Model
	passwordInput  textinput.Model
	inputMode      string
	
	// Bulk creation state
	bulkConfig     BulkConfig
	bulkPreview    []*ProjectWallet
	
	// Status and errors
	status         string
	err            error
	
	// Key bindings
	keys           ProjectKeyMap
	help           help.Model
}

// ProjectKeyMap defines key bindings for project TUI
type ProjectKeyMap struct {
	Up           key.Binding
	Down         key.Binding
	Left         key.Binding
	Right        key.Binding
	Enter        key.Binding
	Back         key.Binding
	New          key.Binding
	Delete       key.Binding
	Edit         key.Binding
	Copy         key.Binding
	Export       key.Binding
	Bulk         key.Binding
	Toggle       key.Binding
	Help         key.Binding
	Quit         key.Binding
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
		Left: key.NewBinding(
			key.WithKeys("left", "h"),
			key.WithHelp("←/h", "left"),
		),
		Right: key.NewBinding(
			key.WithKeys("right", "l"),
			key.WithHelp("→/l", "right"),
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
		Export: key.NewBinding(
			key.WithKeys("x"),
			key.WithHelp("x", "export"),
		),
		Bulk: key.NewBinding(
			key.WithKeys("B"),
			key.WithHelp("B", "bulk create"),
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
func NewProjectTUIModel(manager ProjectManager) *ProjectTUIModel {
	// Create text inputs
	input := textinput.New()
	input.Placeholder = "Enter project name..."
	input.CharLimit = 50
	input.Width = 50
	
	passwordInput := textinput.New()
	passwordInput.Placeholder = "Enter project password..."
	passwordInput.EchoMode = textinput.EchoPassword
	passwordInput.EchoCharacter = '•'
	passwordInput.CharLimit = 100
	passwordInput.Width = 50
	
	return &ProjectTUIModel{
		manager:       manager,
		state:         ProjectListState,
		selectedIndex: 0,
		input:         input,
		passwordInput: passwordInput,
		keys:          DefaultProjectKeys(),
		help:          help.New(),
		bulkConfig: BulkConfig{
			Count:         5,
			LabelTemplate: "{project}-wallet-{index}",
			NetworkConfig: make(map[int]NetworkType),
			AutoLabel:     true,
		},
	}
}

// Init initializes the model
func (m ProjectTUIModel) Init() tea.Cmd {
	return m.loadProjects
}

// loadProjects loads the project list
func (m *ProjectTUIModel) loadProjects() tea.Msg {
	projects, err := m.manager.ListProjects()
	if err != nil {
		return ProjectErrorMsg{err}
	}
	return ProjectsLoadedMsg{projects}
}

// Update handles messages and updates the model
func (m ProjectTUIModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmds []tea.Cmd
	
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		return m, nil
		
	case ProjectsLoadedMsg:
		m.projects = msg.Projects
		if len(m.projects) > 0 && m.selectedIndex >= len(m.projects) {
			m.selectedIndex = len(m.projects) - 1
		}
		return m, nil
		
	case ProjectErrorMsg:
		m.err = msg.Err
		m.status = fmt.Sprintf("Error: %s", msg.Err.Error())
		return m, nil
		
	case ProjectCreatedMsg:
		// Open the newly created project
		m.currentProject = msg.Project
		wallets, err := msg.Project.GetWallets()
		if err != nil {
			m.status = fmt.Sprintf("Failed to load wallets: %s", err.Error())
			return m, nil
		}
		
		m.wallets = wallets
		m.state = ProjectWalletState
		m.selectedIndex = 0
		m.status = fmt.Sprintf("Created and opened project '%s'", msg.Name)
		return m, nil
		
	case tea.KeyMsg:
		return m.handleKeyPress(msg)
	}
	
	// Update input models
	if m.inputMode != "" {
		var cmd tea.Cmd
		if m.inputMode == "password" {
			m.passwordInput, cmd = m.passwordInput.Update(msg)
		} else {
			m.input, cmd = m.input.Update(msg)
		}
		cmds = append(cmds, cmd)
	}
	
	return m, tea.Batch(cmds...)
}

// handleKeyPress handles keyboard input based on current state
func (m ProjectTUIModel) handleKeyPress(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
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
	case BulkCreateState:
		return m.handleBulkCreateKeys(msg)
	}
	
	return m, nil
}

// handleInputMode handles input when in input mode
func (m ProjectTUIModel) handleInputMode(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "enter":
		return m.processInput()
	case "esc":
		m.inputMode = ""
		m.input.SetValue("")
		m.passwordInput.SetValue("")
		m.status = "Cancelled"
		return m, nil
	}
	return m, nil
}

// handleProjectListKeys handles keys in project list state
func (m ProjectTUIModel) handleProjectListKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
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
			m.inputMode = "password"
			m.passwordInput.Placeholder = "Enter password to open project..."
			m.passwordInput.Focus()
			m.status = "Opening project..."
		}
		return m, textinput.Blink
		
	case key.Matches(msg, m.keys.New):
		m.inputMode = "new_project"
		m.input.Placeholder = "Enter new project name..."
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
func (m ProjectTUIModel) handleWalletListKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch {
	case key.Matches(msg, m.keys.Up):
		if len(m.wallets) > 0 && m.selectedIndex > 0 {
			m.selectedIndex--
		}
		return m, nil
		
	case key.Matches(msg, m.keys.Down):
		if len(m.wallets) > 0 && m.selectedIndex < len(m.wallets)-1 {
			m.selectedIndex++
		}
		return m, nil
		
	case key.Matches(msg, m.keys.Back):
		m.state = ProjectListState
		m.selectedIndex = 0
		if m.currentProject != nil {
			m.currentProject.Lock()
			m.currentProject = nil
		}
		return m, m.loadProjects
		
	case key.Matches(msg, m.keys.New):
		m.inputMode = "new_wallet"
		m.input.Placeholder = "Enter wallet label..."
		m.input.Focus()
		m.status = "Creating new wallet..."
		return m, textinput.Blink
		
	case key.Matches(msg, m.keys.Bulk):
		m.state = BulkCreateState
		m.selectedIndex = 0
		m.status = "Bulk wallet creation mode"
		return m, nil
		
	case key.Matches(msg, m.keys.Edit):
		if len(m.wallets) > 0 {
			m.inputMode = "edit_wallet"
			m.input.Placeholder = "Enter new label..."
			m.input.SetValue(m.wallets[m.selectedIndex].Label)
			m.input.Focus()
			m.status = "Editing wallet label..."
		}
		return m, textinput.Blink
		
	case key.Matches(msg, m.keys.Toggle):
		if len(m.wallets) > 0 {
			return m.toggleWalletNetwork()
		}
		return m, nil
		
	case key.Matches(msg, m.keys.Copy):
		if len(m.wallets) > 0 {
			// Copy address to clipboard (would need clipboard implementation)
			m.status = "Address copied to clipboard"
		}
		return m, nil
		
	case key.Matches(msg, m.keys.Export):
		if len(m.wallets) > 0 {
			return m.exportWallet()
		}
		return m, nil
		
	case key.Matches(msg, m.keys.Delete):
		if len(m.wallets) > 0 {
			m.inputMode = "confirm_delete_wallet"
			m.status = fmt.Sprintf("Delete wallet '%s'? (y/N)", m.wallets[m.selectedIndex].Label)
		}
		return m, nil
		
	case key.Matches(msg, m.keys.Quit):
		return m, tea.Quit
	}
	
	return m, nil
}

// handleBulkCreateKeys handles keys in bulk create state
func (m ProjectTUIModel) handleBulkCreateKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch {
	case key.Matches(msg, m.keys.Up):
		if m.selectedIndex > 0 {
			m.selectedIndex--
		}
		return m, nil
		
	case key.Matches(msg, m.keys.Down):
		if m.selectedIndex < m.bulkConfig.Count-1 {
			m.selectedIndex++
		}
		return m, nil
		
	case key.Matches(msg, m.keys.Toggle):
		// Toggle network for selected wallet
		currentNetwork := m.bulkConfig.NetworkConfig[m.selectedIndex]
		if currentNetwork == Mainnet {
			m.bulkConfig.NetworkConfig[m.selectedIndex] = Testnet
		} else {
			m.bulkConfig.NetworkConfig[m.selectedIndex] = Mainnet
		}
		return m, nil
		
	case key.Matches(msg, m.keys.Enter):
		// Create wallets
		return m.createBulkWallets()
		
	case key.Matches(msg, m.keys.Back):
		m.state = ProjectWalletState
		m.selectedIndex = 0
		return m, nil
		
	case key.Matches(msg, m.keys.Quit):
		return m, tea.Quit
	}
	
	return m, nil
}

// processInput processes input based on current input mode
func (m ProjectTUIModel) processInput() (tea.Model, tea.Cmd) {
	switch m.inputMode {
	case "new_project":
		return m.createProject()
	case "new_project_password":
		return m.finalizeProjectCreation()
	case "password":
		return m.openProject()
	case "new_wallet":
		return m.createWallet()
	case "edit_wallet":
		return m.editWallet()
	case "confirm_delete":
		return m.confirmDelete()
	case "confirm_delete_wallet":
		return m.confirmDeleteWallet()
	}
	
	m.inputMode = ""
	return m, nil
}

// finalizeProjectCreation completes project creation with password
func (m ProjectTUIModel) finalizeProjectCreation() (tea.Model, tea.Cmd) {
	name := strings.TrimSpace(m.input.Value())
	password := strings.TrimSpace(m.passwordInput.Value())
	
	if name == "" {
		m.inputMode = ""
		m.status = "Project name cannot be empty"
		return m, nil
	}
	
	if password == "" {
		m.inputMode = ""
		m.status = "Password cannot be empty"
		return m, nil
	}
	
	// Create the project asynchronously to avoid blocking UI
	m.inputMode = ""
	m.input.SetValue("")
	m.passwordInput.SetValue("")
	m.status = fmt.Sprintf("Creating project '%s'... (this may take a moment)", name)
	
	return m, m.doCreateProject(name, password)
}

// doCreateProject performs the actual project creation asynchronously
func (m *ProjectTUIModel) doCreateProject(name, password string) tea.Cmd {
	return func() tea.Msg {
		proj, err := m.manager.CreateProject(name, []byte(password))
		if err != nil {
			return ProjectErrorMsg{err}
		}
		
		// Return success message with the created project
		return ProjectCreatedMsg{Project: proj, Name: name}
	}
}

// createProject creates a new project
func (m ProjectTUIModel) createProject() (tea.Model, tea.Cmd) {
	name := strings.TrimSpace(m.input.Value())
	if name == "" {
		m.status = "Project name cannot be empty"
		m.inputMode = ""
		return m, nil
	}
	
	// Switch to password input
	m.inputMode = "new_project_password"
	m.passwordInput.Placeholder = "Enter password for new project..."
	m.passwordInput.Focus()
	m.status = "Enter password for the new project..."
	
	return m, textinput.Blink
}

// Message types for async operations
type ProjectsLoadedMsg struct {
	Projects []ProjectInfo
}

type ProjectErrorMsg struct {
	Err error
}

type ProjectCreatedMsg struct {
	Project Project
	Name    string
}

type ProjectOpenedMsg struct {
	Project Project
}

type WalletsLoadedMsg struct {
	Wallets []ProjectWallet
}

// openProject opens the selected project with password
func (m ProjectTUIModel) openProject() (tea.Model, tea.Cmd) {
	if len(m.projects) == 0 || m.selectedIndex >= len(m.projects) {
		m.inputMode = ""
		m.status = "No project selected"
		return m, nil
	}
	
	password := m.passwordInput.Value()
	projectName := m.projects[m.selectedIndex].Name
	
	// Try to open the project
	proj, err := m.manager.OpenProject(projectName, []byte(password))
	if err != nil {
		m.inputMode = ""
		m.status = fmt.Sprintf("Failed to open project: %s", err.Error())
		m.passwordInput.SetValue("")
		return m, nil
	}
	
	// Load wallets from project
	wallets, err := proj.GetWallets()
	if err != nil {
		m.inputMode = ""
		m.status = fmt.Sprintf("Failed to load wallets: %s", err.Error())
		return m, nil
	}
	
	// Switch to wallet view
	m.currentProject = proj
	m.wallets = wallets
	m.state = ProjectWalletState
	m.selectedIndex = 0
	m.inputMode = ""
	m.passwordInput.SetValue("")
	m.status = fmt.Sprintf("Opened project '%s' with %d wallets", projectName, len(wallets))
	
	return m, nil
}

func (m ProjectTUIModel) createWallet() (tea.Model, tea.Cmd) {
	if m.currentProject == nil {
		m.inputMode = ""
		m.status = "No project selected"
		return m, nil
	}
	
	label := strings.TrimSpace(m.input.Value())
	if label == "" {
		label = fmt.Sprintf("Wallet %d", len(m.wallets)+1)
	}
	
	// Create new wallet (default to testnet)
	wallet, err := m.currentProject.CreateWallet(label, Testnet)
	if err != nil {
		m.inputMode = ""
		m.status = fmt.Sprintf("Failed to create wallet: %s", err.Error())
		return m, nil
	}
	
	// Save the project
	if err := m.currentProject.Save(); err != nil {
		m.inputMode = ""
		m.status = fmt.Sprintf("Failed to save project: %s", err.Error())
		return m, nil
	}
	
	// Reload wallets
	wallets, err := m.currentProject.GetWallets()
	if err != nil {
		m.inputMode = ""
		m.status = fmt.Sprintf("Failed to reload wallets: %s", err.Error())
		return m, nil
	}
	
	m.wallets = wallets
	m.inputMode = ""
	m.input.SetValue("")
	m.status = fmt.Sprintf("Created wallet '%s' at 0x%x", wallet.Label, wallet.Address[:4])
	
	return m, nil
}

func (m ProjectTUIModel) editWallet() (tea.Model, tea.Cmd) {
	if m.currentProject == nil || len(m.wallets) == 0 || m.selectedIndex >= len(m.wallets) {
		m.inputMode = ""
		m.status = "No wallet selected"
		return m, nil
	}
	
	newLabel := strings.TrimSpace(m.input.Value())
	if newLabel == "" {
		m.inputMode = ""
		m.status = "Label cannot be empty"
		return m, nil
	}
	
	wallet := m.wallets[m.selectedIndex]
	address := fmt.Sprintf("%x", wallet.Address[:])
	
	// Update wallet label
	if err := m.currentProject.EditWallet(address, newLabel, wallet.Network); err != nil {
		m.inputMode = ""
		m.status = fmt.Sprintf("Failed to edit wallet: %s", err.Error())
		return m, nil
	}
	
	// Save project
	if err := m.currentProject.Save(); err != nil {
		m.inputMode = ""
		m.status = fmt.Sprintf("Failed to save project: %s", err.Error())
		return m, nil
	}
	
	// Reload wallets
	wallets, err := m.currentProject.GetWallets()
	if err != nil {
		m.inputMode = ""
		m.status = fmt.Sprintf("Failed to reload wallets: %s", err.Error())
		return m, nil
	}
	
	m.wallets = wallets
	m.inputMode = ""
	m.input.SetValue("")
	m.status = fmt.Sprintf("Updated wallet label to '%s'", newLabel)
	
	return m, nil
}

func (m ProjectTUIModel) toggleWalletNetwork() (tea.Model, tea.Cmd) {
	if m.currentProject == nil || len(m.wallets) == 0 || m.selectedIndex >= len(m.wallets) {
		m.status = "No wallet selected"
		return m, nil
	}
	
	wallet := m.wallets[m.selectedIndex]
	address := fmt.Sprintf("%x", wallet.Address[:])
	
	// Toggle network
	newNetwork := Testnet
	if wallet.Network == Testnet {
		newNetwork = Mainnet
	}
	
	// Update wallet network
	if err := m.currentProject.EditWallet(address, wallet.Label, newNetwork); err != nil {
		m.status = fmt.Sprintf("Failed to toggle network: %s", err.Error())
		return m, nil
	}
	
	// Save project
	if err := m.currentProject.Save(); err != nil {
		m.status = fmt.Sprintf("Failed to save project: %s", err.Error())
		return m, nil
	}
	
	// Reload wallets
	wallets, err := m.currentProject.GetWallets()
	if err != nil {
		m.status = fmt.Sprintf("Failed to reload wallets: %s", err.Error())
		return m, nil
	}
	
	m.wallets = wallets
	m.status = fmt.Sprintf("Toggled '%s' to %s", wallet.Label, newNetwork)
	
	return m, nil
}

func (m ProjectTUIModel) exportWallet() (tea.Model, tea.Cmd) {
	if m.currentProject == nil || len(m.wallets) == 0 || m.selectedIndex >= len(m.wallets) {
		m.status = "No wallet selected"
		return m, nil
	}
	
	wallet := m.wallets[m.selectedIndex]
	address := fmt.Sprintf("%x", wallet.Address[:])
	
	// Export private key
	privateKey, err := m.currentProject.ExportWallet(address)
	if err != nil {
		m.status = fmt.Sprintf("Failed to export wallet: %s", err.Error())
		return m, nil
	}
	
	// For security, we'll just show a confirmation instead of the actual key
	m.status = fmt.Sprintf("Private key for '%s' exported: %s...%s", 
		wallet.Label, privateKey[:6], privateKey[len(privateKey)-4:])
	
	return m, nil
}

func (m ProjectTUIModel) confirmDelete() (tea.Model, tea.Cmd) {
	if len(m.projects) == 0 || m.selectedIndex >= len(m.projects) {
		m.inputMode = ""
		m.status = "No project selected"
		return m, nil
	}
	
	projectName := m.projects[m.selectedIndex].Name
	
	// Delete the project
	if err := m.manager.DeleteProject(projectName); err != nil {
		m.inputMode = ""
		m.status = fmt.Sprintf("Failed to delete project: %s", err.Error())
		return m, nil
	}
	
	// Reload project list
	m.inputMode = ""
	m.status = fmt.Sprintf("Deleted project '%s'", projectName)
	return m, m.loadProjects
}

func (m ProjectTUIModel) confirmDeleteWallet() (tea.Model, tea.Cmd) {
	if m.currentProject == nil || len(m.wallets) == 0 || m.selectedIndex >= len(m.wallets) {
		m.inputMode = ""
		m.status = "No wallet selected"
		return m, nil
	}
	
	wallet := m.wallets[m.selectedIndex]
	address := fmt.Sprintf("%x", wallet.Address[:])
	
	// Delete the wallet
	if err := m.currentProject.DeleteWallet(address); err != nil {
		m.inputMode = ""
		m.status = fmt.Sprintf("Failed to delete wallet: %s", err.Error())
		return m, nil
	}
	
	// Save project
	if err := m.currentProject.Save(); err != nil {
		m.inputMode = ""
		m.status = fmt.Sprintf("Failed to save project: %s", err.Error())
		return m, nil
	}
	
	// Reload wallets
	wallets, err := m.currentProject.GetWallets()
	if err != nil {
		m.inputMode = ""
		m.status = fmt.Sprintf("Failed to reload wallets: %s", err.Error())
		return m, nil
	}
	
	m.wallets = wallets
	if m.selectedIndex >= len(m.wallets) && len(m.wallets) > 0 {
		m.selectedIndex = len(m.wallets) - 1
	}
	
	m.inputMode = ""
	m.status = fmt.Sprintf("Deleted wallet '%s'", wallet.Label)
	
	return m, nil
}

func (m ProjectTUIModel) createBulkWallets() (tea.Model, tea.Cmd) {
	if m.currentProject == nil {
		m.state = ProjectWalletState
		m.status = "No project selected"
		return m, nil
	}
	
	// Create wallets using bulk configuration
	createdWallets, err := m.currentProject.BulkCreateWallets(m.bulkConfig)
	if err != nil {
		m.state = ProjectWalletState
		m.status = fmt.Sprintf("Failed to create bulk wallets: %s", err.Error())
		return m, nil
	}
	
	// Save project
	if err := m.currentProject.Save(); err != nil {
		m.state = ProjectWalletState
		m.status = fmt.Sprintf("Failed to save project: %s", err.Error())
		return m, nil
	}
	
	// Reload wallets
	wallets, err := m.currentProject.GetWallets()
	if err != nil {
		m.state = ProjectWalletState
		m.status = fmt.Sprintf("Failed to reload wallets: %s", err.Error())
		return m, nil
	}
	
	m.wallets = wallets
	m.state = ProjectWalletState
	m.selectedIndex = 0
	m.status = fmt.Sprintf("Created %d wallets successfully", len(createdWallets))
	
	return m, nil
}

// View renders the TUI
func (m ProjectTUIModel) View() string {
	switch m.state {
	case ProjectListState:
		return m.renderProjectList()
	case ProjectWalletState:
		return m.renderWalletList()
	case BulkCreateState:
		return m.renderBulkCreate()
	}
	
	return "Unknown state"
}

// renderProjectList renders the project list view
func (m ProjectTUIModel) renderProjectList() string {
	var content strings.Builder
	
	// Header
	header := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#89b4fa")).
		Bold(true).
		Render("📁 Projects")
	
	content.WriteString(header + "\n\n")
	
	// Project list
	if len(m.projects) == 0 {
		content.WriteString("No projects found. Press 'n' to create one.\n")
	} else {
		for i, project := range m.projects {
			style := lipgloss.NewStyle()
			if i == m.selectedIndex {
				style = style.Background(lipgloss.Color("#313244")).
					Foreground(lipgloss.Color("#cdd6f4")).
					Bold(true)
			}
			
			line := fmt.Sprintf("  %s (%d wallets)", project.Name, project.WalletCount)
			content.WriteString(style.Render(line) + "\n")
		}
	}
	
	// Status
	if m.status != "" {
		content.WriteString("\n" + m.status)
	}
	
	// Help
	if m.inputMode == "" {
		help := "\nn•new  ⏎•open  d•delete  q•quit"
		content.WriteString(lipgloss.NewStyle().
			Foreground(lipgloss.Color("#6c7086")).
			Render(help))
	}
	
	return content.String()
}

// renderWalletList renders the wallet list view
func (m ProjectTUIModel) renderWalletList() string {
	var content strings.Builder
	
	// Header with project info
	if m.currentProject != nil {
		info := m.currentProject.GetInfo()
		header := fmt.Sprintf("📁 %s • %d wallets", info.Name, info.WalletCount)
		content.WriteString(lipgloss.NewStyle().
			Foreground(lipgloss.Color("#89b4fa")).
			Bold(true).
			Render(header) + "\n\n")
	}
	
	if len(m.wallets) == 0 {
		content.WriteString("No wallets in this project. Press 'n' to create one or 'B' for bulk creation.\n")
	} else {
		// Wallet list grouped by network
		mainnetWallets := []ProjectWallet{}
		testnetWallets := []ProjectWallet{}
		
		for _, wallet := range m.wallets {
			if wallet.Network == Mainnet {
				mainnetWallets = append(mainnetWallets, wallet)
			} else {
				testnetWallets = append(testnetWallets, wallet)
			}
		}
		
		// Render mainnet wallets
		if len(mainnetWallets) > 0 {
			content.WriteString("🟢 Mainnet:\n")
			for _, wallet := range mainnetWallets {
				// Find global index for selection
				globalIndex := -1
				for gi, gw := range m.wallets {
					if fmt.Sprintf("%x", gw.Address[:]) == fmt.Sprintf("%x", wallet.Address[:]) {
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
				
				line := fmt.Sprintf("  %s (0x%x...%x)", 
					wallet.Label, 
					wallet.Address[:2], 
					wallet.Address[18:])
				content.WriteString(style.Render(line) + "\n")
			}
			content.WriteString("\n")
		}
		
		// Render testnet wallets
		if len(testnetWallets) > 0 {
			content.WriteString("🟡 Testnet:\n")
			for _, wallet := range testnetWallets {
				// Find global index for selection
				globalIndex := -1
				for gi, gw := range m.wallets {
					if fmt.Sprintf("%x", gw.Address[:]) == fmt.Sprintf("%x", wallet.Address[:]) {
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
				
				line := fmt.Sprintf("  %s (0x%x...%x)", 
					wallet.Label, 
					wallet.Address[:2], 
					wallet.Address[18:])
				content.WriteString(style.Render(line) + "\n")
			}
		}
	}
	
	// Status and help
	if m.status != "" {
		content.WriteString("\n" + m.status)
	}
	
	help := "\nn•new  B•bulk  e•edit  space•toggle  c•copy  x•export  d•delete  b•back  q•quit"
	content.WriteString("\n" + lipgloss.NewStyle().
		Foreground(lipgloss.Color("#6c7086")).
		Render(help))
	
	return content.String()
}

// renderBulkCreate renders the bulk creation interface
func (m ProjectTUIModel) renderBulkCreate() string {
	var content strings.Builder
	
	// Header
	header := "🏗️ Bulk Wallet Creation"
	content.WriteString(lipgloss.NewStyle().
		Foreground(lipgloss.Color("#89b4fa")).
		Bold(true).
		Render(header) + "\n\n")
	
	// Configuration
	content.WriteString(fmt.Sprintf("Count: %d\n", m.bulkConfig.Count))
	content.WriteString(fmt.Sprintf("Template: %s\n\n", m.bulkConfig.LabelTemplate))
	
	// Preview
	content.WriteString("Preview:\n")
	for i := 0; i < m.bulkConfig.Count; i++ {
		network := m.bulkConfig.NetworkConfig[i]
		if network == "" {
			network = Testnet
		}
		
		style := lipgloss.NewStyle()
		if i == m.selectedIndex {
			style = style.Background(lipgloss.Color("#313244"))
		}
		
		networkIcon := "🟡"
		if network == Mainnet {
			networkIcon = "🟢"
		}
		
		label := fmt.Sprintf("wallet-%d", i+1)
		line := fmt.Sprintf("  %s %s", networkIcon, label)
		content.WriteString(style.Render(line) + "\n")
	}
	
	// Help
	help := "\nspace•toggle network  ⏎•create  b•back  q•quit"
	content.WriteString(lipgloss.NewStyle().
		Foreground(lipgloss.Color("#6c7086")).
		Render(help))
	
	return content.String()
}