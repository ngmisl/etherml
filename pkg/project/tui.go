package project

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/help"
	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/list"
	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"golang.design/x/clipboard"
)

// Message types - simpler, like in main.go
type projectOpenCompleteMsg struct{}
type walletRefreshCompleteMsg struct{}
type bulkCreateCompleteMsg struct{}

// ProjectTUI provides a terminal user interface for project management
type ProjectTUI struct {
	manager *Manager
}

// NewProjectTUI creates a new project TUI
func NewProjectTUI(manager *Manager) *ProjectTUI {
	return &ProjectTUI{
		manager: manager,
	}
}

// ProjectListModel represents the project list screen
type ProjectListModel struct {
	manager            *Manager
	projects           []ProjectInfo
	list               list.Model
	keys               ProjectListKeyMap
	help               help.Model
	inputMode          string
	textInput          textinput.Model
	width              int
	height             int
	status             string
	err                error
	pendingProjectName string       // Temporary storage for project name during creation
	pendingProjectID   string       // Temporary storage for project ID during opening/operations
	confirmingDelete   bool         // True when confirming deletion
	projectToDelete    *ProjectInfo // Project pending deletion
	opening            bool         // True when opening a project
	spinner            spinner.Model
	openedProject      *ProjectImpl // Store the opened project
}

// ProjectListKeyMap defines key bindings for project list
type ProjectListKeyMap struct {
	New    key.Binding
	Open   key.Binding
	Delete key.Binding
	Rename key.Binding
	Back   key.Binding
	Help   key.Binding
	Quit   key.Binding
	Enter  key.Binding
	Escape key.Binding
}

// DefaultProjectListKeys returns default key bindings
func DefaultProjectListKeys() ProjectListKeyMap {
	return ProjectListKeyMap{
		New: key.NewBinding(
			key.WithKeys("n"),
			key.WithHelp("n", "new project"),
		),
		Open: key.NewBinding(
			key.WithKeys("o", "enter"),
			key.WithHelp("o/enter", "open project"),
		),
		Delete: key.NewBinding(
			key.WithKeys("d"),
			key.WithHelp("d", "delete project"),
		),
		Rename: key.NewBinding(
			key.WithKeys("r"),
			key.WithHelp("r", "rename project"),
		),
		Back: key.NewBinding(
			key.WithKeys("b", "esc"),
			key.WithHelp("b/esc", "back to main"),
		),
		Help: key.NewBinding(
			key.WithKeys("?"),
			key.WithHelp("?", "help"),
		),
		Quit: key.NewBinding(
			key.WithKeys("q", "ctrl+c"),
			key.WithHelp("q", "quit"),
		),
		Enter: key.NewBinding(
			key.WithKeys("enter"),
			key.WithHelp("enter", "confirm"),
		),
		Escape: key.NewBinding(
			key.WithKeys("esc"),
			key.WithHelp("esc", "cancel"),
		),
	}
}

// ShortHelp returns short help
func (k ProjectListKeyMap) ShortHelp() []key.Binding {
	return []key.Binding{k.New, k.Open, k.Delete, k.Rename, k.Back, k.Help}
}

// FullHelp returns full help
func (k ProjectListKeyMap) FullHelp() [][]key.Binding {
	return [][]key.Binding{
		{k.New, k.Open, k.Delete},
		{k.Rename, k.Back, k.Help, k.Quit},
	}
}

// ProjectListItem represents a project in the list
type ProjectListItem struct {
	info ProjectInfo
}

// FilterValue returns the filter value for list filtering
func (i ProjectListItem) FilterValue() string {
	return i.info.Name + " " + i.info.Description
}

// Title returns the item title
func (i ProjectListItem) Title() string {
	return fmt.Sprintf("📁 %s", i.info.Name)
}

// Description returns the item description
func (i ProjectListItem) Description() string {
	timeAgo := humanizeTime(i.info.LastAccessed)
	return fmt.Sprintf("%d wallets • Last accessed %s", i.info.WalletCount, timeAgo)
}

// humanizeTime formats time in a human-readable way
func humanizeTime(t time.Time) string {
	if t.IsZero() {
		return "never"
	}

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

// NewProjectListModel creates a new project list model
func NewProjectListModel(manager *Manager) ProjectListModel {
	// Load projects
	projects, err := manager.ListProjects()
	if err != nil {
		projects = []ProjectInfo{}
	}

	// Create list items
	items := make([]list.Item, len(projects))
	for i, project := range projects {
		items[i] = ProjectListItem{info: project}
	}

	// Create list
	delegate := list.NewDefaultDelegate()
	delegate.SetHeight(3)
	delegate.SetSpacing(1)

	l := list.New(items, delegate, 0, 0)
	l.Title = "Projects"
	l.SetShowStatusBar(false)
	l.SetFilteringEnabled(true)
	l.SetShowHelp(false)

	// Create text input for new project names
	ti := textinput.New()
	ti.Placeholder = "Enter project name..."
	ti.CharLimit = 64
	ti.Width = 50

	// Create spinner
	s := spinner.New()
	s.Spinner = spinner.Dot
	s.Style = lipgloss.NewStyle().Foreground(lipgloss.Color("#89b4fa"))

	return ProjectListModel{
		manager:   manager,
		projects:  projects,
		list:      l,
		keys:      DefaultProjectListKeys(),
		help:      help.New(),
		textInput: ti,
		spinner:   s,
	}
}

// Init initializes the model
func (m *ProjectListModel) Init() tea.Cmd {
	return tea.Batch(
		m.spinner.Tick,
		textinput.Blink,
	)
}

// Update handles messages
func (m *ProjectListModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmds []tea.Cmd

	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.list.SetSize(msg.Width, msg.Height-4) // Leave space for status and help
		m.help.Width = msg.Width
		return m, nil

	case projectOpenCompleteMsg:
		m.opening = false
		if m.openedProject != nil {
			// Switch to wallet view
			walletModel := NewProjectWalletModel(m.openedProject)
			walletModel.SetSize(m.width, m.height)
			return walletModel, walletModel.Init()
		}
		return m, nil

	case spinner.TickMsg:
		if m.opening {
			var cmd tea.Cmd
			m.spinner, cmd = m.spinner.Update(msg)
			cmds = append(cmds, cmd)
		}
		return m, tea.Batch(cmds...)

	case tea.KeyMsg:
		// Don't process keys while opening
		if m.opening {
			return m, nil
		}

		// Handle input modes first
		if m.inputMode != "" {
			switch msg.String() {
			case "enter":
				switch m.inputMode {
				case "new":
					name := strings.TrimSpace(m.textInput.Value())
					if name != "" {
						// Switch to password input mode
						m.inputMode = "password"
						m.textInput.Placeholder = "Enter password for new project..."
						m.textInput.SetValue("")
						m.textInput.EchoMode = textinput.EchoPassword
						m.textInput.EchoCharacter = '•'
						m.status = fmt.Sprintf("Enter password for project: %s", name)
						// Store the project name temporarily
						m.pendingProjectName = name
						return m, textinput.Blink
					}
				case "password":
					password := m.textInput.Value()
					if password != "" && m.pendingProjectName != "" {
						// Create the project using go routine like in main.go
						m.status = "🔄 Creating project..."
						projectName := m.pendingProjectName

						go func() {
							_, err := m.manager.CreateProject(projectName, "", []byte(password))
							if err != nil {
								m.status = fmt.Sprintf("❌ Error creating project: %s", err.Error())
							} else {
								m.status = fmt.Sprintf("✅ Project '%s' created successfully", projectName)
								m.refreshProjectList()
							}
						}()

						// Clear sensitive data
						m.textInput.SetValue("")
						m.pendingProjectName = ""
						m.inputMode = ""
						m.textInput.EchoMode = textinput.EchoNormal
						m.textInput.Blur()
					} else if password != "" && m.pendingProjectID != "" {
						// Open the project using go routine like in main.go
						m.opening = true
						m.status = "🔄 Opening project..."
						projectID := m.pendingProjectID

						go func() {
							// Small delay for better UX
							time.Sleep(300 * time.Millisecond)

							project, err := m.manager.OpenProject(projectID, []byte(password))
							if err != nil {
								m.status = fmt.Sprintf("❌ Failed to open project: %s", err.Error())
								m.pendingProjectID = ""
								m.opening = false
							} else {
								// Convert to ProjectImpl
								if projectImpl, ok := (*project).(*ProjectImpl); ok {
									m.openedProject = projectImpl
									m.status = "✅ Project opened successfully"
								} else {
									m.status = "❌ Invalid project type"
									m.opening = false
								}
							}
						}()

						// Clear input and send tick to complete
						m.inputMode = ""
						m.textInput.SetValue("")
						m.textInput.EchoMode = textinput.EchoNormal
						m.textInput.Blur()
						m.pendingProjectID = ""

						// Use tea.Tick to trigger completion after delay
						cmds = append(cmds, tea.Tick(500*time.Millisecond, func(t time.Time) tea.Msg {
							return projectOpenCompleteMsg{}
						}))
					}
				case "rename":
					// Rename the project
					name := strings.TrimSpace(m.textInput.Value())
					if name != "" && m.pendingProjectID != "" {
						err := m.manager.RenameProject(m.pendingProjectID, name)
						if err != nil {
							m.status = fmt.Sprintf("❌ Failed to rename: %s", err.Error())
						} else {
							m.status = fmt.Sprintf("✅ Project renamed to: %s", name)
							m.refreshProjectList()
						}
					}
					m.inputMode = ""
					m.pendingProjectID = ""
					m.textInput.SetValue("")
					m.textInput.Blur()
				}

				return m, tea.Batch(cmds...)

			case "esc":
				m.inputMode = ""
				m.textInput.SetValue("")
				m.textInput.Blur()
				m.textInput.EchoMode = textinput.EchoNormal
				m.pendingProjectName = ""
				m.pendingProjectID = ""
				m.status = "Cancelled"
				return m, nil

			default:
				var cmd tea.Cmd
				m.textInput, cmd = m.textInput.Update(msg)
				return m, cmd
			}
		}

		// Handle delete confirmation
		if m.confirmingDelete {
			switch msg.String() {
			case "y", "Y":
				if m.projectToDelete != nil {
					err := m.manager.DeleteProject(m.projectToDelete.ID)
					if err != nil {
						m.status = fmt.Sprintf("❌ Failed to delete: %s", err.Error())
					} else {
						m.status = fmt.Sprintf("✅ Project '%s' deleted", m.projectToDelete.Name)
						m.refreshProjectList()
					}
				}
				m.confirmingDelete = false
				m.projectToDelete = nil
				return m, nil
			case "n", "N", "esc":
				m.confirmingDelete = false
				m.projectToDelete = nil
				m.status = "❌ Delete cancelled"
				return m, nil
			}
			return m, nil
		}

		// Handle main key bindings
		switch {
		case key.Matches(msg, m.keys.New):
			m.inputMode = "new"
			m.textInput.Placeholder = "Enter project name..."
			m.textInput.SetValue("")
			m.textInput.Focus()
			m.status = "📝 Enter name for new project"
			return m, textinput.Blink

		case key.Matches(msg, m.keys.Open):
			if selected := m.getSelectedProject(); selected != nil {
				m.inputMode = "password"
				m.textInput.Placeholder = "Enter project password..."
				m.textInput.SetValue("")
				m.textInput.EchoMode = textinput.EchoPassword
				m.textInput.EchoCharacter = '•'
				m.textInput.Focus()
				m.pendingProjectID = selected.ID
				m.status = fmt.Sprintf("🔐 Enter password to open: %s", selected.Name)
				return m, textinput.Blink
			} else {
				m.status = "⚠️ No project selected"
			}
			return m, nil

		case key.Matches(msg, m.keys.Delete):
			if selected := m.getSelectedProject(); selected != nil {
				m.confirmingDelete = true
				m.projectToDelete = selected
				m.status = fmt.Sprintf("⚠️ Delete project '%s'? (y/N)", selected.Name)
			} else {
				m.status = "⚠️ No project selected"
			}
			return m, nil

		case key.Matches(msg, m.keys.Rename):
			if selected := m.getSelectedProject(); selected != nil {
				// Check if project is currently open
				isOpen := false
				if openProjects, ok := m.manager.projects[selected.ID]; ok && !openProjects.IsLocked() {
					isOpen = true
				}

				if !isOpen {
					m.status = "❌ Project must be open to rename"
					return m, nil
				}

				m.inputMode = "rename"
				m.textInput.Placeholder = "Enter new name..."
				m.textInput.SetValue(selected.Name)
				m.textInput.Focus()
				m.pendingProjectID = selected.ID
				m.status = fmt.Sprintf("✏️ Renaming project: %s", selected.Name)
				return m, textinput.Blink
			} else {
				m.status = "⚠️ No project selected"
			}
			return m, nil

		case key.Matches(msg, m.keys.Back), key.Matches(msg, m.keys.Escape):
			// Signal to return to main menu
			return m, tea.Quit

		case key.Matches(msg, m.keys.Quit):
			return m, tea.Quit
		}

		// Update list for navigation
		var cmd tea.Cmd
		m.list, cmd = m.list.Update(msg)
		cmds = append(cmds, cmd)
	}

	return m, tea.Batch(cmds...)
}

// getSelectedProject returns the currently selected project
func (m *ProjectListModel) getSelectedProject() *ProjectInfo {
	if item, ok := m.list.SelectedItem().(ProjectListItem); ok {
		return &item.info
	}
	return nil
}

// refreshProjectList reloads the project list from the manager
func (m *ProjectListModel) refreshProjectList() {
	projects, err := m.manager.ListProjects()
	if err != nil {
		m.err = err
		projects = []ProjectInfo{}
	}

	m.projects = projects

	// Update list items
	items := make([]list.Item, len(projects))
	for i, project := range projects {
		items[i] = ProjectListItem{info: project}
	}
	m.list.SetItems(items)
}

// SetSize sets the dimensions of the project list model
func (m *ProjectListModel) SetSize(width, height int) {
	m.width = width
	m.height = height
	if m.width > 0 && m.height > 0 {
		m.list.SetSize(width, height-4) // Leave space for status and help
		m.help.Width = width
	}
}

// View renders the model
func (m *ProjectListModel) View() string {
	if m.width == 0 || m.height == 0 {
		return "Loading..."
	}

	var sections []string

	// Header
	header := lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("#89b4fa")).
		Render("🔐 Quantum Wallet Manager - Projects")
	sections = append(sections, header)

	// Loading overlay
	if m.opening {
		modalContent := lipgloss.JoinVertical(
			lipgloss.Center,
			"🔄 Opening Project",
			"",
			m.spinner.View(),
			"",
			"Decrypting project data...",
			"",
			lipgloss.NewStyle().
				Foreground(lipgloss.Color("#6c7086")).
				Render("Please wait..."),
		)

		modal := lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("#89b4fa")).
			Padding(1, 2).
			Render(modalContent)

		return lipgloss.Place(
			m.width, m.height,
			lipgloss.Center, lipgloss.Center,
			modal,
		)
	}

	// Delete confirmation overlay
	if m.confirmingDelete && m.projectToDelete != nil {
		modalWidth := 60
		if modalWidth > m.width-4 {
			modalWidth = m.width - 4
		}

		modalContent := lipgloss.JoinVertical(
			lipgloss.Center,
			"⚠️ Confirm Project Deletion",
			"",
			fmt.Sprintf("Project: %s", m.projectToDelete.Name),
			fmt.Sprintf("Wallets: %d", m.projectToDelete.WalletCount),
			"",
			lipgloss.NewStyle().
				Foreground(lipgloss.Color("#f38ba8")).
				Bold(true).
				Render("This action cannot be undone!"),
			"",
			lipgloss.NewStyle().
				Foreground(lipgloss.Color("#6c7086")).
				Render("y • Confirm | n/Esc • Cancel"),
		)

		modal := lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("#f38ba8")).
			Padding(1, 2).
			MaxWidth(modalWidth).
			AlignHorizontal(lipgloss.Center).
			Render(modalContent)

		return lipgloss.Place(
			m.width, m.height,
			lipgloss.Center, lipgloss.Center,
			modal,
		)
	}

	// Input mode overlay
	if m.inputMode != "" {
		inputTitle := ""
		switch m.inputMode {
		case "new":
			inputTitle = "✨ Create New Project"
		case "password":
			if m.pendingProjectName != "" {
				inputTitle = "🔐 Set Project Password"
			} else {
				inputTitle = "🔐 Enter Project Password"
			}
		case "rename":
			inputTitle = "✏️ Rename Project"
		}

		// Ensure modal doesn't exceed terminal bounds
		modalWidth := 60
		if modalWidth > m.width-4 {
			modalWidth = m.width - 4
		}

		modalContent := lipgloss.JoinVertical(
			lipgloss.Center,
			inputTitle,
			"",
			m.textInput.View(),
			"",
			lipgloss.NewStyle().
				Foreground(lipgloss.Color("#6c7086")).
				Render("Enter • Confirm | Esc • Cancel"),
		)

		modal := lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("#cba6f7")).
			Padding(1, 2).
			MaxWidth(modalWidth).
			AlignHorizontal(lipgloss.Center).
			Render(modalContent)

		return lipgloss.Place(
			m.width, m.height,
			lipgloss.Center, lipgloss.Center,
			modal,
		)
	}

	// Main list
	sections = append(sections, m.list.View())

	// Status bar
	if m.status != "" {
		statusBar := lipgloss.NewStyle().
			Background(lipgloss.Color("#313244")).
			Foreground(lipgloss.Color("#cdd6f4")).
			Padding(0, 1).
			Width(m.width).
			Render(m.status)
		sections = append(sections, statusBar)
	}

	// Help
	helpView := m.help.View(m.keys)
	sections = append(sections, helpView)

	return lipgloss.JoinVertical(lipgloss.Left, sections...)
}

// ProjectWalletModel represents the wallet view for an opened project
type ProjectWalletModel struct {
	project           *ProjectImpl
	wallets           []*ProjectWallet
	selectedIndex     int
	keys              ProjectWalletKeyMap
	help              help.Model
	inputMode         string
	textInput         textinput.Model
	width             int
	height            int
	status            string
	showingPrivateKey bool
	selectedWallet    *ProjectWallet
	confirmingDelete  bool
	walletToDelete    *ProjectWallet
	bulkWizard        *BulkCreationWizard
	exportedKey       string
	loading           bool
	spinner           spinner.Model
}

// ProjectWalletKeyMap defines key bindings for project wallet view
type ProjectWalletKeyMap struct {
	Up     key.Binding
	Down   key.Binding
	New    key.Binding
	Bulk   key.Binding
	Export key.Binding
	Delete key.Binding
	Copy   key.Binding
	Edit   key.Binding
	Toggle key.Binding
	Lock   key.Binding
	Back   key.Binding
	Help   key.Binding
	Quit   key.Binding
}

// DefaultProjectWalletKeys returns default key bindings
func DefaultProjectWalletKeys() ProjectWalletKeyMap {
	return ProjectWalletKeyMap{
		Up: key.NewBinding(
			key.WithKeys("up", "k"),
			key.WithHelp("↑/k", "up"),
		),
		Down: key.NewBinding(
			key.WithKeys("down", "j"),
			key.WithHelp("↓/j", "down"),
		),
		New: key.NewBinding(
			key.WithKeys("n"),
			key.WithHelp("n", "new wallet"),
		),
		Bulk: key.NewBinding(
			key.WithKeys("b"),
			key.WithHelp("b", "bulk create"),
		),
		Export: key.NewBinding(
			key.WithKeys("e"),
			key.WithHelp("e", "export key"),
		),
		Delete: key.NewBinding(
			key.WithKeys("d"),
			key.WithHelp("d", "delete wallet"),
		),
		Copy: key.NewBinding(
			key.WithKeys("c"),
			key.WithHelp("c", "copy address"),
		),
		Edit: key.NewBinding(
			key.WithKeys("r"),
			key.WithHelp("r", "rename label"),
		),
		Toggle: key.NewBinding(
			key.WithKeys("t"),
			key.WithHelp("t", "toggle network"),
		),
		Lock: key.NewBinding(
			key.WithKeys("l"),
			key.WithHelp("l", "lock project"),
		),
		Back: key.NewBinding(
			key.WithKeys("esc"),
			key.WithHelp("esc", "back to projects"),
		),
		Help: key.NewBinding(
			key.WithKeys("?"),
			key.WithHelp("?", "help"),
		),
		Quit: key.NewBinding(
			key.WithKeys("q"),
			key.WithHelp("q", "quit"),
		),
	}
}

// NewProjectWalletModel creates a new project wallet model
func NewProjectWalletModel(project *ProjectImpl) *ProjectWalletModel {
	ti := textinput.New()
	ti.CharLimit = 50
	ti.Width = 50

	// Create spinner
	s := spinner.New()
	s.Spinner = spinner.Dot
	s.Style = lipgloss.NewStyle().Foreground(lipgloss.Color("#89b4fa"))

	m := &ProjectWalletModel{
		project:       project,
		wallets:       []*ProjectWallet{},
		selectedIndex: 0,
		keys:          DefaultProjectWalletKeys(),
		help:          help.New(),
		textInput:     ti,
		status:        "Loading wallets...",
		loading:       true,
		spinner:       s,
	}

	// Load wallets immediately using go routine
	go func() {
		time.Sleep(100 * time.Millisecond) // Small delay for UX
		wallets, err := project.ListWallets()
		if err != nil {
			m.status = fmt.Sprintf("❌ Failed to load wallets: %s", err.Error())
		} else {
			m.wallets = wallets
			if len(wallets) == 0 {
				m.status = "📝 No wallets yet - press 'n' to create one"
			} else {
				m.status = fmt.Sprintf("✅ Project: %s • %d wallets", project.GetName(), len(wallets))
			}
		}
		m.loading = false
	}()

	return m
}

// GetProject returns the current project
func (m *ProjectWalletModel) GetProject() *ProjectImpl {
	return m.project
}

// Init initializes the wallet model
func (m *ProjectWalletModel) Init() tea.Cmd {
	return tea.Batch(
		m.spinner.Tick,
		// Send a tick to refresh after initial load
		tea.Tick(200*time.Millisecond, func(t time.Time) tea.Msg {
			return walletRefreshCompleteMsg{}
		}),
	)
}

// SetSize sets the dimensions
func (m *ProjectWalletModel) SetSize(width, height int) {
	m.width = width
	m.height = height
	m.help.Width = width
}

// refreshWallets reloads the wallet list
func (m *ProjectWalletModel) refreshWallets() {
	m.loading = true
	m.status = "🔄 Refreshing wallets..."

	go func() {
		time.Sleep(100 * time.Millisecond) // Small delay for UX
		wallets, err := m.project.ListWallets()
		if err != nil {
			m.status = fmt.Sprintf("❌ Failed to load wallets: %s", err.Error())
		} else {
			m.wallets = wallets
			if len(wallets) == 0 {
				m.status = "📝 No wallets yet - press 'n' to create one"
			} else {
				m.status = fmt.Sprintf("✅ Refreshed • %d wallets", len(wallets))
			}
			// Reset selection if out of bounds
			if m.selectedIndex >= len(m.wallets) && len(m.wallets) > 0 {
				m.selectedIndex = len(m.wallets) - 1
			}
		}
		m.loading = false
	}()
}

// Update handles messages for the wallet view
func (m *ProjectWalletModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmds []tea.Cmd

	// Handle bulk wizard mode
	if m.bulkWizard != nil {
		updatedWizard, cmd := m.bulkWizard.Update(msg)
		m.bulkWizard = updatedWizard

		// Check if wizard is done
		if m.bulkWizard.done {
			if m.bulkWizard.cancelled {
				m.status = "❌ Bulk creation cancelled"
			} else if m.bulkWizard.error != nil {
				m.status = fmt.Sprintf("❌ Error: %s", m.bulkWizard.error.Error())
			} else {
				m.status = fmt.Sprintf("✅ Created %d wallets successfully", m.bulkWizard.count)
				// Refresh wallet list
				m.refreshWallets()
			}
			m.bulkWizard = nil

			// Send refresh complete message after delay
			cmds = append(cmds, tea.Tick(300*time.Millisecond, func(t time.Time) tea.Msg {
				return walletRefreshCompleteMsg{}
			}))
		}

		return m, tea.Batch(append(cmds, cmd)...)
	}

	switch msg := msg.(type) {
	case walletRefreshCompleteMsg:
		// Force UI update
		return m, nil

	case bulkCreateCompleteMsg:
		// Refresh wallets after bulk create
		m.refreshWallets()
		cmds = append(cmds, tea.Tick(300*time.Millisecond, func(t time.Time) tea.Msg {
			return walletRefreshCompleteMsg{}
		}))
		return m, tea.Batch(cmds...)

	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.help.Width = msg.Width
		// Update bulk wizard size if active
		if m.bulkWizard != nil {
			m.bulkWizard.SetSize(msg.Width, msg.Height)
		}
		return m, nil

	case spinner.TickMsg:
		if m.loading {
			var cmd tea.Cmd
			m.spinner, cmd = m.spinner.Update(msg)
			cmds = append(cmds, cmd)
		}
		return m, tea.Batch(cmds...)

	case tea.KeyMsg:
		// Don't process keys while loading
		if m.loading {
			return m, nil
		}

		// Handle private key display
		if m.showingPrivateKey {
			switch msg.String() {
			case "c", "C":
				// Copy private key
				if m.selectedWallet != nil && m.exportedKey != "" {
					clipboard.Write(clipboard.FmtText, []byte(m.exportedKey))
					m.status = "📋 Private key copied to clipboard (clears in 30s)"
					// Clear clipboard after 30 seconds
					go func() {
						time.Sleep(30 * time.Second)
						clipboard.Write(clipboard.FmtText, []byte(""))
					}()
				}
				return m, nil
			default:
				// Clear private key display
				m.showingPrivateKey = false
				m.exportedKey = ""
				m.selectedWallet = nil
				m.status = "🔒 Private key cleared from display"
				return m, nil
			}
		}

		// Handle delete confirmation
		if m.confirmingDelete {
			switch msg.String() {
			case "y", "Y":
				if m.walletToDelete != nil {
					m.loading = true
					m.status = "🔄 Deleting wallet..."

					go func() {
						err := m.project.DeleteWallet(m.walletToDelete.Address)
						if err != nil {
							m.status = fmt.Sprintf("❌ Failed to delete: %s", err.Error())
						} else {
							m.status = "✅ Wallet deleted"
							m.refreshWallets()
						}
						m.loading = false
					}()

					m.confirmingDelete = false
					m.walletToDelete = nil

					// Trigger refresh
					cmds = append(cmds, tea.Tick(300*time.Millisecond, func(t time.Time) tea.Msg {
						return walletRefreshCompleteMsg{}
					}))
				}
			case "n", "N", "esc":
				m.confirmingDelete = false
				m.walletToDelete = nil
				m.status = "❌ Delete cancelled"
				return m, nil
			}
			return m, tea.Batch(cmds...)
		}

		// Handle input mode (for new wallet label)
		if m.inputMode != "" {
			switch msg.String() {
			case "enter":
				switch m.inputMode {
				case "new":
					label := strings.TrimSpace(m.textInput.Value())
					if label == "" {
						label = fmt.Sprintf("%s-wallet-%d", m.project.GetName(), len(m.wallets)+1)
					}

					// Create wallet using go routine like in main.go
					m.loading = true
					m.status = "🔄 Creating wallet..."

					go func() {
						_, err := m.project.CreateWallet(label, "testnet")
						if err != nil {
							m.status = fmt.Sprintf("❌ Failed to create wallet: %s", err.Error())
						} else {
							m.status = "✅ Wallet created"
							m.refreshWallets()
						}
						m.loading = false
					}()

					m.inputMode = ""
					m.textInput.SetValue("")
					m.textInput.Blur()

					// Trigger refresh
					cmds = append(cmds, tea.Tick(500*time.Millisecond, func(t time.Time) tea.Msg {
						return walletRefreshCompleteMsg{}
					}))

				case "edit":
					if len(m.wallets) > 0 && m.selectedIndex >= 0 && m.selectedIndex < len(m.wallets) {
						wallet := m.wallets[m.selectedIndex]
						newLabel := strings.TrimSpace(m.textInput.Value())
						if newLabel == "" {
							newLabel = "Untitled Wallet"
						}

						// Update wallet label using go routine
						m.loading = true
						m.status = "🔄 Updating label..."

						go func() {
							err := m.project.UpdateWallet(wallet.Address, WalletUpdate{
								Label: &newLabel,
							})
							if err != nil {
								m.status = fmt.Sprintf("❌ Failed to update label: %s", err.Error())
							} else {
								m.status = "✅ Label updated"
								m.refreshWallets()
							}
							m.loading = false
						}()

						m.inputMode = ""
						m.textInput.SetValue("")
						m.textInput.Blur()

						// Trigger refresh
						cmds = append(cmds, tea.Tick(300*time.Millisecond, func(t time.Time) tea.Msg {
							return walletRefreshCompleteMsg{}
						}))
					}
				}
			case "esc":
				m.inputMode = ""
				m.textInput.SetValue("")
				m.textInput.Blur()
				m.status = "❌ Cancelled"
				return m, nil
			default:
				var cmd tea.Cmd
				m.textInput, cmd = m.textInput.Update(msg)
				return m, cmd
			}
			return m, tea.Batch(cmds...)
		}

		// Handle main keys
		switch {
		case key.Matches(msg, m.keys.Up):
			if m.selectedIndex > 0 && len(m.wallets) > 0 {
				m.selectedIndex--
			}
			return m, nil

		case key.Matches(msg, m.keys.Down):
			if m.selectedIndex < len(m.wallets)-1 && len(m.wallets) > 0 {
				m.selectedIndex++
			}
			return m, nil

		case key.Matches(msg, m.keys.New):
			m.inputMode = "new"
			m.textInput.Placeholder = "Enter wallet label..."
			m.textInput.SetValue("")
			m.textInput.Focus()
			m.status = "📝 Enter label for new wallet"
			return m, textinput.Blink

		case key.Matches(msg, m.keys.Bulk):
			// Start bulk creation wizard
			m.bulkWizard = NewBulkCreationWizard(m.project)
			m.bulkWizard.SetSize(m.width, m.height)
			return m, textinput.Blink

		case key.Matches(msg, m.keys.Export):
			if len(m.wallets) > 0 && m.selectedIndex >= 0 && m.selectedIndex < len(m.wallets) {
				wallet := m.wallets[m.selectedIndex]
				exported, err := m.project.ExportWallet(wallet.Address)
				if err != nil {
					m.status = fmt.Sprintf("❌ Failed to export: %s", err.Error())
				} else {
					// Show private key
					m.showingPrivateKey = true
					m.selectedWallet = wallet
					m.exportedKey = exported.PrivateKey
					m.status = "🔑 Private key displayed - Press 'c' to copy, any other key to clear"
				}
			}
			return m, nil

		case key.Matches(msg, m.keys.Copy):
			if len(m.wallets) > 0 && m.selectedIndex >= 0 && m.selectedIndex < len(m.wallets) {
				wallet := m.wallets[m.selectedIndex]
				address := wallet.Address.String()
				clipboard.Write(clipboard.FmtText, []byte(address))
				m.status = fmt.Sprintf("📋 Address copied: %s", address)
			}
			return m, nil

		case key.Matches(msg, m.keys.Delete):
			if len(m.wallets) > 0 && m.selectedIndex >= 0 && m.selectedIndex < len(m.wallets) {
				wallet := m.wallets[m.selectedIndex]
				m.walletToDelete = wallet
				m.confirmingDelete = true
				m.status = fmt.Sprintf("⚠️ Delete wallet %s? (y/N)", wallet.Label)
			}
			return m, nil

		case key.Matches(msg, m.keys.Edit):
			if len(m.wallets) > 0 && m.selectedIndex >= 0 && m.selectedIndex < len(m.wallets) {
				wallet := m.wallets[m.selectedIndex]
				m.inputMode = "edit"
				m.textInput.Placeholder = "Enter new label..."
				m.textInput.SetValue(wallet.Label)
				m.textInput.Focus()
				m.status = fmt.Sprintf("✏️ Editing label for %s", wallet.Address.String())
			}
			return m, textinput.Blink

		case key.Matches(msg, m.keys.Toggle):
			if len(m.wallets) > 0 && m.selectedIndex >= 0 && m.selectedIndex < len(m.wallets) {
				wallet := m.wallets[m.selectedIndex]
				newNetwork := "mainnet"
				if wallet.Network == "mainnet" {
					newNetwork = "testnet"
				}

				// Update wallet network using go routine
				m.loading = true
				m.status = "🔄 Updating network..."

				go func() {
					err := m.project.UpdateWallet(wallet.Address, WalletUpdate{
						Network: &newNetwork,
					})
					if err != nil {
						m.status = fmt.Sprintf("❌ Failed to update network: %s", err.Error())
					} else {
						m.status = "✅ Network updated"
						m.refreshWallets()
					}
					m.loading = false
				}()

				// Trigger refresh
				cmds = append(cmds, tea.Tick(300*time.Millisecond, func(t time.Time) tea.Msg {
					return walletRefreshCompleteMsg{}
				}))
			}
			return m, tea.Batch(cmds...)

		case key.Matches(msg, m.keys.Lock):
			m.project.Lock()
			m.status = "🔒 Project locked"
			// Return to project list
			return m, tea.Quit

		case key.Matches(msg, m.keys.Back):
			// Return to project list
			return m, tea.Quit

		case key.Matches(msg, m.keys.Quit):
			return m, tea.Quit
		}
	}

	return m, tea.Batch(cmds...)
}

// View renders the wallet view
func (m *ProjectWalletModel) View() string {
	if m.width == 0 || m.height == 0 {
		return "Loading..."
	}

	// Show bulk wizard if active
	if m.bulkWizard != nil {
		return m.bulkWizard.View()
	}

	// Show private key export modal
	if m.showingPrivateKey && m.selectedWallet != nil && m.exportedKey != "" {
		modalContent := lipgloss.JoinVertical(
			lipgloss.Center,
			"🔓 Private Key Export",
			"",
			lipgloss.NewStyle().
				Foreground(lipgloss.Color("#f38ba8")).
				Bold(true).
				Render("⚠️ EXTREMELY SENSITIVE DATA"),
			"",
			fmt.Sprintf("Wallet: %s", m.selectedWallet.Label),
			fmt.Sprintf("Address: %s", m.selectedWallet.Address.String()),
			"",
			lipgloss.NewStyle().
				Foreground(lipgloss.Color("#f9e2af")).
				Render("Private Key:"),
			lipgloss.NewStyle().
				Foreground(lipgloss.Color("#f38ba8")).
				Bold(true).
				Render(m.exportedKey),
			"",
			lipgloss.NewStyle().
				Foreground(lipgloss.Color("#6c7086")).
				Render("Press 'c' to copy • Any other key to clear"),
		)

		modal := lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("#f38ba8")).
			Padding(1, 2).
			Render(modalContent)

		return lipgloss.Place(m.width, m.height, lipgloss.Center, lipgloss.Center, modal)
	}

	// Show delete confirmation
	if m.confirmingDelete && m.walletToDelete != nil {
		modalContent := lipgloss.JoinVertical(
			lipgloss.Center,
			"⚠️ Confirm Wallet Deletion",
			"",
			fmt.Sprintf("Wallet: %s", m.walletToDelete.Label),
			fmt.Sprintf("Address: %s", m.walletToDelete.Address.String()),
			"",
			lipgloss.NewStyle().
				Foreground(lipgloss.Color("#f38ba8")).
				Bold(true).
				Render("This action cannot be undone!"),
			"",
			lipgloss.NewStyle().
				Foreground(lipgloss.Color("#6c7086")).
				Render("y • Confirm | n/Esc • Cancel"),
		)

		modal := lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("#f38ba8")).
			Padding(1, 2).
			Render(modalContent)

		return lipgloss.Place(m.width, m.height, lipgloss.Center, lipgloss.Center, modal)
	}

	// Show input mode for new wallet
	if m.inputMode == "new" {
		modalContent := lipgloss.JoinVertical(
			lipgloss.Center,
			"✨ Create New Wallet",
			"",
			m.textInput.View(),
			"",
			lipgloss.NewStyle().
				Foreground(lipgloss.Color("#6c7086")).
				Render("Enter • Create | Esc • Cancel"),
		)

		modal := lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("#cba6f7")).
			Padding(1, 2).
			Render(modalContent)

		return lipgloss.Place(m.width, m.height, lipgloss.Center, lipgloss.Center, modal)
	}

	// Show input mode for editing wallet label
	if m.inputMode == "edit" {
		modalContent := lipgloss.JoinVertical(
			lipgloss.Center,
			"✏️ Edit Wallet Label",
			"",
			m.textInput.View(),
			"",
			lipgloss.NewStyle().
				Foreground(lipgloss.Color("#6c7086")).
				Render("Enter • Save | Esc • Cancel"),
		)

		modal := lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("#f9e2af")).
			Padding(1, 2).
			Render(modalContent)

		return lipgloss.Place(m.width, m.height, lipgloss.Center, lipgloss.Center, modal)
	}

	// Loading state
	if m.loading {
		loadingView := lipgloss.JoinVertical(
			lipgloss.Center,
			m.spinner.View(),
			"",
			lipgloss.NewStyle().
				Foreground(lipgloss.Color("#89b4fa")).
				Bold(true).
				Render(m.status),
		)
		return lipgloss.Place(m.width, m.height, lipgloss.Center, lipgloss.Center, loadingView)
	}

	// Main view
	var sections []string

	// Header
	projectInfo := m.project.GetInfo()
	header := lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("#89b4fa")).
		Render(fmt.Sprintf("📁 %s • %d wallets • %s",
			projectInfo.Name,
			len(m.wallets),
			func() string {
				if m.project.IsLocked() {
					return "🔒 Locked"
				}
				return "🔓 Unlocked"
			}()))
	sections = append(sections, header)

	// Network distribution
	if len(m.wallets) > 0 {
		mainnetCount := 0
		testnetCount := 0
		for _, w := range m.wallets {
			if w.Network == "mainnet" {
				mainnetCount++
			} else {
				testnetCount++
			}
		}

		networkInfo := lipgloss.NewStyle().
			Foreground(lipgloss.Color("#a6e3a1")).
			Render(fmt.Sprintf("🟢 Mainnet: %d • 🟡 Testnet: %d", mainnetCount, testnetCount))
		sections = append(sections, networkInfo)
	}

	sections = append(sections, "") // Spacing

	// Calculate available height for wallet list
	headerHeight := 3 // header + network info + spacing
	footerHeight := 2 // status + help
	availableHeight := m.height - headerHeight - footerHeight

	// Wallet list
	if len(m.wallets) == 0 {
		emptyMsg := lipgloss.NewStyle().
			Foreground(lipgloss.Color("#6c7086")).
			Italic(true).
			Render("No wallets yet. Press 'n' for single wallet or 'b' for bulk creation.")
		sections = append(sections, emptyMsg)

		// Fill remaining space
		for i := 1; i < availableHeight-1; i++ {
			sections = append(sections, "")
		}
	} else {
		// Show wallets with scrolling if needed
		startIdx := 0
		endIdx := len(m.wallets)

		// Calculate visible range if list is longer than available space
		if len(m.wallets) > availableHeight {
			// Ensure selected item is visible
			if m.selectedIndex >= availableHeight/2 {
				startIdx = m.selectedIndex - availableHeight/2
				if startIdx < 0 {
					startIdx = 0
				}
			}
			endIdx = startIdx + availableHeight
			if endIdx > len(m.wallets) {
				endIdx = len(m.wallets)
				startIdx = endIdx - availableHeight
				if startIdx < 0 {
					startIdx = 0
				}
			}
		}

		walletLines := 0
		for i := startIdx; i < endIdx && walletLines < availableHeight; i++ {
			wallet := m.wallets[i]
			isSelected := i == m.selectedIndex

			networkIcon := "🟡" // testnet
			if wallet.Network == "mainnet" {
				networkIcon = "🟢"
			}

			walletLine := fmt.Sprintf("%s %s %s",
				networkIcon,
				wallet.Label,
				wallet.Address.String())

			if isSelected {
				walletLine = lipgloss.NewStyle().
					Foreground(lipgloss.Color("#1e1e2e")).
					Background(lipgloss.Color("#89b4fa")).
					Bold(true).
					Width(m.width).
					Render(walletLine)
			} else {
				walletLine = lipgloss.NewStyle().
					Foreground(lipgloss.Color("#cdd6f4")).
					Width(m.width).
					Render(walletLine)
			}

			sections = append(sections, walletLine)
			walletLines++
		}

		// Fill remaining space
		for i := walletLines; i < availableHeight; i++ {
			sections = append(sections, "")
		}

		// Show scroll indicator if needed
		if len(m.wallets) > availableHeight {
			scrollInfo := fmt.Sprintf("(%d-%d of %d)", startIdx+1, endIdx, len(m.wallets))
			sections[len(sections)-1] = lipgloss.NewStyle().
				Foreground(lipgloss.Color("#6c7086")).
				Align(lipgloss.Right).
				Width(m.width).
				Render(scrollInfo)
		}
	}

	// Status bar
	if m.status != "" {
		statusBar := lipgloss.NewStyle().
			Background(lipgloss.Color("#313244")).
			Foreground(lipgloss.Color("#cdd6f4")).
			Padding(0, 1).
			Width(m.width).
			Render(m.status)
		sections = append(sections, statusBar)
	}

	// Help
	helpKeys := []key.Binding{
		m.keys.New, m.keys.Bulk, m.keys.Export, m.keys.Copy,
		m.keys.Edit, m.keys.Toggle, m.keys.Delete, m.keys.Lock, m.keys.Back,
	}
	helpView := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#6c7086")).
		Width(m.width).
		Render(m.help.ShortHelpView(helpKeys))
	sections = append(sections, helpView)

	return lipgloss.JoinVertical(lipgloss.Left, sections...)
}

// BulkCreationWizard handles bulk wallet creation
type BulkCreationWizard struct {
	project        *ProjectImpl
	step           int
	count          int
	labelTemplate  string
	wallets        []BulkWalletConfig
	countInput     textinput.Model
	templateInput  textinput.Model
	selectedWallet int
	creating       bool
	done           bool
	cancelled      bool
	error          error
	width          int
	height         int
}

// BulkWalletConfig represents a wallet to be created
type BulkWalletConfig struct {
	Label   string
	Network string
}

// NewBulkCreationWizard creates a new bulk creation wizard
func NewBulkCreationWizard(project *ProjectImpl) *BulkCreationWizard {
	countInput := textinput.New()
	countInput.Placeholder = "Number of wallets (1-100)"
	countInput.CharLimit = 3
	countInput.Width = 30
	countInput.Focus()

	templateInput := textinput.New()
	templateInput.Placeholder = "e.g., {project}-{index}"
	templateInput.CharLimit = 50
	templateInput.Width = 50

	return &BulkCreationWizard{
		project:       project,
		count:         5,
		labelTemplate: fmt.Sprintf("%s-wallet-{index}", project.GetName()),
		countInput:    countInput,
		templateInput: templateInput,
		wallets:       []BulkWalletConfig{},
		width:         80,
		height:        24,
	}
}

// SetSize sets dimensions
func (w *BulkCreationWizard) SetSize(width, height int) {
	w.width = width
	w.height = height
}

// Update handles messages for the wizard
func (w *BulkCreationWizard) Update(msg tea.Msg) (*BulkCreationWizard, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		w.width = msg.Width
		w.height = msg.Height
		return w, nil

	case tea.KeyMsg:
		switch w.step {
		case 0: // Count input
			switch msg.String() {
			case "enter":
				countStr := w.countInput.Value()
				if countStr == "" {
					countStr = "5"
				}
				count := 0
				fmt.Sscanf(countStr, "%d", &count)
				if count < 1 || count > 100 {
					w.error = fmt.Errorf("count must be between 1 and 100")
					return w, nil
				}
				w.count = count
				w.step = 1
				w.templateInput.Focus()
				w.templateInput.SetValue(w.labelTemplate)
				return w, textinput.Blink
			case "esc":
				w.cancelled = true
				w.done = true
				return w, nil
			default:
				var cmd tea.Cmd
				w.countInput, cmd = w.countInput.Update(msg)
				return w, cmd
			}

		case 1: // Template input
			switch msg.String() {
			case "enter":
				w.labelTemplate = w.templateInput.Value()
				if w.labelTemplate == "" {
					w.labelTemplate = fmt.Sprintf("%s-wallet-{index}", w.project.GetName())
				}
				// Generate wallet configs
				w.generateWalletConfigs()
				w.step = 2
				return w, nil
			case "esc":
				w.step = 0
				w.countInput.Focus()
				return w, textinput.Blink
			default:
				var cmd tea.Cmd
				w.templateInput, cmd = w.templateInput.Update(msg)
				return w, cmd
			}

		case 2: // Network configuration
			switch msg.String() {
			case "up", "k":
				if w.selectedWallet > 0 {
					w.selectedWallet--
				}
			case "down", "j":
				if w.selectedWallet < len(w.wallets)-1 {
					w.selectedWallet++
				}
			case " ": // Space to toggle network
				if w.selectedWallet < len(w.wallets) {
					wallet := &w.wallets[w.selectedWallet]
					if wallet.Network == "mainnet" {
						wallet.Network = "testnet"
					} else {
						wallet.Network = "mainnet"
					}
				}
			case "enter":
				w.step = 3
				w.creating = true

				// Create wallets using go routine like in main.go
				go func() {
					config := BulkConfig{
						Count:          w.count,
						LabelTemplate:  w.labelTemplate,
						DefaultNetwork: "testnet",
						NetworkMapping: make(map[int]string),
					}

					// Build network mapping
					for i, wallet := range w.wallets {
						if wallet.Network != config.DefaultNetwork {
							config.NetworkMapping[i] = wallet.Network
						}
					}

					_, err := w.project.BulkCreateWallets(config)
					w.error = err
					w.done = true
				}()

				return w, nil
			case "esc":
				w.step = 1
				w.templateInput.Focus()
				return w, textinput.Blink
			}
		}
	}

	return w, nil
}

// generateWalletConfigs generates wallet configurations based on template
func (w *BulkCreationWizard) generateWalletConfigs() {
	w.wallets = make([]BulkWalletConfig, w.count)

	for i := 0; i < w.count; i++ {
		label := w.labelTemplate
		label = strings.ReplaceAll(label, "{project}", w.project.GetName())
		label = strings.ReplaceAll(label, "{index}", fmt.Sprintf("%d", i+1))
		label = strings.ReplaceAll(label, "{index0}", fmt.Sprintf("%d", i))

		// Default: 30% mainnet, 70% testnet
		network := "testnet"
		if float64(i) < float64(w.count)*0.3 {
			network = "mainnet"
		}

		w.wallets[i] = BulkWalletConfig{
			Label:   label,
			Network: network,
		}
	}
}

// View renders the wizard
func (w *BulkCreationWizard) View() string {
	var content string

	switch w.step {
	case 0: // Count input
		content = lipgloss.JoinVertical(
			lipgloss.Center,
			"🏗️ Bulk Wallet Creation",
			"",
			"How many wallets to create?",
			"",
			w.countInput.View(),
			"",
			lipgloss.NewStyle().
				Foreground(lipgloss.Color("#6c7086")).
				Render("Enter • Next | Esc • Cancel"),
		)

	case 1: // Template input
		content = lipgloss.JoinVertical(
			lipgloss.Center,
			"🏗️ Bulk Wallet Creation",
			"",
			"Label template:",
			"",
			w.templateInput.View(),
			"",
			"Available variables:",
			lipgloss.NewStyle().
				Foreground(lipgloss.Color("#a6e3a1")).
				Render("{project} {index} {index0}"),
			"",
			lipgloss.NewStyle().
				Foreground(lipgloss.Color("#6c7086")).
				Render("Enter • Next | Esc • Back"),
		)

	case 2: // Network configuration
		var walletList []string
		walletList = append(walletList, "Configure networks (Space to toggle):")
		walletList = append(walletList, "")

		// Calculate visible range for scrolling
		visibleHeight := w.height - 12 // Leave space for header and help
		if visibleHeight < 5 {
			visibleHeight = 5
		}

		startIdx := 0
		endIdx := len(w.wallets)

		if len(w.wallets) > visibleHeight {
			// Center the selected wallet
			startIdx = w.selectedWallet - visibleHeight/2
			if startIdx < 0 {
				startIdx = 0
			}
			endIdx = startIdx + visibleHeight
			if endIdx > len(w.wallets) {
				endIdx = len(w.wallets)
				startIdx = endIdx - visibleHeight
			}
		}

		for i := startIdx; i < endIdx; i++ {
			wallet := w.wallets[i]
			networkIcon := "🟡" // testnet
			if wallet.Network == "mainnet" {
				networkIcon = "🟢"
			}

			line := fmt.Sprintf("%s %s [%s]", networkIcon, wallet.Label, wallet.Network)

			if i == w.selectedWallet {
				line = lipgloss.NewStyle().
					Foreground(lipgloss.Color("#1e1e2e")).
					Background(lipgloss.Color("#89b4fa")).
					Bold(true).
					Render(line)
			}

			walletList = append(walletList, line)
		}

		if len(w.wallets) > visibleHeight {
			scrollInfo := fmt.Sprintf("(%d-%d of %d)", startIdx+1, endIdx, len(w.wallets))
			walletList = append(walletList, "")
			walletList = append(walletList, lipgloss.NewStyle().
				Foreground(lipgloss.Color("#6c7086")).
				Render(scrollInfo))
		}

		walletList = append(walletList, "")
		walletList = append(walletList, lipgloss.NewStyle().
			Foreground(lipgloss.Color("#6c7086")).
			Render("Space • Toggle | Enter • Create | Esc • Back"))

		content = lipgloss.JoinVertical(lipgloss.Left, walletList...)

	case 3: // Creating
		content = lipgloss.JoinVertical(
			lipgloss.Center,
			"🏗️ Creating Wallets",
			"",
			lipgloss.NewStyle().
				Foreground(lipgloss.Color("#89b4fa")).
				Render(fmt.Sprintf("Creating %d wallets...", w.count)),
			"",
			"Please wait...",
		)
	}

	if w.error != nil {
		content = lipgloss.JoinVertical(
			lipgloss.Center,
			"❌ Error",
			"",
			lipgloss.NewStyle().
				Foreground(lipgloss.Color("#f38ba8")).
				Render(w.error.Error()),
			"",
			"Press any key to continue",
		)
	}

	// Ensure modal fits within terminal bounds
	modalWidth := 80
	if modalWidth > w.width-4 {
		modalWidth = w.width - 4
	}

	modal := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("#cba6f7")).
		Padding(1, 2).
		MaxWidth(modalWidth).
		Render(content)

	return lipgloss.Place(w.width, w.height, lipgloss.Center, lipgloss.Center, modal)
}
