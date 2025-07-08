package tui

import "github.com/charmbracelet/lipgloss"

// Catppuccin Mocha Color Palette
const (
	// Primary colors
	primaryColor   = "#89b4fa" // Blue
	secondaryColor = "#a6e3a1" // Green
	accentColor    = "#fab387" // Peach
	mauveColor     = "#cba6f7" // Mauve
	
	// Semantic colors
	successColor = "#a6e3a1" // Green
	warningColor = "#f9e2af" // Yellow
	errorColor   = "#f38ba8" // Red
	infoColor    = "#94e2d5" // Teal
	
	// Text colors
	textColor     = "#cdd6f4" // Text
	subtext1Color = "#bac2de" // Subtext1
	subtext0Color = "#a6adc8" // Subtext0
	
	// Surface colors
	bgColor      = "#1e1e2e" // Base
	mantleColor  = "#181825" // Mantle
	crustColor   = "#11111b" // Crust
	cardBgColor  = "#313244" // Surface0
	surface1Color = "#45475a" // Surface1
	surface2Color = "#585b70" // Surface2
	
	// Overlay colors
	mutedColor    = "#6c7086" // Overlay0
	overlay1Color = "#7f849c" // Overlay1
	overlay2Color = "#9399b2" // Overlay2
	borderColor   = "#45475a" // Surface1
	
	// Special colors
	highlightColor = "#b4befe" // Lavender
	rosewaterColor = "#f5e0dc" // Rosewater
	pinkColor      = "#f5c2e7" // Pink
)

// Enhanced Styles
var (
	// Base styles
	BaseStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color(textColor))

	// Message styles
	SuccessStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color(successColor)).
			Bold(true)

	ErrorStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color(errorColor)).
			Bold(true)

	WarningStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color(warningColor)).
			Bold(true)

	InfoStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color(infoColor)).
			Bold(true)

	MutedStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color(subtext0Color))

	// Enhanced layout styles
	HeaderStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color(textColor)).
			Background(lipgloss.Color(mantleColor)).
			Bold(true).
			Padding(1, 2).
			MarginBottom(1).
			Align(lipgloss.Center)

	CardStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color(textColor)).
			Background(lipgloss.Color(cardBgColor)).
			Padding(0, 1).
			Border(lipgloss.NormalBorder(), false, false, false, true).
			BorderForeground(lipgloss.Color(borderColor))

	SelectedCardStyle = lipgloss.NewStyle().
				Foreground(lipgloss.Color(crustColor)).
				Background(lipgloss.Color(primaryColor)).
				Bold(true).
				Padding(0, 1).
				Border(lipgloss.NormalBorder(), false, false, false, true).
				BorderForeground(lipgloss.Color(primaryColor))

	ModalStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color(mauveColor)).
			Background(lipgloss.Color(surface2Color)).
			Padding(2, 4).
			AlignHorizontal(lipgloss.Center).
			AlignVertical(lipgloss.Center)

	StatusBarStyle = lipgloss.NewStyle().
			Background(lipgloss.Color(cardBgColor)).
			Foreground(lipgloss.Color(textColor)).
			Padding(0, 1).
			MarginTop(1)

	HelpBarStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color(subtext1Color)).
			Background(lipgloss.Color(mantleColor)).
			Padding(0, 1)

	TitleStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color(primaryColor)).
			Bold(true).
			MarginBottom(1).
			Align(lipgloss.Center)

	AddressStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color(accentColor)).
			Bold(true)

	LabelStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color(secondaryColor)).
			Italic(true)

	IconStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color(primaryColor))

	QuantumBadgeStyle = lipgloss.NewStyle().
				Foreground(lipgloss.Color(crustColor)).
				Background(lipgloss.Color(mauveColor)).
				Padding(0, 1).
				Bold(true)

	BoxStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color(borderColor)).
			Padding(1, 2)
)