package project

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// BulkCreationEngine handles bulk wallet creation with templates
type BulkCreationEngine struct {
	project *ProjectImpl
}

// NewBulkCreationEngine creates a new bulk creation engine
func NewBulkCreationEngine(project *ProjectImpl) *BulkCreationEngine {
	return &BulkCreationEngine{
		project: project,
	}
}

// ValidateConfig validates a bulk creation configuration
func (bce *BulkCreationEngine) ValidateConfig(config BulkConfig) error {
	// Validate count
	if config.Count <= 0 {
		return NewProjectError(ErrCodeBulkCreateFailed, "wallet count must be positive", nil)
	}
	if config.Count > 1000 {
		return NewProjectError(ErrCodeBulkCreateFailed, "wallet count too large (max 1000)", nil)
	}

	// Validate template
	if err := bce.ValidateTemplate(config.LabelTemplate); err != nil {
		return err
	}

	// Validate networks
	if config.DefaultNetwork != "" && !IsValidNetwork(config.DefaultNetwork) {
		return NewProjectError(ErrCodeInvalidNetwork, "invalid default network: "+config.DefaultNetwork, nil)
	}

	for index, network := range config.NetworkMapping {
		if !IsValidNetwork(network) {
			return NewProjectError(ErrCodeInvalidNetwork, fmt.Sprintf("invalid network at index %d: %s", index, network), nil)
		}
	}

	// Validate roles (optional, no specific validation needed)
	// Validate tags (optional, no specific validation needed)

	return nil
}

// ValidateTemplate validates a label template
func (bce *BulkCreationEngine) ValidateTemplate(template string) error {
	if template == "" {
		return NewProjectError(ErrCodeTemplateInvalid, "template cannot be empty", nil)
	}

	// Check for valid template variables
	validVariables := []string{
		"{project}",
		"{index}",
		"{index1}",
		"{role}",
		"{network}",
	}

	// Find all template variables
	re := regexp.MustCompile(`\{[^}]+\}`)
	variables := re.FindAllString(template, -1)

	for _, variable := range variables {
		valid := false
		for _, validVar := range validVariables {
			if variable == validVar {
				valid = true
				break
			}
		}
		if !valid {
			return NewProjectError(ErrCodeTemplateInvalid, "invalid template variable: "+variable, nil)
		}
	}

	return nil
}

// PreviewLabels generates preview labels without creating wallets
func (bce *BulkCreationEngine) PreviewLabels(config BulkConfig) ([]string, error) {
	if err := bce.ValidateConfig(config); err != nil {
		return nil, err
	}

	labels := make([]string, config.Count)
	
	for i := 0; i < config.Count; i++ {
		label := bce.expandTemplate(config.LabelTemplate, i, config)
		labels[i] = label
	}

	return labels, nil
}

// PreviewWalletConfigs generates preview configurations without creating wallets
func (bce *BulkCreationEngine) PreviewWalletConfigs(config BulkConfig) ([]WalletPreview, error) {
	if err := bce.ValidateConfig(config); err != nil {
		return nil, err
	}

	previews := make([]WalletPreview, config.Count)
	
	for i := 0; i < config.Count; i++ {
		// Determine network
		network := config.DefaultNetwork
		if mappedNetwork, exists := config.NetworkMapping[i]; exists {
			network = mappedNetwork
		}

		// Determine role
		role := ""
		if i < len(config.Roles) {
			role = config.Roles[i]
		}

		// Generate label
		label := bce.expandTemplate(config.LabelTemplate, i, config)

		previews[i] = WalletPreview{
			Index:   i,
			Label:   label,
			Network: network,
			Role:    role,
			Tags:    config.Tags,
		}
	}

	return previews, nil
}

// expandTemplate expands a template with the given parameters
func (bce *BulkCreationEngine) expandTemplate(template string, index int, config BulkConfig) string {
	result := template

	// Replace project name
	result = strings.ReplaceAll(result, "{project}", bce.project.GetName())

	// Replace index (0-based)
	result = strings.ReplaceAll(result, "{index}", strconv.Itoa(index))

	// Replace index1 (1-based)
	result = strings.ReplaceAll(result, "{index1}", strconv.Itoa(index+1))

	// Replace role
	role := ""
	if index < len(config.Roles) {
		role = config.Roles[index]
	}
	if role == "" {
		role = "wallet"
	}
	result = strings.ReplaceAll(result, "{role}", role)

	// Replace network
	network := config.DefaultNetwork
	if mappedNetwork, exists := config.NetworkMapping[index]; exists {
		network = mappedNetwork
	}
	result = strings.ReplaceAll(result, "{network}", network)

	return result
}

// WalletPreview represents a preview of a wallet to be created
type WalletPreview struct {
	Index   int      `json:"index"`
	Label   string   `json:"label"`
	Network string   `json:"network"`
	Role    string   `json:"role,omitempty"`
	Tags    []string `json:"tags,omitempty"`
}

// GenerateNetworkMapping creates a network mapping based on distribution
func GenerateNetworkMapping(count int, mainnetRatio float64) map[int]string {
	mapping := make(map[int]string)
	
	mainnetCount := int(float64(count) * mainnetRatio)
	
	for i := 0; i < count; i++ {
		if i < mainnetCount {
			mapping[i] = "mainnet"
		} else {
			mapping[i] = "testnet"
		}
	}
	
	return mapping
}

// GenerateRoleSequence creates a role sequence for bulk creation
func GenerateRoleSequence(roles []string, count int) []string {
	if len(roles) == 0 {
		return make([]string, count)
	}

	result := make([]string, count)
	for i := 0; i < count; i++ {
		result[i] = roles[i%len(roles)]
	}
	
	return result
}

// CommonTemplates returns a set of commonly used templates
func CommonTemplates() map[string]string {
	return map[string]string{
		"Simple Index":     "{project}-{index1}",
		"Role Based":       "{project}-{role}",
		"Network Aware":    "{project}-{network}-{index1}",
		"Full Context":     "{project}-{role}-{network}-{index1}",
		"Deployer Style":   "{project}-{role}",
		"Test Suite":       "{project}-test-{index1}",
		"Team Wallets":     "{project}-team-{role}",
		"Environment":      "{project}-{network}-{role}",
	}
}

// DefaultBulkConfigs returns common bulk creation configurations
func DefaultBulkConfigs() map[string]BulkConfig {
	return map[string]BulkConfig{
		"Simple Project": {
			Count:           5,
			LabelTemplate:   "{project}-wallet-{index1}",
			DefaultNetwork:  "testnet",
			NetworkMapping:  GenerateNetworkMapping(5, 0.2), // 20% mainnet
		},
		"DeFi Development": {
			Count:          8,
			LabelTemplate:  "{project}-{role}",
			DefaultNetwork: "testnet",
			Roles:          []string{"deployer", "treasury", "rewards", "governance", "test-1", "test-2", "test-3", "faucet"},
			NetworkMapping: map[int]string{
				0: "mainnet", // deployer
				1: "mainnet", // treasury
				2: "mainnet", // rewards
				3: "mainnet", // governance
				// rest default to testnet
			},
		},
		"NFT Project": {
			Count:          6,
			LabelTemplate:  "{project}-{role}",
			DefaultNetwork: "testnet",
			Roles:          []string{"deployer", "minter", "marketplace", "royalties", "test-user", "faucet"},
			NetworkMapping: map[int]string{
				0: "mainnet", // deployer
				1: "mainnet", // minter
				2: "mainnet", // marketplace
				3: "mainnet", // royalties
				// rest default to testnet
			},
		},
		"Testing Suite": {
			Count:           10,
			LabelTemplate:   "{project}-test-{index1}",
			DefaultNetwork:  "testnet",
			NetworkMapping:  GenerateNetworkMapping(10, 0.0), // All testnet
			Tags:           []string{"testing", "automation"},
		},
		"Multi-Chain": {
			Count:          12,
			LabelTemplate:  "{project}-{network}-{index1}",
			DefaultNetwork: "testnet",
			NetworkMapping: GenerateNetworkMapping(12, 0.5), // 50/50 split
		},
	}
}

// BulkImporter handles importing wallet configurations
type BulkImporter struct {
	project *ProjectImpl
}

// NewBulkImporter creates a new bulk importer
func NewBulkImporter(project *ProjectImpl) *BulkImporter {
	return &BulkImporter{
		project: project,
	}
}

// ImportFromCSV imports wallet configurations from CSV data
func (bi *BulkImporter) ImportFromCSV(csvData string) (BulkConfig, error) {
	lines := strings.Split(strings.TrimSpace(csvData), "\n")
	if len(lines) < 2 {
		return BulkConfig{}, NewProjectError(ErrCodeTemplateInvalid, "CSV must have header and at least one data row", nil)
	}

	// Parse header
	header := strings.Split(lines[0], ",")
	labelIndex := -1
	networkIndex := -1
	roleIndex := -1

	for i, col := range header {
		col = strings.TrimSpace(strings.ToLower(col))
		switch col {
		case "label":
			labelIndex = i
		case "network":
			networkIndex = i
		case "role":
			roleIndex = i
		}
	}

	if labelIndex == -1 {
		return BulkConfig{}, NewProjectError(ErrCodeTemplateInvalid, "CSV must have 'label' column", nil)
	}

	// Parse data rows
	config := BulkConfig{
		Count:          len(lines) - 1,
		LabelTemplate:  "{project}-imported-{index1}", // fallback template
		DefaultNetwork: "testnet",
		NetworkMapping: make(map[int]string),
		Roles:          make([]string, len(lines)-1),
	}

	for i, line := range lines[1:] {
		cols := strings.Split(line, ",")
		if len(cols) != len(header) {
			return BulkConfig{}, NewProjectError(ErrCodeTemplateInvalid, fmt.Sprintf("row %d has wrong number of columns", i+2), nil)
		}

		// Extract network
		if networkIndex != -1 && networkIndex < len(cols) {
			network := strings.TrimSpace(cols[networkIndex])
			if network != "" {
				if !IsValidNetwork(network) {
					return BulkConfig{}, NewProjectError(ErrCodeInvalidNetwork, fmt.Sprintf("invalid network '%s' at row %d", network, i+2), nil)
				}
				config.NetworkMapping[i] = network
			}
		}

		// Extract role
		if roleIndex != -1 && roleIndex < len(cols) {
			role := strings.TrimSpace(cols[roleIndex])
			config.Roles[i] = role
		}
	}

	return config, nil
}

// TemplateBuilder helps build complex templates
type TemplateBuilder struct {
	parts []string
}

// NewTemplateBuilder creates a new template builder
func NewTemplateBuilder() *TemplateBuilder {
	return &TemplateBuilder{
		parts: make([]string, 0),
	}
}

// AddProject adds the project name variable
func (tb *TemplateBuilder) AddProject() *TemplateBuilder {
	tb.parts = append(tb.parts, "{project}")
	return tb
}

// AddRole adds the role variable
func (tb *TemplateBuilder) AddRole() *TemplateBuilder {
	tb.parts = append(tb.parts, "{role}")
	return tb
}

// AddNetwork adds the network variable
func (tb *TemplateBuilder) AddNetwork() *TemplateBuilder {
	tb.parts = append(tb.parts, "{network}")
	return tb
}

// AddIndex adds the index variable (0-based)
func (tb *TemplateBuilder) AddIndex() *TemplateBuilder {
	tb.parts = append(tb.parts, "{index}")
	return tb
}

// AddIndex1 adds the index1 variable (1-based)
func (tb *TemplateBuilder) AddIndex1() *TemplateBuilder {
	tb.parts = append(tb.parts, "{index1}")
	return tb
}

// AddLiteral adds a literal string
func (tb *TemplateBuilder) AddLiteral(text string) *TemplateBuilder {
	tb.parts = append(tb.parts, text)
	return tb
}

// AddSeparator adds a separator (typically "-" or "_")
func (tb *TemplateBuilder) AddSeparator(separator string) *TemplateBuilder {
	tb.parts = append(tb.parts, separator)
	return tb
}

// Build constructs the final template string
func (tb *TemplateBuilder) Build() string {
	return strings.Join(tb.parts, "")
}

// Reset clears the builder
func (tb *TemplateBuilder) Reset() *TemplateBuilder {
	tb.parts = tb.parts[:0]
	return tb
}