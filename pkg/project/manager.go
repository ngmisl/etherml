package project

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Manager implements ProjectManager interface
type Manager struct {
	projectsDir string
}

// NewManager creates a new project manager
func NewManager(projectsDir string) *Manager {
	return &Manager{
		projectsDir: projectsDir,
	}
}

// GetProjectsDir returns the projects directory path
func (m *Manager) GetProjectsDir() string {
	return m.projectsDir
}

// ListProjects returns all available projects
func (m *Manager) ListProjects() ([]ProjectInfo, error) {
	// Ensure projects directory exists
	if err := os.MkdirAll(m.projectsDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create projects directory: %w", err)
	}
	
	entries, err := os.ReadDir(m.projectsDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read projects directory: %w", err)
	}
	
	var projects []ProjectInfo
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		
		projectPath := filepath.Join(m.projectsDir, entry.Name())
		projectFile := filepath.Join(projectPath, "project.enc")
		
		// Check if project.enc exists
		if _, err := os.Stat(projectFile); os.IsNotExist(err) {
			continue
		}
		
		// Read project info from the file (we'll implement this)
		info, err := m.readProjectInfo(projectFile)
		if err != nil {
			// Skip projects that can't be read
			continue
		}
		
		projects = append(projects, info)
	}
	
	return projects, nil
}

// readProjectInfo reads basic project info without full decryption
func (m *Manager) readProjectInfo(projectFile string) (ProjectInfo, error) {
	data, err := os.ReadFile(projectFile)
	if err != nil {
		return ProjectInfo{}, fmt.Errorf("failed to read project file: %w", err)
	}
	
	var storage ProjectStorage
	if err := json.Unmarshal(data, &storage); err != nil {
		return ProjectInfo{}, fmt.Errorf("failed to unmarshal project: %w", err)
	}
	
	return storage.ProjectInfo, nil
}

// CreateProject creates a new project with the given name and password
func (m *Manager) CreateProject(name string, password []byte) (Project, error) {
	// Validate name
	if strings.TrimSpace(name) == "" {
		return nil, fmt.Errorf("project name cannot be empty")
	}
	
	// Sanitize name for filesystem
	safeName := sanitizeProjectName(name)
	projectPath := filepath.Join(m.projectsDir, safeName)
	
	// Check if project already exists
	if _, err := os.Stat(projectPath); !os.IsNotExist(err) {
		return nil, fmt.Errorf("project '%s' already exists", name)
	}
	
	// Create project directory
	if err := os.MkdirAll(projectPath, 0700); err != nil {
		return nil, fmt.Errorf("failed to create project directory: %w", err)
	}
	
	// Create new project instance
	proj := &ProjectImpl{
		info: ProjectInfo{
			Name:        name,
			Description: fmt.Sprintf("Project: %s", name),
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
		},
		projectPath: projectPath,
		isLocked:    false,
	}
	
	// Initialize the project with encryption
	if err := proj.Initialize(password); err != nil {
		// Clean up on failure
		os.RemoveAll(projectPath)
		return nil, fmt.Errorf("failed to initialize project: %w", err)
	}
	
	return proj, nil
}

// OpenProject opens an existing project with the given password
func (m *Manager) OpenProject(name string, password []byte) (Project, error) {
	safeName := sanitizeProjectName(name)
	projectPath := filepath.Join(m.projectsDir, safeName)
	projectFile := filepath.Join(projectPath, "project.enc")
	
	// Check if project exists
	if _, err := os.Stat(projectFile); os.IsNotExist(err) {
		return nil, fmt.Errorf("project '%s' not found", name)
	}
	
	// Create project instance and load
	proj := &ProjectImpl{
		projectPath: projectPath,
		isLocked:    true,
	}
	
	if err := proj.Load(password); err != nil {
		return nil, fmt.Errorf("failed to open project: %w", err)
	}
	
	return proj, nil
}

// DeleteProject removes a project and all its data
func (m *Manager) DeleteProject(name string) error {
	safeName := sanitizeProjectName(name)
	projectPath := filepath.Join(m.projectsDir, safeName)
	
	// Check if project exists
	if _, err := os.Stat(projectPath); os.IsNotExist(err) {
		return fmt.Errorf("project '%s' not found", name)
	}
	
	// Remove entire project directory
	if err := os.RemoveAll(projectPath); err != nil {
		return fmt.Errorf("failed to delete project: %w", err)
	}
	
	return nil
}

// sanitizeProjectName creates a filesystem-safe project name
func sanitizeProjectName(name string) string {
	// Replace problematic characters with underscores
	safe := strings.ReplaceAll(name, " ", "_")
	safe = strings.ReplaceAll(safe, "/", "_")
	safe = strings.ReplaceAll(safe, "\\", "_")
	safe = strings.ReplaceAll(safe, ":", "_")
	safe = strings.ReplaceAll(safe, "*", "_")
	safe = strings.ReplaceAll(safe, "?", "_")
	safe = strings.ReplaceAll(safe, "\"", "_")
	safe = strings.ReplaceAll(safe, "<", "_")
	safe = strings.ReplaceAll(safe, ">", "_")
	safe = strings.ReplaceAll(safe, "|", "_")
	
	// Ensure it's not empty and not too long
	if safe == "" {
		safe = "unnamed_project"
	}
	if len(safe) > 50 {
		safe = safe[:50]
	}
	
	return safe
}