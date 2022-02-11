package pythonconfig

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/emirpasic/gods/lists/singlylinkedlist"

	"github.com/bazelbuild/rules_python/gazelle/manifest"
)

// Directives
const (
	// PythonExtensionDirective represents the directive that controls whether
	// this Python extension is enabled or not. Sub-packages inherit this value.
	// Can be either "enabled" or "disabled". Defaults to "enabled".
	PythonExtensionDirective = "python_extension"
	// PythonRootDirective represents the directive that sets a Bazel package as
	// a Python root. This is used on monorepos with multiple Python projects
	// that don't share the top-level of the workspace as the root.
	PythonRootDirective = "python_root"
	// PythonManifestFileNameDirective represents the directive that overrides
	// the default gazelle_python.yaml manifest file name.
	PythonManifestFileNameDirective = "python_manifest_file_name"
	// IgnoreFilesDirective represents the directive that controls the ignored
	// files from the generated targets.
	IgnoreFilesDirective = "python_ignore_files"
	// IgnoreDependenciesDirective represents the directive that controls the
	// ignored dependencies from the generated targets.
	IgnoreDependenciesDirective = "python_ignore_dependencies"
	// ValidateImportStatementsDirective represents the directive that controls
	// whether the Python import statements should be validated.
	ValidateImportStatementsDirective = "python_validate_import_statements"
	// GenerationMode represents the directive that controls the target generation
	// mode. See below for the GenerationModeType constants.
	GenerationMode = "python_generation_mode"
	// LibraryNamingConvention represents the directive that controls the
	// py_library naming convention. It interpolates $package_name$ with the
	// Bazel package name. E.g. if the Bazel package name is `foo`, setting this
	// to `$package_name$_my_lib` would render to `foo_my_lib`.
	LibraryNamingConvention = "python_library_naming_convention"
	// BinaryNamingConvention represents the directive that controls the
	// py_binary naming convention. See python_library_naming_convention for
	// more info on the package name interpolation.
	BinaryNamingConvention = "python_binary_naming_convention"
	// TestNamingConvention represents the directive that controls the py_test
	// naming convention. See python_library_naming_convention for more info on
	// the package name interpolation.
	TestNamingConvention = "python_test_naming_convention"
)

// GenerationModeType represents one of the generation modes for the Python
// extension.
type GenerationModeType string

// Generation modes
const (
	// GenerationModePackage defines the mode in which targets will be generated
	// for each __init__.py, or when an existing BUILD or BUILD.bazel file already
	// determines a Bazel package.
	GenerationModePackage GenerationModeType = "package"
	// GenerationModeProject defines the mode in which a coarse-grained target will
	// be generated englobing sub-directories containing Python files.
	GenerationModeProject GenerationModeType = "project"
)

const (
	packageNameNamingConventionSubstitution = "$package_name$"
)

// defaultIgnoreFiles is the list of default values used in the
// python_ignore_files option.
var defaultIgnoreFiles = map[string]struct{}{
	"setup.py": {},
}

// Configs is an extension of map[string]*Config. It provides finding methods
// on top of the mapping.
type Configs map[string]*Config

// ParentForPackage returns the parent Config for the given Bazel package.
func (c *Configs) ParentForPackage(pkg string) *Config {
	dir := filepath.Dir(pkg)
	if dir == "." {
		dir = ""
	}
	parent := (map[string]*Config)(*c)[dir]
	return parent
}

// Config represents a config extension for a specific Bazel package.
type Config struct {
	parent *Config

	extensionEnabled  bool
	repoRoot          string
	pythonProjectRoot string
	gazelleManifest   *manifest.Manifest

	excludedPatterns         *singlylinkedlist.List
	ignoreFiles              map[string]struct{}
	ignoreDependencies       map[string]struct{}
	validateImportStatements bool
	coarseGrainedGeneration  bool
	libraryNamingConvention  string
	binaryNamingConvention   string
	testNamingConvention     string
}

// New creates a new Config.
func New(
	repoRoot string,
	pythonProjectRoot string,
) *Config {
	return &Config{
		extensionEnabled:         true,
		repoRoot:                 repoRoot,
		pythonProjectRoot:        pythonProjectRoot,
		excludedPatterns:         singlylinkedlist.New(),
		ignoreFiles:              make(map[string]struct{}),
		ignoreDependencies:       make(map[string]struct{}),
		validateImportStatements: true,
		coarseGrainedGeneration:  false,
		libraryNamingConvention:  packageNameNamingConventionSubstitution,
		binaryNamingConvention:   fmt.Sprintf("%s_bin", packageNameNamingConventionSubstitution),
		testNamingConvention:     fmt.Sprintf("%s_test", packageNameNamingConventionSubstitution),
	}
}

// Parent returns the parent config.
func (c *Config) Parent() *Config {
	return c.parent
}

// NewChild creates a new child Config. It inherits desired values from the
// current Config and sets itself as the parent to the child.
func (c *Config) NewChild() *Config {
	return &Config{
		parent:                   c,
		extensionEnabled:         c.extensionEnabled,
		repoRoot:                 c.repoRoot,
		pythonProjectRoot:        c.pythonProjectRoot,
		gazelleManifest:          c.gazelleManifest,
		excludedPatterns:         c.excludedPatterns,
		ignoreFiles:              make(map[string]struct{}),
		ignoreDependencies:       make(map[string]struct{}),
		validateImportStatements: c.validateImportStatements,
		coarseGrainedGeneration:  c.coarseGrainedGeneration,
		libraryNamingConvention:  c.libraryNamingConvention,
		binaryNamingConvention:   c.binaryNamingConvention,
		testNamingConvention:     c.testNamingConvention,
	}
}

// AddExcludedPattern adds a glob pattern parsed from the standard
// gazelle:exclude directive.
func (c *Config) AddExcludedPattern(pattern string) {
	c.excludedPatterns.Add(pattern)
}

// ExcludedPatterns returns the excluded patterns list.
func (c *Config) ExcludedPatterns() *singlylinkedlist.List {
	return c.excludedPatterns
}

// SetExtensionEnabled sets whether the extension is enabled or not.
func (c *Config) SetExtensionEnabled(enabled bool) {
	c.extensionEnabled = enabled
}

// ExtensionEnabled returns whether the extension is enabled or not.
func (c *Config) ExtensionEnabled() bool {
	return c.extensionEnabled
}

// SetPythonProjectRoot sets the Python project root.
func (c *Config) SetPythonProjectRoot(pythonProjectRoot string) {
	c.pythonProjectRoot = pythonProjectRoot
}

// PythonProjectRoot returns the Python project root.
func (c *Config) PythonProjectRoot() string {
	return c.pythonProjectRoot
}

// SetGazelleManifest sets the Gazelle manifest parsed from the
// gazelle_python.yaml file.
func (c *Config) SetGazelleManifest(gazelleManifest *manifest.Manifest) {
	c.gazelleManifest = gazelleManifest
}

// PipRepository returns the pip repository name from the manifest.
func (c *Config) PipRepository() string {
	if c.gazelleManifest != nil {
		return c.gazelleManifest.PipDepsRepositoryName
	}
	return ""
}

// ModulesMapping returns the modules mapping from the manifest.
func (c *Config) ModulesMapping() map[string]string {
	if c.gazelleManifest != nil {
		return c.gazelleManifest.ModulesMapping
	}
	return map[string]string{}
}

// AddIgnoreFile adds a file to the list of ignored files for a given package.
// Adding an ignored file to a package also makes it ignored on a subpackage.
func (c *Config) AddIgnoreFile(file string) {
	c.ignoreFiles[strings.TrimSpace(file)] = struct{}{}
}

// IgnoresFile checks if a file is ignored in the given package or in one of the
// parent packages up to the workspace root.
func (c *Config) IgnoresFile(file string) bool {
	trimmedFile := strings.TrimSpace(file)

	if _, ignores := defaultIgnoreFiles[trimmedFile]; ignores {
		return true
	}

	if _, ignores := c.ignoreFiles[trimmedFile]; ignores {
		return true
	}

	parent := c.parent
	for parent != nil {
		if _, ignores := parent.ignoreFiles[trimmedFile]; ignores {
			return true
		}
		parent = parent.parent
	}

	return false
}

// AddIgnoreDependency adds a dependency to the list of ignored dependencies for
// a given package. Adding an ignored dependency to a package also makes it
// ignored on a subpackage.
func (c *Config) AddIgnoreDependency(dep string) {
	c.ignoreDependencies[strings.TrimSpace(dep)] = struct{}{}
}

// IgnoresDependency checks if a dependency is ignored in the given package or
// in one of the parent packages up to the workspace root.
func (c *Config) IgnoresDependency(dep string) bool {
	trimmedDep := strings.TrimSpace(dep)

	if _, ignores := c.ignoreDependencies[trimmedDep]; ignores {
		return true
	}

	parent := c.parent
	for parent != nil {
		if _, ignores := parent.ignoreDependencies[trimmedDep]; ignores {
			return true
		}
		parent = parent.parent
	}

	return false
}

// SetValidateImportStatements sets whether Python import statements should be
// validated or not. It throws an error if this is set multiple times, i.e. if
// the directive is specified multiple times in the Bazel workspace.
func (c *Config) SetValidateImportStatements(validate bool) {
	c.validateImportStatements = validate
}

// ValidateImportStatements returns whether the Python import statements should
// be validated or not. If this option was not explicitly specified by the user,
// it defaults to true.
func (c *Config) ValidateImportStatements() bool {
	return c.validateImportStatements
}

// SetCoarseGrainedGeneration sets whether coarse-grained targets should be
// generated or not.
func (c *Config) SetCoarseGrainedGeneration(coarseGrained bool) {
	c.coarseGrainedGeneration = coarseGrained
}

// CoarseGrainedGeneration returns whether coarse-grained targets should be
// generated or not.
func (c *Config) CoarseGrainedGeneration() bool {
	return c.coarseGrainedGeneration
}

// SetLibraryNamingConvention sets the py_library target naming convention.
func (c *Config) SetLibraryNamingConvention(libraryNamingConvention string) {
	c.libraryNamingConvention = libraryNamingConvention
}

// RenderLibraryName returns the py_library target name by performing all
// substitutions.
func (c *Config) RenderLibraryName(packageName string) string {
	return strings.ReplaceAll(c.libraryNamingConvention, packageNameNamingConventionSubstitution, packageName)
}

// SetBinaryNamingConvention sets the py_binary target naming convention.
func (c *Config) SetBinaryNamingConvention(binaryNamingConvention string) {
	c.binaryNamingConvention = binaryNamingConvention
}

// RenderBinaryName returns the py_binary target name by performing all
// substitutions.
func (c *Config) RenderBinaryName(packageName string) string {
	return strings.ReplaceAll(c.binaryNamingConvention, packageNameNamingConventionSubstitution, packageName)
}

// SetTestNamingConvention sets the py_test target naming convention.
func (c *Config) SetTestNamingConvention(testNamingConvention string) {
	c.testNamingConvention = testNamingConvention
}

// RenderTestName returns the py_test target name by performing all
// substitutions.
func (c *Config) RenderTestName(packageName string) string {
	return strings.ReplaceAll(c.testNamingConvention, packageNameNamingConventionSubstitution, packageName)
}