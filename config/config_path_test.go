package config

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// pathStyles returns the path spellings that must behave identically when
// matching path_regex rules. On Linux only "/" is a separator, so only the
// slash form exists there; on Windows both separators are valid filesystem
// input and must produce the same match decisions.
func pathStyles() map[string]func(string) string {
	styles := map[string]func(string) string{
		"slash": filepath.ToSlash,
	}
	if runtime.GOOS == "windows" {
		styles["backslash"] = func(p string) string {
			return filepath.FromSlash(filepath.ToSlash(p))
		}
	}
	return styles
}

type creationRuleMatrixCase struct {
	name string
	// creationRules is the YAML body of the config file.
	creationRules string
	// configDir and filePath are path segments below the per-case temporary
	// root; configDir is the directory holding .sops.yaml.
	configDir []string
	filePath  []string
	// wantKey is the PGP key of the rule that must match.
	wantKey string
	// wantErr, when set, expects no rule to match and an error containing it.
	wantErr string
}

// TestCreationRuleMatchMatrix is the cross-platform regression matrix for
// creation-rule matching. It covers the two failures reported on Windows:
//
//   - a rule that must match a file inside the config directory did not match,
//     because the path was compared in its native (backslash) spelling while
//     the pattern was written with forward slashes;
//   - a file outside the config directory did match a rule, because the matched
//     string was a verbatim absolute path that happened to contain the pattern
//     as a substring.
//
// Every case is run once per path spelling: on Windows the same file is passed
// with forward and with backslashes, and both must produce the Linux result.
func TestCreationRuleMatchMatrix(t *testing.T) {
	cases := []creationRuleMatrixCase{
		{
			name: "exact relative path",
			creationRules: `
  - path_regex: secrets/prod\.yaml
    pgp: PROD
  - path_regex: ""
    pgp: DEFAULT
`,
			configDir: []string{"repo"},
			filePath:  []string{"repo", "secrets", "prod.yaml"},
			wantKey:   "PROD",
		},
		{
			name: "same file name in another directory uses the default rule",
			creationRules: `
  - path_regex: ^secrets/prod\.yaml$
    pgp: PROD
  - path_regex: ""
    pgp: DEFAULT
`,
			configDir: []string{"repo"},
			filePath:  []string{"repo", "staging", "secrets", "prod.yaml"},
			wantKey:   "DEFAULT",
		},
		{
			name: "anchored directory prefix",
			creationRules: `
  - path_regex: ^secrets/
    pgp: SECRETS
  - path_regex: ""
    pgp: DEFAULT
`,
			configDir: []string{"repo"},
			filePath:  []string{"repo", "secrets", "nested", "api.yaml"},
			wantKey:   "SECRETS",
		},
		{
			name: "a directory that merely starts with the prefix does not match",
			creationRules: `
  - path_regex: ^secrets/
    pgp: SECRETS
  - path_regex: ""
    pgp: DEFAULT
`,
			configDir: []string{"repo"},
			filePath:  []string{"repo", "secrets-old", "api.yaml"},
			wantKey:   "DEFAULT",
		},
		{
			name: "file outside the config directory is not matched by path_regex",
			creationRules: `
  - path_regex: secrets/.*\.yaml
    pgp: SECRETS
  - path_regex: ""
    pgp: DEFAULT
`,
			configDir: []string{"repo"},
			filePath:  []string{"elsewhere", "secrets", "api.yaml"},
			wantKey:   "DEFAULT",
		},
		{
			name: "file outside the config directory fails when only path_regex rules exist",
			creationRules: `
  - path_regex: secrets/.*\.yaml
    pgp: SECRETS
`,
			configDir: []string{"repo"},
			filePath:  []string{"elsewhere", "secrets", "api.yaml"},
			wantErr:   "no matching creation rules found",
		},
		{
			name: "config directory name does not leak into the matched path",
			creationRules: `
  - path_regex: ^secrets/
    pgp: SECRETS
  - path_regex: ""
    pgp: DEFAULT
`,
			configDir: []string{"secrets"},
			filePath:  []string{"secrets", "api.yaml"},
			wantKey:   "DEFAULT",
		},
		{
			name: "dot segments are resolved before matching",
			creationRules: `
  - path_regex: ^secrets/
    pgp: SECRETS
  - path_regex: ""
    pgp: DEFAULT
`,
			configDir: []string{"repo"},
			filePath:  []string{"repo", ".", "secrets", "api.yaml"},
			wantKey:   "SECRETS",
		},
		{
			name: "escaping the config directory is treated as outside",
			creationRules: `
  - path_regex: secrets/.*\.yaml
    pgp: SECRETS
  - path_regex: ""
    pgp: DEFAULT
`,
			configDir: []string{"repo"},
			filePath:  []string{"repo", "..", "secrets", "api.yaml"},
			wantKey:   "DEFAULT",
		},
		{
			name: "nested regex requires the full relative path",
			creationRules: `
  - path_regex: ^env/prod/.+\.ya?ml$
    pgp: ENVPROD
  - path_regex: ""
    pgp: DEFAULT
`,
			configDir: []string{"repo"},
			filePath:  []string{"repo", "env", "prod", "svc.yml"},
			wantKey:   "ENVPROD",
		},
		{
			name: "nested regex does not match a sibling environment",
			creationRules: `
  - path_regex: ^env/prod/.+\.ya?ml$
    pgp: ENVPROD
  - path_regex: ""
    pgp: DEFAULT
`,
			configDir: []string{"repo"},
			filePath:  []string{"repo", "env", "prodx", "svc.yml"},
			wantKey:   "DEFAULT",
		},
		{
			name: "extension anchored regex",
			creationRules: `
  - path_regex: \.json$
    pgp: JSON
  - path_regex: ""
    pgp: DEFAULT
`,
			configDir: []string{"repo"},
			filePath:  []string{"repo", "config", "secrets.json.bak"},
			wantKey:   "DEFAULT",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			conf := parseConfigFile([]byte("creation_rules:\n"+tc.creationRules), t)

			for styleName, style := range pathStyles() {
				t.Run(styleName, func(t *testing.T) {
					root := t.TempDir()
					configDir := filepath.Join(append([]string{root}, tc.configDir...)...)
					configPath := filepath.Join(configDir, ".sops.yaml")
					filePath := filepath.Join(append([]string{root}, tc.filePath...)...)

					got, err := parseCreationRuleForFile(conf, style(configPath), style(filePath), nil)

					if tc.wantErr != "" {
						require.Error(t, err)
						assert.Contains(t, err.Error(), tc.wantErr)
						assert.Nil(t, got)
						return
					}
					require.NoError(t, err)
					require.NotNil(t, got)
					require.NotEmpty(t, got.KeyGroups)
					require.NotEmpty(t, got.KeyGroups[0])
					assert.Equal(t, tc.wantKey, got.KeyGroups[0][0].ToString())
				})
			}
		})
	}
}

func TestCreationRuleMatchWithRelativeFilePath(t *testing.T) {
	conf := parseConfigFile([]byte(`creation_rules:
  - path_regex: ^secrets/
    pgp: SECRETS
  - path_regex: ""
    pgp: DEFAULT
`), t)

	for styleName, style := range pathStyles() {
		t.Run(styleName, func(t *testing.T) {
			configPath := filepath.Join(t.TempDir(), ".sops.yaml")

			got, err := parseCreationRuleForFile(conf, style(configPath), style("secrets/prod.yaml"), nil)
			require.NoError(t, err)
			assert.Equal(t, "SECRETS", got.KeyGroups[0][0].ToString())

			// A relative path that escapes upwards cannot belong to the config
			// directory, so only the catch-all rule applies.
			got, err = parseCreationRuleForFile(conf, style(configPath), style("../secrets/prod.yaml"), nil)
			require.NoError(t, err)
			assert.Equal(t, "DEFAULT", got.KeyGroups[0][0].ToString())
		})
	}
}

func TestDestinationRuleMatchMatrix(t *testing.T) {
	conf := parseConfigFile([]byte(`
destination_rules:
  - path_regex: ^test/
    s3_bucket: my-bucket
    s3_prefix: sops/
    recreation_rule:
      pgp: S3
  - path_regex: ^vault/
    vault_path: secret/sops
    vault_address: https://vault.example.com
    recreation_rule:
      pgp: VAULT
`), t)

	for styleName, style := range pathStyles() {
		t.Run(styleName, func(t *testing.T) {
			got, err := parseDestinationRuleForFile(conf, style("test/secrets.yaml"), nil)
			require.NoError(t, err)
			assert.Equal(t, "S3", got.KeyGroups[0][0].ToString())

			got, err = parseDestinationRuleForFile(conf, style("vault/secrets.yaml"), nil)
			require.NoError(t, err)
			assert.Equal(t, "VAULT", got.KeyGroups[0][0].ToString())

			// The same directory name deeper in the tree must not match an
			// anchored destination rule.
			_, err = parseDestinationRuleForFile(conf, style("nested/test/secrets.yaml"), nil)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "no matching destination found")
		})
	}
}

func TestRulePathForConfig(t *testing.T) {
	root := t.TempDir()
	configDir := filepath.Join(root, "repo")

	normalized, inside := rulePathForConfig(configDir, filepath.Join(configDir, "secrets", "prod.yaml"))
	assert.True(t, inside)
	assert.Equal(t, "secrets/prod.yaml", normalized)

	normalized, inside = rulePathForConfig(configDir, filepath.Join(root, "other", "prod.yaml"))
	assert.False(t, inside)
	assert.Equal(t, "../other/prod.yaml", normalized)

	normalized, inside = rulePathForConfig(configDir, "secrets/prod.yaml")
	assert.True(t, inside)
	assert.Equal(t, "secrets/prod.yaml", normalized)

	for _, escaped := range []string{"..", "../prod.yaml", "a/../../prod.yaml"} {
		_, inside = rulePathForConfig(configDir, escaped)
		assert.False(t, inside, "relative path %q must be reported as outside", escaped)
	}
}

func TestRulePathForConfigDriveLetterCase(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("drive letter case only exists on Windows")
	}
	configDir := filepath.Join(t.TempDir(), "repo")
	filePath := filepath.Join(configDir, "secrets", "prod.yaml")

	swapped := flipDriveLetter(filePath)
	require.NotEqual(t, filePath, swapped)

	normalized, inside := rulePathForConfig(configDir, swapped)
	assert.True(t, inside)
	assert.Equal(t, "secrets/prod.yaml", normalized)
}

func TestRulePathForConfigDifferentVolume(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("volumes only exist on Windows")
	}
	configDir := filepath.Join(t.TempDir(), "repo")
	otherVolume := "Z:"
	if strings.EqualFold(filepath.VolumeName(configDir), otherVolume) {
		otherVolume = "Y:"
	}
	_, inside := rulePathForConfig(configDir, otherVolume+`\repo\secrets\prod.yaml`)
	assert.False(t, inside)
}

func TestRulePathForConfigUNC(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("UNC paths are Windows-specific")
	}
	configDir := `\\server\share\repo`
	inside := `\\server\share\repo\secrets\a.yaml`
	outside := `\\server\share\other\a.yaml`

	normalized, ok := rulePathForConfig(configDir, inside)
	assert.True(t, ok)
	assert.Equal(t, "secrets/a.yaml", normalized)

	normalized, ok = rulePathForConfig(configDir, outside)
	assert.False(t, ok)
	assert.Equal(t, "../other/a.yaml", normalized)

	// The slash spelling of the same UNC path must behave identically.
	normalized, ok = rulePathForConfig(filepath.ToSlash(configDir), filepath.ToSlash(inside))
	assert.True(t, ok)
	assert.Equal(t, "secrets/a.yaml", normalized)
}

func flipDriveLetter(p string) string {
	volume := filepath.VolumeName(p)
	if volume == "" {
		return p
	}
	flipped := volume
	if c := volume[0]; c >= 'a' && c <= 'z' {
		flipped = string(c-'a'+'A') + volume[1:]
	} else if c >= 'A' && c <= 'Z' {
		flipped = string(c-'A'+'a') + volume[1:]
	}
	return flipped + p[len(volume):]
}

func TestNormalizeRulePath(t *testing.T) {
	assert.Equal(t, "", normalizeRulePath(""))
	assert.Equal(t, "a/b.yaml", normalizeRulePath("a/b.yaml"))
	assert.Equal(t, "a/b.yaml", normalizeRulePath("a/./b.yaml"))
	assert.Equal(t, "b.yaml", normalizeRulePath("a/../b.yaml"))
	if runtime.GOOS == "windows" {
		assert.Equal(t, "a/b.yaml", normalizeRulePath(`a\b.yaml`))
		assert.Equal(t, "C:/a/b.yaml", normalizeRulePath(`C:\a\b.yaml`))
	} else {
		// A backslash is a valid file name character on Linux, not a separator.
		assert.Equal(t, `a\b.yaml`, normalizeRulePath(`a\b.yaml`))
	}
}

func TestIsRootedPath(t *testing.T) {
	assert.False(t, isRootedPath(""))
	assert.False(t, isRootedPath("a/b"))
	assert.False(t, isRootedPath(".."))
	if runtime.GOOS == "windows" {
		assert.True(t, isRootedPath("/a/b"))
		assert.True(t, isRootedPath(`C:/a/b`))
		// A leading backslash is root-relative on Windows.
		assert.True(t, isRootedPath(`\a\b`))
	} else {
		assert.True(t, isRootedPath("/a/b"))
		// A leading backslash is just a file name character on Linux.
		assert.False(t, isRootedPath(`\a\b`))
	}
}

func TestLookupConfigFileWithNativeStartPath(t *testing.T) {
	root := t.TempDir()
	start := filepath.Join(root, "a", "b", "file.yaml")
	expected := filepath.ToSlash(filepath.Join(root, "a", ".sops.yaml"))

	for styleName, style := range pathStyles() {
		t.Run(styleName, func(t *testing.T) {
			restoreFS := fs
			defer func() { fs = restoreFS }()
			fs = mockFS{stat: func(name string) (os.FileInfo, error) {
				if name == expected {
					return nil, nil
				}
				return nil, &os.PathError{}
			}}

			// The returned path is normalized to forward slashes on every
			// platform, so callers can print it and feed it back in safely.
			got, err := FindConfigFile(style(start))
			require.NoError(t, err)
			assert.Equal(t, expected, got)
		})
	}
}

func TestLookupConfigFileAlternateNameWithNativeStartPath(t *testing.T) {
	root := t.TempDir()
	start := filepath.Join(root, "a", "b", "file.yaml")
	alternate := filepath.ToSlash(filepath.Join(root, "a", ".sops.yml"))
	expected := filepath.ToSlash(filepath.Join(root, ".sops.yaml"))

	restoreFS := fs
	defer func() { fs = restoreFS }()
	fs = mockFS{stat: func(name string) (os.FileInfo, error) {
		if name == alternate || name == expected {
			return nil, nil
		}
		return nil, &os.PathError{}
	}}

	result, err := LookupConfigFile(filepath.ToSlash(start))
	require.NoError(t, err)
	assert.Equal(t, expected, result.Path)
	assert.Contains(t, result.Warning, alternate)
}

// TestLoadCreationRuleForFileWithNativePaths exercises the full path from the
// caller's path argument through loading the config file, the way the CLI uses
// it: a file inside the config directory must match its rule, and a file outside
// must not be matched by a pattern meant to be relative to the config file.
func TestLoadCreationRuleForFileWithNativePaths(t *testing.T) {
	root := t.TempDir()
	configDir := filepath.Join(root, "repo")
	require.NoError(t, os.MkdirAll(configDir, 0o755))
	configPath := filepath.Join(configDir, ".sops.yaml")
	require.NoError(t, os.WriteFile(configPath, []byte(`
creation_rules:
  - path_regex: ^secrets/
    pgp: SECRETS
  - path_regex: ""
    pgp: DEFAULT
`), 0o600))

	inside := filepath.Join(configDir, "secrets", "prod.yaml")
	outside := filepath.Join(root, "secrets", "prod.yaml")

	for styleName, style := range pathStyles() {
		t.Run(styleName, func(t *testing.T) {
			got, err := LoadCreationRuleForFile(style(configPath), style(inside), nil)
			require.NoError(t, err)
			require.NotNil(t, got)
			assert.Equal(t, "SECRETS", got.KeyGroups[0][0].ToString())

			got, err = LoadCreationRuleForFile(style(configPath), style(outside), nil)
			require.NoError(t, err)
			require.NotNil(t, got)
			assert.Equal(t, "DEFAULT", got.KeyGroups[0][0].ToString())
		})
	}
}
