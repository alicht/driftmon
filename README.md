# Driftmon

AI model output drift detection and monitoring tool for production deployments.

## Overview

Driftmon monitors files in your AI projects and detects configuration drift, prompt changes, and model updates. It provides alerting capabilities through Slack, file logging, and console output.

## Features

- 📸 **Snapshot Management**: Take snapshots of watched files with hash-based change detection
- 🔍 **Drift Detection**: Compare snapshots to identify added, removed, and changed files
- ⚡ **Severity Classification**: Automatically classify changes as HIGH, MEDIUM, or LOW severity
- 🚨 **Multi-Channel Alerts**: Send notifications via Slack, file logs, or console
- 📁 **Artifact Storage**: Save detailed diff reports for audit trails
- 🎯 **Pattern Matching**: Configure watch patterns and ignore rules

## Quick Start

### Installation

```bash
git clone https://github.com/alicht/driftmon.git
cd driftmon
```

### Initialize

```bash
python driftmon.py init
```

This creates the baseline snapshot and initializes the `.drift/` directory.

### Basic Usage

```bash
# Take a new snapshot
python driftmon.py snapshot

# Compare last two snapshots
python driftmon.py diff

# Send alerts if drift detected
python driftmon.py alert

# Full workflow: snapshot + diff + alert
python driftmon.py run
```

## Configuration

Edit `driftmon.yml` to configure:

### Watch Patterns
```yaml
watch:
  - "src/**/*.py"      # Python source files
  - "prompts/**/*.txt" # Prompt templates
  - "config/**/*.yaml" # Configuration files
  - "models/**/*"      # Model definitions
```

### Ignore Patterns
```yaml
ignore:
  - "**/__pycache__/**"
  - "**/.git/**"
  - "*.md"             # Documentation
  - "tests/**"         # Test files
```

### Severity Rules
```yaml
severity_rules:
  - pattern: "**/config/**"
    severity: HIGH
  - pattern: "**/prompts/**"
    severity: MEDIUM
  - pattern: "**/src/**"
    severity: LOW
```

### Alerts
```yaml
alerts:
  enabled: true
  channels:
    - type: console
      level: warning
    - type: file
      path: ".drift/alerts.log"
      level: info
    - type: slack
      webhook: "YOUR_SLACK_WEBHOOK_URL"
      level: critical
```

## CLI Commands

| Command | Description | Exit Code |
|---------|-------------|-----------|
| `init` | Initialize driftmon and take baseline snapshot | 0 |
| `snapshot` | Take a new snapshot of watched files | 0 |
| `diff` | Compare last two snapshots | 0=no drift, 2=drift detected |
| `alert` | Check for drift and send configured alerts | 0=no drift, 2=drift detected |
| `run` | Full workflow: snapshot + diff + alert | 0=no drift, 2=drift detected |
| `hash <file>` | Calculate hash of specific file | 0 |
| `status` | Show current configuration and status | 0 |

## File Structure

```
your-project/
├── driftmon.yml          # Main configuration
├── .driftignore         # Additional ignore patterns
├── .drift/              # Driftmon internal data
│   ├── snapshots.sqlite # Snapshot database
│   ├── artifacts/       # Diff reports and logs
│   └── alerts.log       # Alert history
├── config/              # Your config files (watched)
├── prompts/             # Your prompts (watched)
├── src/                 # Your source code (watched)
└── README.md            # Ignored by default
```

## Testing

### Running Tests

Install pytest and run the test suite:

```bash
pip install pytest
pytest tests/ -v
```

### Test Scenarios

The test suite covers the following scenarios:

#### 1. No Drift Baseline
- **Test**: `test_no_drift_baseline`
- **Scenario**: Take two snapshots without any file changes
- **Expected**: No drift detected, exit code 0
- **Verifies**: Basic snapshot functionality works correctly

#### 2. Low-Severity Drift (Prompt Edited)
- **Test**: `test_low_severity_drift_prompt_edited`
- **Scenario**: Modify a prompt file in `prompts/`
- **Expected**: 1 change detected with MEDIUM severity (based on config)
- **Verifies**: 
  - Change detection works
  - Severity rules applied correctly
  - Artifacts created in `.drift/artifacts/`

#### 3. High-Severity Drift (Models Config Changed)
- **Test**: `test_high_severity_drift_models_changed`
- **Scenario**: Modify `config/models.yaml`
- **Expected**: 1 change detected with HIGH severity
- **Verifies**:
  - Critical config changes flagged as high severity
  - Proper artifact generation with severity labels

#### 4. Ignored File Changes
- **Test**: `test_ignored_file_changes`
- **Scenario**: Modify `README.md` (ignored by default)
- **Expected**: No drift detected
- **Verifies**: Ignore patterns work correctly

#### 5. Multiple Mixed Changes
- **Test**: `test_multiple_changes_mixed_severity`
- **Scenario**: Make changes across different severity levels
- **Expected**: Multiple changes with varying severities
- **Verifies**: Complex scenarios handled properly

#### 6. File Addition/Removal
- **Test**: `test_file_addition_and_removal`
- **Scenario**: Add new files and remove existing ones
- **Expected**: ADDED and REMOVED change types detected
- **Verifies**: File lifecycle changes tracked

#### 7. Database Persistence
- **Test**: `test_database_persistence`
- **Scenario**: Verify SQLite database structure and data
- **Expected**: Proper schema and data storage
- **Verifies**: Data persistence works correctly

#### 8. Slack Integration (Mocked)
- **Test**: `test_slack_alert_integration`
- **Scenario**: Test Slack webhook integration
- **Expected**: Mock webhook called with proper payload
- **Verifies**: Alert system integration

### Running Specific Tests

```bash
# Run only drift detection tests
pytest tests/test_driftmon.py::TestDriftmon::test_no_drift_baseline -v

# Run severity-related tests
pytest tests/test_driftmon.py -k "severity" -v

# Run with coverage
pip install pytest-cov
pytest tests/ --cov=driftmon --cov-report=html
```

### Test Data Structure

Tests create a temporary directory with this structure:

```
temp_test_dir/
├── driftmon.yml         # Test configuration
├── src/
│   ├── main.py         # Test source file
│   └── utils.py        # Test utility file
├── prompts/
│   ├── system.txt      # Test system prompt
│   └── user.txt        # Test user prompt
├── config/
│   ├── models.yaml     # Test model config
│   └── evals.json      # Test evaluation config
└── README.md           # Test ignored file
```

### Manual Testing

For manual testing, you can run these scenarios:

```bash
# Initialize test environment
python driftmon.py init

# Test no drift
python driftmon.py snapshot
python driftmon.py diff
echo $?  # Should be 0

# Test with changes
echo 'print("modified")' > src/test.py
python driftmon.py run
echo $?  # Should be 2

# Test alerts
python driftmon.py alert
ls .drift/artifacts/  # Should show diff files
```

## Exit Codes

- **0**: Success / No drift detected
- **1**: Error or user cancellation  
- **2**: Drift detected

These exit codes make driftmon suitable for CI/CD pipelines and automation scripts.

## Troubleshooting

### Common Issues

1. **No files detected for watching**
   - Check your `watch` patterns in `driftmon.yml`
   - Verify files exist and match the patterns
   - Run `python driftmon.py status` to see current config

2. **Files not ignored properly**
   - Check `ignore` patterns in `driftmon.yml`
   - Verify `.driftignore` file if using additional patterns
   - Remember that ignore patterns use glob syntax

3. **Alerts not sending**
   - Verify `alerts.enabled: true` in config
   - Check webhook URLs are correct
   - Look for error messages in console output

4. **Database errors**
   - Delete `.drift/snapshots.sqlite` to reset
   - Run `python driftmon.py init` to reinitialize

### Debug Mode

Enable verbose output:

```bash
python driftmon.py -c driftmon.yml status
python driftmon.py diff  # Shows detailed change information
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Run the test suite: `pytest tests/ -v`
5. Submit a pull request

## License

MIT License - see LICENSE file for details.