#!/usr/bin/env python3
"""
Test scenarios for driftmon functionality
"""

import pytest
import tempfile
import shutil
from pathlib import Path
import os
import sys
import yaml
import json
import sqlite3
from unittest.mock import patch, MagicMock

# Add parent directory to path to import driftmon
sys.path.insert(0, str(Path(__file__).parent.parent))

from driftmon import Driftmon, ChangeType, Severity, canon_bytes, fingerprint


class TestDriftmon:
    """Test suite for driftmon functionality"""
    
    @pytest.fixture
    def temp_dir(self):
        """Create a temporary directory for testing"""
        temp_dir = tempfile.mkdtemp()
        yield Path(temp_dir)
        shutil.rmtree(temp_dir)
    
    @pytest.fixture
    def test_config(self, temp_dir):
        """Create a test configuration"""
        config = {
            'watch': [
                'src/**/*.py',
                'prompts/**/*.txt', 
                'config/**/*.yaml',
                'config/**/*.json'
            ],
            'ignore': [
                '**/__pycache__/**',
                '*.md',
                'tests/**',
                '**/*.log'
            ],
            'severity_rules': [
                {'pattern': '**/config/**', 'severity': 'HIGH'},
                {'pattern': '**/prompts/**', 'severity': 'MEDIUM'},
                {'pattern': '**/src/**', 'severity': 'LOW'},
                {'pattern': '*.md', 'severity': 'LOW'}
            ],
            'alerts': {
                'enabled': True,
                'channels': [
                    {'type': 'console', 'level': 'warning'},
                    {'type': 'file', 'path': '.drift/alerts.log', 'level': 'info'}
                ]
            }
        }
        
        config_path = temp_dir / 'driftmon.yml'
        with open(config_path, 'w') as f:
            yaml.dump(config, f)
        
        return config_path
    
    @pytest.fixture
    def test_files(self, temp_dir):
        """Create test files structure"""
        # Create directories
        (temp_dir / 'src').mkdir(parents=True, exist_ok=True)
        (temp_dir / 'prompts').mkdir(parents=True, exist_ok=True)
        (temp_dir / 'config').mkdir(parents=True, exist_ok=True)
        
        # Create source files
        (temp_dir / 'src' / 'main.py').write_text('print("Hello World")\n')
        (temp_dir / 'src' / 'utils.py').write_text('def helper(): pass\n')
        
        # Create prompt files
        (temp_dir / 'prompts' / 'system.txt').write_text('You are a helpful assistant.\n')
        (temp_dir / 'prompts' / 'user.txt').write_text('Please help me with coding.\n')
        
        # Create config files
        models_config = {
            'models': [
                {'name': 'gpt-4o', 'provider': 'openai', 'temperature': 0.7},
                {'name': 'gpt-3.5-turbo', 'provider': 'openai', 'temperature': 0.5}
            ],
            'default_model': 'gpt-4o'
        }
        with open(temp_dir / 'config' / 'models.yaml', 'w') as f:
            yaml.dump(models_config, f)
        
        evals_config = {
            'toxicity_threshold': 0.7,
            'bias_threshold': 0.8,
            'quality_threshold': 0.6
        }
        with open(temp_dir / 'config' / 'evals.json', 'w') as f:
            json.dump(evals_config, f)
        
        # Create ignored file
        (temp_dir / 'README.md').write_text('# Test Project\n\nThis is a test project.\n')
        
        return {
            'src_main': temp_dir / 'src' / 'main.py',
            'src_utils': temp_dir / 'src' / 'utils.py',
            'prompt_system': temp_dir / 'prompts' / 'system.txt',
            'prompt_user': temp_dir / 'prompts' / 'user.txt',
            'models_config': temp_dir / 'config' / 'models.yaml',
            'evals_config': temp_dir / 'config' / 'evals.json',
            'readme': temp_dir / 'README.md'
        }
    
    @pytest.fixture
    def driftmon_instance(self, temp_dir, test_config):
        """Create a driftmon instance for testing"""
        # Change to temp directory for testing
        original_cwd = os.getcwd()
        os.chdir(temp_dir)
        
        try:
            instance = Driftmon(str(test_config))
            yield instance
        finally:
            os.chdir(original_cwd)
    
    def test_canonicalization_functions(self, temp_dir):
        """Test canonicalization functions for different file types"""
        # Test JSON canonicalization
        json_file = temp_dir / 'test.json'
        json_content = '{"b": 2, "a": 1, "c": 3}'
        json_file.write_text(json_content)
        
        canonical = canon_bytes(json_file)
        expected = '{"a":1,"b":2,"c":3}'
        assert canonical == expected
        
        # Test YAML canonicalization
        yaml_file = temp_dir / 'test.yml'
        yaml_content = 'z: 3\na: 1\nb: 2\n'
        yaml_file.write_text(yaml_content)
        
        canonical = canon_bytes(yaml_file)
        # YAML should be sorted by keys
        assert 'a: 1' in canonical
        assert canonical.index('a: 1') < canonical.index('b: 2')
        assert canonical.index('b: 2') < canonical.index('z: 3')
        
        # Test text normalization
        text_file = temp_dir / 'test.txt'
        text_content = 'Line 1\r\nLine 2\rLine 3\n'
        text_file.write_text(text_content)
        
        canonical = canon_bytes(text_file)
        expected = 'Line 1\nLine 2\nLine 3\n'
        assert canonical == expected
    
    def test_fingerprint_function(self, temp_dir):
        """Test fingerprint generation"""
        test_file = temp_dir / 'test.txt'
        content = 'test content\n'
        test_file.write_text(content)
        
        hash_value, canonical_text = fingerprint(test_file)
        
        # Verify hash is SHA-256 (64 hex characters)
        assert len(hash_value) == 64
        assert all(c in '0123456789abcdef' for c in hash_value)
        
        # Verify canonical text matches
        assert canonical_text == content
        
        # Verify same content produces same hash
        hash_value2, _ = fingerprint(test_file)
        assert hash_value == hash_value2
    
    def test_no_drift_baseline(self, driftmon_instance, test_files):
        """Test scenario with no drift detected"""
        # Take initial snapshot
        driftmon_instance.snapshot()
        
        # Take another snapshot immediately (no changes)
        driftmon_instance.snapshot()
        
        # Check for drift
        diff_data = driftmon_instance.diff(return_changes=True)
        
        # Should detect no changes
        assert diff_data['total'] == 0
        assert len(diff_data['changes']) == 0
        
        # Test alert function returns 0 changes
        changes_count = driftmon_instance.alert()
        assert changes_count == 0
    
    def test_low_severity_drift_prompt_edited(self, driftmon_instance, test_files):
        """Test low-severity drift when prompt file is edited"""
        # Take initial snapshot
        driftmon_instance.snapshot()
        
        # Modify a prompt file (should be MEDIUM severity based on config)
        original_content = test_files['prompt_system'].read_text()
        new_content = 'You are a highly skilled coding assistant.\n'
        test_files['prompt_system'].write_text(new_content)
        
        # Take new snapshot
        driftmon_instance.snapshot()
        
        # Check for drift
        diff_data = driftmon_instance.diff(return_changes=True)
        
        # Should detect one change
        assert diff_data['total'] == 1
        assert len(diff_data['changes']) == 1
        
        change = diff_data['changes'][0]
        assert change['type'] == ChangeType.CHANGED
        assert change['severity'] == Severity.MEDIUM  # Based on severity rules
        assert 'prompts/system.txt' in change['path']
        
        # Test alert function
        changes_count = driftmon_instance.alert()
        assert changes_count == 1
        
        # Verify artifact was created
        drift_dir = Path('.drift')
        artifacts_dir = drift_dir / 'artifacts'
        assert artifacts_dir.exists()
        
        artifact_files = list(artifacts_dir.glob('*.diff.txt'))
        assert len(artifact_files) >= 1
        
        # Check artifact content
        latest_artifact = max(artifact_files, key=lambda x: x.stat().st_mtime)
        artifact_content = latest_artifact.read_text()
        assert 'CHANGED' in artifact_content
        assert 'prompts/system.txt' in artifact_content
        
        # Restore original content
        test_files['prompt_system'].write_text(original_content)
    
    def test_high_severity_drift_models_changed(self, driftmon_instance, test_files):
        """Test high-severity drift when models.yaml is changed"""
        # Take initial snapshot
        driftmon_instance.snapshot()
        
        # Modify models config (should be HIGH severity based on config)
        models_config = {
            'models': [
                {'name': 'gpt-4o', 'provider': 'openai', 'temperature': 0.9},  # Changed temperature
                {'name': 'claude-3', 'provider': 'anthropic', 'temperature': 0.7}  # Added new model
            ],
            'default_model': 'claude-3'  # Changed default
        }
        
        with open(test_files['models_config'], 'w') as f:
            yaml.dump(models_config, f)
        
        # Take new snapshot
        driftmon_instance.snapshot()
        
        # Check for drift
        diff_data = driftmon_instance.diff(return_changes=True)
        
        # Should detect one change
        assert diff_data['total'] == 1
        assert len(diff_data['changes']) == 1
        
        change = diff_data['changes'][0]
        assert change['type'] == ChangeType.CHANGED
        assert change['severity'] == Severity.HIGH  # Based on severity rules
        assert 'config/models.yaml' in change['path']
        
        # Test alert function
        changes_count = driftmon_instance.alert()
        assert changes_count == 1
        
        # Verify artifact was created with HIGH severity
        artifacts_dir = Path('.drift/artifacts')
        artifact_files = list(artifacts_dir.glob('*.diff.txt'))
        latest_artifact = max(artifact_files, key=lambda x: x.stat().st_mtime)
        artifact_content = latest_artifact.read_text()
        assert 'HIGH' in artifact_content
        assert 'config/models.yaml' in artifact_content
    
    def test_ignored_file_changes(self, driftmon_instance, test_files):
        """Test that ignored files (like README.md) don't trigger drift detection"""
        # Take initial snapshot
        driftmon_instance.snapshot()
        
        # Modify README.md (should be ignored based on config)
        original_content = test_files['readme'].read_text()
        new_content = '# Updated Test Project\n\nThis project has been updated with new features.\n'
        test_files['readme'].write_text(new_content)
        
        # Take new snapshot
        driftmon_instance.snapshot()
        
        # Check for drift
        diff_data = driftmon_instance.diff(return_changes=True)
        
        # Should detect no changes (README.md is ignored)
        assert diff_data['total'] == 0
        assert len(diff_data['changes']) == 0
        
        # Restore original content
        test_files['readme'].write_text(original_content)
    
    def test_multiple_changes_mixed_severity(self, driftmon_instance, test_files):
        """Test scenario with multiple changes of different severities"""
        # Take initial snapshot
        driftmon_instance.snapshot()
        
        # Make multiple changes
        # 1. HIGH severity: Change models config
        models_config = {'models': [{'name': 'new-model', 'provider': 'test'}]}
        with open(test_files['models_config'], 'w') as f:
            yaml.dump(models_config, f)
        
        # 2. MEDIUM severity: Change prompt
        test_files['prompt_user'].write_text('Please help me with advanced coding tasks.\n')
        
        # 3. LOW severity: Change source code
        test_files['src_main'].write_text('print("Hello, World!")\nprint("Updated code")\n')
        
        # 4. Ignored: Change README (should not be detected)
        test_files['readme'].write_text('# Completely New README\n')
        
        # Take new snapshot
        driftmon_instance.snapshot()
        
        # Check for drift
        diff_data = driftmon_instance.diff(return_changes=True)
        
        # Should detect 3 changes (README is ignored)
        assert diff_data['total'] == 3
        assert len(diff_data['changes']) == 3
        
        # Verify severities
        severities = [change['severity'] for change in diff_data['changes']]
        assert Severity.HIGH in severities
        assert Severity.MEDIUM in severities
        assert Severity.LOW in severities
        
        # Test alert function
        changes_count = driftmon_instance.alert()
        assert changes_count == 3
    
    def test_file_addition_and_removal(self, driftmon_instance, test_files):
        """Test detection of added and removed files"""
        # Take initial snapshot
        driftmon_instance.snapshot()
        
        # Add a new file
        new_file = Path('src/new_module.py')
        new_file.write_text('# New module\ndef new_function():\n    pass\n')
        
        # Remove an existing file
        removed_file = test_files['src_utils']
        removed_content = removed_file.read_text()
        removed_file.unlink()
        
        # Take new snapshot
        driftmon_instance.snapshot()
        
        # Check for drift
        diff_data = driftmon_instance.diff(return_changes=True)
        
        # Should detect 2 changes
        assert diff_data['total'] == 2
        
        # Find the added and removed changes
        added_changes = [c for c in diff_data['changes'] if c['type'] == ChangeType.ADDED]
        removed_changes = [c for c in diff_data['changes'] if c['type'] == ChangeType.REMOVED]
        
        assert len(added_changes) == 1
        assert len(removed_changes) == 1
        
        assert 'src/new_module.py' in added_changes[0]['path']
        assert 'src/utils.py' in removed_changes[0]['path']
        
        # Both should be LOW severity (src/** pattern)
        assert added_changes[0]['severity'] == Severity.LOW
        assert removed_changes[0]['severity'] == Severity.LOW
        
        # Cleanup
        new_file.unlink()
        # Restore removed file
        removed_file.write_text(removed_content)
    
    def test_database_persistence(self, driftmon_instance, test_files):
        """Test that snapshots are properly stored in SQLite database"""
        # Take initial snapshot
        driftmon_instance.snapshot()
        
        # Verify database exists and has data
        db_path = Path('.drift/snapshots.sqlite')
        assert db_path.exists()
        
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Check table structure
        cursor.execute("PRAGMA table_info(snapshots)")
        columns = [row[1] for row in cursor.fetchall()]
        expected_columns = ['run_id', 'path', 'hash', 'timestamp']
        assert all(col in columns for col in expected_columns)
        
        # Check data exists
        cursor.execute("SELECT COUNT(*) FROM snapshots")
        count = cursor.fetchone()[0]
        assert count > 0
        
        # Check specific file is recorded
        cursor.execute("SELECT * FROM snapshots WHERE path LIKE '%main.py'")
        results = cursor.fetchall()
        assert len(results) >= 1
        
        conn.close()
    
    @patch('urllib.request.urlopen')
    def test_slack_alert_integration(self, mock_urlopen, driftmon_instance, test_files):
        """Test Slack alert integration (mocked)"""
        # Mock successful Slack response
        mock_response = MagicMock()
        mock_response.status = 200
        mock_urlopen.return_value.__enter__.return_value = mock_response
        
        # Update config to include Slack webhook
        config_path = Path('driftmon.yml')
        with open(config_path, 'r') as f:
            config = yaml.safe_load(f)
        
        config['alerts']['channels'].append({
            'type': 'slack',
            'webhook': 'https://hooks.slack.com/test-webhook',
            'level': 'warning'
        })
        
        with open(config_path, 'w') as f:
            yaml.dump(config, f)
        
        # Reload driftmon instance with new config
        driftmon_instance._load_config()
        
        # Take initial snapshot
        driftmon_instance.snapshot()
        
        # Make a change
        test_files['src_main'].write_text('print("Changed for Slack test")\n')
        driftmon_instance.snapshot()
        
        # Trigger alert
        changes_count = driftmon_instance.alert()
        
        # Verify Slack webhook was called
        assert mock_urlopen.called
        assert changes_count == 1
    
    def test_severity_rule_matching(self, driftmon_instance):
        """Test severity rule pattern matching"""
        # Test different file paths against severity rules
        test_cases = [
            ('config/models.yaml', ChangeType.CHANGED, Severity.HIGH),
            ('config/settings.json', ChangeType.CHANGED, Severity.HIGH),
            ('prompts/system.txt', ChangeType.CHANGED, Severity.MEDIUM),
            ('prompts/user.txt', ChangeType.ADDED, Severity.MEDIUM),
            ('src/main.py', ChangeType.CHANGED, Severity.LOW),
            ('src/utils.py', ChangeType.REMOVED, Severity.LOW),
            ('README.md', ChangeType.CHANGED, Severity.LOW),
        ]
        
        for file_path, change_type, expected_severity in test_cases:
            severity = driftmon_instance._get_severity(file_path, change_type)
            assert severity == expected_severity, f"Failed for {file_path}: expected {expected_severity}, got {severity}"


if __name__ == '__main__':
    pytest.main([__file__, '-v'])