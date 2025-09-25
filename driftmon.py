#!/usr/bin/env python3
"""
Driftmon - AI Model Output Drift Detection and Monitoring
Main CLI entrypoint for the driftmon tool
"""

import argparse
import sys
import os
import json
import yaml
import hashlib
import sqlite3
import uuid
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional, Tuple, List
import glob
import fnmatch
import difflib
from enum import Enum
import urllib.request
import urllib.error


class ChangeType(Enum):
    ADDED = "ADDED"
    REMOVED = "REMOVED"
    CHANGED = "CHANGED"


class Severity(Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


def canon_bytes(path: Path) -> str:
    """
    Normalize text/JSON/YAML content from a file.
    
    Args:
        path: Path to the file to canonicalize
        
    Returns:
        Normalized string representation of the file content
    """
    if not path.exists():
        raise FileNotFoundError(f"File not found: {path}")
    
    content = path.read_text(encoding='utf-8')
    suffix = path.suffix.lower()
    
    if suffix == '.json':
        # Parse and re-serialize JSON with sorted keys
        try:
            data = json.loads(content)
            return json.dumps(data, sort_keys=True, separators=(',', ':'))
        except json.JSONDecodeError:
            # If not valid JSON, treat as text
            pass
    
    elif suffix in ['.yaml', '.yml']:
        # Parse and re-serialize YAML with sorted keys
        try:
            data = yaml.safe_load(content)
            return yaml.dump(data, sort_keys=True, default_flow_style=False)
        except yaml.YAMLError:
            # If not valid YAML, treat as text
            pass
    
    # Default: normalize newlines for text files
    # Convert all line endings to Unix style
    return content.replace('\r\n', '\n').replace('\r', '\n')


def fingerprint(path: Path) -> Tuple[str, str]:
    """
    Generate a SHA-256 hash and canonical text for a file.
    
    Args:
        path: Path to the file to fingerprint
        
    Returns:
        Tuple of (hash, canonical_text)
    """
    canonical_text = canon_bytes(path)
    
    # Calculate SHA-256 hash of the canonical text
    hash_obj = hashlib.sha256()
    hash_obj.update(canonical_text.encode('utf-8'))
    hash_value = hash_obj.hexdigest()
    
    return (hash_value, canonical_text)


class Driftmon:
    """Main Driftmon application class"""
    
    def __init__(self, config_path: str = "driftmon.yml"):
        self.config_path = Path(config_path)
        self.config: Dict[str, Any] = {}
        self.drift_dir = Path(".drift")
        self.artifacts_dir = self.drift_dir / "artifacts"
        self.db_path = self.drift_dir / "snapshots.sqlite"
        
        self._ensure_directories()
        self._load_config()
        self._init_database()
    
    def _ensure_directories(self):
        """Ensure required directories exist"""
        self.drift_dir.mkdir(exist_ok=True)
        self.artifacts_dir.mkdir(exist_ok=True)
    
    def _load_config(self):
        """Load configuration from driftmon.yml"""
        if self.config_path.exists():
            with open(self.config_path, 'r') as f:
                self.config = yaml.safe_load(f) or {}
            print(f"Loaded configuration from {self.config_path}")
        else:
            print(f"Warning: Configuration file {self.config_path} not found")
    
    def _init_database(self):
        """Initialize SQLite database for snapshots"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS snapshots (
                run_id TEXT NOT NULL,
                path TEXT NOT NULL,
                hash TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                PRIMARY KEY (run_id, path)
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def watch(self, paths: Optional[list] = None):
        """Start watching specified paths for drift"""
        watch_paths = paths or self.config.get('watch', [])
        print(f"Starting drift monitoring for: {watch_paths}")
        print("Hello driftmon! Watch mode activated.")
        # TODO: Implement actual watching logic
    
    def check(self, file_path: str):
        """Check a specific file for drift"""
        print(f"Checking {file_path} for drift...")
        print("Hello driftmon! Check mode activated.")
        # TODO: Implement drift checking logic
    
    def status(self):
        """Show current drift monitoring status"""
        print("Driftmon Status")
        print("-" * 40)
        print(f"Config file: {self.config_path}")
        print(f"Drift directory: {self.drift_dir}")
        print(f"Artifacts directory: {self.artifacts_dir}")
        
        if self.config:
            print(f"\nWatching: {self.config.get('watch', [])}")
            print(f"Ignoring: {self.config.get('ignore', [])}")
            print(f"Alerts enabled: {self.config.get('alerts', {}).get('enabled', False)}")
    
    def init(self):
        """Initialize driftmon in the current directory and take baseline snapshot"""
        print("🚀 Initializing driftmon...")
        self._ensure_directories()
        
        # Create default config if it doesn't exist
        if not self.config_path.exists():
            print(f"📄 Creating default configuration at {self.config_path}")
            # TODO: Create default config
            
        print("📸 Taking baseline snapshot...")
        self.snapshot()
        
        print("\n✅ Driftmon initialization complete!")
        print("📋 Next steps:")
        print("  • Run 'driftmon snapshot' to take additional snapshots")
        print("  • Run 'driftmon diff' to compare snapshots")
        print("  • Run 'driftmon alert' to check for drift and send alerts")
        print("  • Run 'driftmon run' for full snapshot + diff + alert workflow")
    
    def hash(self, file_path: str):
        """Calculate and display hash of a file"""
        path = Path(file_path)
        
        try:
            hash_value, canonical_text = fingerprint(path)
            print(f"File: {file_path}")
            print(f"SHA-256: {hash_value}")
            print(f"Canonical size: {len(canonical_text)} bytes")
        except FileNotFoundError as e:
            print(f"Error: {e}")
            sys.exit(1)
        except Exception as e:
            print(f"Error processing file: {e}")
            sys.exit(1)
    
    def _get_files_to_watch(self) -> List[Path]:
        """Get list of files matching watch patterns from config"""
        watch_patterns = self.config.get('watch', [])
        ignore_patterns = self.config.get('ignore', [])
        
        files = []
        for pattern in watch_patterns:
            # Use glob to expand the pattern
            matches = glob.glob(pattern, recursive=True)
            for match in matches:
                path = Path(match)
                if path.is_file():
                    # Check if file should be ignored
                    should_ignore = False
                    for ignore_pattern in ignore_patterns:
                        if glob.fnmatch.fnmatch(str(path), ignore_pattern):
                            should_ignore = True
                            break
                    
                    if not should_ignore:
                        files.append(path)
        
        return files
    
    def snapshot(self):
        """Take a snapshot of all watched files"""
        # Generate unique run ID
        run_id = str(uuid.uuid4())
        timestamp = datetime.now().isoformat()
        
        print(f"Creating snapshot with run_id: {run_id}")
        print(f"Timestamp: {timestamp}")
        
        # Get files to snapshot
        files = self._get_files_to_watch()
        
        if not files:
            print("No files found to snapshot based on watch patterns.")
            return
        
        # Connect to database
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Process each file
        snapshot_count = 0
        error_count = 0
        
        for file_path in files:
            try:
                hash_value, _ = fingerprint(file_path)
                
                # Insert into database
                cursor.execute('''
                    INSERT INTO snapshots (run_id, path, hash, timestamp)
                    VALUES (?, ?, ?, ?)
                ''', (run_id, str(file_path), hash_value, timestamp))
                
                snapshot_count += 1
                print(f"  ✓ {file_path}: {hash_value[:12]}...")
                
            except Exception as e:
                error_count += 1
                print(f"  ✗ {file_path}: {e}")
        
        conn.commit()
        conn.close()
        
        # Print summary
        print(f"\nSnapshot Summary:")
        print(f"  Files processed: {snapshot_count}")
        if error_count > 0:
            print(f"  Errors: {error_count}")
        print(f"  Snapshot saved to: {self.db_path}")
    
    def _get_severity(self, file_path: str, change_type: ChangeType) -> Severity:
        """Determine severity based on file path and change type"""
        # Load severity rules from config
        severity_rules = self.config.get('severity_rules', [])
        
        # Default severity mappings
        default_severity = {
            ChangeType.ADDED: Severity.MEDIUM,
            ChangeType.REMOVED: Severity.MEDIUM,
            ChangeType.CHANGED: Severity.LOW
        }
        
        # Check custom rules first
        for rule in severity_rules:
            pattern = rule.get('pattern', '')
            if fnmatch.fnmatch(file_path, pattern):
                severity_str = rule.get('severity', 'LOW').upper()
                try:
                    return Severity[severity_str]
                except KeyError:
                    pass
        
        # Critical paths get HIGH severity
        critical_patterns = ['**/critical/**', '**/security/**', '**/auth/**']
        for pattern in critical_patterns:
            if fnmatch.fnmatch(file_path, pattern):
                return Severity.HIGH
        
        # Return default based on change type
        return default_severity.get(change_type, Severity.LOW)
    
    def _get_last_two_runs(self) -> Tuple[Optional[str], Optional[str]]:
        """Get the last two run IDs from the database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT DISTINCT run_id, timestamp 
            FROM snapshots 
            ORDER BY timestamp DESC 
            LIMIT 2
        ''')
        
        runs = cursor.fetchall()
        conn.close()
        
        if len(runs) == 0:
            return None, None
        elif len(runs) == 1:
            return runs[0][0], None
        else:
            return runs[0][0], runs[1][0]
    
    def diff(self, return_changes=False):
        """Compare the last two snapshot runs and show differences
        
        Args:
            return_changes: If True, return changes dict instead of printing
            
        Returns:
            Optional dict with changes data if return_changes is True
        """
        # Get last two runs
        current_run, previous_run = self._get_last_two_runs()
        
        if not previous_run:
            if not return_changes:
                print("Not enough snapshots to compare. Need at least 2 snapshots.")
                print("Run 'driftmon snapshot' to create snapshots.")
            return None if return_changes else None
        
        if not return_changes:
            print(f"Comparing snapshots:")
            print(f"  Previous: {previous_run}")
            print(f"  Current:  {current_run}")
            print("-" * 60)
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Get all files from both runs
        cursor.execute('''
            SELECT path, hash FROM snapshots WHERE run_id = ?
        ''', (previous_run,))
        previous_files = {row[0]: row[1] for row in cursor.fetchall()}
        
        cursor.execute('''
            SELECT path, hash FROM snapshots WHERE run_id = ?
        ''', (current_run,))
        current_files = {row[0]: row[1] for row in cursor.fetchall()}
        
        conn.close()
        
        # Track changes
        changes = []
        
        # Check for removed files
        for path in previous_files:
            if path not in current_files:
                severity = self._get_severity(path, ChangeType.REMOVED)
                changes.append({
                    'path': path,
                    'type': ChangeType.REMOVED,
                    'severity': severity
                })
        
        # Check for added and changed files
        for path in current_files:
            if path not in previous_files:
                severity = self._get_severity(path, ChangeType.ADDED)
                changes.append({
                    'path': path,
                    'type': ChangeType.ADDED,
                    'severity': severity
                })
            elif current_files[path] != previous_files[path]:
                severity = self._get_severity(path, ChangeType.CHANGED)
                changes.append({
                    'path': path,
                    'type': ChangeType.CHANGED,
                    'severity': severity,
                    'old_hash': previous_files[path],
                    'new_hash': current_files[path]
                })
        
        # Sort changes by severity and type
        severity_order = {Severity.HIGH: 0, Severity.MEDIUM: 1, Severity.LOW: 2}
        changes.sort(key=lambda x: (severity_order[x['severity']], x['type'].value, x['path']))
        
        # If returning changes, prepare the result
        if return_changes:
            return {
                'current_run': current_run,
                'previous_run': previous_run,
                'changes': changes,
                'total': len(changes)
            }
        
        # Display changes
        if not changes:
            print("No changes detected between snapshots.")
            return
        
        # Print summary
        print(f"\n📊 Change Summary:")
        print(f"  Total changes: {len(changes)}")
        
        # Count by type
        by_type = {}
        for change in changes:
            change_type = change['type']
            by_type[change_type] = by_type.get(change_type, 0) + 1
        
        for change_type, count in by_type.items():
            print(f"  {change_type.value}: {count}")
        
        # Count by severity
        print(f"\n🎯 By Severity:")
        by_severity = {}
        for change in changes:
            sev = change['severity']
            by_severity[sev] = by_severity.get(sev, 0) + 1
        
        for sev in [Severity.HIGH, Severity.MEDIUM, Severity.LOW]:
            if sev in by_severity:
                print(f"  {sev.value}: {by_severity[sev]}")
        
        # Detailed changes
        print(f"\n📝 Detailed Changes:")
        print("-" * 60)
        
        for change in changes:
            severity_icon = {
                Severity.HIGH: "🔴",
                Severity.MEDIUM: "🟡",
                Severity.LOW: "🟢"
            }[change['severity']]
            
            type_icon = {
                ChangeType.ADDED: "➕",
                ChangeType.REMOVED: "➖",
                ChangeType.CHANGED: "📝"
            }[change['type']]
            
            print(f"{severity_icon} [{change['severity'].value:6}] {type_icon} {change['type'].value:8} {change['path']}")
            
            # For changed files, show diff if possible
            if change['type'] == ChangeType.CHANGED:
                path = Path(change['path'])
                if path.exists():
                    try:
                        # Get current content
                        current_content = canon_bytes(path)
                        current_lines = current_content.splitlines(keepends=True)
                        
                        # Try to generate a simple diff preview
                        print(f"    Hash: {change['old_hash'][:12]}... → {change['new_hash'][:12]}...")
                        
                        # For small files, show unified diff
                        if len(current_lines) < 100:
                            # This is simplified - in production you'd retrieve the old content
                            print("    (Run with --verbose for full diff)")
                    except Exception as e:
                        print(f"    Could not generate diff: {e}")
        
        print("-" * 60)
        print(f"✅ Diff complete")
    
    def _save_artifact(self, content: str, artifact_type: str = "diff") -> str:
        """Save artifact to the artifacts directory
        
        Args:
            content: Content to save
            artifact_type: Type of artifact (e.g., 'diff', 'alert')
            
        Returns:
            Path to saved artifact
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        artifact_path = self.artifacts_dir / f"{timestamp}.{artifact_type}.txt"
        
        with open(artifact_path, 'w') as f:
            f.write(content)
        
        return str(artifact_path)
    
    def _send_slack_alert(self, webhook_url: str, message: dict) -> bool:
        """Send alert to Slack webhook
        
        Args:
            webhook_url: Slack webhook URL
            message: Message payload
            
        Returns:
            True if successful, False otherwise
        """
        try:
            data = json.dumps(message).encode('utf-8')
            req = urllib.request.Request(
                webhook_url,
                data=data,
                headers={'Content-Type': 'application/json'}
            )
            
            with urllib.request.urlopen(req) as response:
                return response.status == 200
        except (urllib.error.URLError, urllib.error.HTTPError) as e:
            print(f"Failed to send Slack alert: {e}")
            return False
    
    def alert(self):
        """Check for drift and send alerts if configured"""
        # Get diff data
        diff_data = self.diff(return_changes=True)
        
        if not diff_data:
            print("No snapshots available for comparison.")
            return
        
        if diff_data['total'] == 0:
            print("No drift detected. No alerts sent.")
            return
        
        # Determine overall severity
        severities = [change['severity'] for change in diff_data['changes']]
        if Severity.HIGH in severities:
            overall_severity = "HIGH"
            severity_color = "danger"
        elif Severity.MEDIUM in severities:
            overall_severity = "MEDIUM"
            severity_color = "warning"
        else:
            overall_severity = "LOW"
            severity_color = "good"
        
        # Generate diff content for artifact
        artifact_content = f"Drift Detection Report\n"
        artifact_content += f"Generated: {datetime.now().isoformat()}\n"
        artifact_content += f"Previous Run: {diff_data['previous_run']}\n"
        artifact_content += f"Current Run: {diff_data['current_run']}\n"
        artifact_content += f"Total Changes: {diff_data['total']}\n"
        artifact_content += "=" * 60 + "\n\n"
        
        # Count changes by type
        by_type = {}
        for change in diff_data['changes']:
            change_type = change['type']
            by_type[change_type] = by_type.get(change_type, 0) + 1
        
        # Add summary to artifact
        artifact_content += "SUMMARY\n"
        artifact_content += "-" * 40 + "\n"
        for change_type, count in by_type.items():
            artifact_content += f"{change_type.value}: {count}\n"
        artifact_content += "\n"
        
        # Add detailed changes
        artifact_content += "DETAILED CHANGES\n"
        artifact_content += "-" * 40 + "\n"
        for change in diff_data['changes']:
            artifact_content += f"[{change['severity'].value}] {change['type'].value} {change['path']}\n"
            if change['type'] == ChangeType.CHANGED:
                artifact_content += f"  Old hash: {change['old_hash'][:12]}...\n"
                artifact_content += f"  New hash: {change['new_hash'][:12]}...\n"
                
                # Try to generate unified diff for changed files
                path = Path(change['path'])
                if path.exists():
                    try:
                        current_content = canon_bytes(path)
                        # In a real implementation, we'd retrieve old content from storage
                        artifact_content += f"  (Full diff would be generated from stored content)\n"
                    except Exception as e:
                        artifact_content += f"  Could not generate diff: {e}\n"
            artifact_content += "\n"
        
        # Save artifact
        artifact_path = self._save_artifact(artifact_content, "diff")
        print(f"📁 Diff artifact saved to: {artifact_path}")
        
        # Check alert configuration
        alerts_config = self.config.get('alerts', {})
        if not alerts_config.get('enabled', False):
            print("⚠️  Alerts are disabled in configuration.")
            return
        
        # Process each alert channel
        channels = alerts_config.get('channels', [])
        alerts_sent = []
        
        for channel in channels:
            channel_type = channel.get('type')
            
            if channel_type == 'slack':
                webhook = channel.get('webhook')
                if not webhook or webhook == 'YOUR_SLACK_WEBHOOK':
                    print("⚠️  Slack webhook not configured. Skipping Slack alert.")
                    continue
                
                # Format Slack message
                slack_message = {
                    "text": f"🚨 Config Drift Detected: {overall_severity} Severity",
                    "attachments": [{
                        "color": severity_color,
                        "title": f"Drift Detection Report - {overall_severity} Severity",
                        "fields": [
                            {
                                "title": "Total Changes",
                                "value": str(diff_data['total']),
                                "short": True
                            }
                        ],
                        "footer": "Driftmon",
                        "ts": int(datetime.now().timestamp())
                    }]
                }
                
                # Add change type breakdown
                for change_type, count in by_type.items():
                    slack_message["attachments"][0]["fields"].append({
                        "title": change_type.value,
                        "value": str(count),
                        "short": True
                    })
                
                # Add file list (limited to prevent message being too long)
                file_list = []
                for i, change in enumerate(diff_data['changes'][:10]):  # Limit to first 10
                    severity_emoji = {
                        Severity.HIGH: "🔴",
                        Severity.MEDIUM: "🟡", 
                        Severity.LOW: "🟢"
                    }[change['severity']]
                    
                    type_emoji = {
                        ChangeType.ADDED: "➕",
                        ChangeType.REMOVED: "➖",
                        ChangeType.CHANGED: "📝"
                    }[change['type']]
                    
                    file_list.append(f"{severity_emoji} {type_emoji} {change['path']}")
                
                if diff_data['total'] > 10:
                    file_list.append(f"... and {diff_data['total'] - 10} more")
                
                slack_message["attachments"][0]["fields"].append({
                    "title": "Changed Files",
                    "value": "\n".join(file_list),
                    "short": False
                })
                
                slack_message["attachments"][0]["fields"].append({
                    "title": "Artifact Location",
                    "value": artifact_path,
                    "short": False
                })
                
                # Send Slack alert
                if self._send_slack_alert(webhook, slack_message):
                    alerts_sent.append("Slack")
                    print("✅ Slack alert sent successfully")
                else:
                    print("❌ Failed to send Slack alert")
            
            elif channel_type == 'console':
                # Console output (already done by diff function)
                print("\n🔔 Console Alert:")
                print(f"  Severity: {overall_severity}")
                print(f"  Total drift changes: {diff_data['total']}")
                for change_type, count in by_type.items():
                    print(f"  {change_type.value}: {count}")
                alerts_sent.append("Console")
            
            elif channel_type == 'file':
                alert_log_path = Path(channel.get('path', '.drift/alerts.log'))
                alert_log_path.parent.mkdir(parents=True, exist_ok=True)
                
                with open(alert_log_path, 'a') as f:
                    f.write(f"\n{'=' * 60}\n")
                    f.write(f"Alert Generated: {datetime.now().isoformat()}\n")
                    f.write(f"Severity: {overall_severity}\n")
                    f.write(f"Total Changes: {diff_data['total']}\n")
                    f.write(f"Artifact: {artifact_path}\n")
                    f.write(f"{'=' * 60}\n")
                
                alerts_sent.append("File")
                print(f"📝 Alert logged to: {alert_log_path}")
        
        # Summary
        if alerts_sent:
            print(f"\n✅ Alerts sent via: {', '.join(alerts_sent)}")
        else:
            print("\n⚠️  No alerts were sent (check configuration)")
        
        return diff_data['total']  # Return number of changes for exit code
    
    def run(self):
        """Full workflow: snapshot + diff + alert"""
        print("🔄 Running full driftmon workflow...")
        print("-" * 50)
        
        # Step 1: Take snapshot
        print("📸 Step 1: Taking new snapshot")
        self.snapshot()
        print()
        
        # Step 2: Check for drift
        print("🔍 Step 2: Checking for drift")
        diff_data = self.diff(return_changes=True)
        
        if not diff_data:
            print("⚠️  Not enough snapshots to compare.")
            return 0
            
        changes_count = diff_data['total']
        
        if changes_count == 0:
            print("✅ No drift detected")
            return 0
        
        print(f"🚨 Drift detected: {changes_count} changes")
        print()
        
        # Step 3: Send alerts if drift found
        print("📢 Step 3: Processing alerts")
        alert_result = self.alert()
        
        print("-" * 50)
        print(f"🏁 Workflow complete: {changes_count} changes detected")
        
        return changes_count


def main():
    """Main CLI entrypoint"""
    parser = argparse.ArgumentParser(
        description="Driftmon - AI Model Output Drift Detection and Monitoring",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument(
        "--version",
        action="version",
        version="driftmon 0.1.0"
    )
    
    parser.add_argument(
        "-c", "--config",
        default="driftmon.yml",
        help="Path to configuration file (default: driftmon.yml)"
    )
    
    subparsers = parser.add_subparsers(dest="command", help="Available commands")
    
    # Init command
    init_parser = subparsers.add_parser("init", help="Initialize driftmon in current directory")
    
    # Watch command
    watch_parser = subparsers.add_parser("watch", help="Start watching for drift")
    watch_parser.add_argument(
        "paths",
        nargs="*",
        help="Paths to watch (overrides config file)"
    )
    
    # Check command
    check_parser = subparsers.add_parser("check", help="Check specific file for drift")
    check_parser.add_argument(
        "file",
        help="File path to check"
    )
    
    # Status command
    status_parser = subparsers.add_parser("status", help="Show drift monitoring status")
    
    # Hash command
    hash_parser = subparsers.add_parser("hash", help="Calculate hash of a file")
    hash_parser.add_argument(
        "file",
        help="File path to hash"
    )
    
    # Snapshot command
    snapshot_parser = subparsers.add_parser("snapshot", help="Take a snapshot of all watched files")
    
    # Diff command
    diff_parser = subparsers.add_parser("diff", help="Compare last two snapshots and show differences")
    
    # Alert command
    alert_parser = subparsers.add_parser("alert", help="Check for drift and send alerts if configured")
    
    # Run command
    run_parser = subparsers.add_parser("run", help="Full workflow: snapshot + diff + alert")
    
    args = parser.parse_args()
    
    # Create driftmon instance
    driftmon = Driftmon(config_path=args.config)
    
    # Execute command with proper exit codes
    exit_code = 0
    
    try:
        if args.command == "init":
            driftmon.init()
        elif args.command == "watch":
            driftmon.watch(args.paths if args.paths else None)
        elif args.command == "check":
            driftmon.check(args.file)
        elif args.command == "status":
            driftmon.status()
        elif args.command == "hash":
            driftmon.hash(args.file)
        elif args.command == "snapshot":
            driftmon.snapshot()
        elif args.command == "diff":
            driftmon.diff()  # Show normal output
            diff_data = driftmon.diff(return_changes=True)  # Get data for exit code
            if diff_data and diff_data['total'] > 0:
                exit_code = 2  # Drift detected
        elif args.command == "alert":
            changes_count = driftmon.alert()
            if changes_count and changes_count > 0:
                exit_code = 2  # Drift detected
        elif args.command == "run":
            changes_count = driftmon.run()
            if changes_count and changes_count > 0:
                exit_code = 2  # Drift detected
        else:
            print("🤖 Hello driftmon!")
            print("📖 Use --help to see available commands")
            print("\n📋 Quick start:")
            print("  driftmon init     # Initialize and take baseline snapshot")
            print("  driftmon snapshot # Take new snapshot")
            print("  driftmon diff     # Compare snapshots")
            print("  driftmon alert    # Check drift and send alerts")
            print("  driftmon run      # Full workflow")
            parser.print_help()
            sys.exit(0)
    
    except KeyboardInterrupt:
        print("\n⚠️  Operation cancelled by user")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Error: {e}")
        sys.exit(1)
    
    sys.exit(exit_code)


if __name__ == "__main__":
    main()