"""
Process Control CLI for Windows Service Process Monitoring Agent.

Provides command-line interface for process management:
- Kill suspicious processes
- Whitelist/blacklist processes
- View process control history
- Check whitelist/blacklist status

Examples:
    python process_control_cli.py kill 1234 --reason "Malware detected"
    python process_control_cli.py whitelist "explorer.exe"
    python process_control_cli.py blacklist "mimikatz.exe" --auto-block
    python process_control_cli.py history
    python process_control_cli.py list-whitelist
    python process_control_cli.py list-blacklist
    python process_control_cli.py check-process "notepad.exe"
"""

import argparse
import json
import sys
from pathlib import Path
from typing import Optional

from process_control import ProcessControlManager

# Add current directory to path
current_dir = Path(__file__).parent
if str(current_dir) not in sys.path:
    sys.path.insert(0, str(current_dir))


def format_json(data, indent=2):
    """Format data as JSON."""
    return json.dumps(data, indent=indent, default=str)


def kill_command(args):
    """Kill a process."""
    manager = ProcessControlManager()
    
    try:
        pid = int(args.pid)
    except ValueError:
        print(f"[ERROR] Invalid PID: {args.pid}")
        return False
    
    reason = args.reason or "Manual termination"
    force = args.force
    
    print(f"[*] Killing process PID {pid}...")
    if force:
        print(f"    Force kill: Enabled")
    
    record = manager.kill_process(pid, reason=reason, force=force)
    
    if record.success:
        print(f"[✓] Process killed successfully")
        print(f"    PID: {record.pid}")
        print(f"    Name: {record.name}")
        print(f"    Method: {record.kill_method}")
        print(f"    Time: {record.timestamp}")
    else:
        print(f"[✗] Failed to kill process")
        print(f"    Error: {record.error_message}")
        return False
    
    return True


def whitelist_command(args):
    """Add process to whitelist."""
    manager = ProcessControlManager()
    
    process_name = args.process_name
    process_path = args.path
    reason = args.reason or "Trusted process"
    
    print(f"[*] Adding to whitelist: {process_name}")
    
    success = manager.whitelist_process(
        process_name,
        process_path=process_path,
        reason=reason,
        added_by="cli"
    )
    
    if success:
        print(f"[✓] Process whitelisted successfully")
        print(f"    Process: {process_name}")
        if process_path:
            print(f"    Path: {process_path}")
        print(f"    Reason: {reason}")
    else:
        print(f"[✗] Failed to whitelist process")
        return False
    
    return True


def blacklist_command(args):
    """Add process to blacklist."""
    manager = ProcessControlManager()
    
    process_name = args.process_name
    process_path = args.path
    reason = args.reason or "Suspicious/malicious process"
    auto_block = args.auto_block
    
    print(f"[*] Adding to blacklist: {process_name}")
    if auto_block:
        print(f"    Auto-block: Enabled (process will be killed if detected)")
    
    success = manager.blacklist_process(
        process_name,
        process_path=process_path,
        reason=reason,
        auto_block=auto_block,
        added_by="cli"
    )
    
    if success:
        print(f"[✓] Process blacklisted successfully")
        print(f"    Process: {process_name}")
        if process_path:
            print(f"    Path: {process_path}")
        print(f"    Reason: {reason}")
        print(f"    Auto-block: {'Yes' if auto_block else 'No'}")
    else:
        print(f"[✗] Failed to blacklist process")
        return False
    
    return True


def remove_whitelist_command(args):
    """Remove process from whitelist."""
    manager = ProcessControlManager()
    
    process_name = args.process_name
    
    print(f"[*] Removing from whitelist: {process_name}")
    
    success = manager.remove_from_whitelist(process_name)
    
    if success:
        print(f"[✓] Process removed from whitelist")
    else:
        print(f"[!] Process not found in whitelist")
        return False
    
    return True


def remove_blacklist_command(args):
    """Remove process from blacklist."""
    manager = ProcessControlManager()
    
    process_name = args.process_name
    
    print(f"[*] Removing from blacklist: {process_name}")
    
    success = manager.remove_from_blacklist(process_name)
    
    if success:
        print(f"[✓] Process removed from blacklist")
    else:
        print(f"[!] Process not found in blacklist")
        return False
    
    return True


def list_whitelist_command(args):
    """List all whitelisted processes."""
    manager = ProcessControlManager()
    
    whitelist = manager.get_whitelist()
    
    if not whitelist:
        print("[*] Whitelist is empty")
        return True
    
    print(f"\n[*] Whitelisted Processes ({len(whitelist)} total)")
    print("=" * 80)
    
    for name, info in sorted(whitelist.items()):
        print(f"\nProcess: {info['name']}")
        if info['path']:
            print(f"Path: {info['path']}")
        print(f"Reason: {info['reason']}")
        print(f"Added: {info['added_at'][:10]}")
        print(f"Added by: {info['added_by']}")
    
    print("\n" + "=" * 80)
    return True


def list_blacklist_command(args):
    """List all blacklisted processes."""
    manager = ProcessControlManager()
    
    blacklist = manager.get_blacklist()
    
    if not blacklist:
        print("[*] Blacklist is empty")
        return True
    
    print(f"\n[*] Blacklisted Processes ({len(blacklist)} total)")
    print("=" * 80)
    
    for name, info in sorted(blacklist.items()):
        print(f"\nProcess: {info['name']}")
        if info['path']:
            print(f"Path: {info['path']}")
        print(f"Reason: {info['reason']}")
        print(f"Auto-block: {'Yes' if info['auto_block'] else 'No'}")
        print(f"Added: {info['added_at'][:10]}")
        print(f"Added by: {info['added_by']}")
    
    print("\n" + "=" * 80)
    return True


def history_command(args):
    """Show process kill history."""
    manager = ProcessControlManager()
    
    limit = args.limit or 50
    history = manager.get_kill_history(limit=limit)
    
    if not history:
        print("[*] Kill history is empty")
        return True
    
    print(f"\n[*] Process Kill History ({len(history)} records)")
    print("=" * 100)
    
    for record in reversed(history):
        status = "[✓]" if record["success"] else "[✗]"
        print(f"\n{status} {record['timestamp']}")
        print(f"   PID: {record['pid']} | Name: {record['name']}")
        print(f"   Path: {record['path']}")
        print(f"   Method: {record['kill_method']}")
        print(f"   Reason: {record['reason']}")
        if record['error_message']:
            print(f"   Error: {record['error_message']}")
    
    print("\n" + "=" * 100)
    return True


def check_process_command(args):
    """Check if a process is whitelisted or blacklisted."""
    manager = ProcessControlManager()
    
    process_name = args.process_name
    process_path = args.path
    
    is_whitelisted = manager.is_whitelisted(process_name, process_path)
    is_blacklisted = manager.is_blacklisted(process_name, process_path)
    
    print(f"\n[*] Process Status: {process_name}")
    print("=" * 60)
    print(f"Process: {process_name}")
    if process_path:
        print(f"Path: {process_path}")
    print(f"Whitelisted: {'Yes' if is_whitelisted else 'No'}")
    print(f"Blacklisted: {'Yes' if is_blacklisted else 'No'}")
    print("=" * 60)
    
    if is_whitelisted:
        print("[✓] Process is trusted (whitelisted)")
    elif is_blacklisted:
        print("[✗] Process is suspicious/malicious (blacklisted)")
    else:
        print("[?] Process status unknown (not in any list)")
    
    return True


def stats_command(args):
    """Show process control statistics."""
    manager = ProcessControlManager()
    
    stats = manager.get_statistics()
    
    print(f"\n[*] Process Control Statistics")
    print("=" * 60)
    print(f"Whitelisted Processes: {stats['whitelist_count']}")
    print(f"Blacklisted Processes: {stats['blacklist_count']}")
    print(f"Auto-block Enabled: {stats['auto_block_enabled']}")
    print(f"Total Kills: {stats['kill_history_count']}")
    print(f"  - Successful: {stats['successful_kills']}")
    print(f"  - Failed: {stats['failed_kills']}")
    print("=" * 60)
    
    return True


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Process Control for Windows Service Process Monitoring Agent",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python process_control_cli.py kill 1234 --reason "Malware detected"
  python process_control_cli.py kill 5678 --force
  python process_control_cli.py whitelist "explorer.exe"
  python process_control_cli.py blacklist "mimikatz.exe" --auto-block
  python process_control_cli.py remove-whitelist "explorer.exe"
  python process_control_cli.py list-whitelist
  python process_control_cli.py list-blacklist
  python process_control_cli.py check "notepad.exe"
  python process_control_cli.py history --limit 20
  python process_control_cli.py stats
        """
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Command to execute')
    
    # Kill command
    kill_parser = subparsers.add_parser('kill', help='Kill a process')
    kill_parser.add_argument('pid', help='Process ID (PID) to kill')
    kill_parser.add_argument('--reason', help='Reason for killing')
    kill_parser.add_argument('--force', action='store_true', help='Force kill (bypass graceful termination)')
    kill_parser.set_defaults(func=kill_command)
    
    # Whitelist command
    whitelist_parser = subparsers.add_parser('whitelist', help='Add process to whitelist')
    whitelist_parser.add_argument('process_name', help='Process name to whitelist')
    whitelist_parser.add_argument('--path', help='Full path to process executable')
    whitelist_parser.add_argument('--reason', help='Reason for whitelisting')
    whitelist_parser.set_defaults(func=whitelist_command)
    
    # Blacklist command
    blacklist_parser = subparsers.add_parser('blacklist', help='Add process to blacklist')
    blacklist_parser.add_argument('process_name', help='Process name to blacklist')
    blacklist_parser.add_argument('--path', help='Full path to process executable')
    blacklist_parser.add_argument('--reason', help='Reason for blacklisting')
    blacklist_parser.add_argument('--auto-block', action='store_true', help='Auto-kill if detected')
    blacklist_parser.set_defaults(func=blacklist_command)
    
    # Remove from whitelist command
    remove_whitelist_parser = subparsers.add_parser('remove-whitelist', help='Remove process from whitelist')
    remove_whitelist_parser.add_argument('process_name', help='Process name to remove')
    remove_whitelist_parser.set_defaults(func=remove_whitelist_command)
    
    # Remove from blacklist command
    remove_blacklist_parser = subparsers.add_parser('remove-blacklist', help='Remove process from blacklist')
    remove_blacklist_parser.add_argument('process_name', help='Process name to remove')
    remove_blacklist_parser.set_defaults(func=remove_blacklist_command)
    
    # List whitelist command
    subparsers.add_parser('list-whitelist', help='List all whitelisted processes').set_defaults(func=list_whitelist_command)
    
    # List blacklist command
    subparsers.add_parser('list-blacklist', help='List all blacklisted processes').set_defaults(func=list_blacklist_command)
    
    # History command
    history_parser = subparsers.add_parser('history', help='Show process kill history')
    history_parser.add_argument('--limit', type=int, help='Number of records to show (default: 50)')
    history_parser.set_defaults(func=history_command)
    
    # Check command
    check_parser = subparsers.add_parser('check', help='Check if process is whitelisted/blacklisted')
    check_parser.add_argument('process_name', help='Process name to check')
    check_parser.add_argument('--path', help='Full path to process executable')
    check_parser.set_defaults(func=check_process_command)
    
    # Stats command
    subparsers.add_parser('stats', help='Show process control statistics').set_defaults(func=stats_command)
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return 0
    
    try:
        if hasattr(args, 'func'):
            success = args.func(args)
            return 0 if success else 1
        else:
            parser.print_help()
            return 1
    except Exception as e:
        print(f"[ERROR] {e}", file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
