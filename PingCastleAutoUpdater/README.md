# PingCastle Auto Updater

PingCastleAutoUpdater is an automated update tool that downloads and installs the latest versions of PingCastle from GitHub releases. It manages configuration migrations, handles file updates, and ensures your PingCastle installation stays current with minimal manual effort.

## Features

- **Automatic Version Detection**: Compares current PingCastle version with the latest GitHub release
- **Smart Configuration Handling**: Preserves existing settings when updating, with automatic XML to JSON conversion when needed
- **Initial State Migration**: Automatically migrates legacy XML configurations to JSON format before updates
- **Backup & Recovery**: Automatically backs up existing configurations before updates
- **Dry-Run Preview**: Test updates without modifying any files
- **Flexible Release Selection**: Choose stable releases, preview versions, or wait for a release stabilization period
- **Custom Update Sources**: Point to alternative update repositories if needed
- **Complete Audit Trail**: Generates detailed migration and conversion reports for all operations

## System Requirements

- **Platform**: Windows x64 only
- **.NET Runtime**: Not required - includes self-contained .NET 10.0 runtime
- **Disk Space**: Minimal (executable only, no external dependencies)

## Installation

Place `PingCastleAutoUpdater.exe` in the same directory as `pingcastle.exe`. The tool is self-contained and requires no additional software to be installed.

## Basic Usage

### Simple Update Check and Install

```bash
PingCastleAutoUpdater.exe
```

This will:
1. Check GitHub for the latest stable release
2. Compare it with your current PingCastle version
3. Download and install the update if a newer version is available
4. Handle any configuration migrations automatically

### Preview Changes with Dry-Run

```bash
PingCastleAutoUpdater.exe --dry-run
```

The `--dry-run` option is useful for:
- **Testing before applying updates**: See exactly what files would be modified
- **Verifying configuration migration**: Check if XML to JSON conversion would succeed
- **Audit purposes**: Review what changes an update would introduce
- **No risk operation**: Absolutely no files are modified in dry-run mode

In dry-run mode, you will see:
- Which files would be downloaded and extracted
- How configuration files would be merged or converted
- A detailed conversion report saved to disk for review
- Any custom settings that would be preserved

Example output:
```
[DRY-RUN] No files will be modified. Analyzing update contents...

[DRY-RUN] Would save PingCastle.exe
[DRY-RUN] Would merge .config file: PingCastle.exe.config
[DRY-RUN] Would save PingCastleCommon.dll
...
[DRY-RUN MODE - NO CHANGES WILL BE MADE]

Analyzing configuration conversion...
[OK] Analysis completed - Configuration would be converted successfully

[Report] Preview report saved: ConversionPreview_20240115_143022.txt
[Data] Sections to convert: 5
[Settings] Settings to map: 24

To proceed with conversion, run without --dry-run flag.
```

## Command-Line Switches

### `--help`
Display the help message with all available options.

```bash
PingCastleAutoUpdater.exe --help
```

### `--dry-run`
Preview all changes that would be made without modifying any files.

**Use cases:**
- Test an update before applying it to production systems
- Verify configuration migration will succeed
- Audit what a new version would change
- Run on a test machine before deploying updates

```bash
PingCastleAutoUpdater.exe --dry-run
```

**Note:** Even in dry-run mode, temporary preview reports are generated so you can review the changes in detail. These reports are automatically cleaned up after the operation completes.

### `--use-preview`
Include preview/prerelease versions when checking for updates. By default, only stable releases are considered.

```bash
PingCastleAutoUpdater.exe --use-preview
```

This is useful for:
- Testing new features before official release
- Getting early access to bug fixes
- Running on non-production systems where stability is less critical

### `--force-download`
Download and install the latest release even if your current version is already up to date. Useful for re-installing or downgrading.

```bash
PingCastleAutoUpdater.exe --force-download
```

**Warning:** This will overwrite your current installation. Consider using `--dry-run` first to see what will be replaced.

### `--wait-for-days <n>`
Only use releases that have been published for at least N days. This adds a stabilization period before updating.

```bash
PingCastleAutoUpdater.exe --wait-for-days 30
```

Use cases:
- Implement a controlled update schedule
- Allow time for community feedback on new releases
- Ensure stability in production environments
- Stagger updates across multiple installations

**Example:** With `--wait-for-days 30`, the tool will skip any release published in the last 30 days, even if it's the "latest" release on GitHub.

### `--api-url <url>`
Use a custom API endpoint to check for updates instead of the default GitHub API.

```bash
PingCastleAutoUpdater.exe --api-url https://internal-repo.company.com/releases
```

This allows you to:
- Use an internal mirror of PingCastle releases
- Point to a custom release repository
- Work in restricted network environments

**Note:** The URL must be HTTP or HTTPS. The API should return release information in the same format as GitHub's API.

## Common Scenarios

### Scenario 1: Regular Scheduled Updates

Update PingCastle weekly, but ensure each release has been out for at least 7 days:

```bash
PingCastleAutoUpdater.exe --wait-for-days 7
```

### Scenario 2: Test Update on Non-Production System

Before applying an update to production:

```bash
# First, test on a non-production system
PingCastleAutoUpdater.exe --dry-run

# Review the output and preview reports

# If everything looks good, apply the actual update
PingCastleAutoUpdater.exe
```

### Scenario 3: Early Access to New Features

Get the latest features (including beta/preview versions):

```bash
PingCastleAutoUpdater.exe --use-preview
```

### Scenario 4: Automated Update in Batch Script

Use in a scheduled task or batch script with dry-run first for logging:

```batch
REM Test update (logs to console)
PingCastleAutoUpdater.exe --dry-run > update_preview.log

REM Apply update if preview succeeded
if %ERRORLEVEL% EQU 0 (
    PingCastleAutoUpdater.exe
)
```

### Scenario 5: Force Reinstall of Current Version

Rebuild your installation from the latest released version:

```bash
PingCastleAutoUpdater.exe --force-download --dry-run
# Review changes

PingCastleAutoUpdater.exe --force-download
```

### Scenario 6: First-Time Auto-Updater with Legacy XML Configuration

When an existing user runs the auto-updater for the first time and has both XML and JSON configurations:

```bash
PingCastleAutoUpdater.exe
```

The tool will:
1. Detect both `PingCastle.exe.config` and `appsettings.console.json`
2. Perform initial state migration:
   - Convert XML settings to JSON format
   - Merge XML settings into the existing JSON (XML values take precedence)
   - Archive the legacy XML configuration file as `PingCastle.exe.config.bak` for potential recovery
   - Save a detailed migration report
3. Proceed with downloading and installing the latest update
4. Generate a second report documenting the update's configuration changes

This ensures smooth transition for long-time users upgrading to the new JSON-based configuration system. The original XML configuration is archived and can be restored if needed.

## Configuration Management

### Configuration Migration Phases

PingCastleAutoUpdater handles configuration in two phases:

#### Phase 1: Initial State Migration (Pre-Update)
When the tool first runs, it checks if both legacy XML and modern JSON configurations exist. If so:
- Creates a temporary backup of the existing JSON configuration
- Converts the XML configuration to JSON format
- Merges the converted XML into the existing JSON (XML values take precedence)
- Archives the old XML configuration file as `PingCastle.exe.config.bak` for potential recovery
- Generates an initial state migration report
- Proceeds with the normal update process

This phase ensures existing users' legacy configurations are migrated before the first auto-update. The archived XML file is preserved so you can restore it if needed.

**Example:** An existing user with `PingCastle.exe.config` and `appsettings.console.json` will have their XML settings merged into JSON with XML values taking priority. The original `PingCastle.exe.config` is preserved as `PingCastle.exe.config.bak`.

#### Phase 2: Post-Update Configuration Handling (During/After Update)
During the update extraction:
- **Backup**: New configurations are temporarily stored with `tempNew_` prefix
- **Merge**: Configurations are intelligently merged with existing settings
- **Conversion**: If needed, additional XML-to-JSON conversions are performed
- **Preservation**: Custom settings are preserved across versions

### Configuration Files

The tool manages these configuration files:

- `PingCastle.exe.config` - Legacy XML configuration (for .NET Framework versions) - archived to `.bak` during first run migration
- `appsettings.console.json` - Current JSON configuration (for .NET 10 version)
- `appsettings.console.json.bak` - Backup of previous JSON configuration
- `PingCastle.exe.config.bak` - Archived legacy XML configuration (preserved for potential recovery)

## Understanding Output

### Successful Update with Initial State Migration

When an existing user with both XML and JSON configurations runs the updater:

```
Getting the list of releases
Done
Latest release is: PingCastle 3.3.0.0

Update available: 3.2.0.0 -> PingCastle 3.3.0.0
Downloading https://github.com/netwrix/pingcastle/releases/download/...

Detected both XML and JSON configuration files.
Performing initial state migration...

Configuration migration completed successfully!
Archived old configuration file: PingCastle.exe.config → PingCastle.exe.config.bak
Initial state migration report saved: InitialStateMigration_20240115_143022.txt

Saving PingCastle.exe
Saving PingCastleCommon.dll
Saving config/settings.json
Config files merged successfully!
[OK] Configuration conversion completed successfully!
[Info] Detailed report saved: ConversionReport_20240115_143022.txt
```

Notice the two reports generated:
1. `InitialStateMigration_*.txt` - Documents the pre-update XML-to-JSON migration and archiving
2. `ConversionReport_*.txt` - Documents the post-update configuration merge

The original `PingCastle.exe.config` is archived as `PingCastle.exe.config.bak` and can be restored if needed.

### Successful Update without Initial Migration

```
Getting the list of releases
Done
Latest release is: PingCastle 3.3.0.0

Update available: 3.2.0.0 -> PingCastle 3.3.0.0
Downloading https://github.com/netwrix/pingcastle/releases/download/...

Saving PingCastle.exe
Saving PingCastleCommon.dll
Saving config/settings.json
Config files merged successfully!
[OK] Configuration conversion completed successfully!
[Info] Detailed report saved: ConversionReport_20240115_143022.txt
```

### No Update Required

```
Getting the list of releases
Done
Latest release is: PingCastle 3.3.0.0

Current version 3.3.0.0 is up to date with latest release PingCastle 3.3.0.0
Update is not required. Program is stopping.
```

### Dry-Run with Initial State Migration

When testing with both XML and JSON configurations present:

```
[DRY-RUN] Detected both XML and JSON configuration files.
[DRY-RUN] Would perform initial state migration...

[DRY-RUN] Configuration migration would complete successfully!
[DRY-RUN] Would archive old configuration file: PingCastle.exe.config → PingCastle.exe.config.bak
Initial state migration preview report saved: InitialStateMigration_Preview_20240115_143022.txt

[DRY-RUN] No files will be modified. Analyzing update contents...

[DRY-RUN] Would save PingCastle.exe
[DRY-RUN] Would merge .config file: PingCastle.exe.config
[DRY-RUN MODE - NO CHANGES WILL BE MADE]

Analyzing configuration conversion...
[OK] Analysis completed - Configuration would be converted successfully

[Report] Preview report saved: ConversionPreview_20240115_143022.txt
[Data] Sections to convert: 5
[Settings] Settings to map: 24
[WARNING] Custom elements found: 2 (would be preserved in _unmappedXmlSettings)

To proceed with conversion, run without --dry-run flag.
```

The preview includes both the initial migration that would happen and the post-update configuration handling.

### Dry-Run with Standard Configuration Migration

```
[DRY-RUN] No files will be modified. Analyzing update contents...

[DRY-RUN] Would save PingCastle.exe
[DRY-RUN] Would merge .config file: PingCastle.exe.config
[DRY-RUN MODE - NO CHANGES WILL BE MADE]

Analyzing configuration conversion...
[OK] Analysis completed - Configuration would be converted successfully

[Report] Preview report saved: ConversionPreview_20240115_143022.txt
[Data] Sections to convert: 5
[Settings] Settings to map: 24
[WARNING] Custom elements found: 2 (would be preserved in _unmappedXmlSettings)

To proceed with conversion, run without --dry-run flag.
```

## Reports and Logs

After updates, the tool may generate several report files in the PingCastle directory:

### Migration and Conversion Reports

- `InitialStateMigration_*.txt` - Details of pre-update XML-to-JSON migration when both XML and JSON configs existed initially
  - Tracks which XML sections were converted
  - Documents which settings were merged into JSON
  - Shows which XML values took precedence over existing JSON values
  - Lists any custom XML elements that were preserved

- `ConversionReport_*.txt` - Details of post-update XML to JSON configuration conversion and merging
  - Documents any XML-to-JSON conversions during the update
  - Shows which settings were merged with update versions
  - Lists configuration changes and migrations
  - Provides audit trail for troubleshooting

### Preview Reports (Dry-Run Mode)

- `InitialStateMigration_Preview_*.txt` - Preview of initial state migration without making changes
- `ConversionPreview_*.txt` - Preview of post-update configuration migration without making changes

### Custom Settings

- `_unmappedXmlSettings` - Custom XML settings that couldn't be automatically migrated (preserved for manual review)

**Recommendations:**
- Review migration reports after the first update to confirm settings were preserved correctly
- Keep reports for audit and troubleshooting purposes
- Use dry-run reports to validate changes before applying actual updates

## Troubleshooting

### "No current version detected"

The tool couldn't find `pingcastle.exe` in the same directory as the updater. This is normal for first-time updates. The tool will proceed with the download.

```
No current version detected - download will proceed
```

### Initial State Migration Failed

If migration of XML to JSON fails during the first run:

```
Error during initial state migration: [error details]
Restoring original configuration files...
Original JSON configuration restored.
Initial state migration error report saved...
```

**What happens:**
- Your original JSON configuration is restored from the temporary backup
- An error report is saved with details about what failed
- The update continues using your existing configuration
- You can manually review and merge settings if needed

**Next steps:**
1. Check the error report for details
2. Run with `--dry-run` to preview the migration
3. Contact support with the error report if the issue persists

### Configuration Merge Failed (Post-Update)

If configuration merging fails during the update phase:

```
Warning: Could not backup existing JSON config: [error details]
```

Your previous configuration is preserved as a `.bak` file. You may need to manually review and merge settings.

### Mixed Configuration Warning

If you encounter issues with both XML and JSON configurations:

```
Detected both XML and JSON configuration files.
Performing initial state migration...
```

This is expected behavior on first run. The tool will:
1. Migrate your XML settings to JSON format
2. Archive the legacy XML file as `PingCastle.exe.config.bak` after successful migration
3. Generate a detailed report of what was migrated

The original XML configuration is preserved and can be restored if needed.

### Network Issues

If GitHub is unreachable or the API returns an error:

```
Network error: [error details]
```

Check your network connectivity. You can optionally specify a custom API URL with `--api-url` if GitHub is inaccessible from your network.

## Running as Scheduled Task

To automate updates on a Windows system, you can set up a scheduled task:

1. Open Task Scheduler
2. Create Basic Task
3. Set trigger (e.g., weekly)
4. Set action: Start `PingCastleAutoUpdater.exe` in the PingCastle directory
5. Optional: Add arguments like `--wait-for-days 7`

Example PowerShell command to create a task:

```powershell
$taskAction = New-ScheduledTaskAction -Execute "C:\PingCastle\PingCastleAutoUpdater.exe"
Register-ScheduledTask -TaskName "PingCastle Auto Update" -Action $taskAction -Trigger (New-ScheduledTaskTrigger -Weekly -DaysOfWeek Sunday -At 2AM) -Principal (New-ScheduledTaskPrincipal -UserID "SYSTEM" -LogonType ServiceAccount)
```

## Output Format

The PingCastleAutoUpdater generates reports using ASCII-only characters for maximum compatibility. The following character codes are used in output:

- `[OK]` indicates successful operations (replaces checkmark ✓)
- `[FAILED]` indicates failed operations (replaces X mark ✗)
- `[WARNING]` indicates warnings or issues to review (replaces ⚠)
- `[Info]` indicates informational messages (replaces ℹ)
- `[Report]` indicates report file references (replaces 📋)
- `[Data]` indicates data statistics (replaces 📊)
- `[Settings]` indicates configuration information (replaces ⚙)
- `->` indicates transformations or mappings (replaces →)
- `-` indicates list items (replaces • or -)
- `=` indicates section separators (replaces ═)

Reports are generated with clear ASCII separators and structure for easy parsing and compatibility with all terminal and system environments.

## Safety Considerations

- **Backup First**: The tool automatically backs up configurations, but consider backing up the entire PingCastle directory before the first update
- **Initial Migration**: If you have both XML and JSON configurations, the tool will automatically migrate them on first run. Review the generated migration report to ensure all settings were preserved. The original XML file is archived as `PingCastle.exe.config.bak`
- **Test Updates**: Always use `--dry-run` on a test system before deploying to production, especially for the first update
- **Review Reports**: Check generated conversion and migration reports to ensure your settings are being preserved correctly
- **Verify Installation**: After each update, verify that PingCastle still functions correctly in your environment
- **Restore from Backup**: If something goes wrong, XML and JSON configurations are backed up as `.bak` files for recovery

## Recovery and Restoration

If you need to restore the original XML configuration:

1. **Locate the archived configuration**: Look for `PingCastle.exe.config.bak` in the PingCastle directory
2. **Restore the file**: Rename `PingCastle.exe.config.bak` back to `PingCastle.exe.config`
3. **Verify**: Check that your original settings are present in the restored file
4. **Run the tool again**: The auto-updater will detect both files and perform the migration again

If you need to restore a JSON configuration backup:

1. **Locate the backup**: Look for `appsettings.console.json.bak` in the PingCastle directory
2. **Restore the file**: Copy `appsettings.console.json.bak` over `appsettings.console.json`
3. **Verify**: Check that your settings are correct before running PingCastle

**Note**: Backup files (`.bak`) are preserved indefinitely and are never automatically deleted. You should periodically clean up old backup files to conserve disk space.

## Support

For issues with PingCastle updates or the Auto Updater tool, visit the [PingCastle GitHub repository](https://github.com/netwrix/pingcastle).
