# Configuration Reloading Feature

## Overview
The system now supports dynamic configuration reloading without requiring a process restart. This allows you to add, remove, or update users while the proxy is running.

## Features

### 1. SIGHUP Signal Support
Send `SIGHUP` to the process to trigger configuration reload:
```bash
# Find the process ID
ps aux | grep go-s3-rbac-single-bucket

# Send SIGHUP signal
kill -HUP <PID>
```

### 2. Thread-Safe Updates
- User lookups use read locks for maximum concurrency
- Configuration updates use write locks for atomic updates
- No downtime or connection disruption during reloads

### 3. Automatic File Watching (Optional)
Enable automatic file watching by uncommenting in `main.go`:
```go
// Optional: Start file watcher for automatic reloads
ctx, cancel := context.WithCancel(context.Background())
defer cancel()
configReloader.WatchConfigFile(ctx, 30*time.Second)
```

## Usage Examples

### Adding a New User
1. Edit your `config.yaml` file:
```yaml
users:
  - access_key: "existing-user"
    secret_key: "existing-secret"
    allowed_buckets: ["bucket1"]
  - access_key: "new-user"          # ← Add this
    secret_key: "new-secret"        # ← Add this
    allowed_buckets: ["bucket2"]    # ← Add this
```

2. Trigger reload:
```bash
kill -HUP $(pgrep -f go-s3-rbac-single-bucket)
```

### Removing a User
1. Remove the user from `config.yaml`
2. Send SIGHUP signal
3. The user will be immediately denied access

### Updating User Permissions
1. Modify `allowed_buckets` in `config.yaml`
2. Send SIGHUP signal
3. New permissions take effect immediately

## Logging
The system logs configuration reload events:
```
INFO	configuration reloaded successfully
    config_path: "./config.yaml"
    old_user_count: 2
    new_user_count: 3
    user_count_delta: 1
```

## Error Handling
- Invalid configuration files are rejected
- Failed reloads don't affect current configuration
- Errors are logged with details

## Performance Considerations
- Read operations (user lookups) are highly concurrent
- Write operations (reloads) block briefly during update
- Memory usage optimized with map replacement (not incremental updates)

## Security
- Configuration validation occurs on every reload
- Invalid configurations are rejected
- No secrets exposed in logs

## Testing
Run the configuration reload tests:
```bash
go test -v -run TestConfigReloader
go test -v -run TestIdentityStoreThreadSafety
```