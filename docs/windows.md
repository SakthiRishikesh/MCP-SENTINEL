# Running MCP-Sentinel on Windows

For local filesystem MCP servers, run the Sentinel API on the Windows host. A Sentinel API
inside Docker sees the container's filesystem; it does not see `C:\` unless you explicitly
bind-mount host folders into the container.

## Start the Windows host version

Open PowerShell in the repository and run:

```powershell
py -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\start-windows.ps1
```

The script serves the built dashboard at `http://localhost:8443/app/`, stores local state under
`%LOCALAPPDATA%\MCP-Sentinel`, and uses SQLite without requiring Docker Desktop. If the dashboard
build is missing, install and build the frontend from the `dashboard` and `web` directories first.
The Python launcher and Node.js are needed for local stdio servers; Sentinel resolves Windows
launchers such as `npx.cmd` from `PATH`.

## Connect the Filesystem server to C:

In **Servers -> Connect server -> Local (stdio)**, choose the Filesystem preset and replace its
folder placeholder with `C:\`. Keep the command and pinned package version from the preset. The
server then permits paths under C:; Sentinel still applies its policy checks and redacts sensitive
output. Local Windows paths only work when the Sentinel API itself is running on Windows (or when
the relevant host folder is explicitly mounted into its container).

To find a text file without choosing a fixed filename, use the Filesystem server's `search_files`
tool with the glob pattern `**/*.txt` under the allowed root. Use a returned path with `read_text_file`, then
write the returned text with `write_file` to the destination path selected for that call. This
duplicates text content while leaving the source intact. The destination must also be within the
server's allowed root. The model can repeat this with any discovered `.txt` path; no source filename
is embedded in Sentinel.

## Safe functional check

Use a temporary folder and a generated `.txt` file for the first check. Register the Filesystem
server with that temporary folder as its root, search for `*.txt`, read the result, write it to a
different destination in the same temporary folder, then read the copy and compare the contents.
This exercises dynamic discovery and duplication through the normal MCP tools without touching
existing documents. After it works, change the allowed root to `C:\` if whole-drive access is
needed.

Granting `C:\` makes the upstream server able to enumerate user and system directories subject to
Windows permissions. Sentinel's shadow workspace has per-root limits (`SENTINEL_SANDBOX_MAX_FILES`
and `SENTINEL_SANDBOX_MAX_BYTES`); using the drive root can make mirror synchronization expensive.
For normal use, a smaller folder root is faster and easier to review.
