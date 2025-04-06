# Security Crawler MCP

A web security crawler using headless Chrome that integrates with Claude Desktop via Model Context Protocol (MCP).

## Features

- 🕸️ Website crawling with headless Chrome
- 🔍 URL discovery and mapping
- 🔒 Security vulnerability scanning
- 📊 Detailed security reports
- 🤖 Claude Desktop integration via MCP

## Simple Setup

### Prerequisites

- Python 3.10+
- Chrome or Chromium browser
- Claude Desktop (for MCP integration)

### Installation

1. Clone the repository:

```bash
git clone https://github.com/cowsecurity/security-crawler-mcp.git
cd security-crawler-mcp
```

2. Create and activate a virtual environment:

```bash
# Using uv (recommended)
uv init
uv venv
.venv\Scripts\activate  # Windows
source .venv/bin/activate  # Mac/Linux
```

3. Install dependencies:

```bash
# Using uv
uv add "mcp[cli]" selenium webdriver-manager beautifulsoup4 requests
```

### Claude Desktop Integration

1. Configure Claude Desktop to use the MCP server:

```bash
# Edit the Claude Desktop config file at:
# Windows: %AppData%\Roaming\Claude\claude_desktop_config.json
```

2. Add the following configuration (adjust paths as needed):

```json
{
  "mcpServers": {
    "security_crawler": {
      "command": "uv",
      "args": [
        "run",
        "--directory",
        "C:\\ABSOLUTE\\PATH\\TO\\security-crawler-mcp",
        "main.py"
      ]
    }
  }
}
```

3. Restart Claude Desktop to apply changes.

## Usage

### As an MCP Tool with Claude Desktop

1. Start a conversation with Claude
2. Look for the tools icon (hammer 🔨)
3. Ask Claude to use the security tools:

```
Can you fetch URLs from example.com using the security crawler?
```

or

```
Please analyze the security of example.com with a maximum of 5 pages.
```

### Available Tools

The MCP server provides the following tools:

1. **echo_hello** - Simple test function to verify connectivity
2. **fetch_urls** - Crawls a website and returns discovered URLs
3. **analyze_security** - Performs security analysis on a website

## Security Considerations

- Only scan websites you have permission to test
- Some websites may block automated crawling
- This tool provides basic security scanning and is not a replacement for professional security testing
- Use responsibly and ethically

## Disclaimer

This tool is for educational and legitimate security testing purposes only. Always obtain proper authorization before scanning any website. The authors are not responsible for any misuse of this software.