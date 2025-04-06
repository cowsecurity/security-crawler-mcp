from mcp.server.fastmcp import FastMCP

# Import helpers
from helpers import (fetch_site_urls, analyze_site_security, 
                    format_security_report, log)

# Initialize FastMCP server
mcp = FastMCP("security_crawler")

@mcp.tool()
async def echo_hello() -> str:
    """Echo 'hello' in the shell.
    
    Returns:
        A greeting message from the MCP server.
    """
    # Print to stderr so it appears in Claude Desktop logs
    log("HELLO from echo_hello tool!")
    return "Hello from Security Crawler MCP server!"

@mcp.tool()
async def fetch_urls(url: str, max_urls: int = 10) -> str:
    """Fetch URLs from a website using headless Chrome.
    
    Args:
        url: The starting URL to crawl
        max_urls: Maximum number of URLs to crawl (default: 10)
        
    Returns:
        JSON string with all discovered URLs
    """
    log(f"Fetching URLs from {url} (max: {max_urls})")
    
    try:
        # Call the helper function
        results = fetch_site_urls(url, max_urls)
        
        # Format the response
        if results["success"]:
            response = (
                f"Successfully crawled {url}\n\n"
                f"Found {results['urls_found']} URLs across {results['pages_visited']} pages:\n\n"
            )
            
            # Format URLs as a list
            for i, found_url in enumerate(results["all_urls"], 1):
                response += f"{i}. {found_url}\n"
                
            return response
        else:
            return f"Error crawling {url}: {results.get('error', 'Unknown error')}"
            
    except Exception as e:
        log(f"Error in fetch_urls: {str(e)}")
        return f"An error occurred while fetching URLs: {str(e)}"

@mcp.tool()
async def analyze_security(url: str, max_urls: int = 5) -> str:
    """Analyze a website for security vulnerabilities.
    
    Args:
        url: The starting URL to analyze
        max_urls: Maximum number of URLs to analyze (default: 5)
        
    Returns:
        Detailed security analysis report
    """
    log(f"Analyzing security for {url} (max: {max_urls})")
    
    try:
        # Run the security analysis
        results = analyze_site_security(url, max_urls)
        
        # Format the results as a report
        report = format_security_report(results)
        return report
            
    except Exception as e:
        log(f"Error in analyze_security: {str(e)}")
        return f"An error occurred during security analysis: {str(e)}"

if __name__ == "__main__":
    # Run with stdio transport
    log("Starting Security Crawler MCP server...")
    mcp.run(transport="stdio")