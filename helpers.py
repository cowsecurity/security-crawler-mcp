import sys
import time
import re
from urllib.parse import urlparse, urljoin
from typing import List, Dict, Set, Any
from bs4 import BeautifulSoup
import requests

# Selenium imports
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException, WebDriverException
from webdriver_manager.chrome import ChromeDriverManager

# Set up logging
def log(message: str) -> None:
    """Log a message to stderr for visibility in Claude Desktop logs"""
    print(f"[CRAWLER] {message}", file=sys.stderr)

class HeadlessCrawler:
    def __init__(self, headless: bool = True, timeout: int = 10):
        """Initialize the headless Chrome crawler
        
        Args:
            headless: Whether to run Chrome in headless mode
            timeout: Default timeout for page loading in seconds
        """
        self.timeout = timeout
        self.driver = None
        self.visited_urls: Set[str] = set()
        self.found_urls: Set[str] = set()
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36'
        }
        
        # Initialize driver with options
        self._setup_driver(headless)
        
    def _setup_driver(self, headless: bool) -> None:
        """Set up the Chrome WebDriver with appropriate options"""
        log("Setting up Chrome WebDriver...")
        
        options = Options()
        if headless:
            options.add_argument("--headless=new")
        
        # Security-focused options
        options.add_argument("--disable-gpu")
        options.add_argument("--no-sandbox")
        options.add_argument("--disable-dev-shm-usage")
        options.add_argument("--disable-extensions")
        options.add_argument("--disable-infobars")
        options.add_argument("--window-size=1920,1080")
        
        # Avoid detection
        options.add_experimental_option("excludeSwitches", ["enable-automation"])
        options.add_experimental_option
        ("useAutomationExtension", False)
        options.binary_location= "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe"

        try:
            service = Service(ChromeDriverManager().install())
            self.driver = webdriver.Chrome(service=service, options=options)
            self.driver.set_page_load_timeout(self.timeout)
            log("Chrome WebDriver initialized successfully")
        except Exception as e:
            log(f"Error initializing Chrome WebDriver: {str(e)}")
            raise
    
    def close(self) -> None:
        """Close the WebDriver and release resources"""
        if self.driver:
            self.driver.quit()
            self.driver = None
            log("Chrome WebDriver closed")
    
    def fetch_url(self, url: str) -> Dict[str, Any]:
        """Fetch a URL and return page info with both requests and Selenium
        
        Args:
            url: The URL to fetch
            
        Returns:
            Dict containing page info, HTML content, and status
        """
        log(f"Fetching URL: {url}")
        result = {
            "url": url,
            "title": "",
            "html": "",
            "text": "",
            "status": 0,
            "links": [],
            "success": False,
            "error": None
        }
        
        # First try with requests for speed and efficiency
        try:
            response = requests.get(url, headers=self.headers, timeout=self.timeout)
            result["status"] = response.status_code
            result["html"] = response.text
            
            # Parse with BeautifulSoup for basic extraction
            soup = BeautifulSoup(response.text, "html.parser")
            result["title"] = soup.title.string if soup.title else ""
            result["text"] = soup.get_text()
            result["success"] = True
            
            # If we need JavaScript rendering, use Selenium
            if self._needs_js_rendering(soup):
                log(f"Detected JavaScript-heavy page, using Selenium for: {url}")
                self._fetch_with_selenium(url, result)
            
        except Exception as e:
            log(f"Requests fetch failed, falling back to Selenium for: {url}")
            log(f"Error: {str(e)}")
            self._fetch_with_selenium(url, result)
        
        # Extract links from the page
        if result["html"]:
            result["links"] = self._extract_links(url, result["html"])
            # Update the master list of found URLs
            self.found_urls.update(result["links"])
            # Mark this URL as visited
            self.visited_urls.add(url)
            
        return result
    
    def _fetch_with_selenium(self, url: str, result: Dict[str, Any]) -> None:
        """Fetch a URL using Selenium WebDriver
        
        Args:
            url: The URL to fetch
            result: The result dictionary to update
        """
        if not self.driver:
            self._setup_driver(True)
            
        try:
            self.driver.get(url)
            
            # Wait for page to load
            WebDriverWait(self.driver, self.timeout).until(
                EC.presence_of_element_located((By.TAG_NAME, "body"))
            )
            
            # Get page info
            result["html"] = self.driver.page_source
            result["title"] = self.driver.title
            result["text"] = self.driver.find_element(By.TAG_NAME, "body").text
            result["status"] = 200  # Assume success if no exception
            result["success"] = True
            
            # Take a screenshot for security analysis
            # self.driver.save_screenshot(f"screenshot_{urlparse(url).netloc}.png")
            
        except TimeoutException:
            log(f"Timeout while loading: {url}")
            result["error"] = "Timeout error"
        except WebDriverException as e:
            log(f"WebDriver error for {url}: {str(e)}")
            result["error"] = f"WebDriver error: {str(e)}"
        except Exception as e:
            log(f"Unexpected error fetching {url}: {str(e)}")
            result["error"] = f"Error: {str(e)}"
    
    def _needs_js_rendering(self, soup: BeautifulSoup) -> bool:
        """Determine if a page likely needs JavaScript rendering
        
        Args:
            soup: BeautifulSoup object of the page
            
        Returns:
            True if the page likely needs JS rendering
        """
        # Look for signs of JavaScript-dependent content
        scripts = soup.find_all("script")
        spa_frameworks = [
            "react", "vue", "angular", "ember", "backbone", "svelte", 
            "jquery", "axios", "fetch("
        ]
        
        # Check for SPA frameworks
        for script in scripts:
            script_text = str(script).lower()
            for framework in spa_frameworks:
                if framework in script_text:
                    return True
        
        # Check for minimal content in body
        body = soup.find("body")
        if body and len(body.get_text(strip=True)) < 100:
            return True
            
        return False
    
    def _extract_links(self, base_url: str, html: str) -> List[str]:
        """Extract links from HTML content
        
        Args:
            base_url: The base URL for resolving relative links
            html: The HTML content to parse
            
        Returns:
            List of absolute URLs found in the page
        """
        links = []
        parsed_base = urlparse(base_url)
        base_domain = parsed_base.netloc
        
        try:
            soup = BeautifulSoup(html, "html.parser")
            
            # Extract links from a, link, script, img, form tags
            for tag_name, attr in [
                ("a", "href"), ("link", "href"), 
                ("script", "src"), ("img", "src"),
                ("form", "action")
            ]:
                for tag in soup.find_all(tag_name):
                    if tag.has_attr(attr):
                        url = tag[attr]
                        # Convert to absolute URL
                        absolute_url = urljoin(base_url, url)
                        parsed_url = urlparse(absolute_url)
                        
                        # Filter out non-http(s) schemes
                        if parsed_url.scheme not in ('http', 'https'):
                            continue
                            
                        # Only include URLs from the same domain
                        if parsed_url.netloc == base_domain:
                            links.append(absolute_url)
            
            # Also look for URLs in JavaScript
            for script in soup.find_all("script"):
                script_text = script.string
                if script_text:
                    # Find URLs in JavaScript using regex
                    url_patterns = [
                        r'https?://[^\s\'"]+',
                        r'[\'"]\/[^\s\'"/][^\s\'"]*[\'"]'
                    ]
                    for pattern in url_patterns:
                        for match in re.finditer(pattern, script_text):
                            url = match.group(0).strip('\'"')
                            absolute_url = urljoin(base_url, url)
                            parsed_url = urlparse(absolute_url)
                            
                            # Filter as above
                            if (parsed_url.scheme in ('http', 'https') and 
                                parsed_url.netloc == base_domain):
                                links.append(absolute_url)
        
        except Exception as e:
            log(f"Error extracting links from {base_url}: {str(e)}")
        
        # Remove duplicates and return
        return list(set(links))
    
    def crawl(self, start_url: str, max_urls: int = 10, same_domain_only: bool = True) -> Dict[str, Any]:
        """Crawl a website starting from a given URL
        
        Args:
            start_url: The URL to start crawling from
            max_urls: Maximum number of URLs to crawl
            same_domain_only: Whether to stay on the same domain
            
        Returns:
            Dict with crawl results including found URLs and page data
        """
        log(f"Starting crawl from {start_url} (max: {max_urls} URLs)")
        
        to_visit = [start_url]
        visited_data = {}
        domain = urlparse(start_url).netloc
        
        try:
            while to_visit and len(visited_data) < max_urls:
                current_url = to_visit.pop(0)
                
                # Skip if already visited
                if current_url in self.visited_urls:
                    continue
                
                # Check domain constraint
                if same_domain_only and urlparse(current_url).netloc != domain:
                    continue
                
                # Fetch and process URL
                result = self.fetch_url(current_url)
                visited_data[current_url] = result
                
                # Add new links to visit queue
                new_links = [url for url in result["links"] 
                            if url not in self.visited_urls 
                            and url not in to_visit]
                to_visit.extend(new_links)
                
                # Small delay to avoid overloading the server
                time.sleep(0.5)
        
        except Exception as e:
            log(f"Error during crawl: {str(e)}")
        
        finally:
            crawl_result = {
                "start_url": start_url,
                "pages_visited": len(visited_data),
                "total_urls_found": len(self.found_urls),
                "visited_data": visited_data,
                "all_urls": list(self.found_urls)
            }
            
            return crawl_result


class SecurityAnalyzer:
    """Analyze crawled pages for security issues"""
    
    def __init__(self):
        self.security_patterns = {
            "api_keys": [
                r'api[_-]?key[^a-zA-Z0-9]([a-zA-Z0-9]{20,})',
                r'access[_-]?token[^a-zA-Z0-9]([a-zA-Z0-9]{20,})',
                r'secret[^a-zA-Z0-9]([a-zA-Z0-9]{20,})'
            ],
            "vulnerabilities": {
                "xss": [
                    r'<script>.*?</script>',
                    r'javascript:.*?\(',
                    r'on(click|load|mouseover|error|focus)=',
                ],
                "sql_injection": [
                    r'union\s+select',
                    r'waitfor\s+delay',
                    r'1=1--',
                    r"'OR\s+'1'='1",
                ],
                "open_redirect": [
                    r'redirect=http',
                    r'url=http',
                    r'goto=http',
                    r'return_to=http',
                ],
                "file_inclusion": [
                    r'\.\./\.\.',
                    r'file=/',
                    r'path=/',
                    r'include=/',
                ],
            },
            "sensitive_files": [
                r'\.git/',
                r'\.env',
                r'wp-config\.php',
                r'config\.php',
                r'\.htaccess',
                r'\.ssh/',
                r'backup',
                r'dump\.sql',
            ],
            "server_info": [
                r'apache/[\d\.]+',
                r'nginx/[\d\.]+',
                r'php/[\d\.]+',
                r'server:([^\n]+)',
                r'x-powered-by:([^\n]+)',
            ]
        }
    
    def analyze_page(self, page_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze a single page for security issues
        
        Args:
            page_data: Page data dict from crawler
            
        Returns:
            Dict with analysis results
        """
        analysis = {
            "url": page_data["url"],
            "findings": {
                "api_keys": [],
                "vulnerabilities": {
                    "xss": [],
                    "sql_injection": [],
                    "open_redirect": [],
                    "file_inclusion": []
                },
                "sensitive_files": [],
                "server_info": []
            }
        }
        
        # Combine HTML and text for analysis
        content = page_data["html"] + " " + page_data["text"]
        
        # Check for API keys
        for pattern in self.security_patterns["api_keys"]:
            matches = re.findall(pattern, content, re.IGNORECASE)
            if matches:
                analysis["findings"]["api_keys"].extend(matches)
        
        # Check for vulnerabilities
        for vuln_type, patterns in self.security_patterns["vulnerabilities"].items():
            for pattern in patterns:
                matches = re.findall(pattern, content, re.IGNORECASE)
                if matches:
                    # Limit matches to avoid large output
                    analysis["findings"]["vulnerabilities"][vuln_type].extend(matches[:5])
        
        # Check for sensitive files
        for pattern in self.security_patterns["sensitive_files"]:
            for url in page_data["links"]:
                if re.search(pattern, url, re.IGNORECASE):
                    analysis["findings"]["sensitive_files"].append(url)
        
        # Check for server info in headers
        for pattern in self.security_patterns["server_info"]:
            matches = re.findall(pattern, content, re.IGNORECASE)
            if matches:
                analysis["findings"]["server_info"].extend(matches)
        
        return analysis
    
    def analyze_crawl_results(self, crawl_results: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze all pages from a crawl
        
        Args:
            crawl_results: Results from crawler.crawl()
            
        Returns:
            Dict with analysis of all pages
        """
        security_analysis = {
            "start_url": crawl_results["start_url"],
            "pages_analyzed": crawl_results["pages_visited"],
            "summary": {
                "api_keys_found": 0,
                "potential_vulnerabilities": {
                    "xss": 0,
                    "sql_injection": 0,
                    "open_redirect": 0,
                    "file_inclusion": 0
                },
                "sensitive_files": 0,
                "server_info_leaks": 0
            },
            "page_analyses": []
        }
        
        # Analyze each page
        for url, page_data in crawl_results["visited_data"].items():
            page_analysis = self.analyze_page(page_data)
            security_analysis["page_analyses"].append(page_analysis)
            
            # Update summary counts
            security_analysis["summary"]["api_keys_found"] += len(page_analysis["findings"]["api_keys"])
            security_analysis["summary"]["sensitive_files"] += len(page_analysis["findings"]["sensitive_files"])
            security_analysis["summary"]["server_info_leaks"] += len(page_analysis["findings"]["server_info"])
            
            # Count vulnerabilities
            for vuln_type, findings in page_analysis["findings"]["vulnerabilities"].items():
                security_analysis["summary"]["potential_vulnerabilities"][vuln_type] += len(findings)
        
        return security_analysis


# Helper functions for MCP server

def fetch_site_urls(url: str, max_urls: int = 10) -> Dict[str, Any]:
    """Fetch URLs from a website using headless Chrome
    
    Args:
        url: The starting URL
        max_urls: Maximum number of URLs to crawl
        
    Returns:
        Dict with crawl results
    """
    crawler = HeadlessCrawler(headless=True)
    try:
        results = crawler.crawl(url, max_urls=max_urls, same_domain_only=True)
        return {
            "success": True,
            "urls_found": len(results["all_urls"]),
            "pages_visited": results["pages_visited"],
            "all_urls": results["all_urls"],
            "start_url": url
        }
    except Exception as e:
        log(f"Error fetching site URLs: {str(e)}")
        return {
            "success": False,
            "error": str(e),
            "start_url": url
        }
    finally:
        crawler.close()

def analyze_site_security(url: str, max_urls: int = 5) -> Dict[str, Any]:
    """Analyze a website for security issues
    
    Args:
        url: The starting URL
        max_urls: Maximum number of URLs to crawl and analyze
        
    Returns:
        Dict with security analysis results
    """
    crawler = HeadlessCrawler(headless=True)
    analyzer = SecurityAnalyzer()
    
    try:
        crawl_results = crawler.crawl(url, max_urls=max_urls, same_domain_only=True)
        security_results = analyzer.analyze_crawl_results(crawl_results)
        
        return {
            "success": True,
            "url": url,
            "pages_analyzed": security_results["pages_analyzed"],
            "summary": security_results["summary"],
            "details": security_results["page_analyses"]
        }
    except Exception as e:
        log(f"Error analyzing site security: {str(e)}")
        return {
            "success": False,
            "error": str(e),
            "url": url
        }
    finally:
        crawler.close()

def format_security_report(analysis_results: Dict[str, Any]) -> str:
    """Format security analysis results into a readable report
    
    Args:
        analysis_results: Results from analyze_site_security()
        
    Returns:
        Formatted string report
    """
    if not analysis_results.get("success", False):
        return f"Error analyzing site: {analysis_results.get('error', 'Unknown error')}"
    
    report = []
    report.append(f"# Security Analysis Report for {analysis_results['url']}\n")
    report.append(f"Analyzed {analysis_results['pages_analyzed']} pages\n")
    
    # Summary section
    report.append("## Summary of Findings\n")
    summary = analysis_results["summary"]
    
    report.append(f"* API Keys Found: {summary['api_keys_found']}")
    report.append(f"* Sensitive Files Detected: {summary['sensitive_files']}")
    report.append(f"* Server Information Leaks: {summary['server_info_leaks']}")
    
    report.append("\n### Potential Vulnerabilities:")
    vulns = summary["potential_vulnerabilities"]
    report.append(f"* Cross-Site Scripting (XSS): {vulns['xss']}")
    report.append(f"* SQL Injection: {vulns['sql_injection']}")
    report.append(f"* Open Redirect: {vulns['open_redirect']}")
    report.append(f"* File Inclusion: {vulns['file_inclusion']}")
    
    # Details section
    report.append("\n## Detailed Findings\n")
    for page in analysis_results["details"]:
        url = page["url"]
        findings = page["findings"]
        
        # Only include pages with findings
        has_findings = (len(findings["api_keys"]) > 0 or
                      len(findings["sensitive_files"]) > 0 or
                      len(findings["server_info"]) > 0 or
                      any(len(v) > 0 for v in findings["vulnerabilities"].values()))
        
        if has_findings:
            report.append(f"### Page: {url}\n")
            
            if findings["api_keys"]:
                report.append("#### Potential API Keys/Secrets:")
                for key in findings["api_keys"]:
                    report.append(f"* `{key}`")
                report.append("")
            
            if findings["sensitive_files"]:
                report.append("#### Sensitive Files:")
                for file in findings["sensitive_files"]:
                    report.append(f"* {file}")
                report.append("")
            
            if findings["server_info"]:
                report.append("#### Server Information Leaks:")
                for info in findings["server_info"]:
                    report.append(f"* {info}")
                report.append("")
            
            # Vulnerabilities
            vuln_findings = findings["vulnerabilities"]
            if any(len(v) > 0 for v in vuln_findings.values()):
                report.append("#### Potential Vulnerabilities:")
                
                if vuln_findings["xss"]:
                    report.append("##### XSS:")
                    for xss in vuln_findings["xss"]:
                        report.append(f"* `{xss}`")
                
                if vuln_findings["sql_injection"]:
                    report.append("##### SQL Injection:")
                    for sql in vuln_findings["sql_injection"]:
                        report.append(f"* `{sql}`")
                
                if vuln_findings["open_redirect"]:
                    report.append("##### Open Redirect:")
                    for redir in vuln_findings["open_redirect"]:
                        report.append(f"* `{redir}`")
                
                if vuln_findings["file_inclusion"]:
                    report.append("##### File Inclusion:")
                    for fi in vuln_findings["file_inclusion"]:
                        report.append(f"* `{fi}`")
                report.append("")
    
    # Recommendations section
    report.append("## Recommendations\n")
    report.append("Based on the analysis, consider addressing the following:")
    
    if summary["api_keys_found"] > 0:
        report.append("* **Remove API keys and secrets** from client-side code")
    
    if summary["sensitive_files"] > 0:
        report.append("* **Restrict access to sensitive files** or remove them from public access")
    
    if summary["server_info_leaks"] > 0:
        report.append("* **Configure your server** to not disclose version information")
    
    if vulns["xss"] > 0:
        report.append("* **Implement proper input validation** and output encoding to prevent XSS attacks")
    
    if vulns["sql_injection"] > 0:
        report.append("* **Use parameterized queries** to prevent SQL injection attacks")
    
    if vulns["open_redirect"] > 0:
        report.append("* **Validate all redirect URLs** against a whitelist")
    
    if vulns["file_inclusion"] > 0:
        report.append("* **Restrict file access** and use proper validation for file paths")
    
    return "\n".join(report)