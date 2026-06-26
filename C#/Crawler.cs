using System.Text.RegularExpressions;

namespace SecurityTester;

/// <summary>
/// Represents a single discovered page during crawling.
/// </summary>
public class PageInfo
{
    public string   Url         { get; set; } = "";
    public int      Status      { get; set; }
    public int      Depth       { get; set; }
    public string   ContentType { get; set; } = "";
    public List<string> QueryParams { get; set; } = new();
    public bool     HasForms    { get; set; }
}

/// <summary>
/// Represents a discovered HTML form.
/// </summary>
public class FormInfo
{
    public string       Action  { get; set; } = "";
    public string       Method  { get; set; } = "GET";
    public List<string> Fields  { get; set; } = new();
    public string       FoundOn { get; set; } = "";
}

/// <summary>
/// Full site map produced by the crawler.
/// </summary>
public class SiteMap
{
    public string           StartUrl    { get; set; } = "";
    public List<PageInfo>   Pages       { get; set; } = new();
    public List<FormInfo>   Forms       { get; set; } = new();
    public List<string>     Endpoints   { get; set; } = new();  // URLs without query params
    public List<PageInfo>   ParamUrls   { get; set; } = new();  // URLs that have query params
    public int              TotalFound  => Pages.Count;
}

/// <summary>
/// Web crawler — visits the root URL and follows all internal links recursively.
/// Extracts pages, forms, endpoints, and query parameters for security testing.
/// </summary>
public class Crawler
{
    private static readonly string[] IgnoredExtensions =
    {
        ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp",
        ".pdf", ".zip", ".tar", ".gz", ".mp4", ".mp3", ".woff",
        ".woff2", ".ttf", ".eot", ".css", ".map", ".js"
    };

    private readonly HttpClient _client;
    private readonly int        _maxPages;
    private readonly int        _maxDepth;
    private readonly int        _delayMs;
    private readonly bool       _verbose;

    public Crawler(HttpClient client, int maxPages = 100, int maxDepth = 4, int delayMs = 100, bool verbose = true)
    {
        _client   = client;
        _maxPages = maxPages;
        _maxDepth = maxDepth;
        _delayMs  = delayMs;
        _verbose  = verbose;
    }

    public async Task<SiteMap> CrawlAsync(string startUrl)
    {
        var siteMap  = new SiteMap { StartUrl = startUrl };
        var visited  = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var queue    = new Queue<(string Url, int Depth)>();
        var endpoints = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        queue.Enqueue((startUrl, 0));

        if (_verbose)
        {
            Console.WriteLine($"\n   🕷️  Crawler starting...");
            Console.WriteLine($"   Max pages : {_maxPages}");
            Console.WriteLine($"   Max depth : {_maxDepth}\n");
        }

        while (queue.Count > 0 && visited.Count < _maxPages)
        {
            var (url, depth) = queue.Dequeue();

            if (visited.Contains(url))  continue;
            if (depth > _maxDepth)      continue;

            visited.Add(url);

            if (_verbose)
                Console.Write($"\r   Crawling [{visited.Count}/{_maxPages}]: {url.PadRight(80).Substring(0, Math.Min(url.Length, 75))}...");

            string? body        = null;
            int     status      = 0;
            string  contentType = "";

            try
            {
                var res = await _client.GetAsync(url);
                status      = (int)res.StatusCode;
                contentType = res.Content.Headers.ContentType?.MediaType ?? "";

                if (contentType.Contains("text/html") || contentType.Contains("application/json"))
                    body = await res.Content.ReadAsStringAsync();
            }
            catch { continue; }

            if (status == 404) continue;

            // Build page record
            var pageInfo = new PageInfo
            {
                Url         = url,
                Status      = status,
                Depth       = depth,
                ContentType = contentType,
                QueryParams = ExtractQueryParams(url),
            };

            // Track endpoint (path without query string)
            if (Uri.TryCreate(url, UriKind.Absolute, out var parsedUri))
            {
                var ep = $"{parsedUri.Scheme}://{parsedUri.Host}{parsedUri.AbsolutePath}";
                endpoints.Add(ep.TrimEnd('/'));
            }

            // Track pages with query params
            if (pageInfo.QueryParams.Count > 0)
                siteMap.ParamUrls.Add(pageInfo);

            // Parse HTML
            if (body != null && contentType.Contains("text/html"))
            {
                // Extract forms
                var forms = ExtractForms(url, body);
                if (forms.Count > 0)
                {
                    pageInfo.HasForms = true;
                    siteMap.Forms.AddRange(forms);
                }

                // Extract and queue links
                if (depth < _maxDepth)
                {
                    var links = ExtractLinks(url, body);
                    foreach (var link in links)
                    {
                        if (!visited.Contains(link))
                            queue.Enqueue((link, depth + 1));
                    }
                }
            }

            siteMap.Pages.Add(pageInfo);

            if (_delayMs > 0 && queue.Count > 0)
                await Task.Delay(_delayMs);
        }

        siteMap.Endpoints = endpoints.ToList();

        if (_verbose)
        {
            Console.WriteLine();
            Console.WriteLine($"\n   ✅ Crawl complete: {siteMap.Pages.Count} pages, {siteMap.Forms.Count} forms, {siteMap.Endpoints.Count} endpoints\n");
        }

        return siteMap;
    }

    // ── Private helpers ───────────────────────────────────────

    private List<string> ExtractLinks(string baseUrl, string html)
    {
        var links   = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var baseUri = new Uri(baseUrl);

        // href, action, src attributes
        var attrPattern = new Regex(@"(?:href|action|src)=[""']([^""'#>]+)[""']", RegexOptions.IgnoreCase);
        foreach (Match m in attrPattern.Matches(html))
            links.Add(m.Groups[1].Value.Trim());

        // API endpoints in JS (fetch, axios calls)
        var apiPattern = new Regex(@"(?:fetch|get|post|put|delete|axios)\s*\(\s*[""'`](/[^""'`\s]+)[""'`]", RegexOptions.IgnoreCase);
        foreach (Match m in apiPattern.Matches(html))
            links.Add(m.Groups[1].Value.Trim());

        // Resolve to absolute, filter to same origin
        var resolved = new List<string>();
        foreach (var link in links)
        {
            try
            {
                var abs = new Uri(baseUri, link);
                if (abs.Host != baseUri.Host) continue;

                // Skip ignored extensions
                var path = abs.AbsolutePath.ToLower();
                if (IgnoredExtensions.Any(ext => path.EndsWith(ext))) continue;

                // Remove fragment
                var clean = abs.GetLeftPart(UriPartial.Query);
                resolved.Add(clean);
            }
            catch { }
        }

        return resolved;
    }

    private List<FormInfo> ExtractForms(string pageUrl, string html)
    {
        var forms       = new List<FormInfo>();
        var formPattern = new Regex(@"<form[^>]*>([\s\S]*?)<\/form>", RegexOptions.IgnoreCase);
        var baseUri     = new Uri(pageUrl);

        foreach (Match formMatch in formPattern.Matches(html))
        {
            var formHtml = formMatch.Value;

            var actionMatch = Regex.Match(formHtml, @"action=[""']([^""'>]+)[""']", RegexOptions.IgnoreCase);
            var methodMatch = Regex.Match(formHtml, @"method=[""']([^""'>]+)[""']", RegexOptions.IgnoreCase);

            string action;
            try   { action = new Uri(baseUri, actionMatch.Success ? actionMatch.Groups[1].Value : "").ToString(); }
            catch { action = pageUrl; }

            var method = methodMatch.Success ? methodMatch.Groups[1].Value.ToUpper() : "GET";
            var fields = new List<string>();

            foreach (Match input in Regex.Matches(formHtml, @"<input[^>]*name=[""']([^""'>]+)[""']", RegexOptions.IgnoreCase))
                fields.Add(input.Groups[1].Value);
            foreach (Match sel in Regex.Matches(formHtml, @"<select[^>]*name=[""']([^""'>]+)[""']", RegexOptions.IgnoreCase))
                fields.Add(sel.Groups[1].Value);
            foreach (Match ta in Regex.Matches(formHtml, @"<textarea[^>]*name=[""']([^""'>]+)[""']", RegexOptions.IgnoreCase))
                fields.Add(ta.Groups[1].Value);

            forms.Add(new FormInfo { Action = action, Method = method, Fields = fields, FoundOn = pageUrl });
        }

        return forms;
    }

    private static List<string> ExtractQueryParams(string url)
    {
        try
        {
            var uri    = new Uri(url);
            var query  = System.Web.HttpUtility.ParseQueryString(uri.Query);
            return query.AllKeys.Where(k => k != null).Select(k => k!).ToList();
        }
        catch { return new List<string>(); }
    }
}
