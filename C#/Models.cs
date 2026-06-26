namespace SecurityTester;

/// <summary>
/// Represents a single fix suggestion with a label and code snippet.
/// </summary>
public class FixSuggestion
{
    public string Label { get; set; } = "";
    public string Code  { get; set; } = "";
}

/// <summary>
/// Represents a detected security issue with full details and fix suggestions.
/// </summary>
public class SecurityIssue
{
    public string Title    { get; set; } = "";
    public string Location { get; set; } = "";
    public string Detail   { get; set; } = "";
    public string Severity { get; set; } = "MEDIUM";
    public string Risk     { get; set; } = "";
    public List<FixSuggestion> Fixes { get; set; } = new();
}

/// <summary>
/// Represents the result of a single security test.
/// </summary>
public class TestResult
{
    public string Name         { get; set; } = "";
    public bool   Passed       { get; set; } = true;
    public List<SecurityIssue> Issues { get; set; } = new();
}
