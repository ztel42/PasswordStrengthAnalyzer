using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;

// Password Strength Analyzer
// - Uses regex-based checks (character classes, patterns)
// - Estimates entropy ~ L * log2(poolSize), with small penalties for risky patterns
// - Maps entropy to human-friendly categories and gives suggestions
//
// Build & Run (requires .NET 7/8 SDK):
//   dotnet new console -n PasswordAnalyzer
//   cd PasswordAnalyzer
//   (Replace Program.cs with this file's contents)
//   dotnet run

class Program
{
    // Regexes for features/patterns
    private static readonly Regex RxLower = new("[a-z]");
    private static readonly Regex RxUpper = new("[A-Z]");
    private static readonly Regex RxDigit = new("\\d");
    private static readonly Regex RxSymbol = new("[^A-Za-z0-9]");
    private static readonly Regex RxWhitespace = new("\\s");
    private static readonly Regex RxRepeat3 = new("(.)\\1{2,}"); // any char repeated 3+ in a row
    private static readonly Regex RxDateLike = new(@"(?:(19|20)\\d{2}[-\\/ ]?(0?[1-9]|1[0-2])[-\\/ ]?(0?[1-9]|[12]\\d|3[01]))|((0?[1-9]|[12]\\d|3[01])[-\\/ ]?(0?[1-9]|1[0-2])[-\\/ ]?(19|20)\\d{2})");
    private static readonly Regex RxEmailLike = new(@"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}");

    // Lightweight common password list (expand as desired)
    private static readonly string[] CommonPasswords = new[]
    {
        "password","123456","123456789","qwerty","letmein","111111","admin","welcome",
        "iloveyou","monkey","dragon","football","baseball","abc123","1q2w3e4r","secret"
    };

    static void Main()
    {
        Console.WriteLine("==== Password Strength Analyzer ====");
        Console.Write("Enter a password to evaluate: ");
        var pwd = ReadHidden();
        Console.WriteLine();

        var report = Analyze(pwd);
        PrintReport(report);

        Console.WriteLine("\nTips: Avoid using real names, emails, or dates. Consider a passphrase (4+ random words) with symbols.");
    }

    private static void PrintReport(Analysis a)
    {
        Console.WriteLine("\n=== Analysis ===");
        Console.WriteLine($"Length: {a.Length}");
        Console.WriteLine($"Classes: lower={a.HasLower}, upper={a.HasUpper}, digit={a.HasDigit}, symbol={a.HasSymbol}, whitespace={a.HasWhitespace}");
        Console.WriteLine($"Patterns: repeat>=3={a.HasRepeat3}, sequentialRun={a.HasSequence}, dateLike={a.LooksLikeDate}, emailLike={a.LooksLikeEmail}, commonWord={a.ContainsCommonWord}");
        Console.WriteLine($"Entropy (raw): {a.EntropyBitsRaw:F1} bits");
        Console.WriteLine($"Entropy (adjusted): {a.EntropyBitsAdjusted:F1} bits");
        Console.WriteLine($"Strength: {a.Category}");
        Console.WriteLine($"Estimated crack time @1B guesses/s: {a.CrackTimeEstimate}");

        if (a.Suggestions.Any())
        {
            Console.WriteLine("\nSuggestions:");
            foreach (var s in a.Suggestions) Console.WriteLine($" - {s}");
        }
    }

    private static Analysis Analyze(string pwd)
    {
        var a = new Analysis { Password = pwd, Length = pwd.Length };

        // Regex-driven feature flags
        a.HasLower = RxLower.IsMatch(pwd);
        a.HasUpper = RxUpper.IsMatch(pwd);
        a.HasDigit = RxDigit.IsMatch(pwd);
        a.HasSymbol = RxSymbol.IsMatch(pwd);
        a.HasWhitespace = RxWhitespace.IsMatch(pwd);
        a.HasRepeat3 = RxRepeat3.IsMatch(pwd);
        a.LooksLikeDate = RxDateLike.IsMatch(pwd);
        a.LooksLikeEmail = RxEmailLike.IsMatch(pwd);
        a.ContainsCommonWord = ContainsCommon(pwd);
        a.HasSequence = HasSequentialRun(pwd, 3);

        // Entropy estimate
        var poolSize = EstimatePoolSize(a);
        a.EntropyBitsRaw = a.Length * Log2(poolSize);

        // Tunable penalties for predictable patterns
        double penalty = 0;
        if (a.ContainsCommonWord) penalty += 14;
        if (a.LooksLikeEmail) penalty += 10;
        if (a.LooksLikeDate) penalty += 8;
        if (a.HasSequence) penalty += 6;
        if (a.HasRepeat3) penalty += 4;
        if (a.Length < 12) penalty += (12 - a.Length) * 1.0;

        a.EntropyBitsAdjusted = Math.Max(0, a.EntropyBitsRaw - penalty);
        a.Category = MapCategory(a.EntropyBitsAdjusted);
        a.CrackTimeEstimate = EstimateCrackTime(a.EntropyBitsAdjusted, 1e9); // 1B guesses/sec

        a.Suggestions = BuildSuggestions(a);
        return a;
    }

    private static int EstimatePoolSize(Analysis a)
    {
        int pool = 0;
        if (a.HasLower) pool += 26;
        if (a.HasUpper) pool += 26;
        if (a.HasDigit) pool += 10;
        if (a.HasSymbol) pool += 33;  // approx printable symbols
        if (a.HasWhitespace) pool += 1;
        return Math.Max(pool, 10);    // minimal diversity safeguard
    }

    private static string MapCategory(double bits) => bits switch
    {
        < 28 => "Very Weak",
        < 36 => "Weak",
        < 60 => "Moderate",
        < 80 => "Strong",
        _ => "Excellent"
    };

    private static bool ContainsCommon(string pwd)
    {
        var lower = pwd.ToLowerInvariant();
        foreach (var w in CommonPasswords)
            if (lower.Contains(w)) return true;
        return false;
    }

    // Detect ascending/descending alphanumeric sequences (e.g., abc, 123, cba)
    private static bool HasSequentialRun(string s, int minRun)
    {
        if (string.IsNullOrEmpty(s) || s.Length < minRun) return false;
        int incRun = 1, decRun = 1;
        for (int i = 1; i < s.Length; i++)
        {
            if (AreConsecutive(s[i - 1], s[i], +1)) { incRun++; decRun = 1; }
            else if (AreConsecutive(s[i - 1], s[i], -1)) { decRun++; incRun = 1; }
            else { incRun = 1; decRun = 1; }

            if (incRun >= minRun || decRun >= minRun) return true;
        }
        return false;
    }

    private static bool AreConsecutive(char a, char b, int step) => (char)(a + step) == b;

    private static double Log2(double x) => Math.Log(x, 2);

    private static string EstimateCrackTime(double entropyBits, double guessesPerSecond)
    {
        // Expected guesses ~ 2^(bits-1)
        double expectedGuesses = Math.Pow(2, Math.Max(0, entropyBits - 1));
        double seconds = expectedGuesses / guessesPerSecond;
        return HumanizeDuration(seconds);
    }

    private static string HumanizeDuration(double seconds)
    {
        if (seconds < 1) return "< 1 second";
        if (seconds < 60) return $"{seconds:F0} seconds";
        if (seconds < 3600) return $"{(seconds / 60):F1} minutes";
        if (seconds < 86400) return $"{(seconds / 3600):F1} hours";
        if (seconds < 86400 * 30) return $"{(seconds / 86400):F1} days";
        if (seconds < 86400 * 365) return $"{(seconds / (86400 * 30)):F1} months";
        return "> 100 years";
    }

    private static List<string> BuildSuggestions(Analysis a)
    {
        var tips = new List<string>();
        if (a.Length < 16) tips.Add("Increase length to 16+ characters (or a 4+ word passphrase).");
        if (!a.HasLower) tips.Add("Add lowercase letters.");
        if (!a.HasUpper) tips.Add("Add uppercase letters.");
        if (!a.HasDigit) tips.Add("Include digits.");
        if (!a.HasSymbol) tips.Add("Include symbols (e.g., !@#).");
        if (a.HasRepeat3) tips.Add("Avoid repeating the same character 3+ times.");
        if (a.HasSequence) tips.Add("Avoid sequences like 'abc' or '123' (use non-adjacent characters).");
        if (a.ContainsCommonWord) tips.Add("Remove common words or predictable chunks (e.g., 'password').");
        if (a.LooksLikeEmail) tips.Add("Do not reuse email-like strings in passwords.");
        if (a.LooksLikeDate) tips.Add("Avoid dates/birthdays.");
        if (!tips.Any()) tips.Add("Looks solid. Consider a longer passphrase for even more safety.");
        return tips;
    }

    // Secure-ish console input (hides characters)
    private static string ReadHidden()
    {
        var pwd = string.Empty;
        ConsoleKeyInfo key;
        while ((key = Console.ReadKey(true)).Key != ConsoleKey.Enter)
        {
            if (key.Key == ConsoleKey.Backspace && pwd.Length > 0)
            {
                pwd = pwd[0..^1];
                continue;
            }
            if (!char.IsControl(key.KeyChar))
            {
                pwd += key.KeyChar;
            }
        }
        return pwd;
    }

    public class Analysis
    {
        public string Password { get; set; } = string.Empty;
        public int Length { get; set; }
        public bool HasLower { get; set; }
        public bool HasUpper { get; set; }
        public bool HasDigit { get; set; }
        public bool HasSymbol { get; set; }
        public bool HasWhitespace { get; set; }
        public bool HasRepeat3 { get; set; }
        public bool HasSequence { get; set; }
        public bool LooksLikeDate { get; set; }
        public bool LooksLikeEmail { get; set; }
        public bool ContainsCommonWord { get; set; }
        public double EntropyBitsRaw { get; set; }
        public double EntropyBitsAdjusted { get; set; }
        public string Category { get; set; } = string.Empty;
        public string CrackTimeEstimate { get; set; } = string.Empty;
        public List<string> Suggestions { get; set; } = new();
    }
}