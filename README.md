# Password Strength Analyzer (C#)

A simple, security‑aware **console app** that evaluates password quality using **regex pattern checks** and an **entropy estimate**. It outputs a strength category, a rough crack‑time estimate, and concrete suggestions to improve the password.

> Portfolio‑ready: clean code, tests, CI, and a README that hiring managers can skim quickly.

---

## ✨ Features

* **Regex checks** for character classes and risky patterns (repeats, sequences, date‑like, email‑like, common passwords).
* **Entropy scoring**: ~ `length × log2(poolSize)` with tunable penalties for predictable patterns.
* **Human‑readable output**: strength category + crack‑time (assuming 1B guesses/sec).
* **Actionable suggestions** tailored to your password’s weaknesses.

---

## 🧠 How it works (high level)

1. Detects presence of character classes (lower/upper/digit/symbol/whitespace) to estimate the **character pool size**.
2. Computes **raw entropy**: `L × log2(poolSize)` where `L` is password length.
3. Applies **pattern penalties** for common weak structures (e.g., `password`, `abc`, dates, emails, long repeats, length < 12).
4. Maps adjusted entropy to categories:

   * `< 28` → Very Weak
   * `< 36` → Weak
   * `< 60` → Moderate
   * `< 80` → Strong
   * `≥ 80` → Excellent
5. Estimates crack time using expected guesses `≈ 2^(bits‑1)` at **1B guesses/sec**.

> ⚠️ Disclaimer: This is a **heuristic** (useful for education and quick feedback), not a substitute for a dedicated password strength estimator like zxcvbn for production auth UX.

---

## 📦 Project structure (recommended)

```
PasswordAnalyzer.sln
src/
  PasswordAnalyzer/
    PasswordAnalyzer.csproj
    Program.cs               # your console app
.tests/
  PasswordAnalyzer.Tests/
    PasswordAnalyzer.Tests.csproj
    PasswordAnalyzer.IntegrationTests.cs
.github/
  workflows/
    dotnet.yml               # CI build & test
```

---

## 🚀 Quick start

```bash
# 1) Create solution & projects
mkdir PasswordAnalyzer && cd PasswordAnalyzer

dotnet new sln -n PasswordAnalyzer
mkdir -p src/PasswordAnalyzer
mkdir -p .tests/PasswordAnalyzer.Tests

# If you already have Program.cs, move it here:
# mv /path/to/your/Program.cs src/PasswordAnalyzer/Program.cs

dotnet new console -n PasswordAnalyzer -o src/PasswordAnalyzer

# 2) xUnit test project
cd .tests/PasswordAnalyzer.Tests

dotnet new xunit -n PasswordAnalyzer.Tests -o .
# Add test dependencies useful for integration testing
dotnet add package FluentAssertions --version 6.*

# 3) Link projects in the solution
cd ../../
dotnet sln add src/PasswordAnalyzer/PasswordAnalyzer.csproj
dotnet sln add .tests/PasswordAnalyzer.Tests/PasswordAnalyzer.Tests.csproj

dotnet add .tests/PasswordAnalyzer.Tests/PasswordAnalyzer.Tests.csproj \
  reference src/PasswordAnalyzer/PasswordAnalyzer.csproj

# 4) Drop in the test file & workflow from this README (below).
# 5) Run tests
 dotnet test

# 6) Run the app
 dotnet run --project src/PasswordAnalyzer/PasswordAnalyzer.csproj
```

---

## 🧪 xUnit tests

Create `.tests/PasswordAnalyzer.Tests/PasswordAnalyzer.IntegrationTests.cs`:

```csharp
using System;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using FluentAssertions;
using Xunit;

namespace PasswordAnalyzer.Tests
{
    public class IntegrationTests
    {
        private static async Task<string> RunAppAsync(string password)
        {
            var solutionRoot = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "../../../.."));
            var projectPath = Path.Combine(solutionRoot, "src", "PasswordAnalyzer", "PasswordAnalyzer.csproj");

            var psi = new ProcessStartInfo
            {
                FileName = "dotnet",
                Arguments = $"run --project \"{projectPath}\"",
                RedirectStandardInput = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            using var p = Process.Start(psi)!;
            using var output = new StringBuilder();
            p.OutputDataReceived += (_, e) => { if (e.Data != null) output.AppendLine(e.Data); };
            p.BeginOutputReadLine();

            // feed the password and press Enter
            await Task.Delay(150); // let the app print the prompt
            await p.StandardInput.WriteAsync(password);
            await p.StandardInput.WriteAsync("\n");
            p.StandardInput.Close();

            await p.WaitForExitAsync();
            return output.ToString();
        }

        [Theory]
        [InlineData("password", "Very Weak")]
        [InlineData("P@ssw0rd", "Weak")]
        public async Task WeakPasswords_AreDetected(string pwd, string expectedCategory)
        {
            var output = await RunAppAsync(pwd);
            output.Should().Contain("Strength:")
                  .And.Contain(expectedCategory);
        }

        [Theory]
        [InlineData("Tr33s&Skies_2025!long", "Strong")]
        [InlineData("Sailboat-Horizon_7*Acorn+Maple", "Excellent")]
        public async Task StrongPasswords_AreDetected(string pwd, string expectedCategory)
        {
            var output = await RunAppAsync(pwd);
            output.Should().Contain("Strength:")
                  .And.Contain(expectedCategory);
        }

        [Fact]
        public async Task Output_Shows_Key_Sections()
        {
            var output = await RunAppAsync("Zt!2025_sun&steel");
            output.Should().Contain("Analysis")
                  .And.Contain("Entropy (raw):")
                  .And.Contain("Entropy (adjusted):")
                  .And.Contain("Estimated crack time");
        }
    }
}
```

Replace the default xUnit project file `.tests/PasswordAnalyzer.Tests/PasswordAnalyzer.Tests.csproj` with:

```xml
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <TargetFramework>net8.0</TargetFramework>
    <IsPackable>false</IsPackable>
    <RootNamespace>PasswordAnalyzer.Tests</RootNamespace>
  </PropertyGroup>
  <ItemGroup>
    <PackageReference Include="FluentAssertions" Version="6.*" />
    <PackageReference Include="xunit" Version="2.*" />
    <PackageReference Include="xunit.runner.visualstudio" Version="2.*" />
    <PackageReference Include="Microsoft.NET.Test.Sdk" Version="17.*" />
  </ItemGroup>
  <ItemGroup>
    <ProjectReference Include="..\..\src\PasswordAnalyzer\PasswordAnalyzer.csproj" />
  </ItemGroup>
</Project>
```

> These are **integration tests**: they run the console app and validate output for given inputs. This avoids refactoring your program’s internal methods just for testing.

---

## 🤖 GitHub Actions (CI)

Create `.github/workflows/dotnet.yml`:

```yaml
name: .NET

on:
  push:
    branches: [ main, master ]
  pull_request:
    branches: [ main, master ]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Setup .NET
        uses: actions/setup-dotnet@v4
        with:
          dotnet-version: '8.0.x'
      - name: Restore
        run: dotnet restore
      - name: Build
        run: dotnet build --configuration Release --no-restore
      - name: Test
        run: dotnet test --configuration Release --no-build --verbosity normal
```

---

## 🧩 Extending the analyzer

* Expand the **common password list** (or load from a file).
* Add a **dictionary check** for user‑provided words (names, teams, cities).
* Configure **guesses/sec** for different attacker models (e.g., 1e6 vs 1e11).
* Add an optional **JSON output** flag for machine‑readable pipelines.

---

## 🔐 Security notes

* Don’t log or store real passwords. Use this tool **offline** for demos/education.
* Prefer **passphrases** (4+ random words) stored in a password manager.
* Enable **MFA** anywhere it’s offered.

---

## 📄 License

MIT (feel free to adapt for your portfolio).
