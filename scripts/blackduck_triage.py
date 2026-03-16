import requests
import subprocess
import os
import json
from pathlib import Path
from dotenv import load_dotenv

# Load .env from the same directory as this script
load_dotenv(Path(__file__).parent / ".env")

# --- CONFIGURATION (from .env file / environment variables) ---
BLACK_DUCK_URL = os.environ["BLACK_DUCK_URL"]
API_TOKEN = os.environ["BLACK_DUCK_API_TOKEN"]
GITHUB_TOKEN = os.environ["GITHUB_TOKEN"]
PROJECT_PREFIX = os.environ.get("PROJECT_PREFIX", "sumtotal-React")
REPO_ROOT = os.environ.get("REPO_ROOT", os.getcwd())


def get_bearer_token():
    auth_url = f"{BLACK_DUCK_URL}/api/tokens/authenticate"
    headers = {
        "Authorization": f"token {API_TOKEN}",
        "Accept": "application/vnd.blackducksoftware.user-4+json",
    }
    res = requests.post(auth_url, headers=headers, verify=True)
    res.raise_for_status()
    return res.json().get("bearerToken")


def get_projects(token):
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.blackducksoftware.project-detail-4+json",
    }
    params = {"q": f"name:{PROJECT_PREFIX}", "limit": 100}
    res = requests.get(f"{BLACK_DUCK_URL}/api/projects", headers=headers, params=params)
    res.raise_for_status()
    return [
        p
        for p in res.json().get("items", [])
        if p["name"].lower().startswith(PROJECT_PREFIX.lower())
    ]


def get_latest_version(token, project_href):
    headers = {"Authorization": f"Bearer {token}"}
    res = requests.get(
        f"{project_href}/versions",
        headers=headers,
        params={"sort": "createdAt DESC", "limit": 1},
    )
    res.raise_for_status()
    items = res.json().get("items", [])
    return items[0] if items else None


def get_vulnerabilities(token, version_href):
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.blackducksoftware.bill-of-materials-6+json",
    }
    res = requests.get(f"{version_href}/vulnerable-bom-components", headers=headers)
    res.raise_for_status()
    items = res.json().get("items", [])
    return [
        i
        for i in items
        if i["vulnerabilityWithRemediation"]["severity"] in ("HIGH", "CRITICAL")
        and i["vulnerabilityWithRemediation"]["remediationStatus"] == "NEW"
    ]


def find_usage(package_name, project_name):
    path = os.path.join(REPO_ROOT, project_name)
    if not os.path.exists(path):
        return ["Repository folder not found locally."]
    try:
        cmd = ["rg", "-l", f"['\"){package_name}['\"]", path]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        return result.stdout.splitlines() if result.stdout else ["No direct code usage found."]
    except subprocess.TimeoutExpired:
        return ["Ripgrep search timed out."]
    except FileNotFoundError:
        return ["ripgrep (rg) is not installed."]
    except Exception as e:
        return [f"Error running ripgrep: {e}"]


def get_changelog(package_name, current_v, target_v):
    if target_v == "Unknown":
        return "No remediation target version available."
    try:
        reg = requests.get(f"https://registry.npmjs.org/{package_name}", timeout=15).json()
        repo_url = reg.get("repository", {}).get("url", "")
        if "github.com" not in repo_url:
            return "Changelog not available via API."
        owner_repo = (
            repo_url.split("github.com/")[-1]
            .replace(".git", "")
            .replace("ssh://git@", "")
        )
        headers = {"Authorization": f"token {GITHUB_TOKEN}"}
        rels = requests.get(
            f"https://api.github.com/repos/{owner_repo}/releases",
            headers=headers,
            timeout=15,
        ).json()
        if not isinstance(rels, list):
            return "Unexpected GitHub API response."
        notes = [
            f"### {r['tag_name']}\n{r['body']}"
            for r in rels
            if current_v < r.get("tag_name", "") <= target_v
        ]
        return "\n".join(notes[:5]) if notes else "No relevant release notes found."
    except Exception as e:
        return f"Error fetching changelog: {e}"


def build_prompt(project_name, vuln, usage, changelog):
    vr = vuln["vulnerabilityWithRemediation"]
    comp = vuln["componentName"]
    curr_v = vuln["componentVersionName"]
    target_v = vr.get("remediationTargetVersionName", "Unknown")
    vuln_name = vr["vulnerabilityName"]

    return f"""
--- START PROMPT FOR {project_name} / {comp} ---
Role: Senior Security Architect.
Task: Analyze the effort to fix {vuln_name}.

Context:
- Project: {project_name}
- Component: {comp} ({curr_v} -> {target_v})
- Usage: {usage}
- Changelog Highlights:
{changelog}

Classification:
- Low: No breaking changes used.
- Medium: Minor API changes in < 3 files.
- High: Breaking changes in core files or transitive complexity.

Output JSON: severity, effort_level, summary, files_to_update, next_step.
--- END PROMPT ---
"""


def main():
    token = get_bearer_token()
    projects = get_projects(token)
    print(f"Found {len(projects)} projects matching prefix '{PROJECT_PREFIX}'.")

    prompts = []
    summary = []

    for p in projects:
        name = p["name"]
        print(f"Processing {name}...")
        version = get_latest_version(token, p["_meta"]["href"])
        if not version:
            print(f"  No versions found for {name}, skipping.")
            continue

        vulns = get_vulnerabilities(token, version["_meta"]["href"])
        print(f"  Found {len(vulns)} new HIGH/CRITICAL vulnerabilities.")

        for v in vulns:
            comp = v["componentName"]
            curr_v = v["componentVersionName"]
            target_v = v["vulnerabilityWithRemediation"].get(
                "remediationTargetVersionName", "Unknown"
            )
            vr = v["vulnerabilityWithRemediation"]

            usage = find_usage(comp, name)
            changelog = get_changelog(comp, curr_v, target_v)
            prompt = build_prompt(name, v, usage, changelog)
            prompts.append(prompt)

            summary.append(
                {
                    "project": name,
                    "component": comp,
                    "current_version": curr_v,
                    "target_version": target_v,
                    "severity": vr["severity"],
                    "vulnerability": vr["vulnerabilityName"],
                    "usage_files": usage,
                }
            )

    with open("LLM_Prompts.txt", "w", encoding="utf-8") as f:
        f.writelines(prompts)

    with open("vulnerability_summary.json", "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)

    print(f"\nDone! Generated {len(prompts)} prompts in 'LLM_Prompts.txt'.")
    print(f"Summary written to 'vulnerability_summary.json'.")


if __name__ == "__main__":
    main()
