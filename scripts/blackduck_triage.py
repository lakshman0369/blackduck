import requests
import subprocess
import os
import json
import re
from pathlib import Path
from dotenv import load_dotenv

# Load .env from the same directory as this script
load_dotenv(Path(__file__).parent / ".env")

# --- CONFIGURATION (from .env file / environment variables) ---
BLACK_DUCK_URL = os.environ["BLACK_DUCK_URL"]
API_TOKEN = os.environ["BLACK_DUCK_API_TOKEN"]
GITHUB_TOKEN = os.environ["GH_PAT"]
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
    all_items = []
    offset = 0
    limit = 100
    while True:
        params = {"offset": offset, "limit": limit}
        res = requests.get(
            f"{version_href}/vulnerable-bom-components",
            headers=headers,
            params=params,
        )
        res.raise_for_status()
        data = res.json()
        items = data.get("items", [])
        all_items.extend(items)
        total = data.get("totalCount", len(all_items))
        offset += limit
        if offset >= total or not items:
            break
    return [
        i
        for i in all_items
        if i["vulnerabilityWithRemediation"]["severity"] in ("HIGH", "CRITICAL")
    ]


def get_component_hierarchy(token, version_href, component_href):
    """Get the dependency path to determine if direct or transitive."""
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.blackducksoftware.bill-of-materials-6+json",
    }
    try:
        # Get matched files / hierarchy for the component
        res = requests.get(
            f"{version_href}/components/{_extract_component_id(component_href)}/matched-files",
            headers=headers,
            timeout=15,
        )
        if res.status_code == 200:
            return res.json().get("items", [])
    except Exception:
        pass
    return []


def _extract_component_id(href):
    """Extract component ID from href URL."""
    parts = href.rstrip("/").split("/")
    return parts[-1] if parts else ""


def parse_version(version_str):
    """Parse version string into tuple of ints for comparison."""
    clean = re.sub(r"^[vV]", "", version_str or "")
    parts = re.split(r"[.\-]", clean)
    result = []
    for p in parts:
        try:
            result.append(int(p))
        except ValueError:
            break
    return tuple(result) if result else (0,)


def classify_upgrade(current_v, target_v):
    """Determine if upgrade is major, minor, or patch."""
    if not target_v or target_v == "Unknown":
        return "unknown"
    curr = parse_version(current_v)
    tgt = parse_version(target_v)
    if len(curr) >= 1 and len(tgt) >= 1 and tgt[0] != curr[0]:
        return "major"
    if len(curr) >= 2 and len(tgt) >= 2 and tgt[1] != curr[1]:
        return "minor"
    return "patch"


def get_remediation_info(vuln_item):
    """Extract all remediation-related fields from a vulnerability item."""
    vr = vuln_item["vulnerabilityWithRemediation"]
    return {
        "fix_version": vr.get("remediationTargetVersionName", "Unknown"),
        "latest_version": vr.get("latestFixVersion", "Unknown"),
        "remediation_status": vr.get("remediationStatus", "Unknown"),
        "remediation_comment": vr.get("remediationComment", ""),
        "solution": vr.get("solution", ""),
        "workaround": vr.get("workaround", ""),
    }


def get_dependency_type(vuln_item):
    """Determine if the component is a direct or transitive dependency."""
    match_types = vuln_item.get("matchTypes", [])
    origins = vuln_item.get("origins", [])

    is_transitive = False
    parent_components = []

    for origin in origins:
        ext_ns = origin.get("externalNamespace", "")
        ext_id = origin.get("externalId", "")
        if ext_ns and ext_id:
            parent_components.append(f"{ext_ns}:{ext_id}")

    for mt in match_types:
        if "TRANSITIVE" in mt.upper():
            is_transitive = True
            break

    if not match_types:
        dep_type = vuln_item.get("dependencyType", "")
        if dep_type:
            is_transitive = "TRANSITIVE" in dep_type.upper()

    return {
        "dependency_type": "transitive" if is_transitive else "direct",
        "match_types": match_types,
        "parent_components": parent_components,
    }


def get_bom_component_details(token, version_href, component_name):
    """Check BOM components for dependency hierarchy info."""
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.blackducksoftware.bill-of-materials-6+json",
    }
    try:
        res = requests.get(
            f"{version_href}/components",
            headers=headers,
            params={"q": f"componentName:{component_name}", "limit": 10},
            timeout=15,
        )
        if res.status_code == 200:
            items = res.json().get("items", [])
            for item in items:
                if item.get("componentName", "").lower() == component_name.lower():
                    match_types = item.get("matchTypes", [])
                    origins = item.get("origins", [])
                    is_transitive = any(
                        "TRANSITIVE" in mt.upper() for mt in match_types
                    )
                    return {
                        "dependency_type": "transitive" if is_transitive else "direct",
                        "match_types": match_types,
                        "origins": origins,
                    }
    except Exception as e:
        print(f"    Warning: Could not fetch BOM details for {component_name}: {e}")
    return None


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


def get_npm_latest_version(package_name):
    """Fetch the latest version from npm registry, trying case variations."""
    names_to_try = [package_name, package_name.lower()]
    for name in names_to_try:
        try:
            res = requests.get(
                f"https://registry.npmjs.org/{name}/latest", timeout=10
            )
            if res.status_code == 200:
                return res.json().get("version", "Unknown")
        except Exception:
            continue
    return "Unknown"


def build_prompt(pkg, changelog):
    vuln_lines = "\n".join(
        f"  - {v['name']} (Severity: {v['severity']}, Solution: {v.get('solution', 'N/A')}, "
        f"Fix Version: {v.get('fix_version', 'N/A')})"
        for v in pkg["vulnerabilities"]
    )

    dep_info = f"Dependency Type: {pkg['dependency_type']}"
    if pkg["dependency_type"] == "transitive" and pkg.get("parent_components"):
        dep_info += f"\n  Parent Components: {', '.join(pkg['parent_components'])}"

    upgrade_info = f"Upgrade Type: {pkg['upgrade_type']}"
    if pkg["npm_latest_version"] != "Unknown":
        upgrade_info += f"\n  Latest Available on npm: {pkg['npm_latest_version']}"

    return f"""
--- START PROMPT FOR {pkg['project']} / {pkg['component']} ---
Role: Senior Security Architect.
Task: Analyze the effort to remediate all vulnerabilities in {pkg['component']}.

Context:
- Project: {pkg['project']}
- Component: {pkg['component']} ({pkg['current_version']} -> {pkg['target_version']})
- {dep_info}
- {upgrade_info}
- Vulnerabilities ({len(pkg['vulnerabilities'])}):
{vuln_lines}
- Usage: {pkg['usage_files']}
- Changelog Highlights:
{changelog}

Classification Rules:
- For TRANSITIVE dependencies: Check if upgrading the parent package to a safe version resolves the vulnerability. If yes, effort is typically Low.
- For DIRECT dependencies with PATCH/MINOR upgrade: Effort is Low to Medium.
- For DIRECT dependencies with MAJOR upgrade: Effort is Medium to High (check for breaking changes).
- If no fix version exists: Effort is High (requires alternative library or manual patching).

Provide:
1. Whether this is a direct or transitive dependency and how that affects remediation.
2. If transitive, whether upgrading the parent resolves it.
3. The upgrade type (major/minor/patch) and its implications.
4. Specific files and changes needed.
5. Risk assessment of the upgrade.

Output JSON: severity, effort_level, dependency_type, upgrade_type, summary, remediation_approach, files_to_update, breaking_changes, next_step.
--- END PROMPT ---
"""


def main():
    token = get_bearer_token()
    projects = get_projects(token)
    print(f"Found {len(projects)} projects matching prefix '{PROJECT_PREFIX}'.")

    # Group vulnerabilities by (project, component, version)
    packages = {}  # key: (project, component, version) -> dict

    for p in projects:
        name = p["name"]
        print(f"Processing {name}...")
        version = get_latest_version(token, p["_meta"]["href"])
        if not version:
            print(f"  No versions found for {name}, skipping.")
            continue

        version_href = version["_meta"]["href"]
        vulns = get_vulnerabilities(token, version_href)
        print(f"  Found {len(vulns)} HIGH/CRITICAL vulnerabilities.")

        for v in vulns:
            comp = v["componentName"]
            curr_v = v["componentVersionName"]
            vr = v["vulnerabilityWithRemediation"]
            target_v = vr.get("remediationTargetVersionName", "Unknown")
            key = (name, comp, curr_v)

            # Get dependency type info
            dep_info = get_dependency_type(v)
            # Enrich with BOM component details if vuln response lacks match types
            if not dep_info["match_types"]:
                bom_details = get_bom_component_details(token, version_href, comp)
                if bom_details:
                    dep_info["dependency_type"] = bom_details["dependency_type"]
                    dep_info["match_types"] = bom_details["match_types"]
            remediation = get_remediation_info(v)

            if key not in packages:
                npm_latest = get_npm_latest_version(comp)
                upgrade_type = classify_upgrade(curr_v, target_v)
                if upgrade_type == "unknown" and npm_latest != "Unknown":
                    upgrade_type = classify_upgrade(curr_v, npm_latest) + " (to latest)"

                packages[key] = {
                    "project": name,
                    "component": comp,
                    "current_version": curr_v,
                    "target_version": target_v,
                    "dependency_type": dep_info["dependency_type"],
                    "match_types": dep_info["match_types"],
                    "parent_components": dep_info["parent_components"],
                    "upgrade_type": upgrade_type,
                    "npm_latest_version": npm_latest,
                    "vulnerabilities": [],
                    "usage_files": find_usage(comp, name),
                }

            packages[key]["vulnerabilities"].append(
                {
                    "name": vr["vulnerabilityName"],
                    "severity": vr["severity"],
                    "fix_version": remediation["fix_version"],
                    "latest_version": remediation["latest_version"],
                    "solution": remediation["solution"],
                    "workaround": remediation["workaround"],
                    "remediation_status": remediation["remediation_status"],
                }
            )
            # Keep the most specific target version
            if packages[key]["target_version"] == "Unknown" and target_v != "Unknown":
                packages[key]["target_version"] = target_v
                packages[key]["upgrade_type"] = classify_upgrade(curr_v, target_v)

    prompts = []
    summary = list(packages.values())

    for pkg in summary:
        changelog = get_changelog(pkg["component"], pkg["current_version"], pkg["target_version"])
        prompt = build_prompt(pkg, changelog)
        prompts.append(prompt)

    with open("LLM_Prompts.txt", "w", encoding="utf-8") as f:
        f.writelines(prompts)

    with open("vulnerability_summary.json", "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)

    print(f"\nDone! Generated {len(prompts)} prompts for {len(summary)} packages in 'LLM_Prompts.txt'.")
    print(f"Summary written to 'vulnerability_summary.json'.")


if __name__ == "__main__":
    main()
