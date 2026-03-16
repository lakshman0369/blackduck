import json
import os
import re
import requests
from pathlib import Path
from dotenv import load_dotenv

load_dotenv(Path(__file__).parent / ".env")

GITHUB_TOKEN = os.environ["GH_PAT"]
MODEL = "claude-3.5-sonnet"
CANDIDATE_URLS = [
    "https://models.inference.github.com/chat/completions",
    "https://models.github.ai/inference/v1/chat/completions",
    "https://models.github.ai/inference/chat/completions",
    "https://api.github.com/models/chat/completions",
]
PROMPTS_FILE = Path(__file__).resolve().parent.parent / "LLM_Prompts.txt"
SUMMARY_FILE = Path(__file__).resolve().parent.parent / "vulnerability_summary.json"
OUTPUT_FILE = Path(__file__).resolve().parent.parent / "classification_results.json"


def discover_endpoint():
    """Try candidate URLs and return the first one that doesn't 404."""
    headers = {
        "Authorization": f"Bearer {GITHUB_TOKEN}",
        "Content-Type": "application/json",
    }
    test_payload = {
        "model": MODEL,
        "messages": [{"role": "user", "content": "Say OK"}],
        "max_tokens": 5,
    }
    for url in CANDIDATE_URLS:
        try:
            print(f"  Trying {url}...")
            res = requests.post(url, headers=headers, json=test_payload, timeout=15)
            if res.status_code != 404:
                print(f"  -> Using {url} (status: {res.status_code})")
                return url
        except requests.exceptions.ConnectionError as e:
            print(f"  -> Connection failed: {e}")
            continue
    return None


def parse_prompts():
    text = PROMPTS_FILE.read_text(encoding="utf-8")
    blocks = re.findall(
        r"--- START PROMPT FOR .+? ---(.+?)--- END PROMPT ---",
        text,
        re.DOTALL,
    )
    return [b.strip() for b in blocks]


def call_llm(api_url, prompt):
    headers = {
        "Authorization": f"Bearer {GITHUB_TOKEN}",
        "Content-Type": "application/json",
    }
    payload = {
        "model": MODEL,
        "messages": [
            {
                "role": "system",
                "content": (
                    "You are a Senior Security Architect. Respond ONLY with valid JSON. "
                    "No markdown, no explanation, no code fences. "
                    "Schema: {\"severity\": string, \"effort_level\": \"Low\"|\"Medium\"|\"High\", "
                    "\"summary\": string, \"files_to_update\": [string], \"next_step\": string}"
                ),
            },
            {"role": "user", "content": prompt},
        ],
        "temperature": 0.2,
        "max_tokens": 1024,
    }
    res = requests.post(api_url, headers=headers, json=payload, timeout=60)
    print(f"  Response status: {res.status_code}")
    if res.status_code != 200:
        print(f"  Response body: {res.text[:500]}")
    res.raise_for_status()
    content = res.json()["choices"][0]["message"]["content"].strip()
    content = re.sub(r"^```json\s*", "", content)
    content = re.sub(r"\s*```$", "", content)
    return json.loads(content)


def main():
    prompts = parse_prompts()
    summary = json.loads(SUMMARY_FILE.read_text(encoding="utf-8"))

    if len(prompts) != len(summary):
        print(f"Warning: {len(prompts)} prompts but {len(summary)} packages in summary.")

    print("Discovering GitHub Models API endpoint...")
    api_url = discover_endpoint()
    if not api_url:
        print("ERROR: Could not find a working GitHub Models API endpoint.")
        print("Make sure your GH_PAT has access to GitHub Models.")
        OUTPUT_FILE.write_text(json.dumps([{
            "error": "No working GitHub Models API endpoint found. Tried: " + ", ".join(CANDIDATE_URLS)
        }], indent=2), encoding="utf-8")
        return

    results = []
    for i, (prompt, pkg) in enumerate(zip(prompts, summary)):
        label = f"{pkg['project']} / {pkg['component']}"
        print(f"[{i+1}/{len(prompts)}] Classifying {label}...")
        try:
            classification = call_llm(api_url, prompt)
            classification["project"] = pkg["project"]
            classification["component"] = pkg["component"]
            classification["current_version"] = pkg["current_version"]
            classification["target_version"] = pkg["target_version"]
            classification["vulnerability_count"] = len(pkg["vulnerabilities"])
            classification["vulnerabilities"] = pkg["vulnerabilities"]
            results.append(classification)
            print(f"  -> {classification['effort_level']} effort")
        except Exception as e:
            print(f"  -> ERROR: {e}")
            results.append({
                "project": pkg["project"],
                "component": pkg["component"],
                "error": str(e),
            })

    OUTPUT_FILE.write_text(json.dumps(results, indent=2), encoding="utf-8")
    print(f"\nClassification written to {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
