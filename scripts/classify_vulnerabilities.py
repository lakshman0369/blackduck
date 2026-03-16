import json
import os
import re
import time
import requests
from pathlib import Path
from dotenv import load_dotenv

load_dotenv(Path(__file__).parent / ".env")

GROQ_API_KEY = os.environ["GROQ_API_KEY"]
MODEL = "llama-3.3-70b-versatile"
API_URL = "https://api.groq.com/openai/v1/chat/completions"
PROMPTS_FILE = Path(__file__).resolve().parent.parent / "LLM_Prompts.txt"
SUMMARY_FILE = Path(__file__).resolve().parent.parent / "vulnerability_summary.json"
OUTPUT_FILE = Path(__file__).resolve().parent.parent / "classification_results.json"


def parse_prompts():
    text = PROMPTS_FILE.read_text(encoding="utf-8")
    blocks = re.findall(
        r"--- START PROMPT FOR .+? ---(.+?)--- END PROMPT ---",
        text,
        re.DOTALL,
    )
    return [b.strip() for b in blocks]


def call_llm(prompt):
    headers = {
        "Authorization": f"Bearer {GROQ_API_KEY}",
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
                    "Schema: {"
                    '"severity": string, '
                    '"effort_level": "Low"|"Medium"|"High", '
                    '"dependency_type": "direct"|"transitive", '
                    '"upgrade_type": "patch"|"minor"|"major"|"unknown", '
                    '"summary": string, '
                    '"remediation_approach": string, '
                    '"files_to_update": [string], '
                    '"breaking_changes": [string], '
                    '"next_step": string'
                    "}"
                ),
            },
            {"role": "user", "content": prompt},
        ],
        "temperature": 0.2,
        "max_tokens": 1024,
    }
    for attempt in range(5):
        res = requests.post(API_URL, headers=headers, json=payload, timeout=60)
        if res.status_code == 429:
            wait = 2 ** attempt * 5
            print(f"  Rate limited. Retrying in {wait}s (attempt {attempt + 1}/5)...")
            time.sleep(wait)
            continue
        if res.status_code != 200:
            print(f"  API error: {res.status_code} | {res.text[:500]}")
        res.raise_for_status()
        break
    else:
        raise Exception("API rate limit exceeded after 5 retries")

    content = res.json()["choices"][0]["message"]["content"].strip()
    content = re.sub(r"^```json\s*", "", content)
    content = re.sub(r"\s*```$", "", content)
    return json.loads(content)


def main():
    prompts = parse_prompts()
    summary = json.loads(SUMMARY_FILE.read_text(encoding="utf-8"))

    if len(prompts) != len(summary):
        print(f"Warning: {len(prompts)} prompts but {len(summary)} packages in summary.")

    results = []
    for i, (prompt, pkg) in enumerate(zip(prompts, summary)):
        label = f"{pkg['project']} / {pkg['component']}"
        if i > 0:
            time.sleep(3)
        print(f"[{i+1}/{len(prompts)}] Classifying {label}...")
        try:
            classification = call_llm(prompt)
            # Merge package metadata
            classification["project"] = pkg["project"]
            classification["component"] = pkg["component"]
            classification["current_version"] = pkg["current_version"]
            classification["target_version"] = pkg["target_version"]
            classification["npm_latest_version"] = pkg.get("npm_latest_version", "Unknown")
            classification["vulnerability_count"] = len(pkg["vulnerabilities"])
            classification["vulnerabilities"] = pkg["vulnerabilities"]
            classification["parent_components"] = pkg.get("parent_components", [])
            results.append(classification)
            print(f"  -> {classification['effort_level']} effort | {classification.get('dependency_type', 'unknown')} | {classification.get('upgrade_type', 'unknown')} upgrade")
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
