import json
import os
import re
import requests
from pathlib import Path
from dotenv import load_dotenv

load_dotenv(Path(__file__).parent / ".env")

GEMINI_API_KEY = os.environ["GEMINI_API_KEY"]
MODEL = "gemini-2.0-flash"
API_URL = f"https://generativelanguage.googleapis.com/v1beta/models/{MODEL}:generateContent"
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
    system_instruction = (
        "You are a Senior Security Architect. Respond ONLY with valid JSON. "
        "No markdown, no explanation, no code fences. "
        'Schema: {"severity": string, "effort_level": "Low"|"Medium"|"High", '
        '"summary": string, "files_to_update": [string], "next_step": string}'
    )
    payload = {
        "system_instruction": {"parts": [{"text": system_instruction}]},
        "contents": [{"parts": [{"text": prompt}]}],
        "generationConfig": {
            "temperature": 0.2,
            "maxOutputTokens": 1024,
        },
    }
    res = requests.post(
        API_URL,
        params={"key": GEMINI_API_KEY},
        json=payload,
        timeout=60,
    )
    if res.status_code != 200:
        print(f"  Gemini API error: {res.status_code} | {res.text[:500]}")
    res.raise_for_status()
    content = res.json()["candidates"][0]["content"]["parts"][0]["text"].strip()
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
        print(f"[{i+1}/{len(prompts)}] Classifying {label}...")
        try:
            classification = call_llm(prompt)
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
