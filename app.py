# app.py
import json
import os
import re
from io import BytesIO
from pathlib import Path
from zipfile import ZipFile

import streamlit as st

from validator import (
    detect_message_type_from_xml,
    list_rulesets,
    load_rules_by_ruleset,
    find_rulesets_for_message_type,
    choose_default_ruleset,
    validate_iso20022_xml,
    build_excel_report_bytes,
    build_batch_excel_report_bytes,
    validate_zip_bytes_with_ruleset_mapping,
    filter_rulesets_by_license,
    validate_rules_schema,  # Day27: validate uploaded ruleset
)

# =========================================================
# Config
# =========================================================
RULES_DIR = "rules"

st.set_page_config(page_title="ISO20022 Validator", layout="wide")
st.title("ISO20022 Message Validator")
st.caption("Auto-detect message type, apply layered rulesets (core/gpi/hvps), validate ZIP batches, export reports.")

# =========================================================
# License (Day24: ENV + optional input)
# =========================================================
st.sidebar.header("License")

token_input = st.sidebar.text_input("Enter license token (optional)", type="password")
ENV_TOKEN = os.environ.get("ISO20022_LICENSE_TOKEN", "").strip()
input_token = token_input.strip() if token_input else ""

# If ENV token is set: enterprise enabled (deployment mode).
# If ENV token is not set: any non-empty input unlocks (demo/local mode).
if ENV_TOKEN:
    enterprise_enabled = True
    license_source = "ENV"
else:
    enterprise_enabled = bool(input_token)
    license_source = "INPUT" if enterprise_enabled else "NONE"

if enterprise_enabled:
    st.sidebar.success(f"Enterprise rulesets unlocked ✅ (source: {license_source})")
else:
    st.sidebar.info("Community mode (core rulesets only)")
    st.sidebar.caption("Tip: set env ISO20022_LICENSE_TOKEN to unlock on deployment.")

# =========================================================
# Day27: Ruleset Manager (upload ruleset json)
# =========================================================
st.sidebar.divider()
st.sidebar.header("Ruleset Manager")

uploaded_ruleset = st.sidebar.file_uploader("Upload ruleset (.json)", type=["json"], key="ruleset_uploader")

def _safe_stem(name: str) -> str:
    # allow letters, digits, dot, dash, underscore
    stem = Path(name).stem
    stem = re.sub(r"[^A-Za-z0-9._-]+", "-", stem).strip("-")
    return stem or "ruleset"

if uploaded_ruleset:
    try:
        rules_bytes = uploaded_ruleset.read()
        rules_obj = json.loads(rules_bytes.decode("utf-8"))

        # validate minimal schema (meta + required_fields etc.)
        validate_rules_schema(rules_obj)

        # file name strategy:
        # - prefer uploaded filename stem (so user controls naming)
        # - ensure .json
        stem = _safe_stem(uploaded_ruleset.name)
        out_path = Path(RULES_DIR) / f"{stem}.json"
        Path(RULES_DIR).mkdir(parents=True, exist_ok=True)

        # prevent accidental overwrite unless user confirms
        overwrite = st.sidebar.checkbox(f"Overwrite if exists: {out_path.name}", value=False)
        if out_path.exists() and not overwrite:
            st.sidebar.warning(f"{out_path.name} already exists. Tick overwrite to replace it.")
        else:
            out_path.write_text(json.dumps(rules_obj, ensure_ascii=False, indent=2), encoding="utf-8")
            st.sidebar.success(f"Saved ruleset: {out_path.name}")
            st.sidebar.caption("If you're running via Docker, ensure rules/ is mounted to persist changes.")
            st.rerun()

    except json.JSONDecodeError as e:
        st.sidebar.error(f"Invalid JSON: {e}")
    except Exception as e:
        st.sidebar.error(f"Ruleset upload failed: {e}")

# =========================================================
# Helpers
# =========================================================
def visible_rulesets(all_rulesets: list) -> list:
    return filter_rulesets_by_license(all_rulesets, enterprise_enabled)

def show_ruleset_meta(rules: dict):
    meta = (rules or {}).get("meta", {}) or {}
    st.caption(
        f"Ruleset: **{meta.get('id', 'n/a')}** | "
        f"Profile: **{meta.get('profile', 'n/a')}** | "
        f"Tier: **{meta.get('tier', 'n/a')}** | "
        f"Version: **{meta.get('version', 'n/a')}** | "
        f"Released: **{meta.get('released', 'n/a')}**"
    )

def group_errors(errors: list) -> dict:
    groups = {
        "Header": [],
        "Transaction": [],
        "Party": [],
        "Technical": [],
    }

    for e in errors:
        field = (e.get("field") or "").lower()

        if "msgid" in field or "grphdr" in field:
            groups["Header"].append(e)
        elif "tx" in field or "amt" in field or "pmt" in field:
            groups["Transaction"].append(e)
        elif "dbtr" in field or "cdtr" in field or "party" in field:
            groups["Party"].append(e)
        else:
            groups["Technical"].append(e)

    return groups

def render_validation_result(validation_result: dict):
    st.divider()

    if validation_result.get("status") == "VALID":
        st.success("✅ VALID — All checks passed.")
    else:
        st.error("❌ INVALID — Issues detected.")

    # Errors
    errors = validation_result.get("errors", [])

    if errors:
        st.subheader("❌ Errors (grouped)")

        # 1️⃣ 致命错误高亮（第一个 ERROR）
        first_blocking = errors[0]
        st.markdown("### 🚨 First blocking issue")
        st.error(f"[{first_blocking.get('code')}] {first_blocking.get('message')}")

        with st.expander("Why this blocks processing / How to fix"):
            if first_blocking.get("title"):
                st.markdown(f"**{first_blocking['title']}**")
            if first_blocking.get("explanation"):
                st.markdown(f"- **Explanation:** {first_blocking['explanation']}")
            if first_blocking.get("action"):
                st.markdown(f"- **Suggested fix:** {first_blocking['action']}")
        # 2️⃣ 按业务维度分组展示
        grouped = group_errors(errors)

        for group_name, group_errors_list in grouped.items():
            if not group_errors_list:
                continue

            st.markdown(f"### {group_name} issues ({len(group_errors_list)})")
        for err in group_errors_list:
            st.error(f"[{err.get('code')}] {err.get('message')}")
            with st.expander("Details"):
                if err.get("field"):
                    st.markdown(f"- **Field:** `{err['field']}`")
                if err.get("explanation"):
                    st.markdown(f"- **Explanation:** {err['explanation']}")
                if err.get("action"):
                    st.markdown(f"- **Suggested fix:** {err['action']}")

    # Warnings
    if validation_result.get("warnings"):
        st.subheader("Warnings")
        for w in validation_result["warnings"]:
            st.warning(f"[{w.get('code')}] {w.get('message')}")

    # Parsed required fields
    st.subheader("Parsed required fields")
    parsed = validation_result.get("parsed_fields", {}) or {}
    st.table([{"Field": k, "Value": v} for k, v in parsed.items()])

    # Optional fields
    if isinstance(validation_result.get("optional_fields"), dict) and validation_result["optional_fields"]:
        st.subheader("Optional fields")
        opt = validation_result["optional_fields"]
        st.table([{"Field": k, "Value": v} for k, v in opt.items()])

    # Downloads
    st.divider()
    st.subheader("Download report")

    # Excel
    try:
        xlsx_bytes = build_excel_report_bytes(validation_result)
        st.download_button(
            label="⬇️ Download Excel report (.xlsx)",
            data=xlsx_bytes,
            file_name="validation_report.xlsx",
            mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        )
    except Exception as e:
        st.warning(f"Excel export failed: {e}")

    # JSON
    json_bytes = json.dumps(validation_result, indent=2, ensure_ascii=False).encode("utf-8")
    st.download_button(
        label="⬇️ Download validation result (JSON)",
        data=json_bytes,
        file_name="validation_result.json",
        mime="application/json",
    )

    with st.expander("Show full validation_result JSON"):
        st.json(validation_result)

# =========================================================
# Single file validation (Day20 + Day23 filtering + Day25 report metadata)
# =========================================================
st.header("Single file validation")

mode = st.radio(
    "Validation mode",
    options=["Auto-detect (recommended)", "Manual select ruleset"],
    horizontal=True,
    key="single_mode"
)

uploaded_xml = st.file_uploader("Upload ISO20022 XML", type=["xml"], key="single_xml_uploader")
if uploaded_xml:
    st.session_state["xml_bytes"] = uploaded_xml.read()

xml_bytes = st.session_state.get("xml_bytes")

if xml_bytes:
    rules = None
    ruleset = None

    if mode == "Manual select ruleset":
        all_rs = list_rulesets(RULES_DIR)
        rs_options = visible_rulesets(all_rs)
        if not rs_options:
            st.error("No rulesets available under current license. (Need at least one *-core ruleset.)")
            st.stop()

        ruleset = st.selectbox("Select ruleset", options=rs_options, key="manual_ruleset_select")
        rules = load_rules_by_ruleset(ruleset, RULES_DIR)

    else:
        detected_type = detect_message_type_from_xml(xml_bytes)
        if not detected_type:
            st.error("Could not auto-detect ISO20022 message type from XML namespace.")
            st.stop()

        st.success(f"Detected message type: {detected_type}")

        matched = find_rulesets_for_message_type(detected_type, RULES_DIR)
        matched = visible_rulesets(matched)

        if not matched:
            st.error("No available rulesets for this message type under current license.")
            st.stop()

        default_rs = choose_default_ruleset(matched)
        ruleset = st.selectbox(
            "Ruleset for detected message type",
            options=matched,
            index=matched.index(default_rs) if default_rs in matched else 0,
            key="auto_ruleset_select",
        )
        rules = load_rules_by_ruleset(ruleset, RULES_DIR)

    show_ruleset_meta(rules)

    try:
        validation_result = validate_iso20022_xml(xml_bytes, rules)

        # Day25 metadata for exports / JSON
        validation_result["license_level"] = "Enterprise" if enterprise_enabled else "Community"
        validation_result["ruleset_used"] = ruleset
        validation_result["ruleset_tier"] = (ruleset.split("-", 1)[1] if ruleset and "-" in ruleset else "unknown")

        render_validation_result(validation_result)

    except Exception as e:
        st.error(f"Unexpected error during validation: {e}")
else:
    st.info("Upload an XML to validate it.")

# =========================================================
# Batch ZIP validation (Day22 + Day23 filtering + Day25 license in batch rows)
# =========================================================
st.divider()
st.header("Batch validation (ZIP) — Auto-detect + Ruleset mapping")

zip_file = st.file_uploader(
    "Upload a ZIP containing multiple ISO20022 XML files",
    type=["zip"],
    key="zip_uploader",
)

if zip_file:
    st.session_state["zip_bytes"] = zip_file.read()

zip_bytes = st.session_state.get("zip_bytes")

if zip_bytes:
    # 1) Scan ZIP to detect message types
    detected_types = set()
    total_xml = 0

    with ZipFile(BytesIO(zip_bytes), "r") as z:
        for name in z.namelist():
            if name.endswith("/") or not name.lower().endswith(".xml"):
                continue
            total_xml += 1
            xml_b = z.read(name)
            mt = detect_message_type_from_xml(xml_b)
            if mt:
                detected_types.add(mt)

    detected_types = sorted(list(detected_types))
    st.info(
        f"ZIP contains {total_xml} XML file(s). "
        f"Detected message types: {detected_types if detected_types else 'None'}"
    )

    if not enterprise_enabled:
        st.caption("Community mode: enterprise rulesets (e.g., *-gpi/*-hvps) are hidden.")

    # 2) Mapping UI: per message type choose ruleset
    st.subheader("Ruleset mapping (per message type)")
    ruleset_mapping = {}

    for mt in detected_types:
        options = find_rulesets_for_message_type(mt, RULES_DIR)
        options = visible_rulesets(options)

        if not options:
            st.warning(f"No visible rulesets available for {mt}. Add a core ruleset like rules/{mt}-core.json.")
            continue

        default_rs = choose_default_ruleset(options)
        key = f"map_{mt}"

        if key not in st.session_state:
            st.session_state[key] = default_rs

        chosen = st.selectbox(
            f"{mt} → ruleset",
            options=options,
            index=options.index(st.session_state[key]) if st.session_state[key] in options else 0,
            key=key,
        )
        ruleset_mapping[mt] = chosen

    run = st.button("Run batch validation", type="primary", key="run_batch")

    if run:
        try:
            batch_results = validate_zip_bytes_with_ruleset_mapping(
                zip_bytes=zip_bytes,
                ruleset_mapping=ruleset_mapping,
                rules_dir=RULES_DIR,
            )

            # Day25: attach license level into each batch row
            for item in batch_results:
                item["license_level"] = "Enterprise" if enterprise_enabled else "Community"

            total = len(batch_results)
            valid_count = sum(1 for x in batch_results if x["validation_result"].get("status") == "VALID")
            invalid_count = total - valid_count

            st.success(f"Done. Processed {total} XML file(s) — VALID: {valid_count} | INVALID: {invalid_count}")

            batch_xlsx = build_batch_excel_report_bytes(batch_results)
            st.download_button(
                label="⬇️ Download batch Excel report (.xlsx)",
                data=batch_xlsx,
                file_name="batch_validation_report.xlsx",
                mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            )

            with st.expander("Show batch summary (first 50 rows)"):
                rows = []
                for item in batch_results[:50]:
                    vr = item["validation_result"]
                    ruleset_used = item.get("ruleset_used")
                    ruleset_tier = (ruleset_used.split("-", 1)[1] if ruleset_used and "-" in ruleset_used else "unknown")

                    rows.append(
                        {
                            "File": item.get("file_name"),
                            "Detected Type": item.get("detected_type"),
                            "License": item.get("license_level"),
                            "Ruleset Used": ruleset_used,
                            "Ruleset Tier": ruleset_tier,
                            "Status": vr.get("status"),
                            "Errors": len(vr.get("errors", [])),
                            "Warnings": len(vr.get("warnings", [])),
                        }
                    )
                st.table(rows)

        except Exception as e:
            st.error(f"Batch validation failed: {e}")
else:
    st.info("Upload a ZIP to run batch validation.")
