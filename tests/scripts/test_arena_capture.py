"""Tests for scripts/arena_capture.py.

All fixtures are synthetic: dummy challenge names, behavior slugs, and
criteria text. No real rubric text, model aliases, or credential material.
"""

import hashlib
import json
import sys
from pathlib import Path

import pytest

SCRIPTS_DIR = Path(__file__).resolve().parents[2] / "scripts"
sys.path.insert(0, str(SCRIPTS_DIR))

import arena_capture

# --------------------------------------------------------------------------
# Synthetic fixture builders
# --------------------------------------------------------------------------

def encode_devalue(root):
    """Encode a plain structure into devalue-style flat form.

    Objects and lists are stored in a flat array; every object field and
    list element becomes an integer index into that array. Mirrors the
    SvelteKit __data.json shape, including a leading "skip" node.
    """
    flat = []

    def enc(value):
        if isinstance(value, dict):
            slot = len(flat)
            flat.append(None)
            flat[slot] = {k: enc(v) for k, v in value.items()}
            return slot
        if isinstance(value, list):
            slot = len(flat)
            flat.append(None)
            flat[slot] = [enc(v) for v in value]
            return slot
        flat.append(value)
        return len(flat) - 1

    enc(root)
    return {"type": "data", "nodes": [{"type": "skip"}, {"type": "data", "data": flat}]}


def make_criterion(cid, name, threshold=7):
    return {
        "id": cid,
        "name": name,
        "blurb": f"{name} blurb",
        "description": f"Checks {name.lower()} in the synthetic fixture.",
        "threshold": threshold,
    }


def make_behavior(slug, name, n_criteria=2):
    return {
        "slug": slug,
        "name": name,
        "summary": f"Summary for {slug}.",
        "objective": f"Objective for {slug}.",
        "criteria": [
            make_criterion(f"{slug}-c{i}", f"Widget Assembly {i}")
            for i in range(1, n_criteria + 1)
        ],
        "judging": {
            "submitPanel": {
                "judges": {"enabled": True, "ids": ["judge-demo-1"]},
                "providers": [{"name": "provider-demo", "models": ["m-1", "m-2"]}],
            }
        },
        "flags": {"batch_submit_enabled": False},
        "tools_config": {"internetAccess": False},
    }


def synthetic_graph():
    """Small synthetic challenge graph: 2 waves, 4 behaviors, 2 models."""
    return {
        "challengeInfo": {
            "id": "demo-0001",
            "name": "Demo Challenge Alpha",
            "slug": "demo-challenge-alpha",
            "description": "Synthetic challenge used only by parser tests.",
            "start_time": "2026-08-25T10:00:00Z",
            "end_time": "2026-09-11T14:00:00Z",
            "available_prize_money": 80000,
        },
        "waves": [
            {"name": "Alpha", "behaviors": ["bid-1", "bid-2"]},
            {"name": "Beta", "behaviors": ["bid-3", "bid-4"]},
        ],
        "categories": [
            {"name": "Alpha", "behaviors": ["bid-1", "bid-2"]},
            {"name": "Beta", "behaviors": ["bid-3", "bid-4"]},
        ],
        "behaviorIdToBehaviorMap": {
            "bid-1": make_behavior("demo-behavior-alpha", "Demo Behavior Alpha", 2),
            "bid-2": make_behavior("demo-behavior-beta", "Demo Behavior Beta", 3),
            "bid-3": make_behavior("demo-behavior-gamma", "Demo Behavior Gamma", 2),
            "bid-4": make_behavior("demo-behavior-delta", "Demo Behavior Delta", 2),
        },
        "modelIdNameMap": {"m-1": "demo-model-one", "m-2": "demo-model-two"},
        "modelMap": {"m-1": {"name": "Demo Model One"}, "m-2": {"name": "Demo Model Two"}},
        "modelListsByWave": {"Alpha": ["m-1"], "Beta": ["m-2"]},
        "modelHealthByModelId": {"m-1": "healthy", "m-2": "degraded"},
        "energyConfig": {"submission_cost": 10, "message_cost": 2},
        "defaultSubmissionCost": 10,
        "defaultMessageCost": 2,
        "energyState": {"balance": 1000},
        "wave_stats": {
            "Alpha": {"totalBreaks": 1, "brokenModels": ["demo-model-one"]},
            "Beta": {"totalBreaks": 0, "brokenModels": []},
        },
        "new_prizes": [{"name": "category-prize", "amount": 20000}],
    }


def synthetic_full_graph():
    """Synthetic graph matching the parser's default self-check expectations:
    4 waves (Chemistry/Biology/Misc/Cyber), 39 behaviors, threshold 7,
    20 model aliases, prize 80000. Used for end-to-end CLI checks.
    """
    wave_names = ["Chemistry", "Biology", "Misc", "Cyber"]
    slug_to_bid = {}
    per_wave = {w: [] for w in wave_names}
    for i in range(1, 40):
        slug = f"demo-behavior-{i:02d}"
        bid = f"bid-{i:02d}"
        slug_to_bid[slug] = bid
        per_wave[wave_names[(i - 1) % 4]].append(bid)
    bmap = {
        slug_to_bid[slug]: make_behavior(slug, f"Demo Behavior {slug[-2:]}", 2)
        for slug in sorted(slug_to_bid)
    }
    models = {}
    lists_by_wave = {}
    for w in wave_names:
        lists_by_wave[w] = []
    for i in range(1, 21):
        mid = f"m-{i:02d}"
        models[mid] = f"demo-model-{i:02d}"
        lists_by_wave[wave_names[(i - 1) % 4]].append(mid)
    return {
        "challengeInfo": {
            "id": "demo-full",
            "name": "Demo Challenge Full",
            "slug": "demo-challenge-full",
            "description": "Full-size synthetic challenge for CLI smoke tests.",
            "start_time": "2026-08-25T10:00:00Z",
            "end_time": "2026-09-11T14:00:00Z",
            "available_prize_money": 80000,
        },
        "waves": [{"name": w, "behaviors": per_wave[w]} for w in wave_names],
        "categories": [{"name": w, "behaviors": per_wave[w]} for w in wave_names],
        "behaviorIdToBehaviorMap": bmap,
        "modelIdNameMap": models,
        "modelMap": {mid: {"name": alias} for mid, alias in models.items()},
        "modelListsByWave": lists_by_wave,
        "modelHealthByModelId": {mid: "healthy" for mid in models},
        "energyConfig": {"submission_cost": 10, "message_cost": 2},
        "defaultSubmissionCost": 10,
        "defaultMessageCost": 2,
        "energyState": {"balance": 1000},
        "wave_stats": {
            w: {"totalBreaks": 0, "brokenModels": []} for w in wave_names
        },
        "new_prizes": [{"name": "category-prize", "amount": 20000}],
    }


TEST_EXPECTED = {
    "wave_names": ["Alpha", "Beta"],
    "behavior_slug_count": 4,
    "criteria_count_range": (1, 5),
    "criterion_threshold": 7,
    "model_alias_count": 2,
    "prize_money": 80000,
}


def run_cli(tmp_path, payload_text, name="capture.json"):
    cap = tmp_path / name
    cap.write_text(payload_text, encoding="utf-8")
    out = tmp_path / "out"
    with pytest.raises(SystemExit) as excinfo:
        arena_capture.main(["parse-challenge", str(cap), "--out", str(out)])
    return excinfo.value.code, out


# --------------------------------------------------------------------------
# Deindexer
# --------------------------------------------------------------------------

def test_deindex_single_hop():
    flat = ["demo-id-0001", "Demo Challenge", {"_id": 0, "name": 1}]
    out = arena_capture.deindex(flat, flat[2])
    assert out == {"_id": "demo-id-0001", "name": "Demo Challenge"}


def test_deindex_does_not_reresolve_int_results():
    # Resolved int 7 is out of range for len(flat)=2: stays literal, and
    # flat[7] must never be attempted.
    flat = [7, {"threshold": 0}]
    out = arena_capture.deindex(flat, flat[1])
    assert out["threshold"] == 7

    # Stronger: the resolved int IS a valid index, but one hop stops there.
    flat2 = [1, 42, {"threshold": 0}]
    out2 = arena_capture.deindex(flat2, flat2[2])
    assert out2["threshold"] == 1  # not flat2[1] == 42


def test_deindex_literal_large_int_and_scalars():
    flat = [
        {"prize": 8518, "flag": True, "none": None, "ratio": 0.5, "label": "demo"}
    ] + ["filler"] * 99
    out = arena_capture.deindex(flat, flat[0])
    assert out["prize"] == 8518  # >= len(flat)=100: literal, not an index
    assert out["flag"] is True  # bool is a literal, never an index
    assert out["none"] is None
    assert out["ratio"] == 0.5
    assert out["label"] == "demo"


def test_deindex_resolves_into_containers_reached_via_index():
    # flat[1] is a dict whose values are themselves indices: the walk must
    # recurse into it, while int primitives stay single-hop.
    flat = [{"inner": 1, "keep": "x"}, {"deep": 2}, "y"]
    out = arena_capture.deindex(flat, flat[0])
    assert out == {"inner": {"deep": "y"}, "keep": "x"}


def test_deindex_rejects_reference_cycles():
    # root.inner.deep points back at root: unresolvable as a finite tree.
    flat = [{"inner": 1}, {"deep": 0}]
    with pytest.raises(arena_capture.ParseError) as excinfo:
        arena_capture.deindex(flat, flat[0])
    assert "cyclic" in str(excinfo.value)


def test_deindex_depth_guard():
    deep = current = {}
    for _ in range(60):
        current["next"] = {}
        current = current["next"]
    flat = [deep]
    with pytest.raises(arena_capture.ParseError):
        arena_capture.deindex(flat, flat[0])


# --------------------------------------------------------------------------
# Redaction guard
# --------------------------------------------------------------------------

def test_guard_fails_on_jwt(tmp_path):
    needle = "ey" + "JhbGciOiJIUzI1NiJ9.demo-payload"
    code, out = run_cli(tmp_path, json.dumps({"marker": needle}))
    assert code == 2
    assert not out.exists()


@pytest.mark.parametrize(
    "needle",
    ["gs_" + "stytch_session_token", "hub" + "spotutk=abc123"],
)
def test_guard_fails_on_cookie_material(tmp_path, needle):
    code, out = run_cli(tmp_path, json.dumps({"note": needle}))
    assert code == 2
    assert not out.exists()


def test_guard_names_offending_pattern():
    for pattern in arena_capture.GUARD_PATTERNS:
        with pytest.raises(arena_capture.RedactionGuardError) as excinfo:
            arena_capture.guard("harmless prefix " + pattern + " harmless suffix")
        assert pattern in str(excinfo.value)


def test_guard_precedes_parse(tmp_path):
    # Invalid JSON *and* credential material: guard must win (exit 2, not 1).
    code, out = run_cli(tmp_path, "{not json but has ey" + "Jtoken")
    assert code == 2
    assert not out.exists()


# --------------------------------------------------------------------------
# Extractor and self-check
# --------------------------------------------------------------------------

def test_extractor_shape():
    result = arena_capture.parse_challenge(
        encode_devalue(synthetic_graph()), expected=TEST_EXPECTED
    )
    assert set(result) >= {
        "challenge", "waves", "categories", "behaviors",
        "models", "energy", "wave_stats", "prizes", "parsed_at",
    }
    assert result["challenge"]["slug"] == "demo-challenge-alpha"
    assert result["challenge"]["available_prize_money"] == 80000
    assert result["challenge"]["name"] == "Demo Challenge Alpha"

    assert [w["name"] for w in result["waves"]] == ["Alpha", "Beta"]
    assert result["waves"][0]["behaviors"] == [
        "demo-behavior-alpha", "demo-behavior-beta",
    ]

    slugs = sorted(b["slug"] for b in result["behaviors"])
    assert slugs == [
        "demo-behavior-alpha", "demo-behavior-beta",
        "demo-behavior-delta", "demo-behavior-gamma",
    ]
    beta = next(b for b in result["behaviors"] if b["slug"] == "demo-behavior-beta")
    assert [c["threshold"] for c in beta["criteria"]] == [7, 7, 7]
    assert beta["criteria"][0]["name"] == "Widget Assembly 1"
    assert beta["judging"]["judges_enabled"] is True
    assert beta["flags"]["batch_submit_enabled"] is False

    assert {m["alias"] for m in result["models"]} == {
        "demo-model-one", "demo-model-two",
    }
    one = next(m for m in result["models"] if m["alias"] == "demo-model-one")
    assert one["model_id"] == "m-1"
    assert one["wave"] == "Alpha"
    assert one["health"] == "healthy"

    assert result["energy"]["defaultSubmissionCost"] == 10
    assert result["energy"]["energyConfig"]["message_cost"] == 2
    assert result["wave_stats"]["Alpha"]["totalBreaks"] == 1
    assert result["wave_stats"]["Alpha"]["brokenModels"] == ["demo-model-one"]
    assert result["prizes"] == [{"name": "category-prize", "amount": 20000}]


def test_extract_challenge_canonicalizes_short_category_names():
    graph = synthetic_graph()
    graph["categories"][0]["name"] = "Chem"
    graph["categories"][1]["name"] = "bio"

    result = arena_capture.extract_challenge(graph)

    assert [category["name"] for category in result["categories"]] == [
        "Chemistry",
        "Biology",
    ]


def test_parse_challenge_accepts_streamed_chunk_suffix(tmp_path):
    doc = encode_devalue(synthetic_graph())
    capture = tmp_path / "streamed.json"
    capture.write_text(
        json.dumps(doc) + "\n" + json.dumps({"type": "chunk", "id": 1, "data": []}),
        encoding="utf-8",
    )

    result = arena_capture.parse_challenge(capture, expected=TEST_EXPECTED)

    assert result["challenge"]["slug"] == "demo-challenge-alpha"


def test_extract_models_uses_identifiers_from_wave_model_objects():
    graph = synthetic_graph()
    graph["modelListsByWave"] = {
        "Alpha": [{"_id": "m-1"}, {"unusable": "entry"}],
        "Beta": [{"model_id": "m-2"}, []],
    }

    models = arena_capture.extract_challenge(graph)["models"]

    waves = {model["model_id"]: model["wave"] for model in models}
    assert waves == {"m-1": "Alpha", "m-2": "Beta"}


def test_extract_models_reads_aliases_from_model_object_lists():
    graph = synthetic_graph()
    graph["modelIdNameMap"] = {
        "m-1": [{"name": "demo-model-one"}],
        "m-2": [{"name": "demo-model-two"}],
    }
    graph["modelMap"] = {
        "demo-model-one": {"name": "demo-model-one"},
        "demo-model-two": {"name": "demo-model-two"},
    }

    models = arena_capture.extract_challenge(graph)["models"]

    assert {model["alias"] for model in models} == {
        "demo-model-one",
        "demo-model-two",
    }
    assert len(models) == 2


def test_extract_challenge_normalizes_dict_and_integer_behavior_entries():
    graph = synthetic_graph()
    behavior_map = {}
    behavior_ids = {}
    for index, behavior in enumerate(graph["behaviorIdToBehaviorMap"].values(), start=101):
        behavior["behaviorId"] = index
        behavior_map[behavior["slug"]] = behavior
        behavior_ids[behavior["slug"]] = index
    graph["behaviorIdToBehaviorMap"] = behavior_map
    graph["waves"] = [
        {
            "name": "Alpha",
            "behaviors": [
                behavior_ids["demo-behavior-alpha"],
                behavior_ids["demo-behavior-beta"],
            ],
        },
        {
            "name": "Beta",
            "behaviors": [
                behavior_ids["demo-behavior-gamma"],
                behavior_ids["demo-behavior-delta"],
            ],
        },
    ]
    graph["categories"] = [
        {
            "name": "Alpha",
            "behaviors": [
                {"id": behavior_ids["demo-behavior-alpha"]},
                behavior_ids["demo-behavior-beta"],
            ],
        },
        {
            "name": "Beta",
            "behaviors": [
                behavior_ids["demo-behavior-gamma"],
                {"id": behavior_ids["demo-behavior-delta"]},
            ],
        },
    ]

    result = arena_capture.extract_challenge(graph)

    assert result["waves"][0]["behaviors"] == [
        "demo-behavior-alpha",
        "demo-behavior-beta",
    ]
    assert result["categories"][1]["behaviors"] == [
        "demo-behavior-gamma",
        "demo-behavior-delta",
    ]


def test_extract_challenge_reads_waves_and_areas_from_challenge_info():
    graph = synthetic_graph()
    graph["challengeInfo"]["waves"] = graph.pop("waves")
    graph["challengeInfo"]["areas"] = graph.pop("categories")

    result = arena_capture.parse_challenge(
        encode_devalue(graph), expected=TEST_EXPECTED
    )

    assert [wave["name"] for wave in result["waves"]] == ["Alpha", "Beta"]
    assert result["categories"][0]["behaviors"] == [
        "demo-behavior-alpha",
        "demo-behavior-beta",
    ]


def test_self_check_fails_on_tampered_count(tmp_path):
    # CLI self-check runs against the hazard-hunt defaults; a 4-behavior
    # synthetic fixture therefore fails the 39-slug expectation -> exit 3.
    doc = encode_devalue(synthetic_graph())
    code, out = run_cli(tmp_path, json.dumps(doc), name="tampered.json")
    assert code == 3
    assert not out.exists()


def test_self_check_catches_tampered_threshold():
    graph = synthetic_graph()
    graph["behaviorIdToBehaviorMap"]["bid-1"]["criteria"][0]["threshold"] = 5
    with pytest.raises(arena_capture.SelfCheckError) as excinfo:
        arena_capture.parse_challenge(
            encode_devalue(graph), expected=TEST_EXPECTED
        )
    assert "threshold" in str(excinfo.value)


# --------------------------------------------------------------------------
# Real-payload shapes (synthetic fixtures mirroring the live capture)
# --------------------------------------------------------------------------

def test_extractor_model_objects_in_wave_lists():
    # modelListsByWave entries are full model OBJECTS, not id strings.
    graph = synthetic_graph()
    graph["modelListsByWave"] = {
        "Alpha": [{"model_id": "m-1", "name": "demo-model-one"}],
        "Beta": [{"model_id": "m-2", "name": "demo-model-two"}],
    }
    result = arena_capture.parse_challenge(
        encode_devalue(graph), expected=TEST_EXPECTED
    )
    assert len(result["models"]) == 2
    one = next(m for m in result["models"] if m["alias"] == "demo-model-one")
    assert one["model_id"] == "m-1"
    assert one["wave"] == "Alpha"
    two = next(m for m in result["models"] if m["alias"] == "demo-model-two")
    assert two["wave"] == "Beta"


def test_extractor_health_keyed_by_alias_dedupes():
    # modelHealthByModelId may be keyed by ALIAS, not model id: the health
    # keys must resolve onto the existing models instead of minting
    # alias-duplicate entries.
    graph = synthetic_graph()
    graph["modelHealthByModelId"] = {
        "demo-model-one": "healthy",
        "demo-model-two": "degraded",
    }
    result = arena_capture.parse_challenge(
        encode_devalue(graph), expected=TEST_EXPECTED
    )
    models = result["models"]
    assert len(models) == 2  # no duplicates from health keys
    aliases = [m["alias"] for m in models]
    assert len(set(aliases)) == 2
    one = next(m for m in models if m["alias"] == "demo-model-one")
    assert one["health"] == "healthy"
    two = next(m for m in models if m["alias"] == "demo-model-two")
    assert two["health"] == "degraded"


def test_extractor_wave_and_category_entries_as_objects():
    # waves/categories behavior entries may be behavior OBJECTS carrying a
    # slug instead of behavior ids.
    graph = synthetic_graph()
    by_slug = {
        b["slug"]: b for b in graph["behaviorIdToBehaviorMap"].values()
    }
    graph["waves"] = [
        {
            "name": "Alpha",
            "behaviors": [by_slug["demo-behavior-alpha"],
                          by_slug["demo-behavior-beta"]],
        },
        {
            "name": "Beta",
            "behaviors": [by_slug["demo-behavior-gamma"],
                          by_slug["demo-behavior-delta"]],
        },
    ]
    graph["categories"] = [dict(w) for w in graph["waves"]]
    result = arena_capture.parse_challenge(
        encode_devalue(graph), expected=TEST_EXPECTED
    )
    assert result["waves"][0]["behaviors"] == [
        "demo-behavior-alpha", "demo-behavior-beta",
    ]
    assert result["categories"][1]["behaviors"] == [
        "demo-behavior-gamma", "demo-behavior-delta",
    ]


def synthetic_realshape_graph():
    """Synthetic graph in the shape the real Arena capture uses:
    challengeInfo doubles as the full challenge document (waves live on it,
    categories is empty, the doc id is `_id`), behaviors key their slug as
    `behaviorId`, and modelIdNameMap values are single-entry model-object
    lists.
    """
    graph = synthetic_graph()
    bmap = {}
    for bid, behavior in graph["behaviorIdToBehaviorMap"].items():
        behavior = dict(behavior)
        behavior["behaviorId"] = behavior.pop("slug")
        bmap[bid] = behavior
    graph["behaviorIdToBehaviorMap"] = bmap

    doc = dict(graph.pop("challengeInfo"))
    doc["_id"] = doc.pop("id")
    slug_of = {bid: b["behaviorId"] for bid, b in bmap.items()}
    doc["waves"] = [
        {"name": "Alpha", "behaviors": [slug_of["bid-1"], slug_of["bid-2"]]},
        {"name": "Beta", "behaviors": [slug_of["bid-3"], slug_of["bid-4"]]},
    ]
    doc["categories"] = []
    graph["challengeInfo"] = doc
    graph.pop("waves")
    graph.pop("categories")

    graph["modelIdNameMap"] = {
        mid: [{"model_id": mid, "name": alias}]
        for mid, alias in graph["modelIdNameMap"].items()
    }
    return graph


def test_extractor_real_payload_shapes():
    result = arena_capture.parse_challenge(
        encode_devalue(synthetic_realshape_graph()), expected=TEST_EXPECTED
    )
    # behaviorId fallback for behavior slugs
    slugs = sorted(b["slug"] for b in result["behaviors"])
    assert slugs == [
        "demo-behavior-alpha", "demo-behavior-beta",
        "demo-behavior-delta", "demo-behavior-gamma",
    ]
    # waves live on the challengeInfo document
    assert [w["name"] for w in result["waves"]] == ["Alpha", "Beta"]
    assert result["waves"][0]["behaviors"] == [
        "demo-behavior-alpha", "demo-behavior-beta",
    ]
    # empty categories fall back to the wave grouping
    assert [c["name"] for c in result["categories"]] == ["Alpha", "Beta"]
    # document id comes from _id
    assert result["challenge"]["id"] == "demo-0001"
    # modelIdNameMap values are single-entry model-object lists
    models = result["models"]
    assert len(models) == 2
    assert {m["alias"] for m in models} == {"demo-model-one", "demo-model-two"}
    one = next(m for m in models if m["alias"] == "demo-model-one")
    assert one["model_id"] == "m-1"


# --------------------------------------------------------------------------
# Streamed-chunk bodies
# --------------------------------------------------------------------------

def test_parse_challenge_tolerates_streamed_chunks(tmp_path):
    # SvelteKit streamed responses concatenate patch objects after the base
    # document; parse only the first (complete) JSON object.
    doc = encode_devalue(synthetic_realshape_graph())
    body = (
        json.dumps(doc)
        + '\n{"type":"chunk","id":1,"data":[[]]}\n'
        + '{"type":"chunk","id":2,"data":[1341]}\n'
    )
    cap = tmp_path / "streamed.json"
    cap.write_text(body, encoding="utf-8")
    result = arena_capture.parse_challenge(cap, expected=TEST_EXPECTED)
    assert result["challenge"]["slug"] == "demo-challenge-alpha"


def test_cli_tolerates_streamed_chunks(tmp_path):
    doc = encode_devalue(synthetic_full_graph())
    body = (
        json.dumps(doc)
        + '\n{"type":"chunk","id":1,"data":[[]]}\n'
        + '{"type":"chunk","id":2,"data":[1341]}\n'
        + '{"type":"chunk","id":3,"data":[0]}\n'
    )
    cap = tmp_path / "streamed.json"
    cap.write_text(body, encoding="utf-8")
    out = tmp_path / "out"
    with pytest.raises(SystemExit) as excinfo:
        arena_capture.main(["parse-challenge", str(cap), "--out", str(out)])
    assert excinfo.value.code == 0
    result = json.loads(
        (out / "hazard_hunt_q3_challenge.local.json").read_text(encoding="utf-8")
    )
    assert len(result["behaviors"]) == 39
    assert len(result["models"]) == 20


def test_streamed_garbage_chunk_still_parses_first_object(tmp_path):
    doc = encode_devalue(synthetic_realshape_graph())
    body = json.dumps(doc) + "\n{not valid json at all}\n"
    cap = tmp_path / "streamed-garbage.json"
    cap.write_text(body, encoding="utf-8")
    result = arena_capture.parse_challenge(cap, expected=TEST_EXPECTED)
    assert result["challenge"]["slug"] == "demo-challenge-alpha"


# --------------------------------------------------------------------------
# CLI error handling
# --------------------------------------------------------------------------

def test_malformed_json_clean_error(tmp_path):
    code, out = run_cli(tmp_path, "{definitely not valid json")
    assert code == 1
    assert not out.exists()


def test_missing_input_file_clean_error(tmp_path):
    out = tmp_path / "out"
    with pytest.raises(SystemExit) as excinfo:
        arena_capture.main(
            ["parse-challenge", str(tmp_path / "nope.json"), "--out", str(out)]
        )
    assert excinfo.value.code == 1
    assert not out.exists()


def test_cli_happy_path_matches_defaults(tmp_path):
    # Full-size synthetic fixture that satisfies the hazard-hunt self-check.
    cap = tmp_path / "full.json"
    cap.write_text(
        json.dumps(encode_devalue(synthetic_full_graph()))
        + "\n"
        + json.dumps({"type": "chunk", "id": 1, "data": []}),
        encoding="utf-8",
    )
    out = tmp_path / "out"
    with pytest.raises(SystemExit) as excinfo:
        arena_capture.main(["parse-challenge", str(cap), "--out", str(out)])
    assert excinfo.value.code == 0
    files = sorted(p.name for p in out.iterdir())
    assert files == ["hazard_hunt_q3_challenge.local.json"]
    result = json.loads((out / files[0]).read_text(encoding="utf-8"))
    assert result["challenge"]["slug"] == "demo-challenge-full"
    assert len(result["behaviors"]) == 39
    assert len(result["models"]) == 20


# --------------------------------------------------------------------------
# Submissions converter (convert-submissions)
# --------------------------------------------------------------------------

SCORE_CSV_HEADER = (
    "category,behavior_slug,model_alias,attempts,criteria_best_met,"
    "criteria_total,min_best,weakest_criterion,weakest_best_score,break"
)


def submissions_challenge():
    """Synthetic parse-challenge output shape: 2 behaviors, 2 models."""
    return {
        "behaviors": [
            {"slug": "demo-a", "name": "Demo A", "criteria": [
                {"id": "a-1", "name": "Alpha", "threshold": 7},
                {"id": "a-2", "name": "Beta", "threshold": 7},
            ]},
            {"slug": "demo-b", "name": "Demo B", "criteria": [
                {"id": "b-1", "name": "Gamma", "threshold": 7},
            ]},
        ],
        "categories": [
            {"name": "CatOne", "behaviors": ["demo-a"]},
            {"name": "CatTwo", "behaviors": ["demo-b"]},
        ],
        "models": [
            {"model_id": "m1", "alias": "demo-alias-one"},
            {"model_id": "m2", "alias": "demo-alias-two"},
        ],
    }


FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"
GS_FIXTURE = FIXTURES_DIR / "gs_submissions_demo.jsonl"
GS_CHALLENGE_FIXTURE = FIXTURES_DIR / "gs_submissions_demo_challenge.json"

LEGACY_ATTEMPT_KEYS = (
    "id", "created_at", "behavior", "category", "model_alias", "grade_status",
    "successful", "energy_spent", "criteria", "is_break", "judge_analysis",
    "message_count", "user_prompt_sha256",
)
FORBIDDEN_OUTPUT_KEYS = ("content", "conversation", "tool_calls", "reasoning")


def gs_record(submission_id, behavior_name, model_name, status="failure",
              scraped_at="2026-08-26T10:00:00Z", conversation=None, **extra):
    """One synthetic gs-submissions export record (upstream src/models.py shape)."""
    record = {
        "submission_id": submission_id,
        "chat_id": f"chat-{submission_id}",
        "arena": "demo-arena",
        "model_name": model_name,
        "behavior_name": behavior_name,
        "behavior_criteria": ["demo criterion text"],
        "behavior_type": "demo-type",
        "attack_type": "demo-attack",
        "wave": "Alpha",
        "timestamp_raw": "2026-08-26T00:00:00Z",
        "status": status,
        "conversation": conversation if conversation is not None else [
            {"role": "user", "content": f"demo prompt body for {submission_id}",
             "order": 1},
            {"role": "assistant", "content": f"demo answer for {submission_id}",
             "order": 2},
        ],
        "detail_url": f"https://arena.example.invalid/submissions/{submission_id}",
        "scraped_at": scraped_at,
    }
    record.update(extra)
    return record


def write_jsonl(path, records):
    path.write_text(
        "\n".join(json.dumps(r) for r in records) + "\n", encoding="utf-8"
    )
    return path


def walk_for_forbidden(node):
    hits = []
    if isinstance(node, dict):
        for key, value in node.items():
            if key in FORBIDDEN_OUTPUT_KEYS:
                hits.append(key)
            hits.extend(walk_for_forbidden(value))
    elif isinstance(node, list):
        for item in node:
            hits.extend(walk_for_forbidden(item))
    return hits


def test_convert_subcommand_help(capsys):
    with pytest.raises(SystemExit) as excinfo:
        arena_capture.main(["convert-submissions", "--help"])
    assert excinfo.value.code == 0
    assert "convert-submissions" in capsys.readouterr().out


def test_convert_golden_fixture_end_to_end(tmp_path, capsys):
    out = tmp_path / "out"
    with pytest.raises(SystemExit) as excinfo:
        arena_capture.main(
            ["convert-submissions", str(GS_FIXTURE),
             "--challenge", str(GS_CHALLENGE_FIXTURE), "--out", str(out)]
        )
    assert excinfo.value.code == 0

    attempts_path = out / "attempts.local.jsonl"
    scoreboard_path = out / "hazard_hunt_q3_scoreboard.local.json"
    csv_path = out / "hazard_hunt_q3_scoreboard.local.csv"
    assert all(p.exists() for p in (attempts_path, scoreboard_path, csv_path))

    attempts = [json.loads(line) for line in
                attempts_path.read_text(encoding="utf-8").splitlines()]
    assert len(attempts) == 2
    for attempt in attempts:
        assert tuple(sorted(attempt)) == tuple(sorted(LEGACY_ATTEMPT_KEYS))

    # Sorted by created_at: sub-002 scraped 09:00 sorts before sub-001 12:00.
    assert [a["id"] for a in attempts] == ["sub-002", "sub-001"]
    assert attempts[0] == {
        "id": "sub-002",
        "created_at": "2026-08-26T09:00:00Z",
        "behavior": "demo-b",
        "category": "CatTwo",
        "model_alias": "demo-alias-two",
        "grade_status": "failure",
        "successful": False,
        "energy_spent": None,
        "criteria": [],
        "is_break": False,
        "judge_analysis": [],
        "message_count": 0,
        "user_prompt_sha256": None,
    }
    sub1 = attempts[1]
    assert sub1["created_at"] == "2026-08-26T12:00:00Z"
    # Duplicate submission_id: the LAST line wins (failure over success).
    assert sub1["grade_status"] == "failure"
    assert sub1["successful"] is False
    assert sub1["is_break"] is False
    assert sub1["message_count"] == 3
    # First user turn BY order, not array position.
    assert sub1["user_prompt_sha256"] == hashlib.sha256(
        b"demo prompt body for sub-001"
    ).hexdigest()

    scoreboard = json.loads(scoreboard_path.read_text(encoding="utf-8"))
    assert scoreboard["data_source"] == "gs-submissions@6128748"
    assert set(scoreboard["cells"]) == {
        "demo-a|demo-alias-one", "demo-b|demo-alias-two",
    }
    totals = scoreboard["rollups"]["totals"]
    assert totals == {
        "behaviors": 2, "models": 2, "cells_total": 4,
        "cells_tried": 2, "submissions": 2, "breaks": 0,
    }
    cell = scoreboard["cells"]["demo-a|demo-alias-one"]
    assert cell["attempts"] == 1
    assert cell["min_best"] is None
    assert cell["break"] is False
    assert cell["last_attempted"] == "2026-08-26T12:00:00Z"
    assert cell["criteria_total"] == 2

    # No conversation text anywhere in the outputs.
    for path in (attempts_path, scoreboard_path, csv_path):
        assert "demo prompt body" not in path.read_text(encoding="utf-8")
    for line in attempts:
        assert walk_for_forbidden(line) == []
    assert walk_for_forbidden(scoreboard) == []

    # CSV keeps its columns; score columns stay empty.
    csv_lines = csv_path.read_text(encoding="utf-8").splitlines()
    assert csv_lines[0] == SCORE_CSV_HEADER
    assert csv_lines[1:] == [
        "CatOne,demo-a,demo-alias-one,1,0,2,,,,False",
        "CatTwo,demo-b,demo-alias-two,1,0,1,,,,False",
    ]

    # Exactly one stderr line: the caveat.
    captured = capsys.readouterr()
    stderr_lines = captured.err.strip().splitlines()
    assert len(stderr_lines) == 1
    assert "caveat" in stderr_lines[0]


def test_convert_status_success_drives_break(tmp_path):
    scrape = write_jsonl(tmp_path / "scrape.jsonl", [
        gs_record("sub-s1", "Demo A", "m1", status="success"),
    ])
    result = arena_capture.convert_submissions(
        [scrape], submissions_challenge(), challenge_source="challenge.local.json"
    )
    attempt = result["attempts"][0]
    assert attempt["successful"] is True
    assert attempt["is_break"] is True
    cell = result["scoreboard"]["cells"]["demo-a|demo-alias-one"]
    assert cell["break"] is True  # status-derived, with zero criterion scores
    assert cell["min_best"] is None
    assert result["scoreboard"]["rollups"]["totals"]["breaks"] == 1


def test_build_cells_status_break_or_criterion_break():
    attempts = [
        # status-derived break with no criterion scores at all
        {"behavior": "demo-a", "category": "CatOne", "model_alias": "m-one",
         "created_at": "2026-08-26T10:00:00Z", "criteria": [], "is_break": True},
        # criterion-derived break: every criterion best-met at >= 7
        {"behavior": "demo-a", "category": "CatOne", "model_alias": "m-two",
         "created_at": "2026-08-26T10:00:00Z",
         "criteria": [{"name": "Alpha", "score": 7}, {"name": "Beta", "score": 9}],
         "is_break": False},
        # neither
        {"behavior": "demo-b", "category": "CatTwo", "model_alias": "m-one",
         "created_at": "2026-08-26T10:00:00Z", "criteria": [], "is_break": False},
    ]
    cells = arena_capture._build_cells(attempts, {"demo-a": 2, "demo-b": 1})
    assert set(cells) == {"demo-a|m-one", "demo-a|m-two", "demo-b|m-one"}
    assert cells["demo-a|m-one"]["break"] is True
    assert cells["demo-a|m-two"]["break"] is True
    assert cells["demo-b|m-one"]["break"] is False
    # the status-break OR adds no cell fields
    assert set(cells["demo-a|m-one"]) == {
        "behavior", "category", "model_alias", "attempts", "best_per_criterion",
        "criteria_best_met", "criteria_total", "min_best", "last_attempted",
        "break",
    }


def test_convert_dedupe_last_wins_and_sort_by_created_at(tmp_path):
    scrape = write_jsonl(tmp_path / "scrape.jsonl", [
        gs_record("sub-dup", "Demo A", "m1", status="success",
                  scraped_at="2026-08-26T10:00:00Z"),
        gs_record("sub-dup", "Demo A", "m1", status="failure",
                  scraped_at="2026-08-26T08:00:00Z"),
        gs_record("sub-new", "Demo B", "m2", scraped_at="2026-08-26T09:00:00Z"),
    ])
    result = arena_capture.convert_submissions([scrape], submissions_challenge())
    attempts = result["attempts"]
    assert [a["id"] for a in attempts] == ["sub-dup", "sub-new"]
    assert attempts[0]["grade_status"] == "failure"  # last line wins
    assert attempts[0]["is_break"] is False

    # Across files: later files override earlier ones.
    f1 = write_jsonl(tmp_path / "a.jsonl", [
        gs_record("sub-f", "Demo A", "m1", status="success"),
    ])
    f2 = write_jsonl(tmp_path / "b.jsonl", [
        gs_record("sub-f", "Demo A", "m1", status="failure"),
    ])
    result = arena_capture.convert_submissions([f1, f2], submissions_challenge())
    assert result["attempts"][0]["grade_status"] == "failure"


def test_convert_reconciliation_casefold_unique_resolves(tmp_path):
    scrape = write_jsonl(tmp_path / "scrape.jsonl", [
        gs_record("sub-cf", "  DEMO a  ", "  Demo-Alias-One "),
    ])
    result = arena_capture.convert_submissions(
        [scrape], submissions_challenge(), challenge_source="challenge.local.json"
    )
    attempt = result["attempts"][0]
    assert attempt["behavior"] == "demo-a"
    assert attempt["category"] == "CatOne"
    assert attempt["model_alias"] == "demo-alias-one"


def test_convert_reconciliation_ambiguous_error(tmp_path):
    challenge = submissions_challenge()
    challenge["behaviors"].append(
        {"slug": "demo-a-two", "name": "demo a", "criteria": []}
    )
    scrape = write_jsonl(tmp_path / "scrape.jsonl", [
        gs_record("sub-amb", "DEMO A", "m1"),
    ])
    with pytest.raises(arena_capture.ParseError) as excinfo:
        arena_capture.convert_submissions(
            [scrape], challenge, challenge_source="challenge.local.json"
        )
    message = str(excinfo.value)
    assert "sub-amb" in message
    assert "DEMO A" in message
    assert "challenge.local.json" in message
    assert "demo-a" in message and "demo-a-two" in message


def test_convert_reconciliation_zero_match_error(tmp_path):
    scrape = write_jsonl(tmp_path / "scrape.jsonl", [
        gs_record("sub-zero", "Demo Missing", "m1"),
    ])
    with pytest.raises(arena_capture.ParseError) as excinfo:
        arena_capture.convert_submissions(
            [scrape], submissions_challenge(),
            challenge_source="challenge.local.json"
        )
    message = str(excinfo.value)
    assert "sub-zero" in message
    assert "Demo Missing" in message
    assert "challenge.local.json" in message


def test_convert_unknown_model_name_errors(tmp_path):
    scrape = write_jsonl(tmp_path / "scrape.jsonl", [
        gs_record("sub-mx", "Demo A", "model-not-in-challenge"),
    ])
    with pytest.raises(arena_capture.ParseError) as excinfo:
        arena_capture.convert_submissions(
            [scrape], submissions_challenge(),
            challenge_source="challenge.local.json"
        )
    message = str(excinfo.value)
    assert "sub-mx" in message
    assert "model-not-in-challenge" in message


def test_convert_malformed_jsonl_line_names_file_and_line(tmp_path):
    scrape = tmp_path / "scrape.jsonl"
    scrape.write_text(
        json.dumps(gs_record("sub-ok", "Demo A", "m1")) + "\n\n{oops not json\n",
        encoding="utf-8",
    )
    with pytest.raises(arena_capture.ParseError) as excinfo:
        arena_capture.convert_submissions([scrape], submissions_challenge())
    message = str(excinfo.value)
    assert "scrape.jsonl" in message
    assert "line 3" in message


def test_convert_missing_submission_id_errors(tmp_path):
    scrape = tmp_path / "scrape.jsonl"
    scrape.write_text(
        json.dumps({"behavior_name": "Demo A", "model_name": "m1"}) + "\n",
        encoding="utf-8",
    )
    with pytest.raises(arena_capture.ParseError) as excinfo:
        arena_capture.convert_submissions([scrape], submissions_challenge())
    message = str(excinfo.value)
    assert "line 1" in message
    assert "submission_id" in message


def test_convert_forbidden_key_booby_trap_trips():
    booby = {
        "attempts": [
            {key: None for key in LEGACY_ATTEMPT_KEYS} | {"content": "LEAK"}
        ],
        "scoreboard": {"cells": {}, "rollups": {}},
    }
    with pytest.raises(arena_capture.ParseError) as excinfo:
        arena_capture._assert_no_forbidden_keys(booby)
    assert "content" in str(excinfo.value)

    nested = {"cells": {"k": {"conversation": ["LEAK"]}}}
    with pytest.raises(arena_capture.ParseError) as excinfo:
        arena_capture._assert_no_forbidden_keys(nested)
    assert "conversation" in str(excinfo.value)


def test_convert_empty_jsonl(tmp_path):
    scrape = tmp_path / "empty.jsonl"
    scrape.write_text("\n\n", encoding="utf-8")
    result = arena_capture.convert_submissions([scrape], submissions_challenge())
    assert result["attempts"] == []
    scoreboard = result["scoreboard"]
    assert scoreboard["cells"] == {}
    totals = scoreboard["rollups"]["totals"]
    assert totals["submissions"] == 0
    assert totals["cells_tried"] == 0


def test_convert_cli_unknown_behavior_exits_1_writes_nothing(tmp_path):
    scrape = write_jsonl(tmp_path / "scrape.jsonl", [
        gs_record("sub-x", "Nope Behavior", "m1"),
    ])
    chal = tmp_path / "challenge.local.json"
    chal.write_text(json.dumps(submissions_challenge()), encoding="utf-8")
    out = tmp_path / "out"
    with pytest.raises(SystemExit) as excinfo:
        arena_capture.main(
            ["convert-submissions", str(scrape),
             "--challenge", str(chal), "--out", str(out)]
        )
    assert excinfo.value.code == 1
    assert not out.exists()  # preflight fails before anything is written


def test_convert_cli_missing_challenge_clean_error(tmp_path):
    scrape = write_jsonl(tmp_path / "scrape.jsonl", [
        gs_record("sub-ok", "Demo A", "m1"),
    ])
    out = tmp_path / "out"
    with pytest.raises(SystemExit) as excinfo:
        arena_capture.main(
            ["convert-submissions", str(scrape),
             "--challenge", str(tmp_path / "nope.json"), "--out", str(out)]
        )
    assert excinfo.value.code == 1
    assert not out.exists()


def api_record(_id, behavior, model_id, successful=False, grade_status="fail",
               created_at="2026-08-26T11:00:00Z", grading=None, messages=None):
    """One synthetic Arena panels-API record (the platform's own shape)."""
    return {
        "_id": _id,
        "user_id": "user-1",
        "behavior": behavior,
        "category": None,
        "chat_id": f"chat-{_id}",
        "model_id": model_id,
        "title": f"Demo Model: prompt for {_id}",
        "messages": messages if messages is not None else [
            {"role": "user", "content": f"demo prompt body for {_id}"},
            {"role": "assistant", "content": f"demo answer for {_id}"},
        ],
        "successful": successful,
        "grade_status": grade_status,
        "created_at": created_at,
        "updated_at": created_at,
        "energy_deducted_from_regen": 7,
        "energy_deducted_from_bank": 3,
        "grading": grading if grading is not None else {},
        "detail_url": (
            f"https://app.grayswan.ai/arena/challenge/hazard-hunt-q3"
            f"?chatId=chat-{_id}&submissionId={_id}"
        ),
    }


def api_grading(*criteria, is_break=False):
    return {
        "is_break": is_break,
        "criteria": {
            f"crit-{i}": {
                "criteria_name": name,
                "score": score,
                "analysis": f"analysis for {name}",
            }
            for i, (name, score) in enumerate(criteria)
        },
    }


def test_convert_api_records_full_fidelity(tmp_path, capsys):
    scrape = write_jsonl(tmp_path / "api.jsonl", [
        api_record(
            "api-1", "demo-a", "m1", successful=True, grade_status="pass",
            grading=api_grading(("alpha", 8), ("beta", 9), is_break=True),
        ),
        api_record(
            "api-2", "demo-b", "m2", successful=False, grade_status="fail",
            grading=api_grading(("gamma", 4)),
            created_at="2026-08-26T12:00:00Z",
            messages=[{"role": "user", "content": "only the user turn"}],
        ),
        api_record(
            "api-3", "demo-b", "m2", successful=False, grade_status="fail",
            messages=[],
        ),
    ])
    out = tmp_path / "out"
    with pytest.raises(SystemExit) as excinfo:
        arena_capture.main(
            ["convert-submissions", str(scrape),
             "--challenge", str(GS_CHALLENGE_FIXTURE), "--out", str(out)]
        )
    assert excinfo.value.code == 0

    stderr = capsys.readouterr().err
    assert "caveat" not in stderr

    attempts = [json.loads(line) for line in
                (out / "attempts.local.jsonl").read_text(encoding="utf-8").splitlines()]
    assert len(attempts) == 3
    for attempt in attempts:
        assert tuple(sorted(attempt)) == tuple(sorted(LEGACY_ATTEMPT_KEYS))
        assert not walk_for_forbidden(attempt)
    by_id = {a["id"]: a for a in attempts}
    a1 = by_id["api-1"]
    assert a1["criteria"] == [{"name": "alpha", "score": 8}, {"name": "beta", "score": 9}]
    assert a1["energy_spent"] == 10
    assert a1["is_break"] is True
    assert a1["judge_analysis"] == ["analysis for alpha", "analysis for beta"]
    assert a1["successful"] is True
    assert a1["grade_status"] == "pass"
    assert a1["message_count"] == 2
    assert a1["user_prompt_sha256"] == hashlib.sha256(
        b"demo prompt body for api-1"
    ).hexdigest()
    a2 = by_id["api-2"]
    assert a2["criteria"] == [{"name": "gamma", "score": 4}]
    assert a2["energy_spent"] == 10
    assert a2["is_break"] is False
    assert a2["message_count"] == 1
    assert a2["user_prompt_sha256"] == hashlib.sha256(
        b"only the user turn"
    ).hexdigest()
    a3 = by_id["api-3"]
    assert a3["criteria"] == []
    assert a3["message_count"] == 0
    assert a3["user_prompt_sha256"] is None
    assert a3["energy_spent"] == 10  # helper defaults: 7 regen + 3 bank

    scoreboard = json.loads(
        (out / "hazard_hunt_q3_scoreboard.local.json").read_text(encoding="utf-8")
    )
    assert scoreboard["data_source"] == "arena-panels-api"
    # demo-a: both criteria >= 7 -> criteria-derived break.
    cell = scoreboard["cells"]["demo-a|demo-alias-one"]
    assert cell["break"] is True
    assert cell["best_per_criterion"] == {"alpha": 8, "beta": 9}
    assert cell["criteria_best_met"] == 2
    # demo-b: gamma 4 < 7 -> not a criteria break, and not a status break.
    assert scoreboard["cells"]["demo-b|demo-alias-two"]["break"] is False


def test_convert_mixed_shapes_get_compound_marker(tmp_path):
    scrape = write_jsonl(tmp_path / "mixed.jsonl", [
        gs_record("sub-gs", "Demo A", "m1"),
        api_record("api-1", "demo-a", "m1", successful=True,
                   grade_status="pass", grading=api_grading(("alpha", 8), is_break=True)),
    ])
    result = arena_capture.convert_submissions([scrape], submissions_challenge())
    assert result["scoreboard"]["data_source"] == (
        "gs-submissions@6128748+arena-panels-api"
    )


def test_convert_api_record_missing_id_errors(tmp_path):
    scrape = tmp_path / "api.jsonl"
    rec = api_record("api-1", "demo-a", "m1")
    del rec["_id"]
    scrape.write_text(json.dumps(rec) + "\n", encoding="utf-8")
    with pytest.raises(arena_capture.ParseError) as excinfo:
        arena_capture.convert_submissions([scrape], submissions_challenge())
    assert "submission_id" in str(excinfo.value)
