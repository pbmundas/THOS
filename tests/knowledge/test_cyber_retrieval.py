from services.knowledge import cyber_retrieval


class _Collection:
    def count(self):
        return 1000

    def query(self, **_kwargs):
        return {
            "documents": [[
                "incident response risk management lifecycle",
                "incident response preparation and recovery",
                "an unrelated deleted security group rule",
            ]],
            "metadatas": [[
                {
                    "citation_id": "CYBER:nist_csf_2:one:0",
                    "source_id": "nist_csf_2",
                    "source_title": "NIST CSF",
                    "record_title": "Risk management",
                    "domains": "incident_response",
                },
                {
                    "citation_id": "CYBER:nist_sp_800_61r3:two:0",
                    "source_id": "nist_sp_800_61r3",
                    "source_title": "NIST IR",
                    "record_title": "Incident response",
                    "domains": "incident_response",
                },
                {
                    "citation_id": "CYBER:sigmahq_rules:three:0",
                    "source_id": "sigmahq_rules",
                    "source_title": "Sigma",
                    "record_title": "Deleted group",
                    "domains": "threat_hunting",
                },
            ]],
            "distances": [[0.7, 0.8, 1.25]],
        }


def test_retrieval_preserves_relevant_source_diversity(monkeypatch):
    monkeypatch.setattr(cyber_retrieval, "get_or_create_collection", lambda _name: _Collection())

    hits = cyber_retrieval.search(
        "incident response risk management",
        n_results=10,
        domains=["incident_response"],
    )

    assert [hit["source"]["id"] for hit in hits] == ["nist_csf_2", "nist_sp_800_61r3"]


def test_retrieval_abstains_when_similarity_has_no_lexical_anchor(monkeypatch):
    monkeypatch.setattr(cyber_retrieval, "get_or_create_collection", lambda _name: _Collection())

    assert cyber_retrieval.search(
        "xylophone quasar zephyr",
        n_results=10,
        domains=["threat_hunting"],
    ) == []


def test_retrieval_abstains_before_lookup_for_non_public_current_observations(monkeypatch):
    monkeypatch.setattr(
        cyber_retrieval,
        "get_or_create_collection",
        lambda _name: (_ for _ in ()).throw(AssertionError("collection must not be queried")),
    )

    assert cyber_retrieval.search(
        "private unpublished indicators observed today",
        n_results=10,
        domains=["threat_hunting"],
    ) == []
