"""Render the chart and verify that entity-risk reads can reach fusion."""

from __future__ import annotations

import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
CHART = ROOT / "infra" / "helm" / "aisoc"
HELM = shutil.which("helm")


@unittest.skipUnless(HELM, "Helm is required; these tests run in the Helm render workflow")
class FusionGatewayHelmTests(unittest.TestCase):
    def render(self, values: dict | None = None, *, ha: bool = False) -> list[dict]:
        with tempfile.TemporaryDirectory() as directory:
            overrides = Path(directory) / "values.yaml"
            overrides.write_text(yaml.safe_dump(values or {}), encoding="utf-8")
            command = [HELM or "helm", "template", "fusion-check", str(CHART), "--namespace", "aisoc-test"]
            if ha:
                command.extend(["-f", str(CHART / "values-ha.yaml")])
            command.extend(["-f", str(overrides)])
            result = subprocess.run(command, capture_output=True, text=True, check=True, timeout=30)  # noqa: S603
        return [document for document in yaml.safe_load_all(result.stdout) if document]

    def deployment(self, objects: list[dict], component: str = "api") -> dict:
        return next(
            obj
            for obj in objects
            if obj["kind"] == "Deployment" and obj["metadata"]["labels"].get("app.kubernetes.io/component") == component
        )

    def environment(self, objects: list[dict], component: str = "api", secrets: dict[str, dict[str, str]] | None = None) -> dict[str, str]:
        configmaps = {obj["metadata"]["name"]: obj.get("data", {}) for obj in objects if obj["kind"] == "ConfigMap"}
        container = self.deployment(objects, component)["spec"]["template"]["spec"]["containers"][0]
        environment: dict[str, str] = {}
        for source in container.get("envFrom", []):
            if "configMapRef" in source:
                environment.update(configmaps[source["configMapRef"]["name"]])
            elif "secretRef" in source:
                environment.update((secrets or {}).get(source["secretRef"]["name"], {}))
        environment.update({entry["name"]: entry["value"] for entry in container["env"] if "value" in entry})
        return environment

    def test_api_targets_the_fusion_service_this_chart_renders(self) -> None:
        for values, ha in (
            ({}, False),
            ({}, True),
            ({"fullnameOverride": "custom-soc", "services": {"alert-fusion": {"service": {"port": 8083}}}}, False),
        ):
            with self.subTest(values=values, ha=ha):
                objects = self.render(values, ha=ha)
                fusion = next(
                    obj
                    for obj in objects
                    if obj["kind"] == "Service" and obj["metadata"]["labels"].get("app.kubernetes.io/component") == "alert-fusion"
                )
                port = next(port["port"] for port in fusion["spec"]["ports"] if port["name"] == "http")
                expected = f"http://{fusion['metadata']['name']}:{port}"
                environment = self.environment(objects)
                self.assertEqual(environment.get("FUSION_SERVICE_URL") or environment.get("FUSION_URL"), expected)

    def test_operator_urls_are_not_masked_by_the_chart_default(self) -> None:
        for key in ("FUSION_SERVICE_URL", "FUSION_URL"):
            for source in ("service", "global"):
                for value in ("https://fusion.example.test:8443", ""):
                    with self.subTest(key=key, source=source, value=value):
                        values = (
                            {"services": {"api": {"env": {key: value}}}}
                            if source == "service"
                            else {"global": {"extraConfig": {key: value}}}
                        )
                        environment = self.environment(self.render(values))
                        actual = environment.get("FUSION_SERVICE_URL") or environment.get("FUSION_URL") or ""
                        self.assertEqual(actual, value)

    def test_external_secret_urls_are_not_masked_by_the_chart_default(self) -> None:
        objects = self.render()
        sources = self.deployment(objects)["spec"]["template"]["spec"]["containers"][0]["envFrom"]
        secret_name = next(source["secretRef"]["name"] for source in sources if "secretRef" in source)
        expected = "https://secret-fusion.example.test:8443"
        for key in ("FUSION_SERVICE_URL", "FUSION_URL"):
            with self.subTest(key=key):
                environment = self.environment(objects, secrets={secret_name: {key: expected}})
                self.assertEqual(environment.get("FUSION_SERVICE_URL") or environment.get("FUSION_URL"), expected)

    def test_secret_shared_config_and_explicit_env_keep_their_precedence(self) -> None:
        for key in ("FUSION_SERVICE_URL", "FUSION_URL"):
            for use_explicit_env in (False, True):
                with self.subTest(key=key, use_explicit_env=use_explicit_env):
                    shared_url = "https://shared-fusion.example.test"
                    explicit_url = "https://api-fusion.example.test"
                    values: dict = {"global": {"extraConfig": {key: shared_url}}}
                    if use_explicit_env:
                        values["services"] = {"api": {"env": {key: explicit_url}}}
                    objects = self.render(values)
                    sources = self.deployment(objects)["spec"]["template"]["spec"]["containers"][0]["envFrom"]
                    secret_name = next(source["secretRef"]["name"] for source in sources if "secretRef" in source)
                    environment = self.environment(objects, secrets={secret_name: {key: "https://secret-fusion.example.test"}})
                    self.assertEqual(environment[key], explicit_url if use_explicit_env else shared_url)

    def test_fusion_defaults_do_not_reach_the_web_or_other_services(self) -> None:
        objects = self.render()
        for obj in objects:
            if obj["kind"] != "Deployment":
                continue
            component = obj["metadata"]["labels"].get("app.kubernetes.io/component")
            if component == "api":
                continue
            with self.subTest(component=component):
                environment = self.environment(objects, component=component)
                self.assertNotIn("FUSION_URL", environment)
                self.assertNotIn("FUSION_SERVICE_URL", environment)

    def test_fusion_endpoint_change_rolls_the_api_pods(self) -> None:
        initial = self.render()
        changed = self.render({"services": {"alert-fusion": {"service": {"port": 8083}}}})
        self.assertNotEqual(self.deployment(initial)["spec"]["template"], self.deployment(changed)["spec"]["template"])

    def test_removing_fusion_does_not_invent_an_upstream(self) -> None:
        values: dict = {"services": {"alert-fusion": None}}
        objects = self.render(values)
        environment = self.environment(objects)
        self.assertFalse(environment.get("FUSION_SERVICE_URL") or environment.get("FUSION_URL"))
        self.assertFalse(any(obj["kind"] == "ConfigMap" and "FUSION_URL" in obj.get("data", {}) for obj in objects))

        values["services"]["api"] = {"env": {"FUSION_URL": "https://fusion.example.test"}}
        environment = self.environment(self.render(values))
        self.assertEqual(environment.get("FUSION_URL"), "https://fusion.example.test")
        self.assertNotIn("FUSION_SERVICE_URL", environment)

    def test_removing_api_omits_the_fusion_defaults(self) -> None:
        objects = self.render({"services": {"api": None, "web": {"env": {"API_URL": "https://external-api.example.test"}}}})
        self.assertFalse(any(obj["kind"] == "ConfigMap" and "FUSION_URL" in obj.get("data", {}) for obj in objects))


if __name__ == "__main__":
    unittest.main()
