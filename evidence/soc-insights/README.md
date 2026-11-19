# SOC Insights validation evidence

These screenshots use explicitly synthetic browser-test fixtures. They are not production SOC measurements.

- `before.png`: upstream 7fcfa5d7, the unchanged page.
- `after-dark.png` and `after-light.png`: the proposed fix rendered by the real Next.js console in Chromium.
- `validation.json`: real PostgreSQL/HTTP regression and local synthetic-fixture performance results, including limitations.

The screenshot comparison uses the same seven metrics, including one unmeasured cost tile. The source change is reviewed in the SOC Insights performance pull request; this evidence branch is not intended for merging.
