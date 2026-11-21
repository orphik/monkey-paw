from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scripts.extract_repo_surface import scan_repository  # noqa: E402


class TestExtractRepoSurface(unittest.TestCase):
    def test_empty_directory_degrades_to_greenfield_exit_zero(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            payload, encoded = scan_repository(tmp_path)
            self.assertEqual(payload["mode"], "greenfield")
            self.assertEqual(payload["stats"]["scanned_code_files"], 0)
            self.assertFalse(payload["truncated"])
            self.assertTrue(len(encoded) > 0)

            out_file = tmp_path / ".monkey-paw" / "surface.json"
            proc = subprocess.run(
                [
                    sys.executable,
                    str(REPO_ROOT / "scripts" / "extract_repo_surface.py"),
                    "--repo",
                    str(tmp_path),
                    "--out",
                    str(out_file),
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, msg=proc.stderr)
            disk_payload = json.loads(out_file.read_text(encoding="utf-8"))
            self.assertEqual(disk_payload["mode"], "greenfield")

    def test_docs_only_directory_is_greenfield(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            (tmp_path / "README.md").write_text("# New Idea\nJust prose.", encoding="utf-8")
            (tmp_path / "draft-ticket.md").write_text("Allow users to export CSV.", encoding="utf-8")
            payload, _ = scan_repository(tmp_path)
            self.assertEqual(payload["mode"], "greenfield")

    def test_polyglot_brownfield_extraction(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)

            # 1. Prisma
            prisma_dir = root / "prisma"
            prisma_dir.mkdir()
            (prisma_dir / "schema.prisma").write_text(
                """
enum SubscriptionStatus {
  ACTIVE
  PAUSED
  CANCELED
}

model Subscription {
  id        String @id @default(cuid())
  orgId     String @unique
  status    SubscriptionStatus
}
""",
                encoding="utf-8",
            )

            # 2. SQL + RLS
            sql_dir = root / "migrations"
            sql_dir.mkdir()
            (sql_dir / "001_ledger.sql").write_text(
                """
CREATE TYPE payout_state AS ENUM ('PENDING', 'SETTLED', 'FAILED');

CREATE TABLE IF NOT EXISTS vendor_payouts (
  id UUID PRIMARY KEY,
  vendor_id UUID NOT NULL,
  amount_cents BIGINT NOT NULL
);

ALTER TABLE vendor_payouts ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON vendor_payouts USING (vendor_id = current_setting('app.vendor_id')::uuid);
""",
                encoding="utf-8",
            )

            # 3. Python (FastAPI, Pydantic, SQLAlchemy, Enum, Celery)
            py_dir = root / "services"
            py_dir.mkdir()
            (py_dir / "billing.py").write_text(
                """
from enum import Enum
from fastapi import APIRouter, Depends
from pydantic import BaseModel

router = APIRouter()

class ActorRole(Enum):
    OWNER = "owner"
    SUPPORT = "support"

class RefundPayload(BaseModel):
    amount_cents: int
    reason: str

class ChargeRecord:
    __tablename__ = "charges"
    id: str
    amount_cents: int

def get_current_tenant_user():
    return {"id": "u1"}

@router.post("/v1/charges/{charge_id}/refund")
async def create_refund(charge_id: str, body: RefundPayload, user=Depends(get_current_tenant_user)):
    return {"ok": True}

@shared_task
def sync_stripe_disputes():
    pass
""",
                encoding="utf-8",
            )

            # 4. TypeScript / Zod / Express / BullMQ + Next.js App Router
            ts_dir = root / "web" / "src"
            ts_dir.mkdir(parents=True)
            (ts_dir / "server.ts").write_text(
                """
import { z } from 'zod';
export const PauseSchema = z.object({
  days: z.number(),
  reason: z.string(),
});
export const PauseReason = z.enum(['SEASONAL', 'BUDGET']);
export enum WebhookKind {
  INVOICE_PAID = 'invoice.paid',
}
router.post('/api/v1/pause', requireAuth, async (req, res) => {});
const exportWorker = new Worker('nightly-exports', async () => {});
""",
                encoding="utf-8",
            )
            next_dir = root / "web" / "app" / "api" / "orders"
            next_dir.mkdir(parents=True)
            (next_dir / "route.ts").write_text(
                "export async function POST(req: Request) { return Response.json({}); }\n",
                encoding="utf-8",
            )

            # 5. OpenAPI YAML + GraphQL
            spec_dir = root / "contracts"
            spec_dir.mkdir()
            (spec_dir / "openapi.yaml").write_text(
                """openapi: 3.1.0
paths:
  /v2/payouts/retry:
    post:
      summary: Retry payouts
components:
  schemas:
    PayoutBatch:
      type: object
  securitySchemes:
    BearerJWT:
      type: http
""",
                encoding="utf-8",
            )
            (spec_dir / "schema.graphql").write_text(
                """
enum BidStatus {
  ACTIVE
  WITHDRAWN
}

input WithdrawBidInput {
  auctionId: ID!
}

type Mutation {
  withdrawBid(input: WithdrawBidInput!): Boolean! @authenticated
}
""",
                encoding="utf-8",
            )

            payload, _ = scan_repository(root)
            self.assertEqual(payload["mode"], "brownfield")
            surface = payload["surface"]

            model_names = {m["name"] for m in surface["models"]}
            self.assertTrue(
                {"Subscription", "vendor_payouts", "RefundPayload", "ChargeRecord", "PauseSchema", "PayoutBatch", "WithdrawBidInput"}.issubset(
                    model_names
                ),
                msg=f"Missing expected models from {model_names}",
            )

            enum_names = {e["name"] for e in surface["enums"]}
            self.assertTrue(
                {"SubscriptionStatus", "payout_state", "ActorRole", "PauseReason", "WebhookKind", "BidStatus"}.issubset(
                    enum_names
                ),
                msg=f"Missing expected enums from {enum_names}",
            )

            route_names = {r["name"] for r in surface["routes"]}
            self.assertIn("POST /v1/charges/{charge_id}/refund", route_names)
            self.assertIn("POST /api/v1/pause", route_names)
            self.assertIn("POST /api/orders", route_names)
            self.assertIn("POST /v2/payouts/retry", route_names)
            self.assertIn("GRAPHQL Mutation.withdrawBid", route_names)

            auth_names = {a["name"] for a in surface["auth"]}
            self.assertTrue(any("get_current_tenant_user" in a for a in auth_names))
            self.assertIn("requireAuth", auth_names)
            self.assertIn("BearerJWT", auth_names)
            self.assertIn("@authenticated", auth_names)
            self.assertTrue(any("RLS" in a for a in auth_names))

            worker_names = {w["name"] for w in surface["workers"]}
            self.assertIn("sync_stripe_disputes", worker_names)
            self.assertIn("nightly-exports", worker_names)

            # All emitted paths must be normalized forward-slash POSIX paths
            for fpath in payload["code_files"]:
                self.assertNotIn("\\", fpath)

    def test_gitignore_binaries_large_files_and_secret_isolation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / ".gitignore").write_text(
                "generated/\n*.gen.py\n!keep.gen.py\n",
                encoding="utf-8",
            )

            # Ignored and hard-skipped folders
            (root / "generated").mkdir()
            (root / "generated" / "ignored_model.py").write_text(
                "class IgnoredModel(BaseModel):\n    x: int\n", encoding="utf-8"
            )
            (root / "drop.gen.py").write_text(
                "class DroppedGen(BaseModel):\n    x: int\n", encoding="utf-8"
            )
            (root / "keep.gen.py").write_text(
                "class KeptGen(BaseModel):\n    x: int\n", encoding="utf-8"
            )
            (root / "node_modules" / "pkg").mkdir(parents=True)
            (root / "node_modules" / "pkg" / "index.js").write_text(
                "app.get('/should-not-scan', () => {});", encoding="utf-8"
            )
            (root / "venv" / "lib").mkdir(parents=True)
            (root / "venv" / "lib" / "site.py").write_text(
                "class VenvLeak(BaseModel):\n    id: int\n", encoding="utf-8"
            )

            # Sensitive files that MUST NEVER be opened or leaked
            secret_canary = "CANARY_SUPER_SECRET_ENV_VALUE_8839201"
            (root / ".env").write_text(f"STRIPE_SECRET={secret_canary}\n", encoding="utf-8")
            (root / ".env.production").write_text(f"DB_PASS={secret_canary}\n", encoding="utf-8")
            (root / "server.key").write_text(
                f"-----BEGIN PRIVATE KEY-----\n{secret_canary}\n-----END PRIVATE KEY-----\n",
                encoding="utf-8",
            )
            (root / "service-account.json").write_text(
                json.dumps({"private_key_id": secret_canary}), encoding="utf-8"
            )

            # Inline secret inside a normal code file must be scrubbed
            inline_sk = "sk_live_" + "99887766554433221100AABB"
            (root / "app.py").write_text(
                f'API_TOKEN = "{inline_sk}"\nclass CleanOrder(BaseModel):\n    order_id: str\n',
                encoding="utf-8",
            )

            # Binary file with .py extension (contains NUL byte)
            (root / "binary_blob.py").write_bytes(b"\x00\x01\x02class Fake(BaseModel): pass")

            # Oversized >512KB SQL file
            (root / "huge_dump.sql").write_text(
                "CREATE TABLE huge_tbl (id INT);\n" + ("-- padding\n" * 60_000),
                encoding="utf-8",
            )

            payload, encoded = scan_repository(root)
            raw_json = encoded.decode("utf-8")

            self.assertNotIn(secret_canary, raw_json)
            self.assertNotIn(inline_sk, raw_json)
            self.assertNotIn(".env", raw_json)
            self.assertGreaterEqual(payload["stats"]["skipped_sensitive_files"], 4)
            self.assertGreaterEqual(payload["stats"]["skipped_large_files"], 1)
            self.assertGreaterEqual(payload["stats"]["skipped_binary_files"], 1)

            model_names = {m["name"] for m in payload["surface"]["models"]}
            self.assertIn("KeptGen", model_names)
            self.assertIn("CleanOrder", model_names)
            self.assertNotIn("IgnoredModel", model_names)
            self.assertNotIn("DroppedGen", model_names)
            self.assertNotIn("VenvLeak", model_names)
            self.assertNotIn("huge_tbl", model_names)

            # Refuses writing output over `.env`
            bad_proc = subprocess.run(
                [
                    sys.executable,
                    str(REPO_ROOT / "scripts" / "extract_repo_surface.py"),
                    "--repo",
                    str(root),
                    "--out",
                    str(root / ".env"),
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertNotEqual(bad_proc.returncode, 0)

    def test_byte_cap_truncates_deterministically(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            lines = ["from pydantic import BaseModel\n"]
            for idx in range(80):
                lines.append(f"class DomainModel_{idx:03d}(BaseModel):\n    field_alpha: str\n    field_beta: int\n")
            (root / "many_models.py").write_text("\n".join(lines), encoding="utf-8")

            payload, encoded = scan_repository(root, max_bytes=1500)
            self.assertLessEqual(len(encoded), 1500)
            self.assertTrue(payload["truncated"])
            self.assertEqual(payload["mode"], "brownfield")

    def test_java_spring_and_go_extraction(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            java_dir = root / "src" / "main" / "java" / "com" / "acme"
            java_dir.mkdir(parents=True)
            (java_dir / "BidController.java").write_text(
                """package com.acme;

public sealed interface TechnicalScope permits FixedScope, DiagnosticScope {}

public enum BidTier {
    STANDARD,
    PRIORITY
}

public record SubmitBidRequest(String jobId, long amountCents) {}

@RestController
@RequestMapping("/api/v1/bids")
public class BidController {
    @PreAuthorize("hasRole('CONTRACTOR')")
    @PostMapping("/{jobId}")
    public Response submitBid(SubmitBidRequest req) { return null; }

    @Scheduled(fixedDelay = 5000)
    public void pollJobs() {
        String sql = "SELECT id FROM agent_jobs FOR UPDATE SKIP LOCKED";
    }
}
""",
                encoding="utf-8",
            )

            go_dir = root / "cmd" / "relay"
            go_dir.mkdir(parents=True)
            (go_dir / "main.go").write_text(
                """package main

type OrderIntent struct {
    MarketID string
    Contracts int
}

func register(r Router) {
    r.Use(RequireAuth)
    r.Post("/v1/orders", handleOrder)
}
""",
                encoding="utf-8",
            )

            payload, _ = scan_repository(root)
            surface = payload["surface"]
            models = {m["name"] for m in surface["models"]}
            enums = {e["name"] for e in surface["enums"]}
            routes = {r["name"] for r in surface["routes"]}
            auth = {a["name"] for a in surface["auth"]}
            workers = {w["name"] for w in surface["workers"]}

            self.assertTrue({"TechnicalScope", "SubmitBidRequest", "OrderIntent"}.issubset(models))
            self.assertIn("BidTier", enums)
            self.assertIn("POST /api/v1/bids/{jobId}", routes)
            self.assertIn("POST /v1/orders", routes)
            self.assertTrue(any("PreAuthorize" in a for a in auth))
            self.assertIn("RequireAuth", auth)
            self.assertIn("pollJobs", workers)


if __name__ == "__main__":
    unittest.main()
