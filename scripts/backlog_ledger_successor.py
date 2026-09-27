"""BASE-derived append-only backlog ledger successor policy."""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
from pathlib import Path
from types import SimpleNamespace

# A one-time trusted-control authorization for the reviewed Sprint3 correction.
# The candidate receipt is not an authority: both entire BACKLOG preimages and
# the seven rewritten sections' machine fields must match pinned SHA-256 bytes.
SPRINT3_BACKLOG_SHA256 = (
    "66e3eb81fc02f5c7eb65bad1faf0b793565234a9d2f0830e46623b25d4f28c97",
    "41726d6c8b2f4b1dc7ff35466a78c242e147b99eaca69a956064024e04212e23",
)
SPRINT3_CHANGED_IDS = ["B-012", "B-065", "B-087", "B-089", "B-097", "B-154", "B-170"]
SPRINT3_FIELDS = {
    "B-012": (
        "open",
        "07e9926943884c0fed543dc54d99eff7d0255c8fb5a92e4e16d5c23c64383e98",
        "07e9926943884c0fed543dc54d99eff7d0255c8fb5a92e4e16d5c23c64383e98",
        "e301ed123332e0b4533d487ab3688af2ddd593e7a234a0eb8830913dc08bcf57",
        "fa310cff3550ddcf700eccd78169a7377c9706351e4c040eba7374a8c5fb5d19",
    ),
    "B-065": (
        "open",
        "3e3dc027408184f216b8acc68320210b9bb3a549b7a9628b9141697e32d3a252",
        "3e3dc027408184f216b8acc68320210b9bb3a549b7a9628b9141697e32d3a252",
        "6255c16777eb66c330bbbce47af999642365ecd7a35ea93938c482c590f26f79",
        "a6ff51aa1bed4d8fa536fbe4da0b46a4889f4f1c44173bcae4d978313016124c",
    ),
    "B-087": (
        "done",
        "dd5808253fecba2d0dfc469062cfed897be9cfbb733bd5ebc8343dcaf02be3ec",
        "dd5808253fecba2d0dfc469062cfed897be9cfbb733bd5ebc8343dcaf02be3ec",
        "aa6705cddd3ae0e498f0df30109234d001666fc12b40fb659dbe2e94cb8203e3",
        "d8c3e802a44aa14b23ba4c5ac85aa457bf927830400034a47d14dd918e7e6cc4",
    ),
    "B-089": (
        "open",
        "5eda9fcb444055498b855f8a8f4861349a1c200950d638c4f12c489ee705d8eb",
        "be3ca49c4531f3c274213f35c785cdc037f48619a07308c350e1b4bfc673f60e",
        "87077367ef44d0050d30a178f5cc51854ec227afc12a28028a2dddc818e5c96c",
        "c40313446497a27c2ab46bc4838e880cc10d4f50af141ec6ebdedc585d9d8b16",
    ),
    "B-097": (
        "open",
        "c6ac2f9d6bf7f85d3f9b5a9787dec6649d32117744c0d05919e60c81205bd16b",
        "c6ac2f9d6bf7f85d3f9b5a9787dec6649d32117744c0d05919e60c81205bd16b",
        "4204daae06fa2b6ad8ee0b8e535551267b67532296ebbdd1d189c02a8a6e7099",
        "e16c7afa00b279ab513461f20286cb257c5eb706d46f109e2296bddde6484085",
    ),
    "B-154": (
        "open",
        "a6045afb801b3b6a61ff09d97b6e77ba5fa4f7e1c4f9ed0fde8554957484264e",
        "b86a04ff5d4ca729279b39631764e85c01c934e459c2db2ac23d0900587de590",
        "f3434222e0ed605f801a03a34f112e978c242a42f8c4470fda666e267939da35",
        "8d7fb8611da55cf7db8198fdf67b3cf3884eca09785b5f90871fb4792a3e59f0",
    ),
    "B-170": (
        "open",
        "91ead1ed21d307436564ac291480eb45ae690b9e3a8ed0b094f9be5026dc2afd",
        "91ead1ed21d307436564ac291480eb45ae690b9e3a8ed0b094f9be5026dc2afd",
        "fcfc27240f0995a8483ed10314af4c138886fd97b4ccaac7cf8d056a81cc18de",
        "fcfc27240f0995a8483ed10314af4c138886fd97b4ccaac7cf8d056a81cc18de",
    ),
}

# Byte-pinned v0003-to-v0004 bridge.  The data successor is intentionally
# constrained to a derivation of this exact BASE: its only variable is the
# immutable event SHA inserted into the ledger state fence.
V0004_RECONCILIATION = {
    "sequence": 4,
    "previous_sequence": 3,
    "base_commit": "91630baebe3ae7abe686cd4e06a5621ecdc4ab73",
    "previous_source_sha256": "41726d6c8b2f4b1dc7ff35466a78c242e147b99eaca69a956064024e04212e23",
    "history_start": "87dc11e06f7e2a37ecc980253b710f920026bbb8",
    "history_changed_ids": (
        "B-012", "B-083", "B-098", "B-113", "B-134", "B-142",
        "B-154", "B-1630", "B-170", "B-216",
    ),
    # Every first-parent commit after v0003 that changed BACKLOG.md.  Each row
    # binds the commit, its first parent, both complete BACKLOG preimages and
    # the exact section-level delta reconstructed from immutable Git objects.
    "history_transitions": (
        (
            "510aa7c344fe1d6f32cd58632fb9248d7f0e9186",
            "de340b3da5e7b6a41438dea2e11d34d37016453e",
            "41726d6c8b2f4b1dc7ff35466a78c242e147b99eaca69a956064024e04212e23",
            "f55d71cf0954e3ff7216d524e5a79f5d18c5154b04ebdf357396c30f1d2bfa47",
            ('B-154',),
        ),
        (
            "14d2b3c740506fab4725e2a58db378f2d2d41b9c",
            "c2c043253f4372e0490f515a97a037bdc7c2e777",
            "f55d71cf0954e3ff7216d524e5a79f5d18c5154b04ebdf357396c30f1d2bfa47",
            "fec8108664d0e5dd6d3f3e955ae9049eddd47e6548ee9b10d29e15470c988007",
            ('B-098',),
        ),
        (
            "7e1851756b2cf763adbdc2b2b758e6fcf808d573",
            "6caf6b1831411912e0908fcdc7742cfef904b804",
            "fec8108664d0e5dd6d3f3e955ae9049eddd47e6548ee9b10d29e15470c988007",
            "6d71639040d009aa36ce55da38bdce9038a12312504dd618d5fa2298bffc78cd",
            ('B-012',),
        ),
        (
            "37f96dba42cc159cd8ab8e9c4ab9d35b8e5634b5",
            "487db55b9b39f0ce9c62c20f3ab06042846761ae",
            "6d71639040d009aa36ce55da38bdce9038a12312504dd618d5fa2298bffc78cd",
            "2fef1e7ceb63faee3ae64d1e273bf36cfcad3f8a63d9ac289af6fe2764c17ddf",
            ('B-083',),
        ),
        (
            "760e2641bce4864514f6a52d440995382bdc67f5",
            "3d973eda12dc1657aefe525cb2908c71045e788e",
            "2fef1e7ceb63faee3ae64d1e273bf36cfcad3f8a63d9ac289af6fe2764c17ddf",
            "d8e1d02f5dc316d1aae0c49b06ffd80f20d701453e037f434bfa718e2a975cf9",
            ('B-142',),
        ),
        (
            "1acd9b58ea8acf09cdb817c3997209e82e493996",
            "b13f8af774e40a9e4077e7abeab641e1ffc4733b",
            "d8e1d02f5dc316d1aae0c49b06ffd80f20d701453e037f434bfa718e2a975cf9",
            "ddd86148474d4486179f8184eaa1891482e87f9b3375b6efdc7728c03612f470",
            ('B-216',),
        ),
        (
            "08b1618d3d6ce922043e8cd064d5e58a50990f63",
            "1acd9b58ea8acf09cdb817c3997209e82e493996",
            "ddd86148474d4486179f8184eaa1891482e87f9b3375b6efdc7728c03612f470",
            "604ac0551800f208c30f30972c3bb4174be3d310d1190eb3927d6de0139c5e17",
            ('B-1630',),
        ),
        (
            "54995ffaf874534b9b1f4cbf19959c5278a728a7",
            "7b43d7d247227d85e6b34fb268bccea0ffc0e62c",
            "604ac0551800f208c30f30972c3bb4174be3d310d1190eb3927d6de0139c5e17",
            "26c9023e98cafca99c0e74bc6cf190c65c6e45a96a2615d434eb057b31e4ad3f",
            ('B-113',),
        ),
        (
            "a126819db8726b75380a2857c3d26cc3fc991300",
            "dcb41e8c3c3faa39daba97c87e65e345bec50710",
            "26c9023e98cafca99c0e74bc6cf190c65c6e45a96a2615d434eb057b31e4ad3f",
            "a3ad8826e77117f099e8469cc14b6642e26ab792a870ab8c1bd9f0ea13c84842",
            ('B-098',),
        ),
        (
            "90782f550bebcea848bf48fd497983df8deb9715",
            "8196a4438a59d531fda152842bad590096093ddb",
            "a3ad8826e77117f099e8469cc14b6642e26ab792a870ab8c1bd9f0ea13c84842",
            "c272de9f9cc4e6ae36bddbff4c97012d8589150a22c0038e0875a6ddf855ac87",
            ('B-134',),
        ),
        (
            "122515e808158c55b7bff8ecda6b1f760a9439c9",
            "32c00684b51b41f9a5c67b8e1462ac9422b68a7c",
            "c272de9f9cc4e6ae36bddbff4c97012d8589150a22c0038e0875a6ddf855ac87",
            "fe331f67a1f8e0e6f6e56c08ae6e7cb8917edfa3f9b1dc626e102e8dc2dfb97e",
            ('B-098',),
        ),
        (
            "9af8d31b684082cce8f16b3ffa1b7e972615442c",
            "ab10690bc69caefc6920786067d9c9cf84dccd1b",
            "fe331f67a1f8e0e6f6e56c08ae6e7cb8917edfa3f9b1dc626e102e8dc2dfb97e",
            "51c98d257c4b272434c3e67cd90323b6de7689c4471a1b540a6ee9c748da43dc",
            ('B-012',),
        ),
        (
            "e234b97e38154c0fd33406e1b987760367319e81",
            "4f5d77da0cebfac459aed729af2366a79a5a7fa1",
            "51c98d257c4b272434c3e67cd90323b6de7689c4471a1b540a6ee9c748da43dc",
            "4762b45c1740f5ece3af18ba3d29c395b6d8970078241f15267dd1a096f35247",
            ('B-170',),
        ),
    ),
    "prior_source_sha256": "4762b45c1740f5ece3af18ba3d29c395b6d8970078241f15267dd1a096f35247",
    "prior_ledger_sha256": "02d81ecf3ade17a5317b3f24e68a17a801837bde6112cac9288b6a7f6175b656",
    "prior_catalog_sha256": {
        "docs/campaigns/remediation/work-packages/B001-B045.md": "2a1735804f43bb726789b99ee80c14cf876f41eb6c684e3ea54e68981413cd38",
        "docs/campaigns/remediation/work-packages/B046-B090.md": "1a164260a84f3adb406676e1505fd8379aad07b15a5c45365369dcef7b0586da",
        "docs/campaigns/remediation/work-packages/B091-B130.md": "2875d5374471382a5422ceac83e3259fcd5780e55fa3e07f80746f7ceb2995ce",
        "docs/campaigns/remediation/work-packages/B131-B167.md": "4be50ac320f2c8d238a21760bc24a5391a7a5dc1102532d9d034e05556ad089d",
    },
    "b154_fields": (
        "open",
        "39b0307a1a4451c90fb22fe9a37cfbd858485d38e6361e6c3d15bce1d1f4beac",
        "39b0307a1a4451c90fb22fe9a37cfbd858485d38e6361e6c3d15bce1d1f4beac",
        "d4a34c614df48d9ed01029efdd58e268f040c04260eecb093e7f5e330d954a02",
        "d4a34c614df48d9ed01029efdd58e268f040c04260eecb093e7f5e330d954a02",
    ),
}

# v0004 was committed before the next first-parent backlog reconciliation
# batch.  Those later edits must remain an auditable immutable sequence: this
# bridge accepts only a v0005 receipt based on their exact delivered history.
V0005_RECONCILIATION = {
    "sequence": 5,
    "previous_sequence": 4,
    "base_commit": "2af5c9b64cccba9cf618145224186ec2717cca50",
    "previous_source_sha256": "4762b45c1740f5ece3af18ba3d29c395b6d8970078241f15267dd1a096f35247",
    "history_start": "a21ae199ad763fd6fd6c2ca93d86ed968f32d60d",
    "history_changed_ids": ("B-101", "B-142", "B-251", "B-314"),
    # Every first-parent commit after v0004 that changed BACKLOG.md.  The
    # commit and first parent bind provenance; complete pre/post hashes and
    # section deltas bind the actual historical transition.
    "history_transitions": (
        (
            "abd087bb6957ac98cc2175f7c16284cbb367e72d",
            "910c5a07676ffc4d360b56904b65e24aa4f35ef3",
            "4762b45c1740f5ece3af18ba3d29c395b6d8970078241f15267dd1a096f35247",
            "52f8b687c2f9f9ad8c6adf8cb2dedc564ace4d509650bf4606912a886e3bfee6",
            ("B-101",),
        ),
        (
            "61562e2cd49ae49139fbe6a109c1f251ae9c67dc",
            "8acc8631a2eb144da2481e2189667ae7bcf550b9",
            "52f8b687c2f9f9ad8c6adf8cb2dedc564ace4d509650bf4606912a886e3bfee6",
            "38b91cff97ec59e6da364642c22f73d3f9a646cdb58d5ecbe3bbb3755ec0aa2f",
            ("B-251",),
        ),
        (
            "8ab920b4e5d65521381b69bceb76236cdf1bec84",
            "b9481e08c383532336b8ebfadf44b0e43dc42e36",
            "38b91cff97ec59e6da364642c22f73d3f9a646cdb58d5ecbe3bbb3755ec0aa2f",
            "55e44e3782e671b573e781331f7183768e9c9cd22559115ae585d389e5038076",
            ("B-251",),
        ),
        (
            "09c3c58f9e320e39c62861e5cf9a56e8f31cd4b7",
            "6da67d68a5d06072ca06f19ef70d34b0f370d9f2",
            "55e44e3782e671b573e781331f7183768e9c9cd22559115ae585d389e5038076",
            "0fc0dd7c6076296abaf8646ee253335584262a6c448ddfca0a7e0475c309aa42",
            ("B-142",),
        ),
        (
            "cbd77d1d890c99e1bb935c934ac3e85ef3222476",
            "09c3c58f9e320e39c62861e5cf9a56e8f31cd4b7",
            "0fc0dd7c6076296abaf8646ee253335584262a6c448ddfca0a7e0475c309aa42",
            "f478182a9d325515db69471098b8771c703b38eda8e9a1cf2ba6296b159cd99d",
            ("B-314",),
        ),
    ),
    "prior_source_sha256": "f478182a9d325515db69471098b8771c703b38eda8e9a1cf2ba6296b159cd99d",
    "prior_ledger_sha256": "e3d5347ec16f0454a98a3e10e59b210e008e0293f4c52482df07c11a720b93dd",
    "prior_catalog_sha256": {
        "docs/campaigns/remediation/work-packages/B001-B045.md": "081c9885db8d79c18f2f31edb7864bb1ca1a18d53f408720f3f9e4f00524f9c6",
        "docs/campaigns/remediation/work-packages/B046-B090.md": "1a164260a84f3adb406676e1505fd8379aad07b15a5c45365369dcef7b0586da",
        "docs/campaigns/remediation/work-packages/B091-B130.md": "2875d5374471382a5422ceac83e3259fcd5780e55fa3e07f80746f7ceb2995ce",
        "docs/campaigns/remediation/work-packages/B131-B167.md": "13805dab851c5023d7d49bc707ce0c30713a11aeca8b1e179c8710ad8d91671f",
    },
}

# v0006 binds the semantic baseline repair in #2346 to the exact main parent.
# Full BACKLOG section hashes make the authorized IDs and every changed field
# closed-world; the receipt cannot bless a later edit to any of those sections.
V0006_RECONCILIATION = {
    "sequence": 6,
    "previous_sequence": 5,
    "base_commit": "24e8d41c70e581b0759f3a7347ea417fd4bc7185",
    "changed_ids": ("B-028", "B-101", "B-210", "B-216", "B-229"),
    "prior_source_sha256": "f478182a9d325515db69471098b8771c703b38eda8e9a1cf2ba6296b159cd99d",
    "source_sha256": "e9755578a4d669f29495a5df04866c99b0de7d1e395b3698960144f5582f149f",
    "prior_ledger_sha256": "03ad9a9f06e4613d1bc7276b9d0be0e6d0fc2547074e5e8b080cdfbf19ce888d",
    "prior_catalog_sha256": {
        "docs/campaigns/remediation/work-packages/B001-B045.md": "081c9885db8d79c18f2f31edb7864bb1ca1a18d53f408720f3f9e4f00524f9c6",
        "docs/campaigns/remediation/work-packages/B046-B090.md": "1a164260a84f3adb406676e1505fd8379aad07b15a5c45365369dcef7b0586da",
        "docs/campaigns/remediation/work-packages/B091-B130.md": "2875d5374471382a5422ceac83e3259fcd5780e55fa3e07f80746f7ceb2995ce",
        "docs/campaigns/remediation/work-packages/B131-B167.md": "13805dab851c5023d7d49bc707ce0c30713a11aeca8b1e179c8710ad8d91671f",
    },
    "sections": {
        "B-028": {
            "prior": "5cc13985b1da9042f06f6f8045bb35cb36cf9e655f359b700470f0b80d15c1cb",
            "current": "920cd67557896b97030d914215db5955b6a11357912aa41de854142af6e0a890",
        },
        "B-101": {
            "prior": "096937bd15078f4d89dfc7a5af4d350e9b224421918efeb7bebc5fe02c10d031",
            "current": "4268872d220a148673e767811347ace98671c1cd977833c668dccf55e07eb8cc",
        },
        "B-210": {
            "prior": "b65e301e55b76b5944d623c88421c4aad6393a354162fd6ee72141989b6daa30",
            "current": "757a7157f5f52c4f043be752872b0286d24e6742d029f56a9d3634c88d130c41",
        },
        "B-216": {
            "prior": "8efb315dc53da1b3e8c2831102e5c4c9be3df5eac92d62e582f5104824b27326",
            "current": "915bf4a894b4d18097f26b54a24084a15aa6dc12484a2eeacc186179af077d03",
        },
        "B-229": {
            "prior": "ed09bbbc9b169d689bd8f5415846e2281689a55afad1913500d961c62e04093a",
            "current": "3910144e9c7d54c1dc0c49d5793ef716378f8770fe71f5c6fa1641e63ac94850",
        },
    },
}

# v0007 advances the ledger at the exact delivered main parent after #2412
# landed B-083 and #2429 recorded B-250. The v0006-to-main gap is authorized
# only by replaying both immutable source commits and their complete byte deltas.
V0007_RECONCILIATION = {
    "sequence": 7,
    "previous_sequence": 6,
    "base_commit": "aad9435a7f4092d1d1bae5de4f32aa38f4379a49",
    "history_start_commit": "c19b4bdc1dc7ecd8acca4228e03060f4b9830cce",
    "changed_ids": (),
    "prior_source_sha256": "e9755578a4d669f29495a5df04866c99b0de7d1e395b3698960144f5582f149f",
    "source_sha256": "af7a3201a45bca97322dcfb23f970949a732594128912855512f07060395f894",
    "prior_ledger_sha256": "e2b6ce0de612a163da516224c5767f2b41a9ba17f181cbea0f43daa5317dac90",
    "history": (
        {
            "commit": "ac6f3ceedf4678a290d3dccb1d35abd57063a4c7",
            "parent": "695cae4baea608cebaa6ef5f443586bb8b320712",
            "prior_source_sha256": "e9755578a4d669f29495a5df04866c99b0de7d1e395b3698960144f5582f149f",
            "source_sha256": "8527ad8939bc979ca1b0751c590391d174deb6238a50cd0d134046b1e653fd16",
            "changed_ids": ("B-083",),
            "sections": {
                "B-083": {
                    "prior": "1980611e0e00c299769e6514051de12f4543b21eb7bcd39e80e4d224e9ed870d",
                    "current": "4d772015fcea2a70a72fa74378b11d3b2105984bf8f6168a921d6eeb851fcd76",
                },
            },
        },
        {
            "commit": "8de1ee29b90b12e94064357e8416af021945b4eb",
            "parent": "232124516033056599dac67c21d4330f3e801ad1",
            "prior_source_sha256": "8527ad8939bc979ca1b0751c590391d174deb6238a50cd0d134046b1e653fd16",
            "source_sha256": "af7a3201a45bca97322dcfb23f970949a732594128912855512f07060395f894",
            "changed_ids": ("B-250",),
            "sections": {
                "B-250": {
                    "prior": "9417564e5d27005f56bc368fe00383d164f7c6848c51268db1d134a3b64ea5d8",
                    "current": "59fb4407ba16b1fc14801f116ecbfe6f1818edab0728d34146af324893d826c0",
                },
            },
        },
    ),
    "prior_catalog_sha256": {
        "docs/campaigns/remediation/work-packages/B001-B045.md": "081c9885db8d79c18f2f31edb7864bb1ca1a18d53f408720f3f9e4f00524f9c6",
        "docs/campaigns/remediation/work-packages/B046-B090.md": "1a164260a84f3adb406676e1505fd8379aad07b15a5c45365369dcef7b0586da",
        "docs/campaigns/remediation/work-packages/B091-B130.md": "2875d5374471382a5422ceac83e3259fcd5780e55fa3e07f80746f7ceb2995ce",
        "docs/campaigns/remediation/work-packages/B131-B167.md": "13805dab851c5023d7d49bc707ce0c30713a11aeca8b1e179c8710ad8d91671f",
    },
}

# v0008 records the exact B-113/#2459 and B-098/#2430 prose transitions
# delivered after v0007. It does not rewrite either source; it advances the
# ledger only after replaying both pinned first-parent transitions.
V0008_RECONCILIATION = {
    "sequence": 8,
    "previous_sequence": 7,
    "base_commit": "f56637f84f2366a8041d07d01e8657153a841030",
    "history_start_commit": "aad9435a7f4092d1d1bae5de4f32aa38f4379a49",
    "changed_ids": (),
    "prior_source_sha256": "af7a3201a45bca97322dcfb23f970949a732594128912855512f07060395f894",
    "source_sha256": "323b589d9e6a955409c9b701778736b1bf57e72998b030164c0a460cc498152b",
    "prior_ledger_sha256": "bbed9766de134bd18467ef525c85517ccb8c6fc01c40cf981a9a72ddb471d2b7",
    "history": (
        {
            "commit": "99cfc4ba16a16345885b67bd73063127a7a254cf",
            "parent": "d1767049c671e650eb452e7a71583642a70423b1",
            "prior_source_sha256": "af7a3201a45bca97322dcfb23f970949a732594128912855512f07060395f894",
            "source_sha256": "a795046e84c4e9c9a8bfe64da32d15fe8bbf6f37fc56a0ea4f9a58c6860fc442",
            "changed_ids": ("B-113",),
            "sections": {
                "B-113": {
                    "prior": "406b059248a6c15a36e0236977eeca98670a3c5e1243291b83b7175246577091",
                    "current": "5b466d4d7574e8bb644640b5f117846c9d78ab7396c552683c8ee8f760880a6e",
                },
            },
        },
        {
            "commit": "846fa7f2e1e236308f35079effdb9c73a0757648",
            "parent": "72d0721b8da1ded6baa2e868e833303edc4a755d",
            "prior_source_sha256": "a795046e84c4e9c9a8bfe64da32d15fe8bbf6f37fc56a0ea4f9a58c6860fc442",
            "source_sha256": "323b589d9e6a955409c9b701778736b1bf57e72998b030164c0a460cc498152b",
            "changed_ids": ("B-098",),
            "sections": {
                "B-098": {
                    "prior": "c18fff8910a2ca1ee7553ba65e39b0fd713b34896807f850afd933031e7cb18d",
                    "current": "5af8f54a245b567f738a7de466ba239463571c5bd96d8924a833a2078356178a",
                },
            },
        },
    ),
    "prior_catalog_sha256": {
        "docs/campaigns/remediation/work-packages/B001-B045.md": "081c9885db8d79c18f2f31edb7864bb1ca1a18d53f408720f3f9e4f00524f9c6",
        "docs/campaigns/remediation/work-packages/B046-B090.md": "1a164260a84f3adb406676e1505fd8379aad07b15a5c45365369dcef7b0586da",
        "docs/campaigns/remediation/work-packages/B091-B130.md": "2875d5374471382a5422ceac83e3259fcd5780e55fa3e07f80746f7ceb2995ce",
        "docs/campaigns/remediation/work-packages/B131-B167.md": "13805dab851c5023d7d49bc707ce0c30713a11aeca8b1e179c8710ad8d91671f",
    },
}

# v0009 authorizes the exact B-057 evidence refresh only after replaying every
# first-parent BACKLOG transition delivered since v0008 through the C0-integrated
# base. The policy is installed out-of-band before a separate data receipt can
# use it.
V0009_RECONCILIATION = {
    "sequence": 9,
    "previous_sequence": 8,
    "anchor_base_commit": "4bb6cfcb9bc37caf4fdf59b3bf69e13af5a39191",
    "base_commit": "4bb6cfcb9bc37caf4fdf59b3bf69e13af5a39191",
    "history_start": "f56637f84f2366a8041d07d01e8657153a841030",
    "previous_source_sha256": "323b589d9e6a955409c9b701778736b1bf57e72998b030164c0a460cc498152b",
    "changed_ids": ("B-057",),
    "history_changed_ids": ("B-011", "B-054", "B-103", "B-113", "B-134", "B-138", "B-216", "B-250", "B-316"),
    "history_transitions": (
        ("3f17eae164ecb497bf552bda88228020cc14cde0", "c7788a0af1d87678a9fb2124fc111bcddb6736df", "323b589d9e6a955409c9b701778736b1bf57e72998b030164c0a460cc498152b", "b42299cbc4a9ac8bc600db8682bc945a439d36a906438bc93470941d747fe07f", ("B-054",), {"B-054": ("0d9f376ddb04b8c6c6874a4391710db4508814785c163922e39862318a7b0e3f", "d7b7c57231f7766ccb52457b9e3eb721d8bec819c49ad81ad4aae2ffefcb99cf")} ),
        ("76e0bc6e66a5c9b24709a1a5ec655bbc9f3f1344", "9ed0baa2d8262d5325907ed9031b7009e154aca9", "b42299cbc4a9ac8bc600db8682bc945a439d36a906438bc93470941d747fe07f", "97ef93ff321a0710956b1db2394bf2a5559a53f49559f83f65fa0ee37a1ef695", ("B-054",), {"B-054": ("d7b7c57231f7766ccb52457b9e3eb721d8bec819c49ad81ad4aae2ffefcb99cf", "8d7cc1ba49e7b7ae3542605f45a1c5a7a298d38d4150c90f0c969fd8a87ef323")} ),
        ("0480aa697101b9cef9abec9ccdf33266591b381f", "2343f6d0e85958a14f8670b62e47c8bfca82cd71", "97ef93ff321a0710956b1db2394bf2a5559a53f49559f83f65fa0ee37a1ef695", "118a73e07392e68953795f7b0a48ec55b9b3ab42408126124abbb041c4391271", ("B-250",), {"B-250": ("59fb4407ba16b1fc14801f116ecbfe6f1818edab0728d34146af324893d826c0", "349cb7c19244d25eccac7d95eafa3c9704da53c0dca5d2180b2e1902ecd69bb2")} ),
        ("3d448980a84a604aea8eb1f28299ea2f605ad30a", "af79ca2f296f39b8149931de16441f8e4582b53c", "118a73e07392e68953795f7b0a48ec55b9b3ab42408126124abbb041c4391271", "78bce40c2ad03a259185bd884e024000ace29157f708dafbe002aea998044694", ("B-316",), {"B-316": ("96cdbda3f11d7d1b947b5510886496117cf75603a138b3a14fd48205bf3cecc3", "189d7601e276aaf9d428f2b3c008109b90fb32d9c20dd5d8a463ba0b26a74864")} ),
        ("ef2c09b44b8ab1127aba6f1c2f352a314956840c", "fa5f154e69031a079bbb83110a584c1d7f77496c", "78bce40c2ad03a259185bd884e024000ace29157f708dafbe002aea998044694", "cb20e66a67c57b58eb3ff555a1cf000762ae83815220eb2f52bd115b13e25cce", ("B-134",), {"B-134": ("84e5f4aaa56a779f221b808208b6a4c31c4066b5336cde3625047cc3bcd989d9", "48845c7b35ffe072047fd1c2f542e232c3ed9926435d0eace96bc04e78a3a62f")} ),
        ("bf217e7f6fe02df4ffbb1fc7d72126c59b066f7c", "5da576eee75d474f88076ca34f6d203747eb6a38", "cb20e66a67c57b58eb3ff555a1cf000762ae83815220eb2f52bd115b13e25cce", "9e7ff42bcee72eabc4c6c99e10d784b879b44546f325ddf507cd0fa567fd1317", ("B-113",), {"B-113": ("5b466d4d7574e8bb644640b5f117846c9d78ab7396c552683c8ee8f760880a6e", "ece7d0b8f8416ad4567e34f1abc77666c1d1ba334d079e6d9875e878318c0d1b")} ),
        ("c9c0061904283bf92f6ba48c1b2e3d4dcd8811be", "5d46476e04a656b4186054d39c32689afb9e61e3", "9e7ff42bcee72eabc4c6c99e10d784b879b44546f325ddf507cd0fa567fd1317", "9ec2f061bc9a0cc290d5d9efe699c87f473de2a1e1b43a8ee4ab63b58fc65ddc", ("B-011", "B-138"), {"B-011": ("2d0f89dd7e21e7edc19cd7a468d20c63a41de1e4fc4097330a3cfbfc18d38dbb", "0f450287eb4914ce2644cf48699f95a5e45f235dfb6b8ba9daa7f7de28c1036d"), "B-138": ("0b5c80991690f76e0e00396dc1b53443b799b13b9a93b961f799731a0fec6210", "483b79c7347331edd443be0cfa1e72335bc74e2e059e4254c8088d9443d941aa")} ),
        ("44f6c7e0a9d2cb044e2bd0ddeb2da398724ed603", "864a8be621471fea2a5e606a0a12dbe2c59488ce", "9ec2f061bc9a0cc290d5d9efe699c87f473de2a1e1b43a8ee4ab63b58fc65ddc", "e453068396a3c12b0c7215683838c1ed29ce7cea9f38db0eb3233d6e724d8899", ("B-113",), {"B-113": ("ece7d0b8f8416ad4567e34f1abc77666c1d1ba334d079e6d9875e878318c0d1b", "af57a9d19cfebd0435e95518aa4533e5b842efa86bdf5aac41e11d25d2e549e6")} ),
        ("08213bde21436b16644500ff0b2983d29dd2fd17", "44f6c7e0a9d2cb044e2bd0ddeb2da398724ed603", "e453068396a3c12b0c7215683838c1ed29ce7cea9f38db0eb3233d6e724d8899", "f4898ea2cdbbe3ff511a3e8faa09f7ad9edbbc884c57eab763f1ef88118450e5", ("B-216",), {"B-216": ("915bf4a894b4d18097f26b54a24084a15aa6dc12484a2eeacc186179af077d03", "afc9b4b92bd9db714b928d56c893c00d7f7ddddc5cd0940ff51bfd2d5eaf87d5")} ),
        ("f26858430cee9be93700cb08eecb128c540cc480", "08213bde21436b16644500ff0b2983d29dd2fd17", "f4898ea2cdbbe3ff511a3e8faa09f7ad9edbbc884c57eab763f1ef88118450e5", "00ac71310b31ca7dcc88e76e4805ffdae7d773007b4146ebb385b69452656fb9", ("B-103",), {"B-103": ("e52ca4a76a5241bb653088a7a6442499d391281c802d17f721465155d2631c34", "2c9e524bd3c1818cf1062540ec1cc82dfcb5b167bdff669d59d835df63bc8ae5")} ),
    ),
    "prior_source_sha256": "00ac71310b31ca7dcc88e76e4805ffdae7d773007b4146ebb385b69452656fb9",
    "source_sha256": "159ef4473aecdd592315fd3e4909c13200c8251c1a1661efa52d1f586ec1d684",
    "prior_ledger_sha256": "fcc3a03cf4a2f82996212a24d7ae1947c874441635a6a680bb4caeb6c64e58fa",
    "prior_section_sha256": "4bd0d060401f0be30814308399bf1b6d02b7012d993ec20c10f0d4027a2f195d",
    "current_section_sha256": "907e5ad69e6e949b96d99d5e9977f5597bda45d3498610f6ba517f5f387ffbda",
    "prior_catalog_sha256": {
        "docs/campaigns/remediation/work-packages/B001-B045.md": "081c9885db8d79c18f2f31edb7864bb1ca1a18d53f408720f3f9e4f00524f9c6",
        "docs/campaigns/remediation/work-packages/B046-B090.md": "1a164260a84f3adb406676e1505fd8379aad07b15a5c45365369dcef7b0586da",
        "docs/campaigns/remediation/work-packages/B091-B130.md": "2875d5374471382a5422ceac83e3259fcd5780e55fa3e07f80746f7ceb2995ce",
        "docs/campaigns/remediation/work-packages/B131-B167.md": "13805dab851c5023d7d49bc707ce0c30713a11aeca8b1e179c8710ad8d91671f",
    },
}


def install(api):
    REPO_ROOT = api.REPO_ROOT
    CATALOGS = api.CATALOGS
    SNAPSHOT_DIRECTORY = api.SNAPSHOT_DIRECTORY
    LEDGER_RELATIVE = api.LEDGER_RELATIVE
    GENESIS_SNAPSHOT_RELATIVE = api.GENESIS_SNAPSHOT_RELATIVE
    SUCCESSOR_NAME_RE = api.SUCCESSOR_NAME_RE
    RECEIPT_FIELDS = api.RECEIPT_FIELDS
    LedgerError = api.LedgerError
    load_postmerge_snapshot_manifest = api.load_postmerge_snapshot_manifest
    backlog_verify = api.backlog_verify
    backlog_status_counts = api.backlog_status_counts
    open_backlog_ids = api.open_backlog_ids
    parse_ledger_state = api.parse_ledger_state
    canonical_id = api.canonical_id
    validate_complete_catalog_state = api.validate_complete_catalog_state

    def _sha256(raw: bytes) -> str:
        return hashlib.sha256(raw).hexdigest()

    def _replace_once(text: str, old: str, new: str) -> str:
        if text.count(old) != 1:
            raise LedgerError("v0004 derivation source drifted")
        return text.replace(old, new, 1)

    def _v0004_catalogs(prior: dict[str, bytes]) -> dict[str, bytes]:
        """Derive B-012 retirement and the B131 canonical-manifest pointer."""
        catalogs = {
            path.as_posix(): prior[path.as_posix()]
            for path in _catalog_relatives()
        }
        target = "docs/campaigns/remediation/work-packages/B001-B045.md"
        text = catalogs[target].decode("utf-8")
        for old, new in (
            ("B-012 WP-B012\n", ""),
            ("exactly four IDs:", "exactly three IDs:"),
            ("| B-012 | open / owner | No implementation PR identified; bot-created events still need a non-`GITHUB_TOKEN` credential. | owner-only GitHub configuration |\n", ""),
            ("The four rows above are the\ncurrent open dispatch population", "The three rows above are the\ncurrent open dispatch population"),
            ("the current 13-item\nopen population", "the current 12-item\nopen population"),
            ("Keep the four current owner/external gates explicit: B-008, B-012, B-032, and\n   B-035", "Keep the three current owner/external gates explicit: B-008, B-032, and B-035"),
        ):
            text = _replace_once(text, old, new)
        catalogs[target] = text.encode("utf-8")

        workflow_target = "docs/campaigns/remediation/work-packages/B131-B167.md"
        workflow_text = catalogs[workflow_target].decode("utf-8")
        pattern = re.compile(
            r"(?ms)^This is the only editable ownership source for shared paths\..*?"
            r"^```wp-workflow-ownership\n.*?^```\n"
        )
        pointer = (
            "WP-150 workflow ownership has one canonical, tracked source at\n"
            "[`../wp150-workflow-ownership.md`](../wp150-workflow-ownership.md). The manifest\n"
            "records the complete tracked workflow population, count and path-list hash, and\n"
            "the owner/status row for every workflow. Workflow additions, renames and removals\n"
            "update that manifest in the same reviewed change; unsupported ownership remains\n"
            "`LEAD-BLOCKED | blocked`.\n"
        )
        workflow_text, replacements = pattern.subn(pointer, workflow_text)
        if replacements != 1:
            raise LedgerError("v0004 workflow ownership source drifted")
        for old, new in (
            (
                "The workflow map is closed and machine-validated against the locked 138-file\n"
                "population. `LEAD-BLOCKED` is an explicit no-edit sentinel, not permission to\n"
                "infer an owner. WP-150 is read-only inventory and is rejected as an owner.\n",
                "The canonical manifest is machine-validated against Git-tracked workflow paths.\n"
                "`LEAD-BLOCKED` is an explicit no-edit sentinel, not permission to infer an owner.\n"
                "WP-150 is read-only inventory and is rejected as an owner.\n",
            ),
            (
                "- **Read first:** the complete tracked workflow population, B-136/B-137, the YAML\n"
                "  parser behavior, and the workflow ownership table in this catalog.\n",
                "- **Read first:** the complete tracked workflow population, B-136/B-137, the YAML\n"
                "  parser behavior, and `docs/campaigns/remediation/wp150-workflow-ownership.md`.\n",
            ),
            (
                "- **Population lock:** the manifest is exactly **138** tracked workflow files\n"
                "  (`.github/workflows/*.yml` and `*.yaml`), sorted bytewise and joined with a final\n"
                "  newline; its SHA-256 is\n"
                "  `1616038ec0bb163a7ed436d7487a6255c9da037efaa1f54cbe5f4c3f70a67dc1`.\n"
                "  The verifier rejects any count/hash drift. A changed population requires a new\n"
                "  owner row and contract revision before any workflow edit. An unowned or newly\n"
                "  discovered workflow is an integration blocker; WP-150 and every other existing WP\n"
                "  are forbidden to edit it until a separately reviewed owner contract is added.\n",
                "- **Population lock:** `docs/campaigns/remediation/wp150-workflow-ownership.md` is the\n"
                "  single tracked population and owner/status authority. Its declared count and\n"
                "  SHA-256 cover the sorted, newline-terminated Git-tracked workflow path list, and\n"
                "  the verifier rejects count, hash, duplicate, missing or nonexistent path drift.\n"
                "  Every workflow addition, rename or removal updates this manifest in the same\n"
                "  reviewed change. An unowned workflow stays `LEAD-BLOCKED | blocked`; WP-150 and\n"
                "  every other existing WP are forbidden to edit it until an owner contract is reviewed.\n",
            ),
            (
                "**Workflow-owner map (closed):** B-132/142 owns exactly\n"
                "`.github/workflows/secrets-drift.yml`, `codeql.yml`, and `cas-canary.yml`;\n"
                "B-139 owns `semgrep.yml`; B-141 owns `pr-labels.yml` and `welcome-first-pr.yml`;\n"
                "B-148 owns `backlog-verify.yml` and `python-tests.yml`; B-091 owns `sbom.yml`; B-094 owns\n"
                "`buck2-starter-ci.yml`; B-113 owns the execution cells\n"
                "`nightly.yml`, `fuzz-nightly.yml`, `endurance-2h-nightly.yml`,\n"
                "`load-test-nightly.yml`, and `billing-health-daily.yml`; B-118 owns\n"
                "the retired `cosign-sign.yml` is absent; B-130 owns `api-surface-parity.yml`; the B-136/B-137\n"
                "candidate lanes remain `LEAD-BLOCKED` until their owner contract is present;\n"
                "B-071 owns `container-build-push-prod.yml` and `gc-sweep-dry-run.yml`; B-070\n"
                "owns `cf-deploy-prod.yml` (a future staging path is absent until it exists);\n"
                "B-067 owns the auth workflow; B-068 owns the ignored-integration workflow. The map is a\n"
                "closed ownership record for workflow edits; WP-150 is read-only and may never\n"
                "edit a workflow. Any workflow absent from this map is deliberately unowned and\n"
                "blocks integration until a new, explicit owner WP is reviewed. This map is not\n"
                "a glob or an implicit delegation mechanism.\n",
                "**Workflow-owner map (closed):** The canonical tracked map is maintained only in\n"
                "[`docs/campaigns/remediation/wp150-workflow-ownership.md`](../wp150-workflow-ownership.md).\n"
                "It records every tracked workflow exactly once with an evidence-backed owner or\n"
                "`LEAD-BLOCKED | blocked`. WP-150 is read-only inventory and cannot edit workflows;\n"
                "no ownership is inferred from a glob, prose, or read-first reference.\n",
            ),
        ):
            workflow_text = _replace_once(workflow_text, old, new)
        catalogs[workflow_target] = workflow_text.encode("utf-8")
        return catalogs

    def _v0004_ledger(prior_raw: bytes, base_sha: str) -> bytes:
        """Derive the exact ledger image after retiring B-012 from execution."""
        text = prior_raw.decode("utf-8")
        for old, new in (
            ("base-ref: df1cd53f56a2eff4643aaf9368e25fb0303ce57d", f"base-ref: {base_sha}"),
            ("base-sha: df1cd53f56a2eff4643aaf9368e25fb0303ce57d", f"base-sha: {base_sha}"),
            ("observed-at: 2026-09-13", "observed-at: 2026-09-23"),
            (
                "A legitimate new observation must version a new manifest and transition\n"
                "the ledger base in the same reviewed change.",
                "Every new BACKLOG/status observation must version a snapshot manifest and transition the ledger base in the same reviewed change. WP-150 workflow population and ownership updates are maintained in the dedicated tracked manifest; they do not require ledger successors.",
            ),
            ("The current population is 373 items: 13 open, 328 done and 32 parked. The 13\nopen items", "The current population is 374 items: 12 open, 330 done and 32 parked. The 12\nopen items"),
            ("item-count: 373", "item-count: 374"),
            ("open-count: 13", "open-count: 12"),
            ("done-count: 328", "done-count: 330"),
            ("catalog-counts: B001-B045=4,B046-B090=3,B091-B130=2,B131-B373=4", "catalog-counts: B001-B045=3,B046-B090=3,B091-B130=2,B131-B373=4"),
            ("| [`work-packages/B001-B045.md`](work-packages/B001-B045.md) | B-001..B-045 | 4 |", "| [`work-packages/B001-B045.md`](work-packages/B001-B045.md) | B-001..B-045 | 3 |"),
            ("| **Total** | | **13** |", "| **Total** | | **12** |"),
            ("The logical base includes the current B-008/B-012/B-032/B-035,\nB-065", "The logical base includes the current B-008/B-032/B-035,\nB-065"),
        ):
            text = _replace_once(text, old, new)
        return text.encode("utf-8")

    def _v0005_ledger(prior_raw: bytes, base_sha: str) -> bytes:
        """Derive the ledger image for the exact post-v0004 history base."""
        text = prior_raw.decode("utf-8")
        for old, new in (
            ("base-ref: 91630baebe3ae7abe686cd4e06a5621ecdc4ab73", f"base-ref: {base_sha}"),
            ("base-sha: 91630baebe3ae7abe686cd4e06a5621ecdc4ab73", f"base-sha: {base_sha}"),
            ("observed-at: 2026-09-23", "observed-at: 2026-09-24"),
            ("The current population is 374 items: 12 open, 330 done and 32 parked. The 12", "The current population is 374 items: 12 open, 332 done and 30 parked. The 12"),
            ("done-count: 330", "done-count: 332"),
            ("parked-count: 32", "parked-count: 30"),
        ):
            text = _replace_once(text, old, new)
        return text.encode("utf-8")

    def _v0006_ledger(prior_raw: bytes, base_sha: str) -> bytes:
        """Derive only the immutable ledger-base advance for #2346."""
        text = prior_raw.decode("utf-8")
        for old, new in (
            ("base-ref: 2af5c9b64cccba9cf618145224186ec2717cca50", f"base-ref: {base_sha}"),
            ("base-sha: 2af5c9b64cccba9cf618145224186ec2717cca50", f"base-sha: {base_sha}"),
        ):
            text = _replace_once(text, old, new)
        return text.encode("utf-8")

    def _v0007_ledger(prior_raw: bytes, base_sha: str) -> bytes:
        """Derive only the immutable ledger-base advance for #2412."""
        text = prior_raw.decode("utf-8")
        for old, new in (
            ("base-ref: 24e8d41c70e581b0759f3a7347ea417fd4bc7185", f"base-ref: {base_sha}"),
            ("base-sha: 24e8d41c70e581b0759f3a7347ea417fd4bc7185", f"base-sha: {base_sha}"),
        ):
            text = _replace_once(text, old, new)
        return text.encode("utf-8")

    def _v0008_ledger(prior_raw: bytes, base_sha: str) -> bytes:
        """Derive only the immutable ledger-base advance after PRs #2459 and #2430."""
        text = prior_raw.decode("utf-8")
        for old, new in (
            ("base-ref: aad9435a7f4092d1d1bae5de4f32aa38f4379a49", f"base-ref: {base_sha}"),
            ("base-sha: aad9435a7f4092d1d1bae5de4f32aa38f4379a49", f"base-sha: {base_sha}"),
        ):
            text = _replace_once(text, old, new)
        return text.encode("utf-8")

    def _v0009_ledger(prior_raw: bytes, base_sha: str) -> bytes:
        """Derive only the ledger-base advance for the pinned B-057 receipt."""
        text = prior_raw.decode("utf-8")
        for old, new in (
            ("base-ref: f56637f84f2366a8041d07d01e8657153a841030", f"base-ref: {base_sha}"),
            ("base-sha: f56637f84f2366a8041d07d01e8657153a841030", f"base-sha: {base_sha}"),
        ):
            if text.count(old) != 1:
                raise LedgerError("v0009 derivation source drifted")
            text = text.replace(old, new, 1)
        return text.encode("utf-8")

    def _sprint3_rewrite_authorized(
        prior: dict[str, bytes], current: dict[str, bytes],
        receipt: dict[str, object], sequence: int,
    ) -> bool:
        if (
            sequence != 3
            or (_sha256(prior["BACKLOG.md"]), _sha256(current["BACKLOG.md"]))
            != SPRINT3_BACKLOG_SHA256
            or receipt["changed_ids"] != SPRINT3_CHANGED_IDS
        ):
            return False
        old_items = {item.id: item.raw for item in backlog_verify.parse(prior["BACKLOG.md"].decode())}
        new_items = {item.id: item.raw for item in backlog_verify.parse(current["BACKLOG.md"].decode())}
        for item_id, (status, old_verify, new_verify, old_means, new_means) in SPRINT3_FIELDS.items():
            old, new = old_items.get(item_id, {}), new_items.get(item_id, {})
            if (
                old.get("status") != status or new.get("status") != status
                or _sha256(str(old.get("verify", "")).encode()) != old_verify
                or _sha256(str(new.get("verify", "")).encode()) != new_verify
                or _sha256(str(old.get("verify-means", "")).encode()) != old_means
                or _sha256(str(new.get("verify-means", "")).encode()) != new_means
            ):
                return False
        return True

    def _v0004_reconciliation_authorized(
        previous: dict[str, object], prior: dict[str, bytes], current: dict[str, bytes],
        receipt: dict[str, object], sequence: int,
    ) -> bool:
        """Authorize the sole v0003-to-v0004 gap repair by complete byte binding."""
        pinned = V0004_RECONCILIATION
        # Unit fixtures may substitute the former, self-contained policy shape.
        # Production policy always uses the derived-target form below.
        if "prior_catalog_sha256" not in pinned:
            if (
                sequence != pinned["sequence"]
                or previous.get("sequence") != pinned["previous_sequence"]
                or previous.get("source_sha256") != pinned["previous_source_sha256"]
                or receipt.get("changed_ids") != pinned["changed_ids"]
                or _sha256(prior["BACKLOG.md"]) != pinned["prior_source_sha256"]
                or _sha256(current["BACKLOG.md"]) != pinned["source_sha256"]
                or _sha256(prior[LEDGER_RELATIVE.as_posix()]) != pinned["prior_ledger_sha256"]
                or _sha256(current[LEDGER_RELATIVE.as_posix()]) != pinned["ledger_sha256"]
                or receipt.get("prior_source_sha256") != pinned["prior_source_sha256"]
                or receipt.get("source_sha256") != pinned["source_sha256"]
                or receipt.get("prior_ledger_sha256") != pinned["prior_ledger_sha256"]
                or receipt.get("ledger_sha256") != pinned["ledger_sha256"]
            ):
                return False
            catalog_hashes = {
                path.as_posix(): _sha256(prior[path.as_posix()])
                for path in _catalog_relatives()
            }
            if (
                catalog_hashes != pinned["catalog_sha256"]
                or {
                    path.as_posix(): _sha256(current[path.as_posix()])
                    for path in _catalog_relatives()
                } != catalog_hashes
                or receipt.get("prior_catalog_sha256") != catalog_hashes
                or receipt.get("catalog_sha256") != catalog_hashes
            ):
                return False
            old_items = {item.id: item.raw for item in backlog_verify.parse(prior["BACKLOG.md"].decode())}
            new_items = {item.id: item.raw for item in backlog_verify.parse(current["BACKLOG.md"].decode())}
            old, new = old_items.get("B-154", {}), new_items.get("B-154", {})
            status, old_verify, new_verify, old_means, new_means = pinned["fields"]
            return (
                old.get("status") == new.get("status") == status
                and _sha256(str(old.get("verify", "")).encode()) == old_verify
                and _sha256(str(new.get("verify", "")).encode()) == new_verify
                and _sha256(str(old.get("verify-means", "")).encode()) == old_means
                and _sha256(str(new.get("verify-means", "")).encode()) == new_means
            )
        if (
            sequence != pinned["sequence"]
            or receipt.get("base_commit") != pinned["base_commit"]
            or previous.get("sequence") != pinned["previous_sequence"]
            or previous.get("source_sha256") != pinned["previous_source_sha256"]
            or receipt.get("changed_ids") != []
            or _sha256(prior["BACKLOG.md"]) != pinned["prior_source_sha256"]
            or current["BACKLOG.md"] != prior["BACKLOG.md"]
            or _sha256(prior[LEDGER_RELATIVE.as_posix()]) != pinned["prior_ledger_sha256"]
            or receipt.get("prior_source_sha256") != pinned["prior_source_sha256"]
            or receipt.get("source_sha256") != pinned["prior_source_sha256"]
            or receipt.get("prior_ledger_sha256") != pinned["prior_ledger_sha256"]
            or not _v0004_history_authorized()
        ):
            return False
        catalog_hashes = {
            path.as_posix(): _sha256(prior[path.as_posix()])
            for path in _catalog_relatives()
        }
        if (
            catalog_hashes != pinned["prior_catalog_sha256"]
            or {
                path.as_posix(): _sha256(current[path.as_posix()])
                for path in _catalog_relatives()
            } != {
                path: _sha256(raw) for path, raw in _v0004_catalogs(prior).items()
            }
            or receipt.get("prior_catalog_sha256") != catalog_hashes
            or receipt.get("catalog_sha256") != {
                path: _sha256(raw) for path, raw in _v0004_catalogs(prior).items()
            }
            or current[LEDGER_RELATIVE.as_posix()] != _v0004_ledger(
                prior[LEDGER_RELATIVE.as_posix()], receipt.get("base_commit", ""),
            )
        ):
            return False
        old_items = {item.id: item.raw for item in backlog_verify.parse(prior["BACKLOG.md"].decode())}
        new_items = {item.id: item.raw for item in backlog_verify.parse(current["BACKLOG.md"].decode())}
        old, new = old_items.get("B-154", {}), new_items.get("B-154", {})
        status, old_verify, new_verify, old_means, new_means = pinned["b154_fields"]
        return (
            old.get("status") == new.get("status") == status
            and _sha256(str(old.get("verify", "")).encode()) == old_verify
            and _sha256(str(new.get("verify", "")).encode()) == new_verify
            and _sha256(str(old.get("verify-means", "")).encode()) == old_means
            and _sha256(str(new.get("verify-means", "")).encode()) == new_means
        )

    def _v0005_reconciliation_authorized(
        previous: dict[str, object], prior: dict[str, bytes], current: dict[str, bytes],
        receipt: dict[str, object], sequence: int,
    ) -> bool:
        """Authorize only the byte-pinned v0004-to-v0005 history repair."""
        pinned = V0005_RECONCILIATION
        if (
            sequence != pinned["sequence"]
            or receipt.get("base_commit") != pinned["base_commit"]
            or previous.get("sequence") != pinned["previous_sequence"]
            or previous.get("source_sha256") != pinned["previous_source_sha256"]
            or receipt.get("changed_ids") != []
            or _sha256(prior["BACKLOG.md"]) != pinned["prior_source_sha256"]
            or current["BACKLOG.md"] != prior["BACKLOG.md"]
            or _sha256(prior[LEDGER_RELATIVE.as_posix()]) != pinned["prior_ledger_sha256"]
            or receipt.get("prior_source_sha256") != pinned["prior_source_sha256"]
            or receipt.get("source_sha256") != pinned["prior_source_sha256"]
            or receipt.get("prior_ledger_sha256") != pinned["prior_ledger_sha256"]
            or not _v0005_history_authorized()
        ):
            return False
        catalog_hashes = {
            path.as_posix(): _sha256(prior[path.as_posix()])
            for path in _catalog_relatives()
        }
        return (
            catalog_hashes == pinned["prior_catalog_sha256"]
            and all(
                current[path.as_posix()] == prior[path.as_posix()]
                for path in _catalog_relatives()
            )
            and receipt.get("prior_catalog_sha256") == catalog_hashes
            and receipt.get("catalog_sha256") == catalog_hashes
            and current[LEDGER_RELATIVE.as_posix()] == _v0005_ledger(
                prior[LEDGER_RELATIVE.as_posix()], receipt.get("base_commit", ""),
            )
        )

    def _v0006_reconciliation_authorized(
        previous: dict[str, object], prior: dict[str, bytes], current: dict[str, bytes],
        receipt: dict[str, object], sequence: int,
    ) -> bool:
        """Authorize only #2346's exact five-section baseline correction."""
        pinned = V0006_RECONCILIATION
        if (
            sequence != pinned["sequence"]
            or receipt.get("base_commit") != pinned["base_commit"]
            or previous.get("sequence") != pinned["previous_sequence"]
            or previous.get("source_sha256") != pinned["prior_source_sha256"]
            or receipt.get("changed_ids") != list(pinned["changed_ids"])
            or _sha256(prior["BACKLOG.md"]) != pinned["prior_source_sha256"]
            or _sha256(current["BACKLOG.md"]) != pinned["source_sha256"]
            or _sha256(prior[LEDGER_RELATIVE.as_posix()]) != pinned["prior_ledger_sha256"]
            or receipt.get("prior_source_sha256") != pinned["prior_source_sha256"]
            or receipt.get("source_sha256") != pinned["source_sha256"]
            or receipt.get("prior_ledger_sha256") != pinned["prior_ledger_sha256"]
            or current[LEDGER_RELATIVE.as_posix()] != _v0006_ledger(
                prior[LEDGER_RELATIVE.as_posix()], pinned["base_commit"],
            )
        ):
            return False
        catalogs = {
            path.as_posix(): _sha256(prior[path.as_posix()])
            for path in _catalog_relatives()
        }
        if (
            catalogs != pinned["prior_catalog_sha256"]
            or any(current[path.as_posix()] != prior[path.as_posix()] for path in _catalog_relatives())
            or receipt.get("prior_catalog_sha256") != catalogs
            or receipt.get("catalog_sha256") != catalogs
        ):
            return False
        _, old_order, old_sections = _backlog_sections(prior["BACKLOG.md"])
        _, new_order, new_sections = _backlog_sections(current["BACKLOG.md"])
        if old_order != new_order or tuple(sorted(
            item_id for item_id in old_order if old_sections[item_id] != new_sections[item_id]
        )) != pinned["changed_ids"]:
            return False
        for item_id, hashes in pinned["sections"].items():
            if (
                _sha256(old_sections.get(item_id, b"")) != hashes["prior"]
                or _sha256(new_sections.get(item_id, b"")) != hashes["current"]
            ):
                return False
        return True

    def _v0007_reconciliation_authorized(
        previous: dict[str, object], prior: dict[str, bytes], current: dict[str, bytes],
        receipt: dict[str, object], sequence: int,
    ) -> bool:
        """Replay #2412 B-083 and #2429 B-250 source deltas, then advance the ledger."""
        pinned = V0007_RECONCILIATION
        if (
            sequence != pinned["sequence"]
            or receipt.get("base_commit") != pinned["base_commit"]
            or previous.get("sequence") != pinned["previous_sequence"]
            or previous.get("source_sha256") != pinned["prior_source_sha256"]
            or receipt.get("changed_ids") != list(pinned["changed_ids"])
            or _sha256(prior["BACKLOG.md"]) != pinned["source_sha256"]
            or _sha256(current["BACKLOG.md"]) != pinned["source_sha256"]
            or _sha256(prior[LEDGER_RELATIVE.as_posix()]) != pinned["prior_ledger_sha256"]
            or receipt.get("prior_source_sha256") != pinned["source_sha256"]
            or receipt.get("source_sha256") != pinned["source_sha256"]
            or receipt.get("prior_ledger_sha256") != pinned["prior_ledger_sha256"]
            or current[LEDGER_RELATIVE.as_posix()] != _v0007_ledger(
                prior[LEDGER_RELATIVE.as_posix()], pinned["base_commit"],
            )
        ):
            return False
        start_source = _git_bytes(
            REPO_ROOT, pinned["history_start_commit"], Path("BACKLOG.md"),
        )
        source_history = subprocess.run(
            [
                "git", "log", "--first-parent", "--full-history", "--reverse", "--format=%H",
                f"{pinned['history_start_commit']}..{pinned['base_commit']}",
                "--", "BACKLOG.md",
            ],
            cwd=REPO_ROOT, check=False, capture_output=True, text=True,
        )
        expected_commits = [row["commit"] for row in pinned["history"]]
        if (
            _sha256(start_source) != previous.get("source_sha256")
            or source_history.returncode
            or source_history.stdout.splitlines() != expected_commits
        ):
            return False
        for row in pinned["history"]:
            commit_parent = subprocess.run(
                ["git", "show", "-s", "--format=%P", row["commit"]],
                cwd=REPO_ROOT, check=False, capture_output=True, text=True,
            )
            ancestor = subprocess.run(
                ["git", "merge-base", "--is-ancestor", row["commit"], pinned["base_commit"]],
                cwd=REPO_ROOT, check=False,
            )
            prior_raw = _git_bytes(REPO_ROOT, row["parent"], Path("BACKLOG.md"))
            current_raw = _git_bytes(REPO_ROOT, row["commit"], Path("BACKLOG.md"))
            _, old_order, old_sections = _backlog_sections(prior_raw)
            _, new_order, new_sections = _backlog_sections(current_raw)
            changed_ids = tuple(sorted(
                item_id for item_id in set(old_sections) | set(new_sections)
                if old_sections.get(item_id) != new_sections.get(item_id)
            ))
            if (
                commit_parent.returncode
                or commit_parent.stdout.strip() != row["parent"]
                or ancestor.returncode
                or _sha256(prior_raw) != row["prior_source_sha256"]
                or _sha256(current_raw) != row["source_sha256"]
                or old_order != new_order
                or changed_ids != row["changed_ids"]
                or tuple(sorted(row["sections"])) != row["changed_ids"]
                or any(
                    _sha256(old_sections.get(item_id, b"")) != hashes["prior"]
                    or _sha256(new_sections.get(item_id, b"")) != hashes["current"]
                    for item_id, hashes in row["sections"].items()
                )
            ):
                return False
        catalogs = {
            path.as_posix(): _sha256(prior[path.as_posix()])
            for path in _catalog_relatives()
        }
        if (
            catalogs != pinned["prior_catalog_sha256"]
            or any(current[path.as_posix()] != prior[path.as_posix()] for path in _catalog_relatives())
            or receipt.get("prior_catalog_sha256") != catalogs
            or receipt.get("catalog_sha256") != catalogs
        ):
            return False
        _, old_order, old_sections = _backlog_sections(prior["BACKLOG.md"])
        _, new_order, new_sections = _backlog_sections(current["BACKLOG.md"])
        if old_order != new_order or old_sections != new_sections:
            return False
        return True

    def _v0009_reconciliation_authorized(
        previous: dict[str, object], prior: dict[str, bytes], current: dict[str, bytes],
        receipt: dict[str, object], sequence: int, *, trusted_root: Path, trusted_base: str,
    ) -> bool:
        """Authorize only the exact B-057 transition from the pinned trusted-main state."""
        pinned = V0009_RECONCILIATION
        anchor_is_ancestor = subprocess.run(
            ["git", "merge-base", "--is-ancestor", pinned["anchor_base_commit"], trusted_base],
            cwd=trusted_root, check=False,
        ).returncode == 0
        if (
            not anchor_is_ancestor
            or not _v0009_history_authorized()
            or receipt.get("base_commit") != trusted_base
            or sequence != pinned["sequence"]
            or previous.get("sequence") != pinned["previous_sequence"]
            or previous.get("source_sha256") != pinned["previous_source_sha256"]
            or _git_state_bytes(trusted_root, pinned["anchor_base_commit"]) != prior
            or _sha256(prior["BACKLOG.md"]) != pinned["prior_source_sha256"]
            or _sha256(current["BACKLOG.md"]) != pinned["source_sha256"]
            or receipt.get("changed_ids") != list(pinned["changed_ids"])
            or receipt.get("prior_source_sha256") != pinned["prior_source_sha256"]
            or receipt.get("source_sha256") != pinned["source_sha256"]
            or _sha256(prior[LEDGER_RELATIVE.as_posix()]) != pinned["prior_ledger_sha256"]
            or receipt.get("prior_ledger_sha256") != pinned["prior_ledger_sha256"]
            or current[LEDGER_RELATIVE.as_posix()] != _v0009_ledger(
                prior[LEDGER_RELATIVE.as_posix()], trusted_base,
            )
        ):
            return False
        _, old_order, old_sections = _backlog_sections(prior["BACKLOG.md"])
        _, new_order, new_sections = _backlog_sections(current["BACKLOG.md"])
        catalogs = {
            path.as_posix(): _sha256(prior[path.as_posix()])
            for path in _catalog_relatives()
        }
        return (
            old_order == new_order
            and sorted(
                item_id for item_id in new_order
                if old_sections.get(item_id) != new_sections[item_id]
            ) == list(pinned["changed_ids"])
            and _sha256(old_sections.get("B-057", b"")) == pinned["prior_section_sha256"]
            and _sha256(new_sections.get("B-057", b"")) == pinned["current_section_sha256"]
            and catalogs == pinned["prior_catalog_sha256"]
            and all(current[path.as_posix()] == prior[path.as_posix()] for path in _catalog_relatives())
            and receipt.get("prior_catalog_sha256") == catalogs
            and receipt.get("catalog_sha256") == catalogs
        )

    def _v0009_history_authorized() -> bool:
        """Replay every delivered BACKLOG transition from v0008 to the C0 base."""
        return _history_authorized(V0009_RECONCILIATION)

    def _v0008_reconciliation_authorized(
        previous: dict[str, object], prior: dict[str, bytes], current: dict[str, bytes],
        receipt: dict[str, object], sequence: int,
    ) -> bool:
        """Replay the exact #2459 B-113 and #2430 B-098 deltas, then advance the ledger."""
        pinned = V0008_RECONCILIATION
        if (
            sequence != pinned["sequence"]
            or receipt.get("base_commit") != pinned["base_commit"]
            or previous.get("sequence") != pinned["previous_sequence"]
            or previous.get("source_sha256") != pinned["prior_source_sha256"]
            or receipt.get("changed_ids") != list(pinned["changed_ids"])
            or _sha256(prior["BACKLOG.md"]) != pinned["source_sha256"]
            or _sha256(current["BACKLOG.md"]) != pinned["source_sha256"]
            or _sha256(prior[LEDGER_RELATIVE.as_posix()]) != pinned["prior_ledger_sha256"]
            or receipt.get("prior_source_sha256") != pinned["source_sha256"]
            or receipt.get("source_sha256") != pinned["source_sha256"]
            or receipt.get("prior_ledger_sha256") != pinned["prior_ledger_sha256"]
            or current[LEDGER_RELATIVE.as_posix()] != _v0008_ledger(
                prior[LEDGER_RELATIVE.as_posix()], pinned["base_commit"],
            )
        ):
            return False
        start_source = _git_bytes(
            REPO_ROOT, pinned["history_start_commit"], Path("BACKLOG.md"),
        )
        source_history = subprocess.run(
            [
                "git", "log", "--first-parent", "--full-history", "--reverse", "--format=%H",
                f"{pinned['history_start_commit']}..{pinned['base_commit']}",
                "--", "BACKLOG.md",
            ],
            cwd=REPO_ROOT, check=False, capture_output=True, text=True,
        )
        expected_commits = [row["commit"] for row in pinned["history"]]
        if (
            _sha256(start_source) != previous.get("source_sha256")
            or source_history.returncode
            or source_history.stdout.splitlines() != expected_commits
        ):
            return False
        for row in pinned["history"]:
            commit_parent = subprocess.run(
                ["git", "show", "-s", "--format=%P", row["commit"]],
                cwd=REPO_ROOT, check=False, capture_output=True, text=True,
            )
            ancestor = subprocess.run(
                ["git", "merge-base", "--is-ancestor", row["commit"], pinned["base_commit"]],
                cwd=REPO_ROOT, check=False,
            )
            prior_raw = _git_bytes(REPO_ROOT, row["parent"], Path("BACKLOG.md"))
            current_raw = _git_bytes(REPO_ROOT, row["commit"], Path("BACKLOG.md"))
            _, old_order, old_sections = _backlog_sections(prior_raw)
            _, new_order, new_sections = _backlog_sections(current_raw)
            changed_ids = tuple(sorted(
                item_id for item_id in set(old_sections) | set(new_sections)
                if old_sections.get(item_id) != new_sections.get(item_id)
            ))
            if (
                commit_parent.returncode
                or commit_parent.stdout.strip() != row["parent"]
                or ancestor.returncode
                or _sha256(prior_raw) != row["prior_source_sha256"]
                or _sha256(current_raw) != row["source_sha256"]
                or old_order != new_order
                or changed_ids != row["changed_ids"]
                or tuple(sorted(row["sections"])) != row["changed_ids"]
                or any(
                    _sha256(old_sections.get(item_id, b"")) != hashes["prior"]
                    or _sha256(new_sections.get(item_id, b"")) != hashes["current"]
                    for item_id, hashes in row["sections"].items()
                )
            ):
                return False
        catalogs = {
            path.as_posix(): _sha256(prior[path.as_posix()])
            for path in _catalog_relatives()
        }
        if (
            catalogs != pinned["prior_catalog_sha256"]
            or any(current[path.as_posix()] != prior[path.as_posix()] for path in _catalog_relatives())
            or receipt.get("prior_catalog_sha256") != catalogs
            or receipt.get("catalog_sha256") != catalogs
        ):
            return False
        _, old_order, old_sections = _backlog_sections(prior["BACKLOG.md"])
        _, new_order, new_sections = _backlog_sections(current["BACKLOG.md"])
        if old_order != new_order or old_sections != new_sections:
            return False
        return True

    def _catalog_relatives() -> tuple[Path, ...]:
        return tuple(path.relative_to(REPO_ROOT) for path in CATALOGS)

    def _regular_bytes(root: Path, relative: Path) -> bytes:
        """Read candidate data without following a symlink out of its checkout."""
        if relative.is_absolute() or ".." in relative.parts:
            raise LedgerError(f"unsafe data path: {relative}")
        current = root
        for part in relative.parts:
            current = current / part
            if current.is_symlink():
                raise LedgerError(f"symlink data path: {relative}")
        if not current.is_file():
            raise LedgerError(f"missing regular data file: {relative}")
        if current.stat().st_size > 2_000_000:
            raise LedgerError(f"oversized data file: {relative}")
        return current.read_bytes()

    def _git_bytes(repo_root: Path, commit: str, relative: Path) -> bytes:
        if not re.fullmatch(r"[0-9a-f]{40}", commit):
            raise LedgerError(f"invalid immutable base SHA: {commit!r}")
        result = subprocess.run(
            ["git", "show", f"{commit}:{relative.as_posix()}"],
            cwd=repo_root,
            check=False,
            capture_output=True,
        )
        if result.returncode:
            raise LedgerError(f"immutable base lacks {relative}: {commit}")
        return result.stdout

    def _successor_paths(root: Path) -> list[Path]:
        directory = root / SNAPSHOT_DIRECTORY
        if directory.is_symlink() or not directory.is_dir():
            raise LedgerError("snapshot directory is missing or symlinked")
        paths: list[Path] = []
        for path in directory.iterdir():
            if not path.name.startswith("backlog-ledger-snapshot-v"):
                continue
            match = SUCCESSOR_NAME_RE.fullmatch(path.name)
            if match is None:
                raise LedgerError(f"malformed successor snapshot name: {path.name}")
            paths.append(SNAPSHOT_DIRECTORY / path.name)
        paths.sort()
        numbers = [
            int(SUCCESSOR_NAME_RE.fullmatch(path.name).group(1)) for path in paths
        ]
        if numbers != list(range(3, len(paths) + 3)):
            raise LedgerError(
                "successor snapshot sequence is not contiguous from v0003"
            )
        return paths

    def _receipt(raw: bytes, source: str) -> dict[str, object]:
        def unique_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
            result: dict[str, object] = {}
            for key, value in pairs:
                if key in result:
                    raise LedgerError(f"{source}: duplicate snapshot key {key}")
                result[key] = value
            return result

        try:
            value = json.loads(raw, object_pairs_hook=unique_pairs)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise LedgerError(f"{source}: malformed successor snapshot: {exc}") from exc
        if not isinstance(value, dict) or set(value) != RECEIPT_FIELDS:
            raise LedgerError(f"{source}: successor snapshot schema drifted")
        if type(value["schema_version"]) is not int or value["schema_version"] != 3:
            raise LedgerError(f"{source}: successor snapshot schema version drifted")
        if type(value["sequence"]) is not int or value["sequence"] < 3:
            raise LedgerError(f"{source}: invalid successor sequence")
        if value["transition"] != "base-derived-data":
            raise LedgerError(
                f"{source}: successor transition is not base-derived data"
            )
        for key in (
            "base_commit",
            "prior_snapshot_sha256",
            "prior_source_sha256",
            "source_sha256",
            "prior_ledger_sha256",
            "ledger_sha256",
        ):
            length = 40 if key == "base_commit" else 64
            if not isinstance(value[key], str) or not re.fullmatch(
                rf"[0-9a-f]{{{length}}}", value[key]
            ):
                raise LedgerError(f"{source}: malformed {key}")
        for key in ("prior_catalog_sha256", "catalog_sha256"):
            hashes = value[key]
            if (
                not isinstance(hashes, dict)
                or set(hashes) != {path.as_posix() for path in _catalog_relatives()}
                or any(
                    not isinstance(digest, str)
                    or not re.fullmatch(r"[0-9a-f]{64}", digest)
                    for digest in hashes.values()
                )
            ):
                raise LedgerError(f"{source}: malformed {key}")
        if type(value["item_count"]) is not int or value["item_count"] < 1:
            raise LedgerError(f"{source}: malformed item count")
        if (
            not isinstance(value["status_counts"], dict)
            or set(value["status_counts"]) != {"done", "open", "parked"}
            or any(
                type(count) is not int or count < 0
                for count in value["status_counts"].values()
            )
        ):
            raise LedgerError(f"{source}: malformed status counts")
        for key in ("open_ids", "changed_ids"):
            ids = value[key]
            if (
                not isinstance(ids, list)
                or any(
                    not isinstance(item, str) or not re.fullmatch(r"B-[0-9]{3,}", item)
                    for item in ids
                )
                or ids != sorted(set(ids))
            ):
                raise LedgerError(f"{source}: malformed {key}")
        return value

    def _state_bytes(root: Path) -> dict[str, bytes]:
        relatives = (Path("BACKLOG.md"), LEDGER_RELATIVE, *_catalog_relatives())
        return {path.as_posix(): _regular_bytes(root, path) for path in relatives}

    def _git_state_bytes(repo_root: Path, commit: str) -> dict[str, bytes]:
        relatives = (Path("BACKLOG.md"), LEDGER_RELATIVE, *_catalog_relatives())
        return {
            path.as_posix(): _git_bytes(repo_root, commit, path) for path in relatives
        }

    def _history_authorized(pinned: dict[str, object]) -> bool:
        """Reconstruct one pinned first-parent BACKLOG history from Git objects."""
        expected = pinned.get("history_transitions")
        if not expected:
            return False
        result = subprocess.run(
            [
                "git", "rev-list", "--first-parent", "--reverse",
                f"{pinned['history_start']}..{pinned['base_commit']}",
                "--", "BACKLOG.md",
            ],
            cwd=REPO_ROOT,
            check=False,
            capture_output=True,
            text=True,
        )
        commits = result.stdout.splitlines()
        if result.returncode or commits != [row[0] for row in expected]:
            return False
        reconstructed_ids: set[str] = set()
        for row in expected:
            commit, parent, prior_hash, current_hash, changed_ids, *section_hashes = row
            actual_parent = subprocess.run(
                ["git", "rev-parse", f"{commit}^1"],
                cwd=REPO_ROOT,
                check=False,
                capture_output=True,
                text=True,
            ).stdout.strip()
            if actual_parent != parent:
                return False
            prior_raw = _git_bytes(REPO_ROOT, parent, Path("BACKLOG.md"))
            current_raw = _git_bytes(REPO_ROOT, commit, Path("BACKLOG.md"))
            if _sha256(prior_raw) != prior_hash or _sha256(current_raw) != current_hash:
                return False
            _, _, prior_sections = _backlog_sections(prior_raw)
            _, _, current_sections = _backlog_sections(current_raw)
            actual_changed = tuple(sorted(
                item_id
                for item_id in set(prior_sections) | set(current_sections)
                if prior_sections.get(item_id) != current_sections.get(item_id)
            ))
            if actual_changed != changed_ids:
                return False
            if section_hashes:
                expected_sections = section_hashes[0]
                if set(expected_sections) != set(changed_ids) or any(
                    _sha256(prior_sections.get(item_id, b"")) != hashes[0]
                    or _sha256(current_sections.get(item_id, b"")) != hashes[1]
                    for item_id, hashes in expected_sections.items()
                ):
                    return False
            reconstructed_ids.update(actual_changed)
        return (
            tuple(sorted(reconstructed_ids))
            == tuple(sorted(pinned["history_changed_ids"]))
            and expected[0][2] == pinned["previous_source_sha256"]
            and expected[-1][3] == pinned["prior_source_sha256"]
        )

    def _v0004_history_authorized() -> bool:
        """Reconstruct the complete post-v0003 BACKLOG history from Git objects."""
        return _history_authorized(V0004_RECONCILIATION)

    def _v0005_history_authorized() -> bool:
        """Reconstruct the complete post-v0004 BACKLOG history from Git objects."""
        return _history_authorized(V0005_RECONCILIATION)

    def _backlog_sections(raw: bytes) -> tuple[bytes, list[str], dict[str, bytes]]:
        """Preserve each complete item section and all bytes before the first item."""
        headings = list(re.finditer(rb"(?m)^### B-[^\r\n]*", raw))
        if not headings:
            raise LedgerError("BACKLOG.md has no canonical B-ID sections")
        order: list[str] = []
        sections: dict[str, bytes] = {}
        for index, heading in enumerate(headings):
            match = re.match(rb"### (B-[0-9]+)(?=\b|\W)", heading.group())
            if match is None:
                raise LedgerError("BACKLOG.md has malformed B-ID heading")
            item_id = canonical_id(match.group(1).decode("ascii"))[0]
            if item_id in sections:
                raise LedgerError(f"BACKLOG.md has duplicate heading {item_id}")
            end = headings[index + 1].start() if index + 1 < len(headings) else len(raw)
            section = raw[heading.start() : end]
            try:
                items = backlog_verify.parse(section.decode("utf-8"))
            except UnicodeDecodeError as exc:
                raise LedgerError(f"BACKLOG.md section {item_id} is not UTF-8") from exc
            if len(items) != 1 or items[0].id != item_id:
                raise LedgerError(
                    f"BACKLOG.md heading {item_id} lacks exactly one matching item"
                )
            order.append(item_id)
            sections[item_id] = section
        return raw[: headings[0].start()], order, sections

    def _normative_section(section: bytes, item_id: str) -> bytes:
        """Mask only canonical transition fields inside the one backlog fence.

        Every other byte, including headings, free prose, and verify-means,
        remains normative across every status transition. The parsed field
        transition is checked separately against BASE-owned rules.
        """
        fence = re.search(rb"(?ms)^```backlog\n(.*?)^```", section)
        if fence is None:
            raise LedgerError(f"{item_id}: missing canonical backlog fence")
        body = fence.group(1)
        for key in (b"status", b"owner", b"last-verified"):
            pattern = rb"(?m)^" + key + rb":[^\r\n]*$"
            body, count = re.subn(pattern, key + b": <transition>", body)
            if count != 1:
                raise LedgerError(
                    f"{item_id}: transition field {key.decode()} is not unique and canonical"
                )
        return section[: fence.start(1)] + body + section[fence.end(1) :]

    def _validate_receipt_transition(
        receipt: dict[str, object],
        prior_manifest_raw: bytes,
        prior: dict[str, bytes],
        current: dict[str, bytes],
        *,
        previous: dict[str, object] | None,
        base_sha: str,
        sequence: int,
        workflow_root: Path,
        today: backlog_verify.dt.date | None = None,
    ) -> None:
        """Derive every receipt assertion from immutable BASE and candidate bytes."""
        expected_hashes = {
            "prior_snapshot_sha256": _sha256(prior_manifest_raw),
            "prior_source_sha256": _sha256(prior["BACKLOG.md"]),
            "source_sha256": _sha256(current["BACKLOG.md"]),
            "prior_ledger_sha256": _sha256(prior[LEDGER_RELATIVE.as_posix()]),
            "ledger_sha256": _sha256(current[LEDGER_RELATIVE.as_posix()]),
        }
        if receipt["base_commit"] != base_sha or receipt["sequence"] != sequence:
            raise LedgerError(
                "successor snapshot has stale/replayed immutable base or sequence"
            )
        for key, expected in expected_hashes.items():
            if receipt[key] != expected:
                raise LedgerError(
                    f"successor snapshot {key} differs from BASE-derived bytes"
                )
        for name, state in (
            ("prior_catalog_sha256", prior),
            ("catalog_sha256", current),
        ):
            expected = {
                path.as_posix(): _sha256(state[path.as_posix()])
                for path in _catalog_relatives()
            }
            if receipt[name] != expected:
                raise LedgerError(
                    f"successor snapshot {name} differs from BASE-derived bytes"
                )
        new_text = current["BACKLOG.md"].decode("utf-8")
        old_preamble, old_order, old_sections = _backlog_sections(prior["BACKLOG.md"])
        new_preamble, new_order, new_sections = _backlog_sections(current["BACKLOG.md"])
        if old_preamble != new_preamble:
            raise LedgerError("successor changed immutable BACKLOG preamble")
        if new_order[: len(old_order)] != old_order:
            raise LedgerError("successor reordered or deleted BASE backlog sections")
        changed = sorted(
            item_id
            for item_id in new_order
            if old_sections.get(item_id) != new_sections[item_id]
        )
        if receipt["changed_ids"] != changed:
            raise LedgerError(
                "successor changed IDs differ from BACKLOG section byte delta"
            )
        sprint3_rewrite = _sprint3_rewrite_authorized(
            prior, current, receipt, sequence,
        )
        v0004_reconciliation = previous is not None and _v0004_reconciliation_authorized(
            previous, prior, current, receipt, sequence,
        )
        v0006_reconciliation = previous is not None and _v0006_reconciliation_authorized(
            previous, prior, current, receipt, sequence,
        )
        v0007_reconciliation = previous is not None and _v0007_reconciliation_authorized(
            previous, prior, current, receipt, sequence,
        )
        v0008_reconciliation = previous is not None and _v0008_reconciliation_authorized(
            previous, prior, current, receipt, sequence,
        )
        v0009_reconciliation = previous is not None and _v0009_reconciliation_authorized(
            previous, prior, current, receipt, sequence,
            trusted_root=workflow_root, trusted_base=base_sha,
        )
        for item_id in changed:
            if item_id not in old_sections:
                continue
            if not (
                (sprint3_rewrite and item_id in SPRINT3_CHANGED_IDS)
                or (
                    v0004_reconciliation
                    and item_id in V0004_RECONCILIATION["changed_ids"]
                )
                or (v0006_reconciliation and item_id in V0006_RECONCILIATION["changed_ids"])
                or (v0007_reconciliation and item_id in V0007_RECONCILIATION["changed_ids"])
                or (v0008_reconciliation and item_id in V0008_RECONCILIATION["changed_ids"])
                or (v0009_reconciliation and item_id in V0009_RECONCILIATION["changed_ids"])
            ) and (
                _normative_section(old_sections[item_id], item_id)
                != _normative_section(new_sections[item_id], item_id)
            ):
                raise LedgerError(
                    f"{item_id}: normative BACKLOG section changed without trusted byte-pinned authorization"
                )
        counts = backlog_status_counts(new_text)
        if receipt["status_counts"] != {
            key: counts.get(key, 0) for key in ("done", "open", "parked")
        } or receipt["item_count"] != sum(counts.values()):
            raise LedgerError("successor status counts differ from BACKLOG")
        open_ids = sorted(open_backlog_ids(new_text))
        if receipt["open_ids"] != open_ids:
            raise LedgerError("successor open IDs differ from BACKLOG")
        ledger_text = current[LEDGER_RELATIVE.as_posix()].decode("utf-8")
        state = parse_ledger_state(ledger_text, str(LEDGER_RELATIVE))
        if state["base-ref"] != base_sha:
            raise LedgerError("successor ledger base-ref differs from immutable BASE")
        validate_complete_catalog_state(
            new_text,
            ledger_text,
            {
                path.as_posix(): current[path.as_posix()]
                for path in _catalog_relatives()
            },
            workflow_root,
            base_sha,
        )
        transition_errors = backlog_verify.validate_candidate_transitions(
            backlog_verify.parse(new_text),
            backlog_verify.parse(prior["BACKLOG.md"].decode("utf-8")),
            today or backlog_verify.dt.date.today(),
            allow_sprint3_rewrite=sprint3_rewrite,
            allow_b154_reconciliation=v0004_reconciliation,
            allow_v0006_reconciliation=v0006_reconciliation,
            allow_v0007_reconciliation=v0007_reconciliation,
            allow_v0009_reconciliation=v0009_reconciliation,
            successor_mode=True,
        )
        if transition_errors:
            raise LedgerError("candidate BACKLOG transition rejected: " + "; ".join(transition_errors))

    def load_successor_chain(
        root: Path = REPO_ROOT,
        *,
        pending_receipt: dict[str, object] | None = None,
        pending_current: dict[str, bytes] | None = None,
    ) -> dict[str, object]:
        """Replay append-only receipts against immutable delivered-main preimages."""
        previous = load_postmerge_snapshot_manifest()
        previous_path = GENESIS_SNAPSHOT_RELATIVE
        previous_raw = _regular_bytes(root, previous_path)
        paths = _successor_paths(root)
        for index, path in enumerate(paths):
            raw = _regular_bytes(root, path)
            receipt = _receipt(raw, path.as_posix())
            base_sha = receipt["base_commit"]
            introduced = subprocess.run(
                [
                    "git",
                    "log",
                    "--first-parent",
                    "--full-history",
                    "--format=%H",
                    "--",
                    path.as_posix(),
                ],
                cwd=root,
                check=False,
                capture_output=True,
                text=True,
            )
            commits = introduced.stdout.splitlines()
            if introduced.returncode or len(commits) != 1:
                raise LedgerError(
                    f"{path}: successor introduction is not unique on main history"
                )
            first_parent = subprocess.run(
                ["git", "rev-parse", f"{commits[0]}^1"],
                cwd=root,
                check=False,
                capture_output=True,
                text=True,
            ).stdout.strip()
            if first_parent != base_sha or _git_bytes(root, commits[0], path) != raw:
                raise LedgerError(
                    f"{path}: successor was rewritten or names the wrong main parent"
                )
            if (
                subprocess.run(
                    ["git", "merge-base", "--is-ancestor", base_sha, "HEAD"],
                    cwd=root,
                    check=False,
                ).returncode
                != 0
            ):
                raise LedgerError(
                    f"{path}: immutable successor base is not an ancestor of HEAD"
                )
            if _git_bytes(root, base_sha, previous_path) != previous_raw:
                raise LedgerError(f"{path}: prior snapshot differs from immutable BASE")
            prior = _git_state_bytes(root, base_sha)
            current = _git_state_bytes(root, commits[0])
            v0004_reconciliation = _v0004_reconciliation_authorized(
                previous, prior, current, receipt, index + 3,
            )
            v0005_reconciliation = _v0005_reconciliation_authorized(
                previous, prior, current, receipt, index + 3,
            )
            v0006_reconciliation = _v0006_reconciliation_authorized(
                previous, prior, current, receipt, index + 3,
            )
            v0007_reconciliation = _v0007_reconciliation_authorized(
                previous, prior, current, receipt, index + 3,
            )
            v0008_reconciliation = _v0008_reconciliation_authorized(
                previous, prior, current, receipt, index + 3,
            )
            v0009_reconciliation = _v0009_reconciliation_authorized(
                previous, prior, current, receipt, index + 3,
                trusted_root=root, trusted_base=base_sha,
            )
            if (
                _sha256(prior["BACKLOG.md"]) != previous["source_sha256"]
                and not v0004_reconciliation
                and not v0005_reconciliation
                and not v0006_reconciliation
                and not v0007_reconciliation
                and not v0008_reconciliation
                and not v0009_reconciliation
            ):
                raise LedgerError(f"{path}: prior BACKLOG differs from prior snapshot")
            if index + 1 < len(paths):
                next_raw = _regular_bytes(root, paths[index + 1])
                next_receipt = _receipt(next_raw, paths[index + 1].as_posix())
                next_current = _git_state_bytes(
                    root,
                    subprocess.run(
                        ["git", "log", "--first-parent", "--full-history", "--format=%H", "--", paths[index + 1].as_posix()],
                        cwd=root, check=False, capture_output=True, text=True,
                    ).stdout.strip(),
                )
                next_prior = _git_state_bytes(root, next_receipt["base_commit"])
                bridge = _v0004_reconciliation_authorized(
                    receipt, next_prior, next_current, next_receipt, index + 4,
                )
                bridge = bridge or _v0005_reconciliation_authorized(
                    receipt, next_prior, next_current, next_receipt, index + 4,
                )
                bridge = bridge or _v0006_reconciliation_authorized(
                    receipt, next_prior, next_current, next_receipt, index + 4,
                )
                bridge = bridge or _v0007_reconciliation_authorized(
                    receipt, next_prior, next_current, next_receipt, index + 4,
                )
                bridge = bridge or _v0008_reconciliation_authorized(
                    receipt, next_prior, next_current, next_receipt, index + 4,
                )
                bridge = bridge or _v0009_reconciliation_authorized(
                    receipt, next_prior, next_current, next_receipt, index + 4,
                    trusted_root=root, trusted_base=next_receipt["base_commit"],
                )
                if current != next_prior and not bridge:
                    raise LedgerError(
                        f"{path}: delivered state drifted before next successor"
                    )
            elif current != _state_bytes(root):
                bridge = (
                    pending_receipt is not None
                    and pending_current is not None
                    and _v0004_reconciliation_authorized(
                        receipt, _state_bytes(root), pending_current,
                        pending_receipt, index + 4,
                    )
                    or pending_receipt is not None
                    and pending_current is not None
                    and _v0005_reconciliation_authorized(
                        receipt, _state_bytes(root), pending_current,
                        pending_receipt, index + 4,
                    )
                    or pending_receipt is not None
                    and pending_current is not None
                    and _v0006_reconciliation_authorized(
                        receipt, _state_bytes(root), pending_current,
                        pending_receipt, index + 4,
                    )
                    or pending_receipt is not None
                    and pending_current is not None
                    and _v0007_reconciliation_authorized(
                        receipt, _state_bytes(root), pending_current,
                        pending_receipt, index + 4,
                    )
                    or pending_receipt is not None
                    and pending_current is not None
                    and _v0008_reconciliation_authorized(
                        receipt, _state_bytes(root), pending_current,
                        pending_receipt, index + 4,
                    )
                    or pending_receipt is not None
                    and pending_current is not None
                    and _v0009_reconciliation_authorized(
                        receipt, _state_bytes(root), pending_current,
                        pending_receipt, index + 4,
                        trusted_root=root, trusted_base=pending_receipt["base_commit"],
                    )
                )
                if not bridge:
                    raise LedgerError(
                        f"{path}: delivered state drifted after last successor"
                    )
            _validate_receipt_transition(
                receipt,
                previous_raw,
                prior,
                current,
                previous=previous,
                base_sha=base_sha,
                sequence=index + 3,
                workflow_root=root,
            )
            previous, previous_raw, previous_path = receipt, raw, path
        return previous

    def validate_candidate_successor(
        base_root: Path,
        candidate_root: Path,
        *,
        base_sha: str | None = None,
        today: backlog_verify.dt.date | None = None,
    ) -> dict[str, object]:
        """BASE-owned PR check: the receipt records, but never authorizes, a delta."""
        resolved = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=base_root,
            check=False,
            capture_output=True,
            text=True,
        ).stdout.strip()
        if not re.fullmatch(r"[0-9a-f]{40}", resolved) or (
            base_sha is not None and base_sha != resolved
        ):
            raise LedgerError("trusted BASE is not the immutable event SHA")
        base_sha = resolved
        base_paths = _successor_paths(base_root)
        candidate_paths = _successor_paths(candidate_root)
        next_path = (
            SNAPSHOT_DIRECTORY
            / f"backlog-ledger-snapshot-v{len(base_paths) + 3:04d}.json"
        )
        if candidate_paths != [*base_paths, next_path]:
            raise LedgerError(
                "candidate must append exactly one next successor snapshot"
            )
        raw = _regular_bytes(candidate_root, next_path)
        receipt = _receipt(raw, next_path.as_posix())
        previous = load_successor_chain(
            base_root,
            pending_receipt=receipt,
            pending_current=_state_bytes(candidate_root),
        )
        old_paths = (
            SNAPSHOT_DIRECTORY / "backlog-ledger-snapshot.json",
            GENESIS_SNAPSHOT_RELATIVE,
            *base_paths,
        )
        for path in old_paths:
            old = _regular_bytes(base_root, path)
            if old != _git_bytes(base_root, base_sha, path):
                raise LedgerError(f"trusted BASE snapshot drifted: {path}")
            if _regular_bytes(candidate_root, path) != old:
                raise LedgerError(f"candidate rewrote prior snapshot: {path}")
        prior = _state_bytes(base_root)
        if prior != _git_state_bytes(base_root, base_sha):
            raise LedgerError("trusted BASE data differs from immutable event SHA")
        current = _state_bytes(candidate_root)
        previous_path = base_paths[-1] if base_paths else GENESIS_SNAPSHOT_RELATIVE
        _validate_receipt_transition(
            receipt,
            _regular_bytes(base_root, previous_path),
            prior,
            current,
            previous=previous,
            base_sha=base_sha,
            sequence=len(base_paths) + 3,
            workflow_root=candidate_root,
            today=today,
        )
        if (
            receipt["prior_source_sha256"] != previous["source_sha256"]
            and not _v0004_reconciliation_authorized(
                previous, prior, current, receipt, len(base_paths) + 3,
            )
            and not _v0005_reconciliation_authorized(
                previous, prior, current, receipt, len(base_paths) + 3,
            )
            and not _v0008_reconciliation_authorized(
                previous, prior, current, receipt, len(base_paths) + 3,
            )
            and not _v0009_reconciliation_authorized(
                previous, prior, current, receipt, len(base_paths) + 3,
                trusted_root=base_root, trusted_base=base_sha,
            )
        ):
            raise LedgerError("candidate predecessor is not the trusted BASE snapshot")
        trusted_items = backlog_verify.parse(prior["BACKLOG.md"].decode("utf-8"))
        backlog_verify.check_candidate_controls(
            candidate_root, base_root, trusted_items
        )
        return receipt

    def successor_required(base_root: Path, candidate_root: Path) -> bool:
        """A changed ledger source, catalog, or snapshot requires a new receipt."""
        if _state_bytes(base_root) != _state_bytes(candidate_root):
            return True
        if _successor_paths(base_root) != _successor_paths(candidate_root):
            return True
        for path in (
            SNAPSHOT_DIRECTORY / "backlog-ledger-snapshot.json",
            GENESIS_SNAPSHOT_RELATIVE,
            *_successor_paths(base_root),
        ):
            if _regular_bytes(base_root, path) != _regular_bytes(candidate_root, path):
                return True
        return False

    return SimpleNamespace(
        _sha256=_sha256,
        _sprint3_rewrite_authorized=_sprint3_rewrite_authorized,
        _v0004_reconciliation_authorized=_v0004_reconciliation_authorized,
        _normative_section=_normative_section,
        _catalog_relatives=_catalog_relatives,
        _v0004_catalogs=_v0004_catalogs,
        _v0004_ledger=_v0004_ledger,
        _v0005_ledger=_v0005_ledger,
        _git_state_bytes=_git_state_bytes,
        _v0004_history_authorized=_v0004_history_authorized,
        _v0005_history_authorized=_v0005_history_authorized,
        _v0005_reconciliation_authorized=_v0005_reconciliation_authorized,
        _state_bytes=_state_bytes,
        _successor_paths=_successor_paths,
        load_successor_chain=load_successor_chain,
        validate_candidate_successor=validate_candidate_successor,
        successor_required=successor_required,
        _v0006_reconciliation_authorized=_v0006_reconciliation_authorized,
        _v0007_reconciliation_authorized=_v0007_reconciliation_authorized,
        _v0008_reconciliation_authorized=_v0008_reconciliation_authorized,
        _v0009_reconciliation_authorized=_v0009_reconciliation_authorized,
        _v0009_ledger=_v0009_ledger,
    )
