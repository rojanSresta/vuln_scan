"""CSRF vulnerability check"""

from typing import List, Sequence

from app.constants import TOKEN_KEYWORDS, STATE_CHANGING_KEYWORDS
from app.services.scanning.base import CrawlContext, VulnerabilityFinding, VulnerabilityCheck
from app.services.scanning.common import has_token_name, is_state_changing_form


class CSRFCheck(VulnerabilityCheck):
    category = "csrf"

    def scan(self, context: CrawlContext) -> List[VulnerabilityFinding]:
        for page in context.pages:
            for form in page.forms:
                if form.method != "post":
                    continue
                if not is_state_changing_form(form, STATE_CHANGING_KEYWORDS):
                    continue
                if any(has_token_name(field.name, TOKEN_KEYWORDS) for field in form.fields):
                    continue
                return [
                    VulnerabilityFinding(
                        name="Absence of Anti-CSRF Tokens",
                        risk="Medium",
                        url=form.action_url,
                        description="A state-changing form does not appear to include a CSRF token.",
                        solution="Add a unique server-validated CSRF token to every state-changing form submission.",
                        explanation="Without a per-request token, another site may be able to trigger sensitive actions for a logged-in user.",
                        reference=self._build_reference("CSRF"),
                        cwe_id="352",
                        wasc_id="9",
                    )
                ]
        return []
