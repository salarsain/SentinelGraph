"""
SentinelGraph — Form Parser

Extracts forms, inputs, and parameters from HTML for security analysis.
"""

from dataclasses import dataclass, field
from urllib.parse import urljoin

import structlog
from bs4 import BeautifulSoup

logger = structlog.get_logger(__name__)


@dataclass
class FormInput:
    """A single form input field."""
    name: str
    input_type: str  # text, password, hidden, email, file, etc.
    value: str | None = None
    required: bool = False
    pattern: str | None = None
    placeholder: str | None = None
    max_length: int | None = None


@dataclass
class DiscoveredForm:
    """A form discovered during crawling."""
    action: str
    method: str  # GET or POST
    inputs: list[FormInput] = field(default_factory=list)
    page_url: str = ""
    form_id: str | None = None
    form_name: str | None = None
    has_csrf_token: bool = False
    has_file_upload: bool = False
    has_password_field: bool = False
    enctype: str | None = None

    @property
    def parameter_names(self) -> list[str]:
        return [inp.name for inp in self.inputs if inp.name]


# Common CSRF token field names
CSRF_FIELD_NAMES = {
    "csrf", "csrf_token", "csrftoken", "csrfmiddlewaretoken",
    "_csrf", "_token", "authenticity_token", "xsrf_token",
    "_xsrf", "__requestverificationtoken", "antiforgery",
    "csrf-token", "x-csrf-token",
}


class FormParser:
    """Extracts and analyzes HTML forms."""

    def extract(self, html: str, page_url: str) -> list[DiscoveredForm]:
        """Extract all forms from HTML content.

        Args:
            html: HTML content
            page_url: URL of the page containing the forms

        Returns:
            List of discovered forms with full input details
        """
        forms: list[DiscoveredForm] = []

        try:
            soup = BeautifulSoup(html, "lxml")

            for form_tag in soup.find_all("form"):
                form = self._parse_form(form_tag, page_url)
                if form:
                    forms.append(form)

        except Exception as e:
            logger.warning("form_parser.error", error=str(e))

        return forms

    def _parse_form(self, form_tag, page_url: str) -> DiscoveredForm | None:
        """Parse a single <form> tag."""
        try:
            action = form_tag.get("action", "").strip()
            if action:
                action = urljoin(page_url, action)
            else:
                action = page_url  # Form submits to current page

            method = form_tag.get("method", "GET").upper()
            if method not in ("GET", "POST", "PUT", "PATCH", "DELETE"):
                method = "GET"

            form = DiscoveredForm(
                action=action,
                method=method,
                page_url=page_url,
                form_id=form_tag.get("id"),
                form_name=form_tag.get("name"),
                enctype=form_tag.get("enctype"),
            )

            # Extract input fields
            for input_tag in form_tag.find_all(["input", "textarea", "select"]):
                form_input = self._parse_input(input_tag)
                if form_input:
                    form.inputs.append(form_input)

                    # Detect special field types
                    name_lower = (form_input.name or "").lower()
                    if name_lower in CSRF_FIELD_NAMES:
                        form.has_csrf_token = True
                    if form_input.input_type == "file":
                        form.has_file_upload = True
                    if form_input.input_type == "password":
                        form.has_password_field = True

            return form

        except Exception as e:
            logger.debug("form_parser.parse_error", error=str(e))
            return None

    @staticmethod
    def _parse_input(input_tag) -> FormInput | None:
        """Parse a single form input element."""
        tag_name = input_tag.name

        if tag_name == "textarea":
            return FormInput(
                name=input_tag.get("name", ""),
                input_type="textarea",
                value=input_tag.string,
                required=input_tag.has_attr("required"),
                placeholder=input_tag.get("placeholder"),
                max_length=int(input_tag["maxlength"]) if input_tag.get("maxlength") else None,
            )

        if tag_name == "select":
            options = [opt.get("value", opt.string or "") for opt in input_tag.find_all("option")]
            return FormInput(
                name=input_tag.get("name", ""),
                input_type="select",
                value=options[0] if options else None,
                required=input_tag.has_attr("required"),
            )

        # <input> elements
        name = input_tag.get("name", "")
        if not name:
            return None

        return FormInput(
            name=name,
            input_type=input_tag.get("type", "text").lower(),
            value=input_tag.get("value"),
            required=input_tag.has_attr("required"),
            pattern=input_tag.get("pattern"),
            placeholder=input_tag.get("placeholder"),
            max_length=int(input_tag["maxlength"]) if input_tag.get("maxlength") else None,
        )
