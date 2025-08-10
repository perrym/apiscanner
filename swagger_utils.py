##############################################
# APISCAN - API Security Scanner             #
# Licensed under the MIT License             #
# Author: Perry Mertens pamsniffer@gmail.com #
##############################################
from __future__ import annotations
from typing import Any, Optional, Dict, List
from urllib.parse import urljoin
import random
import string
import uuid
import datetime
import secrets
import re
import json
import logging
import hashlib  
from pathlib import Path
from functools import lru_cache
try:
    import yaml  # optional, we fall back to JSON if missing
    _HAS_YAML = True
except Exception:
    _HAS_YAML = False
HTTP_METHODS = {"get","put","post","delete","patch","head","options","trace"}

# Configure logging
logger = logging.getLogger("swagger_utils")
logger.addHandler(logging.NullHandler())

# ----------------------------------------------------------------------
# Configuration
# ----------------------------------------------------------------------
class DummyGeneratorConfig:
    """Configuration for dummy value generation"""
    __slots__ = (
        'max_array_length', 
        'strict_mode',
        'locale',
        'industry',
        'enable_caching',
        'default_string_length'
    )
    
    def __init__(self):
        self.max_array_length: int = 10
        self.strict_mode: bool = False
        self.locale: str = "en-US"
        self.industry: Optional[str] = None  
        self.enable_caching: bool = True
        self.default_string_length: int = 12

# ----------------------------------------------------------------------
# Main Generator Class
# ----------------------------------------------------------------------
class OpenAPIRequestBuilder:
    """Build realistic API requests from OpenAPI specifications"""
    VALID_TYPES = {"string", "integer", "number", "boolean", "object", "array", "null"}
    PLACEHOLDER_RX = re.compile(r"\{([\w\-+]+)\}|:([\w\-+]+)|<([\w\-+]+)>")

    
    MEDICAL_TERMS = ["cardiology", "orthopedics", "neurology", "pediatrics", "oncology"]
    FINANCE_TERMS = ["IBAN", "SWIFT", "BIC", "ACH", "SEPA"]
    ECOMMERCE_TERMS = ["SKU", "GTIN", "UPC", "EAN", "ASIN"]
    
    def __init__(self, openapi_spec: Optional[Dict] = None, config: Optional[DummyGeneratorConfig] = None):
        self.openapi_spec = openapi_spec or {}
        self.config = config or DummyGeneratorConfig()
        self.value_cache: Dict[str, Any] = {}
        
        # Setup industry-specific generators
        self.industry_generators = {
            "finance": self._generate_finance_value,
            "healthcare": self._generate_medical_value,
            "ecommerce": self._generate_ecommerce_value
        }

    def clear_cache(self):
        """Clear the value generation cache"""
        self.value_cache.clear()


    # ----------------------------------------------------------------
    # Core Value Generation
    # ----------------------------------------------------------------
    def generate_value(self, field_name: str, schema: Optional[Dict] = None) -> Any:
        """Generate a plausible dummy value with caching"""
        if not schema:
            schema = {}
            
        cache_key = self._create_cache_key(field_name, schema)
        
        # Return cached value if available
        if self.config.enable_caching and cache_key in self.value_cache:
            return self.value_cache[cache_key]
        
        # Try industry-specific generator first
        if self.config.industry:
            industry_value = self.industry_generators.get(self.config.industry, lambda n, s: None)(field_name, schema)
            if industry_value is not None:
                if self.config.enable_caching:
                    self.value_cache[cache_key] = industry_value
                return industry_value
        
        # Handle schema combinators
        combinator_value = self._handle_combinators(field_name, schema)
        if combinator_value is not None:
            if self.config.enable_caching:
                self.value_cache[cache_key] = combinator_value
            return combinator_value
        
        # Handle null values
        if schema.get("nullable", False) and random.random() > 0.7:
            if self.config.enable_caching:
                self.value_cache[cache_key] = None
            return None
            
        # Get value based on type or format
        value = self._type_based_value(field_name, schema)
        
        if self.config.enable_caching:
            self.value_cache[cache_key] = value
        print(f"[DUMMY] {field_name} -> {value}")
        return value


# ----------------------------------------------------------------
# Cache-key helper
# ----------------------------------------------------------------
    def _create_cache_key(self, field_name: str, schema: Dict) -> str:
        try:
            # JSON stringify met consistente volgorde - bytes - SHA-1 - hex
            schema_key = hashlib.sha1(
                json.dumps(schema, sort_keys=True).encode("utf-8")
            ).hexdigest()
        except TypeError:
            # Als het schema niet JSON-serialiseerbaar is (zeldzaam),
            # gebruik str() als nood-oplossing
            schema_key = hashlib.sha1(str(schema).encode("utf-8")).hexdigest()

        return f"{field_name}-{schema_key}"


    # ----------------------------------------------------------------
# Schema combinator handler
# ----------------------------------------------------------------
    def _handle_combinators(self, field_name: str, schema: Dict) -> Any:
        """
        Return a generated value when *schema* contains oneOf, anyOf or allOf.
        If the combinator is not present, return None.

        Behaviour
        ---------
        oneOf : choose exactly one random subschema
        anyOf : choose one random subschema (same as oneOf for dummy data)
        allOf : merge every subschema (deep-merge for 'properties' and
                union for 'required', 'enum'); then generate value
        """
        # ----- oneOf / anyOf  ----------------------------------------
        for key in ("oneOf", "anyOf"):
            if key in schema and schema[key]:
                chosen = random.choice(schema[key])
                resolved = self._resolve_ref(chosen)
                return self.generate_value(field_name, resolved)

        # ----- allOf -------------------------------------------------
        if "allOf" in schema and schema["allOf"]:
            merged: Dict[str, Any] = {}

            for sub in schema["allOf"]:
                resolved = self._resolve_ref(sub) or {}
                # deep-merge 'properties'
                if "properties" in resolved:
                    merged.setdefault("properties", {}).update(resolved["properties"])
                # union of 'required'
                if "required" in resolved:
                    req = set(merged.get("required", [])) | set(resolved["required"])
                    merged["required"] = sorted(req)
                # simple overwrite for scalar keys
                for key in ("type", "format", "enum", "items", "nullable"):
                    if key in resolved and key not in merged:
                        merged[key] = resolved[key]

            # After merge, call generator again on merged schema
            return self.generate_value(field_name, merged)

        # ----- no combinator ----------------------------------------
        return None


    def _type_based_value(self, field_name: str, schema: Dict) -> Any:
        """Generate value based on JSON schema type"""
        schema_type = schema.get("type", "string")
        
        # Validate schema type
        if schema_type not in self.VALID_TYPES:
            if self.config.strict_mode:
                raise ValueError(f"Invalid schema type: {schema_type}")
            logger.warning(f"Invalid schema type: {schema_type} for field {field_name}")
            return f"invalid_type_{schema_type}"
        
        # Handle different types
        if schema_type == "integer":
            return self._generate_integer(schema)
            
        if schema_type == "number":
            return self._generate_number(schema)
            
        if schema_type == "boolean":
            return random.choice([True, False])
            
        if schema_type == "object":
            return self._generate_object(schema)
            
        if schema_type == "array":
            return self._generate_array(schema)
            
        if schema_type == "null":
            return None
            
        # Default to string handling
        return self._generate_string(field_name, schema)

    # ----------------------------------------------------------------
    # Type-specific Generators
    # ----------------------------------------------------------------
    def _generate_integer(self, schema: Dict) -> int:
        """Generate integer value with constraints"""
        minimum = schema.get("minimum", 0)
        maximum = schema.get("maximum", 10000)
        return random.randint(minimum, maximum)

    def _generate_number(self, schema: Dict) -> float:
        """Generate float value with constraints"""
        minimum = schema.get("minimum", 0.0)
        maximum = schema.get("maximum", 10000.0)
        return round(random.uniform(minimum, maximum), 2)

    def _generate_string(self, field_name: str, schema: Dict) -> str:
        """Generate string value with format handling"""
        fmt = schema.get("format", "")
        enum = schema.get("enum")
        
        if enum:
            return random.choice(enum)
            
        if fmt == "uuid" or "guid" in field_name.lower():
            return str(uuid.uuid4())
            
        if fmt == "date":
            return datetime.date.today().isoformat()
            
        if fmt in ("date-time", "datetime"):
            return datetime.datetime.now(datetime.timezone.utc).isoformat()
            
        if fmt == "binary":
            return secrets.token_urlsafe(16)
            
        if fmt == "email" or "email" in field_name.lower():
            return f"{self._random_string(8)}@example.com"
            
        if "phone" in field_name.lower() or "tel" in field_name.lower():
            return self._generate_phone_number()
            
        # Fallback to heuristic-based generation
        return self._heuristic_based_value(field_name, schema)

    def _generate_object(self, schema: Dict) -> Dict:
        """Generate object with properties"""
        properties = schema.get("properties", {})
        required = schema.get("required", [])
        
        obj = {}
        for prop, prop_schema in properties.items():
            # Only include required properties + 70% of optional ones
            if prop in required or random.random() < 0.7:
                obj[prop] = self.generate_value(prop, prop_schema)
                
        return obj

    def _generate_array(self, schema: Dict) -> List:
        """
        Generate an array that respects minItems / maxItems
        and the global config.max_array_length.
        """
        item_schema = schema.get("items", {})
        min_items = schema.get("minItems", 1)
        max_items = schema.get("maxItems", self.config.max_array_length)
        # Guard - never let max_items fall below min_items
        max_items = max(min_items, max_items, 1)
        # Clip to global limit
        max_items = min(max_items, self.config.max_array_length)
        # Fixed-size shortcut (minItems == maxItems)
        if "minItems" in schema and "maxItems" in schema and min_items == max_items:
            count = min_items
        else:
            count = random.randint(min_items, max_items)

        return [self.generate_value("array_item", item_schema) for _ in range(count)]

    # ----------------------------------------------------------------
    # Heuristic-based Value Generation
    # ----------------------------------------------------------------
    def _heuristic_based_value(self, field_name: str, schema: Dict) -> Any:
        """Generate value based on field name heuristics"""
        name = field_name.lower()
        
        if name.endswith("id") or name == "id":
            return random.randint(1, 99999)
            
        if name.endswith(("date", "datum")):
            return datetime.date.today().isoformat()
            
        if "time" in name and "date" not in name:
            return datetime.datetime.now(datetime.timezone.utc).time().isoformat()
            
        if any(key in name for key in ("amount", "price", "total", "amt")):
            return round(random.uniform(10, 9999), 2)
            
        if name.startswith(("is_", "has_")) or name.startswith("flag"):
            return random.choice([True, False])
            
        if "code" in name:
            return secrets.token_hex(4)
            
        if "lat" in name or "latitude" in name:
            return round(random.uniform(-90, 90), 6)
            
        if "lon" in name or "lng" in name or "longitude" in name:
            return round(random.uniform(-180, 180), 6)
            
        if "zip" in name or "postal" in name:
            return self._generate_postal_code()
            
        # Fallback to random string
        max_len = schema.get("maxLength", self.config.default_string_length)
        return self._random_string(min(max_len, 50))

    # ----------------------------------------------------------------
    # Industry-specific Generators
    # ----------------------------------------------------------------
    def _generate_finance_value(self, field_name: str, schema: Dict) -> Optional[Any]:
        """Generate finance industry specific values"""
        name = field_name.lower()
        
        if "iban" in name:
            country_code = random.choice(["NL", "DE", "FR", "GB", "US"])
            return f"{country_code}00 ABCD0123456789"
            
        if "bic" in name or "swift" in name:
            return random.choice(["ABNANL2A", "INGBNL2A", "RABONL2U"])
            
        if "currency" in name:
            return random.choice(["USD", "EUR", "GBP", "JPY"])
            
        if "amount" in name or "value" in name:
            return round(random.uniform(100, 1000000), 2)
            
        return None

    def _generate_medical_value(self, field_name: str, schema: Dict) -> Optional[Any]:
        """Generate healthcare industry specific values"""
        name = field_name.lower()
        
        if "diagnosis" in name:
            return random.choice(["J45.909", "I10", "E11.9", "M54.5"])
            
        if "procedure" in name:
            return random.choice(["CPT-99213", "ICD-10-PCS-0DBJ4ZZ"])
            
        if "department" in name:
            return random.choice(self.MEDICAL_TERMS)
            
        if "patient" in name and "id" in name:
            return f"PAT-{random.randint(100000, 999999)}"
            
        return None

    def _generate_ecommerce_value(self, field_name: str, schema: Dict) -> Optional[Any]:
        """Generate e-commerce industry specific values"""
        name = field_name.lower()
        
        if "sku" in name:
            return f"SKU-{random.randint(1000, 9999)}"
            
        if "gtin" in name or "upc" in name:
            return str(random.randint(1000000000000, 9999999999999))
            
        if "price" in name:
            return round(random.uniform(5, 500), 2)
            
        if "quantity" in name:
            return random.randint(1, 10)
            
        return None

    # ----------------------------------------------------------------
    # Utility Methods
    # ----------------------------------------------------------------
    def _random_string(self, length: int = 8) -> str:
        """Return a random lowercase alphanumeric string."""
        alphabet = string.ascii_lowercase + string.digits
        return "".join(random.choices(alphabet, k=length))
            
    def _generate_phone_number(self) -> str:
        """Generate a realistic phone number"""
        formats = [
            "+## ## ########",
            "+## ### ######",
            "+## (###) ###-####",
            "###-###-####"
        ]
        fmt = random.choice(formats)
        return "".join([str(random.randint(0, 9)) if c == "#" else c for c in fmt])
        
    def _generate_postal_code(self) -> str:
        """Generate a postal code based on locale"""
        if self.config.locale.startswith("en-US"):
            return f"{random.randint(10000, 99999)}"
        elif self.config.locale.startswith("en-GB"):
            return f"{random.choice(['AB', 'AL', 'B'])}{random.randint(1, 99)} {random.randint(0, 9)}{random.choice('ABCDEFGHIJKLMNOPQRSTUVWXYZ')}{random.choice('ABCDEFGHIJKLMNOPQRSTUVWXYZ')}"
        else:  # Generic format
            return f"{random.randint(1000, 9999)}{random.choice('ABCDEFGHIJKLMNOPQRSTUVWXYZ')}"

    # ----------------------------------------------------------------
    # Reference Resolution
    # ----------------------------------------------------------------
    def _resolve_ref(self, schema: Dict) -> Dict:
        """Resolve $ref references in the schema"""
        if "$ref" in schema:
            ref_path = schema["$ref"].split("/")[1:]
            current = self.openapi_spec
            try:
                for part in ref_path:
                    current = current.get(part, {})
                return current
            except (KeyError, TypeError):
                logger.error(f"Reference not found: {schema['$ref']}")
                return {}
        return schema

    # ----------------------------------------------------------------
    # Public API Methods
    # ----------------------------------------------------------------
    def build_dummy_body(self, schema: Dict) -> Any:
        """Generate a request body from JSON schema"""
        try:
            resolved_schema = self._resolve_ref(schema)
            return self.generate_value("root", resolved_schema)
        except Exception as e:
            logger.error(f"Error generating dummy body: {e}")
            if self.config.strict_mode:
                raise
            return {"error": str(e)}

    def fill_url_placeholders(self, base_url: str, path: str) -> str:
        """Replace path placeholders with generated values"""
        def replace(match):
            name = match.group(1) or match.group(2) or match.group(3)
            return str(self.generate_value(name))
        
        new_path = self.PLACEHOLDER_RX.sub(replace, path)
        return urljoin(base_url.rstrip("/") + "/", new_path.lstrip("/"))


  
    def build_request_from_operation(
        self,
        base_url: str,
        path: str,
        method: str,
        operation: Dict,
    ) -> Dict[str, Any]:
        """
        Build complete request dictionary for requests library
        Returns: {method, url, params, json, headers}
        """
        # Process parameters
        params: Dict[str, Any] = {}
        headers: Dict[str, str] = {}
        
        for p in operation.get("parameters", []):
            param_schema = p.get("schema", {})
            if p.get("in") == "query":
                params[p["name"]] = self.generate_value(p["name"], param_schema)
            elif p.get("in") == "header":
                headers[p["name"]] = str(self.generate_value(p["name"], param_schema))

        # Build URL
        full_url = self.fill_url_placeholders(base_url, path)

        # Process request body
        body = None
        content_type = "application/json"
        
        if "requestBody" in operation:
            content = operation["requestBody"].get("content", {})
            if content:
                # Get first available content type
                content_type, media_type = next(iter(content.items()))
                schema = media_type.get("schema", {})
                body = self.build_dummy_body(schema)
                
                # Special handling for form data
                if content_type == "application/x-www-form-urlencoded":
                    body = {k: str(v) for k, v in body.items()}
                elif content_type == "multipart/form-data":
                    # Convert to multipart format
                    body = {k: (None, str(v)) for k, v in body.items()}

        # Set content type header if not already specified
        if body and "Content-Type" not in headers:
            headers["Content-Type"] = content_type

        return {
            "method": method.upper(),
            "url": full_url,
            "params": params,
            "json": body if content_type == "application/json" else None,
            "data": body if content_type != "application/json" else None,
            "headers": headers,
        }

# ----------------------------------------------------------------------
# Module-level Interface (Backwards Compatibility)
# ----------------------------------------------------------------------
_DEFAULT_CONFIG = DummyGeneratorConfig()
_DEFAULT_BUILDER = OpenAPIRequestBuilder(config=_DEFAULT_CONFIG)


def enable_dummy_mode(flag: bool = True):
        _DEFAULT_CONFIG.strict_mode = False
        _DEFAULT_CONFIG.enable_caching = True
        if flag:
            print("[DEBUG] Dummy mode enabled in swagger_utils")


@lru_cache(maxsize=128)
def _cached_rand_value(field_name: str, schema: Optional[Dict] = None) -> Any:
    return _DEFAULT_BUILDER.generate_value(field_name, schema or {})

def build_dummy_body(schema: Dict) -> Any:
    return _DEFAULT_BUILDER.build_dummy_body(schema)

def fill_url_placeholders(base_url: str, path: str) -> str:
    return _DEFAULT_BUILDER.fill_url_placeholders(base_url, path)

def build_request_from_operation(
    base_url: str,
    path: str,
    method: str,
    operation: Dict,
) -> Dict[str, Any]:
    return _DEFAULT_BUILDER.build_request_from_operation(
        base_url, path, method, operation
    )

def get_builder() -> OpenAPIRequestBuilder:
    return _DEFAULT_BUILDER

def _merge_allOf(schema: Dict) -> Dict:
    if "allOf" not in schema:
        return schema
    merged: Dict[str, Any] = {}
    for sub in schema["allOf"]:
        res = _DEFAULT_BUILDER._resolve_ref(sub) or {}
        # deep merge properties
        if "properties" in res:
            merged.setdefault("properties", {}).update(res["properties"])
        if "required" in res:
            merged["required"] = sorted(set(merged.get("required", [])) | set(res["required"]))
        for k in ("type","format","items","enum","nullable"):
            if k in res and k not in merged:
                merged[k] = res[k]
    return merged

def _first_of(schema: Dict) -> Dict:
    for k in ("oneOf","anyOf"):
        if k in schema and schema[k]:
            return _DEFAULT_BUILDER._resolve_ref(schema[k][0]) or {}
    return schema

def _collect_body_fields(schema: Dict, prefix: str = "") -> Dict[str, Any]:
    """Flatten requestBody schema into 'dot.notation' keys -> None."""
    schema = _DEFAULT_BUILDER._resolve_ref(schema) or {}
    schema = _merge_allOf(schema)
    schema = _first_of(schema)

    t = schema.get("type")
    out: Dict[str, Any] = {}

    # Primitive or enum -> leaf
    if t in ("string","integer","number","boolean","null") or "enum" in schema or not t:
        key = prefix.rstrip(".") if prefix else "value"
        out[key] = None
        return out

    if t == "object":
        props = schema.get("properties", {}) or {}
        if not props:
            out[prefix.rstrip(".") or "object"] = {}
            return out
        for name, sub in props.items():
            out.update(_collect_body_fields(sub, f"{prefix}{name}."))
        return out

    if t == "array":
        items = schema.get("items", {}) or {}
        # Represent first element as [0]
        return _collect_body_fields(items, f"{prefix}[0].")

    # Unknown -> generic
    out[prefix.rstrip(".") or "value"] = None
    return out

def extract_variables(openapi_spec: Dict) -> Dict[str, Any]:
    """
    Build a fill-in template of variables per path/method.
    Includes: path params, query/header/cookie params, requestBody fields,
    server variables and security scheme placeholders.
    """
    spec = openapi_spec or {}
    out: Dict[str, Any] = {
        "_meta": {
            "generated_by": "apiscan/swagger_utils",
            "note": "Fill in values. Null means 'set me'. Arrays use [0] for first item.",
        },
        "_servers": [],
        "_security": {}
    }

    # Servers (OpenAPI 3)
    servers = spec.get("servers", []) or []
    for srv in servers:
        url = srv.get("url", "")
        vars_ = {k: {"default": v.get("default"), "value": None}
                 for k, v in (srv.get("variables") or {}).items()}
        out["_servers"].append({"url": url, "variables": vars_})

    # Security schemes (names only -> placeholder)
    comps = spec.get("components", {}) or {}
    secdefs = comps.get("securitySchemes", {}) or {}
    for name, sch in secdefs.items():
        typ = sch.get("type")
        placeholder = None
        if typ == "http" and sch.get("scheme") == "bearer":
            placeholder = "Bearer <token>"
        elif typ == "apiKey":
            if sch.get("in") == "header":
                placeholder = f"{sch.get('name','X-API-Key')} value"
            elif sch.get("in") == "query":
                placeholder = f"{sch.get('name','api_key')} value"
        elif typ == "oauth2":
            placeholder = "<access_token>"
        else:
            placeholder = ""
        out["_security"][name] = {"type": typ, "value": placeholder}

    # Paths
    paths = spec.get("paths", {}) or {}
    for path, path_item in paths.items():
        path_level_params = path_item.get("parameters", []) if isinstance(path_item, dict) else []
        for method, op in (path_item or {}).items():
            if method not in HTTP_METHODS or not isinstance(op, dict):
                continue

            # merge op + path-level parameters
            params = []
            for p in (path_level_params + op.get("parameters", [])):
                if "$ref" in p:
                    p = _DEFAULT_BUILDER._resolve_ref(p) or {}
                params.append(p)

            # requestBody
            body_schema = None
            req = op.get("requestBody", {})
            if "$ref" in req:
                req = _DEFAULT_BUILDER._resolve_ref(req) or {}
            content = (req.get("content") or {})
            if content:
                # Prefer JSON if present
                if "application/json" in content:
                    body_schema = content["application/json"].get("schema")
                else:
                    # take the first content type otherwise
                    _, mt = next(iter(content.items()))
                    body_schema = (mt or {}).get("schema")

            # Build operation entry
            opkey = f"{method.upper()} {path}"
            op_out: Dict[str, Any] = {
                "path_params": {},
                "query_params": {},
                "headers": {},
                "cookies": {},
                "body": {},
                "_operationId": op.get("operationId"),
            }

            # Path placeholders from the path itself
            for match in re.findall(r"\{([^{}]+)\}", path):
                op_out["path_params"].setdefault(match, None)

            # Parameters by 'in'
            for p in params:
                loc = p.get("in")
                name = p.get("name")
                if not loc or not name:
                    continue
                # set to None (user will fill)
                if loc == "path":
                    op_out["path_params"][name] = None
                elif loc == "query":
                    op_out["query_params"][name] = None
                elif loc == "header":
                    op_out["headers"][name] = None
                elif loc == "cookie":
                    op_out["cookies"][name] = None

            # requestBody flatten
            if body_schema:
                op_out["body"] = _collect_body_fields(body_schema)

            out.setdefault("operations", {})[opkey] = op_out

    return out

def write_variables_file(variables: Dict[str, Any], out_path: str | Path) -> Path:
    """Write to YAML if extension is .yml/.yaml and PyYAML installed; else JSON."""
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    if out_path.suffix.lower() in (".yml", ".yaml") and _HAS_YAML:
        with open(out_path, "w", encoding="utf-8") as f:
            yaml.safe_dump(variables, f, sort_keys=False, allow_unicode=True)
    else:
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(variables, f, indent=2, ensure_ascii=False)
    print(f"[VARS] Template written to {out_path}")
    return out_path
