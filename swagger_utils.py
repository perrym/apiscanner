########################################################
# APISCAN - API Security Scanner                       #
# Licensed under AGPL-V3.0                             #
# Author: Perry Mertens pamsniffer@gmail.com (C) 2025  #
# version 2.2  2-11--2025                             #
########################################################                                            
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
    import yaml                                             
    _HAS_YAML = True
except Exception:
    _HAS_YAML = False
HTTP_METHODS = {"get","put","post","delete","patch","head","options","trace"}
                   
logger = logging.getLogger("swagger_utils")
logger.addHandler(logging.NullHandler())
            
                                                                        
class DummyGeneratorConfig:
                                                  
    __slots__ = (
        'max_array_length', 
        'strict_mode',
        'locale',
        'industry',
        'enable_caching',
        'default_string_length'
    )
    
    # ----------------------- Funtion __init__ ----------------------------#
    def __init__(self):
        self.max_array_length: int = 10
        self.strict_mode: bool = False
        self.locale: str = "en-US"
        self.industry: Optional[str] = None  
        self.enable_caching: bool = True
        self.default_string_length: int = 12
                 
                                                                        
class OpenAPIRequestBuilder:
                                                                  
    VALID_TYPES = {"string", "integer", "number", "boolean", "object", "array", "null"}
    PLACEHOLDER_RX = re.compile(r"\{([\w\-+]+)\}|:([\w\-+]+)|<([\w\-+]+)>")

    
    MEDICAL_TERMS = ["cardiology", "orthopedics", "neurology", "pediatrics", "oncology"]
    FINANCE_TERMS = ["IBAN", "SWIFT", "BIC", "ACH", "SEPA"]
    ECOMMERCE_TERMS = ["SKU", "GTIN", "UPC", "EAN", "ASIN"]
    
    # ----------------------- Funtion __init__ ----------------------------#
    def __init__(self, openapi_spec: Optional[Dict] = None, config: Optional[DummyGeneratorConfig] = None):
        self.openapi_spec = openapi_spec or {}
        self.config = config or DummyGeneratorConfig()
        self.value_cache: Dict[str, Any] = {}
        
                                            
        self.industry_generators = {
            "finance": self._generate_finance_value,
            "healthcare": self._generate_medical_value,
            "ecommerce": self._generate_ecommerce_value
        }

    # ----------------------- Funtion clear_cache ----------------------------#
    def clear_cache(self):
        self.value_cache.clear()

                                                                    
    # ----------------------- Funtion generate_value ----------------------------#
    def generate_value(self, field_name: str, schema: Optional[Dict] = None) -> Any:
        if not schema:
            schema = {}
        cache_key = self._create_cache_key(field_name, schema)
        if self.config.enable_caching and cache_key in self.value_cache:
            return self.value_cache[cache_key]
                                               
        if self.config.industry:
            industry_value = self.industry_generators.get(self.config.industry, lambda n, s: None)(field_name, schema)
            if industry_value is not None:
                if self.config.enable_caching:
                    self.value_cache[cache_key] = industry_value
                return industry_value
                                   
        combinator_value = self._handle_combinators(field_name, schema)
        if combinator_value is not None:
            if self.config.enable_caching:
                self.value_cache[cache_key] = combinator_value
            return combinator_value
                            
        if schema.get("nullable", False) and random.random() > 0.7:
            if self.config.enable_caching:
                self.value_cache[cache_key] = None
            return None
                                           
        value = self._type_based_value(field_name, schema)
        if self.config.enable_caching:
            self.value_cache[cache_key] = value
        print(f"[DUMMY] {field_name} -> {value}")
        return value
          
                                                                  
    # ----------------------- Funtion _create_cache_key ----------------------------#
    def _create_cache_key(self, field_name: str, schema: Dict) -> str:
        try:
            schema_key = hashlib.sha1(
                json.dumps(schema, sort_keys=True).encode("utf-8")
            ).hexdigest()
        except TypeError:
            schema_key = hashlib.sha1(str(schema).encode("utf-8")).hexdigest()
        return f"{field_name}-{schema_key}"

    # ----------------------- Funtion _handle_combinators ----------------------------#
    def _handle_combinators(self, field_name: str, schema: Dict) -> Any:
        for key in ("oneOf", "anyOf"):
            if key in schema and schema[key]:
                chosen = random.choice(schema[key])
                resolved = self._resolve_ref(chosen)
                return self.generate_value(field_name, resolved)
                                                                       
        if "allOf" in schema and schema["allOf"]:
            merged: Dict[str, Any] = {}

            for sub in schema["allOf"]:
                resolved = self._resolve_ref(sub) or {}
                                         
                if "properties" in resolved:
                    merged.setdefault("properties", {}).update(resolved["properties"])
                                     
                if "required" in resolved:
                    req = set(merged.get("required", [])) | set(resolved["required"])
                    merged["required"] = sorted(req)
                                                  
                for key in ("type", "format", "enum", "items", "nullable"):
                    if key in resolved and key not in merged:
                        merged[key] = resolved[key]
                                                                
            return self.generate_value(field_name, merged)
        return None

    # ----------------------- Funtion _type_based_value ----------------------------#
    def _type_based_value(self, field_name: str, schema: Dict) -> Any:
        schema_type = schema.get("type", "string")
        if schema_type not in self.VALID_TYPES:
            if self.config.strict_mode:
                raise ValueError(f"Invalid schema type: {schema_type}")
            logger.warning(f"Invalid schema type: {schema_type} for field {field_name}")
            return f"invalid_type_{schema_type}"
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
                                    
        return self._generate_string(field_name, schema)
    # ----------------------- Funtion _generate_integer ----------------------------#
    def _generate_integer(self, schema: Dict) -> int:
        minimum = schema.get("minimum", 0)
        maximum = schema.get("maximum", 10000)
        return random.randint(minimum, maximum)

    # ----------------------- Funtion _generate_number ----------------------------#
    def _generate_number(self, schema: Dict) -> float:
        minimum = schema.get("minimum", 0.0)
        maximum = schema.get("maximum", 10000.0)
        return round(random.uniform(minimum, maximum), 2)

    # ----------------------- Funtion _generate_string ----------------------------#
    def _generate_string(self, field_name: str, schema: Dict) -> str:
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
                                                
        return self._heuristic_based_value(field_name, schema)

    # ----------------------- Funtion _generate_object ----------------------------#
    def _generate_object(self, schema: Dict) -> Dict:
        properties = schema.get("properties", {})
        required = schema.get("required", [])
        obj = {}
        for prop, prop_schema in properties.items():
            if prop in required or random.random() < 0.7:
                obj[prop] = self.generate_value(prop, prop_schema)
        return obj

    # ----------------------- Funtion _generate_array ----------------------------#
    def _generate_array(self, schema: Dict) -> List:
        item_schema = schema.get("items", {})
        min_items = schema.get("minItems", 1)
        max_items = schema.get("maxItems", self.config.max_array_length)
        max_items = max(min_items, max_items, 1)
        max_items = min(max_items, self.config.max_array_length)
        if "minItems" in schema and "maxItems" in schema and min_items == max_items:
            count = min_items
        else:
            count = random.randint(min_items, max_items)
        return [self.generate_value("array_item", item_schema) for _ in range(count)]
    # ----------------------- Funtion _heuristic_based_value ----------------------------#
    def _heuristic_based_value(self, field_name: str, schema: Dict) -> Any:
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
                                   
        max_len = schema.get("maxLength", self.config.default_string_length)
        return self._random_string(min(max_len, 50))

    # ----------------------- Funtion _generate_finance_value ----------------------------#
    def _generate_finance_value(self, field_name: str, schema: Dict) -> Optional[Any]:
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

    # ----------------------- Funtion _generate_medical_value ----------------------------#
    def _generate_medical_value(self, field_name: str, schema: Dict) -> Optional[Any]:
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

    # ----------------------- Funtion _generate_ecommerce_value ----------------------------#
    def _generate_ecommerce_value(self, field_name: str, schema: Dict) -> Optional[Any]:
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
                                                                      
    # ----------------------- Funtion _random_string ----------------------------#
    def _random_string(self, length: int = 8) -> str:
        alphabet = string.ascii_lowercase + string.digits
        return "".join(random.choices(alphabet, k=length))
            
    # ----------------------- Funtion _generate_phone_number ----------------------------#
    def _generate_phone_number(self) -> str:
        formats = [
            "+## ## ########",
            "+## ### ######",
            "+## (###) ###-####",
            "###-###-####"
        ]
        fmt = random.choice(formats)
        return "".join([str(random.randint(0, 9)) if c == "#" else c for c in fmt])
        
    # ----------------------- Funtion _generate_postal_code ----------------------------#
    def _generate_postal_code(self) -> str:
        if self.config.locale.startswith("en-US"):
            return f"{random.randint(10000, 99999)}"
        elif self.config.locale.startswith("en-GB"):
            return f"{random.choice(['AB', 'AL', 'B'])}{random.randint(1, 99)} {random.randint(0, 9)}{random.choice('ABCDEFGHIJKLMNOPQRSTUVWXYZ')}{random.choice('ABCDEFGHIJKLMNOPQRSTUVWXYZ')}"
        else:                  
            return f"{random.randint(1000, 9999)}{random.choice('ABCDEFGHIJKLMNOPQRSTUVWXYZ')}"

    # ----------------------- Funtion _resolve_ref ----------------------------#
    def _resolve_ref(self, schema: Dict) -> Dict:
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

    # ----------------------- Funtion build_dummy_body ----------------------------#
    def build_dummy_body(self, schema: Dict) -> Any:
        try:
            resolved_schema = self._resolve_ref(schema)
            return self.generate_value("root", resolved_schema)
        except Exception as e:
            logger.error(f"Error generating dummy body: {e}")
            if self.config.strict_mode:
                raise
            return {"error": str(e)}

    # ----------------------- Funtion fill_url_placeholders ----------------------------#
    def fill_url_placeholders(self, base_url: str, path: str) -> str:
        def replace(match):
            name = match.group(1) or match.group(2) or match.group(3)
            return str(self.generate_value(name))
        
        new_path = self.PLACEHOLDER_RX.sub(replace, path)
        return urljoin(base_url.rstrip("/") + "/", new_path.lstrip("/"))

    # ----------------------- Funtion build_request_from_operation ----------------------------#
    def build_request_from_operation(
        self,
        base_url: str,
        path: str,
        method: str,
        operation: Dict,
    ) -> Dict[str, Any]:
        params: Dict[str, Any] = {}
        headers: Dict[str, str] = {}
        
        for p in operation.get("parameters", []):
            param_schema = p.get("schema", {})
            if p.get("in") == "query":
                params[p["name"]] = self.generate_value(p["name"], param_schema)
            elif p.get("in") == "header":
                headers[p["name"]] = str(self.generate_value(p["name"], param_schema))
        full_url = self.fill_url_placeholders(base_url, path)
        body = None
        content_type = "application/json"
        
        if "requestBody" in operation:
            content = operation["requestBody"].get("content", {})
            if content:
                                                  
                content_type, media_type = next(iter(content.items()))
                schema = media_type.get("schema", {})
                body = self.build_dummy_body(schema)
                                                
                if content_type == "application/x-www-form-urlencoded":
                    body = {k: str(v) for k, v in body.items()}
                elif content_type == "multipart/form-data":
                                                 
                    body = {k: (None, str(v)) for k, v in body.items()}
                                                          
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



# ----------------------- Funtion enable_dummy_mode ----------------------------#
_DEFAULT_CONFIG = DummyGeneratorConfig()
_DEFAULT_BUILDER = OpenAPIRequestBuilder(config=_DEFAULT_CONFIG)

def enable_dummy_mode(flag: bool = True):
        _DEFAULT_CONFIG.strict_mode = False
        _DEFAULT_CONFIG.enable_caching = True
        if flag:
            print("[DEBUG] Dummy mode enabled in swagger_utils")

# ----------------------- Funtion _cached_rand_value ----------------------------#
@lru_cache(maxsize=128)
def _cached_rand_value(field_name: str, schema: Optional[Dict] = None) -> Any:
    return _DEFAULT_BUILDER.generate_value(field_name, schema or {})

# ----------------------- Funtion build_dummy_body ----------------------------#
def build_dummy_body(schema: Dict) -> Any:
    return _DEFAULT_BUILDER.build_dummy_body(schema)

# ----------------------- Funtion fill_url_placeholders ----------------------------#
def fill_url_placeholders(base_url: str, path: str) -> str:
    return _DEFAULT_BUILDER.fill_url_placeholders(base_url, path)

# ----------------------- Funtion build_request_from_operation ----------------------------#
def build_request_from_operation(
    base_url: str,
    path: str,
    method: str,
    operation: Dict,
) -> Dict[str, Any]:
    return _DEFAULT_BUILDER.build_request_from_operation(
        base_url, path, method, operation
    )

# ----------------------- Funtion get_builder ----------------------------#
def get_builder() -> OpenAPIRequestBuilder:
    return _DEFAULT_BUILDER

# ----------------------- Funtion _merge_allOf ----------------------------#
def _merge_allOf(schema: Dict) -> Dict:
    if "allOf" not in schema:
        return schema
    merged: Dict[str, Any] = {}
    for sub in schema["allOf"]:
        res = _DEFAULT_BUILDER._resolve_ref(sub) or {}
                               
        if "properties" in res:
            merged.setdefault("properties", {}).update(res["properties"])
        if "required" in res:
            merged["required"] = sorted(set(merged.get("required", [])) | set(res["required"]))
        for k in ("type","format","items","enum","nullable"):
            if k in res and k not in merged:
                merged[k] = res[k]
    return merged

# ----------------------- Funtion _first_of ----------------------------#
def _first_of(schema: Dict) -> Dict:
    for k in ("oneOf","anyOf"):
        if k in schema and schema[k]:
            return _DEFAULT_BUILDER._resolve_ref(schema[k][0]) or {}
    return schema

# ----------------------- Funtion _collect_body_fields ----------------------------#
def _collect_body_fields(schema: Dict, prefix: str = "") -> Dict[str, Any]:
    schema = _DEFAULT_BUILDER._resolve_ref(schema) or {}
    schema = _merge_allOf(schema)
    schema = _first_of(schema)

    t = schema.get("type")
    out: Dict[str, Any] = {}
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
                                        
        return _collect_body_fields(items, f"{prefix}[0].")
                        
    out[prefix.rstrip(".") or "value"] = None
    return out

# ----------------------- Funtion extract_variables ----------------------------#
def extract_variables(openapi_spec: Dict) -> Dict[str, Any]:
    spec = openapi_spec or {}
    out: Dict[str, Any] = {
        "_meta": {
            "generated_by": "apiscan/swagger_utils",
            "note": "Fill in values. Null means 'set me'. Arrays use [0] for first item.",
        },
        "_servers": [],
        "_security": {}
    }
                         
    servers = spec.get("servers", []) or []
    for srv in servers:
        url = srv.get("url", "")
        vars_ = {k: {"default": v.get("default"), "value": None}
                 for k, v in (srv.get("variables") or {}).items()}
        out["_servers"].append({"url": url, "variables": vars_})
                                                  
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

    paths = spec.get("paths", {}) or {}
    for path, path_item in paths.items():
        path_level_params = path_item.get("parameters", []) if isinstance(path_item, dict) else []
        for method, op in (path_item or {}).items():
            if method not in HTTP_METHODS or not isinstance(op, dict):
                continue
                                              
            params = []
            for p in (path_level_params + op.get("parameters", [])):
                if "$ref" in p:
                    p = _DEFAULT_BUILDER._resolve_ref(p) or {}
                params.append(p)
                         
            body_schema = None
            req = op.get("requestBody", {})
            if "$ref" in req:
                req = _DEFAULT_BUILDER._resolve_ref(req) or {}
            content = (req.get("content") or {})
            if content:
                                        
                if "application/json" in content:
                    body_schema = content["application/json"].get("schema")
                else:
                                                           
                    _, mt = next(iter(content.items()))
                    body_schema = (mt or {}).get("schema")
                                   
            opkey = f"{method.upper()} {path}"
            op_out: Dict[str, Any] = {
                "path_params": {},
                "query_params": {},
                "headers": {},
                "cookies": {},
                "body": {},
                "_operationId": op.get("operationId"),
            }

            for match in re.findall(r"\{([^{}]+)\}", path):
                op_out["path_params"].setdefault(match, None)
                                
            for p in params:
                loc = p.get("in")
                name = p.get("name")
                if not loc or not name:
                    continue
                                              
                if loc == "path":
                    op_out["path_params"][name] = None
                elif loc == "query":
                    op_out["query_params"][name] = None
                elif loc == "header":
                    op_out["headers"][name] = None
                elif loc == "cookie":
                    op_out["cookies"][name] = None

                                 
            if body_schema:
                op_out["body"] = _collect_body_fields(body_schema)

            out.setdefault("operations", {})[opkey] = op_out

    return out

# ----------------------- Funtion write_variables_file ----------------------------#
def write_variables_file(variables: Dict[str, Any], out_path: str | Path) -> Path:
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
