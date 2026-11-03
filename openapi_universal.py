########################################################
# APISCAN - API Security Scanner                       #
# Licensed under the AGPL-v3.0                         #
# Author: Perry Mertens pamsniffer@gmail.com (C) 2026  #
# version 5.5 24-06-2026                               #
########################################################
                                                    
from __future__ import annotations
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Tuple, Set
from urllib.parse import urljoin, urlparse
from datetime import datetime
import requests
import re
import os
import json

__all__ = [
    "SecurityConfig",
    "iter_operations",
    "build_request",
    "apply_security",
    "load_spec",
]

                                                            
@dataclass
class SecurityConfig:
    api_key_header_name: Optional[str] = None
    api_key_value: Optional[str] = None
    api_key_query_name: Optional[str] = None
    bearer_token: Optional[str] = None

HTTP_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}


#================funtion _infer_base_url_from_spec infer base URL from OpenAPI/Swagger servers/host ##########
def _infer_base_url_from_spec(spec: Dict[str, Any]) -> str:
    servers = (spec or {}).get("servers") or []
    for s in servers:
        u = (s or {}).get("url") or ""
        if not u:
            continue
                                                                            
        if u.lower().startswith(("http://", "https://")):
            return u.rstrip("/") + "/"
    host = (spec or {}).get("host", "")
    base_path = (spec or {}).get("basePath", "/") or "/"
    schemes = (spec or {}).get("schemes") or ["http"]
    if host:
        return f"{schemes[0]}://{host}{base_path.rstrip('/')}/"
    return ""


#================funtion _coerce_list coerce value to list ##########
def _coerce_list(x: Any) -> List[Any]:
    if x is None:
        return []
    if isinstance(x, list):
        return x
    return [x]


#================funtion _iter_path_items iterate path items from spec ##########
def _iter_path_items(spec: Dict[str, Any]) -> Iterable[Tuple[str, Dict[str, Any]]]:
    paths = spec.get("paths") or {}
    for p, item in paths.items():
        if not isinstance(item, dict):
            continue
        yield p, item


#================funtion _merge_parameters merge path-level and op-level parameters ##########
def _merge_parameters(path_level: List[Dict[str, Any]], op_level: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    merged: List[Dict[str, Any]] = []
    seen = set()
    for src in (op_level or []) + (path_level or []):
        name = src.get("name")
        loc = src.get("in")
        key = (name, loc)
        if key in seen:
            continue
        seen.add(key)
        merged.append(src)
    return merged


#================funtion _swagger2_request_body_from_params convert Swagger 2 params to requestBody ##########
def _swagger2_request_body_from_params(params: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    if not params:
        return None
    body_params = [p for p in params if p.get("in") == "body"]
    form_params = [p for p in params if p.get("in") == "formData"]
    if body_params:
        schema = body_params[0].get("schema") or {}
        return {"content": {"application/json": {"schema": schema}}}
    if form_params:
        has_file = any((p.get("type") == "file") for p in form_params)
        mime = "multipart/form-data" if has_file else "application/x-www-form-urlencoded"
        props = {}
        required = []
        for p in form_params:
            nm = p.get("name", "")
            tp = p.get("type", "string")
            props[nm] = {"type": tp}
            if p.get("required"):
                required.append(nm)
        schema = {"type": "object", "properties": props}
        if required:
            schema["required"] = required
        return {"content": {mime: {"schema": schema}}}
    return None

                                                                
                                                                               
#================funtion iter_operations yield normalized operations from spec ##########
def iter_operations(spec: Dict[str, Any]) -> Iterable[Dict[str, Any]]:
    for path, item in _iter_path_items(spec or {}):
        path_params = _coerce_list(item.get("parameters"))
        for verb, op in item.items():
            m = verb.upper()
            if m not in HTTP_METHODS:
                continue
            raw = op if isinstance(op, dict) else {}
            op_params = _coerce_list(raw.get("parameters"))
            merged_params = _merge_parameters([_resolve_ref(spec, p['$ref']) if '$ref' in p else p for p in path_params], [_resolve_ref(spec, p['$ref']) if '$ref' in p else p for p in op_params])
            if "requestBody" in raw:
                request_body = raw.get("requestBody")
                if isinstance(request_body, dict) and "$ref" in request_body:
                    request_body = _resolve_ref(spec, request_body["$ref"])
            else:
                request_body = _swagger2_request_body_from_params(merged_params)
            yield {
                "method": m,
                "path": path,
                "tags": _coerce_list(raw.get("tags")),
                "operationId": raw.get("operationId", ""),
                "summary": raw.get("summary", ""),
                "description": raw.get("description", ""),
                "parameters": merged_params,
                "requestBody": request_body,
                "security": raw.get("security", None),
                "raw": raw,
            }


#================funtion _example_for_type return example value by type/format ##########
def _example_for_type(t: str, fmt: str = "") -> Any:
    t = (t or "string").lower()
    if t == "string":
        if fmt == "date-time":
            return datetime.now().isoformat()
        if fmt in ("uri", "url", "uri-reference"):
            return "https://example.invalid/resource"
        if fmt == "uuid":
            return "00000000-0000-4000-8000-000000000001"
        if fmt == "email":
            return "test@example.com"
        return "test"
    if t == "integer":
        return 1
    if t == "number":
        return 1.0
    if t == "boolean":
        return True
    if t == "array":
        return []
    if t == "object":
        return {}
    return "test"


#================funtion _resolve_ref resolve a $ref pointer within the spec ##########
def _resolve_ref(spec, ref):
    seen = set()
    while isinstance(ref, str) and ref.startswith('#/') and ref not in seen and len(seen) < 16:
        seen.add(ref)
        node = spec
        for part in ref[2:].split('/'):
            node = node.get(part.replace('~1', '/').replace('~0', '~')) if isinstance(node, dict) else None
        if not isinstance(node, dict): return {}
        if '$ref' not in node: return node
        ref = node['$ref']
    return {}


def _body_from_schema(schema, spec=None, _depth=0):
    from copy import deepcopy
    if not isinstance(schema, dict) or _depth >= 8: return {}
    if '$ref' in schema:
        schema = dict(_resolve_ref(spec or {}, schema['$ref']), **{k:v for k,v in schema.items() if k != '$ref'})
    for key in ('example', 'default'):
        if key in schema: return deepcopy(schema[key])
    if schema.get('enum'): return deepcopy(schema['enum'][0])
    if schema.get('allOf'):
        out = {}
        for item in schema['allOf']:
            value = _body_from_schema(item, spec, _depth+1)
            if isinstance(value, dict): out.update(value)
        return out
    for key in ('oneOf', 'anyOf'):
        if schema.get(key): return _body_from_schema(schema[key][0], spec, _depth+1)
    t = schema.get('type')
    if t == 'object' or 'properties' in schema:
        return {name:_body_from_schema(prop, spec, _depth+1)
                for name,prop in (schema.get('properties') or {}).items() if not prop.get('readOnly')}
    if t == 'array': return [_body_from_schema(schema.get('items', {}), spec, _depth+1)]
    if t in ('integer', 'number'):
        return max(schema.get('minimum', 1), 1) if t == 'integer' else max(schema.get('minimum', 1.0), 1.0)
    return _example_for_type(t or 'string', schema.get('format', ''))

#================funtion build_request construct HTTP request dict from operation ##########
def build_request(spec: dict, base_url: str | None, op: dict, cfg: "SecurityConfig | None" = None) -> dict:
    base = (base_url or _infer_base_url_from_spec(spec) or "").strip().rstrip("/")
    if not base or base in ("", "/", "//"):
        raise ValueError("base_url is required (CLI --url or spec.servers/host).")
    base = base + "/"

                                  
    method = (op.get("method") or "GET").upper()
    path_tmpl = op.get("path") or "/"
    params = _coerce_list(op.get("parameters"))

    headers: dict[str, str] = {}
    query: dict[str, str] = {}
    cookies: dict[str, str] = {}

             
    #================funtion _pick_example function ##########
    def _pick_example(p: dict) -> object:
        schema = (p.get("schema") or {})
        if not schema and p.get("type"):
            schema = {"type": p["type"]}
        if "example" in p and p["example"] is not None:
            val = p["example"]
        elif "example" in schema and schema["example"] is not None:
            val = schema["example"]
        elif "default" in schema and schema["default"] is not None:
            val = schema["default"]
        elif p.get("required"):
            val = _example_for_type(schema.get("type", "string"), schema.get("format", ""))
        else:
            val = None
        return val

                                               
    path_render = path_tmpl
    for p in params:
        loc = (p.get("in") or "").lower()
        name = p.get("name")
        if not name or loc not in {"path", "query", "header", "cookie"}:
            continue

        val = _pick_example(p)
        if loc == 'path' and name in getattr(spec, 'path_parameter_values', {}):
            val = spec.path_parameter_values[name]
        if loc == 'path' and name not in getattr(spec, 'path_parameter_values', {}) and 'example' not in p and not any(k in (p.get('schema') or p) for k in ('example','default','enum')) and (p.get('schema') or p).get('type','string') == 'string' and (p.get('schema') or p).get('format') != 'uuid':
            raise ValueError('Unresolved path parameter: '+name+'; supply --ids-file')
        if loc == 'path' and val is not None:
            from urllib.parse import quote
            val = quote(str(val), safe='')

                                                  
        if isinstance(val, bool):
            sval = "true" if val else "false"
        elif isinstance(val, (int, float)):
            sval = str(val)
        elif isinstance(val, (list, tuple, set)):
                                                            
            sval = ",".join(map(str, val))
        elif val is None:
            sval = None
        else:
            sval = str(val)

        if loc == "path":
                                           
            if sval is None:
                t = (p.get("schema") or {}).get("type", "string")
                sval = str(_example_for_type(t, ""))
                                        
            path_render = re.sub(r"\{" + re.escape(name) + r"\}", str(sval), path_render)
        elif loc == "query" and sval is not None:
            query[name] = sval
        elif loc == "header" and sval is not None:
            if name.lower() != "authorization":                                                         
                headers[name] = sval
        elif loc == "cookie" and sval is not None:
            cookies[name] = sval

                                               
    json_body = None
    data_body = None
    files = None

                      
    req_body = op.get("requestBody") or {}
    content = req_body.get("content") if isinstance(req_body, dict) else None
    if isinstance(content, dict) and content:
                                                           
        if "application/json" in content:
            schema = content["application/json"].get("schema") or {}
            json_body = content["application/json"].get("example", _body_from_schema(schema, spec))
        elif "application/x-www-form-urlencoded" in content:
            schema = content["application/x-www-form-urlencoded"].get("schema") or {}
            form = _body_from_schema(schema, spec)
            data_body = form if isinstance(form, dict) else {}
            headers.setdefault("Content-Type", "application/x-www-form-urlencoded")
        elif "multipart/form-data" in content:
            schema = content["multipart/form-data"].get("schema") or {}
            form = _body_from_schema(schema, spec)
            data_body = form if isinstance(form, dict) else {}
                                                                                            
        else:
                                                                 
            ctype, media = next(iter(content.items()))
            schema = (media or {}).get("schema") or {}
            body = _body_from_schema(schema, spec)
            if "json" in ctype or isinstance(body, (dict, list)):
                json_body = body
            else:
                data_body = body

                         
    else:
        body_param = next((p for p in params if (p.get("in") or "").lower() == "body"), None)
        if body_param:
            schema = (body_param.get("schema") or {})
            body = _body_from_schema(schema, spec)
            json_body = body if isinstance(body, (dict, list)) else None
            data_body = None if json_body is not None else body

                            
    url = urljoin(base, path_render.lstrip("/"))
    req: dict = {"method": method, "url": url}
    if headers:
        req["headers"] = headers
    if query:
        req["params"] = query
    if cookies:
        req["cookies"] = cookies
    if json_body is not None:
        req["json"] = json_body
    elif data_body is not None:
        req["data"] = data_body
    if files:
        req["files"] = files
                                                        
    if cfg is not None:
        try:
            req = apply_security(req, cfg)
        except Exception:
            pass

    from copy import deepcopy
    op = deepcopy(op)
    for media in (op.get('requestBody') or {}).get('content', {}).values():
        if isinstance(media, dict) and '$ref' in (media.get('schema') or {}):
            media['schema'] = _resolve_ref(spec, media['schema']['$ref'])
    from api10_support import prepare_sql_request
    return prepare_sql_request(req, op, getattr(spec, 'request_data', {}), 'fixture')


                                                                              
#================funtion apply_security apply security config to request ##########
def apply_security(req: Dict[str, Any], cfg: SecurityConfig) -> Dict[str, Any]:
    out = dict(req)
    out.setdefault("headers", {})
    out.setdefault("params", {})

    if cfg.api_key_header_name and cfg.api_key_value:
        if cfg.api_key_header_name.lower() != "authorization":
            out["headers"].setdefault(cfg.api_key_header_name, cfg.api_key_value)

    if cfg.api_key_query_name and cfg.api_key_value:
        out["params"].setdefault(cfg.api_key_query_name, cfg.api_key_value)

    if cfg.bearer_token:
        if "Authorization" not in out["headers"]:
            out["headers"]["Authorization"] = f"Bearer {cfg.bearer_token}"

    return out


                                                                         
#================funtion load_spec load JSON/YAML spec and inject base URL ##########
def load_spec(source, inject_base_url: str | None = None) -> dict:
    import os, json
    from copy import deepcopy
    try:
        from urllib.parse import urlparse
    except ImportError:
        from urlparse import urlparse  
    if isinstance(source, dict):
        spec = deepcopy(source)
    else:
        path = str(source)
        ext = os.path.splitext(path)[1].lower()
        # Try orjson first (3-5x faster), fall back to stdlib json
        try:
            import orjson
            _json_loads = lambda data: orjson.loads(data)
            _json_load = lambda f: orjson.loads(f.read())
        except ImportError:
            _json_loads = json.loads
            _json_load = json.load
        if ext in (".yaml", ".yml"):
            try:
                import yaml
                with open(path, "r", encoding="utf-8") as f:
                    spec = yaml.safe_load(f)
            except Exception as e:
                raise ValueError(f"Spec parse failed (YAML): {e}") from e
        else:
            # JSON path (also handles .json and unknown extensions)
            try:
                with open(path, "rb") as f:
                    spec = _json_load(f)
            except (json.JSONDecodeError, ValueError):
                if ext == ".json":
                    raise ValueError(f"Spec parse failed: invalid JSON in {path}")
                # Unknown extension — try YAML fallback
                try:
                    import yaml
                    with open(path, "r", encoding="utf-8") as f:
                        spec = yaml.safe_load(f)
                except Exception as e:
                    raise ValueError(f"Spec parse failed (not JSON/YAML): {e}") from e
        if not isinstance(spec, dict):
            raise ValueError("Spec content must be a JSON/YAML object.")

    
    if inject_base_url:
        inj = str(inject_base_url).strip()
        if "://" not in inj:
            inj = "http://" + inj
        inj = inj.rstrip("/") + "/"
    else:
        inj = None

                               
    if "openapi" in spec:
        servers = spec.get("servers") or []
        has_abs = any(
            isinstance(s, dict) and str(s.get("url", "")).startswith(("http://", "https://"))
            for s in servers
        )
                                           
        if inj and not has_abs:
            spec["servers"] = [{"url": inj}]
        return spec

                                     
    if "swagger" in spec:
        if inj:
            p = urlparse(inj)
            if p.netloc and not spec.get("host"):
                spec["host"] = p.netloc
            if (p.scheme and not spec.get("schemes")):
                spec["schemes"] = [p.scheme]
            if not spec.get("basePath"):
                                                          
                base_path = p.path or "/"
                if not base_path.startswith("/"):
                    base_path = "/" + base_path
                spec["basePath"] = base_path
        return spec

    
    return spec
