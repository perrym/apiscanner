########################################################
# APISCAN - API Security Scanner                       #
# Licensed under the AGPL-V3.0 License                       #
# Author: Perry Mertens pamsniffer@gmail.com (C) 2025  #
# version 2.2  2-11--2025                              #
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
                                                                            
        if u.startswith(("http://", "https://")):
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
    for src in (path_level or []) + (op_level or []):
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
            merged_params = _merge_parameters(path_params, op_params)
            if "requestBody" in raw:
                request_body = raw.get("requestBody")
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


#================funtion _body_from_schema produce example body from JSON schema ##########
def _body_from_schema(schema: Dict[str, Any]) -> Any:
    if not isinstance(schema, dict):
        return {}
    if "example" in schema:
        return schema["example"]
    t = schema.get("type")
    if t == "object" or ("properties" in schema and not t):
        out = {}
        props = schema.get("properties", {}) or {}
        reqd = set(schema.get("required", []) or [])
        for name, ps in props.items():
            pt = ps.get("type", "string")
            pf = ps.get("format", "")
            if "example" in ps:
                out[name] = ps["example"]
            elif "enum" in ps and isinstance(ps["enum"], list) and ps["enum"]:
                out[name] = ps["enum"][0]
            else:
                out[name] = _example_for_type(pt, pf)
        for name in reqd:
            out.setdefault(name, "test")
        return out
    if t == "array":
        item_schema = schema.get("items", {}) or {}
        return [_body_from_schema(item_schema)]
    return _example_for_type(t or "string", schema.get("format", ""))

                                                                             
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
            json_body = _body_from_schema(schema)
        elif "application/x-www-form-urlencoded" in content:
            schema = content["application/x-www-form-urlencoded"].get("schema") or {}
            form = _body_from_schema(schema)
            data_body = form if isinstance(form, dict) else {}
            headers.setdefault("Content-Type", "application/x-www-form-urlencoded")
        elif "multipart/form-data" in content:
            schema = content["multipart/form-data"].get("schema") or {}
            form = _body_from_schema(schema)
            data_body = form if isinstance(form, dict) else {}
                                                                                            
        else:
                                                                 
            ctype, media = next(iter(content.items()))
            schema = (media or {}).get("schema") or {}
            body = _body_from_schema(schema)
            if "json" in ctype or isinstance(body, (dict, list)):
                json_body = body
            else:
                data_body = body

                         
    else:
        body_param = next((p for p in params if (p.get("in") or "").lower() == "body"), None)
        if body_param:
            schema = (body_param.get("schema") or {})
            body = _body_from_schema(schema)
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

    return req


                                                                              
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
        text = open(path, "r", encoding="utf-8").read()
        try:
            spec = json.loads(text)
        except json.JSONDecodeError:
            try:
                import yaml 
                spec = yaml.safe_load(text)  
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
