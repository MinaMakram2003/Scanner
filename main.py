from typing import Optional
import asyncio
import json
import time
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from fastapi import Path
import httpx
from fastapi import Query
from datetime import datetime

ZAP_BASE_URL = "http://127.0.0.1:8082" # PUT ZAP PORT 
ZAP_API_KEY = "5gijk0op5s07un7gtopc41f35a" # DON'T FORGET PUT YOUR-API-KEY 

timeout = httpx.Timeout(20 * 60.0)
zap_client = httpx.AsyncClient(base_url=ZAP_BASE_URL, timeout=timeout)

app = FastAPI(title="TESTING Exploring API", version="1.0.0")

class TargetRequest(BaseModel):
    target: str

async def _zap_get(path: str, params: dict = None):
    params = params or {}
    params["apikey"] = ZAP_API_KEY
    try:
        r = await zap_client.get(path, params=params)
        r.raise_for_status()
        return r.text
    except httpx.RequestError as e:
        raise HTTPException(status_code=502, detail=f"Request error while calling ZAP: {e}")
    except httpx.HTTPStatusError as e:
        raise HTTPException(status_code=502, detail=f"Bad response from ZAP: {e.response.status_code} - {e.response.text}")

async def _zap_post(path: str, params: dict = None):
    params = params or {}
    params["apikey"] = ZAP_API_KEY
    try:
        r = await zap_client.post(path, data=params)
        r.raise_for_status()
        return r.text
    except httpx.RequestError as e:
        raise HTTPException(status_code=502, detail=f"Request error while calling ZAP: {e}")
    except httpx.HTTPStatusError as e:
        raise HTTPException(status_code=502, detail=f"Bad response from ZAP: {e.response.status_code} - {e.response.text}")

def _try_parse(text):
    try:
        return json.loads(text)
    except Exception:
        return text
    
def seconds_to_minutes(seconds: Optional[float]) -> Optional[int]:
    if seconds is None:
        return None
    return int(seconds // 60)


def format_date(ts: Optional[float]) -> Optional[str]:
    if not ts:
        return None
    return time.strftime("%d/%m/%Y", time.localtime(ts))


def format_datetime(ts: Optional[float]) -> Optional[str]:
    if not ts:
        return None
    return time.strftime("%d/%m/%Y %H:%M:%S", time.localtime(ts))

    
@app.get("/")
async def root():
    return {"message": "ZAP Exploring API is running"}

@app.post("/explore/spider")
async def run_spider(req: TargetRequest):
    target = req.target
    try:
        try:
            await _zap_get("/JSON/core/action/accessUrl/", params={"url": target, "followRedirects": "true"})
        except Exception:
            pass

        start_text = await _zap_get("/JSON/spider/action/scan/", params={"url": target})
        start_parsed = _try_parse(start_text)
        spider_id = start_parsed.get("scan") if isinstance(start_parsed, dict) else None
        if spider_id is None:
            raise HTTPException(status_code=500, detail="Spider ID not found in ZAP response.")

        while True:
            status_text = await _zap_get("/JSON/spider/view/status/", params={"scanId": spider_id})
            status_parsed = _try_parse(status_text)
            status_val = status_parsed.get("status") if isinstance(status_parsed, dict) else None
            if status_val is not None and (str(status_val) == "100" or str(status_val).endswith("100")):
                break
            await asyncio.sleep(2)

        results_text = await _zap_get("/JSON/spider/view/results/", params={"scanId": spider_id})
        results_parsed = _try_parse(results_text)
        urls = []
        if isinstance(results_parsed, dict):
            urls = results_parsed.get("results") or results_parsed.get("urls") or []
        elif isinstance(results_parsed, list):
            urls = results_parsed

        return {
            "status": "crawling completed",
            "scan_id": spider_id,
            "urls_count": len(urls),
            "urls": urls
        }
    except HTTPException:
        raise
    except Exception as ex:
        raise HTTPException(status_code=500, detail=f"Spider failed: {ex}")

@app.post("/explore/ajax")
async def run_ajax_spider(req: TargetRequest):
    target = req.target
    try:
        await _zap_post("/JSON/ajaxSpider/action/scan/", params={"url": target})

        while True:
            status_text = await _zap_get("/JSON/ajaxSpider/view/status/")
            status_parsed = _try_parse(status_text)
            status_val = status_parsed.get("status") if isinstance(status_parsed, dict) else None
            if status_val == "stopped":
                break
            await asyncio.sleep(2)

        results_text = await _zap_get("/JSON/ajaxSpider/view/results/")
        results_parsed = _try_parse(results_text)
        urls = []
        if isinstance(results_parsed, dict):
            urls = results_parsed.get("results") or results_parsed.get("urls") or []
        elif isinstance(results_parsed, list):
            urls = results_parsed

        return {
            "status": "Analysis completed",
            "urls_count": len(urls),
            "urls": urls
        }
    except HTTPException:
        raise
    except Exception as ex:
        raise HTTPException(status_code=500, detail=f"Ajax Spider failed: {ex}")

running_scans = {}  

SQLI_SCANNERS = [
    40018, 
    40019,  
    40020,  
    40021,  
    40022,  
    40027  
]

XSS_SCANNERS = [
    40012, 
    40014,  
    40016,  
    40017,  
    40026  
]

CMDI_SCANNERS = [
    90020, 
    90037,
    10048,  
    40045, 
    40048  
]

LFI_RFI_SCANNERS = [
    6,     
    7      
]

SERVER_SIDE_SCANNERS = [
    90019, 
    90035,  
    90036 
]

XXE_SCANNERS = [
    90023,  
    40044   
]

SSRF_SCANNERS = [
    90034   
]

LOGIC_SCANNERS = [
    20019, 
    40008   
]

INFO_DISCLOSURE_SCANNERS = [
    40028, 
    40029, 
    40032, 
    40034, 
    40035,  
    40042  
]

SUBSCAN_MAP = {
    "SQLI": SQLI_SCANNERS,
    "XSS": XSS_SCANNERS,
    "CMDI": CMDI_SCANNERS,
    "LFI_RFI": LFI_RFI_SCANNERS,
    "SERVER_SIDE": SERVER_SIDE_SCANNERS,
    "XXE": XXE_SCANNERS,
    "SSRF": SSRF_SCANNERS,
    "LOGIC": LOGIC_SCANNERS,
    "INFO": INFO_DISCLOSURE_SCANNERS
}


async def _background_monitor_scan(scan_id: int, baseUrl: str, poll_interval_s: int = 5):
    sid = str(scan_id)

    if sid not in running_scans:
        running_scans[sid] = {
            "baseUrl": baseUrl,
            "started_at": time.time(),
            "alerts": []
        }

    running_scans[sid]["status"] = "running"
    running_scans[sid]["last_poll"] = None

    try:
        while True:
            try:
                txt = await _zap_get(
                    "/JSON/ascan/view/status/",
                    params={"scanId": sid}
                )
                parsed = _try_parse(txt)
                status_val = parsed.get("status") if isinstance(parsed, dict) else parsed
            except Exception as e:
                running_scans[sid]["last_poll"] = {
                    "error": str(e),
                    "time": time.time()
                }
                await asyncio.sleep(poll_interval_s)
                continue

            running_scans[sid]["last_poll"] = {
                "status": status_val,
                "time": time.time()
            }

            if status_val is not None and (
                str(status_val) == "100" or str(status_val).endswith("100")
            ):
                break

            await asyncio.sleep(poll_interval_s)

        try:
            alerts_text = await _zap_get(
                "/JSON/alert/view/alerts/",
                params={"baseurl": baseUrl}
            )
            alerts_parsed = _try_parse(alerts_text)

            alerts = []
            if isinstance(alerts_parsed, dict) and "alerts" in alerts_parsed:
                alerts = alerts_parsed["alerts"]
            elif isinstance(alerts_parsed, list):
                alerts = alerts_parsed

            running_scans[sid]["alerts"] = alerts
            running_scans[sid]["status"] = "completed"
            running_scans[sid]["completed_at"] = time.time()

        except Exception as e:
            running_scans[sid]["status"] = "completed"
            running_scans[sid]["alerts_fetch_error"] = str(e)
            running_scans[sid]["completed_at"] = time.time()

    except Exception as e:
        running_scans[sid]["status"] = "failed"
        running_scans[sid]["error"] = str(e)
        running_scans[sid]["completed_at"] = time.time()

async def _run_subscan(target: str, scanners: list[int], scan_type: str):
    policy = f"{scan_type}_POLICY_{int(time.time())}"

    await _zap_get("/JSON/ascan/action/addScanPolicy/", {
        "scanPolicyName": policy
    })

    await _zap_get("/JSON/ascan/action/disableAllScanners/", {
        "scanPolicyName": policy
    })

    ids_str = ",".join(str(pid) for pid in scanners)

    await _zap_get("/JSON/ascan/action/enableScanners/", {
        "scanPolicyName": policy,
        "ids": ids_str
    })

    start = _try_parse(await _zap_get("/JSON/ascan/action/scan/", {
        "url": target,
        "scanPolicyName": policy
    }))

    scan_id = start.get("scan")
    sid = str(scan_id)

    running_scans.setdefault(sid, {})
    running_scans[sid].update({
        "baseUrl": target,
        "status": "running",
        "scan_type": scan_type,
        "started_at": time.time()
    })

    asyncio.create_task(_background_monitor_scan(scan_id, target))
    return {"scan_id": scan_id, "scan_type": scan_type}


@app.post("/explore/active")
async def run_active_scan(req: TargetRequest):
    target = req.target
    try:
        try:
            await _zap_get("/JSON/core/action/accessUrl/", params={"url": target, "followRedirects": "true"})
        except Exception:
            pass

        start_text = await _zap_get("/JSON/ascan/action/scan/", params={"url": target})
        start_parsed = _try_parse(start_text)
        scan_id_raw = start_parsed.get("scan") if isinstance(start_parsed, dict) else start_parsed
        if scan_id_raw is None:
            raise HTTPException(status_code=500, detail="Scan ID not found in ZAP response.")
        try:
            scan_id = int(scan_id_raw)
        except Exception:
            scan_id = scan_id_raw

        sid = str(scan_id)
        running_scans[sid] = {
            "baseUrl": target,
            "status": "starting",
            "started_at": time.time(),
            "last_poll": None,
            "alerts": []
        }

        asyncio.create_task(_background_monitor_scan(scan_id, target, poll_interval_s=5))

        return {"scan_id": scan_id, "message": "scan started"}
    except HTTPException:
        raise
    except Exception as ex:
        raise HTTPException(status_code=500, detail=f"Failed to start active scan: {ex}")
    
@app.post("/scan/sqli", summary="SQL Injection Scan")
async def scan_sqli(req: TargetRequest):
    return await _run_subscan(req.target, SQLI_SCANNERS, "SQLI")


@app.post("/scan/xss", summary="Cross Site Scripting Scan")
async def scan_xss(req: TargetRequest):
    return await _run_subscan(req.target, XSS_SCANNERS, "XSS")


@app.post("/scan/cmdi", summary="Command Injection / RCE Scan")
async def scan_cmdi(req: TargetRequest):
    return await _run_subscan(req.target, CMDI_SCANNERS, "CMDI")


@app.post("/scan/lfi-rfi", summary="LFI / RFI Scan")
async def scan_lfi_rfi(req: TargetRequest):
    return await _run_subscan(req.target, LFI_RFI_SCANNERS, "LFI_RFI")


@app.post("/scan/server-side", summary="Server Side Injection Scan")
async def scan_server_side(req: TargetRequest):
    return await _run_subscan(req.target, SERVER_SIDE_SCANNERS, "SERVER_SIDE")


@app.post("/scan/xxe", summary="XXE / XML Injection Scan")
async def scan_xxe(req: TargetRequest):
    return await _run_subscan(req.target, XXE_SCANNERS, "XXE")


@app.post("/scan/ssrf", summary="SSRF / Cloud Metadata Scan")
async def scan_ssrf(req: TargetRequest):
    return await _run_subscan(req.target, SSRF_SCANNERS, "SSRF")


@app.post("/scan/logic", summary="Logic / Redirect / Parameter Tampering Scan")
async def scan_logic(req: TargetRequest):
    return await _run_subscan(req.target, LOGIC_SCANNERS, "LOGIC")


@app.post("/scan/info", summary="Information Disclosure Scan")
async def scan_info(req: TargetRequest):
    return await _run_subscan(req.target, INFO_DISCLOSURE_SCANNERS, "INFO")

@app.get("/ascan/{scan_id}/status")
async def ascan_status(scan_id: int = Path(..., description="ZAP scan id")):
    sid = str(scan_id)
    rec = running_scans.get(sid)

    if not rec:
        raise HTTPException(status_code=404, detail="Scan ID not found")

    now = time.time()
    started_at = rec.get("started_at")
    completed_at = rec.get("completed_at")

    end_time = completed_at if completed_at else now
    elapsed_seconds = int(end_time - started_at) if started_at else 0

    progress_percent = None
    if rec.get("last_poll") and rec["last_poll"].get("status") is not None:
        try:
            progress_percent = int(rec["last_poll"]["status"])
        except:
            progress_percent = None

    estimated_remaining_seconds = None
    if progress_percent and progress_percent > 0 and progress_percent < 100:
        estimated_total_seconds = elapsed_seconds * (100 / progress_percent)
        estimated_remaining_seconds = int(estimated_total_seconds - elapsed_seconds)

    return {
        "scan_id": scan_id,
        "scan_type": rec.get("scan_type", "FULL"),
        "status": rec.get("status"),

        "started_at": format_datetime(started_at),
        "started_date": format_date(started_at),
        "completed_at": format_datetime(completed_at),

        "elapsed_seconds": elapsed_seconds,
        "elapsed_minutes": seconds_to_minutes(elapsed_seconds),

        "progress_percent": progress_percent,

        "estimated_remaining_seconds": estimated_remaining_seconds,
        "estimated_remaining_minutes": seconds_to_minutes(estimated_remaining_seconds),

        "baseUrl": rec.get("baseUrl")
    }

@app.get("/ascan/{scan_id}/results")
async def ascan_results(scan_id: int = Path(...), baseUrl: Optional[str] = Query(None)):
    sid = str(scan_id)
    rec = running_scans.get(sid)

    burl = baseUrl or (rec.get("baseUrl") if rec else None)
    if not burl:
        raise HTTPException(status_code=400, detail="baseUrl required when scan not known to server")

    try:
        alerts_text = await _zap_get("/JSON/alert/view/alerts/", params={"baseurl": burl})
        alerts_parsed = _try_parse(alerts_text)
        alerts = []
        if isinstance(alerts_parsed, dict) and "alerts" in alerts_parsed:
            alerts = alerts_parsed["alerts"]
        elif isinstance(alerts_parsed, list):
            alerts = alerts_parsed

        summary_text = await _zap_get("/JSON/alert/view/alertsSummary/", params={"baseurl": burl})
        summary_parsed = _try_parse(summary_text)
        summary_obj = summary_parsed.get("alertsSummary") if isinstance(summary_parsed, dict) else summary_parsed

        summary_total = None
        if isinstance(summary_obj, dict):
            summary_total = 0
            for v in summary_obj.values():
                try:
                    summary_total += int(v)
                except:
                    pass

        if rec is not None:
            rec["alerts"] = alerts
            rec["summary"] = summary_obj

        final_status = "Active scan completed" if rec and rec.get("status") == "completed" else "partial results"

        return {
            "status": final_status,
            "scan_id": scan_id,
            "baseUrl": burl,
            "alerts_count": len(alerts),
            "summary_total": summary_total,
            "summary": summary_obj,
            "alerts": alerts
        }
        
    except HTTPException:
        raise
    except Exception as ex:
        raise HTTPException(status_code=500, detail=f"Failed to fetch results: {ex}")

@app.get("/subscan/results/{scan_id}")
async def results_auto(scan_id: int, baseUrl: Optional[str] = Query(None)):
    sid = str(scan_id)
    rec = running_scans.get(sid)

    if not rec:
        raise HTTPException(status_code=404, detail="Scan ID not found")

    burl = baseUrl or rec.get("baseUrl")
    if not burl:
        raise HTTPException(status_code=400, detail="baseUrl required")

    alerts_text = await _zap_get("/JSON/alert/view/alerts/", {"baseurl": burl})
    parsed = _try_parse(alerts_text)
    alerts = parsed.get("alerts", []) if isinstance(parsed, dict) else []

    if "scan_type" in rec:
        plugin_ids = SUBSCAN_MAP.get(rec["scan_type"], [])

        filtered = [
            a for a in alerts
            if int(a.get("pluginId", -1)) in plugin_ids
        ]

        if len(filtered) == 0:
            return {
                "mode": "sub-scan",
                "scan_id": scan_id,
                "scan_type": rec["scan_type"],
                "alerts_count": 0,
                "message": f"No {rec['scan_type']} vulnerabilities found.",
                "alerts": []
            }

        return {
            "mode": "sub-scan",
            "scan_id": scan_id,
            "scan_type": rec["scan_type"],
            "alerts_count": len(filtered),
            "alerts": filtered
        }

@app.post("/ascan/{scan_id}/stop")
async def ascan_stop(scan_id: int = Path(..., description="ZAP scan id")):
    sid = str(scan_id)
    rec = running_scans.get(sid)

    try:
        await _zap_post("/JSON/ascan/action/stop/", params={"scanId": sid})

        if rec:
            rec["status"] = "stopping"
            rec["last_action"] = {"action": "stop_called", "time": time.time()}

        for _ in range(6):  
            try:
                txt = await _zap_get("/JSON/ascan/view/status/", params={"scanId": sid})
                parsed = _try_parse(txt)
                status_val = parsed.get("status") if isinstance(parsed, dict) else parsed
            except Exception:
                status_val = None

            if status_val is not None and (str(status_val) == "100" or str(status_val).endswith("100")):
                if rec:
                    rec["status"] = "completed"
                    rec["completed_at"] = time.time()
                return {"scan_id": scan_id, "stopped": True, "status": "completed", "message": "scan stopped "}

            await asyncio.sleep(5)

        if rec:
            rec["status"] = "stopped_requested"
            rec["last_action"]["stop_request_time"] = time.time()

        return {"scan_id": scan_id, "stopped": True, "status": "stop_requested", "message": "stop requested; scan may take a bit to finish on ZAP side"}

    except HTTPException:
        raise
    except Exception as ex:
        if rec:
            rec["status"] = "stop_failed"
            rec["error"] = str(ex)
        raise HTTPException(status_code=500, detail=f"Failed to stop scan: {ex}")

from contextlib import asynccontextmanager
@asynccontextmanager
async def lifespan(app: FastAPI):
    try:
        await zap_client.aclose()
    except Exception:
        pass
    
    
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)
