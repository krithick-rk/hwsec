import sys
import os
import json
import importlib

BENCH_ROOT = "/mnt/e/Intern/hwsec/hwsec_artificial_benchmark"

def run_probe(case_id, is_solution=False):
    # Determine base directory
    base_dir = os.path.join(BENCH_ROOT, "solutions" if is_solution else "benchmark_targets")
    
    # Locate folder for case_id
    target_folder = None
    for diff in ["easy", "medium", "hard"]:
        d = os.path.join(base_dir, diff)
        if os.path.isdir(d):
            for sub in os.listdir(d):
                if sub.startswith(case_id):
                    target_folder = os.path.join(d, sub)
                    break
        if target_folder:
            break
            
    if not target_folder:
        return {"error": f"Folder for {case_id} not found"}

    # Add folder to sys.path and import app
    sys.path.insert(0, target_folder)
    
    # Clean up cached modules that might conflict across cases
    for mod in list(sys.modules.keys()):
        if mod in ['app', 'config', 'database'] or mod.startswith('services') or mod.startswith('repositories') or mod.startswith('adapters') or mod.startswith('utils') or mod.startswith('query'):
            del sys.modules[mod]

    try:
        app_mod = importlib.import_module("app")
        app = getattr(app_mod, "app")
        app.config["TESTING"] = True
    except Exception as e:
        sys.path.pop(0)
        return {"error": f"Failed to load app: {str(e)}"}

    result = {}
    
    with app.test_client() as client:
        if case_id == "CASE-E01":
            marker = "/tmp/hwsec_e01_marker"
            if os.path.exists(marker): os.remove(marker)
            # Witness
            resp = client.post("/api/diagnostic/ping", json={"host": f"127.0.0.1; touch {marker}"})
            witness_triggered = os.path.exists(marker)
            if os.path.exists(marker): os.remove(marker)
            # Negative Control
            resp_ctrl = client.post("/api/diagnostic/ping", json={"host": "127.0.0.1"})
            ctrl_passed = not os.path.exists(marker) and resp_ctrl.status_code == 200
            result = {
                "witness_triggered": witness_triggered,
                "witness_status": resp.status_code,
                "control_passed": ctrl_passed,
                "control_status": resp_ctrl.status_code
            }

        elif case_id == "CASE-E02":
            # Witness
            resp = client.get("/api/users/search?username=' OR '1'='1")
            data = resp.get_json() or {}
            witness_triggered = resp.status_code == 200 and data.get("count", 0) > 1
            # Negative Control
            resp_ctrl = client.get("/api/users/search?username=alice")
            data_ctrl = resp_ctrl.get_json() or {}
            ctrl_passed = resp_ctrl.status_code == 200 and data_ctrl.get("count") == 1
            result = {
                "witness_triggered": witness_triggered,
                "witness_count": data.get("count", 0),
                "control_passed": ctrl_passed,
                "control_count": data_ctrl.get("count", 0)
            }

        elif case_id == "CASE-E03":
            # Witness
            resp = client.get("/api/files/download?filename=../../../../etc/hostname")
            data = resp.get_json() or {}
            witness_triggered = resp.status_code == 200 and len(data.get("content", "")) > 0
            # Negative Control
            resp_ctrl = client.get("/api/files/download?filename=hello.txt")
            data_ctrl = resp_ctrl.get_json() or {}
            ctrl_passed = resp_ctrl.status_code == 200 and "Hello World" in data_ctrl.get("content", "")
            result = {
                "witness_triggered": witness_triggered,
                "witness_status": resp.status_code,
                "control_passed": ctrl_passed,
                "control_status": resp_ctrl.status_code
            }

        elif case_id == "CASE-M01":
            # Witness
            payload = "<img src=x onerror=alert(1)>"
            resp = client.get(f"/search?q={payload}")
            raw = resp.data.decode("utf-8")
            witness_triggered = resp.status_code == 200 and payload in raw
            # Negative Control
            resp_ctrl = client.get("/search?q=coffee")
            raw_ctrl = resp_ctrl.data.decode("utf-8")
            ctrl_passed = resp_ctrl.status_code == 200 and "<img" not in raw_ctrl and "Coffee Mug" in raw_ctrl
            result = {
                "witness_triggered": witness_triggered,
                "witness_status": resp.status_code,
                "control_passed": ctrl_passed,
                "control_status": resp_ctrl.status_code
            }

        elif case_id == "CASE-M02":
            # Witness
            resp = client.get("/api/users/search?pattern=' UNION SELECT id, username, email, role, department FROM users-- ")
            data = resp.get_json() or {}
            witness_triggered = resp.status_code == 200 and data.get("count", 0) > 1
            # Negative Control
            resp_ctrl = client.get("/api/users/search?pattern=admin")
            data_ctrl = resp_ctrl.get_json() or {}
            ctrl_passed = resp_ctrl.status_code == 200 and data_ctrl.get("count") == 1
            result = {
                "witness_triggered": witness_triggered,
                "witness_count": data.get("count", 0),
                "control_passed": ctrl_passed,
                "control_count": data_ctrl.get("count", 0)
            }

        elif case_id == "CASE-M03":
            marker = "/tmp/hwsec_m03_marker"
            if os.path.exists(marker): os.remove(marker)
            # Witness
            resp = client.post("/api/diagnostic/run", json={"target": f"127.0.0.1; touch {marker}", "tool": "ping"})
            witness_triggered = os.path.exists(marker)
            if os.path.exists(marker): os.remove(marker)
            # Negative Control (traceroute uses argument list)
            resp_ctrl = client.post("/api/diagnostic/run", json={"target": f"127.0.0.1; touch {marker}", "tool": "traceroute"})
            ctrl_passed = not os.path.exists(marker)
            result = {
                "witness_triggered": witness_triggered,
                "witness_status": resp.status_code,
                "control_passed": ctrl_passed,
                "control_status": resp_ctrl.status_code
            }

        elif case_id == "CASE-H01":
            # Initialize storage
            fs_svc = getattr(app_mod, "file_service", None)
            if fs_svc: fs_svc.init_storage()
            # Witness
            resp = client.get("/api/files/download?filename=../../../../etc/hostname")
            data = resp.get_json() or {}
            witness_triggered = resp.status_code == 200 and len(data.get("content", "")) > 0
            # Negative Control (preview path has safe validation)
            resp_ctrl = client.get("/api/files/preview?filename=../../../../etc/hostname")
            ctrl_passed = resp_ctrl.status_code == 403
            result = {
                "witness_triggered": witness_triggered,
                "witness_status": resp.status_code,
                "control_passed": ctrl_passed,
                "control_status": resp_ctrl.status_code
            }

        elif case_id == "CASE-H02":
            # Witness (Auth bypass with injection)
            resp = client.post("/api/auth/login", json={"username": "admin)(|(userPassword=*", "password": "anything"})
            data = resp.get_json() or {}
            witness_triggered = resp.status_code == 200 and data.get("status") == "success"
            # Negative Control (wrong password)
            resp_ctrl = client.post("/api/auth/login", json={"username": "admin", "password": "wrongpassword"})
            ctrl_passed = resp_ctrl.status_code == 401
            result = {
                "witness_triggered": witness_triggered,
                "witness_status": resp.status_code,
                "control_passed": ctrl_passed,
                "control_status": resp_ctrl.status_code
            }

        elif case_id == "CASE-H03":
            # Witness (XPath boolean bypass)
            resp = client.get("/api/user/search?username=' or '1'='1")
            data = resp.get_json() or {}
            witness_triggered = resp.status_code == 200 and data.get("found") is True and "name" in data.get("user", {})
            # Negative Control (nonexistent user)
            resp_ctrl = client.get("/api/user/search?username=nonexistent_user_xyz")
            data_ctrl = resp_ctrl.get_json() or {}
            ctrl_passed = resp_ctrl.status_code == 200 and data_ctrl.get("found") is False
            result = {
                "witness_triggered": witness_triggered,
                "witness_status": resp.status_code,
                "control_passed": ctrl_passed,
                "control_status": resp_ctrl.status_code
            }

    sys.path.pop(0)
    return result

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(json.dumps({"error": "Usage: probe_runner.py <CASE_ID> [--solution]"}))
        sys.exit(1)
    cid = sys.argv[1]
    is_sol = "--solution" in sys.argv
    res = run_probe(cid, is_sol)
    print(json.dumps(res))
