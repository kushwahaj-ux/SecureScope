import requests
import random
import string

def establish_baseline(target_url):
    """
    Fires TWO random requests to build a more accurate baseline.
    """
    baselines = []
    
    for _ in range(2):
        random_path = "".join(
            random.choices(string.ascii_lowercase + string.digits, k=16)
        ) + ".html"
        fake_url = f"{target_url.rstrip('/')}/{random_path}"
        
        try:
            response = requests.get(
                fake_url, timeout=5, 
                allow_redirects=True,
                verify=False
            )
            baselines.append({
                "status_code": response.status_code,
                "content_length": len(response.content),
                "final_url": response.url,
                "content_sample": response.text[:200]
            })
        except requests.RequestException:
            continue
    
    if not baselines:
        return None
    
    # Average content length from both requests
    avg_length = sum(b["content_length"] for b in baselines) / len(baselines)
    
    return {
        "status_code": baselines[0]["status_code"],
        "content_length": avg_length,
        "final_url": baselines[0]["final_url"],
        "content_sample": baselines[0]["content_sample"]
    }

def is_false_positive(response, baseline):
    """
    Improved comparison with tolerance range and content matching.
    """
    if not baseline:
        return False

    # Condition 1 — Content length within 5% tolerance
    # Catches pages that are almost same size as 404
    tolerance = baseline["content_length"] * 0.05
    if abs(len(response.content) - baseline["content_length"]) <= tolerance:
        return True

    # Condition 2 — Same final URL after redirect
    if response.url == baseline["final_url"]:
        return True

    # Condition 3 — Response contains same content as baseline
    # Catches when site returns homepage for all missing files
    if baseline["content_sample"]:
        if baseline["content_sample"][:100] in response.text:
            return True

    # Condition 4 — Status code matches baseline 404 behavior
    # Some sites return 200 for everything
    if (response.status_code == baseline["status_code"] and
            baseline["status_code"] == 200 and
            len(response.content) < 1000):
        return True

    return False

def verify_finding(target_url, finding_url):
    """
    Complete verification pipeline for a single finding.
    Returns True if finding is REAL, False if false positive.
    """
    baseline = establish_baseline(target_url)
    
    try:
        response = requests.get(
            finding_url, timeout=5,
            allow_redirects=True,
            verify=False
        )
        
        if is_false_positive(response, baseline):
            return False  # False positive — skip it
        
        # Extra check — must have meaningful content
        if len(response.content) < 50:
            return False
            
        return True  # Real finding!
        
    except requests.RequestException:
        return False