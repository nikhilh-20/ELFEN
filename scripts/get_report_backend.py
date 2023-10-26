import os
import json
import argparse
import requests

URL = "http://127.0.0.1:8000/api/report/file"
API_TOKEN = ""


def get_report_backend(submission_uuid, backend):
    url = f"{URL}/{submission_uuid}/{backend}/"
    headers = {"Authorization": f"Bearer {API_TOKEN}"}

    r = requests.get(url, headers=headers)
    if r.ok:
        print(f"Report retrieved successfully for {backend} for {submission_uuid}.")
        return r.json()
    else:
        print(r.text)
        print(f"Failed to get report for {backend} for {submission_uuid}.")
        return None


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--uuid", "-u", type=str, required=True,
                        help="Submission UUID of task")
    parser.add_argument("--backend", "-b", type=str, required=True,
                        help="Backend to retrieve report for",
                        choices=["elfheader", "elfprogheader", "elfsectionheader", "samplefeatures",
                                 "capa", "staticantianalysis", "staticantiantianalysis",
                                 "strings", "memstrings", "fileops", "procops", "netops", "userland",
                                 "droppedfiles", "c2config"])
    parser.add_argument("--output", "-o", type=str, required=True,
                        help="Output directory in which JSON reports will be stored")
    args = parser.parse_args()
    report = get_report_backend(args.uuid, args.backend)

    if report:
        with open(os.path.join(args.output, f"{args.uuid}-{args.backend}.json"), "w") as f:
            json.dump(report, f)
