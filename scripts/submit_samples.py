import os
import json
import time
import argparse
import requests

URL = "http://127.0.0.1:8000/api/submit/file"
API_TOKEN = ""


def _write_submissions_info(opath, submissions):
    # Read submissions.json first
    submissions_ = {}
    if os.path.isfile(opath):
        with open(opath, "r") as f:
            submissions_ = json.load(f)

    # Update submissions.json
    submissions_.update(submissions)

    # Write submissions.json
    with open(opath, "w") as f:
        json.dump(submissions_, f, indent=4)


def submit_samples(fpath, opath):
    submissions = {}

    with open(fpath, "r") as f:
        sample_paths = [ff.strip() for ff in f.readlines()]

    data = {"execution_time": 60, "userland_tracing": True}
    headers = {"Authorization": f"Bearer {API_TOKEN}"}

    for f in sample_paths:
        r = requests.post(URL, files={"file": open(f, "rb")}, data=data, headers=headers)
        if r.ok:
            print(f"Submitted {f} successfully.")
            submissions[f] = r.json()["submission_uuid"]
        else:
            print(f"Failed to submit {f}: {r.text}.")
            submissions[f] = None

        _write_submissions_info(opath, submissions)
        time.sleep(60)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--file", "-f", type=str, required=True,
                        help="Newline-separated full paths to samples")
    parser.add_argument("--output", "-o", type=str, required=True,
                        help="Path to JSON file which will contain submissions info")
    args = parser.parse_args()
    submit_samples(args.file, args.output)
