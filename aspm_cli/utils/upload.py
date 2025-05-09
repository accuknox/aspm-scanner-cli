import requests
import urllib3
import os
from aspm_cli.utils.spinner import Spinner
from colorama import Fore
from aspm_cli.utils.logger import Logger
from requests.exceptions import HTTPError

# Suppress SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def upload_results(result_file, endpoint, tenant_id, label, token, data_type):

    spinner = Spinner(message=f"Uploading the result to AccuKnox...",  color=Fore.GREEN)
    spinner.start()

    """Upload the result JSON to the specified endpoint."""
    Logger.get_logger().debug("Uploading results...")
    try:
        with open(result_file, 'rb') as file:
            response = requests.post(
                f"https://{endpoint}/api/v1/artifact/",
                headers={
                    "Tenant-Id": tenant_id,
                    "Authorization": f"Bearer {token}"
                },
                params={
                    "tenant_id": tenant_id,
                    "data_type": data_type,
                    "label_id": label,
                    "save_to_s3": "true"
                },
                files={"file": file},
                verify=False  # Bypass SSL verification
            )
        response.raise_for_status()
        Logger.get_logger().info(f"Upload successful. Response: {response.status_code}")
    except HTTPError as http_err:
        Logger.get_logger().error(f"Status code: {response.status_code}, Response: {response.text}")
    except requests.exceptions.RequestException as req_err:
        Logger.get_logger().error(f"403 Request exception occurred: {req_err}")
    except Exception as err:
        Logger.get_logger().error(f"Unexpected error occurred: {err}")
    finally:
        spinner.stop()