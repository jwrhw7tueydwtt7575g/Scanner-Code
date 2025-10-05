Overview
========

Welcome to Astronomer! This project was generated after you ran 'astro dev init' using the Astronomer CLI. This readme describes the contents of the project, as well as how to run Apache Airflow on your local machine.

Project Contents
================

Your Astro project contains the following files and folders:

- dags: This folder contains the Python files for your Airflow DAGs. By default, this directory includes one example DAG:
    - `example_astronauts`: This DAG shows a simple ETL pipeline example that queries the list of astronauts currently in space from the Open Notify API and prints a statement for each astronaut. The DAG uses the TaskFlow API to define tasks in Python, and dynamic task mapping to dynamically print a statement for each astronaut. For more on how this DAG works, see our [Getting started tutorial](https://www.astronomer.io/docs/learn/get-started-with-airflow).
- Dockerfile: This file contains a versioned Astro Runtime Docker image that provides a differentiated Airflow experience. If you want to execute other commands or overrides at runtime, specify them here.
- include: This folder contains any additional files that you want to include as part of your project. It is empty by default.
- packages.txt: Install OS-level packages needed for your project by adding them to this file. It is empty by default.
- requirements.txt: Install Python packages needed for your project by adding them to this file. It is empty by default.
- plugins: Add custom or community plugins for your project to this file. It is empty by default.
- airflow_settings.yaml: Use this local-only file to specify Airflow Connections, Variables, and Pools instead of entering them in the Airflow UI as you develop DAGs in this project.

Deploy Your Project Locally
===========================

Start Airflow on your local machine by running 'astro dev start'.

This command will spin up five Docker containers on your machine, each for a different Airflow component:

- Postgres: Airflow's Metadata Database
- Scheduler: The Airflow component responsible for monitoring and triggering tasks
- DAG Processor: The Airflow component responsible for parsing DAGs
- API Server: The Airflow component responsible for serving the Airflow UI and API
- Triggerer: The Airflow component responsible for triggering deferred tasks

When all five containers are ready the command will open the browser to the Airflow UI at http://localhost:8080/. You should also be able to access your Postgres Database at 'localhost:5432/postgres' with username 'postgres' and password 'postgres'.

Note: If you already have either of the above ports allocated, you can either [stop your existing Docker containers or change the port](https://www.astronomer.io/docs/astro/cli/troubleshoot-locally#ports-are-not-available-for-my-local-airflow-webserver).

Deploy Your Project to Astronomer
=================================

If you have an Astronomer account, pushing code to a Deployment on Astronomer is simple. For deploying instructions, refer to Astronomer documentation: https://www.astronomer.io/docs/astro/deploy-code/

Contact
=======

The Astronomer CLI is maintained with love by the Astronomer team. To report a bug or suggest a change, reach out to our support.

Using AWS S3 with Airflow (local Docker image)
-------------------------------------------

If you want Airflow in this project to read/write from S3, the included `Dockerfile` installs the AWS provider and `boto3`.

Build the image:

```powershell
docker build -t edi-airflow:latest .
```

Run Airflow (example using docker run for a quick test):

```powershell
# Run scheduler + webserver in one container for quick testing (not for production)
docker run --rm -p 8080:8080 \
    -e AIRFLOW__CORE__FERNET_KEY=$(python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())") \
    -e AIRFLOW__CORE__EXECUTOR=SequentialExecutor \
    -e AWS_ACCESS_KEY_ID=your_access_key \
    -e AWS_SECRET_ACCESS_KEY=your_secret_key \
    edi-airflow:latest webserver
```

Recommended ways to provide AWS credentials to Airflow

- Environment variables (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_DEFAULT_REGION) — useful for local dev.
- Use an Airflow Connection of type 'S3' or 'aws' via the UI or `airflow connections` CLI. For example:

```powershell
airflow connections add 'aws_default' \
    --conn-type 'aws' \
    --conn-extra '{"region_name": "us-east-1"}' \
    --conn-login 'YOUR_KEY' \
    --conn-password 'YOUR_SECRET'
```

- When running in AWS (ECS/EKS/EC2), prefer IAM Roles for Service Accounts or Instance Profiles instead of static keys.

Quick test DAG

Create a DAG that uses S3Hook to list buckets or upload/download an object to verify connectivity. Example snippet:

```python
from airflow import DAG
from airflow.providers.amazon.aws.hooks.s3 import S3Hook
from airflow.operators.python import PythonOperator
from datetime import datetime

def list_buckets():
        hook = S3Hook(aws_conn_id='aws_default')
        print(hook.get_bucket_names())

with DAG('test_s3', start_date=datetime(2023,1,1), schedule_interval=None, catchup=False) as dag:
        t1 = PythonOperator(task_id='list_buckets', python_callable=list_buckets)

```

Place the DAG under `dags/` and trigger it from the UI to confirm S3 access.

If you want, I can add a ready-made test DAG file to `dags/` and a small script to verify S3 connectivity automatically.
