# ARG AIRFLOW_VERSION=2.7.1
# ARG PYTHON_VERSION=3.11

# # Base on the official Airflow image. Change AIRFLOW_VERSION / PYTHON_VERSION as needed.
# FROM apache/airflow:${AIRFLOW_VERSION}-python${PYTHON_VERSION}

# # Switch to root to install any system packages and python packages
# USER root

# RUN apt-get update \
# 	&& apt-get install -y --no-install-recommends \
# 		build-essential \
# 		git \
# 		curl \
# 	&& apt-get clean \
# 	&& rm -rf /var/lib/apt/lists/*
# # Switch to the airflow user before installing Python packages; the base image
# # enforces using the non-root `airflow` user for package installs.
# USER airflow

# # Install AWS provider, boto3 and awscli using the Airflow constraints that match
# # the Python major.minor version present in the base image. We avoid upgrading
# # setuptools/pip here to reduce the chance of breaking preinstalled packages.
# RUN PY_MINOR=$(python -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')") \
#  && echo "Using Python minor version for constraints: ${PY_MINOR}" \
#  && pip install --no-cache-dir \
# 	apache-airflow-providers-amazon \
# 	boto3 \
# 	awscli \
# 	--constraint "https://raw.githubusercontent.com/apache/airflow/constraints-${AIRFLOW_VERSION}/constraints-${PY_MINOR}.txt"

# # (Optional) Create folders for extras like plugins or logs if your setup needs them
# ENV AIRFLOW__CORE__LOAD_EXAMPLES=False

# # Default entrypoint and CMD are inherited from the official image.
# Airflow Dockerfile compatible with Amazon S3, using Astronomer runtime
FROM quay.io/astronomer/astro-runtime:7.3.0

RUN pip install apache-airflow-providers-amazon