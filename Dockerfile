# Base image: Lightweight Python image
FROM python:3.11-bookworm

ARG TARGETOS TARGETARCH

# Create a working directory for the app
WORKDIR /app

# Copy Pipfile and Pipfile.lock
COPY Pipfile Pipfile.lock /app/

# Install dependencies using pipenv
RUN pip install --upgrade pip wheel setuptools && \
    pip install --no-warn-script-location pipenv && \
    pipenv install --system --deploy --ignore-pipfile --extra-pip-args=--ignore-installed && \
    rm -rf ~/.cache ~/.local

# Copy the entire application code
COPY . /app

# Expose port 9000 for Flask to listen on
EXPOSE 9000

ENV FLASK_APP=uma_vasp.server
ENV FLASK_RUN_PORT=9000

# Start the Flask app
CMD ["flask", "run", "--host", "0.0.0.0"]
