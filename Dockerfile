# Use a base image with Python and a Debian-based OS for LibreOffice
# Python 3.9 slim is chosen for a smaller image size and compatibility with buster
FROM python:3.10-slim-buster

# Set the working directory inside the container
WORKDIR /app

# Update /etc/apt/sources.list to use Debian archive repositories
# This is necessary because buster (oldstable) repositories might have moved.
RUN echo "deb http://archive.debian.org/debian buster main contrib non-free" > /etc/apt/sources.list && \
    echo "deb http://archive.debian.org/debian-security buster/updates main contrib non-free" >> /etc/apt/sources.list && \
    echo "deb http://archive.debian.org/debian buster-updates main contrib non-free" >> /etc/apt/sources.list && \
    \
    # Install system dependencies for LibreOffice and necessary fonts.
    # apt-get update: Updates the list of available packages.
    # apt-get install -y --no-install-recommends: Installs packages without user confirmation
    #                                            and avoids installing recommended packages to keep image small.
    # libreoffice-writer: The core component for DOCX to PDF conversion.
    # fonts-dejavu-core: Provides basic fonts that LibreOffice might need for rendering.
    # rm -rf /var/lib/apt/lists/*: Cleans up apt caches to reduce image size.
    apt-get update && \
    apt-get install -y --no-install-recommends \
    libreoffice-writer \
    fonts-dejavu-core \
    && rm -rf /var/lib/apt/lists/*

# Copy the requirements file into the container
# This step is done separately to leverage Docker's layer caching.
# If only requirements.txt changes, this layer and subsequent layers are rebuilt.
COPY requirements.txt .

# Install Python dependencies from requirements.txt
# --no-cache-dir: Prevents pip from storing downloaded packages, reducing image size.
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of your application code into the container
# This includes main.py, database.py, templates/, static/, etc.
COPY . .

# Create the 'uploads' directory where converted files will be stored.
# This directory will be the mount point for the Docker volume.
RUN mkdir -p uploads

# Define a volume for the 'uploads' directory.
# This instructs Docker that the specified path is intended to be a mount point
# for an external volume, ensuring data persistence.
VOLUME /app/uploads

# Expose the port that FastAPI will run on (default for Uvicorn)
EXPOSE 8000

# Define the command to run the FastAPI application using Uvicorn.
# uvicorn main:app: Specifies that 'app' is the FastAPI instance in 'main.py'.
# --host 0.0.0.0: Makes the server accessible from outside the container.
# --port 8000: Specifies the port to listen on.
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
