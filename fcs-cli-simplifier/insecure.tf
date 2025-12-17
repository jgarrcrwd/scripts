# main.tf

provider "google" {
  # Replace with your project details
  project = "fake-project"
  region  = "us-west1"
}

resource "google_storage_bucket" "insecure_bucket" {
  name          = "insecure-public-bucket-example"
  location      = "US"
  force_destroy = true
  
  # Makes the bucket publicly readable
  uniform_bucket_level_access = false
}

# This makes all objects in the bucket publicly readable
resource "google_storage_bucket_iam_binding" "public_read" {
  bucket = google_storage_bucket.insecure_bucket.name
  role   = "roles/storage.objectViewer"
  members = [
    "allUsers",  # This makes the bucket publicly accessible
  ]
}

# This allows public listing of objects
resource "google_storage_bucket_iam_binding" "public_list" {
  bucket = google_storage_bucket.insecure_bucket.name
  role   = "roles/storage.legacyBucketReader"
  members = [
    "allUsers",
  ]
}
