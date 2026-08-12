"""
SentinelGraph — Object Storage Client

MinIO/S3-compatible storage for evidence files, screenshots, and reports.
"""

import io
from datetime import timedelta
from typing import BinaryIO

import structlog
from minio import Minio
from minio.error import S3Error

from app.config import get_settings

logger = structlog.get_logger(__name__)
settings = get_settings()

# ── MinIO Client ─────────────────────────────────────────────
_minio_client: Minio | None = None


def get_storage_client() -> Minio:
    """Get or create MinIO client singleton."""
    global _minio_client
    if _minio_client is None:
        _minio_client = Minio(
            settings.minio_endpoint,
            access_key=settings.minio_root_user,
            secret_key=settings.minio_root_password,
            secure=settings.minio_use_ssl,
        )
    return _minio_client


async def init_storage() -> None:
    """Initialize storage: create bucket if not exists."""
    client = get_storage_client()
    bucket = settings.minio_bucket

    try:
        if not client.bucket_exists(bucket):
            client.make_bucket(bucket)
            logger.info("storage.bucket_created", bucket=bucket)
        else:
            logger.info("storage.bucket_exists", bucket=bucket)
    except S3Error as e:
        logger.error("storage.init_failed", error=str(e))
        raise


class StorageService:
    """High-level storage operations for evidence and reports."""

    def __init__(self):
        self.client = get_storage_client()
        self.bucket = settings.minio_bucket

    def upload_file(
        self,
        object_name: str,
        data: BinaryIO | bytes,
        content_type: str = "application/octet-stream",
        metadata: dict[str, str] | None = None,
    ) -> str:
        """Upload a file to object storage.

        Args:
            object_name: Path within bucket (e.g., "scans/uuid/screenshots/page.png")
            data: File data as bytes or file-like object
            content_type: MIME type
            metadata: Optional metadata tags

        Returns:
            The object name (key) for retrieval
        """
        if isinstance(data, bytes):
            data_stream = io.BytesIO(data)
            length = len(data)
        else:
            data.seek(0, 2)
            length = data.tell()
            data.seek(0)
            data_stream = data

        self.client.put_object(
            self.bucket,
            object_name,
            data_stream,
            length=length,
            content_type=content_type,
            metadata=metadata,
        )

        logger.info("storage.uploaded", object=object_name, size=length)
        return object_name

    def download_file(self, object_name: str) -> bytes:
        """Download a file from object storage."""
        try:
            response = self.client.get_object(self.bucket, object_name)
            data = response.read()
            response.close()
            response.release_conn()
            return data
        except S3Error as e:
            logger.error("storage.download_failed", object=object_name, error=str(e))
            raise

    def get_presigned_url(
        self,
        object_name: str,
        expires: timedelta = timedelta(hours=1),
    ) -> str:
        """Generate a presigned URL for temporary access."""
        return self.client.presigned_get_object(
            self.bucket,
            object_name,
            expires=expires,
        )

    def delete_file(self, object_name: str) -> None:
        """Delete a file from object storage."""
        self.client.remove_object(self.bucket, object_name)
        logger.info("storage.deleted", object=object_name)

    def list_objects(self, prefix: str) -> list[str]:
        """List objects under a prefix."""
        objects = self.client.list_objects(self.bucket, prefix=prefix, recursive=True)
        return [obj.object_name for obj in objects]
