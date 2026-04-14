"""Cloud asset discovery router — import VMs from AWS EC2 and Azure."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from netlanventory.api.dependencies import get_db
from netlanventory.core.config import get_settings
from netlanventory.core.logging import get_logger
from netlanventory.models.asset import Asset

try:
    import boto3
    _boto3_available = True
except ImportError:
    _boto3_available = False

try:
    from azure.identity import ClientSecretCredential
    from azure.mgmt.compute import ComputeManagementClient
    from azure.mgmt.network import NetworkManagementClient
    _azure_available = True
except ImportError:
    _azure_available = False

logger = get_logger(__name__)
router = APIRouter(prefix="/cloud", tags=["cloud"])

DbDep = Annotated[AsyncSession, Depends(get_db)]


class CloudImportResult(BaseModel):
    provider: str
    imported: int
    updated: int
    errors: list[str]


async def _upsert_asset(db: AsyncSession, ip: str | None, hostname: str | None, name: str | None,
                        os_name: str | None, source: str, tags: dict) -> tuple[bool, bool]:
    """Upsert an asset. Returns (imported, updated)."""
    existing = None
    if ip:
        result = await db.execute(select(Asset).where(Asset.ip == ip))
        existing = result.scalar_one_or_none()
    if not existing and hostname:
        result = await db.execute(select(Asset).where(Asset.hostname == hostname))
        existing = result.scalar_one_or_none()

    if existing:
        existing.hostname = existing.hostname or hostname
        existing.name = existing.name or name
        existing.os_name = existing.os_name or os_name
        await db.flush()
        return False, True
    else:
        asset = Asset(
            ip=ip,
            hostname=hostname,
            name=name,
            os_name=os_name,
            discovery_source=source,
            criticality="medium",
            is_active=True,
        )
        db.add(asset)
        await db.flush()
        return True, False


@router.post("/import/aws", response_model=CloudImportResult)
async def import_aws(db: DbDep) -> CloudImportResult:
    """Import EC2 instances from AWS as assets."""
    if not _boto3_available:
        raise HTTPException(status_code=501, detail="boto3 not installed. Run: pip install netlanventory[cloud]")

    settings = get_settings()
    imported = 0
    updated = 0
    errors: list[str] = []

    try:
        kwargs: dict = {"region_name": settings.aws_region or "eu-west-1"}
        if settings.aws_access_key_id and settings.aws_secret_access_key:
            kwargs["aws_access_key_id"] = settings.aws_access_key_id
            kwargs["aws_secret_access_key"] = settings.aws_secret_access_key

        ec2 = boto3.client("ec2", **kwargs)
        paginator = ec2.get_paginator("describe_instances")

        for page in paginator.paginate(Filters=[{"Name": "instance-state-name", "Values": ["running", "stopped"]}]):
            for reservation in page["Reservations"]:
                for inst in reservation["Instances"]:
                    try:
                        tags_dict = {t["Key"]: t["Value"] for t in inst.get("Tags", [])}
                        name = tags_dict.get("Name")
                        ip = inst.get("PrivateIpAddress")
                        hostname = inst.get("PrivateDnsName") or None
                        os_name = inst.get("PlatformDetails") or None

                        is_new, is_upd = await _upsert_asset(db, ip, hostname, name, os_name, "aws", tags_dict)
                        if is_new:
                            imported += 1
                        elif is_upd:
                            updated += 1
                    except Exception as exc:  # noqa: BLE001
                        errors.append(f"Instance {inst.get('InstanceId', '?')}: {exc}")

    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=502, detail=f"AWS API error: {exc}") from exc

    await db.commit()
    logger.info("AWS import completed", imported=imported, updated=updated)
    return CloudImportResult(provider="aws", imported=imported, updated=updated, errors=errors[:20])


@router.post("/import/azure", response_model=CloudImportResult)
async def import_azure(db: DbDep) -> CloudImportResult:
    """Import Azure VMs as assets."""
    if not _azure_available:
        raise HTTPException(
            status_code=501,
            detail="azure-mgmt-compute not installed. Run: pip install netlanventory[cloud]",
        )

    settings = get_settings()
    if not settings.azure_subscription_id:
        raise HTTPException(status_code=400, detail="AZURE_SUBSCRIPTION_ID not configured")

    imported = 0
    updated = 0
    errors: list[str] = []

    try:
        credential = ClientSecretCredential(
            tenant_id=settings.azure_tenant_id or "",
            client_id=settings.azure_client_id or "",
            client_secret=settings.azure_client_secret or "",
        )
        compute_client = ComputeManagementClient(credential, settings.azure_subscription_id)
        network_client = NetworkManagementClient(credential, settings.azure_subscription_id)

        for vm in compute_client.virtual_machines.list_all():
            try:
                name = vm.name
                os_name = None
                if vm.storage_profile and vm.storage_profile.os_disk:
                    os_type = vm.storage_profile.os_disk.os_type
                    os_name = str(os_type) if os_type else None

                # Try to get primary private IP from first NIC
                ip = None
                if vm.network_profile and vm.network_profile.network_interfaces:
                    nic_ref = vm.network_profile.network_interfaces[0]
                    nic_id = nic_ref.id
                    # Extract resource group from NIC ID
                    parts = nic_id.split("/")
                    rg_idx = next((i for i, p in enumerate(parts) if p.lower() == "resourcegroups"), None)
                    nic_idx = next((i for i, p in enumerate(parts) if p.lower() == "networkinterfaces"), None)
                    if rg_idx and nic_idx:
                        rg = parts[rg_idx + 1]
                        nic_name = parts[nic_idx + 1]
                        try:
                            nic = network_client.network_interfaces.get(rg, nic_name)
                            if nic.ip_configurations:
                                ip = nic.ip_configurations[0].private_ip_address
                        except Exception as exc:  # noqa: BLE001
                            logger.warning("azure_nic_fetch_failed", nic_name=nic_name, error=str(exc))

                is_new, is_upd = await _upsert_asset(db, ip, None, name, os_name, "azure", {})
                if is_new:
                    imported += 1
                elif is_upd:
                    updated += 1
            except Exception as exc:  # noqa: BLE001
                errors.append(f"VM {vm.name}: {exc}")

    except HTTPException:
        raise
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=502, detail=f"Azure API error: {exc}") from exc

    await db.commit()
    logger.info("Azure import completed", imported=imported, updated=updated)
    return CloudImportResult(provider="azure", imported=imported, updated=updated, errors=errors[:20])
