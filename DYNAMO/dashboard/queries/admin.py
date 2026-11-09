from sqlalchemy import text

from storage.database import engine
from storage.models import Base
import streamlit as st

def _all_table_names():
    return sorted(Base.metadata.tables.keys())


def _clear_all_caches() -> None:
    try:
        st.cache_data.clear()
    except Exception:
        pass


def flush_all_data() -> None:
    tables = _all_table_names()
    if not tables:
        return
    with engine.begin() as conn:
        conn.execute(text(
            f"TRUNCATE TABLE {', '.join(tables)} RESTART IDENTITY CASCADE"
        ))
    _clear_all_caches()


def flush_scans_only() -> None:
    with engine.begin() as conn:
        conn.execute(text("TRUNCATE TABLE scans RESTART IDENTITY CASCADE"))
    _clear_all_caches()


@st.cache_data(ttl=60, show_spinner=False)
def table_counts() -> dict[str, int]:
    out: dict[str, int] = {}
    with engine.connect() as conn:
        for t in _all_table_names():
            try:
                out[t] = int(
                    conn.execute(text(f"SELECT COUNT(*) FROM {t}")).scalar() or 0
                )
            except Exception:
                out[t] = -1
    return out


def ping() -> str:
    with engine.connect() as conn:
        v = conn.execute(text("SELECT version()")).scalar()
    return str(v).split(",")[0] if v else "unknown"


def delete_scan_by_id(scan_id: int) -> None:
    from storage.database import SessionLocal
    from storage.models import (
        ScanModel, ScanAssetModel, AssetObservationModel,
        ScanProgressModel, PhaseResultModel,
    )

    session = SessionLocal()
    try:
        session.query(AssetObservationModel).filter(
            AssetObservationModel.scan_id == scan_id
        ).delete(synchronize_session=False)

        session.query(ScanProgressModel).filter(
            ScanProgressModel.scan_id == scan_id
        ).delete(synchronize_session=False)

        session.query(PhaseResultModel).filter(
            PhaseResultModel.scan_id == scan_id
        ).delete(synchronize_session=False)

        session.query(ScanAssetModel).filter(
            ScanAssetModel.scan_id == scan_id
        ).delete(synchronize_session=False)

        scan = session.query(ScanModel).get(scan_id)
        if scan:
            session.delete(scan)
            
        session.commit()
    except Exception as e:
        session.rollback()
        raise e
    finally:
        session.close()
        
    _clear_all_caches()


def delete_target_by_id(domain_id: int) -> None:
    """Delete a target domain AND all of its assets and related backend data.
    Scans remain intact (but are unlinked from the deleted assets)."""
    from storage.database import SessionLocal
    from storage.models import (
        DomainModel, DomainAssetModel, AssetModel,
        AssetIPModel, ServiceModel, AssetCVEModel, ChangeEventModel,
        AssetURLModel, NucleiFindingModel, SQLiFindingModel, AssetVulnModel,
        AssetObservationModel, ScanAssetModel
    )
    
    session = SessionLocal()
    try:
        dom = session.query(DomainModel).get(domain_id)
        if not dom:
            return

        # 1. Find all assets tied to this domain
        asset_ids = [a.id for a in session.query(AssetModel).filter(AssetModel.domain_id == domain_id).all()]
        linked_asset_ids = [da.asset_id for da in session.query(DomainAssetModel).filter(DomainAssetModel.domain_id == domain_id).all()]
        all_asset_ids = list(set(asset_ids + linked_asset_ids))

        if all_asset_ids:
            # 2. Delete all child records for these assets
            session.query(AssetObservationModel).filter(AssetObservationModel.asset_id.in_(all_asset_ids)).delete(synchronize_session=False)
            session.query(ScanAssetModel).filter(ScanAssetModel.asset_id.in_(all_asset_ids)).delete(synchronize_session=False)
            session.query(AssetIPModel).filter(AssetIPModel.asset_id.in_(all_asset_ids)).delete(synchronize_session=False)
            session.query(ServiceModel).filter(ServiceModel.asset_id.in_(all_asset_ids)).delete(synchronize_session=False)
            session.query(AssetCVEModel).filter(AssetCVEModel.asset_id.in_(all_asset_ids)).delete(synchronize_session=False)
            session.query(ChangeEventModel).filter(ChangeEventModel.asset_id.in_(all_asset_ids)).delete(synchronize_session=False)
            session.query(AssetURLModel).filter(AssetURLModel.asset_id.in_(all_asset_ids)).delete(synchronize_session=False)
            session.query(NucleiFindingModel).filter(NucleiFindingModel.asset_id.in_(all_asset_ids)).delete(synchronize_session=False)
            session.query(SQLiFindingModel).filter(SQLiFindingModel.asset_id.in_(all_asset_ids)).delete(synchronize_session=False)
            session.query(AssetVulnModel).filter(AssetVulnModel.asset_id.in_(all_asset_ids)).delete(synchronize_session=False)

            # 3. Delete the association rows FIRST to break the foreign key link
            session.query(DomainAssetModel).filter(DomainAssetModel.asset_id.in_(all_asset_ids)).delete(synchronize_session=False)
            
            # 4. Now delete the assets themselves
            session.query(AssetModel).filter(AssetModel.id.in_(all_asset_ids)).delete(synchronize_session=False)

        # 5. Delete any remaining domain links (for safety) and the domain
        session.query(DomainAssetModel).filter(DomainAssetModel.domain_id == domain_id).delete(synchronize_session=False)
        session.delete(dom)
        
        session.commit()
    except Exception as e:
        session.rollback()
        raise e
    finally:
        session.close()
        
    _clear_all_caches()