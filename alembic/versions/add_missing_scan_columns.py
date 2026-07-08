"""add missing scan columns

Revision ID: a1b2c3d4e5f6
Revises: dc3ba5b51dce
Create Date: 2026-03-11 00:00:00.000000

PURPOSE:
  - scan_jobs:       add scan_type, progress, grade, total_issues,
                     critical_count, high_count, medium_count, low_count
  - vulnerabilities: add vuln_type, severity, cve_id, verified,
                     false_positive, poe_confirmed, poe_detail
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'a1b2c3d4e5f6'
down_revision: Union[str, None] = 'dc3ba5b51dce'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ── scan_jobs: add missing columns ────────────────────────────────
    op.add_column('scan_jobs', sa.Column('scan_type',      sa.String(length=50), nullable=True, server_default='full'))
    op.add_column('scan_jobs', sa.Column('progress',       sa.Integer(),         nullable=True, server_default='0'))
    op.add_column('scan_jobs', sa.Column('grade',          sa.String(length=2),  nullable=True))
    op.add_column('scan_jobs', sa.Column('total_issues',   sa.Integer(),         nullable=True, server_default='0'))
    op.add_column('scan_jobs', sa.Column('critical_count', sa.Integer(),         nullable=True, server_default='0'))
    op.add_column('scan_jobs', sa.Column('high_count',     sa.Integer(),         nullable=True, server_default='0'))
    op.add_column('scan_jobs', sa.Column('medium_count',   sa.Integer(),         nullable=True, server_default='0'))
    op.add_column('scan_jobs', sa.Column('low_count',      sa.Integer(),         nullable=True, server_default='0'))

    # ── vulnerabilities: add missing columns ──────────────────────────
    op.add_column('vulnerabilities', sa.Column('vuln_type',      sa.String(length=100), nullable=True))
    op.add_column('vulnerabilities', sa.Column('severity',       sa.String(length=20),  nullable=True, server_default='medium'))
    op.add_column('vulnerabilities', sa.Column('cve_id',         sa.String(length=50),  nullable=True))
    op.add_column('vulnerabilities', sa.Column('verified',       sa.Boolean(),          nullable=True, server_default='false'))
    op.add_column('vulnerabilities', sa.Column('false_positive', sa.Boolean(),          nullable=True, server_default='false'))
    op.add_column('vulnerabilities', sa.Column('poe_confirmed',  sa.Boolean(),          nullable=True, server_default='false'))
    op.add_column('vulnerabilities', sa.Column('poe_detail',     sa.Text(),             nullable=True))


def downgrade() -> None:
    op.drop_column('vulnerabilities', 'poe_detail')
    op.drop_column('vulnerabilities', 'poe_confirmed')
    op.drop_column('vulnerabilities', 'false_positive')
    op.drop_column('vulnerabilities', 'verified')
    op.drop_column('vulnerabilities', 'cve_id')
    op.drop_column('vulnerabilities', 'severity')
    op.drop_column('vulnerabilities', 'vuln_type')
    op.drop_column('scan_jobs', 'low_count')
    op.drop_column('scan_jobs', 'medium_count')
    op.drop_column('scan_jobs', 'high_count')
    op.drop_column('scan_jobs', 'critical_count')
    op.drop_column('scan_jobs', 'total_issues')
    op.drop_column('scan_jobs', 'grade')
    op.drop_column('scan_jobs', 'progress')
    op.drop_column('scan_jobs', 'scan_type')