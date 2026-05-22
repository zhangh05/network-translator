from __future__ import annotations

from core.ir_models.enums import (
    IRType, IRFhrpProtocol, IRInterfaceType,
    IRRiskLevel, ConversionStatus,
)
from core.ir_models.base import IRModelBase, SourceSpan
from core.ir_models.common import (
    IRInterface, IRStaticRoute, IRAcl, IRAclEntry, IRAaa, IRManagement,
)
from core.ir_models.switch import IRVlan, IRSvi, IRFhrp, IRLag, IRStp
from core.ir_models.router import (
    IROspf, IRBgp, IRVrf, IRPbr, IRNat, IRIpsecVpn,
)
from core.ir_models.firewall import (
    IRZone, IRAddressObject, IRServiceObject,
    IRSecurityPolicy, IRNatRule,
)
from core.ir_models.unsupported import IRUnsupported, IRUnknownBlock
from core.ir_models.ir_config import IRConfig, IRConfigMeta

__all__ = [
    'IRType', 'IRFhrpProtocol', 'IRInterfaceType', 'IRRiskLevel', 'ConversionStatus',
    'SourceSpan', 'IRModelBase',
    'IRInterface', 'IRStaticRoute', 'IRAcl', 'IRAclEntry', 'IRAaa', 'IRManagement',
    'IRVlan', 'IRSvi', 'IRFhrp', 'IRLag', 'IRStp',
    'IROspf', 'IRBgp', 'IRVrf', 'IRPbr', 'IRNat', 'IRIpsecVpn',
    'IRZone', 'IRAddressObject', 'IRServiceObject', 'IRSecurityPolicy', 'IRNatRule',
    'IRUnsupported', 'IRUnknownBlock',
    'IRConfig', 'IRConfigMeta',
]
