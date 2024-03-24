from datetime import datetime, timedelta
from typing import Optional, Type, TypeVar

from lightspark import LightsparkSyncClient, Requester
from lightspark.objects.BitcoinNetwork import BitcoinNetwork
from lightspark.objects.CurrencyAmount import CurrencyAmount
from lightspark.objects.CurrencyUnit import CurrencyUnit
from lightspark.objects.Entity import Entity
from lightspark.objects.GraphNode import GraphNode
from lightspark.objects.Invoice import Invoice
from lightspark.objects.InvoiceData import InvoiceData
from lightspark.objects.LightsparkNode import LightsparkNode
from lightspark.objects.LightsparkNodeStatus import LightsparkNodeStatus
from lightspark.objects.PaymentRequestStatus import PaymentRequestStatus

ENTITY = TypeVar("ENTITY", bound=Entity)


class FakeLightsparkClient(LightsparkSyncClient):
    last_created_invoice: Optional[Invoice] = None

    def __init__(self):
        pass

    def get_entity(
        self, entity_id: str, entity_class: Type[ENTITY]
    ) -> Optional[ENTITY]:
        if entity_class == LightsparkNode:
            # pyre-fixme[7]: Expected `Optional[Variable[ENTITY (bound to Entity)]]` but got `LightsparkNode`.
            return LightsparkNode(
                requester=Requester("abcd", "1234"),
                id=entity_id,
                created_at=datetime.now(),
                updated_at=datetime.now(),
                bitcoin_network=BitcoinNetwork.MAINNET,
                typename="LightsparkNode",
                color=None,
                alias=None,
                conductivity=None,
                public_key="fake_public",
                display_name="fake_display_name",
                owner_id="fake_owner_id",
                status=LightsparkNodeStatus.READY,
                total_balance=None,
                total_local_balance=None,
                local_balance=None,
                remote_balance=None,
                blockchain_balance=None,
                uma_prescreening_utxos=[],
                balances=None,
            )  # type: ignore
        return None

    def create_uma_invoice(
        self,
        node_id: str,
        amount_msats: int,
        metadata: str,
        expiry_secs: Optional[int] = None,
    ) -> Invoice:
        requester = Requester("abcd", "1234")
        destination_node = GraphNode(
            requester=requester,
            id=node_id,
            typename="GraphNode",
            created_at=datetime.now(),
            updated_at=datetime.now(),
            bitcoin_network=BitcoinNetwork.MAINNET,
            color=None,
            alias=None,
            conductivity=None,
            public_key="fake_public",
            display_name="fake_display_name",
        )
        invoice_data = InvoiceData(
            requester=requester,
            encoded_payment_request="fakepaymentrequest",
            bitcoin_network=BitcoinNetwork.MAINNET,
            typename="InvoiceData",
            payment_hash="fake_payment_hash",
            amount=CurrencyAmount(
                requester=requester,
                original_value=amount_msats,
                original_unit=CurrencyUnit.MILLISATOSHI,
                preferred_currency_unit=CurrencyUnit.MILLISATOSHI,
                preferred_currency_value_approx=amount_msats,
                preferred_currency_value_rounded=amount_msats,
            ),
            created_at=datetime.now(),
            expires_at=datetime.now() + timedelta(seconds=expiry_secs or 3600),
            memo=None,
            destination=destination_node,
        )
        invoice = Invoice(
            requester=requester,
            id="fake_invoice_id",
            created_at=datetime.now(),
            updated_at=datetime.now(),
            typename="Invoice",
            data=invoice_data,
            status=PaymentRequestStatus.OPEN,
            amount_paid=None,
        )
        self.last_created_invoice = invoice
        return invoice
