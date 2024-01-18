from typing import List, Optional
from uuid import uuid4

from lightspark import InvoiceData
from uma import Currency, LnurlpResponse

from uma_vasp.sending_vasp_request_cache import (
    ISendingVaspRequestCache,
    SendingVaspInitialRequestData,
    SendingVaspPayReqData,
)


class InMemorySendingVaspRequestCache(ISendingVaspRequestCache):
    def __init__(self):
        self.lnurlp_response_data = {}
        self.payreq_data = {}

    def get_lnurlp_response_data(
        self, uuid: str
    ) -> Optional[SendingVaspInitialRequestData]:
        return self.lnurlp_response_data.get(uuid)

    def get_pay_req_data(self, uuid: str) -> Optional[SendingVaspPayReqData]:
        return self.payreq_data.get(uuid)

    def save_lnurlp_response_data(
        self,
        lnurlp_response: LnurlpResponse,
        receiver_id: str,
        receiving_vasp_domain: str,
    ) -> str:
        uuid = str(uuid4())
        self.lnurlp_response_data[uuid] = SendingVaspInitialRequestData(
            lnurlp_response=lnurlp_response,
            receiver_id=receiver_id,
            receiving_vasp_domain=receiving_vasp_domain,
        )
        return uuid

    def save_pay_req_data(
        self,
        encoded_invoice: str,
        utxo_callback: str,
        invoice_data: InvoiceData,
        sender_currencies: List[Currency],
    ) -> str:
        uuid = str(uuid4())
        self.payreq_data[uuid] = SendingVaspPayReqData(
            encoded_invoice=encoded_invoice,
            utxo_callback=utxo_callback,
            invoice_data=invoice_data,
            sender_currencies=sender_currencies,
        )
        return uuid
