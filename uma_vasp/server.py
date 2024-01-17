from uma_vasp.config import Config

from uma_vasp.demo.demo_use_service import DemoUserService
from uma_vasp.receiving_vasp import ReceivingVasp
from uma_vasp.app import app

user_service = DemoUserService()
config = Config()

receiving_vasp = ReceivingVasp(
    user_service=user_service,
    config=config,
)


@app.route("/.well-known/lnurlp/<username>")
def handle_lnurlp_request(username: str):
    return receiving_vasp.handle_lnurlp_request(username)
