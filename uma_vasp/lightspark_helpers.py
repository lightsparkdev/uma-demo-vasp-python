from lightspark import LightsparkNode, LightsparkSyncClient

from uma_vasp.config import Config
from uma_vasp.flask_helpers import abort_with_error
from uma_vasp.uma_exception import UmaException


def get_node(lightspark_client: LightsparkSyncClient, node_id: str) -> LightsparkNode:
    node = lightspark_client.get_entity(node_id, LightsparkNode)
    if not node:
        raise UmaException(f"Cannot find node {node_id}", 404)
    return node


def load_signing_key(lightspark_client: LightsparkSyncClient, config: Config):
    node = get_node(lightspark_client, config.node_id)

    if "OSK" in node.typename:
        osk_password = config.osk_node_signing_key_password
        if not osk_password:
            abort_with_error(
                400,
                "OSK password is required for OSK nodes.",
            )
        lightspark_client.recover_node_signing_key(config.node_id, osk_password)
        return

    # Assume remote signing.
    master_seed = config.get_remote_signing_node_master_seed()
    if not master_seed:
        abort_with_error(
            400, "Remote signing master seed is required for remote signing nodes."
        )
    lightspark_client.provide_node_master_seed(
        config.node_id, master_seed, node.bitcoin_network
    )
