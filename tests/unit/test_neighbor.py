from isis_attack.core.neighbor import ISNeighborState, ISNeighbor

def test_neighbor_states():
    assert ISNeighborState.DOWN == 0
    assert ISNeighborState.INIT == 1
    assert ISNeighborState.UP == 2

def test_neighbor_creation():
    n = ISNeighbor(sys_id="1921.6800.2001", level=1)
    assert n.sys_id == "1921.6800.2001"
    assert n.state == ISNeighborState.DOWN
    assert n.level == 1

def test_neighbor_transitions():
    n = ISNeighbor(sys_id="1921.6800.2001", level=1)
    n.state = ISNeighborState.INIT
    assert n.state == ISNeighborState.INIT
    n.state = ISNeighborState.UP
    assert n.state == ISNeighborState.UP
