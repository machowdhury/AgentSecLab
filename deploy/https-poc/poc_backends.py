"""Starts the real Attack Service (15001) and AcmeBank (15000) on 127.0.0.1 only, as the PoC target."""
import threading
from werkzeug.serving import make_server
from agentsec.attack_app import AcmeBankClient, create_app as attack
from agentsec.bank_app import build_runtime, create_app as bank
from agentsec.settings import get_settings
b = make_server("127.0.0.1", 15000, bank(build_runtime(get_settings(), otel_enabled=False)), threaded=True)
a = make_server("127.0.0.1", 15001, attack(AcmeBankClient("http://127.0.0.1:15000")), threaded=True)
threading.Thread(target=b.serve_forever, daemon=True).start()
a.serve_forever()
