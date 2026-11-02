"""Interactive paired HTTPS server launcher."""
from gevent import monkey
monkey.patch_all()

from src.pairing import main

if __name__ == "__main__":
    main()
