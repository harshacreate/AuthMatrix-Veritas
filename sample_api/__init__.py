"""Two sample APIs use the same data. One has access bugs for the checks to find. The other
fixes them. Starlette's TestClient runs both inside the process, so they do not open a
network port.
"""
