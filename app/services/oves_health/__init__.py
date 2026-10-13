"""OVES platform health: a 60 s collector for the OVES EKS clusters, code
generation, MongoDB, and the external services OVES and this app depend on.

Entry point: ``app.services.oves_health.service.run_cycle`` (scheduler job
``oves_health_snapshot`` in main.py). Served by ``/api/admin/oves-health*``.
"""
