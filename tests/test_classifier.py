from classify.device_classifier import DeviceClassifier
from core.models import NetworkDevice


def test_printer_classification_high_confidence() -> None:
    classifier = DeviceClassifier(gateway_candidates={"192.168.1.1"})
    device = NetworkDevice(
        ip="192.168.1.50",
        vendor="HP Inc.",
        hostname="hp-printer-lab",
        open_ports=[631, 9100],
        services=["ipp", "jetdirect"],
    )
    result = classifier.classify(device)
    assert result.device_type == "printer"
    assert result.confidence >= 0.8
