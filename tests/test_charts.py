

def test_low_traffic_axis_follows_peak():
    from app.charts import line_chart
    html = line_chart({"Received": [(0, 1024.0), (60, 3 * 1024.0)]}, "B/s")
    assert '<span>5 KiB/s</span>' in html and "Peak 3 KiB/s" in html
    assert "Peak" not in line_chart({"Received": []}, "B/s")
